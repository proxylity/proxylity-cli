using System.Globalization;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation.Adapters;

namespace Proxylity.Cli.Core.Observation;

/// <param name="IncludeLogs">Read Proxylity listener and destination log groups.</param>
/// <param name="IncludeTargetLogs">Read recent error-like lines from target resources' own logs.</param>
/// <param name="LogLimit">Most recent events kept per log group.</param>
/// <param name="CheckRoles">Check destination and listener roles (trust policy and simulated permissions).</param>
public sealed record CollectorOptions(bool IncludeLogs, bool IncludeTargetLogs, int LogLimit = 50, int MaxConcurrency = 8, bool CheckRoles = false);

/// <summary>
/// Reads live operational signals for listeners, their destinations and their target resources. Targets are
/// handled by service adapters (<see cref="TargetAdapters"/>). Metric queries are planned first and sent as one
/// batch per region; descriptions and logs are read with bounded concurrency. Nothing here interprets the
/// data; see <see cref="Diagnoser"/>.
/// </summary>
public sealed class ObservationCollector(IObservabilitySource source, string defaultRegion, CollectorOptions options)
{
    public const string ProxylityNamespace = "Proxylity/UDP Gateway";

    private sealed class Planner
    {
        private int _next;

        public Dictionary<string, List<MetricQuery>> ByRegion { get; } = new(StringComparer.Ordinal);

        public List<(string Region, string Id)> Add(IEnumerable<string> regions, string ns, string metric, IReadOnlyList<KeyValuePair<string, string>> dims, string stat)
        {
            var ids = new List<(string, string)>();
            foreach (var region in regions)
            {
                var id = "q" + (_next++).ToString(CultureInfo.InvariantCulture);
                if (!ByRegion.TryGetValue(region, out var list))
                {
                    ByRegion[region] = list = [];
                }

                list.Add(new MetricQuery(id, ns, metric, dims, stat));
                ids.Add((region, id));
            }

            return ids;
        }
    }

    private sealed record PlannedMetric(string Key, string Statistic, List<(string Region, string Id)> Queries);

    /// <summary>Everything planned for one target.</summary>
    private sealed class TargetWork(DestinationTarget target, DestinationInfo destination, ITargetAdapter? adapter)
    {
        public DestinationTarget Target { get; } = target;

        public DestinationInfo Destination { get; } = destination;

        public ITargetAdapter? Adapter { get; } = adapter;

        public Signal<TargetDescription>? Description { get; set; }

        public List<PlannedMetric> Metrics { get; } = [];

        public Task<LogObservation>? ErrorLogs { get; set; }
    }

    public async Task<ObservationReport> CollectAsync(IReadOnlyList<ListenerInfo> listeners, TimeWindow window, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        var gate = new SemaphoreSlim(Math.Max(1, options.MaxConcurrency));

        // 1. Describe targets through their adapters (deduplicated: the same target can appear more than once).
        var work = new Dictionary<(ListenerInfo, int, int), TargetWork>();
        var describeTasks = new Dictionary<string, Task<Signal<TargetDescription>>>(StringComparer.Ordinal);
        foreach (var listener in listeners)
        {
            for (var di = 0; di < listener.Destinations.Count; di++)
            {
                var destination = listener.Destinations[di];
                for (var ti = 0; ti < destination.Targets.Count; ti++)
                {
                    var target = Concrete(destination.Targets[ti]);
                    var adapter = target.Arn.IsResolved ? TargetAdapters.For(target.Service) : null;
                    var w = new TargetWork(target, destination, adapter);
                    work[(listener, di, ti)] = w;
                    if (adapter is not null)
                    {
                        var key = $"{target.Arn.Value}|{destination.Name}";
                        if (!describeTasks.ContainsKey(key))
                        {
                            describeTasks[key] = Bounded(gate, () => adapter.DescribeAsync(target, destination, source, ct), ct);
                        }
                    }
                }
            }
        }

        foreach (var w in work.Values.Where(w => w.Adapter is not null))
        {
            w.Description = await describeTasks[$"{w.Target.Arn.Value}|{w.Destination.Name}"].ConfigureAwait(false);
        }

        // 2. Plan metric queries.
        var planner = new Planner();
        var listenerPlans = new Dictionary<ListenerInfo, (List<string> Regions, List<PlannedMetric> Metrics)>();
        var destinationPlans = new Dictionary<(ListenerInfo, int), (List<string> Regions, List<PlannedMetric> Metrics)>();
        foreach (var listener in listeners)
        {
            var listenerRegions = ListenerRegions(listener);
            var lm = new List<PlannedMetric>();
            if (listener.MetricsEnabled.Value && listener.Name is { } listenerName)
            {
                lm.AddRange(PlanProxylity(planner, listenerRegions, "Listener", listenerName, includeEgress: false));
            }

            listenerPlans[listener] = (listenerRegions, lm);

            for (var di = 0; di < listener.Destinations.Count; di++)
            {
                var destination = listener.Destinations[di];
                var destinationRegions = DestinationRegions(destination);
                var dm = new List<PlannedMetric>();
                if (destination.MetricsEnabled.Value && destination.Name is { } destinationName)
                {
                    dm.AddRange(PlanProxylity(planner, destinationRegions, "Destination", destinationName, includeEgress: true));
                }

                destinationPlans[(listener, di)] = (destinationRegions, dm);

                for (var ti = 0; ti < destination.Targets.Count; ti++)
                {
                    var w = work[(listener, di, ti)];
                    if (w.Adapter is null || w.Description?.IsAvailable != true)
                    {
                        continue;
                    }

                    List<string> region = [w.Target.ArnRegion ?? defaultRegion];
                    foreach (var m in w.Adapter.Metrics(w.Target, w.Description.Value!))
                    {
                        w.Metrics.Add(new PlannedMetric(m.Key, m.Statistic, planner.Add(region, m.Namespace, m.MetricName, m.Dimensions, m.Statistic)));
                    }
                }
            }
        }

        // 3. One metrics batch per region.
        var results = new Dictionary<(string Region, string Id), Signal<double>>();
        await Task.WhenAll(planner.ByRegion.Select(async kv =>
        {
            var values = await Bounded(gate, () => source.GetMetricsAsync(kv.Key, kv.Value, window, ct), ct).ConfigureAwait(false);
            lock (results)
            {
                foreach (var q in kv.Value)
                {
                    results[(kv.Key, q.Id)] = values.TryGetValue(q.Id, out var v) ? v : Signal<double>.NoData();
                }
            }
        })).ConfigureAwait(false);

        // 4. Logs (deduplicated by group, regions and pattern).
        var logTasks = new Dictionary<string, Task<LogObservation>>(StringComparer.Ordinal);
        Task<LogObservation> ReadLogs(string group, List<string> regions, string? pattern, int limit, bool targetLog)
        {
            var key = $"{group}|{string.Join(',', regions)}|{pattern}|{limit}";
            if (!logTasks.TryGetValue(key, out var task))
            {
                logTasks[key] = task = ReadLogGroupAsync(gate, group, regions, window, pattern, limit, targetLog, ct);
            }

            return task;
        }

        foreach (var w in work.Values)
        {
            if (options.IncludeTargetLogs && w.Adapter is not null && w.Description?.IsAvailable == true
                && w.Adapter.ErrorLogs(w.Target, w.Destination, w.Description.Value!) is { } plan)
            {
                w.ErrorLogs = ReadLogs(plan.LogGroup, [w.Target.ArnRegion ?? defaultRegion], plan.FilterPattern, plan.Limit, true);
            }
        }

        // 5. Roles: trust policy and the permissions each role needs (delivery, logs, metrics).
        var roleTasks = new Dictionary<object, Task<RoleObservation>>(ReferenceEqualityComparer.Instance);
        var configs = new Dictionary<(string Account, string Region), Signal<AccountConfig>>();
        if (options.CheckRoles)
        {
            // The account configuration is optional: without it, checks fall back to structure only.
            var pairs = listeners.Select(l => (l.Stack.AccountId, l.Stack.Region)).Where(p => p.AccountId.Length > 0).Distinct().ToList();
            var reads = await Task.WhenAll(pairs.Select(p => Bounded(gate, () => source.GetAccountConfigAsync(p.Region, p.AccountId, ct), ct))).ConfigureAwait(false);
            for (var i = 0; i < pairs.Count; i++)
            {
                configs[pairs[i]] = reads[i];
            }
        }

        AccountConfig? ConfigFor(ListenerInfo l) =>
            configs.TryGetValue((l.Stack.AccountId, l.Stack.Region), out var c) && c.IsAvailable ? c.Value : null;

        if (options.CheckRoles)
        {
            // IAM has low request-rate limits; role checks get their own, smaller limit.
            var iamGate = new SemaphoreSlim(3);
            var runner = new RoleChecks.Runner(source, f => BoundedAction(iamGate, f, ct), ct);
            foreach (var listener in listeners)
            {
                var account = listener.Stack.AccountId;
                var config = ConfigFor(listener);
                if (listener.Role?.Arn is { IsResolved: true } listenerRole)
                {
                    var requests = RoleChecks.Observability(listener.MetricsEnabled, listener.LogGroupName, listenerPlans[listener].Regions[0], account);
                    roleTasks[listener] = runner.CheckAsync(listenerRole.Value!, account, requests, config, listener.Stack.Region);
                }

                for (var di = 0; di < listener.Destinations.Count; di++)
                {
                    var destination = listener.Destinations[di];
                    if (destination.IsReferenceByName || destination.Role?.Arn is not { IsResolved: true } destinationRole)
                    {
                        continue;
                    }

                    var requests = RoleChecks.Observability(destination.MetricsEnabled, destination.LogGroupName, destinationPlans[(listener, di)].Regions[0], account);
                    for (var ti = 0; ti < destination.Targets.Count; ti++)
                    {
                        var w = work[(listener, di, ti)];
                        if (w.Adapter is not null)
                        {
                            var description = w.Description?.IsAvailable == true ? w.Description.Value : null;
                            requests.AddRange(w.Adapter.Permissions(w.Target, destination, description)
                                .Select(p => new RoleChecks.Request(RoleChecks.Delivery, p.Actions, p.Resource, null)));
                        }
                    }

                    roleTasks[destination] = runner.CheckAsync(destinationRole.Value!, account, requests, config, listener.Stack.Region);
                }
            }
        }

        async Task<RoleObservation?> RoleFor(object owner) =>
            roleTasks.TryGetValue(owner, out var task) ? await task.ConfigureAwait(false) : null;

        // 6. Assemble.
        var observations = new List<ListenerObservation>();
        foreach (var listener in listeners)
        {
            var (lRegions, lMetrics) = listenerPlans[listener];
            var listenerLogs = options.IncludeLogs && listener.LogGroupName.IsResolved
                ? ReadLogs(listener.LogGroupName.Value!, lRegions, null, options.LogLimit, false)
                : null;

            var destinationObservations = new List<DestinationObservation>();
            for (var di = 0; di < listener.Destinations.Count; di++)
            {
                var destination = listener.Destinations[di];
                var (dRegions, dMetrics) = destinationPlans[(listener, di)];
                var destinationLogs = options.IncludeLogs && destination.LogGroupName.IsResolved
                    ? ReadLogs(destination.LogGroupName.Value!, dRegions, null, options.LogLimit, false)
                    : null;

                var targetObservations = new List<TargetObservation>();
                for (var ti = 0; ti < destination.Targets.Count; ti++)
                {
                    var w = work[(listener, di, ti)];
                    targetObservations.Add(new TargetObservation(
                        w.Target,
                        w.Description,
                        Aggregate(w.Metrics, results, null),
                        w.ErrorLogs is null ? null : await w.ErrorLogs.ConfigureAwait(false),
                        []));
                }

                destinationObservations.Add(new DestinationObservation(
                    destination,
                    dRegions,
                    Aggregate(dMetrics, results, MetricsOff(destination.MetricsEnabled, "destination")),
                    destinationLogs is null ? null : await destinationLogs.ConfigureAwait(false),
                    targetObservations,
                    [],
                    dMetrics.Count == 0 ? null : ByRegion(dMetrics, results),
                    await RoleFor(destination).ConfigureAwait(false)));
            }

            observations.Add(new ListenerObservation(
                listener,
                lRegions,
                Aggregate(lMetrics, results, MetricsOff(listener.MetricsEnabled, "listener")),
                listenerLogs is null ? null : await listenerLogs.ConfigureAwait(false),
                destinationObservations,
                [],
                await RoleFor(listener).ConfigureAwait(false),
                AccountCheckFor(listener)));
        }

        AccountCheck? AccountCheckFor(ListenerInfo l)
        {
            if (!configs.TryGetValue((l.Stack.AccountId, l.Stack.Region), out var c))
            {
                return null;
            }

            if (!c.IsAvailable)
            {
                return new AccountCheck(l.Stack.Region, c.State, c.Detail, null, null);
            }

            static bool? Matches(Resolved<string>? template, string? expected) =>
                template is { IsResolved: true } t && expected is not null ? string.Equals(t.Value, expected, StringComparison.Ordinal) : null;

            return new AccountCheck(l.Stack.Region, SignalState.Available, null,
                Matches(l.ServiceTokenFingerprint, c.Value!.ServiceTokenFingerprint(l.Stack.Region)),
                Matches(l.KeyFingerprint, c.Value.KeyFingerprint));
        }

        return new ObservationReport(window, observations, []);
    }

    /// <summary>
    /// A single ARN with "*" as its region resolves to the ingress region, which isn't known here. Inspect the
    /// target in the region the CLI runs against, and mark it so the output can say so.
    /// </summary>
    private DestinationTarget Concrete(DestinationTarget t)
    {
        if (t.ArnRegion != "*" || !t.Arn.IsResolved || ArnParser.Parse(t.Arn.Value) is not { } p)
        {
            return t;
        }

        var arn = $"arn:{p.Partition}:{p.Service}:{defaultRegion}:{p.AccountId}:{p.Resource}";
        return t with { Arn = Resolved<string>.Ok(arn), ArnRegion = defaultRegion, RegionFromIngress = true };
    }

    /// <summary>
    /// Listener metrics and logs are written in the region where traffic entered the gateway, which is not
    /// visible in configuration. Look in the CLI's region and in each destination target's region.
    /// </summary>
    private List<string> ListenerRegions(ListenerInfo listener)
    {
        var regions = new SortedSet<string>(StringComparer.Ordinal) { defaultRegion };
        foreach (var t in listener.Destinations.SelectMany(d => d.Targets))
        {
            if (t.ArnRegion is { Length: > 0 } r && r != "*")
            {
                regions.Add(r);
            }
        }

        return [.. regions];
    }

    /// <summary>Destination metrics and logs are written in the target ARN's region, or the entry region if it has none.</summary>
    private List<string> DestinationRegions(DestinationInfo destination)
    {
        var regions = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var t in destination.Targets)
        {
            regions.Add(t.ArnRegion is { Length: > 0 } r && r != "*" ? r : defaultRegion);
        }

        if (regions.Count == 0)
        {
            regions.Add(defaultRegion);
        }

        return [.. regions];
    }

    private static IEnumerable<PlannedMetric> PlanProxylity(Planner planner, List<string> regions, string dimension, string name, bool includeEgress)
    {
        IReadOnlyList<KeyValuePair<string, string>> dims = [new(dimension, name)];
        yield return new PlannedMetric(MetricKeys.Ingress, "Sum", planner.Add(regions, ProxylityNamespace, "IngressPackets", dims, "Sum"));
        yield return new PlannedMetric(MetricKeys.IngressBytes, "Sum", planner.Add(regions, ProxylityNamespace, "IngressBytes", dims, "Sum"));
        yield return new PlannedMetric(MetricKeys.Filtered, "Sum", planner.Add(regions, ProxylityNamespace, "FilteredPackets", dims, "Sum"));
        yield return new PlannedMetric(MetricKeys.FilteredBytes, "Sum", planner.Add(regions, ProxylityNamespace, "FilteredBytes", dims, "Sum"));
        yield return new PlannedMetric(MetricKeys.Errors, "Sum", planner.Add(regions, ProxylityNamespace, "Errors", dims, "Sum"));
        if (includeEgress)
        {
            yield return new PlannedMetric(MetricKeys.Egress, "Sum", planner.Add(regions, ProxylityNamespace, "EgressPackets", dims, "Sum"));
        }
    }

    private static Signal<double>? MetricsOff(Resolved<bool> enabled, string level) => enabled.State switch
    {
        ValueState.Resolved when enabled.Value => null,
        ValueState.Unresolved => Signal<double>.NotConfigured($"{level} MetricsEnabled could not be determined"),
        _ => Signal<double>.NotConfigured($"{level} metrics are off (MetricsEnabled)"),
    };

    private static Dictionary<string, Signal<double>> Aggregate(
        List<PlannedMetric> plans,
        Dictionary<(string Region, string Id), Signal<double>> results,
        Signal<double>? whenUnplanned)
    {
        var output = new Dictionary<string, Signal<double>>(StringComparer.Ordinal);
        if (plans.Count == 0)
        {
            if (whenUnplanned is not null)
            {
                foreach (var key in new[] { MetricKeys.Ingress, MetricKeys.Filtered, MetricKeys.Errors })
                {
                    output[key] = whenUnplanned;
                }
            }

            return output;
        }

        foreach (var plan in plans)
        {
            output[plan.Key] = Combine(plan.Statistic, [.. plan.Queries.Select(q => results.TryGetValue(q, out var s) ? s : Signal<double>.NoData())]);
        }

        return output;
    }

    /// <summary>The same metrics, kept per region (destination metrics are published in the target ARN's region).</summary>
    private static Dictionary<string, IReadOnlyDictionary<string, Signal<double>>> ByRegion(
        List<PlannedMetric> plans, Dictionary<(string Region, string Id), Signal<double>> results)
    {
        var output = new Dictionary<string, IReadOnlyDictionary<string, Signal<double>>>(StringComparer.Ordinal);
        foreach (var region in plans.SelectMany(p => p.Queries).Select(q => q.Region).Distinct(StringComparer.Ordinal))
        {
            var values = new Dictionary<string, Signal<double>>(StringComparer.Ordinal);
            foreach (var plan in plans)
            {
                var query = plan.Queries.FirstOrDefault(q => q.Region == region);
                if (query != default)
                {
                    values[plan.Key] = results.TryGetValue(query, out var s) ? s : Signal<double>.NoData();
                }
            }

            output[region] = values;
        }

        return output;
    }

    /// <summary>Combines the same metric across regions. Any data wins; otherwise the most informative failure is kept.</summary>
    internal static Signal<double> Combine(string statistic, IReadOnlyList<Signal<double>> signals)
    {
        var available = signals.Where(s => s.IsAvailable).Select(s => s.Value).ToList();
        if (available.Count > 0)
        {
            return Signal<double>.Of(statistic switch
            {
                "Maximum" => available.Max(),
                "Average" => available.Average(),
                _ => available.Sum(),
            });
        }

        return signals.FirstOrDefault(s => s.State == SignalState.NotAccessible)
            ?? signals.FirstOrDefault(s => s.State == SignalState.Failed)
            ?? Signal<double>.NoData("no data in the window");
    }

    private async Task<LogObservation> ReadLogGroupAsync(
        SemaphoreSlim gate, string group, List<string> regions, TimeWindow window, string? pattern, int limit, bool targetLog, CancellationToken ct)
    {
        var events = new List<LogSample>();
        var truncated = false;
        var states = new List<Signal<LogQueryResult>>();
        Func<LogEvent, LogSample> parse = targetLog ? GatewayLogs.ParseFunctionLine : GatewayLogs.Parse;
        foreach (var region in regions)
        {
            var result = await Bounded(gate, () => source.GetLogEventsAsync(region, group, window, pattern, limit, ct), ct).ConfigureAwait(false);
            states.Add(result);
            if (result.IsAvailable)
            {
                truncated |= result.Value!.Truncated;
                events.AddRange(result.Value.Events.Select(parse));
            }
        }

        Signal<IReadOnlyList<LogSample>> signal;
        if (states.Any(s => s.IsAvailable))
        {
            IReadOnlyList<LogSample> ordered = [.. events.OrderBy(e => e.Timestamp).TakeLast(limit)];
            signal = ordered.Count == 0 ? Signal<IReadOnlyList<LogSample>>.NoData("no events in the window") : Signal<IReadOnlyList<LogSample>>.Of(ordered);
        }
        else
        {
            var failure = states.FirstOrDefault(s => s.State == SignalState.NotAccessible)
                ?? states.FirstOrDefault(s => s.State == SignalState.NotFound)
                ?? states.FirstOrDefault()
                ?? Signal<LogQueryResult>.NoData();
            signal = failure.Cast<IReadOnlyList<LogSample>>();
        }

        return new LogObservation(group, regions, signal, truncated);
    }

    private static async Task BoundedAction(SemaphoreSlim gate, Func<Task> call, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await call().ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<T> Bounded<T>(SemaphoreSlim gate, Func<Task<T>> call, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await call().ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }
}
