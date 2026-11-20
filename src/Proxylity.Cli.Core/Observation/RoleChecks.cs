using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation.Adapters;

namespace Proxylity.Cli.Core.Observation;

/// <summary>
/// Plans and runs checks of the IAM roles Proxylity assumes: the trust policy, and the permissions each role needs
/// for delivery, logs and metrics. Everything is read-only (iam:GetRole and iam:SimulatePrincipalPolicy).
/// </summary>
public static class RoleChecks
{
    public const string Delivery = "delivery";
    public const string Logs = "logs";
    public const string Metrics = "metrics";

    public sealed record Request(string Purpose, IReadOnlyList<string> Actions, string Resource, IReadOnlyDictionary<string, string>? Context);

    private static readonly IReadOnlyDictionary<string, string> MetricsContext =
        new Dictionary<string, string>(StringComparer.Ordinal) { ["cloudwatch:namespace"] = ObservationCollector.ProxylityNamespace };

    /// <summary>Permissions a role needs to write its logs and publish its metrics, when those are enabled.</summary>
    public static List<Request> Observability(Resolved<bool> metricsEnabled, Resolved<string> logGroup, string region, string account, string partition = "aws")
    {
        var requests = new List<Request>();
        if (logGroup.IsResolved && !string.IsNullOrEmpty(logGroup.Value) && account.Length > 0)
        {
            requests.Add(new Request(Logs, ["logs:CreateLogStream", "logs:PutLogEvents"],
                $"arn:{partition}:logs:{region}:{account}:log-group:{logGroup.Value}:log-stream:{ServiceAdapter.ProbeName}", null));
        }

        if (metricsEnabled.IsResolved && metricsEnabled.Value)
        {
            requests.Add(new Request(Metrics, ["cloudwatch:PutMetricData"], "*", MetricsContext));
        }

        return requests;
    }

    /// <summary>Checks only roles in the account being inspected; other accounts' roles can't be read from here.</summary>
    public static bool InAccount(string roleArn, string account) =>
        ArnParser.Parse(roleArn) is { Service: "iam" } arn && account.Length > 0 && string.Equals(arn.AccountId, account, StringComparison.Ordinal);

    /// <summary>Runs the trust read and the simulations for one role, deduplicating identical calls across roles.</summary>
    public sealed class Runner(IObservabilitySource source, Func<Func<Task>, Task> bounded, CancellationToken ct)
    {
        private readonly Dictionary<string, Task<Signal<RoleTrust>>> _trust = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Task<Signal<IReadOnlyList<PermissionDecision>>>> _simulations = new(StringComparer.Ordinal);

        /// <param name="config">The account configuration for the stack's region, when it could be read.</param>
        public async Task<RoleObservation> CheckAsync(string roleArn, string account, IReadOnlyList<Request> requests, AccountConfig? config = null, string? region = null)
        {
            if (!InAccount(roleArn, account))
            {
                return new RoleObservation(roleArn, false, Signal<RoleTrust>.NoData("role is in another account"), Signal<IReadOnlyList<PermissionCheck>>.NoData());
            }

            var trust = await Trust(roleArn).ConfigureAwait(false);
            var (externalIdMatches, serviceRoleTrusted) = Compare(trust, config, region);
            if (trust.State == SignalState.NotFound || requests.Count == 0)
            {
                return new RoleObservation(roleArn, true, trust, Signal<IReadOnlyList<PermissionCheck>>.NoData(), externalIdMatches, serviceRoleTrusted);
            }

            // One simulation for everything this role needs: IAM's rate limits are low, so calls are kept few.
            var result = await Simulate(roleArn, requests).ConfigureAwait(false);
            if (!result.IsAvailable)
            {
                return new RoleObservation(roleArn, true, trust, result.Cast<IReadOnlyList<PermissionCheck>>(), externalIdMatches, serviceRoleTrusted);
            }

            var checks = new List<PermissionCheck>();
            foreach (var request in requests)
            {
                foreach (var action in request.Actions)
                {
                    var decision = result.Value!.FirstOrDefault(d =>
                        string.Equals(d.Action, action, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(d.Resource, request.Resource, StringComparison.Ordinal));
                    if (decision is not null)
                    {
                        checks.Add(new PermissionCheck(request.Purpose, decision));
                    }
                }
            }

            return new RoleObservation(roleArn, true, trust, Signal<IReadOnlyList<PermissionCheck>>.Of(checks), externalIdMatches, serviceRoleTrusted);
        }

        /// <summary>Compares the trust policy with the account configuration. Null means "not compared".</summary>
        internal static (bool? ExternalIdMatches, bool? ServiceRoleTrusted) Compare(Signal<RoleTrust> trust, AccountConfig? config, string? region)
        {
            if (config is null || trust.Value is not { AllowsAssumeRole: true } t)
            {
                return (null, null);
            }

            bool? externalId = config.ExternalId is { } expected && t.ExternalIds is { Count: > 0 } ids
                ? ids.Contains(expected, StringComparer.Ordinal)
                : null;
            bool? serviceRole = region is not null && config.ServiceRole(region) is { } principal && t.Principals is not null
                ? t.Principals.Contains(principal, StringComparer.Ordinal)
                : null;
            return (externalId, serviceRole);
        }

        private Task<Signal<RoleTrust>> Trust(string roleArn)
        {
            lock (_trust)
            {
                if (!_trust.TryGetValue(roleArn, out var task))
                {
                    _trust[roleArn] = task = Run(() => source.GetRoleTrustAsync(roleArn, ct));
                }

                return task;
            }
        }

        private Task<Signal<IReadOnlyList<PermissionDecision>>> Simulate(string roleArn, IReadOnlyList<Request> requests)
        {
            List<string> actions = [.. requests.SelectMany(r => r.Actions).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
            List<string> resources = [.. requests.Select(r => r.Resource).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
            var context = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in requests.Where(r => r.Context is not null).SelectMany(r => r.Context!))
            {
                context[kv.Key] = kv.Value;
            }

            var key = $"{roleArn}|{string.Join(',', actions)}|{string.Join(',', resources)}|{string.Join(',', context.OrderBy(kv => kv.Key, StringComparer.Ordinal))}";
            lock (_simulations)
            {
                if (!_simulations.TryGetValue(key, out var task))
                {
                    _simulations[key] = task = Run(() => source.SimulateAsync(roleArn, actions, resources, context.Count == 0 ? null : context, ct));
                }

                return task;
            }
        }

        private async Task<T> Run<T>(Func<Task<T>> call)
        {
            T result = default!;
            await bounded(async () => result = await call().ConfigureAwait(false)).ConfigureAwait(false);
            return result;
        }
    }
}
