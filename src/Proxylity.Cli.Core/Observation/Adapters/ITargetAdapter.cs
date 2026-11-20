using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli.Core.Observation.Adapters;

/// <summary>What an adapter learned about a target resource. Properties are display-ready strings with stable keys.</summary>
public sealed record TargetDescription(string Name, IReadOnlyDictionary<string, string> Properties);

/// <summary>A CloudWatch metric an adapter wants for a target, read in the target's region over the window.</summary>
public sealed record TargetMetric(string Key, string Namespace, string MetricName, IReadOnlyList<KeyValuePair<string, string>> Dimensions, string Statistic);

/// <summary>Actions the destination role must be allowed to perform on a resource (from the public destination docs).</summary>
public sealed record PermissionRequirement(IReadOnlyList<string> Actions, string Resource);

/// <summary>A log group an adapter wants scanned for error-like lines.</summary>
public sealed record TargetLogPlan(string LogGroup, string? FilterPattern, int Limit);

/// <summary>
/// Service-specific knowledge for one kind of destination target. The collector and diagnoser stay generic;
/// adding a service means adding an adapter and registering it in <see cref="TargetAdapters"/>.
/// </summary>
public interface ITargetAdapter
{
    DestinationService Service { get; }

    /// <summary>Human name of the resource kind, for example "Lambda function".</summary>
    string ResourceKind { get; }

    /// <summary>Describes the target (existence, state, key configuration). Must not throw for AWS errors.</summary>
    Task<Signal<TargetDescription>> DescribeAsync(DestinationTarget target, DestinationInfo destination, IObservabilitySource source, CancellationToken cancellationToken);

    IReadOnlyList<TargetMetric> Metrics(DestinationTarget target, TargetDescription description);

    TargetLogPlan? ErrorLogs(DestinationTarget target, DestinationInfo destination, TargetDescription description);

    /// <summary>What the destination role needs for delivery. The description is null when the target could not be described.</summary>
    IReadOnlyList<PermissionRequirement> Permissions(DestinationTarget target, DestinationInfo destination, TargetDescription? description);

    /// <summary>Findings for a target whose description is available.</summary>
    IEnumerable<Finding> Diagnose(TargetObservation o, DestinationObservation destination);
}

public static class TargetAdapters
{
    /// <summary>Registered adapters. An explicit list: no reflection or assembly scanning (trimming/AoT friendly).</summary>
    public static IReadOnlyList<ITargetAdapter> All { get; } =
        [new LambdaAdapter(), new MicrovmAdapter(), .. ServiceAdapter.Specs.Select(s => new ServiceAdapter(s))];

    public static ITargetAdapter? For(DestinationService service)
    {
        foreach (var a in All)
        {
            if (a.Service == service)
            {
                return a;
            }
        }

        return null;
    }
}

/// <summary>Shared helpers for adapters.</summary>
internal static class AdapterText
{
    /// <summary>Log lines that usually indicate a failure, across common runtimes.</summary>
    public const string ErrorPattern = "?ERROR ?Error ?error ?Exception ?\"Task timed out\" ?\"Runtime exited\" ?panic ?Traceback";

    public static string Count(double v) => v.ToString("N0", System.Globalization.CultureInfo.InvariantCulture);

    public static string Units(double v) => v.ToString("N0", System.Globalization.CultureInfo.InvariantCulture) + " packet units";

    public static string Percent(double v) =>
        (v * 100).ToString(v < 0.1 ? "0.#" : "0", System.Globalization.CultureInfo.InvariantCulture) + "%";

    public static bool Has(Signal<double>? s) => s?.IsAvailable == true;

    public static double ValueOr0(Signal<double>? s) => s?.IsAvailable == true ? s.Value : 0;

    public static Finding NotAccessible(string id, string what, string action) =>
        new(id, Health.NotAccessible, Confidence.Confirmed, $"{what} can't be read with the current AWS identity",
            [new("denied action", action)],
            [$"Allow {action} for the identity running the CLI."]);

    /// <summary>Accepted packets for this target: with a region map each packet goes to one regional target.</summary>
    public static Signal<double>? AcceptedFor(DestinationTarget t, DestinationObservation destination) =>
        destination.Targets.Count > 1 && t.ArnRegion is { } r
            ? destination.MetricsByRegion?.GetValueOrDefault(r)?.GetValueOrDefault(MetricKeys.Ingress)
            : destination.Metrics.GetValueOrDefault(MetricKeys.Ingress);

    public static Signal<double>? RepliesFor(DestinationTarget t, DestinationObservation destination) =>
        destination.Targets.Count > 1 && t.ArnRegion is { } r
            ? destination.MetricsByRegion?.GetValueOrDefault(r)?.GetValueOrDefault(MetricKeys.Egress)
            : destination.Metrics.GetValueOrDefault(MetricKeys.Egress);

    /// <summary>Error-like lines found in a target's own logs, shown as untrusted evidence.</summary>
    public static Finding? ErrorLines(string id, TargetObservation o, string what)
    {
        if (o.ErrorLogs?.Events is not { IsAvailable: true } lines || lines.Value!.Count == 0)
        {
            return null;
        }

        return new Finding(id, Health.Warning, Confidence.Possible,
            $"Recent {what} log lines that look like errors",
            [.. lines.Value!.TakeLast(3).Select(l => new Evidence(l.Timestamp.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture), l.Message, Untrusted: true))],
            [$"Open log group {o.ErrorLogs.LogGroup} for full context."]);
    }
}
