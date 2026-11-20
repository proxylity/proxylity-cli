using System.Text.Json.Serialization;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation.Adapters;

namespace Proxylity.Cli.Core.Observation;

[JsonConverter(typeof(CamelCaseEnumConverter<Health>))]
public enum Health
{
    Healthy,
    Warning,
    Error,
    Unknown,
    NotConfigured,
    NotAccessible,
}

[JsonConverter(typeof(CamelCaseEnumConverter<Confidence>))]
public enum Confidence
{
    /// <summary>Directly supported by observed configuration or data.</summary>
    Confirmed,

    /// <summary>Supported by evidence but not conclusively established.</summary>
    Likely,

    /// <summary>A plausible explanation that needs further investigation.</summary>
    Possible,

    /// <summary>Not enough information to draw a conclusion.</summary>
    Unknown,
}

/// <param name="Untrusted">True when the value came from log contents, which can include data derived from network traffic.</param>
public sealed record Evidence(string Label, string Value, bool Untrusted = false);

public sealed record Finding(
    string RuleId,
    Health Health,
    Confidence Confidence,
    string Title,
    IReadOnlyList<Evidence> Evidence,
    IReadOnlyList<string> Suggestions);

/// <param name="Purpose">delivery, logs or metrics: what the permission is needed for.</param>
public sealed record PermissionCheck(string Purpose, PermissionDecision Decision);

/// <summary>What was learned about a destination or listener role.</summary>
/// <param name="Checked">False when the role is in another account or could not be identified; nothing was read.</param>
/// <param name="ExternalIdMatches">Whether the trust policy requires the account's current external ID; null when not compared.</param>
/// <param name="ServiceRoleTrusted">Whether the trust policy names the regional Proxylity service role; null when not compared.</param>
public sealed record RoleObservation(
    string RoleArn,
    bool Checked,
    Signal<RoleTrust> Trust,
    Signal<IReadOnlyList<PermissionCheck>> Permissions,
    bool? ExternalIdMatches = null,
    bool? ServiceRoleTrusted = null);

/// <summary>Comparison of a stack with the account configuration in the stack's region. Values are never included.</summary>
/// <param name="Config">Whether the account configuration could be read.</param>
public sealed record AccountCheck(string Region, SignalState Config, string? Detail, bool? ServiceTokenMatches, bool? KeyMatches);

/// <summary>A gateway log line, parsed and sanitized. <see cref="Message"/> is untrusted text.</summary>
public sealed record LogSample(DateTimeOffset Timestamp, string Level, int Count, string Message, bool Untrusted = true);

public sealed record LogObservation(string LogGroup, IReadOnlyList<string> Regions, Signal<IReadOnlyList<LogSample>> Events, bool Truncated);

/// <param name="Description">Null when no adapter supports the target service.</param>
public sealed record TargetObservation(
    DestinationTarget Target,
    Signal<TargetDescription>? Description,
    IReadOnlyDictionary<string, Signal<double>> Metrics,
    LogObservation? ErrorLogs,
    IReadOnlyList<Finding> Findings);

public sealed record DestinationObservation(
    DestinationInfo Destination,
    IReadOnlyList<string> MetricRegions,
    IReadOnlyDictionary<string, Signal<double>> Metrics,
    LogObservation? Logs,
    IReadOnlyList<TargetObservation> Targets,
    IReadOnlyList<Finding> Findings,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, Signal<double>>>? MetricsByRegion = null,
    RoleObservation? Role = null);

public sealed record ListenerObservation(
    ListenerInfo Listener,
    IReadOnlyList<string> MetricRegions,
    IReadOnlyDictionary<string, Signal<double>> Metrics,
    LogObservation? Logs,
    IReadOnlyList<DestinationObservation> Destinations,
    IReadOnlyList<Finding> Findings,
    RoleObservation? Role = null,
    AccountCheck? Account = null);

public sealed record ObservationReport(
    TimeWindow Window,
    IReadOnlyList<ListenerObservation> Listeners,
    IReadOnlyList<Note> Notes);

/// <summary>Metric keys used in observations (stable; they appear in JSON output).</summary>
public static class MetricKeys
{
    public const string Ingress = "proxylity.ingressPackets";
    public const string IngressBytes = "proxylity.ingressBytes";
    public const string Filtered = "proxylity.filteredPackets";
    public const string FilteredBytes = "proxylity.filteredBytes";
    public const string Egress = "proxylity.egressPackets";
    public const string Errors = "proxylity.errors";

    public const string LambdaInvocations = "lambda.invocations";
    public const string LambdaErrors = "lambda.errors";
    public const string LambdaThrottles = "lambda.throttles";
    public const string LambdaDurationMax = "lambda.durationMaximum";
    public const string LambdaDurationAvg = "lambda.durationAverage";
    public const string LambdaConcurrencyMax = "lambda.concurrentExecutionsMaximum";
}
