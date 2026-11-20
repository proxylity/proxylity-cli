using System.Text.Json.Serialization;
using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli.Core.Observation;

/// <summary>Why a value is or is not available. "No data" is never treated as "zero" or "healthy".</summary>
[JsonConverter(typeof(CamelCaseEnumConverter<SignalState>))]
public enum SignalState
{
    /// <summary>Data was returned (it may be zero).</summary>
    Available,

    /// <summary>The query succeeded but returned nothing for the window.</summary>
    NoData,

    /// <summary>The resource is not set up to produce this signal (for example metrics are off).</summary>
    NotConfigured,

    /// <summary>The current identity is not allowed to read it.</summary>
    NotAccessible,

    /// <summary>The resource (function, log group, ...) does not exist where it was expected.</summary>
    NotFound,

    /// <summary>Another error occurred while reading it.</summary>
    Failed,
}

public sealed record Signal<T>(SignalState State, T? Value, string? Detail = null, string? DeniedAction = null)
{
    public bool IsAvailable => State == SignalState.Available;

    public static Signal<T> Of(T value) => new(SignalState.Available, value);

    public static Signal<T> NoData(string? detail = null) => new(SignalState.NoData, default, detail);

    public static Signal<T> NotConfigured(string detail) => new(SignalState.NotConfigured, default, detail);

    public static Signal<T> NotAccessible(string action) => new(SignalState.NotAccessible, default, $"not permitted: {action}", action);

    public static Signal<T> NotFound(string detail) => new(SignalState.NotFound, default, detail);

    public static Signal<T> Failed(string detail) => new(SignalState.Failed, default, detail);

    public Signal<TOther> Cast<TOther>() => new(State, default, Detail, DeniedAction);
}

public sealed record TimeWindow(DateTimeOffset Start, DateTimeOffset End)
{
    public TimeSpan Length => End - Start;
}

/// <summary>A CloudWatch metric statistic to read over the whole window.</summary>
public sealed record MetricQuery(
    string Id,
    string Namespace,
    string MetricName,
    IReadOnlyList<KeyValuePair<string, string>> Dimensions,
    string Statistic);

public sealed record LogEvent(DateTimeOffset Timestamp, string Message);

public sealed record LogQueryResult(IReadOnlyList<LogEvent> Events, bool Truncated);

public sealed record FunctionInfo(
    string Name,
    string? Runtime,
    int? MemoryMb,
    int? TimeoutSeconds,
    string? State,
    string? StateReason,
    string? LastUpdateStatus,
    int? ReservedConcurrency,
    string LogGroup);

/// <summary>The read-only CloudWatch, CloudWatch Logs and Lambda operations used for observation.</summary>
public interface IObservabilitySource
{
    /// <summary>Reads all queries for one region. Results are keyed by <see cref="MetricQuery.Id"/>.</summary>
    Task<IReadOnlyDictionary<string, Signal<double>>> GetMetricsAsync(
        string region, IReadOnlyList<MetricQuery> queries, TimeWindow window, CancellationToken cancellationToken);

    /// <summary>Returns the most recent matching events in the window (up to <paramref name="limit"/>), oldest first.</summary>
    Task<Signal<LogQueryResult>> GetLogEventsAsync(
        string region, string logGroup, TimeWindow window, string? filterPattern, int limit, CancellationToken cancellationToken);

    Task<Signal<FunctionInfo>> GetFunctionAsync(string functionArn, CancellationToken cancellationToken);

    /// <summary>
    /// Top-level scalar properties of a resource, read through the AWS Cloud Control API using its
    /// CloudFormation type name. Used for services without dedicated SDK read operations.
    /// </summary>
    Task<Signal<IReadOnlyDictionary<string, string>>> GetResourcePropertiesAsync(
        string region, string typeName, string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the account configuration object Proxylity provides for the account in a region
    /// (s3://proxylity-config-REGION/ACCOUNT/customer-config.json). Optional: failures only limit comparisons.
    /// </summary>
    Task<Signal<AccountConfig>> GetAccountConfigAsync(string region, string account, CancellationToken cancellationToken);

    /// <summary>Reads an IAM role's trust policy. NotFound when the role does not exist.</summary>
    Task<Signal<RoleTrust>> GetRoleTrustAsync(string roleArn, CancellationToken cancellationToken);

    /// <summary>
    /// Asks IAM's policy simulator whether the role's identity-based policies allow the actions on the resource.
    /// Nothing is assumed or invoked.
    /// </summary>
    /// <remarks>Every action is evaluated against every resource; callers keep the pairs they asked about.</remarks>
    Task<Signal<IReadOnlyList<PermissionDecision>>> SimulateAsync(
        string roleArn, IReadOnlyList<string> actions, IReadOnlyList<string> resources,
        IReadOnlyDictionary<string, string>? context, CancellationToken cancellationToken);
}

/// <param name="AllowsAssumeRole">Some statement allows sts:AssumeRole to an AWS principal.</param>
/// <param name="RequiresExternalId">Every such statement has a condition on sts:ExternalId.</param>
/// <param name="Principals">AWS principals of the allowing statements; used for comparison only, never output.</param>
/// <param name="ExternalIds">sts:ExternalId values required by those statements; used for comparison only, never output.</param>
public sealed record RoleTrust(
    bool AllowsAssumeRole,
    bool RequiresExternalId,
    [property: System.Text.Json.Serialization.JsonIgnore] IReadOnlyList<string>? Principals = null,
    [property: System.Text.Json.Serialization.JsonIgnore] IReadOnlyList<string>? ExternalIds = null)
{
    public override string ToString() => $"RoleTrust {{ AllowsAssumeRole = {AllowsAssumeRole}, RequiresExternalId = {RequiresExternalId} }}";
}

/// <param name="Decision">allowed, implicitDeny or explicitDeny (IAM's evaluation decision).</param>
public sealed record PermissionDecision(string Action, string Resource, string Decision)
{
    public bool Allowed => string.Equals(Decision, "allowed", StringComparison.OrdinalIgnoreCase);

    public bool ExplicitlyDenied => string.Equals(Decision, "explicitDeny", StringComparison.OrdinalIgnoreCase);
}
