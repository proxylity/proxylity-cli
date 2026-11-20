using System.Text.Json;
using System.Text.Json.Serialization;

namespace Proxylity.Cli.Core.Model;

/// <summary>Serializes enums as camelCase strings using the AoT-safe generic converter.</summary>
public sealed class CamelCaseEnumConverter<T>() : JsonStringEnumConverter<T>(JsonNamingPolicy.CamelCase)
    where T : struct, Enum;

[JsonConverter(typeof(CamelCaseEnumConverter<ValueState>))]
public enum ValueState
{
    /// <summary>The property is not present in the template.</summary>
    Absent,

    /// <summary>The value was determined.</summary>
    Resolved,

    /// <summary>The property is present but its value could not be determined; see the reason.</summary>
    Unresolved,
}

/// <summary>A template value with an explicit state, so "unknown" is never confused with "empty".</summary>
public sealed record Resolved<T>(ValueState State, T? Value, string? Reason)
{
    public static Resolved<T> Absent { get; } = new(ValueState.Absent, default, null);

    public static Resolved<T> Ok(T value) => new(ValueState.Resolved, value, null);

    public static Resolved<T> Fail(string reason) => new(ValueState.Unresolved, default, reason);

    public bool IsResolved => State == ValueState.Resolved;
}

[JsonConverter(typeof(CamelCaseEnumConverter<NameSource>))]
public enum NameSource
{
    /// <summary>Declared in the template.</summary>
    Declared,

    /// <summary>Derived from the stack name, logical ID and position. Less certain than a declared name.</summary>
    Derived,
}

[JsonConverter(typeof(CamelCaseEnumConverter<DestinationService>))]
public enum DestinationService
{
    Unknown,
    Lambda,
    LambdaMicrovm,
    StepFunctions,
    EventBridge,
    Sqs,
    Sns,
    DynamoDb,
    S3,
    Firehose,
    Kinesis,
    CloudWatchLogs,
    ApiGateway,
    IotData,
    LocationTracker,
}

[JsonConverter(typeof(CamelCaseEnumConverter<ClientRestrictionsForm>))]
public enum ClientRestrictionsForm
{
    /// <summary>No ClientRestrictions property: all traffic is blocked.</summary>
    Absent,

    /// <summary>An object with Networks and/or Domains entries.</summary>
    Object,

    /// <summary>An object with no entries: all traffic is blocked.</summary>
    Empty,

    /// <summary>A list. The service expects an object, so this form cannot have deployed as written.</summary>
    List,

    Unresolved,
}

public sealed record StackRef(string Name, string Id, string Region, string AccountId, string Status);

public sealed record ParsedArn(string Partition, string Service, string Region, string AccountId, string Resource);

/// <param name="AttachedFrom">Set when the ARN comes from a DestinationArn resource: "stack/LogicalId".</param>
/// <param name="RegionFromIngress">The ARN uses "*" as its region (it resolves to the ingress region); it was inspected in ArnRegion.</param>
public sealed record DestinationTarget(
    string IngressRegionKey,
    Resolved<string> Arn,
    DestinationService Service,
    string? ArnRegion,
    string? ResourceName,
    string? AttachedFrom = null,
    bool RegionFromIngress = false);

public sealed record RoleInfo(Resolved<string> Arn, bool UsesRoleArnKey);

public sealed record ClientRestrictionsInfo(ClientRestrictionsForm Form, int NetworkCount, int DomainCount);

public sealed record DestinationInfo(
    string? Name,
    NameSource NameSource,
    bool IsReferenceByName,
    Resolved<bool> MetricsEnabled,
    Resolved<string> LogGroupName,
    RoleInfo? Role,
    IReadOnlyList<DestinationTarget> Targets,
    bool HasFilterExpression,
    IReadOnlyDictionary<string, string>? Arguments = null);

public sealed record ListenerInfo(
    StackRef Stack,
    string LogicalId,
    string? Name,
    bool NameIsPlaceholder,
    Resolved<string> Protocol,
    Resolved<bool> MetricsEnabled,
    Resolved<string> LogGroupName,
    RoleInfo? Role,
    ClientRestrictionsInfo ClientRestrictions,
    IReadOnlyList<DestinationInfo> Destinations,
    Resolved<string>? ServiceTokenFingerprint = null,
    Resolved<string>? KeyFingerprint = null,
    IReadOnlyList<TemplateIssue>? TemplateIssues = null);

/// <param name="Matched">True when the attachment was merged into a discovered destination.</param>
public sealed record DestinationAttachment(
    StackRef Stack,
    string LogicalId,
    Resolved<string> Destination,
    Resolved<string> IngressRegionKey,
    Resolved<string> Arn,
    DestinationService Service,
    bool Matched = false);

public sealed record PacketSourceInfo(
    StackRef Stack,
    string LogicalId,
    string? SourceId,
    Resolved<string> ListenerName,
    Resolved<string> TopicArn);

public sealed record Note(string Severity, string Message, string? Stack);

public sealed record DeploymentSnapshot(
    IReadOnlyList<string> Regions,
    IReadOnlyList<StackRef> Stacks,
    IReadOnlyList<ListenerInfo> Listeners,
    IReadOnlyList<DestinationAttachment> DestinationAttachments,
    IReadOnlyList<PacketSourceInfo> PacketSources,
    IReadOnlyList<Note> Notes,
    int StacksFromCache = 0);
