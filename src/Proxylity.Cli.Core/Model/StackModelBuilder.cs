using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Core.Model;

/// <summary>Everything read about one stack, input to <see cref="StackModelBuilder"/>.</summary>
public sealed record StackData(
    StackRef Stack,
    IReadOnlyList<DeployedResource> Resources,
    IReadOnlyDictionary<string, string> Parameters,
    TNode Template,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>? NestedStackOutputs = null);

public sealed record StackModel(
    IReadOnlyList<ListenerInfo> Listeners,
    IReadOnlyList<DestinationAttachment> Attachments,
    IReadOnlyList<PacketSourceInfo> PacketSources,
    IReadOnlyList<Note> Notes);

/// <summary>
/// Builds the Proxylity model for one stack from its (processed) template and deployed resources.
/// Parsing is deliberately tolerant: unknown properties are ignored and unexpected shapes are reported
/// as notes or unresolved values rather than failing.
/// </summary>
public static class StackModelBuilder
{
    public const string ListenerType = "Custom::ProxylityUdpGatewayListener";
    public const string DestinationArnType = "Custom::ProxylityUdpGatewayDestinationArn";
    public const string PacketSourceType = "Custom::ProxylityUdpGatewayPacketSource";
    public const string TypePrefix = "Custom::ProxylityUdpGateway";

    /// <summary>
    /// Properties that hold secrets or service credentials. They are removed from the template before
    /// any resolution happens and are never read, stored, or displayed.
    /// </summary>
    private static readonly HashSet<string> NeverReadKeys = new(StringComparer.Ordinal)
    {
        "ApiKey",
        "ServiceToken",
        "Psks",
        "ServerSecret",
        "UnknownPeerPreSharedKey",
        "SharedSecret",
        "WebRtcSignalingToken",
        "WebRtcSignalingUrl",
    };

    public static bool IsProxylityType(string type) => type.StartsWith(TypePrefix, StringComparison.Ordinal);

    public static StackModel Build(StackData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        var context = new ResolutionContext
        {
            Region = data.Stack.Region,
            AccountId = data.Stack.AccountId,
            StackName = data.Stack.Name,
            StackId = data.Stack.Id,
            Parameters = data.Parameters,
            Resources = data.Resources.ToDictionary(r => r.LogicalId, StringComparer.Ordinal),
            Mappings = data.Template.Get("Mappings"),
            Conditions = data.Template.Get("Conditions"),
            NestedStackOutputs = data.NestedStackOutputs ?? new Dictionary<string, IReadOnlyDictionary<string, string>>(),
        };
        var resolver = new IntrinsicResolver(context);

        var listeners = new List<ListenerInfo>();
        var attachments = new List<DestinationAttachment>();
        var sources = new List<PacketSourceInfo>();
        var notes = new List<Note>();

        var templateResources = data.Template.Get("Resources");
        foreach (var deployed in data.Resources.Where(r => IsProxylityType(r.Type)))
        {
            var definition = templateResources?.Get(deployed.LogicalId);
            if (definition is null)
            {
                notes.Add(new Note("warning", $"{deployed.LogicalId} is deployed but not found in the template.", data.Stack.Name));
                continue;
            }

            var raw = definition.Get("Properties") ?? TNode.Map([]);
            var properties = resolver.Resolve(RemoveNeverReadKeys(raw));
            switch (deployed.Type)
            {
                case ListenerType:
                    // Only one-way fingerprints of these are kept, to compare with the account configuration.
                    listeners.Add(ReadListener(data.Stack, deployed, properties) with
                    {
                        ServiceTokenFingerprint = FingerprintOf(resolver, raw.Get("ServiceToken")),
                        KeyFingerprint = FingerprintOf(resolver, raw.Get("ApiKey")),
                        TemplateIssues = TemplateRules.Check(properties),
                    });
                    break;
                case DestinationArnType:
                    attachments.Add(ReadAttachment(data.Stack, deployed, properties));
                    break;
                case PacketSourceType:
                    sources.Add(ReadPacketSource(data.Stack, deployed, properties));
                    break;
                default:
                    notes.Add(new Note("info", $"{deployed.LogicalId} has the unrecognized Proxylity type {deployed.Type}; it is ignored.", data.Stack.Name));
                    break;
            }
        }

        return new StackModel(listeners, attachments, sources, notes);
    }

    private static Resolved<string> FingerprintOf(IntrinsicResolver resolver, TNode? node)
    {
        if (node is null || node.Kind == NodeKind.Null)
        {
            return Resolved<string>.Absent;
        }

        var value = resolver.Resolve(node);
        return value.Kind == NodeKind.String && !string.IsNullOrEmpty(value.Text)
            ? Resolved<string>.Ok(Observation.Fingerprint.Of(value.Text))
            : Resolved<string>.Fail(value.Kind == NodeKind.Unresolved ? value.Text ?? "unresolved" : "not a string");
    }

    private static TNode RemoveNeverReadKeys(TNode node) => node.Kind switch
    {
        NodeKind.Map => TNode.Map(node.Entries
            .Where(e => !NeverReadKeys.Contains(e.Key))
            .Select(e => new KeyValuePair<string, TNode>(e.Key, RemoveNeverReadKeys(e.Value)))),
        NodeKind.Seq => TNode.Seq(node.Items.Select(RemoveNeverReadKeys)),
        _ => node,
    };

    private static ListenerInfo ReadListener(StackRef stack, DeployedResource deployed, TNode p)
    {
        var physical = deployed.PhysicalId;
        // A failed creation can leave a placeholder that looks like a log path rather than a listener name.
        var placeholder = string.IsNullOrEmpty(physical) || physical.Contains("$LATEST", StringComparison.Ordinal);

        var protocol = p.Get("Protocols") is { Kind: NodeKind.Seq } protocols && protocols.Items.Count > 0
            ? ReadString(protocols.Items[0])
            : ReadString(p.Get("Protocols"));

        return new ListenerInfo(
            stack,
            deployed.LogicalId,
            placeholder ? null : physical,
            placeholder,
            protocol,
            ReadBool(p.Get("MetricsEnabled")),
            ReadString(p.Get("LogGroupName")),
            ReadRole(p.Get("Role")),
            ReadClientRestrictions(p.Get("ClientRestrictions")),
            ReadDestinations(stack, deployed.LogicalId, p.Get("Destinations")));
    }

    private static List<DestinationInfo> ReadDestinations(StackRef stack, string listenerLogicalId, TNode? node)
    {
        var result = new List<DestinationInfo>();
        if (node is null || node.Kind != NodeKind.Seq)
        {
            return result;
        }

        var inlineIndex = 0;
        foreach (var item in node.Items)
        {
            if (item.Kind == NodeKind.Map)
            {
                result.Add(ReadDestination(stack, listenerLogicalId, inlineIndex, item));
                inlineIndex++;
            }
            else if (item.AsString() is { } referenced)
            {
                result.Add(new DestinationInfo(
                    referenced,
                    NameSource.Declared,
                    true,
                    Resolved<bool>.Absent,
                    Resolved<string>.Absent,
                    null,
                    [],
                    false));
            }
        }

        return result;
    }

    private static DestinationInfo ReadDestination(StackRef stack, string listenerLogicalId, int index, TNode d)
    {
        var declared = ReadString(d.Get("Name"));
        string name;
        NameSource source;
        if (declared.IsResolved && !string.IsNullOrEmpty(declared.Value))
        {
            name = declared.Value;
            source = NameSource.Declared;
        }
        else
        {
            // Generated names are deterministic for an unchanged template.
            name = $"dstn-{stack.Name}-{listenerLogicalId}-{index}";
            source = NameSource.Derived;
        }

        return new DestinationInfo(
            name,
            source,
            false,
            ReadBool(d.Get("MetricsEnabled")),
            ReadString(d.Get("LogGroupName")),
            ReadRole(d.Get("Role")),
            ReadTargets(d.Get("DestinationArn")),
            d.Has("FilterExpression"),
            ReadArguments(d.Get("Arguments")));
    }

    /// <summary>
    /// Documented service-specific destination settings that diagnostics use. Only these keys are read;
    /// values that may carry application data (for example RunHookExtraData) are never read. Lists are
    /// recorded as a count; identifiers that only matter by presence are recorded as "set".
    /// </summary>
    private static readonly Dictionary<string, ArgumentKind> KnownArguments = new(StringComparer.Ordinal)
    {
        ["ExecutionRoleArn"] = ArgumentKind.Value,
        ["RuntimeLogGroupName"] = ArgumentKind.Value,
        ["IdleDurationSeconds"] = ArgumentKind.Value,
        ["UseTenantIdForLogStreamName"] = ArgumentKind.Value,
        ["UseAsyncInvoke"] = ArgumentKind.Value,
        ["UseResponseStreaming"] = ArgumentKind.Value,
        ["TenantId"] = ArgumentKind.Presence,
        ["TenantIdExpression"] = ArgumentKind.Presence,
        ["EgressNetworkConnectorArns"] = ArgumentKind.Count,
    };

    private enum ArgumentKind
    {
        Value,
        Presence,
        Count,
    }

    private static Dictionary<string, string>? ReadArguments(TNode? node)
    {
        if (node is null || node.Kind != NodeKind.Map)
        {
            return null;
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in node.Entries)
        {
            if (!KnownArguments.TryGetValue(entry.Key, out var kind))
            {
                continue;
            }

            switch (kind)
            {
                case ArgumentKind.Presence:
                    result[entry.Key] = "set";
                    break;
                case ArgumentKind.Count:
                    result[entry.Key] = entry.Value.Kind == NodeKind.Seq
                        ? entry.Value.Items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)
                        : "1";
                    break;
                default:
                    var value = ReadString(entry.Value);
                    result[entry.Key] = value.IsResolved ? value.Value! : "(unresolved)";
                    break;
            }
        }

        return result.Count == 0 ? null : result;
    }

    private static List<DestinationTarget> ReadTargets(TNode? node)
    {
        var targets = new List<DestinationTarget>();
        if (node is null || node.Kind == NodeKind.Null)
        {
            return targets;
        }

        if (node.Kind == NodeKind.Map)
        {
            foreach (var entry in node.Entries)
            {
                targets.Add(MakeTarget(entry.Key, ReadString(entry.Value)));
            }

            return targets;
        }

        targets.Add(MakeTarget("*", ReadString(node)));
        return targets;
    }

    private static DestinationTarget MakeTarget(string regionKey, Resolved<string> arn)
    {
        var parsed = arn.IsResolved ? ArnParser.Parse(arn.Value) : null;
        var service = parsed is null ? DestinationService.Unknown : ArnParser.ServiceOf(parsed);
        return new DestinationTarget(
            regionKey,
            arn,
            service,
            parsed is { Region.Length: > 0 } ? parsed.Region : null,
            parsed is null ? null : ArnParser.ResourceNameOf(parsed, service));
    }

    private static DestinationAttachment ReadAttachment(StackRef stack, DeployedResource deployed, TNode p)
    {
        var arn = ReadString(p.Get("Arn"));
        var parsed = arn.IsResolved ? ArnParser.Parse(arn.Value) : null;
        return new DestinationAttachment(
            stack,
            deployed.LogicalId,
            ReadString(p.Get("Destination")),
            ReadString(p.Get("IngressRegionKey")),
            arn,
            parsed is null ? DestinationService.Unknown : ArnParser.ServiceOf(parsed));
    }

    private static PacketSourceInfo ReadPacketSource(StackRef stack, DeployedResource deployed, TNode p) =>
        new(
            stack,
            deployed.LogicalId,
            deployed.PhysicalId,
            ReadString(p.Get("ListenerName")),
            ReadString(p.Get("SnsTopicSource")?.Get("TopicArn")));

    private static RoleInfo? ReadRole(TNode? node)
    {
        if (node is null || node.Kind == NodeKind.Null)
        {
            return null;
        }

        if (node.Kind == NodeKind.Unresolved)
        {
            return new RoleInfo(Resolved<string>.Fail(node.Text ?? "unresolved"), false);
        }

        if (node.Kind != NodeKind.Map)
        {
            return new RoleInfo(Resolved<string>.Fail("Role is not an object"), false);
        }

        // The role ARN key is "Arn". "RoleArn" appears in some documentation examples; it is reported, not honored.
        return new RoleInfo(ReadString(node.Get("Arn")), node.Has("RoleArn"));
    }

    private static ClientRestrictionsInfo ReadClientRestrictions(TNode? node)
    {
        switch (node?.Kind)
        {
            case null:
            case NodeKind.Null:
                return new ClientRestrictionsInfo(ClientRestrictionsForm.Absent, 0, 0);
            case NodeKind.Unresolved:
                return new ClientRestrictionsInfo(ClientRestrictionsForm.Unresolved, 0, 0);
            case NodeKind.Seq:
                return new ClientRestrictionsInfo(ClientRestrictionsForm.List, 0, 0);
            case NodeKind.Map:
                var networks = Count(node.Get("Networks"));
                var domains = Count(node.Get("Domains"));
                return new ClientRestrictionsInfo(
                    networks + domains == 0 ? ClientRestrictionsForm.Empty : ClientRestrictionsForm.Object,
                    networks,
                    domains);
            default:
                return new ClientRestrictionsInfo(ClientRestrictionsForm.Unresolved, 0, 0);
        }

        static int Count(TNode? list) => list is { Kind: NodeKind.Seq } ? list.Items.Count : 0;
    }

    private static Resolved<string> ReadString(TNode? node) => node switch
    {
        null => Resolved<string>.Absent,
        { Kind: NodeKind.Null } => Resolved<string>.Absent,
        { Kind: NodeKind.Unresolved } => Resolved<string>.Fail(node.Text ?? "unresolved"),
        { IsScalar: true } => Resolved<string>.Ok(node.Text ?? string.Empty),
        _ => Resolved<string>.Fail("value is not a string"),
    };

    private static Resolved<bool> ReadBool(TNode? node)
    {
        if (node is null || node.Kind == NodeKind.Null)
        {
            return Resolved<bool>.Absent;
        }

        if (node.Kind == NodeKind.Unresolved)
        {
            return Resolved<bool>.Fail(node.Text ?? "unresolved");
        }

        return node.AsBool() is { } b ? Resolved<bool>.Ok(b) : Resolved<bool>.Fail("value is not a boolean");
    }
}
