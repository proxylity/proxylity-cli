using System.Globalization;
using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli;

/// <summary>Renders discovery results for people. Colors are decoration only: every state also has a symbol or word.</summary>
internal sealed class TextRenderer(TextWriter output, bool color)
{
    public void RenderList(DeploymentSnapshot snapshot)
    {
        WriteHeader(snapshot);
        if (snapshot.Listeners.Count == 0)
        {
            WriteNoListeners(snapshot);
            WriteNotes(snapshot);
            return;
        }

        var rows = new List<string[]>();
        foreach (var l in snapshot.Listeners)
        {
            var destinations = l.Destinations.Select(DescribeDestinationShort).ToList();
            rows.Add([l.Stack.Name, l.Name ?? $"{l.LogicalId} (no name)", l.Protocol.IsResolved ? l.Protocol.Value! : "?", destinations.Count > 0 ? destinations[0] : "(none)"]);
            foreach (var extra in destinations.Skip(1))
            {
                rows.Add([string.Empty, string.Empty, string.Empty, extra]);
            }
        }

        var headers = new[] { "STACK", "LISTENER", "PROTOCOL", "DESTINATIONS" };
        var widths = headers.Select((h, i) => Math.Max(h.Length, rows.Max(r => r[i].Length))).ToArray();
        output.WriteLine(Dim(string.Join("  ", headers.Select((h, i) => i == headers.Length - 1 ? h : h.PadRight(widths[i])))));
        foreach (var row in rows)
        {
            output.WriteLine(string.Join("  ", row.Select((cell, i) => i == row.Length - 1 ? cell : cell.PadRight(widths[i]))).TrimEnd());
        }

        WriteAttachmentsAndSources(snapshot);
        WriteNotes(snapshot);
    }

    public void RenderAccess(AccessReport report)
    {
        output.WriteLine($"{Bold("Access check")}  {Dim($"region {report.Region}; read-only probes, nothing is changed")}");
        output.WriteLine();
        var width = report.Probes.Max(p => p.Action.Length);
        foreach (var p in report.Probes)
        {
            var state = p.State switch
            {
                AccessState.Allowed => "allowed",
                AccessState.Denied => "DENIED",
                AccessState.Inconclusive => "inconclusive",
                _ => "not tested",
            };
            var detail = p.Detail is null ? string.Empty : $" ({p.Detail})";
            output.WriteLine($"  {p.Action.PadRight(width)}  {(p.State == AccessState.Denied ? Yellow(state.PadRight(12)) : state.PadRight(12))}  {Dim(p.Used + detail)}");
        }

        output.WriteLine();
        output.WriteLine(Dim("Allowed includes resources that do not exist: the call was authorized. Cloud Control also needs the read permission of the resource type."));
    }

    public void RenderInspect(DeploymentSnapshot snapshot)
    {
        WriteHeader(snapshot);
        if (snapshot.Listeners.Count == 0)
        {
            WriteNoListeners(snapshot);
        }

        foreach (var l in snapshot.Listeners)
        {
            output.WriteLine();
            output.WriteLine($"{Bold("Listener")} {l.Name ?? l.LogicalId}  {Dim($"({(l.Protocol.IsResolved ? l.Protocol.Value : "protocol unknown")})")}");
            Field("stack", $"{l.Stack.Name} ({l.Stack.Status}), as declared in the stack template");
            if (l.NameIsPlaceholder)
            {
                Warn("The listener has no usable name yet (creation may have failed). Check the stack events.");
            }

            Field("metrics", OnOff(l.MetricsEnabled));
            Field("logs", Show(l.LogGroupName, "off"));
            Field("role", l.Role is null ? "none" : Show(l.Role.Arn, "not set"));
            Field("clients", DescribeClients(l.ClientRestrictions));

            if (l.ClientRestrictions.Form is ClientRestrictionsForm.Absent or ClientRestrictionsForm.Empty)
            {
                Warn("No client restrictions: all traffic is blocked.");
            }

            if (l.ClientRestrictions.Form == ClientRestrictionsForm.List)
            {
                Warn("ClientRestrictions is written as a list; the service expects an object with Networks and Domains, so this cannot have deployed as written.");
            }

            if (l.Role?.UsesRoleArnKey == true)
            {
                Warn("Role uses 'RoleArn'; the property is 'Arn', so this listener has no role configured.");
            }

            foreach (var issue in l.TemplateIssues ?? [])
            {
                Warn($"{issue.Message} ({issue.Path}). The next update of this stack will be rejected.");
            }

            if ((l.MetricsEnabled.Value || l.LogGroupName.IsResolved) && (l.Role is null || !l.Role.Arn.IsResolved))
            {
                Warn("Metrics or logging is enabled but no listener Role could be determined.");
            }

            output.WriteLine($"  {Dim("destinations")}");
            if (l.Destinations.Count == 0)
            {
                output.WriteLine("    (none)");
            }

            foreach (var d in l.Destinations)
            {
                RenderDestination(d);
            }
        }

        WriteAttachmentsAndSources(snapshot);
        WriteNotes(snapshot);
    }

    private void RenderDestination(DestinationInfo d)
    {
        var label = d.NameSource == NameSource.Derived ? " (name derived from the template)" : string.Empty;
        output.WriteLine($"    {Bold(d.Name ?? "(unnamed)")}{Dim(label)}");
        if (d.IsReferenceByName)
        {
            output.WriteLine("      reference to a destination defined elsewhere (not validated here)");
            return;
        }

        foreach (var t in d.Targets)
        {
            var where = t.IngressRegionKey == "*" ? "all regions" : $"from {t.IngressRegionKey}";
            var via = t.AttachedFrom is null ? string.Empty : $", attached by {t.AttachedFrom}";
            Field("target", $"{Describe(t)}  {Dim(where + via)}", 6);
        }

        if (d.Targets.Count == 0)
        {
            Field("target", "none (nothing will be delivered)", 6);
        }

        Field("metrics", OnOff(d.MetricsEnabled), 6);
        Field("logs", Show(d.LogGroupName, "off"), 6);
        Field("role", d.Role is null ? "none" : Show(d.Role.Arn, "not set"), 6);
        if (d.HasFilterExpression)
        {
            Field("filter", "a FilterExpression is set; packets that do not match are not delivered", 6);
        }

        if (d.Role is null)
        {
            Warn("No Role: Proxylity has nothing to assume to deliver to this destination.", 6);
        }
        else if (d.Role.UsesRoleArnKey)
        {
            Warn("Role uses 'RoleArn'; the property is 'Arn', so this destination has no role configured.", 6);
        }
    }

    private void WriteHeader(DeploymentSnapshot s)
    {
        var accounts = s.Stacks.Select(x => x.AccountId).Where(a => a.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        var account = accounts.Count == 1 ? $"account {accounts[0]}" : accounts.Count > 1 ? $"{accounts.Count} accounts" : "account unknown";
        var regions = string.Join(", ", s.Regions);
        var cached = s.StacksFromCache > 0 ? Dim($" ({s.StacksFromCache} unchanged, from cache)") : string.Empty;
        output.WriteLine($"{Bold("Proxylity")} {Dim("·")} {account} {Dim("·")} {regions} {Dim("·")} {Plural(s.Stacks.Count, "stack")} with Proxylity resources{cached}");
        output.WriteLine();
    }

    private void WriteNoListeners(DeploymentSnapshot s)
    {
        output.WriteLine(s.Stacks.Count == 0
            ? "No Proxylity resources were found in this account and region."
            : "No listeners were found in the matching stacks.");
        output.WriteLine(Dim("Resources created outside CloudFormation (for example in the dashboard) are not found this way. Check the region, or use --region."));
    }

    private void WriteAttachmentsAndSources(DeploymentSnapshot s)
    {
        var unmatched = s.DestinationAttachments.Where(a => !a.Matched).ToList();
        if (unmatched.Count > 0)
        {
            output.WriteLine();
            output.WriteLine(Bold("Destination ARN attachments for destinations not found here"));
            foreach (var a in unmatched)
            {
                output.WriteLine($"  {a.Stack.Name}/{a.LogicalId}: destination {Show(a.Destination, "?")}, from {Show(a.IngressRegionKey, "?")} → {Show(a.Arn, "?")}");
            }
        }

        if (s.PacketSources.Count > 0)
        {
            output.WriteLine();
            output.WriteLine(Bold("Packet sources"));
            foreach (var p in s.PacketSources)
            {
                output.WriteLine($"  {p.Stack.Name}/{p.LogicalId}: listener {Show(p.ListenerName, "?")}, topic {Show(p.TopicArn, "?")}");
            }
        }
    }

    private void WriteNotes(DeploymentSnapshot s)
    {
        if (s.Notes.Count == 0)
        {
            return;
        }

        output.WriteLine();
        output.WriteLine(Bold("Notes"));
        foreach (var n in s.Notes)
        {
            output.WriteLine($"  {(n.Severity == "warning" ? Yellow("!") : Dim("-"))} {n.Message}");
        }
    }

    private void Field(string name, string value, int indent = 2) => output.WriteLine($"{new string(' ', indent)}{Dim(name.PadRight(13))}{value}");

    private void Warn(string message, int indent = 2) => output.WriteLine($"{new string(' ', indent)}{Yellow("!")} {message}");

    private string DescribeDestinationShort(DestinationInfo d)
    {
        if (d.IsReferenceByName)
        {
            return $"{d.Name} (reference)";
        }

        var first = d.Targets.Count > 0 ? Describe(d.Targets[0]) : "no target";
        var more = d.Targets.Count > 1 ? $" (+{d.Targets.Count - 1} more region{(d.Targets.Count - 1 == 1 ? string.Empty : "s")})" : string.Empty;
        return $"{d.Name} → {first}{more}";
    }

    private static string Describe(DestinationTarget t)
    {
        if (!t.Arn.IsResolved)
        {
            return t.Arn.State == ValueState.Absent ? "no ARN" : $"unresolved ({t.Arn.Reason})";
        }

        var label = ServiceLabel(t.Service);
        return t.Service == DestinationService.Unknown ? t.Arn.Value! : $"{label} {t.ResourceName ?? t.Arn.Value}";
    }

    private static string DescribeClients(ClientRestrictionsInfo c) => c.Form switch
    {
        ClientRestrictionsForm.Object => $"{Plural(c.NetworkCount, "network")}, {Plural(c.DomainCount, "domain")} allowed",
        ClientRestrictionsForm.Absent => "none declared",
        ClientRestrictionsForm.Empty => "empty",
        ClientRestrictionsForm.List => "written as a list",
        _ => "could not be determined",
    };

    internal static string ServiceLabel(DestinationService s) => s switch
    {
        DestinationService.Lambda => "Lambda",
        DestinationService.LambdaMicrovm => "Lambda MicroVM",
        DestinationService.StepFunctions => "Step Functions",
        DestinationService.EventBridge => "EventBridge",
        DestinationService.Sqs => "SQS",
        DestinationService.Sns => "SNS",
        DestinationService.DynamoDb => "DynamoDB",
        DestinationService.S3 => "S3",
        DestinationService.Firehose => "Data Firehose",
        DestinationService.Kinesis => "Kinesis",
        DestinationService.CloudWatchLogs => "CloudWatch Logs",
        DestinationService.ApiGateway => "API Gateway",
        DestinationService.IotData => "IoT Data",
        DestinationService.LocationTracker => "Location tracker",
        _ => "unknown service",
    };

    private static string Show(Resolved<string> v, string absent) => v.State switch
    {
        ValueState.Resolved => v.Value ?? string.Empty,
        ValueState.Absent => absent,
        _ => $"unresolved ({v.Reason})",
    };

    private static string OnOff(Resolved<bool> v) => v.State switch
    {
        ValueState.Resolved => v.Value ? "on" : "off",
        ValueState.Absent => "off (default)",
        _ => $"unresolved ({v.Reason})",
    };

    private static string Plural(int n, string noun) =>
        string.Create(CultureInfo.InvariantCulture, $"{n} {noun}{(n == 1 ? string.Empty : "s")}");

    private string Bold(string s) => color ? $"\u001b[1m{s}\u001b[0m" : s;

    private string Dim(string s) => color ? $"\u001b[2m{s}\u001b[0m" : s;

    private string Yellow(string s) => color ? $"\u001b[33m{s}\u001b[0m" : s;
}
