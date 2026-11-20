using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Core.Model;

/// <param name="Path">Where in the listener's properties, for example "Destinations[1].Batching.Count".</param>
public sealed record TemplateIssue(string RuleId, string Message, string Path);

/// <summary>
/// Requirements the public CloudFormation reference states for Proxylity resources. Templates deployed before a
/// requirement was enforced can still contain values that break it; the next update of such a stack is rejected.
/// Only requirements the documentation states as such are checked (not guidance). Values that could not be
/// resolved are skipped, and checked values are never repeated in messages.
/// </summary>
public static partial class TemplateRules
{
    private static readonly HashSet<string> DestinationProperties = new(StringComparer.Ordinal)
    {
        "Name", "Description", "Role", "Batching", "DestinationArn", "MetricsEnabled", "LogGroupName", "Formatter", "FilterExpression", "Arguments",
    };

    public static List<TemplateIssue> Check(TNode listenerProperties)
    {
        ArgumentNullException.ThrowIfNull(listenerProperties);
        var issues = new List<TemplateIssue>();
        var p = listenerProperties;

        if (p.Get("Protocols") is { Kind: NodeKind.Seq } protocols && protocols.Items.Count != 1)
        {
            issues.Add(new("protocols-count", $"Protocols must contain exactly one value, not {protocols.Items.Count}.", "Protocols"));
        }

        CheckLogGroup(issues, p.Get("LogGroupName"), "LogGroupName");

        if (p.Get("ClientRestrictions")?.Get("Networks") is { Kind: NodeKind.Seq } networks)
        {
            for (var i = 0; i < networks.Items.Count; i++)
            {
                if (networks.Items[i].Kind == NodeKind.String && !IsCidr(networks.Items[i].Text!))
                {
                    issues.Add(new("invalid-cidr", $"Networks entry {i + 1} is not a valid IPv4 or IPv6 CIDR block.", $"ClientRestrictions.Networks[{i}]"));
                }
            }
        }

        if (p.Get("Destinations") is { Kind: NodeKind.Seq } destinations)
        {
            for (var i = 0; i < destinations.Items.Count; i++)
            {
                if (destinations.Items[i].Kind == NodeKind.Map)
                {
                    CheckDestination(issues, destinations.Items[i], $"Destinations[{i}]");
                }
            }
        }

        return issues;
    }

    private static void CheckDestination(List<TemplateIssue> issues, TNode d, string path)
    {
        if (d.Get("Name") is { Kind: NodeKind.String } name && !DestinationName().IsMatch(name.Text!))
        {
            issues.Add(new("destination-name", "Destination Name may contain only letters, digits and hyphens.", $"{path}.Name"));
        }

        CheckLogGroup(issues, d.Get("LogGroupName"), $"{path}.LogGroupName");

        foreach (var key in d.Entries.Select(e => e.Key).Where(k => !DestinationProperties.Contains(k)))
        {
            issues.Add(new("destination-unknown-property", $"'{Safe(key)}' is not a destination property; service settings must be placed inside Arguments.", $"{path}.{Safe(key)}"));
        }

        if (d.Get("Batching") is { Kind: NodeKind.Map } b)
        {
            if (Number(b.Get("Count")) is { } count && (count < 1 || count > 1000 || count != Math.Floor(count)))
            {
                issues.Add(new("batching-count", "Batching Count must be a whole number from 1 through 1,000.", $"{path}.Batching.Count"));
            }

            if (Number(b.Get("TimeoutInSeconds")) is { } timeout
                && (timeout < 0.001 || timeout > 60 || Math.Abs(timeout * 1000 - Math.Round(timeout * 1000)) > 1e-9))
            {
                issues.Add(new("batching-timeout", "Batching TimeoutInSeconds must be from 0.001 through 60 and resolve to whole milliseconds.", $"{path}.Batching.TimeoutInSeconds"));
            }

            if (Number(b.Get("SizeInMB")) is { } size)
            {
                var bytes = size * 1024 * 1024;
                if (bytes < 1024 || bytes > 6 * 1024 * 1024 || Math.Abs(bytes - Math.Round(bytes)) > 1e-6)
                {
                    issues.Add(new("batching-size", "Batching SizeInMB must resolve to a whole number of bytes from 1 KiB through 6 MiB.", $"{path}.Batching.SizeInMB"));
                }
            }
        }

        if (d.Get("DestinationArn") is { Kind: NodeKind.Map } map)
        {
            var services = map.Entries
                .Select(e => e.Value.Kind == NodeKind.String ? ArnParser.Parse(e.Value.Text) : null)
                .Where(a => a is not null)
                .Select(a => ArnParser.ServiceOf(a!))
                .Distinct()
                .ToList();
            if (services.Count > 1)
            {
                issues.Add(new("region-map-mixed-services", "All ARNs in a DestinationArn map must be for the same AWS service.", $"{path}.DestinationArn"));
            }
        }
    }

    private static void CheckLogGroup(List<TemplateIssue> issues, TNode? node, string path)
    {
        if (node is { Kind: NodeKind.String } g && (g.Text!.Length is < 1 or > 512 || !LogGroupName().IsMatch(g.Text)))
        {
            issues.Add(new("log-group-name", "LogGroupName must be 1 to 512 characters: letters, digits, and _ - / . #", path));
        }
    }

    /// <summary>
    /// An address with an optional prefix length. Lenient on purpose: bare addresses and prefixes with host bits
    /// set are accepted, so only entries that are clearly not addresses are reported.
    /// </summary>
    private static bool IsCidr(string value)
    {
        var parts = value.Trim().Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address))
        {
            return false;
        }

        if (parts.Length == 1)
        {
            return true;
        }

        var max = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) && prefix >= 0 && prefix <= max;
    }

    private static double? Number(TNode? node) =>
        node is { IsScalar: true } && double.TryParse(node.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : null;

    /// <summary>Template keys are customer text; keep them printable and short in messages.</summary>
    private static string Safe(string key) => key.Length > 64 ? key[..64] + "..." : new string([.. key.Where(c => !char.IsControl(c))]);

    [GeneratedRegex("^[a-zA-Z0-9-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex DestinationName();

    [GeneratedRegex(@"^[A-Za-z0-9_\-/.#]+$", RegexOptions.CultureInvariant)]
    private static partial Regex LogGroupName();
}
