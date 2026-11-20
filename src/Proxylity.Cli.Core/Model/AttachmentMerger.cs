namespace Proxylity.Cli.Core.Model;

/// <summary>
/// Merges ARNs contributed by <c>Custom::ProxylityUdpGatewayDestinationArn</c> resources (often in other,
/// regional stacks) into the destinations they name, so each destination shows its full target set.
/// </summary>
public static class AttachmentMerger
{
    public static ListenerInfo Apply(ListenerInfo listener, IReadOnlyList<DestinationAttachment> attachments)
    {
        ArgumentNullException.ThrowIfNull(listener);
        ArgumentNullException.ThrowIfNull(attachments);
        if (attachments.Count == 0)
        {
            return listener;
        }

        var destinations = listener.Destinations.Select(d =>
        {
            var extra = attachments
                .Where(a => a.Destination.IsResolved && string.Equals(a.Destination.Value, d.Name, StringComparison.Ordinal))
                .Select(ToTarget)
                .ToList();
            return extra.Count == 0 ? d : d with { Targets = [.. d.Targets, .. extra] };
        }).ToList();

        return listener with { Destinations = destinations };
    }

    /// <summary>Marks attachments that matched a discovered destination.</summary>
    public static List<DestinationAttachment> MarkMatched(IReadOnlyList<DestinationAttachment> attachments, IReadOnlyList<ListenerInfo> listeners)
    {
        ArgumentNullException.ThrowIfNull(attachments);
        ArgumentNullException.ThrowIfNull(listeners);
        var names = listeners.SelectMany(l => l.Destinations).Select(d => d.Name).Where(n => n is not null).ToHashSet(StringComparer.Ordinal);
        return attachments.Select(a => a with { Matched = a.Destination.IsResolved && names.Contains(a.Destination.Value!) }).ToList();
    }

    private static DestinationTarget ToTarget(DestinationAttachment a)
    {
        var parsed = a.Arn.IsResolved ? ArnParser.Parse(a.Arn.Value) : null;
        var service = parsed is null ? DestinationService.Unknown : ArnParser.ServiceOf(parsed);
        return new DestinationTarget(
            a.IngressRegionKey.IsResolved ? a.IngressRegionKey.Value! : "?",
            a.Arn,
            service,
            parsed is { Region.Length: > 0 } ? parsed.Region : null,
            parsed is null ? null : ArnParser.ResourceNameOf(parsed, service),
            $"{a.Stack.Name}/{a.LogicalId}");
    }
}
