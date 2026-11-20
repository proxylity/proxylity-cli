using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli;

internal sealed record TargetResolution(IReadOnlyList<ListenerInfo> Listeners, string? Error, IReadOnlyList<string> Candidates);

/// <summary>
/// Resolves a command target to listeners. A listener name, logical ID or "stack/LogicalId" selects one
/// listener; otherwise a stack name selects every listener in that stack; no target selects all listeners.
/// Listener names are unique in an account, so they take precedence over stack names.
/// </summary>
internal static class TargetResolver
{
    public static TargetResolution Resolve(DeploymentSnapshot snapshot, string? target)
    {
        if (target is null)
        {
            return new TargetResolution(snapshot.Listeners, null, []);
        }

        var byName = snapshot.Listeners.Where(l => string.Equals(l.Name, target, StringComparison.Ordinal)).ToList();
        if (byName.Count > 0)
        {
            return new TargetResolution(byName, null, []);
        }

        var byPath = snapshot.Listeners.Where(l => string.Equals($"{l.Stack.Name}/{l.LogicalId}", target, StringComparison.Ordinal)).ToList();
        if (byPath.Count > 0)
        {
            return new TargetResolution(byPath, null, []);
        }

        var byLogical = snapshot.Listeners.Where(l => string.Equals(l.LogicalId, target, StringComparison.Ordinal)).ToList();
        var byStack = snapshot.Listeners.Where(l => string.Equals(l.Stack.Name, target, StringComparison.Ordinal)).ToList();

        if (byLogical.Count == 1 && byStack.Count == 0)
        {
            return new TargetResolution(byLogical, null, []);
        }

        if (byStack.Count > 0 && byLogical.Count == 0)
        {
            return new TargetResolution(byStack, null, []);
        }

        if (byLogical.Count + byStack.Count > 0)
        {
            return new TargetResolution([], $"'{target}' is ambiguous.", [.. byLogical.Concat(byStack).Distinct().Select(l => $"{l.Stack.Name}/{l.LogicalId}")]);
        }

        var stackWithoutListeners = snapshot.Stacks.Any(s => string.Equals(s.Name, target, StringComparison.Ordinal));
        return new TargetResolution(
            [],
            stackWithoutListeners
                ? $"stack '{target}' has no listeners."
                : $"no listener or stack matches '{target}'. Run 'proxylity list' to see what was found.",
            []);
    }
}
