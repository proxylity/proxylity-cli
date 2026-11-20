using System.Text.Json.Serialization;
using Proxylity.Cli.Core.Discovery;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli;

/// <summary>What one probe found out about an IAM action.</summary>
[JsonConverter(typeof(CamelCaseEnumConverter<AccessState>))]
internal enum AccessState
{
    /// <summary>The call was permitted (including "the resource does not exist", which IAM evaluates after authorization).</summary>
    Allowed,

    /// <summary>The call was denied.</summary>
    Denied,

    /// <summary>The call failed for another reason, for example throttling, so permission is unknown.</summary>
    Inconclusive,

    /// <summary>No probe was made; <see cref="AccessProbe.Detail"/> says why.</summary>
    NotTested,
}

/// <param name="Action">The IAM action the probe exercises.</param>
/// <param name="Used">What the CLI uses the action for.</param>
internal sealed record AccessProbe(string Action, string Used, AccessState State, string? Detail = null);

internal sealed record AccessReport(string Region, IReadOnlyList<AccessProbe> Probes);

/// <summary>
/// Reports which of the read actions the CLI uses the current identity can perform. It calls the same read-only
/// operations the other commands use, against resources that do not exist, so nothing is changed and nothing is
/// invoked. It never reads the account configuration object: that read would return the API key.
/// </summary>
internal sealed class AccessChecker(IStackSource stacks, IObservabilitySource observability)
{
    private const string ProbeName = "proxylity-cli-access-check";

    public async Task<AccessReport> CheckAsync(CancellationToken ct)
    {
        var probes = new List<AccessProbe>();
        IReadOnlyList<StackSummary> listed = [];
        var listProbe = await ProbeStackAsync("cloudformation:ListStacks", "Finding stacks", async () => listed = await stacks.ListStacksAsync(ct).ConfigureAwait(false)).ConfigureAwait(false);
        probes.Add(listProbe);

        var stack = listed.Count > 0 ? listed[0] : null;
        var parsed = stack is null ? null : ArnParser.Parse(stack.Id);
        var region = parsed is { Region.Length: > 0 } ? parsed.Region : stacks.Region;
        var account = parsed?.AccountId ?? string.Empty;
        var partition = parsed?.Partition ?? "aws";
        var noStack = listProbe.State == AccessState.Allowed ? "no stacks were listed" : "ListStacks did not succeed";

        if (stack is null)
        {
            probes.Add(Skipped("cloudformation:ListStackResources", "Finding Proxylity resources in a stack", noStack));
            probes.Add(Skipped("cloudformation:DescribeStacks", "Stack parameters and outputs", noStack));
            probes.Add(Skipped("cloudformation:GetTemplate", "The processed template", noStack));
        }
        else
        {
            probes.Add(await ProbeStackAsync("cloudformation:ListStackResources", "Finding Proxylity resources in a stack", () => stacks.ListResourcesAsync(stack.Id, ct)).ConfigureAwait(false));
            probes.Add(await ProbeStackAsync("cloudformation:DescribeStacks", "Stack parameters and outputs", () => stacks.DescribeAsync(stack.Id, ct)).ConfigureAwait(false));
            probes.Add(await ProbeStackAsync("cloudformation:GetTemplate", "The processed template", () => stacks.GetProcessedTemplateAsync(stack.Id, ct)).ConfigureAwait(false));
        }

        var end = DateTimeOffset.UtcNow;
        var window = new TimeWindow(end.AddMinutes(-5), end);
        var query = new MetricQuery("probe", "Proxylity/UDP Gateway", "IngressPackets", [new("Listener", ProbeName)], "Sum");
        var metrics = await observability.GetMetricsAsync(region, [query], window, ct).ConfigureAwait(false);
        probes.Add(FromSignal("cloudwatch:GetMetricData", "Proxylity metrics and each destination service's own metrics",
            metrics.TryGetValue(query.Id, out var metric) ? metric.Cast<object>() : Signal<object>.Failed("no result returned")));

        var logs = await observability.GetLogEventsAsync(region, $"/{ProbeName}", window, null, 1, ct).ConfigureAwait(false);
        probes.Add(FromSignal("logs:FilterLogEvents", "Listener and destination log groups, and target runtime logs", logs.Cast<object>()));

        if (account.Length == 0)
        {
            const string reason = "no stack was available to take the account from";
            probes.Add(Skipped("lambda:GetFunction", "Lambda function state and configuration", reason));
            probes.Add(Skipped("cloudformation:GetResource", "Whether a target resource exists", reason));
            probes.Add(Skipped("iam:GetRole", "Whether a role exists and what its trust policy requires", reason));
            probes.Add(Skipped("iam:SimulatePrincipalPolicy", "Whether a role's policies allow what Proxylity needs", reason));
        }
        else
        {
            var function = await observability.GetFunctionAsync($"arn:{partition}:lambda:{region}:{account}:function:{ProbeName}", ct).ConfigureAwait(false);
            probes.Add(FromSignal("lambda:GetFunction", "Lambda function state and configuration", function.Cast<object>()));

            var resource = await observability.GetResourcePropertiesAsync(region, "AWS::Logs::LogGroup", ProbeName, ct).ConfigureAwait(false);
            probes.Add(FromSignal("cloudformation:GetResource", "Whether a target resource exists", resource.Cast<object>()));

            var roleArn = $"arn:{partition}:iam::{account}:role/{ProbeName}";
            var trust = await observability.GetRoleTrustAsync(roleArn, ct).ConfigureAwait(false);
            probes.Add(FromSignal("iam:GetRole", "Whether a role exists and what its trust policy requires", trust.Cast<object>()));

            var simulation = await observability.SimulateAsync(roleArn, ["sts:GetCallerIdentity"], ["*"], null, ct).ConfigureAwait(false);
            probes.Add(FromSignal("iam:SimulatePrincipalPolicy", "Whether a role's policies allow what Proxylity needs", simulation.Cast<object>()));
        }

        probes.Add(new AccessProbe(
            "s3:GetObject",
            "Optional: your Proxylity account configuration",
            AccessState.NotTested,
            "probing would read the account configuration; diagnose reports whether it is readable"));
        return new AccessReport(region, probes);
    }

    private static AccessProbe Skipped(string action, string used, string reason) =>
        new(action, used, AccessState.NotTested, reason);

    private static AccessProbe FromSignal(string action, string used, Signal<object> signal) => signal.State switch
    {
        SignalState.NotAccessible => new AccessProbe(action, used, AccessState.Denied),
        SignalState.Failed => new AccessProbe(action, used, AccessState.Inconclusive, signal.Detail),
        _ => new AccessProbe(action, used, AccessState.Allowed),
    };

    /// <summary>Runs a CloudFormation read. Credential problems propagate so the command reports them as usual.</summary>
    private static async Task<AccessProbe> ProbeStackAsync(string action, string used, Func<Task> call)
    {
        try
        {
            await call().ConfigureAwait(false);
            return new AccessProbe(action, used, AccessState.Allowed);
        }
        catch (AccessDeniedException)
        {
            return new AccessProbe(action, used, AccessState.Denied);
        }
        catch (ThrottledException)
        {
            return new AccessProbe(action, used, AccessState.Inconclusive, "throttled by AWS");
        }
    }
}