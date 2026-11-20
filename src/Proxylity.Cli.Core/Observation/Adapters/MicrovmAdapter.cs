using System.Globalization;
using Proxylity.Cli.Core.Model;
using static Proxylity.Cli.Core.Observation.Adapters.AdapterText;

namespace Proxylity.Cli.Core.Observation.Adapters;

/// <summary>
/// Lambda MicroVM images. The destination is an image; Proxylity starts MicroVMs from it as packets arrive.
/// Signals: the image's state and versions (via the CloudFormation resource type, read through Cloud Control),
/// the documented destination Arguments, the MicroVMs' runtime log group, and Proxylity's own destination
/// metrics (MicroVMs are request/response, so replies are meaningful). There are no MicroVM CloudWatch metrics.
/// </summary>
public sealed class MicrovmAdapter : ITargetAdapter
{
    public const string ResourceType = "AWS::Lambda::MicrovmImage";

    public DestinationService Service => DestinationService.LambdaMicrovm;

    public string ResourceKind => "Lambda MicroVM image";

    public async Task<Signal<TargetDescription>> DescribeAsync(DestinationTarget target, DestinationInfo destination, IObservabilitySource source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(source);
        var arn = ArnParser.Parse(target.Arn.Value)!;
        var parts = arn.Resource["microvm-image:".Length..].Split(':');
        var name = parts[0];
        var imageArn = $"arn:{arn.Partition}:lambda:{arn.Region}:{arn.AccountId}:microvm-image:{name}";

        var image = await source.GetResourcePropertiesAsync(arn.Region, ResourceType, imageArn, cancellationToken).ConfigureAwait(false);
        if (!image.IsAvailable)
        {
            return image.Cast<TargetDescription>();
        }

        var args = destination?.Arguments ?? new Dictionary<string, string>();
        var p = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var key in new[] { "State", "LatestActiveImageVersion", "LatestFailedImageVersion" })
        {
            if (image.Value!.TryGetValue(key, out var v) && v.Length > 0)
            {
                p[char.ToLowerInvariant(key[0]) + key[1..]] = v;
            }
        }

        if (parts.Length > 1)
        {
            p["pinnedVersion"] = parts[1];
        }

        p["executionRole"] = args.ContainsKey("ExecutionRoleArn") ? "set" : "not set";
        p["runtimeLogGroup"] = args.GetValueOrDefault("RuntimeLogGroupName") ?? $"/aws/lambda-microvms/{name}";
        p["idleDurationSeconds"] = args.GetValueOrDefault("IdleDurationSeconds") ?? "900 (default)";
        p["tenancy"] = args.ContainsKey("TenantId") || args.ContainsKey("TenantIdExpression") ? "per tenant" : "single";
        if (args.GetValueOrDefault("UseTenantIdForLogStreamName") is { } tenantStreams)
        {
            p["useTenantIdForLogStreamName"] = tenantStreams;
        }

        if (args.GetValueOrDefault("EgressNetworkConnectorArns") is { } connectors)
        {
            p["egressNetworkConnectors"] = connectors;
        }

        return Signal<TargetDescription>.Of(new TargetDescription(name, p));
    }

    /// <summary>Lambda does not publish CloudWatch metrics for MicroVMs; Proxylity's destination metrics cover delivery.</summary>
    public IReadOnlyList<TargetMetric> Metrics(DestinationTarget target, TargetDescription description) => [];

    /// <summary>Runtime output reaches CloudWatch Logs only when the MicroVM runs with an execution role.</summary>
    public TargetLogPlan? ErrorLogs(DestinationTarget target, DestinationInfo destination, TargetDescription description)
    {
        ArgumentNullException.ThrowIfNull(description);
        return description.Properties.GetValueOrDefault("executionRole") == "set"
            ? new TargetLogPlan(description.Properties["runtimeLogGroup"], ErrorPattern, 5)
            : null;
    }

    /// <summary>
    /// Image-scoped actions from the MicroVM destination page. The per-MicroVM actions (GetMicrovm, ResumeMicrovm,
    /// TerminateMicrovm) apply to MicroVM ARNs that only exist at run time, so they are not simulated.
    /// </summary>
    public IReadOnlyList<PermissionRequirement> Permissions(DestinationTarget target, DestinationInfo destination, TargetDescription? description)
    {
        ArgumentNullException.ThrowIfNull(target);
        var arn = ArnParser.Parse(target.Arn.Value)!;
        var name = arn.Resource["microvm-image:".Length..].Split(':')[0];
        var image = $"arn:{arn.Partition}:lambda:{arn.Region}:{arn.AccountId}:microvm-image:{name}";
        var result = new List<PermissionRequirement>
        {
            new(["lambda:RunMicrovm", "lambda:CreateMicrovmAuthToken", "lambda:GetMicrovmImage", "lambda:GetMicrovmImageVersion"], image),
        };
        if (destination?.Arguments?.GetValueOrDefault("ExecutionRoleArn") is { } executionRole && executionRole.StartsWith("arn:", StringComparison.Ordinal))
        {
            result.Add(new(["iam:PassRole"], executionRole));
        }

        return result;
    }

    public IEnumerable<Finding> Diagnose(TargetObservation o, DestinationObservation destination)
    {
        ArgumentNullException.ThrowIfNull(o);
        ArgumentNullException.ThrowIfNull(destination);
        var f = new List<Finding>();
        var p = o.Description!.Value!.Properties;
        var state = p.GetValueOrDefault("state");
        var active = p.GetValueOrDefault("latestActiveImageVersion");
        var failed = p.GetValueOrDefault("latestFailedImageVersion");
        var pinned = p.GetValueOrDefault("pinnedVersion");

        // Image health.
        if (state is not null && state.EndsWith("_FAILED", StringComparison.Ordinal))
        {
            f.Add(new("microvm.image-failed", Health.Error, Confidence.Confirmed,
                "The MicroVM image is in a failed state",
                [new("state", state), new("active version", active ?? "none")],
                ["Check the image's build in the Lambda console or the stack events, then rebuild it."]));
        }

        if (string.IsNullOrEmpty(active))
        {
            f.Add(new("microvm.no-active-version", Health.Error, Confidence.Confirmed,
                "The image has no active version, so MicroVMs can't be started from it",
                [new("state", state ?? "?"), new("latest failed version", failed ?? "none")],
                ["Fix the image build so a version becomes active."]));
        }
        else if (pinned is not null && string.Equals(pinned, failed, StringComparison.Ordinal))
        {
            f.Add(new("microvm.pinned-to-failed-version", Health.Error, Confidence.Likely,
                "The destination is pinned to a version whose build failed",
                [new("pinned version", pinned), new("latest active version", active)],
                ["Pin the destination to an active version, or remove the version suffix from the ARN."]));
        }
        else if (!string.IsNullOrEmpty(failed) && pinned is null && IsNewer(failed, active))
        {
            f.Add(new("microvm.latest-build-failed", Health.Warning, Confidence.Confirmed,
                "The newest image version failed to build; new MicroVMs keep using the previous active version",
                [new("failed version", failed), new("active version", active)],
                ["Fix and rebuild the image if you expected the new version to be running."]));
        }

        // Configuration (documented destination Arguments).
        if (p.GetValueOrDefault("executionRole") != "set")
        {
            f.Add(new("microvm.runtime-logs-off", Health.NotConfigured, Confidence.Confirmed,
                "MicroVM output (stdout/stderr) is not sent to CloudWatch Logs, because no ExecutionRoleArn is set",
                [new("ExecutionRoleArn", "not set")],
                ["Set Arguments.ExecutionRoleArn to a role assumable by lambda.amazonaws.com that can write to the runtime log group."]));
        }

        if (string.Equals(p.GetValueOrDefault("useTenantIdForLogStreamName"), "true", StringComparison.OrdinalIgnoreCase) && p.GetValueOrDefault("tenancy") != "per tenant")
        {
            f.Add(new("microvm.tenant-streams-without-tenant", Health.Warning, Confidence.Confirmed,
                "UseTenantIdForLogStreamName is true but no TenantId or TenantIdExpression is set",
                [new("UseTenantIdForLogStreamName", "true")],
                ["Set TenantId or TenantIdExpression, or remove UseTenantIdForLogStreamName."]));
        }

        // Runtime logs.
        switch (o.ErrorLogs?.Events.State)
        {
            case SignalState.NotFound:
                f.Add(new("microvm.runtime-log-group-missing", Health.Warning, Confidence.Confirmed,
                    "The runtime log group does not exist, so MicroVM output is dropped without an error",
                    [new("log group", o.ErrorLogs.LogGroup)],
                    ["Create the log group (with a retention period) and allow the execution role to write to it."]));
                break;
            case SignalState.NotAccessible:
                f.Add(NotAccessible("microvm.logs-not-accessible", "The MicroVM runtime log group", o.ErrorLogs.Events.DeniedAction ?? "logs:FilterLogEvents"));
                break;
        }

        if (ErrorLines("microvm.error-log-lines", o, "MicroVM runtime") is { } lines)
        {
            f.Add(lines);
        }

        // Traffic, from Proxylity's destination metrics.
        var accepted = AcceptedFor(o.Target, destination);
        var replies = RepliesFor(o.Target, destination);
        var errors = destination.Metrics.GetValueOrDefault(MetricKeys.Errors);
        if (Has(accepted) && accepted!.Value > 0)
        {
            if (Has(replies) && replies!.Value > 0)
            {
                // Replies prove MicroVMs are running and answering, even if some deliveries failed.
                var withErrors = ValueOr0(errors) > 0;
                f.Add(new("microvm.replying", Health.Healthy, withErrors ? Confidence.Possible : Confidence.Likely,
                    withErrors
                        ? "MicroVMs are receiving packets and sending replies, although some delivery errors were reported"
                        : "MicroVMs are receiving packets and sending replies",
                    [new("accepted", Units(accepted.Value)), new("replies", Units(replies.Value))],
                    []));
            }
            else
            {
                f.Add(new("microvm.no-replies", Health.Unknown, Confidence.Possible,
                    "Packets were accepted but no replies were sent",
                    [new("accepted", Units(accepted.Value)), new("replies", "0")],
                    [
                        "This is expected if the application doesn't reply. Otherwise check the destination log and the MicroVM runtime logs.",
                        "The first packet for a tenant starts a MicroVM and may be dropped or answered late.",
                    ]));
            }
        }
        else if (destination.Destination.MetricsEnabled.Value)
        {
            f.Add(new("microvm.no-traffic", Health.Unknown, Confidence.Confirmed,
                "No packets were accepted for this image in the window",
                [new("image", o.Description.Value.Name)],
                []));
        }

        return f;
    }

    /// <summary>Compares versions such as "5.0" and "6.0" numerically where possible.</summary>
    private static bool IsNewer(string candidate, string current) =>
        Version.TryParse(Normalize(candidate), out var a) && Version.TryParse(Normalize(current), out var b)
            ? a > b
            : string.CompareOrdinal(candidate, current) > 0;

    private static string Normalize(string v) => v.Contains('.', StringComparison.Ordinal) ? v : v + ".0";

    internal static string Describe(IReadOnlyDictionary<string, string> p) =>
        string.Join(" · ", p.Select(kv => string.Create(CultureInfo.InvariantCulture, $"{kv.Key} {kv.Value}")));
}
