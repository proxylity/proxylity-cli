using System.Globalization;
using Proxylity.Cli.Core.Model;
using static Proxylity.Cli.Core.Observation.Adapters.AdapterText;

namespace Proxylity.Cli.Core.Observation.Adapters;

/// <summary>Lambda functions: GetFunction for state and configuration, AWS/Lambda metrics, and the function's log group.</summary>
public sealed class LambdaAdapter : ITargetAdapter
{
    public const string Namespace = "AWS/Lambda";

    public DestinationService Service => DestinationService.Lambda;

    public string ResourceKind => "Lambda function";

    public async Task<Signal<TargetDescription>> DescribeAsync(DestinationTarget target, DestinationInfo destination, IObservabilitySource source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(source);
        var fn = await source.GetFunctionAsync(target.Arn.Value!, cancellationToken).ConfigureAwait(false);
        if (!fn.IsAvailable)
        {
            return fn.Cast<TargetDescription>();
        }

        var f = fn.Value!;
        var p = new Dictionary<string, string>(StringComparer.Ordinal) { ["logGroup"] = f.LogGroup };
        void Put(string key, object? value)
        {
            if (value is not null)
            {
                p[key] = Convert.ToString(value, CultureInfo.InvariantCulture)!;
            }
        }

        Put("runtime", f.Runtime);
        Put("memoryMb", f.MemoryMb);
        Put("timeoutSeconds", f.TimeoutSeconds);
        Put("state", f.State);
        Put("stateReason", f.StateReason);
        Put("lastUpdateStatus", f.LastUpdateStatus);
        Put("reservedConcurrency", f.ReservedConcurrency);
        if (destination?.Arguments?.GetValueOrDefault("UseAsyncInvoke") is { } async)
        {
            p["useAsyncInvoke"] = async;
        }

        return Signal<TargetDescription>.Of(new TargetDescription(f.Name, p));
    }

    public IReadOnlyList<TargetMetric> Metrics(DestinationTarget target, TargetDescription description)
    {
        ArgumentNullException.ThrowIfNull(target);
        var arn = ArnParser.Parse(target.Arn.Value)!;
        var parts = arn.Resource["function:".Length..].Split(':');
        IReadOnlyList<KeyValuePair<string, string>> dims = parts.Length > 1
            ? [new("FunctionName", parts[0]), new("Resource", $"{parts[0]}:{parts[1]}")]
            : [new("FunctionName", parts[0])];
        return
        [
            new(MetricKeys.LambdaInvocations, Namespace, "Invocations", dims, "Sum"),
            new(MetricKeys.LambdaErrors, Namespace, "Errors", dims, "Sum"),
            new(MetricKeys.LambdaThrottles, Namespace, "Throttles", dims, "Sum"),
            new(MetricKeys.LambdaDurationMax, Namespace, "Duration", dims, "Maximum"),
            new(MetricKeys.LambdaDurationAvg, Namespace, "Duration", dims, "Average"),
            new(MetricKeys.LambdaConcurrencyMax, Namespace, "ConcurrentExecutions", dims, "Maximum"),
        ];
    }

    public TargetLogPlan? ErrorLogs(DestinationTarget target, DestinationInfo destination, TargetDescription description)
    {
        ArgumentNullException.ThrowIfNull(description);
        return new(description.Properties["logGroup"], ErrorPattern, 5);
    }

    public IReadOnlyList<PermissionRequirement> Permissions(DestinationTarget target, DestinationInfo destination, TargetDescription? description)
    {
        ArgumentNullException.ThrowIfNull(target);
        return [new(["lambda:InvokeFunction"], target.Arn.Value!)];
    }

    public IEnumerable<Finding> Diagnose(TargetObservation o, DestinationObservation destination)
    {
        ArgumentNullException.ThrowIfNull(o);
        ArgumentNullException.ThrowIfNull(destination);
        var f = new List<Finding>();
        var p = o.Description!.Value!.Properties;
        var state = p.GetValueOrDefault("state");
        var lastUpdate = p.GetValueOrDefault("lastUpdateStatus");
        var logGroup = p.GetValueOrDefault("logGroup") ?? "the function's log group";

        if (string.Equals(state, "Failed", StringComparison.OrdinalIgnoreCase) || string.Equals(lastUpdate, "Failed", StringComparison.OrdinalIgnoreCase))
        {
            f.Add(new("lambda.failed-state", Health.Error, Confidence.Confirmed,
                "The Lambda function is in a failed state",
                [new("state", state ?? "?"), new("last update", lastUpdate ?? "?"), new("reason", p.GetValueOrDefault("stateReason") ?? "-")],
                ["Fix the function's configuration or redeploy it."]));
        }
        else if (string.Equals(state, "Inactive", StringComparison.OrdinalIgnoreCase))
        {
            f.Add(new("lambda.inactive", Health.Warning, Confidence.Possible,
                "The Lambda function is inactive (idle for a long time); the first invocations may fail while it reactivates",
                [new("state", "Inactive")],
                []));
        }

        if (p.GetValueOrDefault("reservedConcurrency") == "0")
        {
            f.Add(new("lambda.concurrency-zero", Health.Error, Confidence.Confirmed,
                "Reserved concurrency is 0, so the function can't run and every invocation is throttled",
                [new("reserved concurrency", "0")],
                ["Raise or remove the function's reserved concurrency."]));
        }

        var invocations = o.Metrics.GetValueOrDefault(MetricKeys.LambdaInvocations);
        var errors = o.Metrics.GetValueOrDefault(MetricKeys.LambdaErrors);
        var throttles = o.Metrics.GetValueOrDefault(MetricKeys.LambdaThrottles);
        var durationMax = o.Metrics.GetValueOrDefault(MetricKeys.LambdaDurationMax);

        if (invocations?.State == SignalState.NotAccessible && errors?.State is null or SignalState.NotAccessible)
        {
            f.Add(NotAccessible("lambda.metrics-not-accessible", "Lambda metrics", invocations.DeniedAction ?? "cloudwatch:GetMetricData"));
        }
        else if (!Has(invocations) || invocations!.Value == 0)
        {
            var accepted = AcceptedFor(o.Target, destination);
            if (Has(accepted) && accepted!.Value > 0)
            {
                f.Add(new("lambda.accepted-not-invoked", Health.Warning, Confidence.Possible,
                    "Packets were accepted for this destination but the function was not invoked",
                    [new("accepted", Units(accepted.Value)), new("invocations", "0")],
                    [
                        "Check the destination log for delivery errors (role permissions, function ARN).",
                        "Accepted means queued for delivery, not delivered; batching can delay invocations briefly.",
                    ]));
            }
            else
            {
                f.Add(new("lambda.no-invocations", Health.Unknown, Confidence.Confirmed,
                    "The function was not invoked in the window",
                    [new("invocations", "0")],
                    []));
            }
        }
        else
        {
            var e = ValueOr0(errors);
            var th = ValueOr0(throttles);
            if (th > 0)
            {
                var evidence = new List<Evidence> { new("throttles", Count(th)), new("invocations", Count(invocations.Value)) };
                if (p.GetValueOrDefault("reservedConcurrency") is { } rc)
                {
                    evidence.Add(new("reserved concurrency", rc));
                }

                f.Add(new("lambda.throttled", Health.Error, Confidence.Confirmed,
                    "The function was throttled",
                    evidence,
                    ["Review the function's reserved concurrency and the account's concurrency limit; consider batching to reduce invocations."]));
            }

            if (e > 0)
            {
                f.Add(new("lambda.errors", Health.Error, Confidence.Confirmed,
                    "The function returned errors",
                    [new("errors", Count(e)), new("invocations", Count(invocations.Value)), new("error rate", Percent(e / invocations.Value))],
                    [o.ErrorLogs?.Events.State switch
                    {
                        SignalState.Available => "Recent error-like log lines from the function are listed below.",
                        SignalState.NotFound => $"The function's log group {logGroup} was not found; check the function's logging configuration.",
                        _ => $"No error-like lines were found in {logGroup} for the window; open the log group for full context.",
                    }]));
            }

            if (durationMax?.IsAvailable == true
                && int.TryParse(p.GetValueOrDefault("timeoutSeconds"), NumberStyles.None, CultureInfo.InvariantCulture, out var timeout)
                && timeout > 0 && durationMax.Value >= timeout * 1000 * 0.9)
            {
                f.Add(new("lambda.near-timeout", Health.Warning, Confidence.Likely,
                    "Some invocations ran close to the function's timeout",
                    [new("max duration", (durationMax.Value / 1000).ToString("0.0", CultureInfo.InvariantCulture) + "s"), new("timeout", $"{timeout}s")],
                    ["Increase the timeout or reduce work per invocation (smaller batches)."]));
            }

            if (th == 0 && e == 0)
            {
                f.Add(new("lambda.healthy", Health.Healthy, Confidence.Confirmed,
                    "The function is being invoked with no errors or throttles",
                    [new("invocations", Count(invocations.Value))],
                    []));
            }
        }

        if (o.ErrorLogs?.Events.State == SignalState.NotAccessible)
        {
            f.Add(NotAccessible("lambda.logs-not-accessible", "The function's log group", o.ErrorLogs.Events.DeniedAction ?? "logs:FilterLogEvents"));
        }

        if (ErrorLines("lambda.error-log-lines", o, "function") is { } lines)
        {
            f.Add(lines);
        }

        return f;
    }
}
