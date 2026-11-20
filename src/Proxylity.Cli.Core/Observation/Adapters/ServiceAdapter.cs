using System.Globalization;
using Proxylity.Cli.Core.Model;
using static Proxylity.Cli.Core.Observation.Adapters.AdapterText;

namespace Proxylity.Cli.Core.Observation.Adapters;

/// <summary>How a service metric is interpreted.</summary>
public enum MetricRole
{
    /// <summary>Data arriving at the service. Other producers may contribute.</summary>
    Activity,

    /// <summary>Failures of the work Proxylity hands to the service.</summary>
    Failure,

    /// <summary>The service rejected or slowed writes because of limits.</summary>
    Throttle,

    /// <summary>Failures after the service accepted the data (for example to subscribers or a storage target).</summary>
    DownstreamFailure,

    /// <summary>An average where 1 means every attempt succeeded.</summary>
    SuccessRatio,

    /// <summary>Age in seconds of the oldest unprocessed item.</summary>
    BacklogAge,

    /// <summary>Shown, not judged.</summary>
    Info,
}

public sealed record SpecMetric(string Key, string MetricName, string Statistic, MetricRole Role, string Label);

/// <summary>
/// Everything needed to inspect one service. Facts come from the service's public Proxylity destination page
/// (required actions) and AWS documentation (CloudFormation type, metrics).
/// </summary>
/// <param name="Identifier">Cloud Control primary identifier for the target, or null to skip the existence check.</param>
/// <param name="DescribeKeys">CloudFormation properties to show, mapped to display keys. Only these are kept.</param>
/// <param name="Namespace">CloudWatch namespace of the service metrics, or null when none are useful.</param>
/// <param name="Dimensions">Metric dimensions for the target.</param>
/// <param name="Permissions">Required actions on resources, from the destination docs.</param>
public sealed record ServiceSpec(
    DestinationService Service,
    string RulePrefix,
    string Kind,
    string CfnType,
    Func<ParsedArn, string?> Identifier,
    IReadOnlyDictionary<string, string> DescribeKeys,
    string? Namespace,
    Func<ParsedArn, IReadOnlyList<KeyValuePair<string, string>>>? Dimensions,
    IReadOnlyList<SpecMetric> Metrics,
    Func<ParsedArn, string, IReadOnlyDictionary<string, string>?, IReadOnlyList<PermissionRequirement>> Permissions,
    string? Note = null);

/// <summary>
/// A table-driven adapter for services whose inspection follows the same shape: does the target exist (Cloud Control),
/// what do its own metrics show, and what does the destination role need.
/// </summary>
public sealed class ServiceAdapter(ServiceSpec spec) : ITargetAdapter
{
    public ServiceSpec Spec { get; } = spec;

    public DestinationService Service => Spec.Service;

    public string ResourceKind => Spec.Kind;

    public async Task<Signal<TargetDescription>> DescribeAsync(DestinationTarget target, DestinationInfo destination, IObservabilitySource source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(source);
        var arn = ArnParser.Parse(target.Arn.Value)!;
        var name = target.ResourceName ?? arn.Resource;
        var identifier = Spec.Identifier(arn);
        if (identifier is null)
        {
            return Signal<TargetDescription>.Of(new TargetDescription(name, new Dictionary<string, string> { ["existence"] = "not checked" }));
        }

        var region = arn.Region.Length > 0 ? arn.Region : target.ArnRegion ?? "us-east-1";
        var read = await source.GetResourcePropertiesAsync(region, Spec.CfnType, identifier, cancellationToken).ConfigureAwait(false);

        // API Gateway HTTP and WebSocket APIs are a different resource type than REST APIs.
        if (read.State == SignalState.NotFound && Spec.Service == DestinationService.ApiGateway)
        {
            read = await source.GetResourcePropertiesAsync(region, "AWS::ApiGatewayV2::Api", identifier, cancellationToken).ConfigureAwait(false);
        }

        if (!read.IsAvailable)
        {
            return read.Cast<TargetDescription>();
        }

        var properties = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (cfnKey, displayKey) in Spec.DescribeKeys)
        {
            if (read.Value!.TryGetValue(cfnKey, out var v) && v.Length > 0)
            {
                properties[displayKey] = v;
            }
        }

        return Signal<TargetDescription>.Of(new TargetDescription(name, properties));
    }

    public IReadOnlyList<TargetMetric> Metrics(DestinationTarget target, TargetDescription description)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (Spec.Namespace is null || Spec.Dimensions is null)
        {
            return [];
        }

        var dims = Spec.Dimensions(ArnParser.Parse(target.Arn.Value)!);
        return [.. Spec.Metrics.Select(m => new TargetMetric(m.Key, Spec.Namespace, m.MetricName, dims, m.Statistic))];
    }

    public TargetLogPlan? ErrorLogs(DestinationTarget target, DestinationInfo destination, TargetDescription description) => null;

    public IReadOnlyList<PermissionRequirement> Permissions(DestinationTarget target, DestinationInfo destination, TargetDescription? description)
    {
        ArgumentNullException.ThrowIfNull(target);
        return Spec.Permissions(ArnParser.Parse(target.Arn.Value)!, target.Arn.Value!, description?.Properties);
    }

    public IEnumerable<Finding> Diagnose(TargetObservation o, DestinationObservation destination)
    {
        ArgumentNullException.ThrowIfNull(o);
        ArgumentNullException.ThrowIfNull(destination);
        var f = new List<Finding>();
        var p = Spec.RulePrefix;
        var accepted = AcceptedFor(o.Target, destination);

        if (Spec.Namespace is null)
        {
            f.Add(new($"{p}.metrics-not-inspected", Health.Unknown, Confidence.Confirmed,
                $"{Spec.Kind} metrics are not inspected; delivery is judged from Proxylity's own signals",
                Spec.Note is null ? [] : [new("note", Spec.Note)],
                []));
            return f;
        }

        var values = Spec.Metrics.ToDictionary(m => m, m => o.Metrics.GetValueOrDefault(m.Key));
        if (values.Values.All(v => v?.State == SignalState.NotAccessible))
        {
            f.Add(NotAccessible($"{p}.metrics-not-accessible", $"{Spec.Kind} metrics", values.Values.First()?.DeniedAction ?? "cloudwatch:GetMetricData"));
            return f;
        }

        var problems = false;

        foreach (var (m, v) in values.Where(kv => kv.Key.Role == MetricRole.Throttle && ValueOr0(kv.Value) > 0))
        {
            problems = true;
            f.Add(new($"{p}.throttled", Health.Error, Confidence.Confirmed,
                $"{Spec.Kind} throttled writes",
                [new(m.Label, Count(v!.Value))],
                [$"Check the {Spec.Kind}'s capacity or limits; throttled writes are not stored."]));
        }

        foreach (var (m, v) in values.Where(kv => kv.Key.Role == MetricRole.Failure && ValueOr0(kv.Value) > 0))
        {
            problems = true;
            f.Add(new($"{p}.failures", Health.Error, Confidence.Confirmed,
                $"{Spec.Kind} reported failures",
                [new(m.Label, Count(v!.Value))],
                [$"Open the {Spec.Kind} in the AWS console to see the failure details."]));
        }

        foreach (var (m, v) in values.Where(kv => kv.Key.Role == MetricRole.DownstreamFailure && ValueOr0(kv.Value) > 0))
        {
            f.Add(new($"{p}.downstream-failures", Health.Warning, Confidence.Confirmed,
                $"The {Spec.Kind} accepted data but could not pass some of it on",
                [new(m.Label, Count(v!.Value))],
                ["This happens after delivery from Proxylity succeeded; check the service's own targets or subscribers."]));
        }

        foreach (var (m, v) in values.Where(kv => kv.Key.Role == MetricRole.SuccessRatio && Has(kv.Value) && kv.Value!.Value < 0.999))
        {
            f.Add(new($"{p}.success-below-100", Health.Warning, Confidence.Confirmed,
                $"{m.Label} was below 100%",
                [new("average", Percent(v!.Value))],
                [$"Check the {Spec.Kind}'s error logging for the failing deliveries."]));
        }

        foreach (var (m, v) in values.Where(kv => kv.Key.Role == MetricRole.BacklogAge && ValueOr0(kv.Value) >= 3600))
        {
            f.Add(new($"{p}.backlog", Health.Warning, Confidence.Possible,
                "Messages are waiting a long time to be processed",
                [new(m.Label, $"{v!.Value / 3600:0.#} h")],
                ["Delivery from Proxylity is working, but nothing is consuming the messages quickly enough."]));
        }

        var activityMetric = Spec.Metrics.FirstOrDefault(m => m.Role == MetricRole.Activity);
        var activity = activityMetric is null ? null : values[activityMetric];
        if (activityMetric is not null && Has(activity) && activity!.Value > 0)
        {
            if (!problems)
            {
                f.Add(new($"{p}.receiving", Health.Healthy, Confidence.Likely,
                    $"The {Spec.Kind} is receiving data with no throttling or failures",
                    [new(activityMetric.Label, Count(activity.Value))],
                    []));
            }
        }
        else if (Has(accepted) && accepted!.Value > 0)
        {
            f.Add(new($"{p}.accepted-not-received", Health.Warning, Confidence.Possible,
                $"Packets were accepted for this destination but the {Spec.Kind} shows no incoming data",
                [new("accepted", Units(accepted.Value)), new(activityMetric?.Label ?? "activity", "0")],
                [
                    "Check the destination log and the role's permissions (below).",
                    "Accepted means queued for delivery, not delivered; batching can delay delivery briefly.",
                ]));
        }
        else
        {
            f.Add(new($"{p}.no-activity", Health.Unknown, Confidence.Confirmed,
                $"No incoming data at the {Spec.Kind} in the window",
                [new(activityMetric?.Label ?? "activity", "0")],
                []));
        }

        return f;
    }

    private static IReadOnlyList<KeyValuePair<string, string>> Dim(string name, string value) => [new(name, value)];

    private static string LogGroupArn(ParsedArn a, string name) => $"arn:{a.Partition}:logs:{a.Region}:{a.AccountId}:log-group:{name}";

    private static readonly Dictionary<string, string> NoKeys = new(StringComparer.Ordinal);

    /// <summary>A concrete name used where a permission applies to objects or streams that are created at run time.</summary>
    public const string ProbeName = "proxylity-cli-permission-check";

    /// <summary>The supported services. Required actions are those listed on each service's Proxylity destination page.</summary>
    public static IReadOnlyList<ServiceSpec> Specs { get; } =
    [
        new(DestinationService.StepFunctions, "stepfunctions", "state machine", "AWS::StepFunctions::StateMachine",
            a => $"arn:{a.Partition}:states:{a.Region}:{a.AccountId}:{a.Resource}",
            new Dictionary<string, string> { ["StateMachineType"] = "type" },
            "AWS/States",
            a => Dim("StateMachineArn", $"arn:{a.Partition}:states:{a.Region}:{a.AccountId}:{a.Resource}"),
            [
                new("states.started", "ExecutionsStarted", "Sum", MetricRole.Activity, "executions started"),
                new("states.failed", "ExecutionsFailed", "Sum", MetricRole.Failure, "executions failed"),
                new("states.timedOut", "ExecutionsTimedOut", "Sum", MetricRole.Failure, "executions timed out"),
                new("states.throttled", "ExecutionThrottled", "Sum", MetricRole.Throttle, "executions throttled"),
                new("states.aborted", "ExecutionsAborted", "Sum", MetricRole.Info, "executions aborted"),
            ],
            (a, arn, d) =>
            [
                new(["states:DescribeStateMachine",
                     string.Equals(d?.GetValueOrDefault("type"), "EXPRESS", StringComparison.OrdinalIgnoreCase) ? "states:StartSyncExecution" : "states:StartExecution"],
                    arn),
            ]),

        new(DestinationService.Firehose, "firehose", "Firehose stream", "AWS::KinesisFirehose::DeliveryStream",
            a => a.Resource.Split('/', 2) is [_, var n] ? n : null,
            new Dictionary<string, string> { ["DeliveryStreamType"] = "type" },
            "AWS/Firehose",
            a => Dim("DeliveryStreamName", a.Resource.Split('/', 2)[^1]),
            [
                new("firehose.incoming", "IncomingRecords", "Sum", MetricRole.Activity, "incoming records"),
                new("firehose.throttled", "ThrottledRecords", "Sum", MetricRole.Throttle, "throttled records"),
                new("firehose.s3Success", "DeliveryToS3.Success", "Average", MetricRole.SuccessRatio, "Delivery from Firehose to S3"),
                new("firehose.s3Freshness", "DeliveryToS3.DataFreshness", "Maximum", MetricRole.Info, "data freshness"),
            ],
            (a, arn, d) => [new(["firehose:PutRecord"], $"arn:{a.Partition}:firehose:{a.Region}:{a.AccountId}:{a.Resource}")]),

        new(DestinationService.Sqs, "sqs", "SQS queue", "AWS::SQS::Queue",
            a => $"https://sqs.{a.Region}.amazonaws.com/{a.AccountId}/{a.Resource}",
            new Dictionary<string, string> { ["FifoQueue"] = "fifo" },
            "AWS/SQS",
            a => Dim("QueueName", a.Resource),
            [
                new("sqs.sent", "NumberOfMessagesSent", "Sum", MetricRole.Activity, "messages sent"),
                new("sqs.oldestAge", "ApproximateAgeOfOldestMessage", "Maximum", MetricRole.BacklogAge, "oldest message"),
                new("sqs.visible", "ApproximateNumberOfMessagesVisible", "Maximum", MetricRole.Info, "messages waiting"),
            ],
            (a, arn, d) => [new(["sqs:GetQueueUrl", "sqs:SendMessage"], arn)]),

        new(DestinationService.Sns, "sns", "SNS topic", "AWS::SNS::Topic",
            a => $"arn:{a.Partition}:sns:{a.Region}:{a.AccountId}:{a.Resource}",
            new Dictionary<string, string> { ["FifoTopic"] = "fifo" },
            "AWS/SNS",
            a => Dim("TopicName", a.Resource),
            [
                new("sns.published", "NumberOfMessagesPublished", "Sum", MetricRole.Activity, "messages published"),
                new("sns.failed", "NumberOfNotificationsFailed", "Sum", MetricRole.DownstreamFailure, "notifications failed"),
            ],
            (a, arn, d) => [new(["sns:Publish"], arn)]),

        new(DestinationService.Kinesis, "kinesis", "Kinesis stream", "AWS::Kinesis::Stream",
            a => a.Resource.Split('/', 2) is [_, var n] ? n : null,
            new Dictionary<string, string> { ["ShardCount"] = "shards" },
            "AWS/Kinesis",
            a => Dim("StreamName", a.Resource.Split('/', 2)[^1]),
            [
                new("kinesis.incoming", "IncomingRecords", "Sum", MetricRole.Activity, "incoming records"),
                new("kinesis.throttled", "WriteProvisionedThroughputExceeded", "Sum", MetricRole.Throttle, "throughput exceeded"),
            ],
            (a, arn, d) => [new(["kinesis:PutRecords"], arn)]),

        new(DestinationService.DynamoDb, "dynamodb", "DynamoDB table", "AWS::DynamoDB::Table",
            a => a.Resource.Split('/', 2) is [_, var n] ? n : null,
            new Dictionary<string, string> { ["BillingMode"] = "billing" },
            "AWS/DynamoDB",
            a => Dim("TableName", a.Resource.Split('/', 2)[^1]),
            [
                new("dynamodb.writes", "ConsumedWriteCapacityUnits", "Sum", MetricRole.Activity, "write capacity used"),
                new("dynamodb.throttled", "WriteThrottleEvents", "Sum", MetricRole.Throttle, "write throttle events"),
            ],
            (a, arn, d) => [new(["dynamodb:DescribeTable", "dynamodb:BatchWriteItem"], arn)]),

        new(DestinationService.CloudWatchLogs, "logs", "log group", "AWS::Logs::LogGroup",
            a => a.Resource.StartsWith("log-group:", StringComparison.Ordinal) ? a.Resource["log-group:".Length..].TrimEnd('*').TrimEnd(':') : null,
            new Dictionary<string, string> { ["RetentionInDays"] = "retention days" },
            "AWS/Logs",
            a => Dim("LogGroupName", a.Resource["log-group:".Length..].TrimEnd('*').TrimEnd(':')),
            [new("logs.incoming", "IncomingLogEvents", "Sum", MetricRole.Activity, "incoming log events")],
            (a, arn, d) => [new(["logs:CreateLogStream", "logs:PutLogEvents"], LogGroupArn(a, a.Resource["log-group:".Length..].TrimEnd('*').TrimEnd(':')) + ":log-stream:" + ProbeName)]),

        new(DestinationService.S3, "s3", "S3 bucket", "AWS::S3::Bucket",
            a => a.Resource.Split('/', 2)[0],
            NoKeys,
            null, null, [],
            (a, arn, d) => [new(["s3:PutObject"], arn.Contains('/', StringComparison.Ordinal) ? arn + ProbeName : arn + "/" + ProbeName)],
            "S3 request metrics are only available when configured on the bucket."),

        new(DestinationService.EventBridge, "eventbridge", "event bus", "AWS::Events::EventBus",
            a => a.Resource.Split('/', 2) is [_, var n] ? n : null,
            NoKeys,
            null, null, [],
            (a, arn, d) => [new(["events:PutEvents"], arn)],
            "EventBridge metrics are reported per rule, not per bus."),

        new(DestinationService.ApiGateway, "apigateway", "API", "AWS::ApiGateway::RestApi",
            a => a.Resource.Split('/')[0],
            new Dictionary<string, string> { ["Name"] = "name" },
            null, null, [],
            (a, arn, d) => [new(["execute-api:Invoke"], arn)],
            "API Gateway metrics are keyed by API name and stage; check the API's execution logs."),
    ];

    internal static string Describe(IReadOnlyDictionary<string, string> p) =>
        string.Join(" · ", p.Select(kv => string.Create(CultureInfo.InvariantCulture, $"{kv.Key} {kv.Value}")));
}
