namespace Proxylity.Cli.Core.Model;

/// <summary>Parses ARNs and identifies the destination service from the service and resource fields.</summary>
public static class ArnParser
{
    public static ParsedArn? Parse(string? arn)
    {
        if (string.IsNullOrWhiteSpace(arn))
        {
            return null;
        }

        var parts = arn.Split(':', 6);
        if (parts.Length != 6 || parts[0] != "arn")
        {
            return null;
        }

        return new ParsedArn(parts[1], parts[2], parts[3], parts[4], parts[5]);
    }

    public static DestinationService ServiceOf(ParsedArn arn)
    {
        ArgumentNullException.ThrowIfNull(arn);
        var resource = arn.Resource;
        return arn.Service switch
        {
            "lambda" when resource.StartsWith("function:", StringComparison.Ordinal) => DestinationService.Lambda,
            "lambda" when resource.StartsWith("microvm-image:", StringComparison.Ordinal) => DestinationService.LambdaMicrovm,
            "states" => DestinationService.StepFunctions,
            "events" => DestinationService.EventBridge,
            "sqs" => DestinationService.Sqs,
            "sns" => DestinationService.Sns,
            "dynamodb" => DestinationService.DynamoDb,
            "s3" => DestinationService.S3,
            "firehose" => DestinationService.Firehose,
            // Tolerated: some documentation shows the Firehose ARN with the "logs" service.
            "logs" when resource.StartsWith("deliverystream/", StringComparison.Ordinal) => DestinationService.Firehose,
            "logs" => DestinationService.CloudWatchLogs,
            "kinesis" => DestinationService.Kinesis,
            "execute-api" => DestinationService.ApiGateway,
            "iot" => DestinationService.IotData,
            "geo" => DestinationService.LocationTracker,
            _ => DestinationService.Unknown,
        };
    }

    /// <summary>A short, human-meaningful name for the target resource (function name, queue name, ...).</summary>
    public static string? ResourceNameOf(ParsedArn arn, DestinationService service)
    {
        ArgumentNullException.ThrowIfNull(arn);
        var r = arn.Resource;
        return service switch
        {
            DestinationService.Lambda => After(r, "function:") is { } f ? f.Split(':')[0] : null,
            DestinationService.LambdaMicrovm => After(r, "microvm-image:") is { } m ? m.Split(':')[0] : null,
            DestinationService.StepFunctions => After(r, "stateMachine:") ?? After(r, "express:"),
            DestinationService.EventBridge => After(r, "event-bus/"),
            DestinationService.Sqs or DestinationService.Sns => r,
            DestinationService.DynamoDb => After(r, "table/"),
            DestinationService.S3 => r.Split('/')[0],
            DestinationService.Firehose => After(r, "deliverystream/"),
            DestinationService.Kinesis => After(r, "stream/"),
            DestinationService.CloudWatchLogs => After(r, "log-group:") is { } g ? g.TrimEnd('*').TrimEnd(':') : null,
            DestinationService.ApiGateway => r.Split('/')[0],
            DestinationService.IotData => After(r, "topic/"),
            DestinationService.LocationTracker => After(r, "tracker/"),
            _ => null,
        };
    }

    private static string? After(string value, string prefix) =>
        value.StartsWith(prefix, StringComparison.Ordinal) ? value[prefix.Length..] : null;
}
