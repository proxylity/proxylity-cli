namespace Proxylity.Cli.Core.Templates;

/// <summary>
/// Computes <c>Fn::GetAtt</c> values that can be derived from a resource's physical ID, without calling
/// the service. Anything not listed is reported as unresolved rather than guessed.
/// </summary>
internal static class AttributeProviders
{
    public static string? TryGet(string resourceType, string attribute, string physicalId, ResolutionContext c)
    {
        var p = c.Partition;
        var r = c.Region;
        var a = c.AccountId;
        return (resourceType, attribute) switch
        {
            ("AWS::Lambda::Function", "Arn") => $"arn:{p}:lambda:{r}:{a}:function:{physicalId}",
            ("AWS::SQS::Queue", "Arn") => QueueNameFromUrl(physicalId) is { } q ? $"arn:{p}:sqs:{r}:{a}:{q}" : null,
            ("AWS::SQS::Queue", "QueueName") => QueueNameFromUrl(physicalId),
            ("AWS::SNS::Topic", "TopicArn") => physicalId,
            ("AWS::SNS::Topic", "TopicName") => physicalId[(physicalId.LastIndexOf(':') + 1)..],
            ("AWS::S3::Bucket", "Arn") => $"arn:{p}:s3:::{physicalId}",
            ("AWS::DynamoDB::Table", "Arn") => $"arn:{p}:dynamodb:{r}:{a}:table/{physicalId}",
            ("AWS::Kinesis::Stream", "Arn") => $"arn:{p}:kinesis:{r}:{a}:stream/{physicalId}",
            ("AWS::KinesisFirehose::DeliveryStream", "Arn") => $"arn:{p}:firehose:{r}:{a}:deliverystream/{physicalId}",
            ("AWS::StepFunctions::StateMachine", "Arn") => physicalId,
            ("AWS::StepFunctions::StateMachine", "Name") => physicalId[(physicalId.LastIndexOf(':') + 1)..],
            ("AWS::Events::EventBus", "Arn") => $"arn:{p}:events:{r}:{a}:event-bus/{physicalId}",
            ("AWS::Logs::LogGroup", "Arn") => $"arn:{p}:logs:{r}:{a}:log-group:{physicalId}:*",
            ("AWS::Lambda::MicrovmImage", "ImageArn" or "Arn") when physicalId.StartsWith("arn:", StringComparison.Ordinal) => physicalId,
            ("AWS::Location::Tracker", "Arn" or "TrackerArn") => $"arn:{p}:geo:{r}:{a}:tracker/{physicalId}",
            ("AWS::Location::Tracker", "TrackerName") => physicalId,
            ("AWS::CloudFormation::Stack", _) when attribute.StartsWith("Outputs.", StringComparison.Ordinal)
                && c.NestedStackOutputs.TryGetValue(physicalId, out var outputs)
                && outputs.TryGetValue(attribute["Outputs.".Length..], out var output) => output,
            // Assumes the role has no IAM path, which is the common case.
            ("AWS::IAM::Role", "Arn") => $"arn:{p}:iam::{a}:role/{physicalId}",
            (_, "Id") when resourceType.StartsWith("Custom::ProxylityUdpGatewayListener", StringComparison.Ordinal) => physicalId,
            _ => null,
        };
    }

    private static string? QueueNameFromUrl(string url)
    {
        var slash = url.LastIndexOf('/');
        return slash >= 0 && slash < url.Length - 1 ? url[(slash + 1)..] : null;
    }
}
