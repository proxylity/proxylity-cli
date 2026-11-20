# Public Contract

The facts about Proxylity UDP Gateway that this CLI depends on. Every entry links to public
documentation (base URL: <https://www.proxylity.com/docs/>). Do not add anything that is not publicly
documented or observable in the user's own AWS account.

Templates deployed before a documentation correction can contain older forms. The CLI recognizes those and
reports them rather than failing; see [Older template forms](#older-template-forms).

## 1. CloudFormation resource model

Source: [cloudformation/index.html](https://www.proxylity.com/docs/cloudformation/index.html),
[listener](https://www.proxylity.com/docs/cloudformation/listener.html),
[destination](https://www.proxylity.com/docs/cloudformation/destination.html),
[role](https://www.proxylity.com/docs/cloudformation/role.html),
[destination ARN](https://www.proxylity.com/docs/cloudformation/destination-arn.html),
[packet source](https://www.proxylity.com/docs/cloudformation/packetsource.html)

| Fact | Notes |
|---|---|
| Listener resource type is `Custom::ProxylityUdpGatewayListener` | |
| Other resource types: `Custom::ProxylityUdpGatewayDestinationArn`, `Custom::ProxylityUdpGatewayPacketSource` | See the index page for their purpose |
| A listener declares its destinations inline in its `Destinations` property | Each destination is a configuration type, not a separate resource |
| A listener has an optional `Name`; if omitted, it is generated from the stack name, the resource's logical ID and a random 8-character suffix, joined with hyphens | Unique within the AWS account; it can't be changed after creation |
| The listener name is the value of `Ref` and `Fn::GetAtt Id`, the CloudFormation physical ID, and the `Listener` metric dimension value | The CLI reads it from the physical ID (ListStackResources) |
| Listener properties relevant to observability: `MetricsEnabled`, `LogGroupName`, `Role` | Defaults: `MetricsEnabled` is `false`; `LogGroupName` is optional; `Role` is required when either is set |
| Listener `Protocols` is exactly one of the documented protocols (for example `udp`, `dtls`, `wg`) | The CLI displays the value as written and does not interpret it |
| Listener `ClientRestrictions` is a single object with `Networks` and `Domains` lists; absent or empty means all traffic is blocked | [clientrestriction](https://www.proxylity.com/docs/cloudformation/clientrestriction.html) |
| Listener return values include `Id`, `Port`, `Domain` and `DestinationNames` (destination names in declaration order); `Fn::GetAtt` does not return `Name` | |
| Destination properties: `Name`, `Description`, `Role`, `Batching`, `DestinationArn`, `MetricsEnabled`, `LogGroupName`, `Formatter`, `FilterExpression`, `Arguments` | `Arguments` holds service-specific settings |
| Destination `Name` is unique within the AWS account; if omitted it is `dstn-<stack name>-<listener logical ID>-<n>`, where n counts the listener's inline destinations from zero | References to existing destinations by name are not counted. The CLI labels derived names as such |
| A `Destinations` entry can be an object (an inline destination) or a string (a reference to an existing destination by name) | |
| `Role` has `Arn` and an optional `Duration`; `RoleArn` is not a valid property name | [role](https://www.proxylity.com/docs/cloudformation/role.html) |
| `Batching` has `Count` (default 100, 1 to 1,000), `TimeoutInSeconds` (default 0.25) and `SizeInMB` (default 1.0) | [batching](https://www.proxylity.com/docs/cloudformation/batching.html) |
| `DestinationArn` is a single ARN string, or a map of AWS Region name (or `*`) to ARN | All ARNs in a map must be the same AWS service |
| A region map is resolved in order: the entry for the ingress region, then the `*` entry, then the closest region by latency; keys need not match the ARN's region | |
| A single ARN may use `*` as its region and then resolves to the ingress region | The CLI inspects such targets in the region it runs against and says so |
| `Custom::ProxylityUdpGatewayDestinationArn` adds an ARN for one ingress region key to an existing destination | The CLI merges these into the destination's targets |
| A Packet Source's `Ref` is `<listener name>|<suffix>`, which is also its `PacketSource` metric dimension value | [packetsource](https://www.proxylity.com/docs/cloudformation/packetsource.html) |
| Destination `Formatter` is one of `base64`, `hex`, `utf8`, `ascii`, `coap`, `coap+`, `syslog` | |
| `FilterExpression` drops non-matching packets for that destination only | |
| Multiple destinations on one listener ("composite destinations") are independent | [composite-destinations](https://www.proxylity.com/docs/destinations/composite-destinations.html) |
| Listener and destination `Role` is an IAM role that Proxylity assumes | Listener role is for metrics and logs only |
| Deployment can be through CloudFormation, SAM transform, CDK, or Terraform | CDK synthesizes to CloudFormation |

### Properties that are secrets

These properties hold secrets or credentials according to the documentation. The CLI never prints
their values:

`ApiKey`, `Psks`, `UnknownPeerPreSharedKey`, and the `SharedSecret` of a WireGuard peer.

## 2. Supported destination services

Source: [destinations/*](https://www.proxylity.com/docs/) pages (one per service).

| Service | ARN shape (service/resource) | Page |
|---|---|---|
| AWS Lambda function | `arn:aws:lambda:{region}:{account}:function:{name and qualifier}` | [lambda](https://www.proxylity.com/docs/destinations/lambda.html) |
| Lambda MicroVM image | `arn:aws:lambda:{region}:{account}:microvm-image:{image}` | [lambda-microvm](https://www.proxylity.com/docs/destinations/lambda-microvm.html) |
| Step Functions state machine | `arn:aws:states:{region}:{account}:stateMachine:{name}` | [step-functions](https://www.proxylity.com/docs/destinations/step-functions.html) |
| EventBridge event bus | `arn:aws:events:{region}:{account}:event-bus/{name}` | [event-bridge](https://www.proxylity.com/docs/destinations/event-bridge.html) |
| SQS queue | `arn:aws:sqs:{region}:{account}:{name}` | [sqs](https://www.proxylity.com/docs/destinations/sqs.html) |
| SNS topic | `arn:aws:sns:{region}:{account}:{name}` | [sns](https://www.proxylity.com/docs/destinations/sns.html) |
| DynamoDB table | `arn:aws:dynamodb:{region}:{account}:table/{name}` | [dynamodb](https://www.proxylity.com/docs/destinations/dynamodb.html) |
| S3 bucket | `arn:aws:s3:::{bucket}[/{prefix}]` | [s3](https://www.proxylity.com/docs/destinations/s3.html) |
| Data Firehose delivery stream | `arn:aws:firehose:{region}:{account}:deliverystream/{name}` | [firehose](https://www.proxylity.com/docs/destinations/firehose.html) |
| Kinesis data stream | `arn:aws:kinesis:{region}:{account}:stream/{name}` | [kinesis](https://www.proxylity.com/docs/destinations/kinesis.html) |
| CloudWatch Logs log group | `arn:aws:logs:{region}:{account}:log-group:{name}` | [logs](https://www.proxylity.com/docs/destinations/logs.html) |
| API Gateway | `arn:aws:execute-api:{region}:{account}:{api-id}/{stage}/{method}/{path}` | [api-gateway](https://www.proxylity.com/docs/destinations/api-gateway.html) |
| External (non-AWS) services | via API Gateway | [integrating-outside-aws](https://www.proxylity.com/docs/destinations/integrating-outside-aws.html) |

The pages may document further qualifiers and details per service; the adapter for each service reads
its own page and records any additional facts it relies on here before it is implemented.

## 3. CloudWatch metrics published by UDP Gateway

Source: [metrics.html](https://www.proxylity.com/docs/metrics.html)

| Fact | Notes |
|---|---|
| Namespace is exactly `Proxylity/UDP Gateway` (case-sensitive, contains a space) | |
| Metrics are published into the customer's own AWS account | Requires `MetricsEnabled: true` and a role granting `cloudwatch:PutMetricData` |
| Each metric has exactly one dimension: `Listener`, `Destination`, or `PacketSource` | No combined dimensions, no account totals |
| Dimension value is the resource's name, which is the value returned by `Ref` (for a Packet Source, `<listener name>|<suffix>`), not its ARN, port, domain, or template logical ID | |
| Listener and destination metrics: `IngressPackets`, `IngressBytes`, `EgressPackets`, `EgressBytes`, `FilteredPackets`, `FilteredBytes`, `Errors` | Packet Sources publish only `EgressPackets` and `EgressBytes` |
| `*Packets` metrics are size-weighted: each packet contributes `max(1, ceil(bytes / 1024))` | Not raw packet counts |
| Telemetry is published as interval totals (about 10 seconds), standard resolution | Use `Sum` with periods of 60 seconds or longer |
| Only resources with telemetry in an interval publish data; idle resources do not publish zero samples | Absence of data is not evidence of health or of failure |
| Listener and destination counters overlap and must not be summed as unique traffic | |
| Ingress/egress ratios are not delivery-success rates | |
| Destination ingress means accepted into the delivery queue, not confirmed delivery to the AWS service | |
| A one-way destination (for example SQS) produces no destination egress | Zero egress is expected there |
| No batch-count metric is published | |
| Listener and Packet Source metrics are published in the region of the gateway instance handling traffic; destination metrics in the region of the resolved destination ARN | Inspect each relevant region |
| `Errors` counts reported error occurrences, independent of whether logging is enabled | Warnings and info messages excluded |
| Listener `FilteredPackets` includes firewall-denied (Client Restrictions) and suspended-listener datagrams | Destination `FilteredPackets` is `FilterExpression` rejections |

## 4. CloudWatch Logs written by UDP Gateway

Source: [listener](https://www.proxylity.com/docs/cloudformation/listener.html),
[destination](https://www.proxylity.com/docs/cloudformation/destination.html),
[metrics](https://www.proxylity.com/docs/metrics.html)

| Fact | Notes |
|---|---|
| `LogGroupName` names an existing log group in the customer's account | Listener and destination each have their own setting |
| Logging is independent of `MetricsEnabled` | |
| Listener logs are diagnostic messages; destination logs are error and warning messages during delivery | Useful for role permission problems, malformed destination ARNs, service-specific delivery failures |
| Identical log messages are deduplicated within short time windows, and each line shows an occurrence count such as `[x12]` | [destinations](https://www.proxylity.com/docs/destinations/index.html). The CLI reads the leading count; lines that do not match are shown with an unknown level |
| UDP Gateway creates log streams in the group and writes events | Log content can include data derived from network traffic and must be treated as untrusted |

## 5. Access and permissions

Source: [access-and-permissions](https://www.proxylity.com/docs/access-and-permissions.html)

The CLI does not use Proxylity credentials or call Proxylity services. It uses only the user's own AWS
credentials and read-only AWS API calls (see [permissions.md](permissions.md)).

| Fact | Notes |
|---|---|
| The account configuration object is `s3://proxylity-config-${AWS::Region}/${AWS::AccountId}/customer-config.json`, readable only by that account | Regional settings keyed by AWS Region (`ServiceToken`, `ServiceRole`); account settings under `Account` (`ExternalId`, `ApiKey`). Reading it is optional (`diagnose` only, to compare values with your templates and roles). The API key is reduced to a one-way fingerprint as soon as it is read and is never printed or stored. `check-access` does not read it |
| Proxylity delivers by assuming a role you define, per destination; listener metrics and logs use the listener's `Role` | |
| Destination role trust policies trust the regional `ServiceRole` from the account configuration, with `StringEquals` on `sts:ExternalId` = `Account.ExternalId` | The CLI checks the trust policy's structure (an AWS principal may assume it; every such statement requires `sts:ExternalId`). When it can read the account configuration, it also compares the external ID and the principal with those values |
| Roles that publish metrics need `cloudwatch:PutMetricData` with the condition `cloudwatch:namespace` = `Proxylity/UDP Gateway` | [metrics](https://www.proxylity.com/docs/metrics.html) |
| Roles that write logs need `logs:CreateLogStream` and `logs:PutLogEvents` on the log group's streams | [listener](https://www.proxylity.com/docs/cloudformation/listener.html), [destination](https://www.proxylity.com/docs/cloudformation/destination.html) |

### Delivery actions per service

From the "Actions (required Permissions)" line of each destination page. The CLI simulates these against the
destination role.

| Service | Actions |
|---|---|
| Lambda | `lambda:InvokeFunction` |
| Lambda MicroVM | `lambda:RunMicrovm`, `lambda:CreateMicrovmAuthToken`, `lambda:GetMicrovmImage`, `lambda:GetMicrovmImageVersion` on the image; `iam:PassRole` when `ExecutionRoleArn` is set. (`GetMicrovm`, `ResumeMicrovm`, `TerminateMicrovm` apply to run-time MicroVM ARNs and are not simulated.) |
| Step Functions | `states:DescribeStateMachine`, plus `states:StartSyncExecution` (EXPRESS) or `states:StartExecution` (STANDARD) |
| EventBridge | `events:PutEvents` |
| SQS | `sqs:GetQueueUrl`, `sqs:SendMessage` |
| SNS | `sns:Publish` |
| DynamoDB | `dynamodb:DescribeTable`, `dynamodb:BatchWriteItem` |
| S3 | `s3:PutObject` |
| Data Firehose | `firehose:PutRecord` |
| Kinesis Data Streams | `kinesis:PutRecords` |
| CloudWatch Logs | `logs:CreateLogStream`, `logs:PutLogEvents` |
| API Gateway | `execute-api:Invoke` |

### Lambda MicroVM destinations

Source: [lambda-microvm](https://www.proxylity.com/docs/destinations/lambda-microvm.html)

| Fact | Notes |
|---|---|
| The destination is an image; MicroVMs are started from it when packets arrive | |
| An ARN without a version uses the latest active image version; a version suffix pins it | |
| Arguments used by the CLI: `ExecutionRoleArn`, `RuntimeLogGroupName`, `IdleDurationSeconds`, `UseTenantIdForLogStreamName`, `TenantId`/`TenantIdExpression` (presence only), `EgressNetworkConnectorArns` (count only) | `RunHookExtraData` is never read |
| Runtime output reaches CloudWatch Logs only with an execution role; default group `/aws/lambda-microvms/{image name}`; a missing group drops output without an error | |
| MicroVMs are request/response, so destination replies show MicroVMs are answering | |

## 6. AWS service facts used by adapters

These come from AWS documentation rather than Proxylity documentation. Each row lists only what the linked
page states. Proxylity's own metrics are in [section 3](#3-cloudwatch-metrics-published-by-udp-gateway).

Service metrics are read with `cloudwatch:GetMetricData` in the region of the destination ARN. Metrics are
published only while the resource is active, so a missing metric is not evidence of a failure.

| Adapter | Namespace | Metrics the CLI reads | Dimensions | Source |
|---|---|---|---|---|
| Lambda function | `AWS/Lambda` | `Invocations`, `Errors`, `Throttles`, `Duration`, `ConcurrentExecutions` | `FunctionName` (all versions and aliases) or `Resource` (a version or alias) | [metrics types](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html), [viewing metrics](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-view.html) |
| Step Functions state machine | `AWS/States` | `ExecutionsStarted`, `ExecutionsFailed`, `ExecutionsTimedOut`, `ExecutionThrottled`, `ExecutionsAborted` | `StateMachineArn` | [CloudWatch metrics](https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html) |
| Data Firehose delivery stream | `AWS/Firehose` | `IncomingRecords`, `ThrottledRecords`, `DeliveryToS3.Success`, `DeliveryToS3.DataFreshness` | `DeliveryStreamName` | [CloudWatch metrics](https://docs.aws.amazon.com/firehose/latest/dev/monitoring-with-cloudwatch-metrics.html) |
| SQS queue | `AWS/SQS` | `NumberOfMessagesSent`, `ApproximateAgeOfOldestMessage`, `ApproximateNumberOfMessagesVisible` | `QueueName` | [available metrics](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html) |
| SNS topic | `AWS/SNS` | `NumberOfMessagesPublished`, `NumberOfNotificationsFailed` | `TopicName` | [SNS metrics](https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html) |
| Kinesis data stream | `AWS/Kinesis` | `IncomingRecords`, `WriteProvisionedThroughputExceeded` | `StreamName` | [Kinesis metrics](https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html) |
| DynamoDB table | `AWS/DynamoDB` | `ConsumedWriteCapacityUnits`, `WriteThrottleEvents` | `TableName` (table only, not its indexes) | [metrics and dimensions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html) |
| CloudWatch Logs log group | `AWS/Logs` | `IncomingLogEvents` | `LogGroupName` | [Logs metrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html) |

Notes from those pages that the CLI relies on:

- Lambda `Errors` does not count throttled requests, and `Throttles` requests are not counted as `Invocations`.
- Lambda `Duration` is reported in milliseconds and supports `Average` and `Maximum` statistics.
- Step Functions `ExecutionThrottled` is emitted only when throttling happens.
- Firehose `DeliveryToS3.Success` and `DeliveryToS3.DataFreshness` describe delivery from Firehose to S3 when S3 is the stream's destination.
- SQS `ApproximateAgeOfOldestMessage` is reported only if the queue holds at least one active message.
- SNS `NumberOfNotificationsFailed` excludes messages rejected by subscription filter policies.

Adapters with no metric row:

| Adapter | What the CLI does |
|---|---|
| S3 bucket, EventBridge event bus, API Gateway | Metrics are not inspected. Delivery is judged from Proxylity's own metrics, the target's existence, and the role check |
| Lambda MicroVM image | Lambda MicroVM images have no CloudWatch metrics inspected. Delivery is judged from Proxylity's destination metrics, the image state, and the runtime log group |

## Older template forms

Earlier versions of the documentation showed some forms that are not valid. Templates written from them may
still exist, so the CLI recognizes them and reports what they mean instead of failing.

| Form | What the CLI does |
|---|---|
| `Role: { RoleArn: ... }` | Reports that no role is configured (the property is `Arn`) |
| `ClientRestrictions` written as a list | Reports that the template cannot be deployed as written |
| A Firehose ARN with the `logs` service and a `deliverystream/` resource | Treats it as a Firehose target |
