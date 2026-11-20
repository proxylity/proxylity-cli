# IAM permissions for the CLI

The CLI only reads. It never creates, changes, or invokes anything, and it never assumes the roles it checks.
Grant the identity that runs it the actions below. Anything missing is reported as "not accessible" for the
affected signal only; the rest of the command still works.

## Discovery (`list`, `inspect`, and every other command)

| Action | Used for |
|---|---|
| `cloudformation:ListStacks` | Finding stacks |
| `cloudformation:ListStackResources` | Finding Proxylity resources in a stack |
| `cloudformation:DescribeStacks` | Stack parameters, and outputs of nested stacks |
| `cloudformation:GetTemplate` | The processed template |

## Observation (`diagnose`, `metrics`, `logs`)

| Action | Used for |
|---|---|
| `cloudwatch:GetMetricData` | Proxylity metrics and each destination service's own metrics |
| `logs:FilterLogEvents` | Listener and destination log groups, and target runtime logs |
| `lambda:GetFunction` | Lambda function state and configuration |
| `cloudformation:GetResource` | Whether a target resource exists, and its basic configuration (the [Cloud Control API](https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/security.html) uses the `cloudformation:` prefix) |

Cloud Control also requires the read permission of the resource type it reads, for example
`sqs:GetQueueAttributes`, `states:DescribeStateMachine`, `firehose:DescribeDeliveryStream`,
`sns:GetTopicAttributes`, `kinesis:DescribeStreamSummary`, `dynamodb:DescribeTable`, `events:DescribeEventBus`,
`logs:DescribeLogGroups`, `apigateway:GET`, and `lambda:GetMicrovmImage` for Lambda MicroVM images. The AWS
managed policy `ReadOnlyAccess` covers these.

## Role checks (`diagnose`)

| Action | Used for |
|---|---|
| `iam:GetRole` | Whether a destination or listener role exists, and what its trust policy requires |
| `iam:SimulatePrincipalPolicy` | Whether a role's policies allow what Proxylity needs, without assuming it |
| `s3:GetObject` on `arn:aws:s3:::proxylity-config-*/ACCOUNT_ID/customer-config.json` | Optional. Your Proxylity account configuration, to compare trust policies, the service token and the API key with their current values |

Only roles in the account being inspected are checked. Reading the account configuration is optional: without
it, the comparisons are skipped and everything else still runs. Values read from it are compared in memory (the
API key is reduced to a one-way fingerprint as soon as it is read) and are never stored, cached, or shown. The local cache of discovery
results holds one-way fingerprints of the `ApiKey` and `ServiceToken` values written in your own templates, never
the values.

## Checking your permissions (`check-access`)

`check-access` makes one harmless read call per action listed above, using made-up resource names where a
resource is needed, and reports each action as allowed, denied, or inconclusive. It does not read the account
configuration object, so `s3:GetObject` is listed as not tested; `diagnose` reports whether that object is
readable. The command exits 0 when it ran, even if some actions are denied.

## Example policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:ListStacks",
        "cloudformation:ListStackResources",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
        "cloudwatch:GetMetricData",
        "logs:FilterLogEvents",
        "lambda:GetFunction",
        "cloudformation:GetResource",
        "iam:GetRole",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::proxylity-config-*/ACCOUNT_ID/customer-config.json"
    }
  ]
}
```

Add the resource-type read permissions listed above for the services you use, or attach `ReadOnlyAccess`.
