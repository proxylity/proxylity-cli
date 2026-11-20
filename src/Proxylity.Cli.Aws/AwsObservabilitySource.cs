using System.Collections.Concurrent;
using System.Text.Json;
using Amazon;
using Amazon.CloudControlApi;
using Amazon.CloudControlApi.Model;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.CloudWatch;
using Amazon.CloudWatch.Model;
using Amazon.CloudWatchLogs;
using Amazon.CloudWatchLogs.Model;
using Amazon.Lambda;
using Amazon.Lambda.Model;
using Amazon.Runtime;
using Proxylity.Cli.Core.Discovery;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;
using CoreLogEvent = Proxylity.Cli.Core.Observation.LogEvent;
using CloudControlNotFound = Amazon.CloudControlApi.Model.ResourceNotFoundException;
using LambdaNotFound = Amazon.Lambda.Model.ResourceNotFoundException;
using LogsNotFound = Amazon.CloudWatchLogs.Model.ResourceNotFoundException;

namespace Proxylity.Cli.Aws;

/// <summary>
/// Read-only CloudWatch (GetMetricData), CloudWatch Logs (FilterLogEvents) and Lambda (GetFunction) access.
/// Clients are created per region on demand. Failures become signal states, never exceptions, so one
/// missing permission degrades only the affected signal. Credential problems still throw.
/// </summary>
public sealed class AwsObservabilitySource : IObservabilitySource, IDisposable
{
    private const int MaxLogPages = 10;

    private readonly ConcurrentDictionary<string, AmazonCloudWatchClient> _metrics = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AmazonCloudWatchLogsClient> _logs = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AmazonLambdaClient> _lambda = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AmazonCloudControlApiClient> _cloudControl = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AmazonS3Client> _s3 = new(StringComparer.Ordinal);
    private AmazonIdentityManagementServiceClient? _iam;

    public async Task<IReadOnlyDictionary<string, Signal<double>>> GetMetricsAsync(
        string region, IReadOnlyList<MetricQuery> queries, TimeWindow window, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(queries);
        ArgumentNullException.ThrowIfNull(window);
        var results = new Dictionary<string, Signal<double>>(StringComparer.Ordinal);
        var client = _metrics.GetOrAdd(region, r => new AmazonCloudWatchClient(Config<AmazonCloudWatchConfig>(r)));

        // The whole window as one period, so each query returns (at most a couple of) totals.
        var seconds = (int)Math.Max(60, Math.Ceiling(window.Length.TotalSeconds / 60) * 60);
        var start = window.End.AddSeconds(-seconds);

        foreach (var chunk in queries.Chunk(500))
        {
            var values = chunk.ToDictionary(q => q.Id, _ => new List<double>(), StringComparer.Ordinal);
            var statuses = new Dictionary<string, string>(StringComparer.Ordinal);
            string? token = null;
            try
            {
                do
                {
                    var response = await client.GetMetricDataAsync(new GetMetricDataRequest
                    {
                        StartTime = start.UtcDateTime,
                        EndTime = window.End.UtcDateTime,
                        NextToken = token,
                        MetricDataQueries = [.. chunk.Select(q => new MetricDataQuery
                        {
                            Id = q.Id,
                            ReturnData = true,
                            MetricStat = new MetricStat
                            {
                                Period = seconds,
                                Stat = q.Statistic,
                                Metric = new Amazon.CloudWatch.Model.Metric
                                {
                                    Namespace = q.Namespace,
                                    MetricName = q.MetricName,
                                    Dimensions = [.. q.Dimensions.Select(d => new Dimension { Name = d.Key, Value = d.Value })],
                                },
                            },
                        })],
                    }, cancellationToken).ConfigureAwait(false);

                    foreach (var r in response.MetricDataResults ?? [])
                    {
                        if (r.Id is not null && values.TryGetValue(r.Id, out var list))
                        {
                            list.AddRange(r.Values ?? []);
                            statuses[r.Id] = r.StatusCode?.Value ?? string.Empty;
                        }
                    }

                    token = response.NextToken;
                }
                while (!string.IsNullOrEmpty(token));
            }
            catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
            {
                var failure = Fail<double>(e, "cloudwatch:GetMetricData");
                foreach (var q in chunk)
                {
                    results[q.Id] = failure;
                }

                continue;
            }
            catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
            {
                var failure = ClientFailure<double>(e);
                foreach (var q in chunk)
                {
                    results[q.Id] = failure;
                }

                continue;
            }

            foreach (var q in chunk)
            {
                var list = values[q.Id];
                results[q.Id] = list.Count == 0
                    ? Signal<double>.NoData()
                    : Signal<double>.Of(q.Statistic switch
                    {
                        "Maximum" => list.Max(),
                        "Average" => list.Average(),
                        _ => list.Sum(),
                    });
            }
        }

        return results;
    }

    public async Task<Signal<LogQueryResult>> GetLogEventsAsync(
        string region, string logGroup, TimeWindow window, string? filterPattern, int limit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(window);
        var client = _logs.GetOrAdd(region, r => new AmazonCloudWatchLogsClient(Config<AmazonCloudWatchLogsConfig>(r)));

        // FilterLogEvents returns events oldest first. To get the most recent ones, read the window
        // backwards in growing slices (15 minutes, then 4x larger each time) and stop once enough are found.
        var collected = new List<CoreLogEvent>();
        var truncated = false;
        var sliceEnd = window.End;
        var sliceLength = TimeSpan.FromMinutes(15);
        try
        {
            while (sliceEnd > window.Start && collected.Count < limit)
            {
                var sliceStart = sliceEnd - sliceLength < window.Start ? window.Start : sliceEnd - sliceLength;
                var slice = new List<CoreLogEvent>();
                string? token = null;
                var pages = 0;
                do
                {
                    var response = await client.FilterLogEventsAsync(new FilterLogEventsRequest
                    {
                        LogGroupName = logGroup,
                        StartTime = sliceStart.ToUnixTimeMilliseconds(),
                        EndTime = sliceEnd.ToUnixTimeMilliseconds(),
                        FilterPattern = filterPattern,
                        NextToken = token,
                    }, cancellationToken).ConfigureAwait(false);
                    foreach (var e in response.Events ?? [])
                    {
                        slice.Add(new CoreLogEvent(DateTimeOffset.FromUnixTimeMilliseconds(e.Timestamp ?? 0), e.Message ?? string.Empty));
                    }

                    // Within a busy slice keep only its newest events.
                    if (slice.Count > limit * 4)
                    {
                        slice.RemoveRange(0, slice.Count - limit);
                        truncated = true;
                    }

                    token = response.NextToken;
                    pages++;
                }
                while (!string.IsNullOrEmpty(token) && pages < MaxLogPages);

                truncated |= !string.IsNullOrEmpty(token);
                collected.InsertRange(0, slice);
                sliceEnd = sliceStart;
                sliceLength *= 4;
            }
        }
        catch (LogsNotFound)
        {
            return Signal<LogQueryResult>.NotFound($"log group {logGroup} does not exist in {region}");
        }
        catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
        {
            return Fail<LogQueryResult>(e, "logs:FilterLogEvents");
        }
        catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
        {
            return ClientFailure<LogQueryResult>(e);
        }

        // Older events in the window were not read if we stopped early.
        truncated |= collected.Count > limit || sliceEnd > window.Start;
        return Signal<LogQueryResult>.Of(new LogQueryResult([.. collected.TakeLast(limit)], truncated));
    }
    public async Task<Signal<FunctionInfo>> GetFunctionAsync(string functionArn, CancellationToken cancellationToken)
    {
        var region = ArnParser.Parse(functionArn)?.Region;
        if (string.IsNullOrEmpty(region))
        {
            return Signal<FunctionInfo>.Failed("the function ARN has no region");
        }

        var client = _lambda.GetOrAdd(region, r => new AmazonLambdaClient(Config<AmazonLambdaConfig>(r)));
        try
        {
            var response = await client.GetFunctionAsync(new GetFunctionRequest { FunctionName = functionArn }, cancellationToken).ConfigureAwait(false);
            var c = response.Configuration;
            var name = c?.FunctionName ?? functionArn;
            return Signal<FunctionInfo>.Of(new FunctionInfo(
                name,
                c?.Runtime?.Value,
                c?.MemorySize,
                c?.Timeout,
                c?.State?.Value,
                c?.StateReason,
                c?.LastUpdateStatus?.Value,
                response.Concurrency?.ReservedConcurrentExecutions,
                string.IsNullOrEmpty(c?.LoggingConfig?.LogGroup) ? $"/aws/lambda/{name}" : c!.LoggingConfig.LogGroup));
        }
        catch (LambdaNotFound)
        {
            return Signal<FunctionInfo>.NotFound($"function {functionArn} does not exist");
        }
        catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
        {
            return Fail<FunctionInfo>(e, "lambda:GetFunction");
        }
        catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
        {
            return ClientFailure<FunctionInfo>(e);
        }
    }

    public async Task<Signal<IReadOnlyDictionary<string, string>>> GetResourcePropertiesAsync(
        string region, string typeName, string identifier, CancellationToken cancellationToken)
    {
        var client = _cloudControl.GetOrAdd(region, r => new AmazonCloudControlApiClient(Config<AmazonCloudControlApiConfig>(r)));
        string? json;
        try
        {
            var response = await client.GetResourceAsync(new GetResourceRequest { TypeName = typeName, Identifier = identifier }, cancellationToken).ConfigureAwait(false);
            json = response.ResourceDescription?.Properties;
        }
        catch (CloudControlNotFound)
        {
            return Signal<IReadOnlyDictionary<string, string>>.NotFound($"{identifier} does not exist");
        }
        catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
        {
            // Cloud Control also needs the resource type's own read permission; both surface as access denied.
            return Fail<IReadOnlyDictionary<string, string>>(e, "cloudformation:GetResource");
        }
        catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
        {
            return ClientFailure<IReadOnlyDictionary<string, string>>(e);
        }

        var properties = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(json))
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in doc.RootElement.EnumerateObject())
                    {
                        switch (p.Value.ValueKind)
                        {
                            case JsonValueKind.String:
                                properties[p.Name] = p.Value.GetString() ?? string.Empty;
                                break;
                            case JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False:
                                properties[p.Name] = p.Value.GetRawText();
                                break;
                        }
                    }
                }
            }
            catch (JsonException)
            {
                return Signal<IReadOnlyDictionary<string, string>>.Failed("the resource description could not be parsed");
            }
        }

        return Signal<IReadOnlyDictionary<string, string>>.Of(properties);
    }

    /// <summary>Largest account configuration object accepted; the documented object is a few kilobytes.</summary>
    private const int MaxConfigBytes = 256 * 1024;

    public async Task<Signal<AccountConfig>> GetAccountConfigAsync(string region, string account, CancellationToken cancellationToken)
    {
        var client = _s3.GetOrAdd(region, r => new AmazonS3Client(Config<AmazonS3Config>(r)));
        try
        {
            using var response = await client.GetObjectAsync(new GetObjectRequest
            {
                BucketName = $"proxylity-config-{region}",
                Key = $"{account}/customer-config.json",
            }, cancellationToken).ConfigureAwait(false);
            if (response.ContentLength > MaxConfigBytes)
            {
                return Signal<AccountConfig>.Failed("the account configuration is unexpectedly large");
            }

            using var reader = new StreamReader(response.ResponseStream);
            var json = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            return Signal<AccountConfig>.Of(AccountConfig.Parse(json));
        }
        catch (AmazonS3Exception e) when (e.ErrorCode is "NoSuchKey" or "NoSuchBucket" || e.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return Signal<AccountConfig>.NotFound("not found");
        }
        catch (JsonException)
        {
            return Signal<AccountConfig>.Failed("it could not be parsed");
        }
        catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
        {
            return Fail<AccountConfig>(e, "s3:GetObject");
        }
        catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
        {
            return ClientFailure<AccountConfig>(e);
        }
    }

    public async Task<Signal<RoleTrust>> GetRoleTrustAsync(string roleArn, CancellationToken cancellationToken)
    {
        var name = RoleName(roleArn);
        if (name is null)
        {
            return Signal<RoleTrust>.Failed("not a role ARN");
        }

        try
        {
            var response = await Iam.GetRoleAsync(new GetRoleRequest { RoleName = name }, cancellationToken).ConfigureAwait(false);
            var document = response.Role?.AssumeRolePolicyDocument;
            if (string.IsNullOrEmpty(document))
            {
                return Signal<RoleTrust>.Of(new RoleTrust(false, false));
            }

            // IAM returns policy documents URL-encoded.
            return Signal<RoleTrust>.Of(TrustPolicy.Analyze(Uri.UnescapeDataString(document)));
        }
        catch (NoSuchEntityException)
        {
            return Signal<RoleTrust>.NotFound($"role {name} does not exist");
        }
        catch (JsonException)
        {
            return Signal<RoleTrust>.Failed("the trust policy could not be parsed");
        }
        catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
        {
            return Fail<RoleTrust>(e, "iam:GetRole");
        }
        catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
        {
            return ClientFailure<RoleTrust>(e);
        }
    }

    public async Task<Signal<IReadOnlyList<PermissionDecision>>> SimulateAsync(
        string roleArn, IReadOnlyList<string> actions, IReadOnlyList<string> resources, IReadOnlyDictionary<string, string>? context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actions);
        var request = new SimulatePrincipalPolicyRequest
        {
            PolicySourceArn = roleArn,
            ActionNames = [.. actions],
            ResourceArns = [.. resources],
        };
        if (context is { Count: > 0 })
        {
            request.ContextEntries = [.. context.Select(kv => new ContextEntry
            {
                ContextKeyName = kv.Key,
                ContextKeyType = ContextKeyTypeEnum.String,
                ContextKeyValues = [kv.Value],
            })];
        }

        var decisions = new List<PermissionDecision>();
        try
        {
            string? marker = null;
            do
            {
                request.Marker = marker;
                var response = await Iam.SimulatePrincipalPolicyAsync(request, cancellationToken).ConfigureAwait(false);
                foreach (var r in response.EvaluationResults ?? [])
                {
                    decisions.Add(new PermissionDecision(r.EvalActionName, r.EvalResourceName ?? "*", r.EvalDecision?.Value ?? "unknown"));
                }

                marker = response.IsTruncated == true ? response.Marker : null;
            }
            while (marker is not null);
        }
        catch (NoSuchEntityException)
        {
            return Signal<IReadOnlyList<PermissionDecision>>.NotFound("role does not exist");
        }
        catch (AmazonServiceException e) when (!ErrorMapping.IsCredentialProblem(e))
        {
            return Fail<IReadOnlyList<PermissionDecision>>(e, "iam:SimulatePrincipalPolicy");
        }
        catch (AmazonClientException e) when (ErrorMapping.IsClientFailure(e))
        {
            return ClientFailure<IReadOnlyList<PermissionDecision>>(e);
        }

        return Signal<IReadOnlyList<PermissionDecision>>.Of(decisions);
    }

    /// <summary>IAM is a global service; one client serves every role.</summary>
    private AmazonIdentityManagementServiceClient Iam => _iam ??= new AmazonIdentityManagementServiceClient(Config<AmazonIdentityManagementServiceConfig>("us-east-1"));

    /// <summary>The role name is the last path segment of arn:aws:iam::ACCOUNT:role/optional/path/NAME.</summary>
    private static string? RoleName(string roleArn)
    {
        var arn = ArnParser.Parse(roleArn);
        if (arn is not { Service: "iam" } || !arn.Resource.StartsWith("role/", StringComparison.Ordinal))
        {
            return null;
        }

        return arn.Resource[(arn.Resource.LastIndexOf('/') + 1)..];
    }

    public void Dispose()
    {
        _iam?.Dispose();
        foreach (var c in _s3.Values)
        {
            c.Dispose();
        }

        foreach (var c in _cloudControl.Values)
        {
            c.Dispose();
        }

        foreach (var c in _metrics.Values)
        {
            c.Dispose();
        }

        foreach (var c in _logs.Values)
        {
            c.Dispose();
        }

        foreach (var c in _lambda.Values)
        {
            c.Dispose();
        }
    }

    private static T Config<T>(string region)
        where T : ClientConfig, new() =>
        new()
        {
            RegionEndpoint = RegionEndpoint.GetBySystemName(region),
            RetryMode = RequestRetryMode.Adaptive,
            MaxErrorRetry = 8,
        };

    /// <summary>A client-side failure (for example the SDK's retry budget ran out under throttling) for one signal only.</summary>
    private static Signal<T> ClientFailure<T>(AmazonClientException e) =>
        Signal<T>.Failed(e.Message.Contains("capacity", StringComparison.OrdinalIgnoreCase)
            ? "AWS throttled the requests and the retry budget ran out; try again, or narrow the target"
            : "the request could not be completed: " + e.Message);

    private static Signal<T> Fail<T>(AmazonServiceException e, string action) =>
        ErrorMapping.IsAccessDenied(e) ? Signal<T>.NotAccessible(action)
        : ErrorMapping.IsThrottling(e) ? Signal<T>.Failed($"throttled by AWS ({action})")
        : Signal<T>.Failed($"{action} failed: {e.ErrorCode}");
}
