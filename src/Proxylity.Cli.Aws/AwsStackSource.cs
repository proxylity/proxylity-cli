using Amazon;
using Amazon.CloudFormation;
using Amazon.CloudFormation.Model;
using Amazon.Runtime;
using Proxylity.Cli.Core.Discovery;
using CoreStackResource = Proxylity.Cli.Core.Discovery.StackResource;
using CoreStackSummary = Proxylity.Cli.Core.Discovery.StackSummary;

namespace Proxylity.Cli.Aws;

/// <summary>
/// Read-only CloudFormation access over the AWS SDK. Only list/describe/get operations are used.
/// Credentials and region come from the standard AWS resolution chain (environment, profile,
/// SSO, container and instance roles, ...), optionally overridden by profile and region.
/// </summary>
public sealed class AwsStackSource : IStackSource, IDisposable
{
    private static readonly string[] ActiveStatuses =
    [
        "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE",
        "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED", "ROLLBACK_COMPLETE",
        "DELETE_IN_PROGRESS", "DELETE_FAILED",
        "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_COMPLETE",
        "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
        "REVIEW_IN_PROGRESS",
        "IMPORT_IN_PROGRESS", "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
    ];

    private readonly AmazonCloudFormationClient _client;

    private AwsStackSource(AmazonCloudFormationClient client, string region)
    {
        _client = client;
        Region = region;
    }

    public string Region { get; }

    /// <summary>Creates a source using the default credential and region chain, with optional overrides.</summary>
    public static AwsStackSource Create(string? region, string? profile)
    {
        if (!string.IsNullOrWhiteSpace(profile))
        {
            // The SDK reads the active profile from the environment when resolving credentials and region.
            Environment.SetEnvironmentVariable("AWS_PROFILE", profile);
        }

        try
        {
            // Adaptive retry mode adds client-side rate limiting when AWS throttles, which suits
            // CloudFormation's low per-account read limits.
            var config = new AmazonCloudFormationConfig
            {
                RetryMode = RequestRetryMode.Adaptive,
                MaxErrorRetry = 8,
            };
            if (!string.IsNullOrWhiteSpace(region))
            {
                config.RegionEndpoint = RegionEndpoint.GetBySystemName(region);
            }

            var client = new AmazonCloudFormationClient(config);
            var resolved = client.Config.RegionEndpoint?.SystemName;
            if (string.IsNullOrEmpty(resolved))
            {
                client.Dispose();
                throw new CredentialsException("No AWS region is configured. Use --region, set AWS_REGION, or configure a default region in your AWS profile.");
            }

            return new AwsStackSource(client, resolved);
        }
        catch (AmazonClientException e)
        {
            throw new CredentialsException("Could not initialize AWS access: " + e.Message, e);
        }
    }

    public async Task<IReadOnlyList<CoreStackSummary>> ListStacksAsync(CancellationToken cancellationToken)
    {
        var result = new List<CoreStackSummary>();
        string? token = null;
        do
        {
            var response = await CallAsync(
                "cloudformation:ListStacks",
                () => _client.ListStacksAsync(new ListStacksRequest { NextToken = token, StackStatusFilter = [.. ActiveStatuses] }, cancellationToken))
                .ConfigureAwait(false);
            result.AddRange(response.StackSummaries.Select(s =>
                new CoreStackSummary(
                    s.StackId,
                    s.StackName,
                    s.StackStatus?.Value ?? "UNKNOWN",
                    string.IsNullOrEmpty(s.ParentId) ? null : s.ParentId,
                    ChangeTime(s.LastUpdatedTime ?? s.CreationTime))));
            token = response.NextToken;
        }
        while (!string.IsNullOrEmpty(token));

        return result;
    }

    public async Task<IReadOnlyList<CoreStackResource>> ListResourcesAsync(string stackId, CancellationToken cancellationToken)
    {
        var result = new List<CoreStackResource>();
        string? token = null;
        do
        {
            var response = await CallAsync(
                "cloudformation:ListStackResources",
                () => _client.ListStackResourcesAsync(new ListStackResourcesRequest { StackName = stackId, NextToken = token }, cancellationToken))
                .ConfigureAwait(false);
            result.AddRange(response.StackResourceSummaries.Select(r =>
                new CoreStackResource(r.LogicalResourceId, r.PhysicalResourceId, r.ResourceType, r.ResourceStatus?.Value ?? "UNKNOWN")));
            token = response.NextToken;
        }
        while (!string.IsNullOrEmpty(token));

        return result;
    }

    public async Task<StackDetails> DescribeAsync(string stackId, CancellationToken cancellationToken)
    {
        var response = await CallAsync(
            "cloudformation:DescribeStacks",
            () => _client.DescribeStacksAsync(new DescribeStacksRequest { StackName = stackId }, cancellationToken))
            .ConfigureAwait(false);
        var stack = response.Stacks.FirstOrDefault();
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        var outputs = new Dictionary<string, string>(StringComparer.Ordinal);
        if (stack is not null)
        {
            foreach (var p in stack.Parameters ?? [])
            {
                parameters[p.ParameterKey] = p.ResolvedValue ?? p.ParameterValue ?? string.Empty;
            }

            foreach (var o in stack.Outputs ?? [])
            {
                outputs[o.OutputKey] = o.OutputValue ?? string.Empty;
            }
        }

        return new StackDetails(parameters, outputs);
    }

    public async Task<string> GetProcessedTemplateAsync(string stackId, CancellationToken cancellationToken)
    {
        var response = await CallAsync(
            "cloudformation:GetTemplate",
            () => _client.GetTemplateAsync(new GetTemplateRequest { StackName = stackId, TemplateStage = TemplateStage.Processed }, cancellationToken))
            .ConfigureAwait(false);
        return response.TemplateBody ?? string.Empty;
    }

    public void Dispose() => _client.Dispose();

    private static DateTimeOffset? ChangeTime(DateTime? value) =>
        value is { } v ? new DateTimeOffset(v.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(v, DateTimeKind.Utc) : v.ToUniversalTime()) : null;

    /// <summary>Runs an SDK call and translates authorization and credential failures into typed exceptions.</summary>
    private static async Task<T> CallAsync<T>(string action, Func<Task<T>> call)
    {
        try
        {
            return await call().ConfigureAwait(false);
        }
        catch (AmazonServiceException e) when (ErrorMapping.IsThrottling(e))
        {
            throw new ThrottledException(action, $"AWS throttled {action} after retries ({e.Message}).");
        }
        catch (AmazonServiceException e) when (ErrorMapping.IsAccessDenied(e))
        {
            throw new AccessDeniedException(action, $"Access denied for {action}: {e.Message}");
        }
        catch (AmazonServiceException e) when (ErrorMapping.IsCredentialProblem(e))
        {
            throw new CredentialsException($"AWS rejected the credentials ({e.ErrorCode}): {e.Message}", e);
        }
        catch (AmazonClientException e) when (e.Message.Contains("capacity", StringComparison.OrdinalIgnoreCase))
        {
            // The SDK's client-side retry budget ran out under sustained throttling.
            throw new ThrottledException(action, $"AWS throttled {action} and the retry budget ran out.");
        }
        catch (AmazonClientException e)
        {
            var hint = e.Message.Contains("expired", StringComparison.OrdinalIgnoreCase)
                ? " Sign in again (for example 'aws login' or 'aws sso login') and retry."
                : e.Message.Contains("Failed to resolve AWS credentials", StringComparison.Ordinal)
                    ? " Configure credentials (environment, profile, SSO, or instance role), or pass --profile."
                    : string.Empty;
            throw new CredentialsException("Could not call AWS: " + e.Message + hint, e);
        }
    }
}

internal static class ErrorMapping
{
    public static bool IsAccessDenied(AmazonServiceException e) =>
        e.ErrorCode is "AccessDenied" or "AccessDeniedException" or "UnauthorizedOperation" or "AuthorizationError"
        || (int)e.StatusCode == 403 && e.ErrorCode is not ("ExpiredToken" or "InvalidClientTokenId" or "UnrecognizedClientException" or "SignatureDoesNotMatch");

    /// <summary>
    /// A client-side failure that should degrade one signal rather than end the command. Credential resolution
    /// failures are also client exceptions; those must still stop the command, so they are excluded.
    /// </summary>
    public static bool IsClientFailure(AmazonClientException e) =>
        !e.Message.Contains("credential", StringComparison.OrdinalIgnoreCase)
        && !e.Message.Contains("token has expired", StringComparison.OrdinalIgnoreCase);

    public static bool IsThrottling(AmazonServiceException e) =>
        e.ErrorCode is "Throttling" or "ThrottlingException" or "ThrottledException" or "RequestLimitExceeded"
            or "TooManyRequestsException" or "RequestThrottled" or "RequestThrottledException"
        || (int)e.StatusCode == 429;

    public static bool IsCredentialProblem(AmazonServiceException e) =>
        e.ErrorCode is "ExpiredToken" or "ExpiredTokenException" or "InvalidClientTokenId" or "UnrecognizedClientException"
            or "SignatureDoesNotMatch" or "InvalidSignatureException" or "MissingAuthenticationToken";
}
