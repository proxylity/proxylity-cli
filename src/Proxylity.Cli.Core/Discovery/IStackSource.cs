namespace Proxylity.Cli.Core.Discovery;

/// <param name="LastChanged">Last update time, or creation time if never updated. Used to decide whether a cached read is still valid.</param>
public sealed record StackSummary(string Id, string Name, string Status, string? ParentId, DateTimeOffset? LastChanged = null);

public sealed record StackResource(string LogicalId, string? PhysicalId, string Type, string Status);

public sealed record StackDetails(
    IReadOnlyDictionary<string, string> Parameters,
    IReadOnlyDictionary<string, string> Outputs);

/// <summary>The read-only CloudFormation operations discovery needs. Implemented over the AWS SDK in the Aws project.</summary>
public interface IStackSource
{
    /// <summary>Region the source reads from.</summary>
    string Region { get; }

    Task<IReadOnlyList<StackSummary>> ListStacksAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<StackResource>> ListResourcesAsync(string stackId, CancellationToken cancellationToken);

    Task<StackDetails> DescribeAsync(string stackId, CancellationToken cancellationToken);

    /// <summary>The template after transforms (for example SAM) have been applied.</summary>
    Task<string> GetProcessedTemplateAsync(string stackId, CancellationToken cancellationToken);
}

/// <summary>The identity lacks permission for an operation. Carries the AWS action so users can fix it.</summary>
public sealed class AccessDeniedException(string action, string message) : Exception(message)
{
    public string Action { get; } = action;
}

/// <summary>AWS kept throttling an operation after retries.</summary>
public sealed class ThrottledException(string action, string message) : Exception(message)
{
    public string Action { get; } = action;
}

/// <summary>Credentials or region are missing, expired, or invalid.</summary>
public sealed class CredentialsException(string message, Exception? inner = null) : Exception(message, inner);
