namespace Proxylity.Cli.Core.Templates;

/// <summary>A resource as deployed in a stack (from ListStackResources).</summary>
public sealed record DeployedResource(string LogicalId, string Type, string? PhysicalId, string Status);

/// <summary>Everything the resolver needs to evaluate intrinsic functions for one stack.</summary>
public sealed class ResolutionContext
{
    public required string Region { get; init; }

    public required string AccountId { get; init; }

    public required string StackName { get; init; }

    public required string StackId { get; init; }

    public string Partition { get; init; } = "aws";

    public string UrlSuffix { get; init; } = "amazonaws.com";

    /// <summary>Resolved stack parameter values. NoEcho parameters are masked by CloudFormation as "****".</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; init; } = new Dictionary<string, string>();

    public IReadOnlyDictionary<string, DeployedResource> Resources { get; init; } = new Dictionary<string, DeployedResource>();

    public IReadOnlyDictionary<string, string> Exports { get; init; } = new Dictionary<string, string>();

    /// <summary>Outputs of nested stacks, keyed by the nested stack's ID (its physical ID in the parent).</summary>
    public IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> NestedStackOutputs { get; init; } =
        new Dictionary<string, IReadOnlyDictionary<string, string>>();

    public TNode? Mappings { get; init; }

    public TNode? Conditions { get; init; }
}
