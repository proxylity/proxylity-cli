using System.Text.Json;
using Proxylity.Cli.Core.Discovery;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli.Tests;

/// <summary>Stack source that denies chosen CloudFormation actions, otherwise serving the demo stacks.</summary>
internal sealed class DenyingStackSource(params string[] denied) : IStackSource
{
    private readonly FakeStackSource inner = new();

    public string Region => inner.Region;

    public bool Credentials { get; init; } = true;

    private void Check(string action)
    {
        if (denied.Contains(action, StringComparer.Ordinal))
        {
            throw new AccessDeniedException(action, $"Access denied for {action}");
        }
    }

    public Task<IReadOnlyList<StackSummary>> ListStacksAsync(CancellationToken cancellationToken)
    {
        if (!Credentials)
        {
            throw new CredentialsException("No AWS credentials were found.");
        }

        Check("cloudformation:ListStacks");
        return inner.ListStacksAsync(cancellationToken);
    }

    public Task<IReadOnlyList<StackResource>> ListResourcesAsync(string stackId, CancellationToken cancellationToken)
    {
        Check("cloudformation:ListStackResources");
        return inner.ListResourcesAsync(stackId, cancellationToken);
    }

    public Task<StackDetails> DescribeAsync(string stackId, CancellationToken cancellationToken)
    {
        Check("cloudformation:DescribeStacks");
        return inner.DescribeAsync(stackId, cancellationToken);
    }

    public Task<string> GetProcessedTemplateAsync(string stackId, CancellationToken cancellationToken)
    {
        Check("cloudformation:GetTemplate");
        return inner.GetProcessedTemplateAsync(stackId, cancellationToken);
    }
}

/// <summary>Observability source that reports chosen actions as denied or failed, and records every call.</summary>
internal sealed class DenyingObservabilitySource(params string[] denied) : IObservabilitySource
{
    public List<string> Calls { get; } = [];

    public HashSet<string> Failing { get; } = new(StringComparer.Ordinal);

    /// <summary>Like AWS for a probe of a resource that does not exist: denied, failed, or "not found" (which means permitted).</summary>
    private Signal<T> Result<T>(string action)
    {
        Calls.Add(action);
        return denied.Contains(action, StringComparer.Ordinal) ? Signal<T>.NotAccessible(action)
            : Failing.Contains(action) ? Signal<T>.Failed("throttled by AWS")
            : Signal<T>.NotFound("does not exist");
    }

    public Task<IReadOnlyDictionary<string, Signal<double>>> GetMetricsAsync(string region, IReadOnlyList<MetricQuery> queries, TimeWindow window, CancellationToken cancellationToken)
    {
        var signal = Result<double>("cloudwatch:GetMetricData");
        return Task.FromResult<IReadOnlyDictionary<string, Signal<double>>>(queries.ToDictionary(q => q.Id, _ => signal.State == SignalState.NotFound ? Signal<double>.NoData() : signal));
    }

    public Task<Signal<LogQueryResult>> GetLogEventsAsync(string region, string logGroup, TimeWindow window, string? filterPattern, int limit, CancellationToken cancellationToken) =>
        Task.FromResult(Result<LogQueryResult>("logs:FilterLogEvents"));

    public Task<Signal<FunctionInfo>> GetFunctionAsync(string functionArn, CancellationToken cancellationToken) =>
        Task.FromResult(Result<FunctionInfo>("lambda:GetFunction"));

    public Task<Signal<IReadOnlyDictionary<string, string>>> GetResourcePropertiesAsync(string region, string typeName, string identifier, CancellationToken cancellationToken) =>
        Task.FromResult(Result<IReadOnlyDictionary<string, string>>("cloudformation:GetResource"));
    public Task<Signal<AccountConfig>> GetAccountConfigAsync(string region, string account, CancellationToken cancellationToken)
    {
        Calls.Add("s3:GetObject");
        return Task.FromResult(Signal<AccountConfig>.NotFound("not found"));
    }

    public Task<Signal<RoleTrust>> GetRoleTrustAsync(string roleArn, CancellationToken cancellationToken) =>
        Task.FromResult(Result<RoleTrust>("iam:GetRole"));

    public Task<Signal<IReadOnlyList<PermissionDecision>>> SimulateAsync(string roleArn, IReadOnlyList<string> actions, IReadOnlyList<string> resources, IReadOnlyDictionary<string, string>? context, CancellationToken cancellationToken) =>
        Task.FromResult(Result<IReadOnlyList<PermissionDecision>>("iam:SimulatePrincipalPolicy"));
}

public class CheckAccessTests
{
    private static (int Code, string Out, string Err, DenyingObservabilitySource Obs) Run(
        IStackSource? stacks = null, DenyingObservabilitySource? obs = null, params string[] args)
    {
        obs ??= new DenyingObservabilitySource();
        stacks ??= new DenyingStackSource();
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var app = new CliApp(stdout, stderr, _ => stacks, colorAllowed: false, observabilityFactory: _ => obs);
        var code = app.RunAsync(["check-access", .. args], CancellationToken.None).GetAwaiter().GetResult();
        return (code, stdout.ToString(), stderr.ToString(), obs);
    }

    private static Dictionary<string, string> States(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("result").GetProperty("probes").EnumerateArray()
            .ToDictionary(p => p.GetProperty("action").GetString()!, p => p.GetProperty("state").GetString()!);
    }

    [Fact]
    public void Every_probed_action_is_allowed_and_the_account_configuration_is_not_tested()
    {
        var (code, output, _, obs) = Run(args: ["-o", "json"]);
        Assert.Equal(0, code);
        var states = States(output);
        Assert.Equal("notTested", states["s3:GetObject"]);
        Assert.Equal(10, states.Count(s => s.Value == "allowed"));
        Assert.Equal(11, states.Count);
        Assert.DoesNotContain("s3:GetObject", obs.Calls);
    }

    [Theory]
    [InlineData("cloudformation:ListStacks")]
    [InlineData("cloudformation:ListStackResources")]
    [InlineData("cloudformation:DescribeStacks")]
    [InlineData("cloudformation:GetTemplate")]
    [InlineData("cloudwatch:GetMetricData")]
    [InlineData("logs:FilterLogEvents")]
    [InlineData("lambda:GetFunction")]
    [InlineData("cloudformation:GetResource")]
    [InlineData("iam:GetRole")]
    [InlineData("iam:SimulatePrincipalPolicy")]
    public void A_denied_action_is_listed_as_denied_and_exit_code_stays_0(string action)
    {
        var stacks = new DenyingStackSource(action);
        var (code, output, _, _) = Run(stacks, new DenyingObservabilitySource(action), "-o", "json");
        Assert.Equal(0, code);
        var states = States(output);
        Assert.Equal("denied", states[action]);
        if (action != "cloudformation:ListStacks")
        {
            Assert.Equal(9, states.Count(s => s.Value == "allowed"));
        }
    }

    [Fact]
    public void A_failed_call_is_inconclusive()
    {
        var obs = new DenyingObservabilitySource();
        obs.Failing.Add("lambda:GetFunction");
        var (code, output, _, _) = Run(obs: obs, args: ["-o", "json"]);
        Assert.Equal(0, code);
        Assert.Equal("inconclusive", States(output)["lambda:GetFunction"]);
    }

    [Fact]
    public void Throttled_stack_listing_is_inconclusive()
    {
        var (code, output, _, _) = Run(new FakeStackSource { ThrottleListStacks = true }, args: ["-o", "json"]);
        Assert.Equal(0, code);
        var states = States(output);
        Assert.Equal("inconclusive", states["cloudformation:ListStacks"]);
        Assert.Equal("notTested", states["cloudformation:GetTemplate"]);
    }

    [Fact]
    public void Text_and_markdown_name_each_action_and_the_untested_read()
    {
        var stacks = new DenyingStackSource("cloudformation:GetTemplate");
        var (_, text, _, _) = Run(stacks);
        Assert.Contains("cloudformation:GetTemplate", text, StringComparison.Ordinal);
        Assert.Contains("DENIED", text, StringComparison.Ordinal);
        Assert.Contains("s3:GetObject", text, StringComparison.Ordinal);
        Assert.Contains("not tested", text, StringComparison.Ordinal);
        Assert.Contains("probing would read the account configuration", text, StringComparison.Ordinal);

        var (_, md, _, _) = Run(stacks, null, "-o", "markdown");
        Assert.Contains("| `cloudformation:GetTemplate` | denied |", md, StringComparison.Ordinal);
        Assert.Contains("| `s3:GetObject` | not tested |", md, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_account_configuration_is_never_read()
    {
        // The existing fake serves an account configuration; check-access must not ask for it.
        var obs = new FakeObservabilitySource();
        var stdout = new StringWriter();
        var app = new CliApp(stdout, new StringWriter(), _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => new ThrowingConfigSource(obs));
        Assert.Equal(0, await app.RunAsync(["check-access"], CancellationToken.None));
    }

    [Fact]
    public void Output_contains_no_secret_or_credential_values()
    {
        foreach (var format in new[] { "text", "json", "markdown" })
        {
            var (_, output, err, _) = Run(args: ["-o", format]);
            foreach (var literal in new[] { "literal-secret-value-xyz", "arn:aws:iam::123456789012:role/example-role" })
            {
                Assert.DoesNotContain(literal, output, StringComparison.Ordinal);
                Assert.DoesNotContain(literal, err, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Missing_credentials_keep_exit_code_3()
    {
        var (code, _, err, _) = Run(new DenyingStackSource { Credentials = false });
        Assert.Equal(3, code);
        Assert.Contains("credentials", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Check_access_does_not_take_a_target()
    {
        var (code, _, err, _) = Run(args: ["demo"]);
        Assert.Equal(2, code);
        Assert.Contains("does not take a target", err, StringComparison.Ordinal);
    }

    /// <summary>Fails the test run if the account configuration is requested.</summary>
    private sealed class ThrowingConfigSource(FakeObservabilitySource inner) : IObservabilitySource
    {
        public Task<IReadOnlyDictionary<string, Signal<double>>> GetMetricsAsync(string region, IReadOnlyList<MetricQuery> queries, TimeWindow window, CancellationToken cancellationToken) =>
            inner.GetMetricsAsync(region, queries, window, cancellationToken);

        public Task<Signal<LogQueryResult>> GetLogEventsAsync(string region, string logGroup, TimeWindow window, string? filterPattern, int limit, CancellationToken cancellationToken) =>
            inner.GetLogEventsAsync(region, logGroup, window, filterPattern, limit, cancellationToken);

        public Task<Signal<FunctionInfo>> GetFunctionAsync(string functionArn, CancellationToken cancellationToken) =>
            inner.GetFunctionAsync(functionArn, cancellationToken);

        public Task<Signal<IReadOnlyDictionary<string, string>>> GetResourcePropertiesAsync(string region, string typeName, string identifier, CancellationToken cancellationToken) =>
            inner.GetResourcePropertiesAsync(region, typeName, identifier, cancellationToken);

        public Task<Signal<AccountConfig>> GetAccountConfigAsync(string region, string account, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("check-access must not read the account configuration.");

        public Task<Signal<RoleTrust>> GetRoleTrustAsync(string roleArn, CancellationToken cancellationToken) =>
            inner.GetRoleTrustAsync(roleArn, cancellationToken);

        public Task<Signal<IReadOnlyList<PermissionDecision>>> SimulateAsync(string roleArn, IReadOnlyList<string> actions, IReadOnlyList<string> resources, IReadOnlyDictionary<string, string>? context, CancellationToken cancellationToken) =>
            inner.SimulateAsync(roleArn, actions, resources, context, cancellationToken);
    }
}
