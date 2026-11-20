using System.Text.Json;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli.Tests;

/// <summary>Serves metrics by (namespace, metric, first dimension value, statistic), plus logs and functions.</summary>
internal sealed class FakeObservabilitySource : IObservabilitySource
{
    public Dictionary<(string Ns, string Metric, string Dim, string Stat), double> Metrics { get; } = [];

    public Dictionary<string, Signal<LogQueryResult>> Logs { get; } = new(StringComparer.Ordinal);

    public Signal<FunctionInfo> Function { get; set; } =
        Signal<FunctionInfo>.Of(new FunctionInfo("packet-handler", "dotnet8", 256, 30, "Active", null, "Successful", null, "/aws/lambda/packet-handler"));

    public bool DenyMetrics { get; set; }

    public List<string> MetricRegions { get; } = [];

    public Task<IReadOnlyDictionary<string, Signal<double>>> GetMetricsAsync(string region, IReadOnlyList<MetricQuery> queries, TimeWindow window, CancellationToken cancellationToken)
    {
        lock (MetricRegions)
        {
            MetricRegions.Add(region);
        }

        var result = new Dictionary<string, Signal<double>>();
        foreach (var q in queries)
        {
            result[q.Id] = DenyMetrics
                ? Signal<double>.NotAccessible("cloudwatch:GetMetricData")
                : Metrics.TryGetValue((q.Namespace, q.MetricName, q.Dimensions[0].Value, q.Statistic), out var v)
                    ? Signal<double>.Of(v)
                    : Signal<double>.NoData();
        }

        return Task.FromResult<IReadOnlyDictionary<string, Signal<double>>>(result);
    }

    public Task<Signal<LogQueryResult>> GetLogEventsAsync(string region, string logGroup, TimeWindow window, string? filterPattern, int limit, CancellationToken cancellationToken) =>
        Task.FromResult(Logs.TryGetValue(logGroup, out var s) ? s : Signal<LogQueryResult>.Of(new LogQueryResult([], false)));

    public Task<Signal<FunctionInfo>> GetFunctionAsync(string functionArn, CancellationToken cancellationToken) => Task.FromResult(Function);

    public Signal<AccountConfig> AccountConfig { get; set; } = Signal<AccountConfig>.NotFound("not found");

    public Task<Signal<AccountConfig>> GetAccountConfigAsync(string region, string account, CancellationToken cancellationToken) =>
        Task.FromResult(AccountConfig);

    /// <summary>Trust per role ARN; roles not listed exist with a correct trust policy.</summary>
    public Dictionary<string, Signal<RoleTrust>> Roles { get; } = new(StringComparer.Ordinal);

    /// <summary>Actions that the simulator reports as denied (implicitDeny), and explicitly denied ones.</summary>
    public HashSet<string> DeniedActions { get; } = new(StringComparer.Ordinal);

    public HashSet<string> ExplicitlyDeniedActions { get; } = new(StringComparer.Ordinal);

    public bool DenySimulation { get; set; }

    /// <summary>One entry per simulation call: role, resources and actions (each comma-joined).</summary>
    public List<(string Role, string Resources, string Actions)> Simulations { get; } = [];

    public Task<Signal<RoleTrust>> GetRoleTrustAsync(string roleArn, CancellationToken cancellationToken) =>
        Task.FromResult(Roles.TryGetValue(roleArn, out var t) ? t : Signal<RoleTrust>.Of(new RoleTrust(true, true)));

    public Task<Signal<IReadOnlyList<PermissionDecision>>> SimulateAsync(string roleArn, IReadOnlyList<string> actions, IReadOnlyList<string> resources, IReadOnlyDictionary<string, string>? context, CancellationToken cancellationToken)
    {
        lock (Simulations)
        {
            Simulations.Add((roleArn, string.Join(',', resources), string.Join(',', actions)));
        }

        if (DenySimulation)
        {
            return Task.FromResult(Signal<IReadOnlyList<PermissionDecision>>.NotAccessible("iam:SimulatePrincipalPolicy"));
        }

        // Like IAM: every action against every resource.
        IReadOnlyList<PermissionDecision> decisions = [.. from a in actions from r in resources select new PermissionDecision(a, r,
            ExplicitlyDeniedActions.Contains(a) ? "explicitDeny" : DeniedActions.Contains(a) ? "implicitDeny" : "allowed")];
        return Task.FromResult(Signal<IReadOnlyList<PermissionDecision>>.Of(decisions));
    }

    public Dictionary<string, Signal<IReadOnlyDictionary<string, string>>> Resources { get; } = new(StringComparer.Ordinal);

    public List<(string Type, string Identifier)> ResourceReads { get; } = [];

    public Task<Signal<IReadOnlyDictionary<string, string>>> GetResourcePropertiesAsync(string region, string typeName, string identifier, CancellationToken cancellationToken)
    {
        lock (ResourceReads)
        {
            ResourceReads.Add((typeName, identifier));
        }

        return Task.FromResult(Resources.TryGetValue(identifier, out var r) ? r : Signal<IReadOnlyDictionary<string, string>>.NotFound("not found"));
    }

    public void Proxylity(string dimension, string metric, double value) => Metrics[("Proxylity/UDP Gateway", metric, dimension, "Sum")] = value;

    public void Lambda(string metric, double value, string stat = "Sum") => Metrics[("AWS/Lambda", metric, "packet-handler", stat)] = value;
}

public class DiagnoseTests
{
    private const string Listener = "demo-Listener-1a2b3c4d";
    private const string Destination = "packet-handler";

    private static (int Code, string Out, string Err) Run(FakeObservabilitySource obs, params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var app = new CliApp(stdout, stderr, _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => obs);
        var code = app.RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
        return (code, stdout.ToString(), stderr.ToString());
    }

    private static FakeObservabilitySource Healthy()
    {
        var obs = new FakeObservabilitySource();
        obs.Proxylity(Listener, "IngressPackets", 1000);
        obs.Proxylity(Listener, "IngressBytes", 50_000);
        obs.Proxylity(Listener, "FilteredPackets", 2);
        obs.Proxylity(Listener, "FilteredBytes", 100);
        obs.Proxylity(Listener, "Errors", 0);
        obs.Proxylity(Destination, "IngressPackets", 1000);
        obs.Proxylity(Destination, "Errors", 0);
        obs.Lambda("Invocations", 100);
        obs.Lambda("Errors", 0);
        obs.Lambda("Throttles", 0);
        obs.Lambda("Duration", 120, "Maximum");
        return obs;
    }

    [Fact]
    public void Healthy_path_is_reported_with_positive_evidence_and_exit_code_0()
    {
        var (code, output, _) = Run(Healthy(), "diagnose", Listener);

        Assert.Equal(0, code);
        Assert.Contains("Listener is receiving traffic", output, StringComparison.Ordinal);
        Assert.Contains("Packets are being accepted for delivery", output, StringComparison.Ordinal);
        Assert.Contains("invoked with no errors or throttles", output, StringComparison.Ordinal);
        Assert.DoesNotContain("ERROR", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Throttling_and_function_errors_are_errors_with_exit_code_1()
    {
        var obs = Healthy();
        obs.Lambda("Throttles", 7);
        obs.Lambda("Errors", 3);
        obs.Logs["/aws/lambda/packet-handler"] = Signal<LogQueryResult>.Of(new LogQueryResult(
            [new LogEvent(DateTimeOffset.UtcNow, "ERROR Unhandled exception\u001b[31m injected")], false));

        var (code, output, _) = Run(obs, "diagnose", Listener);

        Assert.Equal(1, code);
        Assert.Contains("The function was throttled", output, StringComparison.Ordinal);
        Assert.Contains("throttles 7", output, StringComparison.Ordinal);
        Assert.Contains("The function returned errors", output, StringComparison.Ordinal);
        // Terminal escape sequences from log content are neutralized.
        Assert.DoesNotContain("\u001b", output, StringComparison.Ordinal);
        Assert.Contains("\\u001b", output, StringComparison.Ordinal);
    }

    [Fact]
    public void No_data_is_unknown_not_healthy()
    {
        var (code, output, _) = Run(new FakeObservabilitySource(), "diagnose", Listener);

        Assert.Equal(0, code);
        Assert.Contains("No listener metrics in the window", output, StringComparison.Ordinal);
        Assert.Contains("not invoked in the window", output, StringComparison.Ordinal);
        // Configuration checks (the role) may pass, but nothing about traffic is reported as healthy.
        Assert.DoesNotContain("receiving traffic", output, StringComparison.Ordinal);
        Assert.DoesNotContain("accepted for delivery", output, StringComparison.Ordinal);
        Assert.DoesNotContain("invoked with no errors", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Listener_traffic_with_a_silent_destination_suggests_a_role_problem()
    {
        var obs = new FakeObservabilitySource();
        obs.Proxylity(Listener, "IngressPackets", 500);
        obs.Proxylity(Listener, "FilteredPackets", 0);

        var (_, output, _) = Run(obs, "diagnose", Listener);

        Assert.Contains("this destination published no metrics", output, StringComparison.Ordinal);
        Assert.Contains("(possible)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void All_traffic_filtered_is_an_error()
    {
        var obs = new FakeObservabilitySource();
        obs.Proxylity(Listener, "IngressPackets", 0);
        obs.Proxylity(Listener, "FilteredPackets", 40);

        var (code, output, _) = Run(obs, "diagnose", Listener);

        Assert.Equal(1, code);
        Assert.Contains("all of it is being rejected", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_function_is_a_confirmed_error()
    {
        var obs = Healthy();
        obs.Function = Signal<FunctionInfo>.NotFound("function does not exist");

        var (code, output, _) = Run(obs, "diagnose", Listener);

        Assert.Equal(1, code);
        Assert.Contains("The Lambda function does not exist", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Denied_metrics_are_reported_as_not_accessible_with_the_action()
    {
        var (_, output, _) = Run(new FakeObservabilitySource { DenyMetrics = true }, "diagnose", Listener);

        Assert.Contains("can't be read with the current AWS identity", output, StringComparison.Ordinal);
        Assert.Contains("cloudwatch:GetMetricData", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Destination_log_errors_are_grouped_and_marked_untrusted_in_json()
    {
        var obs = Healthy();
        obs.Proxylity(Destination, "Errors", 4);
        var t = DateTimeOffset.UtcNow;
        obs.Logs["/example/dest"] = Signal<LogQueryResult>.Of(new LogQueryResult(
        [
            new LogEvent(t, "[x3]: ERROR: Failed to proxy 10 message(s) to Lambda: Rate exceeded."),
            new LogEvent(t, "[x1]: ERROR: Failed to proxy 10 message(s) to Lambda: Rate exceeded."),
        ], false));

        var (code, output, _) = Run(obs, "diagnose", Listener, "--output", "json");

        Assert.Equal(1, code);
        using var doc = JsonDocument.Parse(output);
        var result = doc.RootElement.GetProperty("result");
        Assert.True(result.GetProperty("summary").GetProperty("errors").GetInt32() >= 1);
        var destination = result.GetProperty("report").GetProperty("listeners")[0].GetProperty("destinations")[0];
        var findings = destination.GetProperty("findings").EnumerateArray().ToList();
        Assert.Contains(findings, f => f.GetProperty("ruleId").GetString() == "destination.errors-reported");
    }

    [Fact]
    public void Missing_role_permissions_are_extracted_from_access_denied_log_entries()
    {
        var obs = Healthy();
        obs.Proxylity(Destination, "Errors", 3);
        var t = DateTimeOffset.UtcNow;
        obs.Logs["/example/dest"] = Signal<LogQueryResult>.Of(new LogQueryResult(
        [
            new LogEvent(t, "[x2]: ERROR: Reply loop One or more errors occurred. (User: arn:aws:sts::123456789012:assumed-role/example-role/s is not authorized to perform: lambda:PassNetworkConnector on resource: arn:aws:lambda:us-west-2:aws:network-connector:aws-network-connector:INTERNET_EGRESS because no identity-based policy allows the lambda:PassNetworkConnector action)."),
            new LogEvent(t, "[x1]: WARN: Unable to read image: User: arn:aws:sts::123456789012:assumed-role/example-role/s is not authorized to perform: lambda:GetMicrovmImageVersion …"),
            // Another writer's role: must not be attributed to this destination.
            new LogEvent(t, "[x5]: ERROR: User: arn:aws:sts::123456789012:assumed-role/other-role/s is not authorized to perform: sqs:SendMessage"),
            new LogEvent(t, "[x1]: ERROR: not authorized to perform: <script>:alert"),
        ], false));

        var (_, output, _) = Run(obs, "diagnose", Listener, "--output", "json");

        using var doc = JsonDocument.Parse(output);
        var findings = doc.RootElement.GetProperty("result").GetProperty("report").GetProperty("listeners")[0]
            .GetProperty("destinations")[0].GetProperty("findings").EnumerateArray()
            .Where(f => f.GetProperty("ruleId").GetString() == "destination.role-missing-permission")
            .Select(f => f.GetProperty("title").GetString())
            .ToList();
        Assert.Equal(2, findings.Count);
        Assert.Contains("The destination role is missing permission lambda:PassNetworkConnector", findings);
        Assert.Contains("The destination role is missing permission lambda:GetMicrovmImageVersion", findings);
        Assert.DoesNotContain(findings, f => f!.Contains("script", StringComparison.Ordinal));
    }

    [Fact]
    public void Error_looking_function_log_lines_are_a_possible_warning_not_a_confirmed_error()
    {
        var obs = Healthy();
        obs.Logs["/aws/lambda/packet-handler"] = Signal<LogQueryResult>.Of(new LogQueryResult(
            [new LogEvent(DateTimeOffset.UtcNow, "ERROR Unhandled exception")], false));
        var (_, output, _) = Run(obs, "diagnose", Listener, "--output", "json");
        using var doc = JsonDocument.Parse(output);
        var target = doc.RootElement.GetProperty("result").GetProperty("report").GetProperty("listeners")[0]
            .GetProperty("destinations")[0].GetProperty("targets")[0];
        var finding = target.GetProperty("findings").EnumerateArray().Single(f => f.GetProperty("ruleId").GetString() == "lambda.error-log-lines");
        Assert.Equal("warning", finding.GetProperty("health").GetString());
        Assert.Equal("possible", finding.GetProperty("confidence").GetString());
        Assert.True(finding.GetProperty("evidence")[0].GetProperty("untrusted").GetBoolean());
    }

    [Fact]
    public void Metrics_are_queried_in_the_target_region()
    {
        var obs = Healthy();
        Run(obs, "metrics", Listener);

        Assert.Contains("us-west-2", obs.MetricRegions);
    }

    [Fact]
    public void Metrics_command_shows_values_and_states()
    {
        var (code, output, _) = Run(Healthy(), "metrics", Listener);

        Assert.Equal(0, code);
        Assert.Contains("1,000 units", output, StringComparison.Ordinal);
        Assert.Contains("invocations", output, StringComparison.Ordinal);
        Assert.Contains("size-weighted", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Stack_name_selects_all_listeners_in_the_stack()
    {
        var (code, output, _) = Run(Healthy(), "inspect", "demo");

        Assert.Equal(0, code);
        Assert.Contains(Listener, output, StringComparison.Ordinal);
    }

    [Fact]
    public void Since_is_validated()
    {
        Assert.Equal(2, Run(Healthy(), "diagnose", "--since", "1y").Code);
        Assert.Equal(2, Run(Healthy(), "diagnose", "--since", "30d").Code);
        Assert.Equal(0, Run(Healthy(), "diagnose", Listener, "--since", "6h").Code);
    }
}
