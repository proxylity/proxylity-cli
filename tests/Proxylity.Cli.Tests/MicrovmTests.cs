using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;
using Proxylity.Cli.Core.Observation.Adapters;
using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Tests;

public class MicrovmTests
{
    private const string ImageArn = "arn:aws:lambda:us-west-2:123456789012:microvm-image:echo";

    private static DestinationTarget Target(string arn = ImageArn) =>
        new("*", Resolved<string>.Ok(arn), DestinationService.LambdaMicrovm, "us-west-2", "echo");

    private static DestinationInfo Destination(Dictionary<string, string>? args = null, DestinationTarget? target = null) =>
        new("echo-dest", NameSource.Declared, false, Resolved<bool>.Ok(true), Resolved<string>.Absent,
            new RoleInfo(Resolved<string>.Ok("arn:aws:iam::123456789012:role/r"), false), [target ?? Target()], false, args);

    private static Signal<IReadOnlyDictionary<string, string>> Image(string state = "UPDATED", string active = "5.0", string failed = "") =>
        Signal<IReadOnlyDictionary<string, string>>.Of(new Dictionary<string, string>
        {
            ["State"] = state,
            ["LatestActiveImageVersion"] = active,
            ["LatestFailedImageVersion"] = failed,
            ["Name"] = "echo",
        });

    private static async Task<List<Finding>> DiagnoseAsync(
        Signal<IReadOnlyDictionary<string, string>> image,
        Dictionary<string, string>? args = null,
        Dictionary<string, Signal<double>>? destinationMetrics = null,
        LogObservation? runtimeLogs = null,
        string arn = ImageArn)
    {
        var target = Target(arn);
        var destination = Destination(args, target);
        var source = new FakeObservabilitySource();
        source.Resources[ImageArn] = image;
        var description = await new MicrovmAdapter().DescribeAsync(target, destination, source, CancellationToken.None);
        var targetObservation = new TargetObservation(target, description, new Dictionary<string, Signal<double>>(), runtimeLogs, []);
        var destinationObservation = new DestinationObservation(destination, ["us-west-2"],
            destinationMetrics ?? new Dictionary<string, Signal<double>>(), null, [targetObservation], []);
        var listener = new ListenerInfo(
            new StackRef("s", "arn:aws:cloudformation:us-west-2:123456789012:stack/s/1", "us-west-2", "123456789012", "CREATE_COMPLETE"),
            "L", "s-L-00000000", false, Resolved<string>.Ok("udp"), Resolved<bool>.Absent, Resolved<string>.Absent, null,
            new ClientRestrictionsInfo(ClientRestrictionsForm.Object, 1, 0), [destination]);
        var report = new ObservationReport(new TimeWindow(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow),
            [new ListenerObservation(listener, ["us-west-2"], new Dictionary<string, Signal<double>>(), null, [destinationObservation], [])], []);
        return [.. Diagnoser.Diagnose(report).Listeners[0].Destinations[0].Targets[0].Findings];
    }

    [Fact]
    public async Task Describe_reads_the_unversioned_image_and_records_documented_arguments()
    {
        var source = new FakeObservabilitySource();
        source.Resources[ImageArn] = Image();
        var args = new Dictionary<string, string> { ["ExecutionRoleArn"] = "arn:aws:iam::123456789012:role/exec", ["TenantIdExpression"] = "set" };

        var d = await new MicrovmAdapter().DescribeAsync(Target(ImageArn + ":3"), Destination(args), source, CancellationToken.None);

        Assert.Equal(("AWS::Lambda::MicrovmImage", ImageArn), Assert.Single(source.ResourceReads));
        var p = d.Value!.Properties;
        Assert.Equal("5.0", p["latestActiveImageVersion"]);
        Assert.Equal("3", p["pinnedVersion"]);
        Assert.Equal("set", p["executionRole"]);
        Assert.Equal("/aws/lambda-microvms/echo", p["runtimeLogGroup"]);
        Assert.Equal("per tenant", p["tenancy"]);
        Assert.False(p.ContainsKey("latestFailedImageVersion"));
    }

    [Fact]
    public async Task Failed_image_and_missing_active_version_are_errors()
    {
        var findings = await DiagnoseAsync(Image(state: "CREATE_FAILED", active: ""));

        Assert.Contains(findings, f => f.RuleId == "microvm.image-failed" && f.Health == Health.Error);
        Assert.Contains(findings, f => f.RuleId == "microvm.no-active-version" && f.Health == Health.Error);
    }

    [Fact]
    public async Task A_newer_failed_build_is_a_warning_and_a_pinned_failed_version_is_an_error()
    {
        var unpinned = await DiagnoseAsync(Image(active: "5.0", failed: "6.0"));
        Assert.Contains(unpinned, f => f.RuleId == "microvm.latest-build-failed" && f.Health == Health.Warning);

        var older = await DiagnoseAsync(Image(active: "6.0", failed: "5.0"));
        Assert.DoesNotContain(older, f => f.RuleId == "microvm.latest-build-failed");

        var pinned = await DiagnoseAsync(Image(active: "5.0", failed: "6.0"), arn: ImageArn + ":6.0");
        Assert.Contains(pinned, f => f.RuleId == "microvm.pinned-to-failed-version");
    }

    [Fact]
    public async Task Missing_image_is_a_confirmed_error()
    {
        var findings = await DiagnoseAsync(Signal<IReadOnlyDictionary<string, string>>.NotFound("gone"));

        var f = Assert.Single(findings);
        Assert.Equal("microvm.not-found", f.RuleId);
        Assert.Equal(Health.Error, f.Health);
    }

    [Fact]
    public async Task Runtime_logs_need_an_execution_role_and_an_existing_group()
    {
        var noRole = await DiagnoseAsync(Image());
        Assert.Contains(noRole, f => f.RuleId == "microvm.runtime-logs-off" && f.Health == Health.NotConfigured);

        var missingGroup = await DiagnoseAsync(Image(), new() { ["ExecutionRoleArn"] = "arn:aws:iam::123456789012:role/exec" },
            runtimeLogs: new LogObservation("/aws/lambda-microvms/echo", ["us-west-2"], Signal<IReadOnlyList<LogSample>>.NotFound("missing"), false));
        Assert.Contains(missingGroup, f => f.RuleId == "microvm.runtime-log-group-missing");
        Assert.DoesNotContain(missingGroup, f => f.RuleId == "microvm.runtime-logs-off");
    }

    [Fact]
    public async Task Tenant_log_streams_require_a_tenant_id()
    {
        var findings = await DiagnoseAsync(Image(), new() { ["UseTenantIdForLogStreamName"] = "true" });

        Assert.Contains(findings, f => f.RuleId == "microvm.tenant-streams-without-tenant");
    }

    [Fact]
    public async Task Replies_are_positive_evidence_and_no_replies_is_only_possible()
    {
        Signal<double> v(double x) => Signal<double>.Of(x);
        var replying = await DiagnoseAsync(Image(), destinationMetrics: new() { [MetricKeys.Ingress] = v(10), [MetricKeys.Egress] = v(10), [MetricKeys.Errors] = v(0) });
        Assert.Contains(replying, f => f.RuleId == "microvm.replying" && f.Health == Health.Healthy);

        var silent = await DiagnoseAsync(Image(), destinationMetrics: new() { [MetricKeys.Ingress] = v(10), [MetricKeys.Egress] = v(0) });
        var noReplies = Assert.Single(silent, f => f.RuleId == "microvm.no-replies");
        Assert.Equal(Confidence.Possible, noReplies.Confidence);
        Assert.NotEqual(Health.Error, noReplies.Health);
    }

    [Fact]
    public void Only_documented_arguments_are_read_from_templates()
    {
        var stack = new StackRef("demo", "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000", "us-west-2", "123456789012", "CREATE_COMPLETE");
        const string template = """
            Resources:
              Listener:
                Type: Custom::ProxylityUdpGatewayListener
                Properties:
                  Protocols: [udp]
                  Destinations:
                    - Name: vm
                      DestinationArn: arn:aws:lambda:us-west-2:123456789012:microvm-image:echo
                      Arguments:
                        ExecutionRoleArn: arn:aws:iam::123456789012:role/exec
                        RunHookExtraData: application-secret-ish-value
                        TenantId: customer-42
                        EgressNetworkConnectorArns: [a, b]
                        IdleDurationSeconds: "600"
            """;
        var model = StackModelBuilder.Build(new StackData(stack,
            [new DeployedResource("Listener", "Custom::ProxylityUdpGatewayListener", "demo-Listener-00000000", "CREATE_COMPLETE")],
            new Dictionary<string, string>(), TemplateParser.Parse(template)));

        var args = model.Listeners[0].Destinations[0].Arguments!;
        Assert.Equal("arn:aws:iam::123456789012:role/exec", args["ExecutionRoleArn"]);
        Assert.Equal("600", args["IdleDurationSeconds"]);
        Assert.Equal("2", args["EgressNetworkConnectorArns"]);
        Assert.Equal("set", args["TenantId"]);
        Assert.False(args.ContainsKey("RunHookExtraData"));
        Assert.DoesNotContain("customer-42", model.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("application-secret-ish-value", string.Join(',', args.Values), StringComparison.Ordinal);
    }
}
