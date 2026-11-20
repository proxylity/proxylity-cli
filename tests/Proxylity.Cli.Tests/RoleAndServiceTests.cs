using System.Text.Json;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;
using Proxylity.Cli.Core.Observation.Adapters;

namespace Proxylity.Cli.Tests;

public class TrustPolicyTests
{
    [Fact]
    public void A_trust_policy_with_an_external_id_condition_is_recognized()
    {
        var t = TrustPolicy.Analyze("""
            { "Version": "2012-10-17", "Statement": [{ "Effect": "Allow",
              "Principal": { "AWS": "arn:aws:iam::123456789012:role/service" }, "Action": "sts:AssumeRole",
              "Condition": { "StringEquals": { "sts:ExternalId": "example" } } }] }
            """);

        Assert.True(t.AllowsAssumeRole);
        Assert.True(t.RequiresExternalId);
    }

    [Fact]
    public void Any_allowing_statement_without_the_condition_means_it_is_not_required()
    {
        var t = TrustPolicy.Analyze("""
            { "Statement": [
              { "Effect": "Allow", "Principal": { "AWS": ["arn:aws:iam::123456789012:role/service"] }, "Action": ["sts:AssumeRole"],
                "Condition": { "StringEquals": { "sts:ExternalId": "x" } } },
              { "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::123456789012:root" }, "Action": "sts:AssumeRole" } ] }
            """);

        Assert.True(t.AllowsAssumeRole);
        Assert.False(t.RequiresExternalId);
    }

    [Fact]
    public void Service_principals_and_deny_statements_do_not_count()
    {
        var t = TrustPolicy.Analyze("""
            { "Statement": { "Effect": "Allow", "Principal": { "Service": "lambda.amazonaws.com" }, "Action": "sts:AssumeRole" } }
            """);

        Assert.False(t.AllowsAssumeRole);
        Assert.False(t.RequiresExternalId);
    }
}

public class RoleCheckTests
{
    private const string Listener = "demo-Listener-1a2b3c4d";
    private const string Role = "arn:aws:iam::123456789012:role/example-role";

    private static (int Code, JsonElement Destination, string Text, FakeObservabilitySource Obs) Run(FakeObservabilitySource obs)
    {
        string Invoke(params string[] args)
        {
            var stdout = new StringWriter();
            var app = new CliApp(stdout, new StringWriter(), _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => obs);
            app.RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
            return stdout.ToString();
        }

        var json = Invoke("diagnose", Listener, "--output", "json");
        var text = Invoke("diagnose", Listener, "--no-color");
        var doc = JsonDocument.Parse(json);
        var destination = doc.RootElement.GetProperty("result").GetProperty("report").GetProperty("listeners")[0].GetProperty("destinations")[0].Clone();
        return (0, destination, text, obs);
    }

    private static List<string> RuleIds(JsonElement destination) =>
        [.. destination.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("ruleId").GetString()!)];

    [Fact]
    public void A_good_role_is_checked_for_delivery_logs_and_metrics()
    {
        var obs = new FakeObservabilitySource();
        var (_, destination, _, _) = Run(obs);

        Assert.Contains("destination.role-ok", RuleIds(destination));

        // One simulation per role check, covering delivery, logs and metrics together.
        // Run() executes diagnose twice (JSON and text), so expect exactly one call per run.
        var calls = obs.Simulations.Where(s => s.Role == Role && s.Actions.Contains("lambda:InvokeFunction", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, calls.Count);
        var call = calls[0];
        Assert.Contains("logs:PutLogEvents", call.Actions, StringComparison.Ordinal);
        Assert.Contains("cloudwatch:PutMetricData", call.Actions, StringComparison.Ordinal);
        Assert.Contains(":function:packet-handler", call.Resources, StringComparison.Ordinal);
        Assert.Contains(":log-group:/example/dest:log-stream:", call.Resources, StringComparison.Ordinal);
        Assert.Contains("*", call.Resources.Split(','));
    }

    [Fact]
    public void A_missing_role_is_a_confirmed_error_and_skips_simulation()
    {
        var obs = new FakeObservabilitySource();
        obs.Roles[Role] = Signal<RoleTrust>.NotFound("no such role");

        var (_, destination, _, _) = Run(obs);

        Assert.Contains("destination.role-not-found", RuleIds(destination));
        Assert.Empty(obs.Simulations);
    }

    [Fact]
    public void Trust_without_external_id_is_a_warning()
    {
        var obs = new FakeObservabilitySource();
        obs.Roles[Role] = Signal<RoleTrust>.Of(new RoleTrust(true, false));

        var (_, destination, _, _) = Run(obs);

        Assert.Contains("destination.role-no-external-id", RuleIds(destination));
        Assert.DoesNotContain("destination.role-ok", RuleIds(destination));
    }

    [Fact]
    public void Denied_delivery_and_logging_permissions_are_reported_by_purpose()
    {
        var obs = new FakeObservabilitySource();
        obs.DeniedActions.Add("lambda:InvokeFunction");
        obs.ExplicitlyDeniedActions.Add("logs:PutLogEvents");

        var (_, destination, _, _) = Run(obs);
        var findings = destination.GetProperty("findings").EnumerateArray().ToList();

        var deliver = findings.Single(f => f.GetProperty("ruleId").GetString() == "destination.role-cannot-deliver");
        Assert.Equal("error", deliver.GetProperty("health").GetString());
        Assert.Equal("likely", deliver.GetProperty("confidence").GetString());
        var log = findings.Single(f => f.GetProperty("ruleId").GetString() == "destination.role-cannot-log");
        Assert.Equal("confirmed", log.GetProperty("confidence").GetString());
    }

    [Fact]
    public void A_simulator_permission_problem_is_one_note_not_many_findings()
    {
        var obs = new FakeObservabilitySource { DenySimulation = true };

        var (_, destination, text, _) = Run(obs);

        Assert.DoesNotContain(RuleIds(destination), id => id.StartsWith("destination.role-cannot", StringComparison.Ordinal));
        Assert.Contains("Role permissions were not checked", text, StringComparison.Ordinal);
        Assert.Contains("iam:SimulatePrincipalPolicy", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Roles_in_other_accounts_are_not_read()
    {
        Assert.True(RoleChecks.InAccount("arn:aws:iam::123456789012:role/r", "123456789012"));
        Assert.False(RoleChecks.InAccount("arn:aws:iam::210987654321:role/r", "123456789012")); // gate:allow (synthetic second account for a cross-account test)
        Assert.False(RoleChecks.InAccount("not-an-arn", "123456789012"));
    }
}

public class WildcardRegionTests
{
    [Fact]
    public async Task A_wildcard_region_arn_is_inspected_in_the_cli_region()
    {
        var target = new DestinationTarget("*", Resolved<string>.Ok("arn:aws:sqs:*:123456789012:jobs"), DestinationService.Sqs, "*", "jobs");
        var destination = new DestinationInfo("d", NameSource.Declared, false, Resolved<bool>.Absent, Resolved<string>.Absent, null, [target], false);
        var listener = new ListenerInfo(
            new StackRef("s", "arn:aws:cloudformation:us-west-2:123456789012:stack/s/1", "us-west-2", "123456789012", "CREATE_COMPLETE"),
            "L", "s-L-00000000", false, Resolved<string>.Ok("udp"), Resolved<bool>.Absent, Resolved<string>.Absent, null,
            new ClientRestrictionsInfo(ClientRestrictionsForm.Object, 1, 0), [destination]);
        var source = new FakeObservabilitySource();

        var report = await new ObservationCollector(source, "us-west-2", new CollectorOptions(false, false))
            .CollectAsync([listener], new TimeWindow(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow), CancellationToken.None);

        var observed = report.Listeners[0].Destinations[0].Targets[0].Target;
        Assert.True(observed.RegionFromIngress);
        Assert.Equal("arn:aws:sqs:us-west-2:123456789012:jobs", observed.Arn.Value);
        Assert.Contains(source.ResourceReads, r => r.Identifier == "https://sqs.us-west-2.amazonaws.com/123456789012/jobs");
    }
}

public class SharedLogGroupTests
{
    [Fact]
    public void Entries_in_a_shared_log_group_are_reported_once_on_the_first_writer()
    {
        var logs = new LogObservation("/shared", ["us-west-2"],
            Signal<IReadOnlyList<LogSample>>.Of([new LogSample(DateTimeOffset.UtcNow, "ERROR", 3, "something failed")]), false);
        DestinationInfo Dest(string name) => new(name, NameSource.Declared, false, Resolved<bool>.Absent, Resolved<string>.Ok("/shared"),
            new RoleInfo(Resolved<string>.Ok($"arn:aws:iam::123456789012:role/{name}-role"), false), [], false);
        var a = Dest("a");
        var b = Dest("b");
        var listener = new ListenerInfo(
            new StackRef("s", "arn:aws:cloudformation:us-west-2:123456789012:stack/s/1", "us-west-2", "123456789012", "CREATE_COMPLETE"),
            "L", "s-L-00000000", false, Resolved<string>.Ok("udp"), Resolved<bool>.Absent, Resolved<string>.Ok("/shared"), null,
            new ClientRestrictionsInfo(ClientRestrictionsForm.Object, 1, 0), [a, b]);
        var report = new ObservationReport(new TimeWindow(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow),
            [new ListenerObservation(listener, ["us-west-2"], new Dictionary<string, Signal<double>>(), logs,
                [
                    new DestinationObservation(a, ["us-west-2"], new Dictionary<string, Signal<double>>(), logs, [], []),
                    new DestinationObservation(b, ["us-west-2"], new Dictionary<string, Signal<double>>(), logs, [], []),
                ], [])], []);

        var l = Diagnoser.Diagnose(report).Listeners[0];

        var shared = Assert.Single(l.Findings, f => f.RuleId == "listener.log-error");
        Assert.Contains("shared by 3 writers", shared.Title, StringComparison.Ordinal);
        Assert.All(l.Destinations, d => Assert.DoesNotContain(d.Findings, f => f.RuleId == "destination.log-error"));
    }
}

public class ServiceAdapterTests
{
    private static ServiceAdapter Adapter(DestinationService s) => (ServiceAdapter)TargetAdapters.For(s)!;

    private static List<Finding> Diagnose(DestinationService service, string arn, Dictionary<string, double> metrics, double? accepted = null)
    {
        var parsed = ArnParser.Parse(arn)!;
        var target = new DestinationTarget("*", Resolved<string>.Ok(arn), service, parsed.Region.Length > 0 ? parsed.Region : null, ArnParser.ResourceNameOf(parsed, service));
        var destination = new DestinationInfo("d", NameSource.Declared, false, Resolved<bool>.Ok(true), Resolved<string>.Absent, null, [target], false);
        var observation = new TargetObservation(target,
            Signal<TargetDescription>.Of(new TargetDescription("x", new Dictionary<string, string>())),
            metrics.ToDictionary(kv => kv.Key, kv => Signal<double>.Of(kv.Value)), null, []);
        var destinationMetrics = accepted is null
            ? new Dictionary<string, Signal<double>>()
            : new Dictionary<string, Signal<double>> { [MetricKeys.Ingress] = Signal<double>.Of(accepted.Value) };
        var destinationObservation = new DestinationObservation(destination, ["us-west-2"], destinationMetrics, null, [observation], []);
        return [.. Adapter(service).Diagnose(observation, destinationObservation)];
    }

    [Fact]
    public void Every_documented_service_has_an_adapter()
    {
        foreach (var s in new[]
        {
            DestinationService.Lambda, DestinationService.LambdaMicrovm, DestinationService.StepFunctions, DestinationService.Firehose,
            DestinationService.Sqs, DestinationService.Sns, DestinationService.Kinesis, DestinationService.DynamoDb,
            DestinationService.CloudWatchLogs, DestinationService.S3, DestinationService.EventBridge, DestinationService.ApiGateway,
        })
        {
            Assert.NotNull(TargetAdapters.For(s));
        }
    }

    [Fact]
    public void Step_functions_failures_and_throttles_are_errors()
    {
        var f = Diagnose(DestinationService.StepFunctions, "arn:aws:states:us-west-2:123456789012:stateMachine:flow",
            new() { ["states.started"] = 10, ["states.failed"] = 2, ["states.throttled"] = 1 });

        Assert.Contains(f, x => x.RuleId == "stepfunctions.failures" && x.Health == Health.Error);
        Assert.Contains(f, x => x.RuleId == "stepfunctions.throttled" && x.Health == Health.Error);
        Assert.DoesNotContain(f, x => x.Health == Health.Healthy);
    }

    [Fact]
    public void Express_state_machines_need_start_sync_execution()
    {
        var target = new DestinationTarget("*", Resolved<string>.Ok("arn:aws:states:us-west-2:123456789012:stateMachine:flow"), DestinationService.StepFunctions, "us-west-2", "flow");
        var destination = new DestinationInfo("d", NameSource.Declared, false, Resolved<bool>.Absent, Resolved<string>.Absent, null, [target], false);
        var adapter = Adapter(DestinationService.StepFunctions);

        var express = adapter.Permissions(target, destination, new TargetDescription("flow", new Dictionary<string, string> { ["type"] = "EXPRESS" }));
        var standard = adapter.Permissions(target, destination, new TargetDescription("flow", new Dictionary<string, string> { ["type"] = "STANDARD" }));

        Assert.Contains("states:StartSyncExecution", express[0].Actions);
        Assert.Contains("states:StartExecution", standard[0].Actions);
    }

    [Fact]
    public void Accepted_packets_with_no_activity_at_the_service_is_a_possible_problem()
    {
        var f = Diagnose(DestinationService.Sqs, "arn:aws:sqs:us-west-2:123456789012:jobs", new() { ["sqs.sent"] = 0 }, accepted: 50);

        var finding = Assert.Single(f, x => x.RuleId == "sqs.accepted-not-received");
        Assert.Equal(Confidence.Possible, finding.Confidence);
    }

    [Fact]
    public void Activity_without_problems_is_healthy_and_backlogs_are_flagged()
    {
        var f = Diagnose(DestinationService.Sqs, "arn:aws:sqs:us-west-2:123456789012:jobs", new() { ["sqs.sent"] = 40, ["sqs.oldestAge"] = 7200 });

        Assert.Contains(f, x => x.RuleId == "sqs.receiving" && x.Health == Health.Healthy);
        Assert.Contains(f, x => x.RuleId == "sqs.backlog" && x.Health == Health.Warning);
    }

    [Fact]
    public void Firehose_delivery_below_100_percent_is_a_warning()
    {
        var f = Diagnose(DestinationService.Firehose, "arn:aws:firehose:us-west-2:123456789012:deliverystream/archive",
            new() { ["firehose.incoming"] = 100, ["firehose.s3Success"] = 0.9 });

        Assert.Contains(f, x => x.RuleId == "firehose.success-below-100");
    }

    [Fact]
    public void Services_without_useful_metrics_say_so()
    {
        var f = Diagnose(DestinationService.S3, "arn:aws:s3:::bucket/prefix/", []);

        Assert.Equal("s3.metrics-not-inspected", Assert.Single(f).RuleId);
    }

    [Theory]
    [InlineData("arn:aws:sqs:us-west-2:123456789012:jobs", "https://sqs.us-west-2.amazonaws.com/123456789012/jobs")]
    [InlineData("arn:aws:firehose:us-west-2:123456789012:deliverystream/archive", "archive")]
    [InlineData("arn:aws:logs:us-west-2:123456789012:log-group:/a/b:*", "/a/b")]
    [InlineData("arn:aws:execute-api:us-west-2:123456789012:abc123/prod/POST/hook", "abc123")]
    [InlineData("arn:aws:s3:::bucket/prefix/", "bucket")]
    public void Cloud_control_identifiers_are_built_from_arns(string arn, string expected)
    {
        var parsed = ArnParser.Parse(arn)!;
        var adapter = Adapter(ArnParser.ServiceOf(parsed));

        Assert.Equal(expected, adapter.Spec.Identifier(parsed));
    }

    [Fact]
    public void S3_permissions_are_checked_on_an_object_under_the_prefix()
    {
        var target = new DestinationTarget("*", Resolved<string>.Ok("arn:aws:s3:::bucket/prefix/"), DestinationService.S3, null, "bucket");
        var destination = new DestinationInfo("d", NameSource.Declared, false, Resolved<bool>.Absent, Resolved<string>.Absent, null, [target], false);

        var p = Assert.Single(Adapter(DestinationService.S3).Permissions(target, destination, null));

        Assert.Equal(["s3:PutObject"], p.Actions);
        Assert.Equal("arn:aws:s3:::bucket/prefix/" + ServiceAdapter.ProbeName, p.Resource);
    }
}
