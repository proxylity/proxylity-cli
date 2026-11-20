using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;
using Proxylity.Cli.Core.Observation.Adapters;

namespace Proxylity.Cli.Tests;

public class RegionMapDiagnosisTests
{
    private static DestinationTarget Target(string region) =>
        new(region, Resolved<string>.Ok($"arn:aws:lambda:{region}:123456789012:function:handler"), DestinationService.Lambda, region, "handler");

    private static TargetObservation Idle(DestinationTarget t) =>
        new(t,
            Signal<TargetDescription>.Of(new TargetDescription("handler", new Dictionary<string, string>
            {
                ["state"] = "Active",
                ["timeoutSeconds"] = "30",
                ["logGroup"] = "/aws/lambda/handler",
            })),
            new Dictionary<string, Signal<double>> { [MetricKeys.LambdaInvocations] = Signal<double>.NoData() },
            null,
            []);

    [Fact]
    public void Idle_regional_targets_are_not_blamed_for_traffic_accepted_in_another_region()
    {
        var west = Target("us-west-2");
        var east = Target("us-east-1");
        var destination = new DestinationInfo("regional", NameSource.Declared, false, Resolved<bool>.Ok(true), Resolved<string>.Absent,
            new RoleInfo(Resolved<string>.Ok("arn:aws:iam::123456789012:role/r"), false), [west, east], false);
        var listener = new ListenerInfo(
            new StackRef("s", "arn:aws:cloudformation:us-west-2:123456789012:stack/s/1", "us-west-2", "123456789012", "CREATE_COMPLETE"),
            "L", "s-L-00000000", false, Resolved<string>.Ok("udp"), Resolved<bool>.Absent, Resolved<string>.Absent, null,
            new ClientRestrictionsInfo(ClientRestrictionsForm.Object, 1, 0), [destination]);

        Signal<double> v(double x) => Signal<double>.Of(x);
        var westMetrics = new Dictionary<string, Signal<double>> { [MetricKeys.Ingress] = v(20), [MetricKeys.Errors] = v(0) };
        var eastMetrics = new Dictionary<string, Signal<double>> { [MetricKeys.Ingress] = Signal<double>.NoData(), [MetricKeys.Errors] = Signal<double>.NoData() };
        var westTarget = Idle(west) with { Metrics = new Dictionary<string, Signal<double>> { [MetricKeys.LambdaInvocations] = v(20), [MetricKeys.LambdaErrors] = v(0) } };

        var report = new ObservationReport(
            new TimeWindow(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow),
            [new ListenerObservation(listener, ["us-west-2"], new Dictionary<string, Signal<double>>(), null,
                [new DestinationObservation(destination, ["us-east-1", "us-west-2"], westMetrics, null, [westTarget, Idle(east)], [],
                    new Dictionary<string, IReadOnlyDictionary<string, Signal<double>>> { ["us-west-2"] = westMetrics, ["us-east-1"] = eastMetrics })],
                [])],
            []);

        var diagnosed = Diagnoser.Diagnose(report).Listeners[0].Destinations[0];

        Assert.Contains(diagnosed.Targets[0].Findings, f => f.RuleId == "lambda.healthy");
        Assert.DoesNotContain(diagnosed.Targets[1].Findings, f => f.RuleId == "lambda.accepted-not-invoked");
        Assert.Contains(diagnosed.Targets[1].Findings, f => f.RuleId == "lambda.no-invocations");
    }
}
