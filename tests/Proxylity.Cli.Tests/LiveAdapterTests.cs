using Proxylity.Cli.Aws;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;
using Proxylity.Cli.Core.Observation.Adapters;

namespace Proxylity.Cli.Tests;

/// <summary>
/// Opt-in checks against real AWS resources, read-only, using the ambient credentials. Set
/// PROXYLITY_LIVE_TARGETS to a semicolon-separated list of target ARNs (any resources of supported types;
/// they need not be Proxylity destinations). Without it the test does nothing.
/// </summary>
public class LiveAdapterTests
{
    [Fact]
    public async Task Adapters_describe_and_read_metrics_for_real_resources()
    {
        var arns = (Environment.GetEnvironmentVariable("PROXYLITY_LIVE_TARGETS") ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (arns.Length == 0)
        {
            return;
        }

        using var source = new AwsObservabilitySource();
        var end = DateTimeOffset.UtcNow;
        var window = new TimeWindow(end.AddDays(-14), end);
        var failures = new List<string>();

        foreach (var arn in arns)
        {
            var parsed = ArnParser.Parse(arn) ?? throw new InvalidOperationException($"not an ARN: {arn}");
            var service = ArnParser.ServiceOf(parsed);
            var adapter = TargetAdapters.For(service) ?? throw new InvalidOperationException($"no adapter for {service}");
            var target = new DestinationTarget("*", Resolved<string>.Ok(arn), service, parsed.Region.Length > 0 ? parsed.Region : null, ArnParser.ResourceNameOf(parsed, service));
            var destination = new DestinationInfo("live", NameSource.Declared, false, Resolved<bool>.Absent, Resolved<string>.Absent, null, [target], false);

            var description = await adapter.DescribeAsync(target, destination, source, CancellationToken.None);
            if (!description.IsAvailable)
            {
                failures.Add($"{service}: describe {description.State} ({description.Detail})");
                continue;
            }

            var metrics = adapter.Metrics(target, description.Value!);
            if (metrics.Count > 0)
            {
                var queries = metrics.Select((m, i) => new MetricQuery($"m{i}", m.Namespace, m.MetricName, m.Dimensions, m.Statistic)).ToList();
                var values = await source.GetMetricsAsync(parsed.Region, queries, window, CancellationToken.None);
                failures.AddRange(values.Where(v => v.Value.State is SignalState.Failed or SignalState.NotAccessible)
                    .Select(v => $"{service}: metric {queries.First(q => q.Id == v.Key).MetricName} {v.Value.State} ({v.Value.Detail})"));
            }

            Console.WriteLine($"live {service}: described ({string.Join(", ", description.Value!.Properties.Keys)}), {metrics.Count} metric(s) read");
        }

        Assert.Empty(failures);
    }
}
