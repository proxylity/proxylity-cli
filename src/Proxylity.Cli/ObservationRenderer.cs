using System.Globalization;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli;

/// <summary>
/// Text output for diagnose, metrics and logs. Every state has a word and a symbol; color is decoration.
/// Untrusted log text is already sanitized by the collector and is shown in quotes.
/// </summary>
internal sealed class ObservationRenderer(TextWriter output, bool color)
{
    public void RenderDiagnosis(DeploymentSnapshot snapshot, ObservationReport report, FindingSummary summary)
    {
        Header(snapshot, report.Window);
        if (report.Listeners.Count == 0)
        {
            output.WriteLine("No listeners to diagnose.");
        }

        foreach (var l in report.Listeners)
        {
            output.WriteLine();
            output.WriteLine($"{Bold("Listener")} {ListenerLabel(l.Listener)}  {Dim(Protocol(l.Listener))}");
            Findings(l.Findings, 2);
            foreach (var d in l.Destinations)
            {
                output.WriteLine($"  {Bold("Destination")} {d.Destination.Name ?? "(unnamed)"}");
                Findings(d.Findings, 4);
                foreach (var t in d.Targets)
                {
                    output.WriteLine($"    {Bold("→")} {TargetLabel(t.Target)}");
                    if (t.Description?.IsAvailable == true && DescribeTarget(t.Description.Value!.Properties) is { Length: > 0 } described)
                    {
                        output.WriteLine($"      {Dim(described)}");
                    }

                    Findings(t.Findings, 6);
                }
            }
        }

        output.WriteLine();
        var parts = new List<string>();
        void Part(int n, string word, Func<string, string> paint, bool plural = true)
        {
            if (n > 0)
            {
                parts.Add(paint($"{n} {word}{(n == 1 || !plural ? string.Empty : "s")}"));
            }
        }

        Part(summary.Errors, "error", Red);
        Part(summary.Warnings, "warning", Yellow);
        Part(summary.NotAccessible, "not accessible", s => s, plural: false);
        Part(summary.Unknown, "unknown", s => s);
        Part(summary.NotConfigured, "not configured", Dim, plural: false);
        Part(summary.Healthy, "ok", Green);
        output.WriteLine($"{Bold("Summary")}: {(parts.Count == 0 ? "nothing to report" : string.Join(", ", parts))}");
        output.WriteLine(Dim("No data is never treated as healthy. Log text is shown as received and may contain data from network traffic."));
        Notes(report.Notes);
    }

    public void RenderMetrics(DeploymentSnapshot snapshot, ObservationReport report)
    {
        Header(snapshot, report.Window);
        foreach (var l in report.Listeners)
        {
            output.WriteLine();
            output.WriteLine($"{Bold("Listener")} {ListenerLabel(l.Listener)}  {Dim("regions " + string.Join(", ", l.MetricRegions))}");
            Metric(l.Metrics, MetricKeys.Ingress, "ingress", Units, 2);
            Metric(l.Metrics, MetricKeys.IngressBytes, "ingress bytes", Bytes, 2);
            Metric(l.Metrics, MetricKeys.Filtered, "filtered", Units, 2);
            Metric(l.Metrics, MetricKeys.Errors, "errors", Count, 2);
            foreach (var d in l.Destinations.Where(d => !d.Destination.IsReferenceByName))
            {
                output.WriteLine($"  {Bold("Destination")} {d.Destination.Name}  {Dim("regions " + string.Join(", ", d.MetricRegions))}");
                Metric(d.Metrics, MetricKeys.Ingress, "accepted", Units, 4);
                Metric(d.Metrics, MetricKeys.Filtered, "filtered", Units, 4);
                Metric(d.Metrics, MetricKeys.Egress, "replies", Units, 4);
                Metric(d.Metrics, MetricKeys.Errors, "errors", Count, 4);
                foreach (var t in d.Targets.Where(t => t.Metrics.Count > 0))
                {
                    output.WriteLine($"    {Bold("→")} {TargetLabel(t.Target)}");
                    Metric(t.Metrics, MetricKeys.LambdaInvocations, "invocations", Count, 6);
                    Metric(t.Metrics, MetricKeys.LambdaErrors, "errors", Count, 6);
                    Metric(t.Metrics, MetricKeys.LambdaThrottles, "throttles", Count, 6);
                    Metric(t.Metrics, MetricKeys.LambdaDurationAvg, "duration avg", Millis, 6);
                    Metric(t.Metrics, MetricKeys.LambdaDurationMax, "duration max", Millis, 6);
                    Metric(t.Metrics, MetricKeys.LambdaConcurrencyMax, "concurrency max", Count, 6);
                }
            }
        }

        output.WriteLine();
        output.WriteLine(Dim("Proxylity packet counts are size-weighted units (1 per started KB), not raw datagrams. Listener and destination counts overlap; do not add them."));
        Notes(report.Notes);
    }

    public void RenderLogs(DeploymentSnapshot snapshot, ObservationReport report)
    {
        Header(snapshot, report.Window);
        // Listeners and destinations often share a log group: show each group once, naming every writer.
        var sources = new List<(string Label, LogObservation Logs)>();
        foreach (var l in report.Listeners)
        {
            if (l.Logs is not null)
            {
                sources.Add(($"listener {ListenerLabel(l.Listener)}", l.Logs));
            }

            sources.AddRange(l.Destinations.Where(d => d.Logs is not null).Select(d => ($"destination {d.Destination.Name}", d.Logs!)));
        }

        var groups = sources
            .GroupBy(s => (s.Logs.LogGroup, string.Join(',', s.Logs.Regions)))
            .Select(g => (Label: string.Join(", ", g.Select(x => x.Label).Distinct(StringComparer.Ordinal)), g.First().Logs))
            .ToList();
        var any = groups.Count > 0;
        {
            foreach (var (label, logs) in groups)
            {
                output.WriteLine();
                output.WriteLine($"{Bold(label)}  {Dim(logs.LogGroup + " · " + string.Join(", ", logs.Regions))}");
                switch (logs.Events.State)
                {
                    case SignalState.Available:
                        foreach (var e in logs.Events.Value!)
                        {
                            var count = e.Count > 1 ? Dim($" ×{e.Count}") : string.Empty;
                            output.WriteLine($"  {Dim(e.Timestamp.ToString("MM-dd HH:mm:ss", CultureInfo.InvariantCulture))} {Level(e.Level)} \"{e.Message}\"{count}");
                        }

                        if (logs.Truncated)
                        {
                            output.WriteLine(Dim("  (older entries in the window not shown; use --limit or a shorter --since)"));
                        }

                        break;
                    default:
                        output.WriteLine($"  {Describe(logs.Events.State, logs.Events.Detail)}");
                        break;
                }
            }
        }

        if (!any)
        {
            output.WriteLine();
            output.WriteLine("None of the selected listeners or destinations has a LogGroupName configured.");
        }

        output.WriteLine();
        output.WriteLine(Dim("Times are UTC. Log text is shown as received and may contain data from network traffic."));
        Notes(report.Notes);
    }

    private void Header(DeploymentSnapshot s, TimeWindow w)
    {
        var accounts = s.Stacks.Select(x => x.AccountId).Where(a => a.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        var account = accounts.Count == 1 ? $"account {accounts[0]}" : "account unknown";
        var minutes = (int)Math.Round(w.Length.TotalMinutes);
        var span = minutes % 1440 == 0 ? $"{minutes / 1440}d" : minutes % 60 == 0 ? $"{minutes / 60}h" : $"{minutes}m";
        var range = w.Start.Date == w.End.Date
            ? string.Create(CultureInfo.InvariantCulture, $"{w.Start:MM-dd HH:mm}–{w.End:HH:mm} UTC")
            : string.Create(CultureInfo.InvariantCulture, $"{w.Start:MM-dd HH:mm} – {w.End:MM-dd HH:mm} UTC");
        output.WriteLine($"{Bold("Proxylity")} {Dim("·")} {account} {Dim("·")} {string.Join(", ", s.Regions)} {Dim("·")} last {span} {Dim($"({range})")}");
    }

    private void Findings(IReadOnlyList<Finding> findings, int indent)
    {
        var pad = new string(' ', indent);
        foreach (var f in findings.OrderBy(f => Rank(f.Health)).ThenBy(f => f.Confidence))
        {
            var confidence = f.Confidence is Confidence.Confirmed ? string.Empty : Dim($" ({f.Confidence.ToString().ToLowerInvariant()})");
            output.WriteLine($"{pad}{Badge(f.Health)} {f.Title}{confidence}");
            if (f.Evidence.Count > 0)
            {
                var trusted = f.Evidence.Where(e => !e.Untrusted).Select(e => $"{e.Label} {e.Value}").ToList();
                if (trusted.Count > 0)
                {
                    output.WriteLine($"{pad}          {Dim(string.Join(" · ", trusted))}");
                }

                foreach (var e in f.Evidence.Where(e => e.Untrusted))
                {
                    output.WriteLine($"{pad}          {Dim(e.Label)} \"{e.Value}\"");
                }
            }

            foreach (var s in f.Suggestions)
            {
                output.WriteLine($"{pad}          {Dim("→")} {s}");
            }
        }
    }

    private void Metric(IReadOnlyDictionary<string, Signal<double>> metrics, string key, string label, Func<double, string> format, int indent)
    {
        if (!metrics.TryGetValue(key, out var s))
        {
            return;
        }

        var value = s.State == SignalState.Available ? format(s.Value) : Dim(Describe(s.State, s.Detail));
        output.WriteLine($"{new string(' ', indent)}{label.PadRight(16)}{value}");
    }

    private static string Describe(SignalState state, string? detail) => state switch
    {
        SignalState.NoData => "no data",
        SignalState.NotConfigured => detail ?? "not configured",
        SignalState.NotAccessible => detail ?? "not permitted",
        SignalState.NotFound => detail ?? "not found",
        SignalState.Failed => detail ?? "could not be read",
        _ => detail ?? state.ToString(),
    };

    private static int Rank(Health h) => h switch
    {
        Health.Error => 0,
        Health.Warning => 1,
        Health.NotAccessible => 2,
        Health.Unknown => 3,
        Health.NotConfigured => 4,
        _ => 5,
    };

    private string Badge(Health h) => h switch
    {
        Health.Error => Red("✗ ERROR  "),
        Health.Warning => Yellow("! WARN   "),
        Health.NotAccessible => Yellow("⊘ DENIED "),
        Health.Unknown => "? UNKNOWN",
        Health.NotConfigured => Dim("- OFF    "),
        _ => Green("✓ OK     "),
    };

    private string Level(string level) => level switch
    {
        "ERROR" => Red("ERROR"),
        "WARN" => Yellow("WARN "),
        "INFO" => Dim("INFO "),
        _ => Dim("-    "),
    };

    private static string ListenerLabel(ListenerInfo l) => l.Name ?? $"{l.Stack.Name}/{l.LogicalId}";

    private static string Protocol(ListenerInfo l) => $"({(l.Protocol.IsResolved ? l.Protocol.Value : "?")}, stack {l.Stack.Name})";

    /// <summary>A one-line summary of the target's description, in a fixed order of well-known keys.</summary>
    private static string DescribeTarget(IReadOnlyDictionary<string, string> p)
    {
        (string Key, string Label)[] keys =
        [
            ("state", "state"), ("runtime", "runtime"), ("memoryMb", "memory MB"), ("timeoutSeconds", "timeout s"),
            ("reservedConcurrency", "reserved concurrency"), ("latestActiveImageVersion", "active version"),
            ("pinnedVersion", "pinned version"), ("tenancy", "tenancy"), ("idleDurationSeconds", "idle suspend s"),
            ("type", "type"), ("fifo", "fifo"), ("shards", "shards"), ("billing", "billing"), ("retention days", "retention days"),
            ("name", "name"), ("existence", "existence"),
        ];
        return string.Join(" · ", keys.Where(k => p.ContainsKey(k.Key)).Select(k => $"{k.Label} {p[k.Key]}"));
    }

    private static string TargetLabel(DestinationTarget t)
    {
        var where = t.RegionFromIngress
            ? $" (region * resolves to the ingress region; checked in {t.ArnRegion})"
            : t.IngressRegionKey == "*" ? string.Empty : $" (from {t.IngressRegionKey})";
        return t.Arn.IsResolved
            ? $"{TextRenderer.ServiceLabel(t.Service)} {t.ResourceName ?? t.Arn.Value}{where}"
            : $"target unresolved{where}";
    }

    private void Notes(IReadOnlyList<Note> notes)
    {
        if (notes.Count == 0)
        {
            return;
        }

        output.WriteLine();
        foreach (var n in notes)
        {
            output.WriteLine($"{(n.Severity == "warning" ? Yellow("!") : Dim("-"))} {n.Message}");
        }
    }

    private static string Count(double v) => v.ToString("N0", CultureInfo.InvariantCulture);

    private static string Units(double v) => v.ToString("N0", CultureInfo.InvariantCulture) + " units";

    private static string Millis(double v) => v >= 1000 ? (v / 1000).ToString("0.00", CultureInfo.InvariantCulture) + " s" : v.ToString("0", CultureInfo.InvariantCulture) + " ms";

    private static string Bytes(double v) => v switch
    {
        >= 1 << 30 => (v / (1 << 30)).ToString("0.0", CultureInfo.InvariantCulture) + " GiB",
        >= 1 << 20 => (v / (1 << 20)).ToString("0.0", CultureInfo.InvariantCulture) + " MiB",
        >= 1 << 10 => (v / (1 << 10)).ToString("0.0", CultureInfo.InvariantCulture) + " KiB",
        _ => v.ToString("0", CultureInfo.InvariantCulture) + " B",
    };

    private string Bold(string s) => color ? $"\u001b[1m{s}\u001b[0m" : s;

    private string Dim(string s) => color ? $"\u001b[2m{s}\u001b[0m" : s;

    private string Red(string s) => color ? $"\u001b[31m{s}\u001b[0m" : s;

    private string Yellow(string s) => color ? $"\u001b[33m{s}\u001b[0m" : s;

    private string Green(string s) => color ? $"\u001b[32m{s}\u001b[0m" : s;
}
