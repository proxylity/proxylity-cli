using System.Globalization;
using System.Text;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli;

/// <summary>
/// Markdown output for pasting into issues, pull requests, chats and docs, with a Mermaid diagram of each
/// listener's delivery path. Content safety:
/// - fixed wording is escaped as Markdown text;
/// - resource names are inline code;
/// - untrusted text (log contents) appears only inside fenced code blocks whose fence is longer than any backtick
///   run in the content, so it can't render, link, or break out;
/// - Mermaid labels contain resource names reduced to a safe character set, and no click or link directives are emitted.
/// </summary>
internal sealed class MarkdownRenderer(TextWriter output)
{
    public void RenderList(DeploymentSnapshot s)
    {
        Header("Proxylity deployment", s, null);
        if (s.Listeners.Count == 0)
        {
            output.WriteLine("No listeners were found.");
            Notes(s.Notes);
            return;
        }

        output.WriteLine("| Stack | Listener | Protocol | Destinations |");
        output.WriteLine("|---|---|---|---|");
        foreach (var l in s.Listeners)
        {
            var destinations = string.Join("<br>", l.Destinations.Select(d => Cell(DestinationSummary(d))));
            output.WriteLine($"| {Code(l.Stack.Name)} | {Code(ListenerName(l))} | {Cell(Text(l.Protocol, "?"))} | {(destinations.Length == 0 ? "none" : destinations)} |");
        }

        output.WriteLine();
        Notes(s.Notes);
    }

    public void RenderAccess(AccessReport report)
    {
        output.WriteLine("# Proxylity access check");
        output.WriteLine();
        output.WriteLine($"Region {Code(report.Region)}. Read-only probes; nothing is changed.");
        output.WriteLine();
        output.WriteLine("| Action | Result | Used for |");
        output.WriteLine("|---|---|---|");
        foreach (var p in report.Probes)
        {
            var state = p.State switch
            {
                AccessState.Allowed => "allowed",
                AccessState.Denied => "denied",
                AccessState.Inconclusive => "inconclusive",
                _ => "not tested",
            };
            var used = p.Detail is null ? p.Used : $"{p.Used} ({p.Detail})";
            output.WriteLine($"| {Code(p.Action)} | {state} | {Cell(used)} |");
        }

        output.WriteLine();
    }

    public void RenderInspect(DeploymentSnapshot s)
    {
        Header("Proxylity configuration", s, null);
        foreach (var l in s.Listeners)
        {
            output.WriteLine($"## Listener {Code(ListenerName(l))}");
            output.WriteLine();
            output.WriteLine($"Stack {Code(l.Stack.Name)} ({Escape(l.Stack.Status)}), as declared in the stack template.");
            output.WriteLine();
            Diagram(l, null);
            output.WriteLine("| Setting | Value |");
            output.WriteLine("|---|---|");
            Row("Protocol", Text(l.Protocol, "unknown"));
            Row("Metrics", OnOff(l.MetricsEnabled));
            Row("Logs", Text(l.LogGroupName, "off"));
            Row("Role", l.Role is null ? "none" : Text(l.Role.Arn, "not set"));
            Row("Clients", Clients(l.ClientRestrictions));
            output.WriteLine();

            foreach (var issue in l.TemplateIssues ?? [])
            {
                output.WriteLine($"> **Warning:** {Escape(issue.Message)} ({Code(issue.Path)}). The next update of this stack will be rejected.");
                output.WriteLine();
            }

            foreach (var d in l.Destinations)
            {
                output.WriteLine($"### Destination {Code(d.Name ?? "(unnamed)")}{(d.NameSource == NameSource.Derived ? " (name derived from the template)" : string.Empty)}");
                output.WriteLine();
                if (d.IsReferenceByName)
                {
                    output.WriteLine("Reference to a destination defined elsewhere (not validated here).");
                    output.WriteLine();
                    continue;
                }

                output.WriteLine("| Setting | Value |");
                output.WriteLine("|---|---|");
                foreach (var t in d.Targets)
                {
                    Row(t.IngressRegionKey == "*" ? "Target" : $"Target (from {t.IngressRegionKey})", TargetText(t));
                }

                if (d.Targets.Count == 0)
                {
                    Row("Target", "none (nothing is delivered)");
                }

                Row("Metrics", OnOff(d.MetricsEnabled));
                Row("Logs", Text(d.LogGroupName, "off"));
                Row("Role", d.Role is null ? "none" : Text(d.Role.Arn, "not set"));
                if (d.HasFilterExpression)
                {
                    Row("Filter", "a FilterExpression is set");
                }

                output.WriteLine();
            }
        }

        Notes(s.Notes);
    }

    public void RenderDiagnosis(DeploymentSnapshot s, ObservationReport r, FindingSummary summary)
    {
        Header("Proxylity diagnosis", s, r.Window);
        output.WriteLine($"**Summary:** {Escape(SummaryText(summary))}");
        output.WriteLine();
        foreach (var l in r.Listeners)
        {
            output.WriteLine($"## Listener {Code(ListenerName(l.Listener))}");
            output.WriteLine();
            output.WriteLine($"{Escape(Text(l.Listener.Protocol, "?"))}, stack {Code(l.Listener.Stack.Name)}");
            output.WriteLine();
            Diagram(l.Listener, l);
            Findings(l.Findings);
            foreach (var d in l.Destinations)
            {
                output.WriteLine($"### Destination {Code(d.Destination.Name ?? "(unnamed)")}");
                output.WriteLine();
                Findings(d.Findings);
                foreach (var t in d.Targets)
                {
                    output.WriteLine($"#### {Arrow} {TargetText(t.Target)}");
                    output.WriteLine();
                    Findings(t.Findings);
                }
            }
        }

        output.WriteLine("_No data is never treated as healthy. Log text is shown as received, in code blocks, and may contain data from network traffic._");
        output.WriteLine();
        Notes(r.Notes);
    }

    public void RenderMetrics(DeploymentSnapshot s, ObservationReport r)
    {
        Header("Proxylity metrics", s, r.Window);
        foreach (var l in r.Listeners)
        {
            output.WriteLine($"## Listener {Code(ListenerName(l.Listener))}");
            output.WriteLine();
            output.WriteLine("| Scope | Metric | Value |");
            output.WriteLine("|---|---|---|");
            MetricRows("listener", l.Metrics);
            foreach (var d in l.Destinations.Where(d => !d.Destination.IsReferenceByName))
            {
                MetricRows($"destination {d.Destination.Name}", d.Metrics);
                foreach (var t in d.Targets.Where(t => t.Metrics.Count > 0))
                {
                    MetricRows(TargetPlain(t.Target), t.Metrics);
                }
            }

            output.WriteLine();
        }

        output.WriteLine("_Proxylity packet counts are size-weighted units (1 per started KB), not raw datagrams. Listener and destination counts overlap; do not add them._");
        output.WriteLine();
        Notes(r.Notes);
    }

    public void RenderLogs(DeploymentSnapshot s, ObservationReport r)
    {
        Header("Proxylity logs", s, r.Window);
        var sources = new List<(string Label, LogObservation Logs)>();
        foreach (var l in r.Listeners)
        {
            if (l.Logs is not null)
            {
                sources.Add(($"listener {ListenerName(l.Listener)}", l.Logs));
            }

            sources.AddRange(l.Destinations.Where(d => d.Logs is not null).Select(d => ($"destination {d.Destination.Name}", d.Logs!)));
        }

        var groups = sources.GroupBy(x => (x.Logs.LogGroup, string.Join(',', x.Logs.Regions))).ToList();
        if (groups.Count == 0)
        {
            output.WriteLine("None of the selected listeners or destinations has a LogGroupName configured.");
            output.WriteLine();
        }

        foreach (var g in groups)
        {
            var logs = g.First().Logs;
            output.WriteLine($"## Log group {Code(logs.LogGroup)}");
            output.WriteLine();
            output.WriteLine($"Written by {string.Join(", ", g.Select(x => Code(x.Label)).Distinct(StringComparer.Ordinal))}; regions {Escape(string.Join(", ", logs.Regions))}.");
            output.WriteLine();
            if (logs.Events.State == SignalState.Available)
            {
                Fenced(string.Join('\n', logs.Events.Value!.Select(e =>
                    string.Create(CultureInfo.InvariantCulture, $"{e.Timestamp:MM-dd HH:mm:ss} {e.Level,-5} {(e.Count > 1 ? $"x{e.Count} " : string.Empty)}{e.Message}"))));
                if (logs.Truncated)
                {
                    output.WriteLine("_Older entries in the window are not shown; use `--limit` or a shorter `--since`._");
                    output.WriteLine();
                }
            }
            else
            {
                output.WriteLine(Escape(Describe(logs.Events.State, logs.Events.Detail)));
                output.WriteLine();
            }
        }

        output.WriteLine("_Times are UTC. Log text is shown as received and may contain data from network traffic._");
        output.WriteLine();
        Notes(r.Notes);
    }

    // ---- Diagram ------------------------------------------------------------------------------------------

    /// <summary>A left-to-right flowchart of the delivery path. Nodes are colored by their worst finding when diagnosing.</summary>
    private void Diagram(ListenerInfo l, ListenerObservation? o)
    {
        var sb = new StringBuilder();
        sb.Append("flowchart LR\n");
        sb.Append(CultureInfo.InvariantCulture, $"  L[\"{Label(ListenerName(l))}\"]{Class(o?.Findings)}\n");
        for (var di = 0; di < l.Destinations.Count; di++)
        {
            var d = l.Destinations[di];
            var dObs = o?.Destinations.Count > di ? o.Destinations[di] : null;
            sb.Append(CultureInfo.InvariantCulture, $"  L --> D{di}[\"{Label(d.Name ?? "destination")}\"]{Class(dObs?.Findings)}\n");
            var targets = dObs?.Targets.Select(t => t.Target).ToList() ?? [.. d.Targets];
            for (var ti = 0; ti < targets.Count; ti++)
            {
                var t = targets[ti];
                var tObs = dObs?.Targets.Count > ti ? dObs.Targets[ti] : null;
                var edge = t.IngressRegionKey == "*" ? "-->" : $"-->|{Label(t.IngressRegionKey)}|";
                var name = t.Arn.IsResolved ? $"{TextRenderer.ServiceLabel(t.Service)} {t.ResourceName ?? string.Empty}" : "unresolved target";
                sb.Append(CultureInfo.InvariantCulture, $"  D{di} {edge} T{di}_{ti}[\"{Label(name)}\"]{Class(tObs?.Findings)}\n");
            }
        }

        if (o is not null)
        {
            // Text color is set explicitly: themes change Mermaid's default text color (light on dark themes),
            // so a fill alone can become unreadable. Medium-dark fills with white text contrast at 4.5:1 or
            // better and read the same on light and dark pages.
            sb.Append("  classDef error fill:#b42318,stroke:#7a1610,color:#ffffff\n");
            sb.Append("  classDef warning fill:#a15c07,stroke:#6e3f05,color:#ffffff\n");
            sb.Append("  classDef unknown fill:#475467,stroke:#2c3441,color:#ffffff\n");
            sb.Append("  classDef ok fill:#067647,stroke:#04512f,color:#ffffff\n");
        }

        output.WriteLine("```mermaid");
        output.Write(sb.ToString());
        output.WriteLine("```");
        output.WriteLine();
    }

    private static string Class(IReadOnlyList<Finding>? findings)
    {
        if (findings is null || findings.Count == 0)
        {
            return string.Empty;
        }

        if (findings.Any(f => f.Health == Health.Error))
        {
            return ":::error";
        }

        if (findings.Any(f => f.Health is Health.Warning or Health.NotAccessible))
        {
            return ":::warning";
        }

        return findings.Any(f => f.Health == Health.Healthy) && findings.All(f => f.Health is Health.Healthy or Health.NotConfigured)
            ? ":::ok"
            : ":::unknown";
    }

    /// <summary>Mermaid label text: a safe character set only, so data can't add syntax, links, or markup.</summary>
    internal static string Label(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, 60));
        foreach (var ch in text)
        {
            if (sb.Length >= 60)
            {
                sb.Append("...");
                break;
            }

            sb.Append(char.IsAsciiLetterOrDigit(ch) || ch is ' ' or '-' or '_' or '.' or '/' or ':' or '*' or '+' ? ch : '_');
        }

        return sb.ToString();
    }

    // ---- Findings ------------------------------------------------------------------------------------------

    private void Findings(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return;
        }

        foreach (var f in findings.OrderBy(f => Rank(f.Health)).ThenBy(f => f.Confidence))
        {
            var confidence = f.Confidence == Confidence.Confirmed ? string.Empty : $" _({f.Confidence.ToString().ToLowerInvariant()})_";
            output.WriteLine($"- {Badge(f.Health)} {Escape(f.Title)}{confidence}");
            foreach (var e in f.Evidence.Where(e => !e.Untrusted))
            {
                output.WriteLine($"  - {Escape(e.Label)}: {Code(e.Value)}");
            }

            var untrusted = f.Evidence.Where(e => e.Untrusted).ToList();
            if (untrusted.Count > 0)
            {
                output.WriteLine();
                Fenced(string.Join('\n', untrusted.Select(e => $"{e.Label} {e.Value}")), "  ");
            }

            foreach (var s in f.Suggestions)
            {
                output.WriteLine($"  - {Arrow} {Escape(s)}");
            }
        }

        output.WriteLine();
    }

    /// <summary>
    /// Symbols are written as HTML entities so the Markdown is pure ASCII: renderers show the symbols, and the
    /// bytes survive any shell, pipe, or console code page (for example Windows PowerShell 5.1 redirection).
    /// </summary>
    private const string Arrow = "&rarr;";

    private static string Badge(Health h) => h switch
    {
        Health.Error => "**&#x2717; Error**",
        Health.Warning => "**! Warning**",
        Health.NotAccessible => "**&#x2298; Not accessible**",
        Health.Unknown => "**? Unknown**",
        Health.NotConfigured => "**&ndash; Off**",
        _ => "**&#x2713; OK**",
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

    // ---- Pieces --------------------------------------------------------------------------------------------

    private void Header(string title, DeploymentSnapshot s, TimeWindow? w)
    {
        var accounts = s.Stacks.Select(x => x.AccountId).Where(a => a.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        output.WriteLine($"# {title}");
        output.WriteLine();
        var parts = new List<string>
        {
            accounts.Count == 1 ? $"Account {Code(accounts[0])}" : "Account unknown",
            $"region {Escape(string.Join(", ", s.Regions))}",
            $"{s.Stacks.Count} stack(s) with Proxylity resources",
        };
        if (w is not null)
        {
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"window {w.Start:yyyy-MM-dd HH:mm} to {w.End:yyyy-MM-dd HH:mm} UTC"));
        }

        output.WriteLine(string.Join(" &middot; ", parts));
        output.WriteLine();
    }

    private void Notes(IReadOnlyList<Note> notes)
    {
        if (notes.Count == 0)
        {
            return;
        }

        output.WriteLine("## Notes");
        output.WriteLine();
        foreach (var n in notes)
        {
            output.WriteLine($"- {(n.Severity == "warning" ? "**!** " : string.Empty)}{Escape(n.Message)}");
        }

        output.WriteLine();
    }

    private void Row(string setting, string value) => output.WriteLine($"| {Escape(setting)} | {Cell(value)} |");

    private void MetricRows(string scope, IReadOnlyDictionary<string, Signal<double>> metrics)
    {
        foreach (var (key, s) in metrics.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var value = s.IsAvailable ? s.Value.ToString("N0", CultureInfo.InvariantCulture) : Describe(s.State, s.Detail);
            output.WriteLine($"| {Cell(scope)} | {Code(key)} | {Cell(value)} |");
        }
    }

    /// <summary>Untrusted or literal text in a fenced block; the fence is longer than any backtick run inside.</summary>
    private void Fenced(string content, string indent = "")
    {
        var longest = 0;
        var run = 0;
        foreach (var ch in content)
        {
            run = ch == '`' ? run + 1 : 0;
            longest = Math.Max(longest, run);
        }

        var fence = new string('`', Math.Max(3, longest + 1));
        output.WriteLine($"{indent}{fence}text");
        foreach (var line in content.Split('\n'))
        {
            output.WriteLine(indent + line);
        }

        output.WriteLine($"{indent}{fence}");
        output.WriteLine();
    }

    /// <summary>Inline code for names and values; never contains a line break.</summary>
    internal static string Code(string value)
    {
        // GitHub-flavored tables treat \| as a literal pipe, even inside code spans.
        var text = value.Replace('\n', ' ').Replace('\r', ' ').Replace("|", "\\|", StringComparison.Ordinal);
        var longest = 0;
        var run = 0;
        foreach (var ch in text)
        {
            run = ch == '`' ? run + 1 : 0;
            longest = Math.Max(longest, run);
        }

        var fence = new string('`', longest + 1);
        var pad = text.StartsWith('`') || text.EndsWith('`') ? " " : string.Empty;
        return $"{fence}{pad}{text}{pad}{fence}";
    }

    /// <summary>
    /// Escapes Markdown (and inline HTML) metacharacters in plain text, and writes non-ASCII characters as numeric
    /// entities so rendered prose is pure ASCII.
    /// </summary>
    internal static string Escape(string text)
    {
        var sb = new StringBuilder(text.Length + 8);
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value > 127)
            {
                sb.Append(CultureInfo.InvariantCulture, $"&#x{rune.Value:X};");
                continue;
            }

            var ch = (char)rune.Value;
            switch (ch)
            {
                case '\\' or '`' or '*' or '_' or '{' or '}' or '[' or ']' or '(' or ')' or '#' or '+' or '!' or '|' or '~' or '>':
                    sb.Append('\\').Append(ch);
                    break;
                case '<':
                    sb.Append("&lt;");
                    break;
                case '&':
                    sb.Append("&amp;");
                    break;
                case '\n' or '\r':
                    sb.Append(' ');
                    break;
                default:
                    sb.Append(ch);
                    break;
            }
        }

        return sb.ToString();
    }

    /// <summary>A table cell: names stay code, text is escaped (pipes included).</summary>
    private static string Cell(string text) => Escape(text);

    private static string ListenerName(ListenerInfo l) => l.Name ?? $"{l.Stack.Name}/{l.LogicalId}";

    private static string DestinationSummary(DestinationInfo d) =>
        d.IsReferenceByName ? $"{d.Name} (reference)" : $"{d.Name} → {(d.Targets.Count > 0 ? TargetPlain(d.Targets[0]) : "no target")}{(d.Targets.Count > 1 ? $" (+{d.Targets.Count - 1} more)" : string.Empty)}";

    private static string TargetPlain(DestinationTarget t) =>
        !t.Arn.IsResolved
            ? (t.Arn.State == ValueState.Absent ? "no ARN" : $"unresolved ({t.Arn.Reason})")
            : t.Service == DestinationService.Unknown ? t.Arn.Value! : $"{TextRenderer.ServiceLabel(t.Service)} {t.ResourceName ?? t.Arn.Value}";

    private static string TargetText(DestinationTarget t)
    {
        var where = t.RegionFromIngress ? $" (region * resolves to the ingress region; checked in {t.ArnRegion})" : string.Empty;
        return t.Arn.IsResolved
            ? $"{Escape(TextRenderer.ServiceLabel(t.Service))} {Code(t.ResourceName ?? t.Arn.Value!)}{Escape(where)}"
            : Escape(TargetPlain(t));
    }

    private static string Text(Resolved<string> v, string absent) => v.State switch
    {
        ValueState.Resolved => v.Value ?? string.Empty,
        ValueState.Absent => absent,
        _ => $"unresolved ({v.Reason})",
    };

    private static string OnOff(Resolved<bool> v) => v.State switch
    {
        ValueState.Resolved => v.Value ? "on" : "off",
        ValueState.Absent => "off (default)",
        _ => $"unresolved ({v.Reason})",
    };

    private static string Clients(ClientRestrictionsInfo c) => c.Form switch
    {
        ClientRestrictionsForm.Object => $"{c.NetworkCount} network(s), {c.DomainCount} domain(s) allowed",
        ClientRestrictionsForm.Absent => "none declared (all traffic is blocked)",
        ClientRestrictionsForm.Empty => "empty (all traffic is blocked)",
        ClientRestrictionsForm.List => "written as a list (not valid)",
        _ => "could not be determined",
    };

    private static string Describe(SignalState state, string? detail) => state switch
    {
        SignalState.NoData => "no data",
        SignalState.NotConfigured => detail ?? "not configured",
        SignalState.NotAccessible => detail ?? "not permitted",
        SignalState.NotFound => detail ?? "not found",
        SignalState.Failed => detail ?? "could not be read",
        _ => detail ?? state.ToString(),
    };

    private static string SummaryText(FindingSummary s)
    {
        var parts = new List<string>();
        void Add(int n, string word)
        {
            if (n > 0)
            {
                parts.Add($"{n} {word}");
            }
        }

        Add(s.Errors, s.Errors == 1 ? "error" : "errors");
        Add(s.Warnings, s.Warnings == 1 ? "warning" : "warnings");
        Add(s.NotAccessible, "not accessible");
        Add(s.Unknown, s.Unknown == 1 ? "unknown" : "unknowns");
        Add(s.NotConfigured, "not configured");
        Add(s.Healthy, "ok");
        return parts.Count == 0 ? "nothing to report" : string.Join(", ", parts);
    }
}
