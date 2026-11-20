using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli.Tests;

public class MarkdownTests
{
    private const string Listener = "demo-Listener-1a2b3c4d";

    private const string Hostile =
        "``` \n# Injected heading [click me](javascript:alert(1)) <img src=x onerror=alert(1)> ```` L --> X[\"pwned\"] click L href \"https://example.com\"";

    private static string Run(FakeObservabilitySource obs, params string[] args)
    {
        var stdout = new StringWriter();
        new CliApp(stdout, new StringWriter(), _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => obs)
            .RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
        return stdout.ToString();
    }

    /// <summary>Lines outside fenced code blocks (where Markdown is rendered), and the Mermaid blocks.</summary>
    private static (List<string> Rendered, List<string> Mermaid) Split(string markdown)
    {
        var rendered = new List<string>();
        var mermaid = new List<string>();
        string? fence = null;
        var inMermaid = false;
        foreach (var raw in markdown.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var trimmed = line.TrimStart();
            if (fence is null && trimmed.StartsWith("```", StringComparison.Ordinal))
            {
                fence = new string('`', trimmed.TakeWhile(c => c == '`').Count());
                inMermaid = trimmed[fence.Length..].StartsWith("mermaid", StringComparison.Ordinal);
                continue;
            }

            if (fence is not null && trimmed == fence)
            {
                fence = null;
                inMermaid = false;
                continue;
            }

            if (fence is null)
            {
                rendered.Add(line);
            }
            else if (inMermaid)
            {
                mermaid.Add(line);
            }
        }

        return (rendered, mermaid);
    }

    private static FakeObservabilitySource WithHostileLogs()
    {
        var obs = new FakeObservabilitySource();
        obs.Proxylity("packet-handler", "IngressPackets", 10);
        obs.Proxylity("packet-handler", "Errors", 2);
        obs.Logs["/example/dest"] = Signal<LogQueryResult>.Of(new LogQueryResult([new LogEvent(DateTimeOffset.UtcNow, "[x2]: ERROR: " + Hostile)], false));
        obs.Lambda("Invocations", 5);
        return obs;
    }

    [Fact]
    public void Diagnose_markdown_has_a_diagram_findings_and_summary()
    {
        var md = Run(WithHostileLogs(), "diagnose", Listener, "-o", "md");

        Assert.Contains("# Proxylity diagnosis", md, StringComparison.Ordinal);
        Assert.Contains("```mermaid", md, StringComparison.Ordinal);
        Assert.Contains("flowchart LR", md, StringComparison.Ordinal);
        Assert.Contains("**Summary:**", md, StringComparison.Ordinal);
        Assert.Contains("**&#x2717; Error**", md, StringComparison.Ordinal);
        Assert.Contains(":::error", md, StringComparison.Ordinal);

        // Every class sets its text color, so nodes stay readable under light and dark themes.
        var classDefs = md.Split('\n').Where(l => l.TrimStart().StartsWith("classDef ", StringComparison.Ordinal)).ToList();
        Assert.Equal(4, classDefs.Count);
        Assert.All(classDefs, c => Assert.Contains("color:#ffffff", c, StringComparison.Ordinal));
    }

    [Fact]
    public void Untrusted_log_text_never_reaches_rendered_markdown_or_the_diagram()
    {
        foreach (var command in new[] { "diagnose", "logs" })
        {
            var md = Run(WithHostileLogs(), command, Listener, "--output", "markdown");
            var (rendered, mermaid) = Split(md);

            Assert.Contains("Injected heading", md, StringComparison.Ordinal); // it is shown...
            foreach (var line in rendered.Concat(mermaid))                    // ...but only inside code blocks
            {
                Assert.DoesNotContain("javascript:", line, StringComparison.Ordinal);
                Assert.DoesNotContain("<img", line, StringComparison.Ordinal);
                Assert.DoesNotContain("Injected heading", line, StringComparison.Ordinal);
                Assert.DoesNotContain("pwned", line, StringComparison.Ordinal);
                Assert.DoesNotContain("click", line, StringComparison.Ordinal);
            }
        }
    }

    [Theory]
    [InlineData("name\"] --> X[\"x", "name__ --_ X__x")]
    [InlineData("a`b#c;d", "a_b_c_d")]
    [InlineData("svc:region/*", "svc:region/*")]
    public void Mermaid_labels_keep_only_safe_characters(string input, string expected)
    {
        Assert.Equal(expected, MarkdownRenderer.Label(input));
    }

    [Fact]
    public void Inline_code_and_escaping_cannot_be_broken_out_of()
    {
        Assert.Equal("``a`b``", MarkdownRenderer.Code("a`b"));
        Assert.Equal("`` `x ``", MarkdownRenderer.Code("`x"));
        Assert.Equal(@"`a\|b`", MarkdownRenderer.Code("a|b"));
        Assert.Equal(@"\[x\]\(javascript:y\) &lt;b\>", MarkdownRenderer.Escape("[x](javascript:y) <b>"));
    }

    [Fact]
    public void Markdown_outside_code_blocks_is_pure_ascii()
    {
        foreach (var command in new[] { "diagnose", "inspect", "list", "metrics", "logs" })
        {
            var args = command == "list" ? new[] { command, "-o", "md" } : [command, Listener, "-o", "md"];
            var (rendered, mermaid) = Split(Run(WithHostileLogs(), args));

            foreach (var line in rendered.Concat(mermaid))
            {
                Assert.True(line.All(c => c < 128), $"{command}: non-ASCII in \"{line}\"");
            }
        }

        Assert.Equal("a &#x2192; b", MarkdownRenderer.Escape("a \u2192 b"));
        Assert.Equal("&#x1F600;", MarkdownRenderer.Escape("\U0001F600"));
    }

    [Fact]
    public async Task Redirected_text_output_is_pure_ascii()
    {
        var obs = WithHostileLogs();
        obs.Logs["/example/dest"] = Signal<LogQueryResult>.Of(new LogQueryResult([new LogEvent(DateTimeOffset.UtcNow, "[x1]: ERROR: caf\u00e9 \U0001F600")], false));
        var inner = new StringWriter();
        using var ascii = new AsciiWriter(inner);
        await new CliApp(ascii, new StringWriter(), _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => obs)
            .RunAsync(["diagnose", Listener, "--no-color"], CancellationToken.None);
        await ascii.FlushAsync();
        var text = inner.ToString();

        Assert.All(text, c => Assert.True(c < 128));
        Assert.Contains("x ERROR", text, StringComparison.Ordinal);
        Assert.Contains("-> ", text, StringComparison.Ordinal);
        Assert.Contains("caf\\u00e9", text, StringComparison.Ordinal);
        Assert.Contains("\\ud83d\\ude00", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Out_writes_utf8_without_bom_to_a_file()
    {
        var path = Path.Combine(Path.GetTempPath(), "pxy-out-" + Guid.NewGuid().ToString("N") + ".md");
        try
        {
            var stdout = Run(WithHostileLogs(), "diagnose", Listener, "-o", "md", "--out", path);

            Assert.Empty(stdout);
            var bytes = File.ReadAllBytes(path);
            Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);
            Assert.Contains("# Proxylity diagnosis", System.Text.Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void List_inspect_and_metrics_render_as_markdown()
    {
        var obs = WithHostileLogs();

        Assert.Contains("| Stack | Listener | Protocol | Destinations |", Run(obs, "list", "-o", "md"), StringComparison.Ordinal);
        var inspect = Run(obs, "inspect", Listener, "-o", "md");
        Assert.Contains("## Listener `demo-Listener-1a2b3c4d`", inspect, StringComparison.Ordinal);
        Assert.Contains("```mermaid", inspect, StringComparison.Ordinal);
        Assert.Contains("| Scope | Metric | Value |", Run(obs, "metrics", Listener, "-o", "md"), StringComparison.Ordinal);
    }
}
