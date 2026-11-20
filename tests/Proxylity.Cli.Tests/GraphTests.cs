using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli.Tests;

public class GraphTests
{
    private static readonly StackRef Stack = new("demo", "id", "us-west-2", "123456789012", "UPDATE_COMPLETE");

    private static DestinationTarget Target(string key, string? arn, string? name, string? region, DestinationService service = DestinationService.Lambda, bool fromIngress = false) =>
        new(key, arn is null ? Resolved<string>.Fail("a parameter has no value") : Resolved<string>.Ok(arn), service, region, name, null, fromIngress);

    private static DestinationInfo Destination(string? name, params DestinationTarget[] targets) =>
        new(name, NameSource.Declared, false, Resolved<bool>.Absent, Resolved<string>.Absent, null, targets, false);

    private static ListenerInfo Listener(string name, params DestinationInfo[] destinations) =>
        new(Stack, name + "Id", name, false, Resolved<string>.Ok("udp"), Resolved<bool>.Absent, Resolved<string>.Absent, null,
            new ClientRestrictionsInfo(ClientRestrictionsForm.Absent, 0, 0), destinations);

    private static DeploymentSnapshot Snapshot(IReadOnlyList<ListenerInfo> listeners, IReadOnlyList<Note>? notes = null) =>
        new(["us-west-2"], [Stack], listeners, [], [], notes ?? []);

    private static string Render(DeploymentSnapshot s, bool color = false, int width = 200)
    {
        var w = new StringWriter();
        new GraphRenderer(w, color, width).Render(s);
        return w.ToString().Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    [Fact]
    public void Single_listener_snapshot_is_a_tree()
    {
        var s = Snapshot([Listener("example-listener", Destination("handler", Target("*", "arn:aws:lambda:us-west-2:123456789012:function:handler", "handler", "us-west-2")))]);

        var expected = """
            Proxylity · account 123456789012 · us-west-2 · 1 stack with Proxylity resources

            Listener example-listener (udp)
            stack demo (UPDATE_COMPLETE), as declared in the stack template
            └─ Destination handler
               └─ Lambda handler (region us-west-2; any ingress region)

            """.Replace("\r\n", "\n", StringComparison.Ordinal);
        Assert.Equal(expected, Render(s));
    }

    [Fact]
    public void Colors_are_decoration_only()
    {
        var s = Snapshot([Listener("example-listener", Destination("handler", Target("*", "arn:aws:lambda:us-west-2:123456789012:function:handler", "handler", "us-west-2")))]);

        var colored = Render(s, color: true);

        Assert.Contains("\u001b[1m", colored, StringComparison.Ordinal);
        Assert.Equal(Render(s), System.Text.RegularExpressions.Regex.Replace(colored, "\u001b\\[[0-9;]*m", string.Empty));
    }

    [Fact]
    public void Composite_destinations_and_multiple_listeners_are_all_drawn_and_shared_ones_are_marked()
    {
        var shared = Destination("shared-dest", Target("*", "arn:aws:sqs:us-west-2:123456789012:q", "q", "us-west-2", DestinationService.Sqs));
        var s = Snapshot([
            Listener("first", Destination("only-first", Target("*", "arn:aws:lambda:us-west-2:123456789012:function:a", "a", "us-west-2")), shared),
            Listener("second", shared),
        ]);

        var text = Render(s);

        Assert.Contains("├─ Destination only-first", text, StringComparison.Ordinal);
        Assert.Contains("└─ Destination shared-dest [shared with second]", text, StringComparison.Ordinal);
        Assert.Contains("Destination shared-dest [shared with first]", text, StringComparison.Ordinal);
        Assert.DoesNotContain("only-first [shared", text, StringComparison.Ordinal);
        Assert.Equal(2, text.Split("Listener ", StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void Unresolved_derived_reference_and_empty_cases_use_words()
    {
        var derived = Destination("dstn-demo-L-0", Target("*", null, null, null)) with { NameSource = NameSource.Derived };
        var reference = new DestinationInfo("elsewhere", NameSource.Declared, true, Resolved<bool>.Absent, Resolved<string>.Absent, null, [], false);
        var s = Snapshot([Listener("l", derived, reference, Destination("no-target")), Listener("empty")]);

        var text = Render(s);

        Assert.Contains("! target could not be resolved (a parameter has no value)", text, StringComparison.Ordinal);
        Assert.Contains("(name derived from the template, lower confidence)", text, StringComparison.Ordinal);
        Assert.Contains("reference to a destination defined elsewhere (not validated here)", text, StringComparison.Ordinal);
        Assert.Contains("! no target (nothing will be delivered)", text, StringComparison.Ordinal);
        Assert.Contains("! no destinations (nothing will be delivered)", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Multi_region_maps_show_every_candidate_without_choosing()
    {
        var s = Snapshot([Listener("l", Destination("d",
            Target("us-east-1", "arn:aws:lambda:us-east-1:123456789012:function:east", "east", "us-east-1"),
            Target("eu-west-1", "arn:aws:lambda:eu-west-1:123456789012:function:west", "west", "eu-west-1"),
            Target("*", "arn:aws:lambda:*:123456789012:function:any", "any", "us-west-2", fromIngress: true)))]);

        var text = Render(s);

        Assert.Contains("Lambda east (region us-east-1; from us-east-1)", text, StringComparison.Ordinal);
        Assert.Contains("Lambda west (region eu-west-1; from eu-west-1)", text, StringComparison.Ordinal);
        Assert.Contains("region is the ingress region (checked in us-west-2); any ingress region)", text, StringComparison.Ordinal);
        Assert.Contains("all candidate targets are shown; which one is used is not determined here", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_results_say_so()
    {
        var none = Render(new DeploymentSnapshot(["us-west-2"], [], [], [], [], []));
        Assert.Contains("No Proxylity resources were found in this account and region.", none, StringComparison.Ordinal);
        var stacksOnly = Render(Snapshot([]));
        Assert.Contains("No listeners were found in the matching stacks.", stacksOnly, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(40)]
    [InlineData(25)]
    [InlineData(120)]
    public void Narrow_widths_wrap_without_exceeding_the_width_or_crashing(int width)
    {
        var longArn = "arn:aws:lambda:us-west-2:123456789012:function:" + new string('Q', 90);
        var s = Snapshot([Listener("a-listener-with-a-rather-long-name-for-wrapping", Destination("a-destination-with-a-long-name-too", Target("*", longArn, null, "us-west-2")))],
            [new Note("warning", "A long note that has to be wrapped across more than one line of a narrow terminal.", null)]);

        var text = Render(s, width: width);

        var limit = Math.Max(width, GraphRenderer.MinWidth);
        Assert.All(text.Split('\n'), line => Assert.True(line.Length <= limit, $"{line.Length} > {limit}: {line}"));
        Assert.Contains(new string('Q', 30), text, StringComparison.Ordinal);
        Assert.Equal(90, text.Count(c => c == 'Q'));
    }

    [Fact]
    public void Names_cannot_inject_terminal_control_sequences()
    {
        var hostile = "evil\u001b[2J\u001b]0;pwned\u0007\r\nname\u202Efdp";
        var s = Snapshot([Listener(hostile, Destination(hostile, Target("*", "arn:aws:lambda:us-west-2:123456789012:function:" + hostile, hostile, "us-west-2")))],
            [new Note("info", hostile, null)]);

        var text = Render(s);

        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('\u0007', text);
        Assert.DoesNotContain('\r', text);
        Assert.DoesNotContain('\u202E', text);
        Assert.Contains("evil?[2J?]0;pwned", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Redirected_graph_is_ascii_and_has_no_color_codes()
    {
        var s = Snapshot([Listener("l", Destination("a", Target("*", "arn:aws:lambda:us-west-2:123456789012:function:a", "a", "us-west-2")), Destination("b"))]);
        var inner = new StringWriter();
        using (var ascii = new AsciiWriter(inner))
        {
            new GraphRenderer(ascii, color: false, 200).Render(s);
        }

        var text = inner.ToString();

        Assert.All(text, c => Assert.True(c < 128, $"non-ASCII {(int)c}"));
        Assert.DoesNotContain('\u001b', text);
        Assert.Contains("+- Destination a", text, StringComparison.Ordinal);
        Assert.Contains("\\- Destination b", text, StringComparison.Ordinal);
        Assert.Contains("|  \\- Lambda a", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_with_graph_format_runs_end_to_end_and_other_commands_reject_it()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var code = await new CliApp(stdout, stderr, _ => new FakeStackSource(), colorAllowed: false, terminalWidth: 60)
            .RunAsync(["inspect", "--format", "graph"], CancellationToken.None);

        Assert.Equal(0, code);
        Assert.Contains("Listener demo-Listener-1a2b3c4d (udp)", stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("Lambda packet-handler", stdout.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("literal-secret-value-xyz", stdout.ToString(), StringComparison.Ordinal);

        var err = new StringWriter();
        var bad = await new CliApp(new StringWriter(), err, _ => new FakeStackSource(), colorAllowed: false)
            .RunAsync(["list", "-o", "graph"], CancellationToken.None);
        Assert.Equal(ExitCodes.Usage, bad);
        Assert.Contains("'inspect' only", err.ToString(), StringComparison.Ordinal);
    }
}
