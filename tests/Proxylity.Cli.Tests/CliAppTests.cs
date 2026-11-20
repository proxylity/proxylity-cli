using System.Text.Json;
using Proxylity.Cli.Core.Discovery;

namespace Proxylity.Cli.Tests;

internal sealed class FakeStackSource : IStackSource
{
    public const string DemoStackId = "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000";
    public const string OtherStackId = "arn:aws:cloudformation:us-west-2:123456789012:stack/other/1111";

    public string Region => "us-west-2";

    public bool DenyListStacks { get; init; }

    public bool ThrottleOtherStack { get; init; }

    public bool ThrottleListStacks { get; init; }

    public static readonly DateTimeOffset BaseTime = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public List<string> TemplateFetches { get; } = [];

    public List<string> ResourceListings { get; } = [];

    public DateTimeOffset DemoLastChanged { get; init; } = BaseTime;

    public string DemoStatus { get; init; } = "UPDATE_COMPLETE";

    public bool IncludeOtherStack { get; init; } = true;

    public Task<IReadOnlyList<StackSummary>> ListStacksAsync(CancellationToken cancellationToken)
    {
        if (ThrottleListStacks)
        {
            throw new ThrottledException("cloudformation:ListStacks", "AWS throttled cloudformation:ListStacks after retries (Rate exceeded).");
        }

        if (DenyListStacks)
        {
            throw new AccessDeniedException("cloudformation:ListStacks", "Access denied for cloudformation:ListStacks");
        }

        var stacks = new List<StackSummary> { new(DemoStackId, "demo", DemoStatus, null, DemoLastChanged) };
        if (IncludeOtherStack)
        {
            stacks.Add(new StackSummary(OtherStackId, "other", "CREATE_COMPLETE", null, BaseTime));
        }

        return Task.FromResult<IReadOnlyList<StackSummary>>(stacks);
    }

    public Task<IReadOnlyList<StackResource>> ListResourcesAsync(string stackId, CancellationToken cancellationToken)
    {
        ResourceListings.Add(stackId);
        return ThrottleOtherStack && stackId == OtherStackId
            ? throw new ThrottledException("cloudformation:ListStackResources", "throttled")
            : Task.FromResult<IReadOnlyList<StackResource>>(stackId == DemoStackId
            ?
            [
                new StackResource("PacketHandler", "packet-handler", "AWS::Lambda::Function", "CREATE_COMPLETE"),
                new StackResource("Listener", "demo-Listener-1a2b3c4d", "Custom::ProxylityUdpGatewayListener", "CREATE_COMPLETE"),
            ]
            : [new StackResource("Bucket", "some-bucket", "AWS::S3::Bucket", "CREATE_COMPLETE")]);
    }

    public Task<StackDetails> DescribeAsync(string stackId, CancellationToken cancellationToken) =>
        Task.FromResult(new StackDetails(
            new Dictionary<string, string> { ["RoleArnParam"] = "arn:aws:iam::123456789012:role/example-role" },
            new Dictionary<string, string>()));

    public Task<string> GetProcessedTemplateAsync(string stackId, CancellationToken cancellationToken)
    {
        TemplateFetches.Add(stackId);
        return Task.FromResult("""
            Parameters:
              RoleArnParam:
                Type: String
            Resources:
              PacketHandler:
                Type: AWS::Lambda::Function
              Listener:
                Type: Custom::ProxylityUdpGatewayListener
                Properties:
                  ApiKey: literal-secret-value-xyz
                  Protocols: [udp]
                  MetricsEnabled: true
                  Role:
                    Arn: !Ref RoleArnParam
                  ClientRestrictions:
                    Networks: ["203.0.113.0/24"]
                  Destinations:
                    - Name: packet-handler
                      DestinationArn: !GetAtt PacketHandler.Arn
                      MetricsEnabled: true
                      LogGroupName: /example/dest
                      Role:
                        Arn: !Ref RoleArnParam
            """);
    }
}

public class CliAppTests
{
    private static (int Code, string Out, string Err, FakeStackSource Source) Run(string[] args, FakeStackSource? source = null)
    {
        source ??= new FakeStackSource();
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var app = new CliApp(stdout, stderr, _ => source, colorAllowed: false);
        var code = app.RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
        return (code, stdout.ToString(), stderr.ToString(), source);
    }

    [Fact]
    public void List_shows_the_listener_and_its_destination_in_text()
    {
        var (code, output, _, source) = Run(["list"]);

        Assert.Equal(0, code);
        Assert.Contains("demo-Listener-1a2b3c4d", output, StringComparison.Ordinal);
        Assert.Contains("packet-handler \u2192 Lambda packet-handler", output, StringComparison.Ordinal);
        Assert.Contains("account 123456789012", output, StringComparison.Ordinal);
        // Only stacks that contain Proxylity resources have their templates fetched.
        Assert.Equal([FakeStackSource.DemoStackId], source.TemplateFetches);
    }

    [Fact]
    public void Inspect_shows_configuration_details()
    {
        var (code, output, _, _) = Run(["inspect", "Listener"]);

        Assert.Equal(0, code);
        Assert.Contains("1 network, 0 domains allowed", output, StringComparison.Ordinal);
        Assert.Contains("arn:aws:iam::123456789012:role/example-role", output, StringComparison.Ordinal);
        Assert.Contains("as declared in the stack template", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_output_has_an_envelope_and_never_contains_secrets()
    {
        var (code, output, _, _) = Run(["list", "--output", "json"]);

        Assert.Equal(0, code);
        Assert.DoesNotContain("literal-secret-value-xyz", output, StringComparison.Ordinal);

        using var doc = JsonDocument.Parse(output);
        var root = doc.RootElement;
        Assert.Equal("1", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("proxylity", root.GetProperty("tool").GetProperty("name").GetString());
        Assert.Equal("list", root.GetProperty("command").GetString());

        var listener = root.GetProperty("result").GetProperty("listeners")[0];
        Assert.Equal("demo-Listener-1a2b3c4d", listener.GetProperty("name").GetString());
        Assert.Equal("udp", listener.GetProperty("protocol").GetProperty("value").GetString());
        Assert.Equal("resolved", listener.GetProperty("protocol").GetProperty("state").GetString());
        var target = listener.GetProperty("destinations")[0].GetProperty("targets")[0];
        Assert.Equal("lambda", target.GetProperty("service").GetString());
        Assert.Equal("packet-handler", target.GetProperty("resourceName").GetString());
    }

    [Fact]
    public void Stack_filter_limits_discovery()
    {
        var (code, output, _, source) = Run(["list", "--stack", "nonexistent"]);

        Assert.Equal(0, code);
        Assert.Empty(source.TemplateFetches);
        Assert.Contains("No stacks matched", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_target_is_a_usage_error()
    {
        var (code, _, err, _) = Run(["inspect", "does-not-exist"]);

        Assert.Equal(2, code);
        Assert.Contains("no listener or stack matches", err, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("list", "--bogus")]
    [InlineData("list", "--output", "yaml")]
    [InlineData("list", "--region")]
    [InlineData("list", "extra")]
    public void Bad_usage_returns_exit_code_2(params string[] args)
    {
        var (code, _, err, _) = Run(args);

        Assert.Equal(2, code);
        Assert.Contains("proxylity:", err, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_permission_returns_exit_code_3_and_names_the_action()
    {
        var (code, _, err, _) = Run(["list"], new FakeStackSource { DenyListStacks = true });

        Assert.Equal(3, code);
        Assert.Contains("cloudformation:ListStacks", err, StringComparison.Ordinal);
    }

    [Fact]
    public void Version_and_help_succeed()
    {
        Assert.Equal(0, Run(["--version"]).Code);
        var (code, output, _, _) = Run(["--help"]);
        Assert.Equal(0, code);
        Assert.Contains("read-only", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Running_with_no_command_prints_help_and_signals_a_usage_error()
    {
        var (code, output, _, _) = Run([]);

        Assert.Equal(2, code);
        Assert.Contains("Usage:", output, StringComparison.Ordinal);
    }

    [Fact]
    public void A_throttled_stack_is_skipped_with_a_note_and_others_still_load()
    {
        var (code, output, _, _) = Run(["list"], new FakeStackSource { ThrottleOtherStack = true });

        Assert.Equal(0, code);
        Assert.Contains("demo-Listener-1a2b3c4d", output, StringComparison.Ordinal);
        Assert.Contains("Skipped stack 'other'", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Throttling_of_the_stack_list_returns_exit_code_4_with_guidance()
    {
        var (code, _, err, _) = Run(["list"], new FakeStackSource { ThrottleListStacks = true });

        Assert.Equal(4, code);
        Assert.Contains("--stack", err, StringComparison.Ordinal);
        Assert.DoesNotContain("unexpected", err, StringComparison.Ordinal);
    }

    [Fact]
    public void Version_command_prints_the_same_text_as_the_flag_without_creating_a_source()
    {
        var sourceCreated = false;
        (int Code, string Out) Invoke(string arg)
        {
            var stdout = new StringWriter();
            var app = new CliApp(stdout, new StringWriter(), _ =>
            {
                sourceCreated = true;
                return new FakeStackSource();
            }, colorAllowed: false);
            return (app.RunAsync([arg], CancellationToken.None).GetAwaiter().GetResult(), stdout.ToString());
        }

        var flag = Invoke("--version");
        var command = Invoke("version");
        Assert.Equal(0, command.Code);
        Assert.Equal(flag.Out, command.Out);
        Assert.False(string.IsNullOrWhiteSpace(command.Out));
        Assert.False(sourceCreated);
    }

    [Fact]
    public void Version_command_with_a_target_is_a_usage_error()
    {
        var (code, _, err, _) = Run(["version", "demo"]);
        Assert.Equal(2, code);
        Assert.Contains("does not take a target", err, StringComparison.Ordinal);
    }

    [Fact]
    public void Help_lists_check_access_version_and_quiet()
    {
        var (_, output, _, _) = Run(["--help"]);
        Assert.Contains("check-access", output, StringComparison.Ordinal);
        Assert.Contains("version", output, StringComparison.Ordinal);
        Assert.Contains("--quiet", output, StringComparison.Ordinal);
    }

    private static string RunWithProgress(params string[] args)
    {
        var stderr = new StringWriter();
        var app = new CliApp(new StringWriter(), stderr, _ => new FakeStackSource(), colorAllowed: false, progressAllowed: true,
            observabilityFactory: _ => new FakeObservabilitySource());
        app.RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
        return stderr.ToString();
    }

    [Theory]
    [InlineData("list")]
    [InlineData("diagnose")]
    [InlineData("metrics")]
    public void Progress_is_shown_on_stderr_unless_quiet(string command)
    {
        Assert.Contains("Reading", RunWithProgress(command), StringComparison.Ordinal);
        Assert.Equal(string.Empty, RunWithProgress(command, "--quiet"));
    }

    [Fact]
    public async Task Quiet_still_prints_errors()
    {
        var stderr = new StringWriter();
        var app = new CliApp(new StringWriter(), stderr, _ => new FakeStackSource { DenyListStacks = true }, colorAllowed: false, progressAllowed: true);
        Assert.Equal(3, await app.RunAsync(["list", "--quiet"], CancellationToken.None));
        Assert.Contains("cloudformation:ListStacks", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Quiet_has_no_short_form_and_may_be_combined_with_verbose()
    {
        Assert.Equal(2, Run(["list", "-q"]).Code);
        Assert.Equal(0, Run(["list", "--quiet", "--verbose"]).Code);
    }

    /// <summary>A stack as Terraform's aws_cloudformation_stack creates it: generated name, template with literal values.</summary>
    private sealed class TerraformStackSource : IStackSource
    {
        private const string StackId = "arn:aws:cloudformation:eu-west-1:123456789012:stack/terraform-20250101000000000000000001/2222";

        public string Region => "eu-west-1";

        public Task<IReadOnlyList<StackSummary>> ListStacksAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<StackSummary>>([new StackSummary(StackId, "terraform-20250101000000000000000001", "CREATE_COMPLETE", null, FakeStackSource.BaseTime)]);

        public Task<IReadOnlyList<StackResource>> ListResourcesAsync(string stackId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<StackResource>>([new StackResource("Listener", "tf-listener-0001", "Custom::ProxylityUdpGatewayListener", "CREATE_COMPLETE")]);

        public Task<StackDetails> DescribeAsync(string stackId, CancellationToken cancellationToken) =>
            Task.FromResult(new StackDetails(new Dictionary<string, string>(), new Dictionary<string, string>()));

        public Task<string> GetProcessedTemplateAsync(string stackId, CancellationToken cancellationToken) =>
            Task.FromResult("""
                {
                  "Resources": {
                    "Listener": {
                      "Type": "Custom::ProxylityUdpGatewayListener",
                      "Properties": {
                        "ServiceToken": "arn:aws:lambda:eu-west-1:123456789012:function:handler-token",
                        "ApiKey": "literal-secret-value-xyz",
                        "Protocols": ["udp"],
                        "MetricsEnabled": true,
                        "ClientRestrictions": { "Networks": ["203.0.113.0/24"] },
                        "Destinations": [
                          {
                            "Name": "queue",
                            "DestinationArn": "arn:aws:sqs:eu-west-1:123456789012:jobs",
                            "Role": { "Arn": "arn:aws:iam::123456789012:role/example-role" }
                          }
                        ]
                      }
                    }
                  }
                }
                """);
    }

    [Fact]
    public async Task A_terraform_style_stack_is_discovered_from_its_processed_template()
    {
        var stdout = new StringWriter();
        var app = new CliApp(stdout, new StringWriter(), _ => new TerraformStackSource(), colorAllowed: false);
        Assert.Equal(0, await app.RunAsync(["list", "-o", "json"], CancellationToken.None));
        using var doc = JsonDocument.Parse(stdout.ToString());
        var listener = doc.RootElement.GetProperty("result").GetProperty("listeners").EnumerateArray().Single();
        Assert.Equal("terraform-20250101000000000000000001", listener.GetProperty("stack").GetProperty("name").GetString());
        Assert.Equal("tf-listener-0001", listener.GetProperty("name").GetString());
        Assert.Equal("udp", listener.GetProperty("protocol").GetProperty("value").GetString());
        var target = listener.GetProperty("destinations")[0].GetProperty("targets")[0];
        Assert.Equal("sqs", target.GetProperty("service").GetString());
        Assert.Equal("jobs", target.GetProperty("resourceName").GetString());
        Assert.DoesNotContain("literal-secret-value-xyz", stdout.ToString(), StringComparison.Ordinal);
    }}