using System.Text.Json;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli.Tests;

public class AccountConfigTests
{
    private const string Listener = "demo-Listener-1a2b3c4d";
    private const string Role = "arn:aws:iam::123456789012:role/example-role";
    private const string ServiceRole = "arn:aws:iam::123456789012:role/example-service-role";

    private static string Config(string externalId = "expected-external-id", string apiKey = "literal-secret-value-xyz") => $$"""
        {
          "us-west-2": { "ServiceToken": "arn:aws:lambda:us-west-2:123456789012:function:example-token", "ServiceRole": "{{ServiceRole}}" },
          "Account": { "ExternalId": "{{externalId}}", "ApiKey": "{{apiKey}}" }
        }
        """;

    private static FakeObservabilitySource Obs(string config, IReadOnlyList<string>? externalIds = null, IReadOnlyList<string>? principals = null)
    {
        var obs = new FakeObservabilitySource { AccountConfig = Signal<AccountConfig>.Of(AccountConfig.Parse(config)) };
        obs.Roles[Role] = Signal<RoleTrust>.Of(new RoleTrust(true, true, principals ?? [ServiceRole], externalIds ?? ["expected-external-id"]));
        return obs;
    }

    private static (string Json, string Text) Run(FakeObservabilitySource obs)
    {
        string Invoke(params string[] args)
        {
            var stdout = new StringWriter();
            new CliApp(stdout, new StringWriter(), _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => obs)
                .RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
            return stdout.ToString();
        }

        return (Invoke("diagnose", Listener, "--output", "json"), Invoke("diagnose", Listener, "--no-color"));
    }

    private static List<string> RuleIds(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var listener = doc.RootElement.GetProperty("result").GetProperty("report").GetProperty("listeners")[0];
        return [.. listener.GetProperty("findings").EnumerateArray()
            .Concat(listener.GetProperty("destinations").EnumerateArray().SelectMany(d => d.GetProperty("findings").EnumerateArray()))
            .Select(f => f.GetProperty("ruleId").GetString()!)];
    }

    [Fact]
    public void Parse_reads_the_documented_shape_and_never_shows_values()
    {
        var config = AccountConfig.Parse(Config());

        Assert.Equal("AccountConfig(redacted)", config.ToString());
        Assert.Equal(Fingerprint.Of("literal-secret-value-xyz"), config.KeyFingerprint);
        Assert.Equal(ServiceRole, config.ServiceRole("us-west-2"));
        Assert.Null(config.ServiceRole("eu-west-1"));
    }

    [Fact]
    public void A_matching_external_id_and_service_role_is_positive_evidence()
    {
        var (json, _) = Run(Obs(Config()));

        Assert.Contains("destination.role-ok", RuleIds(json));
        Assert.DoesNotContain("destination.role-external-id-mismatch", RuleIds(json));
        Assert.Contains("matches the account configuration", json, StringComparison.Ordinal);
    }

    [Fact]
    public void A_stale_external_id_is_an_error()
    {
        var (json, _) = Run(Obs(Config(externalId: "regenerated-id")));

        Assert.Contains("destination.role-external-id-mismatch", RuleIds(json));
        Assert.DoesNotContain("destination.role-ok", RuleIds(json));
    }

    [Fact]
    public void An_untrusted_service_role_is_a_warning()
    {
        var (json, _) = Run(Obs(Config(), principals: ["arn:aws:iam::123456789012:role/something-else"]));

        Assert.Contains("destination.role-service-role-not-trusted", RuleIds(json));
    }

    [Fact]
    public void A_stack_deployed_with_another_api_key_is_flagged()
    {
        var (json, _) = Run(Obs(Config(apiKey: "the-current-key-value")));

        Assert.Contains("stack.api-key-mismatch", RuleIds(json));
        Assert.DoesNotContain("the-current-key-value", json, StringComparison.Ordinal);
    }

    [Fact]
    public void No_configuration_values_or_fingerprints_of_them_reach_the_output()
    {
        var (json, text) = Run(Obs(Config(externalId: "regenerated-id")));

        foreach (var secret in new[] { "regenerated-id", "expected-external-id", "literal-secret-value-xyz", "example-token", ServiceRole, Fingerprint.Of("literal-secret-value-xyz") })
        {
            Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void An_unreadable_configuration_is_one_note_and_nothing_else_changes()
    {
        var obs = new FakeObservabilitySource { AccountConfig = Signal<AccountConfig>.NotAccessible("s3:GetObject") };

        var (json, text) = Run(obs);

        Assert.Contains("destination.role-ok", RuleIds(json));
        Assert.Contains("account configuration for us-west-2 was not read", text, StringComparison.Ordinal);
        Assert.Contains("s3:GetObject", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Trust_policy_analysis_collects_values_for_comparison_but_hides_them()
    {
        var t = TrustPolicy.Analyze("""
            { "Statement": [{ "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::123456789012:role/p" }, "Action": "sts:AssumeRole",
              "Condition": { "StringEquals": { "sts:ExternalId": "abc" } } }] }
            """);

        Assert.Equal(["abc"], t.ExternalIds);
        Assert.Equal(["arn:aws:iam::123456789012:role/p"], t.Principals);
        Assert.DoesNotContain("abc", t.ToString(), StringComparison.Ordinal);
    }
}
