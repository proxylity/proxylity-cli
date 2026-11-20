using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Tests;

public class TemplateRulesTests
{
    private static List<string> Rules(string yaml) =>
        [.. TemplateRules.Check(TemplateParser.Parse(yaml)).Select(i => i.RuleId)];

    [Fact]
    public void A_valid_listener_has_no_issues()
    {
        Assert.Empty(Rules("""
            Protocols: [udp]
            LogGroupName: /proxylity/listeners/example
            ClientRestrictions:
              Networks: ["203.0.113.0/24", "198.51.100.7", "10.0.0.1/24", "2001:db8::/32"]
            Destinations:
              - Name: handler-1
                DestinationArn: arn:aws:lambda:us-west-2:123456789012:function:f
                Batching: { Count: 100, TimeoutInSeconds: 0.25, SizeInMB: 1.0 }
                Arguments: { UseAsyncInvoke: "false" }
              - existing-destination
            """));
    }

    [Theory]
    [InlineData("Count: 0", "batching-count")]
    [InlineData("Count: 1001", "batching-count")]
    [InlineData("Count: 1.5", "batching-count")]
    [InlineData("TimeoutInSeconds: 61", "batching-timeout")]
    [InlineData("TimeoutInSeconds: 0.0005", "batching-timeout")]
    [InlineData("SizeInMB: 7", "batching-size")]
    [InlineData("SizeInMB: 0.0005", "batching-size")]
    public void Batching_limits_are_checked(string setting, string rule)
    {
        Assert.Contains(rule, Rules($$"""
            Destinations:
              - Name: d
                Batching: { {{setting}} }
            """));
    }

    [Fact]
    public void Invalid_cidrs_names_log_groups_protocol_counts_and_mixed_maps_are_reported()
    {
        var rules = Rules("""
            Protocols: [udp, dtls]
            LogGroupName: "bad name with spaces"
            ClientRestrictions:
              Networks: ["not-a-cidr", "10.0.0.0/33"]
            Destinations:
              - Name: bad_name
                SendRaw: "true"
                DestinationArn:
                  us-west-2: arn:aws:lambda:us-west-2:123456789012:function:f
                  eu-west-1: arn:aws:sqs:eu-west-1:123456789012:q
            """);

        Assert.Contains("protocols-count", rules);
        Assert.Contains("log-group-name", rules);
        Assert.Equal(2, rules.Count(r => r == "invalid-cidr"));
        Assert.Contains("destination-name", rules);
        Assert.Contains("destination-unknown-property", rules);
        Assert.Contains("region-map-mixed-services", rules);
    }

    [Fact]
    public void Messages_do_not_repeat_the_checked_values()
    {
        var issues = TemplateRules.Check(TemplateParser.Parse("""
            ClientRestrictions:
              Networks: ["192.0.2.999/8"]
            """));

        var issue = Assert.Single(issues);
        Assert.DoesNotContain("192.0.2.999", issue.Message, StringComparison.Ordinal);
        Assert.Equal("ClientRestrictions.Networks[0]", issue.Path);
    }
}
