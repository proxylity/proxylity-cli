using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Tests;

public class IntrinsicResolverTests
{
    private static IntrinsicResolver Create(
        Dictionary<string, string>? parameters = null,
        TNode? conditions = null,
        TNode? mappings = null) =>
        new(new ResolutionContext
        {
            Region = "us-west-2",
            AccountId = "123456789012",
            StackName = "demo",
            StackId = "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000",
            Parameters = parameters ?? [],
            Resources = new Dictionary<string, DeployedResource>
            {
                ["Fn"] = new("Fn", "AWS::Lambda::Function", "packet-handler", "CREATE_COMPLETE"),
                ["Queue"] = new("Queue", "AWS::SQS::Queue", "https://sqs.us-west-2.amazonaws.com/123456789012/jobs", "CREATE_COMPLETE"),
                ["Listener"] = new("Listener", "Custom::ProxylityUdpGatewayListener", "demo-Listener-1a2b3c4d", "CREATE_COMPLETE"),
            },
            Conditions = conditions,
            Mappings = mappings,
        });

    private static TNode Parse(string yaml) => TemplateParser.Parse(yaml);

    [Fact]
    public void Ref_resolves_parameters_resources_and_pseudo_parameters()
    {
        var r = Create(new() { ["Env"] = "prod" });
        var node = Parse("""
            P: !Ref Env
            R: !Ref Fn
            Region: !Ref AWS::Region
            Stack: !Ref AWS::StackName
            """);

        var resolved = r.Resolve(node);

        Assert.Equal("prod", resolved.Get("P")!.AsString());
        Assert.Equal("packet-handler", resolved.Get("R")!.AsString());
        Assert.Equal("us-west-2", resolved.Get("Region")!.AsString());
        Assert.Equal("demo", resolved.Get("Stack")!.AsString());
    }

    [Fact]
    public void GetAtt_builds_arns_from_physical_ids_for_known_types()
    {
        var resolved = Create().Resolve(Parse("""
            Fn: !GetAtt Fn.Arn
            Q: !GetAtt Queue.Arn
            L: !GetAtt Listener.Id
            """));

        Assert.Equal("arn:aws:lambda:us-west-2:123456789012:function:packet-handler", resolved.Get("Fn")!.AsString());
        Assert.Equal("arn:aws:sqs:us-west-2:123456789012:jobs", resolved.Get("Q")!.AsString());
        Assert.Equal("demo-Listener-1a2b3c4d", resolved.Get("L")!.AsString());
    }

    [Fact]
    public void Unknown_attributes_are_unresolved_not_guessed()
    {
        var resolved = Create().Resolve(Parse("X: !GetAtt Fn.SomethingUnknown"));

        Assert.Equal(NodeKind.Unresolved, resolved.Get("X")!.Kind);
    }

    [Fact]
    public void Masked_parameters_and_missing_references_are_unresolved()
    {
        var r = Create(new() { ["Secret"] = "****" });

        var resolved = r.Resolve(Parse("""
            A: !Ref Secret
            B: !Ref Nope
            """));

        Assert.Equal(NodeKind.Unresolved, resolved.Get("A")!.Kind);
        Assert.Contains("NoEcho", resolved.Get("A")!.Text, StringComparison.Ordinal);
        Assert.Equal(NodeKind.Unresolved, resolved.Get("B")!.Kind);
    }

    [Fact]
    public void Sub_handles_variables_pseudo_parameters_attributes_and_literals()
    {
        var resolved = Create(new() { ["Env"] = "prod" }).Resolve(Parse("""
            A: !Sub "${Env}-${AWS::Region}"
            B: !Sub "${Fn.Arn}"
            C: !Sub "${!Literal}"
            D: !Sub ["${X}-${Env}", { X: custom }]
            """));

        Assert.Equal("prod-us-west-2", resolved.Get("A")!.AsString());
        Assert.Equal("arn:aws:lambda:us-west-2:123456789012:function:packet-handler", resolved.Get("B")!.AsString());
        Assert.Equal("${Literal}", resolved.Get("C")!.AsString());
        Assert.Equal("custom-prod", resolved.Get("D")!.AsString());
    }

    [Fact]
    public void Join_select_split_and_findinmap_work()
    {
        var mappings = Parse("""
            Regions:
              us-west-2:
                Name: oregon
            """);
        var resolved = Create(mappings: mappings).Resolve(Parse("""
            J: !Join ["-", [a, !Ref AWS::Region, b]]
            S: !Select [1, !Split [",", "x,y,z"]]
            M: !FindInMap [Regions, !Ref AWS::Region, Name]
            """));

        Assert.Equal("a-us-west-2-b", resolved.Get("J")!.AsString());
        Assert.Equal("y", resolved.Get("S")!.AsString());
        Assert.Equal("oregon", resolved.Get("M")!.AsString());
    }

    [Fact]
    public void Conditions_choose_branches_and_novalue_drops_keys()
    {
        var conditions = Parse("""
            IsProd: !Equals [!Ref Env, prod]
            NotProd: !Not [!Condition IsProd]
            """);
        var resolved = Create(new() { ["Env"] = "prod" }, conditions).Resolve(Parse("""
            Value: !If [IsProd, big, small]
            Dropped: !If [NotProd, here, !Ref AWS::NoValue]
            Kept: yes-here
            """));

        Assert.Equal("big", resolved.Get("Value")!.AsString());
        Assert.False(resolved.Has("Dropped"));
        Assert.True(resolved.Has("Kept"));
    }

    [Fact]
    public void Unevaluable_conditions_make_the_result_unresolved()
    {
        var resolved = Create().Resolve(Parse("X: !If [Missing, a, b]"));

        Assert.Equal(NodeKind.Unresolved, resolved.Get("X")!.Kind);
    }
}
