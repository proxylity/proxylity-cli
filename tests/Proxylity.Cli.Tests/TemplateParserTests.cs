using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Tests;

public class TemplateParserTests
{
    [Fact]
    public void Yaml_short_form_tags_become_long_form_intrinsics()
    {
        const string yaml = """
            Resources:
              Thing:
                Type: AWS::Lambda::Function
                Properties:
                  A: !Ref Param
                  B: !GetAtt Fn.Arn
                  C: !Sub "arn:${AWS::Partition}:x"
                  D: !Join [",", [a, b]]
                  E: !Condition Flag
            """;

        var props = TemplateParser.Parse(yaml).Get("Resources")!.Get("Thing")!.Get("Properties")!;

        Assert.True(props.Get("A")!.IsIntrinsic(out var a, out var aArg));
        Assert.Equal("Ref", a);
        Assert.Equal("Param", aArg.AsString());

        Assert.True(props.Get("B")!.IsIntrinsic(out var b, out var bArg));
        Assert.Equal("Fn::GetAtt", b);
        Assert.Equal(["Fn", "Arn"], bArg.Items.Select(i => i.AsString()));

        Assert.True(props.Get("C")!.IsIntrinsic(out var c, out _));
        Assert.Equal("Fn::Sub", c);

        Assert.True(props.Get("D")!.IsIntrinsic(out var d, out var dArg));
        Assert.Equal("Fn::Join", d);
        Assert.Equal(2, dArg.Items.Count);

        Assert.Equal("Flag", props.Get("E")!.Get("Condition")!.AsString());
    }

    [Fact]
    public void Yaml_scalars_keep_their_types()
    {
        var root = TemplateParser.Parse("""
            Plain: true
            Quoted: "true"
            Number: 42
            Text: hello
            Nothing: ~
            """);

        Assert.Equal(NodeKind.Bool, root.Get("Plain")!.Kind);
        Assert.Equal(NodeKind.String, root.Get("Quoted")!.Kind);
        Assert.Equal(NodeKind.Number, root.Get("Number")!.Kind);
        Assert.Equal(NodeKind.String, root.Get("Text")!.Kind);
        Assert.Equal(NodeKind.Null, root.Get("Nothing")!.Kind);
    }

    [Fact]
    public void Json_templates_parse_to_the_same_shape()
    {
        var root = TemplateParser.Parse("""{ "Resources": { "X": { "Type": "T", "Properties": { "N": 5, "B": false, "R": { "Ref": "P" } } } } }""");
        var props = root.Get("Resources")!.Get("X")!.Get("Properties")!;

        Assert.Equal(NodeKind.Number, props.Get("N")!.Kind);
        Assert.False(props.Get("B")!.AsBool());
        Assert.True(props.Get("R")!.IsIntrinsic(out var name, out _));
        Assert.Equal("Ref", name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_templates_are_rejected(string body)
    {
        Assert.Throws<TemplateParseException>(() => TemplateParser.Parse(body));
    }

    [Fact]
    public void Malformed_json_is_reported_as_a_parse_error()
    {
        Assert.Throws<TemplateParseException>(() => TemplateParser.Parse("{ \"a\": "));
    }
}
