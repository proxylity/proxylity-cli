using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Proxylity.Cli.Core.Templates;

public sealed class TemplateParseException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Parses a CloudFormation template (JSON or YAML) into a <see cref="TNode"/> tree. YAML short-form tags
/// such as <c>!Ref</c> and <c>!GetAtt</c> are normalized to the long form so the rest of the code deals
/// with a single representation. Uses only the YAML representation model (no type binding), which keeps
/// the code trimming- and AoT-friendly.
/// </summary>
public static partial class TemplateParser
{
    public static TNode Parse(string body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var trimmed = body.AsSpan().TrimStart();
        if (trimmed.IsEmpty)
        {
            throw new TemplateParseException("The template is empty.");
        }

        try
        {
            return trimmed[0] == '{' ? ParseJson(body) : ParseYaml(body);
        }
        catch (Exception e) when (e is JsonException or YamlException)
        {
            throw new TemplateParseException("The template could not be parsed: " + e.Message, e);
        }
    }

    private static TNode ParseJson(string body)
    {
        using var doc = JsonDocument.Parse(body, new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        });
        return FromJson(doc.RootElement);
    }

    private static TNode FromJson(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => TNode.Map(e.EnumerateObject().Select(p => new KeyValuePair<string, TNode>(p.Name, FromJson(p.Value)))),
        JsonValueKind.Array => TNode.Seq(e.EnumerateArray().Select(FromJson)),
        JsonValueKind.String => TNode.Str(e.GetString() ?? string.Empty),
        JsonValueKind.Number => TNode.Num(e.GetRawText()),
        JsonValueKind.True => TNode.Bool(true),
        JsonValueKind.False => TNode.Bool(false),
        _ => TNode.Null,
    };

    private static TNode ParseYaml(string body)
    {
        var stream = new YamlStream();
        using var reader = new StringReader(body);
        stream.Load(reader);
        return stream.Documents.Count == 0 ? TNode.Null : FromYaml(stream.Documents[0].RootNode);
    }

    private static TNode FromYaml(YamlNode node)
    {
        var tag = node.Tag.IsEmpty ? null : node.Tag.Value;
        if (tag is { Length: > 1 } && tag[0] == '!' && tag[1] != '!')
        {
            var name = tag[1..];
            var inner = ConvertContent(node, forceString: false);
            if (name == "GetAtt" && inner.Kind == NodeKind.String && inner.Text is { } dotted)
            {
                var dot = dotted.IndexOf('.', StringComparison.Ordinal);
                if (dot > 0)
                {
                    inner = TNode.Seq([TNode.Str(dotted[..dot]), TNode.Str(dotted[(dot + 1)..])]);
                }
            }

            var key = name is "Ref" or "Condition" ? name : "Fn::" + name;
            return TNode.Map([new KeyValuePair<string, TNode>(key, inner)]);
        }

        return ConvertContent(node, tag is "tag:yaml.org,2002:str" or "!!str");
    }

    private static TNode ConvertContent(YamlNode node, bool forceString)
    {
        switch (node)
        {
            case YamlScalarNode scalar:
                return ConvertScalar(scalar, forceString);
            case YamlMappingNode map:
                var entries = new List<KeyValuePair<string, TNode>>();
                foreach (var pair in map.Children)
                {
                    var key = pair.Key is YamlScalarNode k ? k.Value ?? string.Empty : string.Empty;
                    entries.Add(new KeyValuePair<string, TNode>(key, FromYaml(pair.Value)));
                }

                return TNode.Map(entries);
            case YamlSequenceNode seq:
                return TNode.Seq(seq.Children.Select(FromYaml));
            default:
                return TNode.Null;
        }
    }

    private static TNode ConvertScalar(YamlScalarNode scalar, bool forceString)
    {
        var value = scalar.Value ?? string.Empty;
        if (forceString || scalar.Style != ScalarStyle.Plain)
        {
            return TNode.Str(value);
        }

        if (value.Length == 0 || value is "~" || string.Equals(value, "null", StringComparison.OrdinalIgnoreCase))
        {
            return TNode.Null;
        }

        if (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase))
        {
            return TNode.Bool(true);
        }

        if (string.Equals(value, "false", StringComparison.OrdinalIgnoreCase))
        {
            return TNode.Bool(false);
        }

        if (NumberPattern().IsMatch(value))
        {
            return TNode.Num(value);
        }

        return TNode.Str(value);
    }

    [GeneratedRegex(@"^[-+]?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex NumberPattern();
}
