using System.Text;

namespace Proxylity.Cli.Core.Templates;

/// <summary>
/// Evaluates CloudFormation intrinsic functions against deployed state. It never guesses: anything that
/// cannot be determined becomes a <see cref="NodeKind.Unresolved"/> node carrying the reason.
/// </summary>
public sealed class IntrinsicResolver(ResolutionContext context)
{
    private const string MaskedValue = "****";
    private readonly Dictionary<string, bool?> _conditionCache = new(StringComparer.Ordinal);
    private readonly HashSet<string> _conditionsInProgress = new(StringComparer.Ordinal);

    public TNode Resolve(TNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        switch (node.Kind)
        {
            case NodeKind.Map:
                if (node.IsIntrinsic(out var name, out var argument))
                {
                    return ResolveIntrinsic(name, argument);
                }

                var entries = new List<KeyValuePair<string, TNode>>(node.Entries.Count);
                foreach (var entry in node.Entries)
                {
                    var value = Resolve(entry.Value);
                    if (value.Kind != NodeKind.NoValue)
                    {
                        entries.Add(new KeyValuePair<string, TNode>(entry.Key, value));
                    }
                }

                return TNode.Map(entries);
            case NodeKind.Seq:
                return TNode.Seq(node.Items.Select(Resolve).Where(i => i.Kind != NodeKind.NoValue));
            default:
                return node;
        }
    }

    private TNode ResolveIntrinsic(string name, TNode argument) => name switch
    {
        "Ref" => argument.AsString() is { } refName ? ResolveRef(refName) : TNode.Unresolved("Ref argument is not a string"),
        "Fn::GetAtt" => ResolveGetAtt(argument),
        "Fn::Sub" => ResolveSub(argument),
        "Fn::Join" => ResolveJoin(argument),
        "Fn::Select" => ResolveSelect(argument),
        "Fn::Split" => ResolveSplit(argument),
        "Fn::FindInMap" => ResolveFindInMap(argument),
        "Fn::If" => ResolveIf(argument),
        "Fn::Base64" => ResolveBase64(argument),
        "Fn::ImportValue" => ResolveImportValue(argument),
        "Fn::Equals" or "Fn::And" or "Fn::Or" or "Fn::Not" => EvaluateCondition(TNode.Map([new(name, argument)])) is { } b
            ? TNode.Bool(b)
            : TNode.Unresolved($"{name} could not be evaluated"),
        _ => TNode.Unresolved($"{name} is not supported"),
    };

    private TNode ResolveRef(string name)
    {
        switch (name)
        {
            case "AWS::Region":
                return TNode.Str(context.Region);
            case "AWS::AccountId":
                return TNode.Str(context.AccountId);
            case "AWS::StackName":
                return TNode.Str(context.StackName);
            case "AWS::StackId":
                return TNode.Str(context.StackId);
            case "AWS::Partition":
                return TNode.Str(context.Partition);
            case "AWS::URLSuffix":
                return TNode.Str(context.UrlSuffix);
            case "AWS::NoValue":
                return TNode.NoValue;
            case "AWS::NotificationARNs":
                return TNode.Unresolved("AWS::NotificationARNs is not available");
        }

        if (context.Parameters.TryGetValue(name, out var parameter))
        {
            return parameter == MaskedValue
                ? TNode.Unresolved($"parameter '{name}' is masked (NoEcho)")
                : TNode.Str(parameter);
        }

        if (context.Resources.TryGetValue(name, out var resource))
        {
            return resource.PhysicalId is { Length: > 0 } id
                ? TNode.Str(id)
                : TNode.Unresolved($"resource '{name}' has no physical ID yet");
        }

        return TNode.Unresolved($"'{name}' is not a parameter or deployed resource");
    }

    private TNode ResolveGetAtt(TNode argument)
    {
        string? logical;
        string? attribute;
        if (argument.Kind == NodeKind.Seq && argument.Items.Count == 2)
        {
            logical = ResolveToString(argument.Items[0]);
            attribute = ResolveToString(argument.Items[1]);
        }
        else if (argument.AsString() is { } dotted && dotted.IndexOf('.', StringComparison.Ordinal) is var dot and > 0)
        {
            logical = dotted[..dot];
            attribute = dotted[(dot + 1)..];
        }
        else
        {
            return TNode.Unresolved("Fn::GetAtt arguments are not understood");
        }

        if (logical is null || attribute is null)
        {
            return TNode.Unresolved("Fn::GetAtt arguments could not be resolved");
        }

        return GetAttributeValue(logical, attribute);
    }

    private TNode GetAttributeValue(string logical, string attribute)
    {
        if (!context.Resources.TryGetValue(logical, out var resource))
        {
            return TNode.Unresolved($"resource '{logical}' is not deployed");
        }

        if (resource.PhysicalId is not { Length: > 0 } physical)
        {
            return TNode.Unresolved($"resource '{logical}' has no physical ID yet");
        }

        var value = AttributeProviders.TryGet(resource.Type, attribute, physical, context);
        return value is null
            ? TNode.Unresolved($"attribute '{attribute}' of {resource.Type} cannot be determined from stack data")
            : TNode.Str(value);
    }

    private TNode ResolveSub(TNode argument)
    {
        string? template;
        var variables = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (argument.Kind == NodeKind.Seq && argument.Items.Count == 2)
        {
            template = ResolveToString(argument.Items[0]);
            if (argument.Items[1].Kind == NodeKind.Map)
            {
                foreach (var entry in argument.Items[1].Entries)
                {
                    variables[entry.Key] = ResolveToString(entry.Value);
                }
            }
        }
        else
        {
            template = argument.AsString();
        }

        if (template is null)
        {
            return TNode.Unresolved("Fn::Sub template could not be resolved");
        }

        var result = new StringBuilder();
        var index = 0;
        while (index < template.Length)
        {
            var open = template.IndexOf("${", index, StringComparison.Ordinal);
            if (open < 0)
            {
                result.Append(template, index, template.Length - index);
                break;
            }

            var close = template.IndexOf('}', open + 2);
            if (close < 0)
            {
                result.Append(template, index, template.Length - index);
                break;
            }

            result.Append(template, index, open - index);
            var token = template[(open + 2)..close];
            if (token.StartsWith('!'))
            {
                result.Append("${").Append(token.AsSpan(1)).Append('}');
            }
            else
            {
                string? value;
                if (variables.TryGetValue(token, out var mapped))
                {
                    value = mapped;
                }
                else if (token.Contains('.', StringComparison.Ordinal) && !token.StartsWith("AWS::", StringComparison.Ordinal))
                {
                    var dot = token.IndexOf('.', StringComparison.Ordinal);
                    value = GetAttributeValue(token[..dot], token[(dot + 1)..]).AsString();
                }
                else
                {
                    value = ResolveRef(token).AsString();
                }

                if (value is null)
                {
                    return TNode.Unresolved($"Fn::Sub variable '{token}' could not be resolved");
                }

                result.Append(value);
            }

            index = close + 1;
        }

        return TNode.Str(result.ToString());
    }

    private TNode ResolveJoin(TNode argument)
    {
        if (argument.Kind != NodeKind.Seq || argument.Items.Count != 2)
        {
            return TNode.Unresolved("Fn::Join arguments are not understood");
        }

        var delimiter = ResolveToString(argument.Items[0]);
        var list = Resolve(argument.Items[1]);
        if (delimiter is null || list.Kind != NodeKind.Seq)
        {
            return TNode.Unresolved("Fn::Join arguments could not be resolved");
        }

        var parts = new List<string>(list.Items.Count);
        foreach (var item in list.Items)
        {
            if (item.AsString() is not { } text)
            {
                return TNode.Unresolved("Fn::Join contains a value that could not be resolved");
            }

            parts.Add(text);
        }

        return TNode.Str(string.Join(delimiter, parts));
    }

    private TNode ResolveSelect(TNode argument)
    {
        if (argument.Kind != NodeKind.Seq || argument.Items.Count != 2)
        {
            return TNode.Unresolved("Fn::Select arguments are not understood");
        }

        var indexText = ResolveToString(argument.Items[0]);
        var list = Resolve(argument.Items[1]);
        if (indexText is null || !int.TryParse(indexText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var index)
            || list.Kind != NodeKind.Seq || index >= list.Items.Count)
        {
            return TNode.Unresolved("Fn::Select could not be evaluated");
        }

        return list.Items[index];
    }

    private TNode ResolveSplit(TNode argument)
    {
        if (argument.Kind != NodeKind.Seq || argument.Items.Count != 2)
        {
            return TNode.Unresolved("Fn::Split arguments are not understood");
        }

        var delimiter = ResolveToString(argument.Items[0]);
        var text = ResolveToString(argument.Items[1]);
        if (string.IsNullOrEmpty(delimiter) || text is null)
        {
            return TNode.Unresolved("Fn::Split could not be evaluated");
        }

        return TNode.Seq(text.Split(delimiter).Select(TNode.Str));
    }

    private TNode ResolveFindInMap(TNode argument)
    {
        if (argument.Kind != NodeKind.Seq || argument.Items.Count != 3 || context.Mappings is null)
        {
            return TNode.Unresolved("Fn::FindInMap could not be evaluated");
        }

        var keys = argument.Items.Select(ResolveToString).ToArray();
        if (keys.Any(k => k is null))
        {
            return TNode.Unresolved("Fn::FindInMap keys could not be resolved");
        }

        var value = context.Mappings.Get(keys[0]!)?.Get(keys[1]!)?.Get(keys[2]!);
        return value is null ? TNode.Unresolved("Fn::FindInMap found no matching entry") : value;
    }

    private TNode ResolveIf(TNode argument)
    {
        if (argument.Kind != NodeKind.Seq || argument.Items.Count != 3 || argument.Items[0].AsString() is not { } conditionName)
        {
            return TNode.Unresolved("Fn::If arguments are not understood");
        }

        return EvaluateNamedCondition(conditionName) switch
        {
            true => Resolve(argument.Items[1]),
            false => Resolve(argument.Items[2]),
            null => TNode.Unresolved($"condition '{conditionName}' could not be evaluated"),
        };
    }

    private TNode ResolveBase64(TNode argument)
    {
        var text = ResolveToString(argument);
        return text is null
            ? TNode.Unresolved("Fn::Base64 input could not be resolved")
            : TNode.Str(Convert.ToBase64String(Encoding.UTF8.GetBytes(text)));
    }

    private TNode ResolveImportValue(TNode argument)
    {
        var name = ResolveToString(argument);
        if (name is null)
        {
            return TNode.Unresolved("Fn::ImportValue name could not be resolved");
        }

        return context.Exports.TryGetValue(name, out var value)
            ? TNode.Str(value)
            : TNode.Unresolved($"export '{name}' is not available");
    }

    private bool? EvaluateNamedCondition(string name)
    {
        if (_conditionCache.TryGetValue(name, out var cached))
        {
            return cached;
        }

        if (!_conditionsInProgress.Add(name))
        {
            return null; // cyclic definition
        }

        try
        {
            var definition = context.Conditions?.Get(name);
            var result = definition is null ? null : EvaluateCondition(definition);
            _conditionCache[name] = result;
            return result;
        }
        finally
        {
            _conditionsInProgress.Remove(name);
        }
    }

    private bool? EvaluateCondition(TNode expression)
    {
        if (expression.Kind != NodeKind.Map || expression.Entries.Count != 1)
        {
            return null;
        }

        var (key, args) = (expression.Entries[0].Key, expression.Entries[0].Value);
        switch (key)
        {
            case "Condition":
                return args.AsString() is { } conditionName ? EvaluateNamedCondition(conditionName) : null;
            case "Fn::Equals":
                if (args.Kind != NodeKind.Seq || args.Items.Count != 2)
                {
                    return null;
                }

                var left = ResolveToString(args.Items[0]);
                var right = ResolveToString(args.Items[1]);
                return left is null || right is null ? null : string.Equals(left, right, StringComparison.Ordinal);
            case "Fn::Not":
                if (args.Kind != NodeKind.Seq || args.Items.Count != 1)
                {
                    return null;
                }

                var inner = EvaluateCondition(args.Items[0]);
                return inner is null ? null : !inner;
            case "Fn::And":
            case "Fn::Or":
                if (args.Kind != NodeKind.Seq)
                {
                    return null;
                }

                var isAnd = key == "Fn::And";
                var unknown = false;
                foreach (var item in args.Items)
                {
                    var value = EvaluateCondition(item);
                    if (value is null)
                    {
                        unknown = true;
                    }
                    else if (isAnd && !value.Value)
                    {
                        return false;
                    }
                    else if (!isAnd && value.Value)
                    {
                        return true;
                    }
                }

                return unknown ? null : isAnd;
            default:
                return null;
        }
    }

    private string? ResolveToString(TNode node) => Resolve(node).AsString();
}
