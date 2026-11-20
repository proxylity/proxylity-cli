namespace Proxylity.Cli.Core.Templates;

public enum NodeKind
{
    Null,
    String,
    Number,
    Bool,
    Map,
    Seq,

    /// <summary>A value that could not be determined; <see cref="TNode.Text"/> holds the reason.</summary>
    Unresolved,

    /// <summary>The result of <c>Ref: AWS::NoValue</c>; the containing key or item is dropped.</summary>
    NoValue,
}

/// <summary>
/// An immutable, format-neutral template value (JSON or YAML). Intrinsic functions are kept in
/// their long form: a single-key map such as <c>{ "Ref": "X" }</c> or <c>{ "Fn::Sub": ... }</c>.
/// </summary>
public sealed class TNode
{
    private static readonly KeyValuePair<string, TNode>[] EmptyEntries = [];
    private static readonly TNode[] EmptyItems = [];

    private TNode(NodeKind kind, string? text, IReadOnlyList<KeyValuePair<string, TNode>>? entries, IReadOnlyList<TNode>? items)
    {
        Kind = kind;
        Text = text;
        Entries = entries ?? EmptyEntries;
        Items = items ?? EmptyItems;
    }

    public NodeKind Kind { get; }

    /// <summary>Scalar text, or the reason for an <see cref="NodeKind.Unresolved"/> node.</summary>
    public string? Text { get; }

    public IReadOnlyList<KeyValuePair<string, TNode>> Entries { get; }

    public IReadOnlyList<TNode> Items { get; }

    public static TNode Null { get; } = new(NodeKind.Null, null, null, null);

    public static TNode NoValue { get; } = new(NodeKind.NoValue, null, null, null);

    public static TNode Str(string value) => new(NodeKind.String, value, null, null);

    public static TNode Num(string raw) => new(NodeKind.Number, raw, null, null);

    public static TNode Bool(bool value) => new(NodeKind.Bool, value ? "true" : "false", null, null);

    public static TNode Map(IEnumerable<KeyValuePair<string, TNode>> entries) =>
        new(NodeKind.Map, null, entries.ToArray(), null);

    public static TNode Seq(IEnumerable<TNode> items) => new(NodeKind.Seq, null, null, items.ToArray());

    public static TNode Unresolved(string reason) => new(NodeKind.Unresolved, reason, null, null);

    public bool IsScalar => Kind is NodeKind.String or NodeKind.Number or NodeKind.Bool;

    public TNode? Get(string key)
    {
        if (Kind != NodeKind.Map)
        {
            return null;
        }

        foreach (var entry in Entries)
        {
            if (string.Equals(entry.Key, key, StringComparison.Ordinal))
            {
                return entry.Value;
            }
        }

        return null;
    }

    public bool Has(string key) => Get(key) is not null;

    public string? AsString() => IsScalar ? Text : null;

    public bool? AsBool()
    {
        if (Kind == NodeKind.Bool)
        {
            return Text == "true";
        }

        if (Kind == NodeKind.String)
        {
            if (string.Equals(Text, "true", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.Equals(Text, "false", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return null;
    }

    /// <summary>True when this is a single-key map naming an intrinsic function (<c>Ref</c> or <c>Fn::*</c>).</summary>
    public bool IsIntrinsic(out string name, out TNode argument)
    {
        if (Kind == NodeKind.Map && Entries.Count == 1)
        {
            var key = Entries[0].Key;
            if (key == "Ref" || key.StartsWith("Fn::", StringComparison.Ordinal))
            {
                name = key;
                argument = Entries[0].Value;
                return true;
            }
        }

        name = string.Empty;
        argument = Null;
        return false;
    }
}
