using System.Globalization;
using System.Text;
using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli;

/// <summary>
/// Terminal delivery graph for <c>inspect --format graph</c>: one tree per listener (listener, its destinations, the
/// targets of each destination). Meaning is carried by words and symbols; color is decoration only. Lines are wrapped
/// to <paramref name="width"/> with a hanging indent, and names from templates are stripped of control characters.
/// The connectors are box-drawing characters; <see cref="AsciiWriter"/> turns them into ASCII when output is redirected.
/// </summary>
internal sealed class GraphRenderer(TextWriter output, bool color, int width)
{
    internal const int MinWidth = 40;

    private enum Style
    {
        Plain,
        Bold,
        Dim,
        Warn,
    }

    private readonly int width = Math.Max(MinWidth, width);

    public void Render(DeploymentSnapshot s)
    {
        WriteHeader(s);
        if (s.Listeners.Count == 0)
        {
            Line([Seg(s.Stacks.Count == 0
                ? "No Proxylity resources were found in this account and region."
                : "No listeners were found in the matching stacks.")], string.Empty, string.Empty);
            Line([Seg("Resources created outside CloudFormation (for example in the dashboard) are not found this way. Check the region, or use --region.", Style.Dim)], string.Empty, string.Empty);
            WriteNotes(s);
            return;
        }

        // Destinations used by more than one listener in this output are marked as shared.
        var users = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var l in s.Listeners)
        {
            foreach (var name in l.Destinations.Select(d => d.Name).Where(n => n is not null).Distinct(StringComparer.Ordinal))
            {
                if (!users.TryGetValue(name!, out var list))
                {
                    users[name!] = list = [];
                }

                list.Add(ListenerLabel(l));
            }
        }

        foreach (var l in s.Listeners)
        {
            output.WriteLine();
            RenderListener(l, users);
        }

        var unmatched = s.DestinationAttachments.Count(a => !a.Matched);
        if (unmatched > 0)
        {
            output.WriteLine();
            Line([Seg($"{unmatched} destination ARN attachment{(unmatched == 1 ? string.Empty : "s")} belong to destinations not found here and are not drawn. Use 'inspect' without --format for details.", Style.Dim)], string.Empty, string.Empty);
        }

        WriteNotes(s);
    }

    private void RenderListener(ListenerInfo l, Dictionary<string, List<string>> users)
    {
        var protocol = l.Protocol.IsResolved ? Clean(l.Protocol.Value) : "protocol unknown";
        Line([Seg("Listener ", Style.Bold), Seg(ListenerLabel(l), Style.Bold), Seg($" ({protocol})", Style.Dim)], string.Empty, "  ");
        Line([Seg($"stack {Clean(l.Stack.Name)} ({Clean(l.Stack.Status)}), as declared in the stack template", Style.Dim)], string.Empty, string.Empty);

        if (l.Destinations.Count == 0)
        {
            Line([Seg("! ", Style.Warn), Seg("no destinations (nothing will be delivered)")], "\u2514\u2500 ", "   ");
            return;
        }

        for (var i = 0; i < l.Destinations.Count; i++)
        {
            var last = i == l.Destinations.Count - 1;
            RenderDestination(l, l.Destinations[i], users, last);
        }
    }

    private void RenderDestination(ListenerInfo owner, DestinationInfo d, Dictionary<string, List<string>> users, bool lastDestination)
    {
        var branch = lastDestination ? "\u2514\u2500 " : "\u251C\u2500 ";
        var rail = lastDestination ? "   " : "\u2502  ";
        var segs = new List<(string Text, Style Style)> { Seg("Destination ", Style.Dim), Seg(d.Name is null ? "(unnamed)" : Clean(d.Name), Style.Bold) };
        if (d.NameSource == NameSource.Derived)
        {
            segs.Add(Seg(" (name derived from the template, lower confidence)", Style.Dim));
        }

        if (d.Name is not null && users.TryGetValue(d.Name, out var others) && others.Count > 1)
        {
            var also = others.Where(o => !string.Equals(o, ListenerLabel(owner), StringComparison.Ordinal)).Distinct(StringComparer.Ordinal);
            segs.Add(Seg($" [shared with {string.Join(", ", also)}]", Style.Dim));
        }

        Line(segs, branch, rail + "  ");

        if (d.IsReferenceByName)
        {
            Line([Seg("reference to a destination defined elsewhere (not validated here)", Style.Dim)], rail + "\u2514\u2500 ", rail + "   ");
            return;
        }

        if (d.Targets.Count == 0)
        {
            Line([Seg("! ", Style.Warn), Seg("no target (nothing will be delivered)")], rail + "\u2514\u2500 ", rail + "   ");
            return;
        }

        var hasNote = d.Targets.Count > 1;
        for (var i = 0; i < d.Targets.Count; i++)
        {
            var last = i == d.Targets.Count - 1 && !hasNote;
            Line(TargetSegments(d.Targets[i]), rail + (last ? "\u2514\u2500 " : "\u251C\u2500 "), rail + (last ? "   " : "\u2502  ") + "  ");
        }

        if (hasNote)
        {
            Line([Seg("all candidate targets are shown; which one is used is not determined here", Style.Dim)], rail + "\u2514\u2500 ", rail + "   ");
        }
    }

    private static List<(string Text, Style Style)> TargetSegments(DestinationTarget t)
    {
        var segs = new List<(string Text, Style Style)>();
        if (!t.Arn.IsResolved)
        {
            var what = t.Arn.State == ValueState.Absent ? "no ARN is set" : $"could not be resolved ({Clean(t.Arn.Reason)})";
            segs.Add(Seg("! ", Style.Warn));
            segs.Add(Seg($"target {what}"));
        }
        else
        {
            var label = TextRenderer.ServiceLabel(t.Service);
            segs.Add(Seg(t.Service == DestinationService.Unknown ? "target " : $"{label} ", Style.Dim));
            segs.Add(Seg(Clean(t.ResourceName ?? t.Arn.Value), Style.Bold));
        }

        var region = t.RegionFromIngress
            ? $"region is the ingress region (checked in {Clean(t.ArnRegion)})"
            : string.IsNullOrEmpty(t.ArnRegion) ? "region unknown" : $"region {Clean(t.ArnRegion)}";
        var from = t.IngressRegionKey == "*" ? "any ingress region" : $"from {Clean(t.IngressRegionKey)}";
        var via = t.AttachedFrom is null ? string.Empty : $", attached by {Clean(t.AttachedFrom)}";
        segs.Add(Seg($" ({region}; {from}{via})", Style.Dim));
        return segs;
    }

    private void WriteHeader(DeploymentSnapshot s)
    {
        var accounts = s.Stacks.Select(x => x.AccountId).Where(a => a.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        var account = accounts.Count == 1 ? $"account {Clean(accounts[0])}" : accounts.Count > 1 ? $"{accounts.Count} accounts" : "account unknown";
        var regions = string.Join(", ", s.Regions.Select(Clean));
        var stacks = string.Create(CultureInfo.InvariantCulture, $"{s.Stacks.Count} stack{(s.Stacks.Count == 1 ? string.Empty : "s")} with Proxylity resources");
        Line([Seg("Proxylity", Style.Bold), Seg($" \u00B7 {account} \u00B7 {regions} \u00B7 {stacks}", Style.Dim)], string.Empty, "  ");
    }

    private void WriteNotes(DeploymentSnapshot s)
    {
        if (s.Notes.Count == 0)
        {
            return;
        }

        output.WriteLine();
        Line([Seg("Notes", Style.Bold)], string.Empty, string.Empty);
        foreach (var n in s.Notes)
        {
            var warning = n.Severity == "warning";
            Line([warning ? Seg("! ", Style.Warn) : Seg("- ", Style.Dim), Seg(Clean(n.Message))], "  ", "    ");
        }
    }

    private static string ListenerLabel(ListenerInfo l) => Clean(l.Name ?? $"{l.Stack.Name}/{l.LogicalId}");

    private static (string Text, Style Style) Seg(string text, Style style = Style.Plain) => (text, style);

    /// <summary>Writes one node: the prefix on the first line, the hanging prefix on wrapped lines. Long words are split.</summary>
    private void Line(IReadOnlyList<(string Text, Style Style)> segs, string first, string hanging)
    {
        var budget = Math.Max(20, width - Math.Max(first.Length, hanging.Length));
        var lines = new List<List<(string Text, Style Style)>> { new() };
        var used = 0;
        var carry = false;
        foreach (var (text, style) in segs)
        {
            foreach (var (word, spaceBefore0) in Words(text))
            {
                var spaceBefore = spaceBefore0 || carry;
                carry = false;
                var current = lines[^1];
                var gap = used > 0 && spaceBefore ? 1 : 0;
                if (used > 0 && used + gap + word.Length > budget)
                {
                    lines.Add(current = []);
                    used = 0;
                    gap = 0;
                }

                var rest = word;
                while (used + gap + rest.Length > budget)
                {
                    var take = Math.Max(1, budget - used - gap);
                    take = SafeSplit(rest, take);
                    current.Add((new string(' ', gap) + rest[..take], style));
                    rest = rest[take..];
                    lines.Add(current = []);
                    used = 0;
                    gap = 0;
                }

                current.Add((new string(' ', gap) + rest, style));
                used += gap + rest.Length;
            }

            carry = text.EndsWith(' ');
        }

        for (var i = 0; i < lines.Count; i++)
        {
            var sb = new StringBuilder(i == 0 ? Paint(first, Style.Dim) : hanging);
            foreach (var (text, style) in lines[i])
            {
                sb.Append(Paint(text, style));
            }

            output.WriteLine(sb.ToString().TrimEnd());
        }
    }

    /// <summary>Does not cut between the halves of a surrogate pair.</summary>
    private static int SafeSplit(string text, int take) =>
        take < text.Length && take > 0 && char.IsLowSurrogate(text[take]) ? take - 1 is 0 ? take + 1 : take - 1 : take;

    private static IEnumerable<(string Word, bool SpaceBefore)> Words(string text)
    {
        var leading = text.StartsWith(' ');
        var first = true;
        foreach (var w in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            yield return (w, !first || leading);
            first = false;
        }
    }

    private string Paint(string text, Style style) => !color || style == Style.Plain || text.Length == 0
        ? text
        : style switch
        {
            Style.Bold => $"\u001b[1m{text}\u001b[0m",
            Style.Dim => $"\u001b[2m{text}\u001b[0m",
            _ => $"\u001b[33m{text}\u001b[0m",
        };

    /// <summary>Replaces control, format and separator characters (including ESC) so names cannot drive the terminal.</summary>
    internal static string Clean(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            if (rune.Value == 0xFFFD || Rune.IsControl(rune) || category is UnicodeCategory.Format or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator or UnicodeCategory.OtherNotAssigned or UnicodeCategory.PrivateUse
                or UnicodeCategory.Surrogate)
            {
                sb.Append('?');
            }
            else if (Rune.IsWhiteSpace(rune))
            {
                sb.Append(' ');
            }
            else
            {
                sb.Append(rune);
            }
        }

        return sb.ToString();
    }
}
