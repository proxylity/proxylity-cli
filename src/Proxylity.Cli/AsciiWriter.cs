using System.Globalization;
using System.Text;

namespace Proxylity.Cli;

/// <summary>
/// Used when stdout is redirected. Shells re-encode redirected output in different ways (Windows PowerShell 5.1
/// decodes it with the console code page, for example), so redirected output is kept pure ASCII: the CLI's own
/// symbols become ASCII equivalents and any other non-ASCII character is written as a \uXXXX escape.
/// </summary>
internal sealed class AsciiWriter(TextWriter inner) : TextWriter
{
    public override Encoding Encoding => Encoding.ASCII;

    public override IFormatProvider FormatProvider => CultureInfo.InvariantCulture;

    public override void Write(char value)
    {
        if (value < 128)
        {
            inner.Write(value);
            return;
        }

        inner.Write(Replace(value));
    }

    public override void Write(string? value)
    {
        if (value is null)
        {
            return;
        }

        if (!value.Any(c => c >= 128))
        {
            inner.Write(value);
            return;
        }

        var sb = new StringBuilder(value.Length + 16);
        foreach (var c in value)
        {
            if (c < 128)
            {
                sb.Append(c);
            }
            else
            {
                sb.Append(Replace(c));
            }
        }

        inner.Write(sb.ToString());
    }

    public override void Write(char[] buffer, int index, int count) => Write(new string(buffer, index, count));

    public override void WriteLine() => inner.WriteLine();

    public override void Flush() => inner.Flush();

    /// <summary>ASCII stand-ins of the same width for the CLI's symbols; everything else is escaped.</summary>
    internal static string Replace(char c) => c switch
    {
        '\u2192' => "->",   // →
        '\u2500' => "-",    // box drawing: horizontal
        '\u2502' => "|",    // vertical
        '\u251C' => "+",    // branch
        '\u2514' => "\\",   // last branch
        '\u00B7' => "|",    // ·
        '\u00D7' => "x",    // ×
        '\u2013' => "-",    // –
        '\u2014' => "-",    // —
        '\u2026' => "...",  // …
        '\u2717' => "x",    // ✗
        '\u2713' => "+",    // ✓
        '\u2298' => "!",    // ⊘
        _ => string.Create(CultureInfo.InvariantCulture, $"\\u{(int)c:x4}"),
    };

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Flush();
        }

        base.Dispose(disposing);
    }
}
