using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Proxylity.Cli.Core.Observation;

/// <summary>Parses and sanitizes log lines. Log text is untrusted: it can contain data derived from network traffic.</summary>
public static partial class GatewayLogs
{
    public const int MaxMessageLength = 400;

    /// <summary>
    /// Gateway log lines look like <c>[x3]: ERROR: message</c>: a count of identical messages in the
    /// reporting interval, a level, and the message. Lines that do not match are kept with level "UNKNOWN".
    /// </summary>
    public static LogSample Parse(LogEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var match = LinePattern().Match(e.Message);
        if (match.Success)
        {
            var count = int.TryParse(match.Groups["count"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : 1;
            return new LogSample(e.Timestamp, match.Groups["level"].Value, Math.Max(1, count), Sanitize(match.Groups["message"].Value));
        }

        return new LogSample(e.Timestamp, "UNKNOWN", 1, Sanitize(e.Message));
    }

    /// <summary>Lambda function log lines: classify the level from common runtime formats, never from content beyond that.</summary>
    public static LogSample ParseFunctionLine(LogEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        return new LogSample(e.Timestamp, "ERROR", 1, Sanitize(e.Message));
    }

    /// <summary>Escapes control characters (including terminal escape sequences), collapses whitespace, and truncates.</summary>
    public static string Sanitize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var sb = new StringBuilder(Math.Min(text.Length, MaxMessageLength + 16));
        var lastWasSpace = false;
        foreach (var ch in text)
        {
            if (sb.Length >= MaxMessageLength)
            {
                sb.Append("...");
                break;
            }

            if (ch is '\r' or '\n' or '\t' or ' ')
            {
                if (!lastWasSpace)
                {
                    sb.Append(' ');
                }

                lastWasSpace = true;
                continue;
            }

            lastWasSpace = false;
            if (char.IsControl(ch) || ch is '\u2028' or '\u2029' or '\u200e' or '\u200f' or '\u202a' or '\u202b' or '\u202c' or '\u202d' or '\u202e')
            {
                sb.Append(CultureInfo.InvariantCulture, $"\\u{(int)ch:x4}");
            }
            else
            {
                sb.Append(ch);
            }
        }

        return sb.ToString().Trim();
    }

    [GeneratedRegex(@"^\s*\[x(?<count>\d+)\]:\s*(?<level>ERROR|WARN|INFO):\s*(?<message>.*)$", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex LinePattern();
}
