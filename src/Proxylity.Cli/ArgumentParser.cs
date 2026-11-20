using System.Globalization;
using System.Text.RegularExpressions;

namespace Proxylity.Cli;

internal enum OutputFormat
{
    Text,
    Json,
    Markdown,
    Graph,
}

internal sealed class UsageException(string message) : Exception(message);

internal sealed record CliOptions(
    string? Command,
    string? Target,
    string? Profile,
    string? Region,
    IReadOnlyList<string> Stacks,
    OutputFormat Output,
    bool NoColor,
    bool Verbose,
    bool ShowHelp,
    bool ShowVersion,
    bool Refresh = false,
    bool NoCache = false,
    TimeSpan? Since = null,
    int? Limit = null,
    string? OutFile = null,
    bool Quiet = false)
{
    public static readonly TimeSpan DefaultSince = TimeSpan.FromHours(1);

    public TimeSpan Window => Since ?? DefaultSince;
}

/// <summary>
/// A small hand-written parser. The command set is tiny, and avoiding a parsing library keeps the
/// dependency footprint and the AoT surface minimal.
/// </summary>
internal static partial class ArgumentParser
{
    /// <summary>Metrics older than this are only kept at coarse resolution; keep queries cheap and meaningful.</summary>
    public static readonly TimeSpan MaxSince = TimeSpan.FromDays(14);

    public static CliOptions Parse(IReadOnlyList<string> args)
    {
        string? command = null;
        string? target = null;
        string? profile = null;
        string? region = null;
        TimeSpan? since = null;
        int? limit = null;
        string? outFile = null;
        var stacks = new List<string>();
        var output = OutputFormat.Text;
        bool noColor = false, verbose = false, quiet = false, help = false, version = false, refresh = false, noCache = false;

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            string? inline = null;
            if (arg.StartsWith("--", StringComparison.Ordinal) && arg.IndexOf('=', StringComparison.Ordinal) is var eq and > 0)
            {
                inline = arg[(eq + 1)..];
                arg = arg[..eq];
            }

            string Value()
            {
                if (inline is not null)
                {
                    return inline;
                }

                if (i + 1 >= args.Count || args[i + 1].StartsWith('-'))
                {
                    throw new UsageException($"Option '{arg}' requires a value.");
                }

                return args[++i];
            }

            switch (arg)
            {
                case "-h" or "--help":
                    help = true;
                    break;
                case "-V" or "--version":
                    version = true;
                    break;
                case "--no-color":
                    noColor = true;
                    break;
                case "--verbose":
                    verbose = true;
                    break;
                case "--quiet":
                    quiet = true;
                    break;
                case "--refresh":
                    refresh = true;
                    break;
                case "--no-cache":
                    noCache = true;
                    break;
                case "--profile":
                    profile = Value();
                    break;
                case "--region":
                    region = Value();
                    break;
                case "--stack":
                    stacks.Add(Value());
                    break;
                case "--out":
                    outFile = Value();
                    break;
                case "--since":
                    since = ParseDuration(Value());
                    break;
                case "--limit":
                    var text = Value();
                    limit = int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is > 0 and <= 1000
                        ? n
                        : throw new UsageException($"--limit must be a number from 1 to 1000, not '{text}'.");
                    break;
                case "-o" or "--output" or "--format":
                    output = Value().ToLowerInvariant() switch
                    {
                        "text" => OutputFormat.Text,
                        "json" => OutputFormat.Json,
                        "markdown" or "md" => OutputFormat.Markdown,
                        "graph" => OutputFormat.Graph,
                        var other => throw new UsageException($"Unknown output format '{other}'. Use 'text', 'json', 'markdown' or 'graph'."),
                    };
                    break;
                default:
                    if (arg.StartsWith('-') && arg.Length > 1)
                    {
                        throw new UsageException($"Unknown option '{arg}'.");
                    }

                    if (command is null)
                    {
                        command = arg;
                    }
                    else if (target is null)
                    {
                        target = arg;
                    }
                    else
                    {
                        throw new UsageException($"Unexpected argument '{arg}'.");
                    }

                    break;
            }
        }

        return new CliOptions(command, target, profile, region, stacks, output, noColor, verbose, help, version, refresh, noCache, since, limit, outFile, quiet);
    }

    /// <summary>Durations like 15m, 2h, 3d.</summary>
    internal static TimeSpan ParseDuration(string text)
    {
        var m = DurationPattern().Match(text);
        if (!m.Success || !int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n == 0)
        {
            throw new UsageException($"'{text}' is not a duration. Use a number and m, h or d, for example 15m, 2h or 1d.");
        }

        var span = m.Groups[2].Value switch
        {
            "m" => TimeSpan.FromMinutes(n),
            "h" => TimeSpan.FromHours(n),
            _ => TimeSpan.FromDays(n),
        };
        return span > MaxSince
            ? throw new UsageException("--since can be at most 14d.")
            : span < TimeSpan.FromMinutes(5) ? throw new UsageException("--since must be at least 5m (metrics are published in intervals).") : span;
    }

    [GeneratedRegex("^([0-9]+)([mhd])$", RegexOptions.CultureInvariant)]
    private static partial Regex DurationPattern();
}
