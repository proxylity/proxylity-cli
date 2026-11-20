using System.Reflection;
using Proxylity.Cli.Aws;
using Proxylity.Cli.Core.Discovery;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli;

/// <summary>Command dispatch. Takes its streams and AWS access as parameters so it can be tested without a console or AWS.</summary>
/// <param name="cacheDirectory">Where discovery results are cached; null disables caching.</param>
/// <param name="terminalWidth">Columns available to the graph output; narrower than 40 is treated as 40.</param>
/// <param name="observabilityFactory">Creates the metrics/logs/Lambda reader; defaults to AWS.</param>
internal sealed class CliApp(
    TextWriter stdout,
    TextWriter stderr,
    Func<CliOptions, IStackSource> sourceFactory,
    bool colorAllowed,
    bool progressAllowed = false,
    string? cacheDirectory = null,
    Func<CliOptions, IObservabilitySource>? observabilityFactory = null,
    int terminalWidth = 80)
{
    private const string HelpText = """
        proxylity - understand your Proxylity UDP Gateway deployment

        Usage:
          proxylity <command> [target] [options]

        Commands:
          list                 List listeners and their destinations found in CloudFormation
          inspect [target]     Show configuration in detail
          diagnose [target]    Check the delivery path and explain what the evidence shows
          metrics [target]     Show Proxylity and destination service metrics for a time window
          logs [target]        Show recent Proxylity log entries for listeners and destinations
          check-access         Show which of the AWS read actions the CLI uses your identity can perform
          version              Print the version (same as --version)

        A target is a listener name, a logical ID, stack/LogicalId, or a stack name (all its listeners).
        Without a target, commands cover every listener found.

        Options:
          --since <d>          Time window for diagnose, metrics and logs: 15m, 2h, 1d (default 1h, max 14d)
          --limit <n>          Log entries per log group for logs (default 20)
          --profile <name>     AWS profile to use
          --region <name>      AWS region (default: from your AWS configuration)
          --stack <name>       Limit discovery to a stack (repeatable)
          -o, --output <f>     text (default), json, markdown (md; with Mermaid diagrams), or graph (inspect only)
          --format <f>         Same as --output
          --out <file>         Write the output to a file (UTF-8) instead of the terminal
          --refresh            Re-read every stack instead of using cached results
          --no-cache           Do not read or write the local cache
          --no-color           Disable colors
          --verbose            Show more detail on errors
          --quiet              Do not show progress on stderr (errors are still shown)
          -V, --version        Print the version
          -h, --help           Show this help

        The CLI is read-only and uses your existing AWS credentials. It sends nothing to Proxylity.
        Results for unchanged stacks are cached locally (set PROXYLITY_CACHE_DIR to move the cache).
        Exit codes: 0 ok, 1 diagnose found errors, 2 usage error, 3 credentials or permissions,
        4 inconclusive (for example throttled), 5 internal error.
        check-access exits 0 when it ran, even if some actions are denied; it never reads your account configuration.
        """;

    private static readonly string[] Commands = ["list", "inspect", "diagnose", "metrics", "logs", "check-access", "version"];

    public static string Version =>
        typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0-unknown";

    public static CliApp CreateDefault(TextWriter stdout, TextWriter stderr, bool color, bool progress, int terminalWidth = 80) =>
        new(stdout, stderr, o => AwsStackSource.Create(o.Region, o.Profile), color, progress, FileDiscoveryCache.DefaultDirectory(),
            _ => new AwsObservabilitySource(), terminalWidth);

    public async Task<int> RunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        CliOptions options;
        try
        {
            options = ArgumentParser.Parse(args);
        }
        catch (UsageException e)
        {
            stderr.WriteLine($"proxylity: {e.Message}");
            stderr.WriteLine("Try 'proxylity --help'.");
            return ExitCodes.Usage;
        }

        if (options.ShowVersion || (options.Command == "version" && !options.ShowHelp && options.Target is null))
        {
            stdout.WriteLine(Version);
            return ExitCodes.Success;
        }

        if (options.ShowHelp || options.Command is null or "help")
        {
            stdout.WriteLine(HelpText);
            return options.Command is null && !options.ShowHelp ? ExitCodes.Usage : ExitCodes.Success;
        }

        if (!Commands.Contains(options.Command))
        {
            stderr.WriteLine($"proxylity: unknown command '{options.Command}'. Try 'proxylity --help'.");
            return ExitCodes.Usage;
        }

        if (options.Command == "list" && options.Target is not null)
        {
            stderr.WriteLine("proxylity: 'list' does not take a target. Did you mean 'inspect'?");
            return ExitCodes.Usage;
        }

        if (options.Command is "version" or "check-access" && options.Target is not null)
        {
            stderr.WriteLine($"proxylity: '{options.Command}' does not take a target.");
            return ExitCodes.Usage;
        }

        if (options.Output == OutputFormat.Graph && options.Command != "inspect")
        {
            stderr.WriteLine("proxylity: the graph format is available for 'inspect' only. Use 'inspect -o graph', or -o markdown for Mermaid diagrams.");
            return ExitCodes.Usage;
        }

        // --out writes UTF-8 directly, so the result doesn't depend on how a shell re-encodes redirected output.
        StreamWriter? file = null;
        if (options.OutFile is { } path)
        {
            try
            {
                file = new StreamWriter(path, append: false, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                stderr.WriteLine($"proxylity: can't write to '{path}': {e.Message}");
                return ExitCodes.Usage;
            }

            stdout = file;
            colorAllowed = false;
        }

        using var ownedFile = file;

        try
        {
            var source = sourceFactory(options);
            try
            {
                return await RunCommandAsync(options, source, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                (source as IDisposable)?.Dispose();
            }
        }
        catch (AccessDeniedException e)
        {
            stderr.WriteLine($"proxylity: {e.Message}");
            stderr.WriteLine($"The current AWS identity needs permission for {e.Action}.");
            return ExitCodes.Access;
        }
        catch (CredentialsException e)
        {
            stderr.WriteLine($"proxylity: {e.Message}");
            return ExitCodes.Access;
        }
        catch (ThrottledException e)
        {
            stderr.WriteLine($"proxylity: {e.Message}");
            stderr.WriteLine("Wait a moment and retry, or use --stack to limit how many stacks are read.");
            return ExitCodes.Inconclusive;
        }
        catch (OperationCanceledException)
        {
            stderr.WriteLine("proxylity: cancelled.");
            return ExitCodes.Cancelled;
        }
        catch (Exception e)
        {
            stderr.WriteLine($"proxylity: unexpected error: {e.Message}");
            if (options.Verbose)
            {
                stderr.WriteLine(e.ToString());
            }

            return ExitCodes.Internal;
        }
    }

    private async Task<int> RunCommandAsync(CliOptions options, IStackSource source, CancellationToken ct)
    {
        if (options.Command == "check-access")
        {
            return await CheckAccessAsync(options, source, ct).ConfigureAwait(false);
        }

        var snapshot = await DiscoverAsync(options, source, ct).ConfigureAwait(false);
        var resolution = TargetResolver.Resolve(snapshot, options.Target);
        if (resolution.Error is not null)
        {
            stderr.WriteLine($"proxylity: {resolution.Error}");
            if (resolution.Candidates.Count > 0)
            {
                stderr.WriteLine("Matches:");
                foreach (var c in resolution.Candidates)
                {
                    stderr.WriteLine($"  {c}");
                }
            }

            return ExitCodes.Usage;
        }

        if (options.Target is not null)
        {
            snapshot = Scope(snapshot, resolution.Listeners);
        }

        var color = colorAllowed && !options.NoColor && Environment.GetEnvironmentVariable("NO_COLOR") is null;
        switch (options.Command)
        {
            case "list" or "inspect":
                if (options.Output == OutputFormat.Json)
                {
                    stdout.WriteLine(JsonOutput.Serialize(options.Command!, Version, snapshot));
                    return ExitCodes.Success;
                }

                if (options.Output == OutputFormat.Graph)
                {
                    new GraphRenderer(stdout, color, terminalWidth).Render(snapshot);
                    return ExitCodes.Success;
                }

                if (options.Output == OutputFormat.Markdown)
                {
                    var md = new MarkdownRenderer(stdout);
                    if (options.Command == "list")
                    {
                        md.RenderList(snapshot);
                    }
                    else
                    {
                        md.RenderInspect(snapshot);
                    }

                    return ExitCodes.Success;
                }

                var renderer = new TextRenderer(stdout, color);
                if (options.Command == "list")
                {
                    renderer.RenderList(snapshot);
                }
                else
                {
                    renderer.RenderInspect(snapshot);
                }

                return ExitCodes.Success;

            default:
                return await ObserveAsync(options, snapshot, color, ct).ConfigureAwait(false);
        }
    }

    private async Task<int> CheckAccessAsync(CliOptions options, IStackSource source, CancellationToken ct)
    {
        var observability = (observabilityFactory ?? (_ => new AwsObservabilitySource()))(options);
        try
        {
            var report = await new AccessChecker(source, observability).CheckAsync(ct).ConfigureAwait(false);
            switch (options.Output)
            {
                case OutputFormat.Json:
                    stdout.WriteLine(JsonOutput.Serialize("check-access", Version, report));
                    break;
                case OutputFormat.Markdown:
                    new MarkdownRenderer(stdout).RenderAccess(report);
                    break;
                default:
                    new TextRenderer(stdout, colorAllowed && !options.NoColor && Environment.GetEnvironmentVariable("NO_COLOR") is null).RenderAccess(report);
                    break;
            }

            return ExitCodes.Success;
        }
        finally
        {
            (observability as IDisposable)?.Dispose();
        }
    }

    private bool ShowProgress(CliOptions options) => progressAllowed && !options.Quiet && options.Output == OutputFormat.Text;

    private async Task<int> ObserveAsync(CliOptions options, DeploymentSnapshot snapshot, bool color, CancellationToken ct)
    {
        var command = options.Command!;
        var factory = observabilityFactory ?? (_ => new AwsObservabilitySource());
        var observability = factory(options);
        try
        {
            var collectorOptions = command switch
            {
                "metrics" => new CollectorOptions(IncludeLogs: false, IncludeTargetLogs: false),
                "logs" => new CollectorOptions(IncludeLogs: true, IncludeTargetLogs: false, LogLimit: options.Limit ?? 20),
                _ => new CollectorOptions(IncludeLogs: true, IncludeTargetLogs: true, LogLimit: 200, CheckRoles: true),
            };
            var end = DateTimeOffset.UtcNow;
            var window = new TimeWindow(end - options.Window, end);
            var collector = new ObservationCollector(observability, (snapshot.Regions.Count > 0 ? snapshot.Regions[0] : "us-east-1"), collectorOptions);

            if (ShowProgress(options))
            {
                stderr.Write($"\rReading {(command == "logs" ? "logs" : "metrics")} for {snapshot.Listeners.Count} listener(s)...");
            }

            ObservationReport report;
            try
            {
                report = await collector.CollectAsync(snapshot.Listeners, window, ct).ConfigureAwait(false);
            }
            finally
            {
                if (ShowProgress(options))
                {
                    ClearProgress();
                }
            }

            if (command == "diagnose")
            {
                report = Diagnoser.Diagnose(report);
            }

            report = report with { Notes = [.. snapshot.Notes, .. report.Notes] };
            var summary = Summarize(report);

            if (options.Output == OutputFormat.Json)
            {
                stdout.WriteLine(JsonOutput.Serialize(command, Version, new ObservationResult(snapshot.Regions, report, summary)));
            }
            else if (options.Output == OutputFormat.Markdown)
            {
                var md = new MarkdownRenderer(stdout);
                switch (command)
                {
                    case "diagnose":
                        md.RenderDiagnosis(snapshot, report, summary);
                        break;
                    case "metrics":
                        md.RenderMetrics(snapshot, report);
                        break;
                    default:
                        md.RenderLogs(snapshot, report);
                        break;
                }
            }
            else
            {
                var renderer = new ObservationRenderer(stdout, color);
                switch (command)
                {
                    case "diagnose":
                        renderer.RenderDiagnosis(snapshot, report, summary);
                        break;
                    case "metrics":
                        renderer.RenderMetrics(snapshot, report);
                        break;
                    default:
                        renderer.RenderLogs(snapshot, report);
                        break;
                }
            }

            return command == "diagnose" && summary.Errors > 0 ? ExitCodes.FindingsPresent : ExitCodes.Success;
        }
        finally
        {
            (observability as IDisposable)?.Dispose();
        }
    }

    private async Task<DeploymentSnapshot> DiscoverAsync(CliOptions options, IStackSource source, CancellationToken ct)
    {
        Action<int, int>? progress = ShowProgress(options)
            ? (n, total) => stderr.Write($"\rReading stacks {n}/{total}...")
            : null;
        Func<string, string, IDiscoveryCache?>? cacheFactory = cacheDirectory is null || options.NoCache
            ? null
            : (account, region) => FileDiscoveryCache.Open(cacheDirectory, account, region, Version, readEnabled: !options.Refresh);
        var discovery = new DiscoveryService(source, new DiscoveryOptions(options.Stacks, Progress: progress, CacheFactory: cacheFactory));
        try
        {
            return await discovery.DiscoverAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            if (progress is not null)
            {
                ClearProgress();
            }
        }
    }

    /// <summary>Erases the progress line by overwriting it, which works on consoles without escape-sequence support.</summary>
    private void ClearProgress() => stderr.Write("\r" + new string(' ', 60) + "\r");

    /// <summary>Limits a snapshot to the selected listeners and what belongs to them.</summary>
    private static DeploymentSnapshot Scope(DeploymentSnapshot snapshot, IReadOnlyList<ListenerInfo> listeners)
    {
        var names = listeners.Select(l => l.Name).Where(n => n is not null).ToHashSet(StringComparer.Ordinal);
        var destinationNames = listeners.SelectMany(l => l.Destinations).Select(d => d.Name).Where(n => n is not null).ToHashSet(StringComparer.Ordinal);
        return snapshot with
        {
            Listeners = listeners,
            PacketSources = [.. snapshot.PacketSources.Where(p => p.ListenerName.IsResolved && names.Contains(p.ListenerName.Value!))],
            DestinationAttachments = [.. snapshot.DestinationAttachments.Where(a => a.Destination.IsResolved && destinationNames.Contains(a.Destination.Value!))],
        };
    }

    internal static FindingSummary Summarize(ObservationReport report)
    {
        var all = report.Listeners.SelectMany(l => l.Findings
            .Concat(l.Destinations.SelectMany(d => d.Findings
                .Concat(d.Targets.SelectMany(t => t.Findings))))).ToList();
        return new FindingSummary(
            all.Count(f => f.Health == Health.Error),
            all.Count(f => f.Health == Health.Warning),
            all.Count(f => f.Health == Health.Unknown),
            all.Count(f => f.Health == Health.NotConfigured),
            all.Count(f => f.Health == Health.NotAccessible),
            all.Count(f => f.Health == Health.Healthy));
    }
}
