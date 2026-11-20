using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Core.Discovery;

/// <param name="MaxConcurrency">
/// CloudFormation's read APIs have low request-rate limits per account; a few concurrent calls plus
/// adaptive retries in the SDK is faster overall than a wide fan-out that gets throttled.
/// </param>
/// <param name="Progress">Called with (stacks read, stacks to read) as uncached stacks are read.</param>
/// <param name="CacheFactory">Opens the cache for (account, region). Null disables caching.</param>
public sealed record DiscoveryOptions(
    IReadOnlyList<string> StackFilters,
    int MaxConcurrency = 3,
    Action<int, int>? Progress = null,
    Func<string, string, IDiscoveryCache?>? CacheFactory = null);

/// <summary>
/// Finds Proxylity resources through CloudFormation. One ListStacks call yields every stack's change time;
/// stacks unchanged since the last run come from the cache. Others are screened with the cheap
/// ListStackResources call, and templates are fetched only for stacks that contain Proxylity resources.
/// </summary>
public sealed class DiscoveryService(IStackSource source, DiscoveryOptions options)
{
    private sealed record Outcome(StackRef? Stack, StackModel? Model, Note? Note, bool FromCache);

    public async Task<DeploymentSnapshot> DiscoverAsync(CancellationToken cancellationToken)
    {
        var all = await source.ListStacksAsync(cancellationToken).ConfigureAwait(false);
        var stacks = all.Where(s => Matches(s, options.StackFilters)).ToList();

        IDiscoveryCache? cache = null;
        if (options.CacheFactory is not null && all.Count > 0)
        {
            var (region, account) = ParseStackArn(all[0].Id, source.Region);
            cache = options.CacheFactory(account, region);
        }

        var outcomes = new List<Outcome>();
        var toRead = new List<StackSummary>();
        foreach (var summary in stacks)
        {
            if (Cacheable(summary) && cache?.TryGet(summary.Id, summary.LastChanged!.Value, summary.Status) is { } hit)
            {
                outcomes.Add(new Outcome(hit.Stack, hit.Model, null, true));
            }
            else
            {
                toRead.Add(summary);
            }
        }

        var gate = new SemaphoreSlim(Math.Max(1, options.MaxConcurrency));
        var done = 0;
        if (toRead.Count > 0)
        {
            options.Progress?.Invoke(0, toRead.Count);
        }

        var tasks = toRead.Select(async summary =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await InspectAsync(summary, cache, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
                options.Progress?.Invoke(Interlocked.Increment(ref done), toRead.Count);
            }
        }).ToList();

        outcomes.AddRange(await Task.WhenAll(tasks).ConfigureAwait(false));

        if (cache is not null)
        {
            cache.Retain(all.Select(s => s.Id).ToHashSet(StringComparer.Ordinal));
            cache.Save();
        }

        var stackRefs = outcomes.Where(r => r.Stack is not null).Select(r => r.Stack!).OrderBy(s => s.Name, StringComparer.Ordinal).ToList();
        var models = outcomes.Where(r => r.Model is not null).Select(r => r.Model!).ToList();
        var notes = outcomes.Where(r => r.Note is not null).Select(r => r.Note!)
            .Concat(models.SelectMany(m => m.Notes))
            .ToList();

        if (options.StackFilters.Count > 0 && stacks.Count == 0)
        {
            notes.Add(new Note("warning", "No stacks matched the --stack filter.", null));
        }

        var attachments = models.SelectMany(m => m.Attachments).ToList();
        var listeners = models.SelectMany(m => m.Listeners)
            .Select(l => AttachmentMerger.Apply(l, attachments))
            .OrderBy(l => l.Stack.Name, StringComparer.Ordinal).ThenBy(l => l.LogicalId, StringComparer.Ordinal).ToList();
        attachments = AttachmentMerger.MarkMatched(attachments, listeners);

        return new DeploymentSnapshot(
            [source.Region],
            stackRefs,
            listeners,
            attachments,
            models.SelectMany(m => m.PacketSources).ToList(),
            notes,
            outcomes.Count(o => o.FromCache && o.Stack is not null));
    }

    private async Task<Outcome> InspectAsync(StackSummary summary, IDiscoveryCache? cache, CancellationToken ct)
    {
        try
        {
            var resources = await source.ListResourcesAsync(summary.Id, ct).ConfigureAwait(false);
            if (!resources.Any(r => StackModelBuilder.IsProxylityType(r.Type)))
            {
                Remember(cache, summary, null, null);
                return new Outcome(null, null, null, false);
            }

            var (region, account) = ParseStackArn(summary.Id, source.Region);
            var stack = new StackRef(summary.Name, summary.Id, region, account, summary.Status);

            var details = await source.DescribeAsync(summary.Id, ct).ConfigureAwait(false);
            var body = await source.GetProcessedTemplateAsync(summary.Id, ct).ConfigureAwait(false);
            var template = TemplateParser.Parse(body);

            // Outputs of nested stacks are needed to resolve Fn::GetAtt Nested.Outputs.Name.
            var nested = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
            foreach (var child in resources.Where(r => r.Type == "AWS::CloudFormation::Stack" && !string.IsNullOrEmpty(r.PhysicalId)))
            {
                try
                {
                    nested[child.PhysicalId!] = (await source.DescribeAsync(child.PhysicalId!, ct).ConfigureAwait(false)).Outputs;
                }
                catch (AccessDeniedException)
                {
                    // Left unresolved; the affected values will say why.
                }
            }

            var data = new StackData(
                stack,
                resources.Select(r => new DeployedResource(r.LogicalId, r.Type, r.PhysicalId, r.Status)).ToList(),
                details.Parameters,
                template,
                nested);
            var model = StackModelBuilder.Build(data);
            Remember(cache, summary, stack, model);
            return new Outcome(stack, model, null, false);
        }
        catch (AccessDeniedException e)
        {
            return new Outcome(null, null, new Note("warning", $"Could not read stack '{summary.Name}': access denied for {e.Action}.", summary.Name), false);
        }
        catch (ThrottledException e)
        {
            return new Outcome(null, null, new Note("warning", $"Skipped stack '{summary.Name}': AWS throttled {e.Action} after retries. Re-run, or use --stack to narrow the search.", summary.Name), false);
        }
        catch (TemplateParseException e)
        {
            return new Outcome(null, null, new Note("warning", $"Could not read the template of stack '{summary.Name}': {e.Message}", summary.Name), false);
        }
    }

    /// <summary>Only successful reads of settled stacks are cached; failures are retried next time.</summary>
    private static void Remember(IDiscoveryCache? cache, StackSummary summary, StackRef? stack, StackModel? model)
    {
        if (cache is not null && Cacheable(summary))
        {
            cache.Put(new CacheEntry(summary.Id, summary.LastChanged!.Value, summary.Status, model is not null, stack, model));
        }
    }

    private static bool Cacheable(StackSummary s) =>
        s.LastChanged is not null && !s.Status.EndsWith("_IN_PROGRESS", StringComparison.Ordinal);

    private static bool Matches(StackSummary stack, IReadOnlyList<string> filters) =>
        filters.Count == 0
        || filters.Any(f => string.Equals(f, stack.Name, StringComparison.Ordinal) || string.Equals(f, stack.Id, StringComparison.Ordinal));

    /// <summary>Stack ARNs carry the region and account: arn:aws:cloudformation:REGION:ACCOUNT:stack/NAME/ID.</summary>
    internal static (string Region, string Account) ParseStackArn(string stackId, string fallbackRegion)
    {
        var arn = ArnParser.Parse(stackId);
        return arn is null ? (fallbackRegion, string.Empty) : (arn.Region, arn.AccountId);
    }
}
