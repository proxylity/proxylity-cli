using Proxylity.Cli.Core.Discovery;

namespace Proxylity.Cli.Tests;

public sealed class CacheTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pxy-cache-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private (int Code, string Out) Run(FakeStackSource source, params string[] args)
    {
        var stdout = new StringWriter();
        var app = new CliApp(stdout, new StringWriter(), _ => source, colorAllowed: false, cacheDirectory: _dir);
        var code = app.RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
        return (code, stdout.ToString());
    }

    [Fact]
    public void Second_run_uses_the_cache_and_reads_nothing_from_aws_for_unchanged_stacks()
    {
        var source = new FakeStackSource();
        Run(source, "list");
        Assert.Equal(2, source.ResourceListings.Count);
        Assert.Single(source.TemplateFetches);

        var second = new FakeStackSource();
        var (code, output) = Run(second, "list");

        Assert.Equal(0, code);
        Assert.Empty(second.ResourceListings);
        Assert.Empty(second.TemplateFetches);
        Assert.Contains("demo-Listener-1a2b3c4d", output, StringComparison.Ordinal);
        Assert.Contains("1 unchanged, from cache", output, StringComparison.Ordinal);
    }

    [Fact]
    public void A_changed_stack_is_read_again()
    {
        Run(new FakeStackSource(), "list");

        var changed = new FakeStackSource { DemoLastChanged = FakeStackSource.BaseTime.AddMinutes(5) };
        Run(changed, "list");

        Assert.Equal([FakeStackSource.DemoStackId], changed.ResourceListings);
        Assert.Single(changed.TemplateFetches);
    }

    [Fact]
    public void Stacks_in_progress_are_neither_served_from_nor_stored_in_the_cache()
    {
        Run(new FakeStackSource { DemoStatus = "UPDATE_IN_PROGRESS" }, "list");

        var next = new FakeStackSource { DemoStatus = "UPDATE_IN_PROGRESS" };
        Run(next, "list");

        Assert.Contains(FakeStackSource.DemoStackId, next.ResourceListings);
    }

    [Fact]
    public void Refresh_rereads_everything_and_no_cache_writes_nothing()
    {
        Run(new FakeStackSource(), "list");

        var refreshed = new FakeStackSource();
        Run(refreshed, "list", "--refresh");
        Assert.Equal(2, refreshed.ResourceListings.Count);

        Directory.Delete(_dir, recursive: true);
        Run(new FakeStackSource(), "list", "--no-cache");
        Assert.False(Directory.Exists(_dir));
    }

    [Fact]
    public void Deleted_stacks_are_pruned()
    {
        Run(new FakeStackSource(), "list");

        Run(new FakeStackSource { IncludeOtherStack = false }, "list");
        var text = File.ReadAllText(Directory.GetFiles(_dir).Single());

        Assert.DoesNotContain(FakeStackSource.OtherStackId, text, StringComparison.Ordinal);
        Assert.Contains(FakeStackSource.DemoStackId, text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_corrupt_cache_file_is_ignored()
    {
        Run(new FakeStackSource(), "list");
        File.WriteAllText(Directory.GetFiles(_dir).Single(), "{ not json");

        var source = new FakeStackSource();
        var (code, output) = Run(source, "list");

        Assert.Equal(0, code);
        Assert.Equal(2, source.ResourceListings.Count);
        Assert.Contains("demo-Listener-1a2b3c4d", output, StringComparison.Ordinal);
    }

    [Fact]
    public void The_cache_never_contains_secrets_or_raw_templates()
    {
        Run(new FakeStackSource(), "list");
        var text = File.ReadAllText(Directory.GetFiles(_dir).Single());

        Assert.DoesNotContain("literal-secret-value-xyz", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ApiKey", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Custom::ProxylityUdpGatewayListener", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Cache_files_are_per_account_and_region_and_tolerate_a_version_change()
    {
        var cache = FileDiscoveryCache.Open(_dir, "123456789012", "us-west-2", "1.0.0");
        cache.Put(new CacheEntry("id", FakeStackSource.BaseTime, "CREATE_COMPLETE", false, null, null));
        cache.Save();

        Assert.EndsWith("stacks-123456789012-us-west-2.json", cache.FilePath, StringComparison.Ordinal);
        Assert.NotNull(FileDiscoveryCache.Open(_dir, "123456789012", "us-west-2", "1.0.0").TryGet("id", FakeStackSource.BaseTime, "CREATE_COMPLETE"));
        Assert.Null(FileDiscoveryCache.Open(_dir, "123456789012", "us-west-2", "1.0.1").TryGet("id", FakeStackSource.BaseTime, "CREATE_COMPLETE"));
    }
}
