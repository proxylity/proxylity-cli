using System.Text.Json;
using System.Text.Json.Serialization;
using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli.Core.Discovery;

/// <summary>
/// What is known about one stack as of a given change time. Holds the already-built, secret-free model,
/// never the raw template (processed templates can contain literal credentials).
/// </summary>
public sealed record CacheEntry(
    string StackId,
    DateTimeOffset LastChanged,
    string Status,
    bool HasProxylityResources,
    StackRef? Stack,
    StackModel? Model);

public sealed record CacheFile(
    int Format,
    string ToolVersion,
    string AccountId,
    string Region,
    Dictionary<string, CacheEntry> Stacks);

public interface IDiscoveryCache
{
    /// <summary>The cached entry if it was recorded for exactly this change time and status.</summary>
    CacheEntry? TryGet(string stackId, DateTimeOffset lastChanged, string status);

    void Put(CacheEntry entry);

    /// <summary>Drops entries for stacks that no longer exist.</summary>
    void Retain(IReadOnlyCollection<string> liveStackIds);

    void Save();
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CacheFile))]
internal sealed partial class CacheJsonContext : JsonSerializerContext;

/// <summary>
/// A per-account, per-region JSON file in the user's cache directory. Any problem reading it (missing,
/// corrupt, other format or tool version) results in an empty cache; problems writing it are ignored.
/// </summary>
public sealed class FileDiscoveryCache : IDiscoveryCache
{
    /// <summary>Bump when the cache file layout changes.</summary>
    public const int Format = 3;

    private readonly Lock _lock = new();
    private readonly string _path;
    private readonly CacheFile _file;
    private readonly bool _readEnabled;
    private bool _dirty;

    private FileDiscoveryCache(string path, CacheFile file, bool readEnabled)
    {
        _path = path;
        _file = file;
        _readEnabled = readEnabled;
    }

    /// <param name="readEnabled">False to ignore existing entries (a refresh) while still writing new ones.</param>
    public static FileDiscoveryCache Open(string directory, string accountId, string region, string toolVersion, bool readEnabled = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        var safeAccount = string.IsNullOrEmpty(accountId) ? "unknown" : SafeName(accountId);
        var path = Path.Combine(directory, $"stacks-{safeAccount}-{SafeName(region)}.json");
        var empty = new CacheFile(Format, toolVersion, accountId, region, new Dictionary<string, CacheEntry>(StringComparer.Ordinal));
        var loaded = TryLoad(path);
        var usable = loaded is not null
            && loaded.Format == Format
            && string.Equals(loaded.ToolVersion, toolVersion, StringComparison.Ordinal)
            && string.Equals(loaded.Region, region, StringComparison.Ordinal);
        var file = usable ? loaded! with { Stacks = new Dictionary<string, CacheEntry>(loaded!.Stacks, StringComparer.Ordinal) } : empty;
        return new FileDiscoveryCache(path, file, readEnabled);
    }

    /// <summary>The platform's per-user cache directory, or PROXYLITY_CACHE_DIR when set.</summary>
    public static string DefaultDirectory()
    {
        var overridden = Environment.GetEnvironmentVariable("PROXYLITY_CACHE_DIR");
        if (!string.IsNullOrWhiteSpace(overridden))
        {
            return overridden;
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "proxylity", "cache");
        }

        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(home, "Library", "Caches", "proxylity");
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        return Path.Combine(string.IsNullOrWhiteSpace(xdg) ? Path.Combine(home, ".cache") : xdg, "proxylity");
    }

    public string FilePath => _path;

    public CacheEntry? TryGet(string stackId, DateTimeOffset lastChanged, string status)
    {
        if (!_readEnabled)
        {
            return null;
        }

        lock (_lock)
        {
            return _file.Stacks.TryGetValue(stackId, out var entry)
                && entry.LastChanged == lastChanged
                && string.Equals(entry.Status, status, StringComparison.Ordinal)
                ? entry
                : null;
        }
    }

    public void Put(CacheEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        lock (_lock)
        {
            _file.Stacks[entry.StackId] = entry;
            _dirty = true;
        }
    }

    public void Retain(IReadOnlyCollection<string> liveStackIds)
    {
        ArgumentNullException.ThrowIfNull(liveStackIds);
        var live = liveStackIds as ISet<string> ?? new HashSet<string>(liveStackIds, StringComparer.Ordinal);
        lock (_lock)
        {
            foreach (var id in _file.Stacks.Keys.Where(k => !live.Contains(k)).ToList())
            {
                _file.Stacks.Remove(id);
                _dirty = true;
            }
        }
    }

    public void Save()
    {
        string json;
        lock (_lock)
        {
            if (!_dirty)
            {
                return;
            }

            json = JsonSerializer.Serialize(_file, CacheJsonContext.Default.CacheFile);
            _dirty = false;
        }

        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directory);
            }
            else
            {
                Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            // Write to a temporary file and rename, so readers never see a partial file.
            var temp = _path + "." + Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".tmp";
            File.WriteAllText(temp, json);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.Move(temp, _path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The cache is an optimization; failing to write it must not fail the command.
        }
    }

    private static CacheFile? TryLoad(string path)
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize(File.ReadAllText(path), CacheJsonContext.Default.CacheFile) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;
        }
    }

    private static string SafeName(string value) =>
        new(value.Select(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' ? ch : '_').ToArray());
}
