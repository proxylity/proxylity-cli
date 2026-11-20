using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Proxylity.Cli.Core.Observation;

/// <summary>
/// The parts of the account configuration object (s3://proxylity-config-REGION/ACCOUNT/customer-config.json) that
/// diagnostics compare against. Values are held in memory only, never serialized, cached or displayed: comparisons
/// produce match/no-match results. The API key is reduced to a fingerprint as soon as it is read.
/// </summary>
public sealed class AccountConfig
{
    private readonly Dictionary<string, (string? ServiceToken, string? ServiceRole)> _regions;

    private AccountConfig(string? externalId, string? keyFingerprint, Dictionary<string, (string?, string?)> regions)
    {
        ExternalId = externalId;
        KeyFingerprint = keyFingerprint;
        _regions = regions;
    }

    internal string? ExternalId { get; }

    internal string? KeyFingerprint { get; }

    internal string? ServiceRole(string region) => _regions.TryGetValue(region, out var r) ? r.ServiceRole : null;

    internal string? ServiceTokenFingerprint(string region) =>
        _regions.TryGetValue(region, out var r) && r.ServiceToken is { } t ? Fingerprint.Of(t) : null;

    public override string ToString() => "AccountConfig(redacted)";

    /// <summary>
    /// Parses the documented shape: regional settings keyed by AWS Region name (ServiceToken, ServiceRole) and
    /// account settings under "Account" (ExternalId, ApiKey). Unknown content is ignored.
    /// </summary>
    public static AccountConfig Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string? externalId = null;
        string? key = null;
        var regions = new Dictionary<string, (string?, string?)>(StringComparer.Ordinal);
        if (root.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in root.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                if (p.Name == "Account")
                {
                    externalId = Text(p.Value, "ExternalId");
                    key = Text(p.Value, "ApiKey") is { } k ? Fingerprint.Of(k) : null;
                }
                else
                {
                    regions[p.Name] = (Text(p.Value, "ServiceToken"), Text(p.Value, "ServiceRole"));
                }
            }
        }

        return new AccountConfig(externalId, key, regions);
    }

    private static string? Text(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
}

/// <summary>A short one-way fingerprint for comparing credential-like values without keeping them.</summary>
public static class Fingerprint
{
    public static string Of(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];
    }
}
