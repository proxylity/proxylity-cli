using System.Text.Json;

namespace Proxylity.Cli.Core.Observation;

/// <summary>
/// Reads an IAM trust policy (the role's AssumeRolePolicyDocument) to answer two questions: can an AWS principal
/// assume the role, and does every statement that allows it require an external ID. Principals are deliberately
/// not reported: only the structure matters for diagnosis.
/// </summary>
public static class TrustPolicy
{
    public static RoleTrust Analyze(string policyJson)
    {
        ArgumentNullException.ThrowIfNull(policyJson);
        using var doc = JsonDocument.Parse(policyJson);
        var statements = doc.RootElement.TryGetProperty("Statement", out var s) ? s : default;
        var items = statements.ValueKind switch
        {
            JsonValueKind.Array => statements.EnumerateArray().ToList(),
            JsonValueKind.Object => [statements],
            _ => [],
        };

        var allowing = 0;
        var withExternalId = 0;
        var principals = new List<string>();
        var externalIds = new List<string>();
        foreach (var statement in items)
        {
            if (!IsAllow(statement) || !AllowsAssumeRole(statement) || !HasAwsPrincipal(statement))
            {
                continue;
            }

            allowing++;
            principals.AddRange(AwsPrincipals(statement));
            var ids = ExternalIdValues(statement).ToList();
            if (ids.Count > 0)
            {
                withExternalId++;
                externalIds.AddRange(ids);
            }
        }

        return new RoleTrust(allowing > 0, allowing > 0 && withExternalId == allowing, principals, externalIds);
    }

    private static IEnumerable<string> AwsPrincipals(JsonElement statement) =>
        statement.TryGetProperty("Principal", out var p) && p.ValueKind == JsonValueKind.Object && p.TryGetProperty("AWS", out var aws)
            ? Strings(aws)
            : [];

    /// <summary>Values of any condition operator on sts:ExternalId (StringEquals, StringLike, ...).</summary>
    private static IEnumerable<string> ExternalIdValues(JsonElement statement)
    {
        if (!statement.TryGetProperty("Condition", out var condition) || condition.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

        foreach (var op in condition.EnumerateObject().Where(o => o.Value.ValueKind == JsonValueKind.Object))
        {
            foreach (var key in op.Value.EnumerateObject().Where(k => string.Equals(k.Name, "sts:ExternalId", StringComparison.OrdinalIgnoreCase)))
            {
                foreach (var v in Strings(key.Value))
                {
                    yield return v;
                }
            }
        }
    }

    private static bool IsAllow(JsonElement statement) =>
        statement.TryGetProperty("Effect", out var e) && e.ValueKind == JsonValueKind.String
        && string.Equals(e.GetString(), "Allow", StringComparison.OrdinalIgnoreCase);

    private static bool AllowsAssumeRole(JsonElement statement) =>
        statement.TryGetProperty("Action", out var a)
        && Strings(a).Any(x => x is "*" or "sts:*" || string.Equals(x, "sts:AssumeRole", StringComparison.OrdinalIgnoreCase));

    private static bool HasAwsPrincipal(JsonElement statement)
    {
        if (!statement.TryGetProperty("Principal", out var p))
        {
            return false;
        }

        if (p.ValueKind == JsonValueKind.String)
        {
            return p.GetString() == "*";
        }

        return p.ValueKind == JsonValueKind.Object && p.TryGetProperty("AWS", out var aws) && Strings(aws).Any();
    }

    private static IEnumerable<string> Strings(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => [e.GetString() ?? string.Empty],
        JsonValueKind.Array => e.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? string.Empty),
        _ => [],
    };
}
