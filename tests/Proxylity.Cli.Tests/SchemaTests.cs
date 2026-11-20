using System.Text.Json;
using Proxylity.Cli.Core.Observation;

namespace Proxylity.Cli.Tests;

/// <summary>
/// Validates real command output against docs/schema/proxylity-output.schema.json with a small subset validator
/// (type, required, properties, additionalProperties as a schema, items, enum, const, and local $ref/oneOf).
/// </summary>
public class SchemaTests
{
    private const string Listener = "demo-Listener-1a2b3c4d";

    private static readonly JsonElement Schema = LoadSchema();

    private static JsonElement LoadSchema()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Proxylity.Cli.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        var text = File.ReadAllText(Path.Combine(dir.FullName, "docs", "schema", "proxylity-output.schema.json"));
        return JsonElement.Parse(text);
    }

    private static FakeObservabilitySource Observations()
    {
        var obs = new FakeObservabilitySource();
        obs.Proxylity(Listener, "IngressPackets", 1000);
        obs.Proxylity(Listener, "FilteredPackets", 2);
        obs.Proxylity("packet-handler", "IngressPackets", 1000);
        obs.Proxylity("packet-handler", "Errors", 4);
        obs.Lambda("Invocations", 100);
        obs.Lambda("Errors", 3);
        var t = DateTimeOffset.UtcNow;
        obs.Logs["/example/dest"] = Signal<LogQueryResult>.Of(new LogQueryResult(
            [new LogEvent(t, "[x3]: ERROR: Failed to proxy 10 message(s) to Lambda: Rate exceeded.")], false));
        obs.Logs["/aws/lambda/packet-handler"] = Signal<LogQueryResult>.Of(new LogQueryResult(
            [new LogEvent(t, "ERROR Unhandled exception")], false));
        return obs;
    }

    private static string Run(params string[] args)
    {
        var stdout = new StringWriter();
        var app = new CliApp(stdout, new StringWriter(), _ => new FakeStackSource(), colorAllowed: false, observabilityFactory: _ => Observations());
        var code = app.RunAsync(args, CancellationToken.None).GetAwaiter().GetResult();
        Assert.True(code is 0 or 1, $"exit code {code}");
        return stdout.ToString();
    }

    [Theory]
    [InlineData("list")]
    [InlineData("inspect")]
    [InlineData("diagnose")]
    [InlineData("metrics")]
    [InlineData("logs")]
    [InlineData("check-access")]
    public void Real_output_matches_the_published_schema(string command)
    {
        var output = Run(command, "-o", "json");
        using var doc = JsonDocument.Parse(output);
        var errors = new List<string>();
        Validate(doc.RootElement, Schema, "$", errors);
        Assert.Empty(errors);
        Assert.Equal(command, doc.RootElement.GetProperty("command").GetString());
    }

    [Fact]
    public void Diagnose_output_includes_findings_with_evidence_so_those_shapes_are_checked()
    {
        using var doc = JsonDocument.Parse(Run("diagnose", "-o", "json"));
        var findings = doc.RootElement.GetProperty("result").GetProperty("report").GetProperty("listeners")[0]
            .GetProperty("destinations")[0].GetProperty("findings");
        Assert.True(findings.GetArrayLength() > 0);
        Assert.Contains(findings.EnumerateArray(), f => f.GetProperty("evidence").GetArrayLength() > 0);
    }

    [Fact]
    public void A_missing_required_field_is_reported()
    {
        var output = Run("check-access", "-o", "json").Replace("\"action\"", "\"actionX\"", StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(output);
        var errors = new List<string>();
        Validate(doc.RootElement, Schema, "$", errors);
        Assert.NotEmpty(errors);
    }

    [Fact]
    public void A_wrong_envelope_version_is_reported()
    {
        var output = Run("list", "-o", "json").Replace("\"schemaVersion\": \"1\"", "\"schemaVersion\": \"2\"", StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(output);
        var errors = new List<string>();
        Validate(doc.RootElement, Schema, "$", errors);
        Assert.NotEmpty(errors);
    }

    private static void Validate(JsonElement value, JsonElement schema, string path, List<string> errors)
    {
        if (schema.TryGetProperty("$ref", out var reference))
        {
            var name = reference.GetString()!["#/$defs/".Length..];
            Validate(value, Schema.GetProperty("$defs").GetProperty(name), path, errors);
            return;
        }

        if (schema.TryGetProperty("oneOf", out var alternatives))
        {
            var matches = alternatives.EnumerateArray().Count(alt =>
            {
                var inner = new List<string>();
                Validate(value, alt, path, inner);
                return inner.Count == 0;
            });
            if (matches != 1)
            {
                errors.Add($"{path}: matches {matches} of the oneOf alternatives, expected 1");
            }
        }

        if (schema.TryGetProperty("const", out var constant) && !JsonEquals(value, constant))
        {
            errors.Add($"{path}: expected {constant.GetRawText()}");
        }

        if (schema.TryGetProperty("enum", out var allowed) && !allowed.EnumerateArray().Any(a => JsonEquals(value, a)))
        {
            errors.Add($"{path}: {value.GetRawText()} is not one of {allowed.GetRawText()}");
        }

        if (schema.TryGetProperty("type", out var type))
        {
            var types = type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Select(t => t.GetString()!).ToList() : [type.GetString()!];
            if (!types.Any(t => IsType(value, t)))
            {
                errors.Add($"{path}: expected {string.Join(" or ", types)} but found {value.ValueKind}");
                return;
            }
        }

        if (value.ValueKind == JsonValueKind.Object)
        {
            if (schema.TryGetProperty("required", out var required))
            {
                foreach (var name in required.EnumerateArray().Select(r => r.GetString()!).Where(n => !value.TryGetProperty(n, out _)))
                {
                    errors.Add($"{path}: missing required property '{name}'");
                }
            }

            var hasProperties = schema.TryGetProperty("properties", out var properties);
            var additional = schema.TryGetProperty("additionalProperties", out var extra) && extra.ValueKind == JsonValueKind.Object ? extra : (JsonElement?)null;
            foreach (var member in value.EnumerateObject())
            {
                if (hasProperties && properties.TryGetProperty(member.Name, out var memberSchema))
                {
                    Validate(member.Value, memberSchema, $"{path}.{member.Name}", errors);
                }
                else if (additional is { } rest)
                {
                    Validate(member.Value, rest, $"{path}.{member.Name}", errors);
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.Array && schema.TryGetProperty("items", out var items))
        {
            var index = 0;
            foreach (var element in value.EnumerateArray())
            {
                Validate(element, items, $"{path}[{index++}]", errors);
            }
        }
    }

    private static bool IsType(JsonElement value, string type) => type switch
    {
        "object" => value.ValueKind == JsonValueKind.Object,
        "array" => value.ValueKind == JsonValueKind.Array,
        "string" => value.ValueKind == JsonValueKind.String,
        "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
        "number" => value.ValueKind == JsonValueKind.Number,
        "null" => value.ValueKind == JsonValueKind.Null,
        _ => throw new InvalidOperationException($"unsupported type '{type}' in the schema"),
    };

    private static bool JsonEquals(JsonElement a, JsonElement b) =>
        a.ValueKind == b.ValueKind && (a.ValueKind == JsonValueKind.String ? a.GetString() == b.GetString() : a.GetRawText() == b.GetRawText());
}
