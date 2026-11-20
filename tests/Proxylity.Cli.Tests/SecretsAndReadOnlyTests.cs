using Proxylity.Cli.Core.Discovery;
using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Observation;
using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Tests;

public class SecretsAndReadOnlyTests
{
    // Each literal is unique so a leak of any one of them is detectable.
    private const string Template = """
        Resources:
          Listener:
            Type: Custom::ProxylityUdpGatewayListener
            Properties:
              ApiKey: secret-literal-apikey
              Protocols: [wg]
              ServerSecret: secret-literal-serversecret
              UnknownPeerPreSharedKey: secret-literal-unknownpeer
              Psks: { id1: secret-literal-psk }
              WebRtcSignalingToken: secret-literal-token
              WebRtcSignalingUrl: https://secret-literal-signaling.example.invalid/ws
              Peers:
                - PublicKey: example-public-key
                  SharedSecret: secret-literal-peer
              Destinations:
                - DestinationArn: arn:aws:sqs:us-west-2:123456789012:jobs
                  Arguments:
                    SharedSecret: secret-literal-nested
        """;

    private static readonly string[] Secrets =
    [
        "secret-literal-apikey", "secret-literal-serversecret", "secret-literal-unknownpeer", "secret-literal-psk",
        "secret-literal-token", "secret-literal-signaling", "secret-literal-peer", "secret-literal-nested",
    ];

    [Fact]
    public void Every_never_print_property_is_absent_from_the_model_and_json_output()
    {
        var stack = new StackRef("demo", "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000", "us-west-2", "123456789012", "CREATE_COMPLETE");
        var resources = new List<DeployedResource> { new("Listener", "Custom::ProxylityUdpGatewayListener", "demo-Listener-1a2b3c4d", "CREATE_COMPLETE") };
        var model = StackModelBuilder.Build(new StackData(stack, resources, new Dictionary<string, string>(), TemplateParser.Parse(Template)));
        var snapshot = new DeploymentSnapshot(["us-west-2"], [stack], model.Listeners, model.Attachments, model.PacketSources, model.Notes);

        var json = JsonOutput.Serialize("inspect", "0.0.0", snapshot);

        foreach (var secret in Secrets)
        {
            Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, string.Join('\n', model.Listeners.Select(l => l.ToString())), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_source_interfaces_expose_only_read_operations()
    {
        string[] readPrefixes = ["Get", "List", "Describe", "Simulate"];
        var interfaces = new[] { typeof(IStackSource), typeof(IObservabilitySource) };

        foreach (var method in interfaces.SelectMany(i => i.GetMethods()).Where(m => !m.IsSpecialName))
        {
            Assert.True(readPrefixes.Any(p => method.Name.StartsWith(p, StringComparison.Ordinal)),
                $"{method.DeclaringType!.Name}.{method.Name} is not a read operation.");
        }
    }
}
