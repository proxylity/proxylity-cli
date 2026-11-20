using Proxylity.Cli.Core.Model;
using Proxylity.Cli.Core.Templates;

namespace Proxylity.Cli.Tests;

public class StackModelBuilderTests
{
    private const string Template = """
        Parameters:
          RoleArnParam:
            Type: String
          ApiKeyParam:
            Type: String
            NoEcho: true
        Resources:
          PacketHandler:
            Type: AWS::Lambda::Function
          Jobs:
            Type: AWS::SQS::Queue
          Listener:
            Type: Custom::ProxylityUdpGatewayListener
            Properties:
              ServiceToken: arn:aws:lambda:us-west-2:123456789012:function:handler-token
              ApiKey: literal-secret-value-xyz
              Protocols: [udp]
              MetricsEnabled: true
              LogGroupName: /example/listener
              Role:
                Arn: !Ref RoleArnParam
              ClientRestrictions:
                Networks: ["203.0.113.0/24", "198.51.100.0/24"]
              Destinations:
                - existing-shared-destination
                - DestinationArn: !GetAtt PacketHandler.Arn
                  MetricsEnabled: true
                  Role:
                    Arn: !Ref RoleArnParam
                - Name: regional
                  LogGroupName: /example/dest
                  FilterExpression: "[0] == 1"
                  Role:
                    RoleArn: !Ref RoleArnParam
                  DestinationArn:
                    us-west-2: !GetAtt Jobs.Arn
                    "*": arn:aws:sqs:eu-west-1:123456789012:fallback
          ListenerWithListForm:
            Type: Custom::ProxylityUdpGatewayListener
            Properties:
              Protocols: [dtls]
              Psks: { id1: c2VjcmV0 }
              ClientRestrictions:
                - Networks: ["203.0.113.0/24"]
              Destinations: []
          Attach:
            Type: Custom::ProxylityUdpGatewayDestinationArn
            Properties:
              Destination: regional
              IngressRegionKey: eu-central-1
              Arn: arn:aws:firehose:eu-central-1:123456789012:deliverystream/archive
          Source:
            Type: Custom::ProxylityUdpGatewayPacketSource
            Properties:
              ListenerName: !Ref Listener
              SnsTopicSource:
                TopicArn: arn:aws:sns:us-west-2:123456789012:topic
                Role: arn:aws:iam::123456789012:role/example
        """;

    private static StackModel Build()
    {
        var stack = new StackRef("demo", "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000", "us-west-2", "123456789012", "UPDATE_COMPLETE");
        var resources = new List<DeployedResource>
        {
            new("PacketHandler", "AWS::Lambda::Function", "packet-handler", "CREATE_COMPLETE"),
            new("Jobs", "AWS::SQS::Queue", "https://sqs.us-west-2.amazonaws.com/123456789012/jobs", "CREATE_COMPLETE"),
            new("Listener", "Custom::ProxylityUdpGatewayListener", "demo-Listener-1a2b3c4d", "CREATE_COMPLETE"),
            new("ListenerWithListForm", "Custom::ProxylityUdpGatewayListener", "demo-ListenerWithListForm-aabbccdd", "CREATE_COMPLETE"),
            new("Attach", "Custom::ProxylityUdpGatewayDestinationArn", "k3j2h1g0f9e8d7c6b5a4", "CREATE_COMPLETE"),
            new("Source", "Custom::ProxylityUdpGatewayPacketSource", "demo-Listener-1a2b3c4d|0123456789ab", "CREATE_COMPLETE"),
        };
        var parameters = new Dictionary<string, string>
        {
            ["RoleArnParam"] = "arn:aws:iam::123456789012:role/example-destination-role",
            ["ApiKeyParam"] = "****",
        };
        return StackModelBuilder.Build(new StackData(stack, resources, parameters, TemplateParser.Parse(Template)));
    }

    [Fact]
    public void Listener_name_is_the_physical_id_and_basic_settings_are_read()
    {
        var model = Build();
        var listener = model.Listeners.Single(l => l.LogicalId == "Listener");

        Assert.Equal("demo-Listener-1a2b3c4d", listener.Name);
        Assert.False(listener.NameIsPlaceholder);
        Assert.Equal("udp", listener.Protocol.Value);
        Assert.True(listener.MetricsEnabled.Value);
        Assert.Equal("/example/listener", listener.LogGroupName.Value);
        Assert.Equal("arn:aws:iam::123456789012:role/example-destination-role", listener.Role!.Arn.Value);
        Assert.Equal(ClientRestrictionsForm.Object, listener.ClientRestrictions.Form);
        Assert.Equal(2, listener.ClientRestrictions.NetworkCount);
    }

    [Fact]
    public void Destinations_distinguish_references_inline_entries_and_derived_names()
    {
        var destinations = Build().Listeners.Single(l => l.LogicalId == "Listener").Destinations;

        Assert.Equal(3, destinations.Count);

        Assert.True(destinations[0].IsReferenceByName);
        Assert.Equal("existing-shared-destination", destinations[0].Name);

        // The first inline (object) entry is index 0; reference entries are not counted.
        Assert.Equal("dstn-demo-Listener-0", destinations[1].Name);
        Assert.Equal(NameSource.Derived, destinations[1].NameSource);
        var lambda = Assert.Single(destinations[1].Targets);
        Assert.Equal(DestinationService.Lambda, lambda.Service);
        Assert.Equal("packet-handler", lambda.ResourceName);
        Assert.Equal("us-west-2", lambda.ArnRegion);

        Assert.Equal("regional", destinations[2].Name);
        Assert.Equal(NameSource.Declared, destinations[2].NameSource);
        Assert.True(destinations[2].HasFilterExpression);
        Assert.Equal(2, destinations[2].Targets.Count);
        Assert.All(destinations[2].Targets, t => Assert.Equal(DestinationService.Sqs, t.Service));
        Assert.Contains(destinations[2].Targets, t => t.IngressRegionKey == "*" && t.ResourceName == "fallback");
    }

    [Fact]
    public void Role_arn_key_is_flagged_not_honored()
    {
        var regional = Build().Listeners.Single(l => l.LogicalId == "Listener").Destinations[2];

        Assert.True(regional.Role!.UsesRoleArnKey);
        Assert.Equal(ValueState.Absent, regional.Role.Arn.State);
    }

    [Fact]
    public void List_form_client_restrictions_are_reported_as_a_list()
    {
        var listener = Build().Listeners.Single(l => l.LogicalId == "ListenerWithListForm");

        Assert.Equal(ClientRestrictionsForm.List, listener.ClientRestrictions.Form);
    }

    [Fact]
    public void Attachments_and_packet_sources_are_read()
    {
        var model = Build();

        var attachment = Assert.Single(model.Attachments);
        Assert.Equal("regional", attachment.Destination.Value);
        Assert.Equal("eu-central-1", attachment.IngressRegionKey.Value);
        Assert.Equal(DestinationService.Firehose, attachment.Service);

        var source = Assert.Single(model.PacketSources);
        Assert.Equal("demo-Listener-1a2b3c4d", source.ListenerName.Value);
        Assert.Equal("demo-Listener-1a2b3c4d|0123456789ab", source.SourceId);
    }

    [Fact]
    public void Secrets_never_reach_the_model()
    {
        var model = Build();
        var text = string.Join('\n', model.Listeners.Select(l => l.ToString()))
            + string.Join('\n', model.Attachments.Select(a => a.ToString()))
            + string.Join('\n', model.PacketSources.Select(s => s.ToString()));

        Assert.DoesNotContain("literal-secret-value-xyz", text, StringComparison.Ordinal);
        Assert.DoesNotContain("c2VjcmV0", text, StringComparison.Ordinal);
        Assert.DoesNotContain("handler-token", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Placeholder_physical_ids_are_not_treated_as_names()
    {
        var stack = new StackRef("demo", "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000", "us-west-2", "123456789012", "CREATE_FAILED");
        var resources = new List<DeployedResource> { new("Listener", "Custom::ProxylityUdpGatewayListener", "2025/01/01/[$LATEST]abcdef", "CREATE_FAILED") };

        var model = StackModelBuilder.Build(new StackData(stack, resources, new Dictionary<string, string>(),
            TemplateParser.Parse("Resources:\n  Listener:\n    Type: Custom::ProxylityUdpGatewayListener\n    Properties:\n      Protocols: [udp]\n")));

        var listener = Assert.Single(model.Listeners);
        Assert.Null(listener.Name);
        Assert.True(listener.NameIsPlaceholder);
    }

    [Theory]
    [InlineData("arn:aws:lambda:us-west-2:123456789012:function:f:live", DestinationService.Lambda, "f")]
    [InlineData("arn:aws:lambda:us-west-2:123456789012:microvm-image:img:2", DestinationService.LambdaMicrovm, "img")]
    [InlineData("arn:aws:states:us-west-2:123456789012:stateMachine:flow", DestinationService.StepFunctions, "flow")]
    [InlineData("arn:aws:events:us-west-2:123456789012:event-bus/default", DestinationService.EventBridge, "default")]
    [InlineData("arn:aws:sqs:us-west-2:123456789012:q.fifo", DestinationService.Sqs, "q.fifo")]
    [InlineData("arn:aws:dynamodb:us-west-2:123456789012:table/t", DestinationService.DynamoDb, "t")]
    [InlineData("arn:aws:s3:::bucket/prefix/", DestinationService.S3, "bucket")]
    [InlineData("arn:aws:firehose:us-west-2:123456789012:deliverystream/fh", DestinationService.Firehose, "fh")]
    [InlineData("arn:aws:logs:us-west-2:123456789012:deliverystream/fh", DestinationService.Firehose, "fh")]
    [InlineData("arn:aws:kinesis:us-west-2:123456789012:stream/s", DestinationService.Kinesis, "s")]
    [InlineData("arn:aws:logs:us-west-2:123456789012:log-group:/g:*", DestinationService.CloudWatchLogs, "/g")]
    [InlineData("arn:aws:execute-api:us-west-2:123456789012:abc123/prod/POST/hook", DestinationService.ApiGateway, "abc123")]
    [InlineData("arn:aws:iot:us-west-2:123456789012:topic/a/b", DestinationService.IotData, "a/b")]
    [InlineData("arn:aws:geo:us-west-2:123456789012:tracker/t", DestinationService.LocationTracker, "t")]
    public void Arns_are_classified_by_service_and_resource(string arn, DestinationService expected, string name)
    {
        var parsed = ArnParser.Parse(arn)!;
        var service = ArnParser.ServiceOf(parsed);

        Assert.Equal(expected, service);
        Assert.Equal(name, ArnParser.ResourceNameOf(parsed, service));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-an-arn")]
    [InlineData("arn:aws:lambda")]
    public void Malformed_arns_do_not_parse(string arn)
    {
        Assert.Null(ArnParser.Parse(arn));
    }

    [Fact]
    public void Attachments_are_merged_into_the_named_destination()
    {
        var model = Build();
        var listener = AttachmentMerger.Apply(model.Listeners.Single(l => l.LogicalId == "Listener"), model.Attachments);
        var regional = listener.Destinations.Single(d => d.Name == "regional");

        var attached = Assert.Single(regional.Targets, t => t.AttachedFrom is not null);
        Assert.Equal("eu-central-1", attached.IngressRegionKey);
        Assert.Equal(DestinationService.Firehose, attached.Service);
        Assert.Equal("demo/Attach", attached.AttachedFrom);
        Assert.True(Assert.Single(AttachmentMerger.MarkMatched(model.Attachments, [listener])).Matched);
    }

    [Fact]
    public void Nested_stack_outputs_microvm_images_and_trackers_resolve()
    {
        var stack = new StackRef("demo", "arn:aws:cloudformation:us-west-2:123456789012:stack/demo/0000", "us-west-2", "123456789012", "CREATE_COMPLETE");
        const string nestedId = "arn:aws:cloudformation:us-west-2:123456789012:stack/demo-Fn-ABC/1111";
        var resources = new List<DeployedResource>
        {
            new("Nested", "AWS::CloudFormation::Stack", nestedId, "CREATE_COMPLETE"),
            new("Image", "AWS::Lambda::MicrovmImage", "arn:aws:lambda:us-west-2:123456789012:microvm-image:img", "CREATE_COMPLETE"),
            new("Tracker", "AWS::Location::Tracker", "my-tracker", "CREATE_COMPLETE"),
            new("Listener", "Custom::ProxylityUdpGatewayListener", "demo-Listener-00000000", "CREATE_COMPLETE"),
        };
        const string template = """
            Resources:
              Listener:
                Type: Custom::ProxylityUdpGatewayListener
                Properties:
                  Protocols: [udp]
                  Destinations:
                    - DestinationArn: !GetAtt Nested.Outputs.FunctionArn
                    - DestinationArn: !GetAtt Image.ImageArn
                    - DestinationArn: !GetAtt Tracker.Arn
            """;
        var nested = new Dictionary<string, IReadOnlyDictionary<string, string>>
        {
            [nestedId] = new Dictionary<string, string> { ["FunctionArn"] = "arn:aws:lambda:us-west-2:123456789012:function:nested-fn" },
        };

        var model = StackModelBuilder.Build(new StackData(stack, resources, new Dictionary<string, string>(), TemplateParser.Parse(template), nested));
        var targets = model.Listeners.Single().Destinations.Select(d => d.Targets.Single()).ToList();

        Assert.Equal("nested-fn", targets[0].ResourceName);
        Assert.Equal(DestinationService.LambdaMicrovm, targets[1].Service);
        Assert.Equal("arn:aws:geo:us-west-2:123456789012:tracker/my-tracker", targets[2].Arn.Value);
        Assert.Equal(DestinationService.LocationTracker, targets[2].Service);
    }
}