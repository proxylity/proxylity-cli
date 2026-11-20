using System.Globalization;
using Proxylity.Cli.Core.Model;

namespace Proxylity.Cli.Core.Observation;

/// <summary>
/// Turns observations into findings. Rules are pure functions of configuration and collected signals.
/// Principles: absence of data is never reported as healthy; "Healthy" needs positive evidence; every finding
/// carries the evidence it is based on and a confidence; suggestions never change anything themselves.
/// </summary>
public static partial class Diagnoser
{
    /// <summary>
    /// The standard AWS authorization failure text: "... is not authorized to perform: service:Action [on resource: arn]".
    /// The action is constrained to IAM action syntax so it can be shown as a fact; the resource stays untrusted.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex AccessDenied = AccessDeniedPattern();

    [System.Text.RegularExpressions.GeneratedRegex(@"(?:assumed-role/(?<role>[\w+=,.@-]{1,64})/\S+\s+is\s+)?not authorized to perform: (?<action>[a-z0-9-]{2,40}:[A-Za-z0-9]{2,80})(?: on resource: (?<resource>arn:[^\s""]{1,300}?))?(?= because|[\s.)]|$)", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex AccessDeniedPattern();

    public static ObservationReport Diagnose(ObservationReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var roles = report.Listeners.Select(l => l.Role).Concat(report.Listeners.SelectMany(l => l.Destinations).Select(d => d.Role))
            .Where(r => r is not null).ToList();
        var notes = new List<Note>(report.Notes);
        if (roles.FirstOrDefault(r => r!.Trust.State == SignalState.NotAccessible) is { } trustDenied)
        {
            notes.Add(new("warning", $"Roles were not checked: the current identity is not allowed {trustDenied.Trust.DeniedAction ?? "iam:GetRole"}.", null));
        }
        else if (roles.FirstOrDefault(r => r!.Permissions.State == SignalState.NotAccessible) is { } simulateDenied)
        {
            notes.Add(new("warning", $"Role permissions were not checked: the current identity is not allowed {simulateDenied.Permissions.DeniedAction ?? "iam:SimulatePrincipalPolicy"}.", null));
        }

        if (report.Listeners.FirstOrDefault(l => l.Account is { Config: not SignalState.Available }) is { } unread)
        {
            var reason = unread.Account!.Config switch
            {
                SignalState.NotAccessible => "the current identity is not allowed s3:GetObject on it",
                SignalState.NotFound => "it was not found",
                _ => unread.Account.Detail ?? "it could not be read",
            };
            notes.Add(new("info",
                $"The Proxylity account configuration for {unread.Account.Region} was not read ({reason}). "
                + "External ID, service role, service token and API key were not compared; other checks are unaffected.", null));
        }

        var share = LogShare.Build(report);
        return report with { Listeners = report.Listeners.Select(l => DiagnoseListener(l, share)).ToList(), Notes = notes };
    }

    /// <summary>
    /// Listeners and destinations often write to the same log group, and its entries can't be attributed to one
    /// writer from the log alone. General entries are reported once, on the first writer; AWS authorization failures
    /// name the role, so they are attributed to the writer whose role it is.
    /// </summary>
    private sealed class LogShare
    {
        private readonly Dictionary<object, (bool Primary, int Writers)> _owners = new(ReferenceEqualityComparer.Instance);

        public static LogShare Build(ObservationReport report)
        {
            var share = new LogShare();
            var byGroup = new Dictionary<string, List<object>>(StringComparer.Ordinal);
            void Add(object owner, LogObservation? logs)
            {
                if (logs is null)
                {
                    return;
                }

                var key = logs.LogGroup + "|" + string.Join(',', logs.Regions);
                if (!byGroup.TryGetValue(key, out var list))
                {
                    byGroup[key] = list = [];
                }

                list.Add(owner);
            }

            foreach (var l in report.Listeners)
            {
                Add(l, l.Logs);
                foreach (var d in l.Destinations)
                {
                    Add(d, d.Logs);
                }
            }

            foreach (var owners in byGroup.Values)
            {
                for (var i = 0; i < owners.Count; i++)
                {
                    share._owners[owners[i]] = (i == 0, owners.Count);
                }
            }

            return share;
        }

        public (bool Primary, int Writers) For(object owner) => _owners.TryGetValue(owner, out var v) ? v : (true, 1);
    }

    private static string? RoleName(RoleInfo? role) =>
        role?.Arn is { IsResolved: true } arn && arn.Value!.LastIndexOf('/') is var slash and >= 0 ? arn.Value[(slash + 1)..] : null;

    /// <summary>
    /// Findings about a role Proxylity assumes. A role that can't be assumed, or lacks the permissions for logs and
    /// metrics, fails silently: nothing is written to CloudWatch. These checks are the only way to see that from here.
    /// Simulation evaluates the role's identity-based policies; a resource policy on the target can still grant access.
    /// </summary>
    private static IEnumerable<Finding> RoleFindings(RoleObservation? r, string level)
    {
        if (r is null)
        {
            yield break;
        }

        if (!r.Checked)
        {
            yield return new($"{level}.role-not-checked", Health.Unknown, Confidence.Confirmed,
                $"The {level} role is in another account and was not checked",
                [new("role", r.RoleArn)],
                []);
            yield break;
        }

        switch (r.Trust.State)
        {
            case SignalState.NotFound:
                yield return new($"{level}.role-not-found", Health.Error, Confidence.Confirmed,
                    $"The {level} role does not exist, so Proxylity can't assume it",
                    [new("role", r.RoleArn)],
                    [level == "destination"
                        ? "Create the role or fix Role.Arn. Without it nothing is delivered, and nothing is logged or published to report the problem."
                        : "Create the role or fix Role.Arn. Without it listener metrics and logs are silently missing."]);
                yield break;
            case SignalState.Available:
                var trust = r.Trust.Value!;
                if (!trust.AllowsAssumeRole)
                {
                    yield return new($"{level}.role-not-assumable", Health.Error, Confidence.Likely,
                        $"The {level} role's trust policy doesn't allow an AWS account to assume it",
                        [new("role", r.RoleArn)],
                        ["Trust the Proxylity service role from your account configuration, with a condition on sts:ExternalId (see Access & Permissions)."]);
                }
                else if (!trust.RequiresExternalId)
                {
                    yield return new($"{level}.role-no-external-id", Health.Warning, Confidence.Confirmed,
                        $"The {level} role's trust policy doesn't require an external ID",
                        [new("role", r.RoleArn)],
                        ["Add a StringEquals condition on sts:ExternalId with Account.ExternalId from your Proxylity account configuration (see Access & Permissions)."]);
                }

                // Comparisons with the account configuration (when it could be read). Values are never shown.
                if (r.ExternalIdMatches == false)
                {
                    yield return new($"{level}.role-external-id-mismatch", Health.Error, Confidence.Likely,
                        $"The {level} role's trust policy requires an external ID that isn't your account's current one, so Proxylity can't assume it",
                        [new("role", r.RoleArn), new("compared with", "Account.ExternalId in the account configuration")],
                        ["Set the sts:ExternalId condition to Account.ExternalId from your account configuration. It changes when the ID is regenerated."]);
                }

                if (r.ServiceRoleTrusted == false)
                {
                    yield return new($"{level}.role-service-role-not-trusted", Health.Warning, Confidence.Possible,
                        $"The {level} role's trust policy doesn't name the Proxylity service role for the stack's region",
                        [new("role", r.RoleArn), new("compared with", "ServiceRole in the account configuration")],
                        ["Trust the regional ServiceRole from your account configuration (see Access & Permissions)."]);
                }

                break;
        }

        if (!r.Permissions.IsAvailable)
        {
            yield break;
        }

        var denied = r.Permissions.Value!.Where(p => !p.Decision.Allowed).ToList();
        foreach (var group in denied.GroupBy(p => (p.Purpose, p.Decision.Resource)))
        {
            var actions = string.Join(", ", group.Select(p => p.Decision.Action).Distinct(StringComparer.Ordinal));
            var explicitDeny = group.Any(p => p.Decision.ExplicitlyDenied);
            var evidence = new List<Evidence> { new("not allowed", actions), new("resource", group.Key.Resource), new("decision", explicitDeny ? "explicit deny" : "no policy allows it") };
            yield return group.Key.Purpose switch
            {
                RoleChecks.Logs => new($"{level}.role-cannot-log", Health.Warning, explicitDeny ? Confidence.Confirmed : Confidence.Likely,
                    $"The {level} role can't write to its log group, so its log entries are silently lost",
                    evidence,
                    [$"Allow {actions} on the log group's streams in the {level}'s Role."]),
                RoleChecks.Metrics => new($"{level}.role-cannot-publish-metrics", Health.Warning, explicitDeny ? Confidence.Confirmed : Confidence.Likely,
                    $"The {level} role can't publish metrics, so its metrics are silently missing",
                    evidence,
                    [$"Allow cloudwatch:PutMetricData with the condition cloudwatch:namespace = \"{ObservationCollector.ProxylityNamespace}\" in the {level}'s Role."]),
                _ => new($"{level}.role-cannot-deliver", Health.Error, explicitDeny ? Confidence.Confirmed : Confidence.Likely,
                    "The destination role doesn't allow the actions needed for delivery",
                    evidence,
                    [explicitDeny
                        ? $"Remove the explicit deny for {actions}."
                        : $"Allow {actions} on {group.Key.Resource} in the destination's Role, unless a resource policy on the target already grants it."]),
            };
        }

        if (denied.Count == 0 && r.Trust.Value is { AllowsAssumeRole: true, RequiresExternalId: true } && r.Permissions.Value!.Count > 0
            && r.ExternalIdMatches != false && r.ServiceRoleTrusted != false)
        {
            var evidence = new List<Evidence> { new("checked", string.Join(", ", r.Permissions.Value!.Select(p => p.Purpose).Distinct(StringComparer.Ordinal))) };
            if (r.ExternalIdMatches == true)
            {
                evidence.Add(new("external ID", "matches the account configuration"));
            }

            yield return new($"{level}.role-ok", Health.Healthy, Confidence.Likely,
                $"The {level} role exists, requires the external ID, and allows what it needs",
                evidence,
                []);
        }
    }

    /// <summary>
    /// Documented requirements the template (as declared) does not meet. The deployed resources worked when they
    /// were created; the next update of the stack is what gets rejected.
    /// </summary>
    private static IEnumerable<Finding> TemplateFindings(ListenerInfo l)
    {
        foreach (var issue in l.TemplateIssues ?? [])
        {
            yield return issue.RuleId == "destination-unknown-property"
                ? new($"template.{issue.RuleId}", Health.Warning, Confidence.Likely,
                    "A destination setting is in the wrong place: " + issue.Message,
                    [new("property", issue.Path)],
                    ["Move the setting into the destination's Arguments."])
                : new($"template.{issue.RuleId}", Health.Warning, Confidence.Likely,
                    "The next update of this stack will be rejected: " + issue.Message,
                    [new("property", issue.Path)],
                    ["Fix the value in the template before the next deployment."]);
        }
    }

    /// <summary>Stack credentials compared with the account configuration. Only fingerprints are compared.</summary>
    private static IEnumerable<Finding> AccountFindings(AccountCheck? a)
    {
        if (a is null || a.Config != SignalState.Available)
        {
            yield break;
        }

        // A different value is not proof of a problem (an older value may still be accepted), hence "possible".
        if (a.ServiceTokenMatches == false)
        {
            yield return new("stack.service-token-mismatch", Health.Warning, Confidence.Possible,
                $"The stack was deployed with a ServiceToken other than the current one for {a.Region}",
                [new("compared with", $"the {a.Region} ServiceToken in the account configuration")],
                ["If stack updates or deletes fail, redeploy with the ServiceToken from the account configuration."]);
        }

        if (a.KeyMatches == false)
        {
            yield return new("stack.api-key-mismatch", Health.Warning, Confidence.Possible,
                "The stack was deployed with an API key other than your account's current one",
                [new("compared with", "Account.ApiKey in the account configuration")],
                ["If the older key has expired, updates and deletes of this stack's Proxylity resources will fail; redeploy with the current ApiKey."]);
        }
    }

    private static ListenerObservation DiagnoseListener(ListenerObservation o, LogShare share)
    {
        var l = o.Listener;
        var f = new List<Finding>();

        // Configuration.
        if (l.NameIsPlaceholder)
        {
            f.Add(new("listener.not-created", Health.Error, Confidence.Likely,
                "The listener has no name yet; its creation may have failed",
                [new("stack status", l.Stack.Status)],
                ["Check the stack's events in CloudFormation for the failure reason."]));
        }

        switch (l.ClientRestrictions.Form)
        {
            case ClientRestrictionsForm.Absent or ClientRestrictionsForm.Empty:
                f.Add(new("listener.no-client-restrictions", Health.Error, Confidence.Confirmed,
                    "No client restrictions are set, so all traffic is blocked",
                    [new("ClientRestrictions", l.ClientRestrictions.Form == ClientRestrictionsForm.Absent ? "not set" : "empty")],
                    ["Add the networks (CIDR) or domains of your senders to ClientRestrictions."]));
                break;
            case ClientRestrictionsForm.List:
                f.Add(new("listener.client-restrictions-shape", Health.Error, Confidence.Likely,
                    "ClientRestrictions is written as a list; it should be an object with Networks and Domains",
                    [new("ClientRestrictions", "list")],
                    ["Write ClientRestrictions as { Networks: [...], Domains: [...] }."]));
                break;
        }

        f.AddRange(TemplateFindings(l));
        f.AddRange(AccountFindings(o.Account));
        f.AddRange(RoleFindings(o.Role, "listener"));

        var observabilityWanted = l.MetricsEnabled.Value || l.LogGroupName.IsResolved;
        if (observabilityWanted && (l.Role is null || !l.Role.Arn.IsResolved))
        {
            f.Add(new("listener.observability-role-missing", Health.Error, Confidence.Likely,
                l.Role?.UsesRoleArnKey == true
                    ? "Listener Role uses 'RoleArn'; the property is 'Arn', so no role is configured"
                    : "Listener metrics or logs are enabled but no listener Role could be determined",
                [new("MetricsEnabled", Bool(l.MetricsEnabled)), new("LogGroupName", Text(l.LogGroupName))],
                ["Set the listener Role (Role: { Arn: ... }) to a role that can publish metrics and write logs."]));
        }

        // Traffic.
        var ingress = o.Metrics.GetValueOrDefault(MetricKeys.Ingress);
        var filtered = o.Metrics.GetValueOrDefault(MetricKeys.Filtered);
        var ingressBytes = o.Metrics.GetValueOrDefault(MetricKeys.IngressBytes);
        var filteredBytes = o.Metrics.GetValueOrDefault(MetricKeys.FilteredBytes);
        var errors = o.Metrics.GetValueOrDefault(MetricKeys.Errors);
        var regions = string.Join(", ", o.MetricRegions);

        if (!l.MetricsEnabled.Value)
        {
            f.Add(new("listener.metrics-off", Health.NotConfigured, Confidence.Confirmed,
                "Listener metrics are off, so incoming and filtered traffic can't be observed",
                [new("MetricsEnabled", Bool(l.MetricsEnabled))],
                ["Set MetricsEnabled: true and a listener Role that can publish to CloudWatch."]));
        }
        else if (Accessible(ingress, filtered) is { } denied)
        {
            f.Add(NotAccessible("listener.metrics-not-accessible", "Listener metrics", denied));
        }
        else if (!Has(ingress) && !Has(filtered))
        {
            f.Add(new("listener.no-metric-data", Health.Unknown, Confidence.Confirmed,
                "No listener metrics in the window",
                [new("regions checked", regions)],
                [
                    "If traffic was sent, the listener Role may be unable to publish metrics, or traffic entered in a region not checked (use --region).",
                    "Send test traffic and check again after a few minutes.",
                ]));
        }
        else
        {
            var inUnits = ingress.ValueOr0();
            var filteredUnits = filtered.ValueOr0();
            if (inUnits == 0 && filteredUnits > 0)
            {
                f.Add(new("listener.all-traffic-filtered", Health.Error, Confidence.Likely,
                    "Traffic is arriving but all of it is being rejected",
                    [new("filtered", Units(filteredUnits)), new("ingress", "0")],
                    [
                        "Check that your senders' addresses are allowed by ClientRestrictions.",
                        "Filtered traffic also includes traffic received while listeners are suspended; check the Proxylity dashboard.",
                    ]));
            }
            else
            {
                f.Add(new("listener.receiving", Health.Healthy, Confidence.Confirmed,
                    "Listener is receiving traffic",
                    [new("ingress", Units(inUnits)), new("filtered", Units(filteredUnits))],
                    []));
                var bytesIn = ingressBytes.ValueOr0();
                var bytesFiltered = filteredBytes.ValueOr0();
                if (bytesIn + bytesFiltered > 0 && bytesFiltered / (bytesIn + bytesFiltered) >= 0.5)
                {
                    f.Add(new("listener.mostly-filtered", Health.Warning, Confidence.Possible,
                        "Most incoming traffic is being rejected",
                        [new("filtered share", Percent(bytesFiltered / (bytesIn + bytesFiltered)) + " of bytes")],
                        ["Check ClientRestrictions against your senders' addresses; rejected traffic may be unwanted."]));
                }
            }
        }

        if (errors?.IsAvailable == true && errors.Value > 0)
        {
            f.Add(new("listener.errors-reported", Health.Warning, Confidence.Confirmed,
                "The listener reported errors",
                [new("errors", Count(errors.Value))],
                [ErrorLogHint(o.Logs, "listener")]));
        }

        AddLogFindings(f, o.Logs, "listener", RoleName(l.Role), share.For(o));

        var destinations = o.Destinations.Select(d => DiagnoseDestination(d, o, share)).ToList();
        return o with { Findings = f, Destinations = destinations };
    }

    private static DestinationObservation DiagnoseDestination(DestinationObservation o, ListenerObservation listener, LogShare share)
    {
        var d = o.Destination;
        var f = new List<Finding>();
        if (d.IsReferenceByName)
        {
            f.Add(new("destination.reference", Health.Unknown, Confidence.Confirmed,
                "This entry refers to a destination defined elsewhere; it is not inspected here",
                [new("name", d.Name ?? "?")],
                []));
            return o with { Findings = f };
        }

        if (d.Role is null)
        {
            f.Add(new("destination.no-role", Health.Error, Confidence.Confirmed,
                "No Role is set, so there is nothing for Proxylity to assume to deliver packets",
                [new("Role", "not set")],
                ["Set Role: { Arn: ... } to a role that allows delivery to the target."]));
        }
        else if (d.Role.UsesRoleArnKey)
        {
            f.Add(new("destination.role-key", Health.Error, Confidence.Likely,
                "Role uses 'RoleArn'; the property is 'Arn', so no role is configured",
                [new("Role", "RoleArn")],
                ["Rename RoleArn to Arn in the destination's Role."]));
        }

        f.AddRange(RoleFindings(o.Role, "destination"));

        if (d.Targets.Count == 0)
        {
            f.Add(new("destination.no-target", Health.Error, Confidence.Confirmed,
                "No DestinationArn is set, so nothing is delivered",
                [],
                ["Set DestinationArn, or attach one with a DestinationArn resource."]));
        }

        var ingress = o.Metrics.GetValueOrDefault(MetricKeys.Ingress);
        var filtered = o.Metrics.GetValueOrDefault(MetricKeys.Filtered);
        var errors = o.Metrics.GetValueOrDefault(MetricKeys.Errors);
        var listenerIngress = listener.Metrics.GetValueOrDefault(MetricKeys.Ingress);

        // Data found under the derived name confirms it; only flag the uncertainty when nothing was found.
        if (d.NameSource == NameSource.Derived && d.MetricsEnabled.Value && !Has(ingress) && !Has(filtered) && !Has(errors))
        {
            f.Add(new("destination.name-derived", Health.Unknown, Confidence.Possible,
                "This destination has no declared Name; its metrics were looked up under the name it is expected to have",
                [new("expected name", d.Name ?? "?")],
                ["Declare a Name for the destination to make metrics lookups certain."]));
        }

        if (!d.MetricsEnabled.Value)
        {
            f.Add(new("destination.metrics-off", Health.NotConfigured, Confidence.Confirmed,
                "Destination metrics are off, so accepted packets and delivery errors can't be counted",
                [new("MetricsEnabled", Bool(d.MetricsEnabled))],
                ["Set MetricsEnabled: true on the destination and allow cloudwatch:PutMetricData in its Role."]));
        }
        else if (Accessible(ingress, errors) is { } denied)
        {
            f.Add(NotAccessible("destination.metrics-not-accessible", "Destination metrics", denied));
        }
        else if (!Has(ingress) && !Has(filtered) && !Has(errors))
        {
            if (Has(listenerIngress) && listenerIngress!.Value > 0 && !d.HasFilterExpression)
            {
                f.Add(new("destination.silent", Health.Warning, Confidence.Possible,
                    "The listener received traffic but this destination published no metrics",
                    [new("listener ingress", Units(listenerIngress.Value)), new("regions checked", string.Join(", ", o.MetricRegions))],
                    [
                        "The destination Role may be unable to be assumed, or may not allow cloudwatch:PutMetricData; in that case nothing is written to CloudWatch.",
                        "Check the role exists and review recent AssumeRole events for it in CloudTrail.",
                    ]));
            }
            else
            {
                f.Add(new("destination.no-metric-data", Health.Unknown, Confidence.Confirmed,
                    "No destination metrics in the window",
                    [new("regions checked", string.Join(", ", o.MetricRegions))],
                    ["No packets were accepted for this destination in the window, or its metrics could not be published."]));
            }
        }
        else
        {
            var accepted = ingress.ValueOr0();
            var rejected = filtered.ValueOr0();
            if (d.HasFilterExpression && accepted + rejected > 0 && rejected / (accepted + rejected) >= 0.9)
            {
                f.Add(new("destination.filter-dropping", Health.Warning, Confidence.Possible,
                    "The FilterExpression rejects almost all packets",
                    [new("accepted", Units(accepted)), new("filtered", Units(rejected))],
                    ["Review the FilterExpression; packets it rejects are not delivered."]));
            }

            if (errors?.IsAvailable == true && errors.Value > 0)
            {
                f.Add(new("destination.errors-reported", Health.Error, Confidence.Confirmed,
                    "Delivery errors were reported for this destination",
                    [new("errors", Count(errors.Value)), new("accepted", Units(accepted))],
                    [ErrorLogHint(o.Logs, "destination")]));
            }
            else if (accepted > 0)
            {
                f.Add(new("destination.accepting", Health.Healthy, Confidence.Likely,
                    "Packets are being accepted for delivery with no delivery errors reported",
                    [new("accepted", Units(accepted)), new("errors", "0")],
                    []));
            }
        }

        AddLogFindings(f, o.Logs, "destination", RoleName(d.Role), share.For(o));

        var targets = o.Targets.Select(t => DiagnoseTarget(t, o)).ToList();
        return o with { Findings = f, Targets = targets };
    }

    private static TargetObservation DiagnoseTarget(TargetObservation o, DestinationObservation destination)
    {
        var f = new List<Finding>();
        var t = o.Target;
        if (!t.Arn.IsResolved)
        {
            f.Add(new("target.unresolved", Health.Unknown, Confidence.Confirmed,
                "The target ARN could not be determined from the stack",
                [new("reason", t.Arn.Reason ?? "absent")],
                []));
            return o with { Findings = f };
        }

        var adapter = Adapters.TargetAdapters.For(t.Service);
        if (adapter is null || o.Description is null)
        {
            f.Add(new("target.not-inspected", Health.Unknown, Confidence.Confirmed,
                "This service is not inspected yet; only Proxylity's own signals are shown",
                [new("service", t.Service.ToString())],
                []));
            return o with { Findings = f };
        }

        switch (o.Description.State)
        {
            case SignalState.Available:
                f.AddRange(adapter.Diagnose(o, destination));
                break;
            case SignalState.NotFound:
                f.Add(new($"{RulePrefix(t.Service)}.not-found", Health.Error, Confidence.Confirmed,
                    $"The {adapter.ResourceKind} does not exist",
                    [new("ARN", t.Arn.Value!)],
                    ["Fix the DestinationArn, or create the resource in that account and region."]));
                break;
            case SignalState.NotAccessible:
                f.Add(NotAccessible($"{RulePrefix(t.Service)}.not-accessible", $"The {adapter.ResourceKind}", o.Description.DeniedAction ?? "describe"));
                break;
            default:
                f.Add(new($"{RulePrefix(t.Service)}.unknown", Health.Unknown, Confidence.Unknown,
                    $"The {adapter.ResourceKind} could not be described",
                    [new("detail", o.Description.Detail ?? "not read")],
                    []));
                break;
        }

        return o with { Findings = f };
    }

    private static string RulePrefix(DestinationService s) => s switch
    {
        DestinationService.Lambda => "lambda",
        DestinationService.LambdaMicrovm => "microvm",
        _ => Adapters.TargetAdapters.For(s) is Adapters.ServiceAdapter sa ? sa.Spec.RulePrefix : "target",
    };
    /// <summary>
    /// Where to look for the cause of counted errors. Errors are counted independently of logging, so a
    /// log group may legitimately have no matching entries; say so rather than pointing at nothing.
    /// </summary>
    private static string ErrorLogHint(LogObservation? logs, string level)
    {
        if (logs is null)
        {
            return $"Set LogGroupName on the {level} to see error messages.";
        }

        return logs.Events.State switch
        {
            SignalState.Available when logs.Events.Value!.Any(e => e.Level == "ERROR") => $"Error entries from {logs.LogGroup} are shown in this report.",
            SignalState.Available or SignalState.NoData => logs.Truncated
                ? $"No error entries among the most recent entries of {logs.LogGroup}; use 'proxylity logs' with a shorter --since to look further."
                : $"{logs.LogGroup} has no error entries for the window: the errors were counted but not described there.",
            SignalState.NotFound => $"The log group {logs.LogGroup} does not exist, so error messages can't be written.",
            _ => $"The log group {logs.LogGroup} could not be read.",
        };
    }

    private static void AddLogFindings(List<Finding> findings, LogObservation? logs, string level, string? roleName, (bool Primary, int Writers) share)
    {
        if (logs is null)
        {
            return;
        }

        // Group-level states (missing, not readable) are reported once, on the first writer.
        if (!share.Primary && logs.Events.State != SignalState.Available)
        {
            return;
        }

        switch (logs.Events.State)
        {
            case SignalState.NotAccessible:
                findings.Add(NotAccessible($"{level}.logs-not-accessible", $"The {level} log group", logs.Events.DeniedAction ?? "logs:FilterLogEvents"));
                return;
            case SignalState.NotFound:
                findings.Add(new($"{level}.log-group-missing", Health.Warning, Confidence.Confirmed,
                    $"The {level} log group does not exist in the regions checked, so nothing can be logged there",
                    [new("log group", logs.LogGroup), new("regions checked", string.Join(", ", logs.Regions))],
                    ["Create the log group in each region where it will be written."]));
                return;
            case not SignalState.Available:
                return;
        }

        // AWS authorization failures quoted in log entries name the missing action; report them directly.
        var denied = logs.Events.Value!
            .Where(e => e.Level is "ERROR" or "WARN")
            .Select(e => (Match: AccessDenied.Match(e.Message), e.Count, e.Level))
            .Where(x => x.Match.Success)
            // The AWS message names the role; attribute it to the writer using that role.
            .Where(x => x.Match.Groups["role"].Success && roleName is not null
                ? string.Equals(x.Match.Groups["role"].Value, roleName, StringComparison.OrdinalIgnoreCase)
                : share.Primary)
            .GroupBy(x => x.Match.Groups["action"].Value, StringComparer.Ordinal)
            .Select(g => (Action: g.Key, Count: g.Sum(x => x.Count), Resource: g.First().Match.Groups["resource"].Value, IsError: g.Any(x => x.Level == "ERROR")))
            .OrderByDescending(g => g.Count)
            .ToList();
        foreach (var d in denied)
        {
            var evidence = new List<Evidence> { new("denied action", d.Action), new("occurrences", Count(d.Count)) };
            if (d.Resource.Length > 0)
            {
                evidence.Add(new("on resource", d.Resource, Untrusted: true));
            }

            // Severity follows the log level: warnings describe a degraded mode, errors failed work.
            findings.Add(new($"{level}.role-missing-permission", d.IsError ? Health.Error : Health.Warning, Confidence.Confirmed,
                $"The {level} role is missing permission {d.Action}",
                evidence,
                [$"Allow {d.Action} in the {level}'s Role policy" + (d.Resource.Length > 0 ? " for the resource shown." : ".")]));
        }

        if (!share.Primary)
        {
            return;
        }

        var shared = share.Writers > 1 ? $" (log group shared by {share.Writers} writers)" : string.Empty;
        foreach (var (lvl, health) in new[] { ("ERROR", Health.Error), ("WARN", Health.Warning) })
        {
            var groups = logs.Events.Value!
                .Where(e => e.Level == lvl)
                .GroupBy(e => e.Message, StringComparer.Ordinal)
                .Select(g => (Message: g.Key, Count: g.Sum(x => x.Count), Last: g.Max(x => x.Timestamp)))
                .OrderByDescending(g => g.Count)
                .ToList();
            if (groups.Count == 0)
            {
                continue;
            }

            findings.Add(new($"{level}.log-{lvl.ToLowerInvariant()}", health, Confidence.Confirmed,
                $"The {level} log reports {(lvl == "ERROR" ? "errors" : "warnings")}{shared}",
                [.. groups.Take(3).Select(g => new Evidence($"{Count(g.Count)}×", g.Message, Untrusted: true))],
                [$"Log group {logs.LogGroup}" + (logs.Truncated ? " (only the most recent entries were read)" : string.Empty)]));
        }
    }

    private static Finding NotAccessible(string id, string what, string action) =>
        new(id, Health.NotAccessible, Confidence.Confirmed, $"{what} can't be read with the current AWS identity",
            [new("denied action", action)],
            [$"Allow {action} for the identity running the CLI."]);

    private static bool Has(Signal<double>? s) => s?.IsAvailable == true;

    private static string? Accessible(params Signal<double>?[] signals) =>
        signals.All(s => s is null || s.State == SignalState.NotAccessible) && signals.Any(s => s is not null)
            ? signals.First(s => s is not null)!.DeniedAction ?? "cloudwatch:GetMetricData"
            : null;

    private static double ValueOr0(this Signal<double>? s) => s?.IsAvailable == true ? s.Value : 0;

    private static string Count(double v) => v.ToString("N0", CultureInfo.InvariantCulture);

    private static string Units(double v) => v.ToString("N0", CultureInfo.InvariantCulture) + " packet units";

    private static string Percent(double v) => (v * 100).ToString(v < 0.1 ? "0.#" : "0", CultureInfo.InvariantCulture) + "%";

    private static string Bool(Resolved<bool> v) => v.State == ValueState.Resolved ? (v.Value ? "true" : "false") : v.State == ValueState.Absent ? "not set" : "unresolved";

    private static string Text(Resolved<string> v) => v.State == ValueState.Resolved ? v.Value! : v.State == ValueState.Absent ? "not set" : "unresolved";
}
