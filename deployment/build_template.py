"""Build the ARM template for the Sentinel identity lab.

Modes:
  synthetic   rules run against the inline test data in tests/fixtures.kql and stop
              returning results one hour after the template is built. Use this to prove
              the rules, incidents and automation work before real telemetry exists.
  production  rules run against the real SigninLogs and OfficeActivity tables.

Both modes define the containment playbook (dry run by default). The synthetic
automation rule is disabled because fixture identities are fictional.

Usage:
  python3 deployment/build_template.py synthetic /tmp/identity-lab-synthetic.json
  python3 deployment/build_template.py production /tmp/identity-lab-production.json
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = "parameters('workspaceName')"
PLAYBOOK = "parameters('playbookName')"
CONNECTION = "[format('azuresentinel-{0}', parameters('playbookName'))]"
SENTINEL_API = "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'azuresentinel')]"
SENTINEL_RESPONDER_ROLE = "3e150937-b8fe-4cfb-8069-0eaf05ecd056"
SENTINEL_AUTOMATION_CONTRIBUTOR_ROLE = "f4c81013-99ee-4d62-a7ee-b3f1f648599a"

SIGNIN_ENTITIES = [
    {"entityType": "Account", "fieldMappings": [
        {"identifier": "AadUserId", "columnName": "UserId"},
        {"identifier": "FullName", "columnName": "UserPrincipalName"}]},
    {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "IPAddress"}]},
]
MAILBOX_ENTITIES = [
    {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "UserId"}]},
    {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "ClientIP"}]},
]
SPRAY_ENTITIES = [
    {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "IPAddress"}]},
]

# slug: settings. "contain" = incidents from this rule run the containment playbook.
RULES = {
    "password-spray": {
        "name": "Password spray", "frequency": "PT15M", "period": "PT15M", "severity": "Medium",
        "tactics": ["CredentialAccess"], "techniques": ["T1110"], "sub": ["T1110.003"],
        "entities": SPRAY_ENTITIES, "contain": False, "severity_column": "Severity",
        "details": {"AccountCount": "AccountCount", "SuccessfulAccounts": "SuccessfulAccounts"},
    },
    "mfa-push-flood": {
        "name": "MFA push flooding", "frequency": "PT15M", "period": "PT15M", "severity": "Medium",
        "tactics": ["CredentialAccess"], "techniques": ["T1621"], "sub": [],
        "entities": SIGNIN_ENTITIES, "contain": False,
    },
    "mfa-fatigue-success": {
        "name": "MFA fatigue followed by successful sign-in", "frequency": "PT15M", "period": "PT30M",
        "severity": "High", "tactics": ["CredentialAccess", "InitialAccess"],
        "techniques": ["T1621", "T1078"], "sub": ["T1078.004"],
        "entities": SIGNIN_ENTITIES, "contain": True,
        "details": {"FailedPushSignIns": "FailedPushSignIns"},
    },
    "new-country": {
        "name": "Sign-in from a new country", "frequency": "PT1H", "period": "P7D", "severity": "Low",
        "tactics": ["InitialAccess"], "techniques": ["T1078"], "sub": ["T1078.004"],
        "entities": SIGNIN_ENTITIES, "contain": False,
    },
    "impossible-travel": {
        "name": "Impossible travel", "frequency": "PT1H", "period": "PT8H", "severity": "Medium",
        "tactics": ["InitialAccess"], "techniques": ["T1078"], "sub": ["T1078.004"],
        "entities": SIGNIN_ENTITIES, "contain": True,
        "details": {"SpeedKmh": "SpeedKmh", "PreviousCountry": "PreviousCountry"},
    },
    "suspicious-inbox-rule": {
        "name": "Suspicious inbox rule", "frequency": "PT1H", "period": "PT1H", "severity": "High",
        "tactics": ["Collection", "DefenseEvasion"], "techniques": ["T1114", "T1564"],
        "sub": ["T1114.003", "T1564.008"], "entities": MAILBOX_ENTITIES, "contain": True,
    },
    "risky-successful-signin": {
        "name": "High-risk successful sign-in", "frequency": "PT1H", "period": "PT1H", "severity": "High",
        "tactics": ["InitialAccess"], "techniques": ["T1078"], "sub": ["T1078.004"],
        "entities": SIGNIN_ENTITIES, "contain": True,
    },
}


def rule_guid(slug):
    return str(uuid5(NAMESPACE_URL, f"sentinel-identity-lab/{slug}"))


def rule_resource_id(slug):
    return (f"[resourceId('Microsoft.OperationalInsights/workspaces/providers/alertRules', "
            f"{WORKSPACE}, 'Microsoft.SecurityInsights', '{rule_guid(slug)}')]")


def analytics_rule(slug, settings, mode, fixtures, expires_at):
    query = (ROOT / "analytics" / f"{slug}.kql").read_text().rstrip()
    comments = [line.lstrip("/ ") for line in query.splitlines() if line.startswith("//")]
    description = " ".join(comments) or settings["name"]
    entities = settings["entities"]
    if mode == "synthetic":
        # Test users have no Entra object ID, so map them by name only, and stamp
        # results with now() so they fall inside the rule's lookback window.
        query = (f"{fixtures}\n{query}\n| extend TimeGenerated=now()\n"
                 f"| where TimeGenerated < datetime({expires_at})")
        entities = [
            {**e, "fieldMappings": [m for m in e["fieldMappings"] if m["identifier"] != "AadUserId"]}
            for e in entities
        ]
    properties = {
        "displayName": ("[Synthetic] " if mode == "synthetic" else "") + settings["name"],
        "description": description,
        "severity": settings["severity"],
        "enabled": True,
        "query": query,
        "queryFrequency": "PT5M" if mode == "synthetic" else settings["frequency"],
        "queryPeriod": settings["period"],
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionEnabled": mode == "synthetic",
        "suppressionDuration": "PT1H",
        "tactics": settings["tactics"],
        "techniques": settings["techniques"],
        "subTechniques": settings["sub"],
        "entityMappings": entities,
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": False, "reopenClosedIncident": False, "lookbackDuration": "PT1H",
                "matchingMethod": "AllEntities", "groupByEntities": [],
                "groupByAlertDetails": [], "groupByCustomDetails": [],
            },
        },
    }
    if settings.get("severity_column"):
        properties["alertDetailsOverride"] = {"alertSeverityColumnName": settings["severity_column"]}
    if settings.get("details"):
        properties["customDetails"] = settings["details"]
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2024-09-01",
        "name": f"[format('{{0}}/Microsoft.SecurityInsights/{rule_guid(slug)}', {WORKSPACE})]",
        "dependsOn": ["onboarding"],
        "kind": "Scheduled",
        "properties": properties,
    }


def sentinel_action(path, body):
    return {
        "type": "ApiConnection",
        "inputs": {
            "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
            "method": "post",
            "path": path,
            "body": body,
        },
    }


def comment(message, run_after):
    action = sentinel_action("/Incidents/Comment", {
        "incidentArmId": "@triggerBody()?['object']?['id']",
        "message": f"<p>{message}</p>",
    })
    action["runAfter"] = run_after
    return action


def graph_call(method, path, body=None, run_after=None):
    inputs = {
        "method": method,
        "uri": f"https://graph.microsoft.com/v1.0/{path}",
        "authentication": {"type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com"},
    }
    if body is not None:
        inputs["body"] = body
    return {"type": "Http", "inputs": inputs, "runAfter": run_after or {}}


def playbook_definition():
    account = "items('For_each_account')"
    user = "@{outputs('User_id')}"
    contain_actions = {
        "Revoke_sessions": graph_call("POST", f"users/{user}/revokeSignInSessions"),
        "Disable_account": graph_call("PATCH", f"users/{user}", {"accountEnabled": False},
                                      {"Revoke_sessions": ["Succeeded"]}),
        "Comment_contained": comment(
            f"Containment playbook: revoked sessions and disabled {user}. "
            "Reset the password and re-enable the account after investigation.",
            {"Disable_account": ["Succeeded"]}),
    }
    in_lab_group = {
        "type": "If",
        "runAfter": {"Check_lab_group": ["Succeeded", "Failed"]},
        "expression": {"and": [
            {"equals": ["@outputs('Check_lab_group')?['statusCode']", 200]},
            {"contains": ["@body('Check_lab_group')?['value']", "@parameters('LabGroupId')"]},
        ]},
        "actions": {
            "If_dry_run": {
                "type": "If",
                "runAfter": {},
                "expression": {"and": [{"equals": ["@parameters('DryRun')", True]}]},
                "actions": {"Comment_dry_run": comment(
                    f"Containment playbook (dry run): would revoke sessions and disable {user}.", {})},
                "else": {"actions": {
                    "If_explicitly_allowed": {
                        "type": "If",
                        "runAfter": {},
                        "expression": {"and": [
                            {"contains": ["@parameters('AllowedLabUserIds')", "@outputs('User_id')"]},
                            {"equals": ["@outputs('User_id')", f"@{account}?['AadUserId']"]},
                        ]},
                        "actions": contain_actions,
                        "else": {"actions": {"Comment_not_allowed": comment(
                            "Containment skipped because the Entra object ID was outside the explicit lab allowlist.", {})}},
                    },
                }},
            },
        },
        "else": {"actions": {"Comment_not_in_scope": comment(
            f"Containment playbook: {user} was not found or is not in the lab users group. No action taken.",
            {})}},
    }
    per_account = {
        "User_id": {
            "type": "Compose",
            "runAfter": {},
            "inputs": (f"@if(empty({account}?['AadUserId']), "
                       f"concat({account}?['Name'], '@', {account}?['UPNSuffix']), "
                       f"{account}?['AadUserId'])"),
        },
        "Check_lab_group": graph_call(
            "POST", f"users/{user}/checkMemberGroups",
            {"groupIds": ["@{parameters('LabGroupId')}"]}, {"User_id": ["Succeeded"]}),
        "If_in_lab_group": in_lab_group,
    }
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"type": "Object", "defaultValue": {}},
            "LabGroupId": {"type": "String", "defaultValue": ""},
            "AllowedLabUserIds": {"type": "Array", "defaultValue": []},
            "DryRun": {"type": "Bool", "defaultValue": True},
        },
        "triggers": {
            "Microsoft_Sentinel_incident": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
                    "body": {"callback_url": "@{listCallbackUrl()}"},
                    "path": "/incident-creation",
                },
            },
        },
        "actions": {
            "Get_accounts": {
                **sentinel_action("/entities/account",
                                  "@triggerBody()?['object']?['properties']?['relatedEntities']"),
                "runAfter": {},
            },
            "For_each_account": {
                "type": "Foreach",
                "foreach": "@body('Get_accounts')?['Accounts']",
                "runAfter": {"Get_accounts": ["Succeeded"]},
                "actions": per_account,
            },
        },
        "outputs": {},
    }


def playbook_resources():
    playbook_id = f"[resourceId('Microsoft.Logic/workflows', {PLAYBOOK})]"
    workspace_id = f"[resourceId('Microsoft.OperationalInsights/workspaces', {WORKSPACE})]"
    return [
        {
            "type": "Microsoft.Web/connections",
            "apiVersion": "2016-06-01",
            "name": CONNECTION,
            "location": "[parameters('location')]",
            "kind": "V1",
            "properties": {
                "displayName": "Microsoft Sentinel (managed identity)",
                "customParameterValues": {},
                "parameterValueType": "Alternative",
                "api": {"id": SENTINEL_API},
            },
        },
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2019-05-01",
            "name": f"[{PLAYBOOK}]",
            "location": "[parameters('location')]",
            "identity": {"type": "SystemAssigned"},
            "dependsOn": [f"[resourceId('Microsoft.Web/connections', format('azuresentinel-{{0}}', {PLAYBOOK}))]"],
            "properties": {
                "state": "Enabled",
                "definition": playbook_definition(),
                "parameters": {
                    "$connections": {"value": {"azuresentinel": {
                        "connectionId": f"[resourceId('Microsoft.Web/connections', format('azuresentinel-{{0}}', {PLAYBOOK}))]",
                        "connectionName": CONNECTION,
                        "id": SENTINEL_API,
                        "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}},
                    }}},
                    "LabGroupId": {"value": "[parameters('labGroupId')]"},
                    "AllowedLabUserIds": {"value": "[parameters('allowedLabUserIds')]"},
                    "DryRun": {"value": "[parameters('dryRun')]"},
                },
            },
        },
        {
            # Lets the playbook read incidents and add comments.
            "type": "Microsoft.Authorization/roleAssignments",
            "apiVersion": "2022-04-01",
            "scope": f"[format('Microsoft.OperationalInsights/workspaces/{{0}}', {WORKSPACE})]",
            "name": f"[guid({workspace_id}, {PLAYBOOK}, 'responder')]",
            "dependsOn": [playbook_id],
            "properties": {
                "roleDefinitionId": f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{SENTINEL_RESPONDER_ROLE}')]",
                "principalId": f"[reference({playbook_id}, '2019-05-01', 'full').identity.principalId]",
                "principalType": "ServicePrincipal",
            },
        },
        {
            # Lets Microsoft Sentinel start playbooks in this resource group.
            "condition": "[not(empty(parameters('sentinelServicePrincipalObjectId')))]",
            "type": "Microsoft.Authorization/roleAssignments",
            "apiVersion": "2022-04-01",
            "name": "[guid(resourceGroup().id, 'sentinel-automation-contributor')]",
            "properties": {
                "roleDefinitionId": f"[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '{SENTINEL_AUTOMATION_CONTRIBUTOR_ROLE}')]",
                "principalId": "[parameters('sentinelServicePrincipalObjectId')]",
                "principalType": "ServicePrincipal",
            },
        },
    ]


def automation_rule(rule_slugs, enabled):
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/automationRules",
        "apiVersion": "2024-09-01",
        "name": f"[format('{{0}}/Microsoft.SecurityInsights/{uuid5(NAMESPACE_URL, 'sentinel-identity-lab/contain')}', {WORKSPACE})]",
        "dependsOn": [rule_resource_id(s) for s in rule_slugs]
        + [f"[resourceId('Microsoft.Logic/workflows', {PLAYBOOK})]"],
        "properties": {
            "displayName": "Run containment playbook on account-compromise incidents",
            "order": 1,
            "triggeringLogic": {
                "isEnabled": enabled,
                "triggersOn": "Incidents",
                "triggersWhen": "Created",
                "conditions": [{
                    "conditionType": "Property",
                    "conditionProperties": {
                        "propertyName": "IncidentRelatedAnalyticRuleIds",
                        "operator": "Contains",
                        "propertyValues": [rule_resource_id(s) for s in rule_slugs],
                    },
                }],
            },
            "actions": [{
                "order": 1,
                "actionType": "RunPlaybook",
                "actionConfiguration": {
                    "logicAppResourceId": f"[resourceId('Microsoft.Logic/workflows', {PLAYBOOK})]",
                    "tenantId": "[subscription().tenantId]",
                },
            }],
        },
    }


def build(mode, expires_at=None):
    fixtures = (ROOT / "tests/fixtures.kql").read_text() if mode == "synthetic" else None
    resources = [{
        "type": "Microsoft.OperationalInsights/workspaces/providers/onboardingStates",
        "apiVersion": "2024-09-01",
        "name": f"[format('{{0}}/Microsoft.SecurityInsights/default', {WORKSPACE})]",
        "properties": {},
    }]
    for slug, settings in RULES.items():
        resources.append(analytics_rule(slug, settings, mode, fixtures, expires_at))
    resources += playbook_resources()
    resources.append(automation_rule([s for s, r in RULES.items() if r["contain"]], mode == "production"))

    onboarding_id = (f"[resourceId('Microsoft.OperationalInsights/workspaces/providers/onboardingStates', "
                     f"{WORKSPACE}, 'Microsoft.SecurityInsights', 'default')]")
    for resource in resources:
        resource["dependsOn"] = [onboarding_id if d == "onboarding" else d for d in resource.get("dependsOn", [])]
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {"mode": mode},
        "parameters": {
            "workspaceName": {"type": "string", "defaultValue": "law-identity-lab"},
            "location": {"type": "string", "defaultValue": "[resourceGroup().location]"},
            "playbookName": {"type": "string", "defaultValue": "playbook-contain-lab-account"},
            "labGroupId": {"type": "string", "metadata": {
                "description": "Object ID of the Entra group whose members the playbook may contain."}},
            "allowedLabUserIds": {"type": "array", "defaultValue": [], "metadata": {
                "description": "Explicit Entra object IDs eligible for live containment."}},
            "dryRun": {"type": "bool", "defaultValue": True, "metadata": {
                "description": "true = only comment on the incident; false = revoke sessions and disable the account."}},
            "sentinelServicePrincipalObjectId": {"type": "string", "defaultValue": "", "metadata": {
                "description": "Object ID of the 'Azure Security Insights' service principal in your tenant. "
                               "Leave empty to grant Sentinel playbook permissions in the portal instead."}},
        },
        "resources": resources,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["synthetic", "production"])
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    expires_at = None
    if args.mode == "synthetic":
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(build(args.mode, expires_at), indent=2) + "\n")
    print(f"Wrote {args.mode} template to {args.output}")


if __name__ == "__main__":
    main()
