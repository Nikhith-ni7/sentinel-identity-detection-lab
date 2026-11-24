"""Build the ARM template for the synthetic Sentinel lab."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    "password-spray": ("Password spray", "PT15M", ["CredentialAccess"], ["T1110"]),
    "mfa-push-flood": ("MFA push flooding", "PT15M", ["CredentialAccess"], ["T1621"]),
    "new-country": ("New country", "P7D", ["InitialAccess"], ["T1078"]),
    "impossible-travel": ("Impossible travel", "PT8H", ["InitialAccess"], ["T1078"]),
    "suspicious-inbox-rule": ("Suspicious inbox rule", "PT1H", ["Collection"], []),
    "risky-successful-signin": ("High-risk successful sign-in", "PT1H", ["InitialAccess"], ["T1078"]),
}
ONBOARDING_ID = "[resourceId('Microsoft.OperationalInsights/workspaces/providers/onboardingStates', parameters('workspaceName'), 'Microsoft.SecurityInsights', 'default')]"


def build(expires_at):
    fixtures = (ROOT / "tests/fixtures.kql").read_text()
    resources = [{
        "type": "Microsoft.OperationalInsights/workspaces/providers/onboardingStates",
        "apiVersion": "2024-09-01",
        "name": "[format('{0}/Microsoft.SecurityInsights/default', parameters('workspaceName'))]",
        "properties": {},
    }]
    for slug, (name, period, tactics, techniques) in RULES.items():
        rule_id = uuid5(NAMESPACE_URL, f"sentinel-identity-lab/{slug}")
        query = (ROOT / "analytics" / f"{slug}.kql").read_text().rstrip()
        resources.append({
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "apiVersion": "2024-09-01",
            "name": f"[format('{{0}}/Microsoft.SecurityInsights/{rule_id}', parameters('workspaceName'))]",
            "dependsOn": [ONBOARDING_ID],
            "kind": "Scheduled",
            "properties": {
                "displayName": f"[Synthetic] {name}",
                "description": "Lab rule using inline synthetic telemetry. The query stops returning results after the verification window.",
                "severity": "Medium",
                "enabled": True,
                "query": (
                    f"{fixtures}\n{query}\n| extend TimeGenerated=now()\n"
                    f"| where TimeGenerated < datetime({expires_at})"
                ),
                "queryFrequency": "PT5M",
                "queryPeriod": period,
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionEnabled": True,
                "suppressionDuration": "PT1H",
                "tactics": tactics,
                "techniques": techniques,
                "incidentConfiguration": {
                    "createIncident": True,
                    "groupingConfiguration": {
                        "enabled": False,
                        "reopenClosedIncident": False,
                        "lookbackDuration": "PT1H",
                        "matchingMethod": "AllEntities",
                        "groupByEntities": [],
                        "groupByAlertDetails": [],
                        "groupByCustomDetails": [],
                    },
                },
            },
        })

    # A Sentinel incident trigger uses the managed Sentinel connector. Its
    # connection and role assignments are configured in the target workspace.
    resources.append({
        "type": "Microsoft.Logic/workflows",
        "apiVersion": "2019-05-01",
        "name": "logic-identity-lab-dry-run",
        "location": "[parameters('location')]",
        "properties": {
            "state": "Disabled",
            "definition": {
                "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                "contentVersion": "1.0.0.0",
                "triggers": {"Manual_dry_run": {
                    "type": "Request",
                    "kind": "Http",
                    "inputs": {"schema": {
                        "type": "object",
                        "properties": {
                            "incidentId": {"type": "string"},
                            "ruleName": {"type": "string"},
                            "testUser": {"type": "string"},
                        },
                        "required": ["incidentId", "ruleName"],
                    }},
                }},
                "actions": {"Record_intended_response": {
                    "type": "Compose",
                    "inputs": {
                        "mode": "dry-run",
                        "incidentId": "@triggerBody()?['incidentId']",
                        "ruleName": "@triggerBody()?['ruleName']",
                        "proposedAccount": "@triggerBody()?['testUser']",
                        "decision": "Review evidence and confirm a lab account before considering session revocation or account disablement.",
                    },
                    "runAfter": {},
                }},
                "outputs": {},
            },
        },
    })
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspaceName": {"type": "string", "defaultValue": "law-identity-lab"},
            "location": {"type": "string", "defaultValue": "westus3"},
        },
        "resources": resources,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    deadline = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    args.output.write_text(json.dumps(build(deadline), indent=2) + "\n")
