# Validate the identity detection lab

## Run the synthetic exercise

1. Open **Logs** in your lab workspace.
2. Paste `tests/fixtures.kql` followed by a single query from `analytics/`, then run it.
3. Compare the returned rows against the README results table. Check that the normal controls stay out of the results.
4. To verify scheduled incident generation, build a fresh synthetic template and deploy it into a dedicated lab workspace. Record the incident ID, timestamp, and matched rule. The synthetic queries stop matching one hour after generation.
5. Record the Logic App run outcome separately. The inline records use fictional identities and are suitable for detection testing.

## Prepare a live connector validation

Use an isolated Entra tenant with P2, an Azure subscription in that same tenant, and a dedicated Log Analytics workspace. Configure a budget alert before deploying resources. Enable the Entra sign-in and audit categories and verify `SigninLogs` and `AuditLogs` receive ordinary activity from test users. If validating mailbox telemetry, use a licensed test mailbox and the Exchange audit connector, then verify `OfficeActivity` receives events.

Keep the containment playbook in dry-run mode for initial deployment. Configure the workspace and dedicated lab group explicitly, and review the test account object IDs before granting any permissions. Validate the incident trigger, scope check and planned action in run history. Record only actions and outcomes actually observed in the incident report.
