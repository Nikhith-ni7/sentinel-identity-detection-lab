# Validate the identity detection lab

## Run the synthetic exercise

1. Open **Logs** in your lab workspace.
2. Paste `tests/fixtures.kql` followed by a single query from `analytics/`, then run it.
3. Compare the returned rows against the README results table. Check that the normal controls stay out of the results.
4. To verify scheduled incident generation, build a fresh synthetic template and deploy it into a dedicated lab workspace. Record the incident ID, timestamp, and matched rule. The synthetic queries stop matching one hour after generation.
5. Record the Logic App run outcome separately. The inline records use fictional identities and are suitable for detection testing.

| Scenario | Fixture input to inspect | Expected result |
| --- | --- | --- |
| Password spray | Compare the records for `192.0.2.10` with the single-account control at `192.0.2.20`. | One match for `192.0.2.10`, with five accounts and a later success. |
| MFA push flooding | Run `mfa-push-flood.kql` against the notification records for `mfa`. | One match with five failed push sign-ins. |
| MFA fatigue followed by successful sign-in | Run `mfa-fatigue-success.kql` against `fatigue` and the single-denial control `slip`. | `fatigue` matches and `slip` produces no row. |
| New country | Compare the earlier and recent country values for `traveler`. | One match for GB. |
| Impossible travel | Compare the timestamps and coordinates for the two `traveler` sign-ins. | One US-to-GB match, approximately 5,573 km apart. |
| High-risk successful sign-in | Compare the successful sign-in for `risky` with the ordinary sign-in control. | One high-risk match for `risky`. |
| Suspicious inbox rule | Run `suspicious-inbox-rule.kql` against `mail`, `rss`, `client`, and the ordinary folder-move control. | Three matches. The ordinary folder move produces no row. |

## Prepare a live connector validation

Use an isolated Entra tenant with P2, an Azure subscription in that same tenant, and a dedicated Log Analytics workspace. Configure a budget alert before deploying resources. Enable the Entra sign-in and audit categories and verify `SigninLogs` and `AuditLogs` receive ordinary activity from test users. If validating mailbox telemetry, use a licensed test mailbox and the Exchange audit connector, then verify `OfficeActivity` receives events.

Keep the containment playbook in dry-run mode for initial deployment. Configure the workspace and dedicated lab group explicitly, and review the test account object IDs before granting any permissions. Validate the incident trigger, scope check and planned action in run history. Record only actions and outcomes actually observed in the incident report.

For a live ingestion check, sign in normally with a dedicated test user and record the UTC time. Check for the user and time in `SigninLogs`. For `AuditLogs`, use a recorded administrative change such as creating an empty test group. For `OfficeActivity`, create a test mailbox rule that moves a message with a unique test subject to a test folder. Confirm that the expected audit events arrive before running the synthetic detection exercise.
