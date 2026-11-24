# Microsoft Sentinel identity detection lab

This first phase contains KQL for six scheduled analytics rules and synthetic data for query testing. The thresholds are starting values for a small lab. Review alerts before deciding whether to contain an account.

| Query | Suggested run interval / lookup | Expected synthetic result |
| --- | --- | --- |
| Password spray | 15 min / 15 min | Source 192.0.2.10, five distinct accounts |
| MFA push flooding | 15 min / 15 min | mfa@example.test, five sign-ins with failed push steps |
| New country | 1 hour / 7 days | traveler@example.test, GB |
| Impossible travel | 1 hour / 8 hours | traveler@example.test, US to GB |
| Suspicious inbox rule | 1 hour / 1 hour | mail@example.test, ForwardTo |
| High-risk successful sign-in | 1 hour / 1 hour | risky@example.test |

To test a query, paste the full contents of `tests/fixtures.kql` followed by one file from `analytics/` into **Logs** and run the combined query. Repeat for all six. The fixture supplies local tables within the query. Record the output and compare it with the expected row above. These tests require access to a KQL query engine. The fixture blocks are for query testing and should be removed when creating a rule against live tables.

The MFA rule counts sign-ins with unsuccessful mobile notification steps. Check the authentication method label against actual tenant logs before enabling the rule. The sign-in rules use interactive sign-in logs. High-risk sign-ins are leads for investigation. Exchange inbox rules require Exchange audit data in `OfficeActivity`.

## Cloud prerequisites

- Student835 carries the P2 trial and currently has no Azure subscription. The built-in Entra connector requires a Sentinel workspace in the same tenant. The FAU Azure for Students subscription can host the synthetic test path if school policies permit.
- Before enabling any cloud resources, verify P2 recurring billing is off and configure a budget alert for the Azure subscription used by the lab.
- For a live deployment, confirm the connector has populated `SigninLogs` and `AuditLogs`, and verify Exchange auditing separately if testing mailbox activity.
- Validate the response playbook in dry-run mode. For live containment, limit it to explicitly listed lab users and exclude administrators. The password-spray query identifies a source IP and attempted accounts, which is insufficient evidence to disable those accounts.
- Record actual alert evidence, containment results, and outstanding gaps in the incident report after testing.

## Synthetic Sentinel deployment

From the project root, run `python3 deployment/build_template.py /tmp/identity-lab-template.json` immediately before deployment. Use Azure's custom template deployment with the existing `rg-identity-lab` resource group. The generated template targets the existing workspace, onboards Sentinel, and creates six scheduled rules that evaluate inline fixtures. It also creates a disabled, HTTP-triggered Logic App for a manual dry run. The rule queries stop returning results one hour after generation. Confirm the six incidents, then disable the synthetic rules to stop evaluation.

For incident automation, use a Microsoft Sentinel incident trigger in a Consumption Logic App and copy the dry-run Compose action into that playbook. Configure the Sentinel connector and authorize Sentinel to run the playbook. Add an incident-created automation rule scoped to the six synthetic rules. Verify the run history before recording containment evidence in the incident report.

- [Scheduled rule ARM reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules)
- [Microsoft Sentinel incident automation](https://learn.microsoft.com/en-us/azure/sentinel/automate-incident-handling-with-automation-rules)
