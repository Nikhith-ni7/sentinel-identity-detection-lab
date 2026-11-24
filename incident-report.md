# Identity detection lab incident exercise

## Summary

Six detection queries were exercised with inline synthetic records in Azure Monitor Logs on the student subscription. Each returned its expected positive match. Scheduled versions of all six rules then generated one observed incident each in Microsoft Sentinel on `law-identity-lab`.

| Scenario | Observed query evidence | Response decision for the exercise |
| --- | --- | --- |
| Password spray | Five distinct accounts from 192.0.2.10 | Investigate the source and look for successful sign-ins before considering containment. |
| MFA push flooding | Five failed notification sign-ins on one test user | Review MFA outcomes and confirm whether any request was approved. |
| New country | Great Britain after an established U.S. baseline | Confirm expected travel and check the device and network evidence. |
| Impossible travel | Consecutive U.S. and Great Britain sign-ins within two hours | Verify IP geolocation and rule out corporate egress or VPN effects. |
| Suspicious inbox rule | Exchange forwarding rule on a synthetic mailbox | Review the rule destination and remove the rule if the mailbox owner confirms it was unauthorized. |
| High-risk successful sign-in | One successful sign-in labeled high risk | Confirm the test account and verify the sign-in before containment. |

## Cloud incident and containment evidence

| Sentinel incident | Rule | Created (Eastern Standard Time, November 23, 2026) |
| --- | --- | --- |
| 1 | MFA push flooding | 21:57 |
| 2 | Password spray | 21:57 |
| 3 | New country | 21:59 |
| 4 | Impossible travel | 22:00 |
| 5 | Suspicious inbox rule | 22:01 |
| 6 | High-risk successful sign-in | 22:02 |

The incident queue showed medium severity and one alert per incident. The inputs were synthetic. No sessions were revoked and no accounts were disabled. Live response is pending an isolated tenant deployment with dedicated test users and an Azure subscription in that tenant.

The `logic-identity-lab-dry-run` Consumption Logic App was deployed to `rg-identity-lab-playbooks` in West US 3. Its saved workflow has a Sentinel incident trigger and a Compose action that records the incident title, incident number, and dry-run disposition. Sentinel authorization, automation-rule attachment, and run-history verification are pending.
