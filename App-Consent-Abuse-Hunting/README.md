# App Consent Abuse Hunting — Microsoft Sentinel Workbook

A Microsoft Sentinel / Azure Monitor workbook and companion KQL pack for hunting **OAuth application consent abuse** in Microsoft Entra ID.

The central question it answers: *what did applications actually do — on behalf of users (delegated) or as themselves (app-only) — using the consents they already hold?*

Most consent-abuse tooling stops at "who consented to what." That is the root cause, but not the damage. This workbook carries the investigation forward from the consent grant to the mail the app sent, the directory objects it changed, and — where `MicrosoftGraphActivityLogs` is enabled — the individual token that did it.

| | |
|---|---|
| **Platform** | Microsoft Sentinel / Log Analytics (also loads in Azure Monitor workbooks) |
| **Author** | Uğur Güdekli |
| **Files** | `App-Consent-Abuse-Hunting.workbook.json`, `app-consent-abuse-hunting.kql` |

---

## Contents

- [Threat model](#threat-model)
- [Data requirements](#data-requirements)
- [Deployment](#deployment)
- [Workbook walkthrough](#workbook-walkthrough)
- [KQL pack](#kql-pack)
- [Tuning and known limitations](#tuning-and-known-limitations)
- [MITRE ATT&CK coverage](#mitre-attck-coverage)

---

## Threat model

The workbook is built around the illicit-consent-grant kill chain:

1. **Grant.** A user is phished into consenting to a malicious multi-tenant app, or an attacker who already holds a privileged role grants admin consent. Increasingly the grant arrives via **device-code** or **QR-code** phishing, where the victim authenticates a device the attacker controls.
2. **Persist.** The app now holds a refresh token or an application permission. This survives password resets and, for app-only permissions, survives the user entirely.
3. **Act.** The app reads and sends mail, exfiltrates files, adds its own credentials, or assigns directory roles — all as legitimate, fully-authenticated API traffic.

Step 3 is the part that is usually invisible. Sign-in logs show the app authenticated; they do not show what it then did. `MicrosoftGraphActivityLogs` closes that gap, and this workbook is largely an interface onto that table.

Two distinctions drive every query:

- **Delegated vs app-only.** In `MicrosoftGraphActivityLogs`, an empty `UserId` means the call was app-only — the app acting under its own application permissions (`Roles`). A populated `UserId` means delegated — the app acting on behalf of that user under consented scopes (`Scopes`). These have very different blast radii and very different remediation.
- **Grant vs use.** A high-risk permission that was granted but never exercised is a hygiene problem. The same permission showing write traffic is an incident.

---

## Data requirements

Enable these in **Entra ID → Diagnostic settings**, exporting to the Sentinel workspace:

| Table | Feeds | Required |
|---|---|---|
| `AuditLogs` | Consents, grants, app-initiated directory changes | **Yes** |
| `MicrosoftGraphActivityLogs` | All app-activity, mail, admin-write and token-chain views | **Yes** for tabs 2–5 |
| `SigninLogs` | App name lookup, device-code sign-ins | Recommended |
| `AADNonInteractiveUserSignInLogs` | App name lookup, device-code sign-ins, token chain | Recommended |
| `AADServicePrincipalSignInLogs` | App name lookup, app-only sign-in baseline | Recommended |
| `OfficeActivity` | Exchange sends outside Graph (EWS, REST, SMTP OAuth) | Optional — needs the Office 365 connector |

`MicrosoftGraphActivityLogs` is the one to check first. It is not on by default, it is billed as analytics data, and it is high volume in most tenants. Without it, tabs 2 through 5 return nothing and the workbook reduces to a consent-grant report.

Missing tables are tolerated rather than fatal: the queries use `union isfuzzy=true` and `column_ifexists()` throughout, so a workbook in a partially-onboarded tenant renders with empty panels instead of errors.

---

## Deployment

**Portal (quickest):**

1. Microsoft Sentinel → your workspace → **Workbooks** → **Add workbook**.
2. Open the **Advanced editor** (`</>` icon).
3. Replace the contents with `App-Consent-Abuse-Hunting.workbook.json`, click **Apply**, then **Save**.

**As an ARM template:** wrap the JSON in a `Microsoft.Insights/workbooks` resource with `serializedData` set to the stringified file, and `category` set to `sentinel`.

Then set the **Time range** and, optionally, paste an AppId into **App filter** — see the [limitations](#tuning-and-known-limitations) note on which tabs honour that filter.

**Hide known Microsoft apps** (default **Yes**) removes noisy first-party service principals — Office 365 Portal, Teams Services, Azure MFA, Identity Protection, Device Registration Service, Managed Service Identity — from the App activity and both Admin actions panels. Set it to **No** to see everything. See [Microsoft app exclusions](#microsoft-app-exclusions) before relying on it.

---

## Workbook walkthrough

### Overview

Five headline counts over the selected range — consents and grants, mail sent by apps via Graph, admin writes via Graph, Entra changes initiated by apps, and successful device-code sign-ins — followed by a timechart splitting Graph **write** calls into delegated and app-only.

The tiles are a triage surface, not a detection. Read the timechart for shape rather than volume:

- A spike in **delegated writes** from an app nobody recognises, landing shortly after a phishing wave, is the device-code / QR-code pattern.
- A spike in **app-only writes** points at an application permission — `Mail.Send`, `RoleManagement.ReadWrite.Directory` — or at a stolen client secret.

### 1. Consents

The root cause. Pulls `AuditLogs` for `Consent to application`, `Add delegated permission grant`, and `Add app role assignment to service principal`.

The interesting work is in the `mv-apply`: `TargetResources[0].modifiedProperties` is flattened into a property bag so the granted permission string can be lifted out of whichever field carries it — `ConsentAction.Permissions` for interactive consent, `DelegatedPermissionGrant.Scope` for a direct grant, `AppRole.Value` for an app-role assignment. Those three shapes are why a naive query misses grants.

Output surfaces the actor and actor IP, the target app, whether it was **admin** consent (`ConsentContext.IsAdminConsent`), and a `HighRisk` flag set when the permission string matches the shared high-risk list. Rows sort high-risk first.

Triage order: admin consent on a high-risk permission, then user consent on a high-risk permission, then anything granted from an unfamiliar IP.

### 2. App activity

One row per app per access type, from `MicrosoftGraphActivityLogs`. Aggregates call volume, write count, failure count, distinct users, distinct source IPs, and — importantly — `PermissionsUsed`, the set of `Scopes` or `Roles` **actually presented** on those calls.

That last column is what makes this tab worth more than an app inventory. Entra tells you what an app *may* do; this tells you what it *did*. An app holding `Mail.ReadWrite` that has never presented it is a cleanup ticket. The same app presenting it on POST traffic is an investigation.

`FailedCalls` is a useful secondary signal: a high 4xx rate alongside broad URI coverage reads as enumeration — an attacker probing what a stolen token can reach.

### 3. Mail sent by apps

Two panels, deliberately overlapping, because neither source is complete alone.

**Graph sends** matches `POST` against `sendMail`, `send`, `reply`, `replyAll` and `forward`, extracting the target mailbox from `/users/{id}/` in the request URI. The `AccessType` split matters here: app-only mail sends are rarely legitimate outside a known service account, and should be treated as high-signal.

**Exchange sends** covers `Send`, `SendAs` and `SendOnBehalf` in `OfficeActivity`, catching EWS, Outlook REST and SMTP-OAuth traffic that never touches Graph. Five first-party client IDs (OWA, Microsoft Office, Outlook Mobile, One Outlook, Teams) are allowlisted out. Results are aggregated by calling app with a distinct-mailbox count, so one app touching many mailboxes rises to the top — the worm shape.

**The allowlist is the weak point, and it is a deliberate tradeoff.** Device-code phishing typically reuses *first-party* client IDs, which means a real attack can be sitting in the rows this panel just filtered away. Always corroborate with tab 5 rather than reading this panel as exhaustive.

### 4. Admin actions by apps

**Entra audit** returns `AuditLogs` entries where `InitiatedBy.app` is populated — changes made by a service principal with no user in the loop. A `Sensitive` flag marks role assignments, credential additions, application and service-principal ownership changes, password resets, domain federation changes, and Conditional Access edits.

Two of those deserve specific attention. `Add service principal credentials` is how an attacker converts a delegated foothold into durable app-only access — they add their own secret or certificate to an existing trusted app. `Set federation settings on domain` is the federated-trust backdoor; it is rare enough in most tenants that any hit warrants a look.

**Graph admin writes** catches the same intent one layer down, including delegated calls the audit log attributes to the user rather than the app. The URI regex covers `roleManagement`, `directoryRoles`, `oauth2PermissionGrants`, `appRoleAssignments`, `addPassword`, `addKey`, `federatedIdentityCredentials`, `identity/conditionalAccess`, `policies`, `domains`, `authentication/methods` and `owners`.

Run both. The audit panel tells you what changed; the Graph panel tells you which token changed it.

### 5. Device-code chain

The tab the rest of the workbook builds toward, and the one that turns a suspicion into a timeline.

The first panel simply lists device-code sign-ins. The second correlates them end to end:

1. Union `SigninLogs` and `AADNonInteractiveUserSignInLogs`, deriving a `SessionKey` from `SessionId` — falling back to `UniqueTokenIdentifier` where `SessionId` is not populated.
2. Select successful device-code sessions (`AuthenticationProtocol =~ "deviceCode"`, or `OriginalTransferMethod =~ "deviceCodeFlow"`).
3. Collect **every** token issued in those sessions — this is the step that follows refresh-token descendants, so activity from tokens minted hours after the original phish still attributes back.
4. Join `MicrosoftGraphActivityLogs` on `SignInActivityId == UniqueTokenIdentifier` and summarise what each session did.

The result is one row per compromised session: the phish time and IP, the app used, the Graph IPs that followed, a set of the distinct actions taken, and a `MailSends` count.

**Rows with `MailSends > 0` are the strongest single indicator in this workbook** — a successful device-code authentication whose token then sent mail is the self-propagating QR-code phish, and it is very hard to explain benignly.

A caveat on step 3: the fallback to `UniqueTokenIdentifier` when `SessionId` is empty narrows the chain to the device-code token itself, so refresh-token descendants are lost for those sessions. Sessions with a populated `SessionId` give the full picture; treat a thin result as possibly incomplete rather than as an all-clear.

---

## KQL pack

`app-consent-abuse-hunting.kql` holds the same logic as standalone queries for the Logs blade, ad-hoc hunting, or as a starting point for analytics rules. It is a **superset** of the workbook: sections 1–6 mirror the tabs, and section 7 has no workbook equivalent.

**Section 7 — app-only sign-in baseline.** Builds a per-app set of known source IPs from `ago(30d) .. ago(Lookback)`, then diffs the current window against it with `set_difference()` to surface service principals authenticating from IPs they have never used. This is the cheapest available detection for a stolen client secret: the app is unchanged and its permissions are unchanged, but it is suddenly signing in from somewhere new. Worth promoting to a scheduled rule once the baseline is tuned.

**Section 0a — app actor discovery.** Lists every app that initiated changes in `AuditLogs` over 30 days, with its `AppId`, its tenant-specific `ServicePrincipalId`, and whether it is already excluded. Use it to populate `ExcludedMsSPIds` (see [Microsoft app exclusions](#microsoft-app-exclusions)).

Each query is self-contained apart from the shared `let` block at the top (`Lookback`, `HighRiskPerms`, `ExcludedMsApps`, `ExcludedMsSPIds`, `AppNames`) — paste that above whichever query you are running.

---

## Tuning and known limitations

Read this section before treating any panel as authoritative.

**The App filter does not apply to every tab.** The workbook header says it pivots every tab; in the current version it is honoured by the overview timechart, app activity, both mail panels, and both admin panels — but **not** by the overview tiles, the Consents tab, the device-code list, or the token-to-action chain. Those four render unfiltered. Either read them as tenant-wide, or add `| where AppId == AppFilter` before relying on the filter there.

**`HighRiskPerms` matching is term-based.** `has_any` tokenises on `.`, so `Mail.Read` does not match `Mail.ReadWrite` — both are listed explicitly for that reason. Any permission you add to the list should be added in full, and newly-introduced Graph permissions will not be flagged until the list is updated.

**The Exchange allowlist hides real attacks.** See tab 3. It is tuned to cut noise, not to be safe. Widen it only with evidence, and never read that panel in isolation.

**`UniqueTokenId` in KQL section 3.** That column is projected from `MicrosoftGraphActivityLogs`, where the token identifier is `SignInActivityId`; `UniqueTokenIdentifier` belongs to the sign-in tables. Verify against your workspace schema and drop the column if the query errors. The workbook version of the same query omits it and is unaffected.

**`Lookback` versus `{TimeRange}`.** The KQL pack is fixed at `Lookback = 14d`, while the workbook is driven by the time-range parameter. The `AppNames` lookup is pinned to `ago(30d)` in both, independent of the selected range — an app that last signed in more than 30 days ago will show its AppId with a blank name rather than being dropped.

**Cost.** `MicrosoftGraphActivityLogs` is high-volume. Narrow the time range before opening the workbook on a large tenant, and expect the token-chain query to be the most expensive panel — it unions the sign-in tables and performs two joins.

**Tune before alerting.** Every threshold and allowlist here is written for interactive hunting. Baseline your own tenant's normal app behaviour before promoting any of these to an analytics rule.

### Microsoft app exclusions

Two lists drive the **Hide known Microsoft apps** toggle:

- `ExcludedMsApps` — well-known first-party **AppIds**, identical in every tenant. Applied to App activity (tab 2), Entra audit and Graph admin writes (tab 4).
- `ExcludedMsSPIds` — **empty by default.** `AuditLogs` often records first-party actors with a null `appId` and only a `servicePrincipalId`, which is unique to your tenant. Run KQL section 0a, confirm each candidate with `Get-MgServicePrincipal -Filter "appId eq '<appId>'"`, then paste the object IDs into this list in every query that declares it. Only the Entra audit panel uses it.

The exclusion is a noise filter, not a trust decision. An attacker who adds credentials to a first-party service principal, or abuses a managed identity, disappears from these panels while the toggle is on. Switch it to **No** during an active investigation. Overview, Consents, Mail and Device-code chain panels are not filtered.

---

## MITRE ATT&CK coverage

| Technique | Where |
|---|---|
| **T1528** — Steal Application Access Token | Tabs 1, 5 |
| **T1550.001** — Use Alternate Authentication Material: Application Access Token | Tabs 2, 5 |
| **T1098.001** — Account Manipulation: Additional Cloud Credentials | Tab 4 |
| **T1098.003** — Account Manipulation: Additional Cloud Roles | Tab 4 |
| **T1114.002** — Email Collection: Remote Email Collection | Tab 3 |
| **T1566** — Phishing (device-code / QR-code delivery) | Tab 5 |
| **T1484.002** — Domain Trust Modification | Tab 4 |

---

## Contributing

Issues and pull requests are welcome, particularly additions to `HighRiskPerms`, refinements to the Exchange client allowlist, and detections for consent-abuse paths not yet covered.

## Disclaimer

Provided as-is, with no warranty. These queries are hunting aids, not validated detections — test them in your own tenant and tune the allowlists and thresholds before acting on the results or promoting them to alerts.
