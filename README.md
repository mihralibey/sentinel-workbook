# Microsoft Sentinel Workbooks

A collection of Microsoft Sentinel / Azure Monitor workbooks for threat hunting and investigation in Microsoft Entra ID and Microsoft 365. Each workbook ships with a companion KQL pack so the same logic can be run ad hoc in the Logs blade or adapted into analytics rules.

## Workbooks

| Workbook | Focus | Key tables | MITRE ATT&CK |
|---|---|---|---|
| [App Consent Abuse Hunting](App-Consent-Abuse-Hunting/) | What OAuth apps did with the consents they hold: delegated vs app-only Graph activity, mail sent by apps, app-initiated admin changes, and device-code phishing token-to-action correlation | `AuditLogs`, `MicrosoftGraphActivityLogs`, `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `OfficeActivity` | T1528, T1550.001, T1098.001, T1098.003, T1114.002, T1566, T1484.002 |

## Repository layout

```
<Workbook-Name>/
    README.md                     # threat model, data requirements, walkthrough, limitations
    <Workbook-Name>.workbook.json # import via Sentinel > Workbooks > Advanced editor
    <workbook-name>.kql           # standalone hunting queries
```

## Importing a workbook

1. Microsoft Sentinel → your workspace → **Workbooks** → **Add workbook**.
2. Open the **Advanced editor** (`</>`).
3. Paste the contents of the `.workbook.json` file, click **Apply**, then **Save**.

Each workbook's README lists the diagnostic settings and data connectors it depends on. Check those first: missing tables render as empty panels, not errors.

## Contributing

Issues and pull requests are welcome, whether they're query improvements, false-positive tuning, or new workbooks. New workbooks should follow the layout above and include a README covering data requirements and known limitations.

## Disclaimer

Provided as-is, with no warranty. These are hunting aids, not validated detections. Test in your own tenant and tune allowlists and thresholds before acting on results or promoting queries to alerts.

## License

[MIT](LICENSE)
