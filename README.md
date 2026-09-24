# Sentinel Workbooks

Microsoft Sentinel workbooks I've built for threat hunting in Entra ID and Microsoft 365. Each one has its own folder with the workbook JSON, a README, and any setup scripts it needs.

## Workbooks

| Workbook | What it's for | Main tables |
|---|---|---|
| [App Consent Abuse Hunting](App-Consent-Abuse-Hunting/) | Follows OAuth apps from the consent they were given to what they did with it: Graph activity (delegated and app-only), mail sent, admin changes, and device-code phishing traced from sign-in to action | `AuditLogs`, `MicrosoftGraphActivityLogs`, sign-in logs, `OfficeActivity` |

## Adding a workbook to Sentinel

1. In Microsoft Sentinel, open **Workbooks** and click **Add workbook**.
2. Click **Edit**, then the **Advanced editor** (`</>`) button.
3. Paste the contents of the `.workbook.json` file, click **Apply**, then **Save**.

Read the workbook's README before you start. It lists the data connectors and diagnostic settings it depends on. Missing tables don't cause errors; the panels just come up empty.

## Folder layout

```
<Workbook-Name>/
    README.md
    <Workbook-Name>.workbook.json
    *.ps1        optional setup scripts
    images/      screenshots used in the README
```

## Contributing

Issues and pull requests are welcome, whether it's a query fix, false-positive tuning or a new workbook. New workbooks should follow the layout above and include a README covering what data they need and where they fall short.

## Disclaimer

Provided as is, no warranty. These are hunting aids, not tested detections. Try them in your own tenant and tune them before acting on the results or turning them into alerts.

## License

[MIT](LICENSE)
