<#
.SYNOPSIS
  Builds the Sentinel watchlist 'MsFirstPartySPs' used by the App Consent Abuse Hunting workbook.
 
.DESCRIPTION
  Finds every service principal in the CURRENT tenant whose app is owned by a Microsoft tenant
  (AppOwnerOrganizationId), exports them to CSV, and optionally uploads the CSV as a
  Microsoft Sentinel watchlist. Run it in each tenant: service principal object IDs are
  tenant-specific, AppIds are global.
 
  The workbook and KQL pack work without this watchlist: when it is missing or empty,
  nothing is excluded and Microsoft apps are shown.
 
.PARAMETER WorkspaceResourceId
  Optional. Full resource ID of the Sentinel Log Analytics workspace, e.g.
  /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>
  If omitted, only the CSV is written (upload it in Sentinel > Watchlists > New,
  alias 'MsFirstPartySPs', search key 'ServicePrincipalId').
 
.EXAMPLE
  .\Export-MsFirstPartySPs.ps1
  .\Export-MsFirstPartySPs.ps1 -WorkspaceResourceId "/subscriptions/.../workspaces/sentinel-ws"
 
.NOTES
  Requires: Microsoft.Graph.Applications (Application.Read.All)
            Az.Accounts (only for upload; Microsoft Sentinel Contributor on the workspace)
#>
[CmdletBinding()]
param(
    [string]   $WorkspaceResourceId,
    [string]   $Alias      = 'MsFirstPartySPs',
    [string]   $OutputPath = '.\MsFirstPartySPs.csv',
    # Microsoft-owned tenants that publish first-party apps. Add more if your review finds them.
    [string[]] $MicrosoftOwnerTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',   # Microsoft Services
        '72f988bf-86f1-41af-91ab-2d7cd011db47'    # Microsoft
    )
)
 
$ErrorActionPreference = 'Stop'
 
# ---- 1. Collect Microsoft-owned service principals from Entra ID
Connect-MgGraph -Scopes 'Application.Read.All' -NoWelcome
$sps = Get-MgServicePrincipal -All -Property Id, AppId, DisplayName, AppOwnerOrganizationId, ServicePrincipalType |
       Where-Object { $MicrosoftOwnerTenants -contains $_.AppOwnerOrganizationId }
 
if (-not $sps) { throw 'No Microsoft-owned service principals found. Check the Graph connection and tenant.' }
 
$rows = $sps | Sort-Object DisplayName | Select-Object `
    @{ n = 'ServicePrincipalId';     e = { $_.Id } },
    AppId,
    DisplayName,
    AppOwnerOrganizationId
 
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($rows.Count) Microsoft service principals to $OutputPath"
 
# ---- 2. Optional: upload as a Sentinel watchlist
if (-not $WorkspaceResourceId) {
    Write-Host "Upload manually: Sentinel > Watchlists > New. Alias '$Alias', search key 'ServicePrincipalId'."
    return
}
 
if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
$apiVersion = '2023-02-01'
$path = "$WorkspaceResourceId/providers/Microsoft.SecurityInsights/watchlists/$($Alias)?api-version=$apiVersion"
 
# A watchlist cannot be bulk-replaced in place, so delete the old one first
$existing = Invoke-AzRestMethod -Method GET -Path $path
if ($existing.StatusCode -eq 200) {
    Write-Host "Deleting existing watchlist '$Alias'..."
    Invoke-AzRestMethod -Method DELETE -Path $path | Out-Null
    Start-Sleep -Seconds 30
}
 
$csv = (Get-Content -Path $OutputPath -Raw)
$body = @{
    properties = @{
        displayName         = 'Microsoft first-party service principals'
        description         = "Microsoft-owned service principals in this tenant (by AppOwnerOrganizationId). Generated $(Get-Date -Format s)."
        provider            = 'Custom'
        source              = 'MsFirstPartySPs.csv'
        itemsSearchKey      = 'ServicePrincipalId'
        contentType         = 'text/csv'
        numberOfLinesToSkip = 0
        rawContent          = $csv
    }
} | ConvertTo-Json -Depth 5
 
$resp = Invoke-AzRestMethod -Method PUT -Path $path -Payload $body
if ($resp.StatusCode -in 200, 201) {
    Write-Host "Watchlist '$Alias' created. Items can take a few minutes to appear in _GetWatchlist('$Alias')."
} else {
    Write-Warning "Upload failed ($($resp.StatusCode)): $($resp.Content)"
    Write-Host "Fallback: upload $OutputPath manually in Sentinel > Watchlists."
}