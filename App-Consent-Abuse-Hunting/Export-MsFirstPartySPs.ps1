<#
.SYNOPSIS
  Builds the Sentinel watchlist 'MsFirstPartySPs' used by the App Consent Abuse Hunting workbook.

.DESCRIPTION
  Finds every service principal in the target tenant whose app is owned by a Microsoft tenant
  (appOwnerOrganizationId), exports them to CSV, and optionally uploads the CSV as a
  Microsoft Sentinel watchlist. Run it once per tenant: service principal object IDs are
  tenant-specific, AppIds are global.

  Sign-in is pinned to -TenantId and isolated from the Windows / browser SSO session:
    - Windows account broker (WAM) sign-in is turned off for this process only
    - cached Az contexts and Azure CLI accounts on the machine are not used or changed
    - every token is checked: its 'tid' claim must equal the target tenant, or the script stops

  Works in Windows PowerShell 5.1 and PowerShell 7 and uses the first tool it finds:
    1. Az.Accounts module        2. Azure CLI        3. Microsoft.Graph module (CSV only)

.PARAMETER TenantId
  Required. Tenant ID (GUID) or a verified domain (contoso.onmicrosoft.com) of the tenant to export.

.PARAMETER WorkspaceResourceId
  Optional. Full resource ID of the Sentinel workspace, e.g.
  /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>
  If omitted, only the CSV is written.

.PARAMETER UseDeviceCode
  Optional. Sign in with a device code instead of a browser window. Useful when the browser
  keeps picking the wrong account. Note: Conditional Access may block device code flow.

.EXAMPLE
  .\Export-MsFirstPartySPs.ps1 -TenantId contoso.onmicrosoft.com
  .\Export-MsFirstPartySPs.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -WorkspaceResourceId "/subscriptions/.../workspaces/sentinel-ws"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]   $TenantId,
    [string]   $WorkspaceResourceId,
    [switch]   $UseDeviceCode,
    [string]   $Alias      = 'MsFirstPartySPs',
    [string]   $OutputPath = '.\MsFirstPartySPs.csv',
    # Microsoft-owned tenants that publish first-party apps. Add more if your review finds them.
    [string[]] $MicrosoftOwnerTenants = @(
        'f8cdef31-a31e-4b4a-93e4-5f571e91255a',   # Microsoft Services
        '72f988bf-86f1-41af-91ab-2d7cd011db47'    # Microsoft
    )
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 may default to old TLS versions
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$GraphUrl = 'https://graph.microsoft.com'
$ArmUrl   = 'https://management.azure.com'

# ---------------------------------------------------------------- resolve tenant to GUID
function Resolve-TenantGuid([string]$Tenant) {
    $g = [guid]::Empty
    if ([guid]::TryParse($Tenant, [ref]$g)) { return $g.ToString() }
    $cfg = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenant/v2.0/.well-known/openid-configuration"
    if ($cfg.issuer -match '([0-9a-fA-F-]{36})') { return $Matches[1].ToLower() }
    throw "Could not resolve tenant '$Tenant' to a tenant ID."
}
$TenantGuid = Resolve-TenantGuid $TenantId
Write-Host "Target tenant: $TenantGuid"

# ---------------------------------------------------------------- token checks
function Get-TokenTenant([string]$Jwt) {
    $payload = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    $claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
    return [pscustomobject]@{ Tid = [string]$claims.tid; User = [string]($claims.upn, $claims.unique_name, $claims.appid | Where-Object { $_ } | Select-Object -First 1) }
}

$script:TokenChecked = @{}
function Assert-TokenTenant([string]$Jwt, [string]$Resource) {
    if ($script:TokenChecked[$Resource]) { return }
    $info = Get-TokenTenant $Jwt
    if ($info.Tid -ne $TenantGuid) {
        throw "Token for $Resource was issued by tenant $($info.Tid) ($($info.User)), not the target tenant $TenantGuid. Stopping."
    }
    Write-Host "Token OK for $Resource  (tenant $($info.Tid), account $($info.User))"
    $script:TokenChecked[$Resource] = $true
}

# ---------------------------------------------------------------- sign-in providers
$script:Provider = $null   # 'Az' | 'Cli' | 'MgGraph'

function Test-AzAvailable  { [bool](Get-Module -ListAvailable -Name Az.Accounts) }
function Test-CliAvailable { [bool](Get-Command az -ErrorAction SilentlyContinue) }
function Test-MgAvailable  { [bool](Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) }

function Initialize-Az {
    Import-Module Az.Accounts -ErrorAction Stop
    # Isolate from cached contexts and the Windows account broker, for this process only
    Disable-AzContextAutosave -Scope Process | Out-Null
    try { Update-AzConfig -EnableLoginByWam $false -Scope Process | Out-Null } catch {}
    Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue
    $p = @{ TenantId = $TenantGuid; Scope = 'Process'; SkipContextPopulation = $true }
    if ($UseDeviceCode) { $p.UseDeviceAuthentication = $true }
    try { Connect-AzAccount @p | Out-Null }
    catch {
        # Older Az.Accounts versions do not know every parameter; retry only for that case
        if ($_.Exception.Message -notmatch 'parameter') { throw }
        $p.Remove('SkipContextPopulation'); $p.Remove('Scope')
        Connect-AzAccount @p | Out-Null
    }
    $ctx = Get-AzContext
    if (-not $ctx -or $ctx.Tenant.Id -ne $TenantGuid) { throw "Az signed in to tenant $($ctx.Tenant.Id), not $TenantGuid." }
}

function Initialize-Cli {
    # Private Azure CLI profile in a temp folder: existing CLI accounts are not used or changed
    $script:CliDir = Join-Path ([IO.Path]::GetTempPath()) ("az-msfp-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:CliDir -Force | Out-Null
    $env:AZURE_CONFIG_DIR = $script:CliDir
    $env:AZURE_CORE_ENABLE_BROKER_ON_WINDOWS = 'false'   # no WAM / Windows SSO
    $env:AZURE_CORE_LOGIN_EXPERIENCE_V2 = 'off'          # no interactive subscription picker
    $cliArgs = @('login', '--tenant', $TenantGuid, '--allow-no-subscriptions', '--only-show-errors', '--output', 'none')
    if ($UseDeviceCode) { $cliArgs += '--use-device-code' }
    & az @cliArgs
    if ($LASTEXITCODE -ne 0) { throw 'Azure CLI sign-in failed.' }
}

function Initialize-Mg {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    try { Set-MgGraphOption -DisableLoginByWAM $true } catch {}
    $p = @{ TenantId = $TenantGuid; Scopes = 'Application.Read.All'; ContextScope = 'Process'; NoWelcome = $true }
    if ($UseDeviceCode) { $p.UseDeviceCode = $true }
    Connect-MgGraph @p | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx -or $ctx.TenantId -ne $TenantGuid) { throw "Microsoft Graph signed in to tenant $($ctx.TenantId), not $TenantGuid." }
    Write-Host "Microsoft Graph context OK (tenant $($ctx.TenantId), account $($ctx.Account))"
}

function Select-Provider([switch]$NeedArm) {
    $errors = @()
    if (Test-AzAvailable) {
        try { Initialize-Az; $script:Provider = 'Az'; return } catch { $errors += "Az.Accounts: $($_.Exception.Message)" }
    }
    if (Test-CliAvailable) {
        try { Initialize-Cli; $script:Provider = 'Cli'; return } catch { $errors += "Azure CLI: $($_.Exception.Message)" }
    }
    if (-not $NeedArm -and (Test-MgAvailable)) {
        try { Initialize-Mg; $script:Provider = 'MgGraph'; return } catch { $errors += "Microsoft.Graph: $($_.Exception.Message)" }
    }
    $script:Provider = $null
    if ($errors) { Write-Warning ("Sign-in options failed:`n  " + ($errors -join "`n  ")) }
}

function Get-Token([string]$Resource) {
    switch ($script:Provider) {
        'Az' {
            $t = Get-AzAccessToken -ResourceUrl $Resource -TenantId $TenantGuid
            # Az.Accounts 5.x returns a SecureString, older versions a plain string
            if ($t.Token -is [System.Security.SecureString]) {
                $tok = [System.Net.NetworkCredential]::new('', $t.Token).Password
            } else { $tok = $t.Token }
        }
        'Cli' {
            $cliArgs = @('account', 'get-access-token', '--resource', $Resource, '--tenant', $TenantGuid, '--query', 'accessToken', '-o', 'tsv')
            $tok = (& az @cliArgs) | Select-Object -First 1
            if ($LASTEXITCODE -ne 0 -or -not $tok) { throw "Azure CLI could not get a token for $Resource" }
            $tok = $tok.Trim()
        }
        default { throw "No token provider for $Resource" }
    }
    Assert-TokenTenant $tok $Resource
    return $tok
}

function Get-StatusCode($err) {
    try { return [int]$err.Exception.Response.StatusCode } catch { return 0 }
}

function Invoke-Rest([string]$Method, [string]$Uri, [string]$Resource, [string]$Body) {
    $attempt = 0
    while ($true) {
        try {
            if ($script:Provider -eq 'MgGraph') {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType PSObject
            }
            $headers = @{ Authorization = "Bearer $(Get-Token $Resource)" }
            $p = @{ Method = $Method; Uri = $Uri; Headers = $headers }
            if ($Body) {
                $p.Body = [System.Text.Encoding]::UTF8.GetBytes($Body)
                $p.ContentType = 'application/json; charset=utf-8'
            }
            return Invoke-RestMethod @p
        } catch {
            $status = Get-StatusCode $_
            if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 5) {
                $attempt++; Start-Sleep -Seconds ([math]::Pow(2, $attempt)); continue
            }
            throw
        }
    }
}

function Remove-Session {
    switch ($script:Provider) {
        'Az'      { try { Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null } catch {} }
        'Cli'     { try { az logout --only-show-errors 2>$null; Remove-Item $script:CliDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
                    Remove-Item Env:AZURE_CONFIG_DIR -ErrorAction SilentlyContinue }
        'MgGraph' { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {} }
    }
}

try {
    # ------------------------------------------------------------ 1. export
    Select-Provider -NeedArm:([bool]$WorkspaceResourceId)
    if (-not $script:Provider -and $WorkspaceResourceId) { Select-Provider }   # at least get the CSV
    if (-not $script:Provider) {
        throw @'
No sign-in tool worked. Install ONE of these and run again:
  Install-Module Az.Accounts -Scope CurrentUser          (recommended, enables upload)
  winget install Microsoft.AzureCLI                      (also enables upload)
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   (CSV only)
'@
    }
    Write-Host "Using sign-in provider: $script:Provider"

    $select = 'id,appId,displayName,appOwnerOrganizationId'
    $uri = "$GraphUrl/v1.0/servicePrincipals?`$select=$select&`$top=999"
    $all = New-Object System.Collections.Generic.List[object]
    while ($uri) {
        $page = Invoke-Rest GET $uri $GraphUrl
        foreach ($sp in $page.value) { $all.Add($sp) }
        $uri = $page.'@odata.nextLink'
        Write-Host -NoNewline "`rRead $($all.Count) service principals..."
    }
    Write-Host ''

    $rows = $all |
        Where-Object { $MicrosoftOwnerTenants -contains [string]$_.appOwnerOrganizationId } |
        Sort-Object displayName |
        Select-Object @{ n = 'ServicePrincipalId';     e = { [string]$_.id } },
                      @{ n = 'AppId';                  e = { [string]$_.appId } },
                      @{ n = 'DisplayName';            e = { [string]$_.displayName } },
                      @{ n = 'AppOwnerOrganizationId'; e = { [string]$_.appOwnerOrganizationId } }

    if (-not $rows) { throw 'No Microsoft-owned service principals found. Check the target tenant.' }

    # Build the CSV in memory (no BOM, so the first header stays exactly 'ServicePrincipalId')
    $csvText = ($rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path (Get-Location) $OutputPath), $csvText, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Exported $(@($rows).Count) of $($all.Count) service principals (Microsoft-owned) to $OutputPath"

    # ------------------------------------------------------------ 2. upload (optional)
    $manual = "Upload manually: Sentinel > Configuration > Watchlist > New. Name/alias '$Alias', source: $OutputPath, search key 'ServicePrincipalId'."

    if (-not $WorkspaceResourceId) { Write-Host $manual; return }

    if ($script:Provider -eq 'MgGraph') {
        Write-Warning 'Upload needs Az.Accounts or Azure CLI; only the Graph module is available.'
        Write-Host $manual; return
    }

    $apiVersion = '2023-02-01'
    $wlUri = "$ArmUrl$WorkspaceResourceId/providers/Microsoft.SecurityInsights/watchlists/$($Alias)?api-version=$apiVersion"

    try {
        # A watchlist cannot be bulk-replaced in place, so delete the old one first
        $exists = $true
        try { $null = Invoke-Rest GET $wlUri $ArmUrl } catch { if ((Get-StatusCode $_) -eq 404) { $exists = $false } else { throw } }
        if ($exists) {
            Write-Host "Deleting existing watchlist '$Alias'..."
            $null = Invoke-Rest DELETE $wlUri $ArmUrl
            Start-Sleep -Seconds 30
        }

        $body = @{
            properties = @{
                displayName         = 'Microsoft first-party service principals'
                description         = "Microsoft-owned service principals in tenant $TenantGuid (by appOwnerOrganizationId). Generated $(Get-Date -Format s)."
                provider            = 'Custom'
                source              = 'MsFirstPartySPs.csv'
                itemsSearchKey      = 'ServicePrincipalId'
                contentType         = 'text/csv'
                numberOfLinesToSkip = 0
                rawContent          = $csvText
            }
        } | ConvertTo-Json -Depth 5

        $null = Invoke-Rest PUT $wlUri $ArmUrl $body
        Write-Host "Watchlist '$Alias' created. Items can take a few minutes to appear in the Watchlist table."
    } catch {
        Write-Warning "Watchlist upload failed (HTTP $(Get-StatusCode $_)): $($_.Exception.Message)"
        if ($_.ErrorDetails.Message) { Write-Warning $_.ErrorDetails.Message }
        Write-Host $manual
    }
}
finally {
    Remove-Session
}