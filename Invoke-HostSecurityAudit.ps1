<#
.SYNOPSIS
    Read-only Windows host security posture and tamper audit.

.DESCRIPTION
    Collects evidence about trust, traffic interception, persistence and endpoint
    posture on a single Windows host, then auto-triages each finding as
    HIGH / MED / INFO.

    This is a POSTURE AND TAMPER audit, not a vulnerability scanner. It answers
    "has something modified this machine's trust, traffic or persistence?"
    It does not enumerate CVEs in installed software.

    The tool is strictly read-only. It writes nothing outside its own output
    folder and changes no system state.

.PARAMETER OutputPath
    Directory to write the timestamped report folder into.
    Defaults to the current user's Desktop.

.PARAMETER Quiet
    Suppress console output; write report files only.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-HostSecurityAudit.ps1

.EXAMPLE
    pwsh -File .\Invoke-HostSecurityAudit.ps1 -OutputPath C:\Audits -Quiet

.NOTES
    Run elevated. Several checks (LSA configuration, WMI subscriptions,
    machine-scope certificate stores) return incomplete results without
    administrative rights; the report flags when this happens.

    Tested on Windows 10 / 11 and Windows Server 2019+ under Windows
    PowerShell 5.1 and PowerShell 7.x.
#>

[CmdletBinding()]
param(
    [string] $OutputPath = [Environment]::GetFolderPath('Desktop'),
    [switch] $Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Findings collection
# ---------------------------------------------------------------------------

$script:Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory)] [string] $Section,
        [Parameter(Mandatory)] [ValidateSet('HIGH', 'MED', 'INFO')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Title,
        [string] $Detail,
        [hashtable] $Data
    )
    $script:Findings.Add([pscustomobject]@{
        Section  = $Section
        Severity = $Severity
        Title    = $Title
        Detail   = $Detail
        Data     = $Data
    })
}

function Write-Status {
    param([string] $Message)
    if (-not $Quiet) { Write-Host "  [*] $Message" -ForegroundColor DarkGray }
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# Known-good public CA fragments
#
# Deliberately conservative. A root that does not match is reported for review,
# not condemned: enterprise-issued roots are legitimate and common. The point of
# this check is that anything in these registry keys was explicitly added by
# something, so it deserves a human look.
# ---------------------------------------------------------------------------

$script:KnownCaPatterns = @(
    'Microsoft', 'DigiCert', 'Baltimore CyberTrust', 'GlobalSign', 'Sectigo',
    'Comodo', 'Entrust', 'GeoTrust', 'GoDaddy', 'Thawte', 'VeriSign',
    'USERTrust', 'AddTrust', 'Certum', 'QuoVadis', 'SwissSign', 'T-TeleSec',
    'Starfield', 'Amazon Root CA', 'ISRG Root', 'Let''s Encrypt',
    'Google Trust Services', 'GTS Root', 'Actalis', 'Buypass', 'D-TRUST',
    'IdenTrust', 'SecureTrust', 'SSL.com', 'Hongkong Post', 'Network Solutions',
    'AAA Certificate Services', 'Certigna', 'Symantec', 'RSA Security'
)

function Test-KnownCa {
    param([string] $Subject)
    foreach ($pattern in $script:KnownCaPatterns) {
        if ($Subject -like "*$pattern*") { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# 1. Certificate trust audit
#
# Reads the registry locations where roots are EXPLICITLY added rather than
# enumerating Cert:\ , which would return several hundred inbox Microsoft roots
# and bury any real finding.
# ---------------------------------------------------------------------------

function Invoke-CertificateTrustAudit {
    Write-Status 'Auditing certificate trust'

    $scopes = @(
        @{ Name = 'Machine';    Path = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' }
        @{ Name = 'User';       Path = 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates' }
        @{ Name = 'GroupPolicy';Path = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates' }
        @{ Name = 'Enterprise'; Path = 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates' }
    )

    foreach ($scope in $scopes) {
        $thumbprints = Get-ChildItem -Path $scope.Path -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty PSChildName

        foreach ($tp in $thumbprints) {
            $cert = Get-ChildItem -Path 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root' |
                Where-Object { $_.Thumbprint -eq $tp } | Select-Object -First 1

            $subject = if ($cert) { $cert.Subject } else { '(unresolved)' }
            $expiry  = if ($cert) { $cert.NotAfter.ToString('yyyy-MM-dd') } else { 'unknown' }

            if (Test-KnownCa $subject) {
                Add-Finding -Section 'Certificate Trust' -Severity 'INFO' `
                    -Title "Recognized root ($($scope.Name)): $subject" `
                    -Detail "Thumbprint $tp, expires $expiry" `
                    -Data @{ Scope = $scope.Name; Thumbprint = $tp; Subject = $subject }
            }
            else {
                Add-Finding -Section 'Certificate Trust' -Severity 'HIGH' `
                    -Title "Unrecognized trusted root ($($scope.Name)): $subject" `
                    -Detail ("A root CA not matching any known public CA is explicitly trusted. " +
                             "Legitimate causes: corporate PKI, TLS-inspecting proxy, developer tooling. " +
                             "Illegitimate causes: adware, traffic interception. Thumbprint $tp, expires $expiry.") `
                    -Data @{ Scope = $scope.Name; Thumbprint = $tp; Subject = $subject }
            }
        }
    }

    # Injected intermediate CAs
    $caPaths = @(
        @{ Name = 'Machine'; Path = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates' }
        @{ Name = 'User';    Path = 'HKCU:\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates' }
    )
    foreach ($scope in $caPaths) {
        $count = (Get-ChildItem -Path $scope.Path -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($count -gt 0) {
            Add-Finding -Section 'Certificate Trust' -Severity 'INFO' `
                -Title "$count intermediate CA(s) present in $($scope.Name) store" `
                -Detail 'Review if the count is unexpected for this host.'
        }
    }

    # Self-signed certs in the Personal store are a common interception artifact
    $personal = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' |
        Where-Object { $_.Subject -eq $_.Issuer }
    foreach ($cert in $personal) {
        Add-Finding -Section 'Certificate Trust' -Severity 'MED' `
            -Title "Self-signed certificate in Personal store: $($cert.Subject)" `
            -Detail "Thumbprint $($cert.Thumbprint), expires $($cert.NotAfter.ToString('yyyy-MM-dd'))" `
            -Data @{ Thumbprint = $cert.Thumbprint; Subject = $cert.Subject }
    }
}

# ---------------------------------------------------------------------------
# 2. Traffic interception surface
# ---------------------------------------------------------------------------

function Invoke-ProxyAudit {
    Write-Status 'Auditing proxy and traffic redirection'

    $wininet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($wininet) {
        if ($wininet.PSObject.Properties.Name -contains 'ProxyEnable' -and $wininet.ProxyEnable -eq 1) {
            Add-Finding -Section 'Traffic' -Severity 'MED' `
                -Title 'WinINET proxy is enabled' `
                -Detail "ProxyServer = $($wininet.ProxyServer)" `
                -Data @{ ProxyServer = "$($wininet.ProxyServer)" }
        }
        if ($wininet.PSObject.Properties.Name -contains 'AutoConfigURL' -and $wininet.AutoConfigURL) {
            Add-Finding -Section 'Traffic' -Severity 'HIGH' `
                -Title 'PAC file configured (AutoConfigURL)' `
                -Detail ("A PAC URL can silently route selected traffic through an attacker-controlled host: " +
                         "$($wininet.AutoConfigURL)") `
                -Data @{ AutoConfigURL = "$($wininet.AutoConfigURL)" }
        }
    }

    $winhttp = netsh winhttp show proxy 2>$null | Out-String
    if ($winhttp -notmatch 'Direct access') {
        Add-Finding -Section 'Traffic' -Severity 'MED' `
            -Title 'WinHTTP proxy configured' -Detail $winhttp.Trim()
    }

    foreach ($var in 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY') {
        foreach ($scope in 'Machine', 'User') {
            $val = [Environment]::GetEnvironmentVariable($var, $scope)
            if ($val) {
                Add-Finding -Section 'Traffic' -Severity 'MED' `
                    -Title "$var set at $scope scope" -Detail $val
            }
        }
    }

    # Hosts file
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $entries = Get-Content $hostsPath -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^\s*[0-9a-fA-F:.]+\s+\S' -and $_ -notmatch '^\s*#' }
    foreach ($entry in $entries) {
        $severity = if ($entry -match '^\s*(127\.0\.0\.1|::1|0\.0\.0\.0)\s') { 'INFO' } else { 'HIGH' }
        Add-Finding -Section 'Traffic' -Severity $severity `
            -Title 'Hosts file entry' -Detail $entry.Trim()
    }
}

function Invoke-ListenerAudit {
    Write-Status 'Mapping local listeners to processes'

    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($l in $listeners) {
        $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }

        $sig = $null
        if ($proc.Path) { $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue }
        $signed = if ($sig -and $sig.Status -eq 'Valid') { $sig.SignerCertificate.Subject } else { 'UNSIGNED / unverified' }

        $localOnly = $l.LocalAddress -in @('127.0.0.1', '::1')
        $severity  = if ($signed -like 'UNSIGNED*') { 'MED' } elseif ($localOnly) { 'INFO' } else { 'INFO' }

        Add-Finding -Section 'Listeners' -Severity $severity `
            -Title "$($l.LocalAddress):$($l.LocalPort) -> $($proc.ProcessName)" `
            -Detail "PID $($l.OwningProcess), path $($proc.Path), signer: $signed" `
            -Data @{ Port = $l.LocalPort; Process = $proc.ProcessName; Path = "$($proc.Path)" }
    }
}

# ---------------------------------------------------------------------------
# 3. Browser policy abuse
# ---------------------------------------------------------------------------

function Invoke-BrowserPolicyAudit {
    Write-Status 'Checking browser policies'

    $browsers = @(
        @{ Name = 'Chrome'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome' }
        @{ Name = 'Edge';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' }
        @{ Name = 'Firefox';Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' }
    )

    $hotKeys = @('ProxySettings', 'ProxyMode', 'ProxyServer', 'ProxyPacUrl',
                 'AutoSelectCertificateForUrls', 'ExtensionInstallForcelist',
                 'ExtensionInstallSources')

    foreach ($browser in $browsers) {
        $props = Get-ItemProperty -Path $browser.Path -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($key in $hotKeys) {
            if ($props.PSObject.Properties.Name -contains $key) {
                $severity = if ($key -in @('AutoSelectCertificateForUrls', 'ExtensionInstallForcelist')) { 'HIGH' } else { 'MED' }
                Add-Finding -Section 'Browser Policy' -Severity $severity `
                    -Title "$($browser.Name) policy: $key" `
                    -Detail ($props.$key | Out-String).Trim()
            }
        }

        foreach ($sub in 'ExtensionInstallForcelist', 'AutoSelectCertificateForUrls') {
            $subKey = Get-ItemProperty -Path (Join-Path $browser.Path $sub) -ErrorAction SilentlyContinue
            if ($subKey) {
                $values = $subKey.PSObject.Properties |
                    Where-Object { $_.Name -notlike 'PS*' } |
                    ForEach-Object { "$($_.Name) = $($_.Value)" }
                if ($values) {
                    Add-Finding -Section 'Browser Policy' -Severity 'HIGH' `
                        -Title "$($browser.Name) $sub entries" -Detail ($values -join "`n")
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Persistence
# ---------------------------------------------------------------------------

function Invoke-PersistenceAudit {
    Write-Status 'Enumerating persistence mechanisms'

    # Run / RunOnce
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $runKeys) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object {
                $suspicious = $_.Value -match '(?i)(powershell|cmd\.exe|mshta|rundll32|wscript|cscript|regsvr32|-enc|-e[ncodma]* [A-Za-z0-9+/=]{40,})'
                Add-Finding -Section 'Persistence' -Severity $(if ($suspicious) { 'HIGH' } else { 'INFO' }) `
                    -Title "Autorun: $($_.Name)" `
                    -Detail "$key`n$($_.Value)" `
                    -Data @{ Key = $key; Name = $_.Name; Command = "$($_.Value)" }
            }
    }

    # Startup folders
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup')
        [Environment]::GetFolderPath('CommonStartup')
    )
    foreach ($folder in $startupFolders) {
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding -Section 'Persistence' -Severity 'MED' `
                -Title "Startup folder item: $($_.Name)" -Detail $_.FullName
        }
    }

    # Scheduled tasks not shipped by Microsoft
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        ForEach-Object {
            $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
            $lolbin  = $actions -match '(?i)(mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec.*http|-enc |-encodedcommand)'
            Add-Finding -Section 'Persistence' -Severity $(if ($lolbin) { 'HIGH' } else { 'INFO' }) `
                -Title "Scheduled task: $($_.TaskPath)$($_.TaskName)" `
                -Detail "Author: $($_.Author)`nActions: $actions" `
                -Data @{ Task = "$($_.TaskPath)$($_.TaskName)"; Actions = $actions }
        }

    # Services running from user-writable locations
    $writablePrefixes = @("$env:SystemDrive\Users", "$env:ProgramData", "$env:TEMP", "$env:PUBLIC")
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $path = $_.PathName
        if (-not $path) { return }
        foreach ($prefix in $writablePrefixes) {
            if ($path -like "*$prefix*") {
                Add-Finding -Section 'Persistence' -Severity 'HIGH' `
                    -Title "Service binary in user-writable path: $($_.Name)" `
                    -Detail "$path`nStart mode: $($_.StartMode), account: $($_.StartName)" `
                    -Data @{ Service = $_.Name; Path = $path }
                break
            }
        }
        # Unquoted service path with spaces
        if ($path -match '^[^"].*\s.*\.exe' -and $path -notmatch '^"') {
            Add-Finding -Section 'Persistence' -Severity 'MED' `
                -Title "Unquoted service path: $($_.Name)" -Detail $path
        }
    }

    # WMI event subscription persistence
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        if ($c.Name -match '^(SCM Event Log Consumer|BVTConsumer)$') { continue }
        Add-Finding -Section 'Persistence' -Severity 'HIGH' `
            -Title "WMI event consumer: $($c.Name)" `
            -Detail ($c | Out-String).Trim()
    }
}

# ---------------------------------------------------------------------------
# 5. Process posture
# ---------------------------------------------------------------------------

function Invoke-ProcessAudit {
    Write-Status 'Checking running processes'

    $oddPaths = @("$env:TEMP", "$env:APPDATA", "$env:ProgramData", "$env:PUBLIC")
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
        $proc = $_
        $sig = Get-AuthenticodeSignature $proc.Path -ErrorAction SilentlyContinue
        $unsigned = -not ($sig -and $sig.Status -eq 'Valid')
        $oddPath  = $false
        foreach ($p in $oddPaths) { if ($proc.Path -like "$p*") { $oddPath = $true; break } }

        if ($unsigned -or $oddPath) {
            $severity = if ($unsigned -and $oddPath) { 'HIGH' } else { 'MED' }
            Add-Finding -Section 'Processes' -Severity $severity `
                -Title "$($proc.ProcessName) (PID $($proc.Id))" `
                -Detail ("Path: $($proc.Path)`n" +
                         "Signature: $(if ($sig) { $sig.Status } else { 'none' })") `
                -Data @{ Process = $proc.ProcessName; Path = $proc.Path }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Endpoint posture
# ---------------------------------------------------------------------------

function Invoke-PostureAudit {
    Write-Status 'Collecting endpoint posture'

    $mp = Get-MpPreference -ErrorAction SilentlyContinue
    $ms = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if ($ms) {
        if (-not $ms.RealTimeProtectionEnabled) {
            Add-Finding -Section 'Posture' -Severity 'HIGH' -Title 'Defender real-time protection is OFF'
        }
        if ($ms.PSObject.Properties.Name -contains 'IsTamperProtected' -and -not $ms.IsTamperProtected) {
            Add-Finding -Section 'Posture' -Severity 'MED' -Title 'Defender tamper protection is OFF'
        }
        Add-Finding -Section 'Posture' -Severity 'INFO' `
            -Title "Defender signature age: $($ms.AntivirusSignatureAge) day(s)"
    }

    if ($mp) {
        foreach ($set in @(
            @{ Label = 'path';      Values = $mp.ExclusionPath }
            @{ Label = 'process';   Values = $mp.ExclusionProcess }
            @{ Label = 'extension'; Values = $mp.ExclusionExtension }
        )) {
            foreach ($v in $set.Values) {
                Add-Finding -Section 'Posture' -Severity 'HIGH' `
                    -Title "Defender $($set.Label) exclusion: $v" `
                    -Detail 'Exclusions are a classic tampering artifact. Confirm each one is policy-driven and expected.'
            }
        }
    }

    Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $_.Enabled) {
            Add-Finding -Section 'Posture' -Severity 'HIGH' -Title "Firewall profile disabled: $($_.Name)"
        }
    }

    $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue |
        Where-Object { $_.MountPoint -eq $env:SystemDrive }
    if ($bitlocker -and $bitlocker.ProtectionStatus -ne 'On') {
        Add-Finding -Section 'Posture' -Severity 'MED' `
            -Title "BitLocker not protecting $env:SystemDrive" -Detail "Status: $($bitlocker.ProtectionStatus)"
    }

    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    if ($uac -and $uac.PSObject.Properties.Name -contains 'EnableLUA' -and $uac.EnableLUA -ne 1) {
        Add-Finding -Section 'Posture' -Severity 'HIGH' -Title 'UAC is disabled (EnableLUA = 0)'
    }

    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    if (-not ($lsa -and $lsa.PSObject.Properties.Name -contains 'RunAsPPL' -and $lsa.RunAsPPL -ge 1)) {
        Add-Finding -Section 'Posture' -Severity 'MED' `
            -Title 'LSA protected process (RunAsPPL) not enabled' `
            -Detail 'Without LSA protection, credential theft from lsass.exe is materially easier.'
    }

    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq 'Enabled') {
        Add-Finding -Section 'Posture' -Severity 'HIGH' -Title 'SMBv1 is enabled'
    }

    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
    if ($ps2 -and $ps2.State -eq 'Enabled') {
        Add-Finding -Section 'Posture' -Severity 'MED' `
            -Title 'PowerShell v2 engine is enabled' `
            -Detail 'The v2 engine bypasses script block logging and AMSI.'
    }

    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    foreach ($a in $admins) {
        Add-Finding -Section 'Posture' -Severity 'INFO' `
            -Title "Local administrator: $($a.Name)" -Detail "Source: $($a.PrincipalSource)"
    }
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

function Write-Report {
    param([string] $Folder)

    $order = @{ HIGH = 0; MED = 1; INFO = 2 }
    $sorted = $script:Findings | Sort-Object @{ Expression = { $order[$_.Severity] } }, Section, Title

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('=' * 78)
    $lines.Add(' WINDOWS HOST SECURITY AUDIT')
    $lines.Add('=' * 78)
    $lines.Add("Computer     : $env:COMPUTERNAME")
    $lines.Add("User context : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)")
    $lines.Add("Elevated     : $(Test-Elevated)")
    $lines.Add("PS version   : $($PSVersionTable.PSVersion)")
    $lines.Add("Generated    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
    $lines.Add('')

    foreach ($sev in 'HIGH', 'MED', 'INFO') {
        $count = ($sorted | Where-Object Severity -eq $sev | Measure-Object).Count
        $lines.Add("  $sev`t$count finding(s)")
    }
    $lines.Add('')

    foreach ($sev in 'HIGH', 'MED', 'INFO') {
        $group = $sorted | Where-Object Severity -eq $sev
        if (-not $group) { continue }
        $lines.Add('')
        $lines.Add('-' * 78)
        $lines.Add(" $sev")
        $lines.Add('-' * 78)
        foreach ($f in $group) {
            $lines.Add("[$($f.Section)] $($f.Title)")
            if ($f.Detail) {
                foreach ($dl in ($f.Detail -split "`n")) { $lines.Add("    $dl") }
            }
            $lines.Add('')
        }
    }

    $txtPath  = Join-Path $Folder 'report.txt'
    $jsonPath = Join-Path $Folder 'report.json'

    $lines -join "`r`n" | Out-File -FilePath $txtPath -Encoding UTF8

    [pscustomobject]@{
        computer    = $env:COMPUTERNAME
        generated   = (Get-Date).ToString('o')
        elevated    = Test-Elevated
        psVersion   = $PSVersionTable.PSVersion.ToString()
        findings    = $sorted
    } | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

    return @{ Text = $txtPath; Json = $jsonPath }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not $Quiet) {
    Write-Host ''
    Write-Host '  Windows Host Security Audit' -ForegroundColor Cyan
    Write-Host '  Read-only. No system state is modified.' -ForegroundColor DarkGray
    Write-Host ''
}

if (-not (Test-Elevated)) {
    Add-Finding -Section 'Meta' -Severity 'MED' `
        -Title 'Audit ran without administrative rights' `
        -Detail 'Machine-scope certificate stores, LSA settings and WMI subscriptions may be incomplete.'
    if (-not $Quiet) {
        Write-Host '  [!] Not elevated - results will be incomplete.' -ForegroundColor Yellow
    }
}

Invoke-CertificateTrustAudit
Invoke-ProxyAudit
Invoke-ListenerAudit
Invoke-BrowserPolicyAudit
Invoke-PersistenceAudit
Invoke-ProcessAudit
Invoke-PostureAudit

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$folder = Join-Path $OutputPath "HostSecurityAudit-$env:COMPUTERNAME-$stamp"
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$paths = Write-Report -Folder $folder

if (-not $Quiet) {
    Write-Host ''
    foreach ($sev in 'HIGH', 'MED', 'INFO') {
        $count = ($script:Findings | Where-Object Severity -eq $sev | Measure-Object).Count
        $color = switch ($sev) { 'HIGH' { 'Red' } 'MED' { 'Yellow' } default { 'DarkGray' } }
        Write-Host ("  {0,-5} {1}" -f $sev, $count) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host "  Report: $($paths.Text)" -ForegroundColor Green
    Write-Host "  JSON  : $($paths.Json)" -ForegroundColor Green
    Write-Host ''
}
