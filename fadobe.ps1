<#
.SYNOPSIS
    Blocks Adobe auto-update/telemetry, removes Adobe Genuine Service, and
    tombstones the AGS folder so it cannot be reinstalled. RMM-deployable.

.DESCRIPTION
    Stages:
      1. Hosts file blackhole (marker-delimited, safe to re-run)
      2. Windows Firewall outbound block on updater binaries
      3. Registry policy disabling in-app update checks
      4. Kill AGS/ARM processes, delete services, remove scheduled tasks
      5. Tombstone the AGS folder: empty dir + deny-write ACL

    Does NOT block Adobe licensing/activation endpoints. Blocking those
    breaks sign-in and entitlement on legitimately licensed machines.

.PARAMETER Rollback
    Reverses all five stages, including unlocking the tombstoned folder.

.PARAMETER SkipHosts
    Skip hosts modification (use if DNS filtering handles it upstream).

.PARAMETER SkipFirewall
    Skip firewall rule creation.

.PARAMETER SkipTombstone
    Apply removal but leave the AGS folder writable. Use on machines where
    a future clean Acrobat reinstall is expected.

.NOTES
    Exit codes: 0 = success, 1 = not elevated, 2 = partial failure
    Rollback of the tombstone requires taking ownership; handled automatically.
#>

[CmdletBinding()]
param(
    [switch]$Rollback,
    [switch]$SkipHosts,
    [switch]$SkipFirewall,
    [switch]$SkipTombstone
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0
$MarkerStart = '# --- BEGIN ADOBE UPDATE BLOCK (managed) ---'
$MarkerEnd   = '# --- END ADOBE UPDATE BLOCK (managed) ---'
$HostsPath   = "$env:SystemRoot\System32\drivers\etc\hosts"

# Well-known SIDs - locale independent, safe on non-English Windows
$SidEveryone = '*S-1-1-0'
$SidAdmins   = '*S-1-5-32-544'

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO')
    Write-Output ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message)
}

# ---------------------------------------------------------------------------
# TARGETS
# ---------------------------------------------------------------------------

$UpdateDomains = @(
    'swupdl.adobe.com','swupmf.adobe.com','swupdate.adobe.com','armmf.adobe.com'
    'ardownload.adobe.com','ardownload2.adobe.com','ardownload3.adobe.com'
    'ccmdl.adobe.com','ccmdls.adobe.com'
    'prod-rel-ffc-ccm.oobesaas.adobe.com','oobesaas.adobe.com'
    'nastatic.adobe.com','crl.adobe.com'
)

$TelemetryDomains = @(
    'genuine.adobe.com','cc-api-data.adobe.io','gocart-web.adobe.io'
    'assets.adobedtm.com'
    'adobe-dns.adobe.com','adobe-dns-2.adobe.com','adobe-dns-3.adobe.com','adobe-dns-4.adobe.com'
    'na1r.services.adobe.com','na2m-pr.licenses.adobe.com','hlrcv.stage.adobe.com'
    'wip.adobe.com','wip1.adobe.com','wip2.adobe.com','wip3.adobe.com','wip4.adobe.com'
    'ereg.adobe.com','activate.wip.adobe.com','geo2.adobe.com','stats.adobe.com'
)

# DO NOT ENABLE on licensed machines - activation/identity endpoints.
# Blocking these is what pirated-software hosts files do and will cause
# sign-in failure and reduced-functionality mode on a legitimate install.
$ActivationDomains = @(
    # 'practivate.adobe.com','activate.adobe.com','lm.licenses.adobe.com'
    # 'lmlicenses.wip4.adobe.com','ims-na1.adobelogin.com','auth.services.adobe.com'
)

$BlockDomains = ($UpdateDomains + $TelemetryDomains) | Sort-Object -Unique

$UpdaterBinaries = @(
    "$env:ProgramFiles\Common Files\Adobe\ARM\1.0\AdobeARM.exe"
    "$env:ProgramFiles\Common Files\Adobe\ARM\1.0\armsvc.exe"
    "$env:ProgramFiles\Common Files\Adobe\AdobeGCClient\AGSService.exe"
    "$env:ProgramFiles\Common Files\Adobe\AdobeGCClient\AGMService.exe"
    "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp\UWA\UpdaterStartupUtility.exe"
    "${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0\AdobeARM.exe"
    "${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0\armsvc.exe"
    "${env:ProgramFiles(x86)}\Common Files\Adobe\AdobeGCClient\AGSService.exe"
    "${env:ProgramFiles(x86)}\Common Files\Adobe\AdobeGCClient\AGMService.exe"
    "${env:ProgramFiles(x86)}\Common Files\Adobe\OOBE\PDApp\UWA\UpdaterStartupUtility.exe"
)

$KillProcesses = @(
    'AGSService','AGMService','AdobeGCClient','armsvc','AdobeARM'
    'AdobeNotificationClient','AdobeUpdateService','AdobeIPCBroker'
)

$KillServices = @('AGSService','AGMService','AdobeARMservice','AdobeUpdateService')

$KillTaskPatterns = @('AdobeGCInvoker*','Adobe Acrobat Update*','AdobeAAMUpdater*','Adobe Genuine*')

$AgsFolders = @(
    "$env:ProgramFiles\Common Files\Adobe\AdobeGCClient"
    "${env:ProgramFiles(x86)}\Common Files\Adobe\AdobeGCClient"
) | Sort-Object -Unique

# ---------------------------------------------------------------------------
# PREFLIGHT
# ---------------------------------------------------------------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Not running elevated. Aborting." -Level ERROR
    exit 1
}

Write-Log "Running as: $($identity.Name)"
Write-Log ("Mode: {0}" -f $(if ($Rollback) { 'ROLLBACK' } else { 'APPLY' }))

# ---------------------------------------------------------------------------
# STAGE 1: HOSTS
# ---------------------------------------------------------------------------

function Set-HostsBlock {
    if (-not (Test-Path $HostsPath)) {
        Write-Log "Hosts file not found at $HostsPath" -Level ERROR
        $script:Failures++
        return
    }

    $backup = "$HostsPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $HostsPath $backup -Force
    Write-Log "Hosts backed up to $backup"

    $inBlock = $false
    $kept = foreach ($line in (Get-Content $HostsPath)) {
        if ($line -eq $MarkerStart) { $inBlock = $true;  continue }
        if ($line -eq $MarkerEnd)   { $inBlock = $false; continue }
        if (-not $inBlock) { $line }
    }

    if ($Rollback) {
        Set-Content -Path $HostsPath -Value $kept -Encoding ASCII -Force
        Write-Log "Managed hosts block removed." -Level OK
        return
    }

    $new = New-Object System.Collections.Generic.List[string]
    $kept | ForEach-Object { $new.Add($_) }
    $new.Add($MarkerStart)
    $new.Add("# Applied $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - update/telemetry only, activation intact")
    foreach ($d in $BlockDomains) {
        $new.Add("0.0.0.0`t$d")
        $new.Add("::1`t$d")
    }
    $new.Add($MarkerEnd)

    Set-Content -Path $HostsPath -Value $new -Encoding ASCII -Force
    Write-Log "Hosts block applied: $($BlockDomains.Count) domains (IPv4 + IPv6)." -Level OK
}

# ---------------------------------------------------------------------------
# STAGE 2: FIREWALL
# ---------------------------------------------------------------------------

function Set-FirewallRules {
    $prefix = 'BLOCK-Adobe-Updater'

    Get-NetFirewallRule -DisplayName "$prefix*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    if ($Rollback) {
        Write-Log "Firewall rules removed." -Level OK
        return
    }

    # Rules are path-based, so they persist and still apply if Adobe later
    # reinstalls a binary to the same location.
    $count = 0
    foreach ($bin in ($UpdaterBinaries | Sort-Object -Unique)) {
        $arch = if ($bin -like '*(x86)*') { 'x86' } else { 'x64' }
        $name = "$prefix - $(Split-Path $bin -Leaf) ($arch)"
        try {
            New-NetFirewallRule -DisplayName $name `
                -Direction Outbound -Action Block -Program $bin `
                -Profile Any -Enabled True `
                -Description 'Managed: blocks Adobe updater outbound.' | Out-Null
            $count++
        }
        catch {
            Write-Log "Firewall rule failed for ${bin}: $($_.Exception.Message)" -Level WARN
            $script:Failures++
        }
    }
    Write-Log "Firewall rules created: $count." -Level OK
}

# ---------------------------------------------------------------------------
# STAGE 3: REGISTRY POLICY
# ---------------------------------------------------------------------------

function Set-UpdatePolicy {
    foreach ($p in @('Adobe Acrobat','Acrobat Reader')) {
        foreach ($v in @('DC','2017','2020','2024')) {
            $key = "HKLM:\SOFTWARE\Policies\Adobe\$p\$v\FeatureLockDown"
            try {
                if ($Rollback) {
                    if (Test-Path $key) {
                        Remove-ItemProperty -Path $key -Name 'bUpdater' -ErrorAction SilentlyContinue
                    }
                }
                else {
                    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                    New-ItemProperty -Path $key -Name 'bUpdater' -PropertyType DWord -Value 0 -Force | Out-Null
                }
            }
            catch {
                Write-Log "Policy write failed for ${p}/${v}: $($_.Exception.Message)" -Level WARN
                $script:Failures++
            }
        }
    }

    foreach ($k in @('HKLM:\SOFTWARE\Adobe\Adobe ARM\1.0\ARM',
                     'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe ARM\1.0\ARM')) {
        try {
            if ($Rollback) {
                if (Test-Path $k) { Remove-ItemProperty -Path $k -Name 'iCheck' -ErrorAction SilentlyContinue }
            }
            else {
                if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
                New-ItemProperty -Path $k -Name 'iCheck' -PropertyType DWord -Value 0 -Force | Out-Null
            }
        }
        catch {
            Write-Log "ARM policy failed for ${k}: $($_.Exception.Message)" -Level WARN
            $script:Failures++
        }
    }

    Write-Log ("Update policy {0}." -f $(if ($Rollback) {'reverted'} else {'applied'})) -Level OK
}

# ---------------------------------------------------------------------------
# STAGE 4: KILL AND REMOVE
# ---------------------------------------------------------------------------

function Remove-AdobeGenuineService {
    if ($Rollback) {
        Write-Log "Rollback does not reinstall AGS - reinstall Acrobat/CC if needed." -Level INFO
        return
    }

    $killed = 0
    foreach ($proc in $KillProcesses) {
        $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($running) {
            try {
                $running | Stop-Process -Force -ErrorAction Stop
                $killed++
                Write-Log "Killed process: $proc"
            }
            catch {
                Write-Log "Could not kill ${proc}: $($_.Exception.Message)" -Level WARN
                $script:Failures++
            }
        }
    }
    Write-Log "Processes terminated: $killed."

    $removed = 0
    foreach ($svc in $KillServices) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            try {
                if ($s.Status -ne 'Stopped') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
                $null = sc.exe delete $svc
                if ($LASTEXITCODE -eq 0) { $removed++; Write-Log "Deleted service: $svc" }
                else { Write-Log "sc delete returned $LASTEXITCODE for $svc" -Level WARN; $script:Failures++ }
            }
            catch {
                Write-Log "Service removal failed for ${svc}: $($_.Exception.Message)" -Level WARN
                $script:Failures++
            }
        }
    }
    Write-Log "Services deleted: $removed."

    $tasks = 0
    foreach ($pattern in $KillTaskPatterns) {
        Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
                $tasks++
                Write-Log "Removed task: $($_.TaskName)"
            }
            catch {
                Write-Log "Task removal failed for $($_.TaskName): $($_.Exception.Message)" -Level WARN
                $script:Failures++
            }
        }
    }
    Write-Log "Scheduled tasks removed: $tasks." -Level OK
}

# ---------------------------------------------------------------------------
# STAGE 5: TOMBSTONE THE AGS FOLDER
# ---------------------------------------------------------------------------

function Set-AgsTombstone {
    foreach ($folder in $AgsFolders) {

        if ($Rollback) {
            if (-not (Test-Path $folder)) { continue }
            try {
                # Deny ACE may block even admins, so take ownership first.
                $null = takeown.exe /f "$folder" /a /r /d Y
                $null = icacls.exe "$folder" /reset /t /c /q
                Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Tombstone removed and folder unlocked: $folder" -Level OK
            }
            catch {
                Write-Log "Unlock failed for ${folder}: $($_.Exception.Message)" -Level WARN
                $script:Failures++
            }
            continue
        }

        if ($SkipTombstone) { continue }

        try {
            # Wipe existing contents. Take ownership in case Adobe left
            # restrictive ACLs or TrustedInstaller owns the path.
            if (Test-Path $folder) {
                $null = takeown.exe /f "$folder" /a /r /d Y
                $null = icacls.exe "$folder" /reset /t /c /q
                Remove-Item "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                New-Item -Path $folder -ItemType Directory -Force | Out-Null
            }

            # Empty directory now occupies the path. Lock it so the installer
            # cannot write AGS binaries back into it.
            $null = icacls.exe "$folder" /inheritance:r /c /q
            $null = icacls.exe "$folder" /grant "${SidAdmins}:(OI)(CI)(RX)" /c /q
            $null = icacls.exe "$folder" /deny  "${SidEveryone}:(OI)(CI)(W,DE,DC)" /c /q

            Write-Log "Tombstoned and locked: $folder" -Level OK
        }
        catch {
            Write-Log "Tombstone failed for ${folder}: $($_.Exception.Message)" -Level WARN
            $script:Failures++
        }
    }
}

# ---------------------------------------------------------------------------
# EXECUTE
# ---------------------------------------------------------------------------

try {
    if (-not $SkipHosts)    { Set-HostsBlock }    else { Write-Log "Hosts layer skipped." }
    if (-not $SkipFirewall) { Set-FirewallRules } else { Write-Log "Firewall layer skipped." }
    Set-UpdatePolicy
    Remove-AdobeGenuineService
    Set-AgsTombstone

    ipconfig /flushdns | Out-Null
    Write-Log "DNS cache flushed."
}
catch {
    Write-Log "Fatal: $($_.Exception.Message)" -Level ERROR
    exit 2
}

# ---------------------------------------------------------------------------
# VERIFY
# ---------------------------------------------------------------------------

if (-not $Rollback) {
    $vHosts = Select-String -Path $HostsPath -Pattern 'ADOBE UPDATE BLOCK' -Quiet
    $vFw    = (Get-NetFirewallRule -DisplayName 'BLOCK-Adobe-Updater*' -ErrorAction SilentlyContinue).Count
    $vSvc   = @($KillServices | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }).Count
    $vLock  = @($AgsFolders | Where-Object { Test-Path $_ }).Count

    Write-Log "VERIFY hosts block present: $vHosts"
    Write-Log "VERIFY firewall rules: $vFw"
    Write-Log "VERIFY adobe services remaining: $vSvc (expect 0)"
    Write-Log "VERIFY tombstoned folders: $vLock"
}

if ($script:Failures -gt 0) {
    Write-Log "Completed with $($script:Failures) non-fatal failure(s)." -Level WARN
    exit 2
}

Write-Log "Completed successfully." -Level OK
exit 0