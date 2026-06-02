# scripts/windows/full-uninstall.ps1
#
# Completely remove Prompt Gate from a Windows machine. This is the
# stand-alone, user-run teardown — distinct from uninstall.ps1, which is
# the MSI custom-action hook for the service variant only.
#
# Covers BOTH install shapes:
#   - Electron app (NSIS, per-user) + auto-spawned agent + per-user
#     "%USERPROFILE%\.prompt-gate" state.
#   - MSI / Windows-service variant (ProgramData\PromptGate).
#
# And every system side effect either shape can leave behind, matching
# scripts/macos/uninstall.sh and scripts/linux/uninstall.sh:
#   - stale prompt-gate-agent.exe processes
#   - a dangling WinINET (Edge/Chrome) proxy pointed at a dead agent
#   - custom DNS servers set on the active adapters
#   - the trusted "Prompt Gate Local CA" root cert in the LocalMachine\Root store
#
# Best-effort and idempotent.
#
# Usage (elevated PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\full-uninstall.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Assert-Admin {
    $principal = New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "full-uninstall.ps1: re-run from an elevated (Administrator) PowerShell."
        exit 1
    }
}

function Step($msg) { Write-Host "==> $msg" }

Assert-Admin

# ----------------------------------------------------------------------------
# 1. Stop the service and kill any auto-spawned agent / app.
# ----------------------------------------------------------------------------
Step "Stopping service and processes"
if (Get-Service -Name 'PromptGate' -ErrorAction SilentlyContinue) {
    Stop-Service -Name 'PromptGate' -Force -ErrorAction SilentlyContinue
    & sc.exe delete 'PromptGate' | Out-Null
}
foreach ($p in 'prompt-gate-agent', 'Prompt Gate') {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

# ----------------------------------------------------------------------------
# 2. Restore proxy + DNS while the helper scripts are still on disk.
#    Proxy lives in HKCU (per-user); run the restore in the invoking user's
#    context. When this script is launched elevated by the logged-in user,
#    HKCU is already theirs, so a direct restore is correct.
# ----------------------------------------------------------------------------
Step "Restoring WinINET proxy"
$proxyScript = Join-Path $here 'configure-proxy.ps1'
if (Test-Path $proxyScript) {
    & $proxyScript -Restore
} else {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name 'ProxyEnable' -Value 0 -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regPath -Name 'ProxyServer' -ErrorAction SilentlyContinue
    }
}

Step "Restoring DNS"
$dnsScript = Join-Path $here 'configure-dns.ps1'
if (Test-Path $dnsScript) {
    try { & $dnsScript -Action restore } catch {}
}

# ----------------------------------------------------------------------------
# 3. Untrust + remove the Root CA from the LocalMachine\Root store.
# ----------------------------------------------------------------------------
Step "Removing trusted Root CA 'Prompt Gate Local CA'"
& certutil.exe -delstore "Root" "Prompt Gate Local CA" 2>$null | Out-Null
# Belt-and-braces: drop any cert object still matching the subject.
Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like '*Prompt Gate Local CA*' } |
    ForEach-Object { Remove-Item -Path $_.PSPath -Force -ErrorAction SilentlyContinue }

# ----------------------------------------------------------------------------
# 4. Run the Electron NSIS uninstaller silently, if present.
# ----------------------------------------------------------------------------
Step "Removing Electron app (NSIS)"
$uninstallers = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\prompt-gate\Uninstall Prompt Gate.exe'),
    (Join-Path ${env:ProgramFiles} 'Prompt Gate\Uninstall Prompt Gate.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Prompt Gate\Uninstall Prompt Gate.exe')
)
foreach ($u in $uninstallers) {
    if ($u -and (Test-Path $u)) {
        Start-Process -FilePath $u -ArgumentList '/S' -Wait -ErrorAction SilentlyContinue
    }
}

# ----------------------------------------------------------------------------
# 5. Remove service-variant data + per-user state.
# ----------------------------------------------------------------------------
Step "Removing data directories"
$dataDir = Join-Path $env:ProgramData 'PromptGate'
if (Test-Path $dataDir) { Remove-Item -Recurse -Force -Path $dataDir -ErrorAction SilentlyContinue }

$userConfig = Join-Path $env:USERPROFILE '.prompt-gate'
if (Test-Path $userConfig) { Remove-Item -Recurse -Force -Path $userConfig -ErrorAction SilentlyContinue }

# Electron appData (NSIS deleteAppDataOnUninstall covers this when the
# uninstaller ran; remove directly in case it didn't).
$appData = Join-Path $env:APPDATA 'Prompt Gate'
if (Test-Path $appData) { Remove-Item -Recurse -Force -Path $appData -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "Prompt Gate fully uninstalled."
Write-Host "  - service stopped, processes killed, WinINET proxy + DNS restored"
Write-Host "  - Root CA 'Prompt Gate Local CA' removed from LocalMachine\Root"
Write-Host "  - app, service data, and %USERPROFILE%\.prompt-gate removed"
Write-Host ""
Write-Host "Note: Firefox keeps its own CA trust + the browser extension lives in"
Write-Host "the browser; remove those from Firefox / Edge / Chrome settings."
exit 0
