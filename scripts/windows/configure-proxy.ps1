# scripts/windows/configure-proxy.ps1
#
# Toggle the per-user WinINET / Edge / Chrome HTTP(S) proxy to the
# local Prompt Gate MITM listener on 127.0.0.1:8443. Restore writes
# the prior state back. Firefox uses its own proxy settings; see
# Settings -> Network -> Connection Settings for that.
#
# Usage (regular user, not elevated):
#   .\configure-proxy.ps1 -Apply
#   .\configure-proxy.ps1 -Restore

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Restore
)

$ErrorActionPreference = "Stop"

$RegPath  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$BackupKey = "PromptGateProxyBackup"
$ProxyHost = $env:SECURE_EDGE_PROXY_HOST
if ([string]::IsNullOrEmpty($ProxyHost)) { $ProxyHost = "127.0.0.1" }
$ProxyPort = $env:SECURE_EDGE_PROXY_PORT
if ([string]::IsNullOrEmpty($ProxyPort)) { $ProxyPort = "8443" }
# WinINET supports a single ProxyServer value with per-scheme entries.
# https=...:port is what Edge/Chrome use for TLS; we set http=... too
# so plaintext fallbacks still hit our listener.
$ProxyServer = "http=$ProxyHost`:$ProxyPort;https=$ProxyHost`:$ProxyPort"

function Apply-Proxy {
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    # Stash existing values so Restore can put them back verbatim.
    $existingServer = (Get-ItemProperty -Path $RegPath -Name "ProxyServer" -ErrorAction SilentlyContinue).ProxyServer
    $existingEnable = (Get-ItemProperty -Path $RegPath -Name "ProxyEnable" -ErrorAction SilentlyContinue).ProxyEnable
    Set-ItemProperty -Path $RegPath -Name "$BackupKey`Server" -Value ([string]$existingServer)
    Set-ItemProperty -Path $RegPath -Name "$BackupKey`Enable" -Value ([int]($existingEnable | ForEach-Object { if ($_ -eq $null) { 0 } else { $_ } }))

    Set-ItemProperty -Path $RegPath -Name "ProxyServer" -Value $ProxyServer
    Set-ItemProperty -Path $RegPath -Name "ProxyEnable" -Value 1
    Write-Host "prompt-gate: WinINET proxy set to $ProxyServer"
    Write-Host "(Reminder: Firefox keeps its own proxy config; set HTTPS proxy to $ProxyHost:$ProxyPort in browser settings.)"
}

function Restore-Proxy {
    if (-not (Test-Path $RegPath)) {
        Write-Host "prompt-gate: no Internet Settings key found; nothing to restore."
        return
    }
    $bServer = (Get-ItemProperty -Path $RegPath -Name "$BackupKey`Server" -ErrorAction SilentlyContinue)."$BackupKey`Server"
    $bEnable = (Get-ItemProperty -Path $RegPath -Name "$BackupKey`Enable" -ErrorAction SilentlyContinue)."$BackupKey`Enable"

    if ($null -eq $bServer -or $bServer -eq "") {
        Remove-ItemProperty -Path $RegPath -Name "ProxyServer" -ErrorAction SilentlyContinue
    } else {
        Set-ItemProperty -Path $RegPath -Name "ProxyServer" -Value $bServer
    }
    if ($null -eq $bEnable) {
        Set-ItemProperty -Path $RegPath -Name "ProxyEnable" -Value 0
    } else {
        Set-ItemProperty -Path $RegPath -Name "ProxyEnable" -Value ([int]$bEnable)
    }
    Remove-ItemProperty -Path $RegPath -Name "$BackupKey`Server" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $RegPath -Name "$BackupKey`Enable" -ErrorAction SilentlyContinue
    Write-Host "prompt-gate: WinINET proxy restored."
}

if (-not ($Apply -xor $Restore)) {
    Write-Error "Specify exactly one of -Apply or -Restore."
    exit 2
}

if ($Apply)   { Apply-Proxy }
if ($Restore) { Restore-Proxy }
