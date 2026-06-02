<#
.SYNOPSIS
    Point Windows DNS at the local Prompt Gate resolver (127.0.0.1), or
    restore DHCP-provided DNS.

.DESCRIPTION
    Updates the IPv4 DNS server addresses for every "Up" network adapter so
    DNS queries flow through the Prompt Gate agent. Restore mode hands
    DNS back to DHCP.

.PARAMETER Mode
    'apply' (default) — set DNS servers to 127.0.0.1
    'restore'         — clear static DNS, fall back to DHCP

.EXAMPLE
    PS> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    PS> .\configure-dns.ps1 apply
    PS> .\configure-dns.ps1 restore

.NOTES
    Must be run from an elevated PowerShell session (Administrator).
#>

[CmdletBinding()]
param(
    [ValidateSet('apply','restore')]
    [string]$Mode = 'apply',
    [string]$DnsIP = '127.0.0.1'
)

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error 'configure-dns.ps1 must be run from an elevated PowerShell session.'
        exit 1
    }
}

function Get-ActiveAdapters {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object Status -EQ 'Up'
}

function Apply-DNS([string]$ip) {
    Get-ActiveAdapters | ForEach-Object {
        Write-Host "prompt-gate: setting DNS for '$($_.Name)' -> $ip"
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $ip
    }
}

function Restore-DNS {
    Get-ActiveAdapters | ForEach-Object {
        Write-Host "prompt-gate: restoring DHCP DNS for '$($_.Name)'"
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
    }
}

Assert-Admin
switch ($Mode) {
    'apply'   { Apply-DNS $DnsIP }
    'restore' { Restore-DNS }
}
