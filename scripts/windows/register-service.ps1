<#
.SYNOPSIS
    Register the Prompt Gate Go agent as a Windows Service.

.DESCRIPTION
    Creates a Windows Service named "PromptGateAgent" that runs the agent
    binary with the bundled config. Equivalent shell-level command:

        sc.exe create PromptGateAgent ^
            binPath= "\"C:\Program Files\Prompt Gate\prompt-gate-agent.exe\" --config \"C:\ProgramData\Prompt Gate\config.yaml\"" ^
            start= auto ^
            DisplayName= "Prompt Gate Agent"

.PARAMETER Mode
    'install'   — create and start the service (default)
    'uninstall' — stop and remove the service

.EXAMPLE
    PS> .\register-service.ps1 install
    PS> .\register-service.ps1 uninstall

.NOTES
    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [ValidateSet('install','uninstall')]
    [string]$Mode = 'install',
    [string]$BinaryPath = 'C:\Program Files\Prompt Gate\prompt-gate-agent.exe',
    [string]$ConfigPath = 'C:\ProgramData\Prompt Gate\config.yaml',
    [string]$ServiceName = 'PromptGateAgent',
    [string]$DisplayName = 'Prompt Gate Agent'
)

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error 'register-service.ps1 must be run from an elevated PowerShell session.'
        exit 1
    }
}

function Install-Service {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "prompt-gate: service '$ServiceName' already exists; leaving it in place."
        return
    }
    $binPath = "`"$BinaryPath`" --config `"$ConfigPath`""
    Write-Host "prompt-gate: creating service '$ServiceName' -> $binPath"
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $DisplayName `
        -StartupType Automatic -Description 'Prompt Gate DNS + DLP agent.'
    Start-Service -Name $ServiceName
}

function Uninstall-Service {
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Host "prompt-gate: service '$ServiceName' not installed."
        return
    }
    Write-Host "prompt-gate: stopping and removing service '$ServiceName'"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
}

Assert-Admin
switch ($Mode) {
    'install'   { Install-Service }
    'uninstall' { Uninstall-Service }
}
