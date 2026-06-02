# scripts/windows/install-ca.ps1
#
# Trust (or untrust) the Prompt Gate per-device Root CA in the local
# machine "Root" store. Edge, Chrome, and most other Windows TLS
# clients use this store; Firefox keeps its own trust pool, so the
# user is also reminded to import the cert there if they use it.
#
# Usage (elevated PowerShell):
#   .\install-ca.ps1 -Install -CaPath C:\path\to\ca.crt
#   .\install-ca.ps1 -Remove  -CaPath C:\path\to\ca.crt

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Remove,
    [Parameter(Mandatory = $true)]
    [string]$CaPath
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $principal = New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "install-ca.ps1: re-run from an elevated (Administrator) PowerShell."
        exit 1
    }
}

function Install-Ca {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error "install-ca.ps1: cert not found at $Path"
        exit 1
    }
    Write-Host "prompt-gate: trusting $Path in the Root store"
    & certutil.exe -addstore -f "Root" $Path | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "install-ca.ps1: certutil -addstore failed (exit $LASTEXITCODE)."
        exit $LASTEXITCODE
    }
    Write-Host "prompt-gate: CA installed."
    Write-Host "(Reminder: Firefox uses its own trust store. Settings -> Privacy and Security -> Certificates -> View Certificates -> Import.)"
}

function Remove-Ca {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "install-ca.ps1: cert path $Path not found; will attempt removal by Subject CN."
    } else {
        Write-Host "prompt-gate: removing trust for $Path"
        & certutil.exe -delstore "Root" "Prompt Gate Local CA" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "install-ca.ps1: certutil -delstore returned $LASTEXITCODE (entry may already be gone)."
        }
    }
    Write-Host "prompt-gate: CA removed."
}

Assert-Admin

if (-not ($Install -xor $Remove)) {
    Write-Error "Specify exactly one of -Install or -Remove."
    exit 2
}

if ($Install) {
    Install-Ca -Path $CaPath
} else {
    Remove-Ca -Path $CaPath
}
