# Install the Prompt Gate Native Messaging host manifest on Windows.
#
# Usage:
#   .\install.ps1 -ExtensionId <ID> [-AgentPath <C:\Path\To\prompt-gate-agent.exe>]
#
# Writes a host JSON to %LOCALAPPDATA%\PromptGate\NativeMessagingHosts\
# and registers it under
#   HKCU\Software\Google\Chrome\NativeMessagingHosts\com.shieldnet360.promptgate
# pointing at the JSON. Chrome's Native Messaging discovery reads that
# registry key on the next browser launch.

param(
    [Parameter(Mandatory=$true)]
    [string]$ExtensionId,

    [string]$AgentPath = "$env:ProgramFiles\PromptGate\prompt-gate-agent.exe"
)

$ErrorActionPreference = "Stop"

# Chrome's Native Messaging protocol invokes the host binary with the
# caller's chrome-extension://<id>/ origin as the only positional
# argument and offers no way to inject custom flags through the host
# manifest. The agent binary detects that calling convention in main()
# and routes to Native Messaging mode automatically, so the manifest
# "path" can point directly at the production daemon binary without
# a wrapper script.
$hostName  = "com.shieldnet360.promptgate"
$origin    = "chrome-extension://${ExtensionId}/"
$installDir = Join-Path $env:LOCALAPPDATA "PromptGate\NativeMessagingHosts"
$manifest  = Join-Path $installDir "${hostName}.json"

New-Item -ItemType Directory -Path $installDir -Force | Out-Null

$json = [ordered]@{
    name = $hostName
    description = "Prompt Gate DLP companion native messaging host"
    path = $AgentPath
    type = "stdio"
    allowed_origins = @($origin)
} | ConvertTo-Json -Depth 4

Set-Content -Path $manifest -Value $json -Encoding ASCII

# Register the manifest with Chrome (per-user; HKCU avoids needing
# admin). The default value of the key is the absolute path to the
# manifest JSON file.
$regKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
New-Item -Path $regKey -Force | Out-Null
Set-ItemProperty -Path $regKey -Name "(default)" -Value $manifest

Write-Host "Installed $hostName manifest to $manifest"
Write-Host "  agent binary: $AgentPath"
Write-Host "  origin:       $origin"
