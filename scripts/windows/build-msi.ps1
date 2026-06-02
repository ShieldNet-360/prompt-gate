# Build a Prompt Gate MSI installer using WiX Toolset.
#
# This script is intended to run inside a GitHub Actions
# `windows-latest` runner (which already ships with WiX) but works on
# any Windows host with `wix` (v4) or candle/light (v3) on PATH.
#
# Inputs (environment or parameters):
#   -AgentExePath  Path to the freshly-built prompt-gate-agent.exe.
#   -Version       Product version (semver-style, e.g. 1.2.3).
#   -OutputPath    Where to write the .msi. Defaults to dist/windows/.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AgentExePath,
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\..\dist\windows')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $AgentExePath)) {
    throw "prompt-gate-agent.exe not found at: $AgentExePath"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$buildDir = Join-Path $repoRoot 'build\windows'
$wxsPath  = Join-Path $PSScriptRoot 'prompt-gate.wxs'
$rulesDir = Join-Path $repoRoot 'rules'

# Stage the rules folder so heat can harvest a stable component group.
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$rulesHarvest = Join-Path $buildDir 'rules.wxs'

if (Test-Path $rulesDir) {
    # `wix heat dir` generates a wxs fragment referencing every rule
    # file under rules/. The output is wired into RuleFiles by the main
    # wxs's ComponentGroupRef.
    wix heat dir $rulesDir `
        -srd `
        -gg `
        -sfrag `
        -cg RuleFiles `
        -dr RULESFOLDER `
        -var var.RulesSourceDir `
        -out $rulesHarvest
} else {
    Set-Content -Path $rulesHarvest -Encoding UTF8 -Value @'
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Fragment>
    <ComponentGroup Id="RuleFiles" />
  </Fragment>
</Wix>
'@
}

$msiPath = Join-Path $OutputPath "prompt-gate-$Version.msi"

wix build $wxsPath $rulesHarvest `
    -d "ProductVersion=$Version" `
    -d "AgentExePath=$AgentExePath" `
    -d "RulesSourceDir=$rulesDir" `
    -ext WixToolset.Util.wixext `
    -out $msiPath

Write-Host "Wrote $msiPath"
