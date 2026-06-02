# Prompt Gate Windows uninstall hook.
#
# Invoked by the MSI custom action during a "remove" transaction. Runs
# in the system context. Tasks:
#   1. Restore the original DNS settings via configure-dns.ps1 restore.
#   2. Stop and delete the Windows service.
#   3. Remove ProgramData\PromptGate\ (config, rules, sqlite db).
#
# This script intentionally does NOT remove the installed program
# files — the MSI engine handles that.

$ErrorActionPreference = 'Continue'
$dataDir = Join-Path $env:ProgramData 'PromptGate'

try {
    & (Join-Path $PSScriptRoot 'configure-dns.ps1') -Action restore
} catch {
    # Restoring DNS is best-effort: continue to remove the service.
}

if (Get-Service -Name 'PromptGate' -ErrorAction SilentlyContinue) {
    Stop-Service -Name 'PromptGate' -Force -ErrorAction SilentlyContinue
    & sc.exe delete 'PromptGate' | Out-Null
}

if (Test-Path $dataDir) {
    Remove-Item -Recurse -Force -Path $dataDir -ErrorAction SilentlyContinue
}

exit 0
