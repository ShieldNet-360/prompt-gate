# Prompt Gate Windows post-install script.
#
# Invoked by the MSI custom action after files are copied. Runs in the
# system context. Tasks:
#   1. Ensure ProgramData\PromptGate\ exists with the right ACLs.
#   2. Register/start the Windows service (idempotent — sc.exe create
#      fails harmlessly if the service is already there).
#   3. Apply DNS handoff via configure-dns.ps1.
#
# Errors are logged to %ProgramData%\PromptGate\install.log and not
# re-thrown, so an MSI rollback does not strand the user with a broken
# DNS configuration.

$ErrorActionPreference = 'Continue'
$dataDir = Join-Path $env:ProgramData 'PromptGate'
$logPath = Join-Path $dataDir 'install.log'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

function Write-Log($msg) {
    "$(Get-Date -Format o) $msg" | Out-File -FilePath $logPath -Encoding UTF8 -Append
}

Write-Log 'postinstall: starting'

try {
    & (Join-Path $PSScriptRoot 'register-service.ps1')
    Write-Log 'postinstall: service registered'
} catch {
    Write-Log "postinstall: register-service failed: $_"
}

try {
    & (Join-Path $PSScriptRoot 'configure-dns.ps1') -Action apply
    Write-Log 'postinstall: DNS applied'
} catch {
    Write-Log "postinstall: configure-dns apply failed: $_"
}

Write-Log 'postinstall: complete'
exit 0
