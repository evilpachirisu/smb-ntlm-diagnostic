[CmdletBinding()]
param(
    [switch]$DropSSP,
    [switch]$Quiet,
    [switch]$ShowNetNTLM,
    [string]$BindAddress = '127.0.0.1',
    [ValidateRange(1,65535)][int]$Port = 8446,
    [ValidateSet('both','jsonl','text')][string]$Format = 'both',
    [string]$LogDirectory = (Join-Path $PSScriptRoot 'logs')
)
$ErrorActionPreference = 'Stop'
if ($Port -in @(139,445)) { throw 'Use a port other than 139/445.' }
$Python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { throw 'Create .venv and install requirements.txt first (see README).' }
Push-Location $PSScriptRoot
try {
    $ExtraArgs = @()
    if ($ShowNetNTLM) { $ExtraArgs += '--show-netntlm' }
    if ($Quiet) { $ExtraArgs += '--quiet' }
    if ($DropSSP) { $ExtraArgs += '--drop-ssp' }
    & $Python -m smbdiag --bind $BindAddress --port $Port --format $Format `
        --jsonl (Join-Path $LogDirectory 'events.jsonl') --text (Join-Path $LogDirectory 'events.txt') @ExtraArgs
    $ToolExitCode = $LASTEXITCODE
} finally { Pop-Location }
exit $ToolExitCode
