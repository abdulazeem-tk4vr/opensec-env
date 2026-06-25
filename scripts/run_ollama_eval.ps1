# Run OpenSec eval against Ollama using OLLAMA_BASE_URL + OLLAMA_MODEL from .env
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$EvalArgs
)

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Test-Path ".env")) {
    Write-Error "Missing .env — copy .env.example and set OLLAMA_BASE_URL`n  Copy-Item .env.example .env"
    exit 1
}

$allArgs = @("scripts/eval.py", "--ollama") + $EvalArgs
& python @allArgs
exit $LASTEXITCODE
