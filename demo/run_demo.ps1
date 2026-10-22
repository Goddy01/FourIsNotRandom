# Run local audit demos against fixtures + optional mock HTTP server.
# Usage:
#   .\demo\run_demo.ps1
#   .\demo\run_demo.ps1 -WithMock   # also hits http://127.0.0.1:8765 (start mock_server.py first)

param(
    [switch]$WithMock
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Cli = Join-Path $Root ".venv\Scripts\fourisnotrandom.exe"
if (-not (Test-Path $Cli)) {
    Write-Host "Creating venv and installing package..."
    python -m venv .venv
    & .\.venv\Scripts\pip install -e ".[dev]" -q
}

& .\.venv\Scripts\python demo\generate_certs.py

Write-Host ""
Write-Host "=== 1) PHP filesystem: vulnerable Dockerfile (expect FAIL) ===" -ForegroundColor Cyan
& $Cli php fs demo\vulnerable-php

Write-Host ""
Write-Host "=== 2) PHP filesystem: patched Dockerfile (expect PASS) ===" -ForegroundColor Cyan
& $Cli php fs demo\patched-php

Write-Host ""
Write-Host "=== 3) PHP + WordPress webroot on vulnerable PHP (expect FAIL + app finding) ===" -ForegroundColor Cyan
& $Cli php fs demo\webroot

Write-Host ""
Write-Host "=== 4) LiteLLM compromised pin (expect FAIL) ===" -ForegroundColor Cyan
& $Cli litellm path demo\litellm-bad
Write-Host "exit=$LASTEXITCODE"

Write-Host ""
Write-Host "=== 5) LiteLLM safe pin (expect PASS) ===" -ForegroundColor Cyan
& $Cli litellm path demo\litellm-ok
Write-Host "exit=$LASTEXITCODE"

Write-Host ""
Write-Host "=== 6) eMudhra: synthetic bad cert + demo hashes (expect FAIL) ===" -ForegroundColor Cyan
& $Cli --hashes demo\certs\demo-hashes.json emudhra path demo\certs\demo-bad.pem

Write-Host ""
Write-Host "=== 7) eMudhra: clean cert against demo hashes (expect PASS) ===" -ForegroundColor Cyan
& $Cli --hashes demo\certs\demo-hashes.json emudhra path demo\certs\demo-clean.pem

Write-Host ""
Write-Host "=== 8) Toolchains (Go/certifi on this machine) ===" -ForegroundColor Cyan
& $Cli --format json emudhra toolchains

if ($WithMock) {
    Write-Host ""
    Write-Host "=== 9) Mock remote PHP vulnerable header ===" -ForegroundColor Cyan
    & $Cli php url http://127.0.0.1:8765/
    Write-Host ""
    Write-Host "=== 10) Mock remote PHP patched header ===" -ForegroundColor Cyan
    & $Cli php url http://127.0.0.1:8765/patched
    Write-Host ""
    Write-Host "=== 11) Mock GitLab 19.4.2 (PASS 97229 / FAIL 110264) ===" -ForegroundColor Cyan
    & $Cli gitlab --url http://127.0.0.1:8765
} else {
    Write-Host ""
    Write-Host "(Skip remote demos - start mock first:)" -ForegroundColor Yellow
    Write-Host "  .\.venv\Scripts\python demo\mock_server.py"
    Write-Host "  .\demo\run_demo.ps1 -WithMock"
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
