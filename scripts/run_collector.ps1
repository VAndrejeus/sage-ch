$ErrorActionPreference = "Stop"

param(
    [switch]$WithAI
)

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment not found. Run .\scripts\setup_windows.ps1 first."
}

if ($WithAI) {
    & $VenvPython -m collector.main --with-ai
} else {
    & $VenvPython -m collector.main
}
