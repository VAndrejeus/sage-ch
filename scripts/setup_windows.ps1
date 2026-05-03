$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "SAGE-CH Windows setup"
Write-Host "Repository: $RepoRoot"

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    Write-Error "Python was not found on PATH. Install Python 3.11+ and rerun this script."
}

$VersionText = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
Write-Host "Python: $VersionText"

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment: .venv"
    python -m venv .venv
}

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment Python was not created at $VenvPython"
}

Write-Host "Upgrading pip"
& $VenvPython -m pip install --upgrade pip

Write-Host "Installing dependencies"
& $VenvPython -m pip install -r requirements.txt

Write-Host "Running preflight check"
& $VenvPython tools\preflight_check.py

Write-Host ""
Write-Host "Setup complete. Start the app with:"
Write-Host "  .\scripts\run_gui.ps1"
