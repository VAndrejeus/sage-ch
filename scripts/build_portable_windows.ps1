param(
    [string]$PythonVersion = "3.11.9",
    [string]$OutputRoot = "dist\sage-ch-portable",
    [switch]$IncludeOutputs
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$BuildRoot = Join-Path $RepoRoot "build\portable"
$CacheRoot = Join-Path $BuildRoot "cache"
$OutputRootAbs = Join-Path $RepoRoot $OutputRoot
$CollectorRoot = Join-Path $OutputRootAbs "SAGE-CH-Collector-Windows"
$AgentRoot = Join-Path $OutputRootAbs "SAGE-CH-Agent-Windows"
$LinuxAgentRoot = Join-Path $OutputRootAbs "SAGE-CH-Agent-Linux"

New-Item -ItemType Directory -Force -Path $CacheRoot | Out-Null
New-Item -ItemType Directory -Force -Path $OutputRootAbs | Out-Null

function Copy-ProjectItem {
    param(
        [string]$Source,
        [string]$Destination
    )

    if (Test-Path $Destination) {
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function New-EmbeddedPython {
    param(
        [string]$TargetRuntime
    )

    $zipName = "python-$PythonVersion-embed-amd64.zip"
    $zipPath = Join-Path $CacheRoot $zipName
    $url = "https://www.python.org/ftp/python/$PythonVersion/$zipName"

    if (-not (Test-Path $zipPath)) {
        Write-Host "Downloading embedded Python $PythonVersion"
        Invoke-WebRequest -Uri $url -OutFile $zipPath
    }

    if (Test-Path $TargetRuntime) {
        Remove-Item -LiteralPath $TargetRuntime -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $TargetRuntime | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $TargetRuntime -Force

    $pth = Get-ChildItem -LiteralPath $TargetRuntime -Filter "python*._pth" | Select-Object -First 1
    if ($pth) {
        $content = Get-Content -LiteralPath $pth.FullName
        $content = $content | ForEach-Object { $_ -replace '^#import site$', 'import site' }
        if ($content -notcontains "..\..\app") {
            $content += "..\..\app"
        }
        Set-Content -LiteralPath $pth.FullName -Value $content -Encoding ASCII
    }
}

function Install-PipAndRequirements {
    param(
        [string]$RuntimeRoot,
        [string]$RequirementsPath
    )

    $pythonExe = Join-Path $RuntimeRoot "python.exe"
    $getPip = Join-Path $CacheRoot "get-pip.py"

    if (-not (Test-Path $getPip)) {
        Write-Host "Downloading get-pip.py"
        Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getPip
    }

    Write-Host "Installing pip into embedded runtime"
    & $pythonExe $getPip --no-warn-script-location

    Write-Host "Installing package dependencies into embedded runtime"
    & $pythonExe -m pip install --no-warn-script-location -r $RequirementsPath
}

Write-Host "Building portable SAGE-CH package"
Write-Host "Output: $OutputRootAbs"

if (Test-Path $OutputRootAbs) {
    Remove-Item -LiteralPath $OutputRootAbs -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $CollectorRoot, $AgentRoot, $LinuxAgentRoot | Out-Null

Write-Host "Preparing collector package"
New-EmbeddedPython -TargetRuntime (Join-Path $CollectorRoot "runtime\python")
New-Item -ItemType Directory -Force -Path (Join-Path $CollectorRoot "app") | Out-Null

$collectorApp = Join-Path $CollectorRoot "app"
$collectorItems = @(
    ".streamlit",
    "agents",
    "collector",
    "config",
    "gui",
    "scripts",
    "tools",
    "docs",
    "requirements.txt",
    "README.md",
    "MANUAL.md"
)
if ($IncludeOutputs) {
    $collectorItems += "outputs"
}

foreach ($item in $collectorItems) {
    $source = Join-Path $RepoRoot $item
    if (Test-Path $source) {
        Copy-ProjectItem -Source $source -Destination (Join-Path $collectorApp $item)
    }
}

Install-PipAndRequirements `
    -RuntimeRoot (Join-Path $CollectorRoot "runtime\python") `
    -RequirementsPath (Join-Path $collectorApp "requirements.txt")

@"
@echo off
setlocal
cd /d "%~dp0app"
set PYTHONPATH=%~dp0app
"%~dp0runtime\python\python.exe" -m streamlit run "gui\app.py"
"@ | Set-Content -LiteralPath (Join-Path $CollectorRoot "START_COLLECTOR_GUI.bat") -Encoding ASCII

@"
@echo off
setlocal
cd /d "%~dp0app"
set PYTHONPATH=%~dp0app
"%~dp0runtime\python\python.exe" -m collector.main
pause
"@ | Set-Content -LiteralPath (Join-Path $CollectorRoot "RUN_COLLECTOR.bat") -Encoding ASCII

@"
@echo off
setlocal
cd /d "%~dp0app"
set PYTHONPATH=%~dp0app
"%~dp0runtime\python\python.exe" "tools\preflight_check.py"
pause
"@ | Set-Content -LiteralPath (Join-Path $CollectorRoot "RUN_PREFLIGHT.bat") -Encoding ASCII

@"
@echo off
setlocal
cd /d "%~dp0app"
set PYTHONPATH=%~dp0app
"%~dp0runtime\python\python.exe" "tools\rebuild_kuzu_from_consolidated.py"
pause
"@ | Set-Content -LiteralPath (Join-Path $CollectorRoot "REBUILD_KUZU.bat") -Encoding ASCII

Write-Host "Preparing Windows endpoint agent package"
New-EmbeddedPython -TargetRuntime (Join-Path $AgentRoot "runtime\python")
New-Item -ItemType Directory -Force -Path (Join-Path $AgentRoot "app") | Out-Null
Copy-ProjectItem -Source (Join-Path $RepoRoot "agents") -Destination (Join-Path $AgentRoot "app\agents")

@"
@echo off
setlocal
cd /d "%~dp0app"
set PYTHONPATH=%~dp0app
"%~dp0runtime\python\python.exe" -m agents.windows.main
echo.
echo Report written under app\agents\windows\output
pause
"@ | Set-Content -LiteralPath (Join-Path $AgentRoot "RUN_WINDOWS_AGENT.bat") -Encoding ASCII

@"
@echo off
setlocal
cd /d "%~dp0"
if not exist reports mkdir reports
copy /Y "%~dp0app\agents\windows\output\endpoint_report_*.json" "%~dp0reports\" >nul
echo Reports copied to %~dp0reports
pause
"@ | Set-Content -LiteralPath (Join-Path $AgentRoot "COLLECT_REPORTS.bat") -Encoding ASCII

Write-Host "Preparing Linux endpoint agent source package"
New-Item -ItemType Directory -Force -Path (Join-Path $LinuxAgentRoot "app") | Out-Null
Copy-ProjectItem -Source (Join-Path $RepoRoot "agents") -Destination (Join-Path $LinuxAgentRoot "app\agents")

@'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
export PYTHONPATH="$SCRIPT_DIR/app"
python3 -m agents.linux.main
echo "Report written under app/agents/linux/output"
'@ | Set-Content -LiteralPath (Join-Path $LinuxAgentRoot "run_linux_agent.sh") -Encoding ASCII

@'
SAGE-CH Linux agent package

The Linux package contains the agent source and a launcher script.
For a Linux endpoint with no Python installed, build a Linux executable on a matching Linux machine using PyInstaller or ship a distro-specific Python runtime.
Many Linux systems already include Python 3; if so, run:

  chmod +x run_linux_agent.sh
  ./run_linux_agent.sh

Output:
  app/agents/linux/output/
'@ | Set-Content -LiteralPath (Join-Path $LinuxAgentRoot "README_LINUX_AGENT.txt") -Encoding ASCII

@"
SAGE-CH Portable Package

Collector:
  SAGE-CH-Collector-Windows\START_COLLECTOR_GUI.bat
  SAGE-CH-Collector-Windows\RUN_COLLECTOR.bat
  SAGE-CH-Collector-Windows\RUN_PREFLIGHT.bat
  SAGE-CH-Collector-Windows\REBUILD_KUZU.bat

Windows endpoint agent:
  SAGE-CH-Agent-Windows\RUN_WINDOWS_AGENT.bat
  SAGE-CH-Agent-Windows\COLLECT_REPORTS.bat

Linux endpoint agent:
  SAGE-CH-Agent-Linux\run_linux_agent.sh

The Windows collector and Windows agent packages include embedded Python and do not require Python to be installed on the target computer.
"@ | Set-Content -LiteralPath (Join-Path $OutputRootAbs "README_PORTABLE.txt") -Encoding ASCII

Write-Host ""
Write-Host "Portable package complete:"
Write-Host "  $OutputRootAbs"
