@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo First-time setup is required.
  echo Run: powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -m streamlit run gui\app.py
