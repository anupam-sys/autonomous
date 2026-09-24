@echo off
rem One-click launcher: live transparency dashboard
cd /d "%~dp0"
.venv\Scripts\python.exe -m src.main web %*
