@echo off
rem One-click launcher: pipeline daemon (use: run.bat --once for a single pass)
cd /d "%~dp0"
.venv\Scripts\python.exe -m src.main run %*
