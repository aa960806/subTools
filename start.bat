@echo off
cd /d "%~dp0"
set "SUBTOOLS_PYTHON=python"
if exist ".venv\Scripts\python.exe" set "SUBTOOLS_PYTHON=.venv\Scripts\python.exe"
if not exist "data\admin.json" "%SUBTOOLS_PYTHON%" setup_admin.py
if errorlevel 1 exit /b 1
set "SUBTOOLS_OPEN_BROWSER=1"
"%SUBTOOLS_PYTHON%" run_web.py
pause
