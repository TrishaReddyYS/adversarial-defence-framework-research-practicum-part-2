@echo off
REM ==========================================================================
REM  Adversarial Defence Framework  -  one-time setup
REM  Run this ONCE. It creates the environment and installs the dependencies.
REM  When it finishes, use run.bat for the demo (run.bat is then fast).
REM ==========================================================================
cd /d "%~dp0"

echo.
echo ==========================================================================
echo  SETUP  -  creating the environment and installing dependencies
echo  (this takes a few minutes the first time; you only do it once)
echo ==========================================================================
python --version
if errorlevel 1 (
    echo   ERROR: Python was not found. Install Python 3.10 or newer from
    echo   https://www.python.org/downloads/ and tick "Add python.exe to PATH",
    echo   then run this file again.
    pause
    exit /b 1
)
python -m venv .venv
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo   ERROR: dependency installation failed. See the messages above.
    pause
    exit /b 1
)
echo   (optional) installing Semgrep and the Docker library for extra coverage...
pip install "semgrep>=1.0" "docker>=7.0"

echo.
echo ==========================================================================
echo  Setup complete. Now double-click run.bat to run the demo.
echo ==========================================================================
pause
