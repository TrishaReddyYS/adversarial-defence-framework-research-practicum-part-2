@echo off
REM  Adversarial Defence Framework - one-time setup.
cd /d "%~dp0"

echo.
echo Setting up the environment (first time only, this takes a few minutes)...
python --version
if errorlevel 1 (
    echo Python not found. Install Python 3.10 or newer, add it to PATH, and run this again.
    pause
    exit /b 1
)
python -m venv .venv
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency install failed - see the messages above.
    pause
    exit /b 1
)

echo Installing Semgrep and Docker for Layer 2 and Layer 3...
pip install "semgrep>=1.0" "docker>=7.0"

echo Installing the Layer 1 classifier...
pip install -e "." "transformers>=4.40,<5" "huggingface_hub<1.0" "accelerate>=0.30" "torch>=2.2" "openai>=1.30"

echo Caching the Layer 1 model...
set HF_HUB_DISABLE_PROGRESS_BARS=1
set TQDM_DISABLE=1
python -c "from transformers import pipeline; pipeline('text-classification', model='protectai/deberta-v3-base-prompt-injection-v2', truncation=True)" 2>nul

echo.
echo Setup complete - run run.bat for the demo.
pause
