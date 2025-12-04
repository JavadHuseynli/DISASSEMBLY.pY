@echo off
REM EXE Analyzer Setup Script for Windows

echo ==========================================
echo EXE Analyzer - Setup Script
echo ==========================================
echo.

REM Check Python version
echo [1/4] Checking Python version...
python --version
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)
echo.

REM Create virtual environment
echo [2/4] Creating virtual environment...
set /p VENV="Do you want to create a virtual environment? (y/n): "
if /i "%VENV%"=="y" (
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Virtual environment created and activated
)
echo.

REM Install dependencies
echo [3/4] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)
echo.

REM Test installation
echo [4/4] Testing installation...
python -c "import pefile; import capstone; import dnfile; print('All dependencies installed successfully!')"
if errorlevel 1 (
    echo Warning: Some dependencies may not be properly installed
) else (
    echo.
    echo ==========================================
    echo Setup complete!
    echo ==========================================
    echo.
    echo To run the application:
    echo   python main.py
    echo.
)

pause
