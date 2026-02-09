@echo off
REM ============================================================================
REM DESAS Windows Build Script
REM ============================================================================
REM This script builds a standalone DESAS desktop application for Windows.
REM It creates a Python backend executable and packages it with Electron.
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo DESAS Windows Build Script
echo ============================================================================
echo.

set PROJECT_DIR=%~dp0
set VENV_DIR=%PROJECT_DIR%.venv
set BUILD_DIR=%PROJECT_DIR%release

echo Project directory: %PROJECT_DIR%
echo.

REM ============================================================================
REM [1/7] Check Python
REM ============================================================================
echo [1/7] Checking Python...

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found. Install from https://python.org
    exit /b 1
)

python --version
echo Python OK
echo.

REM ============================================================================
REM [2/7] Check Node.js
REM ============================================================================
echo [2/7] Checking Node.js...

where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Node.js not found. Install from https://nodejs.org
    exit /b 1
)

node --version
call npm --version
echo Node.js OK
echo.

REM ============================================================================
REM [3/7] Create Python virtual environment
REM ============================================================================
echo [3/7] Creating Python virtual environment...

if not exist "%VENV_DIR%" (
    python -m venv "%VENV_DIR%"
)

call "%VENV_DIR%\Scripts\activate.bat"
echo Virtual environment activated
echo.

REM ============================================================================
REM [4/7] Install Python dependencies
REM ============================================================================
echo [4/7] Installing Python dependencies...

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo Python dependencies OK
echo.

REM ============================================================================
REM [5/7] Install Playwright Chromium
REM ============================================================================
echo [5/7] Installing Playwright Chromium...

python -m playwright install chromium

echo Playwright OK
echo.

REM ============================================================================
REM [6/7] Build Python backend
REM ============================================================================
echo [6/7] Building Python backend...

REM Clean previous builds and temporary samples
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist system_verify rmdir /s /q system_verify
if exist advanced_samples rmdir /s /q advanced_samples
if exist verification_samples rmdir /s /q verification_samples

REM Build backend for Windows
pyinstaller build_assets\backend.spec --clean --noconfirm

if not exist "dist\backend_server.exe" (
    echo ERROR: backend_server.exe not found
    exit /b 1
)

echo Backend build OK
echo.

REM ============================================================================
REM [7/7] Build Electron application
REM ============================================================================
echo [7/7] Building Electron application...

REM Install Node dependencies
call npm install

REM Build Electron app
call npm run dist

echo Electron build OK
echo.

REM ============================================================================
REM Verify build output
REM ============================================================================
echo Verifying build output...

if not exist "%BUILD_DIR%" (
    echo ERROR: Release directory not found
    exit /b 1
)

dir "%BUILD_DIR%\*.exe" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: No EXE found in release directory
    exit /b 1
)

echo ============================================================================
echo BUILD COMPLETED SUCCESSFULLY
echo ============================================================================
echo Output directory: %BUILD_DIR%
echo.
dir "%BUILD_DIR%\*.exe"
echo.
echo To install: Run the installer EXE
echo.

endlocal
