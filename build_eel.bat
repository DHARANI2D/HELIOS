@echo off
echo.
echo ==========================================================
echo       DESAS - Professional Forensic Workstation
echo          Eel Standalone Build (Single EXE)
echo ==========================================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python not found. Please install Python 3.
    pause
    exit /b
)

:: Install dependencies
echo [1/3] Installing/Updating required Python packages...
pip install eel pyinstaller tldextract pydantic-settings aiohttp uvicorn jinja2 python-multipart python-jose[cryptography] passlib[bcrypt] openpyxl python-magic-bin
if %errorlevel% neq 0 (
    echo [!] Failed to install dependencies.
    pause
    exit /b
)

:: Clean previous builds
if exist build rd /s /q build
if exist dist rd /s /q dist

:: Run PyInstaller via Eel
echo [2/3] Building standalone executable with PyInstaller...
echo [!] This may take a few minutes...

:: Note: --onefile bundles everything, --noconsole hides the cmd window
:: --add-data includes the static folder. 
:: On Windows, the syntax is folder;folder.
python -m eel app/eel_main.py app/static --onefile --noconsole --name desas --icon app/static/favicon.ico --workpath build --distpath dist

if %errorlevel% neq 0 (
    echo [!] Build failed.
    pause
    exit /b
)

echo.
echo [3/3] Build successful!
echo [!] Your standalone executable is located in: dist/desas.exe
echo.
echo ==========================================================
echo.
pause
