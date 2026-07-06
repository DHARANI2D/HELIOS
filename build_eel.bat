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
:: Uses requirements.txt so this build gets every runtime dependency the app
:: actually needs (selenium, oletools, olefile, pefile, pyyaml, etc.) - a
:: hand-picked package list here previously drifted out of sync and left
:: PyInstaller unable to bundle modules that were never even installed.
echo [1/3] Installing/Updating required Python packages...
pip install -r requirements.txt pyinstaller
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
:: --add-data includes the static folder and the scoring rules config.
:: On Windows, the syntax is source;dest.
:: --collect-submodules: app.analyzer.report_generator was silently dropped
:: from the frozen bundle even with an explicit --hidden-import for it and
:: no warning logged - collect-submodules walks the actual package on disk
:: instead of relying on modulegraph's static analysis. Applied to all
:: three app subpackages as insurance.
:: --hidden-import: PyInstaller's static analyzer misses these even though
:: they're directly imported - the same list already used by
:: build_assets/backend.spec for the other (FastAPI-style) build path.
set ICON_ARG=
if exist app\static\favicon.ico set ICON_ARG=--icon app/static/favicon.ico

python -m eel app/eel_main.py app/static --onefile --noconsole --name desas %ICON_ARG% --workpath build --distpath dist ^
    --collect-submodules app.analyzer ^
    --collect-submodules app.core ^
    --collect-submodules app.sandbox ^
    --add-data "app/core/scoring_rules.yaml;app/core" ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.protocols.websockets ^
    --hidden-import uvicorn.protocols.websockets.auto ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    --hidden-import email.mime.text ^
    --hidden-import email.mime.multipart ^
    --hidden-import extract_msg ^
    --hidden-import pypdf ^
    --hidden-import docx ^
    --hidden-import reportlab ^
    --hidden-import reportlab.pdfgen ^
    --hidden-import reportlab.lib ^
    --hidden-import reportlab.platypus ^
    --hidden-import openpyxl ^
    --hidden-import app.analyzer.report_generator

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
