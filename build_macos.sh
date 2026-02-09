#!/bin/bash

# ============================================================================
# DESAS macOS Build Script
# ============================================================================
# This script builds a standalone DESAS desktop application for macOS.
# It creates a Python backend executable and packages it with Electron.
# ============================================================================

set -e  # Exit on error

echo "============================================================================"
echo "DESAS macOS Build Script"
echo "============================================================================"
echo ""

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "ERROR: This script must be run on macOS"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
BUILD_DIR="$PROJECT_DIR/release"

echo "Project directory: $PROJECT_DIR"
echo ""

# ============================================================================
# [1/7] Check Python
# ============================================================================
echo "[1/7] Checking Python..."

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found. Install from https://python.org"
    exit 1
fi

python3 --version
echo "Python OK"
echo ""

# ============================================================================
# [2/7] Check Node.js
# ============================================================================
echo "[2/7] Checking Node.js..."

if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not found. Install from https://nodejs.org"
    exit 1
fi

node --version
npm --version
echo "Node.js OK"
echo ""

# ============================================================================
# [3/7] Create Python virtual environment
# ============================================================================
echo "[3/7] Creating Python virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
echo "Virtual environment activated"
echo ""

# ============================================================================
# [4/7] Install Python dependencies
# ============================================================================
echo "[4/7] Installing Python dependencies..."

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo "Python dependencies OK"
echo ""

# ============================================================================
# [5/7] Install Playwright Chromium
# ============================================================================
echo "[5/7] Installing Playwright Chromium..."

python -m playwright install chromium

echo "Playwright OK"
echo ""

# ============================================================================
# [6/7] Build Python backend
# ============================================================================
echo "[6/7] Building Python backend..."

# Clean previous builds and temporary samples
rm -rf build dist release system_verify advanced_samples verification_samples

# Build backend for macOS
pyinstaller build_assets/backend.spec --clean --noconfirm

if [ ! -f "dist/backend_server" ]; then
    echo "ERROR: backend_server not found"
    exit 1
fi

echo "Backend build OK"
echo ""

# ============================================================================
# [7/7] Build Electron application
# ============================================================================
echo "[7/7] Building Electron application..."

# Clean node_modules for fresh install - SKIP for optimization
# rm -rf node_modules

# Install Node dependencies
npm install

# Build Electron app
npm run dist

echo "Electron build OK"
echo ""

# ============================================================================
# Verify build output
# ============================================================================
echo "Verifying build output..."

if [ ! -d "$BUILD_DIR" ]; then
    echo "ERROR: Release directory not found"
    exit 1
fi

if ! ls "$BUILD_DIR"/*.dmg 1> /dev/null 2>&1; then
    echo "ERROR: No DMG found in release directory"
    exit 1
fi

echo "============================================================================"
echo "BUILD COMPLETED SUCCESSFULLY"
echo "============================================================================"
echo "Output directory: $BUILD_DIR"
echo ""
ls -lh "$BUILD_DIR"/*.dmg
echo ""
echo "To install: Open the DMG and drag DESAS to Applications"
echo ""
