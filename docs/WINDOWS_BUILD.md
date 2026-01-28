# Building DESAS on Windows from GitHub

## Quick Answer
**YES**, the Windows build script will work when you pull the code from GitHub! The `release/` folder is created during the build process and is intentionally excluded from GitHub (via `.gitignore`).

## Prerequisites (Install on Windows Machine)

1. **Python 3.8+**
   - Download from: https://python.org
   - ✅ Check "Add Python to PATH" during installation

2. **Node.js 14+**
   - Download from: https://nodejs.org
   - Includes npm automatically

3. **Git** (to clone the repository)
   - Download from: https://git-scm.com

## Step-by-Step Build Process

### 1. Clone the Repository
```cmd
git clone https://github.com/yourusername/DESAS.git
cd DESAS
```

Or download as ZIP and extract.

### 2. Run the Build Script
```cmd
build_windows.bat
```

That's it! The script will:
- ✅ Create a Python virtual environment (`.venv/`)
- ✅ Install all Python dependencies
- ✅ Download Playwright Chromium browser
- ✅ Build the Python backend executable
- ✅ Install Node.js dependencies
- ✅ Create the `release/` folder
- ✅ Build the Windows installer

### 3. Find Your Installer
```
DESAS/release/DESAS Setup <version>.exe
```

## What Gets Created (Not in GitHub)

The following folders/files are created during the build and are **NOT** in GitHub:

- `.venv/` - Python virtual environment
- `node_modules/` - Node.js dependencies
- `build/` - Temporary build files
- `dist/` - Python backend executable
- `release/` - **Final installer location** ✅
- `settings.json` - User settings
- `whitelist.json` - User whitelist

These are all listed in `.gitignore` and will be created fresh on your Windows machine.

## Build Time & Size

- **First build**: 5-10 minutes (downloads ~500 MB of dependencies)
- **Subsequent builds**: 2-3 minutes (dependencies cached)
- **Final installer size**: ~150-200 MB

## Troubleshooting

### "Python not found"
- Install Python from https://python.org
- Ensure "Add to PATH" was checked during installation
- Restart Command Prompt after installation

### "Node not found"
- Install Node.js from https://nodejs.org
- Restart Command Prompt after installation

### "Build fails at PyInstaller"
- Disable antivirus temporarily (it may block PyInstaller)
- Run Command Prompt as Administrator

### "Build fails at Playwright"
- Ensure you have at least 1 GB free disk space
- Check internet connection

## What's Included in the Build

All the latest enterprise enhancements are automatically included:

✅ **Verdict Explanation Engine** (`app/analyzer/verdict_explainer.py`)
✅ **Score Decomposition** (updated `app/core/scoring.py`)
✅ **Whitelist Integration** (updated verdict explainer)
✅ **All UI enhancements** (updated `app/templates/index.html`)
✅ **Updated schemas** (`app/core/schemas.py`)

## Distribution

Once built, you can distribute the installer:

1. **Find the installer**: `release/DESAS Setup <version>.exe`
2. **Share it**: Upload to cloud storage, USB drive, or network share
3. **Install**: Recipients just run the EXE (no Python/Node.js needed)

## Important Notes

- ✅ The build script works on a fresh GitHub clone
- ✅ No manual configuration needed
- ✅ All dependencies are downloaded automatically
- ✅ The `release/` folder is created during build
- ✅ You can build on Windows even if the code was developed on macOS

## Verification After Build

Run these checks to ensure the build succeeded:

```cmd
dir release\*.exe
```

You should see: `DESAS Setup <version>.exe`

## Next Steps

1. Run the installer to test it
2. Verify all features work (especially new Verdict Justification and Score Breakdown)
3. Distribute the installer to end users
