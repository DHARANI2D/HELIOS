# Troubleshooting Blank Page in Portable Build

## Problem
When running the portable/built version of DESAS, a blank page appears instead of the application UI.

## Root Cause
The backend server (`backend_server` or `backend_server.exe`) is not starting correctly in the packaged application, causing the frontend to fail loading.

## Solution Applied

### 1. Fixed Backend Path Resolution (`main.js`)
- Added verification that backend executable exists before starting
- Added detailed logging to help debug startup issues
- Added proper error handling for backend process failures
- Set `PYTHONUNBUFFERED=1` environment variable for immediate log output

### 2. Fixed extraResources Configuration (`package.json`)
- Changed from `"from": "dist/backend_server"` to `"from": "dist/backend_server*"`
- This ensures both `backend_server` (macOS) and `backend_server.exe` (Windows) are included
- Changed `"to": "."` to place executables directly in resources folder

## How to Debug

### 1. Check Console Logs
When running the portable app, open Developer Tools to see console logs:

**macOS:**
- Right-click in the app window → "Inspect Element"
- Or use menu: View → Toggle Developer Tools

**Windows:**
- Press `Ctrl+Shift+I`
- Or use menu: View → Toggle Developer Tools

Look for these messages:
```
Starting backend from: <path> on port 8282
Is packaged: true
Platform: win32 (or darwin)
Backend executable found at: <path>
```

If you see:
```
ERROR: Backend executable not found at: <path>
```
The backend wasn't included in the build.

### 2. Verify Backend Executable Exists

**macOS:**
```bash
# Navigate to the app bundle
cd /Applications/DESAS.app/Contents/Resources
ls -la backend_server
```

**Windows:**
```cmd
# Navigate to the portable app directory
cd <portable-app-folder>\resources
dir backend_server.exe
```

### 3. Test Backend Manually

**macOS:**
```bash
cd /Applications/DESAS.app/Contents/Resources
./backend_server
```

**Windows:**
```cmd
cd <portable-app-folder>\resources
backend_server.exe
```

The backend should start and show:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8282
```

If it crashes or shows errors, that's the root cause.

## Common Issues

### Issue 1: "Backend executable not found"
**Cause:** PyInstaller build failed or extraResources not configured correctly

**Solution:**
1. Rebuild from scratch: `rm -rf build dist release` (macOS) or `rmdir /s /q build dist release` (Windows)
2. Run build script again
3. Verify `dist/backend_server` (or `.exe`) exists before running `npm run dist`

### Issue 2: Backend crashes immediately
**Cause:** Missing dependencies or Playwright not bundled

**Solution:**
1. Check if Playwright Chromium is included in the build
2. Verify all Python dependencies are in `requirements.txt`
3. Check PyInstaller `hiddenimports` in `backend.spec`

### Issue 3: "Permission denied" (macOS)
**Cause:** Backend executable doesn't have execute permissions

**Solution:**
```bash
chmod +x /Applications/DESAS.app/Contents/Resources/backend_server
```

### Issue 4: Antivirus blocking (Windows)
**Cause:** Antivirus software blocks PyInstaller executables

**Solution:**
1. Add exception for `backend_server.exe` in antivirus
2. Or temporarily disable antivirus during testing

## Verification Checklist

After rebuilding with the fixes:

- [ ] Build completes without errors
- [ ] `dist/backend_server` (or `.exe`) exists
- [ ] Portable app starts without blank page
- [ ] Backend logs appear in console
- [ ] Can upload and analyze emails
- [ ] Verdict Justification card displays
- [ ] Score Breakdown card displays

## Build Command

To rebuild with the fixes:

**macOS:**
```bash
./build_macos.sh
```

**Windows:**
```cmd
build_windows.bat
```

## Still Having Issues?

1. **Enable Developer Tools by default** - Uncomment line 197 in `main.js`:
   ```javascript
   mainWindow.webContents.openDevTools();
   ```

2. **Check backend logs** - Look for Python errors in the console

3. **Test in development mode first** - Run `npm start` to ensure everything works before building

4. **Verify all files are included** - Check `package.json` `files` and `extraResources` sections
