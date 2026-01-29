# Quick Fix: Testing the Debug Build

The new build has **Developer Tools enabled by default** and will show **error dialog boxes** if the backend is missing.

## Test Now

1. **Open the new DMG:**
   ```bash
   open release/DESAS-1.0.0-arm64.dmg
   ```

2. **Run DESAS.app** from the DMG window

3. **What to look for:**
   
   **If you see an error dialog:**
   - It will say "Backend Not Found" with the path it's looking for
   - Take a screenshot and share it
   
   **If Developer Tools open automatically:**
   - Look at the Console tab (should open by default now)
   - Look for messages like:
     - ✅ "Backend executable found at: ..."
     - ✅ "Starting backend from: ..."
     - ✅ "Backend ready! Loading main window."
   - OR error messages like:
     - ❌ "ERROR: Backend executable not found"
     - ❌ "Failed to start backend process"
     - ❌ "Python Error: ..."
   
4. **Share what you see** - either screenshot the console or copy the error messages

## What This Debug Build Does

- **Auto-opens Developer Tools** so you can see all logs immediately
- **Shows error dialog** if backend executable is missing
- **Logs detailed path information** to help identify the issue
- **Lists all files** in Resources directory if backend not found

This will tell us exactly what's wrong!
