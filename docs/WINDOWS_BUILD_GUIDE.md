# Windows Build Guide for DESAS

This guide explains how to build the DESAS application as a standalone Windows executable.

## Prerequisites
- A Windows 10/11 machine.
- [Node.js](https://nodejs.org/) installed.
- [Python 3.10+](https://www.python.org/) installed.
- [Git](https://git-scm.com/) installed.

## Step 1: Prepare the Python Backend
The backend must be compiled on Windows to create a `.exe` file.

1.  Open PowerShell or Command Prompt.
2.  Navigate to the project directory.
3.  Install Python dependencies:
    ```powershell
    pip install -r requirements.txt
    pip install pyinstaller
    ```
4.  Build the backend using the provided spec file:
    ```powershell
    pyinstaller backend.spec
    ```
5.  This will create a `dist/backend_server.exe` file.

## Step 2: Prepare the Electron App
1.  Install Node dependencies:
    ```powershell
    npm install
    ```
2.  Ensure `icon.png` is in the root (already provided).
3.  Ensure `dist/backend_server.exe` exists from Step 1.

## Step 3: Build the Installer
1.  Run the build command:
    ```powershell
    npm run dist
    ```
2.  The final installer (Portable or NSIS) will be available in the `release/` directory.

## Troubleshooting
- **Icon Issues**: If `electron-builder` fails to convert `icon.png`, you can manually convert it to `icon.ico` using an online tool and update `package.json` back to `icon.ico`.
- **Backend Path**: The application expects the backend executable at `resources/backend_server.exe` when packaged. `electron-builder` is configured to copy it from `dist/backend_server` to `backend_server`.
