const { app, BrowserWindow, Menu } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let mainWindow;
let pythonProcess;

function createMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Analyze Email',
                    accelerator: 'CmdOrCtrl+O',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.executeJavaScript(`
                                document.getElementById('emailUpload')?.click();
                            `);
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Settings',
                    accelerator: 'CmdOrCtrl+,',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.executeJavaScript(`
                                document.querySelector('a[href="settings.html"]')?.click();
                            `);
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Exit',
                    accelerator: 'CmdOrCtrl+Q',
                    click: () => {
                        app.quit();
                    }
                }
            ]
        },
        {
            label: 'Edit',
            submenu: [
                { role: 'undo' },
                { role: 'redo' },
                { type: 'separator' },
                { role: 'cut' },
                { role: 'copy' },
                { role: 'paste' },
                { role: 'selectAll' }
            ]
        },
        {
            label: 'View',
            submenu: [
                {
                    label: 'Full Analysis',
                    accelerator: 'CmdOrCtrl+1',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.executeJavaScript(`
                                document.querySelector('.tab-btn[data-tab="fullAnalysis"]')?.click();
                            `);
                        }
                    }
                },
                {
                    label: 'Forensic Toolkit',
                    accelerator: 'CmdOrCtrl+2',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.executeJavaScript(`
                                document.querySelector('.tab-btn[data-tab="forensicToolkit"]')?.click();
                            `);
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Reload',
                    accelerator: 'CmdOrCtrl+R',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.reload();
                        }
                    }
                },
                {
                    label: 'Toggle Developer Tools',
                    accelerator: 'CmdOrCtrl+Shift+I',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.toggleDevTools();
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Actual Size',
                    accelerator: 'CmdOrCtrl+0',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.webContents.setZoomLevel(0);
                        }
                    }
                },
                {
                    label: 'Zoom In',
                    accelerator: 'CmdOrCtrl+Plus',
                    click: () => {
                        if (mainWindow) {
                            const currentZoom = mainWindow.webContents.getZoomLevel();
                            mainWindow.webContents.setZoomLevel(currentZoom + 0.5);
                        }
                    }
                },
                {
                    label: 'Zoom Out',
                    accelerator: 'CmdOrCtrl+-',
                    click: () => {
                        if (mainWindow) {
                            const currentZoom = mainWindow.webContents.getZoomLevel();
                            mainWindow.webContents.setZoomLevel(currentZoom - 0.5);
                        }
                    }
                },
                { type: 'separator' },
                {
                    label: 'Toggle Full Screen',
                    accelerator: 'F11',
                    click: () => {
                        if (mainWindow) {
                            mainWindow.setFullScreen(!mainWindow.isFullScreen());
                        }
                    }
                }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'Documentation',
                    click: () => {
                        require('electron').shell.openExternal('https://github.com/yourusername/desas');
                    }
                },
                {
                    label: 'Report Issue',
                    click: () => {
                        require('electron').shell.openExternal('https://github.com/yourusername/desas/issues');
                    }
                },
                { type: 'separator' },
                {
                    label: 'About DESAS',
                    click: () => {
                        const { dialog } = require('electron');
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'About DESAS',
                            message: 'DESAS - Dynamic Email Sandbox Analysis System',
                            detail: `Version: ${app.getVersion()}\n\nA professional forensic workstation for SOC analysts to safely investigate and detonate suspicious emails.\n\n© 2026 DESAS Project`,
                            buttons: ['OK']
                        });
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 900,
        title: 'DESAS - Dynamic Email Sandbox Analysis System',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
        },
        icon: path.join(__dirname, 'icon.png'),
    });

    // Create menu bar
    createMenu();

    // Enable dev tools for debugging
    // mainWindow.webContents.openDevTools();

    const url = 'http://127.0.0.1:8282';
    const healthUrl = url + '/health';

    // Show loading screen
    mainWindow.loadURL(`data:text/html,
        <html>
            <head>
                <style>
                    body {
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        background: #0a0e27;
                        font-family: 'Segoe UI', sans-serif;
                        color: #fff;
                    }
                    .loader {
                        text-align: center;
                    }
                    .spinner {
                        border: 4px solid rgba(0, 255, 255, 0.1);
                        border-top: 4px solid #00ffff;
                        border-radius: 50%;
                        width: 50px;
                        height: 50px;
                        animation: spin 1s linear infinite;
                        margin: 0 auto 20px;
                    }
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    h2 { color: #00ffff; margin-bottom: 10px; }
                    p { color: #a0aec0; }
                </style>
            </head>
            <body>
                <div class="loader">
                    <div class="spinner"></div>
                    <h2>DESAS</h2>
                    <p>Starting backend server...</p>
                </div>
            </body>
        </html>
    `);

    let pollAttempts = 0;
    const maxAttempts = 60; // 30 seconds

    // Polling function to wait for backend health check
    const pollBackend = async () => {
        try {
            pollAttempts++;
            console.log(`Polling ${healthUrl}... (Attempt ${pollAttempts}/${maxAttempts})`);
            const response = await require('electron').net.fetch(healthUrl);
            if (response.ok) {
                console.log('Backend ready! Loading main window.');
                mainWindow.loadURL(url);
                return;
            }
        } catch (err) {
            console.error(`Backend not ready: ${err.message}`);
        }

        if (pollAttempts >= maxAttempts) {
            console.error('Backend failed to start after 30 seconds');
            mainWindow.loadURL(`data:text/html,
                <html>
                    <head>
                        <style>
                            body {
                                margin: 0;
                                padding: 40px;
                                background: #0a0e27;
                                font-family: 'Segoe UI', sans-serif;
                                color: #fff;
                            }
                            .error {
                                max-width: 600px;
                                margin: 100px auto;
                                text-align: center;
                            }
                            h1 { color: #ff4444; margin-bottom: 20px; }
                            p { color: #a0aec0; line-height: 1.6; margin-bottom: 15px; }
                            code { background: rgba(255,255,255,0.1); padding: 2px 8px; border-radius: 4px; }
                        </style>
                    </head>
                    <body>
                        <div class="error">
                            <h1>⚠️ Backend Failed to Start</h1>
                            <p>The Python backend server could not be started.</p>
                            <p><strong>Possible causes:</strong></p>
                            <ul style="text-align: left; color: #a0aec0;">
                                <li>Port 8282 is already in use</li>
                                <li>Python backend executable is missing</li>
                                <li>Required dependencies are not installed</li>
                            </ul>
                            <p style="margin-top: 30px;">
                                Check the console for error messages or restart the application.
                            </p>
                        </div>
                    </body>
                </html>
            `);
            return;
        }

        setTimeout(pollBackend, 500);
    };

    pollBackend();

    mainWindow.on('closed', () => {
        mainWindow = null;
    });

    // Update title when page loads
    mainWindow.webContents.on('did-finish-load', () => {
        mainWindow.setTitle('DESAS - Dynamic Email Sandbox Analysis System');
    });
}

function startPython() {
    const isPackaged = app.isPackaged;
    let backendPath;
    let args;

    if (isPackaged) {
        const executableName = process.platform === 'win32' ? 'backend_server.exe' : 'backend_server';
        backendPath = path.join(process.resourcesPath, executableName);
        args = [];
    } else {
        backendPath = 'uvicorn';
        args = ['app.main:app', '--host', '127.0.0.1', '--port', '8282'];
    }

    console.log(`Starting backend from: ${backendPath} on port 8282`);

    pythonProcess = spawn(backendPath, args, {
        cwd: isPackaged ? process.resourcesPath : __dirname,
        shell: !isPackaged
    });

    pythonProcess.stdout.on('data', (data) => {
        console.log(`Python: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python Error: ${data}`);
    });

    pythonProcess.on('error', (err) => {
        console.error('Failed to start backend process:', err);
    });
}

app.on('ready', () => {
    startPython();
    createWindow();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('will-quit', () => {
    if (pythonProcess) {
        pythonProcess.kill();
    }
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});
