const { app, BrowserWindow } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const waitOn = require('wait-on');

let mainWindow;
let pythonProcess;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 900,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
        },
        icon: path.join(__dirname, 'icon.png'),
    });

    // mainWindow.webContents.openDevTools();

    const url = 'http://127.0.0.1:8282';
    const healthUrl = url + '/health';

    // Polling function to wait for backend health check
    const pollBackend = async () => {
        try {
            console.log(`Polling ${healthUrl}...`);
            const response = await require('electron').net.fetch(healthUrl);
            if (response.ok) {
                console.log('Backend ready! Loading main window.');
                mainWindow.loadURL(url);
                return;
            }
        } catch (err) {
            // Ignore errors and keep polling
        }
        setTimeout(pollBackend, 500);
    };

    pollBackend();

    mainWindow.on('closed', () => {
        mainWindow = null;
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
