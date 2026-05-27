const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 960,
    height: 660,
    minWidth: 700,
    minHeight: 500,
    title: 'E2E Messenger',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // app.isPackaged is false when running via `electron .` (dev), true when bundled
  if (app.isPackaged) {
    win.loadFile(path.join(__dirname, '../dist/index.html'));
  } else {
    win.loadURL('http://localhost:5173');
  }
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
