const { app, BrowserWindow, screen } = require('electron');
const path = require('path');
const os = require("os");
let mainWindow;

function getOS() {
  const platform = os.platform();
  const arch = os.arch();

  if (platform === "win32") return "windows";
  if (platform === "darwin") return "macos";
  if (platform === "linux") return arch.includes("arm") ? "linux-arm" : "linux";

  throw new Error("Unsupported OS");
}

console.log("Detected OS:", getOS());

function createWindow() {
  const { width, height } = screen.getPrimaryDisplay().workAreaSize;
  mainWindow = new BrowserWindow({
    width: width,
    height: height,
    autoHideMenuBar: false,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'templates/chat.html'));
}


app.whenReady().then(() => {
  createWindow();
});
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
