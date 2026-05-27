const { contextBridge } = require('electron');

// The renderer talks to the FastAPI server directly via fetch.
// Expose platform info only — no node APIs in the renderer.
contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
});
