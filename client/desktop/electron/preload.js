const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
});

contextBridge.exposeInMainWorld('messagingAPI', {
  register:      (args) => ipcRenderer.invoke('auth:register', args),
  login:         (args) => ipcRenderer.invoke('auth:login',    args),
  sendMessage:   (args) => ipcRenderer.invoke('msg:send',      args),
  fetchMessages: ()     => ipcRenderer.invoke('msg:fetch'),
  deleteMessage: (args) => ipcRenderer.invoke('msg:delete',    args),
  revokeMessage:   (args) => ipcRenderer.invoke('msg:revoke',    args),
  downloadMessage: (args) => ipcRenderer.invoke('msg:download',  args),
});
