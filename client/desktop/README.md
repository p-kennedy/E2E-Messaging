# E2E Messenger — Desktop Client

Electron + React desktop app that talks to the FastAPI server.

## Structure

```
client/desktop/
├── electron/
│   ├── main.js          — Electron window, loads Vite in dev / dist/ in prod
│   └── preload.js       — contextBridge (no Node APIs in renderer)
├── src/
│   ├── api.js           — fetch wrapper for your FastAPI endpoints
│   ├── App.jsx          — auth routing, session stored in localStorage
│   ├── App.css          — Signal-style dark sidebar + light chat
│   ├── main.jsx
│   └── components/
│       ├── AuthScreen.jsx      — login / register tabs
│       ├── ChatApp.jsx         — message polling (5s interval), conversation grouping
│       ├── ConversationList.jsx — left sidebar, search bar starts new chats
│       └── ChatWindow.jsx      — bubbles, send form
├── .env                 — VITE_API_URL=http://localhost:8000
├── index.html
├── vite.config.js
└── package.json
```

## Running

```bash
cd client/desktop
npm install
npm run dev       # starts Vite + Electron together
```

## Packaging

```bash
npm run package   # builds dist/ then electron-builder → release/
```
