// Central server configuration for all client modules.
// Electron main.js, account.js, and the C++ addon all read from here.
// Override at runtime with the SERVER_URL / SERVER_HOST / SERVER_PORT env vars.

export const SERVER_HOST = process.env.SERVER_HOST ?? 'cpa-attack.theburkenator.com';
export const SERVER_PORT = process.env.SERVER_PORT ? Number(process.env.SERVER_PORT) : 443;
export const SERVER_URL  = process.env.SERVER_URL  ?? `https://${SERVER_HOST}`;

// Dev fallback used by the Vite renderer (api.js) during local development.
// Ignored once the renderer is fully migrated to IPC.
export const DEV_SERVER_URL = 'http://localhost:8000';
