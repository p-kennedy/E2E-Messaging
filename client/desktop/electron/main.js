// Allow self-signed certs in development (tunnel to university VM)
if (process.env.NODE_ENV !== 'production') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { readFileSync } = require('fs');

// Resolved lazily after app.whenReady so app.getPath('userData') is available.
let addon;    // C++ native addon
let account;  // account.js ESM module
let session;  // session.js ESM module
let store;    // sessionStore.js ESM module
let HOST;     // loaded from client/config.js
let PORT;     // loaded from client/config.js

// Per-session runtime state — rebuilt from disk after every login.
let currentUser = null;   // { username, password, token, keys, kek }
let sessions    = {};     // { [partnerUsername]: ratchetState }

// ── Window ────────────────────────────────────────────────────────────────────

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

  if (app.isPackaged) {
    win.loadFile(path.join(__dirname, '../dist/index.html'));
  } else {
    win.loadURL('http://localhost:5173');
  }
}

// ── Startup ───────────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  // Load central config before anything else so HOST/PORT/SERVER_URL are set.
  const configPath = path.join(__dirname, '../../config.js');
  const config = await import(configPath);
  HOST = config.SERVER_HOST;
  PORT = config.SERVER_PORT;

  // Set env vars before importing account.js so keyPath() and SERVER_URL resolve correctly.
  process.env.KEY_STORE_DIR = app.getPath('userData');
  process.env.SERVER_URL    = config.SERVER_URL;

  // Load the C++ N-API addon.
  // Path is relative to this file: ../../network/build/Release/messaging_client.node
  const addonPath = path.join(__dirname, '../../network/build/Release/messaging_client.node');
  addon = require(addonPath);

  // Dynamically import ESM modules (main.js is CJS; these are "type":"module").
  const userCreationDir = path.join(__dirname, '../../user_creation');
  account = await import(path.join(userCreationDir, 'account.js'));
  session = await import(path.join(userCreationDir, 'session.js'));
  store   = await import(path.join(userCreationDir, 'sessionStore.js'));

  createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ── IPC: auth ─────────────────────────────────────────────────────────────────

ipcMain.handle('auth:register', async (_, { username, password }) => {
  // account.createUser generates all X3DH keys, encrypts them to disk,
  // and registers with the server (uploads prekey bundle + OPKs).
  const result = await account.createUser(username, password);
  return { userId: result.user_id, username: result.username };
});

ipcMain.handle('auth:login', async (_, { username, password }) => {
  // account.login: authenticates, decrypts local key bundle, replenishes OPKs.
  const { token, keys } = await account.login(username, password);

  // Re-derive the KEK so we can load/save sessions.
  const localSalt = readFileSync(
    path.join(process.env.KEY_STORE_DIR, `${username}_local_salt.bin`),
  );
  const kek = await account.deriveKek(Buffer.from(password, 'utf8'), localSalt);

  currentUser = { username, password, token, keys, kek };
  sessions    = store.loadSessions(username, kek);

  return { token };
});

// ── IPC: send message ─────────────────────────────────────────────────────────

ipcMain.handle('msg:send', async (_, { recipient, plaintext }) => {
  const { username, token, keys, kek } = currentUser;
  let state = sessions[recipient];

  let encResult;

  if (!state) {
    // ── First message to this recipient: full X3DH handshake ──────────────
    const bundle = await account.fetchPrekeyBundle(recipient, token);
    const identity = account.verifyIdentity(username, recipient, bundle.ikSignPublic);
    if (!identity.trusted) {
      throw new Error(
        `Identity key mismatch for ${recipient} — possible MITM. Verify out-of-band before sending.`
      );
    }

    const { rootKey, ephPublic, opkId } = session.x3dhSend(keys, bundle);

    state = session.initRatchet(rootKey, bundle.spkPublic, {
      ikSignPublic: bundle.ikSignPublic,
      ikDhPublic:   bundle.ikDhPublic,
    });

    encResult = session.ratchetEncrypt(
      state,
      Buffer.from(plaintext, 'utf8'),
      keys.ikSignPrivate,
      { ephPublic, ikDhPublic: keys.ikDhPrivate.getPublicKey(), opkId },
    );
  } else {
    // ── Subsequent message: existing ratchet state ────────────────────────
    encResult = session.ratchetEncrypt(
      state,
      Buffer.from(plaintext, 'utf8'),
      keys.ikSignPrivate,
    );
  }

  const { header, ciphertext, nonce, signature, digest } = encResult;

  addon.sendMessage(
    HOST, PORT, token, recipient,
    ciphertext.toString('base64'),
    nonce.toString('base64'),
    JSON.stringify(header),
    signature.toString('base64'),
    digest,
  );

  sessions[recipient] = state;
  store.saveSessions(username, kek, sessions);
});

// ── IPC: fetch messages ───────────────────────────────────────────────────────

ipcMain.handle('msg:fetch', async () => {
  const { username, password, token, keys, kek } = currentUser;

  const raw       = addon.fetchMessages(HOST, PORT, token);
  const { messages } = JSON.parse(raw);

  const decrypted = [];

  for (const msg of messages) {
    const header     = JSON.parse(msg.header);
    const ciphertext = Buffer.from(msg.ciphertext, 'base64');
    const nonce      = Buffer.from(msg.nonce,       'base64');
    const signature  = Buffer.from(msg.signature,   'base64');

    // Use sender_id as the session key for received messages.
    const senderKey = msg.sender_id;
    let state = sessions[senderKey];

    if (!state) {
      // ── First message from this sender: reconstruct X3DH root key ────────
      const rootKey = session.x3dhReceive(keys, header);
      state = session.initRatchetReceiver(rootKey, header, keys.spkPrivate);

      if (header.opkId !== null && header.opkId !== undefined) {
        await account.deleteConsumedOpk(username, password, header.opkId);
      }
    }

    // Verify signature before decrypting — reject tampered messages.
    const senderIkSignPublic = state.peerIdentityKeys?.ikSignPublic
      ?? (header.ikSignPublic
          ? account.PublicKey.deserialize(Buffer.from(header.ikSignPublic, 'base64'))
          : null);

    if (senderIkSignPublic) {
      const valid = session.verifyMessage(header, ciphertext, nonce, signature, senderIkSignPublic);
      if (!valid) {
        console.warn(`[security] Dropping message ${msg.message_id} — signature invalid`);
        continue;
      }
    }

    let plaintextBuf;
    try {
      plaintextBuf = session.ratchetDecrypt(state, ciphertext, nonce, header);
    } catch (err) {
      console.warn(`[security] Dropping message ${msg.message_id} — decrypt failed: ${err.message}`);
      continue;
    }

    sessions[senderKey] = state;
    decrypted.push({
      message_id:  msg.message_id,
      sender_id:   msg.sender_id,
      recipient_id: msg.recipient_id,
      plaintext:   plaintextBuf.toString('utf8'),
      created_at:  msg.created_at,
    });
  }

  store.saveSessions(username, kek, sessions);

  // Trigger OPK replenishment in the background after fetch.
  account.replenishOpksIfNeeded(username, password, token)
    .catch(err => console.warn('[account] OPK replenishment failed:', err.message));

  return decrypted;
});
