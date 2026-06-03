const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { readFileSync, writeFileSync } = require('fs');

// Resolved lazily after app.whenReady so app.getPath('userData') is available.
let addon;    // C++ native addon
let account;  // account.js ESM module
let session;  // session.js ESM module
let store;    // sessionStore.js ESM module
let HOST;     // loaded from client/config.js
let PORT;     // loaded from client/config.js

// Per-session runtime state — rebuilt from disk after every login.
let currentUser  = null;  // { username, password, token, keys, kek }
let sessions     = {};    // { [partnerUsername]: ratchetState }
let sentLog      = [];    // { message_id, recipient, plaintext, created_at }[]
let receivedLog  = [];    // { message_id, sender_id, sender_username, plaintext, created_at }[]

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
  const configPath = path.join(__dirname, '../../config.mjs');
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
  sessions     = store.loadSessions(username, kek);
  sentLog      = store.loadSentLog(username, kek);
  receivedLog  = store.loadReceivedLog(username, kek);

  return { token };
});

// ── IPC: send message ─────────────────────────────────────────────────────────

ipcMain.handle('msg:send', async (_, { recipient, plaintext }) => {
  const { username, token, keys, kek } = currentUser;

  // Sessions are keyed by recipient UUID (resolved via prekey bundle) so that
  // the session can be found on either side regardless of how the conversation
  // was initiated (username lookup vs UUID from incoming message).
  // On the first send to a recipient we don't know their UUID yet, so we
  // start with the username as a temporary key and upgrade after the bundle fetch.
  let sessionKey = recipient;
  let state = sessions[sessionKey];

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

    // Prefer UUID as the session key so both sides can find the same session.
    if (bundle.userId) {
      sessionKey = bundle.userId;
      // Migrate any old username-keyed session entry.
      if (sessions[recipient] && recipient !== sessionKey) {
        sessions[sessionKey] = sessions[recipient];
        delete sessions[recipient];
      }
      state = sessions[sessionKey];
    }

    if (!state) {
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
    }
  }

  if (!encResult) {
    // ── Subsequent message (or receiver's first reply) ────────────────────
    // The receiver's session starts with sendingChainKey = null until the
    // first DH ratchet step is performed.
    if (!state.sendingChainKey) {
      session.dhRatchetStep(state);
    }
    encResult = session.ratchetEncrypt(
      state,
      Buffer.from(plaintext, 'utf8'),
      keys.ikSignPrivate,
    );
  }

  const { header, ciphertext, nonce, signature, digest } = encResult;

  const responseStr = addon.sendMessage(
    HOST, PORT, token, recipient,
    ciphertext.toString('base64'),
    nonce.toString('base64'),
    JSON.stringify(header),
    signature.toString('base64'),
    digest,
  );

  // Parse the server-assigned message_id so the sender can revoke later.
  let serverMessageId = require('node:crypto').randomUUID();
  try { serverMessageId = JSON.parse(responseStr).message_id ?? serverMessageId; } catch {}

  sentLog.push({ message_id: serverMessageId, recipient, plaintext, created_at: new Date().toISOString() });
  store.saveSentLog(username, kek, sentLog);

  sessions[sessionKey] = state;
  store.saveSessions(username, kek, sessions);
});

// ── IPC: delete message ───────────────────────────────────────────────────────

ipcMain.handle('msg:delete', async (_, { messageId }) => {
  const { token } = currentUser;
  const res = await fetch(
    `${process.env.SERVER_URL}/api/messages/${encodeURIComponent(messageId)}`,
    { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } },
  );
  if (!res.ok) throw new Error(`Delete failed (${res.status}): ${await res.text()}`);
});

// ── IPC: revoke message (sender retracts before recipient reads) ───────────────

ipcMain.handle('msg:revoke', async (_, { messageId }) => {
  const { token, username, kek } = currentUser;
  const res = await fetch(
    `${process.env.SERVER_URL}/api/messages/${encodeURIComponent(messageId)}`,
    { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } },
  );
  if (!res.ok) throw new Error(`Revoke failed (${res.status}): ${await res.text()}`);
  sentLog = sentLog.filter(m => m.message_id !== messageId);
  store.saveSentLog(username, kek, sentLog);
});

// ── IPC: download message ─────────────────────────────────────────────────────

ipcMain.handle('msg:download', async (_, { senderName, plaintext, createdAt }) => {
  const { filePath } = await dialog.showSaveDialog({
    title: 'Save message',
    defaultPath: `message-${Date.now()}.txt`,
    filters: [{ name: 'Text file', extensions: ['txt'] }],
  });
  if (!filePath) return;
  const date = new Date(createdAt).toLocaleString();
  writeFileSync(filePath, `From: ${senderName}\nDate: ${date}\n\n${plaintext}\n`, 'utf8');
});

// ── IPC: fetch sent/received messages (loaded from local encrypted logs) ──────

ipcMain.handle('msg:fetchSent',     () => sentLog);
ipcMain.handle('msg:fetchReceived', () => receivedLog);

// ── IPC: fetch messages ───────────────────────────────────────────────────────

ipcMain.handle('msg:fetch', async () => {
  if (!currentUser) return [];
  const { username, password, token, keys, kek } = currentUser;

  const raw       = addon.fetchMessages(HOST, PORT, token);
  const { messages } = JSON.parse(raw);

  const decrypted = [];

  for (const msg of messages) {
    const header     = JSON.parse(msg.header);
    const ciphertext = Buffer.from(msg.ciphertext, 'base64');
    const nonce      = Buffer.from(msg.nonce,       'base64');
    const signature  = Buffer.from(msg.signature,   'base64');

    // Key sessions by sender_username (same key the sender uses via prekey bundle userId).
    // Fall back to sender_id (UUID) so old sessions loaded from disk still work.
    const senderKey = msg.sender_username ?? msg.sender_id;
    let state = sessions[senderKey] ?? sessions[msg.sender_id];

    if (!state) {
      // ── First message from this sender: reconstruct X3DH root key ────────
      if (!header.ikDhPublic || !header.ephPublic) {
        console.warn(`[msg:fetch] Dropping message ${msg.message_id} — no X3DH header and no session state`);
        continue;
      }
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
      message_id:      msg.message_id,
      sender_id:       msg.sender_id,
      sender_username: msg.sender_username ?? null,
      recipient_id:    msg.recipient_id,
      plaintext:       plaintextBuf.toString('utf8'),
      created_at:      msg.created_at,
    });
  }

  store.saveSessions(username, kek, sessions);

  if (decrypted.length > 0) {
    receivedLog.push(...decrypted);
    store.saveReceivedLog(username, kek, receivedLog);
  }

  // Delete successfully decrypted messages from the server.
  // The Double Ratchet state has already advanced past these messages, so
  // re-fetching them on the next poll would only produce decrypt failures.
  // Save sessions first so a delete failure can't cause message loss.
  await Promise.all(decrypted.map(msg =>
    fetch(
      `${process.env.SERVER_URL}/api/messages/${encodeURIComponent(msg.message_id)}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } },
    ).catch(err => console.warn(`[msg:fetch] Failed to delete message ${msg.message_id}:`, err.message))
  ));

  // Trigger OPK replenishment in the background after fetch.
  account.replenishOpksIfNeeded(username, password, token)
    .catch(err => console.warn('[account] OPK replenishment failed:', err.message));

  return decrypted;
});
