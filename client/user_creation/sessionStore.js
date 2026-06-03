// Ratchet session state persistence — encrypts the full per-conversation
// Double Ratchet state to disk so sessions survive app restarts.
//
// Storage layout:
//   <KEY_STORE_DIR>/<username>_sessions.bin
//     = [12-byte nonce] + AES-256-GCM( JSON(sessions) ) + [16-byte GCM tag]
//
// The same KEK (Argon2id key) used for private key storage is reused here
// so there is only one password-derived secret to manage per user.

import { PrivateKey, PublicKey } from '@signalapp/libsignal-client';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

function keyPath(filename) {
    const dir = process.env.KEY_STORE_DIR;
    return dir ? join(dir, filename) : filename;
}

// ── Serialization helpers ─────────────────────────────────────────────────────

function serializeKey(key) {
    if (!key) return null;
    return key.serialize().toString('base64');
}

function deserializePrivate(b64) {
    return b64 ? PrivateKey.deserialize(Buffer.from(b64, 'base64')) : null;
}

function deserializePublic(b64) {
    return b64 ? PublicKey.deserialize(Buffer.from(b64, 'base64')) : null;
}

function serializeState(state) {
    return {
        rootKey:             state.rootKey ? Buffer.from(state.rootKey).toString('base64') : null,
        sendingChainKey:     state.sendingChainKey ? Buffer.from(state.sendingChainKey).toString('base64') : null,
        receivingChainKey:   state.receivingChainKey ? Buffer.from(state.receivingChainKey).toString('base64') : null,
        localRatchetPrivate: serializeKey(state.localRatchetPrivate),
        localRatchetPublic:  serializeKey(state.localRatchetPublic),
        remoteRatchetPublic: serializeKey(state.remoteRatchetPublic),
        Ns:                  state.Ns,
        Nr:                  state.Nr,
        PN:                  state.PN,
        // MKSKIPPED: Map<"pubB64:Nr" → Buffer> → array of [key, hex]
        MKSKIPPED: [...(state.MKSKIPPED ?? new Map()).entries()].map(
            ([k, v]) => [k, Buffer.from(v).toString('base64')]
        ),
        peerIdentityKeys: state.peerIdentityKeys ? {
            ikSignPublic: serializeKey(state.peerIdentityKeys.ikSignPublic),
            ikDhPublic:   serializeKey(state.peerIdentityKeys.ikDhPublic),
        } : null,
        fingerprintRecords: state.fingerprintRecords ?? null,
        isEstablished:      state.isEstablished ?? true,
    };
}

function deserializeState(s) {
    const MKSKIPPED = new Map(
        (s.MKSKIPPED ?? []).map(([k, v]) => [k, Buffer.from(v, 'base64')])
    );

    return {
        rootKey:             s.rootKey             ? Buffer.from(s.rootKey,           'base64') : null,
        sendingChainKey:     s.sendingChainKey     ? Buffer.from(s.sendingChainKey,   'base64') : null,
        receivingChainKey:   s.receivingChainKey   ? Buffer.from(s.receivingChainKey, 'base64') : null,
        localRatchetPrivate: deserializePrivate(s.localRatchetPrivate),
        localRatchetPublic:  deserializePublic(s.localRatchetPublic),
        remoteRatchetPublic: deserializePublic(s.remoteRatchetPublic),
        Ns:                  s.Ns,
        Nr:                  s.Nr,
        PN:                  s.PN,
        MKSKIPPED,
        peerIdentityKeys: s.peerIdentityKeys ? {
            ikSignPublic: deserializePublic(s.peerIdentityKeys.ikSignPublic),
            ikDhPublic:   deserializePublic(s.peerIdentityKeys.ikDhPublic),
        } : null,
        fingerprintRecords: s.fingerprintRecords ?? null,
        isEstablished:      s.isEstablished ?? true,
    };
}

// ── AES-256-GCM helpers ───────────────────────────────────────────────────────

function encrypt(kek, plaintext) {
    const nonce  = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, nonce);
    const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
}

function decrypt(kek, blob) {
    const nonce  = blob.subarray(0, 12);
    const tag    = blob.subarray(-16);
    const ct     = blob.subarray(12, -16);
    const d      = createDecipheriv('aes-256-gcm', kek, nonce);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
}

// ── Public API ────────────────────────────────────────────────────────────────

// Load all session states for a user from disk.
// Returns a plain object: { [partnerUsername]: ratchetState }
// Returns {} if no file exists yet.
export function loadSessions(username, kek) {
    const path = keyPath(`${username}_sessions.bin`);
    if (!existsSync(path)) return {};
    try {
        const blob = readFileSync(path);
        const json = decrypt(kek, blob).toString('utf8');
        const raw  = JSON.parse(json);
        const out  = {};
        for (const [partner, s] of Object.entries(raw)) {
            out[partner] = deserializeState(s);
        }
        return out;
    } catch (err) {
        console.warn('[sessionStore] Failed to load sessions:', err.message);
        return {};
    }
}

// Persist all session states for a user to disk.
export function saveSessions(username, kek, sessions) {
    const raw = {};
    for (const [partner, state] of Object.entries(sessions)) {
        raw[partner] = serializeState(state);
    }
    const blob = encrypt(kek, Buffer.from(JSON.stringify(raw), 'utf8'));
    writeFileSync(keyPath(`${username}_sessions.bin`), blob);
}

// ── Sent log ──────────────────────────────────────────────────────────────────
// Stores { message_id, recipient, plaintext, created_at }[] encrypted with the KEK.

export function loadSentLog(username, kek) {
    const p = keyPath(`${username}_sent_log.bin`);
    if (!existsSync(p)) return [];
    try {
        return JSON.parse(decrypt(kek, readFileSync(p)).toString('utf8'));
    } catch {
        return [];
    }
}

export function saveSentLog(username, kek, log) {
    writeFileSync(
        keyPath(`${username}_sent_log.bin`),
        encrypt(kek, Buffer.from(JSON.stringify(log), 'utf8')),
    );
}
