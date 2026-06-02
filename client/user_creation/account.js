import { PrivateKey, PublicKey } from '@signalapp/libsignal-client';
import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'node:crypto';
import argon2 from 'argon2';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';

// Re-exported for use by tests without requiring a separate install
export { PrivateKey, PublicKey };

const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:8000';

// Key files are written to KEY_STORE_DIR when set (Electron sets this to
// app.getPath('userData') before importing this module), otherwise CWD.
function keyPath(filename) {
    const dir = process.env.KEY_STORE_DIR;
    return dir ? join(dir, filename) : filename;
}
const NUM_ONE_TIME_PREKEYS = 100;
const OPK_REPLENISH_THRESHOLD = 20;  // replenish when server count drops below this

// Argon2id KDF — matches Python: iterations=2, lanes=2, memory=2^16 KiB
export async function deriveKek(password, salt) {
    return argon2.hash(password, {
        type: argon2.argon2id,
        salt,
        hashLength: 32,
        timeCost: 2,
        parallelism: 2,
        memoryCost: 65536,
        raw: true,
    });
}

function aesGcmEncrypt(key, nonce, plaintext) {
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

function aesGcmDecrypt(key, nonce, ciphertextWithTag) {
    const tag = ciphertextWithTag.subarray(-16);
    const ciphertext = ciphertextWithTag.subarray(0, -16);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export async function createUser(username, password) {
    // Identity signing key: Curve25519 / XEdDSA (Signal's signing scheme over Curve25519)
    // sign() produces an Ed25519-compatible signature via the XEdDSA transform
    const ikSignPrivate = PrivateKey.generate();
    const ikSignPublic = ikSignPrivate.getPublicKey();

    // Identity DH key: X25519 — long-term key used in X3DH key agreement, never rotated
    const ikDhPrivate = PrivateKey.generate();
    const ikDhPublic = ikDhPrivate.getPublicKey();

    // Signed prekey: X25519 — medium-term, signed so the server cannot substitute it
    const spkPrivate = PrivateKey.generate();
    const spkPublic = spkPrivate.getPublicKey();
    // serialize() returns Signal's key format: 0x05 type-byte + 32 raw bytes = 33 bytes
    const spkSignature = ikSignPrivate.sign(spkPublic.serialize());

    // One-time prekeys: X25519 — each consumed by exactly one session initiation
    const opkPairs = Array.from({ length: NUM_ONE_TIME_PREKEYS }, () => PrivateKey.generate());

    // Derive KEK: Argon2id(password, localSalt) — 32 bytes, never leaves this device
    const localSalt = randomBytes(16);
    const kek = await deriveKek(Buffer.from(password, 'utf8'), localSalt);

    // Private bundle: concatenated 32-byte serialized private keys
    const privateBundle = Buffer.concat([
        ikSignPrivate.serialize(),
        ikDhPrivate.serialize(),
        spkPrivate.serialize(),
        ...opkPairs.map(k => k.serialize()),
    ]);

    // Encrypt bundle: AES-256-GCM, 12-byte nonce, 16-byte auth tag appended by aesGcmEncrypt
    const nonce = randomBytes(12);
    const encryptedBundle = aesGcmEncrypt(kek, nonce, privateBundle);

    // Persist locally — nonce prepended to ciphertext+tag
    writeFileSync(keyPath(`${username}_private_keys.bin`), Buffer.concat([nonce, encryptedBundle]));
    writeFileSync(keyPath(`${username}_local_salt.bin`), localSalt);

    // Public prekey bundle — uploaded so others can initiate X3DH sessions with this user
    const prekeyBundle = {
        ik_sign_pub:   ikSignPublic.serialize().toString('base64'),
        ik_dh_pub:     ikDhPublic.serialize().toString('base64'),
        spk_pub:       spkPublic.serialize().toString('base64'),
        spk_signature: spkSignature.toString('base64'),
        opk_pubs: opkPairs.map((pair, i) => ({
            id: i,
            key: pair.getPublicKey().serialize().toString('base64'),
        })),
    };

    const response = await fetch(`${SERVER_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username,
            password,
            public_key: JSON.stringify(prekeyBundle),
        }),
    });

    if (!response.ok) {
        throw new Error(`Registration failed (${response.status}): ${await response.text()}`);
    }

    return response.json();
}

// Checks the server OPK count and uploads new keys if below threshold.
// Works with an already-decrypted bundle and KEK — used internally by login()
// to avoid re-reading and re-decrypting the key file.
// Returns the (potentially extended) private bundle.
async function _replenish(username, kek, token, privateBundle) {
    const countRes = await fetch(`${SERVER_URL}/api/users/me/opk-count`, {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (!countRes.ok) return privateBundle;
    const { count: serverOpkCount } = await countRes.json();

    if (serverOpkCount >= OPK_REPLENISH_THRESHOLD) return privateBundle;

    const needed         = NUM_ONE_TIME_PREKEYS - serverOpkCount;
    const totalLocalOpks = (privateBundle.length - 96) / 32;
    const newOpkPairs    = Array.from({ length: needed }, () => PrivateKey.generate());

    await fetch(`${SERVER_URL}/api/users/me/opks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
            opk_pubs: newOpkPairs.map((k, i) => ({
                id:  totalLocalOpks + i,
                key: k.getPublicKey().serialize().toString('base64'),
            })),
        }),
    });

    const extended = Buffer.concat([privateBundle, ...newOpkPairs.map(k => k.serialize())]);
    const newNonce = randomBytes(12);
    writeFileSync(
        keyPath(`${username}_private_keys.bin`),
        Buffer.concat([newNonce, aesGcmEncrypt(kek, newNonce, extended)]),
    );

    console.log(`[account] Replenished OPKs: uploaded ${needed} new keys (server was at ${serverOpkCount}).`);
    return extended;
}

// Public replenishment entry point for use outside of login (e.g. after fetching messages).
// Reads and re-encrypts the key file independently — call whenever OPK depletion may have occurred.
export async function replenishOpksIfNeeded(username, password, token) {
    const localSalt   = readFileSync(keyPath(`${username}_local_salt.bin`));
    const keyFile     = readFileSync(keyPath(`${username}_private_keys.bin`));
    const kek         = await deriveKek(Buffer.from(password, 'utf8'), localSalt);
    const privateBundle = aesGcmDecrypt(kek, keyFile.subarray(0, 12), keyFile.subarray(12));
    await _replenish(username, kek, token, privateBundle);
}

// Returns { token, keys: { ikSignPrivate, ikDhPrivate, spkPrivate, opkPrivates } }
export async function login(username, password) {
    const response = await fetch(`${SERVER_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
        throw new Error(`Login failed (${response.status}): ${await response.text()}`);
    }

    const { token } = await response.json();

    const localSalt = readFileSync(keyPath(`${username}_local_salt.bin`));
    const keyFile   = readFileSync(keyPath(`${username}_private_keys.bin`));
    const kek       = await deriveKek(Buffer.from(password, 'utf8'), localSalt);

    const nonce          = keyFile.subarray(0, 12);
    const privateBundle  = await _replenish(
        username, kek, token,
        aesGcmDecrypt(kek, nonce, keyFile.subarray(12)),
    );

    const ikSignPrivate = PrivateKey.deserialize(privateBundle.subarray(0, 32));
    const ikDhPrivate   = PrivateKey.deserialize(privateBundle.subarray(32, 64));
    const spkPrivate    = PrivateKey.deserialize(privateBundle.subarray(64, 96));

    const opkPrivates = [];
    for (let offset = 96; offset < privateBundle.length; offset += 32) {
        const bytes = privateBundle.subarray(offset, offset + 32);
        opkPrivates.push(bytes.every(b => b === 0) ? null : PrivateKey.deserialize(bytes));
    }

    return { token, keys: { ikSignPrivate, ikDhPrivate, spkPrivate, opkPrivates } };
}

// Zeroes the 32-byte private key for the given OPK ID in the encrypted key file.
// Call this after a successful X3DH session establishment to ensure the OPK is never reused.
export async function deleteConsumedOpk(username, password, opkId) {
    const localSalt = readFileSync(keyPath(`${username}_local_salt.bin`));
    const keyFile   = readFileSync(keyPath(`${username}_private_keys.bin`));
    const kek       = await deriveKek(Buffer.from(password, 'utf8'), localSalt);
    const privateBundle = aesGcmDecrypt(kek, keyFile.subarray(0, 12), keyFile.subarray(12));

    const offset = 96 + opkId * 32;
    if (offset + 32 > privateBundle.length) {
        throw new Error(`OPK id ${opkId} out of range`);
    }
    privateBundle.fill(0, offset, offset + 32);

    const newNonce = randomBytes(12);
    writeFileSync(
        keyPath(`${username}_private_keys.bin`),
        Buffer.concat([newNonce, aesGcmEncrypt(kek, newNonce, privateBundle)]),
    );
}

// Fetches messages from the server and triggers OPK replenishment in the background.
// Replenishment is non-blocking — message delivery is never delayed by key uploads.
export async function fetchMessages(token, username, password) {
    const response = await fetch(`${SERVER_URL}/api/messages`, {
        headers: { 'Authorization': `Bearer ${token}` },
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch messages (${response.status}): ${await response.text()}`);
    }

    replenishOpksIfNeeded(username, password, token)
        .catch(err => console.warn('[account] OPK replenishment failed:', err.message));

    return (await response.json()).messages;
}

// Returns Bob's deserialized prekey bundle after verifying the SPK signature.
// Throws if the user is not found, the request fails, or the signature is invalid.
export async function fetchPrekeyBundle(recipientUsername, token) {
    const response = await fetch(
        `${SERVER_URL}/api/users/${encodeURIComponent(recipientUsername)}/prekey-bundle`,
        { headers: { 'Authorization': `Bearer ${token}` } },
    );

    if (!response.ok) {
        throw new Error(`Failed to fetch prekey bundle (${response.status}): ${await response.text()}`);
    }

    const raw = await response.json();

    const ikSignPublic = PublicKey.deserialize(Buffer.from(raw.ik_sign_pub, 'base64'));
    const ikDhPublic   = PublicKey.deserialize(Buffer.from(raw.ik_dh_pub,   'base64'));
    const spkPublic    = PublicKey.deserialize(Buffer.from(raw.spk_pub,     'base64'));
    const spkSignature = Buffer.from(raw.spk_signature, 'base64');

    // Verify the SPK was signed by the recipient's identity key.
    // Catches a server substituting a different SPK.
    if (!ikSignPublic.verify(spkPublic.serialize(), spkSignature)) {
        throw new Error('SPK signature invalid — prekey bundle may have been tampered with');
    }

    if (!raw.opk_pub) {
        console.warn(
            `[security] ${recipientUsername} has no remaining one-time prekeys. ` +
            'This session will use 3DH instead of 4DH — forward secrecy is reduced.'
        );
    }

    return {
        ikSignPublic,
        ikDhPublic,
        spkPublic,
        spkSignature,
        opkPublic: raw.opk_pub ? PublicKey.deserialize(Buffer.from(raw.opk_pub, 'base64')) : null,
        opkId:     raw.opk_id ?? null,
    };
}


// Computes a short human-readable fingerprint from a serialized public key.
function fingerprint(pubKey) {
    return createHash('sha256').update(pubKey.serialize()).digest('hex');
}

// TOFU identity verification.
//
// First encounter with a contact: stores their identity key fingerprint and trusts them.
// Subsequent encounters: compares the live fingerprint against the stored one.
//
// Returns { isNew, trusted, fingerprint }.
// A mismatch sets trusted=false and emits a warning — the caller decides whether to abort.
//
// Contacts are stored in ${ownerUsername}_contacts.json (unencrypted — fingerprints are
// derived from public keys, but the file does reveal your contact list).
export function verifyIdentity(ownerUsername, contactUsername, ikSignPublic) {
    const live = fingerprint(ikSignPublic);
    const contactsPath = keyPath(`${ownerUsername}_contacts.json`);

    let contacts = {};
    try {
        contacts = JSON.parse(readFileSync(contactsPath, 'utf8'));
    } catch (err) {
        if (err.code !== 'ENOENT') throw err;
        // ENOENT: file doesn't exist yet — writeFileSync below will create it
    }

    const known = contacts[contactUsername];

    if (!known) {
        contacts[contactUsername] = { fingerprint: live, firstSeen: new Date().toISOString() };
        writeFileSync(contactsPath, JSON.stringify(contacts, null, 2));
        console.log(`[identity] First contact with ${contactUsername}. Fingerprint: ${live.slice(0, 16)}...`);
        return { isNew: true, trusted: true, fingerprint: live };
    }

    if (known.fingerprint !== live) {
        console.warn(
            `[security] WARNING: ${contactUsername}'s identity key has changed!\n` +
            `  Stored:  ${known.fingerprint}\n` +
            `  Current: ${live}\n` +
            'This may indicate a compromised account or a key reset. Verify out-of-band before continuing.'
        );
        return { isNew: false, trusted: false, fingerprint: live, storedFingerprint: known.fingerprint };
    }

    return { isNew: false, trusted: true, fingerprint: live };
}


// CLI entry point
if (new URL(import.meta.url).pathname === process.argv[1]) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const command  = await rl.question('Command (register/login): ');
    const username = await rl.question('Username: ');
    const password = await rl.question('Password: ');
    rl.close();

    if (command === 'register') {
        const user = await createUser(username, password);
        console.log(`User '${username}' created (user_id: ${user.user_id}).`);
        console.log(`  Private keys encrypted and stored in ${username}_private_keys.bin`);
        console.log(`  ${NUM_ONE_TIME_PREKEYS} one-time prekeys uploaded to server.`);
    } else if (command === 'login') {
        const { token, keys } = await login(username, password);
        console.log(`Logged in as '${username}'.`);
        console.log(`  JWT token: ${token}`);
        console.log(`  Decrypted ${3 + keys.opkPrivates.length} private keys from local bundle.`);
    } else {
        console.error(`Unknown command: ${command}`);
        process.exit(1);
    }
}
