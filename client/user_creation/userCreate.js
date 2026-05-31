import { PrivateKey } from '@signalapp/libsignal-client';
import { randomBytes, createCipheriv } from 'node:crypto';
import argon2 from 'argon2';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';

// Re-exported for use by tests without requiring a separate install
export { PrivateKey };

const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:8000';
const NUM_ONE_TIME_PREKEYS = 100;

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
    writeFileSync(`${username}_private_keys.bin`, Buffer.concat([nonce, encryptedBundle]));
    writeFileSync(`${username}_local_salt.bin`, localSalt);

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

// CLI entry point
if (new URL(import.meta.url).pathname === process.argv[1]) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const username = await rl.question('Enter username: ');
    const password = await rl.question('Enter password: ');
    rl.close();

    const user = await createUser(username, password);
    console.log(`User '${username}' created (user_id: ${user.user_id}).`);
    console.log(`  Private keys encrypted and stored in ${username}_private_keys.bin`);
    console.log(`  ${NUM_ONE_TIME_PREKEYS} one-time prekeys uploaded to server.`);
}
