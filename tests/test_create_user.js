// Unit tests for account.js and session.js — crypto operations only, no server required.
// Run from the repo root:  node tests/test_create_user.js

import { PrivateKey, deriveKek, createUser } from '../client/user_creation/account.js';
import { x3dhSend } from '../client/user_creation/session.js';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, unlinkSync, readFileSync } from 'node:fs';

const TEST_USERNAME = 'test_user_crypto';
const TEST_PASSWORD = 'test_password_123';
const NUM_OPKs = 100;

function aesGcmDecrypt(key, nonce, ciphertextWithTag) {
    const tag = ciphertextWithTag.slice(-16);
    const ciphertext = ciphertextWithTag.slice(0, -16);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

const failures = [];
const pass = msg => console.log(`  PASS  ${msg}`);
const fail = (msg, err) => {
    const line = `  FAIL  ${msg}: ${err?.message ?? err}`;
    failures.push(line);
    console.log(line);
};

// --- Test 1: PrivateKey.generate() produces correct key sizes ---
try {
    const priv = PrivateKey.generate();
    const privBytes = priv.serialize();
    const pubBytes = priv.getPublicKey().serialize();
    if (privBytes.length !== 32) throw new Error(`private key: expected 32 bytes, got ${privBytes.length}`);
    // Signal serializes public keys as 0x05 type-byte + 32 raw bytes = 33 bytes
    if (pubBytes.length !== 33) throw new Error(`public key: expected 33 bytes, got ${pubBytes.length}`);
    if (pubBytes[0] !== 0x05) throw new Error(`expected 0x05 type prefix, got 0x${pubBytes[0].toString(16)}`);
    pass('key sizes correct (priv=32 bytes, pub=33 bytes with 0x05 prefix)');
} catch (e) { fail('key size check', e); }

// --- Test 2: XEdDSA signature over SPK public key verifies correctly ---
try {
    const ikSign = PrivateKey.generate();
    const spkPriv = PrivateKey.generate();
    const spkPubBytes = spkPriv.getPublicKey().serialize();
    const sig = ikSign.sign(spkPubBytes);
    if (sig.length !== 64) throw new Error(`signature: expected 64 bytes, got ${sig.length}`);
    const valid = ikSign.getPublicKey().verify(spkPubBytes, sig);
    if (!valid) throw new Error('signature did not verify');
    pass('XEdDSA signature over SPK public key verifies correctly');
} catch (e) { fail('signature verification', e); }

// --- Test 3: Argon2id derives a 32-byte key ---
try {
    const salt = randomBytes(16);
    const kek = await deriveKek(Buffer.from(TEST_PASSWORD, 'utf8'), salt);
    if (kek.length !== 32) throw new Error(`expected 32 bytes, got ${kek.length}`);
    pass('Argon2id derives 32-byte KEK');
} catch (e) { fail('Argon2id derivation', e); }

// --- Test 4: Same password+salt always produces the same KEK ---
try {
    const salt = randomBytes(16);
    const kek1 = await deriveKek(Buffer.from(TEST_PASSWORD, 'utf8'), salt);
    const kek2 = await deriveKek(Buffer.from(TEST_PASSWORD, 'utf8'), salt);
    if (!Buffer.from(kek1).equals(Buffer.from(kek2))) throw new Error('KEKs differ');
    pass('Argon2id is deterministic for same password+salt');
} catch (e) { fail('Argon2id determinism', e); }

// --- Test 5: Private bundle survives AES-256-GCM round-trip ---
try {
    const keys = Array.from({ length: 3 + NUM_OPKs }, () => PrivateKey.generate());
    const bundle = Buffer.concat(keys.map(k => k.serialize()));

    const expectedLen = 32 * (3 + NUM_OPKs);
    if (bundle.length !== expectedLen)
        throw new Error(`bundle length: expected ${expectedLen}, got ${bundle.length}`);

    const salt = randomBytes(16);
    const kek = await deriveKek(Buffer.from(TEST_PASSWORD, 'utf8'), salt);
    const nonce = randomBytes(12);

    const cipher = createCipheriv('aes-256-gcm', kek, nonce);
    const encrypted = Buffer.concat([
        Buffer.concat([cipher.update(bundle), cipher.final()]),
        cipher.getAuthTag(),
    ]);

    const decrypted = aesGcmDecrypt(kek, nonce, encrypted);
    if (!decrypted.equals(bundle)) throw new Error('decrypted bundle does not match original');
    pass(`private bundle (${bundle.length} bytes) encrypts and decrypts correctly`);
} catch (e) { fail('AES-256-GCM round-trip', e); }

// --- Test 6: Prekey bundle has correct structure and sequential OPK IDs ---
try {
    const ikSign = PrivateKey.generate();
    const ikDh = PrivateKey.generate();
    const spk = PrivateKey.generate();
    const opks = Array.from({ length: NUM_OPKs }, () => PrivateKey.generate());
    const spkSig = ikSign.sign(spk.getPublicKey().serialize());

    const bundle = {
        ik_sign_pub:   ikSign.getPublicKey().serialize().toString('base64'),
        ik_dh_pub:     ikDh.getPublicKey().serialize().toString('base64'),
        spk_pub:       spk.getPublicKey().serialize().toString('base64'),
        spk_signature: spkSig.toString('base64'),
        opk_pubs: opks.map((k, i) => ({ id: i, key: k.getPublicKey().serialize().toString('base64') })),
    };

    for (const field of ['ik_sign_pub', 'ik_dh_pub', 'spk_pub', 'spk_signature', 'opk_pubs']) {
        if (!(field in bundle)) throw new Error(`missing field: ${field}`);
    }
    if (bundle.opk_pubs.length !== NUM_OPKs)
        throw new Error(`expected ${NUM_OPKs} OPKs, got ${bundle.opk_pubs.length}`);
    for (let i = 0; i < bundle.opk_pubs.length; i++) {
        if (bundle.opk_pubs[i].id !== i) throw new Error(`OPK id mismatch at index ${i}`);
    }

    pass(`prekey bundle structure correct (${NUM_OPKs} OPKs, all fields present)`);
} catch (e) { fail('prekey bundle structure', e); }

// --- Test 7: createUser writes local key files (fetch mocked) ---
try {
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
        ok: true,
        json: async () => ({ user_id: 'test-uuid', username: TEST_USERNAME }),
    });

    const result = await createUser(TEST_USERNAME, TEST_PASSWORD);
    globalThis.fetch = origFetch;

    if (result.username !== TEST_USERNAME) throw new Error(`unexpected username: ${result.username}`);
    if (!existsSync(`${TEST_USERNAME}_private_keys.bin`))
        throw new Error('_private_keys.bin not written');
    if (!existsSync(`${TEST_USERNAME}_local_salt.bin`))
        throw new Error('_local_salt.bin not written');

    const saltFile = readFileSync(`${TEST_USERNAME}_local_salt.bin`);
    if (saltFile.length !== 16) throw new Error(`salt: expected 16 bytes, got ${saltFile.length}`);

    pass('createUser writes private_keys.bin and local_salt.bin');
} catch (e) { fail('createUser local file writes', e); }

// --- Test 8: x3dhSend (4DH) returns correct output shape ---
try {
    const initiatorIkDh = PrivateKey.generate();
    const responderIkDh = PrivateKey.generate();
    const responderSpk  = PrivateKey.generate();
    const responderOpk  = PrivateKey.generate();

    const spkSig = PrivateKey.generate().sign(responderSpk.getPublicKey().serialize());

    const bundle = {
        ikDhPublic:  responderIkDh.getPublicKey(),
        spkPublic:   responderSpk.getPublicKey(),
        spkSignature: spkSig,
        opkPublic:   responderOpk.getPublicKey(),
        opkId: 7,
    };

    const { rootKey, ephPublic, opkId } = x3dhSend({ ikDhPrivate: initiatorIkDh }, bundle);

    if (rootKey.length !== 32) throw new Error(`rootKey: expected 32 bytes, got ${rootKey.length}`);
    if (ephPublic.serialize().length !== 33) throw new Error('ephPublic: expected 33-byte Signal key');
    if (opkId !== 7) throw new Error(`opkId: expected 7, got ${opkId}`);

    pass('x3dhSend (4DH): rootKey=32 bytes, ephPublic=33 bytes, opkId preserved');
} catch (e) { fail('x3dhSend 4DH shape', e); }

// --- Test 9: x3dhSend (3DH) — no OPK, opkId is null ---
try {
    const initiatorIkDh = PrivateKey.generate();
    const bundle = {
        ikDhPublic: PrivateKey.generate().getPublicKey(),
        spkPublic:  PrivateKey.generate().getPublicKey(),
        opkPublic:  null,
        opkId:      null,
    };

    const { rootKey, opkId } = x3dhSend({ ikDhPrivate: initiatorIkDh }, bundle);

    if (rootKey.length !== 32) throw new Error(`rootKey: expected 32 bytes, got ${rootKey.length}`);
    if (opkId !== null) throw new Error('opkId should be null for 3DH path');

    pass('x3dhSend (3DH): rootKey=32 bytes, opkId=null');
} catch (e) { fail('x3dhSend 3DH shape', e); }

// --- Test 10: two x3dhSend calls produce different root keys (ephemeral randomness) ---
try {
    const initiatorIkDh = PrivateKey.generate();
    const bundle = {
        ikDhPublic: PrivateKey.generate().getPublicKey(),
        spkPublic:  PrivateKey.generate().getPublicKey(),
        opkPublic:  PrivateKey.generate().getPublicKey(),
        opkId: 0,
    };

    const { rootKey: rk1 } = x3dhSend({ ikDhPrivate: initiatorIkDh }, bundle);
    const { rootKey: rk2 } = x3dhSend({ ikDhPrivate: initiatorIkDh }, bundle);

    if (Buffer.from(rk1).equals(Buffer.from(rk2))) throw new Error('root keys should differ across calls');

    pass('x3dhSend: distinct root keys across calls (ephemeral randomness)');
} catch (e) { fail('x3dhSend ephemeral randomness', e); }

// --- Test 11: 3DH and 4DH paths produce different root keys ---
try {
    const initiatorIkDh = PrivateKey.generate();
    const responderIkDh = PrivateKey.generate();
    const responderSpk  = PrivateKey.generate();
    const responderOpk  = PrivateKey.generate();

    const bundleWith    = { ikDhPublic: responderIkDh.getPublicKey(), spkPublic: responderSpk.getPublicKey(), opkPublic: responderOpk.getPublicKey(), opkId: 0 };
    const bundleWithout = { ikDhPublic: responderIkDh.getPublicKey(), spkPublic: responderSpk.getPublicKey(), opkPublic: null, opkId: null };

    const { rootKey: rk4 } = x3dhSend({ ikDhPrivate: initiatorIkDh }, bundleWith);
    const { rootKey: rk3 } = x3dhSend({ ikDhPrivate: initiatorIkDh }, bundleWithout);

    if (Buffer.from(rk4).equals(Buffer.from(rk3))) throw new Error('3DH and 4DH root keys should differ');

    pass('x3dhSend: 3DH and 4DH paths produce different root keys');
} catch (e) { fail('x3dhSend 3DH vs 4DH', e); }

// --- Cleanup ---
for (const f of [`${TEST_USERNAME}_private_keys.bin`, `${TEST_USERNAME}_local_salt.bin`]) {
    try { unlinkSync(f); } catch {}
}

console.log('');
if (failures.length > 0) {
    console.log(`FAILED — ${failures.length} test(s) failed`);
    process.exit(1);
} else {
    console.log('All tests passed.');
}
