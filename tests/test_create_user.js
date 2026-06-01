// Unit tests for account.js and session.js — crypto operations only, no server required.
// Run from the repo root:  node tests/test_create_user.js

import { PrivateKey, deriveKek, createUser } from '../client/user_creation/account.js';
import { x3dhSend, initRatchet, ratchetEncrypt } from '../client/user_creation/session.js';
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

// --- Test 12: initRatchet returns correct state shape ---
try {
    const rootKey      = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
    const responderSpk = PrivateKey.generate();
    const state        = initRatchet(rootKey, responderSpk.getPublicKey());

    if (state.rootKey.length !== 32)           throw new Error(`rootKey: expected 32 bytes, got ${state.rootKey.length}`);
    if (state.sendingChainKey.length !== 32)   throw new Error(`sendingChainKey: expected 32 bytes`);
    if (state.receivingChainKey !== null)       throw new Error('receivingChainKey should be null');
    if (state.ratchetPublic.serialize().length !== 33) throw new Error('ratchetPublic: expected 33-byte Signal key');
    if (state.Ns !== 0 || state.Nr !== 0 || state.PN !== 0) throw new Error('counters should all be 0');

    pass('initRatchet: correct state shape, counters zeroed, receivingChainKey null');
} catch (e) { fail('initRatchet state shape', e); }

// --- Test 13: initRatchet advances the root key (KDF_RK mutates RK) ---
try {
    const rootKey      = Buffer.from(Array.from({ length: 32 }, () => Math.floor(Math.random() * 256)));
    const responderSpk = PrivateKey.generate().getPublicKey();
    const state        = initRatchet(rootKey, responderSpk);

    if (Buffer.from(state.rootKey).equals(rootKey))
        throw new Error('rootKey should change after KDF_RK step');

    pass('initRatchet: root key advanced by KDF_RK step');
} catch (e) { fail('initRatchet root key advancement', e); }

// --- Test 14: two initRatchet calls produce different state (ratchet key randomness) ---
try {
    const rootKey      = Buffer.alloc(32, 0xab);
    const responderSpk = PrivateKey.generate().getPublicKey();
    const s1 = initRatchet(rootKey, responderSpk);
    const s2 = initRatchet(rootKey, responderSpk);

    if (Buffer.from(s1.sendingChainKey).equals(Buffer.from(s2.sendingChainKey)))
        throw new Error('sendingChainKey should differ across calls');
    if (s1.ratchetPublic.serialize().equals(s2.ratchetPublic.serialize()))
        throw new Error('ratchetPublic should differ across calls');

    pass('initRatchet: distinct state across calls (ratchet key randomness)');
} catch (e) { fail('initRatchet ratchet key randomness', e); }

// --- Test 15: ratchetEncrypt returns correct output shape ---
try {
    const rootKey      = Buffer.alloc(32, 0xab);
    const responderSpk = PrivateKey.generate();
    const state        = initRatchet(rootKey, responderSpk.getPublicKey());
    const ikSign       = PrivateKey.generate();

    const ephPrivate = PrivateKey.generate();
    const ephPublic  = ephPrivate.getPublicKey();
    const plaintext  = Buffer.from('hello world', 'utf8');

    const { header, ciphertext, nonce, signature, digest } = ratchetEncrypt(state, plaintext, ikSign, { ephPublic, opkId: 3 });

    if (nonce.length !== 12)                   throw new Error(`nonce: expected 12 bytes, got ${nonce.length}`);
    if (ciphertext.length < plaintext.length)  throw new Error('ciphertext shorter than plaintext');
    if (!('ratchetPublic' in header))          throw new Error('header missing ratchetPublic');
    if (header.Ns !== 0)                       throw new Error(`header.Ns: expected 0 (pre-increment snapshot), got ${header.Ns}`);
    if (header.PN !== 0)                       throw new Error(`header.PN: expected 0, got ${header.PN}`);
    if (header.opkId !== 3)                    throw new Error(`header.opkId: expected 3, got ${header.opkId}`);
    if (!header.ephPublic)                     throw new Error('header missing ephPublic');
    if (signature.length !== 64)               throw new Error(`signature: expected 64 bytes, got ${signature.length}`);
    if (!/^0x[0-9a-f]{64}$/.test(digest))     throw new Error(`digest: expected 0x-prefixed 32-byte hex, got ${digest}`);

    pass('ratchetEncrypt: correct output shape (nonce=12, ciphertext, header fields, signature=64, digest=keccak256)');
} catch (e) { fail('ratchetEncrypt shape', e); }

// --- Test 16: ratchetEncrypt advances Ns and chain key ---
try {
    const state  = initRatchet(Buffer.alloc(32, 0xcd), PrivateKey.generate().getPublicKey());
    const ikSign = PrivateKey.generate();
    const ck0    = Buffer.from(state.sendingChainKey);

    ratchetEncrypt(state, Buffer.from('msg1'), ikSign);
    if (state.Ns !== 1) throw new Error(`Ns after 1st call: expected 1, got ${state.Ns}`);
    if (Buffer.from(state.sendingChainKey).equals(ck0)) throw new Error('chain key unchanged after 1st call');

    const ck1 = Buffer.from(state.sendingChainKey);
    ratchetEncrypt(state, Buffer.from('msg2'), ikSign);
    if (state.Ns !== 2) throw new Error(`Ns after 2nd call: expected 2, got ${state.Ns}`);
    if (Buffer.from(state.sendingChainKey).equals(ck1)) throw new Error('chain key unchanged after 2nd call');

    pass('ratchetEncrypt: Ns increments and chain key advances each call');
} catch (e) { fail('ratchetEncrypt state mutation', e); }

// --- Test 17: ratchetEncrypt produces distinct ciphertexts for the same plaintext ---
try {
    const state     = initRatchet(Buffer.alloc(32, 0xef), PrivateKey.generate().getPublicKey());
    const ikSign    = PrivateKey.generate();
    const plaintext = Buffer.from('same message');

    const { ciphertext: ct1, nonce: n1 } = ratchetEncrypt(state, plaintext, ikSign);
    const { ciphertext: ct2, nonce: n2 } = ratchetEncrypt(state, plaintext, ikSign);

    if (ct1.equals(ct2)) throw new Error('ciphertexts should differ (different message keys)');
    if (n1.equals(n2))   throw new Error('nonces should differ (random per message)');

    pass('ratchetEncrypt: distinct ciphertexts and nonces across calls');
} catch (e) { fail('ratchetEncrypt distinct outputs', e); }

// --- Test 18: ratchetEncrypt without ephPublic/opkId omits those header fields ---
try {
    const state  = initRatchet(Buffer.alloc(32, 0x12), PrivateKey.generate().getPublicKey());
    const ikSign = PrivateKey.generate();
    const { header } = ratchetEncrypt(state, Buffer.from('no opk'), ikSign);

    if ('opkId'     in header) throw new Error('header should not contain opkId');
    if ('ephPublic' in header) throw new Error('header should not contain ephPublic');

    pass('ratchetEncrypt: ephPublic and opkId absent from header when not provided');
} catch (e) { fail('ratchetEncrypt optional header fields', e); }

// --- Test 19: digest is a distinct keccak256 per message ---
try {
    const ikSign = PrivateKey.generate();
    const state  = initRatchet(Buffer.alloc(32, 0x78), PrivateKey.generate().getPublicKey());

    const { digest: d1 } = ratchetEncrypt(state, Buffer.from('msg A'), ikSign);
    const { digest: d2 } = ratchetEncrypt(state, Buffer.from('msg B'), ikSign);

    if (!/^0x[0-9a-f]{64}$/.test(d1)) throw new Error(`d1 not valid hex digest: ${d1}`);
    if (d1 === d2) throw new Error('digests should differ across messages');

    pass('ratchetEncrypt: keccak256 digest is unique per message');
} catch (e) { fail('ratchetEncrypt digest uniqueness', e); }

// --- Test 20: signature verifies against sender's identity public key ---
try {
    const ikSign = PrivateKey.generate();
    const state  = initRatchet(Buffer.alloc(32, 0x34), PrivateKey.generate().getPublicKey());

    const { ciphertext, nonce, header, signature } = ratchetEncrypt(
        state, Buffer.from('verify me'), ikSign,
    );

    const aad        = Buffer.from(JSON.stringify(header), 'utf8');
    const signedData = Buffer.concat([ciphertext, nonce, aad]);
    const valid      = ikSign.getPublicKey().verify(signedData, signature);
    if (!valid) throw new Error('signature did not verify');

    pass('ratchetEncrypt: signature verifies against sender identity public key');
} catch (e) { fail('ratchetEncrypt signature verification', e); }

// --- Test 20: tampered ciphertext fails signature verification ---
try {
    const ikSign = PrivateKey.generate();
    const state  = initRatchet(Buffer.alloc(32, 0x56), PrivateKey.generate().getPublicKey());

    const { ciphertext, nonce, header, signature } = ratchetEncrypt(
        state, Buffer.from('tamper test'), ikSign,
    );

    const tampered   = Buffer.from(ciphertext);
    tampered[0]     ^= 0xff;
    const aad        = Buffer.from(JSON.stringify(header), 'utf8');
    const signedData = Buffer.concat([tampered, nonce, aad]);
    const valid      = ikSign.getPublicKey().verify(signedData, signature);
    if (valid) throw new Error('tampered ciphertext should not verify');

    pass('ratchetEncrypt: tampered ciphertext fails signature verification');
} catch (e) { fail('ratchetEncrypt tamper detection', e); }

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
