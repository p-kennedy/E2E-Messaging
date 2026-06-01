// Unit tests for account.js and session.js — crypto operations only, no server required.
// Run from the repo root:  node tests/test_create_user.js

import { PrivateKey, deriveKek, createUser, deleteConsumedOpk } from '../client/user_creation/account.js';
import { x3dhSend, initRatchet, ratchetEncrypt, ratchetDecrypt, verifyMessage, x3dhReceive, initRatchetReceiver, dhRatchetStep, advanceRatchet } from '../client/user_creation/session.js';
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

    if (state.rootKey.length !== 32)                                     throw new Error(`rootKey: expected 32 bytes, got ${state.rootKey.length}`);
    if (state.sendingChainKey.length !== 32)                             throw new Error('sendingChainKey: expected 32 bytes');
    if (state.receivingChainKey !== null)                                 throw new Error('receivingChainKey should be null');
    if (state.localRatchetPublic.serialize().length !== 33)              throw new Error('localRatchetPublic: expected 33-byte Signal key');
    if (!(state.localRatchetPrivate instanceof PrivateKey))              throw new Error('localRatchetPrivate: expected PrivateKey');
    if (state.Ns !== 0 || state.Nr !== 0 || state.PN !== 0)             throw new Error('counters should all be 0');
    if (!(state.MKSKIPPED instanceof Map))                               throw new Error('MKSKIPPED: expected Map');
    if (state.peerIdentityKeys !== null)                                 throw new Error('peerIdentityKeys should be null when not provided');
    if (state.fingerprintRecords !== null)                               throw new Error('fingerprintRecords should be null when not provided');

    // With peerIdentityKeys provided
    const ikSign2   = PrivateKey.generate();
    const ikDh2     = PrivateKey.generate();
    const state2    = initRatchet(rootKey, responderSpk.getPublicKey(), { ikSignPublic: ikSign2.getPublicKey(), ikDhPublic: ikDh2.getPublicKey() });
    if (!state2.peerIdentityKeys)                                        throw new Error('peerIdentityKeys should be set');
    if (state2.peerIdentityKeys.ikSignPublic.serialize().length !== 33)  throw new Error('peerIdentityKeys.ikSignPublic: expected 33-byte PublicKey');
    if (!state2.fingerprintRecords)                                      throw new Error('fingerprintRecords should be set');
    if (!/^[0-9a-f]{64}$/.test(state2.fingerprintRecords.fingerprint))  throw new Error('fingerprintRecords.fingerprint: expected 64-char hex');
    if (!state2.fingerprintRecords.firstSeen)                           throw new Error('fingerprintRecords.firstSeen: expected ISO timestamp');

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
    if (s1.localRatchetPublic.serialize().equals(s2.localRatchetPublic.serialize()))
        throw new Error('ratchetPublic should differ across calls');

    pass('initRatchet: distinct state across calls (ratchet key randomness)');
} catch (e) { fail('initRatchet ratchet key randomness', e); }

// --- Test 15: ratchetEncrypt first-message header shape ---
try {
    const rootKey      = Buffer.alloc(32, 0xab);
    const responderSpk = PrivateKey.generate();
    const state        = initRatchet(rootKey, responderSpk.getPublicKey());
    const ikSign       = PrivateKey.generate();
    const ikDh         = PrivateKey.generate();

    const ephPublic = PrivateKey.generate().getPublicKey();
    const plaintext = Buffer.from('hello world', 'utf8');

    const { header, ciphertext, nonce, signature, digest } = ratchetEncrypt(
        state, plaintext, ikSign, { ephPublic, ikDhPublic: ikDh.getPublicKey(), opkId: 3 },
    );

    if (nonce.length !== 12)                   throw new Error(`nonce: expected 12 bytes, got ${nonce.length}`);
    if (ciphertext.length < plaintext.length)  throw new Error('ciphertext shorter than plaintext');
    if (!('ratchetPublic' in header))          throw new Error('header missing ratchetPublic');
    if (header.Ns !== 0)                       throw new Error(`header.Ns: expected 0 (pre-increment snapshot), got ${header.Ns}`);
    if (header.PN !== 0)                       throw new Error(`header.PN: expected 0, got ${header.PN}`);
    if (header.opkId !== 3)                    throw new Error(`header.opkId: expected 3, got ${header.opkId}`);
    if (!header.ephPublic)                     throw new Error('header missing ephPublic');
    if (!header.ikSignPublic)                  throw new Error('header missing ikSignPublic');
    if (!header.ikDhPublic)                    throw new Error('header missing ikDhPublic');
    if (signature.length !== 64)               throw new Error(`signature: expected 64 bytes, got ${signature.length}`);
    if (!/^0x[0-9a-f]{64}$/.test(digest))     throw new Error(`digest: expected 0x-prefixed 32-byte hex, got ${digest}`);

    pass('ratchetEncrypt: first-message header contains all required fields including ikSignPublic and ikDhPublic');
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

// --- Test 22: verifyMessage with ikSignPublic extracted from first-message header ---
try {
    const { PublicKey } = await import('../client/user_creation/account.js');
    const ikSign  = PrivateKey.generate();
    const state   = initRatchet(Buffer.alloc(32, 0xaa), PrivateKey.generate().getPublicKey());
    const ephPublic = PrivateKey.generate().getPublicKey();

    const { header, ciphertext, nonce, signature } = ratchetEncrypt(
        state, Buffer.from('first message'), ikSign, { ephPublic },
    );

    // Recipient extracts ikSignPublic from the first-message header
    const ikSignPublic = PublicKey.deserialize(Buffer.from(header.ikSignPublic, 'base64'));
    const valid = verifyMessage(header, ciphertext, nonce, signature, ikSignPublic);
    if (!valid) throw new Error('verifyMessage returned false for a valid message');

    pass('verifyMessage: valid signature verified using ikSignPublic from first-message header');
} catch (e) { fail('verifyMessage with header ikSignPublic', e); }

// --- Test 23: verifyMessage rejects a tampered header ---
try {
    const ikSign  = PrivateKey.generate();
    const state   = initRatchet(Buffer.alloc(32, 0xbb), PrivateKey.generate().getPublicKey());

    const { header, ciphertext, nonce, signature } = ratchetEncrypt(
        state, Buffer.from('tamper header test'), ikSign,
    );

    const tamperedHeader = { ...header, Ns: 999 };
    const ikSignPublic   = ikSign.getPublicKey();
    const valid = verifyMessage(tamperedHeader, ciphertext, nonce, signature, ikSignPublic);
    if (valid) throw new Error('verifyMessage should reject a tampered header');

    pass('verifyMessage: tampered header fails signature verification');
} catch (e) { fail('verifyMessage tampered header', e); }

// --- Test 24: x3dhReceive output shape ---
try {
    const aliceIkDh = PrivateKey.generate();
    const bobIkDh   = PrivateKey.generate();
    const bobSpk    = PrivateKey.generate();

    const header = {
        ikDhPublic: aliceIkDh.getPublicKey().serialize().toString('base64'),
        ephPublic:  PrivateKey.generate().getPublicKey().serialize().toString('base64'),
        opkId:      null,
        ratchetPublic: PrivateKey.generate().getPublicKey().serialize().toString('base64'),
    };

    const rootKey = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, header);

    if (rootKey.length !== 32) throw new Error(`rootKey: expected 32 bytes, got ${rootKey.length}`);

    pass('x3dhReceive: returns 32-byte root key');
} catch (e) { fail('x3dhReceive shape', e); }

// --- Test 25: x3dhSend and x3dhReceive produce matching root keys ---
try {
    const aliceIkDh = PrivateKey.generate();
    const bobIkDh   = PrivateKey.generate();
    const bobSpk    = PrivateKey.generate();
    const bobOpk    = PrivateKey.generate();

    const bundle = {
        ikDhPublic: bobIkDh.getPublicKey(),
        spkPublic:  bobSpk.getPublicKey(),
        opkPublic:  bobOpk.getPublicKey(),
        opkId:      0,
    };

    const { rootKey: aliceRootKey, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);

    const header = {
        ikDhPublic: aliceIkDh.getPublicKey().serialize().toString('base64'),
        ephPublic:  ephPublic.serialize().toString('base64'),
        opkId:      0,
        ratchetPublic: PrivateKey.generate().getPublicKey().serialize().toString('base64'),
    };

    const bobRootKey = x3dhReceive(
        { ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [bobOpk] },
        header,
    );

    if (!Buffer.from(aliceRootKey).equals(Buffer.from(bobRootKey)))
        throw new Error('root keys do not match');

    pass('x3dhSend and x3dhReceive: both sides derive the same root key');
} catch (e) { fail('x3dhSend/x3dhReceive consistency', e); }

// --- Test 26: initRatchetReceiver output shape ---
try {
    const rootKey  = Buffer.alloc(32, 0xcc);
    const spkPriv  = PrivateKey.generate();

    // Without identity keys in header → peerIdentityKeys null
    const header   = { ratchetPublic: PrivateKey.generate().getPublicKey().serialize().toString('base64') };
    const state    = initRatchetReceiver(rootKey, header, spkPriv);

    if (state.rootKey.length !== 32)                        throw new Error('rootKey: expected 32 bytes');
    if (state.receivingChainKey.length !== 32)              throw new Error('receivingChainKey: expected 32 bytes');
    if (state.sendingChainKey !== null)                     throw new Error('sendingChainKey should be null');
    if (state.localRatchetPublic.serialize().length !== 33) throw new Error('localRatchetPublic: expected 33-byte key');
    if (!(state.localRatchetPrivate instanceof PrivateKey)) throw new Error('localRatchetPrivate: expected PrivateKey');
    if (state.Ns !== 0 || state.Nr !== 0 || state.PN !== 0) throw new Error('counters should all be 0');
    if (state.peerIdentityKeys !== null)                    throw new Error('peerIdentityKeys should be null when absent from header');
    if (state.fingerprintRecords !== null)                  throw new Error('fingerprintRecords should be null when absent from header');

    // With identity keys in header → peerIdentityKeys and fingerprintRecords populated
    const ikSign2   = PrivateKey.generate();
    const ikDh2     = PrivateKey.generate();
    const header2   = {
        ratchetPublic: PrivateKey.generate().getPublicKey().serialize().toString('base64'),
        ikSignPublic:  ikSign2.getPublicKey().serialize().toString('base64'),
        ikDhPublic:    ikDh2.getPublicKey().serialize().toString('base64'),
    };
    const state2    = initRatchetReceiver(rootKey, header2, spkPriv);
    if (!state2.peerIdentityKeys)                                       throw new Error('peerIdentityKeys should be set when header contains identity keys');
    if (state2.peerIdentityKeys.ikSignPublic.serialize().length !== 33) throw new Error('peerIdentityKeys.ikSignPublic: expected 33-byte key');
    if (!state2.fingerprintRecords)                                     throw new Error('fingerprintRecords should be set');
    if (!/^[0-9a-f]{64}$/.test(state2.fingerprintRecords.fingerprint)) throw new Error('fingerprintRecords.fingerprint: expected 64-char hex');

    pass('initRatchetReceiver: correct state shape, sendingChainKey null, counters zeroed');
} catch (e) { fail('initRatchetReceiver shape', e); }

// --- Test 27: initRatchet and initRatchetReceiver produce matching chain keys ---
try {
    // Use consistent X3DH root keys from a full send/receive run
    const aliceIkDh = PrivateKey.generate();
    const bobIkDh   = PrivateKey.generate();
    const bobSpk    = PrivateKey.generate();

    const bundle = {
        ikDhPublic: bobIkDh.getPublicKey(),
        spkPublic:  bobSpk.getPublicKey(),
        opkPublic:  null,
        opkId:      null,
    };

    const { rootKey: aliceX3dhRk, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);

    // Alice inits ratchet (initiator)
    const aliceState = initRatchet(aliceX3dhRk, bobSpk.getPublicKey());

    // Build the first-message header as Alice would send it
    const header = {
        ratchetPublic: aliceState.localRatchetPublic.serialize().toString('base64'),
        ephPublic:     ephPublic.serialize().toString('base64'),
        ikDhPublic:    aliceIkDh.getPublicKey().serialize().toString('base64'),
        opkId:         null,
        Ns: 0, PN: 0,
    };

    // Bob reconstructs X3DH root key and inits ratchet (responder)
    const bobX3dhRk = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, header);
    const bobState  = initRatchetReceiver(bobX3dhRk, header, bobSpk);

    if (!Buffer.from(aliceX3dhRk).equals(Buffer.from(bobX3dhRk)))
        throw new Error('X3DH root keys differ');
    if (!Buffer.from(aliceState.rootKey).equals(Buffer.from(bobState.rootKey)))
        throw new Error('post-ratchet root keys differ');
    if (!Buffer.from(aliceState.sendingChainKey).equals(Buffer.from(bobState.receivingChainKey)))
        throw new Error("Alice's sendingChainKey !== Bob's receivingChainKey");

    pass("initRatchet + initRatchetReceiver: Alice's sendingChainKey matches Bob's receivingChainKey");
} catch (e) { fail('initRatchet/initRatchetReceiver consistency', e); }

// --- Test 28: ratchetDecrypt round-trip (matching chain keys) ---
try {
    // Build matching sender/receiver states using a shared root key
    const sharedRootKey = Buffer.alloc(32, 0xde);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const header        = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, header, bobSpk);

    const plaintext = Buffer.from('hello from alice', 'utf8');
    const { ciphertext, nonce, header: encHeader } = ratchetEncrypt(senderState, plaintext, ikSign);
    const decrypted = ratchetDecrypt(receiverState, ciphertext, nonce, encHeader);

    if (!decrypted.equals(plaintext)) throw new Error(`decrypted mismatch: got "${decrypted}"`);

    pass('ratchetDecrypt: decrypted plaintext matches original');
} catch (e) { fail('ratchetDecrypt round-trip', e); }

// --- Test 29: ratchetDecrypt increments Nr ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xef);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const header        = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, header, bobSpk);

    const { ciphertext: ct1, nonce: n1, header: h1 } = ratchetEncrypt(senderState, Buffer.from('msg1'), ikSign);
    const { ciphertext: ct2, nonce: n2, header: h2 } = ratchetEncrypt(senderState, Buffer.from('msg2'), ikSign);

    ratchetDecrypt(receiverState, ct1, n1, h1);
    if (receiverState.Nr !== 1) throw new Error(`Nr after 1st decrypt: expected 1, got ${receiverState.Nr}`);
    ratchetDecrypt(receiverState, ct2, n2, h2);
    if (receiverState.Nr !== 2) throw new Error(`Nr after 2nd decrypt: expected 2, got ${receiverState.Nr}`);

    pass('ratchetDecrypt: Nr increments on each decryption');
} catch (e) { fail('ratchetDecrypt Nr increment', e); }

// --- Test 30: ratchetDecrypt throws on tampered ciphertext ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xf1);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const header        = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, header, bobSpk);

    const { ciphertext, nonce, header: encHeader } = ratchetEncrypt(senderState, Buffer.from('secret'), ikSign);
    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 0xff;

    let threw = false;
    try { ratchetDecrypt(receiverState, tampered, nonce, encHeader); } catch { threw = true; }
    if (!threw) throw new Error('expected ratchetDecrypt to throw on tampered ciphertext');

    pass('ratchetDecrypt: throws when ciphertext is tampered (GCM auth tag fails)');
} catch (e) { fail('ratchetDecrypt tamper detection', e); }

// --- Test 31: full end-to-end — X3DH + ratchet init + encrypt + verify + decrypt ---
try {
    const { PublicKey } = await import('../client/user_creation/account.js');

    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();
    const bobOpk      = PrivateKey.generate();

    // Alice: X3DH send + ratchet init
    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: bobOpk.getPublicKey(), opkId: 0 };
    const { rootKey: aliceRootKey, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceRootKey, bobSpk.getPublicKey());

    // Alice: encrypt first message
    const plaintext = Buffer.from('end-to-end test message', 'utf8');
    const { header, ciphertext, nonce, signature } = ratchetEncrypt(
        aliceState, plaintext, aliceIkSign,
        { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: 0 },
    );

    // Bob: X3DH receive + ratchet init
    const bobRootKey = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [bobOpk] }, header);
    const bobState   = initRatchetReceiver(bobRootKey, header, bobSpk);

    // Bob: verify signature
    const ikSignPublic = PublicKey.deserialize(Buffer.from(header.ikSignPublic, 'base64'));
    if (!verifyMessage(header, ciphertext, nonce, signature, ikSignPublic))
        throw new Error('signature verification failed');

    // Bob: decrypt
    const decrypted = ratchetDecrypt(bobState, ciphertext, nonce, header);
    if (!decrypted.equals(plaintext)) throw new Error(`decrypted mismatch: got "${decrypted}"`);

    pass('full end-to-end: X3DH → ratchet init → encrypt → verify → decrypt succeeds');
} catch (e) { fail('full end-to-end', e); }

// --- Test 32: dhRatchetStep populates sendingChainKey and resets counters ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xa1);
    const bobSpk        = PrivateKey.generate();
    const aliceRatchetPub = PrivateKey.generate().getPublicKey();

    // Simulate Bob's receiver state after initRatchetReceiver
    const header        = { ratchetPublic: aliceRatchetPub.serialize().toString('base64') };
    const bobState      = initRatchetReceiver(sharedRootKey, header, bobSpk);

    // Bob has received 3 messages before replying
    bobState.Nr = 3;

    const rkBefore  = Buffer.from(bobState.rootKey);
    const rpBefore  = bobState.localRatchetPublic.serialize();

    dhRatchetStep(bobState);

    if (bobState.sendingChainKey === null)             throw new Error('sendingChainKey should be set after DH ratchet step');
    if (bobState.sendingChainKey.length !== 32)        throw new Error('sendingChainKey: expected 32 bytes');
    if (bobState.PN !== 0)                             throw new Error(`PN: expected 0 (Ns was 0), got ${bobState.PN}`);
    if (bobState.Ns !== 0)                             throw new Error(`Ns: expected 0 after reset, got ${bobState.Ns}`);
    if (Buffer.from(bobState.rootKey).equals(rkBefore))  throw new Error('rootKey should change after DH ratchet step');
    if (bobState.localRatchetPublic.serialize().equals(rpBefore)) throw new Error('ratchetPublic should change after DH ratchet step');

    pass('dhRatchetStep: sendingChainKey set, counters reset, rootKey and ratchetPublic updated');
} catch (e) { fail('dhRatchetStep state mutation', e); }

// --- Test 33: dhRatchetStep preserves PN = prior Ns ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xa2);
    const bobSpk        = PrivateKey.generate();
    const header        = { ratchetPublic: PrivateKey.generate().getPublicKey().serialize().toString('base64') };
    const bobState      = initRatchetReceiver(sharedRootKey, header, bobSpk);

    // Bob sends 5 messages before ratcheting (hypothetical — sendingChainKey starts null
    // so we manually set Ns to simulate state after a prior ratchet)
    bobState.sendingChainKey = Buffer.alloc(32, 0xff);
    bobState.Ns = 5;

    dhRatchetStep(bobState);

    if (bobState.PN !== 5) throw new Error(`PN: expected 5 (previous Ns), got ${bobState.PN}`);
    if (bobState.Ns !== 0) throw new Error(`Ns: expected 0 after reset, got ${bobState.Ns}`);

    pass('dhRatchetStep: PN captures previous Ns before reset');
} catch (e) { fail('dhRatchetStep PN/Ns', e); }

// --- Test 34: Bob can ratchetEncrypt after dhRatchetStep ---
try {
    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();
    const bobIkSign   = PrivateKey.generate();

    // Full setup: Alice sends, Bob receives
    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceRootKey, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceRootKey, bobSpk.getPublicKey());

    const { header: h1, ciphertext: ct1, nonce: n1 } = ratchetEncrypt(
        aliceState, Buffer.from('hi bob'), aliceIkSign,
        { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: null },
    );

    const bobRootKey = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, h1);
    const bobState   = initRatchetReceiver(bobRootKey, h1, bobSpk);
    ratchetDecrypt(bobState, ct1, n1, h1);

    // Bob performs DH ratchet step before replying
    dhRatchetStep(bobState);

    // Bob can now encrypt
    const { header: h2, ciphertext: ct2, nonce: n2, signature: sig2 } = ratchetEncrypt(
        bobState, Buffer.from('hi alice'), bobIkSign,
    );

    if (!h2.ratchetPublic)  throw new Error('reply header missing ratchetPublic');
    if (ct2.length === 0)   throw new Error('reply ciphertext is empty');
    if (n2.length !== 12)   throw new Error(`reply nonce: expected 12 bytes, got ${n2.length}`);
    if (sig2.length !== 64) throw new Error('reply signature: expected 64 bytes');

    pass('dhRatchetStep: Bob can ratchetEncrypt after performing DH ratchet step');
} catch (e) { fail('dhRatchetStep then ratchetEncrypt', e); }

// --- Test 35: Bob's reply header matches spec (ratchetPublic, Ns, PN only) ---
try {
    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkSign   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();

    // Alice sends first message
    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceRootKey, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceRootKey, bobSpk.getPublicKey());
    const { header: h1, ciphertext: ct1, nonce: n1 } = ratchetEncrypt(
        aliceState, Buffer.from('hi bob'), aliceIkSign,
        { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: null },
    );

    // Bob receives + performs DH ratchet step
    const bobRootKey = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, h1);
    const bobState   = initRatchetReceiver(bobRootKey, h1, bobSpk);
    ratchetDecrypt(bobState, ct1, n1, h1);
    dhRatchetStep(bobState);

    // Bob sends reply
    const { header: replyHeader, ciphertext: replyCt, nonce: replyNonce, signature: replySig } =
        ratchetEncrypt(bobState, Buffer.from('hi alice'), bobIkSign);

    // Reply header must have ratchetPublic, Ns, PN — and nothing else
    if (!replyHeader.ratchetPublic)        throw new Error('reply header missing ratchetPublic');
    if (replyHeader.Ns !== 0)              throw new Error(`reply header Ns: expected 0, got ${replyHeader.Ns}`);
    if (replyHeader.PN !== 0)              throw new Error(`reply header PN: expected 0 (no prior sends), got ${replyHeader.PN}`);
    if ('ephPublic'    in replyHeader)     throw new Error('reply header should not contain ephPublic');
    if ('ikDhPublic'   in replyHeader)     throw new Error('reply header should not contain ikDhPublic');
    if ('ikSignPublic' in replyHeader)     throw new Error('reply header should not contain ikSignPublic');
    if ('opkId'        in replyHeader)     throw new Error('reply header should not contain opkId');

    // Bob's ratchet public in the reply must differ from Alice's (new key pair from dhRatchetStep)
    if (replyHeader.ratchetPublic === h1.ratchetPublic)
        throw new Error("Bob's reply ratchetPublic should differ from Alice's");

    // Ciphertext and signature are well-formed
    if (replyCt.length === 0)      throw new Error('reply ciphertext is empty');
    if (replyNonce.length !== 12)  throw new Error(`reply nonce: expected 12 bytes, got ${replyNonce.length}`);
    if (replySig.length !== 64)    throw new Error(`reply signature: expected 64 bytes, got ${replySig.length}`);

    // Ns advanced to 1 after send
    if (bobState.Ns !== 1)         throw new Error(`bobState.Ns: expected 1 after send, got ${bobState.Ns}`);

    pass("Bob's reply: header contains ratchetPublic/Ns/PN only, new ratchet public, Ns incremented");
} catch (e) { fail("Bob reply header", e); }

// --- Test 36: advanceRatchet sets all three chains and resets counters ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xb1);
    const bobSpk        = PrivateKey.generate();

    // Simulate Alice's state after initRatchet with 3 messages sent on the current chain
    const aliceState = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const ikSign     = PrivateKey.generate();
    ratchetEncrypt(aliceState, Buffer.from('m1'), ikSign);
    ratchetEncrypt(aliceState, Buffer.from('m2'), ikSign);
    ratchetEncrypt(aliceState, Buffer.from('m3'), ikSign);  // Ns → 3
    aliceState.Nr = 2; // received 2 messages on old chain
    const rkBefore = Buffer.from(aliceState.rootKey);
    const rpBefore = aliceState.localRatchetPublic.serialize();

    // Bob's new ratchet public (what would appear in Bob's reply header)
    const bobNewRatchetPublic = PrivateKey.generate().getPublicKey();
    advanceRatchet(aliceState, bobNewRatchetPublic);

    if (aliceState.receivingChainKey === null)              throw new Error('receivingChainKey should be set');
    if (aliceState.receivingChainKey.length !== 32)        throw new Error('receivingChainKey: expected 32 bytes');
    if (aliceState.sendingChainKey === null)               throw new Error('sendingChainKey should be set');
    if (aliceState.sendingChainKey.length !== 32)          throw new Error('sendingChainKey: expected 32 bytes');
    if (aliceState.Nr !== 0)                               throw new Error(`Nr: expected 0 after reset, got ${aliceState.Nr}`);
    if (aliceState.PN !== 3)                               throw new Error(`PN: expected 3 (previous Ns), got ${aliceState.PN}`);
    if (aliceState.Ns !== 0)                               throw new Error(`Ns: expected 0 after reset, got ${aliceState.Ns}`);
    if (Buffer.from(aliceState.rootKey).equals(rkBefore))  throw new Error('rootKey should change after advance');
    if (aliceState.localRatchetPublic.serialize().equals(rpBefore)) throw new Error('ratchetPublic should change after advance');
    if (aliceState.remoteRatchetPublic.serialize().toString('base64') !== bobNewRatchetPublic.serialize().toString('base64'))
        throw new Error('remoteRatchetPublic should be updated to bobNewRatchetPublic');

    pass('advanceRatchet: receivingChainKey and sendingChainKey set, counters reset, keys updated');
} catch (e) { fail('advanceRatchet state', e); }

// --- Test 37: advanceRatchet Phase 1 — Alice receivingChainKey matches Bob sendingChainKey ---
try {
    // Full X3DH + ratchet init so both sides start with matching root keys
    const aliceIkDh = PrivateKey.generate();
    const bobIkDh   = PrivateKey.generate();
    const bobSpk    = PrivateKey.generate();

    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceX3dhRk, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceX3dhRk, bobSpk.getPublicKey());

    const h1 = {
        ratchetPublic: aliceState.localRatchetPublic.serialize().toString('base64'),
        ephPublic:     ephPublic.serialize().toString('base64'),
        ikDhPublic:    aliceIkDh.getPublicKey().serialize().toString('base64'),
        opkId: null, Ns: 0, PN: 0,
    };

    const bobX3dhRk = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, h1);
    const bobState  = initRatchetReceiver(bobX3dhRk, h1, bobSpk);
    dhRatchetStep(bobState);

    // Simulate Alice seeing Bob's new ratchet public (as it would appear in Bob's reply header)
    advanceRatchet(aliceState, bobState.localRatchetPublic);

    if (!Buffer.from(aliceState.receivingChainKey).equals(Buffer.from(bobState.sendingChainKey)))
        throw new Error("Alice's receivingChainKey should equal Bob's sendingChainKey after advanceRatchet Phase 1");

    pass("advanceRatchet Phase 1: Alice's receivingChainKey matches Bob's sendingChainKey");
} catch (e) { fail('advanceRatchet chain key consistency', e); }

// --- Test 38: full bidirectional handshake — Alice decrypts Bob's reply ---
try {
    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkSign   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();

    // Alice → Bob (first message)
    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceX3dhRk, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceX3dhRk, bobSpk.getPublicKey());
    const { header: h1, ciphertext: ct1, nonce: n1 } = ratchetEncrypt(
        aliceState, Buffer.from('hi bob'), aliceIkSign,
        { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: null },
    );

    // Bob receives Alice's message
    const bobX3dhRk = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, h1);
    const bobState  = initRatchetReceiver(bobX3dhRk, h1, bobSpk);
    ratchetDecrypt(bobState, ct1, n1, h1);

    // Bob performs DH ratchet step and sends reply
    dhRatchetStep(bobState);
    const { header: h2, ciphertext: ct2, nonce: n2, signature: sig2 } =
        ratchetEncrypt(bobState, Buffer.from('hi alice'), bobIkSign);

    // Alice verifies Bob's signature and decrypts
    // (ratchetDecrypt detects the new ratchetPublic and calls advanceRatchet automatically)
    if (!verifyMessage(h2, ct2, n2, sig2, bobIkSign.getPublicKey()))
        throw new Error('signature verification failed for Bob reply');
    const decrypted = ratchetDecrypt(aliceState, ct2, n2, h2);
    if (!decrypted.equals(Buffer.from('hi alice')))
        throw new Error(`decrypted mismatch: got "${decrypted}"`);

    pass('full bidirectional handshake: Alice decrypts Bob reply after advanceRatchet');
} catch (e) { fail('full bidirectional handshake', e); }

// --- Test 39: multiple consecutive sends and receives on the same chain ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xc1);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const initHeader    = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, initHeader, bobSpk);

    const messages = ['first', 'second', 'third'];
    const packets  = messages.map(m => ratchetEncrypt(senderState, Buffer.from(m), ikSign));

    for (let i = 0; i < packets.length; i++) {
        const { ciphertext, nonce, header } = packets[i];
        const plain = ratchetDecrypt(receiverState, ciphertext, nonce, header);
        if (plain.toString() !== messages[i])
            throw new Error(`message ${i}: expected "${messages[i]}", got "${plain}"`);
    }
    if (receiverState.Nr !== 3) throw new Error(`Nr: expected 3, got ${receiverState.Nr}`);
    if (senderState.Ns   !== 3) throw new Error(`Ns: expected 3, got ${senderState.Ns}`);

    pass('multiple consecutive messages: all decrypt correctly, Ns=3, Nr=3');
} catch (e) { fail('multi-message chain', e); }

// --- Test 40: ratchetDecrypt auto-advances ratchet on new remote key ---
try {
    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();

    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceX3dhRk, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceX3dhRk, bobSpk.getPublicKey());
    const { header: h1, ciphertext: ct1, nonce: n1 } = ratchetEncrypt(
        aliceState, Buffer.from('msg1'), aliceIkSign,
        { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: null },
    );

    const bobX3dhRk = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, h1);
    const bobState  = initRatchetReceiver(bobX3dhRk, h1, bobSpk);
    ratchetDecrypt(bobState, ct1, n1, h1);
    dhRatchetStep(bobState);

    const remoteRatchetBefore = aliceState.remoteRatchetPublic.serialize().toString('base64');

    // ratchetDecrypt should auto-advance when it sees Bob's new ratchetPublic
    const bobIkSign = PrivateKey.generate();
    const { header: h2, ciphertext: ct2, nonce: n2 } = ratchetEncrypt(bobState, Buffer.from('reply'), bobIkSign);
    ratchetDecrypt(aliceState, ct2, n2, h2);  // no manual advanceRatchet call

    if (aliceState.remoteRatchetPublic.serialize().toString('base64') === remoteRatchetBefore)
        throw new Error('remoteRatchetPublic should have been updated by auto-advance');
    if (aliceState.Nr !== 1) throw new Error(`aliceState.Nr: expected 1, got ${aliceState.Nr}`);

    pass('ratchetDecrypt auto-advances ratchet when new remote ratchet key detected');
} catch (e) { fail('ratchetDecrypt auto-advance', e); }

// --- Test 41: multi-turn conversation A→B→A→B ---
try {
    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkSign   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();

    // Setup
    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceX3dhRk, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceX3dhRk, bobSpk.getPublicKey());
    const { header: h1, ciphertext: ct1, nonce: n1 } = ratchetEncrypt(
        aliceState, Buffer.from('A1'), aliceIkSign,
        { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: null },
    );
    const bobX3dhRk = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, h1);
    const bobState  = initRatchetReceiver(bobX3dhRk, h1, bobSpk);

    // Turn 1: Bob receives A1
    const plainA1 = ratchetDecrypt(bobState, ct1, n1, h1);
    if (plainA1.toString() !== 'A1') throw new Error(`Turn 1 A1: got "${plainA1}"`);

    // Turn 2: Bob replies B1, B2
    dhRatchetStep(bobState);
    const { header: hB1, ciphertext: cB1, nonce: nB1 } = ratchetEncrypt(bobState, Buffer.from('B1'), bobIkSign);
    const { header: hB2, ciphertext: cB2, nonce: nB2 } = ratchetEncrypt(bobState, Buffer.from('B2'), bobIkSign);

    // Turn 3: Alice receives B1, B2 (auto-advance on B1)
    const plainB1 = ratchetDecrypt(aliceState, cB1, nB1, hB1);
    const plainB2 = ratchetDecrypt(aliceState, cB2, nB2, hB2);
    if (plainB1.toString() !== 'B1') throw new Error(`Turn 3 B1: got "${plainB1}"`);
    if (plainB2.toString() !== 'B2') throw new Error(`Turn 3 B2: got "${plainB2}"`);

    // Turn 4: Alice replies A2
    const { header: hA2, ciphertext: cA2, nonce: nA2 } = ratchetEncrypt(aliceState, Buffer.from('A2'), aliceIkSign);

    // Turn 5: Bob receives A2 (auto-advance on A2)
    const plainA2 = ratchetDecrypt(bobState, cA2, nA2, hA2);
    if (plainA2.toString() !== 'A2') throw new Error(`Turn 5 A2: got "${plainA2}"`);

    pass('multi-turn A→B→A→B: all messages decrypt correctly across ratchet boundaries');
} catch (e) { fail('multi-turn conversation', e); }

// --- Test 42: out-of-order messages on the same chain ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xd1);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const initHeader    = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, initHeader, bobSpk);

    // Encrypt three messages in order
    const p0 = ratchetEncrypt(senderState, Buffer.from('msg0'), ikSign);
    const p1 = ratchetEncrypt(senderState, Buffer.from('msg1'), ikSign);
    const p2 = ratchetEncrypt(senderState, Buffer.from('msg2'), ikSign);

    // Deliver out of order: 0, 2, 1
    const d0 = ratchetDecrypt(receiverState, p0.ciphertext, p0.nonce, p0.header);
    const d2 = ratchetDecrypt(receiverState, p2.ciphertext, p2.nonce, p2.header);  // skips msg1 → cached
    const d1 = ratchetDecrypt(receiverState, p1.ciphertext, p1.nonce, p1.header);  // served from cache

    if (d0.toString() !== 'msg0') throw new Error(`msg0: got "${d0}"`);
    if (d2.toString() !== 'msg2') throw new Error(`msg2: got "${d2}"`);
    if (d1.toString() !== 'msg1') throw new Error(`msg1 (cached): got "${d1}"`);
    if (receiverState.MKSKIPPED.size !== 0) throw new Error('MKSKIPPED should be empty after all messages received');

    pass('out-of-order same chain: all three messages decrypt correctly, cache cleared');
} catch (e) { fail('out-of-order same chain', e); }

// --- Test 43: cached key is deleted after use (cannot decrypt twice) ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xd2);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const initHeader    = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, initHeader, bobSpk);

    const p0 = ratchetEncrypt(senderState, Buffer.from('first'), ikSign);
    const p1 = ratchetEncrypt(senderState, Buffer.from('second'), ikSign);

    ratchetDecrypt(receiverState, p1.ciphertext, p1.nonce, p1.header);  // caches key for p0
    ratchetDecrypt(receiverState, p0.ciphertext, p0.nonce, p0.header);  // uses cached key, deletes it

    // Attempting to decrypt p0 again — cache entry is gone and the chain has moved past it
    let threw = false;
    try { ratchetDecrypt(receiverState, p0.ciphertext, p0.nonce, p0.header); } catch { threw = true; }
    if (!threw) throw new Error('expected second decrypt of p0 to throw');

    pass('cached key deleted after use: second decrypt of same message throws');
} catch (e) { fail('cached key single-use', e); }

// --- Test 44: gap exceeding MAX_SKIP is rejected ---
try {
    const sharedRootKey = Buffer.alloc(32, 0xd3);
    const bobSpk        = PrivateKey.generate();
    const ikSign        = PrivateKey.generate();

    const senderState   = initRatchet(sharedRootKey, bobSpk.getPublicKey());
    const initHeader    = { ratchetPublic: senderState.localRatchetPublic.serialize().toString('base64'), Ns: 0, PN: 0 };
    const receiverState = initRatchetReceiver(sharedRootKey, initHeader, bobSpk);

    // Advance sender Ns to MAX_SKIP + 1 by encrypting one message but forging a higher Ns header
    const p = ratchetEncrypt(senderState, Buffer.from('far future'), ikSign);
    const forgedHeader = { ...p.header, Ns: 1001 };  // beyond MAX_SKIP=1000

    let threw = false;
    try { ratchetDecrypt(receiverState, p.ciphertext, p.nonce, forgedHeader); } catch { threw = true; }
    if (!threw) throw new Error('expected MAX_SKIP exceeded to throw');

    pass('gap exceeding MAX_SKIP (1000) is rejected');
} catch (e) { fail('MAX_SKIP enforcement', e); }

// --- Test 45: out-of-order across a ratchet boundary ---
try {
    const aliceIkSign = PrivateKey.generate();
    const aliceIkDh   = PrivateKey.generate();
    const bobIkSign   = PrivateKey.generate();
    const bobIkDh     = PrivateKey.generate();
    const bobSpk      = PrivateKey.generate();

    // Setup — Alice sends two messages
    const bundle = { ikDhPublic: bobIkDh.getPublicKey(), spkPublic: bobSpk.getPublicKey(), opkPublic: null, opkId: null };
    const { rootKey: aliceX3dhRk, ephPublic } = x3dhSend({ ikDhPrivate: aliceIkDh }, bundle);
    const aliceState = initRatchet(aliceX3dhRk, bobSpk.getPublicKey());

    const opts = { ephPublic, ikDhPublic: aliceIkDh.getPublicKey(), opkId: null };
    const a0   = ratchetEncrypt(aliceState, Buffer.from('A0'), aliceIkSign, opts);
    const a1   = ratchetEncrypt(aliceState, Buffer.from('A1'), aliceIkSign);

    const bobX3dhRk = x3dhReceive({ ikDhPrivate: bobIkDh, spkPrivate: bobSpk, opkPrivates: [] }, a0.header);
    const bobState  = initRatchetReceiver(bobX3dhRk, a0.header, bobSpk);

    // Bob receives A1 first (skips A0 → cached), then A0 (from cache)
    const dA1 = ratchetDecrypt(bobState, a1.ciphertext, a1.nonce, a1.header);
    const dA0 = ratchetDecrypt(bobState, a0.ciphertext, a0.nonce, a0.header);
    if (dA1.toString() !== 'A1') throw new Error(`A1: got "${dA1}"`);
    if (dA0.toString() !== 'A0') throw new Error(`A0 (cached): got "${dA0}"`);

    // Bob replies (ratchet step) and Alice decrypts out of order
    dhRatchetStep(bobState);
    const b0 = ratchetEncrypt(bobState, Buffer.from('B0'), bobIkSign);
    const b1 = ratchetEncrypt(bobState, Buffer.from('B1'), bobIkSign);

    const dB1 = ratchetDecrypt(aliceState, b1.ciphertext, b1.nonce, b1.header);  // skips B0 → cached, advances ratchet
    const dB0 = ratchetDecrypt(aliceState, b0.ciphertext, b0.nonce, b0.header);  // from cache
    if (dB1.toString() !== 'B1') throw new Error(`B1: got "${dB1}"`);
    if (dB0.toString() !== 'B0') throw new Error(`B0 (cached): got "${dB0}"`);

    pass('out-of-order across ratchet boundary: all messages decrypt correctly');
} catch (e) { fail('out-of-order across ratchet boundary', e); }

// --- Test 46: deleteConsumedOpk zeroes the OPK bytes on disk ---
try {
    const { writeFileSync } = await import('node:fs');

    // Build a minimal fake private bundle: 3 fixed keys + 3 OPKs
    const fixedBytes = Buffer.alloc(96, 0xaa);
    const opk0 = Buffer.alloc(32, 0x01);
    const opk1 = Buffer.alloc(32, 0x02);
    const opk2 = Buffer.alloc(32, 0x03);
    const bundle = Buffer.concat([fixedBytes, opk0, opk1, opk2]);

    const salt  = randomBytes(16);
    const kek   = await deriveKek(Buffer.from('pw', 'utf8'), salt);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, nonce);
    const ct = Buffer.concat([cipher.update(bundle), cipher.final(), cipher.getAuthTag()]);

    writeFileSync('_opktest_private_keys.bin', Buffer.concat([nonce, ct]));
    writeFileSync('_opktest_local_salt.bin', salt);

    await deleteConsumedOpk('_opktest', 'pw', 1);  // delete opk1 (index 1)

    const keyFile2 = readFileSync('_opktest_private_keys.bin');
    const d = createDecipheriv('aes-256-gcm', kek, keyFile2.subarray(0, 12));
    d.setAuthTag(keyFile2.subarray(-16));
    const decrypted = Buffer.concat([d.update(keyFile2.subarray(12, -16)), d.final()]);

    if (!decrypted.subarray(96,  128).equals(opk0))      throw new Error('opk0 was modified unexpectedly');
    if (!decrypted.subarray(128, 160).every(b => b === 0)) throw new Error('opk1 was not zeroed');
    if (!decrypted.subarray(160, 192).equals(opk2))      throw new Error('opk2 was modified unexpectedly');

    pass('deleteConsumedOpk: target OPK zeroed, others unchanged');
} catch (e) { fail('deleteConsumedOpk: target OPK zeroed, others unchanged', e); } finally {
    try { unlinkSync('_opktest_private_keys.bin'); } catch {}
    try { unlinkSync('_opktest_local_salt.bin'); } catch {}
}

// --- Test 47: deleteConsumedOpk — out-of-range id throws ---
try {
    const { writeFileSync } = await import('node:fs');

    const bundle = Buffer.alloc(128, 0xbb);  // 96 fixed + 1 OPK (32 bytes)
    const salt  = randomBytes(16);
    const kek   = await deriveKek(Buffer.from('pw', 'utf8'), salt);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, nonce);
    const ct = Buffer.concat([cipher.update(bundle), cipher.final(), cipher.getAuthTag()]);
    writeFileSync('_opktest2_private_keys.bin', Buffer.concat([nonce, ct]));
    writeFileSync('_opktest2_local_salt.bin', salt);

    let threw = false;
    try { await deleteConsumedOpk('_opktest2', 'pw', 5); }
    catch (e) { threw = true; if (!e.message.includes('out of range')) throw new Error(`Wrong error: ${e.message}`); }
    if (!threw) throw new Error('Expected an error for out-of-range opkId');

    pass('deleteConsumedOpk: throws for out-of-range opkId');
} catch (e) { fail('deleteConsumedOpk: throws for out-of-range opkId', e); } finally {
    try { unlinkSync('_opktest2_private_keys.bin'); } catch {}
    try { unlinkSync('_opktest2_local_salt.bin'); } catch {}
}

// --- Test 48: login() OPK-loading loop yields null for zeroed entries ---
try {
    const { writeFileSync } = await import('node:fs');

    // Build bundle: 3 real identity keys + 3 OPK slots (index 1 pre-zeroed)
    const fakeFixed = Buffer.concat([
        PrivateKey.generate().serialize(),
        PrivateKey.generate().serialize(),
        PrivateKey.generate().serialize(),
    ]);
    const opk0bytes = PrivateKey.generate().serialize();
    const opk1bytes = Buffer.alloc(32, 0);  // consumed — zeroed
    const opk2bytes = PrivateKey.generate().serialize();
    const bundle    = Buffer.concat([fakeFixed, opk0bytes, opk1bytes, opk2bytes]);

    const salt  = randomBytes(16);
    const kek   = await deriveKek(Buffer.from(TEST_PASSWORD, 'utf8'), salt);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, nonce);
    const ct     = Buffer.concat([cipher.update(bundle), cipher.final(), cipher.getAuthTag()]);
    writeFileSync(`${TEST_USERNAME}_private_keys.bin`, Buffer.concat([nonce, ct]));
    writeFileSync(`${TEST_USERNAME}_local_salt.bin`, salt);

    // Reproduce the login() OPK-loading loop without a server call
    const kf = readFileSync(`${TEST_USERNAME}_private_keys.bin`);
    const dd = createDecipheriv('aes-256-gcm', kek, kf.subarray(0, 12));
    dd.setAuthTag(kf.subarray(-16));
    const pb = Buffer.concat([dd.update(kf.subarray(12, -16)), dd.final()]);

    const opkPrivates = [];
    for (let offset = 96; offset < pb.length; offset += 32) {
        const bytes = pb.subarray(offset, offset + 32);
        opkPrivates.push(bytes.every(b => b === 0) ? null : PrivateKey.deserialize(bytes));
    }

    if (opkPrivates.length !== 3)  throw new Error(`Expected 3 OPKs, got ${opkPrivates.length}`);
    if (opkPrivates[0] === null)   throw new Error('opk[0] should not be null');
    if (opkPrivates[1] !== null)   throw new Error('opk[1] (zeroed) should be null');
    if (opkPrivates[2] === null)   throw new Error('opk[2] should not be null');

    pass('login: zeroed OPK entries loaded as null');
} catch (e) { fail('login: zeroed OPK entries loaded as null', e); }

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
