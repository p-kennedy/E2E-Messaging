// X3DH session establishment and Double Ratchet initialisation — initiator side.
// Responder side (x3dhReceive) is implemented when processing the first incoming message.

import { PrivateKey, PublicKey, hkdf } from '@signalapp/libsignal-client';
import { randomBytes, createCipheriv, createDecipheriv, createHmac, createHash } from 'node:crypto';
import { keccak256 } from 'ethers';

// Signal X3DH spec: prepend 32 × 0xFF to the DH outputs as domain separation
// between the DH function and the KDF, before feeding into HKDF.
const DOMAIN_SEP  = Buffer.alloc(32, 0xff);
const X3DH_INFO   = Buffer.from('E2E-Messaging X3DH v1', 'utf8');
const KDF_RK_INFO = Buffer.from('E2E-Messaging Ratchet v1', 'utf8');

// Maximum number of out-of-order message keys we will cache per ratchet step.
// Prevents a malicious sender from forcing unbounded key derivation by sending
// a message with Ns=1000000.
const MAX_SKIP = 1000;

// KDF_CK(ck) — Double Ratchet chain key KDF (HMAC-SHA256).
// Returns [messageKey, newChainKey]: both are 32 bytes.
// Constant input bytes follow the Signal spec (0x01 = message key, 0x02 = chain key).
function kdfCk(chainKey) {
    const mk  = createHmac('sha256', chainKey).update(Buffer.from([0x01])).digest();
    const nck = createHmac('sha256', chainKey).update(Buffer.from([0x02])).digest();
    return [mk, nck];
}

// Advances the receiving chain key `upToNr - state.Nr` times, caching each derived
// message key in state.MKSKIPPED keyed by `"ratchetPublicB64:messageNumber"`.
// Throws if the gap exceeds MAX_SKIP to prevent DoS via artificially large Ns values.
function skipMessageKeys(state, ratchetPublicB64, upToNr) {
    if (upToNr - state.Nr > MAX_SKIP)
        throw new Error(`Refusing to skip ${upToNr - state.Nr} messages (MAX_SKIP=${MAX_SKIP})`);
    while (state.Nr < upToNr) {
        const [mk, newCK] = kdfCk(state.receivingChainKey);
        state.receivingChainKey = newCK;
        state.MKSKIPPED.set(`${ratchetPublicB64}:${state.Nr}`, mk);
        state.Nr += 1;
    }
}

// Shared AES-256-GCM decryption used by both cached and non-cached paths in ratchetDecrypt.
function _gcmDecrypt(messageKey, ciphertext, nonce, aad) {
    const tag      = ciphertext.subarray(-16);
    const ct       = ciphertext.subarray(0, -16);
    const decipher = createDecipheriv('aes-256-gcm', messageKey, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(aad);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// KDF_RK(rk, dh_out) — Double Ratchet root key KDF.
// Derives a new root key and chain key from the current root key and a DH output.
// HKDF(ikm=dh_out, salt=rk, info, len=64): first 32 bytes → new RK, next 32 → CK.
function kdfRk(rootKey, dhOutput) {
    const derived = hkdf(64, dhOutput, KDF_RK_INFO, rootKey);
    return [derived.subarray(0, 32), derived.subarray(32)];
}

// Computes the X3DH shared root key from the initiator's perspective.
//
// initiatorKeys  — { ikDhPrivate, ... } from login()
// responderBundle — { ikDhPublic, spkPublic, opkPublic | null, opkId } from fetchPrekeyBundle()
//
// Returns:
//   rootKey    — 32-byte shared secret, used to initialise the Double Ratchet
//   ephPublic  — initiator's ephemeral public key, sent in the initial message header
//   opkId      — which of the responder's OPKs was used (null if 3DH path)
export function x3dhSend(initiatorKeys, responderBundle) {
    const ephPrivate = PrivateKey.generate();
    const ephPublic  = ephPrivate.getPublicKey();

    const dh1 = initiatorKeys.ikDhPrivate.agree(responderBundle.spkPublic);  // DH(IK_i,  SPK_r)
    const dh2 = ephPrivate.agree(responderBundle.ikDhPublic);                 // DH(EK_i,  IK_r)
    const dh3 = ephPrivate.agree(responderBundle.spkPublic);                  // DH(EK_i,  SPK_r)

    const dhParts = [DOMAIN_SEP, dh1, dh2, dh3];

    if (responderBundle.opkPublic) {
        dhParts.push(ephPrivate.agree(responderBundle.opkPublic));            // DH(EK_i,  OPK_r)
    }

    // HKDF(IKM = F || DH1 || DH2 || DH3 [|| DH4], salt = null, info, length = 32)
    const masterSecret = Buffer.concat(dhParts);
    const rootKey = hkdf(32, masterSecret, X3DH_INFO, null);

    return { rootKey, ephPublic, opkId: responderBundle.opkId };
}

// Initialises the Double Ratchet state from the initiator's perspective.
//
// rootKey            — 32-byte shared secret from x3dhSend()
// responderSpkPublic — responder's signed prekey public key (used as the initial
//                      remote ratchet public key before the first ratchet step)
// peerIdentityKeys   — { ikSignPublic, ikDhPublic } from fetchPrekeyBundle(); stored
//                      in state for signature verification and TOFU fingerprinting
//
// Returns the full initial ratchet state:
//   rootKey              — updated root key after the first KDF_RK step
//   sendingChainKey      — CKs, ready to derive the first sending message key
//   receivingChainKey    — null until the responder's first ratchet public key arrives
//   localRatchetPrivate  — initiator's ratchet private key
//   localRatchetPublic   — initiator's ratchet public key (sent in message headers)
//   remoteRatchetPublic  — responder's current ratchet public key
//   Ns, Nr, PN           — message counters (all zero)
//   peerIdentityKeys     — { ikSignPublic, ikDhPublic } | null
//   fingerprintRecords   — { fingerprint, firstSeen } | null
export function initRatchet(rootKey, responderSpkPublic, peerIdentityKeys = null) {
    const ratchetPrivate = PrivateKey.generate();
    const ratchetPublic  = ratchetPrivate.getPublicKey();

    // First DH ratchet step: derive the initial sending chain from the new ratchet key pair
    const dhOut = ratchetPrivate.agree(responderSpkPublic);
    const [newRootKey, sendingChainKey] = kdfRk(rootKey, dhOut);

    const fingerprintRecords = peerIdentityKeys
        ? { fingerprint: createHash('sha256').update(peerIdentityKeys.ikSignPublic.serialize()).digest('hex'), firstSeen: new Date().toISOString() }
        : null;

    return {
        rootKey:             newRootKey,
        sendingChainKey,
        receivingChainKey:   null,
        localRatchetPrivate: ratchetPrivate,
        localRatchetPublic:  ratchetPublic,
        remoteRatchetPublic: responderSpkPublic,
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED:           new Map(),
        peerIdentityKeys,
        fingerprintRecords,
    };
}

// Encrypts and signs one message using the Double Ratchet sending chain.
//
// state          — ratchet state from initRatchet() (mutated in place: sendingChainKey, Ns)
// plaintext      — Buffer of the message to encrypt
// ikSignPrivate  — sender's long-term identity signing key (PrivateKey); signs every message
// ephPublic      — initiator's ephemeral public key from x3dhSend() (first-message headers only)
// ikDhPublic     — initiator's identity DH public key (first-message headers only; responder
//                  needs it to reconstruct DH1 and DH2 in x3dhReceive)
// opkId          — which OPK was consumed (first-message headers only; null for 3DH path)
//
// Returns { header, ciphertext, nonce, signature, digest }:
//   header     — plain-text JSON object used as AAD; must be transmitted with ciphertext
//   ciphertext — AES-256-GCM ciphertext with 16-byte auth tag appended
//   nonce      — 12-byte random nonce; must be transmitted with ciphertext
//   signature  — 64-byte XEdDSA signature over ciphertext || nonce || serialised header
//   digest     — keccak256 commitment over the full package; anchored on-chain
export function ratchetEncrypt(state, plaintext, ikSignPrivate, { ephPublic = null, ikDhPublic = null, opkId = null } = {}) {
    const [messageKey, newChainKey] = kdfCk(state.sendingChainKey);
    state.sendingChainKey = newChainKey;

    const isFirstMessage = ephPublic !== null;
    const header = {
        ratchetPublic: state.localRatchetPublic.serialize().toString('base64'),
        Ns:            state.Ns,
        PN:            state.PN,
        ...(opkId          !== null && { opkId }),
        ...(isFirstMessage         && { ephPublic:    ephPublic.serialize().toString('base64') }),
        ...(isFirstMessage         && { ikSignPublic: ikSignPrivate.getPublicKey().serialize().toString('base64') }),
        ...(ikDhPublic     !== null && { ikDhPublic:  ikDhPublic.serialize().toString('base64') }),
    };

    state.Ns += 1;

    const nonce = randomBytes(12);
    const aad   = Buffer.from(JSON.stringify(header), 'utf8');

    const cipher = createCipheriv('aes-256-gcm', messageKey, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

    // Sign ciphertext || nonce || header so the recipient can verify sender identity
    // before attempting decryption.
    const signedData = Buffer.concat([ciphertext, nonce, aad]);
    const signature  = ikSignPrivate.sign(signedData);

    // Keccak256 commitment over the full authenticated package — submitted to the
    // smart contract so the server cannot silently drop or alter messages.
    const digest = keccak256(Buffer.concat([ciphertext, nonce, aad, signature]));

    return { header, ciphertext, nonce, signature, digest };
}

// Decrypts one message using the Double Ratchet receiving chain.
//
// Handles three cases transparently:
//   - In-order message on the current chain: derive key, decrypt, Nr++
//   - Out-of-order message whose key was already cached: use MKSKIPPED, delete entry
//   - Message with a new ratchetPublic: advance the ratchet, skip any gap, then decrypt
//
// state      — ratchet state (mutated in place)
// ciphertext — AES-256-GCM ciphertext with 16-byte auth tag appended (from ratchetEncrypt)
// nonce      — 12-byte nonce transmitted alongside the ciphertext
// header     — plain-text header object used as AAD
//
// Throws if the GCM auth tag fails or the message gap exceeds MAX_SKIP.
export function ratchetDecrypt(state, ciphertext, nonce, header) {
    const ratchetPublicB64 = header.ratchetPublic;
    const aad              = Buffer.from(JSON.stringify(header), 'utf8');

    // 1. Check the skip cache — this message may have arrived out of order.
    const cacheKey = `${ratchetPublicB64}:${header.Ns}`;
    if (state.MKSKIPPED.has(cacheKey)) {
        const mk = state.MKSKIPPED.get(cacheKey);
        state.MKSKIPPED.delete(cacheKey);
        return _gcmDecrypt(mk, ciphertext, nonce, aad);
    }

    // 2. Ratchet advance — new remote ratchet public key detected.
    if (ratchetPublicB64 !== state.remoteRatchetPublic.serialize().toString('base64')) {
        // Cache any undelivered messages remaining on the old chain (up to PN).
        skipMessageKeys(state, state.remoteRatchetPublic.serialize().toString('base64'), header.PN);
        advanceRatchet(state, PublicKey.deserialize(Buffer.from(ratchetPublicB64, 'base64')));
    }

    // 3. Cache any messages skipped on the current chain.
    skipMessageKeys(state, ratchetPublicB64, header.Ns);

    // 4. Derive the message key and decrypt.
    const [mk, newCK] = kdfCk(state.receivingChainKey);
    state.receivingChainKey = newCK;
    state.Nr += 1;
    return _gcmDecrypt(mk, ciphertext, nonce, aad);
}

// Performs Phase 2 of the DH ratchet — used by the responder before their first reply.
// The receiving chain was already established by initRatchetReceiver, so only the sending
// chain needs to be derived here.
//
// For the general case of receiving a new remote ratchet public key mid-session,
// use advanceRatchet() instead, which runs both phases.
export function dhRatchetStep(state) {
    state.PN = state.Ns;
    state.Ns = 0;

    const newRatchetPrivate = PrivateKey.generate();
    const dhOut = newRatchetPrivate.agree(state.remoteRatchetPublic);
    const [newRootKey, sendingChainKey] = kdfRk(state.rootKey, dhOut);

    state.rootKey               = newRootKey;
    state.sendingChainKey       = sendingChainKey;
    state.localRatchetPrivate   = newRatchetPrivate;
    state.localRatchetPublic    = newRatchetPrivate.getPublicKey();
}

// Advances the ratchet state when a message arrives with a new remote ratchet public key
// (i.e. header.ratchetPublic !== state.remoteRatchetPublic.serialize().toString('base64')).
//
// Two KDF_RK calls in sequence, both keyed on newRemoteRatchetPublic:
//
//   Phase 1 — receiving chain:
//     RK, CKr = KDF_RK(RK, DH(current ratchet private, newRemoteRatchetPublic))
//     → lets the local side decrypt messages from the remote party
//
//   Phase 2 — sending chain:
//     generate new local ratchet key pair
//     RK, CKs = KDF_RK(RK, DH(new ratchet private, newRemoteRatchetPublic))
//     → ready to encrypt replies under the updated root key
//
// State mutations: rootKey, receivingChainKey, sendingChainKey, remoteRatchetPublic,
//                  ratchetPrivate, ratchetPublic, Nr=0, PN=Ns, Ns=0.
export function advanceRatchet(state, newRemoteRatchetPublic) {
    // Phase 1: new receiving chain
    const [rk1, receivingChainKey] = kdfRk(state.rootKey, state.localRatchetPrivate.agree(newRemoteRatchetPublic));
    state.rootKey             = rk1;
    state.receivingChainKey   = receivingChainKey;
    state.remoteRatchetPublic = newRemoteRatchetPublic;
    state.Nr                  = 0;

    // Phase 2: new sending chain + fresh local ratchet key pair
    state.PN = state.Ns;
    state.Ns = 0;
    const newRatchetPrivate = PrivateKey.generate();
    const [rk2, sendingChainKey] = kdfRk(rk1, newRatchetPrivate.agree(newRemoteRatchetPublic));
    state.rootKey               = rk2;
    state.sendingChainKey       = sendingChainKey;
    state.localRatchetPrivate   = newRatchetPrivate;
    state.localRatchetPublic    = newRatchetPrivate.getPublicKey();
}

// Verifies the XEdDSA signature on a received message.
//
// ikSignPublic — sender's identity signing PublicKey (from header.ikSignPublic on first message,
//                or from TOFU contacts storage on subsequent messages)
// Returns true if valid, false otherwise.  Callers should reject the message on false.
export function verifyMessage(header, ciphertext, nonce, signature, ikSignPublic) {
    const aad = Buffer.from(JSON.stringify(header), 'utf8');
    return ikSignPublic.verify(Buffer.concat([ciphertext, nonce, aad]), signature);
}

// Reconstructs the X3DH shared root key from the responder's perspective.
//
// responderKeys — { ikDhPrivate, spkPrivate, opkPrivates[] } from login()
// header        — first-message header from ratchetEncrypt() containing ikDhPublic, ephPublic, opkId
//
// Returns the 32-byte root key — pass directly to initRatchetReceiver().
export function x3dhReceive(responderKeys, header) {
    const ikDhPublic = PublicKey.deserialize(Buffer.from(header.ikDhPublic, 'base64'));
    const ephPublic  = PublicKey.deserialize(Buffer.from(header.ephPublic,  'base64'));

    const dh1 = responderKeys.spkPrivate.agree(ikDhPublic);   // DH(SPK_r,  IK_i)
    const dh2 = responderKeys.ikDhPrivate.agree(ephPublic);   // DH(IK_r,   EK_i)
    const dh3 = responderKeys.spkPrivate.agree(ephPublic);    // DH(SPK_r,  EK_i)

    const dhParts = [DOMAIN_SEP, dh1, dh2, dh3];

    if (header.opkId !== null && header.opkId !== undefined) {
        const opk = responderKeys.opkPrivates[header.opkId];
        if (!opk) throw new Error(`OPK not found for id ${header.opkId}`);
        dhParts.push(opk.agree(ephPublic));                   // DH(OPK_r,  EK_i)
    }

    return hkdf(32, Buffer.concat(dhParts), X3DH_INFO, null);
}

// Initialises the Double Ratchet state from the responder's perspective.
//
// rootKey    — 32-byte shared secret from x3dhReceive()
// header     — first-message header containing the initiator's ratchet public key;
//              may also contain ikSignPublic and ikDhPublic for peer identity storage
// spkPrivate — responder's signed prekey private key (serves as the initial ratchet private key
//              until the responder sends their first reply)
//
// Returns the full initial ratchet state:
//   rootKey              — updated root key after the first KDF_RK step
//   sendingChainKey      — null until the responder performs their first DH ratchet step
//   receivingChainKey    — CKr, ready to derive the first received message key
//   localRatchetPrivate  — spkPrivate (responder's initial ratchet key)
//   localRatchetPublic   — spkPrivate.getPublicKey()
//   remoteRatchetPublic  — initiator's ratchet public key (from header)
//   Ns, Nr, PN           — message counters (all zero)
//   peerIdentityKeys     — { ikSignPublic, ikDhPublic } extracted from first-message header, or null
//   fingerprintRecords   — { fingerprint, firstSeen } | null
export function initRatchetReceiver(rootKey, header, spkPrivate) {
    const remoteRatchetPublic = PublicKey.deserialize(Buffer.from(header.ratchetPublic, 'base64'));

    const dhOut = spkPrivate.agree(remoteRatchetPublic);      // DH(SPK_r, RatchetPub_i)
    const [newRootKey, receivingChainKey] = kdfRk(rootKey, dhOut);

    const peerIdentityKeys = (header.ikSignPublic && header.ikDhPublic)
        ? {
            ikSignPublic: PublicKey.deserialize(Buffer.from(header.ikSignPublic, 'base64')),
            ikDhPublic:   PublicKey.deserialize(Buffer.from(header.ikDhPublic,   'base64')),
          }
        : null;

    const fingerprintRecords = peerIdentityKeys
        ? { fingerprint: createHash('sha256').update(peerIdentityKeys.ikSignPublic.serialize()).digest('hex'), firstSeen: new Date().toISOString() }
        : null;

    return {
        rootKey:             newRootKey,
        sendingChainKey:     null,
        receivingChainKey,
        localRatchetPrivate: spkPrivate,
        localRatchetPublic:  spkPrivate.getPublicKey(),
        remoteRatchetPublic,
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED:           new Map(),
        peerIdentityKeys,
        fingerprintRecords,
    };
}
