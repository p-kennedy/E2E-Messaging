// X3DH session establishment and Double Ratchet initialisation — initiator side.
// Responder side (x3dhReceive) is implemented when processing the first incoming message.

import { PrivateKey, hkdf } from '@signalapp/libsignal-client';
import { randomBytes, createCipheriv, createHmac } from 'node:crypto';
import { keccak256 } from 'ethers';

// Signal X3DH spec: prepend 32 × 0xFF to the DH outputs as domain separation
// between the DH function and the KDF, before feeding into HKDF.
const DOMAIN_SEP  = Buffer.alloc(32, 0xff);
const X3DH_INFO   = Buffer.from('E2E-Messaging X3DH v1', 'utf8');
const KDF_RK_INFO = Buffer.from('E2E-Messaging Ratchet v1', 'utf8');

// KDF_CK(ck) — Double Ratchet chain key KDF (HMAC-SHA256).
// Returns [messageKey, newChainKey]: both are 32 bytes.
// Constant input bytes follow the Signal spec (0x01 = message key, 0x02 = chain key).
function kdfCk(chainKey) {
    const mk  = createHmac('sha256', chainKey).update(Buffer.from([0x01])).digest();
    const nck = createHmac('sha256', chainKey).update(Buffer.from([0x02])).digest();
    return [mk, nck];
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
// rootKey           — 32-byte shared secret from x3dhSend()
// responderSpkPublic — responder's signed prekey public key (used as the initial
//                      remote ratchet public key before the first ratchet step)
//
// Returns the full initial ratchet state:
//   rootKey             — updated root key after the first KDF_RK step
//   sendingChainKey     — CKs, ready to derive the first sending message key
//   receivingChainKey   — null until the responder's first ratchet public key arrives
//   ratchetPrivate      — initiator's ratchet private key
//   ratchetPublic       — initiator's ratchet public key (sent in message headers)
//   remoteRatchetPublic — responder's current ratchet public key
//   Ns, Nr, PN          — message counters (all zero)
export function initRatchet(rootKey, responderSpkPublic) {
    const ratchetPrivate = PrivateKey.generate();
    const ratchetPublic  = ratchetPrivate.getPublicKey();

    // First DH ratchet step: derive the initial sending chain from the new ratchet key pair
    const dhOut = ratchetPrivate.agree(responderSpkPublic);
    const [newRootKey, sendingChainKey] = kdfRk(rootKey, dhOut);

    return {
        rootKey:             newRootKey,
        sendingChainKey,
        receivingChainKey:   null,
        ratchetPrivate,
        ratchetPublic,
        remoteRatchetPublic: responderSpkPublic,
        Ns: 0,
        Nr: 0,
        PN: 0,
    };
}

// Encrypts and signs one message using the Double Ratchet sending chain.
//
// state          — ratchet state from initRatchet() (mutated in place: sendingChainKey, Ns)
// plaintext      — Buffer of the message to encrypt
// ikSignPrivate  — sender's long-term identity signing key (PrivateKey); signs every message
// ephPublic      — initiator's ephemeral public key from x3dhSend() (first-message headers only)
// opkId          — which OPK was consumed (first-message headers only; null for 3DH path)
//
// Returns { header, ciphertext, nonce, signature }:
//   header     — plain-text JSON object used as AAD; must be transmitted with ciphertext
//   ciphertext — AES-256-GCM ciphertext with 16-byte auth tag appended
//   nonce      — 12-byte random nonce; must be transmitted with ciphertext
//   signature  — 64-byte XEdDSA signature over ciphertext || nonce || serialised header
export function ratchetEncrypt(state, plaintext, ikSignPrivate, { ephPublic = null, opkId = null } = {}) {
    const [messageKey, newChainKey] = kdfCk(state.sendingChainKey);
    state.sendingChainKey = newChainKey;

    const header = {
        ratchetPublic: state.ratchetPublic.serialize().toString('base64'),
        Ns:            state.Ns,
        PN:            state.PN,
        ...(opkId     !== null && { opkId }),
        ...(ephPublic !== null && { ephPublic: ephPublic.serialize().toString('base64') }),
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
