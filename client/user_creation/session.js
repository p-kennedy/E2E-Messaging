// X3DH session establishment — initiator side.
// Responder side (x3dhReceive) is implemented when processing the first incoming message.

import { PrivateKey, hkdf } from '@signalapp/libsignal-client';

// Signal X3DH spec: prepend 32 × 0xFF to the DH outputs as domain separation
// between the DH function and the KDF, before feeding into HKDF.
const DOMAIN_SEP = Buffer.alloc(32, 0xff);
const HKDF_INFO  = Buffer.from('E2E-Messaging X3DH v1', 'utf8');

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
    const rootKey = hkdf(32, masterSecret, HKDF_INFO, null);

    return { rootKey, ephPublic, opkId: responderBundle.opkId };
}
