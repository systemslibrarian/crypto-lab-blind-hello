/**
 * The single import point for the consumed HPKE hub — crypto-lab-hpke-envelope,
 * this fleet's real RFC 9180 implementation (DHKEM(X25519, HKDF-SHA256),
 * HKDF-SHA256, AES-128-GCM / ChaCha20-Poly1305).
 *
 * This lab does NOT reimplement HPKE (a stated Non-goal): every seal and every
 * open below runs the hub's code, KATs and all. The relative path expects the
 * hub checked out as a sibling directory of this repo — see the README and
 * deploy.yml for the exact layout.
 */
export {
  setupSender,
  setupRecipient,
  MODE_BASE,
  publicKeyOf,
  type SetupResult,
} from '../../../crypto-lab-hpke-envelope/src/hpke/hpke';
export {
  deriveKeyPair,
  generateKeyPair,
  type KeyPair,
} from '../../../crypto-lab-hpke-envelope/src/hpke/dhkem';
export { OpenError } from '../../../crypto-lab-hpke-envelope/src/hpke/aead';
export {
  AEAD_AES_128_GCM,
  AEAD_CHACHA20_POLY1305,
  AEAD_NAMES,
  KDF_ID,
  KEM_ID,
  NT,
  type AeadId,
} from '../../../crypto-lab-hpke-envelope/src/hpke/consts';
export {
  bytesToHex,
  hexToBytes,
  concatBytes,
  equalBytes,
  i2osp,
  randomBytes,
  utf8,
} from '../../../crypto-lab-hpke-envelope/src/hpke/bytes';
