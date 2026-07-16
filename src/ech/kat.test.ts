/**
 * Known-answer tests, RFC 9180 Appendix A — run THROUGH the consumed hub
 * (crypto-lab-hpke-envelope) from this repo, proving the consumption path is
 * the hub's real implementation and not a local fork.
 *
 * ECH uses HPKE in Base mode only, so this lab pins the two Base-mode
 * vectors: A.1.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM) and
 * A.2.1 (same KEM/KDF, ChaCha20-Poly1305). draft-ietf-tls-esni itself
 * publishes no test vectors; the ECH layer is verified structurally and by
 * round-trip in ech.test.ts, and says so honestly.
 */
import { describe, expect, test } from 'vitest';
import vectors from '../../../crypto-lab-hpke-envelope/src/hpke/vectors/rfc9180.json';
import { bytesToHex, deriveKeyPair, hexToBytes, MODE_BASE, setupRecipient, setupSender, type AeadId } from './hub';

interface VectorEncryption {
  seq: number;
  aad: string;
  ct: string;
  nonce: string;
  pt: string;
}

interface Vector {
  mode: number;
  aead_id: number;
  info: string;
  ikmR: string;
  ikmE: string;
  skRm: string;
  pkRm: string;
  pkEm: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  exporter_secret: string;
  encryptions: VectorEncryption[];
  exports: { exporter_context: string; L: number; exported_value: string }[];
}

const baseVectors = (vectors as unknown as Vector[]).filter((v) => v.mode === MODE_BASE);

test('the hub ships both Base-mode RFC 9180 vectors this lab certifies against', () => {
  expect(baseVectors).toHaveLength(2);
});

for (const v of baseVectors) {
  const aeadId = v.aead_id as AeadId;
  const appendix = aeadId === 1 ? 'A.1.1 (AES-128-GCM)' : 'A.2.1 (ChaCha20-Poly1305)';

  describe(`RFC 9180 ${appendix}, mode Base — through the consumed hub`, () => {
    test('DeriveKeyPair(ikmR) and DeriveKeyPair(ikmE) match the vector', () => {
      const kpR = deriveKeyPair(hexToBytes(v.ikmR));
      expect(bytesToHex(kpR.sk)).toBe(v.skRm);
      expect(bytesToHex(kpR.pk)).toBe(v.pkRm);
      const kpE = deriveKeyPair(hexToBytes(v.ikmE));
      expect(bytesToHex(kpE.pk)).toBe(v.pkEm);
    });

    test('sender setup reproduces enc, shared_secret, and the key schedule', () => {
      const s = setupSender({
        mode: MODE_BASE,
        aeadId,
        pkR: hexToBytes(v.pkRm),
        info: hexToBytes(v.info),
        ephemeralIkm: hexToBytes(v.ikmE),
      });
      expect(bytesToHex(s.enc)).toBe(v.enc);
      expect(bytesToHex(s.kem.sharedSecret)).toBe(v.shared_secret);
      expect(bytesToHex(s.schedule.keyScheduleContext)).toBe(v.key_schedule_context);
      expect(bytesToHex(s.schedule.secret)).toBe(v.secret);
      expect(bytesToHex(s.schedule.key)).toBe(v.key);
      expect(bytesToHex(s.schedule.baseNonce)).toBe(v.base_nonce);
      expect(bytesToHex(s.schedule.exporterSecret)).toBe(v.exporter_secret);
    });

    test('recipient setup decapsulates to the same schedule', () => {
      const r = setupRecipient({
        mode: MODE_BASE,
        aeadId,
        enc: hexToBytes(v.enc),
        skR: deriveKeyPair(hexToBytes(v.ikmR)).sk,
        info: hexToBytes(v.info),
      });
      expect(bytesToHex(r.kem.sharedSecret)).toBe(v.shared_secret);
      expect(bytesToHex(r.schedule.key)).toBe(v.key);
      expect(bytesToHex(r.schedule.baseNonce)).toBe(v.base_nonce);
    });

    test(`Seal reproduces all ${v.encryptions.length} vector ciphertexts (nonce sequencing included)`, async () => {
      const s = setupSender({
        mode: MODE_BASE,
        aeadId,
        pkR: hexToBytes(v.pkRm),
        info: hexToBytes(v.info),
        ephemeralIkm: hexToBytes(v.ikmE),
      });
      for (const enc of v.encryptions) {
        s.context.seq = BigInt(enc.seq);
        const rec = await s.context.seal(hexToBytes(enc.aad), hexToBytes(enc.pt));
        expect(bytesToHex(rec.nonce)).toBe(enc.nonce);
        expect(bytesToHex(rec.ct)).toBe(enc.ct);
      }
    });

    test(`Export reproduces all ${v.exports.length} exported values`, () => {
      const s = setupSender({
        mode: MODE_BASE,
        aeadId,
        pkR: hexToBytes(v.pkRm),
        info: hexToBytes(v.info),
        ephemeralIkm: hexToBytes(v.ikmE),
      });
      for (const ex of v.exports) {
        expect(bytesToHex(s.context.export(hexToBytes(ex.exporter_context), ex.L))).toBe(ex.exported_value);
      }
    });
  });
}
