/**
 * The ECH construction against the real HPKE hub: round-trip, the
 * outer-as-AAD binding, padding, GREASE, and every break-it path the UI
 * exposes. Independent results are asserted independently: the HPKE outcome
 * (`hpkeOpen`) and the server's protocol action (`action`) are separate
 * fields, and the tests check both.
 */
import { describe, expect, test } from 'vitest';
import { parseClientHello, serializeClientHello } from './clienthello';
import { parseECHConfigList } from './echconfig';
import {
  EchServer,
  echInfo,
  encodeClientHelloInner,
  greaseClientHello,
  innerPaddingLength,
  plainClientHello,
  sealEch,
  swapOuterSni,
  tamperConfigPublicKey,
} from './ech';
import { bytesToHex, utf8 } from './hub';
import { observeClientHello, wireContainsAscii } from './observer';
import { WireError } from './wire';

const IKM_S = utf8('blind-hello server ikm — 32+ bytes long!');
const IKM_S2 = utf8('blind-hello ROTATED ikm — 32+ bytes !!');
const IKM_E = utf8('blind-hello ephemeral ikm — 32+ bytes!');

function freshServer() {
  return new EchServer('public.cdn.example', { configId: 42, ikm: IKM_S });
}

describe('ECH round-trip (client seal → server open)', () => {
  test('server recovers the exact inner ClientHello and its SNI', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const result = await server.accept(sealed.wire);
    expect(result.hpkeOpen).toBe('ok');
    expect(result.action).toBe('accepted-inner');
    expect(result.innerSni).toBe('bank.example.com');
    expect(result.outerSni).toBe('public.cdn.example');
    // byte-for-byte: reconstructed inner === the inner the client built
    expect(bytesToHex(serializeClientHello(result.innerCh!))).toBe(bytesToHex(sealed.innerWire));
  });

  test('the AAD is exactly the outer with the payload zeroed', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    expect(sealed.aad.length).toBe(sealed.wire.length);
    let diff = 0;
    for (let i = 0; i < sealed.wire.length; i++) if (sealed.aad[i] !== sealed.wire[i]) diff++;
    // they differ in (at most) the payload bytes and nowhere else
    expect(diff).toBeGreaterThan(0);
    expect(diff).toBeLessThanOrEqual(sealed.payload.length);
  });

  test('HPKE info string binds to the exact ECHConfig bytes', () => {
    const server = freshServer();
    const info = echInfo(server.config);
    expect(new TextDecoder().decode(info.slice(0, 7))).toBe('tls ech');
    expect(info[7]).toBe(0);
    expect(bytesToHex(info.slice(8))).toBe(bytesToHex(server.config.raw));
  });
});

describe('the outer is the AAD — tamper anywhere, the real AEAD open fails', () => {
  test('swapping the outer SNI makes HPKE open fail; inner is never processed', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const swapped = swapOuterSni(sealed.wire, 'attacker.example');
    const result = await server.accept(swapped);
    expect(result.hpkeOpen).toBe('fail');
    expect(result.action).toBe('continue-outer');
    expect(result.innerSni).toBeUndefined();
    expect(result.retryConfigs).toBeDefined();
  });

  test('flipping one payload bit makes HPKE open fail', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const { ch } = parseClientHello(sealed.wire);
    const ech = ch.extensions.find((e) => e.type === 0xfe0d)!;
    ech.data[ech.data.length - 1] ^= 0x01;
    const result = await server.accept(serializeClientHello(ch));
    expect(result.hpkeOpen).toBe('fail');
    expect(result.action).toBe('continue-outer');
  });
});

describe('break-it paths', () => {
  test('tampered ECHConfig public key: client seals to a key nobody holds → open fails', async () => {
    const server = freshServer();
    const bad = tamperConfigPublicKey(server.config);
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: bad, ephemeralIkm: IKM_E });
    const result = await server.accept(sealed.wire);
    expect(result.hpkeOpen).toBe('fail');
    expect(result.action).toBe('continue-outer');
    expect(result.retryConfigs).toBeDefined();
  });

  test('stale config after key rotation: open fails, retry with retry_configs succeeds', async () => {
    const server = freshServer();
    const staleConfig = server.config;
    server.rotateKey(IKM_S2);
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: staleConfig, ephemeralIkm: IKM_E });
    const rejected = await server.accept(sealed.wire);
    expect(rejected.hpkeOpen).toBe('fail');
    expect(rejected.action).toBe('continue-outer');
    expect(rejected.retryConfigs).toBeDefined();

    // the designed recovery: parse retry_configs, seal again, accepted
    const [fresh] = parseECHConfigList(rejected.retryConfigs!);
    const retried = await sealEch({ innerServerName: 'bank.example.com', config: fresh, ephemeralIkm: IKM_E });
    const accepted = await server.accept(retried.wire);
    expect(accepted.hpkeOpen).toBe('ok');
    expect(accepted.action).toBe('accepted-inner');
    expect(accepted.innerSni).toBe('bank.example.com');
  });

  test('unknown config_id (GREASE included) is not distinguishable from a failed open in the action taken', async () => {
    const server = freshServer();
    const grease = greaseClientHello('public.cdn.example', 160);
    const result = await server.accept(grease);
    expect(result.hpkeOpen).not.toBe('ok');
    expect(result.action).toBe('continue-outer');
    expect(result.retryConfigs).toBeDefined();
  });
});

describe('padding (§6.1.3): payload length must not leak the inner name length', () => {
  test('different-length inner names under the same config produce equal payload lengths', async () => {
    const server = freshServer();
    const a = await sealEch({ innerServerName: 'x.example', config: server.config, ephemeralIkm: IKM_E });
    const b = await sealEch({
      innerServerName: 'a-much-longer-hostname.subdomain.example.com',
      config: server.config,
      ephemeralIkm: IKM_E,
    });
    expect(a.payload.length).toBe(b.payload.length);
  });

  test('padding formula: name padded to maximum_name_length, total rounded to 32', () => {
    const pad = innerPaddingLength(100, 10, 64);
    expect(pad).toBeGreaterThanOrEqual(64 - 10); // the name is padded up to maximum_name_length
    expect((100 + pad) % 32).toBe(0); // and the whole encoding rounds up to a multiple of 32
  });

  test('non-zero padding bytes are rejected (fail closed)', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    // corrupt the padding INSIDE the plaintext and decode directly
    const encoded = sealed.encodedInner.bytes.slice();
    encoded[encoded.length - 1] = 0xff;
    const { decodeClientHelloInner } = await import('./ech');
    expect(() => decodeClientHelloInner(encoded, new Uint8Array(32))).toThrow(/padding/);
  });
});

describe('GREASE ECH (§6.2)', () => {
  test('GREASE and real ECH extensions are structurally identical to an observer', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const real = observeClientHello(sealed.wire, { ip: '203.0.113.10', port: 443 });
    const grease = observeClientHello(greaseClientHello('public.cdn.example', real.echOuter!.payloadLen), {
      ip: '203.0.113.10',
      port: 443,
    });
    expect(grease.echPresent).toBe(true);
    expect(grease.echOuter!.encLen).toBe(real.echOuter!.encLen);
    expect(grease.echOuter!.payloadLen).toBe(real.echOuter!.payloadLen);
    expect(grease.echOuter!.kdfId).toBe(real.echOuter!.kdfId);
    expect(grease.echOuter!.aeadId).toBe(real.echOuter!.aeadId);
  });
});

describe('the observer', () => {
  test('without ECH: the inner name is readable on the wire', () => {
    const wire = plainClientHello('bank.example.com');
    const report = observeClientHello(wire, { ip: '203.0.113.10', port: 443 });
    expect(report.sniVisible).toBe('bank.example.com');
    expect(wireContainsAscii(wire, 'bank.example.com')).toBe(true);
  });

  test('with ECH: the wire contains the public name and NOT the inner name, anywhere', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const report = observeClientHello(sealed.wire, { ip: '203.0.113.10', port: 443 });
    expect(report.sniVisible).toBe('public.cdn.example');
    expect(report.echPresent).toBe(true);
    expect(wireContainsAscii(sealed.wire, 'bank.example.com')).toBe(false);
    expect(wireContainsAscii(sealed.wire, 'bank')).toBe(false);
  });

  test('what the observer still learns with ECH: config_id and payload length are readable', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const report = observeClientHello(sealed.wire, { ip: '203.0.113.10', port: 443 });
    expect(report.echOuter!.configId).toBe(42);
    expect(report.echOuter!.payloadLen).toBe(sealed.payload.length);
  });
});

describe('inner encoding invariants', () => {
  test('EncodedClientHelloInner empties legacy_session_id and the server restores the outer one', async () => {
    const server = freshServer();
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: server.config, ephemeralIkm: IKM_E });
    const encoded = encodeClientHelloInner(sealed.innerCh, server.config.maximumNameLength);
    const { ch } = parseClientHello(encoded.bytes, { allowTrailing: true });
    expect(ch.legacySessionId.length).toBe(0);
    const result = await server.accept(sealed.wire);
    expect(bytesToHex(result.innerCh!.legacySessionId)).toBe(bytesToHex(sealed.outerCh.legacySessionId));
  });

  test('an inner without the ech(inner) marker is rejected on decode', async () => {
    const { decodeClientHelloInner } = await import('./ech');
    const bare = plainClientHello('bank.example.com');
    const { ch } = parseClientHello(bare);
    const noSid = serializeClientHello({ ...ch, legacySessionId: new Uint8Array(0) });
    expect(() => decodeClientHelloInner(noSid, new Uint8Array(0))).toThrow(WireError);
  });
});

describe('substituted ECHConfig — the disclosure the delivery channel must prevent', () => {
  const IKM_A = utf8('blind-hello ATTACKER ikm — 32 bytes !!!');

  test('an attacker whose config the client accepted really reads the inner name', async () => {
    // Same public name, same config_id, the ATTACKER's key: exactly what an
    // active attacker on a plaintext DNS path could hand the client.
    const attacker = new EchServer('public.cdn.example', { configId: 42, ikm: IKM_A });
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: attacker.config, ephemeralIkm: IKM_E });
    const stolen = await attacker.accept(sealed.wire);
    expect(stolen.hpkeOpen).toBe('ok');
    expect(stolen.action).toBe('accepted-inner');
    expect(stolen.innerSni).toBe('bank.example.com');
  });

  test('the real server, shown the same wire, cannot decrypt it', async () => {
    const attacker = new EchServer('public.cdn.example', { configId: 42, ikm: IKM_A });
    const server = freshServer(); // also config_id 42 — forces a genuine trial decryption
    const sealed = await sealEch({ innerServerName: 'bank.example.com', config: attacker.config, ephemeralIkm: IKM_E });
    const result = await server.accept(sealed.wire);
    expect(result.hpkeOpen).toBe('fail');
    expect(result.innerSni).toBeUndefined();
  });
});

describe('a ClientHello with no ECH at all', () => {
  test('server just proceeds with the visible SNI (this is the pre-ECH world)', async () => {
    const server = freshServer();
    const result = await server.accept(plainClientHello('bank.example.com'));
    expect(result.echPresent).toBe(false);
    expect(result.hpkeOpen).toBe('not-attempted');
    expect(result.action).toBe('continue-outer');
    expect(result.outerSni).toBe('bank.example.com');
    expect(result.retryConfigs).toBeUndefined();
  });
});
