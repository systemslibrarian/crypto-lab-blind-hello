/** ECHConfig / ECHConfigList: round-trip plus strict fail-closed parsing. */
import { describe, expect, test } from 'vitest';
import { bytesToHex, deriveKeyPair, utf8 } from './hub';
import { ECH_VERSION, makeECHConfig, parseECHConfigList, serializeECHConfigList } from './echconfig';
import { WireError } from './wire';

const kp = deriveKeyPair(utf8('blind-hello echconfig test ikm, 32B+'));

function sampleConfig(configId = 7) {
  return makeECHConfig({ configId, publicKey: kp.pk, publicName: 'public.cdn.example', maximumNameLength: 64 });
}

describe('ECHConfigList round-trip', () => {
  test('serialize → parse restores every field', () => {
    const config = sampleConfig();
    const list = serializeECHConfigList([config]);
    const [parsed] = parseECHConfigList(list);
    expect(parsed.version).toBe(ECH_VERSION);
    expect(parsed.configId).toBe(7);
    expect(parsed.kemId).toBe(0x0020);
    expect(bytesToHex(parsed.publicKey)).toBe(bytesToHex(kp.pk));
    expect(parsed.publicName).toBe('public.cdn.example');
    expect(parsed.maximumNameLength).toBe(64);
    expect(parsed.cipherSuites).toEqual([{ kdfId: 0x0001, aeadId: 0x0001 }]);
    expect(bytesToHex(parsed.raw)).toBe(bytesToHex(config.raw));
  });

  test('a two-config list parses in order', () => {
    const list = serializeECHConfigList([sampleConfig(1), sampleConfig(2)]);
    const parsed = parseECHConfigList(list);
    expect(parsed.map((c) => c.configId)).toEqual([1, 2]);
  });
});

describe('strict parsing fails closed', () => {
  test('unknown version', () => {
    const list = serializeECHConfigList([sampleConfig()]);
    list[2] = 0xfe;
    list[3] = 0x0a; // version 0xfe0a (the retired ESNI era)
    expect(() => parseECHConfigList(list)).toThrow(WireError);
    expect(() => parseECHConfigList(list)).toThrow(/version/);
  });

  test('truncated list', () => {
    const list = serializeECHConfigList([sampleConfig()]);
    expect(() => parseECHConfigList(list.slice(0, list.length - 3))).toThrow(WireError);
  });

  test('trailing garbage after the list', () => {
    const list = serializeECHConfigList([sampleConfig()]);
    const withTrailing = new Uint8Array(list.length + 1);
    withTrailing.set(list);
    expect(() => parseECHConfigList(withTrailing)).toThrow(/trailing/);
  });

  test('empty list', () => {
    expect(() => parseECHConfigList(Uint8Array.of(0, 0))).toThrow(/empty/);
  });

  test('wrong KEM id', () => {
    const list = serializeECHConfigList([sampleConfig()]);
    // kem_id offset: list_len(2) + version(2) + contents_len(2) + config_id(1) = 7
    list[7] = 0x00;
    list[8] = 0x10; // DHKEM(P-256) — not this lab's suite
    expect(() => parseECHConfigList(list)).toThrow(/kem_id/);
  });

  test('maker rejects empty and non-DNS public_name', () => {
    expect(() => makeECHConfig({ configId: 1, publicKey: kp.pk, publicName: '' })).toThrow(WireError);
    expect(() => makeECHConfig({ configId: 1, publicKey: kp.pk, publicName: 'bad name!' })).toThrow(WireError);
  });

  test('maker rejects a non-32-byte public key', () => {
    expect(() => makeECHConfig({ configId: 1, publicKey: new Uint8Array(31), publicName: 'a.example' })).toThrow(
      /32 bytes/,
    );
  });
});
