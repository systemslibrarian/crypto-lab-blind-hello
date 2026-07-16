/** HTTPS RR (RFC 9460): real RDATA round-trip + the modeled lookup views. */
import { describe, expect, test } from 'vitest';
import { deriveKeyPair, utf8, bytesToHex } from '../ech/hub';
import { makeECHConfig, parseECHConfigList, serializeECHConfigList } from '../ech/echconfig';
import { decodeHttpsRdata, encodeHttpsRdata, observeDnsLookup } from './httpsrr';
import { WireError } from '../ech/wire';

const kp = deriveKeyPair(utf8('blind-hello dns test ikm — 32 bytes!!'));
const configList = serializeECHConfigList([
  makeECHConfig({ configId: 3, publicKey: kp.pk, publicName: 'public.cdn.example' }),
]);

describe('HTTPS RDATA round-trip', () => {
  test('encode → decode restores priority, target, alpn, and the ECHConfigList', () => {
    const rdata = encodeHttpsRdata({ priority: 1, targetName: '.', alpn: ['h2', 'http/1.1'], echConfigList: configList });
    const rec = decodeHttpsRdata(rdata);
    expect(rec.priority).toBe(1);
    expect(rec.targetName).toBe('.');
    expect(rec.alpn).toEqual(['h2', 'http/1.1']);
    expect(bytesToHex(rec.echConfigList)).toBe(bytesToHex(configList));
    // and the carried list is a valid ECHConfigList
    expect(parseECHConfigList(rec.echConfigList)[0].configId).toBe(3);
  });

  test('SvcParams must be in strictly increasing key order (fail closed)', () => {
    const rdata = encodeHttpsRdata({ priority: 1, targetName: '.', alpn: ['h2'], echConfigList: configList });
    // duplicate the alpn param (key 1) after ech (key 5): craft by concatenation
    const dup = new Uint8Array([...rdata, 0x00, 0x01, 0x00, 0x03, 0x02, 0x68, 0x32]);
    expect(() => decodeHttpsRdata(dup)).toThrow(WireError);
  });

  test('truncated RDATA fails closed', () => {
    const rdata = encodeHttpsRdata({ priority: 1, targetName: '.', alpn: ['h2'], echConfigList: configList });
    expect(() => decodeHttpsRdata(rdata.slice(0, rdata.length - 2))).toThrow(WireError);
  });
});

describe('the bootstrap leak (modeled lookup views)', () => {
  test('plaintext DNS: the observer reads the query name — before TLS ever starts', () => {
    const obs = observeDnsLookup('bank.example.com', 'plaintext', '192.0.2.53');
    expect(obs.qnameVisible).toBe('bank.example.com');
    expect(obs.items.some((i) => i.visibility === 'readable' && i.value.includes('bank.example.com'))).toBe(true);
  });

  test('DoH: the query name is not in the observable items', () => {
    const obs = observeDnsLookup('bank.example.com', 'doh', '192.0.2.53');
    expect(obs.qnameVisible).toBeUndefined();
    expect(obs.items.every((i) => !i.value.includes('bank.example.com'))).toBe(true);
  });
});
