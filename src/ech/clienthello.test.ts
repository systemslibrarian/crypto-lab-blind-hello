/** ClientHello serialization: round-trip, strictness, and span annotation. */
import { describe, expect, test } from 'vitest';
import {
  annotateClientHello,
  buildClientHello,
  EXT_ECH,
  EXT_SERVER_NAME,
  parseClientHello,
  serializeClientHello,
  TLS12,
} from './clienthello';
import { deriveKeyPair, utf8 } from './hub';
import { WireError } from './wire';

const share = deriveKeyPair(utf8('blind-hello clienthello test ikm 32B')).pk;

describe('ClientHello round-trip', () => {
  test('serialize → parse restores the structure', () => {
    const ch = buildClientHello({ serverName: 'bank.example.com', keySharePublic: share });
    const wire = serializeClientHello(ch);
    const { ch: parsed } = parseClientHello(wire);
    expect(parsed.legacyVersion).toBe(TLS12);
    expect(parsed.cipherSuites).toEqual([0x1301, 0x1302, 0x1303]);
    expect(parsed.extensions.map((e) => e.type)).toEqual(ch.extensions.map((e) => e.type));
    expect(serializeClientHello(parsed)).toEqual(wire);
  });

  test('parse fails closed on truncation and trailing bytes', () => {
    const wire = serializeClientHello(buildClientHello({ serverName: 'a.example', keySharePublic: share }));
    expect(() => parseClientHello(wire.slice(0, wire.length - 1))).toThrow(WireError);
    const longer = new Uint8Array(wire.length + 1);
    longer.set(wire);
    expect(() => parseClientHello(longer)).toThrow(/trailing/);
  });
});

describe('annotation (the observer view)', () => {
  test('locates the exact SNI value bytes on the wire', () => {
    const ch = buildClientHello({ serverName: 'bank.example.com', keySharePublic: share });
    const wire = serializeClientHello(ch);
    const ann = annotateClientHello(wire);
    expect(ann.sniHostname).toBe('bank.example.com');
    const span = ann.sniValueSpan!;
    expect(new TextDecoder().decode(wire.slice(span.start, span.end))).toBe('bank.example.com');
    expect(ann.extensions.some((e) => e.type === EXT_SERVER_NAME)).toBe(true);
    expect(ann.extensions.some((e) => e.type === EXT_ECH)).toBe(false);
  });
});
