/**
 * TLS 1.3 ClientHello (RFC 8446 §4.1.2) — real byte-level serialization and a
 * strict parser, because the whole lab is about which of these bytes an
 * observer can read. Only the ClientHello is built here; the rest of the
 * handshake is out of scope (see crypto-lab-tls-handshake).
 *
 * The parser returns byte SPANS for every field, so the observer panel can
 * highlight the exact wire bytes that carry the server name.
 */
import { concatBytes, randomBytes, utf8 } from './hub';
import { ByteReader, u16, u8, vec16, vec8, WireError } from './wire';

export const EXT_SERVER_NAME = 0x0000;
export const EXT_SUPPORTED_GROUPS = 0x000a;
export const EXT_ALPN = 0x0010;
export const EXT_SUPPORTED_VERSIONS = 0x002b;
export const EXT_KEY_SHARE = 0x0033;
export const EXT_ECH = 0xfe0d;

export const TLS12 = 0x0303;
export const TLS13 = 0x0304;
export const GROUP_X25519 = 0x001d;

/** TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 */
export const TLS13_CIPHER_SUITES = [0x1301, 0x1302, 0x1303];

export interface Extension {
  type: number;
  data: Uint8Array;
}

export interface ClientHello {
  legacyVersion: number;
  random: Uint8Array;
  legacySessionId: Uint8Array;
  cipherSuites: number[];
  compressionMethods: Uint8Array;
  extensions: Extension[];
}

/* ---------- extension bodies ---------- */

/** server_name (RFC 6066 §3): ServerNameList of one host_name entry. */
export function sniExtension(hostname: string): Extension {
  const name = utf8(hostname);
  if (name.length === 0 || name.length > 0xffff) throw new WireError('invalid hostname length');
  const entry = concatBytes(u8(0) /* name_type host_name */, vec16(name));
  return { type: EXT_SERVER_NAME, data: vec16(entry) };
}

/** application_layer_protocol_negotiation (RFC 7301). */
export function alpnExtension(protocols: string[]): Extension {
  const body = concatBytes(...protocols.map((p) => vec8(utf8(p))));
  return { type: EXT_ALPN, data: vec16(body) };
}

export function supportedVersionsExtension(): Extension {
  return { type: EXT_SUPPORTED_VERSIONS, data: vec8(u16(TLS13)) };
}

export function supportedGroupsExtension(): Extension {
  return { type: EXT_SUPPORTED_GROUPS, data: vec16(u16(GROUP_X25519)) };
}

export function keyShareExtension(publicKey: Uint8Array): Extension {
  const share = concatBytes(u16(GROUP_X25519), vec16(publicKey));
  return { type: EXT_KEY_SHARE, data: vec16(share) };
}

/* ---------- serialize / parse ---------- */

export function serializeExtensions(extensions: Extension[]): Uint8Array {
  return vec16(concatBytes(...extensions.map((e) => concatBytes(u16(e.type), vec16(e.data)))));
}

export function serializeClientHello(ch: ClientHello): Uint8Array {
  if (ch.random.length !== 32) throw new WireError('ClientHello.random must be 32 bytes');
  if (ch.legacySessionId.length > 32) throw new WireError('legacy_session_id must be 0..32 bytes');
  if (ch.cipherSuites.length === 0) throw new WireError('cipher_suites must not be empty');
  return concatBytes(
    u16(ch.legacyVersion),
    ch.random,
    vec8(ch.legacySessionId),
    vec16(concatBytes(...ch.cipherSuites.map((s) => u16(s)))),
    vec8(ch.compressionMethods),
    serializeExtensions(ch.extensions),
  );
}

export interface BuildParams {
  serverName: string;
  alpn?: string[];
  keySharePublic: Uint8Array;
  random?: Uint8Array;
  sessionId?: Uint8Array;
  /** Appended last if present (the encrypted_client_hello extension). */
  echExtension?: Extension;
}

export function buildClientHello(p: BuildParams): ClientHello {
  const extensions: Extension[] = [
    sniExtension(p.serverName),
    alpnExtension(p.alpn ?? ['h2', 'http/1.1']),
    supportedVersionsExtension(),
    supportedGroupsExtension(),
    keyShareExtension(p.keySharePublic),
  ];
  if (p.echExtension) extensions.push(p.echExtension);
  return {
    legacyVersion: TLS12,
    random: p.random ?? randomBytes(32),
    legacySessionId: p.sessionId ?? randomBytes(32),
    cipherSuites: [...TLS13_CIPHER_SUITES],
    compressionMethods: Uint8Array.of(0),
    extensions,
  };
}

/**
 * Strict struct parse. With `allowTrailing`, returns how many bytes the
 * structure consumed instead of demanding end-of-buffer — used for
 * EncodedClientHelloInner, whose zero padding follows the struct.
 */
export function parseClientHello(
  bytes: Uint8Array,
  opts: { allowTrailing?: boolean } = {},
): { ch: ClientHello; consumed: number } {
  const r = new ByteReader(bytes);
  const legacyVersion = r.u16();
  const random = r.bytes(32);
  const legacySessionId = r.vec8();
  if (legacySessionId.length > 32) throw new WireError('legacy_session_id longer than 32 bytes');
  const suitesReader = new ByteReader(r.vec16());
  const cipherSuites: number[] = [];
  while (suitesReader.remaining() > 0) cipherSuites.push(suitesReader.u16());
  if (cipherSuites.length === 0) throw new WireError('cipher_suites must not be empty');
  const compressionMethods = r.vec8();
  if (compressionMethods.length === 0) throw new WireError('legacy_compression_methods must not be empty');
  const extReader = new ByteReader(r.vec16());
  const extensions: Extension[] = [];
  while (extReader.remaining() > 0) {
    extensions.push({ type: extReader.u16(), data: extReader.vec16() });
  }
  if (!opts.allowTrailing) r.expectEnd('ClientHello');
  return {
    ch: { legacyVersion, random, legacySessionId, cipherSuites, compressionMethods, extensions },
    consumed: r.offset,
  };
}

/* ---------- byte-span annotation (the observer's view) ---------- */

export interface Span {
  start: number;
  end: number;
}

export interface ExtensionSpan {
  type: number;
  /** Whole extension incl. type+length. */
  span: Span;
  /** The extension_data bytes. */
  bodySpan: Span;
}

export interface ClientHelloAnnotation {
  randomSpan: Span;
  sessionIdSpan: Span;
  extensions: ExtensionSpan[];
  /** The hostname VALUE bytes inside the server_name extension, if present. */
  sniValueSpan?: Span;
  sniHostname?: string;
}

/**
 * Walk the serialized ClientHello recording absolute byte offsets. Separate
 * from parseClientHello so the observer demonstrably works from wire bytes.
 */
export function annotateClientHello(bytes: Uint8Array): ClientHelloAnnotation {
  const r = new ByteReader(bytes);
  r.u16(); // legacy_version
  const randomStart = r.offset;
  r.bytes(32);
  const randomSpan = { start: randomStart, end: r.offset };
  const sidLen = r.u8();
  const sessionIdSpan = { start: r.offset, end: r.offset + sidLen };
  r.bytes(sidLen);
  r.bytes(r.u16()); // cipher_suites
  r.bytes(r.u8()); // compression
  const extTotal = r.u16();
  const extEnd = r.offset + extTotal;
  const extensions: ExtensionSpan[] = [];
  let sniValueSpan: Span | undefined;
  let sniHostname: string | undefined;
  while (r.offset < extEnd) {
    const extStart = r.offset;
    const type = r.u16();
    const bodyLen = r.u16();
    const bodyStart = r.offset;
    const body = r.bytes(bodyLen);
    extensions.push({ type, span: { start: extStart, end: r.offset }, bodySpan: { start: bodyStart, end: r.offset } });
    if (type === EXT_SERVER_NAME) {
      const b = new ByteReader(body);
      b.u16(); // list length
      b.u8(); // name_type
      const nameLen = b.u16();
      const nameStartInBody = b.offset;
      sniHostname = new TextDecoder().decode(b.bytes(nameLen));
      sniValueSpan = { start: bodyStart + nameStartInBody, end: bodyStart + nameStartInBody + nameLen };
    }
  }
  return { randomSpan, sessionIdSpan, extensions, sniValueSpan, sniHostname };
}
