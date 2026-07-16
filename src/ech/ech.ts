/**
 * Encrypted Client Hello (draft-ietf-tls-esni §5–§7) — the ECH-specific
 * construction, hand-rolled: encoding + padding of ClientHelloInner, the
 * "outer is the AAD" binding, GREASE, and the server's trial decryption with
 * the retry_configs recovery path.
 *
 * Every seal/open is the consumed hub's real HPKE (RFC 9180) — see ./hub.ts.
 * The lesson lives in what is around the HPKE call, not inside it.
 */
import {
  buildClientHello,
  type ClientHello,
  EXT_ECH,
  type Extension,
  parseClientHello,
  serializeClientHello,
  sniExtension,
} from './clienthello';
import { type ECHConfig, makeECHConfig, serializeECHConfigList } from './echconfig';
import {
  type AeadId,
  AEAD_AES_128_GCM,
  concatBytes,
  deriveKeyPair,
  generateKeyPair,
  type KeyPair,
  KDF_ID,
  MODE_BASE,
  NT,
  OpenError,
  publicKeyOf,
  randomBytes,
  type SetupResult,
  setupSender,
  setupRecipient,
  utf8,
} from './hub';
import { ByteReader, u16, u8, vec16, WireError } from './wire';

export const ECH_OUTER = 0;
export const ECH_INNER = 1;

/** HPKE info = "tls ech" ‖ 0x00 ‖ ECHConfig — binds the encryption to the exact config. */
export function echInfo(config: ECHConfig): Uint8Array {
  return concatBytes(utf8('tls ech'), u8(0), config.raw);
}

/** The inner ClientHello's marker extension: ECHClientHello with type=inner. */
export function echInnerExtension(): Extension {
  return { type: EXT_ECH, data: u8(ECH_INNER) };
}

export interface EchOuterBody {
  kdfId: number;
  aeadId: AeadId;
  configId: number;
  enc: Uint8Array;
  payload: Uint8Array;
}

export function echOuterExtension(body: EchOuterBody): Extension {
  return {
    type: EXT_ECH,
    data: concatBytes(
      u8(ECH_OUTER),
      u16(body.kdfId),
      u16(body.aeadId),
      u8(body.configId),
      vec16(body.enc),
      vec16(body.payload),
    ),
  };
}

export function parseEchExtension(data: Uint8Array): { kind: 'inner' } | ({ kind: 'outer' } & EchOuterBody) {
  const r = new ByteReader(data);
  const type = r.u8();
  if (type === ECH_INNER) {
    r.expectEnd('ECHClientHello(inner)');
    return { kind: 'inner' };
  }
  if (type !== ECH_OUTER) throw new WireError(`ECHClientHello type must be 0 or 1, got ${type}`);
  const kdfId = r.u16();
  const aeadId = r.u16() as AeadId;
  const configId = r.u8();
  const enc = r.vec16();
  const payload = r.vec16();
  r.expectEnd('ECHClientHello(outer)');
  return { kind: 'outer', kdfId, aeadId, configId, enc, payload };
}

/* ---------- EncodedClientHelloInner (§6.1, padding §6.1.3) ---------- */

/**
 * Padding so the payload length does not leak the inner name's length:
 * first pad the name up to maximum_name_length, then round the whole
 * encoding up to a multiple of 32 (the draft's recommended policy).
 */
export function innerPaddingLength(encodedLen: number, serverNameLen: number, maximumNameLength: number): number {
  let padding = Math.max(0, maximumNameLength - serverNameLen);
  const total = encodedLen + padding;
  padding += 31 - ((total - 1) % 32);
  return padding;
}

export interface EncodedInner {
  /** Serialized inner CH (legacy_session_id emptied) ‖ zero padding. */
  bytes: Uint8Array;
  structLen: number;
  paddingLen: number;
}

export function encodeClientHelloInner(inner: ClientHello, maximumNameLength: number): EncodedInner {
  // §6.1: EncodedClientHelloInner empties legacy_session_id (the server
  // restores it from the outer, which must echo the same value).
  const emptied: ClientHello = { ...inner, legacySessionId: new Uint8Array(0) };
  const struct = serializeClientHello(emptied);
  const sniExt = inner.extensions.find((e) => e.type === 0x0000);
  let nameLen = 0;
  if (sniExt) {
    const r = new ByteReader(sniExt.data);
    r.u16();
    r.u8();
    nameLen = r.u16();
  }
  const paddingLen = innerPaddingLength(struct.length, nameLen, maximumNameLength);
  return { bytes: concatBytes(struct, new Uint8Array(paddingLen)), structLen: struct.length, paddingLen };
}

/** Strict decode: parse the struct, then require every trailing byte to be zero. */
export function decodeClientHelloInner(encoded: Uint8Array, outerSessionId: Uint8Array): ClientHello {
  const { ch, consumed } = parseClientHello(encoded, { allowTrailing: true });
  for (let i = consumed; i < encoded.length; i++) {
    if (encoded[i] !== 0) throw new WireError(`EncodedClientHelloInner padding byte at ${i} is non-zero`);
  }
  if (ch.legacySessionId.length !== 0) {
    throw new WireError('EncodedClientHelloInner must carry an empty legacy_session_id');
  }
  if (!ch.extensions.some((e) => e.type === EXT_ECH && e.data.length === 1 && e.data[0] === ECH_INNER)) {
    throw new WireError('ClientHelloInner must carry the ech(inner) marker extension');
  }
  return { ...ch, legacySessionId: outerSessionId };
}

/* ---------- client: seal ---------- */

export interface SealParams {
  innerServerName: string;
  config: ECHConfig;
  alpn?: string[];
  /** X25519 key_share public value; generated if omitted. */
  keySharePublic?: Uint8Array;
  innerRandom?: Uint8Array;
  outerRandom?: Uint8Array;
  sessionId?: Uint8Array;
  /** Deterministic HPKE ephemeral (tests / replayable UI); omit for fresh randomness. */
  ephemeralIkm?: Uint8Array;
}

export interface SealResult {
  innerCh: ClientHello;
  innerWire: Uint8Array;
  encodedInner: EncodedInner;
  /** The outer with a zeroed payload, serialized — the exact HPKE AAD. */
  aad: Uint8Array;
  outerCh: ClientHello;
  enc: Uint8Array;
  payload: Uint8Array;
  /** The final ClientHelloOuter on the wire (payload spliced in). */
  wire: Uint8Array;
  info: Uint8Array;
  hpke: SetupResult;
  aeadId: AeadId;
}

export async function sealEch(p: SealParams): Promise<SealResult> {
  const config = p.config;
  const suite = config.cipherSuites.find((s) => s.kdfId === KDF_ID && s.aeadId === AEAD_AES_128_GCM) ??
    config.cipherSuites[0];
  const aeadId = suite.aeadId;
  const keySharePublic = p.keySharePublic ?? generateKeyPair().pk;
  const sessionId = p.sessionId ?? randomBytes(32);

  const innerCh = buildClientHello({
    serverName: p.innerServerName,
    alpn: p.alpn,
    keySharePublic,
    random: p.innerRandom,
    sessionId,
    echExtension: echInnerExtension(),
  });
  const innerWire = serializeClientHello(innerCh);
  const encodedInner = encodeClientHelloInner(innerCh, config.maximumNameLength);

  const info = echInfo(config);
  const hpke = setupSender({
    mode: MODE_BASE,
    aeadId,
    pkR: config.publicKey,
    info,
    ephemeralIkm: p.ephemeralIkm,
  });

  const zeroPayload = new Uint8Array(encodedInner.bytes.length + NT);

  // Build the outer ONCE with a zeroed payload; its serialization is the AAD.
  const outerRandom = p.outerRandom ?? randomBytes(32);
  const outerZeroed = buildClientHello({
    serverName: config.publicName,
    alpn: p.alpn,
    keySharePublic,
    random: outerRandom,
    sessionId,
    echExtension: echOuterExtension({
      kdfId: suite.kdfId,
      aeadId,
      configId: config.configId,
      enc: hpke.enc,
      payload: zeroPayload,
    }),
  });
  const aad = serializeClientHello(outerZeroed);
  const rec = await hpke.context.seal(aad, encodedInner.bytes);

  // Splice the real payload into the same outer — identical bytes except the
  // payload field, which is exactly what makes the outer the AAD.
  const outerCh: ClientHello = {
    ...outerZeroed,
    extensions: outerZeroed.extensions.map((e) =>
      e.type === EXT_ECH
        ? echOuterExtension({ kdfId: suite.kdfId, aeadId, configId: config.configId, enc: hpke.enc, payload: rec.ct })
        : e,
    ),
  };
  const wire = serializeClientHello(outerCh);

  return {
    innerCh,
    innerWire,
    encodedInner,
    aad,
    outerCh,
    enc: hpke.enc,
    payload: rec.ct,
    wire,
    info,
    hpke,
    aeadId,
  };
}

/** A plain (no-ECH) ClientHello for the side-by-side observer view. */
export function plainClientHello(serverName: string, alpn?: string[]): Uint8Array {
  return serializeClientHello(
    buildClientHello({ serverName, alpn, keySharePublic: generateKeyPair().pk }),
  );
}

/* ---------- GREASE (§6.2) ---------- */

/**
 * A client with no ECHConfig sends a fake-but-well-formed ECH extension so
 * that "sends ECH" stops being a distinguishing feature of ECH users.
 * The enc is a random (valid) X25519 point and the payload is random bytes —
 * indistinguishable on the wire from a real HPKE ciphertext.
 */
export function greaseEch(payloadLen: number): Extension {
  return echOuterExtension({
    kdfId: KDF_ID,
    aeadId: AEAD_AES_128_GCM,
    configId: randomBytes(1)[0],
    enc: publicKeyOf(randomBytes(32)),
    payload: randomBytes(payloadLen),
  });
}

export function greaseClientHello(serverName: string, payloadLen: number): Uint8Array {
  return serializeClientHello(
    buildClientHello({ serverName, keySharePublic: generateKeyPair().pk, echExtension: greaseEch(payloadLen) }),
  );
}

/* ---------- server: trial decryption + retry_configs ---------- */

export type HpkeOpenOutcome = 'ok' | 'fail' | 'not-attempted';

export interface ServerResult {
  echPresent: boolean;
  outerSni?: string;
  /** The raw cryptographic outcome, reported on its own — never merged with `action`. */
  hpkeOpen: HpkeOpenOutcome;
  openError?: string;
  /** What the server DOES — the protocol action, independent of the crypto result. */
  action: 'accepted-inner' | 'continue-outer';
  innerSni?: string;
  innerCh?: ClientHello;
  matchedConfigId?: number;
  /** Serialized ECHConfigList offered back when ECH was present but not accepted. */
  retryConfigs?: Uint8Array;
}

export class EchServer {
  readonly publicName: string;
  private keyPair: KeyPair;
  private config_: ECHConfig;

  constructor(publicName: string, opts: { configId?: number; ikm?: Uint8Array; maximumNameLength?: number } = {}) {
    this.publicName = publicName;
    this.keyPair = opts.ikm ? deriveKeyPair(opts.ikm) : generateKeyPair();
    this.config_ = makeECHConfig({
      configId: opts.configId ?? randomBytes(1)[0],
      publicKey: this.keyPair.pk,
      publicName,
      maximumNameLength: opts.maximumNameLength ?? 64,
    });
  }

  get config(): ECHConfig {
    return this.config_;
  }

  retryConfigs(): Uint8Array {
    return serializeECHConfigList([this.config_]);
  }

  /**
   * Rotate the HPKE key but keep the config_id — the stale-cached-config
   * scenario: the server still recognizes the id, tries the real decryption,
   * and the real decryption fails.
   */
  rotateKey(ikm?: Uint8Array): void {
    this.keyPair = ikm ? deriveKeyPair(ikm) : generateKeyPair();
    this.config_ = makeECHConfig({
      configId: this.config_.configId,
      publicKey: this.keyPair.pk,
      publicName: this.publicName,
      maximumNameLength: this.config_.maximumNameLength,
    });
  }

  async accept(wire: Uint8Array): Promise<ServerResult> {
    const { ch: outer } = parseClientHello(wire);
    const sniExt = outer.extensions.find((e) => e.type === 0x0000);
    let outerSni: string | undefined;
    if (sniExt) {
      const r = new ByteReader(sniExt.data);
      r.u16();
      r.u8();
      outerSni = new TextDecoder().decode(r.bytes(r.u16()));
    }
    const echExt = outer.extensions.find((e) => e.type === EXT_ECH);
    if (!echExt) {
      return { echPresent: false, outerSni, hpkeOpen: 'not-attempted', action: 'continue-outer' };
    }
    const body = parseEchExtension(echExt.data);
    if (body.kind === 'inner') {
      throw new WireError('received a ClientHello marked inner on the outer wire');
    }
    // Trial decryption: config_id is only a hint. Unknown id — which is what
    // GREASE produces by construction — gets the same answer as a failed
    // decryption, so an observer of the server's behavior learns nothing.
    if (body.configId !== this.config_.configId) {
      return {
        echPresent: true,
        outerSni,
        hpkeOpen: 'not-attempted',
        action: 'continue-outer',
        retryConfigs: this.retryConfigs(),
      };
    }
    // Reconstruct the AAD: the outer with the payload zeroed. Any bit an
    // attacker changed anywhere in the outer changes these bytes.
    const zeroed: ClientHello = {
      ...outer,
      extensions: outer.extensions.map((e) =>
        e.type === EXT_ECH
          ? echOuterExtension({
              kdfId: body.kdfId,
              aeadId: body.aeadId,
              configId: body.configId,
              enc: body.enc,
              payload: new Uint8Array(body.payload.length),
            })
          : e,
      ),
    };
    const aad = serializeClientHello(zeroed);
    try {
      const hpke = setupRecipient({
        mode: MODE_BASE,
        aeadId: body.aeadId,
        enc: body.enc,
        skR: this.keyPair.sk,
        info: echInfo(this.config_),
      });
      const { pt } = await hpke.context.open(aad, body.payload);
      const innerCh = decodeClientHelloInner(pt, outer.legacySessionId);
      const innerSniExt = innerCh.extensions.find((e) => e.type === 0x0000);
      let innerSni: string | undefined;
      if (innerSniExt) {
        const r = new ByteReader(innerSniExt.data);
        r.u16();
        r.u8();
        innerSni = new TextDecoder().decode(r.bytes(r.u16()));
      }
      return {
        echPresent: true,
        outerSni,
        hpkeOpen: 'ok',
        action: 'accepted-inner',
        innerSni,
        innerCh,
        matchedConfigId: body.configId,
      };
    } catch (e) {
      if (e instanceof OpenError || e instanceof WireError) {
        return {
          echPresent: true,
          outerSni,
          hpkeOpen: 'fail',
          openError: e.message,
          action: 'continue-outer',
          matchedConfigId: body.configId,
          retryConfigs: this.retryConfigs(),
        };
      }
      throw e;
    }
  }
}

/* ---------- attack helpers (break-it panel + tests) ---------- */

/** Flip one bit of the config's HPKE public key — the client now seals to a key nobody holds. */
export function tamperConfigPublicKey(config: ECHConfig): ECHConfig {
  const pk = config.publicKey.slice();
  pk[0] ^= 0x01;
  return makeECHConfig({
    configId: config.configId,
    publicKey: pk,
    publicName: config.publicName,
    maximumNameLength: config.maximumNameLength,
    cipherSuites: config.cipherSuites,
  });
}

/**
 * The swap attack: take the sealed ECH payload and carry it inside a
 * DIFFERENT outer (here: outer SNI rewritten). Because the whole outer is
 * the AAD, the server's reconstructed AAD differs and the real AEAD open fails.
 */
export function swapOuterSni(wire: Uint8Array, newServerName: string): Uint8Array {
  const { ch } = parseClientHello(wire);
  const swapped: ClientHello = {
    ...ch,
    extensions: ch.extensions.map((e) => (e.type === 0x0000 ? sniExtension(newServerName) : e)),
  };
  return serializeClientHello(swapped);
}
