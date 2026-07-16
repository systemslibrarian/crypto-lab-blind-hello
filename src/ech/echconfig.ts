/**
 * ECHConfig / ECHConfigList (draft-ietf-tls-esni §4) — the public-key handout
 * a server publishes (via the DNS HTTPS RR) so clients can encrypt their
 * ClientHelloInner to it.
 *
 * Hand-rolled serialize + strict parse: the exact byte layout of this
 * structure is a teaching subject (the observer can read all of it — the
 * config is public by design; only the ClientHello it later encrypts is not).
 */
import { AEAD_AES_128_GCM, type AeadId, bytesToHex, concatBytes, KDF_ID, KEM_ID, utf8 } from './hub';
import { ByteReader, u16, u8, vec16, vec8, WireError } from './wire';

/** encrypted_client_hello wire version (draft-ietf-tls-esni, "ECHConfig.version"). */
export const ECH_VERSION = 0xfe0d;

export interface HpkeSymmetricCipherSuite {
  kdfId: number;
  aeadId: AeadId;
}

export interface ECHConfig {
  version: number;
  configId: number;
  kemId: number;
  publicKey: Uint8Array;
  cipherSuites: HpkeSymmetricCipherSuite[];
  maximumNameLength: number;
  publicName: string;
  /** Raw extensions block (this lab publishes none). */
  extensions: Uint8Array;
  /** The full serialized ECHConfig — fed verbatim into the HPKE info string. */
  raw: Uint8Array;
}

export interface ECHConfigParams {
  configId: number;
  publicKey: Uint8Array;
  publicName: string;
  maximumNameLength?: number;
  cipherSuites?: HpkeSymmetricCipherSuite[];
}

const DEFAULT_SUITES: HpkeSymmetricCipherSuite[] = [{ kdfId: KDF_ID, aeadId: AEAD_AES_128_GCM }];

function checkPublicName(name: string): Uint8Array {
  const b = utf8(name);
  if (b.length < 1 || b.length > 255) {
    throw new WireError(`public_name must be 1..255 bytes, got ${b.length}`);
  }
  // draft §4: public_name is a DNS name — LDH characters and dots only.
  if (!/^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(name)) {
    throw new WireError(`public_name is not a valid DNS name: ${JSON.stringify(name)}`);
  }
  return b;
}

/** Serialize one ECHConfig (version ‖ length ‖ contents). */
export function makeECHConfig(params: ECHConfigParams): ECHConfig {
  const {
    configId,
    publicKey,
    publicName,
    maximumNameLength = 64,
    cipherSuites = DEFAULT_SUITES,
  } = params;
  if (publicKey.length !== 32) throw new WireError(`X25519 public_key must be 32 bytes, got ${publicKey.length}`);
  if (configId < 0 || configId > 0xff) throw new WireError(`config_id must be a uint8, got ${configId}`);
  if (maximumNameLength < 0 || maximumNameLength > 0xff) {
    throw new WireError(`maximum_name_length must be a uint8, got ${maximumNameLength}`);
  }
  if (cipherSuites.length === 0) throw new WireError('cipher_suites must not be empty');
  const nameBytes = checkPublicName(publicName);

  const suitesBody = concatBytes(...cipherSuites.map((s) => concatBytes(u16(s.kdfId), u16(s.aeadId))));
  const keyConfig = concatBytes(u8(configId), u16(KEM_ID), vec16(publicKey), vec16(suitesBody));
  const contents = concatBytes(keyConfig, u8(maximumNameLength), vec8(nameBytes), vec16(new Uint8Array(0)));
  const raw = concatBytes(u16(ECH_VERSION), vec16(contents));

  return {
    version: ECH_VERSION,
    configId,
    kemId: KEM_ID,
    publicKey,
    cipherSuites,
    maximumNameLength,
    publicName,
    extensions: new Uint8Array(0),
    raw,
  };
}

/** ECHConfigList = length-prefixed sequence of ECHConfigs. */
export function serializeECHConfigList(configs: ECHConfig[]): Uint8Array {
  return vec16(concatBytes(...configs.map((c) => c.raw)));
}

function parseOneConfig(r: ByteReader): ECHConfig {
  const start = r.offset;
  const version = r.u16();
  if (version !== ECH_VERSION) {
    throw new WireError(
      `unsupported ECHConfig version 0x${version.toString(16).padStart(4, '0')} (expected 0xfe0d)`,
    );
  }
  const contents = new ByteReader(r.vec16());
  const configId = contents.u8();
  const kemId = contents.u16();
  if (kemId !== KEM_ID) {
    throw new WireError(`unsupported kem_id 0x${kemId.toString(16).padStart(4, '0')} (this lab: DHKEM(X25519) 0x0020)`);
  }
  const publicKey = contents.vec16();
  if (publicKey.length !== 32) throw new WireError(`X25519 public_key must be 32 bytes, got ${publicKey.length}`);
  const suitesBytes = new ByteReader(contents.vec16());
  const cipherSuites: HpkeSymmetricCipherSuite[] = [];
  while (suitesBytes.remaining() > 0) {
    cipherSuites.push({ kdfId: suitesBytes.u16(), aeadId: suitesBytes.u16() as AeadId });
  }
  if (cipherSuites.length === 0) throw new WireError('cipher_suites must not be empty');
  const maximumNameLength = contents.u8();
  const nameBytes = contents.vec8();
  if (nameBytes.length === 0) throw new WireError('public_name must not be empty');
  const publicName = new TextDecoder().decode(nameBytes);
  const extensions = contents.vec16();
  contents.expectEnd('ECHConfigContents');

  // Re-slice raw from the outer buffer via reserialization equality: rebuild
  // and compare is overkill here; instead capture the exact consumed span.
  void start;
  const raw = concatBytes(
    u16(version),
    vec16(
      concatBytes(
        u8(configId),
        u16(kemId),
        vec16(publicKey),
        vec16(concatBytes(...cipherSuites.map((s) => concatBytes(u16(s.kdfId), u16(s.aeadId))))),
        u8(maximumNameLength),
        vec8(nameBytes),
        vec16(extensions),
      ),
    ),
  );

  return { version, configId, kemId, publicKey, cipherSuites, maximumNameLength, publicName, extensions, raw };
}

/** Strict ECHConfigList parser — fails closed on any malformed byte. */
export function parseECHConfigList(bytes: Uint8Array): ECHConfig[] {
  const outer = new ByteReader(bytes);
  const list = new ByteReader(outer.vec16());
  outer.expectEnd('ECHConfigList');
  const configs: ECHConfig[] = [];
  while (list.remaining() > 0) {
    configs.push(parseOneConfig(list));
  }
  if (configs.length === 0) throw new WireError('ECHConfigList is empty');
  return configs;
}

export function describeConfig(c: ECHConfig): string {
  return `config_id=${c.configId} kem=0x0020 pk=${bytesToHex(c.publicKey).slice(0, 16)}… public_name=${c.publicName}`;
}
