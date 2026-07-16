/**
 * DNS HTTPS resource record (RFC 9460) — how the ECHConfig actually reaches
 * a client: the `ech` SvcParam (key 5) carries a serialized ECHConfigList.
 *
 * The RDATA encoding here is the real RFC 9460 wire format (SvcPriority,
 * TargetName, SvcParams). The surrounding DNS *transaction* is modeled — this
 * lab implements no resolver and no DoH/DoT client (a stated non-goal); the
 * plaintext-vs-encrypted lookup views are a labelled model of what each
 * transport exposes.
 */
import { concatBytes, utf8 } from '../ech/hub';
import { ByteReader, u16, vec8, WireError } from '../ech/wire';

export const SVCPARAM_ALPN = 1;
export const SVCPARAM_ECH = 5;

export interface HttpsRecord {
  priority: number;
  /** "." (root) = same owner name, the common ServiceMode form. */
  targetName: string;
  alpn: string[];
  echConfigList: Uint8Array;
}

/** DNS name in wire format: length-prefixed labels, zero-terminated. */
function encodeDnsName(name: string): Uint8Array {
  if (name === '.' || name === '') return Uint8Array.of(0);
  const labels = name.replace(/\.$/, '').split('.');
  const parts: Uint8Array[] = [];
  for (const label of labels) {
    const b = utf8(label);
    if (b.length < 1 || b.length > 63) throw new WireError(`DNS label must be 1..63 bytes: ${label}`);
    parts.push(vec8(b));
  }
  parts.push(Uint8Array.of(0));
  return concatBytes(...parts);
}

function decodeDnsName(r: ByteReader): string {
  const labels: string[] = [];
  for (;;) {
    const len = r.u8();
    if (len === 0) break;
    if (len > 63) throw new WireError('DNS label longer than 63 bytes (compression not supported here)');
    labels.push(new TextDecoder().decode(r.bytes(len)));
  }
  return labels.length === 0 ? '.' : labels.join('.');
}

export function encodeHttpsRdata(rec: HttpsRecord): Uint8Array {
  const params: Uint8Array[] = [];
  if (rec.alpn.length > 0) {
    const body = concatBytes(...rec.alpn.map((p) => vec8(utf8(p))));
    params.push(concatBytes(u16(SVCPARAM_ALPN), u16(body.length), body));
  }
  if (rec.echConfigList.length > 0) {
    params.push(concatBytes(u16(SVCPARAM_ECH), u16(rec.echConfigList.length), rec.echConfigList));
  }
  return concatBytes(u16(rec.priority), encodeDnsName(rec.targetName), ...params);
}

export function decodeHttpsRdata(bytes: Uint8Array): HttpsRecord {
  const r = new ByteReader(bytes);
  const priority = r.u16();
  const targetName = decodeDnsName(r);
  const alpn: string[] = [];
  let echConfigList: Uint8Array = new Uint8Array(0);
  let lastKey = -1;
  while (r.remaining() > 0) {
    const key = r.u16();
    if (key <= lastKey) throw new WireError('SvcParams must be in strictly increasing key order');
    lastKey = key;
    const value = r.bytes(r.u16());
    if (key === SVCPARAM_ALPN) {
      const list = new ByteReader(value);
      while (list.remaining() > 0) alpn.push(new TextDecoder().decode(list.vec8()));
    } else if (key === SVCPARAM_ECH) {
      echConfigList = value;
    }
  }
  r.expectEnd('HTTPS RDATA');
  return { priority, targetName, alpn, echConfigList };
}

/* ---------- the modeled lookup, as an observer sees it ---------- */

export type DnsTransport = 'plaintext' | 'doh';

export interface DnsObservation {
  transport: DnsTransport;
  /** What the on-path observer reads from the lookup itself. */
  items: { label: string; value: string; visibility: 'readable' | 'opaque' }[];
  /** The query name, iff the observer could read it. */
  qnameVisible?: string;
}

export function observeDnsLookup(qname: string, transport: DnsTransport, resolverIp: string): DnsObservation {
  if (transport === 'plaintext') {
    return {
      transport,
      qnameVisible: qname,
      items: [
        { label: 'Resolver address', value: `${resolverIp}:53 (UDP)`, visibility: 'readable' },
        { label: 'Query', value: `HTTPS? ${qname}`, visibility: 'readable' },
        { label: 'Answer', value: `HTTPS record incl. ech=… ECHConfigList`, visibility: 'readable' },
      ],
    };
  }
  return {
    transport,
    items: [
      { label: 'Resolver address', value: `${resolverIp}:443 (TLS)`, visibility: 'readable' },
      { label: 'Query', value: 'inside TLS to the resolver', visibility: 'opaque' },
      { label: 'Answer', value: 'inside TLS to the resolver', visibility: 'opaque' },
    ],
  };
}
