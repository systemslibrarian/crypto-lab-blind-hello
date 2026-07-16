/**
 * The passive network observer — works ONLY from the wire bytes of the
 * ClientHello (plus the packet's addressing, which is modeled: no real
 * network exists in this lab and the wire view is labelled as such).
 *
 * This is deliberately a separate module from the client and server: nothing
 * in here touches a key. If the observer can print it, it was readable on
 * the wire.
 */
import { annotateClientHello, EXT_ALPN, EXT_ECH, type Span } from './clienthello';
import { parseEchExtension } from './ech';
import { ByteReader } from './wire';

export type Visibility = 'readable' | 'opaque';

export interface ObservedItem {
  label: string;
  value: string;
  visibility: Visibility;
}

export interface ObserverReport {
  /** The hostname readable in the server_name extension, if any. */
  sniVisible?: string;
  sniValueSpan?: Span;
  echPresent: boolean;
  echOuter?: { configId: number; kdfId: number; aeadId: number; encLen: number; payloadLen: number };
  echPayloadSpan?: Span;
  alpn: string[];
  items: ObservedItem[];
}

export function observeClientHello(wire: Uint8Array, dst: { ip: string; port: number }): ObserverReport {
  const ann = annotateClientHello(wire);

  const alpn: string[] = [];
  const alpnExt = ann.extensions.find((e) => e.type === EXT_ALPN);
  if (alpnExt) {
    const r = new ByteReader(wire.slice(alpnExt.bodySpan.start, alpnExt.bodySpan.end));
    const list = new ByteReader(r.vec16());
    while (list.remaining() > 0) alpn.push(new TextDecoder().decode(list.vec8()));
  }

  let echOuter: ObserverReport['echOuter'];
  let echPayloadSpan: Span | undefined;
  const echExt = ann.extensions.find((e) => e.type === EXT_ECH);
  if (echExt) {
    const body = parseEchExtension(wire.slice(echExt.bodySpan.start, echExt.bodySpan.end));
    if (body.kind === 'outer') {
      echOuter = {
        configId: body.configId,
        kdfId: body.kdfId,
        aeadId: body.aeadId,
        encLen: body.enc.length,
        payloadLen: body.payload.length,
      };
      // payload sits at the end of the extension body
      echPayloadSpan = { start: echExt.bodySpan.end - body.payload.length, end: echExt.bodySpan.end };
    }
  }

  const items: ObservedItem[] = [
    { label: 'Destination address', value: `${dst.ip}:${dst.port}`, visibility: 'readable' },
    {
      label: 'SNI (server_name)',
      value: ann.sniHostname ?? '(absent)',
      visibility: 'readable',
    },
    { label: 'ALPN protocols', value: alpn.join(', ') || '(absent)', visibility: 'readable' },
    { label: 'Cipher suites offered', value: 'TLS 1.3 suites (readable list)', visibility: 'readable' },
  ];
  if (echOuter) {
    items.push(
      {
        label: 'ECH extension',
        value: `present — config_id ${echOuter.configId}, enc ${echOuter.encLen} B, payload ${echOuter.payloadLen} B`,
        visibility: 'readable',
      },
      {
        label: 'ECH payload contents',
        value: `${echOuter.payloadLen} bytes of HPKE ciphertext`,
        visibility: 'opaque',
      },
    );
  } else {
    items.push({ label: 'ECH extension', value: 'absent', visibility: 'readable' });
  }

  return {
    sniVisible: ann.sniHostname,
    sniValueSpan: ann.sniValueSpan,
    echPresent: !!echExt,
    echOuter,
    echPayloadSpan,
    alpn,
    items,
  };
}

/** True iff `needle`'s UTF-8 bytes appear contiguously anywhere in `haystack`. */
export function wireContainsAscii(haystack: Uint8Array, needle: string): boolean {
  const n = new TextEncoder().encode(needle);
  if (n.length === 0) return true;
  outer: for (let i = 0; i + n.length <= haystack.length; i++) {
    for (let j = 0; j < n.length; j++) {
      if (haystack[i + j] !== n[j]) continue outer;
    }
    return true;
  }
  return false;
}
