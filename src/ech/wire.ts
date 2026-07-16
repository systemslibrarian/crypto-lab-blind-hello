/**
 * TLS presentation-language byte encoding (RFC 8446 §3) — hand-rolled because
 * the wire layout is exactly what this lab exists to expose: which bytes of a
 * ClientHello an on-path observer can read.
 *
 * The reader is strict and fails closed: any truncation, overrun, or trailing
 * garbage throws WireError rather than yielding a partial parse.
 */
import { concatBytes } from './hub';

export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WireError';
  }
}

export function u8(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new WireError(`u8 out of range: ${n}`);
  return Uint8Array.of(n);
}

export function u16(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new WireError(`u16 out of range: ${n}`);
  return Uint8Array.of(n >> 8, n & 0xff);
}

/** opaque data<0..2^8-1> — one-byte length prefix. */
export function vec8(b: Uint8Array): Uint8Array {
  if (b.length > 0xff) throw new WireError(`vec8 too long: ${b.length}`);
  return concatBytes(u8(b.length), b);
}

/** opaque data<0..2^16-1> — two-byte length prefix. */
export function vec16(b: Uint8Array): Uint8Array {
  if (b.length > 0xffff) throw new WireError(`vec16 too long: ${b.length}`);
  return concatBytes(u16(b.length), b);
}

export class ByteReader {
  private readonly buf: Uint8Array;
  private pos = 0;

  constructor(buf: Uint8Array) {
    this.buf = buf;
  }

  get offset(): number {
    return this.pos;
  }

  remaining(): number {
    return this.buf.length - this.pos;
  }

  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.length) {
      throw new WireError(`truncated: need ${n} bytes at offset ${this.pos}, have ${this.remaining()}`);
    }
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  u8(): number {
    return this.bytes(1)[0];
  }

  u16(): number {
    const b = this.bytes(2);
    return (b[0] << 8) | b[1];
  }

  vec8(): Uint8Array {
    return this.bytes(this.u8());
  }

  vec16(): Uint8Array {
    return this.bytes(this.u16());
  }

  /** Everything left, consumed. */
  rest(): Uint8Array {
    return this.bytes(this.remaining());
  }

  /** Fail closed on trailing bytes — a strict parser accepts exactly one encoding. */
  expectEnd(what: string): void {
    if (this.remaining() !== 0) {
      throw new WireError(`${what}: ${this.remaining()} trailing byte(s) after structure`);
    }
  }
}
