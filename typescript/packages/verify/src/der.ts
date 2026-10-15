/** A small, strict DER reader (definite lengths, minimal encodings), enough for X.509, CMS and RFC 3161. */

import { bytesToHex } from "./bytes.js";

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

export interface Tlv {
  /** Full identifier octet (class | constructed | tag number); only low tag numbers (< 31) are supported. */
  tag: number;
  /** The complete encoding (identifier, length and contents). */
  raw: Uint8Array;
  /** The contents octets. */
  value: Uint8Array;
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

export const ctx = (n: number, constructed: boolean): number => 0x80 | (constructed ? 0x20 : 0) | n;

/** Read one TLV at `pos`; returns it and the position after it. */
export function readTlv(buf: Uint8Array, pos: number): [Tlv, number] {
  const start = pos;
  if (pos >= buf.length) throw new DerError("unexpected end of data");
  const tag = buf[pos++]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("high tag numbers are not supported");
  if (pos >= buf.length) throw new DerError("unexpected end of data");
  let len = buf[pos++]!;
  if (len === 0x80) throw new DerError("indefinite length is not DER");
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new DerError("length too long");
    if (pos + n > buf.length) throw new DerError("unexpected end of data");
    if (buf[pos] === 0) throw new DerError("non-minimal length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos++]!;
    if (len < 0x80) throw new DerError("non-minimal length");
  }
  if (pos + len > buf.length) throw new DerError("length exceeds data");
  const value = buf.subarray(pos, pos + len);
  pos += len;
  return [{ tag, raw: buf.subarray(start, pos), value }, pos];
}

/** Parse exactly one TLV filling `buf`. */
export function parseOne(buf: Uint8Array, expectTag?: number): Tlv {
  const [t, end] = readTlv(buf, 0);
  if (end !== buf.length) throw new DerError("trailing data");
  if (expectTag !== undefined && t.tag !== expectTag) throw new DerError(`expected tag 0x${expectTag.toString(16)}`);
  return t;
}

/** The children of a constructed TLV. */
export function children(t: Tlv): Tlv[] {
  if ((t.tag & 0x20) === 0) throw new DerError("not a constructed value");
  const out: Tlv[] = [];
  let pos = 0;
  while (pos < t.value.length) {
    const [c, next] = readTlv(t.value, pos);
    out.push(c);
    pos = next;
  }
  return out;
}

/** Sequential reader over the children of a constructed value. */
export class Reader {
  private readonly items: Tlv[];
  private i = 0;
  constructor(t: Tlv, expectTag?: number) {
    if (expectTag !== undefined && t.tag !== expectTag) {
      throw new DerError(`expected tag 0x${expectTag.toString(16)}, got 0x${t.tag.toString(16)}`);
    }
    this.items = children(t);
  }
  peekTag(): number | undefined {
    return this.items[this.i]?.tag;
  }
  next(expectTag?: number): Tlv {
    const t = this.items[this.i];
    if (!t) throw new DerError("missing element");
    if (expectTag !== undefined && t.tag !== expectTag) {
      throw new DerError(`expected tag 0x${expectTag.toString(16)}, got 0x${t.tag.toString(16)}`);
    }
    this.i++;
    return t;
  }
  optional(tag: number): Tlv | undefined {
    return this.peekTag() === tag ? this.next() : undefined;
  }
  done(): boolean {
    return this.i >= this.items.length;
  }
  end(): void {
    if (!this.done()) throw new DerError("unexpected extra element");
  }
}

export function readInteger(t: Tlv): bigint {
  if (t.tag !== TAG.INTEGER) throw new DerError("expected INTEGER");
  const v = t.value;
  if (v.length === 0) throw new DerError("empty INTEGER");
  if (v.length > 1 && ((v[0] === 0 && (v[1]! & 0x80) === 0) || (v[0] === 0xff && (v[1]! & 0x80) !== 0))) {
    throw new DerError("non-minimal INTEGER");
  }
  let n = 0n;
  for (const b of v) n = (n << 8n) | BigInt(b);
  if (v[0]! & 0x80) n -= 1n << BigInt(8 * v.length);
  return n;
}

export function readOid(t: Tlv): string {
  if (t.tag !== TAG.OID) throw new DerError("expected OBJECT IDENTIFIER");
  const v = t.value;
  if (v.length === 0) throw new DerError("empty OID");
  const arcs: bigint[] = [];
  let cur = 0n;
  let started = false;
  for (let i = 0; i < v.length; i++) {
    const b = v[i]!;
    if (!started && b === 0x80) throw new DerError("non-minimal OID arc");
    started = true;
    cur = (cur << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(cur);
      cur = 0n;
      started = false;
    } else if (i === v.length - 1) throw new DerError("truncated OID");
  }
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].join(".");
}

export function readBoolean(t: Tlv): boolean {
  if (t.tag !== TAG.BOOLEAN || t.value.length !== 1) throw new DerError("expected BOOLEAN");
  if (t.value[0] === 0xff) return true;
  if (t.value[0] === 0) return false;
  throw new DerError("non-DER BOOLEAN");
}

/** BIT STRING contents with no unused bits (keys and signatures). */
export function readBitStringBytes(t: Tlv): Uint8Array {
  if (t.tag !== TAG.BIT_STRING || t.value.length < 1) throw new DerError("expected BIT STRING");
  if (t.value[0] !== 0) throw new DerError("BIT STRING with unused bits");
  return t.value.subarray(1);
}

/** BIT STRING as a list of set bit indexes (for KeyUsage). */
export function readBitFlags(t: Tlv): Set<number> {
  if (t.tag !== TAG.BIT_STRING || t.value.length < 1) throw new DerError("expected BIT STRING");
  const unused = t.value[0]!;
  if (unused > 7) throw new DerError("bad BIT STRING");
  const bits = new Set<number>();
  const data = t.value.subarray(1);
  for (let i = 0; i < data.length * 8 - unused; i++) {
    if (data[i >> 3]! & (0x80 >> (i & 7))) bits.add(i);
  }
  return bits;
}

function digits(s: string, from: number, n: number): number {
  const part = s.slice(from, from + n);
  if (!/^[0-9]+$/.test(part) || part.length !== n) throw new DerError("bad time");
  return Number(part);
}

/** UTCTime or GeneralizedTime (UTC, `Z`), as microseconds since the Unix epoch. */
export function readTime(t: Tlv): bigint {
  const s = new TextDecoder().decode(t.value);
  let y: number;
  let rest: string;
  if (t.tag === TAG.UTC_TIME) {
    if (!/^[0-9]{12}Z$/.test(s)) throw new DerError("bad UTCTime");
    const yy = digits(s, 0, 2);
    y = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = s.slice(2);
  } else if (t.tag === TAG.GENERALIZED_TIME) {
    if (!/^[0-9]{14}(\.[0-9]*[1-9])?Z$/.test(s)) throw new DerError("bad GeneralizedTime");
    y = digits(s, 0, 4);
    rest = s.slice(4);
  } else throw new DerError("expected a time");
  const mo = digits(rest, 0, 2);
  const d = digits(rest, 2, 2);
  const h = digits(rest, 4, 2);
  const mi = digits(rest, 6, 2);
  const sec = digits(rest, 8, 2);
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 59) throw new DerError("bad time");
  const frac = rest.slice(10, -1);
  const us = frac ? Number((frac.slice(1) + "000000").slice(0, 6)) : 0;
  const ms = Date.UTC(y, mo - 1, d, h, mi, sec);
  const check = new Date(ms);
  if (check.getUTCDate() !== d) throw new DerError("bad date");
  return BigInt(ms) * 1000n + BigInt(us);
}

export function hex(b: Uint8Array): string {
  return bytesToHex(b);
}

export const OID = {
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  ecPublicKey: "1.2.840.10045.2.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  ed25519: "1.3.101.112",
  ed448: "1.3.101.113",
  x25519: "1.3.101.110",
  x448: "1.3.101.111",
  rsaEncryption: "1.2.840.113549.1.1.1",
  rsaPss: "1.2.840.113549.1.1.10",
  dsa: "1.2.840.10040.4.1",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  sha256Rsa: "1.2.840.113549.1.1.11",
  sha384Rsa: "1.2.840.113549.1.1.12",
  sha512Rsa: "1.2.840.113549.1.1.13",
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  extKeyUsage: "2.5.29.37",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  kpTimeStamping: "1.3.6.1.5.5.7.3.8",
} as const;
