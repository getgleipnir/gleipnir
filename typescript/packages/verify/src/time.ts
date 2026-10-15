/**
 * Timestamps with microsecond precision, parsed like the reference verifier's `parse_time`
 * (a trailing `Z` becomes `+00:00`, then Python's `datetime.fromisoformat`, timezone required).
 *
 * The accepted grammar is that of CPython 3.10's `fromisoformat`, the strictest of the Python
 * versions the reference supports:
 *   YYYY-MM-DD <any one character> HH[:MM[:SS[.fff|.ffffff]]] (+|-)HH:MM[:SS[.ffffff]]
 * Times are kept as bigint microseconds since the Unix epoch, in UTC.
 */

import { PyError, isWellFormed, pyRepr, pyTypeName } from "./py.js";

export type Micros = bigint;

const US = 1_000_000n;
const DAY_US = 86_400n * US;
const MIN_US = daysFromCivil(1, 1, 1) * DAY_US;
const MAX_US = (daysFromCivil(9999, 12, 31) + 1n) * DAY_US - 1n;

function daysFromCivil(y: number, m: number, d: number): bigint {
  // Howard Hinnant's algorithm, proleptic Gregorian.
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return BigInt(era * 146097 + doe - 719468);
}

function civilFromDays(z0: bigint): [number, number, number] {
  const z = Number(z0) + 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp + (mp < 10 ? 3 : -9);
  return [m <= 2 ? y + 1 : y, m, d];
}

function daysInMonth(y: number, m: number): number {
  if (m === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(m) ? 30 : 31;
}

function invalid(text: string): PyError {
  return new PyError("ValueError", `Invalid isoformat string: ${pyRepr(text)}`);
}

/*
 * A literal port of CPython 3.10's C `datetime.fromisoformat` (Modules/_datetimemodule.c:
 * parse_isoformat_date, parse_hh_mm_ss_ff, parse_isoformat_time), over the UTF-8 bytes of the
 * string followed by a NUL, including its quirks, so both verifiers accept the same timestamps.
 */
const NUL = 0;

function parseDigits(b: Uint8Array, p: number, n: number): [number, number] | null {
  let v = 0;
  for (let i = 0; i < n; i++) {
    const c = b[p + i] ?? NUL;
    if (c < 0x30 || c > 0x39) return null;
    v = v * 10 + (c - 0x30);
  }
  return [p + n, v];
}

/** Returns [rv, h, m, s, us]; rv < 0 is an error, rv 1 means "not the end of the string". */
function parseHhMmSsFf(b: Uint8Array, start: number, end: number): [number, number[], number] {
  const vals = [0, 0, 0];
  let p = start;
  let us = 0;
  let broke = false;
  for (let i = 0; i < 3; i++) {
    const r = parseDigits(b, p, 2);
    if (r === null) return [-3, vals, us];
    p = r[0];
    vals[i] = r[1];
    const c = b[p] ?? NUL;
    p += 1;
    if (p >= end) return [c !== NUL ? 1 : 0, vals, us];
    if (c === 0x3a) continue;
    if (c === 0x2e) {
      broke = true;
      break;
    }
    return [-4, vals, us];
  }
  void broke;
  const remains = end - p;
  if (!(remains === 6 || remains === 3)) return [-3, vals, us];
  const r = parseDigits(b, p, remains);
  if (r === null) return [-3, vals, us];
  p = r[0];
  us = remains === 3 ? r[1] * 1000 : r[1];
  return [(b[p] ?? NUL) !== NUL ? 1 : 0, vals, us];
}

/** Microseconds since the Unix epoch (UTC) for an ISO 8601 string with a timezone. */
export function parseTime(text: unknown): Micros {
  if (typeof text !== "string") {
    throw new PyError("AttributeError", `'${pyTypeName(text)}' object has no attribute 'endswith'`);
  }
  let s = text;
  if (s.endsWith("Z")) s = s.slice(0, -1) + "+00:00";
  const reported = s;
  // _sanitize_isoformat_str: a surrogate is tolerated only as the separator (code point 10).
  const cps = Array.from(s);
  if (cps.length > 10 && /^[\ud800-\udfff]$/u.test(cps[10]!)) {
    cps[10] = "T";
    s = cps.join("");
  }
  if (!isWellFormed(s)) throw invalid(reported);
  const enc = new TextEncoder().encode(s);
  const b = new Uint8Array(enc.length + 1);
  b.set(enc);
  const len = enc.length;

  // parse_isoformat_date
  let rv = 0;
  let year = 0;
  let month = 0;
  let day = 0;
  let p = 0;
  const y = parseDigits(b, p, 4);
  if (y === null) rv = -1;
  else {
    [p, year] = y;
    if (b[p++] !== 0x2d) rv = -2;
    else {
      const m = parseDigits(b, p, 2);
      if (m === null) rv = -1;
      else {
        [p, month] = m;
        if (b[p++] !== 0x2d) rv = -2;
        else {
          const d = parseDigits(b, p, 2);
          if (d === null) rv = -1;
          else day = d[1];
        }
      }
    }
  }

  let hour = 0;
  let minute = 0;
  let second = 0;
  let micro = 0;
  let tzoffset = 0;
  let tzusec = 0;
  if (rv === 0 && len > 10) {
    const sep = b[10]!;
    let t = (sep & 0x80) === 0 ? 11 : (sep & 0xf0) === 0xe0 ? 13 : (sep & 0xf0) === 0xf0 ? 14 : 12;
    const end = len;
    // parse_isoformat_time(b[t..end])
    let tzPos = t;
    do {
      const c = b[tzPos] ?? NUL;
      if (c === 0x2b || c === 0x2d) break;
    } while (++tzPos < end);
    const [r1, v1, us1] = parseHhMmSsFf(b, t, tzPos);
    [hour, minute, second] = v1 as [number, number, number];
    micro = us1;
    if (r1 < 0) rv = r1;
    else if (tzPos === end) rv = r1 === 1 ? -5 : 0;
    else {
      const tzlen = end - tzPos;
      if (!(tzlen === 6 || tzlen === 9 || tzlen === 16)) rv = -5;
      else {
        const sign = b[tzPos] === 0x2d ? -1 : 1;
        t = tzPos + 1;
        const [r2, v2, us2] = parseHhMmSsFf(b, t, end);
        tzoffset = sign * (v2[0]! * 3600 + v2[1]! * 60 + v2[2]!);
        tzusec = us2 * sign;
        rv = r2 !== 0 ? -5 : 1;
      }
    }
  }
  if (rv < 0) throw invalid(reported);

  // tzinfo_from_isoformat_results, then the datetime constructor's range checks
  if (rv === 1) {
    const off = BigInt(tzoffset) * US + BigInt(tzusec);
    if (off <= -DAY_US || off >= DAY_US) {
      throw new PyError(
        "ValueError",
        `offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not ${pyTimedeltaRepr(off)}.`,
      );
    }
  }
  if (year < 1 || year > 9999) throw new PyError("ValueError", `year ${year} is out of range`);
  if (month < 1 || month > 12) throw new PyError("ValueError", "month must be in 1..12");
  if (day < 1 || day > daysInMonth(year, month)) throw new PyError("ValueError", "day is out of range for month");
  if (hour > 23) throw new PyError("ValueError", "hour must be in 0..23");
  if (minute > 59) throw new PyError("ValueError", "minute must be in 0..59");
  if (second > 59) throw new PyError("ValueError", "second must be in 0..59");
  if (rv !== 1) throw new PyError("ValueError", "timestamp without timezone");
  const local =
    daysFromCivil(year, month, day) * DAY_US +
    (BigInt(hour) * 3600n + BigInt(minute) * 60n + BigInt(second)) * US +
    BigInt(micro);
  const utc = local - (BigInt(tzoffset) * US + BigInt(tzusec));
  if (utc < MIN_US || utc > MAX_US) throw new PyError("OverflowError", "date value out of range");
  return utc;
}

/** Python `repr(timedelta)` (3.7+ keyword form). */
function pyTimedeltaRepr(us: bigint): string {
  let days = us / DAY_US;
  let rem = us % DAY_US;
  if (rem < 0n) {
    rem += DAY_US;
    days -= 1n;
  }
  const secs = rem / US;
  const micro = rem % US;
  const parts: string[] = [];
  if (days) parts.push(`days=${days}`);
  if (secs) parts.push(`seconds=${secs}`);
  if (micro) parts.push(`microseconds=${micro}`);
  return `datetime.timedelta(${parts.join(", ") || "0"})`;
}

function pad(n: number | bigint, w = 2): string {
  return String(n).padStart(w, "0");
}

function split(t: Micros): { y: number; mo: number; d: number; h: number; mi: number; s: number; us: number } {
  let days = t / DAY_US;
  let rem = t % DAY_US;
  if (rem < 0n) {
    rem += DAY_US;
    days -= 1n;
  }
  const [y, mo, d] = civilFromDays(days);
  const secs = Number(rem / US);
  return { y, mo, d, h: Math.floor(secs / 3600), mi: Math.floor((secs % 3600) / 60), s: secs % 60, us: Number(rem % US) };
}

/** RFC 3339 UTC with millisecond precision and a Z suffix (truncated, like the SDK's `iso`). */
export function isoMillis(t: Micros): string {
  const p = split(t);
  return `${pad(p.y, 4)}-${pad(p.mo)}-${pad(p.d)}T${pad(p.h)}:${pad(p.mi)}:${pad(p.s)}.${pad(Math.floor(p.us / 1000), 3)}Z`;
}

/** Python `datetime.isoformat()` of a UTC datetime. */
export function pyIsoformat(t: Micros): string {
  const p = split(t);
  const frac = p.us ? "." + pad(p.us, 6) : "";
  return `${pad(p.y, 4)}-${pad(p.mo)}-${pad(p.d)}T${pad(p.h)}:${pad(p.mi)}:${pad(p.s)}${frac}+00:00`;
}

/** Python `str(timedelta)`. */
export function pyTimedelta(us: bigint): string {
  let days = us / DAY_US;
  let rem = us % DAY_US;
  if (rem < 0n) {
    rem += DAY_US;
    days -= 1n;
  }
  const secs = Number(rem / US);
  const micro = Number(rem % US);
  let out = `${Math.floor(secs / 3600)}:${pad(Math.floor((secs % 3600) / 60))}:${pad(secs % 60)}`;
  if (micro) out += "." + pad(micro, 6);
  if (days !== 0n) out = `${days} day${days === 1n || days === -1n ? "" : "s"}, ${out}`;
  return out;
}

export function microsFromDate(d: Date): Micros {
  return BigInt(d.getTime()) * 1000n;
}

export function microsToDate(t: Micros): Date {
  return new Date(Number(t / 1000n));
}

export const MICROS_PER_SECOND = US;
