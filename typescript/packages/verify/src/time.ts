/**
 * Timestamps with microsecond precision. The grammar is strict RFC 3339 (see `parseTime`).
 * Times are kept as bigint microseconds since the Unix epoch, in UTC.
 */

import { PyError, pyRepr } from "./py.js";

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

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/;

/**
 * Microseconds since the Unix epoch (UTC) for a strict RFC 3339 timestamp:
 * `YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+HH:MM|-HH:MM)`. Same grammar and errors as the Python
 * reference's `parse_time`, so validity never depends on the implementation.
 */
export function parseTime(text: unknown): Micros {
  if (typeof text !== "string") throw new PyError("ValueError", "timestamp must be a string");
  const m = RFC3339.exec(text);
  if (m === null) throw new PyError("ValueError", `Invalid RFC 3339 timestamp: ${pyRepr(text)}`);
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map((x) => Number(x)) as [
    number, number, number, number, number, number,
  ];
  const micro = Number((m[7] ?? "").padEnd(6, "0") || "0");
  const tz = m[8]!;
  let off = 0n;
  if (tz !== "Z") {
    const sign = tz[0] === "-" ? -1n : 1n;
    off = sign * (BigInt(Number(tz.slice(1, 3))) * 3600n + BigInt(Number(tz.slice(4, 6))) * 60n) * US;
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
  const local =
    daysFromCivil(year, month, day) * DAY_US +
    (BigInt(hour) * 3600n + BigInt(minute) * 60n + BigInt(second)) * US +
    BigInt(micro);
  const utc = local - off;
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
