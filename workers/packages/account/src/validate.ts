/**
 * Field checks for the account RPCs. Inputs arrive over Durable Object RPC (structured clone), so
 * money is a JavaScript number here, not the decimal string of credit's HTTP API; every boundary
 * still refuses anything that is not a safe integer (docs/cloudflare-native.md section 6.2: above
 * 2^53 micro-USD is invalid data, never truncated).
 */

/** Identifiers chosen by the gateway: workspace, request key, key id, provider, accrual id (workers/credit/src/lib/validate.ts ID_RE). */
export const ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

/** `reason` of a release: 1 to 512 characters, as credit's `reason` fields (workers/credit/src/lib/validate.ts REASON_MAX_CHARS). */
export const REASON_MAX_CHARS = 512;

/** An input that cannot be served as given: the caller gets `bad_request` naming the field. */
export class InvalidInput extends Error {
  readonly field: string;
  constructor(field: string, why: string) {
    super(`${field}: ${why}`);
    this.name = "InvalidInput";
    this.field = field;
  }
}

export function isId(v: unknown): v is string {
  return typeof v === "string" && ID_PATTERN.test(v);
}

export function id(v: unknown, field: string): string {
  if (!isId(v)) throw new InvalidInput(field, "must be 1-128 characters of [A-Za-z0-9_.:-]");
  return v;
}

export function optionalId(v: unknown, field: string): string | null {
  return v === null || v === undefined ? null : id(v, field);
}

export function isAmount(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

/** Integer micro-USD, at least `min`. */
export function amount(v: unknown, field: string, min = 0): number {
  if (!isAmount(v)) throw new InvalidInput(field, "must be a safe non-negative integer of micro-USD");
  if (v < min) throw new InvalidInput(field, `must be at least ${min}`);
  return v;
}

export function optionalAmount(v: unknown, field: string): number | null {
  return v === null || v === undefined ? null : amount(v, field);
}

export function uint(v: unknown, field: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || v > max) throw new InvalidInput(field, `must be an integer between 0 and ${max}`);
  return v;
}

export function text(v: unknown, field: string, max: number): string {
  if (typeof v !== "string" || v.length === 0 || v.length > max) throw new InvalidInput(field, `must be a string of 1-${max} characters`);
  return v;
}

export function object(v: unknown, field: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new InvalidInput(field, "must be an object");
  return v as Record<string, unknown>;
}

/** Sum of safe integers that must stay safe; an overflow is a bug or invalid data, never wrapped. */
export function add(a: number, b: number, what: string): number {
  const s = a + b;
  if (!Number.isSafeInteger(s)) throw new RangeError(`${what} left the safe integer range`);
  return s;
}

export type Scalar = string | number | boolean | null;
export type ScalarRecord = Readonly<Record<string, Scalar>>;

/**
 * A flat record of scalars (usage counts, projection metadata), stored with the item it belongs
 * to. Numbers must be finite; keys follow ID_PATTERN so the stored JSON needs no escaping beyond
 * the values'.
 */
export function scalarRecord(v: unknown, field: string, maxKeys: number): ScalarRecord | null {
  if (v === null || v === undefined) return null;
  const o = object(v, field);
  const keys = Object.keys(o);
  if (keys.length > maxKeys) throw new InvalidInput(field, `has more than ${maxKeys} fields`);
  const out: Record<string, Scalar> = {};
  for (const k of keys) {
    if (!ID_PATTERN.test(k)) throw new InvalidInput(`${field}.${k}`, "field names must match [A-Za-z0-9_.:-]{1,128}");
    const value = o[k];
    if (value === null || typeof value === "string" || typeof value === "boolean") out[k] = value;
    else if (typeof value === "number" && Number.isFinite(value)) out[k] = value;
    else throw new InvalidInput(`${field}.${k}`, "must be a string, finite number, boolean or null");
  }
  return out;
}

const ENCODER = new TextEncoder();

/** UTF-8 length of a string: limits count bytes, not UTF-16 code units (docs/cloudflare-native.md section 6.5). */
export function utf8Length(s: string): number {
  return ENCODER.encode(s).byteLength;
}
