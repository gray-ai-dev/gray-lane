import { compareUtf8, formatF64 } from "@gray/json";

/**
 * serde_json's writing of a Rust struct: fields in declaration order (objects here keep insertion order),
 * integers as written (a bigint too), f64 in serde_json's float format (`F64`). JSON.stringify writes strings exactly as
 * serde_json does, so only numbers need care.
 */
export class F64 {
  readonly value: number;
  constructor(value: number) {
    this.value = value;
  }
}

/** JSON text written as it is: a subtree another writer already serialised (a request's own values). */
export class RawJson {
  readonly text: string;
  constructor(text: string) {
    this.text = text;
  }
}

/** A `bigint` is a Rust integer past 2^53 (a u64 read whole, @gray/json `parsePlainWide`), written as the integer it is. */
export type StructValue = null | boolean | string | number | bigint | F64 | RawJson | readonly StructValue[] | { readonly [key: string]: StructValue | undefined };

export function structJson(value: StructValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${value} is not an integer this writer can hold exactly; floats are F64`);
    return String(value);
  }
  if (typeof value === "bigint") return value.toString();
  if (value instanceof F64) return formatF64(value.value);
  if (value instanceof RawJson) return value.text;
  if (Array.isArray(value)) return `[${value.map((v) => structJson(v as StructValue)).join(",")}]`;
  const parts: string[] = [];
  for (const [key, v] of Object.entries(value as Record<string, StructValue | undefined>)) {
    if (v === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${structJson(v)}`);
  }
  return `{${parts.join(",")}}`;
}

/**
 * serde_json's writing of a `serde_json::Value` built from a struct (`json!({...})`, `to_value`): the same
 * values, but every object's keys in byte order, as the workspace's serde_json (no `preserve_order`) keeps
 * them. Digests of `json!` values hash this text.
 */
export function valueJson(value: StructValue): string {
  if (value === null || typeof value !== "object" || value instanceof F64 || value instanceof RawJson) return structJson(value);
  if (Array.isArray(value)) return `[${value.map((v) => valueJson(v as StructValue)).join(",")}]`;
  const entries = Object.entries(value as Record<string, StructValue | undefined>).filter(([, v]) => v !== undefined) as [string, StructValue][];
  entries.sort(([a], [b]) => compareUtf8(a, b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${valueJson(v)}`).join(",")}}`;
}
