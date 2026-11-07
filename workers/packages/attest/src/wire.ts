import { parseSerde, type Json } from "@gray/json";

/**
 * Reading a served ACI document — a receipt, a report, a keyset — from the text an HTTP response
 * carried. This is the *only* supported way to read one, and the package's text readers
 * ([`parseReceiptText`](./receipt.ts), [`parseKeysetText`](./identity.ts),
 * [`parseAttestationReportText`](./report.ts)) all go through here.
 *
 * Why it must be `@gray/json`'s serde reader and not `parsePlain`: an ACI document is
 * serde_json-shaped, so an integer is a `bigint` here (Rust u64/i64, `workers/README.md`). The
 * workspace's rule for text from another service is `parsePlain`, which reads every number as a JS
 * `number`; a receipt read that way has `served_at` as a `number`, so every schema in this package
 * refuses it as `invalid_document` — every served receipt would fail to verify — and a value above
 * 2^53 would already be rounded. `parseSerde` is the reader the Rust side uses
 * (`serde_json::from_str::<Value>`): integers arrive as `bigint`, `2.0` stays a float and is refused
 * by the ACI schemas exactly as PAG refuses it.
 *
 * The value is returned as parsed, not just as a typed view: a receipt's signature covers the
 * document that was served (unknown members included), and a report's keyset digest is over the
 * object as parsed (§3.1, §7.2), so the caller needs the whole value.
 */

/** The value a served document's text parsed to, or why it is not JSON. */
export type JsonReadResult =
  | { readonly ok: true; readonly value: Json }
  | { readonly ok: false; readonly message: string };

/** Read a served ACI document's text (`application/json`) with serde_json's reader. */
export function readJsonText(text: string): JsonReadResult {
  if (typeof text !== "string") return { ok: false, message: "not JSON text: the served value is not a string" };
  try {
    return { ok: true, value: parseSerde(text) };
  } catch (error) {
    return { ok: false, message: `not JSON: ${messageOf(error)}` };
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
