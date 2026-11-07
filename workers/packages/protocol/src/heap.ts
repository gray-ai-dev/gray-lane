/**
 * What values a stream's decoder, tool gate and translator keep cost in V8's heap (the owner's first
 * hard limit: a Worker isolate has 128 MB, shared by every request it serves, so what a stream keeps
 * while it runs is weighed against ANSWER_HELD_MAX_BYTES with the frames it holds; the gateway's
 * relay.ts). The costs are the ones the gateway's non-streaming answers are weighed with
 * (`PROJECTION_NODE_BYTES`, measured in Node without pointer compression, an upper bound of workerd's
 * V8), re-measured on parsed tool calls in workerd itself (gateway/measure/answer-heap.ts, 2026-10-19;
 * docs/cloudflare-native/gateway.md section 9).
 */
import type { Json } from "@gray/json";
import { PROJECTION_NODE_BYTES } from "./answer-projection.ts";

/**
 * The bytes V8 stores a string's characters in: one a character when every one is in Latin-1, else
 * two (a "two-byte" string, however few of its characters need it). Its header is not counted
 * (`PROJECTION_NODE_BYTES.string` where a value is weighed). A loop, not a regular expression: a
 * successful match keeps its subject alive in the isolate's last-match state until the next match
 * (measured: a weighed 1 MB string stayed in the heap after it was let go).
 */
export function stringHeapBytes(text: string): number {
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) > 0xff) return 2 * text.length;
  return text.length;
}

/**
 * What a parsed JSON value holds in the heap: each node at `PROJECTION_NODE_BYTES` (an array's slots,
 * an object, each member, a string's header, a number) and the characters of its strings and keys at
 * `stringHeapBytes`. `true`, `false` and `null` are shared. Walks the value once, without recursion.
 */
export function jsonHeapBytes(value: Json): number {
  let bytes = 0;
  const pending: Json[] = [value];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    const v = next;
    if (typeof v === "string") bytes += PROJECTION_NODE_BYTES.string + stringHeapBytes(v);
    else if (typeof v === "number") bytes += PROJECTION_NODE_BYTES.number;
    // A BigInt's header and its 64-bit digits.
    else if (typeof v === "bigint") bytes += PROJECTION_NODE_BYTES.number + 8 * Math.ceil(v.toString(16).length / 16);
    else if (Array.isArray(v)) {
      bytes += PROJECTION_NODE_BYTES.array + v.length * PROJECTION_NODE_BYTES.item;
      for (const item of v) pending.push(item);
    } else if (v !== null && typeof v === "object") {
      bytes += PROJECTION_NODE_BYTES.object;
      for (const key of Object.keys(v)) {
        bytes += PROJECTION_NODE_BYTES.member + stringHeapBytes(key);
        pending.push(v[key] as Json);
      }
    }
  }
  return bytes;
}
