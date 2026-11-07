/**
 * Whether a request's JSON text can hold a handle at all (crates/gray-gateway/src/tool_call_ids.rs
 * `may_hold_handles`): a request whose bytes cannot spell one is not walked, so a request without
 * handles costs one search of its bytes and nothing more (no lookup, no round trip).
 *
 * A handle is `gtc1_`, a region character and 27 base62 characters: every character of it is one of
 * `[0-9A-Za-z_]`. JSON spells such a character as itself or as `\u00XX` with XX from 30 to 7A (hex
 * digits of either case). So a text that can hold a handle holds `gtc1_` as written, or an escape
 * `\u003`..`\u007`. The server looks for any `\u` escape; this looks only for the escapes a handle's
 * characters can take, so a body whose non-ASCII text is escaped (`é`, `中`, as some
 * clients write every non-ASCII character) is not walked for nothing. It never misses a handle,
 * however its JSON spells it.
 */

const PREFIX = [0x67, 0x74, 0x63, 0x31, 0x5f]; // "gtc1_"
const BACKSLASH = 0x5c;
const U = 0x75;
const ZERO = 0x30;

/** Whether `bytes[at..]` starts an escape a handle's character can take: `\u003`..`\u007`. */
function handleEscape(bytes: Uint8Array, at: number): boolean {
  return bytes[at] === BACKSLASH && bytes[at + 1] === U && bytes[at + 2] === ZERO && bytes[at + 3] === ZERO && bytes[at + 4]! >= 0x33 && bytes[at + 4]! <= 0x37;
}

function prefixAt(bytes: Uint8Array, at: number): boolean {
  for (let i = 0; i < PREFIX.length; i++) if (bytes[at + i] !== PREFIX[i]) return false;
  return true;
}

/** Whether the JSON text `bytes` can hold a handle in any of its strings (`may_hold_handles`). */
export function mayHoldHandles(bytes: Uint8Array): boolean {
  for (let at = bytes.indexOf(PREFIX[0]!); at >= 0; at = bytes.indexOf(PREFIX[0]!, at + 1)) if (prefixAt(bytes, at)) return true;
  for (let at = bytes.indexOf(BACKSLASH); at >= 0; at = bytes.indexOf(BACKSLASH, at + 1)) if (handleEscape(bytes, at)) return true;
  return false;
}

/** The longest pattern looked for, less one: what a chunk keeps of the one before it. */
const CARRY = 4;

/** `mayHoldHandles` over a text read in chunks (a tier C body as it is received): `push` each chunk, then read `found`. */
export class HandleWatch {
  found = false;
  private tail = new Uint8Array(0);

  push(chunk: Uint8Array): void {
    if (this.found || chunk.length === 0) return;
    const joined = new Uint8Array(this.tail.length + Math.min(chunk.length, CARRY));
    joined.set(this.tail);
    joined.set(chunk.subarray(0, Math.min(chunk.length, CARRY)), this.tail.length);
    // A pattern across the boundary, then within the chunk.
    if (mayHoldHandles(joined) || mayHoldHandles(chunk)) {
      this.found = true;
      return;
    }
    const keep = Math.min(CARRY, this.tail.length + chunk.length);
    const next = new Uint8Array(keep);
    const fromChunk = Math.min(keep, chunk.length);
    next.set(this.tail.subarray(this.tail.length - (keep - fromChunk)), 0);
    next.set(chunk.subarray(chunk.length - fromChunk), keep - fromChunk);
    this.tail = next;
  }
}
