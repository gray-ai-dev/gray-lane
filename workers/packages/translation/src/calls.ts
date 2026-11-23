/**
 * Tool calls as (name, arguments) for comparing the inspected upstream calls with what the client
 * decoder reads from the translated bytes (crates/gray-gateway/src/translation/mod.rs, `CallSet`).
 * Arguments text is compared strictly as JSON when it parses (`parseStrict`: duplicate keys are
 * refused so ambiguous objects never collapse last-wins), and non-JSON raw strings carry a
 * disjoint tag so they never collide with valid JSON string literals; empty arguments equal `{}`.
 */
import { type Json, compareUtf8, parseStrict, toJsonString } from "@gray/json";
import { PROJECTION_NODE_BYTES, rustTrim, stringHeapBytes } from "@gray/protocol";

/**
 * Canonical comparison key for one tool call's arguments:
 * - `null` and blank/whitespace-only strings equal the empty JSON object (`j:{}`);
 * - strings that parse strictly as JSON (duplicate keys refused) use their canonical JSON form (`j:...`);
 * - non-string JSON values use their canonical JSON form (`j:...`);
 * - strings that are not strict JSON (malformed JSON, trailing tokens, or objects with duplicate keys)
 *   keep their raw text under a disjoint prefix (`r:...`), so they neither collapse duplicate keys
 *   nor collide with valid JSON string literals (e.g. `"\"x\""` vs `"x"`).
 */
export function canonicalArguments(args: Json): string {
  if (args === null) return "j:{}";
  if (typeof args === "string") {
    if (rustTrim(args) === "") return "j:{}";
    try {
      return `j:${toJsonString(parseStrict(args))}`;
    } catch {
      return `r:${args}`;
    }
  }
  return `j:${toJsonString(args)}`;
}

export class CallSet {
  private readonly calls: Array<readonly [string, string]> = [];
  private heap = 0;

  /**
   * What the set keeps, in heap bytes: each call's entry (a pair in a list slot, at the costs of
   * @gray/protocol `PROJECTION_NODE_BYTES`) and its arguments written as text (a new string); the
   * name is the decoder's.
   */
  retainedBytes(): number {
    return this.heap;
  }

  push(name: string, args: Json): void {
    const text = canonicalArguments(args);
    this.calls.push([name, text]);
    this.heap += PROJECTION_NODE_BYTES.item + PROJECTION_NODE_BYTES.array + 2 * PROJECTION_NODE_BYTES.item + PROJECTION_NODE_BYTES.string + stringHeapBytes(text);
  }

  /**
   * The same calls, in any order (a client protocol may serialize parallel calls in another order
   * than the upstream interleaved them). Each call counts once: two equal calls match two.
   */
  same(other: CallSet): boolean {
    if (this.calls.length !== other.calls.length) return false;
    const sorted = (calls: ReadonlyArray<readonly [string, string]>) =>
      [...calls].sort((a, b) => compareUtf8(a[0], b[0]) || compareUtf8(a[1], b[1]));
    const a = sorted(this.calls);
    const b = sorted(other.calls);
    return a.every(([name, text], i) => name === (b[i] as readonly [string, string])[0] && text === (b[i] as readonly [string, string])[1]);
  }
}
