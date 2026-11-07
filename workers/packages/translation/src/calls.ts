/**
 * Tool calls as (name, arguments) for comparing the inspected upstream calls with what the client
 * decoder reads from the translated bytes (crates/gray-gateway/src/translation/mod.rs, `CallSet`).
 * Arguments text is compared as JSON when it parses (serde_json's `from_str`: of two equal keys
 * the last wins); empty arguments equal `{}`.
 */
import { type Json, compareUtf8, parseSerde, toJsonString } from "@gray/json";
import { PROJECTION_NODE_BYTES, rustTrim, stringHeapBytes } from "@gray/protocol";

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
    let value: Json;
    if (args === null) {
      value = {};
    } else if (typeof args === "string") {
      if (rustTrim(args) === "") {
        value = {};
      } else {
        try {
          value = parseSerde(args);
        } catch {
          value = args;
        }
      }
    } else {
      value = args;
    }
    const text = toJsonString(value);
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
