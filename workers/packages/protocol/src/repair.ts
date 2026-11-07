/**
 * The repair of a forwarded Responses stream's argument text (crates/gray-gateway/src/inference.rs
 * `RepairSites`, `ArgumentSite`, `ToolGate::repair_fragments`; bf29a2c1, c41621be). A relay may send
 * a call's argument deltas short of its done item: yylx's gpt-6.1-sol sent only the end of each
 * call's arguments as deltas on 10 of 18 streams (2026-10-17). Clients that run the call read the
 * done item (Codex, the AI SDK); clients that build it from the deltas would build no call at all.
 * The gate inspects the complete call; a stream held to its end (enforce mode, a declared tool) then
 * gets the done item's own text in place of the deltas, so every client reads the call the gate
 * passed. What is replaced is held frames by their place among the held frames; every other frame
 * goes out as the very bytes held.
 */
import { type Json, get, isObject, parseStrict } from "@gray/json";
import { editJson, type JsonPath, rewriteSseFrame, sseData } from "./sse-edit.ts";
import { responsesArgumentSite, responsesCompleteCall } from "./stream.ts";
import type { CanonicalEvent } from "./types.ts";

const fatal = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * A held frame of a forwarded Responses stream that carries text of a call's arguments
 * (`responsesArgumentSite`): the call's index, which held frame it is, and the path to that text.
 */
interface ArgumentSite {
  readonly call: bigint;
  readonly frame: number;
  readonly path: JsonPath;
}

/**
 * What `RepairSites` keeps for each argument frame (its site: an object with the call's index, a list
 * slot; the path is one of two shared values) and for each call's complete statement (a map entry).
 * Measured in workerd (gateway/measure/answer-heap.ts, 2026-10-19, 16 Responses streams of 128 calls,
 * the sites kept with the decoder against the decoder alone): 100.8 bytes a call of one argument
 * frame, 235.8 a call of four: 45.0 a site and 55.8 a complete statement.
 */
export const REPAIR_SITE_BYTES = 48;
export const REPAIR_COMPLETE_BYTES = 56;

/**
 * `RepairSites`: the held frames of a forwarded Responses stream that a repair of a call's argument
 * text reads and rewrites (`ToolGate::repair_fragments`), by their place in the held frames.
 */
export class RepairSites {
  /** Each frame that carries text of a call's arguments, in order. */
  private arguments: ArgumentSite[] = [];
  /** Each call's frame that states its complete arguments, and whether it is the call's done item: one is kept once it is. */
  private readonly complete = new Map<bigint, { readonly frame: number; readonly doneItem: boolean }>();

  /** What the sites keep, in heap bytes (`REPAIR_SITE_BYTES`, `REPAIR_COMPLETE_BYTES`): the gateway weighs it with the frames held. */
  retainedBytes(): number {
    return this.arguments.length * REPAIR_SITE_BYTES + this.complete.size * REPAIR_COMPLETE_BYTES;
  }

  /** Notes the sites of a frame whose `events` were just decoded, about to be held as held frame `frame`. */
  hold(events: readonly CanonicalEvent[], frame: number): void {
    let path: JsonPath | undefined;
    let stated: ReturnType<typeof responsesCompleteCall>;
    for (const event of events) {
      if (event.type !== "native") continue;
      path ??= responsesArgumentSite(event.payload);
      stated ??= responsesCompleteCall(event.payload);
    }
    // The call is the index its tool event names, the event's own `output_index`, as the decoder
    // refuses a call's event whose index and item id name different items.
    const delta = events.find((event) => event.type === "tool_call_delta");
    if (path !== undefined && delta?.type === "tool_call_delta") this.arguments.push({ call: delta.index, frame, path });
    if (stated !== undefined) {
      const kept = this.complete.get(stated.call);
      if (kept === undefined || (stated.doneItem && !kept.doneItem)) this.complete.set(stated.call, { frame, doneItem: stated.doneItem });
    }
  }

  /** The held frames were released: no site lies in them any more. */
  clear(): void {
    this.arguments = [];
    this.complete.clear();
  }

  /** The exact text of `call`'s complete arguments as the held frames state them: its done item's `arguments`, else its `arguments.done` event's. */
  private completeText(call: bigint, held: readonly Uint8Array[]): string | undefined {
    const site = this.complete.get(call);
    const frame = site === undefined ? undefined : held[site.frame];
    const data = frame === undefined ? undefined : sseData(frame);
    if (data === undefined) return undefined;
    let stated: Json;
    try {
      stated = parseStrict(fatal.decode(data));
    } catch {
      return undefined;
    }
    const args = get(stated, "arguments");
    if (args !== undefined && args !== null && typeof args !== "string") return undefined;
    const item = get(stated, "item");
    if (item !== undefined && item !== null) {
      const own = isObject(item) ? get(item, "arguments") : undefined;
      return typeof own === "string" ? own : undefined;
    }
    return typeof args === "string" ? args : undefined;
  }

  /**
   * `repair_fragments`: the held frames as they go out, with the argument text a forwarded Responses
   * stream holds for each call in `repairs` (its deltas, and arguments its added item carries)
   * replaced by the call's complete arguments: the first site takes them whole, every later one
   * becomes empty. The text is the done item's own (else its `arguments.done` event's), not the
   * inspected value written again, which would sort its keys and round a number beyond 64 bits. A
   * client that reads the call from its deltas then reads the very text that clients reading its done
   * item run, and that the gate passed. Every other frame is the held frame itself, not a copy. Null
   * when the held frames cannot be repaired so (`invalid_upstream_stream`).
   */
  repair(held: readonly Uint8Array[], repairs: ReadonlySet<bigint>): Uint8Array[] | null {
    if (repairs.size === 0) return [...held];
    const out = [...held];
    const whole = new Set<bigint>();
    for (const site of this.arguments) {
      if (!repairs.has(site.call)) continue;
      let text = "";
      if (!whole.has(site.call)) {
        whole.add(site.call);
        const complete = this.completeText(site.call, held);
        if (complete === undefined) return null;
        text = complete;
      }
      const frame = held[site.frame];
      const rewritten = frame === undefined ? undefined : rewriteSseFrame(frame, (data) => editJson(data, [[site.path, { kind: "text", text }]]));
      if (rewritten === undefined) return null;
      out[site.frame] = rewritten;
    }
    // A call is repaired only for fragments it was given, which held frames carried.
    for (const call of repairs) if (!whole.has(call)) return null;
    return out;
  }
}
