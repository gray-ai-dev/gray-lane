/**
 * `StreamToolInspector` (crates/gray-gateway/src/trust.rs): the incremental tool-call gate of an
 * enforced stream. Feed it every decoded event in upstream order, one complete SSE frame at a time,
 * and release a frame only after `observe` accepted it and `releasable` is true. Text and reasoning
 * before any tool call can therefore stream. The first frame carrying any sign of a tool call (a
 * canonical tool event, or a native shape the decoder does not project) sets a sticky `toolSeen`;
 * that frame and every later one stay held, in order, until the end-of-stream checks pass. No call,
 * including one already validated, reaches the client before a later call, snapshot or end-of-stream
 * check could still refuse the answer.
 *
 * It keeps only what the checks need: each call's argument text while it is still arriving (dropped
 * once the complete call matched it) and each complete call. It never keeps frames; the gate that
 * holds bytes keeps the raw frames, not a parsed copy (src/gate.ts).
 */
import { type Json, asStr, get, isArray, jsonEqual, pointer, utf8Length } from "@gray/json";
import { type CanonicalEvent, argumentValue } from "@gray/protocol";
import { MAX_TOOLS } from "./limits.ts";
import type { GateRequest, ToolSchemas, TrustPolicy } from "./policy.ts";
import { type Call, carriesToolCall, inspectNativeStream, responseItemCalls } from "./shapes.ts";
import { type InspectionResult, NOTHING_FOUND, type TrustViolation, attempt, pass, refuse } from "./violations.ts";

interface Fragments {
  name: string | undefined;
  text: string;
  /** UTF-8 bytes of `text` (Rust's `String::len`). */
  bytes: number;
  /** The heap bytes `text` adds to the decoder's (`retainedBytes`). */
  heap: number;
}

/**
 * What the gate's own join of a call's argument fragments costs beyond the decoder's: one rope node a
 * fragment, the fragment's string being the decoder's (the same value). Measured in workerd
 * (gateway/measure/answer-heap.ts, 2026-10-19): 10,000 fragments of 64 characters joined into two
 * strings held 1,160,128 bytes, into one 976,708: 18.3 a fragment for the second.
 */
export const GATE_FRAGMENT_BYTES = 19;

/**
 * What the gate keeps for each call beyond its values: its fragments' entry from its first fragment
 * (`GATE_CALL_BYTES`), and its complete call's entries once complete (`GATE_COMPLETE_BYTES`; the
 * arguments are the decoder's value, not a copy). Measured in workerd (gateway/measure/answer-heap.ts,
 * 2026-10-19, 16 streams of 128 calls each, the gate kept with the decoder against the decoder
 * alone): 130.1 bytes a complete call in Chat streams, 141.6 to 148.3 in Responses streams; the two
 * entries together take the largest.
 */
export const GATE_CALL_BYTES = 72;
export const GATE_COMPLETE_BYTES = 80;

/**
 * What a client gets of a streamed call's argument fragments, as the caller of a
 * `StreamToolInspector` releases them (Rust's `Fragments`):
 * - `forwarded`: the fragments as sent, so they must state the complete call;
 * - `repaired`: the fragments as sent where they state the complete call, else the complete
 *   arguments in their place (`withFragmentRepair`);
 * - `unused`: none of them: the client gets each call from its complete arguments alone
 *   (`withFragmentsUnused`).
 */
export type FragmentUse = "forwarded" | "repaired" | "unused";

function sameCall(a: Call | undefined, b: Call | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a[0] === b[0] && jsonEqual(a[1], b[1]);
}

export class StreamToolInspector {
  private readonly policy: TrustPolicy;
  private readonly gate: GateRequest;
  /** The answer's validators, or the violation the request's declarations already have. */
  private readonly schemas: ToolSchemas | TrustViolation;
  private readonly argumentLimit: number;
  private readonly deltas = new Map<bigint, Fragments>();
  private readonly complete = new Map<bigint, Call>();
  /** The call of each id: its index in `complete`, not a second copy. */
  private readonly completeIds = new Map<string, bigint>();
  private nativeCount = 0;
  private done = false;
  /** Sticky: once set, nothing more is releasable before the end of the stream. */
  private toolSeen = false;
  private rejected: TrustViolation | undefined;
  private readonly passed: TrustViolation[] = [];
  private reported = 0;
  /** What the client gets of each call's argument fragments. */
  private fragments: FragmentUse = "forwarded";
  /** The calls whose fragments differ from their complete arguments, for the caller to give the complete arguments in their place. */
  private readonly repairs = new Set<bigint>();
  /** What the gate keeps beyond the decoder's values, in heap bytes (`retainedBytes`). */
  private kept = 0;

  constructor(policy: TrustPolicy, gate: GateRequest, schemas: ToolSchemas | TrustViolation, argumentLimit: number) {
    this.policy = policy;
    this.gate = gate;
    this.schemas = schemas;
    this.argumentLimit = argumentLimit;
  }

  /**
   * `with_fragment_repair`: this inspector for a caller that holds every frame of a call until the
   * end (enforce) and, before it releases them, replaces the argument fragments of each call in
   * `fragmentRepairs()` with the call's complete arguments, as the gateway does for a Responses
   * stream it forwards. A call whose fragments differ from its complete arguments is then recorded
   * for that instead of refusing the answer: every statement of the call the client gets is the
   * inspected one. On the Responses API the complete call is the one clients run (Codex and the AI
   * SDK run each `response.output_item.done` item and never the argument deltas), so a relay whose
   * deltas fall short of it is served as directly: yylx's gpt-6.1-sol sent only the end of each
   * call's arguments as deltas on 10 of 18 streams (2026-10-17), and OpenCode 2.0.27 ran every one
   * of those calls. In audit and off a frame is released as it comes, so nothing is repaired and such
   * a call is still a violation.
   */
  withFragmentRepair(): this {
    this.fragments = "repaired";
    return this;
  }

  /**
   * `with_fragments_unused`: this inspector for a caller that gives the client each call from its
   * complete arguments alone and none of its argument fragments, as the gateway's translation of a
   * Responses stream does (`StreamTranslator.streamsCallArguments`): fragments that differ from the
   * complete arguments are then nothing a client reads, in any mode. Whatever reaches the client is
   * compared with the inspected calls before it is released (the translation stage's `finish`).
   */
  withFragmentsUnused(): this {
    this.fragments = "unused";
    return this;
  }

  /** The calls, by index, whose argument fragments the caller must replace with their complete arguments (`withFragmentRepair`). */
  fragmentRepairs(): ReadonlySet<bigint> {
    return this.repairs;
  }

  /**
   * What the gate keeps of the stream beyond the decoder's values, in the heap (the gateway weighs it
   * with the frames a stream holds): its own join of each call's fragments until the call is complete
   * (`GATE_FRAGMENT_BYTES` a fragment), and each call's entries (`GATE_CALL_BYTES`,
   * `GATE_COMPLETE_BYTES`). A complete call's arguments are the decoder's value, weighed there.
   */
  retainedBytes(): number {
    return this.kept;
  }

  /** The call `id` names, once complete. */
  private callOf(id: string): Call | undefined {
    const index = this.completeIds.get(id);
    return index === undefined ? undefined : this.complete.get(index);
  }

  /**
   * One frame's events (or those decoded at the end). A refusal is sticky: enforce keeps refusing,
   * audit reports it once and stops inspecting. A passed finding is reported by the call that first
   * found it.
   */
  observe(events: readonly CanonicalEvent[]): InspectionResult {
    if (this.policy.mode === "off") return { ok: true, inspection: NOTHING_FOUND };
    if (this.rejected !== undefined) {
      const sticky = this.policy.decision(this.rejected, []);
      return sticky.ok ? { ok: true, inspection: NOTHING_FOUND } : sticky;
    }
    const violation = attempt(() => {
      for (const event of events) this.observeEvent(event);
    });
    if (violation !== undefined) this.rejected = violation;
    const found = this.passed.slice(this.reported);
    this.reported = this.passed.length;
    return this.policy.decision(violation, found);
  }

  /**
   * True while no tool call has been seen, so every accepted byte may be released. False from the
   * first sign of a tool call: the caller holds that frame and every later byte until `finish` and
   * its own end-of-stream checks succeed.
   */
  releasable(): boolean {
    return this.policy.mode !== "enforce" || (this.rejected === undefined && !this.toolSeen);
  }

  /** The end-of-stream checks: after the decoder finished and its final events were observed. */
  finish(): InspectionResult {
    if (this.policy.mode === "off") return { ok: true, inspection: NOTHING_FOUND };
    if (this.rejected !== undefined) {
      const sticky = this.policy.decision(this.rejected, []);
      return sticky.ok ? { ok: true, inspection: NOTHING_FOUND } : sticky;
    }
    const violation = attempt(() => {
      if (typeof this.schemas === "string") refuse(this.schemas);
      if (!this.done || this.nativeCount === 0 || [...this.deltas.keys()].some((index) => !this.complete.has(index))) {
        refuse("trust_opaque_tool_payload");
      }
    });
    // Every passed finding was reported by the `observe` that found it.
    return this.policy.decision(violation, []);
  }

  private observeEvent(event: CanonicalEvent): void {
    if (event.type === "tool_call_delta" || event.type === "tool_call_complete") this.toolSeen = true;
    else if (event.type === "native") this.toolSeen ||= carriesToolCall(event.payload);
    if (typeof this.schemas === "string") refuse(this.schemas);
    const schemas = this.schemas;
    const { request } = this.gate;
    switch (event.type) {
      case "tool_call_delta": {
        if (this.complete.has(event.index)) refuse("trust_invalid_tool_arguments");
        let fragments = this.deltas.get(event.index);
        if (fragments === undefined) {
          fragments = { name: undefined, text: "", bytes: 0, heap: 0 };
          this.deltas.set(event.index, fragments);
          this.kept += GATE_CALL_BYTES;
        }
        if (event.name !== null) {
          const name = event.name;
          if (!request.tools.some((tool) => tool.name === name)) pass(this.passed, "trust_tool_not_allowed");
          if (fragments.name !== undefined && fragments.name !== name) refuse("trust_opaque_tool_payload");
          fragments.name = name;
        }
        fragments.text += event.arguments;
        fragments.bytes += utf8Length(event.arguments);
        if (event.arguments !== "") {
          fragments.heap += GATE_FRAGMENT_BYTES;
          this.kept += GATE_FRAGMENT_BYTES;
        }
        if (fragments.bytes > this.argumentLimit) refuse("trust_payload_limit");
        break;
      }
      case "tool_call_complete": {
        if (event.name === null) refuse("trust_opaque_tool_payload");
        const name = event.name;
        const call: Call = [name, event.arguments];
        this.policy.inspectCall(this.gate, schemas, name, event.arguments, this.passed, this.argumentLimit);
        // One answer that states one call two different ways leaves which one a client runs unknown:
        // refused, not passed, unless the caller gives the client the complete call in place of the
        // fragments (`withFragmentRepair`) or the client gets no fragments (`withFragmentsUnused`).
        const fragments = this.deltas.get(event.index);
        if (fragments !== undefined) {
          if (fragments.name !== undefined && fragments.name !== name) refuse("trust_opaque_tool_payload");
          if (fragments.text !== "" && !jsonEqual(argumentValue(fragments.text), event.arguments)) {
            if (this.fragments === "repaired" && this.policy.mode === "enforce") this.repairs.add(event.index);
            else if (this.fragments !== "unused") refuse("trust_invalid_tool_arguments");
          }
          // Matched or repaired: a later snapshot of this call is compared with the complete call below.
          fragments.text = "";
          fragments.bytes = 0;
          this.kept -= fragments.heap;
          fragments.heap = 0;
        }
        const earlier = this.complete.get(event.index);
        if (earlier !== undefined && !sameCall(earlier, call)) refuse("trust_invalid_tool_arguments");
        if (event.id !== null) {
          const named = this.callOf(event.id);
          if (named !== undefined && !sameCall(named, call)) refuse("trust_invalid_tool_arguments");
        }
        if (earlier === undefined) this.kept += GATE_COMPLETE_BYTES;
        this.complete.set(event.index, call);
        if (event.id !== null) this.completeIds.set(event.id, event.index);
        break;
      }
      case "native": {
        this.nativeCount += 1;
        if (event.protocol !== request.protocol) refuse("trust_protocol_mismatch");
        for (const [name, args] of inspectNativeStream(event.protocol, event.payload, true)) {
          this.policy.inspectCall(this.gate, schemas, name, args, this.passed, this.argumentLimit);
        }
        const kind = asStr(get(event.payload, "type"));
        if (event.protocol === "open_ai_responses" && (kind === "response.completed" || kind === "response.incomplete")) {
          const output = pointer(event.payload, "/response/output");
          if (isArray(output)) {
            for (const item of output) {
              if (asStr(get(item, "type")) !== "function_call") continue;
              const id = asStr(get(item, "call_id"));
              if (id === undefined) refuse("trust_opaque_tool_payload");
              const snapshot: Call[] = [];
              responseItemCalls(item as Json, snapshot);
              if (!sameCall(snapshot[0], this.callOf(id))) refuse("trust_invalid_tool_arguments");
            }
          }
        }
        break;
      }
      case "error":
        refuse("trust_opaque_tool_payload");
        break;
      case "done":
        this.done = true;
        break;
      default:
        break;
    }
    if (this.deltas.size > MAX_TOOLS || this.complete.size > MAX_TOOLS) refuse("trust_payload_limit");
  }
}
