/**
 * The tool gate as the gateway's relay calls it, once per complete SSE frame (crates/gray-gateway/
 * src/inference.rs: what `relay_gated` and `relay_open` ask the trust policy). The relay splits the
 * upstream's bytes into frames, decodes each with `ProtocolStreamDecoder.pushFrame`, and before any
 * byte of a frame leaves it asks `observe` about that frame's events:
 *
 * - a refusal ends the stream (`upstream_trust_policy_rejected`), and nothing held is released;
 * - otherwise the frame may go to the client while `releasable()` is true and no terminal event has
 *   arrived; from the first frame `releasable()` is false for (the first sign of a tool call in a
 *   gated stream), or the first terminal event, the relay holds that frame and every later one, as
 *   the raw bytes it received, until the end-of-stream checks pass and the answer is settled;
 * - at the end of the upstream's body the relay decodes the tail (`push` and `finish`), calls
 *   `observe` with those events and then `finish()`.
 *
 * A gated stream (`holdsToolCalls`, Rust's `requires_buffered_stream`: enforce mode, a streamed
 * request that declared tools) is checked by a `StreamToolInspector`; an open one by
 * `inspectStreamEvents` on each frame, with no end-of-stream check of its own (Rust's open relay has
 * none). `ToolGate` and `OpenGate` (src/gate.ts) are the whole release rule built on the same calls,
 * held to Rust's own relay by the `trust` fixtures (targets `gate` and `open_gate`).
 */
import { type Json, type JsonObject, isObject, setMember } from "@gray/json";
import { type CanonicalEvent, conversationFields } from "@gray/protocol";
import type { FragmentUse, StreamToolInspector } from "./inspector.ts";
import type { GateRequest, TrustPolicy } from "./policy.ts";
import { type InspectionResult, NOTHING_FOUND } from "./violations.ts";

/** One stream's tool gate, fed every frame's decoded events in upstream order. */
export interface StreamCheck {
  /**
   * Frames from the first sign of a tool call on are held to the end of the stream (Rust's
   * `requires_buffered_stream`, or a translated stream). Every stream also holds from its first
   * terminal event; that part is the relay's.
   */
  readonly holdsToolCalls: boolean;
  /** One complete frame's events, or the tail's at the end; a refusal is sticky in a gated stream. */
  observe(events: readonly CanonicalEvent[]): InspectionResult;
  /** No tool call seen yet in a gated stream (always true in an open one). */
  releasable(): boolean;
  /** The end-of-stream checks, after the tail's events were observed. */
  finish(): InspectionResult;
  /**
   * The calls, by index, whose argument fragments the relay must replace with their complete
   * arguments before it releases them (`StreamToolInspector.fragmentRepairs`; always empty unless the
   * check was made with `fragments: "repaired"`).
   */
  fragmentRepairs(): ReadonlySet<bigint>;
  /**
   * What the check keeps of the stream beyond the decoder's values, in heap bytes
   * (`StreamToolInspector.retainedBytes`; nothing in an open stream): the relay weighs it with the
   * frames it holds.
   */
  retainedBytes(): number;
}

export interface StreamCheckOptions {
  /**
   * True gates the stream whatever the request declared: Rust gates every translated stream
   * (`relay`: `translation.is_some() || requires_buffered_stream`), whose client bytes are made from
   * inspected events. False checks it as an open stream. Absent: `requiresBufferedStream` decides.
   */
  readonly gated?: boolean;
  /**
   * What the client gets of a gated stream's argument fragments (`FragmentUse`): `repaired` for an
   * untranslated Responses stream the relay repairs (`relay_gated`'s `with_fragment_repair`),
   * `unused` for a translation that gives the client each call whole (`with_fragments_unused`).
   * Absent: `forwarded`.
   */
  readonly fragments?: FragmentUse;
}

const NO_REPAIRS: ReadonlySet<bigint> = new Set();

class GatedCheck implements StreamCheck {
  readonly holdsToolCalls = true;
  private readonly inspector: StreamToolInspector;

  constructor(inspector: StreamToolInspector) {
    this.inspector = inspector;
  }

  observe(events: readonly CanonicalEvent[]): InspectionResult {
    return this.inspector.observe(events);
  }

  releasable(): boolean {
    return this.inspector.releasable();
  }

  finish(): InspectionResult {
    return this.inspector.finish();
  }

  fragmentRepairs(): ReadonlySet<bigint> {
    return this.inspector.fragmentRepairs();
  }

  retainedBytes(): number {
    return this.inspector.retainedBytes();
  }
}

class OpenCheck implements StreamCheck {
  readonly holdsToolCalls = false;
  private readonly policy: TrustPolicy;
  private readonly gate: GateRequest;

  constructor(policy: TrustPolicy, gate: GateRequest) {
    this.policy = policy;
    this.gate = gate;
  }

  observe(events: readonly CanonicalEvent[]): InspectionResult {
    return this.policy.inspectStreamEvents(this.gate, events);
  }

  releasable(): boolean {
    return true;
  }

  finish(): InspectionResult {
    return { ok: true, inspection: NOTHING_FOUND };
  }

  fragmentRepairs(): ReadonlySet<bigint> {
    return NO_REPAIRS;
  }

  retainedBytes(): number {
    return 0;
  }
}

/** `TrustPolicy.streamCheck`. */
export function streamCheck(policy: TrustPolicy, gate: GateRequest, answerLimit: number, options: StreamCheckOptions = {}): StreamCheck {
  if (options.gated ?? policy.requiresBufferedStream(gate.request)) {
    const inspector = policy.streamToolInspector(gate, answerLimit);
    if (options.fragments === "repaired") inspector.withFragmentRepair();
    else if (options.fragments === "unused") inspector.withFragmentsUnused();
    return new GatedCheck(inspector);
  }
  return new OpenCheck(policy, gate);
}

/**
 * The request as the gateway keeps it after admission (`CanonicalRequest::without_conversation`):
 * no messages, and a native body without its conversation fields (Chat `messages`; Anthropic
 * `messages` and `system`; Responses `input` and `instructions`; Gemini `contents` and the system
 * instruction under either name). Everything checked after admission is in the other fields (tools,
 * tool selection), so a stream need not keep the conversation alive while it runs. The body is a
 * shallow copy: the kept members are shared with the original.
 */
export function answerContract(gate: GateRequest): GateRequest {
  const conversation = conversationFields(gate.request.protocol);
  let body: Json | undefined = gate.body;
  if (isObject(body)) {
    const kept: JsonObject = {};
    for (const key of Object.keys(body)) if (!conversation.includes(key)) setMember(kept, key, body[key] as Json);
    body = kept;
  }
  return { request: { ...gate.request, messages: [] }, body };
}
