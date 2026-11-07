/**
 * `ToolGate` (crates/gray-gateway/src/inference.rs): the per-frame release rule of a gated stream,
 * for the gateway's relay to call with each chunk the upstream sends.
 *
 * Every complete SSE frame is decoded and inspected before it joins the held bytes. Held bytes are
 * released only while the inspector has seen no tool call and no terminal event has arrived. From the
 * first frame carrying a tool call or a terminal event, every byte waits for the end of the stream:
 * the tail must decode, the stream must be complete, the inspector's end checks must pass and the
 * answer must be settled before the rest goes to the client. A refused frame and everything held
 * before it are never released.
 *
 * What is held is the upstream's raw frames, as they arrived (or, with a translation stage, the
 * client bytes the stage made of them), never the decoded events. The inspector keeps only each
 * call's arguments while they arrive and each complete call.
 *
 * The gateway keeps what `Admission` does in Rust: it observes each frame's events (time to first
 * token, the final usage), records findings, settles the answer from `finish`'s usage before it
 * releases the held bytes, fails the request with the step's code, and aborts the upstream when the
 * client leaves (docs/cloudflare-native.md 5.6), dropping the gate.
 */
import type { Json } from "@gray/json";
import {
  type CanonicalEvent,
  type Protocol,
  type Usage,
  GeminiRefusal,
  ProtocolError,
  ProtocolStreamDecoder,
  RepairSites,
  SseFrames,
  StreamObserver,
  dropNullsInFrame,
  finalUsageMissingReason,
  isTerminalEvent,
  keepAlive,
} from "@gray/protocol";
import type { GateRequest, TrustPolicy } from "./policy.ts";
import type { StreamCheck } from "./stream.ts";
import type { InspectionResult, TrustInspection, TrustViolation } from "./violations.ts";

/** Why a stream fails, as the Rust gateway's codes name it. */
export type GateFailure =
  | "invalid_upstream_stream"
  | "upstream_stream_invalid"
  | "upstream_stream_interrupted"
  | "upstream_stream_limit"
  | "upstream_frame_limit"
  | "upstream_trust_policy_rejected"
  | "upstream_stream_incomplete"
  | "upstream_stream_empty"
  | (string & {});

/**
 * `after_commit` (crates/gray-gateway/src/inference.rs): the code a frame the decoder refuses fails a
 * stream with once it is under way. An error event from the upstream ends it with Gray's single error
 * event, never the relay's own (`upstream_stream_interrupted`); any other undecodable frame is
 * `invalid`.
 */
export function afterCommit(error: unknown, invalid: GateFailure): GateFailure {
  return error instanceof ProtocolError && error.detail.kind === "provider" ? "upstream_stream_interrupted" : invalid;
}

/**
 * Which way the end of a stream is settled, once everything held has passed (the gateway's
 * `Admission::finish_stream`, `refused_answer` and `deliver_free`): the model's refusal of a Gemini
 * request is delivered uncharged and needs no usage (`refused`); a streamed request's answer whose
 * final usage never came is delivered free (`free`, with the request log's reason; USAGE_MISSING
 * `free`, the default); any other is billed from its usage by the account (`bill`), which may still
 * refuse a usage that is malformed or beyond the request's limits.
 */
export type Settle = { readonly refused: string } | { readonly free: string } | { readonly bill: true };

/**
 * What the request path does for the gate, as far as the release rule sees it (the Rust mirror's
 * `Stand`): it notes the model's refusal of a Gemini request and whether the final usage came
 * (`Admission::observe_content`), writes each frame without a null `usage.iterations` of an
 * Anthropic answer (`Admission::rewrite_frame`, `drop_nulls`), and says which way the end is settled.
 */
class Stand {
  private readonly protocol: Protocol;
  private readonly streamed: boolean;
  private readonly refusal = new GeminiRefusal();
  private readonly observer: StreamObserver;
  /** Each member left out, as a JSON pointer, once (the request log's `dropped_nulls`). */
  readonly dropped: string[] = [];

  constructor(request: GateRequest["request"]) {
    this.protocol = request.protocol;
    this.streamed = request.stream;
    this.observer = new StreamObserver(request.protocol);
  }

  observeContent(events: readonly CanonicalEvent[]): void {
    this.observer.observe(events);
    if (this.protocol !== "gemini") return;
    for (const event of events) if (event.type === "native") this.refusal.observe(event.payload);
  }

  /** `frame` without a null `usage.iterations` of an Anthropic answer, every other byte as the upstream sent it. */
  rewriteFrame(frame: Uint8Array, events: readonly CanonicalEvent[]): Uint8Array {
    const native = events.find((event) => event.type === "native");
    const dropped = dropNullsInFrame(this.protocol, frame, native?.type === "native" ? native.payload : undefined);
    if (dropped === undefined) throw new GateFailed("upstream_stream_invalid");
    if (dropped.dropped !== null && !this.dropped.includes(dropped.dropped)) this.dropped.push(dropped.dropped);
    return dropped.frame;
  }

  settle(raw: Json): Settle {
    const reason = this.refusal.reason();
    if (reason !== undefined) return { refused: reason };
    if (this.streamed && !this.observer.finalUsageSeen) return { free: finalUsageMissingReason(this.protocol, raw) };
    return { bill: true };
  }
}


/**
 * A translated stream (`translation::StreamStage`, `StreamStage` of `@gray/translation`): inspected
 * upstream events become client bytes, and those are what the gate holds. A failure is an error
 * carrying the failure code as `code` (the translation package's `TranslationFailure`).
 */
export interface StreamStage {
  /** The client bytes of one frame's inspected events (possibly none). */
  push(events: readonly CanonicalEvent[]): Uint8Array;
  /** True until the first tool call on either side. */
  releasable(): boolean;
  /** The end-of-stream checks: the client stream is complete and carries the inspected calls. */
  finish(): void;
  /**
   * Whether the client gets each call's arguments as the upstream streams them (absent: it does);
   * when it does not (a Responses upstream), the inspector reads the fragments as unused.
   */
  streamsCallArguments?(): boolean;
}

/** A stage's failure: an error with a string `code`. */
function stageCode(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined;
  const code = (error as Error & { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

export interface GateOptions {
  /**
   * The request's answer limit in bytes (`Admission::answer_limit`): it bounds the frames that carry
   * the answer, each frame still arriving, and each call's arguments.
   */
  readonly answerLimit: number;
  /** Each frame's decoded events, and the tail's, before the gate decides on them (`observe_content`). */
  readonly observe?: (events: readonly CanonicalEvent[]) => void;
  readonly translation?: StreamStage;
}

/** What one inspection reported: findings of an answer let through, or the refusal. */
export type Finding = { readonly kind: "found"; readonly inspection: TrustInspection } | { readonly kind: "refused"; readonly violation: TrustViolation };

export type GateStep =
  | {
      readonly ok: true;
      /** Bytes the client may have now, in order (often none). */
      readonly release: readonly Uint8Array[];
      /** Bytes are held from here to the end of the stream. */
      readonly holding: boolean;
      readonly findings: readonly Finding[];
    }
  | { readonly ok: false; readonly code: GateFailure; readonly findings: readonly Finding[] };

export type GateEnd =
  | {
      readonly ok: true;
      /** What the answer is settled from (the decoder's accumulated usage). */
      readonly usage: Usage;
      readonly rawUsage: Json;
      /** Which way the answer is settled (`Settle`). */
      readonly settle: Settle;
      /** The held bytes: give them to the client only once the answer is settled. */
      readonly release: readonly Uint8Array[];
      readonly findings: readonly Finding[];
    }
  | { readonly ok: false; readonly status: 502; readonly code: GateFailure; readonly findings: readonly Finding[] };

class GateFailed extends Error {
  readonly code: GateFailure;

  constructor(code: GateFailure) {
    super(code);
    this.code = code;
  }
}

export class ToolGate {
  readonly decoder: ProtocolStreamDecoder;
  /** The stream's tool gate, always the gated kind here (`StreamToolInspector`). */
  private readonly check: StreamCheck;
  private readonly stand: Stand;
  private readonly pending = new SseFrames();
  private held: Uint8Array[] = [];
  private heldBytes = 0;
  /** A forwarded Responses stream: the held frames a repair of a call's arguments reads and rewrites. */
  private readonly fragments: RepairSites | undefined;
  private receivedBytes = 0;
  /** Bytes of the frames that carry the answer, counted against the limit. */
  private total = 0;
  private terminal = false;
  private holdingNow = false;
  private releasedAny = false;
  private readonly limit: number;
  private readonly onEvents: ((events: readonly CanonicalEvent[]) => void) | undefined;
  private readonly translation: StreamStage | undefined;

  constructor(policy: TrustPolicy, gate: GateRequest, options: GateOptions) {
    this.decoder = new ProtocolStreamDecoder(gate.request.protocol);
    // A forwarded Responses stream gives the client each call's complete arguments where its argument
    // deltas differ from them (`repair`); a translation of one gives the client each call from its
    // complete arguments alone (`relay_gated`).
    const forwardedResponses = options.translation === undefined && gate.request.protocol === "open_ai_responses";
    const fragments = forwardedResponses ? "repaired" : options.translation !== undefined && !(options.translation.streamsCallArguments?.() ?? true) ? "unused" : "forwarded";
    this.check = policy.streamCheck(gate, options.answerLimit, { gated: true, fragments });
    this.fragments = forwardedResponses ? new RepairSites() : undefined;
    this.stand = new Stand(gate.request);
    this.limit = options.answerLimit;
    this.onEvents = options.observe;
    this.translation = options.translation;
  }

  /** Bytes are being held until the end-of-stream checks. */
  get holding(): boolean {
    return this.holdingNow;
  }

  /**
   * Some bytes have gone to the client. The relay's code for an upstream that stops before its end (a
   * read error, the silence or total deadline) rests on it, as `relay_gated` does:
   * `upstream_stream_interrupted` once anything was released, `upstream_stream_incomplete` before.
   * Rust also notes a deadline cut when `received` is above zero (`note_deadline_cut`).
   */
  get released(): boolean {
    return this.releasedAny;
  }

  /** Bytes received, keep-alives and the frame still arriving included. */
  get received(): number {
    return this.receivedBytes;
  }

  /** Bytes held for the client now. */
  get heldSize(): number {
    return this.heldBytes;
  }

  /** The null members left out of the client's frames so far, as JSON pointers (the request log's `dropped_nulls`). */
  get droppedNulls(): readonly string[] {
    return this.stand.dropped;
  }

  /** `ToolGate::push`: one chunk from the upstream; the bytes that may go to the client now, or the failure. */
  push(chunk: Uint8Array): GateStep {
    const findings: Finding[] = [];
    try {
      this.receivedBytes += chunk.length;
      this.pending.push(chunk);
      const release: Uint8Array[] = [];
      for (let frame = this.pending.nextFrame(); frame !== undefined; frame = this.pending.nextFrame()) {
        // pushFrame returns this frame's own events, so a release never rests on an earlier frame.
        let events: CanonicalEvent[];
        try {
          events = this.decoder.pushFrame(frame);
        } catch (error) {
          throw new GateFailed(afterCommit(error, "invalid_upstream_stream"));
        }
        // A keep-alive carries none of the answer: any number may come, so it is not counted, and one
        // that comes while frames are held is let go (the client gets Gray's own keep-alives).
        const ka = keepAlive(events);
        if (!ka) {
          this.total += frame.length;
          if (this.total > this.limit) throw new GateFailed("upstream_stream_limit");
        }
        this.accept(events, findings);
        if (ka && this.holdingNow) continue;
        if (this.translation === undefined) {
          const bytes = this.stand.rewriteFrame(frame, events);
          this.fragments?.hold(events, this.held.length);
          this.hold(bytes);
        } else {
          this.hold(this.stage(() => (this.translation as StreamStage).push(events)));
        }
        if (!this.terminal && this.check.releasable() && (this.translation?.releasable() ?? true)) {
          // One at a time, not spread into `push`: more frames may be held than a call's arguments can take.
          for (const held of this.held) release.push(held);
          this.held = [];
          this.heldBytes = 0;
          this.fragments?.clear();
        } else {
          this.holdingNow = true;
        }
      }
      // A frame still arriving is part of the answer, and no larger.
      if (this.pending.length > this.limit) throw new GateFailed("upstream_frame_limit");
      if (release.length > 0) this.releasedAny = true;
      return { ok: true, release, holding: this.holdingNow, findings };
    } catch (error) {
      if (error instanceof GateFailed) return { ok: false, code: error.code, findings };
      throw error;
    }
  }

  /**
   * `ToolGate::finish` up to the charge: the tail decodes and completes the stream, the inspector's
   * end checks pass, and a forwarded Responses stream's argument text is repaired where the inspector
   * asked for it. The caller then settles the answer (`settle`: no usage, no charge) and only after
   * that releases `release`.
   */
  finish(): GateEnd {
    const findings: Finding[] = [];
    try {
      const tail = this.pending.rest();
      let events: CanonicalEvent[];
      try {
        events = this.decoder.push(tail);
        events.push(...this.decoder.finish());
      } catch {
        throw new GateFailed("upstream_stream_incomplete");
      }
      this.accept(events, findings);
      // The rest of the stream is its last frame, perhaps without its blank line or ending in a lone CR.
      if (this.translation === undefined) this.hold(this.stand.rewriteFrame(tail, events));
      else this.hold(this.stage(() => (this.translation as StreamStage).push(events)));
      if (!this.record(this.check.finish(), findings)) throw new GateFailed("upstream_trust_policy_rejected");
      // The decoder finished, so the stream ended with its terminal event; whether it reported the
      // usage Gray bills from is the settlement's to say.
      if (this.translation !== undefined) this.stage(() => (this.translation as StreamStage).finish());
      const release = this.fragments === undefined ? this.held : this.fragments.repair(this.held, this.check.fragmentRepairs());
      if (release === null) throw new GateFailed("invalid_upstream_stream");
      const raw = this.decoder.rawUsage();
      this.held = [];
      this.heldBytes = 0;
      return { ok: true, usage: this.decoder.usage(), rawUsage: raw, settle: this.stand.settle(raw), release, findings };
    } catch (error) {
      if (error instanceof GateFailed) return { ok: false, status: 502, code: error.code, findings };
      throw error;
    }
  }

  private hold(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    this.held.push(chunk);
    this.heldBytes += chunk.length;
  }

  private stage<T>(run: () => T): T {
    try {
      return run();
    } catch (error) {
      const code = stageCode(error);
      if (code !== undefined) throw new GateFailed(code);
      throw error;
    }
  }

  /** `ToolGate::accept`. */
  private accept(events: readonly CanonicalEvent[], findings: Finding[]): void {
    this.onEvents?.(events);
    this.stand.observeContent(events);
    if (!this.record(this.check.observe(events), findings)) throw new GateFailed("upstream_trust_policy_rejected");
    this.terminal ||= events.some(isTerminalEvent);
  }

  /** What `Admission::policy` keeps of an inspection: false when it refused the answer. */
  private record(result: InspectionResult, findings: Finding[]): boolean {
    if (!result.ok) {
      findings.push({ kind: "refused", violation: result.violation });
      return false;
    }
    if (result.inspection.violations.length > 0 || result.inspection.passed.length > 0) findings.push({ kind: "found", inspection: result.inspection });
    return true;
  }
}

/**
 * `relay_open` (crates/gray-gateway/src/inference.rs): an ungated stream, for a request
 * `TrustPolicy.requiresBufferedStream` does not gate (no tools declared, or a mode that does not
 * enforce). Frames are released as soon as their events pass `inspectStreamEvents`, so text streams
 * at once; from the first terminal event every byte is held until the end of the stream, so a client
 * that stops at the end marker cannot cancel the charge before it is recorded. A call in an answer to
 * a request that declared no tool is recorded and passed on, as the gate does.
 *
 * The same contract as `ToolGate`: `push` per chunk, `finish` at the end of the upstream's body,
 * settle as `settle` says, then release. The relay chooses the code for a stream that stops early:
 * the Rust gateway answers `upstream_stream_empty` before the first frame (`started` false) and
 * `upstream_stream_interrupted` after it.
 */
export class OpenGate {
  readonly decoder: ProtocolStreamDecoder;
  /** The stream's tool gate, always the open kind here (`inspectStreamEvents` per frame). */
  private readonly check: StreamCheck;
  private readonly stand: Stand;
  private readonly pending = new SseFrames();
  private readonly limit: number;
  private readonly onEvents: ((events: readonly CanonicalEvent[]) => void) | undefined;
  private total = 0;
  private startedNow = false;
  private holdingNow = false;
  private held: Uint8Array[] = [];
  private receivedBytes = 0;

  constructor(policy: TrustPolicy, gate: GateRequest, options: Omit<GateOptions, "translation">) {
    this.decoder = new ProtocolStreamDecoder(gate.request.protocol);
    this.check = policy.streamCheck(gate, options.answerLimit, { gated: false });
    this.stand = new Stand(gate.request);
    this.limit = options.answerLimit;
    this.onEvents = options.observe;
  }

  /** The first complete frame has arrived. */
  get started(): boolean {
    return this.startedNow;
  }

  get holding(): boolean {
    return this.holdingNow;
  }

  /**
   * Bytes received, keep-alives and the frame still arriving included. `relay_open` counts them and
   * notes a deadline cut (`note_deadline_cut`, Gray's own limit ended the stream) when the silence or
   * total deadline stops a stream that has received any, before the first frame as after it.
   */
  get received(): number {
    return this.receivedBytes;
  }

  /** The null members left out of the client's frames so far, as JSON pointers (the request log's `dropped_nulls`). */
  get droppedNulls(): readonly string[] {
    return this.stand.dropped;
  }

  private inspect(events: readonly CanonicalEvent[], findings: Finding[]): void {
    const result = this.check.observe(events);
    if (!result.ok) {
      findings.push({ kind: "refused", violation: result.violation });
      throw new GateFailed("upstream_trust_policy_rejected");
    }
    if (result.inspection.violations.length > 0 || result.inspection.passed.length > 0) findings.push({ kind: "found", inspection: result.inspection });
  }

  push(chunk: Uint8Array): GateStep {
    const findings: Finding[] = [];
    try {
      this.receivedBytes += chunk.length;
      this.pending.push(chunk);
      const release: Uint8Array[] = [];
      for (let frame = this.pending.nextFrame(); frame !== undefined; frame = this.pending.nextFrame()) {
        const first = !this.startedNow;
        this.startedNow = true;
        let events: CanonicalEvent[];
        try {
          events = this.decoder.pushFrame(frame);
        } catch (error) {
          // The first frame's failure has its own code in the Rust relay.
          throw new GateFailed(afterCommit(error, first ? "invalid_upstream_stream" : "upstream_stream_invalid"));
        }
        const ka = keepAlive(events);
        if (!ka) {
          this.total += frame.length;
          if (this.total > this.limit) throw new GateFailed("upstream_stream_limit");
        }
        this.inspect(events, findings);
        this.onEvents?.(events);
        this.stand.observeContent(events);
        const bytes = this.stand.rewriteFrame(frame, events);
        if (!this.holdingNow && events.some(isTerminalEvent)) this.holdingNow = true;
        if (this.holdingNow) {
          // A keep-alive while frames are held is dropped, not held (the client gets Gray's own); the
          // first frame is held whatever it is.
          if (!(ka && !first)) this.held.push(bytes);
        } else {
          release.push(bytes);
        }
      }
      if (this.pending.length > this.limit) throw new GateFailed("upstream_frame_limit");
      return { ok: true, release, holding: this.holdingNow, findings };
    } catch (error) {
      if (error instanceof GateFailed) return { ok: false, code: error.code, findings };
      throw error;
    }
  }

  /** `finish_stream_tail` up to the charge, then what the relay sends: the held bytes and the tail, and which way it is settled. */
  finish(): GateEnd {
    const findings: Finding[] = [];
    try {
      if (!this.startedNow && this.pending.isEmpty()) throw new GateFailed("upstream_stream_empty");
      const tail = this.pending.rest();
      let events: CanonicalEvent[];
      try {
        events = this.decoder.push(tail);
      } catch {
        throw new GateFailed("upstream_stream_invalid");
      }
      try {
        events.push(...this.decoder.finish());
      } catch {
        throw new GateFailed("upstream_stream_incomplete");
      }
      this.inspect(events, findings);
      this.onEvents?.(events);
      this.stand.observeContent(events);
      const last = this.stand.rewriteFrame(tail, events);
      const raw = this.decoder.rawUsage();
      const release = last.length > 0 ? [...this.held, last] : this.held;
      this.held = [];
      return { ok: true, usage: this.decoder.usage(), rawUsage: raw, settle: this.stand.settle(raw), release, findings };
    } catch (error) {
      if (error instanceof GateFailed) return { ok: false, status: 502, code: error.code, findings };
      throw error;
    }
  }
}
