import type { Json } from "@gray/json";
import type { CanonicalEvent, CanonicalRequest, ProjectionObserver, Protocol } from "@gray/protocol";

/**
 * The tool gate's hook in the request path (the server's trust policy: crates/gray-gateway/src/
 * trust.rs `TrustPolicy`, and what inference.rs `Admission` asks of it). The gateway asks it four
 * things:
 *
 * 1. before admission, whether the request itself may be served (`inspectRequest`), with the native
 *    body it was parsed from;
 * 2. per stream, an inspector (`stream`): whether frames are held from the first tool call until the
 *    end-of-stream checks pass (`holdsToolCalls`, Rust's `requires_buffered_stream`; every translated
 *    stream is), and per frame, after the frame is decoded and before any of its bytes are released
 *    (`observe`), and at the end of the stream (`finish`);
 * 3. per non-streaming answer, what of it is held back while it passes (`answer`: its call entries
 *    until each is checked, @gray/trust `AnswerCallCheck`), and at its end, on its projection and
 *    before it is billed, the verdict (`inspectResponse`).
 *
 * After admission the gate reads the request without its conversation (`contract`, Rust's
 * `without_conversation`): a stream need not keep the conversation alive while it runs.
 *
 * A frame is decoded and inspected whole before it is released, whatever the gate says, and every
 * frame from the first terminal event on is held until billing commits (relay.ts): that part is the
 * relay's. The relay holds the raw frames it received (or, for a translated stream, the client bytes
 * made of them), never a parsed copy; the inspector keeps only each call's arguments while they
 * arrive and each complete call (@gray/trust `StreamToolInspector`).
 *
 * The production gate is @gray/trust's (trust.ts); `PASS_THROUGH` below lets everything through and
 * holds nothing, for tests that are not about the gate.
 */

/** A canonical request with the native body it was parsed from (@gray/trust `GateRequest`, Rust's `raw_body`). */
export interface GateRequest {
  readonly request: CanonicalRequest;
  /** Tier A: the whole body. Tiers B and C: every member but the conversation, which was not read. */
  readonly body: Json | undefined;
}

/**
 * What an inspection decided (@gray/trust `InspectionResult`): let through with what it found, or a
 * refusal. `violations` are what enforce mode would refuse, reported because the mode is audit;
 * `passed` are findings let through in every mode (a call the client checks itself).
 */
export type GateVerdict =
  | { readonly ok: true; readonly violations: readonly string[]; readonly passed: readonly string[] }
  | { readonly ok: false; readonly violation: string };

export const CLEAN: GateVerdict = Object.freeze({ ok: true, violations: Object.freeze([]) as readonly string[], passed: Object.freeze([]) as readonly string[] });

/** One stream's inspector, fed every frame's events in upstream order (@gray/trust `StreamCheck`). */
export interface StreamInspector {
  /** Frames are held from the first sign of a tool call to the end of the stream. */
  readonly holdsToolCalls: boolean;
  /** One complete frame's events; a refusal ends the stream with `upstream_trust_policy_rejected`. */
  observe(events: readonly CanonicalEvent[]): GateVerdict;
  /** No tool call has been seen yet (sticky once one has): frames may still be released as they pass. */
  releasable(): boolean;
  /** The end of the stream, after the tail's events were observed: every call complete and valid, or a refusal. */
  finish(): GateVerdict;
  /**
   * The calls, by index, whose argument deltas the relay replaces with their complete arguments
   * before it releases them (@gray/trust `StreamToolInspector.fragmentRepairs`): a forwarded
   * Responses stream held to its end, whose deltas fall short of the done item. Empty otherwise.
   */
  fragmentRepairs(): ReadonlySet<bigint>;
  /**
   * What the gate keeps of the stream beyond the decoder's values, in heap bytes (@gray/trust
   * `StreamToolInspector.retainedBytes`): the relay weighs it with the frames it holds.
   */
  retainedBytes(): number;
}

/**
 * What the client gets of a gated stream's argument fragments (@gray/trust `FragmentUse`):
 * `repaired` for an untranslated Responses stream the relay repairs, `unused` for a translation that
 * gives the client each call whole, `forwarded` otherwise.
 */
export type FragmentUse = "forwarded" | "repaired" | "unused";

/**
 * What the gate holds back of one non-streaming answer while it passes (@gray/trust
 * `AnswerCallCheck`): it hears the answer's projection token by token and says from which byte on
 * nothing may go out yet, and whether a call it checked refused the answer.
 */
export interface AnswerInspector extends ProjectionObserver {
  /** The first byte held (+Infinity when none). */
  heldFrom(): number;
  /** The refusal of a checked entry: nothing more goes out, and the answer is refused. */
  readonly refused: string | undefined;
}

/**
 * The gate could not inspect the request in this isolate now (@gray/trust `RegexEngineUnavailable`:
 * the regex engine trapped and was restarted, or the request spent its allowance for compiling
 * patterns new to the isolate). Not a verdict on the request: the gateway answers 429
 * `gateway_capacity`, retryable.
 */
export class GateCapacity extends Error {
  override readonly name = "GateCapacity";
}

export interface ToolGate {
  /** The trust mode for the record (`enforce`, `audit`, `off`). */
  readonly mode: string;
  /**
   * The request before admission. `opaque`: its conversation was not read (tiers B and C), so a
   * policy that looks for secret markers in it cannot pass it. Throws `GateCapacity`.
   */
  inspectRequest(request: GateRequest, opaque: boolean): GateVerdict;
  /** The request as the gate keeps it after admission: without its conversation. */
  contract(request: GateRequest): GateRequest;
  /**
   * Whether a stream answering `request` will hold its frames from the first tool call on (Rust's
   * `requires_buffered_stream`), known before admission: such an answer is held in memory, so its
   * output cap must fit what the gateway holds (inference.ts `answerRoom`).
   */
  holdsToolCalls(request: GateRequest): boolean;
  /**
   * The inspector of one stream answering `contract`. `answerLimit` bounds every call's arguments as
   * it bounds the answer. `gated`: hold tool calls whatever the request declared (a translated stream).
   * `fragments`: what the client gets of a call's argument fragments (absent: `forwarded`).
   */
  stream(contract: GateRequest, answerLimit: number, gated: boolean, fragments?: FragmentUse): StreamInspector;
  /**
   * What is held back of a non-streaming answer to `contract` while it passes, or null when the gate
   * holds nothing of it (audit and off modes: their findings are recorded at the end).
   */
  answer(contract: GateRequest, protocol: Protocol, answerLimit: number): AnswerInspector | null;
  /** A non-streaming answer (`body` its native JSON, or its projection), before it is billed. */
  inspectResponse(contract: GateRequest, answer: { readonly protocol: Protocol; readonly body: Json }, answerLimit: number): GateVerdict;
}

const NO_REPAIRS: ReadonlySet<bigint> = new Set();

const OPEN_INSPECTOR: StreamInspector = Object.freeze({
  holdsToolCalls: false,
  observe: () => CLEAN,
  releasable: () => true,
  finish: () => CLEAN,
  fragmentRepairs: () => NO_REPAIRS,
  retainedBytes: () => 0,
});

/** Lets everything through and holds nothing (tests that are not about the gate). */
export const PASS_THROUGH: ToolGate = Object.freeze({
  mode: "off",
  inspectRequest: () => CLEAN,
  contract: (request: GateRequest) => request,
  holdsToolCalls: () => false,
  stream: () => OPEN_INSPECTOR,
  answer: () => null,
  inspectResponse: () => CLEAN,
});
