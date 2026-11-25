import { ReceiptBuilder, StackEventsChain, type SignedReceipt } from "@gray/attest";
import type { GatewayConfig } from "@gray/config";
import { ApiError, ERROR_BODY_WAIT_MS, isErrorBody } from "@gray/errors";
import { isObject, parseStrictBytes, readSerdeBytes, toJsonString, type Json } from "@gray/json";
import { stackBodyDigest, StackEventDigester, type LaneProtocol } from "@gray/lane";
import {
  encodePeerFrame,
  encodePeerRefusal,
  fitStackTrace,
  laneReportedUsageDtoOf,
  PEER_CHECKS_WORDS,
  PEER_COMMENT,
  PEER_FRAME_MAX_BYTES,
  PEER_GATE_REFUSED,
  PEER_REFUSAL_STATUS,
  peerErrorHeadersOf,
  peerReadsOf,
  stackTraceDtoOf,
  type PeerEndDto,
  type PeerEnvelopeDto,
  type PeerErrorHeadersDto,
  type PeerRefusalCode,
  type StackTraceDto,
} from "@gray/lane-wire";
import { safeUsageCounters } from "@gray/ledger-keys";
import { type AnswerChecks, bufferedUsage, COUNT_REPLY_LIMIT, countReply, countTarget, inspectedCountRequest, parseResponse, UNCOUNTED_CHECKS } from "@gray/protocol";
import { AnswerRelay, keepsAnswerText } from "../answer.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence, ClientStream, errorFrame, type StreamTimers } from "../client.ts";
import type { FragmentUse, StreamInspector, ToolGate } from "../gate.ts";
import { PASS_THROUGH, refusedAnswerChecks } from "../gate.ts";
import { parseHeld, type ParsedRequest } from "../parse.ts";
import { primeStream, relayStream } from "../relay.ts";
import { countedChecks } from "../sinks.ts";
import { AnswerShare, Retained } from "../retained.ts";
import { completedResponse } from "./codex.ts";
import { bodyHashOf, responseHash } from "./hooks.ts";
import { PeerAttempts, type PeerState } from "./peer.ts";
import {
  addStackReceipt,
  LANE_RELAY_FAILED,
  newStackRid,
  reportViolation,
  StackCall,
  stackClientHeaders,
  stackRawQuery,
  stackRelayHeaders,
  stackRewriteSpec,
  stackTraceOf,
  type StackOutcome,
  type StackReturned,
} from "./stack.ts";
import type { StackRelayConfig, StackRelayRoute, StackViolationFound } from "./stack-config.ts";
import { DEBUG_ANSWER_CAPTURE_MAX_BYTES } from "./stack-debug.ts";
import type { CapturedCall } from "./stack-debug-record.ts";
import { stackRequestBody } from "./stack-rewrite.ts";
import type { LaneState, StackTransport } from "./types.ts";

/**
 * A stack VM's backend mode (docs/confidential-lane-stack-routing.md section 4.5): a request an entry forwarded over
 * the peer hop, its envelope checked (`peer.ts`, checks 1 to 5), runs the S23 attempt exactly as the stack VM runs
 * one for a direct client, and answers in PR 2's frames (`@gray/lane-wire` peer.ts). It reads no snapshot and makes
 * no admission, permit, settle or record call (L3): money and records are the entry's, from the `end` frame.
 *
 * The attempt is the direct path's own pieces, in the order `InferenceRun` uses them for a stack route, so what a
 * direct client would have been written is what the `data` frames carry, byte for byte (L6):
 *
 * - `StackCall` registers the rid at egress, calls the relay's container and releases what the feed records (S23,
 *   S24); its outcome when nothing can be released decides `vendor_error`, `relay_failed` or `not_dialed` (S25);
 * - a stream is primed to its commit (`primeStream`) and relayed (`relayStream`) through a `ClientStream`, with the
 *   lane's trust gate, the null rule and the terminal check; Gray's error frame ends a stream cut after release;
 * - a buffered answer passes through `AnswerRelay`; a buffered Codex request is answered the terminal event's
 *   `response` (`completedResponse`, D129).
 *
 * What differs from the direct path is only what is not the attempt's: the stream relay's `settle` records the usage
 * the vendor reported instead of charging it (the `end` frame's `usage`, `safe_usage_counters`' counters), the answer
 * limit is ANSWER_HELD_MAX_BYTES (the hold that sizes it is the entry's), and the client is the hop: no keep-alive is
 * written into the bytes, the hop has its own comment from the moment the answer opens (egress's silence bound runs
 * from the connection, PR 3), and a hop that closes is a client that left with no read-on window (the entry has gone,
 * so nothing is read on for it).
 *
 * The inner receipt is the S26 v2 receipt of the attempt with `peer.entry` right after `request.received` (section
 * 4.8), signed with this boot's receipt key; it goes in `end` and stays in the attempts table for the late follow-up.
 *
 * The attempt's two answer checks (docs/error-rates.md, r14) go in `end.checks` to an entry that named `checks` in
 * `x-gray-peer-reads`: the entry gets no byte of an answer refused here, so they are the attempt's only reading. They are
 * read where `InferenceRun` reads a direct client's: a stream's once as the relay ends it (relay.ts `StreamEnd.checks`),
 * its priming's not finished when it failed before its commit, a buffered answer's from `ToolGate.responseChecks` (its
 * text whole when its structured output is checked, `keepsAnswerText`) or from the call check that refused it on the
 * way, a Codex request's from its terminal response or its stream's inspector; and they count nothing where the stack
 * VM ended the answer itself (sinks.ts `countedChecks`: its hold limits and own failures, its deadline, the entry gone).
 * What the vendor's answer was for the attempt's record (its error's class) is the entry's, which counts the checks
 * again by its record of the attempt.
 */

/** The hop comment's cadence while nothing else is written (section 4.5: every 15 s; egress's silence bound is 45 s). */
export const PEER_COMMENT_MS = 15_000;

/** The route an envelope names, from the stack configuration alone (section 4.5 check 6), or why there is none. */
export function backendRouteOf(config: StackRelayConfig, envelope: PeerEnvelopeDto, protocol: LaneProtocol): StackRelayRoute | null {
  if (envelope.route.protocol !== protocol) return null;
  return config.routes.find((route) => route.protocol === protocol && route.requested_model === envelope.route.model) ?? null;
}

/** A refusal before any frame: `{code, dialed: false}` with its status. */
export function peerRefusal(code: PeerRefusalCode): Response {
  return new Response(encodePeerRefusal(code), { status: PEER_REFUSAL_STATUS[code], headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

export interface BackendInput {
  readonly request: Request;
  readonly protocol: LaneProtocol;
  /** The client path the entry forwarded (`/v1/messages`, ...): the receipt's `endpoint`. */
  readonly path: string;
  readonly envelope: PeerEnvelopeDto;
  /** The client's exact bytes (check 5 held them to `received_sha256`). */
  readonly body: Uint8Array;
  /** True for Anthropic `/v1/messages/count_tokens`. */
  readonly countTokens?: boolean;
  readonly cfg: GatewayConfig;
  readonly state: Pick<LaneState, "receiptKey" | "receiptKeyId" | "keysetDigest">;
  readonly relayImage: string | null;
  readonly config: StackRelayConfig | null;
  readonly transport: StackTransport | undefined;
  readonly peer: PeerState;
  readonly gate: ToolGate;
  /** The isolate's answer pool share of this request (`IsolateLoad.answers.share()`). */
  readonly share: AnswerShare;
  readonly clock: () => number;
  readonly timers: StreamTimers;
  readonly waitUntil: (promise: Promise<unknown>) => void;
  /** Where a closed call's non-compliant change goes (`StackRelayConfigProvider.violation`, docs/design/relay-ejection.md). */
  readonly violation?: (found: StackViolationFound) => void;
  /**
   * The stack VM's debug store (docs/design/relay-debug-sharing.md §2): what Gray's programs saw of the call, once it
   * ended. Present, the call asks egress for its forwarded bodies too. Absent (a VM that shares nothing): neither.
   */
  readonly debug?: (call: CapturedCall) => void;
}

/** How the attempt ended, for `end`. */
interface Ended {
  readonly outcome: PeerEndDto["outcome"];
  readonly code: PeerEndDto["code"];
}

/**
 * Serves one enveloped request: check 6, then the SSE answer, opened at once with the hop comment, its frames written
 * as the attempt goes. A refusal of check 6 is the 4xx before any frame; everything after it is frames.
 */
export function serveBackend(input: BackendInput): Response {
  const { envelope, config } = input;
  const route = config === null ? null : backendRouteOf(config, envelope, input.protocol);
  if (config !== null && route === null) return peerRefusal("route_unconfigured");
  const key = PeerAttempts.key(envelope);
  input.peer.attempts.take(key, input.clock());
  const hop = new HopStream(input.timers, input.clock);
  const run = new BackendRun(input, route, key, hop);
  input.waitUntil(run.run());
  return new Response(hop.readable, { status: 200, headers: { "content-type": "text/event-stream", "cache-control": "no-store" } });
}

/**
 * The hop's answer stream: frames as they come, `PEER_COMMENT` while nothing was written for PEER_COMMENT_MS, the
 * comment first of all so egress's silence bound starts its count at once. Its cancel is the entry leaving.
 */
class HopStream {
  readonly readable: ReadableStream<Uint8Array>;
  #controller!: ReadableStreamDefaultController<Uint8Array>;
  #closed = false;
  #lastWrite: number;
  #interval: unknown;
  #pulled: (() => void) | null = null;
  readonly #left = new Set<() => void>();
  readonly #timers: StreamTimers;
  readonly #clock: () => number;

  constructor(timers: StreamTimers, clock: () => number) {
    this.#timers = timers;
    this.#clock = clock;
    this.#lastWrite = clock();
    this.readable = new ReadableStream<Uint8Array>(
      {
        start: (controller) => {
          this.#controller = controller;
        },
        pull: () => {
          const resolve = this.#pulled;
          this.#pulled = null;
          resolve?.();
        },
        cancel: () => this.#leave(),
      },
      { highWaterMark: 4 * PEER_FRAME_MAX_BYTES, size: (chunk: Uint8Array) => chunk.byteLength },
    );
    this.#enqueue(PEER_COMMENT);
    this.#interval = timers.setInterval(() => {
      if (this.#closed) return;
      if (this.#clock() - this.#lastWrite >= PEER_COMMENT_MS) this.#enqueue(PEER_COMMENT);
    }, PEER_COMMENT_MS / 3);
  }

  /** Calls `listener` when the entry leaves (the hop closed under the answer). */
  onLeave(listener: () => void): void {
    this.#left.add(listener);
  }

  #leave(): void {
    this.#finish();
    for (const listener of [...this.#left]) listener();
    this.#left.clear();
  }

  #enqueue(bytes: Uint8Array): boolean {
    if (this.#closed) return false;
    try {
      this.#controller.enqueue(bytes);
      this.#lastWrite = this.#clock();
      return true;
    } catch {
      this.#leave();
      return false;
    }
  }

  /** One frame, waiting while the hop's queue is full (the entry reads at its client's pace). */
  async write(frame: Uint8Array): Promise<boolean> {
    if (!this.#enqueue(frame)) return false;
    const size = this.#controller.desiredSize;
    if (size !== null && size <= 0 && !this.#closed) await new Promise<void>((resolve) => (this.#pulled = resolve));
    return !this.#closed;
  }

  close(): void {
    if (this.#closed) return;
    this.#finish();
    try {
      this.#controller.close();
    } catch {
      // The entry already left.
    }
  }

  #finish(): void {
    this.#closed = true;
    this.#timers.clearInterval(this.#interval);
    const resolve = this.#pulled;
    this.#pulled = null;
    resolve?.();
  }
}

class BackendRun {
  readonly #input: BackendInput;
  readonly #route: StackRelayRoute | null;
  readonly #key: string;
  readonly #hop: HopStream;
  /** The entry left (the hop closed): the attempt's client is gone, with nothing read on for it. */
  readonly #presence: ClientPresence;
  readonly #retained = new Retained();
  /** What the client was written: every byte for `body_hash`, a stream's S19 chain or a body's bytes (S26). */
  readonly #hash = responseHash();
  readonly #digester = new StackEventDigester();
  readonly #chain = new StackEventsChain();
  readonly #body: Uint8Array[] = [];
  /** The client's bytes for the debug capture, up to DEBUG_ANSWER_CAPTURE_MAX_BYTES, and how many were written. */
  readonly #captured: Uint8Array[] = [];
  #capturedBytes = 0;
  #writtenBytes = 0;
  #stream = false;
  /**
   * Whether what the client is written is an event stream: the head's `stream` once it is written. The request's
   * `stream` says only what the client asked for: a streamed request the vendor answered with an error gets that
   * error's body (`vendor_error`), whose digest the receipt ties to the vendor's (S32), not its events.
   */
  #answerStream = false;
  #headed = false;
  #status = 502;
  #replacedError = false;
  #grayBody = false;
  #leftAnswered: boolean | null = null;
  #undelivered = false;
  #rawUsage: Json | null = null;
  #call: StackCall | null = null;
  /** The entry named `checks` in `x-gray-peer-reads`: its `end` reads them (an entry before r14 refuses them). */
  readonly #readsChecks: boolean;
  /** The entry named `receipt_refused`: it reads a dialed attempt's `end` without a receipt, and why. */
  readonly #readsReceiptRefused: boolean;
  /** The entry named `vendor_event`: it reads the vendor's own error event that ended an answer before the commit. */
  readonly #readsVendorEvent: boolean;
  /** The entry named `error_headers`: it reads allowlisted vendor error response headers on a non-200 `head`. */
  readonly #readsErrorHeaders: boolean;
  /** The entry named `relay_status`: it reads the container's own error status on a token count not dialed. */
  readonly #readsRelayStatus: boolean;
  /** The entry named `gate_refused`: it reads `PEER_GATE_REFUSED` as the code of an answer the gate refused before the commit. */
  readonly #readsGateRefused: boolean;
  /** The entry named `gate_cut`: it reads `PEER_GATE_REFUSED` as the code of an answer the gate refused after the commit. */
  readonly #readsGateCut: boolean;
  /** The vendor's own error event that ended its stream before the commit (`primeStream`'s `event`), as it came. */
  #vendorEvent: Json | null = null;
  /** Why the receipt was not signed (a closed word, `receiptProblem`), once `#receipt` failed. */
  #receiptRefused: string | null = null;
  /** The gate's reading of the answer, once a path made it: none until then. */
  #checks: AnswerChecks = UNCOUNTED_CHECKS;
  /** How the stack VM itself ended the answer, for `countedChecks`: its own limit or failure, the entry gone, its deadline. */
  #ownEnd: "gray_error" | "client_left" | null = null;
  #deadlineCut = false;

  constructor(input: BackendInput, route: StackRelayRoute | null, key: string, hop: HopStream) {
    this.#input = input;
    this.#route = route;
    this.#key = key;
    this.#hop = hop;
    const reads = peerReadsOf(input.request.headers);
    this.#readsChecks = reads.has("checks");
    this.#readsReceiptRefused = reads.has("receipt_refused");
    this.#readsVendorEvent = reads.has("vendor_event");
    this.#readsErrorHeaders = reads.has("error_headers");
    this.#readsRelayStatus = reads.has("relay_status");
    this.#readsGateRefused = reads.has("gate_refused");
    this.#readsGateCut = reads.has("gate_cut");
    this.#presence = new ClientPresence(null, input.clock, 0);
    hop.onLeave(() => this.#presence.leave("client_left"));
    this.#presence.onLeave(() => {
      this.#leftAnswered ??= this.#chain.count() > 0 || this.#body.some((chunk) => chunk.length > 0);
    });
  }

  async run(): Promise<void> {
    let ended: Ended;
    try {
      ended = await this.#attempt();
    } catch (error) {
      // A failure of the lane's own (a bug): whatever was released ends with Gray's error, as `InferenceRun.relayed`'s.
      console.error(JSON.stringify({ level: "error", event: "lane_backend_failed", rid: this.#input.envelope.rid, error: error instanceof Error ? error.name : "error" }));
      const dialed = (this.#call?.feed.dialed().length ?? 0) > 0;
      ended = { outcome: !dialed ? "not_dialed" : this.#headed && this.#status === 200 ? "cut" : "relay_failed", code: "entry_internal" };
      this.#replacedError = true;
      this.#ownEnd = "gray_error";
      if (ended.outcome === "cut" && this.#stream) await this.#data(errorFrame(this.#input.protocol, "internal_error", 0n));
    }
    const call = this.#call;
    // The rid ends at egress and the feed is read through `done` before the receipt is written (S26).
    await call?.close();
    if (call !== null) reportViolation(call, this.#input.violation, this.#input.envelope.rid);
    const receipt = call === null ? null : await this.#receipt(call, ended);
    // The trace goes with the attempt's facts too: an entry that let go of the hop before `end` asks the follow-up for it.
    const trace = this.#trace(call);
    this.#input.peer.attempts.done(this.#key, receipt === null ? null : receiptDocument(receipt), trace);
    if (call !== null) this.#capture(call, ended);
    if (!this.#headed) await this.#head(this.#status, false);
    let frame: Uint8Array | null = null;
    try {
      frame = encodePeerFrame({ event: "end", end: this.#end(call, ended, receipt, trace) });
    } catch (error) {
      // An `end` the wire refuses (a dialed attempt whose receipt could not be signed, to an entry that does not read
      // `receipt_refused`): the hop ends without it, which the entry reads as a broken answer (after its commit,
      // `upstream_stream_interrupted`), with no inner receipt, trace or attempt row (production 2026-11-19/20).
      console.error(JSON.stringify({ level: "error", event: "lane_backend_end_refused", rid: this.#input.envelope.rid, error: error instanceof Error ? error.name : "error" }));
    }
    if (frame !== null) await this.#hop.write(frame);
    this.#hop.close();
  }

  /**
   * The call's debug capture (docs/design/relay-debug-sharing.md §2): the client's request as the entry forwarded it,
   * egress's records of the rid's calls, and what the client was written. Diagnostics: a capture that fails is logged
   * and left out, never the answer's concern.
   */
  #capture(call: StackCall, ended: Ended): void {
    const input = this.#input;
    if (input.debug === undefined) return;
    try {
      const headers: Record<string, string> = stackClientHeaders(input.request.headers, input.protocol);
      const answer = new Uint8Array(this.#capturedBytes);
      let at = 0;
      for (const chunk of this.#captured) {
        answer.set(chunk, at);
        at += chunk.length;
      }
      input.debug({
        rid: call.rid,
        startedAt: call.startedAt,
        protocol: input.protocol,
        path: input.path,
        query: stackRawQuery(input.request.url),
        headers,
        body: input.body,
        attempts: [...call.feed.attempts.values()].sort((left, right) => left.n - right.n),
        answer: { status: this.#status, stream: this.#answerStream, outcome: ended.outcome, code: ended.code, servedAttempt: call.served?.n ?? null, bytes: answer, size: this.#writtenBytes },
      });
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_debug_capture_failed", rid: input.envelope.rid, error: error instanceof Error ? error.name : "error" }));
    }
  }

  /** The `end` frame, held to `peerEndSchema`'s rules by its outcome. */
  #end(call: StackCall | null, ended: Ended, receipt: SignedReceipt | null, trace: StackTraceDto | null): PeerEndDto {
    const dialed = ended.outcome !== "not_dialed";
    const attempts = call?.feed.dialed() ?? [];
    const served = ended.outcome === "served" || ended.outcome === "vendor_error" || ended.outcome === "cut" ? (call?.served?.n ?? attempts.at(-1)?.n ?? null) : null;
    const usage = this.#rawUsage === null ? null : peerUsageOf(this.#rawUsage);
    const vendorEvent = this.#vendorEvent;
    return {
      outcome: ended.outcome,
      dialed,
      served_attempt: served === null ? null : BigInt(served),
      // Egress's calls for the rid (its `n` counts each one, refused or dialed), so `served_attempt` is one of them.
      attempts: dialed ? BigInt(call?.feed.attempts.size ?? 0) : 0n,
      // The served attempt's account (S61), as `served_attempt` names it and a local stack attempt's `accountId` reads it;
      // the last dialed attempt's when none was served.
      relay_account_id: dialed ? (call?.served?.accepted?.accountId ?? attempts.at(-1)?.accepted?.accountId ?? null) : null,
      usage: dialed ? usage : null,
      code: ended.code,
      receipt: receipt === null ? null : (receiptDocument(receipt) as Record<string, unknown>),
      ...(trace === null ? {} : { trace }),
      ...(this.#readsChecks ? { checks: this.#endChecks(ended) } : {}),
      // A dialed attempt without its receipt: why, to an entry that reads it, which then still has the attempt's outcome,
      // usage and trace (an older entry gets no `end`: `run`).
      ...(dialed && receipt === null && this.#readsReceiptRefused ? { receipt_refused: this.#receiptRefused ?? "receipt_failed" } : {}),
      // The vendor's error that ended the answer before the commit, to an entry that reads it; one past VENDOR_EVENT_MAX_BYTES
      // (no vendor error is) goes without it, and the entry answers as before.
      ...(ended.outcome === "relay_failed" && this.#readsVendorEvent && isObject(vendorEvent) && toJsonString(vendorEvent).length <= VENDOR_EVENT_MAX_BYTES
        ? { vendor_event: vendorEvent as Record<string, unknown> }
        : {}),
      // A token count the container answered with an error of its own before any vendor call: its status, to an entry that
      // reads it, which takes 404, 405 and 501 for a container without a count path (relay standard section 2).
      ...(this.#input.countTokens === true && ended.outcome === "not_dialed" && ended.code === "relay_error_status" && call?.relayStatus !== null && call?.relayStatus !== undefined && this.#readsRelayStatus
        ? { relay_status: BigInt(call.relayStatus) }
        : {}),
    };
  }

  /**
   * The attempt's checks for `end`: the gate's reading, counted as `InferenceRun` counts a direct client's attempt
   * (sinks.ts `countedChecks`) where the stack VM or its egress ended the answer itself, in the words the entry's `checks` names
   * (`PEER_CHECKS_WORDS`: a word of a later list goes as null, review r14 finding 1).
   */
  #endChecks(ended: Ended): NonNullable<PeerEndDto["checks"]> {
    // Egress is Gray's process: an answer it cut at its budget (`feed.limited`, a fault by egress) is Gray's hold limit, and
    // a fault of Gray's own (its ending of the rid: `timeout`, `entry_closed`) is Gray's too, on every path alike (review
    // r14 blocker 7). A fault of the relay's container stands as the main gateway counts a stack route's.
    const call = this.#call;
    const fault = call?.fault ?? null;
    const gray = (call !== null && call.feed.limited !== null) || fault?.by === "egress" || fault?.by === "gray";
    const counted = countedChecks(this.#checks, { outcome: gray ? "gray_error" : (this.#ownEnd ?? ended.outcome), code: ended.code, rejected: false, deadlineCut: this.#deadlineCut });
    const tool = counted.toolCallCheck;
    const output = counted.outputCheck;
    return {
      tool_call_check: tool !== null && (PEER_CHECKS_WORDS.tool_call_check as readonly string[]).includes(tool) ? (tool as NonNullable<PeerEndDto["checks"]>["tool_call_check"]) : null,
      output_check: output !== null && (PEER_CHECKS_WORDS.output_check as readonly string[]).includes(output) ? (output as NonNullable<PeerEndDto["checks"]>["output_check"]) : null,
    };
  }

  /**
   * The call's S43 trace for `end`, its offsets from the call's start (the entry moves them to its request's), within
   * S43's bounds. Null without a call; a trace that cannot be built (a defect of the lane's own) is left out and logged,
   * as `InferenceRun.withStackTrace` leaves it out of a direct client's row: the trace is diagnostics, `end` is the answer.
   */
  #trace(call: StackCall | null): StackTraceDto | null {
    const relayId = this.#input.config?.relayId ?? null;
    if (call === null || relayId === null) return null;
    try {
      const trace = stackTraceOf({ relayId, requestStart: call.startedAt, calls: [call] });
      return trace === null ? null : stackTraceDtoOf(fitStackTrace(trace));
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_stack_trace_failed", rid: this.#input.envelope.rid, error: error instanceof Error ? error.name : "error" }));
      return null;
    }
  }

  /** The attempt (S23): planned from the configuration, sent, its answer released into frames. */
  async #attempt(): Promise<Ended> {
    const input = this.#input;
    const { cfg, envelope, clock } = input;
    if (input.config === null) return { outcome: "not_dialed", code: "config_unready" };
    if (input.transport === undefined) return { outcome: "not_dialed", code: "no_relay_binding" };
    const route = this.#route!;
    const protocol = input.protocol;
    const isCount = input.countTokens === true;
    let parsed: ParsedRequest | null = null;
    let bodyValue: Json;
    let stripModels = false;
    let stream = false;
    if (isCount) {
      if (protocol !== "anthropic_messages") return { outcome: "not_dialed", code: "protocol" };
      let read: ReturnType<typeof readSerdeBytes>;
      try {
        read = readSerdeBytes(input.body);
      } catch {
        return { outcome: "not_dialed", code: "protocol" };
      }
      if (read.duplicateKeys || !isObject(read.value)) return { outcome: "not_dialed", code: "protocol" };
      const rawModel = countTarget(protocol, input.path, read.value);
      if (rawModel === undefined) return { outcome: "not_dialed", code: "protocol" };
      try {
        inspectedCountRequest(protocol, rawModel, read.value);
      } catch {
        return { outcome: "not_dialed", code: "protocol" };
      }
      bodyValue = read.value;
    } else {
      // The entry parsed these bytes before it forwarded them; a body that does not parse here is refused before egress.
      const held = parseHeld(protocol, "A", input.body, null);
      if (held instanceof ApiError) return { outcome: "not_dialed", code: "protocol" };
      parsed = held;
      bodyValue = held.value;
      stripModels = held.strip;
      stream = held.canonical.stream;
    }
    this.#stream = stream;
    // What the relay's container is sent (relay standard v1.7): the entry forwarded the client's bytes, and the required
    // changes are applied here, so the hop's `received_sha256` stays the client's.
    const body = stackRequestBody({ config: input.config, route, protocol, stream, received: input.body, value: bodyValue, stripModels });
    if (!body.ok) return { outcome: "not_dialed", code: body.code };
    const rid = newStackRid();
    const conversation = envelope.conversation;
    const started = clock();
    // Bounded by its own limits and by what the entry left of the request (section 4.5: `budget_ms`).
    const totalMs = isCount ? Math.min(cfg.nonStreamTotalMs, 120_000) : stream ? cfg.streamTotalSeconds * 1000 : cfg.nonStreamTotalMs;
    const deadline = Math.min(started + totalMs, started + Number(envelope.budget_ms));
    const controller = new AbortController();
    this.#presence.onLeave(() => controller.abort("client_left"));
    const timer = input.timers.setTimeout(() => controller.abort("attempt_deadline"), Math.max(0, deadline - clock()));
    const call = new StackCall({
      rid,
      endpointId: envelope.route.endpoint,
      protocol,
      received: input.body,
      forwarded: body.forwarded,
      query: stackRawQuery(input.request.url),
      // The client's own headers, as the entry passed them over the hop, under the same rule again.
      clientHeaders: stackClientHeaders(input.request.headers, protocol),
      vendor: route.vendor,
      // The customer's opt-out comes over the hop in the envelope (docs/relay-request-changes.md).
      rewrite: stackRewriteSpec({
        protocol,
        upstreamModel: route.upstream_model,
        route,
        stream,
        appends: input.config.appends,
        relayChanges: envelope.relay_changes !== "exclude",
        ...(isCount ? { countTokens: true } : {}),
      }),
      attemptsMax: input.config.limits.attempts_max,
      expiresAt: Math.ceil(deadline / 1000),
      headers: stackRelayHeaders(input.request.headers, protocol, input.config.inboundToken, rid, body.routeModel, conversation),
      egress: input.transport.egress,
      relay: input.transport.relay,
      // docs/design/relay-debug-sharing.md: egress writes each forwarded body into the feed for the debug capture.
      ...(input.debug === undefined ? {} : { captureForwarded: true }),
      ...(isCount ? { countTokens: true } : {}),
      signal: controller.signal,
      timers: input.timers,
      clock,
      holdMs: cfg.upstreamSilenceMs,
      settleMs: ERROR_BODY_WAIT_MS,
      queueMs: cfg.upstreamHeaderMs,
      answerMaxBytes: isCount ? COUNT_REPLY_LIMIT : cfg.answerHeldMaxBytes,
      deleteBackoffMs: cfg.retryBackoffMs,
      deleteBackoffMaxMs: cfg.retryBackoffMaxMs,
    });
    this.#call = call;
    // S25 across the hop: the follow-up says `dialed` once the feed shows a vendor attempt.
    void (async () => {
      while (!call.feed.closed && call.feed.dialed().length === 0) await call.feed.changed;
      if (call.feed.dialed().length > 0) input.peer.attempts.dialed(this.#key);
    })();
    try {
      const sent = await call.send();
      if (sent.kind === "aborted") return this.#failed(call, await call.decided(), controller.signal.reason === "attempt_deadline");
      if (sent.kind === "failed") return this.#failed(call, sent.outcome, false);
      if (isCount) return await this.#countTokens(call, sent.response, deadline);
      if (stream) return await this.#relayStream(call, sent.response, deadline, parsed!);
      if (protocol === "open_ai_responses" && route.vendor === "chatgpt_codex") return await this.#codex(call, sent.response, deadline, parsed!);
      return await this.#buffered(call, sent.response, deadline, parsed!);
    } finally {
      input.timers.clearTimeout(timer);
    }
  }

  /** A token-counting answer: bounded by COUNT_REPLY_LIMIT, validated by countReply, and JCS-tied to egress's digest. */
  async #countTokens(call: StackCall, response: Response, deadline: number): Promise<Ended> {
    const { clock, protocol, timers } = this.#input;
    const vendorBytes = await readBoundedWithin(response.body, COUNT_REPLY_LIMIT, deadline, clock, timers, this.#presence);
    if (this.#presence.gone) {
      this.#ownEnd = "client_left";
      return { outcome: call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    }
    if (vendorBytes === null) {
      call.served = null;
      this.#status = 502;
      this.#replacedError = true;
      this.#grayBody = true;
      return { outcome: "relay_failed", code: "body_mismatch" };
    }
    let counts: Json | undefined;
    try {
      counts = countReply(protocol, parseStrictBytes(vendorBytes));
    } catch {
      counts = undefined;
    }
    if (counts === undefined) {
      call.served = null;
      this.#status = 502;
      this.#replacedError = true;
      this.#grayBody = true;
      return { outcome: "relay_failed", code: "body_mismatch" };
    }
    const rebuilt = utf8Encoder.encode(toJsonString(counts));
    let digestMatches = false;
    try {
      digestMatches = stackBodyDigest(vendorBytes) === stackBodyDigest(rebuilt);
    } catch {
      digestMatches = false;
    }
    if (!digestMatches) {
      call.served = null;
      this.#status = 502;
      this.#replacedError = true;
      this.#grayBody = true;
      return { outcome: "relay_failed", code: "body_mismatch" };
    }
    this.#rawUsage = null;
    await this.#head(200, false);
    await this.#data(rebuilt);
    return { outcome: "served", code: null };
  }

  /** A call whose answer was not released (S24, S25): the vendor's error is the answer; otherwise the entry's to render. */
  async #failed(call: StackCall, outcome: StackOutcome, timedOut: boolean): Promise<Ended> {
    const fault = call.fault;
    if (outcome.kind === "not_dialed") {
      // Nothing of the container's reaches the client: its answer is the entry's (another route, or Gray's error).
      this.#replacedError = true;
      this.#grayBody = true;
      return { outcome: "not_dialed", code: fault?.why ?? "relay_transport" };
    }
    if (outcome.kind === "vendor_error") {
      const headers = this.#readsErrorHeaders ? peerErrorHeadersOf(outcome.headers) : undefined;
      await this.#head(outcome.status, false, headers);
      // The vendor's error is the served attempt's answer, tied by its body digest (S32), not a replacement.
      await this.#data(outcome.body);
      return { outcome: "vendor_error", code: null };
    }
    const limited = call.feed.limited !== null;
    // What a direct client would be answered: Gray's own 502 (`lane_relay_failed`, or `upstream_unavailable` when the
    // attempt's bound ended it); the entry renders it.
    this.#status = 502;
    this.#replacedError = true;
    this.#grayBody = true;
    return { outcome: "relay_failed", code: limited ? "egress_limit" : (fault?.why ?? (timedOut ? "timeout" : "relay_transport")) };
  }

  /**
   * An answer that failed before it committed (S25): the feed settles first, then decides; nothing of it was written.
   *
   * `gateRefused`: the lane's trust gate refused the vendor's answer. A vendor was dialed, so the request ends here, and
   * its error is the request's own, `upstream_trust_policy_rejected`, as `InferenceRun.stackFailed` ends a local stack
   * attempt's: `end.code` says so (`PEER_GATE_REFUSED`) in place of `relay_transport`, which the entry reads as the
   * relay's failure. A fault of the relay's container or egress's cut at its budget keeps its own code, as it does there.
   * Only to an entry that reads it (`gate_refused`): an older entry's strict `end` refuses a code it does not know.
   */
  async #uncommitted(call: StackCall, gateRefused = false): Promise<Ended> {
    const outcome = await call.failedAfterAnswer();
    if (outcome.kind !== "vendor_error") call.served = null;
    const ended = await this.#failed(call, outcome, false);
    const fault = call.fault;
    const relayFault = fault?.by === "relay" || fault?.by === "egress" || call.feed.limited !== null;
    return gateRefused && this.#readsGateRefused && ended.outcome === "relay_failed" && !relayFault ? { ...ended, code: PEER_GATE_REFUSED } : ended;
  }

  /**
   * An answer cut after its commit, part of it released: `code` its own (`entry_internal` when none). `gateRefused`: the
   * lane's trust gate refused a later part of it, which the entry ends the client's stream with as a local stack attempt's
   * (`upstream_trust_policy_rejected`), not as the upstream's broken stream: `end.code` says so (`PEER_GATE_REFUSED`)
   * when no fault of the call (the relay's container, egress, its budget) has a word of its own, which stands.
   * Only to an entry that reads it (`gate_cut`): an entry before it refuses that code on a `cut` end.
   */
  #cut(call: StackCall, gateRefused: boolean, code: Ended["code"] = call.fault?.why ?? "entry_internal"): Ended {
    const faulted = call.fault !== null || call.feed.limited !== null;
    return { outcome: "cut", code: gateRefused && this.#readsGateCut && !faulted ? PEER_GATE_REFUSED : code };
  }

  /** A stream (S24 released events), primed to its commit and relayed as `InferenceRun.relay` relays one. */
  async #relayStream(call: StackCall, response: Response, deadline: number, parsed: ParsedRequest): Promise<Ended> {
    const { cfg, clock, protocol } = this.#input;
    const fragments: FragmentUse = protocol === "open_ai_responses" ? "repaired" : "forwarded";
    // The lane's trust gate over the request as it keeps it after admission, as `InferenceRun.prime` and `openStream` build
    // it: one inspector for the priming, a fresh one for the relay, which inspects the same frames again from the start.
    const contract = this.#input.gate.contract({ request: parsed.canonical, body: parsed.value });
    const inspector = (): StreamInspector => {
      try {
        return this.#input.gate.stream(contract, Number.MAX_SAFE_INTEGER, false, fragments);
      } catch {
        // The gate's failure is Gray's own, found again by the relay (`InferenceRun.prime`).
        return PASS_THROUGH.stream(contract, Number.MAX_SAFE_INTEGER, false);
      }
    };
    const primer = inspector();
    const primed = await primeStream({
      protocol,
      response,
      presence: this.#presence,
      inspector: primer,
      answerLimit: Number.MAX_SAFE_INTEGER,
      frameLimit: cfg.answerHeldMaxBytes,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      clock,
      retained: this.#retained,
      isolate: this.#input.share,
      heldLimit: cfg.answerHeldMaxBytes,
    });
    if (primed.kind === "left") {
      this.#ownEnd = "client_left";
      return { outcome: call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    }
    if (primed.kind === "gray") this.#ownEnd = "gray_error";
    if (primed.kind === "uncommitted") {
      // It failed before its commit, so before its finish: its checks are its priming's inspector's, the only one that
      // read it (`InferenceRun.prime`).
      this.#checks = primer.checks(false);
      if (primed.cutByDeadline === true) this.#deadlineCut = true;
    }
    // The vendor's own error event before the commit (an Anthropic `error` after `message_start`): nothing was released,
    // and the entry answers it as the vendor's error, as the main gateway answers an upstream's in-band error (`end`).
    if (primed.kind === "uncommitted" && primed.event !== null) this.#vendorEvent = primed.event;
    if (primed.kind !== "committed") return this.#uncommitted(call, primed.kind === "uncommitted" && primed.violation !== undefined);
    await this.#head(200, true);
    const client = new ClientStream(this.#presence, clock, cfg.streamClientStallMs, undefined, (bytes) => this.#tap(bytes), this.#input.timers);
    const pumped = this.#pump(client.readable);
    const end = await relayStream({
      protocol,
      body: response.body!,
      primed,
      client,
      presence: this.#presence,
      inspector: inspector(),
      stage: null,
      tap: null,
      answerLimit: Number.MAX_SAFE_INTEGER,
      frameLimit: cfg.answerHeldMaxBytes,
      heldLimit: cfg.answerHeldMaxBytes,
      isolate: this.#input.share,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      clock,
      outputLimit: { maxOutputTokens: undefined, allowance: 0n, candidateCount: 1 },
      // The usage is the entry's to charge (`end.usage`): recorded here, never charged.
      settle: async (_settlement, _usage, rawUsage) => {
        this.#rawUsage = rawUsage;
        return { ok: true };
      },
      upstreamDone: () => {},
      sink: null,
      retained: this.#retained,
      onFirstContent: () => {},
      drainMs: 0,
      stalledEnd: errorFrame(protocol, "client_read_timeout", 0n),
    });
    // The answer's checks as the relay read them once the stream ended (`InferenceRun.relay`).
    this.#checks = end.checks;
    if (end.kind === "settled") {
      await pumped;
      if (!end.delivered) this.#undelivered = true;
      return { outcome: "served", code: null };
    }
    if (end.kind === "client_left") {
      this.#ownEnd = "client_left";
      client.end();
      await pumped;
      return { outcome: "cut", code: "attempt_ended" };
    }
    // A failure of none of the vendor's doing is Gray's own, and Gray's deadline cut the answer (`InferenceRun.relay`).
    if (end.supplierFailure === null) this.#ownEnd = "gray_error";
    if (end.cutByDeadline === true) this.#deadlineCut = true;
    // S24: a container whose answer stopped matching the feed, or egress's cut at its budget, ends the stream with
    // the lane's own error; a vendor stream that was cut keeps the relay's own code.
    const fault = call.fault;
    const code = fault !== null && (fault.by === "relay" || fault.by === "egress") ? LANE_RELAY_FAILED : end.code;
    client.end(errorFrame(protocol, code, 0n));
    this.#replacedError = true;
    await pumped;
    return this.#cut(call, end.code === PEER_GATE_REFUSED);
  }

  /** A buffered answer, passed through `AnswerRelay` as `InferenceRun.nativeAnswer` passes one. */
  async #buffered(call: StackCall, response: Response, deadline: number, parsed: ParsedRequest): Promise<Ended> {
    const { cfg, clock, protocol } = this.#input;
    if (response.body === null) return this.#uncommitted(call);
    let pumped: Promise<void> = Promise.resolve();
    const contract = this.#input.gate.contract({ request: parsed.canonical, body: parsed.value });
    const answerInspector = this.#input.gate.answer(contract, protocol, Number.MAX_SAFE_INTEGER);
    const relay = new AnswerRelay({
      protocol,
      body: response.body,
      presence: this.#presence,
      clock,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      answerLimit: Number.MAX_SAFE_INTEGER,
      heldLimit: cfg.answerHeldMaxBytes,
      isolate: this.#input.share,
      primeBytes: cfg.answerPrimeBytes,
      stallMs: cfg.streamClientStallMs,
      timers: this.#input.timers,
      drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
      inspector: answerInspector,
      // The structured output check reads the answer's text, which the projection keeps whole for it alone.
      wholeText: keepsAnswerText(this.#input.gate.mode, contract),
      retained: this.#retained,
      sink: null,
      tap: (bytes) => this.#tap(bytes),
      start: (stream) => {
        pumped = this.#head(200, false).then(() => this.#pump(stream));
      },
    });
    const read = await relay.read();
    if (read.kind === "client_left") {
      this.#ownEnd = "client_left";
      relay.abort(read.why);
      await pumped;
      return { outcome: relay.started ? "cut" : call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    }
    if (read.kind === "failed") {
      if (read.cutByDeadline === true) this.#deadlineCut = true;
      // A call the gate refused on the way: what refused it (`InferenceRun.nativeAnswer`).
      if (read.violation !== undefined) this.#checks = refusedAnswerChecks(answerInspector);
      // Gray's limits: the isolate's answers together, or one answer past ANSWER_HELD_MAX_BYTES.
      if (read.code === "gateway_capacity" || read.limitSource !== undefined) this.#ownEnd = "gray_error";
      if (!relay.started) {
        relay.abort(read.code);
        return this.#uncommitted(call, read.violation !== undefined);
      }
      relay.abort(read.code);
      this.#replacedError = true;
      await pumped;
      return this.#cut(call, read.violation !== undefined);
    }
    let answer;
    try {
      answer = parseResponse(protocol, read.projection);
    } catch {
      if (!relay.started) {
        relay.abort(isErrorBody(protocol, read.projection) ? "upstream_error" : "invalid_upstream_protocol");
        return this.#uncommitted(call);
      }
      relay.abort("invalid_upstream_protocol");
      this.#replacedError = true;
      await pumped;
      return { outcome: "cut", code: "entry_internal" };
    }
    // The gate's verdict on the whole answer, and a call it refused on the way (`InferenceRun.nativeAnswer`); the answer's
    // checks of the same request and projection (a text it cut, `textCut`, is the output check's `unknown`), whatever the
    // verdict, or what refused a call on the way.
    this.#checks = relay.refusedByGate !== undefined ? refusedAnswerChecks(answerInspector) : this.#input.gate.responseChecks(contract, { protocol, body: read.projection, textCut: read.textCut });
    if (!this.#input.gate.inspectResponse(contract, { protocol, body: read.projection }, Number.MAX_SAFE_INTEGER).ok || relay.refusedByGate !== undefined) {
      relay.abort("upstream_trust_policy_rejected");
      if (!relay.started) return this.#uncommitted(call, true);
      this.#replacedError = true;
      await pumped;
      return this.#cut(call, true, "entry_internal");
    }
    const raw = bufferedUsage(protocol, read.projection) ?? null;
    this.#rawUsage = isObject(raw) && answer.usage !== null ? raw : null;
    if (!relay.finish()) {
      // Gray's own: a tool-call id it could not account for.
      this.#ownEnd = "gray_error";
      relay.abort("tool_call_id_rewrite_incomplete");
      return relay.started ? { outcome: "cut", code: "entry_internal" } : this.#uncommitted(call);
    }
    const out = await relay.deliver();
    await pumped;
    if (!out.delivered) this.#undelivered = true;
    return { outcome: "served", code: null };
  }

  /** A buffered Codex request (D129): the terminal event's `response`, as `InferenceRun.codexAnswer` answers it. */
  async #codex(call: StackCall, response: Response, deadline: number, parsed: ParsedRequest): Promise<Ended> {
    const { cfg, clock, protocol } = this.#input;
    const contract = this.#input.gate.contract({ request: parsed.canonical, body: parsed.value });
    // The stream's inspector, for the checks of a stream that ends before its terminal event, gated as
    // `InferenceRun.codexAnswer` makes it (the whole stream is held for the client's one answer).
    let inspector: StreamInspector;
    try {
      inspector = this.#input.gate.stream(contract, Number.MAX_SAFE_INTEGER, true);
    } catch {
      inspector = PASS_THROUGH.stream(contract, Number.MAX_SAFE_INTEGER, false);
    }
    const read = await completedResponse({
      response,
      presence: this.#presence,
      answerLimit: Number.MAX_SAFE_INTEGER,
      frameLimit: cfg.answerHeldMaxBytes,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      drainMs: 0,
      clock,
      retained: this.#retained,
      isolate: this.#input.share,
      heldLimit: cfg.answerHeldMaxBytes,
      inspector,
    });
    if (read.kind === "left") {
      this.#ownEnd = "client_left";
      return { outcome: call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    }
    if (read.kind === "gray") this.#ownEnd = "gray_error";
    if (read.kind === "uncommitted") {
      // An inspector that failed while it was fed read nothing that counts (review r14 minor 12).
      this.#checks = read.inspectorFailed === true ? UNCOUNTED_CHECKS : inspector.checks(false);
      if (read.cutByDeadline === true) this.#deadlineCut = true;
    }
    if (read.kind !== "completed") return this.#uncommitted(call);
    try {
      parseResponse(protocol, read.response);
    } catch {
      return this.#uncommitted(call);
    }
    // The terminal response is the answer, as `InferenceRun.codexAnswer` reads its checks and enforces the gate verdict.
    this.#checks = this.#input.gate.responseChecks(contract, { protocol, body: read.response });
    if (!this.#input.gate.inspectResponse(contract, { protocol, body: read.response }, Number.MAX_SAFE_INTEGER).ok) {
      return this.#uncommitted(call, true);
    }
    const raw = bufferedUsage(protocol, read.response) ?? null;
    this.#rawUsage = isObject(raw) ? raw : null;
    await this.#head(200, false);
    await this.#data(read.bytes);
    return { outcome: "served", code: null };
  }

  /** Every byte the client is written, as `InferenceRun`'s lane tap hears it: the receipt's `response.returned`. */
  #tap(bytes: Uint8Array): void {
    this.#hash.update(bytes);
    this.#writtenBytes += bytes.length;
    if (this.#input.debug !== undefined && this.#capturedBytes < DEBUG_ANSWER_CAPTURE_MAX_BYTES) {
      const kept = bytes.slice(0, DEBUG_ANSWER_CAPTURE_MAX_BYTES - this.#capturedBytes);
      this.#captured.push(kept);
      this.#capturedBytes += kept.length;
    }
    if (this.#headed ? this.#answerStream : this.#stream) {
      for (const digest of this.#digester.write(bytes)) this.#chain.push(digest);
      return;
    }
    this.#body.push(bytes.slice());
  }

  async #head(status: number, stream: boolean, headers?: PeerErrorHeadersDto): Promise<void> {
    if (this.#headed) return;
    this.#headed = true;
    this.#status = status;
    this.#answerStream = stream;
    await this.#hop.write(encodePeerFrame({ event: "head", head: { status: BigInt(status), stream, ...(headers === undefined ? {} : { headers }) } }));
  }

  /** Bytes the client is written outside a `ClientStream` (a vendor error, a Codex answer, Gray's last frame). */
  async #data(bytes: Uint8Array): Promise<void> {
    this.#tap(bytes);
    for (let at = 0; at < bytes.length; at += PEER_FRAME_MAX_BYTES) {
      if (!(await this.#hop.write(encodePeerFrame({ event: "data", bytes: bytes.subarray(at, at + PEER_FRAME_MAX_BYTES) })))) return;
    }
  }

  /** The client's body as it is written: each chunk goes out as `data` frames, at the hop's pace. */
  async #pump(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    try {
      for (;;) {
        const read = await reader.read();
        if (read.done) return;
        for (let at = 0; at < read.value.length; at += PEER_FRAME_MAX_BYTES) {
          if (!(await this.#hop.write(encodePeerFrame({ event: "data", bytes: read.value.subarray(at, at + PEER_FRAME_MAX_BYTES) })))) {
            await reader.cancel().catch(() => {});
            return;
          }
        }
      }
    } catch {
      // The body was aborted (a buffered answer cut after it started): the frames so far are what went.
    }
  }

  /** The inner receipt (S26 v2, `peer.entry` after `request.received`), signed with this boot's receipt key. */
  async #receipt(call: StackCall, ended: Ended): Promise<SignedReceipt | null> {
    const input = this.#input;
    const { envelope } = input;
    const builder = new ReceiptBuilder({
      receiptId: `rcpt_${call.rid}`,
      chatId: null,
      model: envelope.route.model,
      workloadKeysetDigest: input.state.keysetDigest,
      endpoint: input.path,
      method: "POST",
      servedAt: BigInt(Math.floor(input.clock() / 1000)),
      ...(input.relayImage === null ? {} : { relayImage: input.relayImage }),
    });
    try {
      addStackReceipt(builder, {
        receivedHash: bodyHashOf(input.body),
        peerEntry: { keysetDigest: envelope.entry, receiptId: envelope.receipt_id, rid: envelope.rid, n: envelope.n },
        calls: [call],
        returned: this.#returned(call, ended),
      });
      return await builder.finalize(input.state.receiptKey, input.state.receiptKeyId);
    } catch (error) {
      // What the grammar refused, a closed word: `end` names it to an entry that reads it (`receipt_refused`).
      this.#receiptRefused = receiptProblem(error);
      console.error(JSON.stringify({ level: "error", event: "lane_backend_receipt_failed", rid: envelope.rid, error: error instanceof Error ? error.name : "error", problem: this.#receiptRefused }));
      return null;
    }
  }

  /** What `response.returned` says the client got (S26, S32), as `InferenceRun.stackReturned` says it. */
  #returned(call: StackCall, ended: Ended): StackReturned {
    const bodyHash = this.#hash.bodyHash();
    const status = this.#status;
    if (this.#leftAnswered === false) {
      return {
        bodyHash,
        status,
        eventsSha256: this.#stream ? new StackEventsChain().hex() : null,
        bodySha256: this.#stream ? null : stackBodyDigest(new Uint8Array(0)),
        replacedError: false,
        servedAs: "client_left",
        leftBeforeAnswer: true,
      };
    }
    const served = call.served !== null && !this.#replacedError;
    const left = this.#leftAnswered === true || this.#undelivered;
    if (this.#headed && this.#answerStream) {
      for (const digest of this.#digester.close()) this.#chain.push(digest);
      return { bodyHash, status, eventsSha256: this.#chain.hex(), bodySha256: null, replacedError: this.#replacedError, ...(served && left ? { servedAs: "client_left" as const } : {}) };
    }
    const length = this.#body.reduce((n, chunk) => n + chunk.length, 0);
    const body = new Uint8Array(length);
    let at = 0;
    for (const chunk of this.#body) {
      body.set(chunk, at);
      at += chunk.length;
    }
    return {
      bodyHash,
      status,
      eventsSha256: null,
      bodySha256: stackBodyDigest(body),
      replacedError: this.#replacedError,
      ...(this.#grayBody ? { grayErrorOnly: true } : {}),
      ...(served && left ? { servedAs: "client_left" as const } : served && call.streamed ? { servedAs: "codex_terminal_response" as const } : {}),
    };
  }
}

/** The largest vendor error event `end.vendor_event` carries: a vendor's in-band error is a few hundred bytes. */
const VENDOR_EVENT_MAX_BYTES = 16 * 1024;
const utf8Encoder = new TextEncoder();

/** Read a bounded non-stream reply within `deadline` and while `presence` stays open; null on overflow, error or timeout. */
async function readBoundedWithin(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  deadline: number,
  clock: () => number,
  timers: StreamTimers,
  presence: ClientPresence,
): Promise<Uint8Array | null> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let timedOut = false;
  const timer = timers.setTimeout(() => {
    timedOut = true;
    void reader.cancel("deadline").catch(() => {});
  }, Math.max(0, deadline - clock()));
  const unsub = presence.onLeave(() => void reader.cancel("client_left").catch(() => {}));
  try {
    for (;;) {
      const read = await reader.read();
      if (read.done) break;
      total += read.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("limit").catch(() => {});
        return null;
      }
      chunks.push(read.value);
    }
  } catch {
    return null;
  } finally {
    timers.clearTimeout(timer);
    unsub();
    reader.releaseLock();
  }
  if (timedOut || presence.gone) return null;
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

/**
 * The word `end.receipt_refused` gives for a receipt that was not signed: the receipt grammar's first problem (a
 * `ReceiptError` `invalid_event_log`, whose message is each problem's code and description, `; `-separated), else the
 * error's own code (`ReceiptError.code`), else `receipt_failed`. A closed lower-case word, never content.
 */
function receiptProblem(error: unknown): string {
  if (error instanceof Error && error.name === "ReceiptError") {
    const code = (error as Error & { readonly code?: unknown }).code;
    const first = /^([a-z][a-z_]{0,63}):/.exec(error.message)?.[1];
    if (code === "invalid_event_log" && first !== undefined) return first;
    if (typeof code === "string" && /^[a-z][a-z_]{0,63}$/.test(code)) return code;
  }
  return "receipt_failed";
}

/**
 * A signed receipt's document as `end` and the follow-up carry it: the value that was signed, member for member, never
 * read back through the typed model (`parseReceiptText`'s `document` adds `relay_image: null` to a receipt without
 * one, a member the signature does not cover). The entry serves its JCS bytes (`peer-client.ts` `inner`,
 * `receipt-route.ts`), and JCS of this value is `receipt.document`, the bytes that were signed, exactly.
 */
function receiptDocument(receipt: SignedReceipt): Json {
  return receipt.value;
}

/**
 * The vendor's reported usage as `end.usage` carries it: `safe_usage_counters`' counters, or null when none. The entry
 * reads its own copy of the released answer the same way and settles only when the two agree (`peer-client.ts`).
 */
export function peerUsageOf(raw: Json): PeerEndDto["usage"] {
  const projected = safeUsageCounters(raw);
  if (Object.keys(projected).length === 0) return null;
  try {
    return laneReportedUsageDtoOf(projected);
  } catch {
    return null;
  }
}
