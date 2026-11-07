import { ReceiptBuilder, StackEventsChain, type SignedReceipt } from "@gray/attest";
import type { GatewayConfig } from "@gray/config";
import { ApiError, ERROR_BODY_WAIT_MS, isErrorBody } from "@gray/errors";
import { isObject, type Json } from "@gray/json";
import { stackBodyDigest, StackEventDigester, type LaneProtocol } from "@gray/lane";
import {
  encodePeerFrame,
  encodePeerRefusal,
  fitStackTrace,
  laneReportedUsageDtoOf,
  PEER_COMMENT,
  PEER_FRAME_MAX_BYTES,
  PEER_REFUSAL_STATUS,
  stackTraceDtoOf,
  type PeerEndDto,
  type PeerEnvelopeDto,
  type PeerRefusalCode,
  type StackTraceDto,
} from "@gray/lane-wire";
import { safeUsageCounters } from "@gray/ledger-keys";
import { bufferedUsage, parseResponse } from "@gray/protocol";
import { AnswerRelay } from "../answer.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence, ClientStream, errorFrame, type StreamTimers } from "../client.ts";
import type { FragmentUse, StreamInspector, ToolGate } from "../gate.ts";
import { PASS_THROUGH } from "../gate.ts";
import { parseHeld, type ParsedRequest } from "../parse.ts";
import { primeStream, relayStream } from "../relay.ts";
import { AnswerShare, Retained } from "../retained.ts";
import { completedResponse } from "./codex.ts";
import { bodyHashOf, responseHash } from "./hooks.ts";
import { PeerAttempts, type PeerState } from "./peer.ts";
import {
  addStackReceipt,
  LANE_RELAY_FAILED,
  newStackRid,
  StackCall,
  stackBehaviourHeaders,
  stackRawQuery,
  stackRelayHeaders,
  stackRewriteSpec,
  stackTraceOf,
  type StackOutcome,
  type StackReturned,
} from "./stack.ts";
import type { StackRelayConfig, StackRelayRoute } from "./stack-config.ts";
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

  constructor(input: BackendInput, route: StackRelayRoute | null, key: string, hop: HopStream) {
    this.#input = input;
    this.#route = route;
    this.#key = key;
    this.#hop = hop;
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
      if (ended.outcome === "cut" && this.#stream) await this.#data(errorFrame(this.#input.protocol, "internal_error", 0n));
    }
    const call = this.#call;
    // The rid ends at egress and the feed is read through `done` before the receipt is written (S26).
    await call?.close();
    const receipt = call === null ? null : await this.#receipt(call, ended);
    this.#input.peer.attempts.done(this.#key, receipt === null ? null : receiptDocument(receipt));
    if (!this.#headed) await this.#head(this.#status, false);
    let frame: Uint8Array | null = null;
    try {
      frame = encodePeerFrame({ event: "end", end: this.#end(call, ended, receipt) });
    } catch (error) {
      // An `end` the wire refuses (a dialed attempt whose receipt could not be signed): the hop ends without it, which the
      // entry reads as a broken answer and asks the follow-up about.
      console.error(JSON.stringify({ level: "error", event: "lane_backend_end_refused", rid: this.#input.envelope.rid, error: error instanceof Error ? error.name : "error" }));
    }
    if (frame !== null) await this.#hop.write(frame);
    this.#hop.close();
  }

  /** The `end` frame, held to `peerEndSchema`'s rules by its outcome. */
  #end(call: StackCall | null, ended: Ended, receipt: SignedReceipt | null): PeerEndDto {
    const dialed = ended.outcome !== "not_dialed";
    const attempts = call?.feed.dialed() ?? [];
    const served = ended.outcome === "served" || ended.outcome === "vendor_error" || ended.outcome === "cut" ? (call?.served?.n ?? attempts.at(-1)?.n ?? null) : null;
    const usage = this.#rawUsage === null ? null : peerUsageOf(this.#rawUsage);
    const trace = this.#trace(call);
    return {
      outcome: ended.outcome,
      dialed,
      served_attempt: served === null ? null : BigInt(served),
      // Egress's calls for the rid (its `n` counts each one, refused or dialed), so `served_attempt` is one of them.
      attempts: dialed ? BigInt(call?.feed.attempts.size ?? 0) : 0n,
      relay_account_id: dialed ? (attempts.at(-1)?.accepted?.accountId ?? null) : null,
      usage: dialed ? usage : null,
      code: ended.code,
      receipt: receipt === null ? null : (receiptDocument(receipt) as Record<string, unknown>),
      ...(trace === null ? {} : { trace }),
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
    // The entry parsed these bytes before it forwarded them; a body that does not parse here is refused before egress.
    const parsed = parseHeld(protocol, "A", input.body, null);
    if (parsed instanceof ApiError) return { outcome: "not_dialed", code: "protocol" };
    const stream = parsed.canonical.stream;
    this.#stream = stream;
    // What the relay's container is sent (relay standard v1.7): the entry forwarded the client's bytes, and the required
    // changes are applied here, so the hop's `received_sha256` stays the client's.
    const body = stackRequestBody({ config: input.config, route, protocol, stream, received: input.body, value: parsed.value });
    if (!body.ok) return { outcome: "not_dialed", code: body.code };
    const rid = newStackRid();
    const conversation = envelope.conversation;
    const started = clock();
    // Bounded by its own limits and by what the entry left of the request (section 4.5: `budget_ms`).
    const deadline = Math.min(started + (stream ? cfg.streamTotalSeconds * 1000 : cfg.nonStreamTotalMs), started + Number(envelope.budget_ms));
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
      behaviourHeaders: stackBehaviourHeaders(input.request.headers, protocol),
      vendor: route.vendor,
      // S32a over the hop: the envelope names no workspace, so the entry derived the conversation id with its own boot
      // key (relay standard v1.7) and egress derives the vendor's session ids from it; absent (no session named), egress
      // makes one per rid, as for a direct client that named no session.
      ...(conversation === undefined ? {} : { conversation }),
      // The customer's opt-out comes over the hop in the envelope (docs/relay-request-changes.md).
      rewrite: stackRewriteSpec({ protocol, upstreamModel: route.upstream_model, route, stream, appends: input.config.appends, relayChanges: envelope.relay_changes !== "exclude" }),
      attemptsMax: input.config.limits.attempts_max,
      expiresAt: Math.ceil(deadline / 1000),
      headers: stackRelayHeaders(input.request.headers, protocol, input.config.inboundToken, rid, body.routeModel, conversation),
      egress: input.transport.egress,
      relay: input.transport.relay,
      signal: controller.signal,
      timers: input.timers,
      clock,
      holdMs: cfg.upstreamSilenceMs,
      settleMs: ERROR_BODY_WAIT_MS,
      queueMs: cfg.upstreamHeaderMs,
      answerMaxBytes: cfg.answerHeldMaxBytes,
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
      if (stream) return await this.#relayStream(call, sent.response, deadline, parsed);
      if (protocol === "open_ai_responses" && route.vendor === "chatgpt_codex") return await this.#codex(call, sent.response, deadline);
      return await this.#buffered(call, sent.response, deadline, parsed);
    } finally {
      input.timers.clearTimeout(timer);
    }
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
      await this.#head(outcome.status, false);
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

  /** An answer that failed before it committed (S25): the feed settles first, then decides; nothing of it was written. */
  async #uncommitted(call: StackCall): Promise<Ended> {
    const outcome = await call.failedAfterAnswer();
    if (outcome.kind !== "vendor_error") call.served = null;
    return this.#failed(call, outcome, false);
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
    const primed = await primeStream({
      protocol,
      response,
      presence: this.#presence,
      inspector: inspector(),
      answerLimit: Number.MAX_SAFE_INTEGER,
      frameLimit: cfg.answerHeldMaxBytes,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      clock,
      retained: this.#retained,
      isolate: this.#input.share,
      heldLimit: cfg.answerHeldMaxBytes,
    });
    if (primed.kind === "left") return { outcome: call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    if (primed.kind !== "committed") return this.#uncommitted(call);
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
    if (end.kind === "settled") {
      await pumped;
      if (!end.delivered) this.#undelivered = true;
      return { outcome: "served", code: null };
    }
    if (end.kind === "client_left") {
      client.end();
      await pumped;
      return { outcome: "cut", code: "attempt_ended" };
    }
    // S24: a container whose answer stopped matching the feed, or egress's cut at its budget, ends the stream with
    // the lane's own error; a vendor stream that was cut keeps the relay's own code.
    const fault = call.fault;
    const code = fault !== null && (fault.by === "relay" || fault.by === "egress") ? LANE_RELAY_FAILED : end.code;
    client.end(errorFrame(protocol, code, 0n));
    this.#replacedError = true;
    await pumped;
    return { outcome: "cut", code: fault?.why ?? "entry_internal" };
  }

  /** A buffered answer, passed through `AnswerRelay` as `InferenceRun.nativeAnswer` passes one. */
  async #buffered(call: StackCall, response: Response, deadline: number, parsed: ParsedRequest): Promise<Ended> {
    const { cfg, clock, protocol } = this.#input;
    if (response.body === null) return this.#uncommitted(call);
    let pumped: Promise<void> = Promise.resolve();
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
      inspector: this.#input.gate.answer(this.#input.gate.contract({ request: parsed.canonical, body: parsed.value }), protocol, Number.MAX_SAFE_INTEGER),
      retained: this.#retained,
      sink: null,
      tap: (bytes) => this.#tap(bytes),
      start: (stream) => {
        pumped = this.#head(200, false).then(() => this.#pump(stream));
      },
    });
    const read = await relay.read();
    if (read.kind === "client_left") {
      relay.abort(read.why);
      await pumped;
      return { outcome: relay.started ? "cut" : call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    }
    if (read.kind === "failed") {
      if (!relay.started) {
        relay.abort(read.code);
        return this.#uncommitted(call);
      }
      relay.abort(read.code);
      this.#replacedError = true;
      await pumped;
      return { outcome: "cut", code: call.fault?.why ?? "entry_internal" };
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
    // The gate's verdict on the whole answer, and a call it refused on the way (`InferenceRun.nativeAnswer`).
    const contract = this.#input.gate.contract({ request: parsed.canonical, body: parsed.value });
    if (!this.#input.gate.inspectResponse(contract, { protocol, body: read.projection }, Number.MAX_SAFE_INTEGER).ok || relay.refusedByGate !== undefined) {
      relay.abort("upstream_trust_policy_rejected");
      if (!relay.started) return this.#uncommitted(call);
      this.#replacedError = true;
      await pumped;
      return { outcome: "cut", code: "entry_internal" };
    }
    const raw = bufferedUsage(protocol, read.projection) ?? null;
    this.#rawUsage = isObject(raw) && answer.usage !== null ? raw : null;
    if (!relay.finish()) {
      relay.abort("tool_call_id_rewrite_incomplete");
      return relay.started ? { outcome: "cut", code: "entry_internal" } : this.#uncommitted(call);
    }
    const out = await relay.deliver();
    await pumped;
    if (!out.delivered) this.#undelivered = true;
    return { outcome: "served", code: null };
  }

  /** A buffered Codex request (D129): the terminal event's `response`, as `InferenceRun.codexAnswer` answers it. */
  async #codex(call: StackCall, response: Response, deadline: number): Promise<Ended> {
    const { cfg, clock, protocol } = this.#input;
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
    });
    if (read.kind === "left") return { outcome: call.feed.dialed().length > 0 ? "relay_failed" : "not_dialed", code: "attempt_ended" };
    if (read.kind !== "completed") return this.#uncommitted(call);
    try {
      parseResponse(protocol, read.response);
    } catch {
      return this.#uncommitted(call);
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
    if (this.#headed ? this.#answerStream : this.#stream) {
      for (const digest of this.#digester.write(bytes)) this.#chain.push(digest);
      return;
    }
    this.#body.push(bytes.slice());
  }

  async #head(status: number, stream: boolean): Promise<void> {
    if (this.#headed) return;
    this.#headed = true;
    this.#status = status;
    this.#answerStream = stream;
    await this.#hop.write(encodePeerFrame({ event: "head", head: { status: BigInt(status), stream } }));
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
      console.error(JSON.stringify({ level: "error", event: "lane_backend_receipt_failed", rid: envelope.rid, error: error instanceof Error ? error.name : "error" }));
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
