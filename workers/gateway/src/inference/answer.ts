/**
 * An answer's delivery (`InferenceRun`, inference.ts): a stream primed to its commit and relayed to the client, an
 * upstream's error answer, and what a failed or defective answer settles.
 */
import { bindContinuation } from "@gray/continuation";
import { type Outcome as EndpointOutcome, answeredFailure } from "@gray/endpoint";
import { ApiError, bareOutcome, classifyEvent } from "@gray/errors";
import type { Json } from "@gray/json";
import { PEER_GATE_REFUSED } from "@gray/lane-wire";
import { AnswerBytes, requestsImages } from "@gray/limits";
import { AnswerEnd, GeminiRefusal, StreamBillingObserver } from "@gray/protocol";
import type { StreamStage } from "@gray/translation";
import { AnswerRelay } from "../answer.ts";
import { AFTER_CLIENT_LEFT_MS, ClientStream, platformTimers } from "../client.ts";
import { countedFailure } from "../dispatcher.ts";
import { type FragmentUse, PASS_THROUGH, type StreamInspector } from "../gate.ts";
import { geminiImages } from "../image-usage.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import { laneFaultCode, peerEndVerdict } from "../lane/stack.ts";
import type { ParsedRequest } from "../parse.ts";
import { type LimitSource, type Primed as PrimedStream, type StreamEnd, type Uncommitted as StreamUncommitted, primeStream, relayStream } from "../relay.ts";
import { type RequestOutcome, ToolCallNames } from "../sinks.ts";
import { StreamIds, TOOL_ID_CODES } from "../tool-ids.ts";
import { cutByDeadline } from "./attempt-pure.ts";
import { capacityError, ownLimitError } from "./errors.ts";
import { PEER_END_WAIT_MS, endKept } from "./peer-end.ts";
import { answerEndFailed, answerTokens, outputLimit, outputsImages } from "./settle-pure.ts";
// The settlement step goes by the name answer-buffered.ts gives it, whose buffered paths keep a local `settle`.
import { type SettleRun, settle as settleAnswer, settleRefused } from "./settle.ts";
import type { Answering, Attempt, Dispatch, PrimeResult, Sent, Uncommitted } from "./types.ts";
import { binding, laneBindState } from "./zdr.ts";
import { type StackPeerRun, stackCut } from "./stack-peer.ts";
import { classifyContext, committedFailureEvidence, endAttempt, lateChecks, leftDetail, noteAgentRefusal } from "./attempt.ts";
import { answerLimitCut, endStream, errorFrameOf, failedBeforeBytes, heldLimitAlert, told, type StreamRun } from "./stream.ts";
import { continuationStoreTiming, releaseHold } from "./hold.ts";
import { droppedNull, errorResponse, inspected, record } from "./record.ts";
import { attemptIds, holdToolIds } from "./tool-call-ids.ts";

/** What answer.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface AnswerRun extends StreamRun, SettleRun, StackPeerRun {}

/**
 * Reads a 2xx stream up to its commit (`prime`, relay.ts `primeStream`): its first frame outside the
 * preamble (@gray/errors `Preamble`: `message_start`, a ping, an empty text block start, a role-only
 * chunk, text of whitespace alone and the frames around it ...), held with the preamble, in order and as
 * sent, and handed back to the same reader for the relay to read again.
 * Until then nothing of the answer reached the client and nothing was charged, so the attempt may still
 * fail and another one go: an error event closes it as the status it maps to (`classifyEvent`); the end
 * of the stream or a cut is a transport failure, silence or the attempt's bound a timeout, a frame that
 * cannot be decoded, that the tool gate refuses or that passes the answer limit an answer defect. Each
 * frame held passes a fresh inspector of the gate as the relay that releases it inspects it (the relay
 * inspects the same frames again from the start, with the same verdicts). What priming holds is weighed
 * as the relay weighs a stream, against ANSWER_HELD_MAX_BYTES and the isolate's answer pool: past them it
 * is Gray's own limit (`final`), which no other attempt lifts.
 */
export async function prime(run: AnswerRun, a: Answering, attempt: Attempt, response: Response, deadline: number, firstBytesBy: number | null, fragments: FragmentUse): Promise<PrimeResult> {
  const { cfg, clock } = run.deps;
  attempt.status = response.status;
  let inspector: StreamInspector;
  try {
    inspector = run.deps.gate.stream(a.contract, a.answerLimit, run.facts.translation !== null, fragments);
  } catch {
    // The gate's failure is Gray's own, found again by the relay after the commit.
    inspector = PASS_THROUGH.stream(a.contract, a.answerLimit, false);
  }
  // A peer answer keeps its hop open past a priming that let go of it, for the `end` that follows (`peerUncommitted`).
  const hop = attempt.peer !== undefined ? endKept(response, run.deps.timers ?? platformTimers, (reason) => attempt.controller.abort(reason)) : null;
  if (hop !== null) attempt.hop = hop;
  const primed = await primeStream({
    protocol: a.protocol,
    response: hop?.response ?? response,
    presence: run.presence,
    inspector,
    onRefused: (verdict) => inspected(run, verdict, true),
    answerLimit: a.answerLimit,
    frameLimit: cfg.answerHeldMaxBytes,
    deadline,
    ...(firstBytesBy === null ? {} : { firstBytesBy }),
    silenceMs: cfg.upstreamSilenceMs,
    clock,
    retained: run.retained,
    isolate: run.answerShare,
    heldLimit: cfg.answerHeldMaxBytes,
  });
  // Save after a failure before the commit, which `peerUncommitted` closes, what lets go of the answer closes the hop,
  // as it did: a let-go priming kept back is passed on now.
  if (primed.kind !== "uncommitted") hop?.commit();
  switch (primed.kind) {
    case "committed":
      return { kind: "committed", stream: primed };
    case "left":
      return { kind: "left" };
    case "gray":
      if (primed.limitSource === "request_output_limit") answerLimitCut(run, attempt.route, primed.code, primed.limitBytes, primed.received);
      return { kind: "final", code: primed.code, error: primed.code === "gateway_capacity" ? capacityError() : ownLimitError(primed.code, primed.limitSource, primed.limitBytes) };
    case "uncommitted":
      // It failed before its commit, so before its finish: its checks are its priming's inspector's, the only one
      // that read it (the relay's reads a committed stream again from its start).
      attempt.checks = inspector.checks(false);
      return { kind: "uncommitted", failure: streamFailure(run, a, attempt, primed) };
  }
}

/**
 * A stream's failure before its commit as the dispatcher reads it (`Uncommitted`): an upstream error
 * event as the status it maps to (`classifyEvent`), any other failure its class (`bareOutcome`) with a
 * 502 of its code.
 */
export function streamFailure(run: AnswerRun, a: Answering, attempt: Attempt, failure: StreamUncommitted): Uncommitted {
  const { clock } = run.deps;
  const elapsed = clock() - attempt.startedAt;
  if (failure.event !== null) {
    const classified = classifyEvent(a.protocol, failure.event, classifyContext(run, a.model, attempt.route), elapsed, clock());
    noteAgentRefusal(run, attempt, classified.outcome, { inBand: failure.event });
    return { outcome: classified.outcome, error: classified.error, code: "upstream_error", upstreamMayStillWork: failure.upstreamMayStillWork };
  }
  if (failure.cutByDeadline === true) cutByDeadline(attempt);
  return { outcome: bareOutcome(failure.class ?? "answer_defect", elapsed), error: new ApiError(502, failure.code), code: failure.code, upstreamMayStillWork: failure.upstreamMayStillWork };
}

/**
 * A failure before an answer: releases the hold with `reason`. Without headers sent it records the
 * request and returns the error response; a stream whose headers went records once its error event
 * is written (`openStream`). `failed`: a limit of Gray's own after an upstream answered, which the
 * record calls failed whatever its status (a 429 `gateway_capacity`). `handedOn`: the error is one the
 * next model the customer listed may replace (`errorResponse`).
 */
export function fail(run: AnswerRun, error: ApiError, reason: string, attempt: Attempt | null, received: number, failed = false, handedOn = false): Sent {
  const left = reason === "client_left" || reason === "client_left_unread" || reason === "client_read_timeout";
  if (left) run.answer.leftBeforeFinal = true;
  releaseHold(run, { reason, detail: left ? leftDetail(run, attempt, received) : { code: error.code, endpoint: attempt?.route.record.endpointId ?? null, attempt: attempt?.index ?? null, status: attempt?.status ?? null } });
  if (run.answer.headersSent) return { kind: "failed", response: null, code: error.code, outcome: left ? "cancelled" : "interrupted" };
  const response = errorResponse(run, error, handedOn);
  const outcome: RequestOutcome = left ? "cancelled" : failed || error.status >= 500 ? "failed" : "rejected";
  record(run, error.status, outcome, error.code);
  return { kind: "failed", response, code: error.code, outcome };
}

/**
 * The most bytes the answer may take (`answer_limit`): from the output the hold covers, the serving endpoints' allowance
 * and the candidates, under the upstream's protocol, with generated images when the answer may carry them (`images`).
 */
export function answerLimit(run: AnswerRun, o: Dispatch): number {
  const limit = answerSizes(run, o.parsed, outputsImages(o.snapshot, o.canonical.model)).upstream.limit(answerTokens(o.sizing, o.routes, o.snapshot, o.canonical.model, o.candidates));
  return limit > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(limit);
}

/**
 * How many bytes a token of the answer takes as the upstream sends it, and as the client gets it (they differ when
 * translated). `modelImages`: the model outputs images; the answer may carry them then, or when the upstream's request
 * asks for them itself (inference.rs `images`, read from the upstream's request).
 */
export function answerSizes(run: AnswerRun, parsed: ParsedRequest, modelImages: boolean): { upstream: AnswerBytes; client: AnswerBytes } {
  const t = run.facts.translation;
  const images = modelImages || (t === null ? requestsImages(run.protocol, parsed.value) : requestsImages(t.upstream, t.body));
  const client = AnswerBytes.of(run.protocol, parsed.value, images);
  return { upstream: t === null ? client : AnswerBytes.of(t.upstream, t.body, images), client };
}

/**
 * The answer of `attempt` failed before its end was released, with `frames` prepared and never sent (the
 * relay's held frames, then the frame a check stopped). They go to the sealed content after what the client
 * got, as the answer it was not sent, when the answer issued tool-call id handles (main 9da4b74c,
 * `keep_unsent` with `IdMapper::rewrote`): the bytes Gray prepared then differ from the upstream's and say
 * what each handle stands for. Without a handle they are dropped, as the server drops them.
 */
export function keepUnsent(run: AnswerRun, attempt: Attempt, frames: readonly Uint8Array[]): void {
  if ((attemptIds(run, attempt)?.minted ?? 0) === 0) return;
  for (const frame of frames) run.facts.content?.push(frame);
}

/** Steps 8-10 for a stream: relay, settle or release, the permit back, the record. */
export async function relay(run: AnswerRun, a: Answering, attempt: Attempt, response: Response, primed: PrimedStream, client: ClientStream, deadline: number, inspector: StreamInspector, stage: StreamStage | null, answerLimit: number): Promise<void> {
  const { cfg, clock } = run.deps;
  const route = attempt.route;
  const calls = new ToolCallNames();
  run.facts.toolCalls = 0;
  run.facts.toolNames = calls.names;
  // The upstream's stop reasons, read from its events for an end that is the chain's failure (`settle`).
  const answerEnd = new AnswerEnd(a.protocol);
  const billingObserver = new StreamBillingObserver(a.protocol, run.settlement.pricingFeatures);
  const { tap, stateTap } = binding(run, a, attempt);
  // The answer's tool-call ids that not every client keeps get handles (TOOL_CALL_ID_MINTING).
  const mapper = run.facts.toolIds?.beginAnswer(attempt.issuer, a.protocol) ?? null;
  const streamIds = mapper === null ? null : new StreamIds(mapper, () => holdToolIds(run) === null);
  const relayed: StreamEnd = await relayStream({
          protocol: a.protocol,
          // Read through the reader priming used: the frames it held first, then the rest (`primed`).
          body: response.body!,
          primed,
          client,
          presence: run.presence,
          inspector,
          stage,
          tap,
          answerLimit,
          frameLimit: cfg.answerHeldMaxBytes,
          heldLimit: cfg.answerHeldMaxBytes,
          isolate: run.answerShare,
          deadline,
          silenceMs: cfg.upstreamSilenceMs,
          clock,
          outputLimit: outputLimit(a, route),
          settle: (settlement, _usage, rawUsage) => settleAnswer(run, a, attempt, settlement, rawUsage, { failure: answerEnd.failure(), unfinished: false }, billingObserver.finish(rawUsage)),
          // A Gemini answer is read for the model's refusal, delivered uncharged (`settleRefused`).
          refusal: a.protocol === "gemini" ? new GeminiRefusal() : undefined,
          // A refusal whose end is also its chain's failure is that failure (`answerEndFailed`).
          settleRefused: (reason) => {
            const failure = answerEnd.failure();
            return failure === undefined ? settleRefused(run, attempt, reason) : Promise.resolve(answerEndFailed(attempt, failure));
          },
          upstreamDone: () => endAttempt(run, attempt, { kind: "success" }, false, null),
          sink: run.facts.content,
          unsent: (frames) => keepUnsent(run, attempt, frames),
          ids: streamIds,
          retained: run.retained,
          // The request's time to first token is when its client first got content; the attempt's own (its record and
          // its ranking sample) when its first content was observed, as the server's `observe_content` sets it.
          onFirstContent: () => {
            run.answer.ttftMs ??= clock() - run.started;
          },
          onContentObserved: () => {
            attempt.ttftMs ??= clock() - attempt.startedAt;
          },
          // What is left of the 30 s after the client left, less the settlement's retries.
          drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
          onLeftBeforeFinal: () => {
            run.answer.leftBeforeFinal = true;
          },
          stalledEnd: errorFrameOf(run, stage, "client_read_timeout"),
          onHold: (bytes) => {
            if (bytes > run.answer.heldBytes) run.answer.heldBytes = bytes;
          },
          onVerdict: (verdict) => inspected(run, verdict, true),
          onDroppedNull: (member) => droppedNull(run, attempt, member),
          onEvents: (events) => {
            billingObserver.observe(events);
            if (run.traffic !== null) attempt.evidence?.observeEvents(events);
            for (const event of events) {
              if (event.type === "native") answerEnd.observe(event.payload);
              if (event.type === "tool_call_complete") calls.add(event.name);
              // A generated image in any candidate of a Gemini event, read where its usage is read.
              else if (event.type === "native" && event.protocol === "gemini" && attempt.answeredImage !== true && geminiImages(event.payload)) attempt.answeredImage = true;
            }
            run.facts.toolCalls = calls.count;
            run.facts.toolNames = calls.names;
          },
        });
  // S24: a vendor stream that was cut keeps the upstream's own code. An answer that failed Gray's check ends it with
  // `upstream_answer_refused`, any other fault of the relay's `lane_relay_failed`. A peer attempt's fault is the stack VM's: its error frame reads here as the upstream's own
  // (`upstream_stream_interrupted`), and its verdict comes in the `end` it writes right after that frame, waited for
  // PEER_END_WAIT_MS at most (production, 2026-11-19: a relay that changed its answer was told to the customer as an
  // upstream whose stream broke, inviting a retry that failed the same way).
  // A stack VM whose gate refused a later part of the answer says so in `end.code` (`PEER_GATE_REFUSED`, GL-23): the
  // stream ends as an answer the entry's own gate refused (relay.ts `drain`), `upstream_trust_policy_rejected`
  // (the route's `invalid_response`, the request trust-rejected), and not as the upstream's broken stream.
  let laneCode: ReturnType<typeof laneFaultCode> = null;
  let gateCut = false;
  if (relayed.kind === "failed" && laneCode === null && attempt.peer !== undefined && relayed.code === "upstream_stream_interrupted") {
    const peerEnd = await attempt.peer.endWithin(clock() + PEER_END_WAIT_MS);
    const verdict = peerEndVerdict(attempt.peer.trace?.calls.at(-1)?.fault ?? null, peerEnd);
    laneCode = verdict.kind === "lane" ? verdict.code : null;
    gateCut = verdict.kind === "gate";
  }
  if (gateCut) run.answer.trustRejected = true;
  const end: StreamEnd =
    relayed.kind !== "failed" ? relayed
    : laneCode !== null ? { ...relayed, code: laneCode, reason: laneCode }
    : gateCut ? { ...relayed, code: PEER_GATE_REFUSED, reason: PEER_GATE_REFUSED, supplierFailure: "invalid_response" }
    : relayed;
  // The answer's checks as the relay read them once the stream ended and its end went out.
  attempt.checks = end.checks;
  // What the relay held went with it.
  run.retained.set("held", 0);
  run.retained.set("frame", 0);
  run.retained.set("stream_state", 0);
  run.answer.responseBytes = client.written;
  if (end.kind === "settled") {
    if (stateTap !== null) {
      const captured = stateTap.finishSse();
      if (run.lane !== null) {
        run.ctx.waitUntil(laneBindState(run, a, attempt, captured));
      } else if (captured.outputIds.length > 0) {
        run.ctx.waitUntil(
          bindContinuation({
            locate: run.io.continuation,
            workspace: run.caller.key!.workspaceId,
            region: run.deps.region,
            timing: continuationStoreTiming(run, "post"),
            endpoint: route.record.endpointId,
            model: a.model,
            reply: { output: captured.outputIds.map((id) => ({ id })) },
          }),
        );
      }
    }
    endAttempt(run, attempt, { kind: "success" }, false, null);
    // What passed: what the client was sent and the rest read on after it left, in the content too
    // (capture.rs `Captured::append` adds the tail to the response's total).
    run.answer.responseBytes = client.written + end.unsent;
    // A client that left has the rest of the answer in the request's content (relay.ts): it is whole.
    run.answer.responseComplete = true;
    // Its attempt closed with the upstream (`upstreamDone`), before the checks were read after the held frames.
    lateChecks(run, attempt, end.checks);
    recordCharged(run, end.delivered, true);
    return;
  }
  if (end.kind === "client_left") {
    attempt.controller.abort(end.why);
    run.answer.leftBeforeFinal = true;
    endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, end.why);
    releaseHold(run, { reason: end.why, detail: leftDetail(run, attempt, end.received) });
    // The last frame follows how the client went, not why the read ended (`client_left_unread`): a client
    // that stopped reading is told its answer was cut off, never given an ordinary end that would pass the
    // cut answer for a whole one (request_logs.rs `a_client_that_stops_reading_a_stream_is_told_it_was_cut_off`).
    endStream(run, client, run.presence.reason === "client_read_timeout" ? errorFrameOf(run, stage, "client_read_timeout") : undefined);
    record(run, 200, "cancelled", end.why);
    return;
  }
  // A peer stream's hop still has the stack VM's `end` on its way, which the attempt's record takes its checks from
  // (`withPeerTrace`): `endKept` ends the fetch once it is in, PEER_END_WAIT_MS later at most, or when the call closes
  // (review r14 whole-pr blocker 1). Any other upstream that may still work is stopped here.
  if (end.upstreamMayStillWork) {
    if (attempt.hop !== undefined) attempt.hop.closeAfterEnd(end.code);
    else attempt.controller.abort(end.code);
  }
  // An answer the upstream gave as its own API allows that Gray failed (tool arguments the client's API cannot carry,
  // Gray's own failure to account for its tool-call ids) is its route's success (`answered_by_upstream`).
  const answered = answeredFailure(end.code);
  const outcome: EndpointOutcome = answered ? { kind: "success" } : end.supplierFailure === null ? { kind: "not_counted", reason: "gray_error" } : { kind: "supplier_failure", reason: end.supplierFailure };
  if (end.cutByDeadline === true) cutByDeadline(attempt);
  if (outcome.kind === "supplier_failure") committedFailureEvidence(run, attempt, end.code);
  endAttempt(run, attempt, outcome, end.upstreamMayStillWork, end.code, answered ? { answered: true } : { failure: countedFailure(null, end.code) });
  const detail: Record<string, string | number | boolean | null> = { code: end.code, why: end.why.slice(0, 200), endpoint: route.record.endpointId, provider: route.record.operator, attempt: attempt.index, bytes_received: end.received };
  if (end.limitSource !== undefined) detail.limit_source = end.limitSource;
  if (end.silenceMs !== undefined) {
    // What ended the read, and how long the upstream had been silent by then: an edge's read timeout
    // (a supplier behind Cloudflare is cut after 125 s without a byte) reads as a long silence, a
    // transfer that broke as a short one (staging 2026-10-18).
    detail.silence_ms = end.silenceMs;
    console.warn(JSON.stringify(run.lane === null ? { level: "warn", event: "upstream_stream_cut", request_id: run.requestId, code: end.code, why: end.why.slice(0, 200), silence_ms: end.silenceMs, bytes_received: end.received, endpoint: route.record.endpointId } : laneSafeLog({ level: "warn", event: "upstream_stream_cut", request_id: run.requestId, code: end.code, silence_ms: end.silenceMs, bytes_received: end.received, endpoint: route.record.endpointId })));
  }
  releaseHold(run, { reason: end.reason, detail });
  if (end.limitSource === "gateway_memory") heldLimitAlert(run, route);
  if (end.limitSource === "request_output_limit") answerLimitCut(run, route, end.code, null, end.received);
  // An answer that followed a held refusal and failed before its first bytes: the client, still without
  // headers, gets that refusal (`openStream`).
  if (failedBeforeBytes(run, client)) return;
  endStream(run, client, errorFrameOf(run, stage, end.code));
  // An upstream that failed after its client left: free, and the record says the client went (request_logs.rs
  // `an_upstream_that_fails_after_its_client_left_charges_nothing`).
  record(run, 200, run.presence.gone ? "cancelled" : "interrupted", end.code);
}

/**
 * The record of an answer read to its end and charged: completed, or cancelled (`client_cancelled`) with
 * its charge when the client left before it had all of it, as the server records a client that went away
 * mid-answer (request_logs.rs `a_client_that_goes_away_mid_stream_is_charged_for_the_answer_read_to_its_end`).
 * `started`: the client had the response's status (a stream's always is 200); a buffered answer whose client
 * left before then is 499.
 */
export function recordCharged(run: AnswerRun, delivered: boolean, started: boolean): void {
  if (delivered || !run.presence.gone) {
    record(run, 200, "completed", null);
    return;
  }
  // The client left before its answer was all delivered: a stack receipt's `client_left` (S32).
  run.stackPeer.stackUndelivered = true;
  record(run, started ? 200 : 499, "cancelled", run.presence.reason === "client_read_timeout" ? "client_read_timeout" : "client_cancelled");
}

/**
 * A non-streaming answer's failure after it committed (answer.ts): the endpoint's outcome, the hold
 * released with the reason, and the client told: the JSON error with its status while nothing went out
 * (handed over through `handOver`), else the body ends without its closing bracket and the record says
 * interrupted.
 */
export function answerFailed(run: AnswerRun, o: {
  readonly attempt: Attempt;
  readonly relay: AnswerRelay | null;
  readonly handOver: (response: Response) => void;
  readonly code: string;
  readonly reason: string;
  readonly why: string;
  readonly supplier: "timeout" | "upstream_error" | "invalid_response" | null;
  readonly upstreamMayStillWork?: boolean;
  readonly error?: ApiError;
  /** Gray's own bound ended the answer: the release's detail says so, as a held stream's does. */
  readonly limitSource?: LimitSource;
}): void {
  const { attempt, relay, code } = o;
  const route = attempt.route;
  if (o.upstreamMayStillWork === true) attempt.controller.abort(code);
  // An answer Gray failed though the upstream gave it as its own API allows is its route's success (`answeredFailure`).
  const answered = answeredFailure(code);
  if (o.supplier !== null && !answered) committedFailureEvidence(run, attempt, code);
  endAttempt(run, attempt, answered ? { kind: "success" } : o.supplier === null ? { kind: "not_counted", reason: "gray_error" } : { kind: "supplier_failure", reason: o.supplier }, o.upstreamMayStillWork === true, code, answered ? { answered: true } : { failure: countedFailure(null, code) });
  const detail: Record<string, string | number | boolean | null> = { code, why: o.why.slice(0, 200), endpoint: route.record.endpointId, provider: route.record.operator, attempt: attempt.index };
  if (o.limitSource !== undefined) detail.limit_source = o.limitSource;
  releaseHold(run, { reason: o.reason, detail });
  if (relay !== null) run.answer.heldBytes = Math.max(run.answer.heldBytes, relay.heldMost);
  if (relay?.started) {
    stackCut(run);
    relay.abort(code);
    run.answer.responseBytes = relay.written;
    record(run, 200, "interrupted", code);
    return;
  }
  // A withheld answer is not charged in the end either (a late charge is refunded, `withhold`): the catalog's sentence holds.
  const error = told(run, o.error ?? new ApiError(code === "billing_finalize_failed" || code === TOOL_ID_CODES.storeUnavailable ? 503 : 502, code));
  const res = errorResponse(run, error);
  record(run, error.status, "failed", code);
  o.handOver(res);
}

/**
 * A failure of an answer before it committed, as the dispatcher reads it (`buffered_answer`'s
 * `Uncommitted`): a 2xx whose body is an error object is the status it maps to (`classifyEvent`), any
 * other failure an answer defect with its code (`answered`: the upstream answered as its own API allows,
 * no failure of its route).
 */
export function defect(run: AnswerRun, attempt: Attempt, code: string, upstreamMayStillWork: boolean, answered = false): Uncommitted {
  return { outcome: bareOutcome("answer_defect", run.deps.clock() - attempt.startedAt), error: new ApiError(502, code), code, upstreamMayStillWork, ...(answered ? { answered: true } : {}) };
}

/** A 2xx answer whose body is an error object, read as the status it maps to (`classify_event`). */
export function errorAnswer(run: AnswerRun, a: Answering, attempt: Attempt, payload: Json): Uncommitted {
  const { clock } = run.deps;
  const classified = classifyEvent(a.protocol, payload, classifyContext(run, a.model, attempt.route), clock() - attempt.startedAt, clock());
  noteAgentRefusal(run, attempt, classified.outcome, { inBand: payload });
  return { outcome: classified.outcome, error: classified.error, code: "upstream_error", upstreamMayStillWork: false };
}
