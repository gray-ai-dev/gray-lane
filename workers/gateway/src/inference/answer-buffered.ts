/**
 * A buffered answer (`InferenceRun`, inference.ts): a native, translated or Codex answer read whole, checked, settled
 * and served.
 */
import { bindReplyReferences } from "@gray/continuation";
import { answeredFailure } from "@gray/endpoint";
import { ApiError, isErrorBody } from "@gray/errors";
import { type Json, cloneJson, isObject, parseStrictBytes } from "@gray/json";
import { PEER_GATE_REFUSED } from "@gray/lane-wire";
import { generatedIdSeed } from "@gray/ledger-keys";
import { type AnswerChecks, ProtocolError, UNCOUNTED_CHECKS, bufferedSettlement, bufferedUsage, extractBufferedBillingMeta, parseResponse } from "@gray/protocol";
import { TranslationFailure } from "@gray/translation";
import { AnswerRelay, keepsAnswerText, wholeAnswerWeight } from "../answer.ts";
import { AFTER_CLIENT_LEFT_MS, ClientStream } from "../client.ts";
import { Dispatcher } from "../dispatcher.ts";
import { PASS_THROUGH, type StreamInspector, refusedAnswerChecks } from "../gate.ts";
import { geminiImages } from "../image-usage.ts";
import { completedResponse, keptWeight } from "../lane/codex.ts";
import { ResponsesStateTap } from "../lane/responses-continuation.ts";
import { peerEndVerdict } from "../lane/stack.ts";
import { type LimitSource, readAnswer } from "../relay.ts";
import { ToolCallNames } from "../sinks.ts";
import { AnswerIds, TOOL_ID_CODES, ToolIdFailure, releasesAny, clientBytes as toolIdClientBytes, upstreamValue } from "../tool-ids.ts";
import { UPSTREAM_BODY_CHUNK_BYTES } from "../upstream.ts";
import { type AnswerRun, answerFailed, defect, errorAnswer, recordCharged, streamFailure } from "./answer.ts";
import { cutByDeadline, providerRef } from "./attempt-pure.ts";
import { capacityError } from "./errors.ts";
import { PEER_END_WAIT_MS } from "./peer-end.ts";
import { bufferedEnd, grayAfterCheck, outputLimit, refusedOf, unreported } from "./settle-pure.ts";
// `settle` is a local of the buffered answer paths: the settlement step is imported under another name.
import { settle as settleAnswer, settleRefused } from "./settle.ts";
import type { Answering, Attempt, BufferedResult, Uncommitted } from "./types.ts";
import { laneBindState, laneBinds } from "./zdr.ts";
import { stackCut } from "./stack-peer.ts";
import { laneCodexBuffered, laneCodexRoute } from "./lane-attempt.ts";
import { bodyPastOutputLimit, commit, endAttempt, lateChecks, leftDetail } from "./attempt.ts";
import { type SendRun, laneTap } from "./send.ts";
import { abandon, answerLimitCut, capHeaders, heldLimitAlert, modelHeader } from "./stream.ts";
import { continuationStoreTiming, releaseHold } from "./hold.ts";
import { droppedHeader, droppedNull, errorResponse, inspected, record, refuse } from "./record.ts";
import { holdToolIds } from "./tool-call-ids.ts";

/** What answer-buffered.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface BufferedAnswerRun extends SendRun, AnswerRun {}

/**
 * Steps 8-10 for a non-streaming answer: a native one passes as it arrives (`nativeAnswer`), a translated
 * one is read whole (`translatedAnswer`). An answer that fails before it commits (nothing reached the
 * client, nothing was charged) comes back `uncommitted`, and the dispatcher may send the next attempt.
 */
export function buffered(run: BufferedAnswerRun, a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
  attempt.status = response.status;
  if (laneCodexBuffered(run, attempt)) return codexAnswer(run, a, attempt, response, deadline, d);
  // Its upstream answers buffered: a success with output and no time to first token is an estimation point (r24). A
  // Codex route's upstream streams whatever its client asked (D129), read to its terminal event here (`codexAnswer`) or
  // at the stack VM behind a peer attempt: never a buffered read.
  if (!laneCodexRoute(run, attempt.route.record)) attempt.bufferedRead = true;
  return run.facts.translation === null ? nativeAnswer(run, a, attempt, response, deadline, d) : translatedAnswer(run, a, attempt, response, deadline, d);
}

/**
 * Steps 8-10 for a native non-streaming answer, passed on as it arrives (answer.ts). Resolves as soon as
 * the client may have a response: the streamed body once the answer starts, or the whole answer, or the
 * error, when it ends before; the rest runs in the background (`relayed`), as a stream's relay does. The
 * answer commits when it starts, or once its end checks pass and its usage is settled (main commits a
 * buffered answer read whole after its checks, `buffered_answer`): until then a failure is `uncommitted`
 * and the dispatcher may send the next attempt. A failure after the start reaches the client as a cut
 * body (gateway.md 13.14).
 */
export function nativeAnswer(run: BufferedAnswerRun, a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
  const { cfg, clock } = run.deps;
  const route = attempt.route;
  const body = response.body;
  let settle!: (result: BufferedResult) => void;
  const handed = new Promise<BufferedResult>((resolve) => (settle = resolve));
  const handOver = (response: Response): void => settle({ kind: "response", response });
  let relay: AnswerRelay | null = null;
  const reading = (async () => {
    if (body === null) {
      settle({ kind: "uncommitted", failure: defect(run, attempt, "upstream_body_incomplete", false) });
      return;
    }
    const provider = await providerRef(route);
    const headers = (): Headers => {
      const h = new Headers({ "content-type": "application/json", "x-request-id": run.requestId, "x-gray-provider": provider, "x-gray-attempt": String(attempt.index + 1) });
      if (run.protocol === "anthropic_messages") h.set("request-id", run.requestId);
      capHeaders(run, h);
      modelHeader(run, h);
      droppedHeader(run, h);
      return h;
    };
    // The answer's tool-call ids that not every client keeps get handles as its bytes go (TOOL_CALL_ID_MINTING).
    const mapper = run.facts.toolIds?.beginAnswer(attempt.issuer, a.protocol) ?? null;
    const answerIds = mapper === null ? null : new AnswerIds(mapper, a.protocol, () => holdToolIds(run) === null);
    const answerInspector = run.deps.gate.answer(a.contract, a.protocol, a.answerLimit);
    const stateTap = run.lane !== null && laneBinds(run, a, attempt) ? new ResponsesStateTap() : null;
    relay = new AnswerRelay({
      protocol: a.protocol,
      body,
      presence: run.presence,
      clock,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      answerLimit: a.answerLimit,
      heldLimit: cfg.answerHeldMaxBytes,
      isolate: run.answerShare,
      primeBytes: cfg.answerPrimeBytes,
      stallMs: cfg.streamClientStallMs,
      // D54: the client stall bound follows the request's timers seam like every other stream's.
      timers: run.deps.timers,
      // What is left of the 30 s after the client left, less the settlement's retries.
      drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
      inspector: answerInspector,
      // The structured output check reads the answer's text, which the projection keeps whole for it alone.
      wholeText: keepsAnswerText(run.deps.gate.mode, a.contract),
      retained: run.retained,
      sink: run.facts.content,
      queued: run.deps.meter?.clientQueued,
      tap: laneTap(run),
      ...(stateTap === null ? {} : { onRawChunk: (chunk: Uint8Array) => stateTap.pushBufferedChunk(chunk) }),
      onDroppedNull: (member) => droppedNull(run, attempt, member),
      ids: answerIds,
      start: (stream, length) => {
        // The answer starts: it committed, and no other attempt follows. One that ended before it started
        // committed after its end checks and its charge, and starts here whole, with its length (answer.ts
        // `deliver`): it commits once.
        if (!attempt.committed) commit(run, d, attempt);
        run.answer.ttfbMs = clock() - run.started;
        const h = headers();
        // An answer that never started goes whole with its length (answer.ts `deliver`).
        if (length !== undefined) h.set("content-length", String(length));
        handOver(new Response(stream, { status: 200, headers: h }));
      },
    });
    const current = relay;
    // A failure before the answer started: nothing reached the client and nothing was charged, so the
    // dispatcher may send the next attempt (false: the answer started, the failure is the client's).
    const uncommitted = (failure: Uncommitted): boolean => {
      if (current.started) return false;
      current.abort(failure.code);
      settle({ kind: "uncommitted", failure });
      return true;
    };
    const read = await current.read();
    // The body's read ended: the attempt's end, whatever its settlement adds after (r24).
    attempt.readEndMs = clock();
    run.answer.heldBytes = Math.max(run.answer.heldBytes, current.heldMost);
    const failed = (
      code: string,
      reason: string,
      why: string,
      supplier: "timeout" | "upstream_error" | "invalid_response" | null,
      extra: { upstreamMayStillWork?: boolean; error?: ApiError; limitSource?: LimitSource } = {},
    ) => answerFailed(run, { attempt, relay: current, handOver, code, reason, why, supplier, ...extra });
    if (read.kind === "client_left") {
      attempt.controller.abort(read.why);
      run.answer.leftBeforeFinal = true;
      endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, read.why);
      releaseHold(run, { reason: read.why, detail: leftDetail(run, attempt, read.received) });
      if (current.started) {
        current.abort(read.why);
        run.answer.responseBytes = current.written;
        record(run, 200, "cancelled", read.why);
        return;
      }
      const res = errorResponse(run, new ApiError(499, "client_cancelled"));
      record(run, 499, "cancelled", read.why);
      handOver(res);
      return;
    }
    if (read.kind === "failed") {
      if (read.cutByDeadline === true) cutByDeadline(attempt);
      // A call the gate refused on the way: the verdict is recorded as the end's would have been, and the answer's
      // checks are what refused it (the rest of it is not read).
      if (read.violation !== undefined) {
        inspected(run, { ok: false, violation: read.violation }, true);
        attempt.checks = refusedAnswerChecks(answerInspector);
      }
      // The isolate's answers hold too much together: Gray's limit, a 429 the client may retry. One
      // answer kept more than ANSWER_HELD_MAX_BYTES, or grew past the bytes its request's output limit
      // allows: Gray's limit too, said as a held stream's is. None is the supplier's, and no other attempt
      // would hold more (a stream's `final`): the request ends here.
      if (read.code === "gateway_capacity" || read.limitSource !== undefined) {
        // Past the bytes its output cap allows: a route that did not honour the cap, said in a code of its own.
        const code = read.limitSource === "request_output_limit" ? bodyPastOutputLimit(run, attempt) : read.code;
        const error =
          read.code === "gateway_capacity"
            ? new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory")
            : new ApiError(502, code).withMeta("limit_bytes", BigInt(read.limitSource === "request_output_limit" ? a.answerLimit : cfg.answerHeldMaxBytes)).withMeta("limit_source", read.limitSource!);
        failed(code, code, read.why, read.supplierFailure, {
          upstreamMayStillWork: read.upstreamMayStillWork,
          error,
          ...(read.limitSource === undefined ? {} : { limitSource: read.limitSource }),
        });
        if (read.limitSource === "gateway_memory") heldLimitAlert(run, route);
        if (read.limitSource === "request_output_limit") answerLimitCut(run, route, code, a.answerLimit, read.received);
        return;
      }
      if (uncommitted(defect(run, attempt, read.code, read.upstreamMayStillWork))) return;
      // A started peer answer whose hop broke: the stack VM's `cut` end errors the body (peer-client `#answer`), and its
      // verdict is in that `end`, read as a stream's (`relay`): a fault of the relay's is the lane's code, and its trust
      // gate's refusal of a later part (GL-23) is `upstream_trust_policy_rejected`, the request trust-rejected.
      if (attempt.peer !== undefined && read.code === "upstream_body_incomplete") {
        const peerEnd = await attempt.peer.endWithin(clock() + PEER_END_WAIT_MS);
        const verdict = peerEndVerdict(attempt.peer.trace?.calls.at(-1)?.fault ?? null, peerEnd);
        if (verdict.kind === "lane") {
          failed(verdict.code, verdict.code, read.why, read.supplierFailure, { upstreamMayStillWork: read.upstreamMayStillWork });
          return;
        }
        if (verdict.kind === "gate") {
          run.answer.trustRejected = true;
          failed(PEER_GATE_REFUSED, PEER_GATE_REFUSED, "the stack VM's trust gate refused a later part of the answer", "invalid_response");
          return;
        }
      }
      failed(read.code, read.code, read.why, read.supplierFailure, { upstreamMayStillWork: read.upstreamMayStillWork });
      return;
    }
    const upstream = a.protocol;
    const payload = read.projection;
    let parsedAnswer;
    try {
      parsedAnswer = parseResponse(upstream, payload);
    } catch (error) {
      // A 2xx whose body is an error object: the status it maps to decides what follows.
      if (isErrorBody(upstream, payload) && uncommitted(errorAnswer(run, a, attempt, payload))) return;
      if (uncommitted(defect(run, attempt, "invalid_upstream_protocol", false))) return;
      failed("invalid_upstream_protocol", "invalid_upstream_protocol", error instanceof ProtocolError ? error.message : String(error), "invalid_response");
      return;
    }
    const calls = new ToolCallNames();
    for (const call of parsedAnswer.tool_calls) calls.add(call.name);
    run.facts.toolCalls = calls.count;
    run.facts.toolNames = calls.names;
    // The answer's checks, of the same request and projection as the verdict (its text whole when its structured
    // output is checked, `keepsAnswerText`), whatever follows: read once the answer went out, or as the attempt
    // ends without it (`checksLater`), never before the answer's end.
    // Its text cut by the projection (`textCut`) is the output check's `unknown` (@gray/trust `outputCheck`).
    const textCut = read.textCut;
    attempt.checksLater = () => run.deps.gate.responseChecks(a.contract, { protocol: upstream, body: payload, textCut });
    // The verdict on the projection is the verdict on the whole answer (@gray/protocol AnswerProjection).
    const verdict = run.deps.gate.inspectResponse(a.contract, { protocol: upstream, body: payload }, a.answerLimit);
    if (!inspected(run, verdict, true)) {
      if (uncommitted(defect(run, attempt, "upstream_trust_policy_rejected", false))) return;
      failed("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", verdict.ok ? "" : verdict.violation, "invalid_response");
      return;
    }
    const refused = current.refusedByGate;
    if (refused !== undefined) {
      // A call refused on the way is one the whole answer is refused for (@gray/trust AnswerCallCheck);
      // its bytes are gone, so the refusal stands even if the verdict above disagreed.
      console.error(JSON.stringify({ level: "alert", event: "answer_check_disagrees", request_id: run.requestId, violation: refused }));
      inspected(run, { ok: false, violation: refused }, true);
      // Counted by what refused it, as an answer refused on the way is: the inspector's check, none when its refusal was
      // a rule of Gray's own (@gray/trust AnswerCallCheck), never the whole answer's that the verdict passed.
      attempt.checks = refusedAnswerChecks(answerInspector);
      if (uncommitted(defect(run, attempt, "upstream_trust_policy_rejected", false))) return;
      failed("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", refused, "invalid_response");
      return;
    }
    if (run.traffic !== null) attempt.evidence?.observeResponse(parsedAnswer, payload);
    // Nothing of it goes out while it holds a replaced tool-call id at a site the rewriting does not know
    // (`check_release`, before the commit).
    if (!current.finish()) {
      if (uncommitted(defect(run, attempt, TOOL_ID_CODES.rewriteIncomplete, false))) return;
      failed(TOOL_ID_CODES.rewriteIncomplete, TOOL_ID_CODES.rewriteIncomplete, "the answer still held a replaced tool-call id", null);
      return;
    }
    // The model's refusal (a Gemini answer of a blocked prompt, or a refusal and nothing else) is delivered
    // uncharged, so it needs no usage. The projection keeps what the refusal is read from: every key, and
    // every short string whole (@gray/protocol AnswerProjection). It is settled after the commit, as main's
    // `Settlement::ModelRefused` is: a failure of its own (its handles not stored) is Gray's.
    const refusedFor = refusedOf(upstream, payload);
    if (upstream === "gemini") attempt.answeredImage = geminiImages(payload);
    // A served answer's checks are read once it went out (its attempt closes before).
    let later: (() => AnswerChecks) | undefined;
    if (refusedFor !== undefined) {
      // The model's refusal: its attempt is no route's answer, and nothing of it is counted.
      attempt.checksLater = undefined;
      if (!current.started) commit(run, d, attempt);
      const refused = await settleRefused(run, attempt, refusedFor);
      if (!refused.ok) {
        failed(refused.code, refused.reason, refused.why, null);
        return;
      }
    } else {
      const rawUsage = bufferedUsage(upstream, payload) ?? null;
      const reported = isObject(rawUsage) && parsedAnswer.usage !== null;
      // An answer without usage is missing what it is billed on: delivered free, or refused under
      // GRAY_USAGE_MISSING refuse (`settle`), saying which.
      const settled = await settleAnswer(
        run,
        a,
        attempt,
        reported ? bufferedSettlement(upstream, parsedAnswer.usage!, rawUsage, outputLimit(a, route)) : unreported(upstream, rawUsage),
        rawUsage,
        bufferedEnd(upstream, payload, parsedAnswer.finish_reason),
        extractBufferedBillingMeta(upstream, payload, rawUsage, run.settlement.pricingFeatures),
      );
      if (!settled.ok) {
        // A usage the gateway would not bill charged nothing: another attempt may serve the request. A
        // settlement that was not confirmed may have charged, and a failed review of Gray's own evidence
        // is Gray's after a valid answer (`buffered_answer` settles after the commit): either is the
        // committed answer's failure.
        const grays = grayAfterCheck(settled);
        if (!grays && uncommitted({ ...defect(run, attempt, settled.code, false), error: new ApiError(502, settled.code), reason: settled.reason })) return;
        if (!current.started) commit(run, d, attempt);
        failed(settled.code, settled.reason, settled.why, grays ? null : "invalid_response");
        return;
      }
      if (!current.started) commit(run, d, attempt);
      later = attempt.checksLater;
      attempt.checksLater = undefined;
      endAttempt(run, attempt, { kind: "success" }, false, null);
    }
    // A Responses reply that stores is bound to its endpoint before the client has its last byte (`bind`); a lane's,
    // through its own record (`laneBindState`).
    if (run.lane !== null) {
      if (stateTap !== null && response.status >= 200 && response.status <= 299) {
        await laneBindState(run, a, attempt, stateTap.finishBuffered(payload));
      }
    } else {
      await bindReplyReferences({
        locate: run.io.continuation,
        workspace: run.caller.key!.workspaceId,
        region: run.deps.region,
        timing: continuationStoreTiming(run, "post"),
        endpoint: route.record.endpointId,
        model: a.model,
        protocol: upstream,
        stores: a.stores,
        translated: false,
        status: response.status,
        reply: payload,
      });
    }
    // The rest goes to the client at its pace, whole with its length when the answer never started
    // (answer.ts `deliver`); the record, which lets go of the request's part of the isolate's answers,
    // follows the client. The sealed content got the bytes before it hears they are all (`AnswerSink.end`).
    const out = await current.deliver();
    run.facts.content?.end();
    run.answer.responseBytes = current.written;
    run.answer.responseComplete = out.delivered;
    // A peer attempt's are its stack VM's (`end.checks`): the entry's own would parse the answer for nothing.
    if (later !== undefined && attempt.peer === undefined) lateChecks(run, attempt, later());
    recordCharged(run, out.delivered, current.started);
  })();
  // A failure of Gray's own (a bug) still ends the request: free, the upstream and the permit let
  // go, the record written; the client gets 500 before the answer started, a cut body after.
  run.answer.relayed = reading.catch((error: unknown) => {
    const started = relay?.started === true;
    if (!started && run.settlement.billing === "charged") {
      run.settlement.billing = "unsettled";
      run.settlement.charged = null;
      run.settlement.chargedSides = null;
      run.settlement.chargeSeq = null;
    }
    abandon(run, error, started ? "relay_failed" : "request_failed");
    if (started) {
      stackCut(run);
      relay!.abort("internal_error");
      run.answer.responseBytes = relay!.written;
      record(run, 200, "failed", "internal_error");
      return;
    }
    // Gray's own failure is final: no later model either.
    run.log.deferRecord = false;
    handOver(refuse(run, new ApiError(500, "internal_error"), run.admitting.admission));
  });
  run.ctx.waitUntil(run.answer.relayed);
  return handed;
}

/**
 * Steps 8-10 for a translated non-streaming answer: read whole (the translator makes the client's
 * document from the whole upstream document, @gray/translation `translateAnswer`), at most
 * BODY_PARSE_MAX_BYTES of it, the most of one document the gateway parses whole (m0/memory.md); a
 * longer answer is refused, Gray's limit and not the supplier's fault, and not charged. So is one past
 * the bytes its request's output limit allows, as a native answer is, which shows its route did not
 * honour the cap (`bodyPastOutputLimit`). The answer
 * commits once it is read, checked, translated and its usage settled: every failure before is
 * `uncommitted`, and the dispatcher may send the next attempt; Gray's own limits are not, since no
 * other attempt would hold less.
 *
 * What it holds is an answer's like any other (review 2026-10-19): the bytes as they are read (twice
 * while joined), then their parse and the translation (answer.ts `wholeAnswerWeight`), the request's
 * part of the isolate's answers (retained.ts `AnswerPool`). Past ANSWER_HELD_MAX_BYTES alone it is
 * refused with `upstream_body_limit`, past what the isolate's answers hold together with a 429
 * `gateway_capacity`, both Gray's limit (`gateway_memory`), free, the endpoint not blamed. The
 * translated answer then goes at its client's pace, with its length, and stays held until the client
 * took it; the record, which lets go of it, follows the client, as a native answer's does.
 */
export async function translatedAnswer(run: BufferedAnswerRun, a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
  const { cfg, clock } = run.deps;
  const route = attempt.route;
  let handed: Response | null = null;
  const handOver = (r: Response) => (handed = r);
  const failed = (
    code: string,
    reason: string,
    why: string,
    supplier: "timeout" | "upstream_error" | "invalid_response" | null,
    extra: { upstreamMayStillWork?: boolean; error?: ApiError; limitSource?: LimitSource } = {},
  ): BufferedResult => {
    answerFailed(run, { attempt, relay: null, handOver, code, reason, why, supplier, ...extra });
    return { kind: "response", response: handed! };
  };
  const heldLimit = cfg.answerHeldMaxBytes;
  // A failure before the commit: what this attempt held, in the request and in the isolate's answers,
  // is no longer held when the next attempt goes.
  const uncommitted = (failure: Uncommitted): BufferedResult => {
    run.retained.set("answer", 0);
    run.answerShare.hold(0, heldLimit);
    return { kind: "uncommitted", failure };
  };
  const capacity = (): ApiError => new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
  /**
   * What the answer holds now, weighed: a refusal when one answer may not hold that much, or the isolate's
   * answers together; null when it may. Gray's limit either way: the request ends with it.
   */
  const holds = (weight: number, what: string): BufferedResult | null => {
    if (weight > heldLimit) {
      const error = new ApiError(502, "upstream_body_limit")
        .withMessage(`This model is served through another API here, and translating the provider's answer would hold more than the ${heldLimit} bytes Gray holds of one answer. You are not charged for it; ask for less output.`)
        .withMeta("limit_bytes", BigInt(heldLimit))
        .withMeta("limit_source", "gateway_memory");
      return failed("upstream_body_limit", "upstream_body_limit", `the answer's ${what} would hold ${weight} weighed bytes, past the ${heldLimit} the gateway holds of one`, null, { error, limitSource: "gateway_memory" });
    }
    if (!run.answerShare.hold(weight, heldLimit)) {
      return failed("gateway_capacity", "gateway_capacity", `the answers in flight in this isolate would keep more than the ${heldLimit} weighed bytes the gateway holds of them together`, null, { error: capacity() });
    }
    return null;
  };
  if (response.body === null) return uncommitted(defect(run, attempt, "upstream_body_incomplete", false));
  const memoryLimit = cfg.bodyParseMaxBytes < a.answerLimit;
  const read = await readAnswer(response.body, Math.min(a.answerLimit, cfg.bodyParseMaxBytes), deadline, cfg.upstreamSilenceMs, run.presence, clock, run.retained, { share: run.answerShare, limit: heldLimit });
  // The body's read ended: the attempt's end, whatever its settlement adds after (r24).
  attempt.readEndMs = clock();
  if (read.kind === "client_left") {
    // The client left and the answer did not end while the Worker could still read it (relay.ts `UpstreamReader`).
    attempt.controller.abort("client_left_unread");
    run.answer.leftBeforeFinal = true;
    endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left_unread");
    releaseHold(run, { reason: "client_left_unread", detail: leftDetail(run, attempt, read.received) });
    const res = errorResponse(run, new ApiError(499, "client_cancelled"));
    record(run, 499, "cancelled", "client_left_unread");
    return { kind: "response", response: res };
  }
  if (read.kind === "failed") {
    if (read.cutByDeadline === true) cutByDeadline(attempt);
    if (read.code === "upstream_body_limit" && memoryLimit) {
      // Gray's own limit on what it translates: no other attempt translates more.
      const error = new ApiError(502, "upstream_body_limit")
        .withMessage(
          `This model is served through another API here, and Gray translates answers of at most ${cfg.bodyParseMaxBytes} bytes; the provider's answer was larger. You are not charged for it; ask for less output.`,
        )
        .withMeta("limit_bytes", BigInt(cfg.bodyParseMaxBytes))
        .withMeta("limit_source", "gateway_memory");
      return failed(read.code, read.code, read.why, null, { upstreamMayStillWork: true, error, limitSource: "gateway_memory" });
    }
    if (read.code === "upstream_body_limit") {
      // Past the bytes its request's output limit allows, the read's bound here: as a native answer past it (answer.ts),
      // Gray's limit, which no other route lifts, never its route's failure in the circuit (inference.rs
      // `gray_answer_limit`); and a route that did not honour the cap (`bodyPastOutputLimit`).
      const code = bodyPastOutputLimit(run, attempt);
      answerLimitCut(run, route, code, a.answerLimit, read.received ?? 0);
      const error = new ApiError(502, code).withMeta("limit_bytes", BigInt(a.answerLimit)).withMeta("limit_source", "request_output_limit");
      return failed(code, code, read.why, null, { upstreamMayStillWork: true, error, limitSource: "request_output_limit" });
    }
    // The isolate's answers hold too much together: Gray's limit, a 429 the client may retry.
    if (read.code === "gateway_capacity") return failed(read.code, read.code, read.why, null, { upstreamMayStillWork: true, error: capacity() });
    return uncommitted(defect(run, attempt, read.code, read.code === "upstream_body_incomplete"));
  }
  const upstream = a.protocol;
  let bytes = read.bytes;
  const raw = bytes.length;
  // The whole parse comes on top of the bytes.
  const parse = holds(wholeAnswerWeight(raw), "parse");
  if (parse !== null) return parse;
  let payload: Json;
  try {
    payload = parseStrictBytes(bytes);
  } catch {
    return uncommitted(defect(run, attempt, "invalid_upstream_json", false));
  }
  let parsedAnswer;
  try {
    parsedAnswer = parseResponse(upstream, payload);
  } catch {
    return uncommitted(isErrorBody(upstream, payload) ? errorAnswer(run, a, attempt, payload) : defect(run, attempt, "invalid_upstream_protocol", false));
  }
  const calls = new ToolCallNames();
  for (const call of parsedAnswer.tool_calls) calls.add(call.name);
  run.facts.toolCalls = calls.count;
  run.facts.toolNames = calls.names;
  // The answer's checks, of the same request and whole answer as the verdict, whatever follows. Read here, with the
  // verdict, not once the answer went out: the answer is read whole and made ready before any of it goes, and reading
  // them after its delivery would keep its parse alive while the client reads, which the answer's weight no longer
  // counts from here (review r14 output-class finding 7).
  attempt.checks = run.deps.gate.responseChecks(a.contract, { protocol: upstream, body: payload });
  const verdict = run.deps.gate.inspectResponse(a.contract, { protocol: upstream, body: payload }, a.answerLimit);
  if (!inspected(run, verdict, true)) return uncommitted(defect(run, attempt, "upstream_trust_policy_rejected", false));
  if (run.traffic !== null) attempt.evidence?.observeResponse(parsedAnswer, payload);
  // The model's refusal (a Gemini upstream's) is delivered translated and uncharged, so it needs no usage.
  const refusedFor = refusedOf(upstream, payload);
  if (upstream === "gemini") attempt.answeredImage = geminiImages(payload);
  const rawUsage = bufferedUsage(upstream, payload) ?? null;
  const reported = isObject(rawUsage) && parsedAnswer.usage !== null;
  // A translated answer is made into the client's before it is billed: a failure there is free (`translate_body`).
  // With TOOL_CALL_ID_MINTING, the upstream's ids get handles before translation (on a copy) and the ids
  // the translation composed after it (`rewrite_upstream_value`, `rewrite_client_value`).
  const translation = run.facts.translation!;
  const mapper = run.facts.toolIds?.beginAnswer(attempt.issuer, upstream) ?? null;
  try {
    let translatable = payload;
    if (mapper !== null) {
      translatable = cloneJson(payload);
      await upstreamValue(mapper, translatable);
    }
    bytes = translation.translateAnswer(translatable, parsedAnswer, translation.context(generatedIdSeed(run.requestId), BigInt(Math.floor(clock() / 1000)), a.model));
    if (mapper !== null) bytes = await toolIdClientBytes(mapper, bytes);
  } catch (error) {
    // Ids the answer cannot carry as handles are its defect, before the commit (`translate_body`).
    if (error instanceof ToolIdFailure) return uncommitted(defect(run, attempt, error.code, false));
    if (!(error instanceof TranslationFailure)) throw error;
    // Tool arguments the client's API cannot carry are the upstream's answer as its own API allows: no
    // failure of its route (`answered_by_upstream`).
    return uncommitted(defect(run, attempt, error.code, false, answeredFailure(error.code)));
  }
  if (mapper !== null) {
    // What the handles hold is held in the isolate's answers too: Gray's limit when they cannot take it.
    if (holdToolIds(run) !== null) return failed("gateway_capacity", "gateway_capacity", "the answers in flight in this isolate hold too much", null, { error: capacityError() });
    if (releasesAny(mapper, bytes)) return uncommitted(defect(run, attempt, TOOL_ID_CODES.rewriteIncomplete, false));
  }
  // The translation on top of the bytes and their parse, until the client has it.
  const translated = holds(wholeAnswerWeight(raw, bytes.length), "parse and translation");
  if (translated !== null) return translated;
  run.retained.set("answer", raw + bytes.length);
  if (refusedFor !== undefined) {
    // Settled after the commit, as main's `Settlement::ModelRefused` is: a failure of its own is Gray's.
    commit(run, d, attempt);
    const refused = await settleRefused(run, attempt, refusedFor);
    if (!refused.ok) return failed(refused.code, refused.reason, refused.why, null);
  } else {
    const settled = await settleAnswer(
      run,
      a,
      attempt,
      reported ? bufferedSettlement(upstream, parsedAnswer.usage!, rawUsage, outputLimit(a, route)) : unreported(upstream, rawUsage),
      rawUsage,
      bufferedEnd(upstream, payload, parsedAnswer.finish_reason),
      extractBufferedBillingMeta(upstream, payload, rawUsage, run.settlement.pricingFeatures),
    );
    if (!settled.ok) {
      if (!grayAfterCheck(settled)) return uncommitted({ ...defect(run, attempt, settled.code, false), error: new ApiError(502, settled.code), reason: settled.reason });
      commit(run, d, attempt);
      return failed(settled.code, settled.reason, settled.why, null);
    }
    commit(run, d, attempt);
    endAttempt(run, attempt, { kind: "success" }, false, null);
  }
  const headers = new Headers({ "content-type": "application/json", "x-request-id": run.requestId, "x-gray-provider": await providerRef(route), "x-gray-attempt": String(attempt.index + 1) });
  if (run.protocol === "anthropic_messages") headers.set("request-id", run.requestId);
  for (const [name, value] of Object.entries(translation.headers())) headers.set(name, value);
  capHeaders(run, headers);
  modelHeader(run, headers);
  droppedHeader(run, headers);
  headers.set("content-length", String(bytes.length));
  // The bytes and their parse are not needed past here; the translated answer goes at its client's
  // pace through its queue, in workerd's chunk size, with its length (a FixedLengthStream carries it),
  // and stays held until the client took it (answer.ts `deliver` does the same for a native answer).
  const out = bytes;
  run.retained.set("answer", out.length);
  run.answerShare.hold(out.length, heldLimit);
  const client = new ClientStream(run.presence, clock, cfg.streamClientStallMs, run.deps.meter?.clientQueued, laneTap(run), run.deps.timers);
  const fixed = new FixedLengthStream(out.length);
  // A client that cancels its body cancels the pipe's source, the client's queue: it counts as gone.
  client.readable.pipeTo(fixed.writable).catch(() => {});
  run.answer.ttfbMs = clock() - run.started;
  run.answer.relayed = (async () => {
    // The sealed content takes the client's bytes as they go (content.md 3.5); never let a sealing fault cut a paid answer.
    try {
      run.facts.content?.push(out);
    } catch (err) {
      abandon(run, err, "content_push_failed");
    }
    let delivered = true;
    for (let at = 0; at < out.length && delivered; at += UPSTREAM_BODY_CHUNK_BYTES) delivered = await client.write(out.subarray(at, at + UPSTREAM_BODY_CHUNK_BYTES));
    client.end();
    run.answer.responseBytes = client.written;
    run.answer.responseComplete = delivered;
    run.retained.set("answer", 0);
    recordCharged(run, delivered, true);
  })().catch((error: unknown) => {
    // A fault of Gray's own after the charge: the body is cut off, the record says so.
    abandon(run, error, "relay_failed");
    stackCut(run);
    client.abort("internal_error");
    run.answer.responseBytes = client.written;
    run.retained.set("answer", 0);
    record(run, 200, "failed", "internal_error");
  });
  run.ctx.waitUntil(run.answer.relayed);
  return { kind: "response", response: new Response(fixed.readable, { status: 200, headers }) };
}

/**
 * Steps 8-10 for a buffered Responses request on a lane Codex route (D129): the upstream was asked
 * for a stream (`planOps`' declared `stream: true`), which `completedResponse` (lane/codex.ts) reads
 * to its end, keeping the terminal event's `response`; the client gets that object as a buffered
 * request's answer, exactly the bytes the vendor wrote it with, `application/json` with its length.
 *
 * Everything else is a buffered answer's, as `translatedAnswer` does it for an answer read whole: the
 * object is parsed as a Responses answer, the trust gate inspects it as the answer the client gets
 * (`inspectResponse`), its usage settles the charge (`bufferedUsage`), and the answer commits only
 * then: every failure before is `uncommitted` (nothing reached the client, nothing was charged) and
 * the dispatcher may send the next attempt. A stream that ends without its terminal event is the
 * stream's `upstream_stream_incomplete`. What the read and the answer hold is weighed against
 * ANSWER_HELD_MAX_BYTES and the isolate's answers, Gray's limit either way. The response hash taps
 * the client's stream (`laneTap`), so the receipt's `response.returned` is the JSON the client got.
 */
export async function codexAnswer(run: BufferedAnswerRun, a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
  const { cfg, clock } = run.deps;
  const route = attempt.route;
  let handed: Response | null = null;
  const handOver = (r: Response) => (handed = r);
  const failed = (code: string, reason: string, why: string, supplier: "timeout" | "upstream_error" | "invalid_response" | null, extra: { upstreamMayStillWork?: boolean; error?: ApiError; limitSource?: LimitSource } = {}): BufferedResult => {
    answerFailed(run, { attempt, relay: null, handOver, code, reason, why, supplier, ...extra });
    return { kind: "response", response: handed! };
  };
  const heldLimit = cfg.answerHeldMaxBytes;
  const uncommitted = (failure: Uncommitted): BufferedResult => {
    run.retained.set("answer", 0);
    run.answerShare.hold(0, heldLimit);
    return { kind: "uncommitted", failure };
  };
  // The stream's inspector, for the attempt's answer checks of a stream that ends before its terminal event (as
  // `prime`'s); the terminal response's are the gate's `responseChecks` below. Gated: the whole stream is held for the
  // client's one answer, and an open check reads no declared call.
  let inspector: StreamInspector;
  try {
    inspector = run.deps.gate.stream(a.contract, a.answerLimit, true);
  } catch {
    inspector = PASS_THROUGH.stream(a.contract, a.answerLimit, false);
  }
  const read = await completedResponse({
    response,
    presence: run.presence,
    answerLimit: a.answerLimit,
    frameLimit: heldLimit,
    deadline,
    silenceMs: cfg.upstreamSilenceMs,
    // What is left of the 30 s after the client left, less the settlement's retries (as the stream relay's).
    drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
    clock,
    retained: run.retained,
    isolate: run.answerShare,
    heldLimit,
    inspector,
  });
  switch (read.kind) {
    case "left": {
      attempt.controller.abort("client_left_unread");
      run.answer.leftBeforeFinal = true;
      endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left_unread");
      releaseHold(run, { reason: "client_left_unread", detail: leftDetail(run, attempt, read.received) });
      const res = errorResponse(run, new ApiError(499, "client_cancelled"));
      record(run, 499, "cancelled", "client_left_unread");
      return { kind: "response", response: res };
    }
    case "gray":
      // Gray's own limit, which no other attempt lifts: the request ends with it, free.
      if (read.limitSource === "request_output_limit") answerLimitCut(run, route, read.code, read.limitBytes, read.received);
      return failed(read.code, read.code, read.why, null, {
        upstreamMayStillWork: true,
        error: read.code === "gateway_capacity" ? capacityError() : new ApiError(502, read.code).withMeta("limit_bytes", BigInt(read.limitBytes)).withMeta("limit_source", read.limitSource),
        ...(read.code === "gateway_capacity" ? {} : { limitSource: read.limitSource }),
      });
    case "uncommitted":
      // It ended before its terminal event: its checks are its stream's inspector's, not finished; none when the
      // inspector failed while it was fed (Gray's own).
      attempt.checks = read.inspectorFailed === true ? UNCOUNTED_CHECKS : inspector.checks(false);
      return uncommitted(streamFailure(run, a, attempt, read));
    case "completed":
      break;
  }
  const upstream = a.protocol;
  const payload = read.response;
  const bytes = read.bytes;
  // The object's parse and its bytes stay held through the checks and the settlement (lane/codex.ts `keptWeight`).
  const weight = keptWeight(payload, bytes.length);
  if (weight > heldLimit) {
    const error = new ApiError(502, "upstream_body_limit").withMeta("limit_bytes", BigInt(heldLimit)).withMeta("limit_source", "gateway_memory");
    return failed("upstream_body_limit", "upstream_body_limit", `the answer would hold ${weight} weighed bytes, past the ${heldLimit} the gateway holds of one`, null, { error, limitSource: "gateway_memory" });
  }
  if (!run.answerShare.hold(weight, heldLimit)) {
    return failed("gateway_capacity", "gateway_capacity", `the answers in flight in this isolate would keep more than the ${heldLimit} weighed bytes the gateway holds of them together`, null, { error: capacityError() });
  }
  run.retained.set("answer", weight);
  let parsedAnswer;
  try {
    parsedAnswer = parseResponse(upstream, payload);
  } catch {
    return uncommitted(isErrorBody(upstream, payload) ? errorAnswer(run, a, attempt, payload) : defect(run, attempt, "invalid_upstream_protocol", false));
  }
  const calls = new ToolCallNames();
  for (const call of parsedAnswer.tool_calls) calls.add(call.name);
  run.facts.toolCalls = calls.count;
  run.facts.toolNames = calls.names;
  // The answer's checks, of the same request and whole answer as the verdict, whatever follows. Read here, with the
  // verdict, not once the answer went out: the answer is read whole and made ready before any of it goes, and reading
  // them after its delivery would keep its parse alive while the client reads, which the answer's weight no longer
  // counts from here (review r14 output-class finding 7).
  attempt.checks = run.deps.gate.responseChecks(a.contract, { protocol: upstream, body: payload });
  const verdict = run.deps.gate.inspectResponse(a.contract, { protocol: upstream, body: payload }, a.answerLimit);
  if (!inspected(run, verdict, true)) return uncommitted(defect(run, attempt, "upstream_trust_policy_rejected", false));
  const rawUsage = bufferedUsage(upstream, payload) ?? null;
  const reported = isObject(rawUsage) && parsedAnswer.usage !== null;
  const settled = await settleAnswer(
    run,
    a,
    attempt,
    reported ? bufferedSettlement(upstream, parsedAnswer.usage!, rawUsage, outputLimit(a, route)) : unreported(upstream, rawUsage),
    rawUsage,
    bufferedEnd(upstream, payload, parsedAnswer.finish_reason),
    extractBufferedBillingMeta(upstream, payload, rawUsage, run.settlement.pricingFeatures),
  );
  if (!settled.ok) {
    if (!grayAfterCheck(settled)) return uncommitted({ ...defect(run, attempt, settled.code, false), error: new ApiError(502, settled.code), reason: settled.reason });
    commit(run, d, attempt);
    return failed(settled.code, settled.reason, settled.why, null);
  }
  commit(run, d, attempt);
  endAttempt(run, attempt, { kind: "success" }, false, null);
  // The terminal response is the reply: recorded before the client has it, as `nativeAnswer` records a buffered one.
  if (laneBinds(run, a, attempt)) {
    const tap = new ResponsesStateTap();
    await laneBindState(run, a, attempt, tap.setResponse(payload));
  }
  const headers = new Headers({ "content-type": "application/json", "x-request-id": run.requestId, "x-gray-provider": await providerRef(route), "x-gray-attempt": String(attempt.index + 1) });
  if (run.protocol === "anthropic_messages") headers.set("request-id", run.requestId);
  capHeaders(run, headers);
  modelHeader(run, headers);
  droppedHeader(run, headers);
  headers.set("content-length", String(bytes.length));
  // The parse is not needed past here; the bytes stay held until the client took them (as `translatedAnswer`).
  run.retained.set("answer", bytes.length);
  run.answerShare.hold(bytes.length, heldLimit);
  const client = new ClientStream(run.presence, clock, cfg.streamClientStallMs, run.deps.meter?.clientQueued, laneTap(run), run.deps.timers);
  const fixed = new FixedLengthStream(bytes.length);
  // A client that cancels its body cancels the pipe's source, the client's queue: it counts as gone.
  client.readable.pipeTo(fixed.writable).catch(() => {});
  run.answer.ttfbMs = clock() - run.started;
  run.answer.relayed = (async () => {
    try {
      run.facts.content?.push(bytes);
    } catch (err) {
      abandon(run, err, "content_push_failed");
    }
    let delivered = true;
    for (let at = 0; at < bytes.length && delivered; at += UPSTREAM_BODY_CHUNK_BYTES) delivered = await client.write(bytes.subarray(at, at + UPSTREAM_BODY_CHUNK_BYTES));
    client.end();
    run.answer.responseBytes = client.written;
    run.answer.responseComplete = delivered;
    run.retained.set("answer", 0);
    recordCharged(run, delivered, true);
  })().catch((error: unknown) => {
    // A fault of Gray's own after the charge: the body is cut off, the record says so.
    abandon(run, error, "relay_failed");
    stackCut(run);
    client.abort("internal_error");
    run.answer.responseBytes = client.written;
    run.retained.set("answer", 0);
    record(run, 200, "failed", "internal_error");
  });
  run.ctx.waitUntil(run.answer.relayed);
  return { kind: "response", response: new Response(fixed.readable, { status: 200, headers }) };
}
