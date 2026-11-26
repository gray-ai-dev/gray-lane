/**
 * The request's record and its refusals (`InferenceRun`, inference.ts): the client's error response, a refusal, what an
 * inspection found, the record, written once the request ends or held while a later model or the key's count may still
 * answer, and the count of a keyed request against its key's minute.
 */
import { type LocationHint, isLocationHint } from "@gray/config";
import { type DetailsRecord, type WriterResult, notWritten } from "@gray/content";
import { ApiError, shapeOf } from "@gray/errors";
import { droppedHeaders } from "@gray/translation";
import { accountBlockGauges, accountBlockIsolate } from "../account-blocks.ts";
import { withinPhase } from "../budget.ts";
import { AFTER_CLIENT_LEFT_MS, platformTimers } from "../client.ts";
import { type KeylessLimits, confidentialContent } from "../content.ts";
import { viaEntryOf } from "../entry-forward.ts";
import type { GateVerdict } from "../gate.ts";
import { type KeyRateCount, countKeyRate } from "../key-rate.ts";
import { laneSafeRecord } from "../lane/hooks.ts";
import { flushSinks } from "../lane/remote/sinks.ts";
import { withoutTicket } from "../model-check.ts";
import { redactedHeaders, redactedQuery } from "../redact.ts";
import { recordOfFacts } from "../request-routing.ts";
import { type AdmissionStage, type RequestOutcome, type RequestRecord, contentAttempts, emitRecord, recordDelivery, usageCounters } from "../sinks.ts";
import type { KeyRecord } from "../snapshot.ts";
import { settledBy } from "../withheld.ts";
import { type AttemptRun, settleHeld } from "./attempt.ts";
import { type LaneReceiptRun, finishLane, laneReceipt, restartLaneResponse, stackErrorWritten, withPeerTrace } from "./lane-receipt.ts";
import type { Attempt, ModelResult } from "./types.ts";

const encoder = new TextEncoder();

/** What record.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface RecordRun extends LaneReceiptRun, AttemptRun {
  readonly responded: Promise<void>;
}

/**
 * The client's error response; its body is the response part of the request's content. A refusal a later
 * model may still replace waits for the end (`pendingErrorBody`): only the answer the client gets is kept.
 * `handedOn`: the dispatcher left the request to the next model the customer listed (`Unserved::NextModel`).
 */
export function errorResponse(run: RecordRun, error: ApiError, handedOn = false): Response {
  const rendered = error.render({ shape: shapeOf(run.path), origins: run.origins, requestId: run.requestId });
  const body = encoder.encode(rendered.body);
  if (holding(run)) run.answer.pendingErrorBody = body;
  else run.facts.content?.push(body);
  run.answer.responseBytes = body.length;
  // A lane answer the client gets as an error body rather than a stream: its bytes are what
  // `response.returned` hashes (design v2 §C.9), and there is no client stream to tap.
  if (run.lane !== null && run.receipt.laneResponse !== null) run.receipt.laneResponse.update(body);
  stackErrorWritten(run, body, true);
  const response = new Response(body, { status: rendered.status, headers: rendered.headers });
  // Gray's error names what the native body dropped as its answer would (`mark_dropped` on the response
  // `serve_model` returns), except a refusal handed to the next model, which `serve_model` returns unmarked even
  // when no model follows. Nothing is dropped before the request is prepared (`prepare`).
  if (!handedOn) droppedHeader(run, response.headers);
  return response;
}

/**
 * The content's details record (content.md 4.2, the server's store.rs `Details` without its attempts): the
 * headers and query with their credentials redacted (redact.ts), the usage, and why no further upstream
 * attempt followed one that failed. A model-check ticket's header is left out, valid or not (model-check.ts).
 */
export function details(run: RecordRun, record: RequestRecord): DetailsRecord {
  const key = run.deps.fingerprintKey;
  const query = new URL(run.request.url).search;
  return {
    request_headers: redactedHeaders(key, withoutTicket(run.request.headers)),
    response_headers: run.answer.responseHead === null ? [] : redactedHeaders(key, run.answer.responseHead.headers),
    query: redactedQuery(key, query.length > 1 ? query.slice(1) : null),
    usage: usageCounters(record.usage),
    retry_stop: record.retry?.stop ?? null,
  };
}

/** A request that ends here with `error` and never reached the hold, or whose hold was released already. */
export function refuse(run: RecordRun, error: ApiError, stage: AdmissionStage | "admitted"): Response {
  run.admitting.admission = stage;
  const response = errorResponse(run, error);
  record(run, error.status, error.status >= 500 ? "failed" : error.status === 499 ? "cancelled" : "rejected", error.code);
  return response;
}

/**
 * The end of a keyed request that no admission counted against its key's requests per minute (`rateOpen`): one call
 * to an account shard counts it (key-rate.ts `countKeyRate`), as the server's preflight counts every keyed request.
 * A key over its minute is answered the server's 429 in place of the request's own refusal, at stage `key_rate`;
 * otherwise the refusal that waited is recorded as it was. Once per request; a request whose refusal was never held
 * (none was made) is counted and answered as it is.
 */
export async function closeRate(run: RecordRun, response: Response): Promise<Response> {
  if (!run.caller.rateOpen) return response;
  run.caller.rateOpen = false;
  const key = run.caller.key!;
  const home = run.routing.snapshot?.workspaces[key.workspaceId]?.home;
  // A snapshot without the workspace's home has no shard to count at (`workspaceHome`): the refusal stands. So it
  // does when an admission attempt the gateway gave up on admitted after all, or has not answered (its shard counted
  // the request, or still may): a second count would take two units of the key's minute for one request.
  const over = !isLocationHint(home) || run.caller.rateAdmissions.some((mayHaveCounted) => mayHaveCounted()) ? null : await countKeyRate(rateCount(run, key, home, run.deps.cfg.accountAdmitAttemptMs));
  if (over === null || run.log.pendingRecord === null) {
    flushRecord(run);
    return response;
  }
  // The key's minute answers instead: the refusal that waited is not the answer (its body was hashed for the lane's
  // receipt when it was rendered, so the lane hashes the answer's again from the start, as a later model's does).
  run.log.pendingRecord = null;
  run.answer.pendingErrorBody = null;
  run.log.deferRecord = false;
  if (run.lane !== null) restartLaneResponse(run);
  return refuse(run, over, "key_rate");
}

/** One count of the request against `key`'s minute at its home's shard, waiting `waitMs` (key-rate.ts `countKeyRate`, `countModelCheck`). */
export function rateCount(run: RecordRun, key: KeyRecord, home: LocationHint, waitMs: number): KeyRateCount {
  return {
    locate: run.io.accounts,
    counts: run.deps.shardCounts,
    workspace: key.workspaceId,
    region: run.deps.region,
    home,
    keyId: key.keyId,
    requestId: run.requestId,
    waitMs,
    clock: run.deps.clock,
    ...(run.deps.admissionTimers === undefined ? {} : { timers: run.deps.admissionTimers }),
    ...(run.lane === null ? {} : { lane: true }),
  };
}

/** Keeps what an inspection found (each code once); false when it refused. */
export function inspected(run: RecordRun, verdict: GateVerdict, response: boolean): boolean {
  const list = response ? run.answer.trustResponse : run.answer.trustRequest;
  // An audited violation is evidence against the answer's mapping; a tool call passed for the client to check
  // is neither that nor proof that the mapping's tool calls work (`policy`).
  const evidence = response ? run.admitting.current?.evidence : undefined;
  if (evidence !== undefined && verdict.ok) {
    if (verdict.passed.length > 0) evidence.passedToolCall = true;
    if (verdict.violations.length > 0) evidence.flagged = true;
  }
  const found = verdict.ok ? [...verdict.violations, ...verdict.passed] : [verdict.violation];
  for (const code of found) if (!list.includes(code)) list.push(code);
  if (!verdict.ok) run.answer.trustRejected = true;
  return verdict.ok;
}

/** Notes a null member left out of what the client gets of `attempt`'s answer, once (`Admission::drop_nulls`). */
export function droppedNull(run: RecordRun, attempt: Attempt, member: string): void {
  const list = run.log.droppedNulls.get(attempt) ?? [];
  if (!list.includes(member)) list.push(member);
  run.log.droppedNulls.set(attempt, list);
}

/**
 * The model being served joins (`relaxable` true: its preset's own floor alone refused it, inference/ranking.ts and the
 * translation's judge in serve-model.ts) or leaves (false: it was admitted, admission.ts) the models the relaxed floor's
 * pass tries (intake.ts). A model admitted in the first pass is never served again, so no admission takes an id twice.
 * The last model of the first pass holds its refusal only while some model is left to try, so a request with none
 * answers as before (a stack relay's vendor error as it is, S24). Nothing changes in the relaxed pass itself.
 */
export function noteRelaxable(run: RecordRun, relaxable: boolean): void {
  if (run.routing.relaxFloor) return;
  const list = run.routing.relaxable;
  const at = list.indexOf(run.admitting.modelIndex);
  if (relaxable && at < 0) list.push(run.admitting.modelIndex);
  if (!relaxable && at >= 0) list.splice(at, 1);
  if (run.routing.lastOfPass) run.log.deferRecord = list.length > 0;
}

/**
 * Whether a refusal's record and error body wait: a later model the customer listed may still serve the request
 * (`deferRecord`), or the request's count may still answer the key's 429 in its place (`rateOpen`).
 */
export function holding(run: RecordRun): boolean {
  return run.log.deferRecord || run.caller.rateOpen;
}

export function record(run: RecordRun, status: number, outcome: RequestOutcome, code: string | null): void {
  if (run.log.recorded) return;
  // A later model the customer listed may still serve the request, or its count answer 429: its record waits.
  if (holding(run)) {
    run.log.pendingRecord = { status, outcome, code };
    return;
  }
  // The request ends: a refusal still held for a failover counts against its route if the answer reached
  // the client, and is dropped otherwise (`close_request`).
  settleHeld(run, outcome === "completed");
  run.log.recorded = true;
  run.log.recordedStatus = status;
  for (const release of run.facts.holds) release();
  run.deps.load.leave();
  run.answerShare.release();
  const finishedAt = run.deps.clock();
  // S27, S32: a stack relay's request names the relay account whose vendor answer ended it: the answer that
  // was charged (a client that left before its end included: the per-account usage and the relay's windows
  // count what each account consumed), or the vendor error the client was served (errors per account; it
  // carries no tokens). None when no account's vendor answer ended it (egress_limit, refusals, relay faults,
  // nothing dialed, a container that never finished).
  const relayAccountId = run.stackPeer.stackAnsweredAccount;
  const record: RequestRecord = {
    requestId: run.requestId,
    requestKey: run.caller.requestKey,
    startedAt: run.started,
    finishedAt,
    method: run.request.method,
    path: run.path,
    protocol: run.protocol,
    model: run.facts.model,
    stream: run.facts.stream,
    region: run.deps.region,
    entry: run.deps.entry,
    authResult: run.caller.authResult,
    authScheme: run.caller.authScheme,
    workspaceId: (run.caller.key ?? run.caller.refusedKey)?.workspaceId ?? null,
    keyId: (run.caller.key ?? run.caller.refusedKey)?.keyId ?? null,
    userId: (run.caller.key ?? run.caller.refusedKey)?.userId ?? null,
    admission: run.admitting.admission,
    heldMicrousd: run.settlement.heldMicrousd,
    boundMicrousd: run.settlement.boundMicrousd,
    outputCap: run.facts.outputCap,
    outputCapSource: run.facts.outputCapSource,
    outputCapReason: run.facts.outputCapReason,
    attempts: [...run.log.attempts],
    status,
    outcome,
    errorCode: code,
    billing: run.settlement.billing,
    chargedMicrousd: run.settlement.charged,
    chargedInputMicrousd: run.settlement.chargedSides?.input ?? null,
    chargedOutputMicrousd: run.settlement.chargedSides?.output ?? null,
    chargeSeq: run.settlement.chargeSeq,
    releaseReason: run.settlement.releaseReason,
    freeReason: run.settlement.freeReason,
    usage: run.settlement.usage,
    leftBeforeFinal: run.answer.leftBeforeFinal,
    ttftMs: run.answer.ttftMs,
    bodyTier: run.facts.bodyTier,
    requestBytes: run.facts.requestBytes,
    requestComplete: run.facts.requestComplete,
    responseBytes: run.answer.responseBytes,
    responseComplete: run.answer.responseComplete,
    gated: run.answer.gated,
    // A response handed over at its end (a refusal, a buffered answer) gave its first byte then.
    ttfbMs: run.answer.ttfbMs ?? finishedAt - run.started,
    bodyReadMs: run.facts.bodyReadMs,
    ...run.client,
    toolCount: run.facts.toolCount,
    turnStart: run.facts.turnStart,
    toolCalls: run.facts.toolCalls,
    toolNames: run.facts.toolNames,
    reasoningTokens: run.facts.reasoningTokens,
    isolateInFlight: run.isolateInFlight,
    heldBytes: run.answer.heldBytes,
    trustMode: run.deps.gate.mode,
    trustRequestViolations: [...run.answer.trustRequest],
    trustResponseViolations: [...run.answer.trustResponse],
    trustRejected: run.answer.trustRejected,
    upstreamProtocol: run.facts.translation?.upstream ?? null,
    nativeRoutes: run.facts.nativeRouteCount,
    translationDropped: run.facts.translation !== null ? [...run.facts.translation.dropped] : [...run.facts.nativeDropped],
    admissionDegraded: run.admitting.admissionDegraded,
    admissions: [...run.admitting.admissions],
    connectionsPeak: run.outbound.peak,
    connectionsQueuedMs: run.outbound.queuedMs,
    retainedPeakBytes: run.retained.peak,
    routingCandidates: run.admitting.routingCandidates,
    // How the request was routed (request_logs.routing): the record of the facts as they stand now; in lane mode the
    // confidential entry's projection, bounded as it leaves the CVM.
    routing: recordOfFacts(run.routing.routingFacts, run.routing.preferenceLevels, run.routing.preference.order, run.routing.routingEvidence, run.admitting.headReason, run.lane !== null),
    ...(run.routing.preferenceRecord === null ? {} : { preference: run.routing.preferenceRecord }),
    ...(run.routing.routingGroup === "" ? {} : { routingGroup: run.routing.routingGroup, rankingBaseAgeMs: run.routing.rankingBaseAgeMs }),
    ...(run.routing.routingEvidence === null ? {} : { routingEvidence: run.routing.routingEvidence }),
    ...(run.routing.eligibleRoutes === null ? {} : { eligibleRoutes: run.routing.eligibleRoutes }),
    routeRefusals: [...run.routing.routeRefusals],
    ...(run.routing.isolateGapMs === undefined ? {} : { isolateGapMs: run.routing.isolateGapMs }),
    ...(run.routing.checksUnapplied === null ? {} : { checksUnapplied: { reason: run.routing.checksUnapplied, waitedMs: run.routing.rankingWaitMs } }),
    ...(run.routing.floorRelaxed === null ? {} : { floorRelaxed: { preset: run.routing.routingParams.preset, ...run.routing.floorRelaxed } }),
    ...(relayAccountId === null ? {} : { relayAccountId }),
    retry: {
      attemptsAllowed: run.admitting.attemptsAllowedCount,
      stop: run.admitting.retryStop,
      skipped: [...run.admitting.skippedRoutes],
      headReason: run.admitting.headReason,
      recoveryProbeEndpoint: run.admitting.recoveryProbeEndpoint,
      recoveryRetryAfterS: run.admitting.recoveryRetryAfterS,
      requestedModel: run.admitting.listedModels.length > 0 ? run.admitting.listedModels[0]! : null,
      fallbackModels: run.admitting.listedModels.slice(1),
      events: [...run.admitting.retryEvents],
    },
  };
  // A lane record carries no client fingerprint (design v2 §D, M13, M20): the bridge's sink and the
  // tables behind it are Gray's, and the lane's promise is that Gray learns nothing of the client.
  const safe = run.lane === null ? record : laneSafeRecord(record);
  const content = run.facts.content;
  // The content's deadline: the end of the answer plus the platform's 30 s for waitUntil, less what
  // the record itself needs to go out (content.md 3.6). Past it the content is failed, the row sent.
  // The platform's 30 s run from when the client left, not from the end of an answer drained after it
  // left (relay.ts `drainMs`), so a client that left first sets the start.
  const deadline = Math.min(finishedAt, run.presence.at ?? finishedAt) + AFTER_CLIENT_LEFT_MS - run.deps.cfg.contentTailReserveMs;
  const requestComplete = run.facts.requestComplete;
  run.log.emitted = (async () => {
    // The response's headers are the details' too: they are known once `serve` handed the response over.
    await run.responded;
    // The lane's receipt is signed and stored now, as the answer has ended (its bytes are hashed as they are queued to
    // the client, so the hash is final), beside the record's own work rather than after it: a client that verifies at
    // once finds it, where after the record's sends (two bridge calls, LANE_BRIDGE_CALL_MS each) it was 404 for
    // seconds (staging 2026-11-18, lane release V).
    const receipt = laneReceipt(run);
    // A withheld answer's record says how its hold's resolution ended (`withhold`), when that ends before the content's
    // deadline (at most two settle budgets after the answer); past it the record says unsettled.
    let ended = record;
    let endedSafe = safe;
    if (run.settlement.withheld !== null && (await settledBy(run.settlement.withheld, deadline, run.deps.clock, run.deps.waitTimers ?? run.deps.timers ?? platformTimers))) {
      const billing = { billing: run.settlement.billing, releaseReason: run.settlement.releaseReason };
      ended = { ...record, ...billing };
      endedSafe = { ...safe, ...billing };
    }
    // S43: an entry's request that went over the peer hop has the trace its stack VMs sent (`withPeerTrace`).
    const emitted = run.stackPeer.peerCalls.length > 0 ? await withPeerTrace(run, endedSafe) : endedSafe;
    let result: WriterResult;
    if (run.lane !== null) {
      // The confidential entry opens no writer (`openContent`): its row says the content was not kept, by design.
      result = confidentialContent();
    } else if (content === null) {
      result = notWritten("failed", "no_recipient");
    } else if (content.placement.kind === "anonymous" && run.deps.keyless !== null && !(await keylessAllowed(run, run.deps.keyless))) {
      // A keyless request past its sender's or its location's limit: no object, no index row (content.md 9).
      content.discard();
      result = notWritten("failed", "keyless_rate");
    } else {
      // Each attempt a record of its own, as the request record ends them (what followed a failure, its
      // error body as read), then the details.
      for (const attempt of contentAttempts(ended)) content.attempt(attempt);
      result = await content.finish({ deadline, details: details(run, ended), requestComplete });
    }
    const now = run.deps.clock();
    const gauge = run.deps.accountBlocks === undefined ? accountBlockGauges.next(now, () => accountBlockIsolate.paused(now)) : null;
    const delivery = recordDelivery(run.deps.cfg, deadline + run.deps.cfg.contentTailReserveMs, run.deps.clock, run.deps.waitTimers ?? run.deps.timers ?? platformTimers);
    await emitRecord({ record: emitted, sinks: run.io.sinks, content: result, service: run.deps.service, gauge, evidence: run.traffic?.buffer.wire() ?? null, delivery });
    // The relay's outcome report closes the request here, in the same `waitUntil` (design v2 §C.10), after the
    // receipt (F2 D31): both are metadata that may fail without changing what the client already got.
    await receipt;
    finishLane(run, emitted, finishedAt);
    // The lane's sinks buffer (remote/sinks.ts): the point and the service events of this request
    // exist from here on and never before, so the flush belongs after the record (F2 bridge-1).
    // `deps.sinks` is the request's `RemoteSinks`; `io.sinks` (Outbound) has no `flush`.
    // `deps.sinks` is a `Sinks`; only the lane's `RemoteSinks` has `flush`, which `flushSinks` reads.
    if (run.lane !== null) await flushSinks(run.deps.sinks as unknown as { flush?: () => Promise<unknown> });
  })().catch(() => {});
  run.ctx.waitUntil(run.log.emitted);
}

/**
 * Whether a keyless request's content is within its sender's and its location's limits (content.md 9), asked within
 * REQUEST_POST_BUDGET_MS: limits that do not answer by then let it through, as limits that fail do (`keylessLimits`),
 * so a stalled binding never holds the record past the platform's 30 s.
 */
export async function keylessAllowed(run: RecordRun, keyless: KeylessLimits): Promise<boolean> {
  const asked = run.outbound.run(() => keyless.allow(run.client.clientIp, viaEntryOf(run.request.headers)), false);
  try {
    return await withinPhase(asked, run.deps.cfg.requestPostBudgetMs, run.deps.waitTimers ?? run.deps.timers ?? platformTimers);
  } catch {
    return true;
  }
}

/**
 * A native answer names what its request dropped of an earlier translated turn (`mark_dropped`); a translated one
 * names what its translation dropped (`mark_response`, `Translation.headers`), and nothing else.
 */
export function droppedHeader(run: RecordRun, headers: Headers): void {
  if (run.facts.translation !== null) return;
  for (const [name, value] of Object.entries(droppedHeaders(run.facts.nativeDropped))) headers.set(name, value);
}

/**
 * The request ends with the response of this model: a record that waited is written now, unless the request's count
 * is still to come (`closeRate` writes it then).
 */
export function flushRecord(run: RecordRun): void {
  run.log.deferRecord = false;
  if (run.caller.rateOpen) return;
  const pending = run.log.pendingRecord;
  run.log.pendingRecord = null;
  // The refusal that waited is the answer the client gets: the content keeps it.
  const body = run.answer.pendingErrorBody;
  run.answer.pendingErrorBody = null;
  if (body !== null) run.facts.content?.push(body);
  if (pending !== null) record(run, pending.status, pending.outcome, pending.code);
}

/**
 * A refusal of this model only (`Unserved::NextModel`): no eligible provider, none in the request's region,
 * no priced route, a translation that cannot take it, a hold its prices cannot size, or every attempt it
 * was allowed failed. The next model the customer listed may serve the request; without one this is the
 * client's error.
 */
export function unserved(run: RecordRun, error: ApiError, stage: AdmissionStage | "admitted"): ModelResult {
  return { kind: "next", response: refuse(run, error, stage) };
}
