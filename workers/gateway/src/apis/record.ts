/**
 * The model API request's refusals and its record (`ModelApiRun`, apis.ts): a refusal, the record and the receipt signed
 * after it, the receipt id on the response, and the key's rate count closed on the answer.
 */
import { isLocationHint } from "@gray/config";
import { ApiError } from "@gray/errors";
import { AFTER_CLIENT_LEFT_MS, platformTimers } from "../client.ts";
import { confidentialContent } from "../content.ts";
import { countKeyRate } from "../key-rate.ts";
import { bodyHashOf, laneSafeRecord } from "../lane/hooks.ts";
import { flushSinks } from "../lane/remote/sinks.ts";
import { signEntryReceipt } from "../lane/standard-api.ts";
import { recordOfFacts } from "../request-routing.ts";
import { emitRecord, recordDelivery, type AdmissionStage, type RequestOutcome, type RequestRecord } from "../sinks.ts";
import { settledBy } from "../withheld.ts";
import type { ApiRunCore } from "./state.ts";
import { accounts, errorResponse } from "./io.ts";
import { settleHeld } from "./hold.ts";

/** A request that ends here with `error`, before the hold or after it was decided. */
export function refuse(run: ApiRunCore, error: ApiError, stage: AdmissionStage | "admitted"): Response {
  run.admission = stage;
  const response = errorResponse(run, error);
  record(run, error.status, error.status >= 500 ? "failed" : error.status === 499 ? "cancelled" : "rejected", error.code);
  return response;
}

export function record(run: ApiRunCore, status: number, outcome: RequestOutcome, code: string | null): void {
  if (run.recorded) return;
  // The request's count may still answer the key's 429 in this refusal's place: its record waits (`closeRate`).
  if (run.rateOpen) {
    run.pendingRecord = { status, outcome, code };
    return;
  }
  // The request ends: a refusal still held for a failover counts against its route if the answer reached
  // the client, and is dropped otherwise (`close_request`).
  settleHeld(run, outcome === "completed");
  run.recorded = true;
  run.answerShare.release();
  run.deps.load.leave();
  const finishedAt = run.deps.clock();
  const record: RequestRecord = {
    requestId: run.requestId,
    requestKey: run.requestKey,
    startedAt: run.started,
    finishedAt,
    method: run.request.method,
    path: run.path,
    protocol: run.protocol,
    model: run.model,
    stream: false,
    region: run.deps.region,
    entry: run.deps.entry,
    authResult: run.authResult,
    authScheme: run.authScheme,
    workspaceId: run.key?.workspaceId ?? null,
    keyId: run.key?.keyId ?? null,
    userId: run.key?.userId ?? null,
    admission: run.admission,
    heldMicrousd: run.heldMicrousd,
    boundMicrousd: run.boundMicrousd,
    outputCap: null,
    outputCapSource: null,
    outputCapReason: null,
    attempts: [...run.attempts],
    status,
    outcome,
    errorCode: code,
    billing: run.billing,
    freeReason: run.freeReason,
    chargedMicrousd: run.charged,
    chargedInputMicrousd: run.chargedSides?.input ?? null,
    chargedOutputMicrousd: run.chargedSides?.output ?? null,
    chargeSeq: run.chargeSeq,
    releaseReason: run.releaseReason,
    usage: run.usage,
    leftBeforeFinal: run.leftBeforeFinal,
    ttftMs: null,
    bodyTier: run.bodyTier,
    requestBytes: run.requestBytes,
    requestComplete: run.requestComplete,
    responseBytes: run.responseBytes,
    responseComplete: run.responseComplete,
    gated: false,
    ttfbMs: run.ttfbMs ?? finishedAt - run.started,
    bodyReadMs: run.bodyReadMs,
    ...run.client,
    toolCount: null,
    turnStart: null,
    toolCalls: null,
    toolNames: null,
    reasoningTokens: null,
    isolateInFlight: run.isolateInFlight,
    heldBytes: run.heldBytes,
    trustMode: run.deps.gate.mode,
    trustRequestViolations: [],
    trustResponseViolations: [],
    trustRejected: false,
    upstreamProtocol: null,
    admissionDegraded: run.admissionDegraded,
    admissions: [...run.admissions],
    connectionsPeak: run.outbound.peak,
    connectionsQueuedMs: run.outbound.queuedMs,
    retainedPeakBytes: run.retained.peak,
    ...(run.preferenceRecord === null ? {} : { preference: run.preferenceRecord }),
    ...(run.routingGroup === "" ? {} : { routingGroup: run.routingGroup, rankingBaseAgeMs: run.rankingBaseAgeMs }),
    ...(run.floorRelaxed === null ? {} : { floorRelaxed: { preset: run.routingParams.preset, ...run.floorRelaxed } }),
    ...(run.routingEvidence === null ? {} : { routingEvidence: run.routingEvidence, eligibleRoutes: run.eligibleRoutes }),
    routingCandidates: run.routingCandidates,
    // How the request was routed (request_logs.routing): the record of the facts as they stand now; at the entry its
    // projection, bounded as it leaves the CVM (inference.ts).
    routing: recordOfFacts(run.routingFacts, run.preferenceLevels, run.preference.order, run.routingEvidence, run.headReason, run.lane !== null),
    ...(run.isolateGapMs === undefined ? {} : { isolateGapMs: run.isolateGapMs }),
    routeRefusals: [...run.routeRefusals],
    retry: {
      attemptsAllowed: run.attemptsAllowedCount,
      stop: run.retryStop,
      skipped: [...run.skippedRoutes],
      headReason: run.headReason,
      recoveryProbeEndpoint: run.recoveryProbeEndpoint,
      recoveryRetryAfterS: run.recoveryRetryAfterS,
      // The model APIs take no list of fallback models (apis/mod.rs: `requested_model: None`, `fallback_models: vec![]`).
      requestedModel: null,
      fallbackModels: [],
      events: [...run.retryEvents],
    },
  };
  run.entryBody = null;
  run.entryForwards = null;
  const sinks = run.outbound.sinks(run.deps.sinks);
  // A record of the confidential entry carries no client fingerprint (lane/hooks.ts `laneSafeRecord`).
  const safe = laneSafeRecord(record);
  // The confidential entry keeps no request content (inference.ts `openContent`): the row says so, never a failure.
  // The platform's 30 s run from the answer's end, or from the client's leaving when that came first.
  const end = Math.min(finishedAt, run.presence.at ?? finishedAt) + AFTER_CLIENT_LEFT_MS;
  const delivery = recordDelivery(run.deps.cfg, end, run.deps.clock, platformTimers);
  const withheld = run.withheld;
  const emitted = (async () => {
    // The entry's receipt is signed and stored as soon as the answer has ended, beside the record's own work and never
    // after its sends (inference.ts `record`): a client that verifies at once finds it.
    const receipt = run.responded.then(() => laneReceipt(run));
    // A withheld answer's record says how its hold's resolution ended (`withhold`), when that ends while the record
    // still has its reserve (CONTENT_TAIL_RESERVE_MS, as on the inference path); past it the record says unsettled.
    const timers = run.deps.waitTimers ?? run.deps.timers ?? platformTimers;
    const ended = withheld !== null && (await settledBy(withheld, end - run.deps.cfg.contentTailReserveMs, run.deps.clock, timers)) ? { ...safe, billing: run.billing, releaseReason: run.releaseReason } : safe;
    await emitRecord({ record: ended, sinks, content: confidentialContent(), service: run.deps.service, evidence: run.traffic.buffer.wire(), delivery });
    await receipt;
    // The lane's sinks buffer: the request's point and service events exist from here on (lane/remote/sinks.ts).
    await flushSinks(run.deps.sinks as unknown as { flush?: () => Promise<unknown> });
  })().catch(() => {});
  run.ctx.waitUntil(emitted);
}

/**
 * The entry's receipt id on the response the client gets, whatever built it (inference.ts `serve`): only when a
 * receipt will be signed for it, a committed attempt's or the last body a provider's fetch took. The id reads as
 * pending until its receipt is stored or the request ends without one (`laneReceipt`).
 */
export function named(run: ApiRunCore, response: Response): Response {
  const lane = run.lane;
  if (run.laneReceiptId === null || (run.laneDraft ?? run.laneForwardedDraft) === null || run.laneOwner === null) return response;
  const headers = new Headers(response.headers);
  headers.set("x-receipt-id", run.laneReceiptId);
  lane.state.receipts.announce(run.laneReceiptId, run.laneOwner);
  run.laneAnnounced = run.laneReceiptId;
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * The receipt of a request the entry served (docs/design/standard-media-at-entry.md section 2.4), signed once the
 * answer has ended, under the id the response named: the committed attempt's draft, else the last one whose body a
 * provider's fetch took. A request that forwarded nothing has no honest receipt and none is signed. Metadata: a
 * failure is logged without content and never changes the answer.
 */
export async function laneReceipt(run: ApiRunCore): Promise<void> {
  const lane = run.lane;
  const receiptId = run.laneReceiptId;
  try {
    const draft = run.laneDraft ?? run.laneForwardedDraft;
    if (draft !== null && receiptId !== null && run.laneReceivedHash !== null && run.laneOwner !== null) {
      await signEntryReceipt(lane, {
        ctx: run.ctx,
        receiptId,
        model: run.model,
        path: run.path,
        method: run.request.method,
        servedAtMs: run.deps.clock(),
        receivedHash: run.laneReceivedHash,
        draft,
        responseHash: run.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)),
        owner: run.laneOwner,
      });
    }
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: run.requestId, receipt_id: receiptId, name: error instanceof Error ? error.name : "unknown" }));
  } finally {
    // A stored receipt is no longer pending; an id the response named with no receipt under it reads as unknown.
    if (run.laneAnnounced !== null) lane.state.receipts.withdraw(run.laneAnnounced);
  }
}

/**
 * The end of a keyed request that no admission counted against its key's requests per minute (`rateOpen`): one call
 * to an account shard counts it (key-rate.ts `countKeyRate`), as the server's preflight counts every keyed request
 * (apis/mod.rs `forward_traced`). A key over its minute is answered the server's 429 in place of the request's own
 * refusal, at stage `key_rate`; otherwise the refusal that waited is recorded as it was.
 */
export async function closeRate(run: ApiRunCore, response: Response): Promise<Response> {
  if (!run.rateOpen) return response;
  run.rateOpen = false;
  const key = run.key!;
  const home = run.snapshot?.workspaces[key.workspaceId]?.home;
  // A snapshot without the workspace's home has no shard to count at (`workspaceHome`): the refusal stands. So it
  // does when an admission attempt the gateway gave up on admitted after all, or has not answered (its shard counted
  // the request, or still may): a second count would take two units of the key's minute for one request.
  const over =
    !isLocationHint(home) || run.rateAdmission?.() === true
      ? null
      : await countKeyRate({
          locate: accounts(run),
          counts: run.deps.shardCounts,
          workspace: key.workspaceId,
          region: run.deps.region,
          home,
          keyId: key.keyId,
          requestId: run.requestId,
          waitMs: run.deps.cfg.accountAdmitAttemptMs,
          clock: run.deps.clock,
          ...(run.deps.admissionTimers === undefined ? {} : { timers: run.deps.admissionTimers }),
          lane: true,
        });
  const pending = run.pendingRecord;
  run.pendingRecord = null;
  if (over === null || pending === null) {
    if (pending !== null) record(run, pending.status, pending.outcome, pending.code);
    return response;
  }
  // The key's minute answers instead of the refusal that waited.
  return refuse(run, over, "key_rate");
}
