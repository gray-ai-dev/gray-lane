/**
 * The count's answers and its record (`CountTokensRun`, count-tokens.ts): the client's success and error responses, an
 * attempt and a passed-over route as the record keeps them, the record itself, and the count of the request against
 * its key's minute.
 */
import { isLocationHint, type LocationHint } from "@gray/config";
import { ApiError, shapeOf, type ClassifyContext } from "@gray/errors";
import { type JsonObject, toJsonString } from "@gray/json";
import { workspaceHome } from "../account.ts";
import { bodyTooLarge } from "../body.ts";
import { platformTimers } from "../client.ts";
import { admissionUnavailable, keyRateRefusal, type KeyRateCount } from "../key-rate.ts";
import { STACK_BODY_MAX_BYTES, STACK_OVER_LIMIT_SKIP, VM_BODY_LIMIT_SOURCE } from "../lane/body-limits.ts";
import { responseHash } from "../lane/hooks.ts";
import type { Route } from "../routes.ts";
import type { AdmissionStage, RequestRecord } from "../sinks.ts";
import type { GatewaySnapshot, KeyRecord } from "../snapshot.ts";
import { countTokensAtShard, hostOf, encoder } from "./pure.ts";
import type { CountRunCore, AttemptResult } from "./state.ts";

export function renderSuccess(run: CountRunCore, counts: JsonObject): Response {
  const json = toJsonString(counts);
  const bytes = encoder.encode(json);
  run.responseBytes = bytes.length;
  run.responseComplete = true;
  run.recordedStatus = 200;
  run.recordedOutcome = "completed";
  run.recordedErrorCode = null;
  if (run.lane !== null) {
    run.laneResponse = responseHash();
    run.laneResponse.update(bytes);
  }
  const headers = new Headers({
    "content-type": "application/json",
    "x-request-id": run.requestId,
  });
  if (run.protocol === "anthropic_messages") {
    headers.set("request-id", run.requestId);
  }
  return new Response(bytes, { status: 200, headers });
}

export function renderError(run: CountRunCore, error: ApiError, stage: AdmissionStage): Response {
  run.admission = stage;
  const rendered = error.render({ shape: shapeOf(run.path), origins: run.origins, requestId: run.requestId });
  const bytes = encoder.encode(rendered.body);
  run.responseBytes = bytes.length;
  run.responseComplete = true;
  run.recordedStatus = rendered.status;
  run.recordedOutcome = rendered.status >= 500 || rendered.status === 429 ? "failed" : "rejected";
  run.recordedErrorCode = error.code;
  if (run.lane !== null) {
    run.laneResponse = responseHash();
    run.laneResponse.update(bytes);
    if (run.lastForwardedReceipt === "peer" || run.winningReceipt === "peer") {
      run.peerReturnedBytes = bytes;
      run.peerReplacedError = true;
      run.peerGrayBody = true;
    }
  }
  return new Response(bytes, { status: rendered.status, headers: rendered.headers });
}

export function atEntry(run: CountRunCore, error: ApiError): ApiError {
  const entry = run.deps.entryChat;
  if (entry === undefined || error.code !== "verifiable_routes_at_lane") return error;
  return error.withMessage(
    `The routing preference \`verifiable: true\` asks for verifiable routes, which are served only at Gray's confidential VM address, ${entry.origin}, not at this one. Send the request there.`,
  );
}

export function classifyContext(run: CountRunCore, model: string, route: Route, restored: readonly (readonly [string, string])[]): ClassifyContext {
  return {
    model,
    upstreamModel: route.record.upstreamModel,
    endpoint: { name: route.record.name, baseUrl: route.record.baseUrl },
    restored,
    image: false,
    textFallback: run.deps.cfg.errorTextFallback === "on",
  };
}

/**
 * A stack route too small for the body (relay standard v1.7 section 4): passed over as `request_body_limit`, and the
 * client's 413 names the VM's limit when no route is asked (inference/body-limits.ts `overVmLimit`).
 */
export function overStackLimit(run: CountRunCore, route: Route): AttemptResult {
  skipRoute(run, route, STACK_OVER_LIMIT_SKIP);
  return { kind: "oversized", error: bodyTooLarge(run.protocol, STACK_BODY_MAX_BYTES, VM_BODY_LIMIT_SOURCE) };
}

export function skipRoute(run: CountRunCore, route: Route, reason: string): void {
  run.skippedRoutes.push({ endpointId: route.record.endpointId, reason });
}

export function pushAttempt(run: CountRunCore, route: Route, startedAt: number, status: number | null, outcome: string, code: string | null, rejected = false): void {
  const now = run.deps.clock();
  run.attempts.push({
    ...(rejected ? { rejected: true } : {}),
    endpointId: route.record.endpointId,
    operator: route.record.operator,
    startedAt,
    durationMs: Math.max(0, now - startedAt),
    status,
    outcome,
    code,
    model: run.model,
    upstreamModel: route.record.upstreamModel,
    upstreamHost: hostOf(route.record.url),
    protocol: route.record.protocol,
  });
}

export function sleepMs(run: CountRunCore, ms: number): Promise<void> {
  const timers = run.deps.timers ?? platformTimers;
  return new Promise<void>((resolve) => {
    timers.setTimeout(resolve, Math.max(0, ms));
  });
}

export function buildRecord(run: CountRunCore, finishedAt: number): RequestRecord {
  const key = run.key ?? run.refusedKey;
  return {
    requestId: run.requestId,
    requestKey: null,
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
    workspaceId: key?.workspaceId ?? null,
    keyId: key?.keyId ?? null,
    userId: key?.userId ?? null,
    admission: run.recordedStatus < 400 || run.attempts.length > 0 ? null : run.admission,
    heldMicrousd: null,
    boundMicrousd: null,
    outputCap: null,
    outputCapSource: null,
    outputCapReason: null,
    attempts: run.attempts,
    status: run.recordedStatus,
    outcome: run.recordedOutcome,
    errorCode: run.recordedErrorCode,
    billing: "none",
    chargedMicrousd: null,
    chargeSeq: null,
    releaseReason: null,
    usage: null,
    leftBeforeFinal: run.presence.gone,
    ttftMs: null,
    bodyTier: run.bodyTier,
    requestBytes: run.requestBytes,
    requestComplete: run.requestComplete,
    responseBytes: run.responseBytes,
    responseComplete: run.responseComplete,
    gated: false,
    ttfbMs: Math.max(0, finishedAt - run.started),
    bodyReadMs: run.bodyReadMs,
    clientIp: run.client.clientIp,
    userAgent: run.client.userAgent,
    client: run.client.client,
    clientVersion: run.client.clientVersion,
    sessionId: run.client.sessionId,
    parentSessionId: run.client.parentSessionId,
    toolCount: run.toolCount,
    turnStart: null,
    toolCalls: null,
    toolNames: null,
    reasoningTokens: null,
    isolateInFlight: run.isolateInFlight,
    heldBytes: 0,
    trustMode: run.deps.gate.mode,
    trustRequestViolations: run.trustRequestViolations,
    trustResponseViolations: [],
    trustRejected: run.trustRejected,
    upstreamProtocol: null,
    ...(run.nativeRoutesCount === null ? {} : { nativeRoutes: run.nativeRoutesCount }),
    admissionDegraded: false,
    connectionsPeak: run.outbound.peak,
    connectionsQueuedMs: run.outbound.queuedMs,
    retainedPeakBytes: run.requestBytes,
    admissions: [],
    ...(run.isolateGapMs === null ? {} : { isolateGapMs: run.isolateGapMs }),
    ...(run.preferenceFacts === undefined ? {} : { preference: run.preferenceFacts }),
    ...(run.skippedRoutes.length === 0
      ? {}
      : {
          retry: {
            attemptsAllowed: Math.max(1, run.deps.cfg.retryMaxAttempts),
            stop: run.recordedStatus === 200 ? "served" : run.recordedErrorCode,
            skipped: run.skippedRoutes,
            headReason: null,
            recoveryProbeEndpoint: null,
            recoveryRetryAfterS: null,
            requestedModel: run.model,
            fallbackModels: [],
            events: [],
          },
        }),
  };
}

export async function closeRate(run: CountRunCore, response: Response): Promise<Response> {
  if (!run.rateOpen || run.key === null || run.snapshot === null) return response;
  run.rateOpen = false;
  // A snapshot without a valid workspace home has no shard to count at (`workspaceHome`): let the refusal stand.
  if (!isLocationHint(run.snapshot.workspaces[run.key.workspaceId]?.home)) return response;
  const refused = await checkKeyRate(run, run.snapshot, run.key, false);
  if (refused === null) return response;
  // Key's 429/401 answers in place of the local refusal; no receipt is issued for a rate-limited request.
  run.laneDraft = null;
  run.laneForwardedDraft = null;
  run.winningReceipt = null;
  run.lastForwardedReceipt = null;
  run.laneReceiptId = null;
  return renderError(run, refused.error, refused.stage);
}

export async function checkKeyRate(
  run: CountRunCore,
  snapshot: GatewaySnapshot,
  key: KeyRecord,
  failClosed: boolean,
): Promise<{ readonly error: ApiError; readonly stage: AdmissionStage } | null> {
  const waitMs = run.budget.preWait(run.deps.cfg.accountAdmitAttemptMs);
  if (waitMs <= 0) {
    return failClosed ? { error: admissionUnavailable(), stage: "key_rate" } : null;
  }
  const home: LocationHint = workspaceHome(snapshot, key.workspaceId);
  const input: KeyRateCount = {
    locate: run.io.accounts,
    counts: run.deps.shardCounts,
    workspace: key.workspaceId,
    region: run.deps.region,
    home,
    keyId: key.keyId,
    requestId: run.requestId,
    waitMs,
    clock: run.deps.clock,
    ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers }),
  };
  const result = await countTokensAtShard(input);
  if (result.ok) return null;
  if (result.code === "key_rate_limit") {
    return { error: keyRateRefusal(result.limit, result.retryAfterMs, input.clock()), stage: "key_rate" };
  }
  if (result.code === "revoked") {
    return { error: new ApiError(401, "api_key_revoked"), stage: "auth" };
  }
  if (failClosed || result.code === "unavailable" || result.code === "bad_request" || result.code === "moved") {
    // The entry's container log is readable outside the VM (deploy/tee/IMPLEMENTATION_NOTES.md §9.1): there the line
    // names neither the workspace nor the key, as key-rate.ts's.
    const who = run.lane === null ? { workspace: key.workspaceId, key: key.keyId } : {};
    console.warn(
      JSON.stringify({
        level: "warn",
        event: "key_rate_count_failed",
        request_id: run.requestId,
        ...who,
        code: result.code,
      }),
    );
  }
  return failClosed ? { error: admissionUnavailable(), stage: "key_rate" } : null;
}
