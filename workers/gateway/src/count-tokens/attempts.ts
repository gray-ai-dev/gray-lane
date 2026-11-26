/**
 * A count's attempt on one route (`CountTokensRun`, count-tokens.ts): which path a route takes, the main gateway's
 * attempt, an entry's endpoint route and an entry's lane relay route.
 */
import { ApiError } from "@gray/errors";
import { type JsonObject, get, isObject, setMember, toJsonString } from "@gray/json";
import { applyDeclaredChanges, checkOfficialUpstream, type GrayRewriteOp } from "@gray/lane";
import { requestLimit } from "@gray/limits";
import { Overlay, countOverlay } from "@gray/protocol";
import type { Preference } from "@gray/routing";
import { openCredential } from "../crypto.ts";
import { EGRESS_HEADER, bodyHashOf, egressHeader, laneDuplicateKey, laneHeaders, lanePolicyRefused, laneUpstreamOf, officialUpstream, receiptDraft } from "../lane/hooks.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import { applyGeminiCountModelRewrite } from "../lane/standard-api.ts";
import type { LaneDeps, LaneEgress } from "../lane/types.ts";
import type { Route } from "../routes.ts";
import { upstreamHeaders } from "../upstream.ts";
import { laneEndpointRoute, laneEndpointKey, stackRoute, entryPeers, runLanePolicy, laneAffinityFor, reportLaneNotSent, flushLaneReports } from "./lane.ts";
import { attemptPeer } from "./peer.ts";
import { countedValue, countUrlOf, laneVendor, laneFailureCode, encoder } from "./pure.ts";
import { skipRoute, sleepMs } from "./record.ts";
import { executeHttpAttempt } from "./send.ts";
import type { CountRunCore, AttemptResult } from "./state.ts";
import { issuerOf } from "./tool-ids.ts";

export async function runRoute(run: CountRunCore, input: {
  readonly route: Route;
  readonly model: string;
  readonly value: JsonObject;
  readonly received: Uint8Array;
  readonly statedProvider: boolean;
  readonly preference: Preference;
  readonly deadline: number;
  readonly attemptIndex: number;
  readonly repeatedConnect: boolean;
}): Promise<AttemptResult> {
  const { route } = input;
  if (run.lane === null) {
    return attemptMain(run, input);
  }
  if (stackRoute(run, route.record)) {
    if (entryPeers(run) !== null) return attemptPeer(run, input);
    skipRoute(run, route, "lane_stack_unavailable");
    return { kind: "pass" };
  }
  if (route.record.auth === "lane_relay") {
    return attemptLaneRelay(run, input);
  }
  if (laneEndpointRoute(run, route.record)) {
    return attemptLaneEndpoint(run, input);
  }
  skipRoute(run, route, "route_inactive");
  return { kind: "pass" };
}

export async function attemptMain(run: CountRunCore, input: {
  readonly route: Route;
  readonly model: string;
  readonly value: JsonObject;
  readonly deadline: number;
  readonly repeatedConnect: boolean;
}): Promise<AttemptResult> {
  const { route, model, value, deadline, repeatedConnect } = input;
  const master = await run.deps.master();
  const credential = master === null ? null : await openCredential(master, route.record.endpointId, route.record.credential);
  if (credential === null) {
    skipRoute(run, route, "route_inactive");
    return { kind: "pass" };
  }

  const targetUrl = countUrlOf(run.protocol, route.record.url);
  if (targetUrl === null) {
    skipRoute(run, route, "invalid_native_mapping");
    return { kind: "pass" };
  }

  // End-user identifiers never reach the provider (docs/api-provider-standard.en.md 2.3): Anthropic's
  // `metadata.user_id` is taken out, and `metadata` with it when it held nothing else, as on generation.
  const cloned = new Overlay().withoutEndUserIds(run.protocol, value).apply(value) as JsonObject;
  const overlay = countOverlay(run.protocol, cloned, route.record.upstreamModel);
  if (overlay !== undefined) {
    setMember(cloned, overlay[0], overlay[1]);
  }

  let restored = 0;
  let unvouched = false;
  let restoredPairs: readonly (readonly [string, string])[] = [];
  if (run.toolIds !== null) {
    run.toolIds.startAttempt();
    const issuer = await issuerOf(run, route.record, credential);
    const change = run.toolIds.forAttempt(issuer, run.protocol);
    if (change.value !== null) {
      change.value(countedValue(run.protocol, cloned));
    }
    const rec = run.toolIds.record();
    restored = rec?.restored ?? 0;
    unvouched = run.toolIds.sentUnvouched;
    restoredPairs = run.toolIds.restoredPairs;
  }

  const payloadBytes = encoder.encode(toJsonString(cloned));
  if (restored > 0 && payloadBytes.length > Number(requestLimit(run.protocol))) {
    skipRoute(run, route, "request_body_limit");
    return {
      kind: "oversized",
      error: new ApiError(413, "request_body_limit").withMeta("limit_bytes", requestLimit(run.protocol)).withMeta("limit_source", "restored tool-call ids exceeded the API request limit"),
    };
  }

  const headers = upstreamHeaders(run.protocol, route.record, credential, run.request.headers);
  return executeHttpAttempt(run, {
    route,
    model,
    url: targetUrl,
    headers,
    bodyBytes: payloadBytes,
    fetcher: run.io.fetch,
    deadline,
    unvouched,
    restoredPairs,
    repeatedConnect,
    laneContext: null,
  });
}

export async function attemptLaneEndpoint(run: CountRunCore, input: {
  readonly route: Route;
  readonly model: string;
  readonly value: JsonObject;
  readonly received: Uint8Array;
  readonly statedProvider: boolean;
  readonly deadline: number;
  readonly repeatedConnect: boolean;
}): Promise<AttemptResult> {
  const lane = run.lane!;
  const { route, model, value, received, statedProvider, deadline, repeatedConnect } = input;
  const credential = await laneEndpointKey(run, route.record, deadline);
  if (credential === null) {
    skipRoute(run, route, "route_inactive");
    return { kind: "pass" };
  }
  const targetUrl = countUrlOf(run.protocol, route.record.url);
  if (targetUrl === null) {
    skipRoute(run, route, "invalid_native_mapping");
    return { kind: "pass" };
  }

  let forwarded: Uint8Array;
  let modEvents: readonly Readonly<Record<string, unknown>>[];

  if (run.protocol === "anthropic_messages") {
    const grayOps: GrayRewriteOp[] = [{ op: "set_member", path: "/model", value: route.record.upstreamModel }];
    if (statedProvider) grayOps.push({ op: "remove_member", path: "/provider" });
    // The end-user identifier is a declared removal, as on the lane relay path and on generation.
    const metadata = get(value, "metadata");
    if (isObject(metadata) && Object.hasOwn(metadata, "user_id")) grayOps.push({ op: "remove_member", path: "/metadata/user_id" });
    const applied = applyDeclaredChanges(received, "anthropic_messages", { grayOps, appends: [] });
    if (!applied.ok) {
      return {
        kind: "stop",
        stage: "parse",
        error: applied.code === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_json"),
      };
    }
    forwarded = applied.forwarded;
    modEvents = applied.events as unknown as readonly Readonly<Record<string, unknown>>[];
  } else {
    const inner = get(value, "generateContentRequest");
    if (!isObject(inner)) {
      forwarded = received;
      modEvents = [];
    } else {
      const targetModel = `models/${route.record.upstreamModel}`;
      const existingModel = get(inner, "model");
      if (existingModel === targetModel) {
        forwarded = received;
        modEvents = [];
      } else {
        const op =
          existingModel === undefined
            ? ({ op: "insert_member", path: "/generateContentRequest/model", value: targetModel } as const)
            : ({ op: "set_member", path: "/generateContentRequest/model", value: targetModel } as const);
        const applied = applyGeminiCountModelRewrite(received, op);
        if (!applied.ok) {
          return {
            kind: "stop",
            stage: "parse",
            error: applied.code === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_json"),
          };
        }
        forwarded = applied.forwarded;
        modEvents = applied.events as unknown as readonly Readonly<Record<string, unknown>>[];
      }
    }
  }

  const headers = upstreamHeaders(run.protocol, route.record, credential, run.request.headers);
  headers.delete(EGRESS_HEADER);
  const draft = receiptDraft({
    modifiedEvents: modEvents,
    policy: null,
    forwardedHash: bodyHashOf(forwarded),
    accountId: null,
    upstreamModel: route.record.upstreamModel,
    upstream: laneUpstreamOf(route.record),
  });

  const endpointFetcher = run.outbound.fetch(lane.endpointFetch!(route.record));
  return executeHttpAttempt(run, {
    route,
    model,
    url: targetUrl,
    headers,
    bodyBytes: forwarded,
    fetcher: endpointFetcher,
    deadline,
    unvouched: false,
    restoredPairs: [],
    repeatedConnect,
    laneContext: { kind: "endpoint", draft },
  });
}

export async function attemptLaneRelay(run: CountRunCore, input: {
  readonly route: Route;
  readonly model: string;
  readonly value: JsonObject;
  readonly received: Uint8Array;
  readonly statedProvider: boolean;
  readonly deadline: number;
  readonly attemptIndex: number;
  readonly repeatedConnect: boolean;
}): Promise<AttemptResult> {
  const lane = run.lane!;
  const { route, model, value, received, statedProvider, deadline, attemptIndex, repeatedConnect } = input;
  if (run.protocol !== "anthropic_messages") {
    skipRoute(run, route, "invalid_protocol_request");
    return { kind: "pass" };
  }
  const relayId = route.record.lane?.relayId ?? null;
  const targetUrl = countUrlOf(run.protocol, route.record.url);
  const official = checkOfficialUpstream(route.record.url);
  if (relayId === null || targetUrl === null || !official.ok || !officialUpstream(targetUrl)) {
    skipRoute(run, route, "lane_upstream_not_official");
    return { kind: "pass" };
  }

  // 1. Relay policy step (cached per (relayId, protocol, model), missing policy passes route).
  if (lane.policies.get(relayId) === undefined) {
    skipRoute(run, route, "lane_policy_missing");
    return { kind: "pass" };
  }
  const policyKey = `${relayId}\u0000${run.protocol}\u0000${model}`;
  let decision = run.lanePolicy.get(policyKey);
  if (decision === undefined) {
    const running = runLanePolicy(run, lane, relayId, run.protocol, model, received);
    if (running === null) {
      skipRoute(run, route, "lane_policy_missing");
      return { kind: "pass" };
    }
    decision = running;
    run.lanePolicy.set(policyKey, decision);
  }
  const policyAnswer = await decision;
  if (!policyAnswer.allow) {
    run.laneDraft = receiptDraft({
      modifiedEvents: [],
      policy: policyAnswer.outcome,
      forwardedHash: null,
      accountId: null,
      upstreamModel: route.record.upstreamModel,
      upstream: laneUpstreamOf(route.record),
    });
    run.winningReceipt = "lane";
    run.laneReceiptId ??= newLaneReceiptId();
    return { kind: "stop", stage: "routes", error: lanePolicyRefused() };
  }
  if (run.deps.clock() >= deadline) {
    return { kind: "unavailable" };
  }

  // 2. Scheduler pick (inputTokens: 0n, stream: false).
  const vendor = laneVendor(official.vendor);
  const affinity = laneAffinityFor(run, relayId);
  let picked: Awaited<ReturnType<ReturnType<LaneDeps["schedulers"]>["pickFor"]>> | null = null;
  try {
    for (let tries = 0; tries < 2; tries++) {
      picked = await lane.schedulers(relayId).pickFor({
        vendor,
        model: route.record.upstreamModel,
        inputTokens: 0n,
        stream: false,
        attempt: BigInt(attemptIndex),
        previous: run.lanePrevious.get(relayId) ?? [],
        ...(affinity === undefined ? {} : { affinity }),
      });
      if (picked.kind !== "retry_after" || tries === 1) break;
      const waitMs = Math.min(Number(picked.retry_after_ms), 250);
      await sleepMs(run, waitMs);
    }
  } catch (error) {
    flushLaneReports(run, relayId);
    skipRoute(run, route, `lane_account_unavailable:${laneFailureCode(error)}`);
    return { kind: "pass" };
  }
  if (picked === null || picked.kind !== "account") {
    flushLaneReports(run, relayId);
    skipRoute(run, route, "lane_account_unavailable:lane_no_account");
    return { kind: "pass" };
  }

  let auth: { readonly headers: Readonly<Record<string, string>>; readonly egress?: LaneEgress };
  try {
    auth = lane.credentials.upstreamAuth(picked.account_id, run.deps.clock(), relayId);
  } catch (error) {
    reportLaneNotSent(run, relayId, picked.account_id, picked.request_ref);
    skipRoute(run, route, `lane_account_unavailable:${laneFailureCode(error)}`);
    return { kind: "pass" };
  }

  // 3. Apply declared rewrites + appends.
  const grayOps: GrayRewriteOp[] = [{ op: "set_member", path: "/model", value: route.record.upstreamModel }];
  if (statedProvider) grayOps.push({ op: "remove_member", path: "/provider" });
  const metadata = get(value, "metadata");
  if (isObject(metadata) && Object.hasOwn(metadata, "user_id")) {
    grayOps.push({ op: "remove_member", path: "/metadata/user_id" });
  }
  const applied = applyDeclaredChanges(received, "anthropic_messages", { grayOps, appends: policyAnswer.appends });
  if (!applied.ok) {
    reportLaneNotSent(run, relayId, picked.account_id, picked.request_ref);
    if (applied.code === "position_protocol" || applied.code === "invalid_text" || applied.code === "append_shape") {
      run.laneDraft = receiptDraft({
        modifiedEvents: [],
        policy: {
          type: "relay_policy.refused",
          moduleSha256: policyAnswer.outcome.moduleSha256,
          policyVersion: policyAnswer.outcome.policyVersion,
          reasonCode: "policy_unavailable",
        },
        forwardedHash: null,
        accountId: null,
        upstreamModel: route.record.upstreamModel,
        upstream: laneUpstreamOf(route.record),
      });
      run.winningReceipt = "lane";
      run.laneReceiptId ??= newLaneReceiptId();
      return { kind: "stop", stage: "routes", error: lanePolicyRefused() };
    }
    return {
      kind: "stop",
      stage: "parse",
      error: applied.code === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_json"),
    };
  }

  const headers = laneHeaders("anthropic_messages", run.request.headers, auth.headers);
  headers.delete(EGRESS_HEADER);
  if (auth.egress !== undefined) headers.set(EGRESS_HEADER, egressHeader(auth.egress));

  const draft = receiptDraft({
    modifiedEvents: applied.events as unknown as readonly Readonly<Record<string, unknown>>[],
    policy: policyAnswer.outcome,
    forwardedHash: bodyHashOf(applied.forwarded),
    accountId: picked.account_id,
    upstreamModel: route.record.upstreamModel,
    upstream: laneUpstreamOf(route.record),
  });

  return executeHttpAttempt(run, {
    route,
    model,
    url: targetUrl,
    headers,
    bodyBytes: applied.forwarded,
    fetcher: run.io.fetch,
    deadline,
    unvouched: false,
    restoredPairs: [],
    repeatedConnect,
    laneContext: {
      kind: "relay",
      draft,
      relayId,
      accountId: picked.account_id,
      requestRef: picked.request_ref,
    },
  });
}
