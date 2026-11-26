/**
 * The confidential entry's routes and relays for a count (`CountTokensRun`, count-tokens.ts): which routes the lane
 * serves and how, the peer hop's body, the relay policy step, the affinity tokens, and the reports to a relay's
 * scheduler.
 */
import type { JsonObject } from "@gray/json";
import type { LaneProtocol } from "@gray/lane";
import { LANE_BRIDGE_CALL_MS } from "@gray/lane-wire";
import { CONVERSATION_DOMAIN, deriveAffinity } from "../lane/affinity.ts";
import { peerHopBody as composePeerHop, type PeerHopBody } from "../lane/claude-code-user-id.ts";
import { laneOutcomeWord, latencyBand, policyStep } from "../lane/hooks.ts";
import type { LaneDeps } from "../lane/types.ts";
import type { RouteRecord } from "../snapshot.ts";
import { laneFailureCode } from "./pure.ts";
import { sleepMs } from "./record.ts";
import { type CountRunCore, type PolicyAnswer, ZERO_LANE_USAGE } from "./state.ts";

export function laneEndpointRoute(run: CountRunCore, route: RouteRecord): boolean {
  return run.lane !== null && route.auth !== "lane_relay" && run.lane.endpointFetch !== undefined && run.lane.endpointCredentials !== undefined;
}

export async function laneEndpointKey(run: CountRunCore, route: RouteRecord, deadline: number): Promise<string | null> {
  const keys = run.lane?.endpointCredentials;
  if (keys === undefined) return null;
  const budgetMs = Math.max(0, Math.min(LANE_BRIDGE_CALL_MS, deadline - run.deps.clock()));
  try {
    return await keys.credential(route.endpointId, route.credentialGeneration, budgetMs);
  } catch {
    return null;
  }
}

export function stackRoute(run: CountRunCore, route: RouteRecord): boolean {
  return run.lane !== null && route.auth === "lane_relay" && route.lane?.mode === "stack";
}

export function entryPeers(run: CountRunCore): NonNullable<LaneDeps["peers"]> | null {
  const lane = run.lane;
  if (lane === null || lane.peers === undefined || (lane.stackConfig?.relayId ?? null) !== null) return null;
  return lane.peers;
}

export function laneRoutes(run: CountRunCore, route: RouteRecord): boolean {
  if (run.lane === null) return true;
  const own = run.lane.stackConfig?.relayId ?? null;
  if (own === null) {
    if (!stackRoute(run, route)) return true;
    const peers = entryPeers(run);
    const lane = route.lane;
    return peers !== null && lane !== undefined && lane !== null && peers.registry.usable(lane.relayId).length > 0;
  }
  return stackRoute(run, route) && route.lane?.relayId === own;
}

/**
 * The bytes the peer hop to `relayId`'s VM carries: the client's, with a Claude Code `metadata.user_id` replaced by
 * the stand-in for this workspace, key and relay (any other `user_id` removed) and `/provider` removed when the
 * client stated its routing preference in the body, as on the inference path (`inference.ts` `peerHopBody`). Null
 * when the ops do not apply (the route is passed over).
 */
export function peerHopBody(run: CountRunCore, received: Uint8Array, statedProvider: boolean, relayId: string, value?: JsonObject): PeerHopBody | null {
  const cached = run.peerHops.get(relayId);
  if (cached !== undefined) return cached;
  const key = run.key;
  const hop = composePeerHop({
    protocol: "anthropic_messages",
    base: received,
    ...(value === undefined ? {} : { value }),
    stripProvider: statedProvider,
    key: run.lane!.state.affinityKey,
    owner: key === null ? null : { workspaceId: key.workspaceId, keyId: key.keyId },
    relayId,
  });
  if (hop !== null) run.peerHops.set(relayId, hop);
  return hop;
}

export function runLanePolicy(run: CountRunCore, lane: LaneDeps, relayId: string, protocol: LaneProtocol, model: string, body: Uint8Array): Promise<PolicyAnswer> | null {
  const record = lane.policies.get(relayId);
  if (record === undefined) return null;
  const sleep = run.deps.laneSleep ?? ((ms: number) => sleepMs(run, ms));
  return policyStep(
    {
      timing: lane.timing,
      fuel: record.fuel({ protocol, model, body }),
      run: () => {
        const answer = record.run({ protocol, model, body });
        if (!answer.ok) return { kind: "unavailable" };
        if (answer.decision === "block") return { kind: "block", reasonCode: answer.reasonCode };
        return { kind: "allow", appends: answer.appends };
      },
      sleep,
      clock: run.deps.clock,
    },
    record.moduleSha256,
    record.policyVersion,
  ).then((step) => ({ allow: step.allow, appends: step.appends, outcome: step.outcome }));
}

export function laneAffinityFor(run: CountRunCore, relayId: string): string | undefined {
  return laneTokenFor(run, run.laneAffinities, relayId, undefined);
}

export function laneConversationFor(run: CountRunCore, relayId: string): string | undefined {
  return laneTokenFor(run, run.laneConversations, relayId, CONVERSATION_DOMAIN);
}

export function laneTokenFor(run: CountRunCore, cache: Map<string, string>, relayId: string, domain: string | undefined): string | undefined {
  const lane = run.lane;
  const sessionId = run.client.sessionId;
  const workspaceId = run.key?.workspaceId;
  if (lane === null || sessionId === null || workspaceId === undefined) return undefined;
  const cached = cache.get(relayId);
  if (cached !== undefined) return cached;
  const token = deriveAffinity(lane.state.affinityKey, relayId, workspaceId, sessionId, domain);
  cache.set(relayId, token);
  return token;
}

export function recordLanePrevious(run: CountRunCore, relayId: string, accountId: string, outcome: string): void {
  let list = run.lanePrevious.get(relayId);
  if (list === undefined) {
    list = [];
    run.lanePrevious.set(relayId, list);
  }
  list.push({ account_id: accountId, outcome });
}

export function reportLaneNotSent(run: CountRunCore, relayId: string, accountId: string, requestRef: string): void {
  const lane = run.lane;
  if (lane === null) return;
  reportLanePick(run, lane, relayId, { account_id: accountId, request_ref: requestRef, outcome: "not_sent" });
}

export function reportLanePick(run: CountRunCore, lane: LaneDeps, relayId: string, report: Readonly<Record<string, unknown>> & { readonly request_ref: string }): void {
  run.ctx.waitUntil(
    (async () => {
      try {
        const scheduler = lane.schedulers(relayId);
        try {
          scheduler.report([report]);
        } catch (error) {
          if (laneFailureCode(error) !== "scheduler_unknown_account") throw error;
          scheduler.report([{ request_ref: report.request_ref, outcome: "not_sent" }]);
        }
        await scheduler.flushReports();
      } catch {
        // Scheduler report failures never fail the request.
      }
    })(),
  );
}

export function flushLaneReports(run: CountRunCore, relayId: string): void {
  const lane = run.lane;
  if (lane === null) return;
  try {
    const scheduler = lane.schedulers(relayId);
    run.ctx.waitUntil(Promise.resolve(scheduler.flushReports()).catch(() => undefined));
  } catch {
    // Nothing to flush.
  }
}

export function reportLaneOutcome(run: CountRunCore, lane: LaneDeps, finishedAt: number): void {
  const serving = run.laneServing;
  if (serving === null) return;
  const word = laneOutcomeWord({
    ok: serving.status >= 200 && serving.status <= 299 && serving.code === "",
    status: serving.status,
    clientLeft: false,
    timedOut: false,
    rateLimited: serving.status === 429,
    authFailed: serving.status === 401 || serving.status === 403,
    quotaExhausted: serving.status === 402,
    overloaded: serving.status === 503 || serving.status === 529,
  });
  reportLanePick(run, lane, serving.relayId, {
    account_id: serving.accountId,
    request_ref: serving.requestRef,
    outcome: word,
    usage: ZERO_LANE_USAGE,
    latency_bucket: latencyBand(finishedAt - run.started),
  });
}
