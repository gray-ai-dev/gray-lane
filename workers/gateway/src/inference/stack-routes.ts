/**
 * Which routes of a confidential-lane request are a stack relay's, an endpoint route's or a peer's (`InferenceRun`,
 * inference.ts), with the region a route ranks in and the stack relay config the request uses.
 */
import { LANE_BRIDGE_CALL_MS } from "@gray/lane-wire";
import type { StackRelayConfig } from "../lane/stack-config.ts";
import type { LaneDeps } from "../lane/types.ts";
import { REST_EGRESS_REGION } from "../rests.ts";
import type { RouteRecord } from "../snapshot.ts";
import type { RunCore } from "./state.ts";

/** What stack-routes.ts needs of the run: its state alone. */
export interface StackRoutesRun extends RunCore {}

/**
 * An entry's endpoint route (docs/design/lane-provider-routes.md section 5): any route the lane's view holds that is
 * not a lane relay's, attempted through egress's `/route/` kind when the entry has its keys and table
 * (`lane.endpointFetch`).
 */
export function laneEndpointRoute(run: StackRoutesRun, route: RouteRecord): boolean {
  return run.lane !== null && route.auth !== "lane_relay" && run.lane.endpointFetch !== undefined && run.lane.endpointCredentials !== undefined;
}

/**
 * The provider's key of an entry's endpoint route at its credential generation (section 3.2): the one in the entry's
 * memory, else one `endpoint.credential` call (or the one out) waited for within a bridge call's bound and the time to
 * the answer's deadline. Null when none came.
 *
 * The wait is its own bound, not what the request's pre phase left: it is a step of the attempt (`openAttempt` runs
 * with the pre clock stopped), as the lane relay's pick is (LANE_SCHEDULER_PICK_MS), and the attempt cannot be sent
 * without it. A replica's first request to a route, after a restart or once the route or its key generation is new to
 * it, has no key in memory, and the snapshot, admission and permit before it may have spent the whole pre phase:
 * bounded by what they left, the wait was 0 (or shorter than one cold `endpoint.credential`) and the route was passed
 * over as `route_inactive`, the request 503 `provider_capacity_or_quote_unavailable` with no attempt (staging
 * 2026-11-18, lane release V). A fetch that failed rests (`EntryEndpointRoutes`), so a console that is down costs one
 * wait per rest, not one per request.
 */
export async function laneEndpointKey(run: StackRoutesRun, route: RouteRecord, answerDeadline: number): Promise<string | null> {
  const keys = run.lane?.endpointCredentials;
  if (keys === undefined) return null;
  const budgetMs = Math.max(0, Math.min(LANE_BRIDGE_CALL_MS, answerDeadline - run.deps.clock()));
  try {
    return await keys.credential(route.endpointId, route.credentialGeneration, budgetMs);
  } catch {
    return null;
  }
}

/**
 * The egress region of an attempt's rank key, whose circuit judges it at the endpoint's root (rests.ts `rankKey`). An
 * entry's endpoint route has the entry's own, `lane-<env>`: the provider sees the entry's requests come from the CVM's
 * address, so a failure only the entry sees (a provider that refuses that address) opens the entry's circuits and not
 * the `api` address's, and the other way round (docs/design/lane-provider-routes.md section 5). The shard the permit
 * comes from is the same either way (the request's region): a route's concurrency is one, whoever sends.
 */
export function rankRegion(run: StackRoutesRun, route: RouteRecord): string {
  return laneEndpointRoute(run, route) ? `lane-${run.deps.cfg.deployEnv}` : REST_EGRESS_REGION;
}

/** A stack relay's route (S22): `lane_relay` whose lane record is `mode: "stack"`. */
export function stackRoute(run: StackRoutesRun, route: RouteRecord): boolean {
  return run.lane !== null && route.auth === "lane_relay" && route.lane?.mode === "stack";
}

/**
 * S22: whether this lane routes `route`. A VM laid out for a stack relay (`stackConfig.relayId`,
 * fixed per boot) routes only that relay's stack endpoints and no sealed-credential lane route; any
 * other lane routes no stack endpoint. The main lane routes everything it routed before.
 */
export function laneRoutes(run: StackRoutesRun, route: RouteRecord): boolean {
  if (run.lane === null) return true;
  const own = run.lane.stackConfig?.relayId ?? null;
  if (own === null) return !stackRoute(run, route) || peerRoutable(run, route);
  return stackRoute(run, route) && route.lane?.relayId === own;
}

/** Whether this lane is an entry that routes stack routes over the peer hop (LANE_PEERS, a default-layout lane). */
export function entryPeers(run: StackRoutesRun): NonNullable<LaneDeps["peers"]> | null {
  const lane = run.lane;
  if (lane === null || lane.peers === undefined || (lane.stackConfig?.relayId ?? null) !== null) return null;
  return lane.peers;
}

/**
 * An entry routes a stack route while a peer of its relay is usable now (docs/confidential-lane-stack-routing.md
 * section 4.7): pinned, its hello current, not resting. A peer that is down, refused or not yet attested leaves its
 * routes out of the candidates on this instance at once, as a local rest; the registry re-pins it in the background (L5).
 */
export function peerRoutable(run: StackRoutesRun, route: RouteRecord): boolean {
  const peers = entryPeers(run);
  const lane = route.lane;
  if (peers === null || lane === undefined || lane === null) return false;
  return peers.registry.usable(lane.relayId).length > 0;
}

/** The relay config this request uses: one `current()` per request (one served version), null when none is ready. */
export function stackConfig(run: StackRoutesRun): StackRelayConfig | null {
  if (run.stackPeer.stackConfigRead === undefined) run.stackPeer.stackConfigRead = run.lane?.stackConfig?.current(run.ctx) ?? null;
  return run.stackPeer.stackConfigRead;
}
