import { ACCOUNT_BLOCKS, type AccountBlock } from "@gray/errors";
import type { Exploration } from "@gray/routing";
import { blockedSuppliers, independentSecond, type PlanRoute, steer } from "./account-blocks.ts";
import type { BlockGates } from "./dispatcher.ts";

/**
 * How admission orders a request's ranked routes (crates/gray-gateway/src/inference.rs `steer`, `order_plan`,
 * `settle_head`, `head_reason`; area `plan-order`): the suppliers an account-block gate holds the request off,
 * the cache and tool-call issuer pins that skip them, the routes ranking left out that the steering appends, the
 * stable partition and its reason, the independent operator for the second attempt, the head a customer order
 * and ranking's recovery probe settle, and why the head is first. Pure: the gates, the ranker and the stores are
 * read through what the caller passes.
 *
 * A route's rank key is its endpoint id here, as ranking keys it (routes.ts `rankDetailed`).
 */

/** What the ordering reads of the customer's routing preference (`Preference`). */
export interface PlanPreference<R extends PlanRoute> {
  /** The customer named an order (`Preference::order` is not empty). */
  readonly ordered: boolean;
  /** Where the order puts a route, by its provider or supplier reference (`Preference::position`); undefined when it names neither. */
  readonly position: (route: R) => number | undefined;
  /** A conversation may go back to its cache target or tool-call issuer (`Preference::affinity_allowed`): affinity `auto` and no order. */
  readonly affinityAllowed: boolean;
}

/** No preference (`Preference::default`): a request that states none, at any level (preference.ts `planPreference` of it). */
export const NO_PREFERENCE: PlanPreference<PlanRoute> = { ordered: false, position: () => undefined, affinityAllowed: true };

/** What admission decides of a request's routes before ranking them (`Steering`). */
export interface Steering {
  /** The suppliers whose account-block gate holds the request off, with the block (`Plan::steered`). */
  readonly blocked: ReadonlyMap<string, AccountBlock>;
  /** The endpoint the conversation's cache pins the head to. */
  readonly affinityTarget: string | null;
  /**
   * The routes of the issuer of the conversation's latest tool call with a handle, while the customer names no
   * order (`preferred_issuer`); null when there is none.
   */
  readonly issued: ReadonlySet<string> | null;
  /** The rank keys of that issuer's routes a pin may take (`issuer_target`). */
  readonly issuerTarget: ReadonlySet<string>;
  readonly exploration: Exploration;
}

/**
 * What admission decides of `routes`, the eligible routes of a request, before ranking them (`steer`): the
 * suppliers it is steered away from, as their gates read now, the pins that skip them, and whether an
 * exploratory probe may take the head. `affinity` is the conversation's cache target as its store has it,
 * `issued` the routes of the issuer of its latest tool call (null: none), and `pinHolds` whether ranking lets a
 * pin hold at the route of a rank key.
 */
export function steering<R extends PlanRoute>(
  routes: readonly R[],
  preference: PlanPreference<R>,
  gates: BlockGates | null,
  affinity: () => string | null,
  issued: ReadonlySet<string> | null,
  pinHolds: (key: string) => boolean,
): Steering {
  // A vendor's block on a supplier's upstream account (D4), for this request's client and tool shape: a
  // supplier whose gate holds it off goes after every supplier that does not, unless the customer named an
  // order. Read before the pins, which skip a route the block would refuse anyway.
  const blocked = !preference.ordered && gates !== null ? blockedSuppliers(routes, gates) : new Map<string, AccountBlock>();
  const away = (r: R) => blocked.has(r.record.operator);
  const wanted = affinity();
  const affinityTarget = wanted !== null && routes.some((r) => r.record.endpointId === wanted && !away(r) && pinHolds(r.record.endpointId)) ? wanted : null;
  // A conversation whose tool calls a route's upstream issued goes back to that issuer, as long as it is about as
  // reliable as the best route: only the issuer takes its own ids back. Ahead of the cache pin, which only saves
  // money.
  const preferred = preference.affinityAllowed ? issued : null;
  const issuerTarget = new Set<string>();
  if (preferred !== null) for (const r of routes) if (preferred.has(r.record.endpointId) && !away(r) && pinHolds(r.record.endpointId)) issuerTarget.add(r.record.endpointId);
  // An exploratory probe placed first would move this conversation off its warm cache or its issuer.
  const exploration: Exploration = affinityTarget !== null || issuerTarget.size > 0 ? "suppressed" : preference.ordered ? "suppressed" : "allowed";
  return { blocked, affinityTarget, issued: preferred, issuerTarget, exploration };
}

/** What ranking returned, as the ordering reads it: its evidence gains the steering's reason. */
export interface RankedPlan {
  readonly orderedIds: readonly string[];
  readonly evidence: readonly { readonly endpointId: string; readonly reasons: string[] }[];
  readonly explorationId: string | undefined;
  readonly recoveryProbeId: string | undefined;
}

/** Why a plan's head is first, for the request log (`head_reason`). */
export type HeadReason = "recovery_probe" | "recovery_trial" | "account_block" | "tool_call_issuer" | "affinity" | "order" | "exploration" | "ranking";

/** What is true of a plan's head (`HeadFacts`). */
export interface HeadFacts {
  /** It holds a recovery probe's lease. */
  readonly leased: boolean;
  /** It goes as a recovery trial. */
  readonly trial: boolean;
  /** The steering of a blocked supplier's routes moved it to the head. */
  readonly steered: boolean;
  /** The conversation's tool-call issuer was pinned to the head. */
  readonly issuerPinned: boolean;
  /** It is the conversation's cache target. */
  readonly affinity: boolean;
  /** The customer named an order. */
  readonly ordered: boolean;
  /** It is ranking's exploratory candidate. */
  readonly exploration: boolean;
}

/** Why a plan's head is first: the first of these that holds of it (`head_reason`). */
export function headReason(head: HeadFacts): HeadReason {
  if (head.leased) return "recovery_probe";
  if (head.trial) return "recovery_trial";
  if (head.steered) return "account_block";
  if (head.issuerPinned) return "tool_call_issuer";
  if (head.affinity) return "affinity";
  if (head.ordered) return "order";
  if (head.exploration) return "exploration";
  return "ranking";
}

/** The plan admission orders a request's ranked routes into (`PlanOrder`). */
export interface PlanOrder<R extends PlanRoute> {
  readonly routes: R[];
  /** The rank key of the recovery probe whose lease the head holds for the request (`settleHead`). */
  readonly leased: string | null;
  /** Why the head is first, by what ranking and the ordering know of it; null with no route. */
  readonly headReason: HeadReason | null;
  /** The blocks whose steering moved a route ahead of a steered one, each once, for the steering counter. */
  readonly steers: AccountBlock[];
  /** The steering moved another route to the head. */
  readonly steeredHead: boolean;
  /** The conversation's tool-call issuer took the head. */
  readonly issuerPinned: boolean;
}

/**
 * Orders a request's routes as ranking returned them (`ranked`, whose evidence gains the steering's reason;
 * `byId`, every eligible route by its rank key) under what `steering` decided (`order_plan`): the pins, the
 * steering of a blocked supplier's routes behind every other route, the independent operator for the second
 * attempt, then the head `settle` fixes (`settleHead`). `rankUnranked` ranks the routes ranking left out,
 * without exploration, and returns their rank keys in order.
 */
export async function orderPlan<R extends PlanRoute>(
  ranked: RankedPlan,
  byId: Map<string, R>,
  steering: Steering,
  preference: PlanPreference<R>,
  rankUnranked: (unranked: readonly R[]) => Promise<readonly string[]>,
  settle: (byId: Map<string, R>, routes: R[]) => Promise<string | null>,
): Promise<PlanOrder<R>> {
  const { blocked } = steering;
  const away = (r: R) => blocked.has(r.record.operator);
  const take = (id: string): R | undefined => {
    const route = byId.get(id);
    if (route !== undefined) byId.delete(id);
    return route;
  };
  let routes = ranked.orderedIds.map(take).filter((r): r is R => r !== undefined);
  // Cache affinity decides the head before the independent-operator preference picks the second attempt.
  const pinToHead = (index: number) => {
    const [pinned] = routes.splice(index, 1);
    routes.unshift(pinned!);
  };
  if (steering.affinityTarget !== null) {
    const index = routes.findIndex((r) => r.record.endpointId === steering.affinityTarget);
    if (index >= 0) pinToHead(index);
  }
  // The issuer's best-ranked route takes the head unless the head is one of the issuer's already.
  let issuerPinned = false;
  if (steering.issued !== null && routes.length > 0 && !steering.issued.has(routes[0]!.record.endpointId)) {
    const index = routes.findIndex((r) => steering.issuerTarget.has(r.record.endpointId));
    if (index >= 0) {
      pinToHead(index);
      issuerPinned = true;
    }
  }
  // The steering (D4): a stable partition that moves every route of a blocked supplier behind every route that
  // is not. The pins skipped blocked routes, so a pinned head stays the head.
  let steeredHead = false;
  let steers: AccountBlock[] = [];
  if (blocked.size > 0) {
    // With only blocked routes ranked, the routes ranking left out for want of recent samples go there first,
    // in the order a ranking without exploration gives them. A route left out for its circuit stays out.
    let unsampled: R[] = [];
    if (routes.every(away)) {
      const unranked = ranked.evidence
        .filter((e) => e.reasons.some((reason) => reason === "insufficient_recent_samples" || reason === "stale_observations_excluded"))
        .map((e) => byId.get(e.endpointId))
        .filter((r): r is R => r !== undefined && !away(r));
      if (unranked.length > 0) unsampled = (await rankUnranked(unranked)).map(take).filter((r): r is R => r !== undefined);
    }
    const steered = steer(routes, blocked, unsampled);
    routes = steered.plan;
    steeredHead = steered.head;
    if (steeredHead) issuerPinned = false;
    for (const route of [...byId.values(), ...routes]) {
      if (!away(route)) continue;
      ranked.evidence.find((e) => e.endpointId === route.record.endpointId)?.reasons.push("account_block_steered");
    }
    if (steered.moved) steers = ACCOUNT_BLOCKS.filter((kind) => [...blocked.values()].includes(kind));
  }
  // Prefer an independent operator for the only permitted second attempt, among the suppliers no block steered
  // the request away from.
  if (!preference.ordered) routes = independentSecond(routes, blocked);
  const leased = await settle(byId, routes);
  const head = routes[0];
  const reason =
    head === undefined
      ? null
      : headReason({
          leased: leased !== null,
          trial: ranked.evidence.some((e) => e.endpointId === head.record.endpointId && e.reasons.includes("recovery_trial")),
          steered: steeredHead,
          issuerPinned,
          affinity: steering.affinityTarget !== null && head.record.endpointId === steering.affinityTarget,
          ordered: preference.ordered,
          exploration: ranked.explorationId === head.record.endpointId,
        });
  return { routes, leased, headReason: reason, steers, steeredHead, issuerPinned };
}

/** The recovery leases of the ranker that ranked a plan (@gray/routing `Ranker`). */
export interface ProbeLeases {
  claimRecovery(endpoint: string, requestKey: string, nowMs: number): Promise<boolean>;
  abandonRecovery(endpoint: string, requestKey: string): Promise<void>;
}

/**
 * `leases` (a ranker keyed by rank keys, the gateway's: routes.ts `probeLeases`) for a plan's endpoint ids: each id is
 * taken as its route's rank key in the request's mode (`keyOf`), the keys the server's `settle_head` passes its ranker
 * (review r31 minor: the gateway passed endpoint ids, which name no rank key's state).
 */
export function rankKeyLeases(leases: ProbeLeases, keyOf: (endpointId: string) => string): ProbeLeases {
  return {
    claimRecovery: (endpoint, requestKey, nowMs) => leases.claimRecovery(keyOf(endpoint), requestKey, nowMs),
    abandonRecovery: (endpoint, requestKey) => leases.abandonRecovery(keyOf(endpoint), requestKey),
  };
}

/**
 * Fixes the head of `routes`, the ranked routes of one request, in place, and returns the rank key of the
 * recovery probe whose lease the head holds for the request, if any (`settle_head`). Under a customer order the
 * routes it named go first in its order, and an endpoint it names ahead of every ranked route, whose cooldown has
 * passed, gets its recovery probe at the head. A recovery lease is dispatched only as the first attempt: a probe
 * moved off the head gives its lease back and leaves the plan.
 */
export async function settleHead<R extends PlanRoute>(
  ranker: ProbeLeases,
  nowMs: number,
  preference: PlanPreference<R>,
  ranked: RankedPlan,
  byId: Map<string, R>,
  routes: R[],
  requestKey: string,
): Promise<string | null> {
  let claimed: string | null = null;
  if (preference.ordered) {
    const position = (r: R) => preference.position(r) ?? Number.MAX_SAFE_INTEGER;
    // An explicit order is the customer's: routes it did not name keep their ranked order behind the named ones.
    const sorted = [...routes].sort((a, b) => position(a) - position(b));
    routes.splice(0, routes.length, ...sorted);
    const head = routes.length === 0 ? Number.MAX_SAFE_INTEGER : position(routes[0]!);
    let due: { at: number; id: string } | undefined;
    for (const e of ranked.evidence) {
      if (!e.reasons.includes("recovery_probe_due")) continue;
      const route = byId.get(e.endpointId);
      const at = route === undefined ? undefined : preference.position(route);
      if (at === undefined || at >= head) continue;
      if (due === undefined || at < due.at) due = { at, id: e.endpointId };
    }
    if (due !== undefined && (await ranker.claimRecovery(due.id, requestKey, nowMs))) {
      const named = byId.get(due.id)!;
      byId.delete(due.id);
      routes.unshift(named);
      claimed = due.id;
    }
  }
  const probe = ranked.recoveryProbeId;
  if (probe !== undefined && routes.length > 0 && routes[0]!.record.endpointId !== probe) {
    await ranker.abandonRecovery(probe, requestKey);
    const kept = routes.filter((r) => r.record.endpointId !== probe);
    routes.splice(0, routes.length, ...kept);
  }
  const head = routes[0]?.record.endpointId;
  if (head === undefined) return null;
  return claimed === head || probe === head ? head : null;
}
