import { ACCOUNT_BLOCKS, type AccountBlock } from "@gray/errors";
import { sessionRedraw, type SessionKind, type SessionRecord, type SessionRouteState, type SessionState, type Workload } from "@gray/routing";
import { blockedSuppliers, independentSecond, type PlanRoute, steer } from "./account-blocks.ts";
import type { BlockGates } from "./dispatcher.ts";

/**
 * How admission orders a request's routes (crates/gray-gateway/src/inference.rs `steer`, `order_plan`, `settle_head`,
 * `head_reason`; area `plan-order`; docs/utility-routing.md "Draw and order"): the plan starts from the formula's order;
 * the suppliers an account-block gate holds the request off go behind every other; the session's provider (the place
 * cache affinity held) and the tool-call issuer, which skip them, take the head; a route whose recovery probe is due goes
 * first for a request that could choose it; the independent operator for the second attempt; the head a customer order
 * and a probe's lease settle; and why the head is first. Pure: the gates and the leases are read through what the caller
 * passes, and no ranker is read.
 *
 * A route's rank key is its endpoint id here, as the request path maps it back (routes.ts `rankKeyOf`).
 */

/** What the ordering reads of the customer's routing preference (`Preference`). */
export interface PlanPreference<R extends PlanRoute> {
  /** The customer named an order (`Preference::order` is not empty). */
  readonly ordered: boolean;
  /** Where the order puts a route, by its provider or supplier reference (`Preference::position`); undefined when it names neither. */
  readonly position: (route: R) => number | undefined;
  /** A conversation may go back to its session's provider or tool-call issuer (`Preference::affinity_allowed`): affinity `auto` and no order. */
  readonly affinityAllowed: boolean;
}

/** No preference (`Preference::default`): a request that states none, at any level (preference.ts `planPreference` of it). */
export const NO_PREFERENCE: PlanPreference<PlanRoute> = { ordered: false, position: () => undefined, affinityAllowed: true };

/** What admission decides of a request's routes before ordering them (`Steering`). */
export interface Steering {
  /** The suppliers whose account-block gate holds the request off, with the block (`Plan::steered`). */
  readonly blocked: ReadonlyMap<string, AccountBlock>;
  /** The endpoint the request's session goes back to: its provider, among the routes and not steered away. */
  readonly sessionTarget: string | null;
  /**
   * What the session's key was made of (`session_kind`): a hit of the `client` or `cache` kind keeps a due recovery
   * probe back (its warm cache), one of the `key` kind carries it (docs/utility-routing.md "Draw and order", lead
   * decision K11).
   */
  readonly sessionKind: SessionKind | null;
  /**
   * The routes of the issuer of the conversation's latest tool call with a handle, while the customer names no
   * order (`preferred_issuer`); null when there is none.
   */
  readonly issued: ReadonlySet<string> | null;
  /** The rank keys of that issuer's routes no block steers the request away from (`issuer_target`). */
  readonly issuerTarget: ReadonlySet<string>;
  /**
   * Every route of the request's tool-call issuer, whatever an order, the affinity setting or a block does with it
   * (`issuer_routes`): while one is a candidate the request carries no other route's due probe (`orderPlan`, `settleHead`).
   */
  readonly issuerRoutes: ReadonlySet<string>;
}

/**
 * What admission decides of `routes`, the eligible routes of a request, before ordering them (`steer`): the suppliers
 * it is steered away from, as their gates read now, and the session and issuer targets, which skip them. `session` is
 * the endpoint of the request's session provider when its session may go back there (its circuit lets it serve),
 * `issued` the routes of the issuer of its latest tool call (null: none), `sessionKind` what the session's key was made
 * of (null: no key). Neither target holds under a customer order or with affinity off.
 */
export function steering<R extends PlanRoute>(
  routes: readonly R[],
  preference: PlanPreference<R>,
  gates: BlockGates | null,
  session: () => string | null,
  issued: ReadonlySet<string> | null,
  sessionKind: SessionKind | null,
): Steering {
  // A vendor's block on a supplier's upstream account (D4), for this request's client and tool shape: a supplier whose
  // gate holds it off goes after every supplier that does not, unless the customer named an order. Read before the
  // targets, which skip a route the block would refuse anyway.
  const blocked = !preference.ordered && gates !== null ? blockedSuppliers(routes, gates) : new Map<string, AccountBlock>();
  const away = (r: R) => blocked.has(r.record.operator);
  const wanted = session();
  const sessionTarget = preference.affinityAllowed && wanted !== null && routes.some((r) => r.record.endpointId === wanted && !away(r)) ? wanted : null;
  // A conversation whose tool calls a route's upstream issued goes back to that issuer: only the issuer takes its own
  // ids back. Ahead of the session, which only saves money.
  const issuerRoutes = new Set(issued === null ? [] : routes.filter((r) => issued.has(r.record.endpointId)).map((r) => r.record.endpointId));
  const preferred = preference.affinityAllowed ? issued : null;
  const issuerTarget = new Set<string>();
  if (preferred !== null) for (const r of routes) if (preferred.has(r.record.endpointId) && !away(r)) issuerTarget.add(r.record.endpointId);
  return { blocked, sessionTarget, sessionKind, issued: preferred, issuerTarget, issuerRoutes };
}

/**
 * The session's state of a request (inference.rs `session_state`; docs/utility-routing.md "Sessions"): `off` when the
 * request may not go back to a provider (`affinity: "off"`, a customer order), `none` without a key, `new` when its key
 * names no live record; else, of its provider's route as the request sees it now (`route`, null when the model has none
 * of it: `gone`), the re-draw `sessionRedraw`
 * finds (`gone`, `preference`, `failed`, `circuit`, `rest`, `constraint`, `price`), a re-draw `blocked` when an account
 * block steers the request away from the provider's supplier (`blocked`), else a `hit`.
 */
export function sessionState(allowed: boolean, keyed: boolean, record: SessionRecord | null, route: SessionRouteState | null, workload: Workload, blocked: boolean): SessionState {
  if (!allowed) return { kind: "off" };
  if (!keyed) return { kind: "none" };
  if (record === null) return { kind: "new" };
  const reason = route === null ? "gone" : sessionRedraw(record, route, workload);
  if (reason !== null) return { kind: "redraw", reason };
  return blocked ? { kind: "redraw", reason: "blocked" } : { kind: "hit" };
}

/** What a request's plan is ordered from (`Ordered`, docs/utility-routing.md "Draw and order"), by endpoint id. */
export interface Ordered {
  /** The formula's order: the candidates whose circuit lets them serve. */
  readonly order: readonly string[];
  /** The route whose recovery probe the ranking leased itself, when every candidate's circuit is open: only at the head. */
  readonly leased: string | null;
  /** The routes left out of the order for their circuit whose recovery probe is due, in candidate order, which the request could choose. */
  readonly due: readonly string[];
  /** The routes the ranking sends as recovery trials. */
  readonly trials: readonly string[];
  /** The route the unselected share moved to the head of the order. */
  readonly unselected: string | null;
}

/** Why a plan's head is first, for the request log (`head_reason`). `ranking` is the formula's draw. */
export type HeadReason = "recovery_probe" | "recovery_trial" | "account_block" | "tool_call_issuer" | "session" | "order" | "unselected" | "ranking";

/** What is true of a plan's head (`HeadFacts`). */
export interface HeadFacts {
  /** It holds a recovery probe's lease. */
  readonly leased: boolean;
  /** The ranking sends it as a recovery trial. */
  readonly trial: boolean;
  /** The steering of a blocked supplier's routes moved it to the head. */
  readonly steered: boolean;
  /** The conversation's tool-call issuer was pinned to the head. */
  readonly issuerPinned: boolean;
  /** It is the request's session provider. */
  readonly session: boolean;
  /** The customer named an order. */
  readonly ordered: boolean;
  /** The unselected share moved it to the head. */
  readonly unselected: boolean;
}

/** Why a plan's head is first: the first of these that holds of it (`head_reason`). */
export function headReason(head: HeadFacts): HeadReason {
  if (head.leased) return "recovery_probe";
  if (head.trial) return "recovery_trial";
  if (head.steered) return "account_block";
  if (head.issuerPinned) return "tool_call_issuer";
  if (head.session) return "session";
  if (head.ordered) return "order";
  if (head.unselected) return "unselected";
  return "ranking";
}

/** The plan admission orders a request's routes into (`PlanOrder`). */
export interface PlanOrder<R extends PlanRoute> {
  readonly routes: R[];
  /** The rank key of the recovery probe whose lease the head holds for the request (`settleHead`). */
  readonly leased: string | null;
  /** Why the head is first; null with no route. */
  readonly headReason: HeadReason | null;
  /** The blocks whose steering moved a route ahead of a steered one, each once, for the steering counter. */
  readonly steers: AccountBlock[];
  /** The steering moved another route to the head. */
  readonly steeredHead: boolean;
  /** The conversation's tool-call issuer took the head. */
  readonly issuerPinned: boolean;
  /** Every route of a steered supplier, planned (in order) or left out (by id): the request log's `account_block_steered`. */
  readonly steeredRoutes: readonly string[];
}

/** The recovery leases of the ranker a plan's probes are of (@gray/routing `Ranker`). */
export interface ProbeLeases {
  claimRecovery(endpoint: string, requestKey: string, nowMs: number): Promise<boolean>;
  abandonRecovery(endpoint: string, requestKey: string): Promise<void>;
}

/**
 * The recovery lease a plan's head holds for one request (`orderPlan`'s `leased`) until an attempt is sent, as the
 * server's `ProbeLease`: the attempt owns it from there (`sent`); a request that ends or ranks again before any attempt
 * went out gives it back (`giveBack`), so the next request that could choose the probe takes it.
 */
export class HeldProbe {
  private held: { readonly endpoint: string; readonly leases: ProbeLeases; readonly requestKey: string } | null = null;

  /**
   * The lease the plan's head holds now (`orderPlan`'s `leased`, or a failover's re-ranked head's), null for none, of
   * `leases`, for `requestKey`: one held before for another route, never sent, goes back.
   */
  async hold(endpoint: string | null, leases: ProbeLeases, requestKey: string): Promise<void> {
    const before = this.held;
    this.held = endpoint === null ? null : { endpoint, leases, requestKey };
    if (before !== null && before.endpoint !== endpoint) await before.leases.abandonRecovery(before.endpoint, before.requestKey);
  }

  /** An attempt was sent to `endpoint`: it owns the lease held for it from here; a lease held for another goes back. */
  async sent(endpoint: string): Promise<void> {
    const held = this.held;
    this.held = null;
    if (held !== null && held.endpoint !== endpoint) await held.leases.abandonRecovery(held.endpoint, held.requestKey);
  }

  /** `endpoint` was passed over without an attempt: a lease held for it goes back. */
  async passed(endpoint: string): Promise<void> {
    if (this.held?.endpoint === endpoint) await this.giveBack();
  }

  /** No attempt was sent: the lease goes back. */
  async giveBack(): Promise<void> {
    const held = this.held;
    this.held = null;
    if (held !== null) await held.leases.abandonRecovery(held.endpoint, held.requestKey);
  }
}

/**
 * Orders a request's routes (`byId`, every eligible route by its rank key) from `ordered` under what `steering` decided
 * (`order_plan`): a due recovery probe first for a request that could choose it, by its lease (`leases`, for
 * `requestKey` at `nowMs`); the session and issuer targets; the steering of a blocked supplier's routes behind every
 * other route; the independent operator for the second attempt; then the head `settleHead` fixes.
 */
export async function orderPlan<R extends PlanRoute>(ordered: Ordered, byId: Map<string, R>, steering: Steering, preference: PlanPreference<R>, leases: ProbeLeases, nowMs: number, requestKey: string): Promise<PlanOrder<R>> {
  const { blocked } = steering;
  const away = (r: R) => blocked.has(r.record.operator);
  const take = (id: string): R | undefined => {
    const route = byId.get(id);
    if (route !== undefined) byId.delete(id);
    return route;
  };
  let routes = ordered.order.map(take).filter((r): r is R => r !== undefined);
  // A route whose recovery probe is due goes first, one at a time (its lease), for a request that could choose it: no
  // customer order (whose routes go first in its order, `settleHead`), no hit of a `client` or `cache` session at its
  // provider (which keeps its warm cache; a `key` session's hit carries the probe, since steady traffic is nearly all
  // such hits, lead decision K11), and no probe the ranking leased itself. A session target out of the order cannot take
  // the head, so it keeps no probe away. A request with a route of its tool-call issuer among its candidates, wherever
  // the order, its circuit or a block put it, carries only that issuer's own due probe, which leads as both: only the
  // issuer takes its ids, so the request is likely to fail elsewhere, and a probe that fails for its sake cools the route
  // again (docs/utility-routing.md "Draw and order"). Before the independent-operator preference.
  const sessionHit = steering.sessionTarget !== null && routes.some((r) => r.record.endpointId === steering.sessionTarget);
  const keySession = steering.sessionKind === "key";
  const mayProbe = (id: string) => steering.issuerRoutes.size === 0 || steering.issuerRoutes.has(id);
  let claimed: string | null = null;
  if (!preference.ordered && !(sessionHit && !keySession) && ordered.leased === null) {
    for (const id of ordered.due) {
      const due = byId.get(id);
      if (due === undefined || !mayProbe(id) || away(due) || !(await leases.claimRecovery(id, requestKey, nowMs))) continue;
      byId.delete(id);
      routes.unshift(due);
      claimed = id;
      break;
    }
  }
  const pinToHead = (index: number) => {
    const [pinned] = routes.splice(index, 1);
    routes.unshift(pinned!);
  };
  // The session decides the head before the independent-operator preference picks the second attempt. Behind a probe
  // its session carries (the `key` kind), the provider is next.
  if (steering.sessionTarget !== null) {
    const index = routes.findIndex((r) => r.record.endpointId === steering.sessionTarget);
    if (index >= 0 && claimed === null) pinToHead(index);
    else if (index >= 0) routes.splice(1, 0, ...routes.splice(index, 1));
  }
  // The issuer's first route takes the head unless the head is one of the issuer's already.
  let issuerPinned = false;
  if (steering.issued !== null && routes.length > 0 && !steering.issued.has(routes[0]!.record.endpointId)) {
    const index = routes.findIndex((r) => steering.issuerTarget.has(r.record.endpointId));
    if (index >= 0) {
      pinToHead(index);
      issuerPinned = true;
    }
  }
  // The steering (D4): a stable partition that moves every route of a blocked supplier behind every route that is not.
  // The targets and the probe skipped blocked routes, so a head they placed stays the head.
  let steeredHead = false;
  let steers: AccountBlock[] = [];
  let steeredRoutes: string[] = [];
  if (blocked.size > 0) {
    const steered = steer(routes, blocked);
    routes = steered.plan;
    steeredHead = steered.head;
    if (steeredHead) issuerPinned = false;
    const leftOut = [...byId.values()].filter(away).map((r) => r.record.endpointId);
    leftOut.sort();
    steeredRoutes = [...routes.filter(away).map((r) => r.record.endpointId), ...leftOut];
    if (steered.moved) steers = ACCOUNT_BLOCKS.filter((kind) => [...blocked.values()].includes(kind));
  }
  // Prefer an independent operator for the only permitted second attempt, among the suppliers no block steered the
  // request away from.
  if (!preference.ordered) routes = independentSecond(routes, blocked);
  const leased = await settleHead(leases, preference, ordered.leased, claimed, ordered.due, true, { routes: steering.issuerRoutes, away }, byId, routes, requestKey, nowMs);
  const head = routes[0];
  const reason =
    head === undefined
      ? null
      : headReason({
          leased: leased !== null,
          trial: ordered.trials.includes(head.record.endpointId),
          steered: steeredHead,
          issuerPinned,
          session: steering.sessionTarget !== null && head.record.endpointId === steering.sessionTarget,
          ordered: preference.ordered,
          unselected: ordered.unselected === head.record.endpointId,
        });
  return { routes, leased, headReason: reason, steers, steeredHead, issuerPinned, steeredRoutes };
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
 * What `settleHead` reads of a request's tool-call issuer (`ProbeIssuer`): the rank keys of its routes among the
 * request's candidates, cooling and steered ones included (`Steering.issuerRoutes`; at a failover's re-rank those left),
 * and whether a block steers the request away from a route's supplier.
 */
export interface ProbeIssuer<R extends PlanRoute> {
  readonly routes: ReadonlySet<string>;
  readonly away: (route: R) => boolean;
}

/** No tool-call issuer among a request's candidates, and no supplier steered away: a model API's request. */
export const NO_ISSUER: ProbeIssuer<PlanRoute> = { routes: new Set(), away: () => false };

/**
 * Fixes the head of `routes`, the ordered routes of one request, in place, and returns the rank key of the recovery
 * probe whose lease the head holds for the request (`settle_head`): `leased`, the probe the ranking leased itself,
 * `claimed`, the due probe the plan put first, or one it claims of `due` (still in `byId`): with every candidate left
 * open (the ranking leased a probe itself) the tool-call issuer's due route, else the one a customer order names; under
 * an order also at `admission` whenever it names that one ahead of every route and the `issuer` condition lets the
 * request carry it. Under a customer order the routes it named go first in its order. A recovery lease is dispatched
 * only as the first attempt: a probe moved off the head gives its lease back and leaves the plan.
 */
export async function settleHead<R extends PlanRoute>(
  leases: ProbeLeases,
  preference: PlanPreference<R>,
  leased: string | null,
  claimed: string | null,
  due: readonly string[],
  admission: boolean,
  issuer: ProbeIssuer<R>,
  byId: Map<string, R>,
  routes: R[],
  requestKey: string,
  nowMs: number,
): Promise<string | null> {
  let named: string | null = null;
  const position = (r: R) => preference.position(r) ?? Number.MAX_SAFE_INTEGER;
  if (preference.ordered) {
    // An explicit order is the customer's: routes it did not name keep their order behind the named ones.
    const sorted = [...routes].sort((a, b) => position(a) - position(b));
    routes.splice(0, routes.length, ...sorted);
  }
  // Every candidate left is open (the ranking leased a probe itself): the request has nowhere else to go, so the issuer
  // condition does not hold it back (docs/utility-routing.md "Draw and order", contract 0602784d9). The tool-call
  // issuer's due route takes the probe first, as at admission not one of a supplier a block steers the request away
  // from: the one the ranking leased when it is the issuer's, at the head wherever the order put it, else the first of
  // `due` whose lease is free.
  let issuers = false;
  if (leased !== null) {
    const issuersDue = (r: R) => issuer.routes.has(r.record.endpointId) && !issuer.away(r);
    const index = routes.findIndex((r) => r.record.endpointId === leased && issuersDue(r));
    if (index >= 0) {
      const [probe] = routes.splice(index, 1);
      routes.unshift(probe!);
      issuers = true;
    } else {
      for (const id of due) {
        const route = byId.get(id);
        if (route === undefined || !issuersDue(route) || !(await leases.claimRecovery(id, requestKey, nowMs))) continue;
        byId.delete(id);
        routes.unshift(route);
        named = id;
        issuers = true;
        break;
      }
    }
  }
  // An endpoint the order names ahead of every route the ranking returned, whose probe is due, takes the probe at the
  // head, as before r17 (docs/utility-routing.md "Draw and order", lead decision K11): the customer chose it, and when the
  // order is a key's or a workspace's default these requests may be all the traffic that endpoint ever sees. At
  // admission the issuer condition holds as for any due probe. A failover's re-rank carries no due probe of its own: only
  // in place of the one its ranking leased when every route left was open, which the ranking picked knowing nothing of
  // the order, and then whoever's it is.
  if (!issuers && preference.ordered && (admission || leased !== null)) {
    const mayProbe = (id: string) => issuer.routes.size === 0 || issuer.routes.has(id);
    const head = routes.length === 0 ? Number.MAX_SAFE_INTEGER : position(routes[0]!);
    let first: { at: number; id: string } | undefined;
    for (const id of due) {
      const route = byId.get(id);
      const at = route === undefined || (leased === null && !mayProbe(id)) ? undefined : preference.position(route);
      if (at === undefined || at >= head) continue;
      if (first === undefined || at < first.at) first = { at, id };
    }
    if (first !== undefined && (await leases.claimRecovery(first.id, requestKey, nowMs))) {
      const route = byId.get(first.id)!;
      byId.delete(first.id);
      routes.unshift(route);
      named = first.id;
    }
  }
  for (const probe of [leased, claimed, named]) {
    if (probe === null || routes.length === 0 || routes[0]!.record.endpointId === probe) continue;
    await leases.abandonRecovery(probe, requestKey);
    const kept = routes.filter((r) => r.record.endpointId !== probe);
    routes.splice(0, routes.length, ...kept);
  }
  const head = routes[0]?.record.endpointId;
  if (head === undefined) return null;
  return head === leased || head === claimed || head === named ? head : null;
}

/**
 * The plan's reasons for the route at `rankKey` (endpoint `id`) among the record's candidates (docs/utility-routing.md
 * "Evidence"; inference.rs `plan_reasons`), in this order: `session` (the session's provider the plan went back to),
 * `probe` (the head's lease), `unselected` (the formula's unselected share moved it first), `order` (the customer's order
 * names it), `account_block_steered` (a block steered the request away from its supplier).
 */
export function planReasons(
  rankKey: string,
  id: string,
  plan: { readonly session: string | null; readonly probe: string | null; readonly unselected: string | null; readonly named: (id: string) => boolean; readonly steered: readonly string[] },
): string[] {
  const reasons: string[] = [];
  if (plan.session === id) reasons.push("session");
  if (plan.probe === id) reasons.push("probe");
  if (plan.unselected === rankKey) reasons.push("unselected");
  if (plan.named(id)) reasons.push("order");
  if (plan.steered.includes(id)) reasons.push("account_block_steered");
  return reasons;
}
