import type { AccountBlock } from "@gray/errors";
import { AccountBlockGates, type Pattern } from "@gray/endpoint";
import type { BlockGates, GateReading } from "./dispatcher.ts";
import type { Route } from "./routes.ts";
import { AccountBlockGaugeWriter } from "./sinks.ts";

/**
 * A vendor's block on a supplier's upstream account in this gateway (release 4; the server's
 * `AccountBlockGates` in `InferenceRuntime` and the steering of `admit`, crates/gray-gateway/src/inference.rs):
 * the isolate's gates, and how admission orders a request's routes by them.
 *
 * The gates are isolate-local, as the server's are process-local (docs/cloudflare-native/gateway.md section 13):
 * nothing on the request path asks another object, and an isolate learns a block from a refusal it met itself.
 */

/**
 * How many gates an isolate keeps: the server's bound, `RankingConfig::max_endpoints` (4,096), the bound of
 * its second-opinion gates and of the endpoint shards' (`RETRY_STATE_BOUND`, @gray/endpoint shard.ts). A gate
 * is a few hundred bytes, so the bound holds about a megabyte at most.
 */
export const ACCOUNT_BLOCK_BOUND = 4096;

/** The isolate's gates: one per (supplier workspace, model, client and tool shape). */
export const accountBlockIsolate = new AccountBlockGates(ACCOUNT_BLOCK_BOUND);

/** When the isolate writes its gauge of paused gates (gray_upstream_account_blocks_paused). */
export const accountBlockGauges = new AccountBlockGaugeWriter();

/** `gates` of one request's `model` and `pattern`, read at `clock` (the dispatcher's `BlockGates`). */
export function blockGates(gates: AccountBlockGates, model: string, pattern: Pattern, clock: () => number): BlockGates {
  return {
    holdsOff: (supplier: string, reading: GateReading) =>
      reading.at === null ? gates.holdsOff(supplier, model, pattern, clock(), reading.own) : gates.willHoldOff(supplier, model, pattern, reading.at, reading.own),
    pass: (supplier) => gates.pass(supplier, model, pattern, clock()),
  };
}

/**
 * The suppliers of `routes` whose gate holds the request off now, with the block (`admit`, D4): paused, or
 * unproven with its one re-test lease out. None when every supplier of the model is held off alike: with no
 * supplier left to go to first, the order is unchanged. Takes nothing: a supplier whose gate is unproven with
 * its lease free keeps its ranked place, and an attempt sent there takes the lease (`Dispatcher.passGate`).
 */
export function blockedSuppliers(routes: readonly PlanRoute[], gates: BlockGates): Map<string, AccountBlock> {
  const blocked = new Map<string, AccountBlock>();
  for (const supplier of new Set(routes.map((r) => r.record.operator))) {
    const block = gates.holdsOff(supplier, { own: null, at: null });
    if (block !== undefined) blocked.set(supplier, block);
  }
  if (routes.every((r) => blocked.has(r.record.operator))) blocked.clear();
  return blocked;
}

/**
 * What admission's ordering reads of a route: its endpoint and its supplier (the operator). A `Route` is one; a
 * conformance replay of the plan order builds them from JSON alone.
 */
export interface PlanRoute {
  readonly record: { readonly endpointId: string; readonly operator: string };
}

/** What the steering made of a ranked plan. */
export interface Steered<R extends PlanRoute = Route> {
  readonly plan: R[];
  /** The plan's head is another than ranking gave it: the request log's `routing_head_reason` is `account_block`. */
  readonly head: boolean;
  /** A route of a blocked supplier was put behind one of another (the steers counter's event). */
  readonly moved: boolean;
}

/**
 * The steering (`admit`, D4): a stable partition that moves every route of a `blocked` supplier behind every
 * route that is not. With only blocked routes ranked, the supplier's refusal would send the request to one of
 * the routes ranking left out for want of samples after all: `unsampled` (those, not blocked, ranked without
 * exploration) go there first. A route left out for its circuit stays out. The pins skipped blocked routes
 * before, so a pinned head stays the head.
 */
export function steer<R extends PlanRoute>(plan: readonly R[], blocked: ReadonlyMap<string, AccountBlock>, unsampled: readonly R[]): Steered<R> {
  if (blocked.size === 0) return { plan: [...plan], head: false, moved: false };
  const away = (r: R) => blocked.has(r.record.operator);
  const routes = plan.every(away) ? [...plan, ...unsampled.filter((r) => !away(r) && !plan.includes(r))] : [...plan];
  const headBefore = routes[0]?.record.endpointId;
  let seenAway = false;
  let moved = false;
  for (const route of routes) {
    if (away(route)) seenAway = true;
    else if (seenAway) moved = true;
  }
  const steered = [...routes.filter((r) => !away(r)), ...routes.filter(away)];
  return { plan: steered, head: steered[0]?.record.endpointId !== headBefore, moved };
}

/**
 * The independent-operator preference (`admit`, after the steering): of a plan of more than two routes, the
 * first route after the head whose operator is another than the head's, among the suppliers no block steered
 * the request away from, changes places with the second, so the one permitted failover goes to an independent
 * failure domain. A steered supplier's routes stay behind every other route. Never under a customer order
 * (plan-order.ts `orderPlan`): the order is kept as named.
 */
export function independentSecond<R extends PlanRoute>(plan: readonly R[], blocked: ReadonlyMap<string, AccountBlock>): R[] {
  const routes = [...plan];
  const head = routes[0];
  if (head === undefined || routes.length <= 2) return routes;
  const index = routes.findIndex((r, i) => i >= 1 && r.record.operator !== head.record.operator && !blocked.has(r.record.operator));
  if (index > 1) [routes[1], routes[index]] = [routes[index]!, routes[1]!];
  return routes;
}
