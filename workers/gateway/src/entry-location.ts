import type { DeployEnv, LocationHint } from "@gray/config";
import type { EntryNode, EntryRegion, EntryReplica, ServingEntry } from "@gray/request-index";

/**
 * The entry that served a request, for its index row (`entry_node`, `entry_region`; workers/db/migrations/0110,
 * docs/design/request-logs.md "The serving entry"). Recorded only: no routing, ranking or permit reads it.
 *
 * The node is what the platform or the boot established, never what the request says: on the Workers gateway the data
 * center Cloudflare names in `request.cf.colo` (`workerEntry`), in the TEE entry the replica index the boot validated
 * (`teeEntry`, LANE_REPLICA). The region is looked up in the inventory compiled into the build for the deployment
 * environment, keyed by the node; a node it does not name is `unknown`. The request's own region
 * (`requestRegion`, the client's continent or GATEWAY_FALLBACK_REGION) is a Durable Object location hint and is never
 * taken for the entry's.
 */

/** A region an inventory names: a word of the location vocabulary (`unknown` is what a lookup gives for a node it lacks). */
export type InventoryRegion = Exclude<EntryRegion, "unknown">;

/** Where the nodes of one deployment environment are, by node word. */
export interface EntryInventory {
  /** The Workers gateway's data centers (`cf:SJC`). */
  readonly edge: Readonly<Record<string, InventoryRegion>>;
  /** The TEE entry's replicas (`tee:1` ... `tee:16`, `tee:single`). */
  readonly tee: Readonly<Record<string, InventoryRegion>>;
}

const EMPTY: EntryInventory = Object.freeze({ edge: Object.freeze({}), tee: Object.freeze({}) });

/**
 * Each deployment environment's inventory (@gray/config `DEPLOY_ENVS`). Empty this round: where each replica of each
 * environment runs is Jin's to supply, so every node's region is `unknown` until then. A new data center or replica is
 * an entry here and nothing else.
 */
export const ENTRY_INVENTORIES: Readonly<Record<DeployEnv, EntryInventory>> = Object.freeze({ local: EMPTY, testnet: EMPTY, production: EMPTY });

/** A Cloudflare data center's code as `request.cf.colo` states it: three upper-case letters. */
const COLO = /^[A-Z]{3}$/;

const regionOf = (node: EntryNode, sites: Readonly<Record<string, InventoryRegion>>): EntryRegion => (Object.hasOwn(sites, node) ? sites[node]! : "unknown");

/** The Workers gateway's entry: `cf:` and the platform's data center code, `cf:unknown` for a missing or malformed one. */
export function workerEntry(colo: unknown, sites: EntryInventory["edge"]): ServingEntry {
  const node: EntryNode = typeof colo === "string" && COLO.test(colo) ? `cf:${colo}` : "cf:unknown";
  return { node, region: regionOf(node, sites) };
}

/** The TEE entry's: its validated replica index as `tee:<n>`, `tee:single` for an entry without one (never `tee:1`). */
export function teeEntry(index: EntryReplica | null, sites: EntryInventory["tee"]): ServingEntry {
  const node: EntryNode = index === null ? "tee:single" : `tee:${index}`;
  return { node, region: regionOf(node, sites) };
}

/** The inventory's words are the location vocabulary's (@gray/config `LOCATION_HINTS`): either list changing alone fails here. */
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
const SAME_VOCABULARY: Same<InventoryRegion, LocationHint> = true;
void SAME_VOCABULARY;
