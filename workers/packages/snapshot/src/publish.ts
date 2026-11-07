import { accountKeyConfig, type SnapshotKey } from "./keys.ts";
import type { RouteRestChecks } from "./rests.ts";
import type { SnapshotCapacity, SnapshotWorkspace } from "./snapshot.ts";

/**
 * What ConfigDO tells the authorities after a rebuild (docs/cloudflare-native.md 2.3, rule 2: the
 * snapshot proposes, the authoritative object decides):
 *
 * - each workspace's account root, every key whose admission terms changed: refused or not (revoked,
 *   disabled, held by a Viewer, expired), requests a minute, spend limit (AccountRootDO.putKey). The
 *   root pushes it to its active shards at once (@gray/account).
 * - each capacity key's endpoint root, the concurrency its supplier agreed to
 *   (EndpointRootDO.configure) with the checks of its route that passed, which end the failure rests
 *   that began no later, a withdrawal when the capacity is no longer enabled (no current pass, the
 *   endpoint left the registry) and a reinstatement when it is again.
 *
 * ConfigDO keeps what it last told each one and sends only differences; a call that failed is
 * tried again after the next rebuild, since the record is written only after it succeeded. Both
 * calls are idempotent at the receiver (putKey with the same terms changes nothing, configure with
 * the same maximum delivers nothing), so a repeat after a lost answer is harmless.
 */

export interface KeyTerms {
  readonly workspaceId: string;
  /** The workspace's home region (`SnapshotContent.workspaces`): where its root is created, a location hint. */
  readonly home: string;
  readonly keyId: string;
  readonly revoked: boolean;
  readonly rpm: number | null;
  readonly limit: number | null;
  readonly period: "never" | "day" | "week" | "month";
}

export interface CapacityTerms {
  readonly capacityKey: string;
  readonly maxConcurrency: number;
  readonly withdrawn: boolean;
  /** The checks of the route that passed (`SnapshotCapacity.restChecks`); absent in a record published before them. */
  readonly restChecks?: RouteRestChecks;
}

/**
 * The key terms each workspace's root should have at `atSeconds`, by key id; `workspaces` names each key's
 * workspace's home region (`SnapshotContent.workspaces`, which has a row for every key's workspace).
 */
export function keyTerms(keys: readonly SnapshotKey[], atSeconds: number, workspaces: readonly SnapshotWorkspace[]): Map<string, KeyTerms> {
  const homes = new Map(workspaces.map((w) => [w.workspaceId, w.home]));
  const out = new Map<string, KeyTerms>();
  for (const k of keys) {
    const c = accountKeyConfig(k, atSeconds);
    const home = homes.get(k.workspaceId);
    if (home === undefined) throw new RangeError(`no workspace row for key ${k.keyId}'s workspace ${k.workspaceId}`);
    out.set(k.keyId, { workspaceId: k.workspaceId, home, keyId: k.keyId, revoked: c.revoked, rpm: c.rpm, limit: c.limit, period: c.period });
  }
  return out;
}

export const sameKeyTerms = (a: KeyTerms, b: KeyTerms) =>
  a.workspaceId === b.workspaceId && a.home === b.home && a.revoked === b.revoked && a.rpm === b.rpm && a.limit === b.limit && a.period === b.period;

/**
 * The key changes to send: every key whose terms differ from what was published, and every key
 * published before that is gone from the snapshot, as revoked (a key row is never deleted, so that is
 * a key the snapshot can no longer serve).
 */
export function keyChanges(want: ReadonlyMap<string, KeyTerms>, published: ReadonlyMap<string, KeyTerms>): KeyTerms[] {
  const out: KeyTerms[] = [];
  for (const [id, terms] of want) {
    const prior = published.get(id);
    if (!prior || !sameKeyTerms(prior, terms)) out.push(terms);
  }
  for (const [id, prior] of published) if (!want.has(id) && !prior.revoked) out.push({ ...prior, revoked: true });
  return out;
}

/**
 * The published keys to forget: revoked, and gone from the snapshot, which leaves out a key revoked longer than
 * REVOKED_KEY_MEMORY_MS ago (gray-jobs' snapshot reader). Its root was told it is revoked, and keeps that in its own
 * revoked_keys; the key's row stays revoked. Forgetting it keeps the record of publications the size of the keys
 * in use, as the snapshot is. A key gone while still published as live is not here: keyChanges revokes it first.
 */
export function forgottenKeys(want: ReadonlyMap<string, KeyTerms>, published: ReadonlyMap<string, KeyTerms>): string[] {
  const out: string[] = [];
  for (const [id, prior] of published) if (prior.revoked && !want.has(id)) out.push(id);
  return out;
}

/** The capacity terms the endpoint roots should have: enabled capacities serve, the rest are withdrawn. */
export function capacityTerms(capacities: readonly SnapshotCapacity[]): Map<string, CapacityTerms> {
  return new Map(capacities.map((c) => [c.capacityKey, { capacityKey: c.capacityKey, maxConcurrency: c.maxConcurrency, withdrawn: !c.enabled, ...(c.restChecks === undefined ? {} : { restChecks: c.restChecks }) }]));
}

/** The capacity changes to send; a published capacity gone from the snapshot is withdrawn. */
export function capacityChanges(want: ReadonlyMap<string, CapacityTerms>, published: ReadonlyMap<string, CapacityTerms>): CapacityTerms[] {
  const out: CapacityTerms[] = [];
  for (const [key, terms] of want) {
    const prior = published.get(key);
    // A newer pass of the route's checks is told too: it ends the rests its root holds that began no later.
    if (!prior || prior.maxConcurrency !== terms.maxConcurrency || prior.withdrawn !== terms.withdrawn || !sameChecks(prior.restChecks, terms.restChecks)) out.push(terms);
  }
  for (const [key, prior] of published) if (!want.has(key) && !prior.withdrawn) out.push({ ...prior, withdrawn: true });
  return out;
}

/**
 * How long ConfigDO's record of what it told an endpoint root stands before it tells that root again (`capacityResends`):
 * an hour (docs/request-path-availability.md section 5 row 11, assumption A7). A root whose storage started over, not a
 * documented condition (an object's confirmed storage survives every reset), is unconfigured and refuses every borrow,
 * while the record says it was told; sending only changes, ConfigDO would never tell it again. Each re-send is one call
 * per capacity an hour, which changes nothing at a root that kept its storage (the same maximum, `EndpointRoot.configure`;
 * a withdrawal of a withdrawn root).
 */
export const CAPACITY_RESEND_MS = 3_600_000;

/** A capacity as ConfigDO recorded telling its root: the terms, and when it told it (absent in a record written before). */
export interface PublishedCapacity extends CapacityTerms {
  readonly sentAtMs?: number;
  /**
   * The root was configured at least once since this record began (a withdrawal alone configures nothing): what lets a
   * later configure say `published` (@gray/endpoint ConfigureInput, docs/request-path-availability.md M12). Absent in
   * records written before it: read as configured unless the record is a withdrawal.
   */
  readonly configured?: boolean;
}

/** Whether a root was configured before, by ConfigDO's record of it (`PublishedCapacity.configured`). */
export function configuredBefore(record: PublishedCapacity | undefined): boolean {
  return record !== undefined && (record.configured ?? !record.withdrawn);
}

/**
 * The capacities of the snapshot (`want`) whose root was last told `resendMs` or more before `nowMs`, unchanged since
 * (`capacityChanges` has the changed ones), to tell again; a record without its time is due at once. Withdrawn ones too
 * (a root that started over is not withdrawn), but none gone from the snapshot: its root was told to withdraw, and one
 * that started over refuses as unconfigured anyway.
 */
export function capacityResends(want: ReadonlyMap<string, CapacityTerms>, published: ReadonlyMap<string, PublishedCapacity>, nowMs: number, resendMs: number = CAPACITY_RESEND_MS): CapacityTerms[] {
  const out: CapacityTerms[] = [];
  for (const [key, terms] of want) {
    const prior = published.get(key);
    if (prior === undefined || prior.maxConcurrency !== terms.maxConcurrency || prior.withdrawn !== terms.withdrawn || !sameChecks(prior.restChecks, terms.restChecks)) continue;
    if (prior.sentAtMs === undefined || nowMs - prior.sentAtMs >= resendMs) out.push(terms);
  }
  return out;
}

/**
 * How long ConfigDO's record of a key it told an account root stands before it tells that root again (`keyResends`): an
 * hour, as capacities (docs/request-path-availability.md M12, PR 11b). An account root whose storage started over (A7)
 * has no keys, and refuses every keyed admit `unknown_key`, while the record says it was told: sending only changes,
 * ConfigDO would never tell it again. A root that kept its storage takes unchanged terms as a no-op (@gray/account
 * `writeKey`): one read per key an hour.
 */
export const KEY_RESEND_MS = 3_600_000;

/** A key as ConfigDO recorded telling its root: the terms, and when it told it (absent in a record written before). */
export interface PublishedKey extends KeyTerms {
  readonly sentAtMs?: number;
}

/**
 * The keys of the snapshot (`want`) whose root was last told `resendMs` or more before `nowMs`, unchanged since
 * (`keyChanges` has the changed ones), to tell again; a record without its time is due at once. Revoked ones too: a root
 * that started over learns the key is revoked. None gone from the snapshot: `keyChanges` revoked those.
 */
export function keyResends(want: ReadonlyMap<string, KeyTerms>, published: ReadonlyMap<string, PublishedKey>, nowMs: number, resendMs: number = KEY_RESEND_MS): KeyTerms[] {
  const out: KeyTerms[] = [];
  for (const [id, terms] of want) {
    const prior = published.get(id);
    if (prior === undefined || !sameKeyTerms(prior, terms)) continue;
    if (prior.sentAtMs === undefined || nowMs - prior.sentAtMs >= resendMs) out.push(terms);
  }
  return out;
}

function sameChecks(a: RouteRestChecks | undefined, b: RouteRestChecks | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.endpointMs === b.endpointMs && a.modelMs === b.modelMs && a.routeMs === b.routeMs;
}

/**
 * One call ConfigDO makes on an authority. A capacity that serves is `reinstate`d before it is
 * configured whenever ConfigDO cannot be sure its root is not withdrawn: it told the root to withdraw,
 * or it has no record of what it told the root at all (a first publication, or its storage started
 * over), since the root may still be withdrawn from before. Reinstating a root that is not withdrawn
 * changes nothing (@gray/endpoint EndpointRoot.reinstate).
 */
export type Publication =
  | { readonly kind: "key"; readonly terms: KeyTerms }
  | { readonly kind: "capacity"; readonly terms: CapacityTerms; readonly reinstate: boolean };

/**
 * The calls for these changes, most urgent first: revocations (a key that must stop being admitted),
 * then withdrawals (a capacity that must stop serving), then the other key and capacity changes
 * taken in turn, so neither list starves the other. A long list (a first publication, thousands of
 * keys) is sent over several rebuilds; a revocation that arrives meanwhile goes ahead of what is left.
 */
export function publications(keys: readonly KeyTerms[], capacities: readonly CapacityTerms[], publishedCapacities: ReadonlyMap<string, CapacityTerms>): Publication[] {
  const key = (terms: KeyTerms): Publication => ({ kind: "key", terms });
  const capacity = (terms: CapacityTerms): Publication => {
    const prior = publishedCapacities.get(terms.capacityKey);
    return { kind: "capacity", terms, reinstate: !terms.withdrawn && (prior === undefined || prior.withdrawn) };
  };
  const revocations = keys.filter((t) => t.revoked).map(key);
  const withdrawals = capacities.filter((t) => t.withdrawn).map(capacity);
  const otherKeys = keys.filter((t) => !t.revoked).map(key);
  const otherCapacities = capacities.filter((t) => !t.withdrawn).map(capacity);
  const rest: Publication[] = [];
  for (let i = 0; i < Math.max(otherKeys.length, otherCapacities.length); i++) {
    if (i < otherKeys.length) rest.push(otherKeys[i]!);
    if (i < otherCapacities.length) rest.push(otherCapacities[i]!);
  }
  return [...revocations, ...withdrawals, ...rest];
}

/** How many publications at the head of `todo` (as `publications` orders them) are revocations or withdrawals. */
export function urgentCount(todo: readonly Publication[]): number {
  const n = todo.findIndex((p) => !(p.kind === "key" ? p.terms.revoked : p.terms.withdrawn));
  return n === -1 ? todo.length : n;
}

export interface SendOptions<T> {
  /** At most this many calls in flight (CONFIG_PUBLISH_CONCURRENCY). */
  readonly concurrency: number;
  /** No call starts at or after this time (ms), except the urgent ones; calls in flight end by their own timeout. */
  readonly deadline: number;
  /**
   * The first this many items start whatever the time (default 0): the revocations and withdrawals
   * (`urgentCount`), which must not wait for a later rebuild however slow this one was.
   */
  readonly urgent?: number;
  readonly clock: () => number;
  /** Makes one call: true when it was delivered, false when it failed (it is tried again later). */
  readonly send: (item: T) => Promise<boolean>;
}

/** Sends `items` in order with at most `concurrency` in flight: the urgent ones all, the rest until the deadline. What was not started is `pending`. */
export async function sendInOrder<T>(items: readonly T[], o: SendOptions<T>): Promise<{ readonly sent: number; readonly failed: number; readonly pending: number }> {
  if (!Number.isSafeInteger(o.concurrency) || o.concurrency < 1) throw new RangeError(`concurrency must be a positive integer, got ${o.concurrency}`);
  const urgent = o.urgent ?? 0;
  let next = 0;
  let sent = 0;
  let failed = 0;
  const worker = async () => {
    while (next < items.length && (next < urgent || o.clock() < o.deadline)) {
      const item = items[next++]!;
      if (await o.send(item)) sent++;
      else failed++;
    }
  };
  await Promise.all(Array.from({ length: Math.min(o.concurrency, items.length) }, worker));
  return { sent, failed, pending: items.length - next };
}
