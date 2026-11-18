import {
  ENTRY_ROUTE_DENY_SUFFIXES,
  ROUTE_ROW_MAX_TTL_SECONDS,
  ROUTE_TABLE_MAX_ROWS,
  endpointRouteKey,
  endpointRoutePath,
  endpointRouteTarget,
  routeInMode,
  snapshotRoutes,
  validRouteRow,
  type EndpointRouteRow,
  type Snapshot,
} from "@gray/snapshot";
import { parseSerde } from "@gray/json";
import type { GatewaySnapshot, RouteRecord } from "../snapshot.ts";
import { BridgeCallError } from "./remote/client.ts";
import { LaneFetchRefusal } from "./fetch-refusal.ts";

/**
 * An entry's endpoint routes (docs/design/lane-provider-routes.md sections 3.2, 4.2 and 5): the routes a provider set up
 * with an API address and a key, which the entry serves beside its lane relays' when its view admits them
 * (@gray/snapshot `routeInMode`). One per boot state, in memory only.
 *
 * - **The route table.** Every endpoint route the view admits has one row in egress's table, by endpoint: the route id
 *   `endpointRouteKey(endpoint id)`, the base URL's host and path. The table goes to egress (`PUT /v1/routes`, the
 *   pins' pattern, `peer-client.ts`) under the registry's start epoch and a push counter: after every snapshot change,
 *   again from `maintain()` until egress took it (204; a 409 `routes_stale` means a later push got there first), and
 *   again before its rows' `not_after` (an hour at most) runs out.
 * - **The keys.** The provider's API key of each endpoint at its credential generation, from the bridge's
 *   `endpoint.credential` (`remote/endpoint-credential.ts`): prefetched for the view's endpoint routes after each change,
 *   a few at a time, and dropped when the generation changes or the route leaves. An attempt whose key is not here
 *   fetches it once (or joins the fetch out) and waits for it within its own budget (`credential`); the fetch itself
 *   has the background bound. A key is never written to a log, a disk or a record.
 * - **The fetch.** An attempt's own fetch (`fetchFor`): its route's URL, `https://<host><path>`, goes to egress as
 *   `http://route.gray.invalid/route/<key><path>` only when the host and the path prefix are the endpoint's row, and
 *   only once egress has taken a table holding that row (the attempt pushes it within its own bound if not).
 *
 * Every background call is bounded (BACKGROUND_CALL_MS) by the clock of the fetch that finds it, never by its own
 * timer alone: once the fetch that started a call ends, neither its call nor its timer settles (D116 (c)), so a push or a
 * key fetch past its bound is let go and the next fetch starts a new one.
 */

/** egress's control API and route kind on the lane's unix socket (deploy/tee/egress/endpoint_routes.go). */
export const ROUTES_CONTROL_URL = "http://egress/v1/routes";
/** The fixed host of a `/route/` request: egress ignores it and takes the host from the table (design 4.1). */
export const ROUTE_ORIGIN = "http://route.gray.invalid";

/** The bound of one background call: the bridge's background reads' (`remote/background.ts` BACKGROUND_CALL_MS). */
const CALL_MS = 15_000;
/** The keys fetched at once after a snapshot change (a bound on the bridge's and the console's load, not a measure). */
const PREFETCH_CONCURRENCY = 4;
/** A row's lifetime as pushed: egress's most (an hour); the table is pushed again when half of it is gone. */
const ROW_TTL_MS = ROUTE_ROW_MAX_TTL_SECONDS * 1000;
/** After a push egress refused (not as stale), or a key the console refused, the wait before asking again. */
const REFUSED_BACKOFF_MS = 60_000;
/** After a key fetch that failed otherwise (a transport failure, a generation the snapshot has not caught up with). */
const FAILED_BACKOFF_MS = 5_000;

/** One endpoint the view admits, as the table and the key cache need it. */
interface EndpointRow {
  readonly endpointId: string;
  readonly generation: number;
  readonly key: string;
  readonly host: string;
  readonly pathPrefix: string;
}

/** The endpoint routes of a raw snapshot the lane view admits (`routeInMode` "lane", not a lane relay), by endpoint. */
export function endpointRowsOfSnapshot(snapshot: Snapshot): { readonly endpointId: string; readonly generation: number; readonly baseUrl: string }[] {
  return snapshotRoutes(snapshot)
    .filter((r) => r.config.auth !== "lane_relay" && routeInMode(r, "lane"))
    .map((r) => ({ endpointId: r.endpointId, generation: r.credentialGeneration, baseUrl: r.config.base_url }));
}

/** The endpoint routes of a lane view, by endpoint (the view holds only routes `routeInMode` admits). */
export function endpointRowsOfView(view: GatewaySnapshot): { readonly endpointId: string; readonly generation: number; readonly baseUrl: string }[] {
  return view.routes.filter((r) => r.auth !== "lane_relay").map((r) => ({ endpointId: r.endpointId, generation: r.credentialGeneration, baseUrl: r.baseUrl }));
}

export interface EntryEndpointRoutesDeps {
  /** The EGRESS binding: the table push and every `/route/` request. */
  readonly egress: (input: string, init: RequestInit) => Promise<Response>;
  /** `endpoint.credential` over the bridge (`remoteEndpointCredentials`), within `timeoutMs`. */
  readonly credential: (endpointId: string, generation: number, timeoutMs: number) => Promise<Uint8Array>;
  readonly clock: () => number;
  readonly log: (line: Record<string, unknown>) => void;
  /** The background call bound (CALL_MS by default; a test's own). */
  readonly callMs?: number;
}

/** A background call out now, and the clock by which it has ended or is let go. */
interface Running<T> {
  done: Promise<T>;
  until: number;
}

/** A key in memory: its generation and the key as the console stores it (UTF-8 text). */
interface HeldKey {
  readonly generation: number;
  readonly key: string;
}

export class EntryEndpointRoutes {
  readonly #deps: EntryEndpointRoutesDeps;
  readonly #callMs: number;
  /** `X-Gray-Route-Version`: fixed when the registry starts, so a restarted lane's table counts above the last. */
  readonly #epoch: number;
  #push = 0;
  /** The snapshot version the rows are of; -1 before the first. */
  #version = -1;
  #rows = new Map<string, EndpointRow>();
  /** Changes of the table (`sync`), and how many of them the last table egress took (204) covered. */
  #changes = 0;
  #pushedChanges = 0;
  /** When the table egress last took runs out: its rows' `not_after` (ms), 0 before any. */
  #pushedUntil = 0;
  /** Not before this: egress refused the last table (400), and the next push waits. */
  #refusedUntil = 0;
  #pushing: Running<boolean> | null = null;
  readonly #keys = new Map<string, HeldKey>();
  readonly #fetching = new Map<string, Running<string | null>>();
  /** Not before this, per `endpoint\0generation`: its last fetch failed. */
  readonly #keyBackoff = new Map<string, number>();

  constructor(deps: EntryEndpointRoutesDeps) {
    this.#deps = deps;
    this.#callMs = deps.callMs ?? CALL_MS;
    this.#epoch = deps.clock();
  }

  /** How many endpoints the table holds and how many of their keys are in memory (`/healthz`: counts only). */
  summary(): { readonly endpoints: number; readonly keys: number; readonly pushed: boolean } {
    let keys = 0;
    for (const row of this.#rows.values()) if (this.#keys.get(row.endpointId)?.generation === row.generation) keys += 1;
    return { endpoints: this.#rows.size, keys, pushed: this.#pushedChanges >= this.#changes && this.#deps.clock() < this.#pushedUntil };
  }

  /**
   * The view of snapshot `version` admits `routes`: the rows of a newer version replace the table's, a changed table is
   * due a push, and a key whose endpoint left or whose generation changed is dropped. No call is made here: `maintain`
   * and the attempts make them. An older version than the rows' changes nothing.
   */
  sync(version: number, routes: readonly { readonly endpointId: string; readonly generation: number; readonly baseUrl: string }[]): void {
    if (version <= this.#version) return;
    this.#version = version;
    const rows = new Map<string, EndpointRow>();
    for (const route of routes) {
      if (rows.has(route.endpointId)) continue;
      const target = endpointRouteTarget(route.baseUrl, ENTRY_ROUTE_DENY_SUFFIXES);
      // The view admitted it by this same rule; a route that does not pass is a view of another build, left out.
      if (target === null) continue;
      rows.set(route.endpointId, { endpointId: route.endpointId, generation: route.generation, key: endpointRouteKey(route.endpointId), host: target.host, pathPrefix: target.pathPrefix });
    }
    if (rows.size > ROUTE_TABLE_MAX_ROWS) {
      // egress refuses a larger table whole; the endpoints past the bound (by route key) are left out of it, and their
      // attempts are refused by `fetchFor` (no row). Logged by count only.
      const kept = [...rows.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)).slice(0, ROUTE_TABLE_MAX_ROWS);
      this.#deps.log({ level: "error", event: "lane_routes_over_bound", endpoints: rows.size, kept: kept.length });
      rows.clear();
      for (const row of kept) rows.set(row.endpointId, row);
    }
    const changed = rows.size !== this.#rows.size || [...rows.values()].some((row) => {
      const was = this.#rows.get(row.endpointId);
      return was === undefined || was.host !== row.host || was.pathPrefix !== row.pathPrefix;
    });
    this.#rows = rows;
    if (changed) this.#changes += 1;
    for (const [endpointId, held] of this.#keys) {
      if (rows.get(endpointId)?.generation !== held.generation) this.#keys.delete(endpointId);
    }
    for (const fetchKey of this.#keyBackoff.keys()) {
      const [endpointId, generation] = fetchKey.split("\u0000");
      if (String(rows.get(endpointId!)?.generation) !== generation) this.#keyBackoff.delete(fetchKey);
    }
  }

  /**
   * Everything due, from the fetch that calls it: the table when egress has not taken its last change or half its rows'
   * lifetime is gone, and the keys of the table's endpoints not in memory, PREFETCH_CONCURRENCY at a time. Resolves when
   * the work it started has ended or been let go; never throws.
   */
  async maintain(): Promise<void> {
    const now = this.#deps.clock();
    const work: Promise<unknown>[] = [];
    if (this.#pushDue(now)) work.push(this.#pushBackground());
    const due = [...this.#rows.values()].filter((row) => this.#keyDue(row, now));
    if (due.length > 0) work.push(this.#prefetch(due));
    await Promise.all(work);
  }

  /**
   * The key of `endpointId` at `generation` for an attempt: the one in memory, else one fetch (or the one already out)
   * waited for within `budgetMs`. Null when none could be had in that time, the endpoint has no row at that generation
   * (the table's snapshot is another), or its last fetch failed within its rest (the console refused it, or the bridge
   * did not answer): the attempt passes its route over as `route_inactive`.
   *
   * A fetch the attempt starts has the background bound (CALL_MS), as a prefetch has, whatever the attempt waits: an
   * attempt that stops waiting lets it go on, so the key is in memory for the next attempt. Cut at the attempt's own
   * wait, a cold `endpoint.credential` slower than that wait never landed, and its failure rested the key five seconds
   * (staging 2026-11-18, lane release V: a replica's first request to a quick route was 503 with no attempt).
   */
  async credential(endpointId: string, generation: number, budgetMs: number): Promise<string | null> {
    const held = this.#keys.get(endpointId);
    if (held !== undefined && held.generation === generation) return held.key;
    if (budgetMs <= 0) return null;
    const row = this.#rows.get(endpointId);
    if (row === undefined || row.generation !== generation) return null;
    // A key the console just refused, or whose fetch just failed, is not asked again by every attempt meanwhile.
    if (this.#deps.clock() < (this.#keyBackoff.get(keyOf(endpointId, generation)) ?? 0)) return null;
    const running = this.#fetchKey(row, this.#callMs);
    let timer: ReturnType<typeof setTimeout> | null = null;
    const late = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), budgetMs);
    });
    try {
      return await Promise.race([running, late]);
    } finally {
      if (timer !== null) clearTimeout(timer);
    }
  }

  /**
   * The fetch of one attempt at `route` (an endpoint route of the lane view): the route's URL to egress's `/route/` kind
   * under the endpoint's row, a `LaneFetchRefusal` when the table holds no row for the endpoint or the URL is not under
   * it. The row comes from the table, never from the request, and the URL is checked against it as egress checks it.
   */
  fetchFor(route: Pick<RouteRecord, "endpointId" | "baseUrl">): (input: string, init: RequestInit) => Promise<Response> {
    return async (input, init) => {
      const row = this.#rows.get(route.endpointId);
      if (row === undefined) throw new LaneFetchRefusal("route_unknown");
      const target = endpointRouteTarget(route.baseUrl, ENTRY_ROUTE_DENY_SUFFIXES);
      if (target === null || target.host !== row.host || target.pathPrefix !== row.pathPrefix) throw new LaneFetchRefusal("route_mismatch");
      const path = endpointRoutePath(input, row);
      if (path === null) throw new LaneFetchRefusal("route_path");
      await this.#ensureTable();
      const answer = await this.#deps.egress(`${ROUTE_ORIGIN}/route/${row.key}${path}`, init);
      // An egress that does not hold the row (it restarted, and lost its table with it) answers `route_unknown` before
      // any dial: the table is pushed again by the next attempt or fetch, not half an hour later.
      if (answer.status === 502 && refusalCode(await answer.clone().text(), 502) === "route_unknown") {
        this.#pushedUntil = 0;
        this.#deps.log({ level: "warn", event: "lane_route_unknown" });
      }
      return answer;
    };
  }

  /** Whether egress holds the table as it is now: its last change taken, its rows not past their `not_after`. */
  #tableHeld(now: number): boolean {
    return this.#pushedChanges >= this.#changes && now < this.#pushedUntil;
  }

  /**
   * An attempt's row must be in the table egress holds: when it may not be, the push out is waited for (within its
   * bound) or one is made now, in the attempt's own fetch. An egress that still does not hold it answers
   * `route_unknown` before any dial, which the attempt reads as a failure before the provider.
   */
  async #ensureTable(): Promise<void> {
    const now = this.#deps.clock();
    if (this.#tableHeld(now) || now < this.#refusedUntil) return;
    const running = this.#pushing;
    if (running === null || now >= running.until) {
      await this.#pushBackground();
      return;
    }
    let timer: ReturnType<typeof setTimeout> | null = null;
    await Promise.race([running.done, new Promise<void>((resolve) => (timer = setTimeout(resolve, running.until - now)))]);
    if (timer !== null) clearTimeout(timer);
    if (!this.#tableHeld(this.#deps.clock()) && this.#pushing === null) await this.#pushBackground();
  }

  /** The table's rows as egress takes them, each valid an hour from `nowMs` at most. */
  rows(nowMs: number): EndpointRouteRow[] {
    const nowSeconds = Math.floor(nowMs / 1000);
    const notAfter = nowSeconds + ROUTE_ROW_MAX_TTL_SECONDS;
    return [...this.#rows.values()]
      .map((row) => ({ route: row.key, host: row.host, path_prefix: row.pathPrefix, not_after: notAfter }))
      .filter((row) => validRouteRow(row, nowSeconds, ENTRY_ROUTE_DENY_SUFFIXES));
  }

  /**
   * Whether `maintain` pushes now: a change egress has not taken, or half the table's lifetime is gone (or egress lost
   * it, `route_unknown`), unless egress just refused one. A push out within its bound is left alone (it may yet be
   * answered). An entry whose view has no endpoint route and never had one pushes nothing.
   */
  #pushDue(now: number): boolean {
    if (now < this.#refusedUntil) return false;
    if (this.#pushing !== null && now < this.#pushing.until) return false;
    if (this.#pushedChanges < this.#changes) return true;
    if (this.#rows.size === 0) return false;
    return now >= this.#pushedUntil - ROW_TTL_MS / 2;
  }

  /**
   * The table pushed in the background of the calling fetch: one push at a time, and again at once when a change came in
   * while one was out. A push past its bound by the caller's clock is let go (`lane_routes_push_lapsed`); should it be
   * answered after all, its number is below the new push's and egress refuses it (409 `routes_stale`). Resolves whether
   * egress took the last one.
   */
  #pushBackground(): Promise<boolean> {
    const now = this.#deps.clock();
    const running = this.#pushing;
    if (running !== null && now < running.until) return running.done;
    if (running !== null) this.#deps.log({ level: "warn", event: "lane_routes_push_lapsed", held_ms: now - (running.until - this.#callMs) });
    const push: Running<boolean> = { done: Promise.resolve(false), until: now + this.#callMs };
    this.#pushing = push;
    push.done = (async () => {
      let taken = false;
      do {
        push.until = this.#deps.clock() + this.#callMs;
        taken = await this.#pushTable();
      } while (taken && this.#pushedChanges < this.#changes && this.#pushing === push);
      return taken;
    })().finally(() => {
      if (this.#pushing === push) this.#pushing = null;
    });
    return push.done;
  }

  /** `PUT /v1/routes`: the whole table under the epoch and the next push number, bounded by the call bound. Never throws. */
  async #pushTable(): Promise<boolean> {
    this.#push += 1;
    const covers = this.#changes;
    const now = this.#deps.clock();
    const rows = this.rows(now);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort("routes_push_timeout"), this.#callMs);
    try {
      const answer = await this.#deps.egress(ROUTES_CONTROL_URL, {
        method: "PUT",
        headers: { "content-type": "application/json", "x-gray-route-version": String(this.#epoch), "x-gray-route-push": String(this.#push) },
        body: JSON.stringify(rows),
        signal: controller.signal,
      });
      const body = await answer.text();
      if (answer.status === 204) {
        this.#pushedChanges = Math.max(this.#pushedChanges, covers);
        this.#pushedUntil = Math.floor(now / 1000) * 1000 + ROW_TTL_MS;
        if (rows.length > 0 || covers > 0) this.#deps.log({ level: "info", event: "lane_routes_pushed", rows: rows.length });
        return true;
      }
      const code = refusalCode(body, answer.status);
      // A later push of this registry reached egress first: its table, read after this one's, is the one that holds.
      if (answer.status === 409 && code === "routes_stale") return false;
      this.#refusedUntil = this.#deps.clock() + REFUSED_BACKOFF_MS;
      this.#deps.log({ level: "error", event: "lane_routes_refused", status: answer.status, code, rows: rows.length });
      return false;
    } catch {
      this.#deps.log({ level: "error", event: "lane_routes_push_failed" });
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Whether `row`'s key is to be fetched in the background now: not in memory, not being fetched, not resting. */
  #keyDue(row: EndpointRow, now: number): boolean {
    if (this.#keys.get(row.endpointId)?.generation === row.generation) return false;
    const fetchKey = keyOf(row.endpointId, row.generation);
    const running = this.#fetching.get(fetchKey);
    if (running !== undefined && now < running.until) return false;
    return now >= (this.#keyBackoff.get(fetchKey) ?? 0);
  }

  /** The keys of `rows`, PREFETCH_CONCURRENCY at a time, each within the call bound. */
  async #prefetch(rows: readonly EndpointRow[]): Promise<void> {
    const queue = [...rows];
    const worker = async (): Promise<void> => {
      for (let row = queue.shift(); row !== undefined; row = queue.shift()) {
        if (this.#keyDue(row, this.#deps.clock())) await this.#fetchKey(row, this.#callMs);
      }
    };
    await Promise.all(Array.from({ length: Math.min(PREFETCH_CONCURRENCY, queue.length) }, worker));
  }

  /**
   * One `endpoint.credential` call for `row`'s key, or the one already out within its bound. The key is kept while the
   * table still names that endpoint at that generation; a refusal or a failure rests the fetch (REFUSED_BACKOFF_MS for
   * the console's 403, FAILED_BACKOFF_MS otherwise). Resolves to the key or null; never throws.
   */
  #fetchKey(row: EndpointRow, timeoutMs: number): Promise<string | null> {
    const fetchKey = keyOf(row.endpointId, row.generation);
    const now = this.#deps.clock();
    const running = this.#fetching.get(fetchKey);
    if (running !== undefined && now < running.until) return running.done;
    const fetching: Running<string | null> = { done: Promise.resolve(null), until: now + timeoutMs };
    this.#fetching.set(fetchKey, fetching);
    fetching.done = (async () => {
      try {
        const bytes = await this.#deps.credential(row.endpointId, row.generation, timeoutMs);
        // The key's exact bytes, a leading BOM included: the provider compares them as the console stored them.
        const key = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
        // Kept only while the table still names the endpoint at this generation.
        if (this.#rows.get(row.endpointId)?.generation === row.generation) this.#keys.set(row.endpointId, { generation: row.generation, key });
        this.#keyBackoff.delete(fetchKey);
        return key;
      } catch (thrown) {
        // The status and the error's name, never the key or the endpoint's answer.
        const status = thrown instanceof BridgeCallError ? thrown.status : null;
        this.#keyBackoff.set(fetchKey, this.#deps.clock() + (status === 403 ? REFUSED_BACKOFF_MS : FAILED_BACKOFF_MS));
        this.#deps.log({ level: "warn", event: "lane_endpoint_credential_failed", endpoint: row.endpointId, generation: row.generation, status, code: thrown instanceof Error ? thrown.name : "error" });
        return null;
      } finally {
        if (this.#fetching.get(fetchKey) === fetching) this.#fetching.delete(fetchKey);
      }
    })();
    return fetching.done;
  }
}

function keyOf(endpointId: string, generation: number): string {
  return `${endpointId}\u0000${generation}`;
}

/** The closed code of an egress refusal body (`{error}`), or the status's when it has none. */
function refusalCode(body: string, status: number): string {
  try {
    const value = parseSerde(body) as { readonly error?: unknown };
    if (typeof value.error === "string" && /^[a-z_]{1,64}$/.test(value.error)) return value.error;
  } catch {
    // Not a closed body.
  }
  return `status_${status}`;
}
