import type { GatewayConfig } from "@gray/config";
import { ApiError, shapeOf } from "@gray/errors";
import { compareUtf8 } from "@gray/json";
import { newRequestId } from "@gray/ledger-keys";
import { within } from "@gray/snapshot";
import { geminiModelValue, listedIn, openaiModelValue, reachable, suggest, type CatalogJson } from "./catalog.ts";
import type { GatewayEnv } from "./env.ts";
import { originsOf } from "./hosts.ts";
import { checkStaleKey, lookUpKey, type KeyLookup, type KeyRevocationCheck } from "./key-lookup.ts";
import { Outbound } from "./outbound.ts";
import type { GatewaySnapshot, SnapshotCache, SnapshotSource } from "./snapshot.ts";
import { viaEntryOf } from "./entry-forward.ts";
import { translationRules, type TranslationRules } from "./translate.ts";

/**
 * The model API's read-only routes beside the generation APIs (crates/gray-gateway/src/inference.rs
 * `router`, model_catalog.rs):
 *
 * - `GET /v1/models` (and its alias `GET /models`), `GET /v1/models/{id}`: the OpenAI model list with
 *   OpenRouter's model fields. Public without a key; with one, exactly the models the key may call.
 * - `GET /v1beta/models`, `GET /v1beta/models/{model}`: the Gemini list of the models a Gemini client can
 *   call. A key in the query string is refused, as on generation.
 * - `GET /v1/key`: what the presented key is and may still spend.
 *
 * The listings are worked out from the key and route snapshot the isolate holds (catalog.ts): nothing
 * else is asked. `GET /v1/key` reads the key's use and its workspace's balance, which no snapshot holds,
 * from gray-console's PublicSetup entrypoint (`keyStatus`), as the server reads them from its database
 * and the credit account. Every answer carries the request's id in `x-request-id`, and an error has it in
 * its body too, in the shape of the path's API (`public_errors::finish`); a `HEAD` is answered as the
 * `GET`, without a body (axum's `get`).
 */

export type CatalogRoute =
  | { readonly kind: "models" }
  | { readonly kind: "model"; readonly id: string }
  | { readonly kind: "gemini_models" }
  | { readonly kind: "gemini_model"; readonly id: string }
  | { readonly kind: "key" };

/** A path segment as axum's `Path` gives it: percent-decoded (the text as sent when it does not decode). */
function decoded(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** The read-only route `method` and `path` name (the client's base URL already taken off), or null. */
export function catalogRoute(method: string, path: string): CatalogRoute | null {
  if (method !== "GET" && method !== "HEAD") return null;
  if (path === "/v1/models" || path === "/models") return { kind: "models" };
  if (path === "/v1beta/models") return { kind: "gemini_models" };
  if (path === "/v1/key") return { kind: "key" };
  // `{*id}`: the rest of the path, slashes included; an empty rest matches no route.
  if (path.startsWith("/v1/models/") && path.length > "/v1/models/".length) return { kind: "model", id: decoded(path.slice("/v1/models/".length)) };
  if (path.startsWith("/v1beta/models/") && path.length > "/v1beta/models/".length) return { kind: "gemini_model", id: decoded(path.slice("/v1beta/models/".length)) };
  return null;
}

/** gray-console's PublicSetup `keyStatus` (workers/console/src/setup/key-status.ts). */
export interface KeyStatusRpc {
  keyStatus(input: KeyStatusInput): Promise<KeyStatusAnswer>;
}

/** The key as the snapshot holds it: its record and its spend limit (`key_limit` reads the auth record). */
export interface KeyStatusInput {
  readonly keyId: string;
  readonly workspaceId: string;
  readonly limitMicrousd: number | null;
  readonly limitPeriod: string | null;
}

/** The status's JSON text (`{"data": ...}`), or why it could not be read. */
export type KeyStatusAnswer = { readonly ok: true; readonly body: string } | { readonly ok: false; readonly reason: string };

export interface CatalogDeps {
  /** Whether this entry serves `GET /v1/key` (true on the main gateway, false on the confidential entry). */
  readonly serveKeyStatus: boolean;
  /** The main gateway's bindings, for `/v1/key`'s console call; null on the lane, which serves only the listings. */
  readonly env: GatewayEnv | null;
  /** Real-time revocation check when the snapshot is stale (`checkStaleKey`). */
  readonly keyRevoked: KeyRevocationCheck;
  readonly cfg: GatewayConfig;
  readonly snapshots: SnapshotCache;
  readonly source: SnapshotSource;
  readonly background: (p: Promise<unknown>) => void;
  /**
   * The confidential entry's own listings (lane mode): the APIs it translates a model onto by its own rule
   * (translate.ts `entryRules`). Absent: the main gateway's, by the operator's policy.
   */
  readonly lane?: boolean;
}

/** `key_status`'s refusal when the key's record, use or balance cannot be read. */
function statusUnavailable(): ApiError {
  return new ApiError(503, "billing_admission_unavailable").withMessage("Gray could not read this key's usage right now. Retry in a moment.").withRetryAfter(5n);
}

/** `query_credentials`: a Gemini client's `?key=` is refused here as on generation, rather than ignored. */
function queryCredentials(url: URL): boolean {
  return url.search.length > 1 && url.search.slice(1).split("&").some((p) => p.startsWith("key="));
}

/** Serves `route` (`path` is the request's, its client's base URL taken off) as the request `requestId` (its record's, public-record.ts). */
export async function serveCatalog(request: Request, route: CatalogRoute, path: string, d: CatalogDeps, requestId: string = newRequestId(Date.now())): Promise<Response> {
  const url = new URL(request.url);
  const head = request.method === "HEAD";
  const lookup: KeyLookup = { cfg: d.cfg, snapshots: d.snapshots, source: d.source, background: d.background, outbound: new Outbound() };
  try {
    switch (route.kind) {
      case "models":
      case "model": {
        const looked = await lookUpKey(request.headers, lookup, true);
        await checkStaleKey(looked, d.keyRevoked, lookup, "catalog_key_check_failed");
        return listing(route, looked.snapshot, looked.key?.models ?? null, d.cfg, requestId, head, rulesFor(d, request), url);
      }
      case "gemini_models":
      case "gemini_model": {
        if (queryCredentials(url)) throw new ApiError(400, "query_credentials_unsupported");
        const looked = await lookUpKey(request.headers, lookup, true);
        await checkStaleKey(looked, d.keyRevoked, lookup, "catalog_key_check_failed");
        return geminiListing(route, looked.snapshot, looked.key?.models ?? null, d.cfg, requestId, head, rulesFor(d, request));
      }
      case "key": {
        // The lane serves no key status (its entry routes only the listings here).
        if (!d.serveKeyStatus || d.env === null) throw new ApiError(404, "unsupported_protocol");
        const env = d.env;
        const looked = await lookUpKey(request.headers, lookup, false);
        await checkStaleKey(looked, d.keyRevoked, lookup, "key_status_key_check_failed");
        const key = looked.key!;
        let answer: KeyStatusAnswer;
        try {
          const console_ = env.CONSOLE as unknown as KeyStatusRpc;
          answer = await lookup.outbound.run(() =>
            within(console_.keyStatus({ keyId: key.keyId, workspaceId: key.workspaceId, limitMicrousd: key.limitMicrousd, limitPeriod: key.limitPeriod }), d.cfg.internalCallTimeoutMs, "the key status"),
          );
        } catch (error) {
          answer = { ok: false, reason: error instanceof Error ? error.message : String(error) };
        }
        if (!answer.ok) {
          console.warn(JSON.stringify({ level: "warn", event: "key_status_unavailable", key: key.keyId, reason: answer.reason }));
          throw statusUnavailable();
        }
        return json(answer.body, requestId, head);
      }
    }
  } catch (error) {
    const refusal = error instanceof ApiError ? error : new ApiError(500, "internal_error");
    if (!(error instanceof ApiError)) {
      // The confidential entry's container log is readable outside the VM (deploy/tee/IMPLEMENTATION_NOTES.md §9,
      // "public_logs"): there the line has the error's class, never the client's path or the error's message.
      const line = d.lane === true
        ? { level: "error", event: "catalog_route_failed", code: error instanceof Error ? error.name : "error" }
        : { level: "error", event: "catalog_route_failed", path, message: error instanceof Error ? error.message : String(error) };
      console.error(JSON.stringify(line));
    }
    const rendered = refusal.render({ shape: shapeOf(path), origins: originsOf(d.cfg, url), requestId });
    return new Response(head ? null : rendered.body, { status: rendered.status, headers: rendered.headers });
  }
}

function json(body: string, requestId: string, head: boolean, anthropicId = false): Response {
  const headers: Record<string, string> = { "content-type": "application/json", "x-request-id": requestId };
  if (anthropicId) headers["request-id"] = requestId;
  return new Response(head ? null : body, { status: 200, headers });
}

function value(v: CatalogJson, requestId: string, head: boolean, anthropicId = false): Response {
  return json(JSON.stringify(v), requestId, head, anthropicId);
}

/** Anthropic `/v1/models` cursor pagination query parameters (`?limit`, `?before_id`, `?after_id`). */
interface ModelPagination {
  readonly limit: number | null;
  readonly beforeId: string | null;
  readonly afterId: string | null;
}

const MAX_MODEL_PAGE_LIMIT = 1000;

function parseModelPagination(url: URL): ModelPagination {
  let limit: number | null = null;
  let beforeId: string | null = null;
  let afterId: string | null = null;
  for (const [key, raw] of url.searchParams) {
    if (key === "limit") {
      if (!/^[0-9]+$/.test(raw)) {
        throw new ApiError(400, "invalid_limit").withMessage("`limit` must be an integer from 1 to 1000.").withParam("limit");
      }
      const n = Number(raw);
      if (!Number.isSafeInteger(n) || n < 1 || n > MAX_MODEL_PAGE_LIMIT) {
        throw new ApiError(400, "invalid_limit").withMessage("`limit` must be an integer from 1 to 1000.").withParam("limit");
      }
      limit = n;
    } else if (key === "before_id") {
      if (raw === "") throw new ApiError(400, "invalid_request_field").withMessage("`before_id` must be a non-empty string.").withParam("before_id");
      beforeId = raw;
    } else if (key === "after_id") {
      if (raw === "") throw new ApiError(400, "invalid_request_field").withMessage("`after_id` must be a non-empty string.").withParam("after_id");
      afterId = raw;
    }
  }
  if (beforeId !== null && afterId !== null) {
    throw new ApiError(400, "invalid_request_field").withMessage("`before_id` and `after_id` cannot both be specified.");
  }
  return { limit, beforeId, afterId };
}

/**
 * Slices UTF-8 byte-ordered `ids` according to Anthropic's `/v1/models` cursor pagination. When none of `limit`,
 * `before_id` or `after_id` are set, returns the full list (`hasMore: false`) so OpenAI/OpenRouter clients still
 * receive the entire catalog.
 */
export function paginateModelIds(ids: readonly string[], page: ModelPagination): { readonly ids: readonly string[]; readonly hasMore: boolean } {
  let filtered: readonly string[];
  if (page.afterId !== null) {
    const after = page.afterId;
    filtered = ids.filter((id) => compareUtf8(id, after) > 0);
  } else if (page.beforeId !== null) {
    const before = page.beforeId;
    filtered = ids.filter((id) => compareUtf8(id, before) < 0);
  } else {
    filtered = ids;
  }
  if (page.limit === null) return { ids: filtered, hasMore: false };
  const hasMore = filtered.length > page.limit;
  if (page.beforeId !== null) {
    const start = Math.max(0, filtered.length - page.limit);
    return { ids: filtered.slice(start), hasMore };
  }
  return { ids: filtered.slice(0, page.limit), hasMore };
}

/**
 * The translation rules a listing reads (translate.ts `translationRules`): the entry's own at the entry; none for the
 * entry's own copy of this gateway's list (a request it marked), so the entry is told only the APIs this gateway serves
 * natively and never forwards a request this gateway would translate; else the operator's policy.
 */
function rulesFor(d: CatalogDeps, request: Request): (snapshot: GatewaySnapshot) => TranslationRules {
  const lane = d.lane === true;
  const viaEntry = !lane && viaEntryOf(request.headers) !== null;
  return (snapshot) => translationRules(snapshot, lane, viaEntry);
}

/** `list` and `model`: the OpenAI listing, every API (`listed(rt, auth, None)`). */
function listing(
  route: Extract<CatalogRoute, { kind: "models" | "model" }>,
  snapshot: GatewaySnapshot | null,
  scope: readonly string[] | null,
  cfg: GatewayConfig,
  requestId: string,
  head: boolean,
  rules: (snapshot: GatewaySnapshot) => TranslationRules,
  url: URL,
): Response {
  const pagination = route.kind === "models" ? parseModelPagination(url) : null;
  const nowMs = Date.now();
  if (snapshot === null) {
    if (route.kind === "models") return value({ data: [], first_id: null, has_more: false, last_id: null, object: "list" }, requestId, head, true);
    throw notListed(route.id, []);
  }
  const policy = rules(snapshot);
  const models = listedIn(snapshot, policy, scope, null, nowMs, cfg.platformFeeBps);
  const facts = snapshot.facts ?? {};
  // A model id is client text (`constructor` is a valid one): only the record's own entries count.
  const objectOf = (id: string) => openaiModelValue(id, models.get(id)!, Object.hasOwn(facts, id) ? facts[id]! : {}, reachable(policy, id, models.get(id)!.protocols));
  if (route.kind === "models") {
    const page = paginateModelIds([...models.keys()], pagination!);
    const firstId = page.ids[0] ?? null;
    const lastId = page.ids.at(-1) ?? null;
    return value({ data: page.ids.map(objectOf), first_id: firstId, has_more: page.hasMore, last_id: lastId, object: "list" }, requestId, head, true);
  }
  if (models.has(route.id)) return value(objectOf(route.id), requestId, head, true);
  throw notListed(route.id, suggest(route.id, models.keys()));
}

/** `model`'s 404: the model is not listed for this key, with the most similar listed ones. */
function notListed(id: string, suggestions: readonly string[]): ApiError {
  let message = `The model \`${id}\` is not listed on Gray.`;
  if (suggestions.length > 0) message += ` Similar models: ${suggestions.join(", ")}.`;
  return new ApiError(404, "model_not_found").withMessage(message).withMeta("suggestions", [...suggestions]);
}

/** `gemini_list` and `gemini_model`: the models a Gemini client can call (`listed(rt, auth, Some(Gemini))`). */
function geminiListing(route: Extract<CatalogRoute, { kind: "gemini_models" | "gemini_model" }>, snapshot: GatewaySnapshot | null, scope: readonly string[] | null, cfg: GatewayConfig, requestId: string, head: boolean, rules: (snapshot: GatewaySnapshot) => TranslationRules): Response {
  const models = snapshot === null ? new Map() : listedIn(snapshot, rules(snapshot), scope, "gemini", Date.now(), cfg.platformFeeBps);
  if (route.kind === "gemini_models") return value({ models: [...models].map(([id, listed]) => geminiModelValue(id, listed.native)) }, requestId, head);
  const found = models.get(route.id);
  if (found !== undefined) return value(geminiModelValue(route.id, found.native), requestId, head);
  throw new ApiError(404, "model_not_found").withMessage(`The model \`${route.id}\` is not served to Gemini clients on Gray.`);
}
