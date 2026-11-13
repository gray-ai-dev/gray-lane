import type { GatewayConfig } from "@gray/config";
import { ApiError, shapeOf } from "@gray/errors";
import { newRequestId } from "@gray/ledger-keys";
import { within } from "@gray/snapshot";
import { geminiModelValue, listedIn, openaiModelValue, reachable, suggest, type CatalogJson } from "./catalog.ts";
import type { GatewayEnv } from "./env.ts";
import { originsOf } from "./hosts.ts";
import { checkStaleKey, lookUpKey, type KeyLookup } from "./key-lookup.ts";
import { Outbound } from "./outbound.ts";
import type { GatewaySnapshot, SnapshotCache, SnapshotSource } from "./snapshot.ts";
import { translationPolicy } from "./translate.ts";

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
  /** The main gateway's bindings, for `/v1/key`'s console call; null on the lane, which serves only the OpenAI listings. */
  readonly env: GatewayEnv | null;
  readonly cfg: GatewayConfig;
  readonly snapshots: SnapshotCache;
  readonly source: SnapshotSource;
  readonly background: (p: Promise<unknown>) => void;
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
        return listing(route, looked.snapshot, looked.key?.models ?? null, d.cfg, requestId, head);
      }
      case "gemini_models":
      case "gemini_model": {
        if (queryCredentials(url)) throw new ApiError(400, "query_credentials_unsupported");
        const looked = await lookUpKey(request.headers, lookup, true);
        return geminiListing(route, looked.snapshot, looked.key?.models ?? null, d.cfg, requestId, head);
      }
      case "key": {
        // The lane serves no key status (its entry routes only the OpenAI listings here).
        if (d.env === null) throw new ApiError(404, "unsupported_protocol");
        const env = d.env;
        const looked = await lookUpKey(request.headers, lookup, false);
        await checkStaleKey(looked, env, lookup, "key_status_key_check_failed");
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
      console.error(JSON.stringify({ level: "error", event: "catalog_route_failed", path, message: error instanceof Error ? error.message : String(error) }));
    }
    const rendered = refusal.render({ shape: shapeOf(path), origins: originsOf(d.cfg, url), requestId });
    return new Response(head ? null : rendered.body, { status: rendered.status, headers: rendered.headers });
  }
}

function json(body: string, requestId: string, head: boolean): Response {
  return new Response(head ? null : body, { status: 200, headers: { "content-type": "application/json", "x-request-id": requestId } });
}

function value(v: CatalogJson, requestId: string, head: boolean): Response {
  return json(JSON.stringify(v), requestId, head);
}

/** `list` and `model`: the OpenAI listing, every API (`listed(rt, auth, None)`). */
function listing(route: Extract<CatalogRoute, { kind: "models" | "model" }>, snapshot: GatewaySnapshot | null, scope: readonly string[] | null, cfg: GatewayConfig, requestId: string, head: boolean): Response {
  const nowMs = Date.now();
  if (snapshot === null) {
    if (route.kind === "models") return value({ data: [], object: "list" }, requestId, head);
    throw notListed(route.id, []);
  }
  const policy = translationPolicy(snapshot);
  const models = listedIn(snapshot, policy, scope, null, nowMs, cfg.platformFeeBps);
  const facts = snapshot.facts ?? {};
  // A model id is client text (`constructor` is a valid one): only the record's own entries count.
  const objectOf = (id: string) => openaiModelValue(id, models.get(id)!, Object.hasOwn(facts, id) ? facts[id]! : {}, reachable(snapshot, policy, id, models.get(id)!.protocols, nowMs));
  if (route.kind === "models") return value({ data: [...models.keys()].map(objectOf), object: "list" }, requestId, head);
  if (models.has(route.id)) return value(objectOf(route.id), requestId, head);
  throw notListed(route.id, suggest(route.id, models.keys()));
}

/** `model`'s 404: the model is not listed for this key, with the most similar listed ones. */
function notListed(id: string, suggestions: readonly string[]): ApiError {
  let message = `The model \`${id}\` is not listed on Gray.`;
  if (suggestions.length > 0) message += ` Similar models: ${suggestions.join(", ")}.`;
  return new ApiError(404, "model_not_found").withMessage(message).withMeta("suggestions", [...suggestions]);
}

/** `gemini_list` and `gemini_model`: the models a Gemini client can call (`listed(rt, auth, Some(Gemini))`). */
function geminiListing(route: Extract<CatalogRoute, { kind: "gemini_models" | "gemini_model" }>, snapshot: GatewaySnapshot | null, scope: readonly string[] | null, cfg: GatewayConfig, requestId: string, head: boolean): Response {
  const models = snapshot === null ? new Map() : listedIn(snapshot, translationPolicy(snapshot), scope, "gemini", Date.now(), cfg.platformFeeBps);
  if (route.kind === "gemini_models") return value({ models: [...models].map(([id, listed]) => geminiModelValue(id, listed.native)) }, requestId, head);
  const found = models.get(route.id);
  if (found !== undefined) return value(geminiModelValue(route.id, found.native), requestId, head);
  throw new ApiError(404, "model_not_found").withMessage(`The model \`${route.id}\` is not served to Gemini clients on Gray.`);
}
