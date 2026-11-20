import type { GatewayConfig } from "@gray/config";
import { ApiError, shapeOf } from "@gray/errors";
import { parsePlain } from "@gray/json";
import { newRequestId } from "@gray/ledger-keys";
import { API_FORWARD_HEADER, ENTRY_FORWARD_HEADER, signForwardMark, VIA_ENTRY_HEADER, type BridgeSigner } from "@gray/lane-wire";
import { originsOf } from "../hosts.ts";
import type { CatalogRoute } from "../listings.ts";
import type { LaneApiForward } from "./types.ts";

/**
 * docs/design/one-address.md: the entry serves every path at one address. The chat APIs, the model listings and its own
 * `/v1/aci/*` routes it answers itself; every other public path it forwards to the API Worker of its measured compose
 * (`API_ORIGIN`, app-compose.mjs `--api-origin`), through the `API` service the entrypoint renders for it (an HTTPS
 * connection verified against the browser roots for the API's host, as the bridge's is). The origin is never taken from
 * the request.
 *
 * A forwarded request carries the client's method, path and query, body (streamed) and headers, less hop-by-hop,
 * proxy and address headers, cookies and Gray's internal headers, plus the entry's mark (`x-gray-entry-forward`, signed
 * by its bridge key, @gray/lane-wire forward-mark.ts), which the API Worker checks before it takes the request as the
 * entry's. Its answer comes back as the API sent it (status, headers but the hop-by-hop ones and the API's own CORS
 * headers, the body as it streams), with `x-gray-served-by` naming the API origin and no receipt: the entry reads,
 * stores and signs nothing of it.
 *
 * `/v1/models` and `/v1beta/models` are the entry's own lists merged with the API's (`mergedListing`).
 *
 * A generation request the entry has no route for, on its API, that the API serves there (a Gemini image model, a model
 * the API serves only through translation) is forwarded too, from InferenceRun's lane path once the request's
 * preference is layered (`LaneApiForward`, InferenceRun `forwardToApi`): the API records it, the entry neither records
 * it nor signs a receipt.
 */

/** The answer header naming the origin that served a forwarded path. */
export const SERVED_BY_HEADER = "x-gray-served-by";
/** On a model listing the API's half of which could not be read: `api`. */
export const MODELS_PARTIAL_HEADER = "x-gray-models-partial";

/** How long the entry waits for the API's model list before it answers its own (`x-gray-models-partial: api`). */
export const MODELS_API_TIMEOUT_MS = 10_000;
/** The most of the API's model list the entry reads to merge; a longer one is answered as unread. */
export const MODELS_API_MAX_BYTES = 8 * 1024 * 1024;

/** The API Worker the entry forwards to. */
export interface ApiForward {
  /** `API_ORIGIN`: an https origin, `scheme://host[:port]`. */
  readonly origin: string;
  /** The `API` service binding. */
  readonly fetch: (request: Request) => Promise<Response>;
  /** The binding itself: what the isolate keeps per API (`ApiModelsView`). */
  readonly binding: object;
}

/** What `apiForwardOf` read: the forward, or null with no problem when unset, or the problem with the setting. */
export type ApiForwardRead = { readonly forward: ApiForward | null; readonly problem: string | null };

/**
 * The entry's forward from its bindings: null when `API_ORIGIN` is unset or empty (the entry then answers its 404 for
 * the paths it does not serve, as before). Set, it must be an https origin written as one, outside the relay-stack
 * layout, with a usable `API` binding; otherwise the problem, which the entry treats as a misconfiguration.
 */
export function apiForwardOf(env: { readonly API?: unknown; readonly API_ORIGIN?: unknown }, stackLayout: boolean): ApiForwardRead {
  const origin = env.API_ORIGIN;
  if (origin === undefined || origin === "") return { forward: null, problem: null };
  if (typeof origin !== "string" || !isHttpsOrigin(origin)) return { forward: null, problem: "API_ORIGIN" };
  if (stackLayout) return { forward: null, problem: "API_ORIGIN" };
  const binding = env.API;
  if (typeof binding !== "object" || binding === null || typeof (binding as { fetch?: unknown }).fetch !== "function") return { forward: null, problem: "API" };
  const fetcher = binding as { fetch(request: Request): Promise<Response> };
  return { forward: { origin, fetch: (request) => fetcher.fetch(request), binding: fetcher }, problem: null };
}

function isHttpsOrigin(text: string): boolean {
  try {
    const url = new URL(text);
    return url.protocol === "https:" && url.origin === text;
  } catch {
    return false;
  }
}

/**
 * Whether the entry keeps `path` itself even when it does not serve it: its own namespaces (`/v1/aci/*`, the peer hop's
 * `/v1/peer/*`), which no other service answers. Everything else public the entry does not serve is forwarded.
 */
export function entryOwnPath(path: string): boolean {
  return path === "/v1/aci" || path.startsWith("/v1/aci/") || path === "/v1/peer" || path.startsWith("/v1/peer/");
}

/** Hop-by-hop headers (RFC 9110 section 7.6.1), and `host`, which the forwarded request's URL sets. */
const HOP_BY_HOP: ReadonlySet<string> = new Set(["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host"]);
/** What a client or a proxy in front of the entry states about the connection, credentials no API reads, Gray's own marks. */
const REQUEST_DROPPED: ReadonlySet<string> = new Set(["forwarded", "via", "x-real-ip", "proxy-authorization", "cookie", ENTRY_FORWARD_HEADER, API_FORWARD_HEADER, VIA_ENTRY_HEADER]);
const REQUEST_DROPPED_PREFIXES: readonly string[] = ["x-forwarded-", "cf-"];

/** The names a `connection` header lists, which are hop-by-hop for this one message (RFC 9110 section 7.6.1). */
function connectionNamed(headers: Headers): ReadonlySet<string> {
  const value = headers.get("connection");
  if (value === null) return new Set();
  return new Set(value.split(",").map((name) => name.trim().toLowerCase()).filter((name) => name !== ""));
}

/** The client's headers as the API gets them. */
export function forwardedRequestHeaders(headers: Headers): Headers {
  const named = connectionNamed(headers);
  const out = new Headers();
  for (const [name, value] of headers) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || named.has(lower) || REQUEST_DROPPED.has(lower) || REQUEST_DROPPED_PREFIXES.some((prefix) => lower.startsWith(prefix))) continue;
    out.append(name, value);
  }
  return out;
}

/**
 * The API's headers as the client gets them: not the hop-by-hop ones, no cookie (Gray's API sets none), and not the API's
 * CORS headers: the entry decides CORS for its own origin (`withCors`, CONSOLE_ORIGIN, the same console the API allows),
 * so a page reads a forwarded answer exactly when it may read any of the entry's. `vary: Origin` is the entry's to add.
 */
export function forwardedAnswerHeaders(headers: Headers): Headers {
  const named = connectionNamed(headers);
  const out = new Headers();
  for (const [name, value] of headers) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || named.has(lower) || lower === "set-cookie" || lower.startsWith("access-control-")) continue;
    if (lower === "vary") {
      const kept = value.split(",").map((token) => token.trim()).filter((token) => token !== "" && token.toLowerCase() !== "origin");
      if (kept.length > 0) out.append(name, kept.join(", "));
      continue;
    }
    out.append(name, value);
  }
  return out;
}

/** What a forward needs of the boot: its bridge key and the clock. */
export interface ForwardSigner {
  readonly keyId: string;
  readonly signer: BridgeSigner;
  readonly now: () => number;
}

/** What the 502 of an unreachable API names (the path's error shape, the help links' origins). */
export interface ForwardContext {
  readonly cfg: GatewayConfig;
  readonly url: URL;
  readonly path: string;
}

/**
 * `request` (arrived at `url`) forwarded to the API: its method, path and query as sent (a declared
 * `/v1/client/<client>/` base URL included), its body as a stream, its headers (`forwardedRequestHeaders`) and the
 * entry's mark. The answer as the API sent it (`forwardedAnswerHeaders`), with `x-gray-served-by`; a 502
 * `api_unreachable` in the path's error shape when no answer came.
 */
export async function forwardToApi(request: Request, url: URL, forward: ApiForward, sign: ForwardSigner, context: ForwardContext): Promise<Response> {
  return (await sendToApi(request, url, forward, sign)) ?? unreachable(context);
}

/** `forwardToApi`'s exchange: the API's answer as the client gets it, or null when no answer came (logged). */
export async function sendToApi(request: Request, url: URL, forward: ApiForward, sign: ForwardSigner): Promise<Response | null> {
  // Concatenated, never resolved against the origin: a path that starts with `//` stays a path on the API's host.
  const target = new URL(`${forward.origin}${url.pathname}${url.search}`);
  const headers = forwardedRequestHeaders(request.headers);
  headers.set(ENTRY_FORWARD_HEADER, await signForwardMark("entry", { keyId: sign.keyId, signer: sign.signer, nowMs: sign.now(), target: { method: request.method, host: target.host, pathAndQuery: `${target.pathname}${target.search}` } }));
  const bodied = request.method !== "GET" && request.method !== "HEAD" && request.body !== null;
  const init: RequestInit & { duplex?: "half" } = {
    method: request.method,
    headers,
    redirect: "manual",
    signal: request.signal,
    ...(bodied ? { body: request.body, duplex: "half" } : {}),
  };
  let answer: Response;
  try {
    answer = await forward.fetch(new Request(target, init));
  } catch (thrown) {
    console.error(JSON.stringify({ level: "error", event: "lane_api_forward_failed", method: request.method, path: url.pathname, message: thrown instanceof Error ? thrown.message : String(thrown) }));
    return null;
  }
  if (answer.status < 200 || answer.status > 599) {
    await answer.body?.cancel().catch(() => undefined);
    console.error(JSON.stringify({ level: "error", event: "lane_api_forward_failed", method: request.method, path: url.pathname, message: `status ${answer.status}` }));
    return null;
  }
  const out = forwardedAnswerHeaders(answer.headers);
  out.set(SERVED_BY_HEADER, forward.origin);
  return new Response(answer.body, { status: answer.status, statusText: answer.statusText, headers: out });
}

/** The 502 a forward that got no answer is told, in the path's error shape. */
export function apiUnreachable(): ApiError {
  return new ApiError(502, "api_unreachable").withMessage("Gray's confidential VM could not reach Gray's API, which serves this path. Retry in a moment.").withHelp(null);
}

function unreachable(context: ForwardContext): Response {
  const rendered = apiUnreachable()
    .render({ shape: shapeOf(context.path), origins: originsOf(context.cfg, context.url), requestId: newRequestId(Date.now()) });
  return new Response(rendered.body, { status: rendered.status, headers: rendered.headers });
}

type Item = Record<string, unknown>;

/** An endpoint's API (`protocol`), what one model lists once; another value as its text. */
function endpointKey(endpoint: unknown): string {
  return isItem(endpoint) && typeof endpoint.protocol === "string" ? endpoint.protocol : JSON.stringify(endpoint);
}

/** `own` (the entry's item) with `api`'s endpoints on the APIs it does not list itself, after its own. */
function withApiEndpoints(own: Item, api: Item | null): Item {
  if (api === null || !Array.isArray(api.endpoints)) return own;
  const mine = Array.isArray(own.endpoints) ? (own.endpoints as unknown[]) : [];
  const seen = new Set(mine.map(endpointKey));
  const added = (api.endpoints as unknown[]).filter((e) => {
    const key = endpointKey(e);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return added.length === 0 ? own : { ...own, endpoints: [...mine, ...added] };
}

function isItem(value: unknown): value is Item {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The merge of the entry's list and the API's (docs/design/one-address.md "/v1/models"): the entry's items first, each
 * with the API item's endpoints it does not list itself; then the items only the API lists, as the API lists them. Every
 * endpoint listed is one a client reaches at the entry: the entry serves its own routes, and forwards a request for a
 * model it has no route of on that API to the API (`LaneApiForward`).
 */
export function mergeModelLists(own: readonly Item[], api: readonly Item[], key: (item: Item) => unknown = (item) => item.id): Item[] {
  const byKey = new Map<string, Item>();
  for (const item of api) {
    const k = key(item);
    if (typeof k === "string" && !byKey.has(k)) byKey.set(k, item);
  }
  const ownKeys = new Set<string>();
  const merged: Item[] = [];
  for (const item of own) {
    const k = key(item);
    if (typeof k === "string") ownKeys.add(k);
    merged.push(withApiEndpoints(item, typeof k === "string" ? (byKey.get(k) ?? null) : null));
  }
  for (const item of api) {
    const k = key(item);
    if (typeof k !== "string" || ownKeys.has(k)) continue;
    ownKeys.add(k);
    merged.push(item);
  }
  return merged;
}

async function boundedJson(response: Response, max: number): Promise<unknown> {
  const reader = response.body?.getReader();
  if (reader === undefined) return undefined;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.byteLength;
  }
  try {
    // @gray/json reads the keys V8 may read wrong in an escaped form (packages/json, "Keys V8 reads wrong").
    return parsePlain(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return undefined;
  }
}

/** The API's answer to the same listing, read: 200 with its JSON, 404, or unread (no answer, another status, not JSON). */
type ApiListing = { readonly kind: "ok"; readonly value: unknown } | { readonly kind: "not_found" } | { readonly kind: "unread" };

async function apiListing(request: Request, url: URL, forward: ApiForward, sign: ForwardSigner, context: ForwardContext): Promise<ApiListing> {
  const signal = AbortSignal.timeout(MODELS_API_TIMEOUT_MS);
  const asked = new Request(request.url, { method: "GET", headers: request.headers, signal });
  try {
    const answer = await forwardToApi(asked, url, forward, sign, context);
    if (answer.headers.get(SERVED_BY_HEADER) === null) return { kind: "unread" };
    if (answer.status === 404) {
      await answer.body?.cancel().catch(() => undefined);
      return { kind: "not_found" };
    }
    if (answer.status !== 200) {
      await answer.body?.cancel().catch(() => undefined);
      return { kind: "unread" };
    }
    const value = await boundedJson(answer, MODELS_API_MAX_BYTES);
    return value === undefined ? { kind: "unread" } : { kind: "ok", value };
  } catch {
    return { kind: "unread" };
  }
}

function jsonAnswer(own: Response, value: unknown, head: boolean, extra: Record<string, string> = {}): Response {
  const headers = new Headers(own.headers);
  headers.delete("content-length");
  for (const [name, v] of Object.entries(extra)) headers.set(name, v);
  return new Response(head ? null : JSON.stringify(value), { status: 200, headers });
}

function withHeader(response: Response, name: string, value: string): Response {
  const headers = new Headers(response.headers);
  headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * `GET|HEAD /v1/models`, `/v1/models/{id}`, `/v1beta/models` and `/v1beta/models/{id}` at an entry that forwards
 * (docs/design/one-address.md "/v1/models"): `ownAnswer` is the entry's own listing, answered to the request as a GET.
 * The API's answer to the same path, asked with the client's credential headers (so a key's scope is the same on both),
 * is merged in:
 *
 * - a list: `mergeModelLists` (OpenAI's `data` by `id`, Gemini's `models` by `name`); the API's half unread, the entry's
 *   own list and `x-gray-models-partial: api`;
 * - one model the entry lists: its item (an OpenAI item with the API item's endpoints);
 * - one model it does not list: the API's item, else the entry's 404.
 *
 * Any other answer of the entry's (a refused key) is answered as it is.
 */
export async function mergedListing(request: Request, url: URL, route: Extract<CatalogRoute, { kind: "models" | "model" | "gemini_models" | "gemini_model" }>, ownAnswer: Response, forward: ApiForward, sign: ForwardSigner, context: ForwardContext): Promise<Response> {
  const head = request.method === "HEAD";
  const ownStatus = ownAnswer.status;
  const one = route.kind === "model" || route.kind === "gemini_model";
  if (ownStatus !== 200 && !(one && ownStatus === 404)) return head ? withoutBody(ownAnswer) : ownAnswer;
  const own = ownStatus === 200 ? await boundedJson(ownAnswer.clone(), MODELS_API_MAX_BYTES) : undefined;
  const api = await apiListing(request, url, forward, sign, context);
  if (!one) {
    const member = route.kind === "models" ? "data" : "models";
    const key = route.kind === "models" ? (item: Item) => item.id : (item: Item) => item.name;
    const ownData = isItem(own) && Array.isArray(own[member]) ? (own[member] as unknown[]).filter(isItem) : null;
    if (ownData === null) return head ? withoutBody(ownAnswer) : ownAnswer;
    const apiData = api.kind === "ok" && isItem(api.value) && Array.isArray(api.value[member]) ? (api.value[member] as unknown[]).filter(isItem) : null;
    if (apiData === null) return jsonAnswer(ownAnswer, own, head, { [MODELS_PARTIAL_HEADER]: "api" });
    return jsonAnswer(ownAnswer, { ...(own as Item), [member]: mergeModelLists(ownData, apiData, key) }, head);
  }
  const apiItem = api.kind === "ok" && isItem(api.value) ? api.value : null;
  if (ownStatus === 200 && isItem(own)) {
    if (api.kind === "unread") return jsonAnswer(ownAnswer, own, head, { [MODELS_PARTIAL_HEADER]: "api" });
    return jsonAnswer(ownAnswer, route.kind === "model" ? withApiEndpoints(own, apiItem) : own, head);
  }
  if (ownStatus === 200) return head ? withoutBody(ownAnswer) : ownAnswer;
  // The entry does not list the model.
  if (apiItem !== null) return jsonAnswer(ownAnswer, apiItem, head);
  const notListed = api.kind === "unread" ? withHeader(ownAnswer, MODELS_PARTIAL_HEADER, "api") : ownAnswer;
  return head ? withoutBody(notListed) : notListed;
}

function withoutBody(response: Response): Response {
  void response.body?.cancel().catch(() => undefined);
  return new Response(null, { status: response.status, statusText: response.statusText, headers: response.headers });
}

/** How long the entry's copy of the API's model list is used as it is; past it a request refreshes it. */
export const API_MODELS_FRESH_MS = 60_000;
/** Past this the copy is not used: a request waits for a refresh (at most MODELS_API_TIMEOUT_MS). */
export const API_MODELS_MAX_AGE_MS = 600_000;
/** After a refresh that got no list, how long the next request waits before it tries again. */
export const API_MODELS_RETRY_MS = 10_000;

/** Each model the API lists, with the APIs (`endpoints[].protocol`) it lists it on. */
export type ApiServed = ReadonlyMap<string, ReadonlySet<string>>;

/** The protocols of each item of an OpenAI model list (`/v1/models`'s `data`), or null when it is not one. */
export function apiServedOf(value: unknown): ApiServed | null {
  if (!isItem(value) || !Array.isArray(value.data)) return null;
  const served = new Map<string, Set<string>>();
  for (const item of value.data) {
    if (!isItem(item) || typeof item.id !== "string" || !Array.isArray(item.endpoints)) continue;
    const protocols = served.get(item.id) ?? new Set<string>();
    for (const endpoint of item.endpoints) if (isItem(endpoint) && typeof endpoint.protocol === "string") protocols.add(endpoint.protocol);
    served.set(item.id, protocols);
  }
  return served;
}

/**
 * The entry's copy of the models Gray's API serves, by API: the API's keyless `GET /v1/models` (every model it lists,
 * with each one's endpoints; a key's scope is the API's to apply to the forwarded request), one per isolate and API
 * binding. Fresh for API_MODELS_FRESH_MS; then used while a refresh runs behind the request, up to API_MODELS_MAX_AGE_MS;
 * past that a request waits for the refresh. A refresh that gets no list keeps the copy and is not tried again for
 * API_MODELS_RETRY_MS. One refresh at a time.
 */
export class ApiModelsView {
  private kept: { readonly at: number; readonly served: ApiServed } | null = null;
  private loading: Promise<void> | null = null;
  private failedAt = -Infinity;

  private readonly load: () => Promise<ApiServed | null>;
  private readonly now: () => number;

  constructor(load: () => Promise<ApiServed | null>, now: () => number) {
    this.load = load;
    this.now = now;
  }

  /** The API's models, or null when no copy younger than API_MODELS_MAX_AGE_MS could be had. */
  async served(background: (work: Promise<unknown>) => void): Promise<ApiServed | null> {
    const now = this.now();
    const kept = this.kept;
    if (kept !== null && now - kept.at < API_MODELS_FRESH_MS) return kept.served;
    if (now - this.failedAt < API_MODELS_RETRY_MS) return kept !== null && now - kept.at < API_MODELS_MAX_AGE_MS ? kept.served : null;
    const refresh = this.refresh();
    if (kept !== null && now - kept.at < API_MODELS_MAX_AGE_MS) {
      background(refresh);
      return kept.served;
    }
    await refresh;
    const after = this.kept;
    return after !== null && this.now() - after.at < API_MODELS_MAX_AGE_MS ? after.served : null;
  }

  private refresh(): Promise<void> {
    this.loading ??= this.load()
      .then(
        (served) => {
          if (served === null) this.failedAt = this.now();
          else this.kept = { at: this.now(), served };
        },
        () => {
          this.failedAt = this.now();
        },
      )
      .finally(() => {
        this.loading = null;
      });
    return this.loading;
  }
}

/** One view per API binding (the isolate's), so a test's other binding never reads another's copy. */
const apiModelViews = new WeakMap<object, ApiModelsView>();

function apiModelsViewOf(forward: ApiForward, sign: ForwardSigner): ApiModelsView {
  const key = forward.binding;
  let view = apiModelViews.get(key);
  if (view === undefined) {
    const listUrl = new URL("/v1/models", forward.origin);
    view = new ApiModelsView(async () => {
      const asked = new Request(listUrl, { method: "GET", signal: AbortSignal.timeout(MODELS_API_TIMEOUT_MS) });
      const answer = await sendToApi(asked, listUrl, forward, sign);
      if (answer === null) return null;
      if (answer.status !== 200) {
        await answer.body?.cancel().catch(() => undefined);
        return null;
      }
      return apiServedOf(await boundedJson(answer, MODELS_API_MAX_BYTES));
    }, sign.now);
    apiModelViews.set(key, view);
  }
  return view;
}

/**
 * The entry's forward of a generation request InferenceRun's lane path does not serve itself (`LaneApiForward`):
 * whether the API lists one of the request's models on its API (`ApiModelsView`), and the exchange (`sendToApi`) for the
 * request at `url`, as it arrived.
 */
export function laneApiForward(forward: ApiForward, sign: ForwardSigner, url: URL, background: (work: Promise<unknown>) => void): LaneApiForward {
  const view = apiModelsViewOf(forward, sign);
  return {
    async serves(models, protocol) {
      const served = await view.served(background);
      return served !== null && models.some((model) => served.get(model)?.has(protocol) ?? false);
    },
    send: (request) => sendToApi(request, url, forward, sign),
  };
}
