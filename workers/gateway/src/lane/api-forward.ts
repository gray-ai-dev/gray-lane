import type { GatewayConfig } from "@gray/config";
import { ApiError, shapeOf } from "@gray/errors";
import { newRequestId } from "@gray/ledger-keys";
import { API_FORWARD_HEADER, ENTRY_FORWARD_HEADER, signForwardMark, VIA_ENTRY_HEADER, type BridgeSigner } from "@gray/lane-wire";
import { originsOf } from "../hosts.ts";
import { catalogRoute } from "../listings.ts";
import { isSetupPath } from "../paths.ts";

/**
 * docs/design/standard-media-at-entry.md section 2.9: the entry forwards to the API Worker only the paths that carry no
 * prompt or other model content (`forwardedPath`): the key's status and the setup routes, which read the console's
 * database. Every other path is answered in the VM: a model path by the entry's own request paths, on a route it has or
 * with its own answer for a model it does not serve, and a path no API serves with the entry's 404. No model request
 * and no model list is read from, or sent to, the API Worker.
 *
 * A forwarded request goes to the API Worker of the entry's measured compose (`API_ORIGIN`, app-compose.mjs
 * `--api-origin`), through the `API` service the entrypoint renders for it (an HTTPS connection verified against the
 * browser roots for the API's host, as the bridge's is). The origin is never taken from the request
 * (docs/design/one-address.md).
 *
 * It carries the client's method, path and query, body (streamed) and headers, less hop-by-hop, proxy and address
 * headers, cookies and Gray's internal headers, plus the entry's mark (`x-gray-entry-forward`, signed by its bridge key,
 * @gray/lane-wire forward-mark.ts), which the API Worker checks before it takes the request as the entry's. Its answer
 * comes back as the API sent it (status, headers but the hop-by-hop ones and the API's own CORS headers, the body as it
 * streams), with `x-gray-served-by` naming the API origin and no receipt: the entry reads, stores and signs nothing of
 * it.
 */

/**
 * Whether the entry forwards `method` at `path` (a client's base URL taken off) to the API Worker: the whole list.
 *
 * - `GET` and `HEAD /v1/key`: the key's limits, spend and balance (listings.ts `catalogRoute`). Another method there
 *   has no route at the API either and is not sent.
 * - `/v1/setup/*`, `/v1/provider-setup/*` and `/v1/lane-stack/*`, any method: the agent and provider setup, claims
 *   included, and a relay stack's public routes, which the console answers (paths.ts `isSetupPath`, the rule the API
 *   Worker routes them by).
 *
 * A path is added here only when its requests and answers carry no prompt and no model output: what is forwarded leaves
 * the VM and ends its TLS at Cloudflare. test/lane/api-forward.test.ts holds the list and every model path against it.
 */
export function forwardedPath(method: string, path: string): boolean {
  return isSetupPath(path) || catalogRoute(method, path)?.kind === "key";
}

/** A forwarded path's kind, the closed word its log lines carry in place of the path. */
export function forwardedKind(path: string): "setup" | "provider_setup" | "lane_stack" | "key" {
  if (path.startsWith("/v1/provider-setup/")) return "provider_setup";
  if (path.startsWith("/v1/lane-stack/")) return "lane_stack";
  if (path.startsWith("/v1/setup/")) return "setup";
  return "key";
}

/** The answer header naming the origin that served a forwarded path. */
export const SERVED_BY_HEADER = "x-gray-served-by";

/** The API Worker the entry forwards to. */
export interface ApiForward {
  /** `API_ORIGIN`: an https origin, `scheme://host[:port]`. */
  readonly origin: string;
  /** The `API` service binding. */
  readonly fetch: (request: Request) => Promise<Response>;
}

/** What `apiForwardOf` read: the forward, or null with no problem when unset, or the problem with the setting. */
export type ApiForwardRead = { readonly forward: ApiForward | null; readonly problem: string | null };

/**
 * The entry's forward from its bindings: null when `API_ORIGIN` is unset or empty (the entry then answers its 404 for
 * the paths it would forward). Set, it must be an https origin written as one, outside the relay-stack layout, with a
 * usable `API` binding; otherwise the problem, which the entry treats as a misconfiguration.
 */
export function apiForwardOf(env: { readonly API?: unknown; readonly API_ORIGIN?: unknown }, stackLayout: boolean): ApiForwardRead {
  const origin = env.API_ORIGIN;
  if (origin === undefined || origin === "") return { forward: null, problem: null };
  if (typeof origin !== "string" || !isHttpsOrigin(origin)) return { forward: null, problem: "API_ORIGIN" };
  if (stackLayout) return { forward: null, problem: "API_ORIGIN" };
  const binding = env.API;
  if (typeof binding !== "object" || binding === null || typeof (binding as { fetch?: unknown }).fetch !== "function") return { forward: null, problem: "API" };
  const fetcher = binding as { fetch(request: Request): Promise<Response> };
  return { forward: { origin, fetch: (request) => fetcher.fetch(request) }, problem: null };
}

function isHttpsOrigin(text: string): boolean {
  try {
    const url = new URL(text);
    return url.protocol === "https:" && url.origin === text;
  } catch {
    return false;
  }
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
 * `request` (arrived at `url`, a path of `forwardedPath`) forwarded to the API: its method, path and query as sent (a
 * declared `/v1/client/<client>/` base URL included), its body as a stream, its headers (`forwardedRequestHeaders`) and
 * the entry's mark. The answer as the API sent it (`forwardedAnswerHeaders`), with `x-gray-served-by`; a 502
 * `api_unreachable` in the path's error shape when no answer came (logged).
 */
export async function forwardToApi(request: Request, url: URL, forward: ApiForward, sign: ForwardSigner, context: ForwardContext): Promise<Response> {
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
    // The entry's container log is readable outside the VM (deploy/tee/IMPLEMENTATION_NOTES.md §9, "public_logs"): the
    // path's kind, never the client's path (which carries ids and whatever a client put after the prefix), and the
    // error's class, never its message.
    console.error(JSON.stringify({ level: "error", event: "lane_api_forward_failed", method: request.method, kind: forwardedKind(url.pathname), code: thrown instanceof Error ? thrown.name : "error" }));
    return unreachable(context);
  }
  if (answer.status < 200 || answer.status > 599) {
    await answer.body?.cancel().catch(() => undefined);
    console.error(JSON.stringify({ level: "error", event: "lane_api_forward_failed", method: request.method, kind: forwardedKind(url.pathname), status: answer.status }));
    return unreachable(context);
  }
  const out = forwardedAnswerHeaders(answer.headers);
  out.set(SERVED_BY_HEADER, forward.origin);
  return new Response(answer.body, { status: answer.status, statusText: answer.statusText, headers: out });
}

/** The 502 a forward that got no answer is told, in the path's error shape. */
function unreachable(context: ForwardContext): Response {
  const rendered = new ApiError(502, "api_unreachable")
    .withMessage("Gray's confidential VM could not reach Gray's API, which serves this path. Retry in a moment.")
    .withHelp(null)
    .render({ shape: shapeOf(context.path), origins: originsOf(context.cfg, context.url), requestId: newRequestId(Date.now()) });
  return new Response(rendered.body, { status: rendered.status, headers: rendered.headers });
}
