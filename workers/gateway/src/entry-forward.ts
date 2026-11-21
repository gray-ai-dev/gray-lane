import type { GatewayConfig } from "@gray/config";
import { API_FORWARD_HEADER, API_FORWARD_KEY_ID, apiForwardSeed, checkForwardMark, ENTRY_FORWARD_HEADER, forwardMarkKeys, signForwardMark, VIA_ENTRY_HEADER, type ForwardMarkTarget } from "@gray/lane-wire";
import type { Protocol } from "@gray/protocol";
import { entryEndpointRoute, entryTranslationTargets, laneServedKey } from "@gray/snapshot";
import type { GatewaySnapshot } from "./snapshot.ts";

/**
 * The API Worker's side of one customer address (docs/design/one-address.md).
 *
 * - **From the entry.** The confidential entry forwards every path it does not serve here, marked `x-gray-entry-forward`
 *   with its bridge key (@gray/lane-wire forward-mark.ts). `takeEntryMark` checks the mark against
 *   LANE_ENTRY_PUBLIC_KEYS and takes it off; a request it verifies goes on with `x-gray-via-entry: <key id>`, which says
 *   the client's address is unknown here (the address this Worker sees is the entry VM's own): its record keeps none
 *   (sinks.ts `clientFields`) and gray-console counts its per-network limits in the entry's window (console
 *   network.ts). A client's copy of either header, or of `x-gray-api-forward`, is taken off every request.
 * - **To the entry.** With LANE_ENTRY_ORIGIN set, a chat request without a verifiable routing preference is forwarded
 *   to the entry (`EntryChatForward`, InferenceRun `forwardToEntry`), marked `x-gray-api-forward` with a key derived
 *   from MASTER_KEY, whose public half the entry's compose measures, when the entry serves one of the request's models
 *   on its API (`entryServes`); a request for any other model is answered here, as before. A request the entry forwarded
 *   is never sent back.
 * - **Deprecation.** With LANE_ENTRY_ORIGIN set, every answer to a request that did not come through the entry says
 *   this address is the older one (`withDeprecation`).
 */

/** What `takeEntryMark` gives the router: the request without Gray's internal headers, and the entry key id it verified. */
export interface EntryMarked {
  readonly request: Request;
  /** The entry key id whose mark verified; null for a request from anyone else. */
  readonly viaEntry: string | null;
}

/** The headers only Gray's own services set on a request; a client's copy of any is taken off. */
const INTERNAL = [ENTRY_FORWARD_HEADER, API_FORWARD_HEADER, VIA_ENTRY_HEADER] as const;

/** The mark's target as this Worker received the request. */
export function markTarget(method: string, url: URL): ForwardMarkTarget {
  return { method, host: url.host, pathAndQuery: `${url.pathname}${url.search}` };
}

/**
 * The request without Gray's internal headers; with `x-gray-via-entry` when its `x-gray-entry-forward` mark verifies
 * with one of LANE_ENTRY_PUBLIC_KEYS for this method, host, path and query, within the mark's time window. A mark that
 * does not verify is dropped like a client's header: the request is then any client's. A key list that does not parse
 * accepts nothing (the config check refuses it first).
 */
export async function takeEntryMark(request: Request, cfg: Pick<GatewayConfig, "laneEntryPublicKeys">, nowMs: number): Promise<EntryMarked> {
  const present = INTERNAL.some((name) => request.headers.has(name));
  if (!present) return { request, viaEntry: null };
  const mark = request.headers.get(ENTRY_FORWARD_HEADER);
  let viaEntry: string | null = null;
  if (mark !== null) {
    const keys = forwardMarkKeys(cfg.laneEntryPublicKeys);
    if (keys.ok && keys.keys.size > 0) {
      const checked = await checkForwardMark("entry", mark, { keys: keys.keys, nowMs, target: markTarget(request.method, new URL(request.url)) });
      if (checked.ok) viaEntry = checked.keyId;
    }
  }
  const headers = new Headers(request.headers);
  for (const name of INTERNAL) headers.delete(name);
  if (viaEntry !== null) headers.set(VIA_ENTRY_HEADER, viaEntry);
  // The client's signal goes along: a client that leaves still ends the request's work (docs/cloudflare-native.md 5.6).
  // So does what Cloudflare states of the request (`cf`), which places it in its region (region.ts).
  const init: RequestInit = { headers, signal: request.signal };
  if (request.cf !== undefined) init.cf = request.cf;
  return { request: new Request(request, init), viaEntry };
}

/** Whether `headers` say the request came through the entry (set only by `takeEntryMark`). */
export function viaEntryOf(headers: Headers): string | null {
  return headers.get(VIA_ENTRY_HEADER);
}

/**
 * The time this address became the older one, as `Deprecation` states it (RFC 9745: `@` and Unix seconds):
 * 2026-11-21T00:00:00Z, the release that made the entry serve every path.
 */
export const DEPRECATED_SINCE_S = 1_795_219_200;

/** The answer headers a console page may read beside the default list while the address is deprecated. */
export const DEPRECATION_EXPOSED = "deprecation, link";

/** `response` with `Deprecation` and a `successor-version` link to the entry (RFC 9745, RFC 5829). The body streams on. */
export function withDeprecation(response: Response, entryOrigin: string): Response {
  const headers = new Headers(response.headers);
  headers.set("deprecation", `@${DEPRECATED_SINCE_S}`);
  headers.append("link", `<${entryOrigin}>; rel="successor-version"`);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** Request headers never passed to the entry: hop by hop, framing, addresses and proxies, cookies, Gray's own. */
const DROPPED_REQUEST = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "forwarded",
  "via",
  "x-real-ip",
  "cookie",
  "proxy-authorization",
  ...INTERNAL,
  "x-gray-public-request-id",
  "x-gray-claimed-key",
]);

/** Answer headers never passed back: hop by hop. */
const DROPPED_ANSWER = new Set(["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

/** The client's headers as they go to the entry. */
export function forwardedRequestHeaders(from: Headers): Headers {
  const headers = new Headers();
  for (const [name, value] of from) {
    if (DROPPED_REQUEST.has(name) || name.startsWith("cf-") || name.startsWith("x-forwarded-")) continue;
    headers.append(name, value);
  }
  return headers;
}

/**
 * `stream` as it is read, calling `onEnd` once when it ends, fails or is cancelled (the reader left): how the request
 * knows the entry has read its body, or that its answer has reached the client.
 */
export function endingWith(stream: ReadableStream<Uint8Array>, onEnd: () => void): ReadableStream<Uint8Array> {
  const reader = stream.getReader();
  let ended = false;
  const end = (): void => {
    if (ended) return;
    ended = true;
    onEnd();
  };
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            end();
            controller.close();
            return;
          }
          controller.enqueue(value);
        } catch (error) {
          end();
          controller.error(error);
        }
      },
      async cancel(reason) {
        end();
        await reader.cancel(reason).catch(() => {});
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * The entry's answer as the client gets it: its status, its headers but the hop-by-hop ones, its body as it streams;
 * `onEnd` once the body has ended, failed or been cancelled (at once for an answer without a body).
 */
export function forwardedAnswer(answer: Response, onEnd: () => void = () => {}): Response {
  const headers = new Headers();
  for (const [name, value] of answer.headers) if (!DROPPED_ANSWER.has(name)) headers.append(name, value);
  if (answer.body === null) onEnd();
  const body = answer.body === null ? null : endingWith(answer.body, onEnd);
  return new Response(body, { status: answer.status, statusText: answer.statusText, headers });
}

/**
 * Whether the confidential entry serves one of `models` on `protocol`, by this gateway's snapshot and the rules the
 * entry's own view is built with (@gray/snapshot `routeInMode(…, "lane")`): a lane relay's route of the pair
 * (`laneServed`), an endpoint route the entry serves too (`entryEndpointRoute`) with exactly that API, or, while the
 * entry translates (`entryTranslation`), an endpoint route of the model there on another text API it translates onto
 * (@gray/snapshot `entryTranslationTargets`). A route's existence decides, not whether it serves now: a pair whose routes
 * are all down is still the entry's to answer. A model the entry has no such route of (a Gemini image model served
 * through its image routes, one this gateway serves only through its operator's translation) is answered here: the
 * entry never forwards a request back.
 */
export function entryServes(snapshot: Pick<GatewaySnapshot, "routes" | "laneServed" | "entryTranslation">, models: readonly string[], protocol: Protocol): boolean {
  const served = snapshot.laneServed ?? {};
  if (models.some((model) => Object.hasOwn(served, laneServedKey(model, protocol)))) return true;
  const endpoint = snapshot.routes.filter((r) => r.auth !== "lane_relay" && models.includes(r.model) && entryEndpointRoute({ auth: r.auth, protocol: r.protocol, adapter: r.adapter, baseUrl: r.baseUrl, url: r.url }));
  if (endpoint.some((r) => r.protocol === protocol)) return true;
  if (snapshot.entryTranslation === "off") return false;
  // No route of the pair at the entry (above): a model with an endpoint route there on another text API is translated.
  return models.some((model) => entryTranslationTargets(protocol, () => false, (api) => endpoint.some((r) => r.model === model && r.protocol === api)).length > 0);
}

/**
 * Whether a request listing `models` on `protocol` goes to the entry (InferenceRun `forwardToEntry`): the entry serves one
 * of them (`entryServes`), and no model this gateway knows (a route or a mapping of it here) is one the entry does not
 * serve. A list naming such a model is answered here, as before: at the entry that model would be skipped for a later one
 * the client listed after it, and the entry never forwards a request back.
 */
export function entryServesChain(snapshot: Pick<GatewaySnapshot, "routes" | "laneServed" | "mapped" | "entryTranslation">, models: readonly string[], protocol: Protocol): boolean {
  let any = false;
  for (const model of models) {
    if (entryServes(snapshot, [model], protocol)) {
      any = true;
      continue;
    }
    if (snapshot.routes.some((r) => r.model === model) || (snapshot.mapped?.some((m) => m.model === model) ?? false)) return false;
  }
  return any;
}

/** How the main gateway forwards an older client's chat request to the entry (InferenceRun `forwardToEntry`). */
export interface EntryChatForward {
  /** LANE_ENTRY_ORIGIN. */
  readonly origin: string;
  /** The `x-gray-api-forward` value for a request to `target`, signed at `nowMs`. */
  mark(target: ForwardMarkTarget, nowMs: number): Promise<string>;
  readonly fetch: (request: Request) => Promise<Response>;
}

/**
 * The forward to LANE_ENTRY_ORIGIN, or null: the setting is empty, the request came through the entry (it is never sent
 * back), or there is no usable MASTER_KEY to derive the mark's key from (the request is then answered here, as without
 * the setting).
 */
export function entryChatForward(cfg: Pick<GatewayConfig, "laneEntryOrigin">, masterKey: string | undefined, viaEntry: string | null, fetcher: (request: Request) => Promise<Response>): EntryChatForward | null {
  if (cfg.laneEntryOrigin === "" || viaEntry !== null || masterKey === undefined || !/^[0-9a-fA-F]{64}$/.test(masterKey.trim())) return null;
  let seed: Promise<Uint8Array | null> | null = null;
  return {
    origin: cfg.laneEntryOrigin,
    async mark(target, nowMs) {
      seed ??= apiForwardSeed(masterKey);
      const signer = await seed;
      if (signer === null) throw new Error("MASTER_KEY is not 64 hex digits: no forward key");
      return signForwardMark("api", { keyId: API_FORWARD_KEY_ID, nowMs, signer, target });
    },
    fetch: fetcher,
  };
}
