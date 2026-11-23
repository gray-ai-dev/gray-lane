import { LANE_PROTOCOLS } from "@gray/control";
import { get, isObject, parseStrict, type Json } from "@gray/json";
import type { Protocol } from "@gray/protocol";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/**
 * The endpoint routes the confidential lane's entry serves (docs/design/lane-provider-routes.md sections 2, 4.2, 5):
 * routes a provider set up with an API address and a key (`auth` `bearer` or `protocol_native`) on one of the three
 * protocols the entry speaks, which it sends through gray-egress's `/route/<id>/<path>` to the host of the row it pushed
 * for the endpoint (`PUT /v1/routes`, deploy/tee/egress/endpoint_routes.go).
 *
 * Egress refuses a whole table when one row breaks its rules (`400 route_control_invalid`), so the lane view admits an
 * endpoint route only when its row is one egress accepts: the row rules below are Go's (`validRouteID`,
 * `validRouteHost`, `validRoutePathPrefix`), held to the same accepted and refused tables as Go
 * (`deploy/tee/egress/test/route-table.json`, test/endpoint-route.test.ts). On top of the row rules, a route is admitted
 * only when every request the entry would send for it passes egress's `/route/` checks: its URL is the row's host and
 * a path under the row's prefix (`routeUrl` writes it from the endpoint's base URL and the mapping's native path, and
 * the native path need not extend the base path).
 */

/**
 * The deployment's own zones, which no row's host may be or be under: the entry's egress runs with
 * `-route-deny-suffix` set to these (deploy/tee/compose.yaml; the gate holds the two together), so no row can point
 * back at Gray.
 */
export const ENTRY_ROUTE_DENY_SUFFIXES: readonly string[] = Object.freeze(["usefallback.com"]);

/**
 * The standard APIs of docs/design/standard-media-at-entry.md section 2.1: embeddings, rerank, image generations and
 * edits, speech, transcriptions, translations, videos and System One. A video route's URL is its create path, and its
 * job paths append `/<id>` and `/<id>/content`, which pass `endpointRoutePath` for every id of the standard's clause
 * 11.10 (test/endpoint-route.test.ts).
 *
 * The entry serves them all (in ENTRY_ENDPOINT_PROTOCOLS): the synchronous ones within their request
 * (`ENTRY_STANDARD_PROTOCOLS`), and video jobs, which it records behind the bridge and polls and settles itself
 * (section 2.7 of that design). A video route is therefore in the entry's model listing, its mapped pairs and egress's
 * route table, as the others are.
 */
export const ENTRY_MEDIA_PROTOCOLS: readonly Protocol[] = Object.freeze([
  "open_ai_embeddings",
  "rerank",
  "open_ai_image_generations",
  "open_ai_image_edits",
  "open_ai_speech",
  "open_ai_transcriptions",
  "open_ai_translations",
  "open_ai_videos",
  "system_one",
]);

/**
 * The standard APIs that answer within their request (section 2.2 of that design), as a pass of the provider's own
 * answer. Every one of ENTRY_MEDIA_PROTOCOLS but videos, whose jobs outlive a request.
 */
export const ENTRY_STANDARD_PROTOCOLS: readonly Protocol[] = Object.freeze(ENTRY_MEDIA_PROTOCOLS.filter((protocol) => protocol !== "open_ai_videos"));

/**
 * The protocols the entry serves an endpoint route on (docs/design/lane-provider-routes.md sections 2 and 7;
 * docs/design/standard-media-at-entry.md section 2.1): the lane relays' three (`LANE_PROTOCOLS`: Messages, Chat
 * Completions, Responses), Gemini's generation API, and the standard APIs (`ENTRY_MEDIA_PROTOCOLS`). A lane relay
 * stays on the three: its templates and the lane's rewrite plan are defined for those alone.
 */
export const ENTRY_ENDPOINT_PROTOCOLS: readonly Protocol[] = Object.freeze([...LANE_PROTOCOLS, "gemini", ...ENTRY_MEDIA_PROTOCOLS]);

/** egress's routeRefusedZones: special-use and private names, none of which is a public provider's API host. */
const REFUSED_ZONES: readonly string[] = ["invalid", "local", "internal", "localhost", "test", "example", "arpa", "onion"];

/** RFC 1035's bounds in text form, as egress applies them. */
const DNS_NAME_MAX_BYTES = 253;
const DNS_LABEL_MAX_BYTES = 63;

/** egress's routeIDMaxBytes: an id is 1-64 of [a-z0-9_-]. */
const ROUTE_ID_MAX_BYTES = 64;

/** An endpoint's route id in egress's table: the first 32 lower-hex characters of SHA-256 of the endpoint id. */
const ROUTE_KEY_HEX = 32;

/** `validRouteID`: 1-64 of [a-z0-9_-]. */
export function validRouteId(id: string): boolean {
  return id.length >= 1 && id.length <= ROUTE_ID_MAX_BYTES && /^[a-z0-9_-]+$/.test(id);
}

/** `validDNSName`: labels of 1-63 of [a-z0-9-], none starting or ending with '-', at most 253 bytes, no empty label. */
function validDnsName(name: string): boolean {
  if (name === "" || name.length > DNS_NAME_MAX_BYTES) return false;
  return name.split(".").every((label) => label !== "" && label.length <= DNS_LABEL_MAX_BYTES && /^[a-z0-9-]+$/.test(label) && !label.startsWith("-") && !label.endsWith("-"));
}

/**
 * `validRouteHost`: a lower-case DNS name of at least two labels whose last label starts with a letter (so no IPv4
 * spelling and no IPv6 literal), no port, no trailing dot, neither a special-use zone nor one of `deny`, nor under one.
 */
export function validRouteHost(host: string, deny: readonly string[]): boolean {
  if (!validDnsName(host)) return false;
  const dot = host.lastIndexOf(".");
  if (dot < 0 || !/^[a-z]$/.test(host.charAt(dot + 1))) return false;
  for (const zone of [...REFUSED_ZONES, ...deny]) {
    if (host === zone || host.endsWith(`.${zone}`)) return false;
  }
  return true;
}

/**
 * Percent-encoded path separators (`%2f` and `%5c`, any hex case). Upstream proxies that percent-decode before
 * routing treat them as separators, letting payloads like `..%2f..%2fadmin` escape a row's path prefix.
 */
const ENCODED_SEPARATOR = /%(?:2f|5c)/i;

/**
 * `validRoutePathPrefix`: starts and ends with '/', does not start with "//", holds no '?', '#', '\\', or encoded
 * path separator (`%2f` / `%5c`), and passes the vendor routes' path rule (`validRawPath`: no byte at or below 0x20,
 * no 0x7f).
 */
export function validRoutePathPrefix(prefix: string): boolean {
  if (!prefix.startsWith("/") || !prefix.endsWith("/") || prefix.startsWith("//") || /[?#\\]/.test(prefix) || ENCODED_SEPARATOR.test(prefix)) return false;
  const bytes = utf8ToBytes(prefix);
  return bytes.every((b) => b > 0x20 && b !== 0x7f);
}

/** One row of the table, as the entry sends it: `{route, host, path_prefix, not_after}` (route-table.json). */
export interface EndpointRouteRow {
  readonly route: string;
  readonly host: string;
  readonly path_prefix: string;
  readonly not_after: number;
}

/** egress's routeMaxRows: the most rows one table may hold. */
export const ROUTE_TABLE_MAX_ROWS = 4096;

/** egress's routeRowMaxTTL: a row's `not_after` is at most an hour from the current second. */
export const ROUTE_ROW_MAX_TTL_SECONDS = 3600;

/** Whether egress accepts `row` at `nowSeconds` with `-route-deny-suffix` `deny` (`parseRouteRow`, an hour at most). */
export function validRouteRow(row: EndpointRouteRow, nowSeconds: number, deny: readonly string[]): boolean {
  return (
    validRouteId(row.route) &&
    validRouteHost(row.host, deny) &&
    validRoutePathPrefix(row.path_prefix) &&
    Number.isSafeInteger(row.not_after) &&
    row.not_after >= 0 &&
    row.not_after <= nowSeconds + ROUTE_ROW_MAX_TTL_SECONDS
  );
}

const ROW_MEMBERS = ["route", "host", "path_prefix", "not_after"] as const;

/**
 * A `PUT /v1/routes` body as egress reads it (`putRoutes`), or null when egress answers `400 route_control_invalid`: a
 * JSON array without duplicate members (`parseStrict`, Go's `checkStrictJSON`) of at most ROUTE_TABLE_MAX_ROWS rows,
 * each exactly the four members, `not_after` an integer, every row valid at `nowSeconds` and each id once. The entry
 * writes its table with `JSON.stringify` of rows `validRouteRow` passed; this reader is the wire format's other half,
 * which test/endpoint-route.test.ts holds to egress's own table of cases.
 */
export function routeTableOf(text: string, nowSeconds: number, deny: readonly string[]): EndpointRouteRow[] | null {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    return null;
  }
  if (!Array.isArray(value) || value.length > ROUTE_TABLE_MAX_ROWS) return null;
  const rows: EndpointRouteRow[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!isObject(item) || Object.keys(item).length !== ROW_MEMBERS.length || !ROW_MEMBERS.every((name) => Object.hasOwn(item, name))) return null;
    const [route, host, prefix, notAfter] = ROW_MEMBERS.map((name) => get(item, name));
    if (typeof route !== "string" || typeof host !== "string" || typeof prefix !== "string" || typeof notAfter !== "bigint") return null;
    if (notAfter < 0n || notAfter > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    const row: EndpointRouteRow = { route, host, path_prefix: prefix, not_after: Number(notAfter) };
    if (!validRouteRow(row, nowSeconds, deny) || seen.has(route)) return null;
    seen.add(route);
    rows.push(row);
  }
  return rows;
}

/**
 * The route id egress's table names `endpointId` by: the first 32 lower-hex characters of its SHA-256. Endpoint ids are
 * UUIDs today, but nothing holds them to egress's id grammar; the digest always meets it, and 128 bits keep two
 * endpoints apart.
 */
export function endpointRouteKey(endpointId: string): string {
  return bytesToHex(sha256(utf8ToBytes(endpointId))).slice(0, ROUTE_KEY_HEX);
}

/** Where egress sends an endpoint's requests: the row's host (443 implied) and path prefix. */
export interface EndpointRouteTarget {
  readonly host: string;
  readonly pathPrefix: string;
}

/**
 * The row target of an endpoint's base URL, or null when egress could not carry it: an `https` URL with no userinfo,
 * no port or port 443, no query or fragment, whose host and path pass the row rules. The URL is read as `routeUrl`
 * reads it (WHATWG, so the host is the one the route's URL names), and its path is the prefix, ending in '/'.
 */
export function endpointRouteTarget(baseUrl: string, deny: readonly string[] = ENTRY_ROUTE_DENY_SUFFIXES): EndpointRouteTarget | null {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    return null;
  }
  // WHATWG drops the scheme's default port, so `:443` reads as no port.
  if (url.protocol !== "https:" || url.port !== "" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") return null;
  const pathPrefix = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  if (!validRouteHost(url.hostname, deny) || !validRoutePathPrefix(pathPrefix)) return null;
  return { host: url.hostname, pathPrefix };
}

/**
 * A path of the bytes WHATWG's URL parser leaves as they are in an `http` URL's path (every printable ASCII byte but
 * its path percent-encode set, `"` `#` `<` `>` `?` `` ` `` `{` `}`, and `\\`, which it reads as `/`), '%' only as an
 * escape (Go's server refuses a bad one): what the entry hands workerd's fetch is what egress reads.
 */
const VERBATIM_PATH = /^(?:[A-Za-z0-9!$&'()*+,\-./:;=@[\]^_|~]|%[0-9A-Fa-f]{2})*$/;
/** The same for a query, whose special-scheme percent-encode set also holds `'`, and which may hold `?`. */
const VERBATIM_QUERY = /^(?:[A-Za-z0-9!$&()*+,\-./:;=?@[\]^_|~]|%[0-9A-Fa-f]{2})*$/;

/**
 * The path and query `url` sends to under `target`, or null when egress's `/route/` checks would refuse it:
 * `https://<host>`, then a path under the prefix with no dot segment in any spelling and no byte the URL parser would
 * escape again, then an optional query of the same kind (a Gemini stream's `alt=sse`; egress passes the query on as it
 * is), and no fragment. The parity cases egress's tests read (deploy/tee/egress/test/egress-path-parity.json
 * `route_cases`) map byte for byte. `routeUrl` and `geminiOperationUrl` write a route's URL through WHATWG, so it is already in the
 * form egress compares.
 */
export function endpointRoutePath(url: string, target: EndpointRouteTarget): string | null {
  const origin = `https://${target.host}`;
  if (!url.startsWith(`${origin}/`)) return null;
  const rest = url.slice(origin.length);
  const mark = rest.indexOf("?");
  const path = mark < 0 ? rest : rest.slice(0, mark);
  const query = mark < 0 ? null : rest.slice(mark + 1);
  if (!path.startsWith(target.pathPrefix) || path.startsWith("//") || !VERBATIM_PATH.test(path) || ENCODED_SEPARATOR.test(path)) return null;
  // An empty query (`?` alone) is kept: egress passes it on as the client wrote it (ForceQuery).
  if (query !== null && !VERBATIM_QUERY.test(query)) return null;
  if (path.split("/").some((segment) => [".", "%2e", "..", ".%2e", "%2e.", "%2e%2e"].includes(segment.toLowerCase()))) return null;
  return rest;
}

/** The fields of a route the entry's rule reads (a `SnapshotRoute`'s config and mapping, or a gateway route record's). */
export interface EntryRouteFacts {
  readonly auth: string;
  readonly protocol: Protocol;
  readonly baseUrl: string;
  readonly url: string;
}

/**
 * Whether the confidential lane's entry serves an endpoint route (design section 2): `bearer` or `protocol_native`, on
 * a protocol the entry serves endpoint routes on (`ENTRY_ENDPOINT_PROTOCOLS`: Messages, Chat, Responses, Gemini and the
 * synchronous standard APIs), and a base URL egress can carry whose row covers the route's URL.
 * A `lane_relay` route is not an endpoint route. `protocols` is the entry's list; only the tests pass another
 * (ENTRY_MEDIA_PROTOCOLS beside it, for the video routes).
 */
export function entryEndpointRoute(
  r: EntryRouteFacts,
  deny: readonly string[] = ENTRY_ROUTE_DENY_SUFFIXES,
  protocols: readonly Protocol[] = ENTRY_ENDPOINT_PROTOCOLS,
): boolean {
  if ((r.auth !== "bearer" && r.auth !== "protocol_native") || !protocols.includes(r.protocol)) return false;
  const target = endpointRouteTarget(r.baseUrl, deny);
  return target !== null && endpointRoutePath(r.url, target) !== null;
}

/**
 * The APIs the entry translates between (docs/design/lane-provider-routes.md section 10; the owner's decision of
 * 2026-11-21): its endpoint protocols, the four text APIs @gray/translation carries in both directions. Their order is
 * the order the entry tries translation targets in, the client's own API left out: @gray/protocol's `PROTOCOLS` order,
 * which for a Responses client is the implied fallback's (@gray/translation `RESPONSES_FALLBACK`).
 */
export const ENTRY_TRANSLATED_APIS: readonly Protocol[] = Object.freeze(["open_ai_chat", "open_ai_responses", "anthropic_messages", "gemini"]);

/**
 * The APIs a request on `client` for one model is translated onto at the entry, in the order they are tried: none when
 * `client` is not one of ENTRY_TRANSLATED_APIS or the model has a route of its own on it at the entry (`native`: a lane
 * relay's route or an endpoint route, live or not, so a native route always comes first, its failures included);
 * otherwise each other API of the list on which the model has an endpoint route at the entry (`endpoint`). A lane
 * relay's route is never a target: its receipt promises the vendor got the client's bytes. The entry's routing, its
 * model lists, the main gateway's forward to the entry and the catalog read this one rule.
 */
export function entryTranslationTargets(client: Protocol, native: (api: Protocol) => boolean, endpoint: (api: Protocol) => boolean): Protocol[] {
  if (!ENTRY_TRANSLATED_APIS.includes(client) || native(client)) return [];
  return ENTRY_TRANSLATED_APIS.filter((api) => api !== client && endpoint(api));
}

/** One route of the entry's view as `entryTranslations` reads it: its model, its API, and whether it is an endpoint route (else a lane relay's). */
export interface EntryOffer {
  readonly model: string;
  readonly protocol: Protocol;
  readonly endpoint: boolean;
}

/**
 * For each model of `routes` (the entry's view: lane relays' routes and the endpoint routes it serves), each API it is
 * offered on at the entry only through translation, with the APIs it is translated onto (`entryTranslationTargets`), in
 * ENTRY_TRANSLATED_APIS order. A model with none is left out. Empty when `off`.
 */
export function entryTranslations(routes: Iterable<EntryOffer>, off: boolean): Map<string, Map<Protocol, Protocol[]>> {
  const out = new Map<string, Map<Protocol, Protocol[]>>();
  if (off) return out;
  const native = new Map<string, Set<Protocol>>();
  const endpoint = new Map<string, Set<Protocol>>();
  for (const r of routes) {
    let all = native.get(r.model);
    if (all === undefined) native.set(r.model, (all = new Set()));
    all.add(r.protocol);
    if (!r.endpoint) continue;
    let own = endpoint.get(r.model);
    if (own === undefined) endpoint.set(r.model, (own = new Set()));
    own.add(r.protocol);
  }
  for (const [model, apis] of endpoint) {
    const all = native.get(model)!;
    const translated = new Map<Protocol, Protocol[]>();
    for (const client of ENTRY_TRANSLATED_APIS) {
      const targets = entryTranslationTargets(client, (api) => all.has(api), (api) => apis.has(api));
      if (targets.length > 0) translated.set(client, targets);
    }
    if (translated.size > 0) out.set(model, translated);
  }
  return out;
}
