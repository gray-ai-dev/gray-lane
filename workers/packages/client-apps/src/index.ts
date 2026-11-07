/// <reference path="./uap-ref-impl.d.ts" />
import makeParser, { type UserAgentParser } from "uap-ref-impl";
import catalogDocument from "../../../../crates/gray-gateway/src/client_apps.json" with { type: "json" };

/**
 * @gray/client-apps: the client application a request came from (Claude Code, Codex, Cline, ...),
 * for the request record and the ledger: crates/gray-gateway/src/client_apps.rs, from the same
 * catalog file the server compiles in (`client_apps.json`), and held to it by the `client-apps`
 * conformance area.
 *
 * Clients name themselves in the User-Agent's product token (`claude-cli/2.1.295 (external, cli)`)
 * and some in a header of their own (`originator: codex_exec`, `X-Title: Cline`). User-Agents are
 * parsed by the catalog's uap-core parsers with uap-ref-impl, the ua-parser project's JavaScript
 * implementation of the format the server's `ua-parser` crate reads; headers are compared for
 * equality. A product the catalog does not know is kept as `ua:<product>`. A client that names
 * itself nowhere is named by the base URL it is given, `/v1/client/<client>/v1/...` (`declaredPath`).
 *
 * A client can send anything, so this is attribution, never an access decision. Only the id and the
 * version are kept, never the User-Agent itself (the record keeps that separately).
 *
 * One difference from the server: a Worker sees a header sent twice as one value, both joined with
 * ", " (the Fetch standard's `get`), where the server reads the first (docs/cloudflare-native/gateway.md
 * section 13).
 */

/** Stored versions stay within the request record's limits (client_apps.rs MAX_VERSION). */
const MAX_VERSION = 32;
/** The header a `/v1/client/<client>/` base URL becomes (`declaredPath`); a client may send it itself. */
export const DECLARED_HEADER = "x-gray-client";
/** What an agent the catalog does not list declares, and what an unlisted declared id counts as. */
export const OTHER_AGENT = "other-agent";
/** The path a client's base URL starts with, before its id. */
export const CLIENT_PREFIX = "/v1/client/";
/** The longest client id a path may declare (client_apps.rs MAX_DECLARED). */
const MAX_DECLARED = 40;

/** A recognised client: a catalog id, or `ua:<product>` for a product the catalog does not know; its version when the request says. */
export interface ClientApp {
  readonly id: string;
  readonly version: string | null;
}

/** What a client is read from: a request's headers (`Headers`), by lower-case name. */
export interface HeaderSource {
  get(name: string): string | null;
}

interface App {
  readonly id: string;
  readonly name: string;
  /** `app`: a coding agent or chat application; `library`: an SDK or HTTP library, the answer only when nothing names the application. */
  readonly kind: "app" | "library";
  readonly sources: readonly string[];
  /** A header the real client always sends; a request with the User-Agent but not this header is the `otherwise` app. */
  readonly confirm?: { readonly header: string; readonly otherwise: string };
}

interface HeaderRule {
  readonly header: string;
  readonly equals?: readonly string[];
  readonly present?: boolean;
  readonly app: string;
}

interface CatalogDocument {
  readonly apps: readonly App[];
  readonly user_agent_parsers: readonly UserAgentParser[];
  readonly headers: readonly HeaderRule[];
}

/** No parser matched (uap-ref-impl's default family); no catalog parser names it (checked below). */
const NO_MATCH = "Other";

/** The catalog, checked as client_apps.rs `catalog` checks it: a broken file fails at load, never per request. */
function load(doc: CatalogDocument) {
  const apps = new Map(doc.apps.map((a) => [a.id, a]));
  for (const app of doc.apps) {
    if (app.sources.length === 0) throw new Error(`client_apps.json: ${app.id} lists no source`);
    if (app.confirm !== undefined && !apps.has(app.confirm.otherwise)) throw new Error(`client_apps.json: ${app.id} falls back to unknown app ${app.confirm.otherwise}`);
  }
  for (const parser of doc.user_agent_parsers) {
    const id = parser.family_replacement;
    if (id === undefined || !(apps.has(id) || id === "ua:$1") || id === NO_MATCH) throw new Error(`client_apps.json: user agent parser names unknown app ${String(id)}`);
  }
  for (const rule of doc.headers) {
    if (!apps.has(rule.app)) throw new Error(`client_apps.json: header rule names unknown app ${rule.app}`);
    if ((rule.present === true) === ((rule.equals ?? []).length > 0)) throw new Error(`client_apps.json: ${rule.header} rule needs either equals or present`);
  }
  return { apps, headers: doc.headers, agents: makeParser({ user_agent_parsers: doc.user_agent_parsers, os_parsers: [], device_parsers: [] }) };
}

const CATALOG = load(catalogDocument as unknown as CatalogDocument);

/** ASCII lower case only (Rust's `to_ascii_lowercase`, `eq_ignore_ascii_case`). */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/**
 * The header's value as the server reads it (`HeaderValue::to_str`, then `str::trim`): only visible
 * ASCII and tabs, else no value at all. A Worker's header value holds one byte per character.
 */
function text(headers: HeaderSource, name: string): string | null {
  const value = headers.get(name);
  if (value === null) return null;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (!((c >= 32 && c < 127) || c === 9)) return null;
  }
  return value.trim();
}

function isApp(id: string): boolean {
  return CATALOG.apps.get(id)?.kind === "app";
}

/** `id`, or its `otherwise` app when the catalog confirms `id` by a header the request does not have. */
function confirmed(id: string, headers: HeaderSource): string {
  const confirm = CATALOG.apps.get(id)?.confirm;
  return confirm !== undefined && headers.get(confirm.header) === null ? confirm.otherwise : id;
}

function byUserAgent(ua: string, headers: HeaderSource): ClientApp | null {
  const v = CATALOG.agents.parseUA(ua);
  if (v.family === NO_MATCH) return null;
  const parts: string[] = [];
  for (const part of [v.major, v.minor, v.patch]) {
    if (part === null) break;
    parts.push(part);
  }
  const version = parts.join(".");
  return { id: confirmed(v.family, headers), version: version.length > 0 && version.length <= MAX_VERSION ? version : null };
}

function byHeader(headers: HeaderSource): string | null {
  for (const rule of CATALOG.headers) {
    const value = text(headers, rule.header);
    if (value === null) continue;
    if (rule.present === true || (rule.equals ?? []).some((e) => asciiLower(e) === asciiLower(value))) return rule.app;
  }
  return null;
}

/**
 * The app a request declares (DECLARED_HEADER): a catalog app, confirmed as its User-Agent would be
 * (a declared `claude-code` without Claude Code's session header is `claude-code-compatible`), or
 * OTHER_AGENT for any other value.
 */
function declared(headers: HeaderSource): string | null {
  const value = text(headers, DECLARED_HEADER);
  if (value === null || value.length === 0) return null;
  const id = asciiLower(value);
  return isApp(id) ? confirmed(id, headers) : OTHER_AGENT;
}

/**
 * The client application that sent a request with these headers: a User-Agent naming an app, else a
 * header naming one, else the app its base URL declares, else what the User-Agent says (an SDK, a
 * library or an unknown product). Null when the request has no usable User-Agent and names no client.
 */
export function identify(headers: HeaderSource): ClientApp | null {
  const ua = text(headers, "user-agent");
  const byUa = ua === null || ua.length === 0 ? null : byUserAgent(ua, headers);
  if (byUa !== null && isApp(byUa.id)) return byUa;
  // The User-Agent's version, if any, is an SDK's, not the app's.
  const header = byHeader(headers);
  if (header !== null) return { id: header, version: null };
  const id = declared(headers);
  if (id !== null) return { id, version: null };
  return byUa;
}

/** `headers` with DECLARED_HEADER set to `client`, replacing one the request sent (what `declaredPath` does to the request). */
export function withDeclared(headers: HeaderSource, client: string): HeaderSource {
  return { get: (name) => (asciiLower(name) === DECLARED_HEADER ? client : headers.get(name)) };
}

/**
 * `/v1/client/<client>/v1/...` and `/v1/client/<client>/v1beta/...` as the public API path, and the
 * client it declares (client_apps.rs `declared_path`); null for any other path, which is served as it
 * came. `<client>` is 1 to 40 of a-z, 0-9 and `-`. The query is not part of `path` and stays as it is.
 */
export function declaredPath(path: string): { readonly path: string; readonly client: string } | null {
  if (!path.startsWith(CLIENT_PREFIX)) return null;
  const after = path.slice(CLIENT_PREFIX.length);
  const slash = after.indexOf("/");
  if (slash < 0) return null;
  const client = after.slice(0, slash);
  const rest = after.slice(slash + 1);
  const isPublic = ["v1", "v1beta"].some((api) => rest === api || rest.startsWith(`${api}/`));
  const named = client.length > 0 && client.length <= MAX_DECLARED && /^[a-z0-9-]+$/.test(client);
  if (!isPublic || !named) return null;
  return { path: `/${rest}`, client };
}

/**
 * The ids and names of the apps a base URL may declare, for agent.md (client_apps.rs `declarable`):
 * every app but OTHER_AGENT and the stand-ins for unconfirmed clients, by name in ASCII lower case.
 */
export function declarable(): [string, string][] {
  const standIns = [...CATALOG.apps.values()].flatMap((a) => (a.confirm === undefined ? [] : [a.confirm.otherwise]));
  return [...CATALOG.apps.values()]
    .filter((a) => a.kind === "app" && a.id !== OTHER_AGENT && !standIns.includes(a.id))
    .map((a) => [a.id, a.name] as [string, string])
    .sort(([, x], [, y]) => {
      const a = asciiLower(x);
      const b = asciiLower(y);
      return a < b ? -1 : a > b ? 1 : 0;
    });
}

/** The display name of a client id: the catalog's, or the product of an unknown `ua:` one (client_apps.rs `label`). */
export function label(id: string): string {
  return CATALOG.apps.get(id)?.name ?? (id.startsWith("ua:") ? id.slice("ua:".length) : id);
}
