/**
 * Rule A of the confidential lane: a request may only be sent to an official vendor origin.
 *
 * The lane's customers accept that the vendor sees their data and forbid every intermediate node —
 * Gray, the relay, the cloud host — from seeing it, so the one host a lane request may reach is the
 * vendor's own API, over `https`, with no way for a URL to name a second origin.
 *
 * What is allowed, exactly:
 * - `https://api.anthropic.com` with a path under `/v1/`;
 * - `https://api.openai.com` with a path under `/v1/`;
 * - `https://chatgpt.com` with a path under `/backend-api/codex/`;
 * - each OpenAI-compatible vendor's host with a path under its prefix (`vendors.ts`, for example
 *   `https://generativelanguage.googleapis.com` under `/v1beta/openai/`).
 *
 * The host is compared after the platform `URL` parser has run, against the names spelled out
 * here and in the vendor table: an exact match, never a suffix or a wildcard, lower-case (the parser lower-cases), and a
 * trailing dot is refused rather than dropped (a host with a trailing dot is the same DNS name but
 * not the same string, and a lane customer who reads the URL should see the host that is compared).
 *
 * Every other part of the URL is checked for what it can hide:
 * - a backslash is refused anywhere: for a special scheme the parser treats `\` as `/`, so
 *   `https://api.anthropic.com\@evil.example/...` splits into the official host and a path, while
 *   some other readers of the same string would see `evil.example` as the host;
 * - a control character or space is refused anywhere: the parser strips tabs and newlines and
 *   percent-encodes spaces, so a string with one does not describe the URL it stands for;
 * - the authority must be plain ASCII and carry no percent escape: `api%2Eanthropic%2Ecom` and
 *   `api。anthropic。com` both parse to `api.anthropic.com` (the parser percent-decodes and applies
 *   IDNA), and a check that only compared the parsed host would allow a URL whose text says
 *   something else;
 * - userinfo (`user:pass@`) is refused, so `https://api.anthropic.com@evil.example/` and
 *   `https://evil.example@api.anthropic.com/` both fail;
 * - a fragment (`#`) is refused: it is never sent, so a URL with one is not the URL that was checked;
 * - the port must be absent or 443 (the parser drops `:443` and `:0443`, so `url.port` is empty for
 *   both; any other port is refused);
 * - IPv6 literals can never match a vendor host, so they are refused as unknown hosts.
 *
 * Parsing is the platform's `URL` class (`SPEC_URL`), not this package's own: the string given to
 * `fetch` is the string checked here, and the only parser that guarantees that is the one the
 * runtime uses.
 */
import { refusal, type Refusal } from "./refusal.ts";
import { OPENAI_COMPATIBLE_VENDORS, type OpenAiCompatibleVendorId } from "./vendors.ts";

/** The lane's vendors: the three of its early scope (owner decision) and the OpenAI-compatible table's. */
export type OfficialVendor = "anthropic" | "openai" | "chatgpt" | OpenAiCompatibleVendorId;

/** A URL that may be sent to: the official origin, its vendor, and the URL to use. */
export interface OfficialOrigin {
  readonly ok: true;
  readonly vendor: OfficialVendor;
  readonly host: string;
  readonly url: string;
}

/** Why a URL is not an official origin. One code per kind of trick, never a guess. */
export type OriginRefusalCode =
  | "not_a_url"
  | "control_character"
  | "backslash"
  | "scheme"
  | "authority_encoding"
  | "invalid_url"
  | "userinfo"
  | "fragment"
  | "port"
  | "trailing_dot"
  | "unknown_host"
  | "path";

/** The origins of the lane, by host. The only hosts a lane request may reach. */
const VENDORS: Readonly<Record<string, { readonly vendor: OfficialVendor; readonly pathPrefix: string }>> = Object.freeze({
  "api.anthropic.com": { vendor: "anthropic", pathPrefix: "/v1/" },
  "api.openai.com": { vendor: "openai", pathPrefix: "/v1/" },
  "chatgpt.com": { vendor: "chatgpt", pathPrefix: "/backend-api/codex/" },
  ...Object.fromEntries(OPENAI_COMPATIBLE_VENDORS.map((v) => [v.host, { vendor: v.id, pathPrefix: v.pathPrefix }])),
});

/** Space, the C0 controls and DEL: characters the URL parser strips or encodes rather than keeps. */
const CONTROL_OR_SPACE = /[\u0000-\u0020\u007f]/;

/** Anything outside printable ASCII: refused in the authority (a host is compared as written). */
const NON_ASCII = /[^\u0021-\u007e]/;

/**
 * Check that `url` names an official vendor origin, as rule A requires. Total: any string answers
 * with the origin or with a refusal, and nothing is thrown.
 */
export function checkOfficialUpstream(url: string): OfficialOrigin | Refusal<OriginRefusalCode> {
  if (typeof url !== "string" || url.length === 0) return refusal("not_a_url", "the upstream URL is not a non-empty string");
  if (CONTROL_OR_SPACE.test(url)) {
    return refusal("control_character", "the upstream URL holds a space, a control character or a tab; the parser would strip or re-encode it");
  }
  if (url.includes("\\")) {
    return refusal("backslash", "the upstream URL holds a backslash, which some readers treat as a path separator and others as part of the host");
  }
  if (!/^https:\/\//i.test(url)) {
    return refusal("scheme", "the upstream URL does not start with https://");
  }
  const authority = url.slice("https://".length).split(/[/?#]/, 1)[0] ?? "";
  if (authority.length === 0) return refusal("invalid_url", "the upstream URL has no host");
  if (authority.includes("%") || NON_ASCII.test(authority)) {
    return refusal("authority_encoding", "the host is percent-encoded or not plain ASCII, so its text and the parsed host differ");
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return refusal("invalid_url", "the upstream URL does not parse");
  }

  if (parsed.username !== "" || parsed.password !== "" || authority.includes("@")) {
    return refusal("userinfo", "the upstream URL carries user information before the host");
  }
  if (parsed.hash !== "" || url.includes("#")) return refusal("fragment", "the upstream URL carries a fragment");
  if (parsed.protocol !== "https:") return refusal("scheme", "the upstream URL is not https");
  if (parsed.port !== "") return refusal("port", "the upstream URL names a port other than 443");
  if (parsed.hostname.endsWith(".")) return refusal("trailing_dot", "the host ends with a dot");
  const vendor = Object.hasOwn(VENDORS, parsed.hostname) ? VENDORS[parsed.hostname] : undefined;
  if (vendor === undefined) return refusal("unknown_host", "the host is not one of the lane's official vendor hosts");
  if (!parsed.pathname.startsWith(vendor.pathPrefix)) {
    return refusal("path", `the path is not under the vendor's ${vendor.pathPrefix}`);
  }
  return { ok: true, vendor: vendor.vendor, host: parsed.hostname, url: parsed.href };
}
