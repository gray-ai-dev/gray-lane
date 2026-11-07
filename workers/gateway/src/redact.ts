/// <reference path="../../packages/content/src/node.d.ts" />
import { createHash } from "node:crypto";
import { parsePlain } from "@gray/json";

/**
 * Headers and queries as the request content's details keep them (crates/gray-gateway/src/
 * request_log/client.rs `headers`, `query`, `fingerprint`; docs/design/request-logs.md 68-97;
 * docs/cloudflare-native/content.md 3.1 step 6): every header in order, a credential replaced by a
 * redaction marker and a short keyed fingerprint, so requests with one key can be told apart and the
 * key never stored. A credential is recognised twice over, by the words of its name and by the shape
 * of its value, as the server does; the rules here are the server's, ported as written.
 *
 * The fingerprint key is the server's: SHA-256("gray.request-log.fingerprint-key.v1\0" ‖ master key),
 * derived offline and given to the gateway as REQUEST_LOG_FINGERPRINT_KEY (content.md 2.2). It opens
 * nothing; without it a credential is stored as a bare marker.
 */

/** Words that mark a header or a query parameter as a credential's, wherever they stand in its name (client.rs CREDENTIAL_WORDS). */
const CREDENTIAL_WORDS = new Set([
  "auth",
  "authorization",
  "authentication",
  "apikey",
  "key",
  "token",
  "secret",
  "password",
  "passwd",
  "credential",
  "credentials",
  "cookie",
  "signature",
  "sig",
  "jwt",
  "bearer",
  "assertion",
  "passphrase",
]);
/** Names those words catch that hold no credential and that the log needs as sent (client.rs NOT_CREDENTIALS). */
const NOT_CREDENTIALS = new Set(["idempotency-key", "sec-websocket-key", "x-gray-key-limit-reset"]);
/** Header prefixes of credentials no word marks: Cloudflare Access service tokens. */
const CREDENTIAL_HEADER_PREFIXES = ["cf-access-"];
/** Query parameters that are credentials without a word: OAuth's authorization `code`. */
const CREDENTIAL_QUERY_KEYS = new Set(["code"]);
/** Headers that carry a challenge in a credential's syntax (RFC 9110 11.3). */
const CHALLENGE_HEADERS = new Set(["www-authenticate", "proxy-authenticate"]);
/** Longest stored header value (client.rs MAX_HEADER_VALUE). */
export const MAX_HEADER_VALUE = 8 * 1024;

/** Gray's own credential prefixes (inference.rs GRAY_KEY_PREFIX, provider_setup.rs TOKEN_PREFIX and CODE_PREFIX, setup_codes.rs CODE_PREFIX). */
const GRAY_KEY_PREFIX = "gray_key_";
const PROVIDER_TOKEN_PREFIX = "gray_pst_";
const CUSTOMER_CODE_PREFIX = "GSC";
const PROVIDER_CODE_PREFIX = "GPC";

/**
 * client.rs CREDENTIAL_SHAPE, as two patterns: the scheme form is case-insensitive there (`(?i:...)`)
 * and the rest is not, which one JavaScript pattern cannot say on its own.
 */
const TOKEN68 = "[A-Za-z0-9._~+/-]{16,}=*";
const PARAMS = "[A-Za-z0-9!#$%&'*+.^_`|~-]+[ \\t]*=[ \\t]*[^ \\t].*";
const SCHEMES = "basic|bearer|concealed|digest|dpop|gnap|hoba|mutual|negotiate|ntlm|oauth|privatetoken|scram-sha-1|scram-sha-256|vapid|aws4-hmac-sha256";
const SCHEME_SHAPE = new RegExp(`^[ \\t]*(?:${SCHEMES})[ \\t]+(?:${TOKEN68}|${PARAMS})[ \\t]*$`, "i");
const VALUE_SHAPE = new RegExp(
  `\\b${GRAY_KEY_PREFIX}|\\b${PROVIDER_TOKEN_PREFIX}|\\b(?:${CUSTOMER_CODE_PREFIX}|${PROVIDER_CODE_PREFIX})(?:-[0-9A-Za-z]{4}){3}\\b|\\bsk-[A-Za-z0-9_-]{20,}|\\bAIza[0-9A-Za-z_-]{35}`,
);
/** Three base64url parts that may be a compact JWS (client.rs JWS_SHAPE). */
const JWS_SHAPE = /\b(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

function base64urlText(part: string): string | null {
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** A JSON Web Token: three base64url parts whose first decodes to a JSON object naming its `alg` (client.rs `jws`). */
function jws(value: string): boolean {
  for (const m of value.matchAll(JWS_SHAPE)) {
    const text = base64urlText(m[1]!);
    if (text === null) continue;
    try {
      const header = parsePlain(text);
      if (header !== null && typeof header === "object" && typeof (header as { alg?: unknown }).alg === "string") return true;
    } catch {
      // Not JSON: not a JOSE header.
    }
  }
  return false;
}

function credentialShaped(value: string): boolean {
  return SCHEME_SHAPE.test(value) || VALUE_SHAPE.test(value) || jws(value);
}

function credentialNamed(name: string): boolean {
  return !NOT_CREDENTIALS.has(name) && name.split(/[^A-Za-z0-9]/).some((word) => CREDENTIAL_WORDS.has(word));
}

function credentialHeader(name: string): boolean {
  return credentialNamed(name) || CREDENTIAL_HEADER_PREFIXES.some((p) => name.startsWith(p));
}

const utf8 = new TextEncoder();
const lenient = new TextDecoder();

/** client.rs `fingerprint`: 12 hex digits of SHA-256("gray.request-log.fingerprint.v1\0" ‖ key ‖ value). */
export function fingerprint(key: Uint8Array, value: string): string {
  return createHash("sha256").update("gray.request-log.fingerprint.v1\0").update(key).update(value, "utf8").digest("hex").slice(0, 12);
}

/** The marker stored instead of a credential; an Authorization value keeps its scheme (client.rs `redacted`). */
function redacted(key: Uint8Array | null, name: string, value: string): string {
  let scheme: string | null = null;
  if (name === "authorization" || name === "proxy-authorization") {
    const at = value.indexOf(" ");
    const s = at > 0 ? value.slice(0, at) : "";
    if (s.length > 0 && s.length <= 32 && /^[A-Za-z0-9]+$/.test(s)) scheme = s;
  }
  const marker = key === null ? "[redacted]" : `[redacted ${fingerprint(key, value)}]`;
  return scheme === null ? marker : `${scheme} ${marker}`;
}

/** `value` cut at a character boundary to at most `limit` UTF-8 bytes. */
function bounded(value: string, limit: number): string {
  const bytes = utf8.encode(value);
  if (bytes.length <= limit) return value;
  let end = limit;
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return lenient.decode(bytes.subarray(0, end));
}

/** Every header in order (lower-case names, as Headers gives them), credentials redacted, long values cut (client.rs `headers`). */
export function redactedHeaders(key: Uint8Array | null, headers: Headers): [string, string][] {
  const out: [string, string][] = [];
  headers.forEach((value, name) => {
    const credential = credentialHeader(name) || (!CHALLENGE_HEADERS.has(name) && credentialShaped(value));
    out.push([name, credential ? redacted(key, name, value) : bounded(value, MAX_HEADER_VALUE)]);
  });
  return out;
}

/** The query with credential parameters redacted, by name or by the shape of their value; null without a query (client.rs `query`). */
export function redactedQuery(key: Uint8Array | null, query: string | null): string | null {
  if (query === null || query === "") return null;
  const out = new URLSearchParams();
  for (const [name, value] of new URLSearchParams(query)) {
    const lower = name.toLowerCase();
    out.append(name, credentialNamed(lower) || CREDENTIAL_QUERY_KEYS.has(lower) || credentialShaped(value) ? redacted(key, "", value) : value);
  }
  return out.toString();
}

/** REQUEST_LOG_FINGERPRINT_KEY: 64 hex digits; null when unset or not that. */
export function fingerprintKey(secret: string | undefined): Uint8Array | null {
  const text = secret?.trim() ?? "";
  if (!/^[0-9a-fA-F]{64}$/.test(text)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}
