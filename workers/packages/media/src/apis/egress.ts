/**
 * Fetching what a vendor hands back by URL (an image result, a video file): without credentials,
 * redirects followed by hand and each hop vetted again, bounded in size and time
 * (crates/gray-gateway/src/apis/images.rs `download`, apis/video/content.rs).
 *
 * The server version resolves and pins every hop's addresses to public networks. A Worker cannot
 * choose addresses (docs/cloudflare-native.md section 7), so a hop is vetted by URL instead: https
 * only, no credentials in it, no IP literal, no host on Gray's own zones; the gateway runs with
 * `global_fetch_strictly_public`. `allowPrivate` (http and IP literals) exists for local tests and
 * development only, as the server's `allow_private_upstreams` outside production.
 */
import { ApiError } from "@gray/errors";

export interface EgressPolicy {
  /** http and IP-literal hosts are taken: local development and tests only. */
  readonly allowPrivate: boolean;
  /** Gray's own zones (`usefallback.com`): a URL on one, or under one, is never fetched. */
  readonly ownZones: readonly string[];
}

/** A host the WHATWG URL parser wrote as an IP address: dotted-quad IPv4 (every IPv4 form is normalised to it) or bracketed IPv6. */
function ipLiteral(hostname: string): boolean {
  return hostname.startsWith("[") || /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostname);
}

/**
 * `upstream_url` for a fetched URL: https (http only with `allowPrivate`), no user name or password,
 * no IP literal (unless `allowPrivate`), no host on Gray's own zones. Undefined when refused.
 */
export function vetUrl(raw: string, policy: EgressPolicy): URL | undefined {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.username !== "" || url.password !== "") return undefined;
  if (url.protocol !== "https:" && !(policy.allowPrivate && url.protocol === "http:")) return undefined;
  const host = url.hostname.toLowerCase();
  if (!policy.allowPrivate && ipLiteral(host)) return undefined;
  if (policy.ownZones.some((zone) => host === zone || host.endsWith(`.${zone}`))) return undefined;
  return url;
}

/** `is_image`: PNG, JPEG or WebP by signature. */
export function isImage(bytes: Uint8Array): boolean {
  const starts = (sig: readonly number[]) => sig.every((b, i) => bytes[i] === b);
  return (
    starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) ||
    starts([0xff, 0xd8, 0xff]) ||
    (bytes.length >= 12 && starts([0x52, 0x49, 0x46, 0x46]) && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50)
  );
}

/**
 * `is_inline_image`: an inline image held to the rule a downloaded one meets. Its first 16
 * characters, decoded as standard base64 with canonical padding (bits past the last byte left
 * unchecked, as Rust's engine is configured), carry a PNG, JPEG or WebP signature. A data URI,
 * URL-safe base64, a GIF or text is no image. The decode is the platform's `atob` (WHATWG
 * forgiving-base64, which ignores trailing bits) after the alphabet and padding checks Rust makes.
 */
export function isInlineImage(b64: string): boolean {
  if (b64.length < 16) return false;
  const head = b64.slice(0, 16);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(head)) return false;
  let binary: string;
  try {
    binary = atob(head);
  } catch {
    return false;
  }
  return isImage(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

/** Standard base64 with padding of `bytes` (the platform's `btoa`). */
export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}

/** The fetch the gateway sends on: the platform's, or a test's. */
export type Fetcher = (input: Request) => Promise<Response>;

/** What is left of one answer's download budget (`DOWNLOAD_LIMIT`), shared by its images. */
export interface Budget {
  remaining: number;
}

const unavailable = () => new ApiError(502, "upstream_media_unavailable");
const tooLarge = () => new ApiError(502, "upstream_media_too_large");

/** Milliseconds left before `deadlineMs`, at least 1 so a timer can fire. */
function left(deadlineMs: number): number {
  return Math.max(1, deadlineMs - Date.now());
}

/**
 * Reads a whole body within `limit` bytes before `deadlineMs`. Undefined when the body is over the
 * limit (announced or not); throws `upstream_media_unavailable` on a read failure or the deadline.
 */
export async function readCapped(response: Response, limit: number, deadlineMs: number): Promise<Uint8Array | undefined> {
  const length = response.headers.get("content-length");
  if (length !== null && /^[0-9]+$/.test(length) && Number(length) > limit) {
    await response.body?.cancel();
    return undefined;
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<"expired">((resolve) => {
    timer = setTimeout(() => resolve("expired"), left(deadlineMs));
  });
  try {
    for (;;) {
      const next = await Promise.race([reader.read(), expired]);
      if (next === "expired") {
        await reader.cancel().catch(() => {});
        throw unavailable();
      }
      if (next.done) break;
      if (next.value.length > limit - total) {
        await reader.cancel().catch(() => {});
        return undefined;
      }
      chunks.push(next.value);
      total += next.value.length;
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw unavailable();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/**
 * `download`: one image fetched without credentials. Every hop is vetted (`vetUrl`), at most
 * `maxRedirects` redirects are followed, the bytes count against `budget`, and the result must be
 * a PNG, JPEG or WebP image. Codes: `upstream_media_unavailable`, `upstream_media_too_large`,
 * `invalid_upstream_response` (not an image).
 */
export async function downloadImage(
  fetcher: Fetcher,
  raw: string,
  policy: EgressPolicy,
  budget: Budget,
  deadlineMs: number,
  maxRedirects: number,
): Promise<Uint8Array> {
  let target: URL | undefined;
  try {
    target = new URL(raw);
  } catch {
    throw unavailable();
  }
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const vetted = vetUrl(target.toString(), policy);
    if (vetted === undefined) throw unavailable();
    let response: Response;
    try {
      response = await fetcher(new Request(vetted.toString(), { method: "GET", redirect: "manual", signal: AbortSignal.timeout(left(deadlineMs)) }));
    } catch {
      throw unavailable();
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (location === null) throw unavailable();
      try {
        target = new URL(location, vetted);
      } catch {
        throw unavailable();
      }
      continue;
    }
    if (response.status < 200 || response.status >= 300) {
      await response.body?.cancel();
      throw unavailable();
    }
    const bytes = await readCapped(response, budget.remaining, deadlineMs);
    if (bytes === undefined) throw tooLarge();
    if (!isImage(bytes)) throw new ApiError(502, "invalid_upstream_response");
    budget.remaining -= bytes.length;
    return bytes;
  }
  throw unavailable();
}
