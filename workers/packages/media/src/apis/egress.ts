/**
 * Fetching what an upstream hands back by URL (a video file): without credentials, redirects followed
 * by hand and each hop vetted again, bounded in size and time (crates/gray-gateway/src/apis/video/content.rs);
 * and what an inline image must carry.
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

/** A host name as it is compared: lower-case, without any trailing root dots. */
function hostKey(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, "");
}

/**
 * `upstream_url` for a fetched URL: https (http only with `allowPrivate`), no user name or password,
 * no IP literal or localhost (unless `allowPrivate`), no host on Gray's own zones. Undefined when refused.
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
  const host = hostKey(url.hostname);
  if (host === "") return undefined;
  if (!policy.allowPrivate && (host === "localhost" || host.endsWith(".localhost") || ipLiteral(host))) return undefined;
  if (policy.ownZones.map(hostKey).some((zone) => zone !== "" && (host === zone || host.endsWith(`.${zone}`)))) return undefined;
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
 * `is_inline_image`: an image an answer carries inline. Its first 16 characters, decoded as standard
 * base64 with canonical padding (bits past the last byte left unchecked, as Rust's engine is
 * configured), carry a PNG, JPEG or WebP signature (`isImage`). A data URI,
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

const unavailable = () => new ApiError(502, "upstream_media_unavailable");

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
