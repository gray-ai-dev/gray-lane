/// <reference path="./node.d.ts" />
import { createHash } from "node:crypto";

/**
 * Where a request's content goes in the content bucket and whose identity seals it
 * (docs/cloudflare-native/content.md 2.2 and 3.3).
 *
 * Scopes: `workspace:<id>` for a request whose workspace is known (a usable key, or a revoked or
 * expired one: then the object goes under `anon/v3/w/`, which the bucket expires after 30 days), and
 * `anonymous` for a request whose workspace is not (no key, an unknown key).
 *
 * The base key `B` of a request: `content/v3/{segment}/{yyyy}/{mm}/{dd}/{HHMMSSmmm}-{request}`, or
 * `anon/v3/w/{segment}/...`, or `anon/v3/a/{yyyy}/{mm}/{dd}/{HHMMSSmmm}-{request}`, the date and time
 * those of the request's start, UTC. Its pieces are `B.p000001`, `B.p000002`, ...; the tail object is
 * `B` itself, written last. A request id is 32 hex digits, so the prefix `B` lists that request's
 * objects and no other's, and a deletion by prefix takes the pieces with the tail.
 */

export const ANONYMOUS = "anonymous";

export type ContentScope = { readonly kind: "workspace"; readonly id: string } | { readonly kind: "anonymous" };

/** `workspace:<id>` or `anonymous`. */
export function scopeLabel(scope: ContentScope): string {
  return scope.kind === "workspace" ? `workspace:${scope.id}` : ANONYMOUS;
}

/** A scope label read back; null for anything else. */
export function parseScope(label: string): ContentScope | null {
  if (label === ANONYMOUS) return { kind: "anonymous" };
  if (label.startsWith("workspace:") && label.length > "workspace:".length) return { kind: "workspace", id: label.slice("workspace:".length) };
  return null;
}

/**
 * Where the object goes: under `content/v3/` (sealed to the workspace, a usable key), `anon/v3/w/`
 * (sealed to the workspace, a revoked or expired key: expired by the bucket after 30 days) or
 * `anon/v3/a/` (sealed to the anonymous scope).
 */
export type Placement = { readonly kind: "workspace"; readonly workspace: string } | { readonly kind: "revoked"; readonly workspace: string } | { readonly kind: "anonymous" };

/** The scope that seals a placement. */
export function placementScope(p: Placement): ContentScope {
  return p.kind === "anonymous" ? { kind: "anonymous" } : { kind: "workspace", id: p.workspace };
}

const utf8 = new TextEncoder();

/**
 * crates/gray-gateway/src/request_log/content.rs `segment`: a workspace id as one key segment, or
 * `h-` and 40 hex digits of its SHA-256 when it is not a plain one, so no id reaches into another
 * prefix. The same rule the console's deletions use (workers/console/src/control/workspaces.ts).
 */
export function segment(workspace: string): string {
  const plain = workspace !== "" && utf8.encode(workspace).length <= 128 && /^[A-Za-z0-9_-]+$/.test(workspace);
  if (plain) return workspace;
  return `h-${createHash("sha256").update(workspace, "utf8").digest("hex").slice(0, 40)}`;
}

const pad = (n: number, width: number) => String(n).padStart(width, "0");

/** yyyymmdd of `ms`, UTC. */
export function utcDay(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

/** yyyymm of `ms`, UTC. */
export function utcMonth(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 100 + d.getUTCMonth() + 1;
}

/** The first ms of a yyyymmdd day, UTC. */
export function dayStartMs(day: number): number {
  return Date.UTC(Math.floor(day / 10000), (Math.floor(day / 100) % 100) - 1, day % 100);
}

/** The yyyymmdd `n` days after `day` (before, for a negative `n`). */
export function addDays(day: number, n: number): number {
  return utcDay(dayStartMs(day) + n * 86_400_000);
}

/** `yyyy/mm/dd` of a day. */
export function dayPath(day: number): string {
  return `${pad(Math.floor(day / 10000), 4)}/${pad(Math.floor(day / 100) % 100, 2)}/${pad(day % 100, 2)}`;
}

const REQUEST_ID = /^[0-9a-f]{32}$/;

/** The base key `B` of a request (see above). The request id must be the gateway's: 32 lowercase hex digits. */
export function objectKey(placement: Placement, startedMs: number, requestId: string): string {
  if (!REQUEST_ID.test(requestId)) throw new RangeError("a content key needs a request id of 32 lowercase hex digits");
  const d = new Date(startedMs);
  const time = `${pad(d.getUTCHours(), 2)}${pad(d.getUTCMinutes(), 2)}${pad(d.getUTCSeconds(), 2)}${pad(d.getUTCMilliseconds(), 3)}`;
  return `${dayPrefix(placement, utcDay(startedMs))}${time}-${requestId}`;
}

/** The prefix of a placement's objects of one day. */
export function dayPrefix(placement: Placement, day: number): string {
  switch (placement.kind) {
    case "workspace":
      return `content/v3/${segment(placement.workspace)}/${dayPath(day)}/`;
    case "revoked":
      return `anon/v3/w/${segment(placement.workspace)}/${dayPath(day)}/`;
    case "anonymous":
      return `anon/v3/a/${dayPath(day)}/`;
  }
}

/** The prefix of a placement's objects of one month (yyyymm). */
export function monthPrefix(placement: Placement, month: number): string {
  const dir = `${pad(Math.floor(month / 100), 4)}/${pad(month % 100, 2)}/`;
  switch (placement.kind) {
    case "workspace":
      return `content/v3/${segment(placement.workspace)}/${dir}`;
    case "revoked":
      return `anon/v3/w/${segment(placement.workspace)}/${dir}`;
    case "anonymous":
      return `anon/v3/a/${dir}`;
  }
}

/** Every prefix a workspace's content objects are under: sealed to it with a usable key, and with a revoked or expired one. */
export function workspacePrefixes(workspace: string): readonly [string, string] {
  const s = segment(workspace);
  return [`content/v3/${s}/`, `anon/v3/w/${s}/`];
}

/** The key of piece `n` (from 1) of the object whose base key is `base`. */
export function pieceKey(base: string, n: number): string {
  if (!Number.isSafeInteger(n) || n < 1 || n > 999_999) throw new RangeError(`piece ${n} is out of range`);
  return `${base}.p${pad(n, 6)}`;
}

/**
 * What a base key says of itself (content.md 4.5): the placement's prefix, the day and the start time
 * of the request, and its id. Null for a key that is not a GRC3 base key.
 */
export function parseObjectKey(key: string): { readonly prefix: "content/v3/" | "anon/v3/w/" | "anon/v3/a/"; readonly segment: string | null; readonly day: number; readonly startedMs: number; readonly requestId: string } | null {
  const m = /^(content\/v3\/|anon\/v3\/w\/|anon\/v3\/a\/)(?:([A-Za-z0-9_-]+)\/)?(\d{4})\/(\d{2})\/(\d{2})\/(\d{2})(\d{2})(\d{2})(\d{3})-([0-9a-f]{32})$/.exec(key);
  if (m === null) return null;
  const prefix = m[1] as "content/v3/" | "anon/v3/w/" | "anon/v3/a/";
  const seg = m[2] ?? null;
  if ((prefix === "anon/v3/a/") !== (seg === null)) return null;
  const [y, mo, d, h, mi, s, ms] = [m[3], m[4], m[5], m[6], m[7], m[8], m[9]].map(Number) as [number, number, number, number, number, number, number];
  const startedMs = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  const day = y * 10000 + mo * 100 + d;
  if (utcDay(startedMs) !== day || new Date(startedMs).getUTCHours() !== h || new Date(startedMs).getUTCMinutes() !== mi || new Date(startedMs).getUTCSeconds() !== s) return null;
  return { prefix, segment: seg, day, startedMs, requestId: m[10]! };
}

/** `<scope>/<day>/<generation>`: one identity, never reused (content.md 2.2). */
export function identityKeyId(scope: string, day: number, generation: number): string {
  return `${scope}/${day}/${generation}`;
}
