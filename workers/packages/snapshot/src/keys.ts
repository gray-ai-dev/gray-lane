/**
 * API keys as the gateway authenticates them: crates/gray-control GatewayAuthRecord, as
 * `gateway_auth_snapshot` reads them, and the gateway's `key_refusal` (crates/gray-gateway/src/
 * inference.rs). The snapshot carries every key, usable or not; whether one may send a request
 * depends on the time (`expires_at`), so the gateway decides it per request with `keyRefusal`.
 */

/** gray_control::Role, by its stored name. An unknown role fails the whole read, as `Role::parse` fails the server's refresh. */
export const ROLES = ["owner", "operator", "viewer", "customer", "provider", "admin"] as const;
export type Role = (typeof ROLES)[number];

export function isRole(v: unknown): v is Role {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v);
}

/**
 * The stored `expires_at` of a key that never expires: 9999-12-31T23:59:59Z in Unix seconds
 * (crates/gray-control/src/lib.rs KEY_NEVER_EXPIRES_AT); `key_expiry` reads it, and NULL, as never.
 */
export const KEY_NEVER_EXPIRES_AT = 253_402_300_799;

export function keyExpiry(stored: number | null): number | null {
  return stored !== null && stored < KEY_NEVER_EXPIRES_AT ? stored : null;
}

/** One key (GatewayAuthRecord). Never expose `tokenHash` in an answer. */
export interface SnapshotKey {
  readonly keyId: string;
  readonly tokenHash: string;
  readonly workspaceId: string;
  readonly userId: string;
  readonly role: Role;
  /** Refused like a revoked key while set. */
  readonly disabled: boolean;
  /** Revoked, or its holder is a Viewer (gateway_auth_snapshot folds that in). */
  readonly revoked: boolean;
  readonly limitMicrousd: number | null;
  readonly limitPeriod: string | null;
  /** This key's routing default, as the stated JSON the gateway parses. */
  readonly routing: string | null;
  readonly models: readonly string[];
  readonly requestsPerMinute: number;
  /** Unix seconds; null for a key that never expires. */
  readonly expiresAt: number | null;
}

export type KeyRefusal = { readonly kind: "viewer" } | { readonly kind: "revoked" } | { readonly kind: "disabled" } | { readonly kind: "expired"; readonly expiresAt: number };

/** `key_refusal`: why a key may not send a request at `atSeconds`, or null. The order is the server's. */
export function keyRefusal(k: SnapshotKey, atSeconds: number): KeyRefusal | null {
  if (k.role === "viewer") return { kind: "viewer" };
  if (k.revoked) return { kind: "revoked" };
  if (k.disabled) return { kind: "disabled" };
  if (k.expiresAt !== null && k.expiresAt <= atSeconds) return { kind: "expired", expiresAt: k.expiresAt };
  return null;
}

/** The error code `key_state` answers a refusal with (ApiError code; the status is 403 for a viewer, 401 otherwise). */
export function keyRefusalCode(r: KeyRefusal): { readonly status: 401 | 403; readonly code: string } {
  switch (r.kind) {
    case "viewer":
      return { status: 403, code: "api_key_owner_viewer" };
    case "revoked":
      return { status: 401, code: "api_key_revoked" };
    case "disabled":
      return { status: 401, code: "api_key_disabled" };
    case "expired":
      return { status: 401, code: "api_key_expired" };
  }
}

/** The key periods (crates/gray-control/src/lib.rs KEY_SPEND_PERIODS); null is `never`. */
const SPEND_PERIODS = new Set(["never", "day", "week", "month"]);

/**
 * What a workspace's account root keeps of a key (@gray/account KeyConfig): refused or not, its
 * requests a minute and its spend limit. A key refused for any reason at `atSeconds` (revoked,
 * disabled, held by a Viewer, expired) is published as revoked, so the shards refuse it at admission
 * whatever an isolate's snapshot says (docs/cloudflare-native.md 4.1: 吊销由账户分片在 admit 时判断).
 *
 * So is a key allowed 0 requests a minute. gray-control refuses 0 when a key is created but stores it
 * on an update (it checks only the upper bound, 10,000), and the server then refuses every request of
 * that key (crates/gray-gateway/src/inference.rs RateWindow::admit: `used >= limit`). @gray/account
 * reads a null rpm as no limit and takes no 0, so the refusal travels as revoked: the key is refused
 * at every shard, with the revoked code where the server answers 429.
 */
export function accountKeyConfig(k: SnapshotKey, atSeconds: number): { readonly keyId: string; readonly revoked: boolean; readonly rpm: number | null; readonly limit: number | null; readonly period: "never" | "day" | "week" | "month" } {
  const period = k.limitPeriod ?? "never";
  return {
    keyId: k.keyId,
    revoked: keyRefusal(k, atSeconds) !== null || k.requestsPerMinute === 0,
    rpm: k.requestsPerMinute > 0 ? k.requestsPerMinute : null,
    limit: k.limitMicrousd,
    period: (SPEND_PERIODS.has(period) ? period : "never") as "never" | "day" | "week" | "month",
  };
}
