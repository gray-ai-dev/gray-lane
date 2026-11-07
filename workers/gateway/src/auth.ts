import { ApiError } from "@gray/errors";
import type { KeyRecord } from "./snapshot.ts";

/**
 * The API key a request presents, and what the key snapshot says about it
 * (crates/gray-gateway/src/inference.rs `presented_key`, `authenticate`, `key_refusal`,
 * `key_state`). The key itself is never stored or logged: the snapshot is keyed by its SHA-256.
 */

/** How every Gray API key token starts (`gray_control::create_api_key`). */
export const GRAY_KEY_PREFIX = "gray_key_";

export type KeyScheme = "bearer" | "x-api-key" | "x-goog-api-key";

export interface PresentedKey {
  readonly token: string;
  readonly scheme: KeyScheme;
}

function header(headers: Headers, name: string): string | undefined {
  const value = headers.get(name)?.trim();
  return value === undefined || value === "" ? undefined : value;
}

/**
 * `presented_key`: `Authorization: Bearer <key>` (the scheme in any case), else `x-api-key`, else
 * `x-goog-api-key`. A Bearer token that is not a Gray key gives way to a Gray key in `x-api-key`
 * (Claude Code sends a leftover `ANTHROPIC_AUTH_TOKEN` as the Bearer token beside its key helper's
 * Gray key). An `Authorization` header that is not a bearer key is refused only when no other key
 * header is present.
 */
export function presentedKey(headers: Headers): PresentedKey | ApiError {
  const authorization = header(headers, "authorization");
  let bearer: string | undefined;
  if (authorization !== undefined) {
    const at = authorization.search(/\s/);
    if (at > 0) {
      const scheme = authorization.slice(0, at);
      const token = authorization.slice(at + 1).trim();
      if (scheme.toLowerCase() === "bearer" && token !== "" && !token.includes(" ")) bearer = token;
    }
  }
  const apiKey = header(headers, "x-api-key");
  if (bearer !== undefined && apiKey !== undefined && !bearer.startsWith(GRAY_KEY_PREFIX) && apiKey.startsWith(GRAY_KEY_PREFIX)) {
    return { token: apiKey, scheme: "x-api-key" };
  }
  if (bearer !== undefined) return { token: bearer, scheme: "bearer" };
  if (apiKey !== undefined) return { token: apiKey, scheme: "x-api-key" };
  const goog = header(headers, "x-goog-api-key");
  if (goog !== undefined) return { token: goog, scheme: "x-goog-api-key" };
  return new ApiError(401, authorization !== undefined ? "malformed_authorization_header" : "missing_api_key");
}

const encoder = new TextEncoder();

/** The snapshot's key for a token: lowercase hex SHA-256 of its bytes, as the server's `authenticate`. */
export async function keyHash(token: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(token)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

/**
 * `key_state`: why a known key may not send requests at `nowSeconds`, checked in the server's
 * order: held by a Viewer, revoked, disabled, expired. Null when it may.
 */
export function keyRefusal(key: KeyRecord, nowSeconds: number): ApiError | null {
  if (key.viewer) return new ApiError(403, "api_key_owner_viewer");
  if (key.revoked) return new ApiError(401, "api_key_revoked");
  if (key.disabled) return new ApiError(401, "api_key_disabled");
  if (key.expiresAt !== null && key.expiresAt <= nowSeconds) {
    const at = new Date(key.expiresAt * 1000);
    const valid = !Number.isNaN(at.getTime());
    // chrono's `%Y-%m-%d %H:%M UTC` and `to_rfc3339` (`+00:00`, whole seconds).
    const date = valid ? `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())} ${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())} UTC` : String(key.expiresAt);
    const rfc3339 = valid ? `${at.toISOString().slice(0, 19)}+00:00` : null;
    return new ApiError(401, "api_key_expired").withMessage(`This API key expired on ${date}. Create a new key.`).withMeta("expired_at", rfc3339);
  }
  return null;
}

/** The key's model scope: an empty list allows every model. */
export function modelScopeRefusal(key: KeyRecord, model: string): ApiError | null {
  if (key.models.length === 0 || key.models.includes(model)) return null;
  return new ApiError(403, "model_scope_denied").withMessage(
    `This API key may not call \`${model}\`; its model scope allows only: ${key.models.join(", ")}. Use a key whose scope includes the model, or change this key's scope.`,
  );
}
