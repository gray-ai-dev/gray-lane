import {
  assertCredentialFormat,
  chatgptTokenClaims,
  credentialClass,
  isCredentialExpired,
  type Credential,
  type Vendor,
} from "./credential.ts";
import type { EgressSpec } from "./egress.ts";
import { RelayConnectorError } from "./errors.ts";

/**
 * The auth headers each official API expects for one credential class. These are the *only* bytes
 * this package ever derives from a secret, and the returned object has no other member: there is no
 * `value`, no `credential`, no getter.
 *
 * Sources (read 2026-10-21):
 * - Anthropic API keys: `x-api-key` is still supported in place of `Authorization: Bearer`
 *   (docs.anthropic.com/en/manage-claude/authentication). The task and PAG both use this legacy
 *   header for API keys, so it is kept and tested; `anthropic-version: 2023-06-01` is the version
 *   the API overview's request table requires. OAuth access tokens use Bearer instead (below).
 * - Anthropic OAuth access tokens: `Authorization: Bearer <token>` plus the official TypeScript
 *   SDK's `OAUTH_API_BETA_HEADER = "oauth-2025-04-20"`, documented there as "required on
 *   authenticated API requests using an OAuth bearer token"; the version header is still required.
 * - OpenAI API keys: `Authorization: Bearer <key>` (openai/openai-openapi `ApiKeyAuth`).
 * - ChatGPT/Codex OAuth: `Authorization: Bearer <JWT>`, `chatgpt-account-id` from the JWT's
 *   `https://api.openai.com/auth.chatgpt_account_id` claim, and `originator: codex_cli_rs`, the
 *   Codex CLI's default originator that its backend requests carry
 *   (github.com/openai/codex, `codex-rs/login/src/auth/default_client.rs`,
 *   `codex-rs/login/src/token_data.rs`, `codex-rs/core/tests/suite/client.rs`). Gray identifies
 *   itself with that client value because ChatGPT's Codex backend is a private API defined by that
 *   client.
 *
 * Still open (documented, not sent): Codex's normal backend request also carries `session-id` and
 * `thread-id` (`codex-api/src/requests/headers.rs`) and the WebSocket variant adds `OpenAI-Beta`.
 * They are telemetry rather than authentication as far as the public sources show, but no source
 * proves the backend never requires them; a relay that needs them must say so, and they would be
 * non-secret per-request values rather than part of the sealed bundle (F14). The
 * `chatgpt-account-id` value comes from the access token's
 * `https://api.openai.com/auth.chatgpt_account_id` claim; a real token without that claim is
 * refused, and a non-secret `account_id` bundle field/fallback is the open question (F14).
 */

/** The Anthropic API version every Messages request names. */
export const ANTHROPIC_VERSION = "2023-06-01";

/** The beta header the official Anthropic SDK attaches to an OAuth bearer token. */
export const ANTHROPIC_OAUTH_BETA = "oauth-2025-04-20";

/** The `originator` value Codex CLI sends; see the module comment. */
export const CHATGPT_CODEX_ORIGINATOR = "codex_cli_rs";

/**
 * What `upstreamAuth` returns: the auth headers (nothing that can recover the secret) and, when the
 * account declared one, its egress proxy. The proxy is not a credential and is never named in a
 * receipt, a record, a log line or a bridge call; `laneFetch` puts it in one sidecar header.
 */
export interface UpstreamAuth {
  readonly headers: Readonly<Record<string, string>>;
  readonly egress?: EgressSpec;
}

/**
 * Build the auth headers for one stored credential. Refuses an expired credential
 * (`credential_expired`) and a value that no longer matches its vendor's class
 * (`invalid_credential`), so a stored-but-broken secret never reaches a request builder.
 */
export function upstreamHeaders(vendor: Vendor, credential: Credential, nowMs: number): UpstreamAuth {
  // The format check runs first (inside `authHeaders`): the expiry of a value of the wrong class means nothing.
  const headers = authHeaders(vendor, credential);
  const nowSecs = BigInt(Math.floor(nowMs / 1000));
  if (isCredentialExpired(credential, nowSecs)) throw new RelayConnectorError("credential_expired");
  return Object.freeze({ headers });
}

/**
 * The header form of one credential class, whatever the clock says: what `upstreamHeaders` sends,
 * without its expiry refusal. A relay stack's container sends exactly these headers for the account
 * (docs/confidential-lane-supply-implementation.md §8), and egress recognises the account by the
 * SHA-256 of their auth value (S15), so the entry's account table is computed from this one form.
 * Refuses a value that does not match its vendor's class (`invalid_credential`).
 */
export function authHeaders(vendor: Vendor, credential: Credential): Readonly<Record<string, string>> {
  assertCredentialFormat(vendor, credential);
  const klass = credentialClass(vendor, credential.type);
  const headers: Record<string, string> = {};
  switch (klass) {
    case "anthropic_api_key":
      headers["x-api-key"] = credential.value;
      headers["anthropic-version"] = ANTHROPIC_VERSION;
      break;
    case "anthropic_oauth_access_token":
      headers["authorization"] = `Bearer ${credential.value}`;
      headers["anthropic-version"] = ANTHROPIC_VERSION;
      headers["anthropic-beta"] = ANTHROPIC_OAUTH_BETA;
      break;
    case "openai_api_key":
    case "openai_compatible_api_key":
      headers["authorization"] = `Bearer ${credential.value}`;
      break;
    case "chatgpt_codex_oauth_access_token":
      headers["authorization"] = `Bearer ${credential.value}`;
      headers["chatgpt-account-id"] = chatgptTokenClaims(credential.value).accountId;
      headers["originator"] = CHATGPT_CODEX_ORIGINATOR;
      break;
    // A password signs in; it is never sent as an auth header (the account serves with its sign-in's token).
    case "chatgpt_codex_password":
    case "anthropic_password":
    case null:
      throw new RelayConnectorError("invalid_credential", "credential.type");
  }
  return Object.freeze(headers);
}
