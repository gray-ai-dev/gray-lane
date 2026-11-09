import { isObject, get, parseStrict, type Json } from "@gray/json";
import { LANE_STACK_VENDORS, isOpenAiCompatibleVendor } from "@gray/lane";
import { RelayConnectorError } from "./errors.ts";

/**
 * Credential format classes for the lane's vendors: the three of the early scope and the OpenAI-compatible table's
 * (`@gray/lane` vendors.ts), and nothing else.
 *
 * A class is a *format* claim, not proof that the secret is live: the relay receives the secret from
 * the account owner and only the vendor can accept or reject it. The TEE checks the class so a
 * bundle cannot put an OAuth token where an API key belongs (whose header would silently differ),
 * and so a malformed paste fails at intake instead of at the upstream.
 *
 * Sources for the shapes and the wire headers:
 * - Anthropic, "Authentication" (docs.anthropic.com/en/manage-claude/authentication, read
 *   2026-10-21): API keys are "Static `sk-ant-api...` secret sent as a bearer token"; the legacy
 *   `x-api-key` header is "still supported in place of Authorization"; `anthropic-version:
 *   2023-06-01` is required on requests (docs.anthropic.com/en/api/overview).
 * - Anthropic OAuth access tokens: the Workload Identity Federation reference
 *   (docs.anthropic.com/en/api/workload-identity-federation, read 2026-10-21) returns a
 *   "short-lived `sk-ant-oat01-...` token" to send as `Authorization: Bearer`. The official
 *   TypeScript SDK's `OAUTH_API_BETA_HEADER` is `oauth-2025-04-20` and its comment calls it
 *   "required on authenticated API requests using an OAuth bearer token"
 *   (github.com/anthropics/anthropic-sdk-typescript, `src/lib/credentials/types.ts`).
 * - OpenAI: `Authorization: Bearer $OPENAI_API_KEY` (openai/openai-openapi `openapi.yaml`,
 *   `securitySchemes.ApiKeyAuth: {type: http, scheme: bearer}` and every example); key values in
 *   that spec are `sk-...`/`sk-admin-...`, and project keys use the same `sk-` prefix.
 * - ChatGPT/Codex: `https://chatgpt.com/backend-api/codex` and the token shape are from the Codex
 *   CLI (github.com/openai/codex, `codex-rs/core/src/client.rs`, `codex-rs/login/src/token_data.rs`,
 *   `codex-rs/login/src/auth/manager.rs`, read 2026-10-21); the access token is a JWT, and every
 *   Codex backend request carries `Authorization: Bearer <access token>`, `chatgpt-account-id`,
 *   and `originator` (asserted on the wire by `codex-rs/core/tests/suite/client.rs`).
 * - OpenAI-compatible vendors (docs/relay-openai-compatible-vendors.md): an API key sent as `Authorization: Bearer`,
 *   the form each vendor's OpenAI-compatible endpoint documents. Their key shapes differ (Google `AIza…`, `sk-…`,
 *   Zhipu's `<id>.<secret>`, `xai-…`), so the class checks the shape they share: 16 or more URL-safe token characters.
 */

export const VENDORS = LANE_STACK_VENDORS;
export type Vendor = (typeof VENDORS)[number];

/**
 * `password` is a ChatGPT or Claude subscription account's sign-in, sealed so the relay's own software signs it in
 * inside the VM (docs/design/relay-in-cvm-login.md): `value` is the password, `username` the sign-in e-mail,
 * `totp_secret` the optional TOTP secret. It is never an auth header: the account serves with the access token that
 * sign-in ends with.
 */
export const CREDENTIAL_TYPES = ["api_key", "oauth_access_token", "password"] as const;
export type CredentialType = (typeof CREDENTIAL_TYPES)[number];

/** The credential class of one `(vendor, type)` pair; the matrix is closed. */
export type CredentialClass =
  | "anthropic_api_key"
  | "anthropic_oauth_access_token"
  | "anthropic_password"
  | "openai_api_key"
  | "chatgpt_codex_oauth_access_token"
  | "chatgpt_codex_password"
  | "openai_compatible_api_key";

/** The longest secret this lane accepts (the largest real JWT is a few kilobytes). */
export const MAX_CREDENTIAL_LENGTH = 8192;

/**
 * A secret as the sealed bundle carries it. `expires_at` is unix seconds when the issuer knows one. `refresh_token`
 * is an access token's refresh token, sealed only for an account egress refreshes inside the VM (`refresh: "gray"`,
 * docs/relay-changes-v2.md §6); the relay's container is never served it.
 */
export interface Credential {
  readonly type: CredentialType;
  readonly value: string;
  readonly expires_at?: bigint;
  readonly refresh_token?: string;
  /** A `password` credential's sign-in e-mail. */
  readonly username?: string;
  /** A `password` credential's TOTP secret: RFC 4648 base32, upper case, no padding (`normalizeTotpSecret`). */
  readonly totp_secret?: string;
}

/** The longest password (UTF-8 bytes) and sign-in e-mail a `password` credential carries; its TOTP secret's bounds in bytes. */
export const MAX_PASSWORD_LENGTH = 1024;
export const MAX_USERNAME_LENGTH = 254;
export const TOTP_SECRET_MIN_BYTES = 10;
export const TOTP_SECRET_MAX_BYTES = 64;

/**
 * A TOTP secret as an authenticator app shows it, in the sealed form: spaces and `=` padding dropped, upper case. Null
 * when what is left is not RFC 4648 base32 of 10 to 64 bytes (an `otpauth://` URI's `secret` parameter is the text to
 * give).
 */
export function normalizeTotpSecret(text: string): string | null {
  const secret = text.replace(/[\s=]/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(secret) || ![0, 2, 4, 5, 7].includes(secret.length % 8)) return null;
  const bytes = Math.floor((secret.length * 5) / 8);
  return bytes >= TOTP_SECRET_MIN_BYTES && bytes <= TOTP_SECRET_MAX_BYTES ? secret : null;
}

/** A sign-in e-mail: printable ASCII without a space, exactly one `@`, with text on both sides. */
const USERNAME = /^[\x21-\x3f\x41-\x7e]+@[\x21-\x3f\x41-\x7e]+$/;

function assertPasswordCredential(credential: Credential): void {
  const { value, username, totp_secret: secret } = credential;
  // A password may hold any printable character, spaces and letters beyond ASCII included; never a control character.
  if (value.length === 0 || new TextEncoder().encode(value).length > MAX_PASSWORD_LENGTH || /[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    throw new RelayConnectorError("invalid_credential", "credential.value");
  }
  if (username === undefined || username.length < 3 || username.length > MAX_USERNAME_LENGTH || !USERNAME.test(username)) {
    throw new RelayConnectorError("invalid_credential", "credential.username");
  }
  if (secret !== undefined && normalizeTotpSecret(secret) !== secret) throw new RelayConnectorError("invalid_credential", "credential.totp_secret");
  if (credential.expires_at !== undefined || credential.refresh_token !== undefined) throw new RelayConnectorError("invalid_credential", "credential.type");
}

/** Anthropic API keys: `sk-ant-api` + two version digits + a dash + the secret. */
const ANTHROPIC_API_KEY = /^sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}$/;
/** Anthropic OAuth access tokens: `sk-ant-oat` + two version digits (today `01`). */
const ANTHROPIC_OAUTH = /^sk-ant-oat[0-9]{2}-[A-Za-z0-9_-]{20,}$/;
/**
 * OpenAI API keys: `sk-` + the secret, excluding the Anthropic and Admin-API families. This covers
 * the legacy `sk-...` and project/service-account `sk-proj-...` / `sk-svcacct-...` forms; admin keys
 * are a different API and are refused here so they cannot be spent on inference by mistake.
 */
const OPENAI_API_KEY = /^sk-(?!ant-|admin-)[A-Za-z0-9_-]{20,}$/;
/** An OpenAI-compatible vendor's API key: the token characters every such vendor's keys are made of. */
const OPENAI_COMPATIBLE_API_KEY = /^[A-Za-z0-9._~+/=-]{16,}$/;
/** A JWT: three base64url segments. */
const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The class a `(vendor, type)` pair names, or null when the vendor does not use that type. */
export function credentialClass(vendor: Vendor, type: CredentialType): CredentialClass | null {
  switch (vendor) {
    case "anthropic":
      return type === "api_key" ? "anthropic_api_key" : type === "oauth_access_token" ? "anthropic_oauth_access_token" : type === "password" ? "anthropic_password" : null;
    case "openai":
      return type === "api_key" ? "openai_api_key" : null;
    case "chatgpt_codex":
      return type === "oauth_access_token" ? "chatgpt_codex_oauth_access_token" : type === "password" ? "chatgpt_codex_password" : null;
    default:
      return isOpenAiCompatibleVendor(vendor) && type === "api_key" ? "openai_compatible_api_key" : null;
  }
}

/**
 * Check the credential's format class for its vendor, with the closed `invalid_credential` refusal.
 * The value is never echoed in the error (value, length, prefix and hash all stay out).
 */
export function assertCredentialFormat(vendor: Vendor, credential: Credential): CredentialClass {
  const klass = credentialClass(vendor, credential.type);
  if (klass === null) throw new RelayConnectorError("invalid_credential", "credential.type");
  if (klass === "chatgpt_codex_password" || klass === "anthropic_password") {
    assertPasswordCredential(credential);
    return klass;
  }
  if (credential.username !== undefined || credential.totp_secret !== undefined) throw new RelayConnectorError("invalid_credential", "credential.type");
  const value = credential.value;
  if (value.length === 0 || value.length > MAX_CREDENTIAL_LENGTH || !/^[\u0021-\u007e]+$/.test(value)) {
    throw new RelayConnectorError("invalid_credential", "credential.value");
  }
  switch (klass) {
    case "anthropic_api_key":
      if (!ANTHROPIC_API_KEY.test(value)) throw new RelayConnectorError("invalid_credential", "credential.value");
      return klass;
    case "anthropic_oauth_access_token":
      if (!ANTHROPIC_OAUTH.test(value)) throw new RelayConnectorError("invalid_credential", "credential.value");
      return klass;
    case "openai_api_key":
      if (!OPENAI_API_KEY.test(value)) throw new RelayConnectorError("invalid_credential", "credential.value");
      return klass;
    case "chatgpt_codex_oauth_access_token":
      if (!JWT.test(value)) throw new RelayConnectorError("invalid_credential", "credential.value");
      // Parse now, so a token whose claims the header builder needs cannot enter the store.
      chatgptAccountId(value);
      return klass;
    case "openai_compatible_api_key":
      if (!OPENAI_COMPATIBLE_API_KEY.test(value)) throw new RelayConnectorError("invalid_credential", "credential.value");
      return klass;
  }
}

/** The claims of a ChatGPT/Codex OAuth access token this lane relies on, none of them secret. */
export interface ChatgptTokenClaims {
  /** `exp` from the JWT payload, unix seconds. */
  readonly expiresAt: bigint;
  /** `https://api.openai.com/auth.chatgpt_account_id`, the `chatgpt-account-id` header value. */
  readonly accountId: string;
  /** The header's `alg`, for diagnostics only; the signature is not checked here. */
  readonly algorithm: string;
}

/**
 * Read the claims of a ChatGPT/Codex access token. The token is a bearer credential whose signature
 * only OpenAI can check (its JWKS is not part of this channel), so this is a format and claims
 * parse: exactly three base64url segments, a JSON header with an algorithm other than `none`, a
 * JSON payload with an integer `exp`, and the `https://api.openai.com/auth` object carrying
 * `chatgpt_account_id`. Anything else is `invalid_credential`.
 */
export function chatgptTokenClaims(value: string): ChatgptTokenClaims {
  const parts = value.split(".");
  if (parts.length !== 3) throw new RelayConnectorError("invalid_credential", "credential.value");
  const header = decodeSegment(parts[0] as string);
  const payload = decodeSegment(parts[1] as string);
  if (!isObject(header) || !isObject(payload)) throw new RelayConnectorError("invalid_credential", "credential.value");
  const algorithm = get(header, "alg");
  if (typeof algorithm !== "string" || algorithm.length === 0 || algorithm === "none") {
    throw new RelayConnectorError("invalid_credential", "credential.value");
  }
  const expiresAt = get(payload, "exp");
  if (typeof expiresAt !== "bigint" || expiresAt <= 0n) throw new RelayConnectorError("invalid_credential", "credential.value");
  const auth = get(payload, "https://api.openai.com/auth");
  if (!isObject(auth)) throw new RelayConnectorError("invalid_credential", "credential.value");
  const accountId = get(auth, "chatgpt_account_id");
  if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) {
    throw new RelayConnectorError("invalid_credential", "credential.value");
  }
  return { expiresAt, accountId, algorithm };
}

/** Shorthand for the header builder: the account id of a ChatGPT/Codex token. */
export function chatgptAccountId(value: string): string {
  return chatgptTokenClaims(value).accountId;
}

function decodeSegment(segment: string): Json | null {
  if (!/^[A-Za-z0-9_-]+$/.test(segment) || segment.length > 3 * MAX_CREDENTIAL_LENGTH) return null;
  const padded = segment.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (segment.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
    return parseStrict(text);
  } catch {
    return null;
  }
}

/** The unix second after which this credential must not be used, or null when it never expires. */
export function credentialExpiry(credential: Credential): bigint | null {
  const fromField = credential.expires_at ?? null;
  if (credential.type === "oauth_access_token" && credential.value.startsWith("sk-ant-oat")) return fromField;
  if (credential.type === "oauth_access_token" && JWT.test(credential.value)) {
    const fromToken = chatgptTokenClaims(credential.value).expiresAt;
    return fromField === null || fromToken < fromField ? fromToken : fromField;
  }
  return fromField;
}

/** Whether the credential is expired at `nowSecs` (the first second it is rejected). */
export function isCredentialExpired(credential: Credential, nowSecs: bigint): boolean {
  const expiry = credentialExpiry(credential);
  return expiry !== null && nowSecs >= expiry;
}
