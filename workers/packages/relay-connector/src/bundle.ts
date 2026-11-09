import { get, isObject, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { CREDENTIAL_TYPES, MAX_CREDENTIAL_LENGTH, VENDORS, assertCredentialFormat, type Credential, type Vendor } from "./credential.ts";
import { wireEgressSchema, egressValue, type EgressSpec } from "./egress.ts";
import { RelayConnectorError } from "./errors.ts";
import { MAX_CREDENTIAL_LEASE_SECONDS } from "./lease.ts";

/**
 * The plaintext the relay signs and the TEE applies: one full bundle, one partial update, or one
 * revocation.
 *
 * ```json
 * {"relay_id":"relay-1","version":7,"issued_at":1790000000,"expires_at":1790003600,
 *  "accounts":[{"account_id":"acc-1","vendor":"anthropic",
 *               "credential":{"type":"api_key","value":"sk-ant-api03-...","expires_at":1790003600}}]}
 * {"relay_id":"relay-1","version":8,"account_id":"acc-1",
 *  "credential":{"type":"oauth_access_token","value":"sk-ant-oat01-..."}}
 * {"relay_id":"relay-1","version":9,"revoke":"account","account_id":"acc-1"}
 * {"relay_id":"relay-1","version":10,"revoke":"relay"}
 * ```
 *
 * Integers are `bigint` (the workspace's Rust-u64 rule), so the canonical JSON writes `7`, not
 * `7.0`. `version` is a per-relay counter that every message kind shares and that must strictly
 * increase: equality is a replay, a smaller value is a rollback. A full bundle replaces the relay's
 * whole account map, including with an empty list (`accounts: []` revokes the pool); an update
 * replaces one existing account's credential; `revoke: "account"` removes one account and
 * `revoke: "relay"` removes every account the relay has. Revocations are signed messages with the
 * same version rule, so a relay can stop use of a credential without restarting the TEE.
 *
 * `expires_at - issued_at` is the credential lease: at most `MAX_CREDENTIAL_LEASE_SECONDS` (D35), the
 * window D21 keeps a retired OS image in the signed release list for.
 */

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Ids that may appear in a URL path, a log line and a JSON member without an escape. */
export const RESOURCE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** At most this many accounts in one bundle (a bound on the TEE's memory). */
export const MAX_ACCOUNTS_PER_BUNDLE = 1000;

export interface Account {
  readonly account_id: string;
  readonly vendor: Vendor;
  readonly credential: Credential;
  /** The proxy this account's vendor traffic leaves through; absent means the sidecar's direct path. */
  readonly egress?: EgressSpec;
}

export interface CredentialBundle {
  readonly relay_id: string;
  readonly version: bigint;
  readonly issued_at: bigint;
  readonly expires_at: bigint;
  /** May be empty: a signed full replacement with no accounts revokes the relay's whole pool. */
  readonly accounts: readonly Account[];
  /**
   * The relay's choice for its VM's vault (docs/design/relay-no-always-on-host.md H13), for a VM that keeps one (an app
   * on an on-chain KMS): `persist: false` keeps the accounts in memory only, with no disk record and no copy at Gray, so
   * every boot starts with none. Absent is `persist: true`. A VM without a vault (phase 1) keeps memory only either way.
   * The choice holds until the next bundle; an update or a revoke keeps it.
   */
  readonly vault?: BundleVaultOptions;
}

export interface BundleVaultOptions {
  readonly persist: boolean;
}

export interface CredentialUpdate {
  readonly relay_id: string;
  readonly version: bigint;
  readonly account_id: string;
  /** Absent in an egress-only rotation; at least one of `credential` and `egress` is present. */
  readonly credential?: Credential;
  /** Replace the account's proxy, or `null` to clear it; absent leaves it unchanged. */
  readonly egress?: EgressSpec | null;
}

/** Remove one account from the relay's pool. */
export interface CredentialRevokeAccount {
  readonly relay_id: string;
  readonly version: bigint;
  readonly revoke: "account";
  readonly account_id: string;
}

/** Remove every account the relay has (the relay itself stays registered for later bundles). */
export interface CredentialRevokeRelay {
  readonly relay_id: string;
  readonly version: bigint;
  readonly revoke: "relay";
}

export type CredentialRevoke = CredentialRevokeAccount | CredentialRevokeRelay;

export type CredentialPayload = CredentialBundle | CredentialUpdate | CredentialRevoke;

const idSchema = z.string().regex(RESOURCE_ID);
const u64Schema = z.bigint().min(0n).max(U64_MAX);
const versionSchema = z.bigint().min(1n).max(U64_MAX);

const credentialTypeSchema = z.enum(CREDENTIAL_TYPES);

/** A sealed credential's closed shape, as a bundle, an update and a vault record (vault-state.ts) carry it. */
export const credentialSchema = z
  .object({
    type: credentialTypeSchema,
    value: z.string().min(1).max(MAX_CREDENTIAL_LENGTH),
    expires_at: u64Schema.optional(),
    refresh_token: z.string().min(1).max(MAX_CREDENTIAL_LENGTH).regex(/^[\x21-\x7e]+$/).optional(),
    // A `password` credential's sign-in e-mail and TOTP secret (credential.ts checks their form).
    username: z.string().min(1).max(MAX_CREDENTIAL_LENGTH).optional(),
    totp_secret: z.string().min(1).max(MAX_CREDENTIAL_LENGTH).optional(),
  })
  .strict()
  .refine((credential) => credential.refresh_token === undefined || credential.type === "oauth_access_token", { message: "only an access token has a refresh token" })
  .refine((credential) => (credential.type === "password") === (credential.username !== undefined), { message: "a password, and only a password, has a username" })
  .refine((credential) => credential.totp_secret === undefined || credential.type === "password", { message: "only a password has a TOTP secret" });

/** One account's closed shape, as a bundle and a vault record (vault-state.ts) carry it. */
export const accountSchema = z
  .object({
    account_id: idSchema,
    vendor: z.enum(VENDORS),
    credential: credentialSchema,
    egress: wireEgressSchema.optional(),
  })
  .strict();

/** H13: the bundle's `vault` member, closed: `{"persist": true|false}`. */
const bundleVaultSchema = z.object({ persist: z.boolean() }).strict();

const bundleSchema = z
  .object({
    relay_id: idSchema,
    version: versionSchema,
    issued_at: u64Schema,
    expires_at: u64Schema,
    accounts: z.array(accountSchema).max(MAX_ACCOUNTS_PER_BUNDLE),
    vault: bundleVaultSchema.optional(),
  })
  .strict();

const updateSchema = z
  .object({
    relay_id: idSchema,
    version: versionSchema,
    account_id: idSchema,
    credential: credentialSchema.optional(),
    egress: wireEgressSchema.nullable().optional(),
  })
  .strict()
  // An update with neither half would be a version-only no-op; the wire has no such message.
  .refine((value) => value.credential !== undefined || value.egress !== undefined, { path: ["credential"], message: "an update carries a credential, an egress, or both" });

const revokeSchema = z.discriminatedUnion("revoke", [
  z
    .object({
      relay_id: idSchema,
      version: versionSchema,
      revoke: z.literal("account"),
      account_id: idSchema,
    })
    .strict(),
  z
    .object({
      relay_id: idSchema,
      version: versionSchema,
      revoke: z.literal("relay"),
    })
    .strict(),
]);

function refusal(error: z.ZodError, code: "invalid_bundle" | "invalid_credential"): RelayConnectorError {
  const issue = error.issues[0];
  const path = issue === undefined || issue.path.length === 0 ? null : issue.path.map(String).join(".");
  return new RelayConnectorError(code, path);
}

/** Whether a parsed JSON value is a bundle, an update or a revocation, judged by its members. */
export function payloadKind(value: Json): "bundle" | "update" | "revoke" | null {
  if (!isObject(value)) return null;
  const accounts = get(value, "accounts");
  const accountId = get(value, "account_id");
  const revoke = get(value, "revoke");
  if (revoke !== undefined && accounts === undefined) return "revoke";
  if (accounts !== undefined && accountId === undefined && revoke === undefined) return "bundle";
  if (accountId !== undefined && accounts === undefined && revoke === undefined) return "update";
  return null;
}

/**
 * Parse one signed payload and enforce every structural and format rule: the closed member set,
 * u64 versions, account/vendor/type shapes, a bounded account list (empty is allowed for a full
 * revocation), globally unique account ids in a bundle, each credential's format class for its
 * vendor, and the revocation shapes. Throws this package's closed error.
 */
export function parseCredentialPayload(value: Json): CredentialPayload {
  const kind = payloadKind(value);
  if (kind === null) throw new RelayConnectorError("invalid_bundle");
  if (kind === "revoke") {
    const parsed = revokeSchema.safeParse(value);
    if (!parsed.success) throw refusal(parsed.error, "invalid_bundle");
    return parsed.data;
  }
  if (kind === "update") {
    const parsed = updateSchema.safeParse(value);
    if (!parsed.success) throw refusal(parsed.error, "invalid_bundle");
    // The update carries no vendor: its format is checked against the stored account's vendor.
    return parsed.data;
  }
  const parsed = bundleSchema.safeParse(value);
  if (!parsed.success) throw refusal(parsed.error, "invalid_bundle");
  const bundle: CredentialBundle = parsed.data;
  if (bundle.expires_at <= bundle.issued_at) throw new RelayConnectorError("invalid_bundle", "expires_at");
  const seen = new Set<string>();
  for (let index = 0; index < bundle.accounts.length; index += 1) {
    const account = bundle.accounts[index] as Account;
    if (seen.has(account.account_id)) throw new RelayConnectorError("invalid_bundle", `accounts.${index}.account_id`);
    seen.add(account.account_id);
    try {
      assertCredentialFormat(account.vendor, account.credential);
    } catch (error) {
      if (error instanceof RelayConnectorError) throw new RelayConnectorError("invalid_credential", `accounts.${index}.credential`);
      throw error;
    }
  }
  return bundle;
}

/** The credential member as sealed: the type, the secret, and an expiry only when the issuer has one. */
export function credentialValue(credential: Credential): JsonObject {
  const out: JsonObject = { type: credential.type, value: credential.value };
  if (credential.expires_at !== undefined) out.expires_at = credential.expires_at;
  if (credential.refresh_token !== undefined) out.refresh_token = credential.refresh_token;
  if (credential.username !== undefined) out.username = credential.username;
  if (credential.totp_secret !== undefined) out.totp_secret = credential.totp_secret;
  return out;
}

function accountValue(account: Account): JsonObject {
  return {
    account_id: account.account_id,
    vendor: account.vendor,
    credential: credentialValue(account.credential),
    ...(account.egress === undefined ? {} : { egress: egressValue(account.egress) }),
  };
}

/** The canonical JSON value of a payload; `jcsBytes` over this is the relay's signature preimage. */
export function payloadValue(payload: CredentialPayload): JsonObject {
  if ("revoke" in payload) {
    return "account_id" in payload
      ? { relay_id: payload.relay_id, version: payload.version, revoke: payload.revoke, account_id: payload.account_id }
      : { relay_id: payload.relay_id, version: payload.version, revoke: payload.revoke };
  }
  if ("accounts" in payload) {
    return {
      relay_id: payload.relay_id,
      version: payload.version,
      issued_at: payload.issued_at,
      expires_at: payload.expires_at,
      accounts: payload.accounts.map(accountValue),
      ...(payload.vault === undefined ? {} : { vault: { persist: payload.vault.persist } }),
    };
  }
  return {
    relay_id: payload.relay_id,
    version: payload.version,
    account_id: payload.account_id,
    ...(payload.credential === undefined ? {} : { credential: credentialValue(payload.credential) }),
    ...(payload.egress === undefined ? {} : { egress: payload.egress === null ? null : egressValue(payload.egress) }),
  };
}

export function payloadKindOf(payload: CredentialPayload): "bundle" | "update" | "revoke" {
  if ("revoke" in payload) return "revoke";
  return "accounts" in payload ? "bundle" : "update";
}

/** The `relay_id` a payload names, without trusting the rest of it. */
export function payloadRelayId(payload: Json): string | null {
  if (!isObject(payload)) return null;
  const relayId = get(payload, "relay_id");
  return typeof relayId === "string" ? relayId : null;
}

/**
 * The freshness rules the TEE applies to an accepted bundle (§ none in ACI; Gray's rule): a bundle
 * is refused from the first second its `expires_at` names, an `issued_at` too far in the future
 * is refused rather than accepted on the relay's clock, and the lease it declares is at most
 * `MAX_CREDENTIAL_LEASE_SECONDS` (D35, implementing D21: one day, so a retired OS image's relay
 * can still act within one lease). `maxSkewSeconds` is the clock allowance.
 */
export function checkBundleFreshness(bundle: CredentialBundle, nowSecs: bigint, maxSkewSeconds: bigint): void {
  if (nowSecs >= bundle.expires_at) throw new RelayConnectorError("bundle_expired", "expires_at");
  if (bundle.issued_at > nowSecs + maxSkewSeconds) throw new RelayConnectorError("bundle_not_yet_valid", "issued_at");
  if (bundle.expires_at - bundle.issued_at > MAX_CREDENTIAL_LEASE_SECONDS) throw new RelayConnectorError("invalid_bundle", "expires_at");
}

/**
 * The relay-side check before signing: never seal a bundle that is already expired, and never seal a
 * lease longer than the TEE accepts (D35), so the relay's tooling refuses exactly the bundle the
 * TEE would instead of learning it after the round trip.
 */
export function assertBundleSealable(bundle: CredentialBundle, nowSecs: bigint): void {
  if (bundle.expires_at <= nowSecs) throw new RelayConnectorError("invalid_bundle", "expires_at");
  if (bundle.expires_at - bundle.issued_at > MAX_CREDENTIAL_LEASE_SECONDS) throw new RelayConnectorError("invalid_bundle", "expires_at");
}
