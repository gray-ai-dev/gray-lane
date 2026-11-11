import { jcsBytes } from "@gray/attest";
import { parseStrictBytes, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { accountSchema, credentialSchema, credentialValue, RESOURCE_ID } from "./bundle.ts";
import { egressValue } from "./egress.ts";
import { RelayConnectorError } from "./errors.ts";
import type { RelayVaultSnapshot } from "./store.ts";

/**
 * The plaintext of a VM's vault record (P2e, docs/design/relay-no-always-on-host.md §3.1 and 13.11): one relay's
 * accounts as `RelayCredentialStore.vaultSnapshot` reads them, as the JCS of a closed object. `vault.ts` seals it under
 * `K_vault`; nothing else ever sees it in the clear.
 *
 * ```json
 * {"format":"gray-relay-vault-state/v1","relay_id":"relay-1","version":7,"persist":true,
 *  "accounts":[{"account_id":"acc-1","vendor":"anthropic","credential":{...},"version":7}],
 *  "refreshed":[{"account_id":"acc-1","based_on":7,"credential":{"type":"oauth_access_token",...}}]}
 * ```
 *
 * `version` is the relay's sealed version (its bundles', updates' and revokes' counter), not the record's: the record
 * header's version grows with every write (a refreshed token is a write and no sealed version). Integers are `bigint`
 * (the workspace's u64 rule). `persist: false` (H13) is a record with no account: written once when the relay chooses
 * RAM-only after a persisted record, so a reboot does not bring the older accounts back. `logins` (P2e-2, 13.5) is each
 * password account's sign-in pacing, present only when there is any. An account's `login_since` is the first sealed
 * version the account is the same one from (a `password` account's e-mail, a `sign_in` account, an access token sealed
 * again unchanged: `store.ts` `sameSealed`), present only when it is older than `version`.
 */

export const VAULT_STATE_FORMAT = "gray-relay-vault-state/v1";

const u64 = z.bigint().min(0n).max(0xffff_ffff_ffff_ffffn);

const vaultAccountSchema = accountSchema.extend({ version: u64.min(1n), login_since: u64.min(1n).optional() }).strict();

const refreshedSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    based_on: u64,
    credential: credentialSchema,
    username: z.string().min(1).optional(),
  })
  .strict();

/** P2e-2 (13.5): a sign-in's pacing; the codes are egress's closed sign-in codes (`@gray/lane-wire` STACK_LOGIN_CODES). */
const LOGIN_CODES = ["vendor_rejected", "invalid_answer", "proxy_failed", "connect_failed", "timeout", "egress_error"] as const;
const loginSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    username: z.string().min(1).max(254),
    failures: u64,
    last: z
      .object({ outcome: z.enum(["ok", "failed"]), code: z.enum(LOGIN_CODES).nullable(), at_ms: u64.min(1n) })
      .strict()
      .refine((l) => (l.outcome === "ok") === (l.code === null), { message: "an ok exchange has no code, a failed one names one" })
      .nullable(),
    last_ok_ms: u64.min(1n).nullable(),
  })
  .strict();

/** D7: a pinned authorize-URL template, per (image digest, vendor, flow). */
const pinSchema = z
  .object({
    image: z.string().min(1).max(512),
    vendor: z.string().regex(/^[a-z0-9_]{1,64}$/),
    flow: z.enum(["code", "callback", "callback_input"]),
    template: z.string().min(1).max(2048),
  })
  .strict();

const vaultStateSchema = z
  .object({
    format: z.literal(VAULT_STATE_FORMAT),
    relay_id: z.string().regex(RESOURCE_ID),
    version: u64,
    persist: z.boolean(),
    accounts: z.array(vaultAccountSchema),
    refreshed: z.array(refreshedSchema),
    logins: z.array(loginSchema).optional(),
    sign_in_pins: z.array(pinSchema).optional(),
  })
  .strict();

/** The snapshot of `relayId` as a vault record's plaintext (JCS bytes). */
export function vaultStatePlaintext(relayId: string, snapshot: RelayVaultSnapshot): Uint8Array {
  const value: JsonObject = {
    format: VAULT_STATE_FORMAT,
    relay_id: relayId,
    version: snapshot.version,
    persist: snapshot.persist,
    accounts: snapshot.accounts.map((account) => ({
      account_id: account.account_id,
      vendor: account.vendor,
      credential: credentialValue(account.credential),
      ...(account.egress === undefined ? {} : { egress: egressValue(account.egress) }),
      version: account.version,
      // Only for an account sealed again as the same one, so other records are the same bytes as before.
      ...(account.login_since === undefined ? {} : { login_since: account.login_since }),
    })),
    refreshed: snapshot.refreshed.map((token) => ({
      account_id: token.account_id,
      based_on: token.based_on,
      credential: credentialValue(token.credential),
      ...(token.username === undefined ? {} : { username: token.username }),
    })),
    // P2e-2: only with pacing to keep, so a record without any is the same bytes as before.
    ...(snapshot.logins === undefined || snapshot.logins.length === 0
      ? {}
      : {
          logins: snapshot.logins.map((login) => ({
            account_id: login.account_id,
            username: login.username,
            failures: login.failures,
            last: login.last === null ? null : { outcome: login.last.outcome, code: login.last.code, at_ms: login.last.at_ms },
            last_ok_ms: login.last_ok_ms,
          })),
        }),
    // D7: only with pins to keep, so a record without any is the same bytes as before.
    ...(snapshot.sign_in_pins === undefined || snapshot.sign_in_pins.length === 0
      ? {}
      : { sign_in_pins: [...snapshot.sign_in_pins].sort(byPinKey).map((pin) => ({ image: pin.image, vendor: pin.vendor, flow: pin.flow, template: pin.template })) }),
  };
  return jcsBytes(value);
}

/**
 * A vault record's plaintext read back, for `relayId` only: strict UTF-8 and JSON, the closed shape, the relay's own id.
 * The store checks each credential's class when it restores the snapshot. Throws `invalid_plaintext`.
 */
export function parseVaultState(relayId: string, plaintext: Uint8Array): RelayVaultSnapshot {
  let value: Json;
  try {
    value = parseStrictBytes(plaintext);
  } catch {
    throw new RelayConnectorError("invalid_plaintext");
  }
  const parsed = vaultStateSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("invalid_plaintext", issue === undefined || issue.path.length === 0 ? null : issue.path.map(String).join("."));
  }
  if (parsed.data.relay_id !== relayId) throw new RelayConnectorError("invalid_plaintext", "relay_id");
  const state = parsed.data;
  return {
    version: state.version,
    persist: state.persist,
    accounts: state.accounts.map((account) => ({
      account_id: account.account_id,
      vendor: account.vendor,
      credential: account.credential,
      ...(account.egress === undefined ? {} : { egress: account.egress }),
      version: account.version,
      ...(account.login_since === undefined ? {} : { login_since: account.login_since }),
    })),
    refreshed: state.refreshed.map((token) => ({
      account_id: token.account_id,
      based_on: token.based_on,
      credential: token.credential,
      ...(token.username === undefined ? {} : { username: token.username }),
    })),
    ...(state.logins === undefined ? {} : { logins: state.logins.map((login) => ({ ...login, last: login.last === null ? null : { ...login.last } })) }),
    ...(state.sign_in_pins === undefined ? {} : { sign_in_pins: state.sign_in_pins.map((pin) => ({ ...pin })) }),
  };
}

/** A pin's key, as the vault orders and merges them. */
export function vaultPinKey(pin: { readonly image: string; readonly vendor: string; readonly flow: string }): string {
  return `${pin.image}|${pin.vendor}|${pin.flow}`;
}

function byPinKey(l: { readonly image: string; readonly vendor: string; readonly flow: string }, r: { readonly image: string; readonly vendor: string; readonly flow: string }): number {
  const a = vaultPinKey(l);
  const b = vaultPinKey(r);
  return a < b ? -1 : a > b ? 1 : 0;
}
