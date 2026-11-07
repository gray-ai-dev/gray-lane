import { sha256BareHex } from "@gray/attest";
import { isObject, parseStrict, toJsonString, type JsonObject } from "@gray/json";
import { DEFAULT_MAX_ITEMS, DEFAULT_MAX_TOTAL_BYTES, isLaneProtocol, OPENAI_COMPATIBLE_VENDOR_IDS, POSITIONS_BY_PROTOCOL, utf8Length, type LaneProtocol } from "@gray/lane";
import type { StackConfigAccount, StackConfigDocument, StackConfigProxy, StackIdentity } from "@gray/lane-wire";
import { authHeaders, egressValue, type Credential, type CredentialType, type EgressSpec, type StackSealedAccount } from "@gray/relay-connector";
import type { StackRelayAppend, StackRelayCap, StackRelayConfig, StackRelayRoute, StackVendor } from "./stack-config.ts";

/**
 * The relay config document of a stack lane (docs/confidential-lane-supply-implementation.md §8, S28)
 * and the egress account table that goes with it (S15): pure functions, no clock, no I/O.
 *
 * One build joins three inputs:
 *
 * - the console's metadata (the bridge op `stack.config`, S28a): accounts, proxies, routes, appends,
 *   settings, with no secret in them (S29);
 * - the credentials gray-relay sealed to this boot (`RelayCredentialStore.stackAccounts`), each with
 *   the sealed version that last set it;
 * - the boot's own values: the inbound token, `attempts_max` and each route's cap source.
 *
 * **Which accounts are served.** A panel account is in the document only when this boot holds its
 * sealed credential for the same vendor at a sealed version at or past the account's
 * `credential_version` (0 takes any), and its proxy matches: a panel `proxy_id` needs the panel's
 * proxy, a sealed proxy of the same type, host and port, and a sealed version at or past the proxy's
 * `credential_version`; no panel proxy needs no sealed proxy. Every other account stays out of the
 * document and the table, with a closed reason the service logs, until what it waits for arrives (the
 * document then changes, so the version does). Leaving it out rather than marking it keeps the
 * standard's account object one shape: every served account has a usable credential. A sealed
 * account the panel does not name is not served (it has no models, limits or status).
 *
 * **Which accounts egress knows.** The table holds the served accounts whose `status` is `active`. A
 * `paused` account is served as paused (§8) but egress refuses its credential (403
 * `stack_credential_unknown`), so a pause holds whatever the relay's software does with it. Each row
 * names the sealed credential's type (`credential_type`, what the cooling rules' `credential` filter
 * matches, S38) and the account's client identity when the panel registered one (S32a): egress writes
 * it on every call of the account. A panel account that declares a `credential_type` other than the
 * sealed credential's is not served (`invalid_credential`): the relay's container would send a form
 * the declaration does not name, and the panel's test profile would be another class's.
 *
 * **Routes and appends (S21a).** At most one route per (`protocol`, `requested_model`): two the panel
 * gives that agree are served once (visible if either is), two that disagree are both left out, since
 * the relay could not tell which one the entry registers. Never more appends than one request may
 * carry: the appends of one protocol family's positions (Anthropic's `system_*`, the OpenAI family's
 * `instructions_*`) are left out together when they exceed `@gray/lane`'s DEFAULT_MAX_ITEMS or
 * DEFAULT_MAX_TOTAL_BYTES (egress's append limits default to the same, pinned by its parity test).
 *
 * **Two digests** (relay standard v1.7 §1), from which the service numbers the routing `version` and
 * `credentials_version` apart, so a credential refresh never moves the routing version:
 *
 * - `routingDigest` covers everything the relay is served except the two versions, each account's
 *   `credential.value` and `credential.expires_at`, each window's `used_requests` and `used_tokens` and
 *   `usage_as_of` (read when the document is served, S31, S21a; the console's version and digest leave
 *   them out too); and it covers what the entry does with the served routes: the panel's `appends_by`
 *   and every registered append, which a document under `appends_by: gray` does not list;
 * - `credentialsDigest` covers the served accounts' `(id, type, value, expires_at)` in account order.
 *
 * A credential's type is in both (it names the request form). `usage_as_of` is the console's own
 * `used_at_ms`, the time it read the counters, not the entry's. Under `appends_by: gray` the document
 * serves `appends: []`: the entry inserts them (`StackRelayConfig.appendsBy`). Relay standard v1.7 is the live
 * one: its container reads `appends` and inserts them under `appends_by: relay` (docs/relay-changes-v2.md §8's
 * removal waits for v2's release).
 *
 * **Refreshed credentials** (§6, own calls): a token egress refreshed for a `refresh: "gray"` account stands in
 * for the sealed credential it was refreshed from (`RelayCredentialStore.applyRefreshed`, taken by
 * `stack-ops.ts`), so it is what `sealed` holds here: `credentialsDigest` moves with it, and so does
 * `credentials_version`, while the routing version stays. A credential's `refresh_token` is never served and is
 * in neither digest.
 */

/** S30: the relay's `settings` object is at most 64 KiB. */
export const STACK_SETTINGS_MAX_BYTES = 64 * 1024;

/**
 * The largest output cap `gray-lane-rewrites-v1` lets anyone write (`set_member` `/max_tokens`,
 * `/max_output_tokens`: integer 1..4294967295, deploy/tee/egress/gray-lane-rewrites-v1.json).
 */
export const STACK_CAP_POLICY_MAX = 4_294_967_295;

/**
 * S16's route table: the vendors each protocol has an egress route for (egress `stackProtocolRoutes`).
 * A route whose pair is not here could never pass egress's route check, so it is not served.
 */
export const STACK_ROUTE_VENDORS: Readonly<Record<LaneProtocol, readonly StackVendor[]>> = Object.freeze({
  anthropic_messages: ["anthropic"],
  open_ai_chat: ["openai", ...OPENAI_COMPATIBLE_VENDOR_IDS],
  open_ai_responses: ["openai", "chatgpt_codex"],
});

/**
 * The output-cap member a relay writes for each protocol (`gray-lane-rewrites-v1`'s integer rule that
 * also has an insert): Messages and Chat `max_tokens`, Responses `max_output_tokens`. Chat's
 * `max_completion_tokens` has no insert in the policy, so it is not the route's cap member.
 */
export const STACK_CAP_FIELDS: Readonly<Record<LaneProtocol, string>> = Object.freeze({
  anthropic_messages: "max_tokens",
  open_ai_chat: "max_tokens",
  open_ai_responses: "max_output_tokens",
});

/** Why a panel account, a route or an append is not served: closed codes, logged with the id only. */
export type StackExclusionReason =
  | "not_sealed"
  | "vendor_mismatch"
  | "credential_waiting"
  | "invalid_credential"
  | "proxy_unknown"
  | "proxy_mismatch"
  | "proxy_waiting"
  | "duplicate_credential"
  | "route_unserved"
  | "route_conflict"
  | "append_digest_mismatch"
  | "appends_over_limit";

export interface StackExclusion {
  readonly kind: "account" | "route" | "append";
  readonly id: string;
  readonly reason: StackExclusionReason;
  /** A route's protocol and requested model as the panel wrote them (`id` joins them with a space): the report names both (S42). */
  readonly route?: { readonly protocol: string; readonly requestedModel: string };
}

/**
 * One S15 row (`PUT /v1/stack/accounts`): `proxy` and `proxy_id` together or not at all; `credential_type`
 * the sealed credential's; `identity` (S32a) only when the panel registered one.
 */
export interface StackAccountRow {
  readonly account_id: string;
  readonly vendor: StackVendor;
  readonly credential_sha256: string;
  readonly credential_type: CredentialType;
  readonly proxy?: JsonObject;
  readonly proxy_id?: string;
  readonly identity?: StackIdentity;
}

/** What a build needs. */
export interface StackDocumentInput {
  readonly relayId: string;
  readonly inboundToken: string;
  /** The console's metadata (`stack.config`'s `config`). */
  readonly metadata: StackConfigDocument;
  /** The relay's sealed accounts (`RelayCredentialStore.stackAccounts`). */
  readonly sealed: readonly StackSealedAccount[];
  /** `limits.attempts_max` (RETRY_MAX_ATTEMPTS). */
  readonly attemptsMax: number;
  /** The longest output a request to a requested model may be sent with (the snapshot's `longestOutput`), when a source states one. */
  readonly longestOutput: (requestedModel: string) => number | undefined;
}

/** One build: the digests, the request path's view, the egress rows, the exclusions and the served texts. */
export interface StackDocument {
  /** Everything served but the credentials' values and expiries and the used counters, with `appends_by` and the appends. */
  readonly routingDigest: string;
  /** The served accounts' `(id, type, value, expires_at)` in account order. */
  readonly credentialsDigest: string;
  /** How many accounts are served (the table holds the active ones). */
  readonly accounts: number;
  readonly relay: Omit<StackRelayConfig, "version" | "credentialsVersion">;
  readonly table: readonly StackAccountRow[];
  readonly excluded: readonly StackExclusion[];
  /**
   * The served JSON text under the routing `version` and `credentialsVersion` (u64 decimal text each), with
   * the windows' used counters as built.
   */
  text(version: string, credentialsVersion: string): string;
  /** `GET …/config/credentials`: `{"accounts":[{"credential","id"}],"credentials_version","version"}`. */
  credentialsText(version: string, credentialsVersion: string): string;
}

/** A document the build refuses as a whole (a settings text that is not a JSON object within S30's bound). */
export class StackDocumentError extends Error {
  override readonly name = "StackDocumentError";
}

/**
 * S15's `credential_sha256` of one credential: SHA-256 (lower hex) of the exact value of its one auth
 * header in `@gray/relay-connector`'s `authHeaders` form, the form the relay is told to send (§8):
 * `x-api-key` for an Anthropic API key, `authorization` otherwise; for `chatgpt_codex` that value, a
 * line feed, and the `chatgpt-account-id` value. Egress computes the same text from the call's
 * headers (`stackCredential`, deploy/tee/egress/stack_relay.go); the shared vectors pin both.
 */
export function stackCredentialSha256(vendor: StackVendor, credential: Credential): string {
  const headers = authHeaders(vendor, credential);
  const apiKey = headers["x-api-key"];
  let value = apiKey ?? headers["authorization"];
  if (value === undefined) throw new Error("a credential class without an auth header");
  if (vendor === "chatgpt_codex") value = `${value}\n${headers["chatgpt-account-id"] ?? ""}`;
  return sha256BareHex(new TextEncoder().encode(value));
}

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/** 62^43 > 2^256 > 62^42: 32 bytes take exactly 43 digits. */
const INBOUND_TOKEN_DIGITS = 43;

/**
 * The inbound token's text from its 32 random bytes: the bytes as one number in base 62, 43 digits,
 * leading zeros kept. Letters and digits only, and 43 characters: a relay's software stores it as one
 * of its own API keys, and new-api's key column (one-api's `char(48)`) and its `sk-<key>-<channel>`
 * parsing would truncate a longer token or one with a `-`.
 */
export function inboundTokenText(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error("an inbound token is 32 random bytes");
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  let text = "";
  for (let index = 0; index < INBOUND_TOKEN_DIGITS; index += 1) {
    text = BASE62[Number(n % 62n)] + text;
    n /= 62n;
  }
  return text;
}

/** The cap a route is served with: the protocol's member and the longest output a source states, else none. */
export function stackCapOf(protocol: LaneProtocol, longestOutput: number | undefined): StackRelayCap | null {
  if (longestOutput === undefined || !Number.isSafeInteger(longestOutput) || longestOutput < 1) return null;
  return { field: STACK_CAP_FIELDS[protocol], max: Math.min(longestOutput, STACK_CAP_POLICY_MAX) };
}

function proxyMatches(panel: StackConfigProxy, sealed: EgressSpec): boolean {
  return panel.type === sealed.type && panel.host === sealed.host && panel.port === sealed.port;
}

/** The served credential object (§8): exactly as sealed. */
function servedCredential(credential: Credential): JsonObject {
  return {
    type: credential.type,
    value: credential.value,
    ...(credential.expires_at === undefined ? {} : { expires_at: credential.expires_at }),
  };
}

/** The served account object (§8): `credential` exactly as sealed. */
function servedAccount(account: StackConfigAccount, credential: Credential): JsonObject {
  return {
    id: account.id,
    vendor: account.vendor,
    credential: servedCredential(credential),
    models: [...account.models],
    weight: BigInt(account.weight),
    max_concurrency: BigInt(account.max_concurrency),
    windows: account.windows.map((window) => ({
      seconds: BigInt(window.seconds),
      max_requests: BigInt(window.max_requests),
      max_tokens: BigInt(window.max_tokens),
      used_requests: BigInt(window.used_requests),
      used_tokens: BigInt(window.used_tokens),
    })),
    status: account.status,
    labels: [...account.labels],
  };
}

/** The settings text as served: the console's bytes, once they are one strict JSON object within S30's bound. */
function settingsText(text: string): string {
  if (utf8Length(text) > STACK_SETTINGS_MAX_BYTES) throw new StackDocumentError("settings is over 64 KiB (S30)");
  let value;
  try {
    value = parseStrict(text);
  } catch {
    throw new StackDocumentError("settings is not strict JSON");
  }
  if (!isObject(value)) throw new StackDocumentError("settings is not a JSON object (S30)");
  return text;
}

/** Build the document of `input`. Throws `StackDocumentError` for a document no relay could be served. */
export function buildStackDocument(input: StackDocumentInput): StackDocument {
  const { metadata } = input;
  if (metadata.relay_id !== input.relayId) throw new StackDocumentError("the console answered for another relay");
  const settings = settingsText(metadata.settings_json);
  const excluded: StackExclusion[] = [];
  const sealedById = new Map(input.sealed.map((account) => [account.account_id, account]));
  const proxies = new Map(metadata.proxies.map((proxy) => [proxy.id, proxy]));

  // Accounts, in the panel's id order so the document and the table do not depend on the console's row order.
  const panel = [...metadata.accounts].sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const served: { readonly account: StackConfigAccount; readonly sealed: StackSealedAccount; readonly sha256: string }[] = [];
  const hashes = new Set<string>();
  for (const account of panel) {
    const sealed = sealedById.get(account.id);
    const reason = ((): StackExclusionReason | null => {
      if (sealed === undefined) return "not_sealed";
      if (sealed.vendor !== account.vendor) return "vendor_mismatch";
      if (sealed.version < BigInt(account.credential_version)) return "credential_waiting";
      if (account.credential_type !== undefined && account.credential_type !== sealed.credential.type) return "invalid_credential";
      if (account.proxy_id === null) return sealed.egress === undefined ? null : "proxy_mismatch";
      const proxy = proxies.get(account.proxy_id);
      if (proxy === undefined) return "proxy_unknown";
      if (sealed.egress === undefined || !proxyMatches(proxy, sealed.egress)) return "proxy_mismatch";
      if (sealed.version < BigInt(proxy.credential_version)) return "proxy_waiting";
      return null;
    })();
    if (reason !== null || sealed === undefined) {
      excluded.push({ kind: "account", id: account.id, reason: reason ?? "not_sealed" });
      continue;
    }
    let sha256: string;
    try {
      sha256 = stackCredentialSha256(account.vendor, sealed.credential);
    } catch {
      excluded.push({ kind: "account", id: account.id, reason: "invalid_credential" });
      continue;
    }
    // One credential names one account at egress (S15 refuses a table with a repeated hash): the first id keeps it.
    if (hashes.has(sha256)) {
      excluded.push({ kind: "account", id: account.id, reason: "duplicate_credential" });
      continue;
    }
    hashes.add(sha256);
    served.push({ account, sealed, sha256 });
  }

  const table: StackAccountRow[] = [];
  for (const { account, sealed, sha256 } of served) {
    if (account.status !== "active") continue;
    table.push({
      account_id: account.id,
      vendor: account.vendor,
      credential_sha256: sha256,
      credential_type: sealed.credential.type,
      ...(account.proxy_id === null || sealed.egress === undefined ? {} : { proxy: egressValue(sealed.egress), proxy_id: account.proxy_id }),
      ...(account.identity === undefined ? {} : { identity: account.identity }),
    });
  }

  // S21a: one route per (protocol, requested model). Keyed with a NUL, which neither name can hold.
  const byKey = new Map<string, StackRelayRoute | null>();
  for (const route of metadata.routes) {
    const named = { protocol: route.protocol, requestedModel: route.requested_model };
    if (!isLaneProtocol(route.protocol) || !STACK_ROUTE_VENDORS[route.protocol].includes(route.vendor)) {
      excluded.push({ kind: "route", id: `${route.protocol} ${route.requested_model}`, reason: "route_unserved", route: named });
      continue;
    }
    const key = `${route.protocol}\u0000${route.requested_model}`;
    const held = byKey.get(key);
    if (held === null) continue;
    if (held !== undefined) {
      if (held.upstream_model === route.upstream_model && held.vendor === route.vendor) {
        byKey.set(key, { ...held, visible: held.visible || route.visible });
      } else {
        byKey.set(key, null);
        excluded.push({ kind: "route", id: `${route.protocol} ${route.requested_model}`, reason: "route_conflict", route: named });
      }
      continue;
    }
    byKey.set(key, {
      requested_model: route.requested_model,
      upstream_model: route.upstream_model,
      vendor: route.vendor,
      protocol: route.protocol,
      visible: route.visible,
      cap: stackCapOf(route.protocol, input.longestOutput(route.requested_model)),
    });
  }
  const routes = [...byKey.values()].filter((route): route is StackRelayRoute => route !== null);

  // The console computes each append's SHA-256; the entry recomputes it, since egress matches the text by it (S18).
  const appends: { readonly id: string; readonly position: StackRelayAppend["position"]; readonly text: string; readonly spec: StackRelayAppend }[] = [];
  for (const append of metadata.appends) {
    const bytes = new TextEncoder().encode(append.text);
    const sha256 = sha256BareHex(bytes);
    if (sha256 !== append.sha256) {
      excluded.push({ kind: "append", id: append.id, reason: "append_digest_mismatch" });
      continue;
    }
    appends.push({ id: append.id, position: append.position, text: append.text, spec: { template_id: append.id, position: append.position, sha256, bytes: bytes.byteLength } });
  }
  // S21a: what one request may carry, per protocol family (the families' positions do not overlap).
  const overLimit = new Set<string>();
  for (const positions of [POSITIONS_BY_PROTOCOL.anthropic_messages, POSITIONS_BY_PROTOCOL.open_ai_responses]) {
    const family = appends.filter((append) => positions.includes(append.position));
    const total = family.reduce((sum, append) => sum + append.spec.bytes, 0);
    if (family.length > DEFAULT_MAX_ITEMS || total > DEFAULT_MAX_TOTAL_BYTES) {
      for (const append of family) {
        overLimit.add(append.id);
        excluded.push({ kind: "append", id: append.id, reason: "appends_over_limit" });
      }
    }
  }
  const servedAppends = appends.filter((append) => !overLimit.has(append.id));

  const limits = { attempts_max: input.attemptsMax };
  const appendsBy = stackAppendsBy(metadata);
  const appendObjects = servedAppends.map((append) => ({ id: append.id, position: append.position, text: append.text }));
  // `secrets: false` leaves each credential's type only (the routing digest's view).
  const head = (counters: boolean, secrets = true): JsonObject => ({
    relay_id: input.relayId,
    inbound_token: input.inboundToken,
    accounts: served.map(({ account, sealed }): JsonObject => {
      const value: JsonObject = { ...servedAccount(account, sealed.credential), ...(secrets ? {} : { credential: { type: sealed.credential.type } }) };
      if (counters) return value;
      const windows = account.windows.map((window) => ({ seconds: BigInt(window.seconds), max_requests: BigInt(window.max_requests), max_tokens: BigInt(window.max_tokens) }));
      return { ...value, windows };
    }),
    routes: routes.map((route) => ({
      requested_model: route.requested_model,
      upstream_model: route.upstream_model,
      vendor: route.vendor,
      protocol: route.protocol,
      visible: route.visible,
      cap: route.cap === null ? null : { field: route.cap.field, max: BigInt(route.cap.max) },
    })),
    limits: { attempts_max: BigInt(limits.attempts_max) },
    appends: appendsBy === "gray" ? [] : appendObjects,
  });
  const sha256Of = (value: JsonObject | JsonObject[]): string => sha256BareHex(new TextEncoder().encode(toJsonString(value)));
  const routingDigest = sha256Of({ ...head(false, false), appends: appendObjects, appends_by: appendsBy, settings_json: settings });
  const credentialsDigest = sha256Of(served.map(({ account, sealed }) => ({ id: account.id, ...servedCredential(sealed.credential) })));
  const usageAsOf = toJsonString(BigInt(metadata.used_at_ms));
  return {
    routingDigest,
    credentialsDigest,
    accounts: served.length,
    relay: {
      relayId: input.relayId,
      inboundToken: input.inboundToken,
      routes,
      appends: servedAppends.map((append) => append.spec),
      appendTexts: servedAppends.map((append) => ({ templateId: append.id, position: append.position, text: append.text })),
      appendsBy,
      limits,
    },
    table,
    excluded,
    // `settings` is the console's text as it is (S28a: byte for byte), so it is placed after the
    // serialised members rather than parsed and written again; "settings", "usage_as_of" and "version"
    // sort after every other member, so the text keeps `toJsonString`'s byte order of keys.
    text: (version, credentialsVersion) => {
      const members = toJsonString({ ...head(true), credentials_version: credentialsVersion });
      return `${members.slice(0, -1)},"settings":${settings},"usage_as_of":${usageAsOf},"version":${JSON.stringify(version)}}`;
    },
    credentialsText: (version, credentialsVersion) =>
      toJsonString({
        accounts: served.map(({ account, sealed }) => ({ id: account.id, credential: servedCredential(sealed.credential) })),
        credentials_version: credentialsVersion,
        version,
      }),
  };
}

/**
 * The panel's `appends_by` (relay standard v1.7 §2; the console's relay-stack settings, carried by
 * `stack.config`): `gray` only when the metadata says so, `relay` when it says `relay` or nothing.
 */
export function stackAppendsBy(metadata: StackConfigDocument): "relay" | "gray" {
  return (metadata as StackConfigDocument & { readonly appends_by?: string }).appends_by === "gray" ? "gray" : "relay";
}

/** The S15 body of a table: the rows as a JSON array (`[]` empties egress's table). */
export function stackTableBody(rows: readonly StackAccountRow[]): string {
  return toJsonString(rows.map((row) => ({ ...row, ...(row.identity === undefined ? {} : { identity: { headers: { ...row.identity.headers }, betas: [...row.identity.betas], generated: [...row.identity.generated] } }) })) as unknown as JsonObject[]);
}
