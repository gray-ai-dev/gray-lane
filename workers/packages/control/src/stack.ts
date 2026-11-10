import semver from "semver";
import { DEFAULT_MAX_ITEMS, DEFAULT_MAX_TOTAL_BYTES, LANE_PROTOCOLS, LANE_STACK_VENDORS, OPENAI_COMPATIBLE_VENDORS, POSITIONS, POSITIONS_BY_PROTOCOL, type Position } from "@gray/lane";
import { EGRESS_TYPES, isValidEgressHost } from "@gray/relay-connector/egress";
import { z } from "zod";
import { InvalidConfig, LANE_RELAY_ID_PATTERN, validModelId, validSchedulerUrl } from "./endpoint.ts";
import { laneVendorOf } from "./lane.ts";
import { utf8Length } from "./text.ts";

/**
 * A relay stack's configuration as the console takes it (docs/confidential-lane-supply-implementation.md sections 8
 * and 9 E): the relay's VM-facing record, its upstream accounts, egress proxies, route visibility and appended texts,
 * the rules each must keep, and the pull-token issue a relay reports (S13). Pure: the console stores what passes, the
 * lane bridge serves it, and the entry in the VM joins it with the credentials gray-relay sealed (S29: no secret here).
 *
 * Each rule reuses the one its value already has elsewhere: ids are the lane's relay-id pattern, models the model-id
 * rule, proxies @gray/relay-connector's egress member (the sidecar's own rules), positions and the append bound
 * @gray/lane's (GRAY_LANE_REWRITES_V1), the token service's address the scheduler-URL rule.
 */

/** An account's vendor as the relay's configuration names it (section 8): the lane's vendors (`@gray/lane` LANE_STACK_VENDORS). */
export const STACK_VENDORS = LANE_STACK_VENDORS;
export type StackVendor = (typeof STACK_VENDORS)[number];

/** Each stack vendor's own name, for Endpoints, the panel and the guide (an OpenAI-compatible vendor's is its row's). */
export const STACK_VENDOR_NAMES: Readonly<Record<StackVendor, string>> = Object.freeze({
  anthropic: "Anthropic",
  openai: "OpenAI",
  chatgpt_codex: "ChatGPT Codex",
  ...Object.fromEntries(OPENAI_COMPATIBLE_VENDORS.map((v) => [v.id, v.name])),
} as Record<StackVendor, string>);

/** The OpenAI-compatible vendors' rows (`@gray/lane` vendors.ts), for the console's guide and contract. */
export { OPENAI_COMPATIBLE_VENDORS } from "@gray/lane";

/** The vendor a stack endpoint's base URL names (`laneVendorOf`, with the Codex backend as section 8 spells it). */
export function stackVendorOf(baseUrl: string): StackVendor | null {
  const vendor = laneVendorOf(baseUrl);
  return vendor === null ? null : vendor === "chatgpt" ? "chatgpt_codex" : vendor;
}

export const STACK_ACCOUNT_STATUSES = ["active", "paused"] as const;
export type StackAccountStatus = (typeof STACK_ACCOUNT_STATUSES)[number];

/** Account, proxy, append and issue ids, and labels: the lane's relay-id pattern (they reach receipts and logs). */
export const STACK_ID_PATTERN = LANE_RELAY_ID_PATTERN;

/** A dstack app id: 20 bytes as 40 lower-case hex digits (the `app-id` event; relay-kit `APP_ID_PATTERN`). */
export const STACK_APP_ID_PATTERN = /^[0-9a-f]{40}$/;

/** `<repo>@sha256:<64 hex>`: a digest, never a tag (@gray/lane-compose `PINNED_IMAGE`, app-compose.mjs). */
export const STACK_IMAGE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$/;

/** S30: the relay's own `settings` object, as JSON text, is at most 64 KiB. */
export const STACK_SETTINGS_MAX_BYTES = 64 * 1024;

/**
 * The longest limit window an account may name: 7 days, the weekly limits of the Claude and Codex subscriptions
 * (their 5-hour windows are the other kind). `used_*` of a window comes from LANE_STACK_USAGE_KEEP_DAYS of usage
 * (@gray/config), whose minimum covers it (S31).
 */
export const LANE_STACK_WINDOW_MAX_SECONDS = 7 * 86_400;

/** An appended text can be no longer than everything one request may have appended (@gray/lane, review.md 3.5). */
export const STACK_APPEND_MAX_BYTES = DEFAULT_MAX_TOTAL_BYTES;

/** Where a text may be appended: @gray/lane's four positions. */
export const STACK_APPEND_POSITIONS: readonly Position[] = POSITIONS;

/** A u32 count, as the other console inputs bound theirs. */
const U32 = 4_294_967_295;
const u64 = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

// The console's wording of each refusal.
export const STACK_ID_RULE = "An id or a label is 1-128 characters of A-Z a-z 0-9 . _ : -.";
export const STACK_APP_ID_RULE = "A dstack app id is 40 lower-case hex digits.";
export const STACK_TOKEN_URL_RULE = "The pull-token service's address is an https origin without a path, a query or a fragment: pre-launch appends /v1/pull-token/... to it.";
export const STACK_REGISTRY_RULE = "A registry is a host name with an optional port, as docker login takes it, in lower case: no scheme, path or user.";
export const STACK_IMAGE_RULE = "The relay's image is pinned by its digest: <repository>@sha256:<64 lower-case hex digits>.";
export const STACK_SETTINGS_RULE = `The relay's settings are a JSON object of at most ${STACK_SETTINGS_MAX_BYTES} bytes.`;
export const STACK_MODELS_RULE = "An account's models are distinct model IDs (a letter or digit, then letters, digits and . _ : @ + / -, at most 256).";
export const STACK_LABELS_RULE = "An account's labels are distinct, each 1-128 characters of A-Z a-z 0-9 . _ : -.";
export const STACK_WINDOWS_RULE = `An account's limit windows have distinct lengths of 1 to ${LANE_STACK_WINDOW_MAX_SECONDS} seconds (7 days).`;
export const STACK_PROXY_HOST_RULE = "A proxy host is a name or an IP address without a scheme, user, port, path or brackets.";
export const STACK_APPEND_RULE = `An appended text is non-empty, well-formed text of at most ${STACK_APPEND_MAX_BYTES} UTF-8 bytes.`;

/**
 * Who inserts the relay's registered appends (relay standard v1.7 §2): `relay`, its container as before, or `gray`, the
 * entry, which serves a declared container `"appends": []` (the lane's stack document). A panel switch on the relay's
 * settings, carried in `stack.config` as `appends_by`.
 */
export const STACK_APPENDS_BY = ["relay", "gray"] as const;
export type StackAppendsBy = (typeof STACK_APPENDS_BY)[number];

// ------------------------------------------------------------------------------------------- own calls (upkeep)

/**
 * Egress's own calls of each account (docs/relay-changes-v2.md section 6, deploy/tee/egress/stack_ops.go): it runs
 * `limits` and `models` from its vendor table on its own schedule. The relay sets the cadence per operation:
 * `own_calls.every_seconds.{limits,models}`, seconds between runs per account, 0 for off, null for the vendor's
 * default. Egress holds a value to the vendor's own bounds; these are the widest of them across the table
 * (deploy/tee/egress/vendor-ops-v1.json `every_seconds`; the gateway's tests hold the two equal), so the console
 * refuses only what no vendor takes. Absent: both null.
 */
export const STACK_OWN_CALL_OPS = ["limits", "models"] as const;
export type StackOwnCallOp = (typeof STACK_OWN_CALL_OPS)[number];
export const STACK_OWN_CALL_BOUNDS: Readonly<Record<StackOwnCallOp, { readonly min: number; readonly max: number }>> = Object.freeze({
  limits: Object.freeze({ min: 60, max: 86_400 }),
  models: Object.freeze({ min: 300, max: 86_400 }),
});
export const STACK_OWN_CALLS_RULE =
  `Own calls: every_seconds.limits is 0 (off) or ${STACK_OWN_CALL_BOUNDS.limits.min} to ${STACK_OWN_CALL_BOUNDS.limits.max}, ` +
  `every_seconds.models 0 (off) or ${STACK_OWN_CALL_BOUNDS.models.min} to ${STACK_OWN_CALL_BOUNDS.models.max}, or null for the vendor's default.`;
export interface StackOwnCalls {
  readonly every_seconds: { readonly limits: number | null; readonly models: number | null };
}
export const STACK_OWN_CALLS_DEFAULT: StackOwnCalls = Object.freeze({ every_seconds: Object.freeze({ limits: null, models: null }) });

function ownCallSeconds(op: StackOwnCallOp) {
  const { min, max } = STACK_OWN_CALL_BOUNDS[op];
  return z
    .number()
    .int(STACK_OWN_CALLS_RULE)
    .refine((s) => s === 0 || (s >= min && s <= max), { message: STACK_OWN_CALLS_RULE })
    .nullable()
    .default(null);
}

/**
 * Where an account's OAuth token is refreshed (section 6): `source`, the relay's software outside the VM, as before
 * (the default), or `gray`, egress before expiry, whose token gray-relay writes back to the account source. Egress
 * refreshes only accounts whose vendor table has a `refresh` operation and whose sealed credential has a refresh
 * token; on any other account `gray` does nothing.
 */
export const STACK_REFRESH_MODES = ["source", "gray"] as const;
export type StackRefreshMode = (typeof STACK_REFRESH_MODES)[number];

/**
 * The relay's own record (`PUT`/`POST` body): every member, null where the relay has not named it yet; `appends_by`
 * `relay` when not named. The dstack app id is Gray's, with the lane origin and the KMS CA key
 * (`stackInstanceInputSchema`): a body that names one is refused.
 */
export const stackRelayInputSchema = z
  .object({
    token_url: z.string().nullable().default(null),
    registry: z.string().nullable().default(null),
    image: z.string().nullable().default(null),
    settings: z.record(z.string(), z.unknown()).default({}),
    appends_by: z.enum(STACK_APPENDS_BY).default("relay"),
    own_calls: z
      .object({ every_seconds: z.object({ limits: ownCallSeconds("limits"), models: ownCallSeconds("models") }).strict().default(STACK_OWN_CALLS_DEFAULT.every_seconds) })
      .strict()
      .default(STACK_OWN_CALLS_DEFAULT),
  })
  .strict();
export type StackRelayInput = z.infer<typeof stackRelayInputSchema>;

/** One limit window of an account (section 8 `windows`): its length and limits, 0 for none. */
export const stackWindowSchema = z
  .object({
    seconds: z.number().int().min(1).max(LANE_STACK_WINDOW_MAX_SECONDS),
    max_requests: u64.default(0),
    max_tokens: u64.default(0),
  })
  .strict();
export type StackWindow = z.infer<typeof stackWindowSchema>;

/** An identity profile's name (`.../identity-profiles/{name}`): lower-case letters, digits, `_` and `-`, a letter or digit first, at most 64. */
export const STACK_IDENTITY_PROFILE_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export const STACK_IDENTITY_PROFILE_RULE = "An identity profile's name is 1 to 64 of a-z, 0-9, _ and -, starting with a letter or a digit.";

/**
 * A client identity as a body carries it (S32a): the shape only; which names a vendor's route takes and the values'
 * rules are `@gray/lane-wire`'s (`stackIdentitySchema`, `stackIdentityProblem`), which the console applies.
 */
export const stackIdentityInputSchema = z.object({ headers: z.record(z.string(), z.string()), betas: z.array(z.string()), generated: z.array(z.string()) }).strict();

/** An account (`PUT .../accounts/{id}` body). */
export const stackAccountInputSchema = z
  .object({
    vendor: z.enum(STACK_VENDORS),
    labels: z.array(z.string()).default([]),
    models: z.array(z.string()).default([]),
    weight: z.number().int().min(1).max(U32).default(1),
    max_concurrency: z.number().int().min(1).max(U32),
    windows: z.array(stackWindowSchema).default([]),
    status: z.enum(STACK_ACCOUNT_STATUSES).default("active"),
    proxy_id: z.string().nullable().default(null),
    /** The sealed credential version the entry waits for; 0 takes any. */
    credential_version: u64.default(0),
    /** The type of credential the relay seals for the account; null: not declared. */
    credential_type: z.enum(["api_key", "oauth_access_token"]).nullable().default(null),
    /**
     * The client identity the relay registers for the account (S32a, the owner's trust-model decision of 2026-10-29):
     * the static `headers` and Anthropic `betas` of the vendor's own client and the ids egress makes itself
     * (`generated`), which egress holds the account's calls to. Which names a vendor's route takes and the values'
     * rules are `@gray/lane-wire`'s (`stackIdentitySchema`, `stackIdentityProblem`), which the console applies; null:
     * none. An account replaced without it has none.
     */
    identity: stackIdentityInputSchema.nullable().default(null),
    /**
     * The relay's identity profile the account takes its client identity from (`.../identity-profiles/{name}`), or
     * null. An inline `identity` wins when both are set; the profile must be of the account's vendor. An account
     * replaced without it names none.
     */
    identity_profile: z.string().regex(STACK_IDENTITY_PROFILE_PATTERN, STACK_IDENTITY_PROFILE_RULE).nullable().default(null),
    /** Where the account's OAuth token is refreshed (`STACK_REFRESH_MODES`); an account replaced without it is `source`. */
    refresh: z.enum(STACK_REFRESH_MODES).default("source"),
  })
  .strict();
export type StackAccountInput = z.infer<typeof stackAccountInputSchema>;

/**
 * An identity profile (`PUT .../identity-profiles/{name}` body): a vendor and a client identity, or a preset of
 * Gray's (`GET .../identity-presets`) to copy; the `none` preset names no vendor, so its body names one.
 */
export const stackIdentityProfileInputSchema = z.union([
  z.object({ vendor: z.enum(STACK_VENDORS), identity: stackIdentityInputSchema }).strict(),
  z.object({ preset: z.string().min(1).max(64), vendor: z.enum(STACK_VENDORS).optional() }).strict(),
]);
export type StackIdentityProfileInput = z.infer<typeof stackIdentityProfileInputSchema>;

/** The most accounts one batch names: the most a relay's VM serves (`@gray/relay-connector` DEFAULT_MAX_ACCOUNTS_PER_RELAY, S42). */
export const STACK_ACCOUNTS_PATCH_MAX = 1000;

/**
 * A batch edit of accounts (`PATCH .../accounts` body): for every listed account, the identity profile (null clears
 * it) and the token refresh mode, each only when named; at least one of them.
 */
export const stackAccountsPatchSchema = z
  .object({
    account_ids: z.array(z.string()).min(1).max(STACK_ACCOUNTS_PATCH_MAX),
    identity_profile: z.string().regex(STACK_IDENTITY_PROFILE_PATTERN, STACK_IDENTITY_PROFILE_RULE).nullable().optional(),
    refresh: z.enum(STACK_REFRESH_MODES).optional(),
  })
  .strict()
  .refine((b) => b.identity_profile !== undefined || b.refresh !== undefined, { message: "A batch edit names identity_profile, refresh or both." });
export type StackAccountsPatch = z.infer<typeof stackAccountsPatchSchema>;

/** A proxy (`PUT .../proxies/{id}` body); its user name and password are sealed, never sent here. */
export const stackProxyInputSchema = z
  .object({
    type: z.enum(EGRESS_TYPES),
    host: z.string(),
    port: z.number().int().min(1).max(65_535),
    credential_version: u64.default(0),
  })
  .strict();
export type StackProxyInput = z.infer<typeof stackProxyInputSchema>;

/** An appended text (`PUT .../appends/{id}` body). */
export const stackAppendInputSchema = z.object({ position: z.enum(POSITIONS), text: z.string() }).strict();
export type StackAppendInput = z.infer<typeof stackAppendInputSchema>;

/** One route's visibility (`PUT .../routes` body): a mapping of one of the relay's stack endpoints. */
export const stackRouteInputSchema = z.object({ endpoint_id: z.string(), requested_model: z.string(), protocol: z.string(), visible: z.boolean() }).strict();
export type StackRouteInput = z.infer<typeof stackRouteInputSchema>;

/** Whether `id` is an account, proxy, append or issue id, or a label. */
export function validStackId(id: string): boolean {
  return STACK_ID_PATTERN.test(id);
}

/** Whether `registry` is `host[:port]` as the WHATWG URL parser reads it back unchanged (no scheme, user, path). */
export function validRegistry(registry: string): boolean {
  if (registry === "" || /[/\\?#@\s]/.test(registry)) return false;
  try {
    const url = new URL(`https://${registry}`);
    return url.host === registry && url.hostname !== "" && url.pathname === "/";
  } catch {
    return false;
  }
}

function refuse(rule: string): never {
  throw new InvalidConfig(rule);
}

/** The relay record's rules; `settingsJson` is the settings object as the console stores it. */
export function checkStackRelay(input: StackRelayInput, settingsJson: string): void {
  if (input.token_url !== null && !validSchedulerUrl(input.token_url)) refuse(STACK_TOKEN_URL_RULE);
  if (input.registry !== null && !validRegistry(input.registry)) refuse(STACK_REGISTRY_RULE);
  if (input.image !== null && !STACK_IMAGE_PATTERN.test(input.image)) refuse(STACK_IMAGE_RULE);
  if (utf8Length(settingsJson) > STACK_SETTINGS_MAX_BYTES) refuse(STACK_SETTINGS_RULE);
}

function distinct(values: readonly unknown[]): boolean {
  return new Set(values).size === values.length;
}

/** An account's own rules (its proxy's existence is the store's). */
export function checkStackAccount(input: StackAccountInput): void {
  if (!input.labels.every(validStackId) || !distinct(input.labels)) refuse(STACK_LABELS_RULE);
  if (!input.models.every(validModelId) || !distinct(input.models)) refuse(STACK_MODELS_RULE);
  if (!distinct(input.windows.map((w) => w.seconds))) refuse(STACK_WINDOWS_RULE);
  if (input.proxy_id !== null && !validStackId(input.proxy_id)) refuse(STACK_ID_RULE);
}

/** A proxy's own rules: the egress sidecar's host rule (@gray/relay-connector `isValidEgressHost`). */
export function checkStackProxy(input: StackProxyInput): void {
  if (!isValidEgressHost(input.host)) refuse(STACK_PROXY_HOST_RULE);
}

/** An appended text's own rules: what @gray/lane's template registry accepts of a text. */
export function checkStackAppend(input: StackAppendInput): void {
  if (input.text === "" || !input.text.isWellFormed() || utf8Length(input.text) > STACK_APPEND_MAX_BYTES) refuse(STACK_APPEND_RULE);
}

// ------------------------------------------------------------------------------------- the published instance (S12)

/**
 * The node KMS's `ca_pubkey` a relay pins in `lane.instances` (S12): a P-256 SubjectPublicKeyInfo, 91 bytes as 182
 * lower-case hex digits. relay-kit's `KMS_CA_PUBKEY_PATTERN` (src/lane-binding.ts), the rule
 * `deploy/tee/app-compose.mjs` applies to `--kms-ca-pubkey`; relay-kit's tests hold the two to one text.
 */
export const STACK_KMS_CA_PUBKEY_PATTERN = /^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$/;

export const STACK_LANE_ORIGIN_RULE =
  "A relay stack's lane origin is Gray's entry tunnel route for the relay, spelled as itself: https://<entry>/v1/peer/tunnel/<relay_id>. " +
  "A stack VM takes no inbound connection, so it has no address of its own.";
export const STACK_LANE_TUNNEL_RULE = "A tunnel lane origin names the relay it is published for: https://<entry>/v1/peer/tunnel/<this relay's id>, not another relay's.";
export const STACK_LANE_TUNNEL_NO_ENTRY_RULE =
  "This deployment names no entry (LANE_STACK_ENTRY_ORIGIN is empty), so it publishes no tunnel lane origin: configure the entry an outbound-only VM is reached through first.";
/** The refusal of a tunnel lane origin through another entry than this deployment's (LANE_STACK_ENTRY_ORIGIN). */
export function stackLaneTunnelEntryRule(entryOrigin: string): string {
  return `A tunnel lane origin goes through this deployment's entry, ${entryOrigin}: ${entryOrigin}${PEER_TUNNEL_PATH}<relay_id>.`;
}
export const STACK_KMS_CA_PUBKEY_RULE = "A KMS CA public key is the node KMS's ca_pubkey: a P-256 SubjectPublicKeyInfo as 182 lower-case hex digits.";

/** Whether `origin` is an https origin as `new URL(origin).origin` writes it (what relay-kit's `lane.instances` keys on). */
export function validLaneOrigin(origin: string): boolean {
  if (!validSchedulerUrl(origin)) return false;
  try {
    return new URL(origin).origin === origin;
  } catch {
    return false;
  }
}

/**
 * The entry's tunnel route (docs/design/relay-outbound-only.md section 5): an outbound-only VM's lane origin, the one
 * gray-relay adopts from Gray's answer (relay-kit's `src/lane-origin.ts` is the client's side of the same form).
 */
export const PEER_TUNNEL_PATH = "/v1/peer/tunnel/";

/**
 * The entry and relay a tunnel lane origin names (`https://<entry>/v1/peer/tunnel/<relay>`, spelled as itself: the
 * entry a `validLaneOrigin`, one relay id and nothing after it), or null when `origin` is not one (a plain origin
 * included).
 */
export function tunnelOriginParts(origin: string): { readonly entry: string; readonly relayId: string } | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (!url.pathname.startsWith(PEER_TUNNEL_PATH) || !validLaneOrigin(url.origin)) return null;
  const relayId = url.pathname.slice(PEER_TUNNEL_PATH.length);
  if (!LANE_RELAY_ID_PATTERN.test(relayId) || relayId === "." || relayId === "..") return null;
  return `${url.origin}${PEER_TUNNEL_PATH}${relayId}` === origin ? { entry: url.origin, relayId } : null;
}

/** The relay a tunnel lane origin names (`tunnelOriginParts`), or null when `origin` is not one. */
export function tunnelRelayOf(origin: string): string | null {
  return tunnelOriginParts(origin)?.relayId ?? null;
}

/**
 * What Gray's operators publish of a relay stack's lane instance (`PUT /api/v1/ops/lane-stacks/{relay_id}/instance`):
 * Gray's deployment of the relay's VM, the three values a relay pins in `lane.instances` (S12): the dstack app id, the
 * lane's origin and the KMS CA key its key-provider event names, each null until known, with the operator's reason.
 * The relay's own members cannot set them.
 */
export const stackInstanceInputSchema = z
  .object({
    app_id: z.string().nullable(),
    lane_origin: z.string().nullable(),
    kms_ca_pubkey: z.string().nullable(),
    reason: z.string(),
  })
  .strict();
export type StackInstanceInput = z.infer<typeof stackInstanceInputSchema>;

/**
 * The instance values of relay `relayId`'s record: a lane origin is the entry's tunnel route of this relay through
 * this deployment's entry (`entryOrigin`, LANE_STACK_ENTRY_ORIGIN; null when none is configured), since every stack VM
 * is outbound-only (docs/design/relay-outbound-only.md section 5). Each refusal has its own rule: not a tunnel route,
 * no entry configured, another entry (the rule names the expected one, so a typo is not a VM nobody reaches), or
 * another relay's tunnel (gray-relay would refuse to adopt it).
 */
export function checkStackInstance(input: Pick<StackInstanceInput, "app_id" | "lane_origin" | "kms_ca_pubkey">, relayId: string, entryOrigin: string | null): void {
  if (input.app_id !== null && !STACK_APP_ID_PATTERN.test(input.app_id)) refuse(STACK_APP_ID_RULE);
  if (input.lane_origin !== null) {
    const tunnel = tunnelOriginParts(input.lane_origin);
    if (tunnel === null) refuse(STACK_LANE_ORIGIN_RULE);
    if (entryOrigin === null || entryOrigin === "") refuse(STACK_LANE_TUNNEL_NO_ENTRY_RULE);
    if (tunnel.entry !== entryOrigin) refuse(stackLaneTunnelEntryRule(entryOrigin));
    if (tunnel.relayId !== relayId) refuse(STACK_LANE_TUNNEL_RULE);
  }
  if (input.kms_ca_pubkey !== null && !STACK_KMS_CA_PUBKEY_PATTERN.test(input.kms_ca_pubkey)) refuse(STACK_KMS_CA_PUBKEY_RULE);
}

// ------------------------------------------------------------------------------------- the served configuration (S21a)

/** One route as the configuration serves it: an enabled stack endpoint's mapping. */
export interface StackServedRoute {
  readonly endpoint_id: string;
  readonly requested_model: string;
  readonly protocol: string;
}

/**
 * S21a: a relay stack's configuration has at most one route per protocol and requested model (its router picks by
 * both), and the routes come from the mappings of its enabled stack endpoints, so two endpoints could name the same
 * pair. The first such pair as the refusal's words, or null when there is none.
 */
export function stackRoutesProblem(routes: readonly StackServedRoute[]): string | null {
  const seen = new Map<string, string>();
  for (const r of routes) {
    const key = JSON.stringify([r.protocol, r.requested_model]);
    const first = seen.get(key);
    if (first === undefined) {
      seen.set(key, r.endpoint_id);
      continue;
    }
    return (
      `A relay stack serves one route per protocol and requested model: ${r.requested_model} (${r.protocol}) is mapped by its enabled ` +
      `endpoints ${first} and ${r.endpoint_id}. Remove the mapping from one of them, or disable one, first.`
    );
  }
  return null;
}

/** One appended text as the configuration serves it. */
export interface StackServedAppend {
  readonly append_id: string;
  readonly position: string;
  readonly text: string;
}

/**
 * S21a: the configuration never holds more appended texts than one request may carry, so a relay that inserts them
 * does not choose among them: per protocol, the texts at its positions (@gray/lane `POSITIONS_BY_PROTOCOL`) are at
 * most `DEFAULT_MAX_ITEMS` and `DEFAULT_MAX_TOTAL_BYTES` UTF-8 bytes together, @gray/lane's limits of one request,
 * which the lane's template registry applies. The first protocol over them as the refusal's words, or null.
 */
export function stackAppendsProblem(appends: readonly StackServedAppend[]): string | null {
  for (const protocol of LANE_PROTOCOLS) {
    const positions: readonly string[] = POSITIONS_BY_PROTOCOL[protocol];
    const at = appends.filter((a) => positions.includes(a.position));
    const bytes = at.reduce((sum, a) => sum + utf8Length(a.text), 0);
    if (at.length > DEFAULT_MAX_ITEMS || bytes > DEFAULT_MAX_TOTAL_BYTES) {
      return (
        `One ${protocol} request carries at most ${DEFAULT_MAX_ITEMS} appended texts of ${DEFAULT_MAX_TOTAL_BYTES} bytes together, and a relay ` +
        `stack's texts at ${positions.join(" and ")} would be ${at.length} of ${bytes} bytes. Remove or shorten one first.`
      );
    }
  }
  return null;
}

// ------------------------------------------------------------------------------------- pull-token issues (S13)

/**
 * One pull token the relay's token service issued (S13): when, until when, to which compose (its hash, the
 * quote's compose-hash event) and which quote (SHA-256 of the quote bytes). The relay signs it with its lane
 * record's Ed25519 key and reports it; the panel shows the latest. `expires_ms` is null when the relay's registry token
 * has no known expiry (relay standard v1.7: `stack.registry.expires_at` is optional).
 */
export const pullTokenIssueSchema = z
  .object({
    relay_id: z.string().regex(LANE_RELAY_ID_PATTERN),
    issue_id: z.string().regex(STACK_ID_PATTERN),
    issued_ms: u64,
    expires_ms: u64.nullable(),
    compose_hash: z.string().regex(/^[0-9a-f]{64}$/),
    quote_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict()
  .refine((r) => r.expires_ms === null || r.expires_ms >= r.issued_ms, { message: "expires_ms is before issued_ms", path: ["expires_ms"] });
export type PullTokenIssue = z.infer<typeof pullTokenIssueSchema>;

/** A report: the record and the relay's Ed25519 signature over `pullTokenIssueMessage`, 128 lower-case hex digits. */
export const pullTokenIssueReportSchema = z.object({ record: pullTokenIssueSchema, signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();
export type PullTokenIssueReport = z.infer<typeof pullTokenIssueReportSchema>;

/** The first line of the signed message: what the signature is for, so it can be read as nothing else. */
export const PULL_TOKEN_ISSUE_DOMAIN = "gray-relay-pull-token-issue/v1";

/**
 * The bytes the relay signs: the domain and each member on a line of its own, in this order, integers in decimal.
 * No member can hold a newline (each has a pattern), so one message has one reading. A null `expires_ms` is an empty
 * line (no integer is empty), so a record with an expiry signs exactly the bytes it did before.
 */
export function pullTokenIssueMessage(r: PullTokenIssue): Uint8Array {
  return new TextEncoder().encode([PULL_TOKEN_ISSUE_DOMAIN, r.relay_id, r.issue_id, String(r.issued_ms), r.expires_ms === null ? "" : String(r.expires_ms), r.compose_hash, r.quote_sha256].join("\n"));
}

/**
 * S53: a relay image reference, `<registry host[:port]>/<repository>@sha256:<64 hex>` (@gray/lane-verify
 * `STACK_RELAY_IMAGE_PATTERN`; pre-launch tests the same).
 */
export const STACK_RELAY_IMAGE_PATTERN = /^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)\/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$/;

/** Why a relay asks Gray to restart its app (S53): the image it rolled out or back to, or the same one again. */
export const STACK_RESTART_REASONS = ["rollout", "rollback", "restart"] as const;
export type StackRestartReason = (typeof STACK_RESTART_REASONS)[number];

/** A restart request id: `r` and 32 lower-case hex digits, fresh per request. */
export const STACK_RESTART_REQUEST_ID_PATTERN = /^r[0-9a-f]{32}$/;

/**
 * P7: a gray-assistant kit version as a restart request carries it: strict semver (node-semver), as its own text, no
 * newline. Build metadata is part of it: a released kit names its commit there (`1.3.0+2373d8cc36e3`,
 * deploy/relay/image/bundle.mjs), and the kit gate ignores it (`kitAtLeast`).
 */
function kitVersionText(text: string): boolean {
  if (/\s/.test(text)) return false;
  const version = semver.parse(text);
  if (version === null) return false;
  return (version.build.length === 0 ? version.version : `${version.version}+${version.build.join(".")}`) === text;
}
const restartKitSchema = z.string().min(5).max(80).refine(kitVersionText, { message: "a kit version is strict semver" });

/**
 * S53: the relay asks Gray to restart its stack app so the next boot takes the image its token service now names.
 * `image` is what the relay rolled out (null for a plain restart); Gray never acts on it, since the VM gets its image
 * from the token service at boot. The relay signs it with its lane record's Ed25519 key, as its issue reports.
 *
 * P7 (docs/design/relay-no-always-on-host.md 13.4): a phase-2 relay's tool adds its own version (`kit`), which the
 * console's rollout gate reads for a relay with no gray-relay daemon to report it, and the boot box version the VM's
 * receipt named (`boot_version`), which the provisioner waits for in Gray's copy before it starts a second instance.
 * Both optional; the signature covers them when present.
 */
export const stackRestartRequestSchema = z
  .object({
    relay_id: z.string().regex(LANE_RELAY_ID_PATTERN),
    request_id: z.string().regex(STACK_RESTART_REQUEST_ID_PATTERN),
    issued_ms: u64,
    app_id: z.string().regex(STACK_APP_ID_PATTERN),
    reason: z.enum(STACK_RESTART_REASONS),
    image: z.string().max(512).regex(STACK_RELAY_IMAGE_PATTERN).nullable(),
    kit: restartKitSchema.optional(),
    boot_version: u64.optional(),
  })
  .strict()
  .refine((r) => r.reason === "restart" || r.image !== null, { message: "a rollout or rollback names its image", path: ["image"] });
export type StackRestartRequest = z.infer<typeof stackRestartRequestSchema>;

/** The request and the relay's Ed25519 signature over `stackRestartRequestMessage`, 128 lower-case hex digits. */
export const stackRestartRequestReportSchema = z.object({ request: stackRestartRequestSchema, signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();
export type StackRestartRequestReport = z.infer<typeof stackRestartRequestReportSchema>;

/** The first line of the signed restart request. */
export const STACK_RESTART_REQUEST_DOMAIN = "gray-relay-stack-restart/v1";

/**
 * The bytes the relay signs: the domain and each member on its own line, in this order; a null image is empty. P7's
 * `kit` and `boot_version` add two lines (an absent one empty) only when either is present, so a request without them
 * signs exactly the bytes it did before, and one message has one reading (seven lines or nine).
 */
export function stackRestartRequestMessage(r: StackRestartRequest): Uint8Array {
  const lines = [STACK_RESTART_REQUEST_DOMAIN, r.relay_id, r.request_id, String(r.issued_ms), r.app_id, r.reason, r.image ?? ""];
  if (r.kit !== undefined || r.boot_version !== undefined) lines.push(r.kit ?? "", r.boot_version === undefined ? "" : String(r.boot_version));
  return new TextEncoder().encode(lines.join("\n"));
}

/** Where a restart request stands: recorded and waiting, or settled by the provisioner or Gray's operator. */
export const STACK_RESTART_STATUSES = ["pending", "done", "failed", "superseded"] as const;
export type StackRestartStatus = (typeof STACK_RESTART_STATUSES)[number];
