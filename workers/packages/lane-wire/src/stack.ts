import { sha256BareHex } from "@gray/attest";
import { toJsonString, type Json } from "@gray/json";
import { LANE_STACK_VENDORS, OPENAI_COMPATIBLE_VENDOR_IDS, type LaneStackVendor } from "@gray/lane";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import { BRIDGE_LINE_PATTERN } from "./ops.ts";
import {
  STACK_CREDENTIAL_TYPES,
  STACK_IDENTITY_GENERATED,
  STACK_IDENTITY_GENERATED_ANTHROPIC,
  STACK_IDENTITY_GENERATED_CHATGPT,
  STACK_IDENTITY_HEADERS,
  STACK_IDENTITY_STATIC_ANTHROPIC,
  STACK_IDENTITY_STATIC_CHATGPT,
  STACK_IDENTITY_STATIC_OPENAI,
  STACK_REFRESH_MODES,
  type StackRefreshMode,
} from "./stack-health.ts";

/**
 * `stack.config` (docs/confidential-lane-supply-implementation.md S28, section 8, package E): the metadata of one
 * relay stack, which the entry in the VM joins with the credentials gray-relay sealed to it into the configuration
 * document it serves the relay's container. No secret is in it (S29).
 *
 * The request names the relay and the version the entry has (`have`); the answer carries the control plane's
 * version and the digest of the configuration, and the configuration itself only when `have` is not that version
 * (`have: 0` always gets it). `version` grows with every change of what is served (the console's triggers,
 * workers/db/migrations/0029_lane_stack.sql), so the entry polls with the version it has and rebuilds on a change.
 *
 * The used counters of each limit window (`used_requests`, `used_tokens`, S31) and `used_at_ms` are read when the
 * configuration is served: they are not configuration, and neither the version nor the digest covers them.
 * `settings_json` is the relay's own settings object as JSON text, byte for byte as the console stored it (S30).
 * `appends_by` (relay standard v1.7 §2) is the panel's switch for who inserts the relay's appends: `relay` (the
 * default) or `gray`, the entry. The console always sends it; a document without it reads as `relay`.
 * An account's `refresh` and the relay's `own_calls` are egress's account upkeep (docs/relay-changes-v2.md section 6,
 * `stackOwnCallSettings`): absent when they say nothing (`source`, the vendor's default cadence).
 *
 * The integer rule is the bridge's (ints.ts): integers are bigints on the wire; the console answers with JS numbers
 * and the converters below are where the two meet.
 */

/** The target of one `stack.config` call: the relay, namespaced as `scheduler/<relay_id>` is. */
export const STACK_TARGET_PREFIX = "stack/";

/** `stack/<relay_id>`, the target a `stack.config` call signs. */
export function stackTarget(relayId: string): string {
  const target = `${STACK_TARGET_PREFIX}${relayId}`;
  if (!BRIDGE_LINE_PATTERN.test(target)) throw new BridgeWireError("invalid_target", null, "a relay id is printable ASCII without spaces, which a target can carry");
  return target;
}

/** A relay, account, proxy or append id: the lane's relay-id pattern (`@gray/control` LANE_RELAY_ID_PATTERN). */
const id = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

export const stackConfigRequestSchema = z.object({ relay_id: id, have: uintSchema }).strict();
export type StackConfigRequestDto = z.infer<typeof stackConfigRequestSchema>;

const windowSchema = z.object({ seconds: uintSchema, max_requests: uintSchema, max_tokens: uintSchema, used_requests: uintSchema, used_tokens: uintSchema }).strict();

/** S32a's identity bounds (egress `stack_identity.go`): headers, a value's bytes, betas. */
export const STACK_IDENTITY_HEADERS_MAX = 16;
export const STACK_IDENTITY_VALUE_MAX = 512;
export const STACK_IDENTITY_BETAS_MAX = 8;
/** An identity header's value: 1 to 512 bytes of printable ASCII, no space at either end. */
export const STACK_IDENTITY_VALUE_PATTERN = /^[\x21-\x7e](?:[\x20-\x7e]{0,510}[\x21-\x7e])?$/;

/** A relay stack's account and route vendor (section 8): `@gray/lane` LANE_STACK_VENDORS. */
export type StackVendorName = LaneStackVendor;

interface StackIdentityRoute {
  readonly static: readonly string[];
  readonly generated: readonly string[];
  readonly betas: boolean;
}

/**
 * The identity names each vendor's route takes: its static headers and the ids egress makes there (S32a). An
 * OpenAI-compatible vendor's route takes `/openai`'s: `user-agent` and `accept`, no generated id.
 */
export const STACK_IDENTITY_ROUTES: Readonly<Record<StackVendorName, StackIdentityRoute>> = Object.freeze({
  anthropic: { static: STACK_IDENTITY_STATIC_ANTHROPIC, generated: STACK_IDENTITY_GENERATED_ANTHROPIC, betas: true },
  openai: { static: STACK_IDENTITY_STATIC_OPENAI, generated: [] as readonly string[], betas: false },
  chatgpt_codex: { static: STACK_IDENTITY_STATIC_CHATGPT, generated: STACK_IDENTITY_GENERATED_CHATGPT, betas: false },
  ...(Object.fromEntries(OPENAI_COMPATIBLE_VENDOR_IDS.map((id) => [id, { static: STACK_IDENTITY_STATIC_OPENAI, generated: [], betas: false }])) as unknown as Record<
    (typeof OPENAI_COMPATIBLE_VENDOR_IDS)[number],
    StackIdentityRoute
  >),
});

/**
 * An account's client identity (S32a, the owner's trust-model decision of 2026-10-29): the static `headers` of the
 * vendor's own client the relay registered for the account (at most 16, each value 1 to 512 bytes of printable ASCII
 * with no space at either end), the Anthropic `betas` it sends (`anthropic-beta`, at most 8), and the ids egress makes
 * itself per call or session (`generated`). Egress holds each of the account's calls to it. The names are the closed
 * lists of stack-health.ts; which a route takes is `stackIdentityProblem`'s.
 */
export const stackIdentitySchema = z
  .object({
    headers: z.partialRecord(z.enum(STACK_IDENTITY_HEADERS), z.string().regex(STACK_IDENTITY_VALUE_PATTERN)),
    betas: z.array(z.string().regex(/^[a-z0-9-]{1,64}$/)).max(STACK_IDENTITY_BETAS_MAX),
    generated: z.array(z.enum(STACK_IDENTITY_GENERATED)),
  })
  .strict()
  .refine((i) => Object.keys(i.headers).length <= STACK_IDENTITY_HEADERS_MAX, { message: `at most ${STACK_IDENTITY_HEADERS_MAX} headers`, path: ["headers"] })
  .refine((i) => new Set(i.betas).size === i.betas.length && new Set(i.generated).size === i.generated.length, { message: "a beta or a generated id is listed twice" });
export interface StackIdentity {
  readonly headers: Readonly<Partial<Record<(typeof STACK_IDENTITY_HEADERS)[number], string>>>;
  readonly betas: readonly string[];
  readonly generated: readonly (typeof STACK_IDENTITY_GENERATED)[number][];
}

/** Why `identity` does not fit a `vendor` account's route (a header or an id the route does not take, betas off Anthropic), or null. */
export function stackIdentityProblem(vendor: StackVendorName, identity: StackIdentity): string | null {
  const route = STACK_IDENTITY_ROUTES[vendor];
  const staticNames: readonly string[] = route.static;
  const generatedNames: readonly string[] = route.generated;
  const header = Object.keys(identity.headers).find((name) => !staticNames.includes(name));
  if (header !== undefined) return `${header} is not a header a ${vendor} account's identity sets (${staticNames.join(", ")})`;
  const made = identity.generated.find((name) => !generatedNames.includes(name));
  if (made !== undefined) return generatedNames.length === 0 ? `egress makes no id for a ${vendor} account` : `${made} is not an id egress makes for a ${vendor} account (${generatedNames.join(", ")})`;
  if (!route.betas && identity.betas.length > 0) return "betas are an Anthropic account's";
  return null;
}

// Where an account's OAuth token is refreshed (`@gray/control` STACK_REFRESH_MODES; absent is `source`): stack-health.ts's
// STACK_REFRESH_MODES, which the report's refresh names too.

/**
 * One upstream account (section 8): vendors as section 8 names them, `@gray/control` STACK_VENDORS. `credential_type`
 * (the sealed credential's type the relay declares) and `identity` (S32a) are later members: absent when the relay set
 * none, so an entry that predates them still reads every configuration whose accounts set none.
 */
const accountSchema = z
  .object({
    id,
    vendor: z.enum(LANE_STACK_VENDORS),
    labels: z.array(z.string()),
    models: z.array(z.string()),
    weight: uintSchema,
    max_concurrency: uintSchema,
    windows: z.array(windowSchema),
    status: z.enum(["active", "paused"]),
    proxy_id: id.nullable(),
    credential_version: uintSchema,
    credential_type: z.enum(STACK_CREDENTIAL_TYPES).optional(),
    identity: stackIdentitySchema.optional(),
    refresh: z.enum(STACK_REFRESH_MODES).optional(),
  })
  .strict()
  .superRefine((a, ctx) => {
    const problem = a.identity === undefined ? null : stackIdentityProblem(a.vendor, a.identity as StackIdentity);
    if (problem !== null) ctx.addIssue({ code: "custom", path: ["identity"], message: problem });
  });

/** One egress proxy: the types are @gray/relay-connector's EGRESS_TYPES, the egress sidecar's. */
const proxySchema = z.object({ id, type: z.enum(["http", "https", "socks5", "socks5h"]), host: z.string(), port: uintSchema, credential_version: uintSchema }).strict();

/** One route: a mapping of one of the relay's stack endpoints. */
const routeSchema = z.object({ requested_model: z.string(), upstream_model: z.string(), vendor: z.enum(LANE_STACK_VENDORS), protocol: z.string(), visible: z.boolean() }).strict();

/** One appended text: positions are @gray/lane's (GRAY_LANE_REWRITES_V1); `sha256` of its UTF-8 bytes. */
const appendSchema = z.object({ id, position: z.enum(["system_start", "system_end", "instructions_before", "instructions_after"]), text: z.string(), sha256: hex64 }).strict();

/** Egress's own-call cadence: seconds between `limits` and `models` runs per account, 0 off, absent the vendor's default. */
const ownCallsSchema = z.object({ every_seconds: z.object({ limits: uintSchema.optional(), models: uintSchema.optional() }).strict() }).strict();

export const stackConfigDocumentSchema = z
  .object({
    relay_id: id,
    version: uintSchema,
    app_id: z.string().nullable(),
    token_url: z.string().nullable(),
    registry: z.string().nullable(),
    image: z.string().nullable(),
    settings_json: z.string(),
    accounts: z.array(accountSchema),
    proxies: z.array(proxySchema),
    routes: z.array(routeSchema),
    appends: z.array(appendSchema),
    appends_by: z.enum(["relay", "gray"]).default("relay"),
    own_calls: ownCallsSchema.optional(),
    used_at_ms: uintSchema,
  })
  .strict();
export type StackConfigDocumentDto = z.infer<typeof stackConfigDocumentSchema>;

/**
 * An entry name a stack VM dials (docs/design/relay-outbound-only.md section 3.2): a lowercase DNS name. `entries` is the
 * environment's list (`stack.entries`); absent, the VM keeps the image's default for the environment. The VM attests
 * every entry it dials, so a wrong list costs availability only.
 */
export const STACK_ENTRY_NAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
/** The most entry names one answer carries. */
export const STACK_ENTRIES_MAX = 16;
const entryName = z.string().regex(STACK_ENTRY_NAME);

/**
 * Why `addr` is not an entry's dial address (`<DNS name or IP>:<port>`, peerlink's `validDialAddr`), or null. The host
 * must be one the WHATWG URL parser writes as it is (a lowercase DNS name of two or more labels, a dotted IPv4, or a
 * bracketed IPv6), and the port a decimal 1 to 65535 without a leading zero.
 */
export function stackEntryAddrProblem(addr: string): string | null {
  const colon = addr.lastIndexOf(":");
  if (colon <= 0) return "is not <host>:<port>";
  const host = addr.slice(0, colon);
  const port = addr.slice(colon + 1);
  if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) return "has no port from 1 to 65535";
  let parsed: string;
  try {
    parsed = new URL(`https://${host}/`).hostname;
  } catch {
    return "is not a host";
  }
  if (parsed !== host) return "is not a host as written";
  if (!host.startsWith("[") && !/^[0-9.]+$/.test(host) && !STACK_ENTRY_NAME.test(host)) return "is not a DNS name of two or more labels or an IP";
  return null;
}

/**
 * `entry_addrs` (docs/design/relay-outbound-only.md section 8.4): for an entry of `entries`, the address the VM's
 * peerlink dials before `<entry>:443`, for example the entry's door at Phala's gateway, so the peer leg does not cross
 * Cloudflare. SNI, the certificate name and the attested pin stay the entry's; an address that fails falls back to
 * `<entry>:443`. Absent: every entry is dialed by its name.
 */
const entryAddrSchema = z
  .object({ entry: entryName, addr: z.string().refine((addr) => stackEntryAddrProblem(addr) === null) })
  .strict();

export const stackConfigAnswerSchema = z
  .object({
    relay_id: id,
    version: uintSchema,
    digest: hex64,
    config: stackConfigDocumentSchema.nullable(),
    entries: z.array(entryName).min(1).max(STACK_ENTRIES_MAX).optional(),
    entry_addrs: z.array(entryAddrSchema).min(1).max(STACK_ENTRIES_MAX).optional(),
  })
  .strict()
  .refine(
    (answer) => {
      const addrs = answer.entry_addrs ?? [];
      const named = new Set(answer.entries ?? []);
      return addrs.every((row) => named.has(row.entry)) && new Set(addrs.map((row) => row.entry)).size === addrs.length;
    },
    { message: "entry_addrs names an entry of entries, once each", path: ["entry_addrs"] },
  );
export type StackConfigAnswerDto = z.infer<typeof stackConfigAnswerSchema>;

/** The configuration as the console builds it and the entry uses it: the wire document with JS numbers. */
export interface StackConfigWindow {
  readonly seconds: number;
  readonly max_requests: number;
  readonly max_tokens: number;
  readonly used_requests: number;
  readonly used_tokens: number;
}
export interface StackConfigAccount {
  readonly id: string;
  readonly vendor: StackVendorName;
  readonly labels: readonly string[];
  readonly models: readonly string[];
  readonly weight: number;
  readonly max_concurrency: number;
  readonly windows: readonly StackConfigWindow[];
  readonly status: "active" | "paused";
  readonly proxy_id: string | null;
  readonly credential_version: number;
  /** The sealed credential's type the relay declares; absent when it declared none. */
  readonly credential_type?: (typeof STACK_CREDENTIAL_TYPES)[number];
  /** The account's client identity (S32a); absent when the relay registered none. */
  readonly identity?: StackIdentity;
  /** Where the account's OAuth token is refreshed (section 6); absent: `source`. */
  readonly refresh?: StackRefreshMode;
}
export interface StackConfigProxy {
  readonly id: string;
  readonly type: "http" | "https" | "socks5" | "socks5h";
  readonly host: string;
  readonly port: number;
  readonly credential_version: number;
}
export interface StackConfigRoute {
  readonly requested_model: string;
  readonly upstream_model: string;
  readonly vendor: StackVendorName;
  readonly protocol: string;
  readonly visible: boolean;
}
export interface StackConfigAppend {
  readonly id: string;
  readonly position: "system_start" | "system_end" | "instructions_before" | "instructions_after";
  readonly text: string;
  readonly sha256: string;
}
export interface StackConfigDocument {
  readonly relay_id: string;
  readonly version: number;
  readonly app_id: string | null;
  readonly token_url: string | null;
  readonly registry: string | null;
  readonly image: string | null;
  readonly settings_json: string;
  readonly accounts: readonly StackConfigAccount[];
  readonly proxies: readonly StackConfigProxy[];
  readonly routes: readonly StackConfigRoute[];
  readonly appends: readonly StackConfigAppend[];
  /** Who inserts the appends (v1.7 §2); the console always sends it, and the wire schema reads one without it as `relay`. */
  readonly appends_by?: "relay" | "gray";
  /** Egress's own-call cadence (section 6); absent, or a member absent: the vendor's default. 0 turns one off. */
  readonly own_calls?: { readonly every_seconds: { readonly limits?: number; readonly models?: number } };
  readonly used_at_ms: number;
}

/**
 * The relay's account upkeep as egress gets it (docs/relay-changes-v2.md section 6; the gateway's stack-ops.ts sends it
 * to egress's `PUT /v1/stack/ops/accounts`): per account the refresh mode, per relay the cadence of `limits` and
 * `models` in seconds (0 turns one off; absent takes the vendor's default; egress clamps to the vendor's bounds).
 */
export interface StackOwnCallSettings {
  readonly refresh: ReadonlyMap<string, StackRefreshMode>;
  readonly everySeconds: { readonly limits?: number; readonly models?: number };
}

/** The upkeep settings of a configuration (`null`: none yet): an absent member is the default. */
export function stackOwnCallSettings(metadata: StackConfigDocument | null): StackOwnCallSettings {
  const refresh = new Map<string, StackRefreshMode>();
  for (const account of metadata?.accounts ?? []) refresh.set(account.id, account.refresh === "gray" ? "gray" : "source");
  const every = metadata?.own_calls?.every_seconds;
  const seconds = (value: unknown): number | undefined => (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined);
  const limits = seconds(every?.limits);
  const models = seconds(every?.models);
  return { refresh, everySeconds: { ...(limits === undefined ? {} : { limits }), ...(models === undefined ? {} : { models }) } };
}
export interface StackConfigAnswer {
  readonly relay_id: string;
  readonly version: number;
  readonly digest: string;
  readonly config: StackConfigDocument | null;
  /** The entry names the VM dials (`stack.entries`); absent, the image's default. */
  readonly entries?: readonly string[];
  /** For some of `entries`, the address dialed before `<entry>:443` (section 8.4); absent, none. */
  readonly entry_addrs?: readonly { readonly entry: string; readonly addr: string }[];
}

/** The wire answer of the console's answer: integers to bigints, then the strict schema (a malformed one throws). */
export function stackConfigAnswerDtoOf(answer: StackConfigAnswer): StackConfigAnswerDto {
  const parsed = stackConfigAnswerSchema.safeParse(integersOfJson(answer, ""));
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new BridgeWireError("invalid_document", issue?.path.map(String).join(".") ?? null, "the stack configuration is not its wire shape");
  }
  return parsed.data;
}

/** The answer the entry uses: the wire answer with JS numbers. */
export function stackConfigAnswerOf(dto: StackConfigAnswerDto): StackConfigAnswer {
  return numbersOfJson(dto, "") as StackConfigAnswer;
}

/**
 * The configuration's digest: SHA-256 of `@gray/json`'s text (keys in byte order) of the wire document without the
 * used counters and `used_at_ms`, lower-case hex. Equal configurations have equal digests whatever the order their
 * members were built in; the console and the entry compute it with this one function.
 */
export function stackConfigDigest(document: StackConfigDocument | StackConfigDocumentDto): string {
  const dto = integersOfJson(document, "") as StackConfigDocumentDto;
  const configured: Record<string, unknown> = { ...dto };
  delete configured.used_at_ms;
  configured.accounts = dto.accounts.map((a) => ({
    ...a,
    windows: a.windows.map((w) => ({ seconds: w.seconds, max_requests: w.max_requests, max_tokens: w.max_tokens })),
  }));
  return sha256BareHex(new TextEncoder().encode(toJsonString(configured as unknown as Json)));
}

// ------------------------------------------------------------------------------------------------- proxy checks

/**
 * `stack.proxy_checks` (design section 8.1, package E): the proxy connectivity checks the relay asked for in the panel,
 * run by the lane in the relay's VM, the one place with the proxy's sealed credentials and the network the relay's
 * calls leave from. The lane sends the results of the checks it ran (`results`, at most `PROXY_CHECK_RESULTS_MAX`)
 * and gets the checks still pending for its relay (`pending`); a lane with nothing to report polls with `results: []`.
 * A check the VM has not answered within the console's LANE_STACK_PROXY_CHECK_EXPIRY_MS (120 s by default) of being
 * queued expires: it is no longer pending, and a result sent for it later is dropped.
 * The bridge answers a key only for its own relay (LANE_BRIDGE_STACK_RELAYS), as `stack.config`.
 *
 * What the lane does for one pending check (C2): through its egress, dial the proxy exactly as the egress dials it for
 * the relay's vendor calls (S15's proxy spec, with the sealed credential of `credential_version`), open a tunnel to
 * the vendor's API host on 443 (`api.anthropic.com`, `api.openai.com` or `chatgpt.com` for `vendor`), complete a TLS
 * handshake that verifies the vendor's certificate against the system roots, send nothing, close. No account
 * credential is used and no request reaches the vendor. `latency_ms` is from the dial to the end of the handshake;
 * `checked_ms` the lane's clock when it ended. A check `ok` has no code; a failed one names one of `PROXY_CHECK_CODES`:
 *
 * - `credential_missing`: the lane has no sealed credential of `credential_version` for the proxy;
 * - `proxy_unreachable`: no connection to the proxy; `proxy_auth_failed`: the proxy refused the credentials;
 * - `proxy_refused`: the proxy refused the tunnel; `upstream_unreachable`: the proxy could not reach the vendor;
 * - `tls_failed`: the vendor's handshake failed or its certificate did not verify; `timeout`: no answer in time.
 */
export const PROXY_CHECK_CODES = ["credential_missing", "proxy_unreachable", "proxy_auth_failed", "proxy_refused", "upstream_unreachable", "tls_failed", "timeout"] as const;
export type ProxyCheckCode = (typeof PROXY_CHECK_CODES)[number];

/** The most results one call carries (a relay's checks pending at once are its proxies times three vendors). */
export const PROXY_CHECK_RESULTS_MAX = 64;

const checkId = z.string().regex(/^[0-9a-f]{32}$/);

const proxyCheckResultSchema = z
  .object({ check_id: checkId, outcome: z.enum(["ok", "failed"]), code: z.enum(PROXY_CHECK_CODES).nullable(), latency_ms: uintSchema.nullable(), checked_ms: uintSchema })
  .strict()
  .refine((r) => (r.outcome === "ok") === (r.code === null), { message: "an ok check has no code, a failed one names one", path: ["code"] });

export const stackProxyChecksRequestSchema = z.object({ relay_id: id, results: z.array(proxyCheckResultSchema).max(PROXY_CHECK_RESULTS_MAX) }).strict();
export type StackProxyChecksRequestDto = z.infer<typeof stackProxyChecksRequestSchema>;

export const stackProxyChecksAnswerSchema = z
  .object({ pending: z.array(z.object({ check_id: checkId, proxy_id: id, vendor: z.enum(LANE_STACK_VENDORS), credential_version: uintSchema }).strict()) })
  .strict();
export type StackProxyChecksAnswerDto = z.infer<typeof stackProxyChecksAnswerSchema>;

/** One check's result as the console records it: the wire result with JS numbers. */
export interface ProxyCheckResult {
  readonly check_id: string;
  readonly outcome: "ok" | "failed";
  readonly code: ProxyCheckCode | null;
  readonly latency_ms: number | null;
  readonly checked_ms: number;
}
/** One check the lane is to run. */
export interface PendingProxyCheck {
  readonly check_id: string;
  readonly proxy_id: string;
  readonly vendor: StackVendorName;
  readonly credential_version: number;
}

/** The results a call carries, with JS numbers (the console's input). */
export function proxyCheckResultsOf(dto: StackProxyChecksRequestDto): ProxyCheckResult[] {
  return numbersOfJson(dto.results, "results") as ProxyCheckResult[];
}

/** The wire answer of the console's pending checks: integers to bigints, then the strict schema. */
export function stackProxyChecksAnswerDtoOf(answer: { readonly pending: readonly PendingProxyCheck[] }): StackProxyChecksAnswerDto {
  const parsed = stackProxyChecksAnswerSchema.safeParse(integersOfJson(answer, ""));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the pending proxy checks are not their wire shape");
  return parsed.data;
}
