import { sha256BareHex } from "@gray/attest";
import { toJsonString, type Json } from "@gray/json";
import { LANE_STACK_VENDORS } from "@gray/lane";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { integersOfJson, numbersOfJson } from "./ints.ts";
import {
  STACK_ATTEMPT_CLASSES,
  STACK_COOLING_KINDS,
  STACK_COOLING_MODES,
  STACK_RULE_CLEARS,
  STACK_RULE_CREDENTIALS,
  STACK_RULE_SCOPES,
  STACK_RULE_UNTIL,
  STACK_VENDOR_CODES,
  STACK_WINDOW_RULE_WINDOWS,
  type StackAttemptClass,
  type StackCoolingKind,
  type StackCoolingMode,
  type StackVendorCode,
} from "./stack-health.ts";

/** A cooling rule's vendors (S38 `vendors`): every stack vendor (`@gray/lane` LANE_STACK_VENDORS; egress `coolingVendors`). */
export const STACK_RULE_VENDORS = LANE_STACK_VENDORS;

/**
 * Cooling rules (docs/confidential-lane-supply-implementation.md S38, S39) and their delivery to the relay's VM, bridge
 * op `stack.rules` (S41): the console holds each relay's rules (`lane_stack_relays.cooling_*`, migration 0032) and each
 * account's clear generation (`lane_stack_account_state.clear_gen`); the entry polls with the digest it has and pushes
 * what it gets to egress (`PUT /v1/stack/cooling`, S40), and after an egress restart asks for the entries to restore.
 *
 * Every member of a rule is always present (null where it does not apply), so egress reads one fixed shape:
 *
 *     {"id", "vendors": [...], "credential", "status": [...], "codes": [...], "action": "cool"|"hold",
 *      "until": "fixed"|"stated"|null, "seconds": n|null, "max_seconds": n|null, "scope", "clears": [...]}
 *
 * A hold has `until`, `seconds` and `max_seconds` null; a fixed cool has `seconds` and `max_seconds` null; a stated cool
 * has both, `seconds` (the end when the vendor states none) at most `max_seconds`. A window rule is
 * `{"id", "window", "at_percent", "scope"}`. The schemas are built once over JS numbers (the panel's bodies) and once over
 * the bridge's bigints (ints.ts), from one definition.
 */

/** A rule's id (S38): unique among a relay's rules and window rules. */
export const STACK_RULE_ID_PATTERN = /^[a-z0-9_-]{1,64}$/;
/** S38's bounds: at most 32 rules, 4 window rules; 1..8 statuses, 0..16 codes; 5 s to 8 days (sub2api's 429 fallback, its reset sanity bound). */
export const STACK_RULES_MAX = 32;
export const STACK_WINDOW_RULES_MAX = 4;
export const STACK_RULE_STATUSES_MAX = 8;
export const STACK_RULE_CODES_MAX = 16;
export const STACK_RULE_SECONDS_MIN = 5;
export const STACK_RULE_SECONDS_MAX = 691_200;
/** S40: the most entries one restore carries. */
export const STACK_RESTORE_MAX = 2048;
/** The most accounts a relay's VM serves (`@gray/relay-connector` DEFAULT_MAX_ACCOUNTS_PER_RELAY, S42). */
export const STACK_ACCOUNTS_MAX = 1000;
/** The name of Gray's default rules (S39). */
export const GRAY_COOLING_DEFAULTS = "gray-cooling-v1";

/** An account, proxy or relay id: the lane's relay-id pattern (`@gray/control` LANE_RELAY_ID_PATTERN). */
export const STACK_WIRE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const id = z.string().regex(STACK_WIRE_ID_PATTERN);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);

/** One integer of a schema, between two bounds: a JS number (the panel) or a bigint (the bridge). */
type IntOf = (min: number, max: number) => z.ZodType;
const numberInt: IntOf = (min, max) => z.number().int().min(min).max(max);
const bigintInt: IntOf = (min, max) => z.bigint().min(BigInt(min)).max(BigInt(max));

function unique(values: readonly unknown[]): boolean {
  return new Set(values.map((v) => String(v))).size === values.length;
}

function ruleSchemaOf(int: IntOf) {
  return z
    .object({
      id: z.string().regex(STACK_RULE_ID_PATTERN),
      vendors: z.array(z.enum(STACK_RULE_VENDORS)).max(STACK_RULE_VENDORS.length),
      credential: z.enum(STACK_RULE_CREDENTIALS),
      status: z.array(int(400, 599)).min(1).max(STACK_RULE_STATUSES_MAX),
      codes: z.array(z.enum(STACK_VENDOR_CODES)).max(STACK_RULE_CODES_MAX),
      action: z.enum(STACK_COOLING_KINDS),
      until: z.enum(STACK_RULE_UNTIL).nullable(),
      seconds: int(STACK_RULE_SECONDS_MIN, STACK_RULE_SECONDS_MAX).nullable(),
      max_seconds: int(STACK_RULE_SECONDS_MIN, STACK_RULE_SECONDS_MAX).nullable(),
      scope: z.enum(STACK_RULE_SCOPES),
      clears: z.array(z.enum(STACK_RULE_CLEARS)).max(STACK_RULE_CLEARS.length),
    })
    .strict()
    .superRefine((r, ctx) => {
      for (const key of ["vendors", "status", "codes", "clears"] as const) {
        if (!unique(r[key] as readonly unknown[])) ctx.addIssue({ code: "custom", path: [key], message: `${key} lists a value twice` });
      }
      const seconds = r.seconds === null ? null : Number(r.seconds);
      const most = r.max_seconds === null ? null : Number(r.max_seconds);
      if (r.action === "hold") {
        if (r.until !== null || seconds !== null || most !== null) ctx.addIssue({ code: "custom", path: ["until"], message: "a hold has no end: until, seconds and max_seconds are null" });
      } else if (r.until === null) {
        ctx.addIssue({ code: "custom", path: ["until"], message: "a cool ends: until is fixed or stated" });
      } else if (r.until === "fixed") {
        if (seconds === null || most !== null) ctx.addIssue({ code: "custom", path: ["seconds"], message: "a fixed cool names seconds and no max_seconds" });
      } else if (seconds === null || most === null || seconds > most) {
        ctx.addIssue({ code: "custom", path: ["max_seconds"], message: "a stated cool names seconds (its end when the vendor states none) at most max_seconds" });
      }
    });
}

function windowRuleSchemaOf(int: IntOf) {
  return z
    .object({ id: z.string().regex(STACK_RULE_ID_PATTERN), window: z.enum(STACK_WINDOW_RULE_WINDOWS), at_percent: int(50, 100), scope: z.enum(STACK_RULE_SCOPES) })
    .strict()
    .refine((w) => w.window !== "model" || w.scope === "model", { message: "a model window rule's scope is model", path: ["scope"] });
}

/** The rules and window rules of one relay: within S38's bounds, every id once. */
function ruleListsOf(int: IntOf) {
  return {
    rules: z.array(ruleSchemaOf(int)).max(STACK_RULES_MAX),
    windows: z.array(windowRuleSchemaOf(int)).max(STACK_WINDOW_RULES_MAX),
  };
}

function idsUnique(value: { readonly rules: readonly { readonly id: string }[]; readonly windows: readonly { readonly id: string }[] }, ctx: z.RefinementCtx): void {
  if (!unique([...value.rules.map((r) => r.id), ...value.windows.map((w) => w.id)])) ctx.addIssue({ code: "custom", path: ["rules"], message: "a rule id is used twice among rules and windows" });
}

/**
 * The panel's body of `PUT …/cooling` (S46): the mode, and either Gray's defaults (`defaults: "gray-cooling-v1"`, no
 * `rules` or `windows`: the console serves its current defaults) or the relay's own rules (`defaults: null`).
 */
export const stackCoolingInputSchema = z
  .object({
    mode: z.enum(STACK_COOLING_MODES),
    defaults: z.literal(GRAY_COOLING_DEFAULTS).nullable(),
    rules: ruleListsOf(numberInt).rules.optional(),
    windows: ruleListsOf(numberInt).windows.optional(),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.defaults !== null) {
      if (v.rules !== undefined || v.windows !== undefined) ctx.addIssue({ code: "custom", path: ["rules"], message: "Gray's defaults take no rules or windows of the relay's" });
      return;
    }
    if (v.rules === undefined || v.windows === undefined) {
      ctx.addIssue({ code: "custom", path: ["rules"], message: "the relay's own rules name rules and windows" });
      return;
    }
    idsUnique({ rules: v.rules, windows: v.windows }, ctx);
  });

/** One cooling rule, with JS numbers. */
export interface StackCoolingRule {
  readonly id: string;
  readonly vendors: readonly (typeof STACK_RULE_VENDORS)[number][];
  readonly credential: (typeof STACK_RULE_CREDENTIALS)[number];
  readonly status: readonly number[];
  readonly codes: readonly StackVendorCode[];
  readonly action: StackCoolingKind;
  readonly until: (typeof STACK_RULE_UNTIL)[number] | null;
  readonly seconds: number | null;
  readonly max_seconds: number | null;
  readonly scope: (typeof STACK_RULE_SCOPES)[number];
  readonly clears: readonly (typeof STACK_RULE_CLEARS)[number][];
}
/** One window rule, with JS numbers. */
export interface StackWindowRule {
  readonly id: string;
  readonly window: (typeof STACK_WINDOW_RULE_WINDOWS)[number];
  readonly at_percent: number;
  readonly scope: (typeof STACK_RULE_SCOPES)[number];
}
/** A relay's rules as the console stores them (`cooling_rules`, null = the defaults). */
export interface StackRuleLists {
  readonly rules: readonly StackCoolingRule[];
  readonly windows: readonly StackWindowRule[];
}

const hold = (id: string, status: number[], codes: StackVendorCode[], scope: "account" | "model", clears: ("credential" | "test")[], credential: StackCoolingRule["credential"] = "any"): StackCoolingRule => ({
  id,
  vendors: [],
  credential,
  status,
  codes,
  action: "hold",
  until: null,
  seconds: null,
  max_seconds: null,
  scope,
  clears,
});
const fixed = (id: string, status: number[], codes: StackVendorCode[], seconds: number, scope: "account" | "model", clears: ("credential" | "test")[], credential: StackCoolingRule["credential"] = "any"): StackCoolingRule => ({
  id,
  vendors: [],
  credential,
  status,
  codes,
  action: "cool",
  until: "fixed",
  seconds,
  max_seconds: null,
  scope,
  clears,
});
const stated = (id: string, status: number[], codes: StackVendorCode[], seconds: number, most: number, scope: "account" | "model", clears: ("credential" | "test")[]): StackCoolingRule => ({
  id,
  vendors: [],
  credential: "any",
  status,
  codes,
  action: "cool",
  until: "stated",
  seconds,
  max_seconds: most,
  scope,
  clears,
});

/**
 * Gray's default rules, `gray-cooling-v1` (S39's table, in its order; first match wins): sub2api's behaviour with
 * nothing configured (`ratelimit_service.go`), the research's challenge detection and 403 pause. No window rule: S38's
 * "rest at 90 %" is off by default. A relay whose `cooling_rules` is null is served these.
 */
export const GRAY_COOLING_V1: StackRuleLists = Object.freeze({
  rules: Object.freeze([
    stated("window_exhausted", [429], ["window_exhausted", "usage_limit_reached"], 300, STACK_RULE_SECONDS_MAX, "account", ["test"]),
    stated("model_window_exhausted", [429], ["model_window_exhausted"], 300, STACK_RULE_SECONDS_MAX, "model", ["test"]),
    hold("billing", [400, 402, 403, 429], ["billing_error", "insufficient_quota", "billing_not_active", "insufficient_balance", "credit_balance_too_low"], "account", ["test"]),
    hold(
      "restricted",
      [400, 401, 402, 403],
      ["token_revoked", "token_invalidated", "deactivated_workspace", "usage_not_included", "account_state", "organization_disabled", "identity_verification_required", "detail_unauthorized"],
      "account",
      ["credential", "test"],
    ),
    fixed("oauth_auth", [401], [], 600, "account", ["credential", "test"], "oauth_access_token"),
    hold("key_auth", [401], [], "account", ["credential", "test"], "api_key"),
    fixed("challenge", [403, 429, 503], ["html_challenge"], 600, "account", ["test"]),
    hold("forbidden", [403], [], "model", ["test"]),
    stated("rate_limit", [429], [], 5, 3600, "account", []),
    fixed("overloaded", [529], [], 600, "account", []),
  ]),
  windows: Object.freeze([]),
});

/** sub2api's presets (`CreateAccountModal.vue`), one click away in the panel (S39): each a rule the relay may add. */
export const STACK_COOLING_PRESETS: readonly StackCoolingRule[] = Object.freeze([
  fixed("529_60m", [529], [], 3600, "model", []),
  fixed("429_10m", [429], [], 600, "model", []),
  fixed("503_30m", [503], [], 1800, "model", []),
]);

// ------------------------------------------------------------------------------------------------- stack.rules (S41)

/** One entry the entry asks egress to restore after a restart (S40 `restore`): the VM's last report, as the console kept it. */
function restoreEntrySchemaOf(int: IntOf) {
  return z
    .object({
      account_id: id,
      model: z.string().min(1).max(256).nullable(),
      kind: z.enum(STACK_COOLING_KINDS),
      until_ms: int(0, Number.MAX_SAFE_INTEGER).nullable(),
      rule_id: z.string().regex(STACK_RULE_ID_PATTERN),
      class: z.enum(STACK_ATTEMPT_CLASSES),
      vendor_code: z.enum(STACK_VENDOR_CODES),
      set_ms: int(0, Number.MAX_SAFE_INTEGER),
      gen: int(0, Number.MAX_SAFE_INTEGER),
      clears: z.array(z.enum(STACK_RULE_CLEARS)).max(STACK_RULE_CLEARS.length),
      observed: z.boolean(),
    })
    .strict()
    .refine((e) => (e.kind === "hold") === (e.until_ms === null), { message: "a hold has no end, a cool has one", path: ["until_ms"] });
}

function rulesDocumentSchemaOf(int: IntOf) {
  const lists = ruleListsOf(int);
  return z
    .object({
      mode: z.enum(STACK_COOLING_MODES),
      rules: lists.rules,
      windows: lists.windows,
      accounts: z.record(id, int(0, Number.MAX_SAFE_INTEGER)).refine((a) => Object.keys(a).length <= STACK_ACCOUNTS_MAX, { message: `at most ${STACK_ACCOUNTS_MAX} accounts` }),
    })
    .strict()
    .superRefine(idsUnique);
}

/** The request: the relay, the digest of the document the entry has (`""`: none), and whether it asks for the entries to restore. */
export const stackRulesRequestSchema = z.object({ relay_id: id, have: z.union([hex64, z.literal("")]), restore: z.boolean() }).strict();
export type StackRulesRequestDto = z.infer<typeof stackRulesRequestSchema>;

/** The document egress is pushed (S40's body without `digest` and `restore`), on the wire. */
export const stackRulesDocumentSchema = rulesDocumentSchemaOf(bigintInt);
export const stackRestoreEntrySchema = restoreEntrySchemaOf(bigintInt);

/** The answer: `document` null when `have` is the digest; `restore` empty unless asked for. */
export const stackRulesAnswerSchema = z
  .object({ relay_id: id, digest: hex64, document: stackRulesDocumentSchema.nullable(), restore: z.array(stackRestoreEntrySchema).max(STACK_RESTORE_MAX) })
  .strict();
export type StackRulesAnswerDto = z.infer<typeof stackRulesAnswerSchema>;

/** The document with JS numbers: the mode, the rules served, and every panel account's clear generation. */
export interface StackRulesDocument extends StackRuleLists {
  readonly mode: StackCoolingMode;
  readonly accounts: Readonly<Record<string, number>>;
}
/** One restore entry with JS numbers. */
export interface StackRestoreEntry {
  readonly account_id: string;
  readonly model: string | null;
  readonly kind: StackCoolingKind;
  readonly until_ms: number | null;
  readonly rule_id: string;
  readonly class: StackAttemptClass;
  readonly vendor_code: StackVendorCode;
  readonly set_ms: number;
  readonly gen: number;
  readonly clears: readonly (typeof STACK_RULE_CLEARS)[number][];
  /** Made in observe mode: egress keeps it marked so, and refuses nothing for it. */
  readonly observed: boolean;
}
export interface StackRulesAnswer {
  readonly relay_id: string;
  readonly digest: string;
  readonly document: StackRulesDocument | null;
  readonly restore: readonly StackRestoreEntry[];
}

/** S41's digest: SHA-256 of the document's `@gray/json` text (keys in byte order), lower-case hex; the console and the entry compute it with this. */
export function stackRulesDigest(document: StackRulesDocument): string {
  return sha256BareHex(new TextEncoder().encode(toJsonString(integersOfJson(document, "") as Json)));
}

/** The panel's rules as the wire's numbers check them (a stored value that no longer fits throws). */
export function checkedRulesDocument(document: StackRulesDocument): StackRulesDocument {
  const parsed = rulesDocumentSchemaOf(numberInt).safeParse(document);
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the cooling rules are not their wire shape");
  return parsed.data as StackRulesDocument;
}

/** The wire answer of the console's answer: integers to bigints, then the strict schema (a malformed one throws). */
export function stackRulesAnswerDtoOf(answer: StackRulesAnswer): StackRulesAnswerDto {
  const parsed = stackRulesAnswerSchema.safeParse(integersOfJson(answer, ""));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the cooling rules answer is not its wire shape");
  return parsed.data;
}

/** The answer the entry uses: the wire answer with JS numbers. */
export function stackRulesAnswerOf(dto: StackRulesAnswerDto): StackRulesAnswer {
  return numbersOfJson(dto, "") as StackRulesAnswer;
}
