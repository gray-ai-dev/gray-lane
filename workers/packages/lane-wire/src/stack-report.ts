import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import {
  STACK_ATTEMPT_CLASSES,
  STACK_CONFIG_ABSENT,
  STACK_COOLING_KINDS,
  STACK_COOLING_MODES,
  STACK_CREDENTIAL_TYPES,
  STACK_LOGIN_BY,
  STACK_LOGIN_CODES,
  STACK_LOGIN_STATES,
  STACK_REFRESH_CODES,
  STACK_REFRESH_MODES,
  STACK_REFRESH_PROBLEMS,
  STACK_RULE_CLEARS,
  STACK_SERVED,
  STACK_VENDOR_CODES,
  STACK_WINDOW_CLAIMS,
  STACK_WINDOW_KEYS,
  STACK_WINDOW_STATUSES,
  type StackAttemptClass,
  type StackCoolingKind,
  type StackCoolingMode,
  type StackExclusionReasonWord,
  type StackLoginCode,
  type StackLoginState,
  type StackRefreshCode,
  type StackRefreshMode,
  type StackVendorCode,
  type StackWindowClaim,
  type StackWindowKey,
  type StackWindowStatus,
} from "./stack-health.ts";
import { STACK_ACCOUNTS_MAX, STACK_RULE_ID_PATTERN, STACK_WIRE_ID_PATTERN } from "./stack-rules.ts";

/**
 * `stack.report` (docs/confidential-lane-supply-implementation.md S42): the relay VM's live state, as the entry reads it
 * from its own document build (`buildStackDocument`), its store and egress's health (S37), sent to the console on a
 * change at most every LANE_STACK_REPORT_MIN_MS and as a heartbeat every LANE_STACK_REPORT_HEARTBEAT_MS. State, not
 * events: the console keeps the latest report per relay and account (`lane_stack_vm_state`, `lane_stack_account_state`).
 *
 * No member carries customer content (S33): closed words (stack-health.ts), ids the relay chose and Gray stores, counts,
 * and times that are all minutes (`*_minute_ms`: start times floored, end times ceiled; the schema refuses any other).
 * `lease_expires_at_s` and a sealed credential's `expires_at_s` are the relay's own values in seconds.
 *
 * Unknowns are null: an egress the entry could not read leaves `boot.egress_started_minute_ms`, `cooling.mode`,
 * `cooling.digest` and `counters` null, and its accounts without cooling entries or windows. A cooling entry is egress's
 * health entry (S37) with its times as minutes: its class and vendor code (a window rule's are `window_exhausted`),
 * whether it was made in observe mode, and what clears it, which the console hands back to restore (S41).
 *
 * `relay_image` (S55) is the image the relay chose for this boot, as pre-launch measured it in RTMR3
 * (`gray-relay-image`, S52): the entrypoint reads it from the guest agent and the entry repeats it. Null when the boot
 * has none (a default-layout entry never sends a report); absent from an entry older than S55.
 *
 * The answer is `{"recorded": <bool>}`: false for a `seq` that is not newer than the console's latest of the same boot
 * (`boot.started_minute_ms`). A failed send is not retried (no queue); the next refresh builds a fresh report.
 */

/**
 * S52/S55: a relay image reference, `<registry host[:port]>/<repository>@sha256:<64 hex>` (@gray/lane-verify
 * `STACK_RELAY_IMAGE_PATTERN`, @gray/control `STACK_RELAY_IMAGE_PATTERN`).
 */
export const STACK_REPORT_RELAY_IMAGE_PATTERN = /^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)\/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$/;

/** S42's body cap, added to `bridgeRequestMaxBytes`: 1000 accounts do not fit the small ops' 64 KiB. */
export const STACK_REPORT_MAX_BYTES = 1024 * 1024;
/** S42's bounds per account and per relay. */
export const STACK_REPORT_COOLING_MAX = 64;
export const STACK_REPORT_WINDOWS_MAX = 6;
export const STACK_REPORT_ROUTES_MAX = 256;
export const STACK_REPORT_APPENDS_MAX = 64;
const U32_MAX = 4_294_967_295;

const MINUTE_MS = 60_000n;
const id = z.string().regex(STACK_WIRE_ID_PATTERN);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
/** A model name the relay's routes and accounts name (an upstream or requested model): Gray stores it already. */
const model = z.string().min(1).max(256);
/** A time in the report: a whole minute (S33 rule 3). */
const minute = uintSchema.refine((v) => v % MINUTE_MS === 0n, { message: "a time in stack.report is a whole minute" });
const u32 = uintSchema.max(BigInt(U32_MAX));

/**
 * A non-compliant change the lane found (docs/design/relay-ejection.md section 1): egress refused the relay's change to a
 * kept request field (`stack_rewrite_refused` at a kept member, `stack_header_refused` for a P6 header) on a rid that
 * allowed relay changes, or the relay's answer was not the vendor's (`event_mismatch`, `event_unrecorded`,
 * `event_hold_bound`, `body_mismatch`, each confirmed against egress's whole record). The console takes the relay out of
 * routing on the first one it has not taken.
 */
export const STACK_VIOLATION_KINDS = ["request", "answer"] as const;
export type StackViolationKind = (typeof STACK_VIOLATION_KINDS)[number];
export const STACK_VIOLATION_REQUEST_CODES = ["stack_rewrite_refused", "stack_header_refused"] as const;
export const STACK_VIOLATION_ANSWER_CODES = ["event_mismatch", "event_unrecorded", "event_hold_bound", "body_mismatch"] as const;
export const STACK_VIOLATION_CODES = [...STACK_VIOLATION_REQUEST_CODES, ...STACK_VIOLATION_ANSWER_CODES] as const;
export type StackViolationCode = (typeof STACK_VIOLATION_CODES)[number];
/** A kept body member as the refusal path's first token (`/model`, `/stream_options`, `/tools`): names from egress's lists. */
export const STACK_VIOLATION_BODY_FIELD_PATTERN = /^\/[A-Za-z0-9_]{1,64}$/;
/** A refused header's name (egress writes it lower-case): `openai-organization`, `cookie`, `x-api-key`. */
export const STACK_VIOLATION_HEADER_FIELD_PATTERN = /^[a-z0-9-]{1,64}$/;
/** Gray's public request id (`x-request-id`, @gray/ledger-keys `newRequestId`): a UUIDv7's 32 lower-case hex digits. */
export const STACK_VIOLATION_REQUEST_ID_PATTERN = /^[0-9a-f]{32}$/;

export const stackViolationSchema = z
  .object({
    /** A random id of the lane's: the console takes a violation once. */
    id: z.string().regex(/^[0-9a-f]{32}$/),
    kind: z.enum(STACK_VIOLATION_KINDS),
    code: z.enum(STACK_VIOLATION_CODES),
    /** The kept member (`/model`) or the header name a request violation names; null for an answer. */
    field: z.string().max(65).nullable(),
    /** Gray's request id the entry named, or null (a direct client's lane always knows it). */
    request_id: z.string().regex(STACK_VIOLATION_REQUEST_ID_PATTERN).nullable(),
    at_minute_ms: minute,
  })
  .strict()
  .superRefine((v, ctx) => {
    const request = (STACK_VIOLATION_REQUEST_CODES as readonly string[]).includes(v.code);
    if (request !== (v.kind === "request")) ctx.addIssue({ code: "custom", path: ["code"], message: "a request violation has a request code, an answer one an answer code" });
    if (v.kind === "answer" && v.field !== null) ctx.addIssue({ code: "custom", path: ["field"], message: "an answer violation names no field" });
    if (v.kind === "request") {
      const pattern = v.code === "stack_header_refused" ? STACK_VIOLATION_HEADER_FIELD_PATTERN : STACK_VIOLATION_BODY_FIELD_PATTERN;
      if (v.field === null || !pattern.test(v.field)) ctx.addIssue({ code: "custom", path: ["field"], message: "a request violation names the kept member or the header" });
    }
  });

/** One violation as the report carries it, with JS numbers. */
export interface StackViolation {
  readonly id: string;
  readonly kind: StackViolationKind;
  readonly code: StackViolationCode;
  readonly field: string | null;
  readonly request_id: string | null;
  readonly at_minute_ms: number;
}

/** The exclusions of an account (`StackExclusionReason`'s account words). */
export const STACK_ACCOUNT_EXCLUSIONS = [
  "not_sealed",
  "vendor_mismatch",
  "credential_waiting",
  "invalid_credential",
  "proxy_unknown",
  "proxy_mismatch",
  "proxy_waiting",
  "duplicate_credential",
  "login_waiting",
] as const satisfies readonly StackExclusionReasonWord[];

const coolingSchema = z
  .object({
    model: model.nullable(),
    kind: z.enum(STACK_COOLING_KINDS),
    until_minute_ms: minute.nullable(),
    rule_id: z.string().regex(STACK_RULE_ID_PATTERN),
    class: z.enum(STACK_ATTEMPT_CLASSES),
    vendor_code: z.enum(STACK_VENDOR_CODES),
    set_minute_ms: minute,
    gen: uintSchema,
    observed: z.boolean(),
    clears: z.array(z.enum(STACK_RULE_CLEARS)).max(STACK_RULE_CLEARS.length),
  })
  .strict()
  .refine((e) => (e.kind === "hold") === (e.until_minute_ms === null), { message: "a hold has no end, a cool has one", path: ["until_minute_ms"] });

const windowSchema = z
  .object({
    key: z.enum(STACK_WINDOW_KEYS),
    window_minutes: uintSchema.min(1n).max(20_160n).nullable(),
    used_percent: uintSchema.max(1000n).nullable(),
    status: z.enum(STACK_WINDOW_STATUSES).nullable(),
    claim: z.enum(STACK_WINDOW_CLAIMS).nullable(),
    resets_at_minute_ms: minute.nullable(),
    observed_minute_ms: minute,
  })
  .strict();

/** The windows of one account, each key once (egress keeps the latest per key, S36). */
export const stackWindowsSchema = z
  .array(windowSchema)
  .max(STACK_REPORT_WINDOWS_MAX)
  .refine((ws) => new Set(ws.map((w) => w.key)).size === ws.length, { message: "a window key is listed twice" });

/**
 * Who refreshes a subscription account's token and how it went, from egress's own-call schedule (stack_ops.go): the
 * mode, whether the sealed credential carries a refresh token (in either mode, never the token), `no_refresh_token` when the mode is `gray` and the sealed credential has no refresh token (egress never refreshes
 * it), egress's last attempt (its minute, floored) and the next one (ceiled), and the failed attempts in a row. Null when
 * egress does not keep the account up (an API key, a vendor its table has no refresh for, egress unread); absent from an
 * entry older than it.
 */
export const stackReportRefreshSchema = z
  .object({
    mode: z.enum(STACK_REFRESH_MODES),
    has_refresh_token: z.boolean(),
    problem: z.enum(STACK_REFRESH_PROBLEMS).nullable(),
    last: z
      .object({ outcome: z.enum(["ok", "failed"]), code: z.enum(STACK_REFRESH_CODES).nullable(), minute_ms: minute })
      .strict()
      .refine((l) => (l.outcome === "ok") === (l.code === null), { message: "an ok refresh has no code, a failed one names one", path: ["code"] })
      .nullable(),
    next_minute_ms: minute.nullable(),
    failures: u32,
  })
  .strict();

const HOUR_MS = 3_600_000n;
/** A sign-in's time in the report: a whole hour (the container chooses when it signs in: relay-changes-v2 V8). */
const hour = uintSchema.refine((v) => v % HOUR_MS === 0n, { message: "a sign-in time in stack.report is a whole hour" });

/**
 * A password account's sign-in inside the VM (egress stack_login.go `loginHealth`): who signs in, the state, the failed
 * token exchanges in a row, the last one's outcome and hour, and the hour of the last one that gave a token. Absent for
 * every other account, and from an entry older than it.
 */
export const stackReportLoginSchema = z
  .object({
    by: z.enum(STACK_LOGIN_BY),
    state: z.enum(STACK_LOGIN_STATES),
    failures: u32,
    last: z
      .object({ outcome: z.enum(["ok", "failed"]), code: z.enum(STACK_LOGIN_CODES).nullable(), hour_ms: hour })
      .strict()
      .refine((l) => (l.outcome === "ok") === (l.code === null), { message: "an ok sign-in has no code, a failed one names one", path: ["code"] })
      .nullable(),
    last_ok_hour_ms: hour.nullable(),
  })
  .strict();

const accountSchema = z
  .object({
    account_id: id,
    served: z.enum(STACK_SERVED),
    reason: z.enum(STACK_ACCOUNT_EXCLUSIONS).nullable(),
    sealed: z.object({ version: uintSchema, type: z.enum(STACK_CREDENTIAL_TYPES), expires_at_s: uintSchema.nullable() }).strict().nullable(),
    proxy_id: id.nullable(),
    in_flight_peak: z.object({ minute_ms: minute, value: u32 }).strict().nullable(),
    cooling: z.array(coolingSchema).max(STACK_REPORT_COOLING_MAX),
    windows: stackWindowsSchema,
    refresh: stackReportRefreshSchema.nullable().optional(),
    login: stackReportLoginSchema.nullable().optional(),
  })
  .strict()
  .refine((a) => (a.served === "excluded") === (a.reason !== null), { message: "an excluded account names why, a served or paused one does not", path: ["reason"] });

export const stackReportSchema = z
  .object({
    relay_id: id,
    seq: uintSchema,
    boot: z.object({ started_minute_ms: minute, egress_started_minute_ms: minute.nullable(), lease_expires_at_s: uintSchema.nullable() }).strict(),
    config: z
      .object({ console_version: uintSchema.nullable(), fetched_current: z.boolean(), fetched_minute_ms: minute.nullable(), absent: z.enum(STACK_CONFIG_ABSENT).nullable() })
      .strict(),
    cooling: z.object({ mode: z.enum(STACK_COOLING_MODES).nullable(), digest: hex64.nullable() }).strict(),
    counters: z
      .object({
        request_unknown: uintSchema,
        attempts_exceeded: uintSchema,
        attempts_accepted: uintSchema.optional(),
        body_changed: uintSchema.optional(),
        headers_changed: uintSchema.optional(),
        body_added_bytes: uintSchema.optional(),
        body_removed_bytes: uintSchema.optional(),
      })
      .strict()
      .nullable(),
    accounts: z
      .array(accountSchema)
      .max(STACK_ACCOUNTS_MAX)
      .refine((as) => new Set(as.map((a) => a.account_id)).size === as.length, { message: "an account is listed twice" }),
    sealed_unnamed: u32,
    routes_excluded: z
      .array(z.object({ protocol: z.string().regex(/^[a-z0-9_]{1,64}$/), requested_model: model, reason: z.enum(["route_unserved", "route_conflict"]) }).strict())
      .max(STACK_REPORT_ROUTES_MAX),
    appends_excluded: z.array(z.object({ append_id: id, reason: z.enum(["append_digest_mismatch", "appends_over_limit"]) }).strict()).max(STACK_REPORT_APPENDS_MAX),
    relay_image: z.string().max(512).regex(STACK_REPORT_RELAY_IMAGE_PATTERN).nullable().optional(),
    /** The boot's first violation the console has not taken (docs/design/relay-ejection.md); absent when none. */
    violation: stackViolationSchema.optional(),
  })
  .strict();
export type StackReportDto = z.infer<typeof stackReportSchema>;

export const stackReportAnswerSchema = z.object({ recorded: z.boolean() }).strict();
export type StackReportAnswerDto = z.infer<typeof stackReportAnswerSchema>;

/** One cooling entry of an account, with JS numbers. */
export interface StackReportCooling {
  readonly model: string | null;
  readonly kind: StackCoolingKind;
  readonly until_minute_ms: number | null;
  readonly rule_id: string;
  readonly class: StackAttemptClass;
  readonly vendor_code: StackVendorCode;
  readonly set_minute_ms: number;
  readonly gen: number;
  readonly observed: boolean;
  readonly clears: readonly (typeof STACK_RULE_CLEARS)[number][];
}
/** One vendor window of an account, with JS numbers. */
export interface StackReportWindow {
  readonly key: StackWindowKey;
  readonly window_minutes: number | null;
  readonly used_percent: number | null;
  readonly status: StackWindowStatus | null;
  readonly claim: StackWindowClaim | null;
  readonly resets_at_minute_ms: number | null;
  readonly observed_minute_ms: number;
}
/** An account's token refresh as the report carries it, with JS numbers. */
export interface StackReportRefresh {
  readonly mode: StackRefreshMode;
  /** Whether the credential in the VM carries a refresh token (never the token): `gray` is offered only with one. */
  readonly has_refresh_token: boolean;
  readonly problem: (typeof STACK_REFRESH_PROBLEMS)[number] | null;
  readonly last: { readonly outcome: "ok" | "failed"; readonly code: StackRefreshCode | null; readonly minute_ms: number } | null;
  readonly next_minute_ms: number | null;
  readonly failures: number;
}
/** One account of the report, with JS numbers. */
export interface StackReportAccount {
  readonly account_id: string;
  readonly served: (typeof STACK_SERVED)[number];
  readonly reason: (typeof STACK_ACCOUNT_EXCLUSIONS)[number] | null;
  readonly sealed: { readonly version: number; readonly type: (typeof STACK_CREDENTIAL_TYPES)[number]; readonly expires_at_s: number | null } | null;
  readonly proxy_id: string | null;
  readonly in_flight_peak: { readonly minute_ms: number; readonly value: number } | null;
  readonly cooling: readonly StackReportCooling[];
  readonly windows: readonly StackReportWindow[];
  /** Egress's refresh of the account; absent from an entry older than it. */
  readonly refresh?: StackReportRefresh | null;
  /** A password account's sign-in inside the VM; absent for every other account and from an entry older than it. */
  readonly login?: StackReportLogin | null;
}
/** A password account's sign-in as the report carries it, with JS numbers. */
export interface StackReportLogin {
  readonly by: (typeof STACK_LOGIN_BY)[number];
  readonly state: StackLoginState;
  readonly failures: number;
  readonly last: { readonly outcome: "ok" | "failed"; readonly code: StackLoginCode | null; readonly hour_ms: number } | null;
  readonly last_ok_hour_ms: number | null;
}
/** The report with JS numbers. */
/**
 * The relay's own request changes since egress started (docs/relay-request-changes.md), from an egress that counts
 * them: the calls egress accepted, those whose body or headers the relay changed, and the body bytes the relay's
 * changes added and removed (the receipts' totals). A relay padding requests to inflate token bills shows here.
 */
export interface StackRelayChangeCounters {
  readonly attempts_accepted: number;
  readonly body_changed: number;
  readonly headers_changed: number;
  readonly body_added_bytes: number;
  readonly body_removed_bytes: number;
}

export interface StackReport {
  readonly relay_id: string;
  readonly seq: number;
  readonly boot: { readonly started_minute_ms: number; readonly egress_started_minute_ms: number | null; readonly lease_expires_at_s: number | null };
  readonly config: { readonly console_version: number | null; readonly fetched_current: boolean; readonly fetched_minute_ms: number | null; readonly absent: (typeof STACK_CONFIG_ABSENT)[number] | null };
  readonly cooling: { readonly mode: StackCoolingMode | null; readonly digest: string | null };
  readonly counters: ({ readonly request_unknown: number; readonly attempts_exceeded: number } & Partial<StackRelayChangeCounters>) | null;
  readonly accounts: readonly StackReportAccount[];
  readonly sealed_unnamed: number;
  readonly routes_excluded: readonly { readonly protocol: string; readonly requested_model: string; readonly reason: "route_unserved" | "route_conflict" }[];
  readonly appends_excluded: readonly { readonly append_id: string; readonly reason: "append_digest_mismatch" | "appends_over_limit" }[];
  /** S55: the boot's relay image; absent from an entry older than S55. */
  readonly relay_image?: string | null;
  /** The boot's first violation the console has not taken; absent when none (docs/design/relay-ejection.md). */
  readonly violation?: StackViolation;
}

/** The report the console stores: the wire report with JS numbers. */
export function stackReportOf(dto: StackReportDto): StackReport {
  return numbersOfJson(dto, "") as StackReport;
}

/** The wire report of `report` (the entry's side): integers to bigints, then the strict schema (a malformed one throws). */
export function stackReportDtoOf(report: StackReport): StackReportDto {
  const parsed = stackReportSchema.safeParse(integersOfJson(report, ""));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the report is not its wire shape");
  return parsed.data;
}

/** `report` (JS numbers, as the bridge hands it on) checked again by the wire's schema: the console's own guard. */
export function checkedStackReport(report: unknown): StackReport {
  return stackReportOf(stackReportDtoOf(report as StackReport));
}

/** A minute of `ms`, floored: how the entry writes a start time (S33 rule 3). */
export function floorMinute(ms: number): number {
  return ms - (ms % 60_000);
}

/** A minute of `ms`, ceiled: how the entry writes an end time (S33 rule 3). */
export function ceilMinute(ms: number): number {
  const rest = ms % 60_000;
  return rest === 0 ? ms : ms - rest + 60_000;
}
