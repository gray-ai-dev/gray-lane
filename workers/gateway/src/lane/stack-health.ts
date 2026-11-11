import { parseStrict, toJsonString, type Json } from "@gray/json";
import { OPENAI_COMPATIBLE_VENDOR_IDS } from "@gray/lane";
import {
  ceilMinute,
  floorMinute,
  integersOfJson,
  numbersOfJson,
  STACK_ACCOUNTS_MAX,
  STACK_ATTEMPT_CLASSES,
  STACK_COOLING_KINDS,
  STACK_COOLING_MODES,
  STACK_LOGIN_BY,
  STACK_LOGIN_CODES,
  STACK_LOGIN_STATES,
  STACK_REPORT_APPENDS_MAX,
  STACK_REPORT_COOLING_MAX,
  STACK_REPORT_MAX_BYTES,
  STACK_REPORT_ROUTES_MAX,
  STACK_REPORT_WINDOWS_MAX,
  STACK_RULE_CLEARS,
  STACK_RULE_ID_PATTERN,
  STACK_TEST_CODES,
  STACK_TEST_OUTCOMES,
  STACK_TESTS_MAX,
  STACK_VENDOR_CODES,
  STACK_WINDOW_CLAIMS,
  STACK_WINDOW_KEYS,
  STACK_WINDOW_STATUSES,
  STACK_WIRE_ID_PATTERN,
  stackRulesDigest,
  uintSchema,
  type PendingStackTest,
  type StackConfigDocument,
  type StackReport,
  type StackReportAccount,
  type StackReportCooling,
  type StackReportKmsLease,
  type StackReportVault,
  type StackReportLogin,
  type StackRelayChangeCounters,
  type StackReportWindow,
  type StackRestoreEntry,
  type StackRulesAnswer,
  type StackRulesDocument,
  type StackTestCode,
  type StackTestResult,
  type StackTestsAnswer,
  type StackViolation,
} from "@gray/lane-wire";
import { authHeaders, credentialExpiry, egressValue, type StackSealedAccount } from "@gray/relay-connector";
import { z } from "zod";
import { BridgeCallError } from "./remote/client.ts";
import type { StackExclusion, StackExclusionReason } from "./stack-document.ts";

/**
 * Account health in the relay's VM (docs/confidential-lane-supply-implementation.md §9a, S40–S44): the entry's half,
 * between the console (the bridge ops `stack.rules`, `stack.report`, `stack.tests`) and egress (its control API's
 * `GET /v1/stack/health`, `PUT`/`GET /v1/stack/cooling`, `POST /v1/stack/account-tests`, on the unix socket). The
 * config service (`stack-service.ts`) runs it in its refresh, after the step that polled `stack.config`, so it rides on
 * the same traffic (the relay's version polls, requests, intakes): workerd runs nothing between requests.
 *
 * **One round** (at most one at a time, at most once per `LANE_STACK_POLL_MS`):
 *
 * 1. Egress's live state (S37). Egress keeps its rules and cooling entries in memory only, and its push number is 0
 *    until its first push since it started: then it holds nothing, after a restart or before any push, and the
 *    entries of the VM's last report are to be restored (S40, S41). One with a push number above 0 holds what the
 *    entry pushed, its entries included, also across a restart of the entry alone, which then restores nothing (that
 *    could bring back an entry a passing test cleared since the last report). The push number is also where this
 *    boot's numbering continues (`X-Gray-Stack-Cooling-Push`: egress refuses a lower one, 409 `stack_cooling_stale`).
 * 2. `stack.rules` (S41) with the digest held (`""` before any), `restore` at the first poll unless egress was read
 *    holding a push, and whenever egress holds nothing and no restore is held. A document is taken only when its
 *    digest is S41's (`stackRulesDigest`). Then `PUT /v1/stack/cooling` when egress holds another digest than the one
 *    taken (a new document, a push that did not take), or holds nothing; an egress that holds nothing gets its rules
 *    only together with its restore, so it never runs rules without the entries it lost. A restore stays held until a
 *    push carrying it took, or egress refused that push as malformed (400: the same body would be refused again).
 *    Console unreachable: egress keeps what it has.
 * 3. `stack.report` (S42) when it differs from the last one recorded and `LANE_STACK_REPORT_MIN_MS` passed since the
 *    last try, or `LANE_STACK_REPORT_HEARTBEAT_MS` passed since the last recorded one. No queue: a failed send is not
 *    retried; a later round builds a fresh one. Every time in it is a minute (S33 rule 3). The console keeps each
 *    account's entries of the latest report as the source of a later restore, so while egress's entries are not its
 *    own (unreadable, or lost and not yet restored) each account's entries are the last ones egress held settled, or
 *    those held to restore, ended ones left out; the relay-level members still say what is unknown (null). Until the
 *    VM knows any of them (egress not read settled, no restore answered yet: a boot before egress listens) no report
 *    is sent, so the console's copy stays the one to restore from.
 *
 * **Tests** (S44) run in a round of their own beside it, since one takes up to a minute: report the results held, take
 * the tests pending, run at most four at once (egress's bound), report their results with the next `stack.tests`
 * call, which takes the next ones; a test egress gave no answer to (unreachable, `stack_tests_busy`) is not invented
 * and stays pending at the console, and is not tried again in the same round.
 *
 * **The container's view** (S40): `GET …/v1/relay/config/cooling` answers egress's `GET /v1/stack/cooling` body as it
 * is, read at most once a second; it never changes `version`.
 *
 * Nothing here reads a request or an answer, and no line it logs names a credential, a value of a header or an
 * error's text: closed codes, ids the relay chose, counts.
 */

/** The three bridge ops (`StackConfigClient`). */
export interface StackHealthSource {
  rules(relayId: string, have: string, restore: boolean): Promise<StackRulesAnswer>;
  report(report: StackReport): Promise<boolean>;
  tests(relayId: string, results: readonly StackTestResult[]): Promise<StackTestsAnswer>;
}

/** Egress's control API over the unix socket (`EGRESS`). */
export interface StackHealthEgress {
  fetch(input: string, init: RequestInit): Promise<Response>;
}

/** What the config service holds that the report and the tests read (`StackConfigService.healthView`). */
export interface StackHealthView {
  /** The console's metadata, or null while it has none (absent, or not polled yet). */
  readonly metadata: StackConfigDocument | null;
  /** The console version `metadata` is (`stack.config`'s `version`); null with no metadata. */
  readonly consoleVersion: number | null;
  /** Why the console serves nothing for the relay (S42 `config.absent`), or null. */
  readonly absent: "unknown_relay" | "stack_config_refused" | null;
  /** The latest build's exclusions; null before any build. */
  readonly excluded: readonly StackExclusion[] | null;
  /** The relay's container fetched the latest build. */
  readonly fetchedCurrent: boolean;
  /** When it last fetched one, or null. */
  readonly fetchedAt: number | null;
}

export interface StackHealthOptions {
  readonly relayId: string;
  /** S55: the boot's measured relay image (LANE_STACK_RELAY_IMAGE), which the report repeats; null when unknown. */
  readonly relayImage: string | null;
  readonly source: StackHealthSource;
  readonly egress: StackHealthEgress | undefined;
  readonly credentials: {
    stackAccounts(relayId: string, nowMs: number): readonly StackSealedAccount[];
    stackLease(relayId: string): bigint | null;
  };
  readonly now: () => number;
  /** `LANE_STACK_POLL_MS`: one round per interval, and a control call's timeout. */
  readonly pollMs: number;
  /** `LANE_STACK_REPORT_MIN_MS` and `LANE_STACK_REPORT_HEARTBEAT_MS` (S42). */
  readonly reportMinMs: number;
  readonly reportHeartbeatMs: number;
  /**
   * P2c-2: the VM's KMS lease at a time, for the report's `kms_lease` (docs/design/relay-no-always-on-host.md H9); absent
   * for a VM without one, whose report has no such member. `credentials` then already reads through the lease's gate.
   */
  readonly kmsLease?: (nowMs: number) => StackReportKmsLease;
  /** P2e: the vault's versions for the report's `vault` (docs/design/relay-no-always-on-host.md 13.4); absent without a vault. */
  readonly vault?: () => StackReportVault;
  /** One JSON line per event; never a credential, a header value or a document. */
  readonly log?: (line: Record<string, unknown>) => void;
}

/** Egress's live state (S37). */
export const STACK_HEALTH_URL = "http://egress/v1/stack/health";
/** Egress's cooling rules and the container's view (S40). */
export const STACK_COOLING_URL = "http://egress/v1/stack/cooling";
/** Egress's account test (S44). */
export const STACK_ACCOUNT_TEST_URL = "http://egress/v1/stack/account-tests";
/** The header that numbers a cooling push in the entry's sequence (S40). */
export const STACK_COOLING_PUSH_HEADER = "x-gray-stack-cooling-push";
/**
 * How long the entry waits for one test's answer: egress bounds a whole test by 60 s (`proxyConnectCap`, S44), and
 * the entry allows one poll interval more for the answer to come back (as for a proxy check).
 */
export const STACK_TEST_EGRESS_CAP_MS = 60_000;
/** At most four tests at once (S44; egress answers a fifth 503 `stack_tests_busy`). */
export const STACK_TESTS_AT_ONCE = 4;
/** How long the container's cooling view is served from the last read (S40: cached ≤ 1 s). */
export const STACK_COOLING_VIEW_MS = 1_000;

/** The fixed body of a view the entry cannot give now. */
const UNAVAILABLE = '{"error":"stack_config_unavailable"}';

const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const u64Text = z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
/** An account id as egress writes it (`validStackID`: 1-128 bytes of printable ASCII without space). */
const egressId = z.string().regex(/^[\x21-\x7e]{1,128}$/);
const model = z.string().min(1).max(256);

/** One vendor window as egress reads it (S36), within the report's bounds. */
const egressWindowSchema = z
  .object({
    key: z.enum(STACK_WINDOW_KEYS),
    window_minutes: uintSchema.min(1n).max(20_160n).nullable(),
    used_percent: uintSchema.max(1000n).nullable(),
    status: z.enum(STACK_WINDOW_STATUSES).nullable(),
    claim: z.enum(STACK_WINDOW_CLAIMS).nullable(),
    resets_at_s: uintSchema.nullable(),
    observed_ms: uintSchema,
  })
  .strict();

const egressCoolingSchema = z
  .object({
    model: model.nullable(),
    kind: z.enum(STACK_COOLING_KINDS),
    until_ms: uintSchema.nullable(),
    rule_id: z.string().regex(STACK_RULE_ID_PATTERN),
    class: z.enum(STACK_ATTEMPT_CLASSES),
    vendor_code: z.enum(STACK_VENDOR_CODES),
    set_ms: uintSchema,
    gen: uintSchema,
    observed: z.boolean(),
    clears: z.array(z.enum(STACK_RULE_CLEARS)).max(STACK_RULE_CLEARS.length),
  })
  .strict();

/** A password account's sign-in (egress stack_login.go `loginHealth`): its times are already whole hours. */
const egressLoginSchema = z
  .object({
    by: z.enum(STACK_LOGIN_BY),
    state: z.enum(STACK_LOGIN_STATES),
    failures: uintSchema.max(4_294_967_295n),
    last: z.object({ outcome: z.enum(["ok", "failed"]), code: z.enum(STACK_LOGIN_CODES).nullable(), hour_ms: uintSchema }).strict().nullable(),
    last_ok_hour_ms: uintSchema.nullable(),
  })
  .strict();

/** `GET /v1/stack/health` (S37, egress `stack_health.go`), its integers as `parseStrict` reads them. */
const egressHealthSchema = z
  .object({
    started_ms: uintSchema,
    rules: z.object({ push: u64Text, digest: hex64.nullable(), mode: z.enum(STACK_COOLING_MODES) }).strict(),
    // With the relay-change counters (docs/relay-request-changes.md): egress and this lane ship in one stack lane release.
    counters: z
      .object({
        request_unknown: uintSchema,
        attempts_exceeded: uintSchema,
        attempts_accepted: uintSchema,
        body_changed: uintSchema,
        headers_changed: uintSchema,
        body_added_bytes: uintSchema,
        body_removed_bytes: uintSchema,
      })
      .strict(),
    accounts: z.array(
      z
        .object({
          account_id: egressId,
          in_flight: uintSchema,
          peak: z.object({ minute_ms: uintSchema, in_flight: uintSchema.max(4_294_967_295n) }).strict().nullable(),
          cooling: z.array(egressCoolingSchema),
          windows: z.array(egressWindowSchema),
          // A password account's sign-in inside the VM (docs/design/relay-in-cvm-login.md §4); absent for the others.
          login: egressLoginSchema.optional(),
        })
        .strict(),
    ),
  })
  .strict();

/** One window as egress reads it, with JS numbers. */
interface EgressWindow {
  readonly key: (typeof STACK_WINDOW_KEYS)[number];
  readonly window_minutes: number | null;
  readonly used_percent: number | null;
  readonly status: (typeof STACK_WINDOW_STATUSES)[number] | null;
  readonly claim: (typeof STACK_WINDOW_CLAIMS)[number] | null;
  readonly resets_at_s: number | null;
  readonly observed_ms: number;
}

/** Egress's live state with JS numbers; `push` stays a bigint (a u64). */
interface EgressHealth {
  readonly started_ms: number;
  readonly rules: { readonly push: bigint; readonly digest: string | null; readonly mode: (typeof STACK_COOLING_MODES)[number] };
  readonly counters: { readonly request_unknown: number; readonly attempts_exceeded: number } & StackRelayChangeCounters;
  readonly accounts: readonly {
    readonly account_id: string;
    readonly in_flight: number;
    readonly peak: { readonly minute_ms: number; readonly in_flight: number } | null;
    readonly cooling: readonly {
      readonly model: string | null;
      readonly kind: (typeof STACK_COOLING_KINDS)[number];
      readonly until_ms: number | null;
      readonly rule_id: string;
      readonly class: (typeof STACK_ATTEMPT_CLASSES)[number];
      readonly vendor_code: (typeof STACK_VENDOR_CODES)[number];
      readonly set_ms: number;
      readonly gen: number;
      readonly observed: boolean;
      readonly clears: readonly (typeof STACK_RULE_CLEARS)[number][];
    }[];
    readonly windows: readonly EgressWindow[];
    readonly login?: StackReportLogin;
  }[];
}

/** S44's answer (egress `stack_accounttest.go` `accountTestAnswer`): always 200. */
const egressTestAnswerSchema = z
  .object({
    outcome: z.enum(STACK_TEST_OUTCOMES),
    code: z.enum(STACK_TEST_CODES).nullable(),
    status: uintSchema.min(100n).max(599n).nullable(),
    class: z.enum(STACK_ATTEMPT_CLASSES).nullable(),
    vendor_code: z.enum(STACK_VENDOR_CODES).nullable(),
    first_byte_ms: uintSchema.nullable(),
    first_token_ms: uintSchema.nullable(),
    total_ms: uintSchema,
    windows: z.array(egressWindowSchema).max(STACK_REPORT_WINDOWS_MAX),
    cleared: uintSchema.max(4_294_967_295n),
  })
  .strict()
  .refine((a) => (a.outcome === "ok") === (a.code === null), { message: "an ok test has no code, a failed one names one" });

/** `GET /v1/stack/cooling` (S40): the container's view, checked for its shape before it is served as it is. */
const egressCoolingViewSchema = z
  .object({ as_of_ms: uintSchema, accounts: z.array(z.object({ id: egressId, model: model.nullable(), until_ms: uintSchema.nullable() }).strict()) })
  .strict();

/**
 * The credential form's auth headers egress takes for a test (`stackTestCredentialForms`, relay-connector `authHeaders`):
 * an OpenAI-compatible vendor's API key is `authorization`, as OpenAI's.
 */
const STACK_TEST_CREDENTIAL_FORMS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "anthropic/api_key": ["x-api-key"],
  "anthropic/oauth_access_token": ["authorization"],
  "openai/api_key": ["authorization"],
  "chatgpt_codex/oauth_access_token": ["authorization", "chatgpt-account-id"],
  ...Object.fromEntries(OPENAI_COMPATIBLE_VENDOR_IDS.map((id) => [`${id}/api_key`, ["authorization"]])),
});

/**
 * The exclusions under which the VM does not hold the sealed credential and proxy the panel names for an account
 * (S44 `not_sealed`): a test of what the VM does hold would not be the account's. A duplicate credential is the
 * account's own, so it is tested.
 */
const NOT_SEALED_FOR_TEST: ReadonlySet<StackExclusionReason> = new Set([
  "not_sealed",
  "vendor_mismatch",
  "credential_waiting",
  "invalid_credential",
  "proxy_unknown",
  "proxy_mismatch",
  "proxy_waiting",
  // A password account before its first sign-in has no token to test with.
  "login_waiting",
]);

/** The protocol word a report's excluded route may carry (the bridge's schema). */
const REPORT_PROTOCOL = /^[a-z0-9_]{1,64}$/;

/** A sealed version or an expiry as the report's JS number: a u64 past 2^53 is reported as the largest exact one. */
function safeNumber(value: bigint): number {
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
}

function errorCode(error: unknown): string {
  if (error instanceof BridgeCallError) return error.code;
  return error instanceof Error ? error.name : "error";
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/** A cooling entry as the report carries it: its times as minutes (the end ceiled, the start floored). */
function reportCooling(entry: EgressHealth["accounts"][number]["cooling"][number]): StackReportCooling {
  return {
    model: entry.model,
    kind: entry.kind,
    until_minute_ms: entry.until_ms === null ? null : ceilMinute(entry.until_ms),
    rule_id: entry.rule_id,
    class: entry.class,
    vendor_code: entry.vendor_code,
    set_minute_ms: floorMinute(entry.set_ms),
    gen: entry.gen,
    observed: entry.observed,
    clears: [...entry.clears],
  };
}

/** A restore entry (the console's copy of a report's entry, its times already minutes) as the report carries it. */
function restoredCooling(entry: StackRestoreEntry): StackReportCooling {
  return {
    model: entry.model,
    kind: entry.kind,
    until_minute_ms: entry.until_ms === null ? null : ceilMinute(entry.until_ms),
    rule_id: entry.rule_id,
    class: entry.class,
    vendor_code: entry.vendor_code,
    set_minute_ms: floorMinute(entry.set_ms),
    gen: entry.gen,
    observed: entry.observed,
    clears: [...entry.clears],
  };
}

/** A window as the report and a test result carry it: its times as minutes (ends ceiled, the observation floored). */
function reportWindow(w: EgressWindow): StackReportWindow {
  return {
    key: w.key,
    window_minutes: w.window_minutes,
    used_percent: w.used_percent,
    status: w.status,
    claim: w.claim,
    resets_at_minute_ms: w.resets_at_s === null ? null : ceilMinute(w.resets_at_s * 1000),
    observed_minute_ms: floorMinute(w.observed_ms),
  };
}

/** `text` parsed strictly and held to `schema`, its integers as JS numbers; null when it is not that document. */
function egressDocument<T>(text: string, schema: z.ZodType): T | null {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    return null;
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success) return null;
  try {
    return numbersOfJson(parsed.data, "") as T;
  } catch {
    return null;
  }
}

export class StackHealthService {
  readonly #options: StackHealthOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  /** This boot's start: the report's `boot.started_minute_ms`. */
  readonly #bootedAt: number;
  #polledAt: number | null = null;
  #running = false;
  /** The rules taken from the console, by their S41 digest. */
  #rules: { readonly digest: string; readonly document: StackRulesDocument } | null = null;
  /**
   * The next poll asks for the entries to restore: at the first (egress may be unread yet, and the restore is then the
   * report's source of the accounts' entries), and whenever egress holds nothing (push 0) and no restore is held.
   */
  #restoreWanted = true;
  /** The VM knows its accounts' entries: egress was read holding its own, or a restore was answered. */
  #entriesKnown = false;
  /** Entries to restore that no push carried yet. */
  #restore: readonly StackRestoreEntry[] | null = null;
  /** Each account's entries and windows as egress last held them settled (its own, restored), as the report has them. */
  #settled = new Map<string, { readonly cooling: readonly StackReportCooling[]; readonly windows: readonly StackReportWindow[] }>();
  /** Each password account's sign-in as egress was last read: a round that cannot read egress reports these. */
  #login = new Map<string, StackReportLogin>();
  /** Egress's `started_ms` as last read. */
  #egressStarted: number | null = null;
  /** The last cooling push number used or seen at egress (S40's sequence). */
  #coolingPush = 0n;
  /** The report: the last one the console took (its text without `seq`, and when), the last try, the last `seq`. */
  #reported: { readonly text: string; readonly at: number } | null = null;
  #reportTriedAt: number | null = null;
  #seq = 0;
  /** Tests (S44): when the bridge was last asked, whether a round runs, and the results not yet reported. */
  #testsPolledAt: number | null = null;
  #testing = false;
  #testResults: StackTestResult[] = [];
  /** The container's view (S40): the last body egress gave and when, and a read in flight. */
  #view: { readonly body: string; readonly at: number } | null = null;
  #viewRead: Promise<string | null> | null = null;
  /**
   * The boot's first violation the console has not taken (docs/design/relay-ejection.md section 2): the report carries
   * it until a report that carried it is recorded. One is enough: a later one waits until the console took it.
   */
  #violation: StackViolation | null = null;
  /** Whether a report carried the held violation yet: its first send does not wait for LANE_STACK_REPORT_MIN_MS. */
  #violationSent = false;

  constructor(options: StackHealthOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
    this.#bootedAt = options.now();
  }

  /** Holds `violation` for the next report unless one is held already; true when it is now held. */
  hold(violation: StackViolation): boolean {
    if (this.#violation !== null) return false;
    this.#violation = violation;
    this.#violationSent = false;
    return true;
  }

  /** A violation is held: the console has not taken it yet. */
  get holding(): boolean {
    return this.#violation !== null;
  }

  /**
   * One round: egress's state, the rules, the report (at most one at a time, once per poll interval). None while the
   * console has no stack for the relay (`unknown_relay`): each op would be the same 404.
   */
  async round(view: () => StackHealthView): Promise<void> {
    const now = this.#options.now();
    if (this.#running || (this.#polledAt !== null && now - this.#polledAt < this.#options.pollMs) || view().absent === "unknown_relay") return;
    this.#running = true;
    this.#polledAt = now;
    try {
      let health = await this.#readHealth();
      if (health !== null) this.#observe(health);
      // A push changes what egress holds (its mode, its digest, the entries restored): the report says what it holds after.
      if (await this.#syncRules(health)) {
        health = await this.#readHealth();
        if (health !== null) this.#observe(health);
      }
      if (health !== null) this.#login = new Map(health.accounts.flatMap((a) => (a.login ? [[a.account_id, a.login] as const] : [])));
      if (health !== null && this.#holdsOwn(health)) {
        this.#settled = new Map(health.accounts.map((a) => [a.account_id, { cooling: a.cooling.map(reportCooling), windows: a.windows.map(reportWindow) }]));
        this.#entriesKnown = true;
      }
      if (this.#entriesKnown) await this.#maybeReport(view(), health);
    } finally {
      this.#running = false;
    }
  }

  // ------------------------------------------------------------------------------------------- egress's state

  async #readHealth(): Promise<EgressHealth | null> {
    const text = await this.#egressText(STACK_HEALTH_URL, { method: "GET" }, "lane_stack_health_read_failed");
    if (text === null) return null;
    const wire = egressDocument<Omit<EgressHealth, "rules"> & { readonly rules: { readonly push: string; readonly digest: string | null; readonly mode: EgressHealth["rules"]["mode"] } }>(text, egressHealthSchema);
    if (wire === null) {
      this.#log({ level: "warn", event: "lane_stack_health_read_failed", relay_id: this.#options.relayId, code: "invalid_document" });
      return null;
    }
    return { ...wire, rules: { ...wire.rules, push: BigInt(wire.rules.push) } };
  }

  /** A 200 body of egress's at `url`, or null (logged as `event`) when there is none. */
  async #egressText(url: string, init: RequestInit, event: string, timeoutMs = this.#options.pollMs): Promise<string | null> {
    const egress = this.#options.egress;
    if (egress === undefined) {
      this.#log({ level: "error", event, relay_id: this.#options.relayId, code: "no_binding" });
      return null;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await egress.fetch(url, { ...init, signal: controller.signal });
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined);
        this.#log({ level: "warn", event, relay_id: this.#options.relayId, code: "status", status: response.status });
        return null;
      }
      return await response.text();
    } catch (error) {
      this.#log({ level: "warn", event, relay_id: this.#options.relayId, code: errorCode(error) });
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * An egress that holds nothing (push 0) wants a restore unless one is held; one that holds a push has its entries,
   * so a held restore is dropped (a push carrying it took, or another boot's did). Egress's push number is the floor
   * of this boot's next one.
   */
  #observe(health: EgressHealth): void {
    if (this.#egressStarted !== null && this.#egressStarted !== health.started_ms) this.#log({ level: "info", event: "lane_stack_egress_restarted", relay_id: this.#options.relayId });
    this.#egressStarted = health.started_ms;
    if (health.rules.push === 0n) {
      if (this.#restore === null) this.#restoreWanted = true;
    } else {
      this.#restoreWanted = false;
      this.#restore = null;
    }
    if (health.rules.push > this.#coolingPush) this.#coolingPush = health.rules.push;
  }

  /** Egress's entries are its own: it holds a push, and no restore is wanted or held. */
  #holdsOwn(health: EgressHealth): boolean {
    return health.rules.push > 0n && !this.#restoreWanted && this.#restore === null;
  }

  // ------------------------------------------------------------------------------------------- rules (S41)

  /** Poll the rules and push them when egress holds other ones or a restore came; true when a push took. */
  async #syncRules(health: EgressHealth | null): Promise<boolean> {
    const options = this.#options;
    const restore = this.#restoreWanted;
    try {
      const answer = await options.source.rules(options.relayId, this.#rules?.digest ?? "", restore);
      if (answer.document !== null) {
        const digest = stackRulesDigest(answer.document);
        if (digest === answer.digest) this.#rules = { digest, document: answer.document };
        else this.#log({ level: "error", event: "lane_stack_rules_refused", relay_id: options.relayId, code: "digest_mismatch" });
      }
      if (restore) {
        this.#restore = answer.restore;
        this.#restoreWanted = false;
        this.#entriesKnown = true;
      }
    } catch (error) {
      // Console unreachable or the relay unknown: egress keeps what it has.
      this.#log({ level: "warn", event: "lane_stack_rules_poll_failed", relay_id: options.relayId, code: errorCode(error), ...(error instanceof BridgeCallError && error.status !== null ? { status: error.status } : {}) });
    }
    const rules = this.#rules;
    if (health === null || rules === null) return false;
    if (health.rules.push === 0n) {
      // Egress holds nothing: its rules go together with what it is to restore, once the console gave that.
      if (this.#restore === null) return false;
    } else if (health.rules.digest === rules.digest) {
      return false;
    }
    return this.#pushCooling(rules);
  }

  async #pushCooling(rules: { readonly digest: string; readonly document: StackRulesDocument }): Promise<boolean> {
    const options = this.#options;
    const egress = options.egress;
    if (egress === undefined) return false;
    const restore = this.#restore;
    const { mode, rules: list, windows, accounts } = rules.document;
    const body = toJsonString(integersOfJson({ digest: rules.digest, mode, rules: list, windows, accounts, ...(restore === null ? {} : { restore }) }, "") as Json);
    this.#coolingPush += 1n;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.pollMs);
    let status: number;
    try {
      const response = await egress.fetch(STACK_COOLING_URL, {
        method: "PUT",
        headers: { "content-type": "application/json", [STACK_COOLING_PUSH_HEADER]: this.#coolingPush.toString() },
        body,
        signal: controller.signal,
      });
      status = response.status;
      await response.body?.cancel().catch(() => undefined);
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_cooling_push_failed", relay_id: options.relayId, code: errorCode(error) });
      return false;
    } finally {
      clearTimeout(timer);
    }
    if (status === 204) {
      if (this.#restore === restore) this.#restore = null;
      this.#log({ level: "info", event: "lane_stack_cooling_pushed", relay_id: options.relayId, digest: rules.digest, mode, restored: restore?.length ?? 0 });
      return true;
    }
    // 409 `stack_cooling_stale`: egress holds a higher push number than this one; the next round reads it from egress's
    // state and numbers above it. Anything else is egress's fixed refusal, found in its own log by the status; a
    // malformed body (400) is refused again as it is, so a restore it carried goes and the rules go alone next round.
    this.#log({ level: "warn", event: status === 409 ? "lane_stack_cooling_push_stale" : "lane_stack_cooling_push_failed", relay_id: options.relayId, code: "status", status });
    if (status === 400 && restore !== null && this.#restore === restore) {
      this.#restore = [];
      this.#log({ level: "error", event: "lane_stack_restore_dropped", relay_id: options.relayId, entries: restore.length });
    }
    return false;
  }

  // ------------------------------------------------------------------------------------------- the report (S42)

  async #maybeReport(view: StackHealthView, health: EgressHealth | null): Promise<void> {
    const options = this.#options;
    const now = options.now();
    // A violation's first report goes at once; any other waits LANE_STACK_REPORT_MIN_MS after the last try.
    const urgent = this.#violation !== null && !this.#violationSent;
    if (!urgent && this.#reportTriedAt !== null && now - this.#reportTriedAt < options.reportMinMs) return;
    // What changed is what the console would store: the report without its sequence number (still 0 here), as fitting
    // it serialized it.
    const { report, text } = this.#fitted(this.#buildReport(view, health, now));
    const reported = this.#reported;
    if (reported !== null && reported.text === text && now - reported.at < options.reportHeartbeatMs) return;
    this.#reportTriedAt = now;
    const carried = report.violation ?? null;
    if (carried !== null) this.#violationSent = true;
    // Per boot and growing; past every earlier boot's too (milliseconds), so an entry restarted within one boot minute
    // is not refused as older than the boot before it (S42's order: boot minute, then seq).
    this.#seq = Math.max(this.#seq + 1, now);
    try {
      const recorded = await options.source.report({ ...report, seq: this.#seq });
      // A violation the console did not record is sent again after LANE_STACK_REPORT_MIN_MS, not at the heartbeat.
      if (recorded || carried === null) this.#reported = { text, at: now };
      if (!recorded) this.#log({ level: "warn", event: "lane_stack_report_not_recorded", relay_id: options.relayId });
      // The console took the violation, and decided whether the relay routes.
      if (recorded && carried !== null && this.#violation?.id === carried.id) {
        this.#violation = null;
        this.#log({ level: "info", event: "lane_stack_violation_taken", relay_id: options.relayId, code: carried.code });
      }
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_report_failed", relay_id: options.relayId, code: errorCode(error) });
    }
  }

  /** S42's report of now, `seq` left 0. */
  #buildReport(view: StackHealthView, health: EgressHealth | null, now: number): StackReport {
    const options = this.#options;
    const sealed = options.credentials.stackAccounts(options.relayId, now);
    const sealedById = new Map(sealed.map((account) => [account.account_id, account]));
    const lease = options.credentials.stackLease(options.relayId);
    const metadata = view.metadata;
    const excluded = view.excluded ?? [];
    const accountReasons = new Map(excluded.filter((e) => e.kind === "account").map((e) => [e.id, e.reason]));
    const egressById = new Map((health?.accounts ?? []).map((a) => [a.account_id, a]));
    // While egress's entries are not its own, an account's are the last it held settled, else those held to restore.
    const own = health !== null && this.#holdsOwn(health);
    const restoring = new Map<string, StackReportCooling[]>();
    for (const entry of this.#restore ?? []) restoring.set(entry.account_id, [...(restoring.get(entry.account_id) ?? []), restoredCooling(entry)]);
    // An entry a Clear since then dropped (its generation below the account's in the rules held) is not carried.
    const generations = this.#rules?.document.accounts ?? {};
    const carried = (accountId: string): readonly StackReportCooling[] =>
      (this.#settled.get(accountId)?.cooling ?? restoring.get(accountId) ?? []).filter((entry) => (entry.until_minute_ms === null || entry.until_minute_ms > now) && entry.gen >= (generations[accountId] ?? 0));
    const panel = [...(metadata?.accounts ?? [])].sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0)).slice(0, STACK_ACCOUNTS_MAX);
    const named = new Set(panel.map((account) => account.id));
    const accounts = panel.map((account): StackReportAccount => {
      const reason = accountReasons.get(account.id) ?? null;
      const held = sealedById.get(account.id);
      const live = egressById.get(account.id);
      // docs/design/relay-sign-in-in-vm.md: an account sealed for sign-in inside the VM says so, and one egress reports
      // nothing of yet (a `sign_in` account before its first sign-in) needs one.
      const vmSignIn = held !== undefined && (held.credential.type === "sign_in" || held.credential.type === "password");
      const reported = this.#login.get(account.id);
      const login: StackReportLogin | undefined =
        reported !== undefined
          ? { ...reported, ...(vmSignIn ? { vm_sign_in: true as const } : {}) }
          : held?.credential.type === "sign_in"
            ? { by: "relay", state: "needed", failures: 0, last: null, last_ok_hour_ms: null, vm_sign_in: true }
            : undefined;
      return {
        account_id: account.id,
        served: reason !== null ? "excluded" : account.status === "paused" ? "paused" : "served",
        reason: reason as StackReportAccount["reason"],
        // A password account serves with its sign-in's access token, the type the report names.
        sealed:
          held === undefined
            ? null
            : { version: safeNumber(held.version), type: held.credential.type === "password" || held.credential.type === "sign_in" ? "oauth_access_token" : held.credential.type, expires_at_s: sealedExpiry(held) },
        proxy_id: account.proxy_id,
        in_flight_peak: live === undefined || live.peak === null ? null : { minute_ms: floorMinute(live.peak.minute_ms), value: live.peak.in_flight },
        cooling: (own ? (live?.cooling ?? []).map(reportCooling) : carried(account.id)).slice(0, STACK_REPORT_COOLING_MAX),
        windows: (health === null ? (this.#settled.get(account.id)?.windows ?? []) : (live?.windows ?? []).map(reportWindow)).slice(0, STACK_REPORT_WINDOWS_MAX),
        ...(login === undefined ? {} : { login }),
      };
    });
    return {
      relay_id: options.relayId,
      seq: 0,
      boot: { started_minute_ms: floorMinute(this.#bootedAt), egress_started_minute_ms: health === null ? null : floorMinute(health.started_ms), lease_expires_at_s: lease === null ? null : safeNumber(lease) },
      config: { console_version: view.consoleVersion, fetched_current: view.fetchedCurrent, fetched_minute_ms: view.fetchedAt === null ? null : floorMinute(view.fetchedAt), absent: view.absent },
      cooling: { mode: health?.rules.mode ?? null, digest: health?.rules.digest ?? null },
      counters: health === null ? null : { ...health.counters },
      accounts,
      sealed_unnamed: sealed.filter((account) => !named.has(account.account_id)).length,
      routes_excluded: excluded
        .flatMap((e) =>
          e.kind === "route" && e.route !== undefined && REPORT_PROTOCOL.test(e.route.protocol) && e.route.requestedModel.length >= 1 && e.route.requestedModel.length <= 256
            ? [{ protocol: e.route.protocol, requested_model: e.route.requestedModel, reason: e.reason as "route_unserved" | "route_conflict" }]
            : [],
        )
        .slice(0, STACK_REPORT_ROUTES_MAX),
      appends_excluded: excluded
        .flatMap((e) => (e.kind === "append" && STACK_WIRE_ID_PATTERN.test(e.id) ? [{ append_id: e.id, reason: e.reason as "append_digest_mismatch" | "appends_over_limit" }] : []))
        .slice(0, STACK_REPORT_APPENDS_MAX),
      relay_image: options.relayImage,
      ...(this.#violation === null ? {} : { violation: this.#violation }),
      ...(options.kmsLease === undefined ? {} : { kms_lease: options.kmsLease(now) }),
      ...(options.vault === undefined ? {} : { vault: options.vault() }),
    };
  }

  /**
   * `report` within S42's 1 MiB: a relay with very many accounts, each with every window and many cooling entries, can
   * pass it. The windows go first (the latest values, read again at the next report), then each account's cooling
   * entries past a bound that halves until it fits (entries are the account's own first, then by model). With its text:
   * each candidate is serialized once, and a bound at or above the longest list, which cuts nothing, not at all.
   */
  #fitted(report: StackReport): { readonly report: StackReport; readonly text: string } {
    const encoded = (r: StackReport) => {
      const text = toJsonString(integersOfJson(r, "") as Json);
      return { report: r, text, bytes: new TextEncoder().encode(text).byteLength };
    };
    let fitted = encoded(report);
    if (fitted.bytes <= STACK_REPORT_MAX_BYTES) return fitted;
    fitted = encoded({ ...report, accounts: report.accounts.map((a) => ({ ...a, windows: [] })) });
    let longest = Math.max(0, ...fitted.report.accounts.map((a) => a.cooling.length));
    for (let most = STACK_REPORT_COOLING_MAX / 2; fitted.bytes > STACK_REPORT_MAX_BYTES && most >= 0; most = most === 0 ? -1 : Math.floor(most / 2)) {
      if (most >= longest) continue;
      fitted = encoded({ ...fitted.report, accounts: fitted.report.accounts.map((a) => ({ ...a, cooling: a.cooling.slice(0, most) })) });
      longest = most;
    }
    this.#log({ level: "warn", event: "lane_stack_report_trimmed", relay_id: this.#options.relayId, accounts: report.accounts.length });
    return fitted;
  }

  // ------------------------------------------------------------------------------------------- tests (S44)

  /** One round of tests, at most one at a time and once per poll interval; none for a relay the console does not have. */
  async testsRound(view: () => StackHealthView): Promise<void> {
    const options = this.#options;
    const now = options.now();
    if (this.#testing || (this.#testsPolledAt !== null && now - this.#testsPolledAt < options.pollMs) || view().absent === "unknown_relay") return;
    this.#testing = true;
    this.#testsPolledAt = now;
    // Tests egress gave no answer to in this round: still pending at the console, not tried again until the next round.
    const tried = new Set<string>();
    try {
      for (;;) {
        const answer = await this.#exchangeTests();
        if (answer === null) return;
        const held = new Set(this.#testResults.map((result) => result.test_id));
        const room = Math.max(0, STACK_TESTS_MAX - this.#testResults.length);
        const fresh = answer.pending.filter((test) => !held.has(test.test_id) && !tried.has(test.test_id)).slice(0, Math.min(STACK_TESTS_AT_ONCE, room));
        if (fresh.length === 0) return;
        for (const test of fresh) tried.add(test.test_id);
        const results = await Promise.all(fresh.map((test) => this.#runTest(test, view())));
        for (const result of results) if (result !== null) this.#testResults.push(result);
      }
    } finally {
      this.#testing = false;
    }
  }

  /** Report up to STACK_TESTS_MAX held results; the console's answer, or null when the bridge did not answer. */
  async #exchangeTests(): Promise<StackTestsAnswer | null> {
    const options = this.#options;
    const sent = this.#testResults.slice(0, STACK_TESTS_MAX);
    try {
      const answer = await options.source.tests(options.relayId, sent);
      this.#testResults = this.#testResults.filter((result) => !sent.includes(result));
      return answer;
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_tests_failed", relay_id: options.relayId, code: errorCode(error) });
      return null;
    }
  }

  /**
   * One test (S44): the account's sealed credential in its form's auth headers, its identity and its sealed proxy
   * (the body is egress's table template: the relay's test profiles no longer reach a vendor); or the entry's own failure without calling egress (`account_unknown`,
   * `model_unknown`, `not_sealed`, `credential_expired`). Null when egress gave no answer.
   */
  async #runTest(test: PendingStackTest, view: StackHealthView): Promise<StackTestResult | null> {
    const options = this.#options;
    const failed = (code: StackTestCode): StackTestResult => ({
      test_id: test.test_id,
      outcome: "failed",
      code,
      status: null,
      class: null,
      vendor_code: null,
      first_byte_ms: null,
      first_token_ms: null,
      total_ms: null,
      windows: [],
      cleared: 0,
      checked_ms: options.now(),
    });
    const account = view.metadata?.accounts.find((a) => a.id === test.account_id);
    if (account === undefined) return failed("account_unknown");
    if (!account.models.includes(test.model)) return failed("model_unknown");
    const reason = (view.excluded ?? []).find((e) => e.kind === "account" && e.id === account.id)?.reason;
    const sealed = options.credentials.stackAccounts(options.relayId, options.now()).find((a) => a.account_id === account.id);
    if ((reason !== undefined && NOT_SEALED_FOR_TEST.has(reason)) || sealed === undefined || sealed.vendor !== account.vendor) return failed("not_sealed");
    const proxied = account.proxy_id !== null;
    if (proxied !== (sealed.egress !== undefined)) return failed("not_sealed");
    const expiry = sealedExpiry(sealed);
    if (expiry !== null && Math.floor(options.now() / 1000) >= expiry) return failed("credential_expired");
    const formKey = `${account.vendor}/${sealed.credential.type}`;
    let credential: Record<string, string>;
    try {
      const headers = authHeaders(account.vendor, sealed.credential);
      credential = Object.fromEntries((STACK_TEST_CREDENTIAL_FORMS[formKey] ?? []).map((name) => [name, headers[name] ?? ""]));
    } catch {
      return failed("not_sealed");
    }
    const body = {
      test_id: test.test_id,
      account_id: account.id,
      vendor: account.vendor,
      credential_type: sealed.credential.type,
      protocol: test.protocol,
      model: test.model,
      credential,
      identity: account.identity === undefined ? null : { headers: { ...account.identity.headers }, betas: [...account.identity.betas], generated: [...account.identity.generated] },
      // No text of the relay's: egress builds the body from its vendor operations table's test template
      // (docs/relay-changes-v2.md §6), whose texts are the table's own constants.
      proxy: sealed.egress === undefined ? null : egressValue(sealed.egress),
      proxy_id: account.proxy_id,
    };
    const text = await this.#egressText(
      STACK_ACCOUNT_TEST_URL,
      { method: "POST", headers: { "content-type": "application/json" }, body: toJsonString(integersOfJson(body, "") as Json) },
      "lane_stack_test_failed",
      STACK_TEST_EGRESS_CAP_MS + options.pollMs,
    );
    if (text === null) return null;
    const answer = egressDocument<{
      readonly outcome: "ok" | "failed";
      readonly code: StackTestCode | null;
      readonly status: number | null;
      readonly class: StackTestResult["class"];
      readonly vendor_code: StackTestResult["vendor_code"];
      readonly first_byte_ms: number | null;
      readonly first_token_ms: number | null;
      readonly total_ms: number;
      readonly windows: readonly EgressWindow[];
      readonly cleared: number;
    }>(text, egressTestAnswerSchema);
    if (answer === null) {
      this.#log({ level: "warn", event: "lane_stack_test_failed", relay_id: options.relayId, test_id: test.test_id, code: "invalid_document" });
      return null;
    }
    return {
      test_id: test.test_id,
      outcome: answer.outcome,
      code: answer.code,
      status: answer.status,
      class: answer.class,
      vendor_code: answer.vendor_code,
      first_byte_ms: answer.first_byte_ms,
      first_token_ms: answer.first_token_ms,
      total_ms: answer.total_ms,
      windows: answer.windows.map(reportWindow),
      cleared: answer.cleared,
      checked_ms: options.now(),
    };
  }

  // ------------------------------------------------------------------------------------------- the container's view (S40)

  /**
   * `GET …/v1/relay/config/cooling`: egress's `GET /v1/stack/cooling` body as it is (the enforced entries, exact
   * times: the reader is the relay's own container in the VM), read at most once a second; 503 while egress gives none.
   */
  async serveCooling(): Promise<Response> {
    const now = this.#options.now();
    const cached = this.#view;
    if (cached !== null && now - cached.at < STACK_COOLING_VIEW_MS) return json(200, cached.body);
    this.#viewRead ??= (async () => {
      try {
        const text = await this.#egressText(STACK_COOLING_URL, { method: "GET" }, "lane_stack_cooling_view_failed");
        if (text === null) return null;
        if (egressDocument(text, egressCoolingViewSchema) === null) {
          this.#log({ level: "warn", event: "lane_stack_cooling_view_failed", relay_id: this.#options.relayId, code: "invalid_document" });
          return null;
        }
        this.#view = { body: text, at: this.#options.now() };
        return text;
      } finally {
        this.#viewRead = null;
      }
    })();
    const body = await this.#viewRead;
    return body === null ? json(503, UNAVAILABLE) : json(200, body);
  }
}

/** A sealed credential's expiry in Unix seconds as the report carries it, or null (none known, or unreadable). */
function sealedExpiry(account: StackSealedAccount): number | null {
  try {
    const expiry = credentialExpiry(account.credential);
    return expiry === null ? null : safeNumber(expiry);
  } catch {
    return null;
  }
}
