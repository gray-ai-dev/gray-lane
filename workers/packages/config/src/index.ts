/**
 * @gray/config: every Worker var of the new Workers (gray-gateway, gray-jobs, gray-console,
 * gray-identity) in one table, and the parser that turns a Worker's env into a typed, frozen
 * configuration.
 *
 * Rules (the repository's config-not-hardcoded rule, and workers/credit/src/lib/config.ts):
 * - A tunable is a row here with a default, bounds and `source`: where the default and the bounds
 *   come from (provider docs, a measurement, today's server value). A row without a source does
 *   not pass the tests.
 * - Defaults live only here. A wrangler file carries what an environment is and explicit overrides.
 * - Nothing is clamped: a value out of range is an error that names the var. Every problem is
 *   reported at once, in a ConfigError.
 * - A bound one var's source states against another var is a cross check (CROSS_CHECKS), with its
 *   own source; each row's own bounds cannot express it.
 * - Code reads vars only through `gatewayConfig(env)` / `jobsConfig(env)` / `consoleConfig(env)` /
 *   `identityConfig(env)`, never `env.NAME`.
 *
 * Pure code, erasable TypeScript only: loaded by workerd, vitest and Node (deploy checks).
 */

import { LEDGER_CROSS_CHECKS, ledgerSettings, type LedgerJobsConfig } from "./ledger.ts";

export type WorkerName = "gateway" | "jobs" | "console" | "identity" | "alerts" | "content";
export const DEPLOY_ENVS = ["local", "testnet", "production"] as const;
export type DeployEnv = (typeof DEPLOY_ENVS)[number];
/**
 * Durable Object location hints (C51 in docs/cloudflare-native.md section 14,
 * https://developers.cloudflare.com/durable-objects/reference/data-location/, read 2026-10-17); the same
 * list as workers/credit/src/lib/config.ts LOCATION_HINTS. @gray/account names its regions with these.
 */
export const LOCATION_HINTS = ["wnam", "enam", "sam", "weur", "eeur", "apac", "apac-ne", "apac-se", "oc", "afr", "me"] as const;
export type LocationHint = (typeof LOCATION_HINTS)[number];
/** The region rule itself (`region.ts`): the hint a request's `cf` blob names, shared by the gateway and the lane bridge. */
export { durableObjectOverloaded, durableObjectReset } from "./platform.ts";
export { DEFAULT_HOME_REGION, isLocationHint, requestRegion, type RequestPlace } from "./region.ts";
/** The RPC surfaces between Workers and between two versions of one, and the rules a release keeps them by (`rpc.ts`). */
export {
  ADDED_CALLS,
  RETIRED_CALLS,
  RPC_SURFACES,
  rpcChanges,
  rpcLists,
  rpcProblems,
  type CallsOnly,
  type Exposes,
  type MethodNames,
  type RpcSurface,
  type RpcSurfaceId,
  type RpcWorker,
} from "./rpc.ts";
/** USAGE_MISSING values: what an answer without usage gets (release 2's GRAY_USAGE_MISSING without `estimate`). */
export const USAGE_MISSING_RULES = ["free", "refuse"] as const;
export type UsageMissingRule = (typeof USAGE_MISSING_RULES)[number];
/** IMAGE_USAGE_UNSPLIT values: what a Gemini image answer whose usage does not count the image apart is billed at (release 4's GRAY_IMAGE_USAGE_UNSPLIT). */
export const IMAGE_USAGE_UNSPLIT_POLICIES = ["image_price", "free"] as const;
export type ImageUsageUnsplit = (typeof IMAGE_USAGE_UNSPLIT_POLICIES)[number];
/** ACCOUNT_CLIENT_KEY_FALLBACK values (@gray/account client.ts ClientKeyFallback). */
export const CLIENT_KEY_FALLBACKS = ["local", "none"] as const;
export type ClientKeyFallbackSetting = (typeof CLIENT_KEY_FALLBACKS)[number];
/**
 * LANE_STACK_EJECTION values (docs/design/relay-ejection.md): `enforce` takes a relay whose VM reported a non-compliant
 * change out of routing; `record` only records it and tells the relay.
 */
export const LANE_STACK_EJECTION_MODES = ["enforce", "record"] as const;
export type LaneStackEjectionMode = (typeof LANE_STACK_EJECTION_MODES)[number];
export const LANE_STACK_RELEASE_MOVE_MODES = ["off", "on"] as const;
export type LaneStackReleaseMoveMode = (typeof LANE_STACK_RELEASE_MOVE_MODES)[number];
/** ALERT_PAGING values: whether gray-alerts sends its pages (workers/alerts/src/paging.ts). */
export const ALERT_PAGING_MODES = ["on", "off"] as const;
export type AlertPaging = (typeof ALERT_PAGING_MODES)[number];
/**
 * TRANSLATION_FALLBACK values: the server's GRAY_TRANSLATION_FALLBACK (crates/gray-gateway/src/translation/mod.rs
 * `Fallback`), @gray/translation `Fallback`.
 */
export const TRANSLATION_FALLBACKS = ["open_ai_responses", "off"] as const;
export type TranslationFallback = (typeof TRANSLATION_FALLBACKS)[number];
/**
 * translation/mod.rs `FALLBACK_RULE` without the variable's name, which each side puts before it (the server's
 * "GRAY_TRANSLATION_FALLBACK must be open_ai_responses or off", here `ConfigError`'s "TRANSLATION_FALLBACK: ...").
 */
export const TRANSLATION_FALLBACK_RULE = "must be open_ai_responses or off";
/** ERROR_TEXT_FALLBACK values: the server's GRAY_ERROR_TEXT_FALLBACK (crates/gray-gateway/src/config/requests.rs), @gray/errors `readRest`'s `text`. */
export const ERROR_TEXT_FALLBACK_MODES = ["on", "off"] as const;
export type ErrorTextFallback = (typeof ERROR_TEXT_FALLBACK_MODES)[number];
export const CHECK_CONFIRMATION_MODES = ["on", "off"] as const;
export type CheckConfirmation = (typeof CHECK_CONFIRMATION_MODES)[number];
/** ALLOW_PRIVATE_UPSTREAMS values: the server's GRAY_ALLOW_PRIVATE_UPSTREAMS, `1` on a development console. */
export const PRIVATE_UPSTREAM_SWITCHES = ["0", "1"] as const;
export type PrivateUpstreamSwitch = (typeof PRIVATE_UPSTREAM_SWITCHES)[number];
/**
 * verification.rs `CHECK_CONFIRMATION_RULE`: what the server says of any CHECK_CONFIRMATION value but unset, empty,
 * `on` and `off` (case and spaces included), in words that name no variable: each side names its own in the
 * configuration error around it (here `ConfigError`, "CHECK_CONFIRMATION: must be on or off"; the server's
 * "GRAY_CHECK_CONFIRMATION: must be on or off").
 */
export const CHECK_CONFIRMATION_RULE = "must be on or off";
/**
 * What a MODELTRACE_MODELS value but the empty string, `all` or a comma-separated list of model ids is told: the
 * server's `mixing::CHECKED_MODELS_RULE` after its "must be" (config/env.rs `expected`), without the variable's name,
 * which `ConfigError` puts before it.
 */
export const MODELTRACE_MODELS_RULE = "must be empty, all, or a comma-separated list of model ids";

/** `str::trim`'s whitespace: Rust's `char::is_whitespace` is the Unicode White_Space property. */
const rustTrimmed = (text: string): string => text.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");

/** gray-control's `valid_model_id` (@gray/control `validModelId`): what a model id may be. */
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,255}$/;

/**
 * MODELTRACE_MODELS's rule (decided 2026-10-30), the server's `mixing::CheckedModels::parse`, which @gray/modeltrace
 * `CheckedModels.parse` ports (conformance target modeltrace/checked_models, which test/modeltrace-models.test.ts holds
 * this to): blank, `all`, or a comma-separated list whose items, spaces around them trimmed, are each a model id and
 * not `all` in any case (review r4). Null when `value` follows it, else the rule. The staging and production values
 * files hold their `modeltraceModels` to it too.
 */
export function modeltraceModelsProblem(value: string): string | null {
  const text = rustTrimmed(value);
  if (text === "" || text === "all") return null;
  return text.split(",").every((item) => {
    const id = rustTrimmed(item);
    return MODEL_ID.test(id) && id.toLowerCase() !== "all";
  })
    ? null
    : MODELTRACE_MODELS_RULE;
}

/**
 * What the console says of a DEBT_MODE value but `off`: the server's `auto` included, since the Workers gateway has no
 * debt mode yet (a declared difference, accepted by the product lead 2026-10-23, item 5; an open equivalence gap,
 * docs/cloudflare-native.md 6.7).
 */
export const DEBT_MODE_RULE =
  "must be off: the Workers gateway has no debt mode yet and holds every request for the most it can cost, so the server's auto is refused " +
  "(docs/cloudflare-native.md 6.7)";

export interface SettingSpec {
  /** The Worker var. */
  readonly name: string;
  /** The property in the parsed configuration. */
  readonly key: string;
  readonly workers: readonly WorkerName[];
  /** `text`: a string the row's `textCheck` accepts (an origin, an address, a list). */
  readonly type: "int" | "enum" | "text";
  /** Absent: required. */
  readonly default?: string;
  /** Inclusive bounds of an int. */
  readonly min?: number;
  readonly max?: number;
  readonly values?: readonly string[];
  /** What an enum row says of a value not among its `values`; absent: the values it takes. */
  readonly refusal?: string;
  /** A further rule on a parsed int; returns the problem or null. */
  readonly check?: (value: number) => string | null;
  /** The rule of a text row (required for one); returns the problem or null. "" reaches it only as a default. */
  readonly textCheck?: (value: string) => string | null;
  /** Where the default and the bounds come from. Required. */
  readonly source: string;
  /**
   * The default as the server's settings table writes it, where the value is not a literal one (Rust `Setting`'s
   * `shown_default`): what an unset var means, `unset` or where the value comes from. The settings-registry replay
   * compares it with the server's default; `default` is still what a var left unset reads as.
   */
  readonly shown?: string;
  /**
   * Why this var's default or bounds are not the server's GRAY_ setting's: a platform reason, which the
   * settings-registry replay reads (conformance/README.md): it compares such a pair's description only, and holds its
   * default or bounds to still differing. Absent: the server's default and bounds.
   */
  readonly platform?: string;
  /**
   * What it does, in one line. For a var the server has too, its description of its GRAY_ setting, with each setting
   * named as the Workers name it (no `GRAY_`): one text true on both (the settings-registry replay).
   */
  readonly doc: string;
}

const powerOfTwo = (n: number): string | null => ((n & (n - 1)) === 0 ? null : `${n} is not a power of two`);

export const SETTINGS: readonly SettingSpec[] = [
  {
    name: "DEPLOY_ENV",
    key: "deployEnv",
    workers: ["gateway", "jobs", "console", "identity", "alerts", "content"],
    type: "enum",
    values: DEPLOY_ENVS,
    source: "Required, no default. Same names as workers/credit/src/lib/config.ts DEPLOY_ENVS; equals the wrangler env name.",
    doc: "Which environment this is. `local` in the local-only wrangler files.",
  },
  {
    name: "ACCOUNT_SHARD_COUNT",
    key: "accountShardCount",
    workers: ["gateway"],
    type: "int",
    default: "32",
    min: 1,
    max: 32,
    check: powerOfTwo,
    source:
      "docs/cloudflare-native/scaling.md section 5 (measured 2026-10-17): K = 32 carried 2,992 requests a second for one workspace with no errors " +
      "(m0/raw/shard-ws2k-k32-20261017.jsonl); one shard tops out near 1,060. The maximum is the largest K measured. " +
      "Powers of two only: K changes only by doubling (scaling.md section 5, on changing the shard count).",
    doc:
      "The most account shards per workspace and region. The root starts a region at one shard and doubles or halves K with load " +
      "(ACCOUNT_SHARD_TARGET_RPS) up to this; a request's shard is chosen by hashing its request key and attempt.",
  },
  {
    name: "ACCOUNT_SHARD_TARGET_RPS",
    key: "accountShardTargetRps",
    workers: ["gateway"],
    type: "int",
    default: "350",
    min: 1,
    max: 1060,
    source:
      "docs/cloudflare-native.md section 2.6: one third of the single-shard ceiling of about 1,060 requests a second measured 2026-10-17 " +
      "(m0/raw/shard-capacity-k1-gm20-20261017.jsonl). The maximum is that measured ceiling.",
    doc:
      "Requests a second per shard above which the root doubles a region's K. It halves K when the region's rate falls below a quarter of " +
      "this per shard, so the halved shards stay under half the target and a halving never triggers a doubling.",
  },
  {
    name: "SETTLE_BATCH_MS",
    key: "settleBatchMs",
    workers: ["gateway"],
    type: "int",
    default: "20",
    min: 0,
    max: 100,
    source:
      "docs/cloudflare-native/scaling.md section 5: the shard prototype batched settlements for 20 ms in every measured run " +
      "(shard-capacity-k1-gm20, shard-ws2k-k32, shard-crash-k8). The maximum is the 100 ms upper end of the window in section 3.",
    doc:
      "The longest a shard collects settlements before writing them as one row; the final frame waits for the write. A shard that expects " +
      "less than one more settlement within the window writes at once, since waiting would gather nothing (scaling.md section 5, change 5).",
  },
  {
    name: "ACCOUNT_ALLOWANCE_SECONDS",
    key: "accountAllowanceSeconds",
    workers: ["gateway"],
    type: "int",
    default: "10",
    min: 1,
    max: 60,
    source:
      "docs/cloudflare-native.md section 2.6: a grant covers about 10 s of the shard's recent use, so the root sees about K / 10 grants a " +
      "second; with K = 32 the root took 4.6 calls a second (scaling.md section 5, shard-ws2k-k32). Active shards check in every " +
      "ACCOUNT_VERSION_CHECK_MS anyway, so grants sized past a minute only lock more of the balance in one shard.",
    doc: "How many seconds of a shard's recent spending one grant from the root covers.",
  },
  {
    name: "ACCOUNT_ALLOWANCE_MIN_MICROUSD",
    key: "accountAllowanceMinMicroUsd",
    workers: ["gateway"],
    type: "int",
    default: "2000000",
    min: 1,
    max: 100000000,
    source:
      "The prototype's fixed refill of 2,000,000 micro-USD (docs/cloudflare-native/m0/shard-proto/src/index.ts:85), with which almost no " +
      "request waited on the root in the measured runs (scaling.md section 5). The maximum is $100, the most a single request may cost " +
      "(docs/holds-debt-mode.md 3.1, K).",
    doc: "The smallest grant a shard asks for, so a shard with little history does not go to the root for every request.",
  },
  {
    name: "ACCOUNT_LOW_WATER_PERCENT",
    key: "accountLowWaterPercent",
    workers: ["gateway"],
    type: "int",
    default: "25",
    min: 0,
    max: 100,
    source:
      "docs/cloudflare-native.md section 2.6 and the prototype, which refilled below a quarter of its grant " +
      "(docs/cloudflare-native/m0/shard-proto/src/index.ts:167); in the measured runs almost no request waited on the root.",
    doc:
      "A shard asks the root for more, in the background, when what it has left falls below this percentage of one grant. 0: only when a hold does not fit.",
  },
  {
    name: "ACCOUNT_IDLE_RETURN_MS",
    key: "accountIdleReturnMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 2000,
    max: 600000,
    source:
      "docs/cloudflare-native.md section 2.6: 30 s without a call (open holds keep what they hold), not much longer than the 10 s after which a " +
      "hibernatable object may be evicted (C19), long enough not to grant and return in a loop. The minimum is the 2 s first retry of a " +
      "failed alarm (C22); the maximum, 10 minutes, keeps an idle shard's allowance from sitting out most of a stream's hour.",
    doc:
      "After this long without a call a shard hands its unused allowance back to the root, all but a standing allowance it keeps for the " +
      "first request after the pause (ACCOUNT_STANDING_RETURN_MS). K changes no faster than this, so at most two generations of shards hold " +
      "allowance at once.",
  },
  {
    name: "ACCOUNT_STANDING_RETURN_MS",
    key: "accountStandingReturnMs",
    workers: ["gateway"],
    type: "int",
    default: "3600000",
    min: 2000,
    max: 3600000,
    source:
      "The 90th percentile of the measured human think time between turns, 3,070 s (perf-agent-load/model/wm2/workload_spec_v2.json " +
      "session_process.tables.think: p50 186 s, p75 716 s, p90 3,070 s, measured over 548 active Claude Code hours on one machine; branch " +
      "perf/agent-load-20261015), rounded up to the hour, which is also the longest stream (STREAM_TOTAL_SECONDS): nine of ten turns that " +
      "start after a pause find the standing allowance and need no call to the root, which may be a region away (174-229 ms, " +
      "m0/raw/dolat-online-20261017.jsonl), and a shard stays warm through any request it serves; the owner's decision of 2026-10-29 " +
      "(docs/request-path-availability.md M2, keep-warm). It was the 75th percentile, 12 minutes: one turn in four after a pause waited on " +
      "the root. Maximum: the hour; longer only keeps money from the workspace's other shards. At least ACCOUNT_IDLE_RETURN_MS and at " +
      "most ACCOUNT_LEASE_MS (cross checks).",
    doc:
      "How long an idle shard keeps its standing allowance: in each pool the most it had out at once in that time (a burst of requests " +
      "together, not only the largest one), and of a key's requests per minute its largest minute. After this long without a call it hands " +
      "that back too.",
  },
  {
    name: "ACCOUNT_VERSION_CHECK_MS",
    key: "accountVersionCheckMs",
    workers: ["gateway"],
    type: "int",
    default: "2000",
    min: 250,
    max: 60000,
    source:
      "The server refreshes its key snapshot every 2 s (crates/gray-gateway/src/background.rs:67), so a revocation takes effect within 2 s " +
      "(docs/cloudflare-native.md section 4.1). Minimum: 32 shards checking every 250 ms make 128 root calls a second, an eighth of the " +
      "1,000 a second one object takes (C20). Maximum: 60 s, the server's REFRESH_TTL (crates/gray-gateway/src/inference.rs:118-120), the " +
      "longest the server serves a key snapshot it could not refresh.",
    doc:
      "An active shard asks the root for the key list's version this often, in the background; the root also pushes every change to active shards.",
  },
  {
    name: "ACCOUNT_LEASE_MS",
    key: "accountLeaseMs",
    workers: ["gateway"],
    type: "int",
    default: "3600000",
    min: 2000,
    max: 3600000,
    source:
      "ACCOUNT_STANDING_RETURN_MS, an hour (the measured 90th percentile think time; a cross check keeps the lease at least that): a shard " +
      "that wakes within its standing period admits without a call to the root only while its lease runs, so a lease as long as the " +
      "standing period needs no renewal calls while the shard is idle (docs/request-path-availability.md M2). It was 15 minutes, the " +
      "standing period's 12 rounded up. A change the root makes is pushed to every shard whose lease may still run (root.ts `broadcast`), " +
      "and the owner gave the snapshot hours on 2026-10-18 (CONFIG_MAX_AGE_MS). " +
      "Revocations do not wait on it: while the root does not answer, keys are refused after ACCOUNT_KEY_LIST_MAX_AGE_MS. Minimum: the " +
      "server's 2 s refresh (crates/gray-gateway/src/background.rs:67). Maximum: an hour, the longest stream (STREAM_TOTAL_SECONDS).",
    doc:
      "How long a shard may admit from the allowance it holds, by the key list the root last confirmed, without hearing from the root. " +
      "While the root does not answer, a shard admits until its allowance runs out or this lease expires, then refuses (`unavailable`); " +
      "an admit under a key stops earlier, at ACCOUNT_KEY_LIST_MAX_AGE_MS. The root pushes every change to each shard whose lease may still run.",
  },
  {
    name: "ACCOUNT_KEY_LIST_MAX_AGE_MS",
    key: "accountKeyListMaxAgeMs",
    workers: ["gateway"],
    type: "int",
    default: "60000",
    min: 2000,
    max: 3600000,
    source:
      "The server's REFRESH_TTL = 60 s (crates/gray-gateway/src/inference.rs:118-120): it refuses every request once its key snapshot could " +
      "not be refreshed for a minute (inference.rs:1640-1650), so a revocation the server cannot read waits at most that long. Whether to " +
      "serve longer on the last confirmed list was docs/cloudflare-native.md section 12 item 9; the owner's answer of 2026-10-18 (hours) is " +
      "for PostgreSQL and Hyperdrive, while the roots answer and revocations reach the shards, so this stays. The owner may raise it up to " +
      "ACCOUNT_LEASE_MS (a cross check). Minimum: the server's 2 s refresh (crates/gray-gateway/src/background.rs:67).",
    doc:
      "After a call to the root failed, a shard refuses (`unavailable`) admits under a key once the key list was last confirmed longer ago " +
      "than this, since a revocation may be waiting at the root. An idle shard that wakes asks the root in the background and admits meanwhile: " +
      "the root pushes every change to it, so its list is current unless a push and that check both fail.",
  },
  {
    name: "ACCOUNT_CLIENT_KEY_FALLBACK",
    key: "accountClientKeyFallback",
    workers: ["gateway"],
    type: "enum",
    values: CLIENT_KEY_FALLBACKS,
    default: "local",
    source:
      "docs/cloudflare-native.md 2.3 and the owner's rule of 2026-10-17: no single point on the request path. A request under a client's " +
      "Idempotency-Key is pinned to one shard of the home region (workers/packages/account/README.md); `local` lets it fall back, " +
      "degraded, to the region it came in when that shard fails or answers `unavailable`, so one shard or the home region is no single " +
      "point. `none` keeps it on the one shard and refuses instead: exactly-once admission over availability, the owner's to choose.",
    doc:
      "Where a request under a client's key goes when its home shard cannot admit it: `local`, the attempt's shard of the region it came " +
      "in, as a key the gateway made up (a repeat there is caught only by the projection, as in wave 1); `none`, nowhere (`unavailable`).",
  },
  {
    name: "ACCOUNT_LIMIT_GRANT_PERCENT",
    key: "accountLimitGrantPercent",
    workers: ["gateway"],
    type: "int",
    default: "10",
    min: 5,
    max: 100,
    source:
      "Measured 2026-10-17 with workers/packages/account/test/workerd/limits.test.ts (workerd, test clock; rerun by setting this var in " +
      "test/workerd/wrangler.jsonc): a key of 300 a minute over 8 shards at twice the limit for 3 minutes, admits that waited for the root " +
      "out of 900 / units left at a shard the root could not recall (limit 40, the error below the limit): 1% 321 / 12, 5% 99 / 13, " +
      "10% 98 / 15, 25% 116 / 20, 50% 207 / 23, 75% 268 / 30, 100% 354 / 30. At half the limit every value waited 8 times of 450, and the " +
      "spend budget was used up exactly. 10% is the fewest waits; at 1% a grant is one unit and waits triple, hence the minimum 5. " +
      "One machine, synthetic traffic: recheck with real traffic.",
    doc:
      "Of a key's limit (requests per minute, spend budget) left beyond what waiting admits need, the most one grant to a shard gives. " +
      "Lower keeps more for the next shard that asks; higher makes fewer shards ask again.",
  },
  {
    name: "ACCOUNT_HOLD_MARGIN_MS",
    key: "accountHoldMarginMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 5000,
    max: 120000,
    source:
      "After the response or a disconnect a Worker keeps working at most 30 s (C3, developers.cloudflare.com/workers/runtime-apis/context/; " +
      "measured in m0/disconnect.md, E1): a gateway settles or releases at the latest that long after its stream ends. It must also cover " +
      "the gateway's settlement retries, which take up to ACCOUNT_ADMIT_BUDGET_MS (a cross check); the minimum, 5 s, is above that " +
      "budget's 3 s default. Above four times C3 a margin only delays the return of a crashed shard's allowance.",
    doc:
      "A hold token lives STREAM_TOTAL_SECONDS plus this. A restarted shard returns the allowance of its lost holds (in doubt) the token " +
      "lifetime plus this after the restart (scaling.md section 5, change 2).",
  },
  {
    name: "ACCOUNT_REPLAY_CACHE_MS",
    key: "accountReplayCacheMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 1000,
    max: 60000,
    source:
      "C3: after its client leaves a gateway keeps working on a request at most 30 s, so the retries of a settlement arrive within that; " +
      "later replays are answered from the stored batches. Maximum: an object resets without an error past about 130-180 MB " +
      "(m0/memory.md, E2/E8); at the measured 1,060 requests a second per shard (scaling.md section 5) a minute is about 64,000 records. " +
      "One closed hold kept in the shard's three maps (by hold, by request key, decision) took 384-504 bytes of V8 heap, measured " +
      "2026-10-17 with node --expose-gc on 200,000 records with 64-character request keys and evidence hashes (Node 26.10, V8 as in " +
      "workerd): about 32 MB for a minute.",
    doc:
      "How long a shard keeps closed holds in memory to answer a repeated settlement with the first result; a restarted shard rebuilds this window from its batches.",
  },
  {
    name: "ACCOUNT_SHARD_FLOOR_MICROUSD",
    key: "accountShardFloorMicroUsd",
    workers: ["gateway"],
    type: "int",
    default: "100000000",
    min: 1,
    max: 100000000,
    source:
      "$100, the most a single request may cost (docs/holds-debt-mode.md 3.1, K: at most the contract's per-entry cap). With less than this " +
      "per shard of the workspace's money left, one shard could not hold the largest request while K shards each hold a fragment " +
      "(scaling.md section 5, on fragments of the allowance). Above $100 no single request needs more.",
    doc:
      "The root keeps a region at most (money left / this) shards, rounded down to a power of two and at least one, so a low balance is not split into fragments.",
  },
  {
    name: "ACCOUNT_ROOT_CALL_TIMEOUT_MS",
    key: "accountRootCallTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "3000",
    min: 100,
    max: 30000,
    source:
      "Staging soak r4 (2026-10-29), the account roots' own wall time for the 29,904 calls of its two runs (Workers Logs, AccountDO jsrpc; " +
      "an apac root, its shards in apac and wnam): median 106 and 143 ms, p99 267 and 326 ms, p99.9 747 and 399 ms, longest 3,056 and 2,724 ms " +
      "at about 0 ms of CPU; 14 calls took over 1 s, 3 over 2 s, 1 over 3 s. With the earlier 1 s the wnam shard gave up on 16 of them " +
      "(root_exchange_failed), and each turned the admits waiting on it into 503s. Cloudflare sets no limit of its own: a Durable Object call " +
      "runs as long as its caller stays connected (developers.cloudflare.com/durable-objects/platform/limits, wall time by invocation type, " +
      "read 2026-10-29), so this is the only bound. Default: the admission budget's (ACCOUNT_ADMIT_BUDGET_MS): a call serves every admit " +
      "that waits for it, the gateway's next attempt on the same shard too (each admit waits only its own ACCOUNT_ADMIT_ATTEMPT_MS); past " +
      "the budget none of them is left, and a call that hangs longer only keeps the next ones from asking afresh (a cross check). It covers " +
      "all but 1 in 29,904 measured calls. The minimum is 20 times the 2-5 ms of a same-region call; the maximum the budget's. The root " +
      "waits half of it for the shards it recalls allowance from, so it still answers in time, and as long for a shard when it reads the " +
      "customer's balance: a workspace's first such read, the root's first call to that shard, took 668 ms and 703 ms in production " +
      "(2026-10-23, new-customer run 8: Singapore to Hong Kong), later ones 85-92 ms.",
    doc:
      "How long a shard waits for the root before it gives up on that call (the call may still land; the next exchange settles the totals); " +
      "an admit waiting for it gives up at its own wait, and the call goes on for the next. As long for another shard of its region (a " +
      "client key's claim and arbitration during a change of K). How long the root waits for a shard when it reads the customer's balance " +
      "(a shard that did not answer is asked once more), and half of it for a shard it recalls allowance from.",
  },
  {
    name: "ACCOUNT_ADMIT_ATTEMPT_MS",
    key: "accountAdmitAttemptMs",
    workers: ["gateway"],
    type: "int",
    default: "1500",
    min: 100,
    max: 3000,
    source:
      "Today's per-attempt admission timeout GRAY_CREDIT_ADMIT_ATTEMPT_MS = 1500 (deploy/runtime/compose.production.yaml:101). The maximum " +
      "is the admission budget's default (ACCOUNT_ADMIT_BUDGET_MS).",
    doc:
      "How long the gateway waits for one admit. A failed or slow attempt goes to the shard of the next attempt number (scaling.md section 5, change 4).",
  },
  {
    name: "ACCOUNT_ADMIT_BUDGET_MS",
    key: "accountAdmitBudgetMs",
    workers: ["gateway"],
    type: "int",
    default: "3000",
    min: 100,
    max: 30000,
    source:
      "Today's admission budget GRAY_CREDIT_ADMIT_BUDGET_MS = 3000 (deploy/runtime/compose.production.yaml:102). The maximum is the 30 s a " +
      "streamed response may wait for an upstream before Gray sends its headers (crates/gray-gateway/src/config/mod.rs:189, stream_headers).",
    doc: "How long the gateway keeps trying admits for one request before it answers that credit is unavailable.",
  },
  {
    name: "REQUEST_PRE_BUDGET_MS",
    key: "requestPreBudgetMs",
    workers: ["gateway"],
    type: "int",
    default: "3000",
    min: 100,
    max: 30000,
    source:
      "The longest single cross-region root call measured, 3,056 ms (staging soak r4, ACCOUNT_ROOT_CALL_TIMEOUT_MS's source), and the " +
      "server's production admission budget GRAY_CREDIT_ADMIT_BUDGET_MS = 3000 (deploy/runtime/compose.production.yaml:108): one far call " +
      "fits, two do not (docs/request-path-availability.md section 3.3). The maximum is ACCOUNT_ADMIT_BUDGET_MS's: the 30 s a streamed " +
      "response may wait before Gray sends its headers.",
    doc:
      "How long a request may wait on Gray's own dependencies before its first upstream byte, the client's own upload excluded " +
      "(docs/request-path-availability.md section 3.3, M1).",
  },
  {
    name: "REQUEST_POST_BUDGET_MS",
    key: "requestPostBudgetMs",
    workers: ["gateway"],
    type: "int",
    default: "3000",
    min: 100,
    max: 30000,
    source:
      "The longest single cross-region root call measured, 3,056 ms (staging soak r4, ACCOUNT_ROOT_CALL_TIMEOUT_MS's source), and the " +
      "server's production admission budget GRAY_CREDIT_ADMIT_BUDGET_MS = 3000 (deploy/runtime/compose.production.yaml:108): one far call " +
      "fits, two do not (docs/request-path-availability.md section 3.3). The maximum is ACCOUNT_ADMIT_BUDGET_MS's: the 30 s a streamed " +
      "response may wait before Gray sends its headers.",
    doc:
      "How long a request may wait on Gray's own dependencies between the last upstream byte and the final frame " +
      "(docs/request-path-availability.md section 3.3, M1).",
  },
  {
    name: "ANSWER_MARGIN_MS",
    key: "answerMarginMs",
    workers: ["gateway"],
    type: "int",
    default: "100",
    min: 10,
    max: 3000,
    source:
      "A Durable Object call in one region takes 2-5 ms (docs/cloudflare-native/scaling.md section 1): the default is 20 times the slowest, " +
      "so a shard's answer reaches a gateway in its region before the gateway's own timer. Minimum: twice the slowest, the call's way there " +
      "and its answer's way back. Maximum: ACCOUNT_ADMIT_ATTEMPT_MS's maximum; it must also stay below ACCOUNT_ADMIT_ATTEMPT_MS (a check).",
    doc:
      "How long before the gateway stops waiting for an admit or a count an account shard that is still waiting on its root answers " +
      "unavailable: the gateway then reads an answer, not a silence, and may try the same shard again, joining its root call " +
      "(docs/request-path-availability.md M4).",
  },
  {
    name: "ACCOUNT_MINUTE_CEILING_CHUNKS",
    key: "accountMinuteCeilingChunks",
    workers: ["gateway"],
    type: "int",
    default: "4",
    min: 1,
    max: 10000,
    source:
      "Four: a key at its share writes the lease row at most four times a minute for it, and a restart counts at most a quarter of the " +
      "share more than was admitted (docs/request-path-availability.md M3). Minimum: one chunk is the whole share, a restart counting the " +
      "minute as used up (the behaviour before the ceiling). Maximum: a key's largest limit, 10,000 requests a minute " +
      "(crates/gray-gateway/src/app.rs:735), beyond which every chunk is already one request.",
    doc:
      "In how many chunks an account shard writes ahead how much of a key's minute it has counted (`countedUpTo`): a shard restarted with " +
      "requests open counts the minute from that ceiling instead of as used up, so a key with share left is admitted without the root.",
  },
  {
    name: "PROJECTION_INTERVAL_MS",
    key: "projectionIntervalMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 100,
    max: 60000,
    source:
      "docs/cloudflare-native/m0/account.md section 3: variants A-C sent their projection within 1 s, D-F once a minute (the maximum); " +
      "section 5.3 wants PostgreSQL a few seconds behind. One send an interval keeps a busy shard at one watermark write a second.",
    doc: "How often a shard hands its new settlement batches to the projection queue.",
  },
  {
    name: "PROJECTION_RETRY_MAX_MS",
    key: "projectionRetryMaxMs",
    workers: ["gateway"],
    type: "int",
    default: "60000",
    min: 100,
    max: 600000,
    source:
      "Not a measurement of a failing queue: m0 variants D-F projected once a minute by design and reconciled line by line " +
      "(docs/cloudflare-native/m0/account.md section 3), so a back-off capped at a minute keeps a failing queue's retries at least as " +
      "frequent as a projection interval known to work. The maximum, 10 minutes, is a sixth of the hour whose round closes only below " +
      "every shard's watermark (docs/cloudflare-native.md 5.4); a longer gap would hold that close for a large part of the hour. It is at " +
      "least PROJECTION_INTERVAL_MS (a cross check).",
    doc: "After a failed send to the projection queue a shard waits PROJECTION_INTERVAL_MS doubling with each failure, at most this long.",
  },
  {
    name: "ENDPOINT_ROOT_LOCATION_HINT",
    key: "endpointRootLocationHint",
    // Every caller passes it, so the first call places the root here whoever makes it (C51): the
    // gateway's endpoint shards (reports, borrows, probe leases), the console (configure, withdraw,
    // health) and the jobs.
    workers: ["gateway", "jobs", "console"],
    type: "enum",
    values: LOCATION_HINTS,
    default: "wnam",
    source:
      "The database's region, DEFAULT_HOME_REGION = wnam (region.ts): a root is reached on the request path only when a shard holds no " +
      "permit for an acquire (a borrow) or a probe lease is claimed, and the console that configures it runs next to the database in " +
      "western North America (placement aws:us-west-1). Measured 2026-10-22 on staging: roots created without a hint sat in Hong Kong, " +
      "161 ms from SJC; a wnam root is 2-3 ms from SJC and 105 ms from NRT (gateway.md section 14).",
    doc:
      "Where every EndpointRootDO is created (a location hint; an object never moves). One root per capacity key; its shards are in every " +
      "region. A region's shard that holds no permit waits for one round trip to the root on an acquire (at most ENDPOINT_ROOT_CALL_TIMEOUT_MS).",
  },
  {
    name: "STREAM_TOTAL_SECONDS",
    key: "streamTotalSeconds",
    workers: ["gateway"],
    type: "int",
    default: "3600",
    min: 1,
    max: 3600,
    source:
      "Today's server default (GRAY_STREAM_TOTAL_SECONDS, crates/gray-gateway/src/config/mod.rs:187). Not raised: Cloudflare runtime updates give a request " +
      "at most 20 minutes (C1, C18 in docs/cloudflare-native.md section 5.6); whether to lower it is item 4 of section 12.",
    platform:
      "At most its default, an hour, where the server's bound is its clock's far future (30 years): Cloudflare cuts a Worker's request on its own " +
      "runtime updates (docs/cloudflare-native.md section 5.6, C1 and C18), so a longer bound is not offered.",
    doc: "The longest a streamed request may run, from the end of its body",
  },
  // The request path of gray-gateway (workers/gateway/src/inference.ts). The server values cited are
  // crates/gray-gateway/src/config/mod.rs Timeouts::default (lines 123-197) unless a row says otherwise.
  // A client that disconnects ends the upstream at once (the owner's decision of 2026-10-17,
  // docs/cloudflare-native.md 5.6), so no var keeps reading an upstream after its client left.
  {
    name: "BODY_PARSE_MAX_BYTES",
    key: "bodyParseMaxBytes",
    workers: ["gateway"],
    type: "int",
    default: "4194304",
    min: 1048576,
    max: 16777216,
    source:
      "docs/cloudflare-native.md section 3 (tier A up to 4 MiB) and m0/memory.md (measured 2026-10-17): a parsed 4 MB body takes about 5-5.5 MB, " +
      "1.25-1.36 times its bytes, and an isolate reset after 33-36 parsed 4 MB bodies. Maximum 16 MiB: a parsed body of about 22 MB, a sixth of " +
      "the 128 MB isolate limit (C1). Minimum 1 MiB: smaller would send most agent bodies to tier B (p90 3.59 MB, docs/limits.md:107).",
    doc:
      "Tier A: a body up to this many bytes is parsed whole (every feature, translation included). Above it the body is tier B (raw bytes, " +
      "top-level fields read from the bytes, native routes only). Also the most of a translated non-streaming answer the gateway reads: " +
      "the translation needs the whole document, so a longer one is refused with 502 upstream_body_limit (limit_source gateway_memory, " +
      "not charged). To be set from E2.",
  },
  {
    name: "BODY_RAW_MAX_BYTES",
    key: "bodyRawMaxBytes",
    workers: ["gateway"],
    type: "int",
    default: "25165824",
    min: 1048576,
    max: 67108864,
    source:
      "docs/cloudflare-native.md section 3 (tier B 4-24 MiB, default pending E2). m0/memory.md: raw bytes reached about 180 MB in one isolate " +
      "before it reset; the maximum, 64 MiB, keeps one request's raw body at a third of that.",
    doc:
      "Tier B ends here: a body up to this many bytes is held as raw bytes; a larger one (tier C) is spooled to R2 as it arrives and sent " +
      "upstream from there. Every API's own limit still applies (@gray/limits requestLimit). The longest single value (string or number) " +
      "of a tier C body is held whole while its layout is read, so a tier C body with a longer one is refused with 413 (limit_source gateway_memory).",
  },
  {
    name: "AFFINITY_ENTRIES_PER_WORKSPACE",
    key: "affinityEntriesPerWorkspace",
    workers: ["gateway"],
    type: "int",
    default: "128",
    min: 1,
    max: 512,
    source:
      "The isolate's cache affinity map (gateway preference.ts `isolateAffinity`) frees entries only when a workspace's shard or the map is " +
      "full, so it grows to its bounds over an isolate's life. Measured by the release 4 routing-preference check (Node on the 5090 box, " +
      "2026-10-23, 64-hex keys): about 200 bytes an entry, 100 workspaces of 512 entries 10 MiB, 4,096 of them 409 MiB, past the isolate's " +
      "128 MB (C1). With AFFINITY_WORKSPACES the default holds 40,960 entries, about 8 MB. Maximum: the server's own bound (routing.rs " +
      "`Affinity::default`, 512); the two together are bounded by a cross check. An Anthropic turn writes at most four entries " +
      "(ANTHROPIC_MAX_BREAKPOINTS), so 128 hold the latest 32 conversations or more of a workspace in one isolate for their five minutes.",
    doc: "The most cache affinity entries the gateway's isolate keeps for one workspace; past it the entry closest to expiry goes.",
  },
  {
    name: "AFFINITY_WORKSPACES",
    key: "affinityWorkspaces",
    workers: ["gateway"],
    type: "int",
    default: "320",
    min: 1,
    max: 4096,
    source:
      "AFFINITY_ENTRIES_PER_WORKSPACE source: 320 workspaces of 128 entries are about 8 MB of the isolate's 128 MB. Maximum: the server's own " +
      "bound (routing.rs `Affinity::default`, 4096).",
    doc: "The most workspaces the gateway's isolate keeps cache affinity entries for; a new one waits until a workspace's entries all expired.",
  },
  {
    name: "ANSWER_HELD_MAX_BYTES",
    key: "answerHeldMaxBytes",
    workers: ["gateway"],
    type: "int",
    default: "67108864",
    min: 1048576,
    max: 67108864,
    source:
      "docs/limits.md section 4 and its answer examples (sources read 2026-10-15): a 128,000-token answer, the largest output of the reference " +
      "catalog's agent models (Claude Sonnet 5.5, GPT-5.5), takes at most 48.8 MB in Chat Completions, the largest of the generation APIs " +
      "(Responses 37.4 MB, Messages 18.3 MB; Claude Code's own 64,000 tokens 9.15 MB). m0/memory.md (measured 2026-10-17): raw bytes reached " +
      "about 180 MB in one isolate before it reset; 64 MiB keeps one held answer at a third of that, as BODY_RAW_MAX_BYTES' maximum keeps a body, " +
      "and the answers held in one isolate together at the same third (workers/gateway/src/retained.ts AnswerPool). " +
      "Minimum 1 MiB: an answer of about 2,700 tokens in Chat.",
    doc:
      "The most of one answer the gateway holds in memory: the frames a gated or translated stream holds back, one SSE frame of any stream, " +
      "and what a non-streaming answer keeps while it passes (its bytes not yet sent, tool calls being checked, the value being read and its " +
      "projection, each with its measured factor, and the projection's nodes at their measured heap bytes, workers/gateway/src/answer.ts). " +
      "A non-streaming answer past it fails with 502 upstream_body_limit, not charged. It also bounds the sum over the answers in flight in one " +
      "isolate, each counted as its own bound counts it: an answer that grows past the sum fails with 429 gateway_capacity before it started " +
      "(a cut body, or a stream's error event, after), not charged and not the endpoint's fault. Nothing of an answer is sized at admission, " +
      "whatever the request's output limit: a stream's held frames and its frames are counted as they arrive, and past this the stream ends " +
      "with upstream_stream_limit or upstream_frame_limit, free.",
  },
  {
    name: "ANSWER_PRIME_BYTES",
    key: "answerPrimeBytes",
    workers: ["gateway"],
    type: "int",
    default: "24384",
    min: 0,
    max: 16777216,
    source:
      "CLIENT_QUEUE_BYTES (workers/gateway/src/client.ts): the server's 64 steps (CLIENT_FRAMES) of the largest token event of any generation " +
      "API (381 bytes, Chat), 64 x 381 = 24,384 bytes. Before a non-streaming answer starts to go out these bytes wait where the client's " +
      "queue waits after, and the two never exist at once. Maximum: BODY_PARSE_MAX_BYTES (cross check), the most of one document the gateway " +
      "holds whole (m0/memory.md); the row's own maximum is that var's. 0 sends from the first byte that may go.",
    doc:
      "A non-streaming answer is held until more than this many of its bytes may go out, or until it ends. Until then it behaves as before: " +
      "an answer that fails, or a 2xx error body, gets the JSON error with its status, and a whole answer is sent with Content-Length. Past " +
      "it the response starts (200, no Content-Length): the rest follows as it arrives, the closing brace last, after the checks and the " +
      "charge; a later failure ends the body without it (not charged), and a later retry is impossible.",
  },
  {
    name: "USAGE_MISSING",
    key: "usageMissing",
    workers: ["gateway"],
    type: "enum",
    values: USAGE_MISSING_RULES,
    default: "free",
    source:
      "The owner's decision of 2026-10-16 and release 2's GRAY_USAGE_MISSING (default free; the yylx relay bills such turns at $0): an " +
      "answer without usage is delivered and charged nothing. release 2's third value, estimate, is not ported.",
    doc:
      "What becomes of an answer whose provider did not report its usage (no usage object, or one without a counter Gray bills on): free delivers " +
      "it as it came, charges nothing, repeats nothing and pays its supplier nothing (the owner's decision of 2026-10-16); refuse fails the attempt " +
      "with upstream_usage_missing, uncharged (docs/api-errors.md)",
  },
  {
    name: "TRANSLATION_FALLBACK",
    key: "translationFallback",
    workers: ["gateway"],
    type: "enum",
    values: TRANSLATION_FALLBACKS,
    default: "open_ai_responses",
    refusal: TRANSLATION_FALLBACK_RULE,
    source:
      "Release 4's GRAY_TRANSLATION_FALLBACK (crates/gray-gateway/src/translation/mod.rs `Fallback::from_env`), on by default: decision (b) " +
      "of 2026-10-23, after the yylx relay answered buffered Responses requests of gpt-6.1-sol with HTTP 500 while its Chat route served " +
      "(final-design.md B12). Unset and empty mean on, as on the server; any other value is refused at start.",
    doc:
      "The implied Responses fallback: `open_ai_responses` translates a Responses request of a model some endpoint maps on Responses, " +
      "which no live native Responses route can take because of what its verification proved, to a live Chat, Messages or Gemini route " +
      "of the same model (in that order, the first that serves it; an operator translation rule for the model replaces the list). `off` " +
      "turns it off: such a request gets the answer it gets without a translation. A request admitted before a change keeps its plan.",
  },
  {
    name: "IMAGE_USAGE_UNSPLIT",
    key: "imageUsageUnsplit",
    workers: ["gateway"],
    type: "enum",
    values: IMAGE_USAGE_UNSPLIT_POLICIES,
    default: "image_price",
    source:
      "Release 4's GRAY_IMAGE_USAGE_UNSPLIT (crates/gray-gateway/src/config/requests.rs `ImageUsageUnsplit::DEFAULT`), whose default " +
      "image_price is the owner's decision of 2026-10-20: a relay charges for the image whether its usage counts it apart or not (yylx " +
      "billed request de93ee8a, Nano Banana preview, $0.03 for 1,522 output tokens without candidatesTokensDetails, which Gray billed as " +
      "text at $0, docs/supplier-accounting.md). free is the operator's alternative.",
    doc:
      "What becomes of a Gemini answer with a generated image on a route priced by image output tokens whose usage does not count the image tokens " +
      "apart (no IMAGE entry in candidatesTokensDetails): image_price bills the visible output (candidatesTokenCount; thoughts stay text output) at " +
      "the image output price (the owner's decision of 2026-10-20); free delivers it at $0 and pays its supplier nothing; either way with the alert " +
      "image_usage_unsplit (docs/supplier-accounting.md)",
  },
  {
    name: "REQUEST_BODY_MS",
    key: "requestBodyMs",
    workers: ["gateway"],
    type: "int",
    default: "600000",
    min: 1000,
    max: 600000,
    source:
      "GRAY_REQUEST_BODY_SECONDS, default 600 (config/mod.rs:174-179): Claude Code's request timeout API_TIMEOUT_MS of 600,000 ms, the longest " +
      "of the documented agent clients, after which the client has given up.",
    doc: "How long a request body may take to arrive; past it the request ends with 408 request_body_timeout.",
  },
  {
    name: "UPSTREAM_HEADER_MS",
    key: "upstreamHeaderMs",
    workers: ["gateway"],
    type: "int",
    default: "600000",
    min: 1000,
    max: 3600000,
    source:
      "GRAY_UPSTREAM_HEADER_SECONDS, default 600 (config/mod.rs:124-134). Maximum: the longest stream, STREAM_TOTAL_SECONDS at its maximum.",
    doc:
      "How long a streamed request waits, from admission and across its attempts, for an upstream to answer with response headers. A buffered " +
      "request waits until NON_STREAM_TOTAL_MS instead, since a buffered answer sends its headers only when complete.",
  },
  {
    name: "UPSTREAM_SILENCE_MS",
    key: "upstreamSilenceMs",
    workers: ["gateway"],
    type: "int",
    default: "600000",
    min: 1000,
    max: 3600000,
    source: "GRAY_UPSTREAM_SILENCE_SECONDS, default 600 (config/mod.rs:135-138). Maximum: STREAM_TOTAL_SECONDS at its maximum.",
    doc:
      "The longest gap between two reads of an upstream body once the upstream answered. An upstream behind a Cloudflare zone is cut " +
      "sooner by that zone's Proxy Read Timeout, 125 s without a byte by default (docs/edge-load-balancing.md proxy-1, proxy-5): the " +
      "stream then ends with upstream_stream_interrupted, free, and the release says how long the upstream had been silent (staging " +
      "2026-10-18: a supplier's 220 s stall was cut at 124 s). Whether to end such a stream sooner is open (docs/limits.md, #31).",
  },
  {
    name: "NON_STREAM_TOTAL_MS",
    key: "nonStreamTotalMs",
    workers: ["gateway"],
    type: "int",
    default: "1740000",
    min: 1000,
    max: 1740000,
    source:
      "GRAY_NON_STREAM_TOTAL_SECONDS, default 1740 (config/mod.rs:142-148): a minute under the edge's longest read timeout of 1800 s, so a client " +
      "gets Gray's own error rather than the edge's. Not raised above it for the same reason.",
    doc: "The longest a buffered request may run, from the end of its body, admission included.",
  },
  {
    name: "STREAM_HEADERS_MS",
    key: "streamHeadersMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 100,
    max: 120000,
    source:
      "GRAY_STREAM_HEADERS_SECONDS, default 30 (config/mod.rs:149-151). Maximum: under the edge's default read timeout of 125 s for a silent " +
      "origin (crates/gray-gateway/src/inference.rs sse_reply).",
    doc: "A streamed response sends its headers when an upstream answers, or this long after admission if none has yet.",
  },
  {
    name: "LANE_SCHEDULER_PICK_MS",
    key: "laneSchedulerPickMs",
    workers: ["gateway"],
    type: "int",
    default: "1500",
    min: 100,
    max: 30000,
    source:
      "D109': the confidential lane's pick budget, until now @gray/relay-connector's DEFAULT_SCHEDULER_TIMINGS.pickTimeoutMs = 1500 " +
      "(packages/relay-connector/src/scheduler/client.ts). One remote call on the request path, the class of ACCOUNT_ADMIT_ATTEMPT_MS " +
      "(1500, min 100). D109'(c), measured at the maximum (D123: staging, real TDX, 2026-10-22 07:30-08:01Z, relay behind a " +
      "trycloudflare quick tunnel): 48 picks, bridge forward wall time p50 674 ms, p90 866 ms, max 987 ms, none timed out, so the " +
      "connector's 1500 stays the default. The maximum is STREAM_HEADERS_MS's default, 30000, by which a streamed answer must have sent " +
      "its headers.",
    doc:
      "How long the lane (the gateway in the TEE) waits for one scheduler pick, through the lane bridge to the relay's scheduler. Each " +
      "forward carries what is left of it when the TEE sends as budget_ms, and the bridge's deadline for that forward is that remainder. " +
      "Read by the lane only.",
  },
  {
    name: "LANE_ROUTE_WARM_MS",
    key: "laneRouteWarmMs",
    workers: ["gateway"],
    type: "int",
    default: "10000",
    min: 1000,
    max: 60000,
    source:
      "docs/request-path-availability.md M13, sized from staging 2026-10-30 (1.1, C9): a new endpoint's root answered its first report " +
      "4,583 ms after it was asked (wall time, 10 ms of CPU; idle 7 min 23 s since its configure), and a shard that had never served " +
      "started 0.5-1.03 s after the bridge's call. 10 s is about twice their sum. It bounds background work only, never a request. The " +
      "minimum is ENDPOINT_ROOT_CALL_TIMEOUT_MS's default (one root call); the maximum a minute, past which a root that has not answered " +
      "is a stall (C6), not a cold start.",
    doc:
      "How long the lane (the gateway in the TEE) keeps asking a route's endpoint shard in its region to hold its standing permit when " +
      "the route goes live (its boot, a new route, a relay's credentials) or its last warm is half a standing return old: one bridge " +
      "endpoint.warm call per root-call timeout until the shard holds a permit. Read by the lane only.",
  },
  {
    name: "LANE_BRIDGE_ANSWER_MARGIN_MS",
    key: "laneBridgeAnswerMarginMs",
    workers: ["gateway"],
    type: "int",
    default: "250",
    min: 0,
    max: 3000,
    source:
      "docs/request-path-availability.md M14, staging 2026-10-30 15:37 (the lane's first request after its boot; Workers Logs traces " +
      "of its bridge calls): the bridge's own work after the object answered took 28, 112 and 124 ms, and the lane's request reached the " +
      "bridge at most 73 ms after it began, the lane's own work included. 250 ms is their largest sum (197 ms) with a quarter more. The " +
      "maximum is ACCOUNT_ADMIT_ATTEMPT_MS's maximum; it must also stay below ACCOUNT_ADMIT_ATTEMPT_MS (a check).",
    doc:
      "How much of an admission attempt's wait the lane keeps for the way back from the bridge: it tells the bridge the attempt's wait " +
      "less this margin (`wait_ms`), the bridge takes off its own time before it calls the account shard, and the shard answers by what " +
      "is left (ANSWER_MARGIN_MS before it), so its answer, `unavailable` included, reaches the lane before the lane's own timer. Read by " +
      "the lane only.",
  },
  {
    name: "LANE_STACK_POLL_MS",
    key: "laneStackPollMs",
    workers: ["gateway"],
    type: "int",
    default: "5000",
    min: 1000,
    max: 60000,
    source:
      "S21.2: a relay stack's container polls the entry's GET /v1/relay/config/version every 5 s, and the entry's refreshes ride on those " +
      "polls (workerd runs nothing between requests), so a shorter interval tells the relay nothing sooner. Maximum: " +
      "LANE_STACK_PROXY_CHECK_EXPIRY_MS's default (120 s) less egress's 60 s cap on a proxied connect (proxyConnectCap, " +
      "deploy/tee/egress/server.go): a proxy check picked up one interval after it was queued still answers before it expires. Minimum: " +
      "one bridge round (stack.config, snapshot.current, stack.proxy_checks) per second per VM at most [estimated].",
    doc:
      "How often a relay-stack lane asks the bridge for its relay's configuration (stack.config with the version it has) and for pending " +
      "proxy checks (stack.proxy_checks), and how often it pushes an unchanged account table to egress again; also the timeout of one " +
      "push. At most once per interval, on the relay's polls, intake and client requests. Read by the lane in the relay-stack layout only.",
  },
  {
    name: "LANE_STACK_REPORT_MIN_MS",
    key: "laneStackReportMinMs",
    workers: ["gateway"],
    type: "int",
    default: "15000",
    min: 1000,
    max: 60000,
    source:
      "S42 (docs/confidential-lane-supply-implementation.md section 9a): 15 s is the fastest refresh of the panel that reads the report, " +
      "sub2api's ops dashboard. The minimum is LANE_STACK_POLL_MS's minimum, the lane's refresh step that builds the report; the maximum is " +
      "LANE_STACK_REPORT_HEARTBEAT_MS's default, by which a report is sent changed or not [estimated].",
    doc:
      "The shortest interval between two stack.report calls of a relay-stack lane that carry a change of its VM's state (accounts served, " +
      "paused or excluded, sealed credentials, cooling, windows). Read by the lane in the relay-stack layout only.",
  },
  {
    name: "LANE_STACK_REPORT_HEARTBEAT_MS",
    key: "laneStackReportHeartbeatMs",
    workers: ["gateway"],
    type: "int",
    default: "60000",
    min: 15000,
    max: 180000,
    source:
      "S42: the panel's \"as of\" names the report's age; a report a minute old at most, whether anything changed. The minimum is " +
      "LANE_STACK_REPORT_MIN_MS's default; the maximum is the age past which the panel says \"as of\" (3 min, S46), so a lane at its maximum " +
      "still keeps a quiet relay's panel current [estimated].",
    doc:
      "How often a relay-stack lane sends stack.report when nothing changed. Read by the lane in the relay-stack layout only.",
  },
  {
    name: "PEER_PROBE_MS",
    key: "peerProbeMs",
    workers: ["gateway"],
    type: "int",
    default: "15000",
    min: 1000,
    max: 60000,
    source:
      "docs/confidential-lane-stack-routing.md sections 4.3 and 4.4 (PR 5): a pinned peer's /healthz every 15 s finds a reboot (a new " +
      "SPKI, peer_pin_mismatch) before a request does. Egress keeps an idle peer connection 3 s (-peer-idle-timeout, under workerd's 5 s), " +
      "so 15 s keeps none warm; keeping one warm needs a probe under 3 s per peer to save a new connection's cost (X1, " +
      "deploy/tee/probe/routing-measure/README.md, 2026-10-31: a new connection p50 89 ms, p99 130 ms in region), which X1 on staging " +
      "decides. The minimum, 1 s, allows that (a warm probe took about 5 ms, X1); the maximum is PEER_DOWN_MAX_MS's default, a minute: a " +
      "reboot the probe has not seen yet waits no longer than a down peer's longest rest [estimated].",
    doc:
      "How often an entry asks each pinned stack VM's /healthz through the peer hop, which finds a reboot (a new TLS key) before a " +
      "request does. Read by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "PEER_DOWN_MS",
    key: "peerDownMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 200,
    max: 10000,
    source:
      "docs/confidential-lane-stack-routing.md section 4.7, row 1: a dial that sent nothing rests the peer 1 s, doubling to " +
      "PEER_DOWN_MAX_MS. The minimum is egress's -peer-connect-timeout minimum, 200 ms (deploy/tee/egress/config.go), above X1's largest " +
      "new connection (165 ms, deploy/tee/probe/routing-measure/README.md): a sooner retry would start before a dial at that bound could " +
      "have ended. The maximum, 10 s, keeps the first rest of a transient fault short [estimated].",
    doc:
      "How long an entry rests a stack VM after a dial that sent nothing (or a list, collateral or hello it could not get), doubling " +
      "with each failure up to PEER_DOWN_MAX_MS. Read by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "PEER_DOWN_MAX_MS",
    key: "peerDownMaxMs",
    workers: ["gateway"],
    type: "int",
    default: "60000",
    min: 1000,
    max: 300000,
    source:
      "docs/confidential-lane-stack-routing.md section 4.7, row 1: the backoff doubles from PEER_DOWN_MS up to 60 s. The minimum is " +
      "PEER_DOWN_MS's default, a backoff that does not grow; it is never below PEER_DOWN_MS (a check). The maximum is PEER_RECHECK_MS's " +
      "default (5 min): a peer down for a transient fault never rests longer than a refused one (a check).",
    doc: "The longest rest of a stack VM that keeps failing, PEER_DOWN_MS doubled. Read by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "PEER_RECHECK_MS",
    key: "peerRecheckMs",
    workers: ["gateway"],
    type: "int",
    default: "300000",
    min: 60000,
    max: 1800000,
    source:
      "docs/confidential-lane-stack-routing.md section 5, rows 16 and 17 (PR 5): a refused peer is attested again after 5 min. Each check " +
      "costs the stack VM an attestation (about 1.0 s in the VM, X5, deploy/tee/probe/routing-measure/README.md) and the entry a " +
      "verification; the minimum keeps that to one per peer per minute [estimated]. The maximum is LISTS_REFRESH_MS (30 min, " +
      "workers/gateway/src/lane/peer.ts: a list is read again every 30 min), so a peer refused on a list that has changed since is checked " +
      "against the new one by then.",
    doc:
      "How long after an entry refused a stack VM (its report did not verify, or it refused the entry's hello) the entry attests it " +
      "again. Read by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "PEER_RENEW_MS",
    key: "peerRenewMs",
    workers: ["gateway"],
    type: "int",
    default: "300000",
    min: 60000,
    max: 900000,
    source:
      "docs/confidential-lane-stack-routing.md section 4.3 (PR 5): a pin or a hello is renewed 5 min before it lapses (at most an hour " +
      "after it was made, PEER_PIN_MAX_MS), so a busy peer never lapses under its traffic. A renewal is at most four background calls " +
      "(the attestation, the pin push, the challenge, the hello), each bounded by PEER_CALL_MS, so it is at least four of them (a check); " +
      "the minimum, a minute, is four calls at PEER_CALL_MS's default. The maximum, 15 min, a quarter of the pin's hour, leaves a pin " +
      "45 min between renewals [estimated].",
    doc:
      "How long before a stack VM's pin or hello lapses the entry renews it, in the background, while the old one keeps serving. Read " +
      "by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "PEER_CALL_MS",
    key: "peerCallMs",
    workers: ["gateway"],
    type: "int",
    default: "15000",
    min: 2000,
    max: 60000,
    source:
      "PR 5 (workers/gateway/src/lane/peer-client.ts): one background call of the entry's peer registry (the attestation route, the " +
      "challenge, the hello, a probe, a pin push). The attestation route took at most 1,075 ms in the VM and 1,499 ms to its last byte on " +
      "a warm connection (X5, deploy/tee/probe/routing-measure/README.md), and a new connection adds at most 165 ms (X1). The default is " +
      "the lane's bound on a bridge background call (BACKGROUND_CALL_MS, 15 s, workers/gateway/src/lane/remote/background.ts). The " +
      "minimum, 2 s, is above the slowest attestation measured with a new connection; the maximum, a minute: a call not answered by then " +
      "is a stall, and the peer rests for its backoff [estimated].",
    doc:
      "The bound of one background call an entry makes to a stack VM through egress (attestation, challenge, hello, probe) or to egress " +
      "(the pin table). Read by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "PEER_FOLLOW_UP_MS",
    key: "peerFollowUpMs",
    workers: ["gateway"],
    type: "int",
    default: "2000",
    min: 500,
    max: 30000,
    source:
      "docs/confidential-lane-stack-routing.md section 4.7 (PR 5): the follow-up is a new connection (X1, " +
      "deploy/tee/probe/routing-measure/README.md: p99 130 ms in region, 165 ms at most) and an answer from the stack VM's memory, with " +
      "room for a loaded VM, and never more than the request's pre phase has left. The minimum is egress's -peer-connect-timeout default, " +
      "500 ms (deploy/tee/egress/config.go), which the follow-up's new connection may take; the maximum is REQUEST_PRE_BUDGET_MS's " +
      "maximum, past which the pre phase's own bound cuts it first.",
    doc:
      "The longest an entry asks a stack VM what became of an attempt the peer hop left unknown (GET /v1/peer/attempts/<rid>), within " +
      "what the request's pre phase has left. Read by the lane (an entry with LANE_PEERS on) only.",
  },
  {
    name: "LANE_POLICY_FUEL_PER_MS",
    key: "lanePolicyFuelPerMs",
    workers: ["gateway"],
    type: "int",
    default: "188401",
    min: 1,
    max: 1000000,
    source:
      "F2 D128' measurement, 2026-10-22: workers/packages/relay-policy/bench/policy-step.ts on the build box (AMD Ryzen 9 9950X3D, " +
      "idle; workerd 1.20261006.1, the version the lane image runs; 50 timed runs per cell; raw output kept on the box as " +
      "~/gray-tee/d128-bench-{node,workerd}.txt). The benchmark runs the lane's real sandbox on modules that spend their whole fuel " +
      "budget, in three shapes (a branch loop, a loop over the input, a loop of calls) at 1 KiB to 4 MiB, and takes the smallest " +
      "fuel / (p99 - LANE_POLICY_OVERHEAD_MS), rounded down: 188,401 fuel per ms in workerd, set by the branch loop (burn-branch), the " +
      "slowest shape. That worst shape, not a scan, is what bounds a module that spends its whole budget: a full scan runs about " +
      "686,000 fuel per ms (17,841,890 fuel in 26.0 ms, workerd on an Apple M3 Ultra, relay-policy IMPLEMENTATION_NOTES §7), so " +
      "dividing by the scan rate would let a branch-heavy module outlast its step. Node on the same box measured 199,430 (not used: " +
      "the lane runs workerd). The lane also measures all three shapes at boot on its own CPU (which one is slowest depends on the " +
      "CPU) with a derivation that can only read slow, and uses the slower of the two " +
      "(workers/gateway/src/lane/calibration.ts), so this value is a ceiling on speed. Minimum 1: a fuel count is an integer. " +
      "Maximum: @gray/relay-policy's fuelBase, 1,000,000, at which the whole fixed budget would run in 1 ms.",
    doc:
      "The confidential lane's policy sandbox throughput, in wasmi fuel per millisecond, on the slowest module shape. The lane's " +
      "policy step waits ceil(fuel / LANE_POLICY_FUEL_PER_MS) + LANE_POLICY_OVERHEAD_MS for a request, at most LANE_POLICY_STEP_MS " +
      "(or the cap the boot raises it to when its calibration would make LANE_POLICY_STEP_MS bind, F2 D130), " +
      "where fuel is the sandbox's budget for that request's input (a function of its size), so the wait depends only on the input's " +
      "size. A run observed past it is policy_unavailable. The lane lowers it at boot when its own calibration is slower. Read by " +
      "the lane only.",
  },
  {
    name: "LANE_POLICY_OVERHEAD_MS",
    key: "lanePolicyOverheadMs",
    workers: ["gateway"],
    type: "int",
    default: "3",
    min: 0,
    max: 60000,
    source:
      "F2 D128' measurement, 2026-10-22, the same run as LANE_POLICY_FUEL_PER_MS (build box, AMD Ryzen 9 9950X3D; workerd " +
      "1.20261006.1; 50 runs per cell; ~/gray-tee/d128-bench-workerd.txt): the largest p99 of a module that answers at once (allow), " +
      "over every input size from 1 KiB to 4 MiB, rounded up: 3 ms in workerd (Node on the same box: 2). The benchmark as committed " +
      "with D128 (21a4127e9) ended each workerd sample with a setTimeout(0) (it assumed workerd's clock stood still during a run), so " +
      "that timer's latency is inside this number and it errs long. The lane takes the larger of this and its own boot calibration " +
      "(workers/gateway/src/lane/calibration.ts). Maximum: LANE_POLICY_STEP_MS's own maximum, 60,000 " +
      "(workers/gateway/src/lane/entry.ts laneTiming).",
    doc:
      "The fixed cost around one policy run on the lane, in ms: building the module's input, a fresh instance, reading its answer. It " +
      "is added to every request's policy step wait (see LANE_POLICY_FUEL_PER_MS); the lane raises it at boot when its own " +
      "calibration is larger. Read by the lane only.",
  },
  {
    name: "STREAM_KEEPALIVE_MS",
    key: "streamKeepAliveMs",
    workers: ["gateway"],
    type: "int",
    default: "15000",
    min: 100,
    max: 120000,
    source:
      "GRAY_STREAM_KEEPALIVE_SECONDS, default 15 (config/mod.rs:153-155). Maximum: under the edge's default read timeout of 125 s (inference.rs " +
      "sse_reply), and Claude Code's event-level idle watchdog of 300 s.",
    doc:
      "A streamed response that has written nothing for this long writes a keep-alive between whole frames: a comment, or Anthropic's own ping " +
      "event for an Anthropic client.",
  },
  {
    name: "STREAM_CLIENT_STALL_MS",
    key: "streamClientStallMs",
    workers: ["gateway"],
    type: "int",
    default: "60000",
    min: 1000,
    max: 600000,
    source:
      "GRAY_STREAM_CLIENT_STALL_SECONDS, default 60 (config/mod.rs:163-167). Maximum: REQUEST_BODY_MS's maximum, the longest an agent client " +
      "waits on a request before giving up.",
    doc:
      "How long a stream, or a non-streaming answer that has started to go out, waits for a client that takes nothing from a full buffer. " +
      "Then it is treated as a client that left: a stream ends with the client_read_timeout error event, a non-streaming body is cut off, " +
      "the upstream is cancelled and nothing is charged (docs/cloudflare-native.md 5.6).",
  },
  {
    name: "CONFIG_VERSION_CHECK_MS",
    key: "configVersionCheckMs",
    workers: ["gateway"],
    type: "int",
    default: "2000",
    min: 250,
    max: 60000,
    source:
      "The server refreshes its key and route snapshot every 2 s (crates/gray-gateway/src/background.rs:67); docs/cloudflare-native.md 2.6 and " +
      "4.1 keep that interval for the isolate's version check. Maximum: the alert age's default (CONFIG_ALERT_AGE_MS, 60 s): a copy confirmed " +
      "less often would cross the alert age between checks while its source is well.",
    doc: "How often an isolate asks its snapshot source for the current version of the key and route snapshot (at most once per interval).",
  },
  {
    name: "CONFIG_MAX_AGE_MS",
    key: "configMaxAgeMs",
    // gray-jobs' ConfigDO lists no public catalog past it, as the server's lists none once its snapshot expired (`public_catalog`).
    workers: ["gateway", "console", "jobs"],
    type: "int",
    default: "21600000",
    min: 2000,
    max: 21600000,
    source:
      "owner, 2026-10-18: \"a few hours\" (while PostgreSQL or Hyperdrive is down, the gateway keeps serving from the last snapshot for hours and " +
      "alerts; docs/cloudflare-native/database.md section 8 item 14). 6 hours, which is also the maximum: a longer grace is the owner's " +
      "call. It replaces the server's REFRESH_TTL of 60 s (crates/gray-gateway/src/inference.rs:120), the refusal age until then and " +
      "now the alert age (CONFIG_ALERT_AGE_MS). Minimum: the server's 2 s refresh (crates/gray-gateway/src/background.rs:67).",
    doc:
      "How long an isolate serves from a snapshot whose writer (gray-jobs' ConfigDO) has not completed a rebuild from PostgreSQL. Past it " +
      "requests answer 503 auth_snapshot_expired. Before it, keys, routes and prices are those of the last rebuild: a key, an offer or a " +
      "price changed in the database meanwhile waits for it; revocations and balances are decided by the account shards and roots, not by " +
      "the snapshot, and take effect as before. The console reads the same value to report, in the operations investigation's route " +
      "health, when the current snapshot expires: set it alike on both.",
  },
  {
    name: "CONFIG_ALERT_AGE_MS",
    key: "configAlertAgeMs",
    workers: ["gateway", "jobs"],
    type: "int",
    default: "60000",
    min: 2000,
    max: 21600000,
    source:
      "REFRESH_TTL of 60 s (crates/gray-gateway/src/inference.rs:120): the age past which the server refuses every request with " +
      "auth_snapshot_expired, and this gateway did until the owner's decision of 2026-10-18 to serve for hours and alert (CONFIG_MAX_AGE_MS). " +
      "Minimum: the server's 2 s refresh (crates/gray-gateway/src/background.rs:67). Maximum: CONFIG_MAX_AGE_MS's maximum; a cross check " +
      "keeps it at most CONFIG_MAX_AGE_MS, since an alert past the refusal would never be raised while serving. gray-jobs reads the same " +
      "value, so its writer says the outage at the age the isolates do; set it to the gateway's.",
    doc:
      "Snapshot age past which an isolate that still serves raises the `snapshot_stale` alert (Workers Logs, level alert), once until a " +
      "copy within this age arrives again; past CONFIG_MAX_AGE_MS it raises `snapshot_expired` once and refuses. In gray-jobs, the age past " +
      "which ConfigDO, still failing to rebuild, raises its own `snapshot_stale` alert, once until a rebuild succeeds (each failed rebuild " +
      "is a warning). Every one of these alerts carries the same `alert_key` for one outage (docs/cloudflare-native/jobs.md section 1.4).",
  },
  {
    name: "ALERT_GROUP_MS",
    key: "alertGroupMs",
    workers: ["gateway", "jobs", "alerts"],
    type: "int",
    default: "3600000",
    min: 60000,
    max: 86400000,
    source:
      "The reconciliation's period, RECONCILE_INTERVAL_MS (1 hour, docs/cloudflare-native.md 5.3): an alert that comes with requests (an " +
      "Idempotency-Key admitted degraded because its home shard failed, a duplicate charge refunded) says the same thing for as long as it " +
      "lasts, and the hourly reconciliation counts what is still open (refund_credit_pending, open mismatches), so a page an hour per sick " +
      "shard or per workspace is enough. Minimum: CONFIG_ALERT_AGE_MS's default (60 s), the shortest wait before any alert here. Maximum: " +
      "a day, SEAL_MAX_AGE_MS (the longest a charge waits for its hourly entry).",
    doc:
      "How long the alerts that come with requests group under one `alert_key` (docs/cloudflare-native/jobs.md section 1.4): the gateway's " +
      "`admission_degraded`, keyed by the home shard that failed, said at level alert by each isolate at its first degraded admission and " +
      "again at the first one half this long after its last alert, at warn for every other request; gray-jobs' `projection_mismatch` for a " +
      "duplicate charge it refunded, keyed by the workspace and the period of the repeat's request_at. Set it alike in the gateway, the jobs " +
      "and gray-alerts. gray-alerts closes a key no authoritative resolve line closes (an alert line without `alert_key`, a cause without " +
      "`resolvedBy` in its catalog such as these two, an invocation outcome, its own `alert_delivery_failed`) once this long passes " +
      "without an alert line of it, and sends its resolve; each of its isolates hands such a key to its object at most once per half this " +
      "long, counting the lines between (workers/alerts/src/forwarding.ts).",
  },
  // ---------------------------------------------------------------- gray-alerts (the alert router, workers/alerts)
  {
    name: "ALERT_PAGING",
    key: "alertPaging",
    workers: ["alerts"],
    type: "enum",
    values: ALERT_PAGING_MODES,
    default: "on",
    source:
      "docs/cloudflare-native/alerts.md section 3.1 (paging off): `on` is the router as designed, a page to every destination set. `off` is " +
      "the owner's decision of 2026-10-20 for production's first deployment on testnet (skip the destinations for now, record the alerts): " +
      "production's values.jsonc alertPaging names it, so a deploy takes it from a commit.",
    doc:
      "Whether the alert router pages. `on`: at least one destination secret outside DEPLOY_ENV local, as before. `off`: no destination " +
      "secret may be set (ALERT_PAGERDUTY_ROUTING_KEY, ALERT_LARK_WEBHOOK_URL, ALERT_LARK_SECRET, ALERT_WEBHOOK_URL), and each page the " +
      "router would have sent is an error line `alert_page_not_sent` in its Workers Logs instead (workers/alerts/src/paging.ts).",
  },
  {
    name: "ALERT_RUNBOOK_URL",
    key: "alertRunbookUrl",
    workers: ["alerts"],
    type: "text",
    default: "https://github.com/megaeth-labs/gray/blob/main/docs/cloudflare-native/alerts.md",
    textCheck: (v) => (httpUrlProblem(v) === null && v.startsWith("https://") ? null : "is not an https URL"),
    source: "docs/cloudflare-native/alerts.md: the table of every cause the Workers alert on, its threshold and its source; each page links its cause's area there.",
    doc: "The runbook a page links to: the page adds `#` and the cause's area (workers/alerts/src/catalog.ts).",
  },
  {
    name: "ALERT_DELIVERY_RETRY_MS",
    key: "alertDeliveryRetryMs",
    workers: ["alerts"],
    type: "int",
    default: "60000",
    min: 1000,
    max: 600000,
    source:
      "PagerDuty Events API v2 (developer.pagerduty.com, Events API v2 overview, Response Codes & Retry Logic, read 2026-10-19): retry a 429 " +
      "or a 5xx 'after some time', a 429 'preferably with a backoff of a few minutes'; the Lark custom bot takes 100 messages a minute and 5 a " +
      "second and answers 11232 when throttled (open.larksuite.com, custom bot, read 2026-10-19). A minute first, then doubling.",
    doc: "How long the alert router waits before it sends a page that did not go through again; each further wait doubles, up to ALERT_DELIVERY_RETRY_MAX_MS.",
  },
  {
    name: "ALERT_DELIVERY_RETRY_MAX_MS",
    key: "alertDeliveryRetryMaxMs",
    workers: ["alerts"],
    type: "int",
    default: "600000",
    min: 60000,
    max: 3600000,
    source: "PagerDuty's 'a backoff of a few minutes' (ALERT_DELIVERY_RETRY_MS): at most ten minutes between two tries of one page.",
    doc: "The longest wait between two tries of one page.",
  },
  {
    name: "ALERT_DELIVERY_TIMEOUT_MS",
    key: "alertDeliveryTimeoutMs",
    workers: ["alerts"],
    type: "int",
    default: "60000",
    min: 1000,
    max: 600000,
    source:
      "ALERT_DELIVERY_RETRY_MS's minute: a try still unanswered when a failed one would be sent again counts as failed. A fetch from a Worker " +
      "has no deadline of its own, so without one a destination that holds the connection open would hold its page forever. Maximum: " +
      "ALERT_DELIVERY_RETRY_MAX_MS's default, the longest wait between two tries.",
    doc:
      "How long the alert router waits for a destination to answer one try of a page. Past it the try counts as failed and is sent again " +
      "later; the destination may have taken it all the same, so its key's resolve goes there too.",
  },
  {
    name: "ALERT_DELIVERY_GIVE_UP_MS",
    key: "alertDeliveryGiveUpMs",
    workers: ["alerts"],
    type: "int",
    default: "86400000",
    min: 600000,
    max: 604800000,
    source:
      "ALERT_GROUP_MS's maximum, a day: the alerts that come with requests open a new key at least once a day while they last, so a page " +
      "older than that has a successor. Maximum: Workers Logs' retention, 7 days (Workers Logs, Limits, read 2026-10-19).",
    doc: "How long the alert router keeps trying one page; past it the page is dropped with an error line `alert_delivery_given_up` (the alert's state stays).",
  },
  {
    name: "ALERT_KEY_RETENTION_MS",
    key: "alertKeyRetentionMs",
    workers: ["alerts"],
    type: "int",
    default: "604800000",
    min: 86400000,
    max: 2592000000,
    source:
      "Workers Logs keeps a log line 7 days (Workers Logs, Limits, read 2026-10-19): an alert key nobody has said for that long has nothing left " +
      "to look up, so its state is forgotten. Minimum: ALERT_GROUP_MS's maximum, a day.",
    doc: "How long the alert router keeps an alert key's state after its last line: a later line of the same key opens a new alert and pages again.",
  },
  {
    name: "PLATFORM_FEE_BPS",
    key: "platformFeeBps",
    // gray-jobs' ConfigDO prices the public catalog with it, as the server's catalog reads its own (inference.rs `refresh_catalog`).
    workers: ["gateway", "console", "jobs"],
    type: "int",
    default: "500",
    min: 0,
    max: 10000,
    source:
      "GRAY_PLATFORM_FEE_BPS, default DEFAULT_PLATFORM_FEE_BPS = 500 (crates/gray-gateway/src/config/mod.rs:23, :394-403); the maximum is " +
      "gray-ledger's MAX_PLATFORM_FEE_BPS (10,000), which @gray/holds customerRate enforces.",
    doc: "Gray's fee on a supplier's quoted price, in basis points: the customer rate is the quote times (1 + fee), rounded up (customerRate). The console's " +
      "/api/v1/config states it.",
  },
  {
    name: "GATEWAY_FALLBACK_REGION",
    key: "gatewayFallbackRegion",
    // The console names a new workspace's home region with the same rule (`requestRegion`), so it reads the same fallback.
    workers: ["gateway", "console"],
    type: "enum",
    values: LOCATION_HINTS,
    default: "wnam",
    source:
      "DEFAULT_HOME_REGION (region.ts, wnam: the database's region, workers/credit/wrangler.api.jsonc ACCOUNT_LOCATION_HINT): a request whose " +
      "location Cloudflare does not state (request.cf without a continent, as in local development) is served where the database is.",
    doc:
      "The region (Durable Object location hint) of a request whose continent is unknown. Otherwise the region comes from request.cf " +
      "(`requestRegion`, this package's `region.ts`). The console names a new workspace's home region by the same rule.",
  },
  {
    name: "CONSOLE_ORIGIN",
    key: "consoleOrigin",
    workers: ["gateway"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" ? null : originProblem(v)),
    source:
      "docs/two-region-launch.md section 3 (settled 2026-10-15): the console stays on the apex and the model API has its own host, so the " +
      "console's Media Playground, which calls the model API as an application would, calls another origin. The console's ORIGIN; empty " +
      "where both are one origin (the server, local development).",
    doc:
      "The console's origin (https://usefallback.com), the one origin whose pages may call the model API from a browser: the gateway answers " +
      "its CORS preflight and lets its pages read the answers (workers/gateway/src/cors.ts). No credentials ride on such a call (the page " +
      "sends an API key it created, never a cookie). The gateway's errors link to the console's pages there (`public_errors::Origins`). " +
      "Empty: no cross-origin call is allowed, and the errors link to the request's own origin, as one origin for both.",
  },
  // Endpoint permits and circuits: EndpointRootDO and EndpointShardDO (workers/packages/endpoint,
  // docs/cloudflare-native/endpoint.md). The server values cited are crates/gray-gateway/src/ranking.rs
  // RankingConfig::default and crates/gray-gateway/src/config/mod.rs Timeouts::default.
  {
    name: "ENDPOINT_REPORT_MS",
    key: "endpointReportMs",
    workers: ["gateway"],
    type: "int",
    default: "2000",
    min: 500,
    max: 10000,
    source:
      "Routing state may be 2 s stale everywhere else: the server refreshes its snapshot every 2 s (crates/gray-gateway/src/background.rs:67) and " +
      "docs/cloudflare-native.md section 2.6 checks revocations every 2 s. Minimum: 32 shards reporting every 0.5 s are 64 calls a second, far below " +
      "the ~1,000 a second one object takes (scaling.md section 1). Maximum: a key's outcomes reach its circuit within one interval, a third of the " +
      "30 s cooldown (ranking.rs `cooldown_ms`).",
    doc:
      "How often an active endpoint shard reports its counts, each rank key's outcomes and its lease to the root; and the longest a shard waits " +
      "for a report's answer: one still unanswered counts as failed and is sent again, so a root that stalls holds no alarm and no later " +
      "report (docs/request-path-availability.md M3).",
  },
  {
    name: "ENDPOINT_BREAKER_FAILURE_THRESHOLD",
    key: "endpointBreakerFailureThreshold",
    workers: ["gateway"],
    type: "int",
    default: "3",
    min: 1,
    max: 4096,
    source:
      "The server's failure_threshold 3 (crates/gray-gateway/src/ranking.rs, RankingConfig::default; `record` opens a key's circuit at it). " +
      "Minimum 1, as the server's EndpointRanker::new refuses 0. Maximum: 4,096 failures in a row fill the most samples the server lets a key " +
      "keep (its EndpointRanker::new bound on max_samples_per_endpoint), and the failure-rate rule opens the circuit first.",
    doc: "First-call supplier failures in a row at one rank key (a route in one mode) that open that key's circuit.",
  },
  {
    name: "ENDPOINT_BREAKER_MIN_SAMPLES",
    key: "endpointBreakerMinSamples",
    workers: ["gateway"],
    type: "int",
    default: "5",
    min: 1,
    max: 128,
    source:
      "The server's minimum_samples 5 (crates/gray-gateway/src/ranking.rs, RankingConfig::default), its failure-rate rule's least count (`record`). " +
      "Maximum: the server's default 128 samples per key (max_samples_per_endpoint); at most ENDPOINT_BREAKER_MAX_SAMPLES (a cross check, as EndpointRanker::new).",
    doc: "The failure-rate rule: at least this many recent first calls at a rank key, of at least half this much half-life weight, before their failure rate can open its circuit.",
  },
  {
    name: "ENDPOINT_BREAKER_FAILURE_RATE_PERCENT",
    key: "endpointBreakerFailureRatePercent",
    workers: ["gateway"],
    type: "int",
    default: "60",
    min: 1,
    max: 100,
    source: "The server's failure_rate_threshold 0.6 (crates/gray-gateway/src/ranking.rs, RankingConfig::default; the rule in `record`).",
    doc: "The failure-rate rule: recent first calls at a rank key failing at least this percentage of their half-life weight open its circuit.",
  },
  {
    name: "ENDPOINT_BREAKER_HALF_LIFE_SECONDS",
    key: "endpointBreakerHalfLifeSeconds",
    workers: ["gateway"],
    type: "int",
    default: "120",
    min: 10,
    max: 600,
    source:
      "The server's half_life_ms 120,000 (crates/gray-gateway/src/ranking.rs, RankingConfig::default). Minimum: the server's 10 s trial window " +
      "(trial_window_ms). At most ENDPOINT_BREAKER_STALE_SECONDS (a cross check, as EndpointRanker::new).",
    doc: "A first call's weight in the failure-rate rule halves every this many seconds.",
  },
  {
    name: "ENDPOINT_BREAKER_STALE_SECONDS",
    key: "endpointBreakerStaleSeconds",
    workers: ["gateway"],
    type: "int",
    default: "600",
    min: 10,
    max: 3600,
    source:
      "The server's stale_after_ms 600,000 (crates/gray-gateway/src/ranking.rs, RankingConfig::default). Minimum: the half-life's. Maximum: " +
      "an hour, thirty half-lives at the default, past which a sample weighs less than 1e-9.",
    doc: "Outcomes older than this many seconds count in no rank key's circuit.",
  },
  {
    name: "ENDPOINT_BREAKER_MAX_SAMPLES",
    key: "endpointBreakerMaxSamples",
    workers: ["gateway"],
    type: "int",
    default: "128",
    min: 1,
    max: 128,
    source:
      "The server's max_samples_per_endpoint 128 (crates/gray-gateway/src/ranking.rs, RankingConfig::default). Maximum 128 (the server's " +
      "EndpointRanker::new allows 4,096): a key's samples travel to every gateway isolate, gray-jobs replica and the ranking collector " +
      "(the ranking feed), whose memory was measured at 4,096 keys x 128 samples in workerd: an isolate's base 18.4 MB of the 21 MB share " +
      "of ISOLATE_TABLE_ENTRIES' precedent, a replica's copy and the collector 23.1 MB (workers/gateway/measure/ranking-heap.ts, " +
      "docs/cloudflare-native/endpoint.md section 12; review r31). Past 128 a key would outgrow that share and the replicas' bound.",
    doc:
      "The newest outcomes a rank key's circuit keeps; also the most runs of alike outcomes a shard holds per key between two reports " +
      "(the oldest go first, which only a root that took no report for a long time misses).",
  },
  {
    name: "ENDPOINT_BREAKER_COOLDOWN_SECONDS",
    key: "endpointBreakerCooldownSeconds",
    workers: ["gateway"],
    type: "int",
    default: "30",
    min: 1,
    max: 600,
    source: "Today's server value (`RankingConfig::default` `cooldown_ms`, 30,000, crates/gray-gateway/src/ranking.rs). Maximum: the server's 600 s stale window (`stale_after_ms`).",
    doc: "How long an isolated endpoint gets no traffic before probes may test it, and the wait after a failed probe.",
  },
  {
    name: "ENDPOINT_PROBE_LEASE_SECONDS",
    key: "endpointProbeLeaseSeconds",
    workers: ["gateway"],
    type: "int",
    default: "120",
    min: 1,
    max: 3600,
    source: "Today's server value (`RankingConfig::default` `recovery_lease_ms`, 120,000, crates/gray-gateway/src/ranking.rs). Maximum: the stream total (STREAM_TOTAL_SECONDS).",
    doc: "How long one probe holds the endpoint's only probe lease; its result counts only within it, and no other probe goes meanwhile.",
  },
  {
    name: "ENDPOINT_RECOVERY_SUCCESSES",
    key: "endpointRecoverySuccesses",
    workers: ["gateway"],
    type: "int",
    default: "2",
    min: 1,
    max: 10,
    source:
      "Today's server value (`RankingConfig::default` `recovery_successes`, 2, crates/gray-gateway/src/ranking.rs). Maximum: 10 probes a 30 s cooldown apart keep recovery " +
      "within 5 minutes, half the server's 600 s stale window (`stale_after_ms`).",
    doc: "Successful probes in a row that close the breaker.",
  },
  {
    name: "ENDPOINT_HEALTH_SAVE_MS",
    key: "endpointHealthSaveMs",
    workers: ["gateway"],
    type: "int",
    default: "5000",
    min: 1000,
    max: 9000,
    source:
      "A Durable Object with nothing to do may leave memory after 10 s (docs C19: a hibernatable object idle 10 s; workerd evicts after 10 s of " +
      "inactivity, workerd.capnp `preventEviction`), and the endpoint root holds the outcomes of the reports since its last write of its circuits in " +
      "memory (a busy root writes them at most ENDPOINT_HEALTH_CHECKPOINT_MS apart). Half of those 10 s: an alarm late by up to 5 s on a loaded " +
      "host still finds the object in memory, and a route that is serving reports every ENDPOINT_REPORT_MS (2 s), so it writes when the route pauses, " +
      "not between two reports. Maximum: below the 10 s. Minimum: 1 s.",
    doc:
      "How long after the last report that brought supplier outcomes the endpoint root writes its circuits to disk, when the disk does not hold " +
      "them yet: a root the platform took out of memory comes back with every outcome its circuits held.",
  },
  {
    name: "ENDPOINT_HEALTH_CHECKPOINT_MS",
    key: "endpointHealthCheckpointMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 1000,
    max: 600000,
    source:
      "The server writes its runtime checkpoint, its ranker's circuits among it, at most every 30 s (crates/gray-gateway/src/inference.rs " +
      "`checkpoint_runtime`). Minimum 1 s: at most one write a second per root, a thousandth of the ~1,000 calls a second one object takes " +
      "(scaling.md section 1); maximum the server's 600 s stale window, past which the outcomes it would keep say nothing.",
    doc:
      "While reports keep bringing supplier outcomes, the endpoint root writes its circuits at least this often (each opening, closing and probe " +
      "is written at once): what a root that fails between two writes loses.",
  },
  {
    name: "ENDPOINT_UNOBSERVED_WORK_SECONDS",
    key: "endpointUnobservedWorkSeconds",
    workers: ["gateway"],
    type: "int",
    default: "120",
    min: 60,
    max: 3600,
    source:
      "Today's server value (GRAY_UNOBSERVED_WORK_SECONDS, default 120, crates/gray-gateway/src/config/mod.rs:191); the server holds at least 60 s " +
      "(inference.rs close_attempt, .max(60 s)). Maximum: the stream total.",
    doc: "How long a permit stays taken after Gray stopped reading an attempt the supplier may still be working on.",
  },
  {
    name: "ENDPOINT_PERMIT_HEADROOM_PERCENT",
    key: "endpointPermitHeadroomPercent",
    workers: ["gateway"],
    type: "int",
    default: "25",
    min: 0,
    max: 100,
    source:
      "The account shard prototype refilled its allowance when a quarter was left (docs/cloudflare-native/m0/shard-proto/src/index.ts, chunk / 4), and " +
      "almost no request waited on the root (docs/cloudflare-native.md section 2.6). Maximum 100: doubling.",
    doc: "Permits a shard asks for above its recent peak in use, and the margin of its in-use bound on disk.",
  },
  {
    name: "ENDPOINT_IDLE_RETURN_SECONDS",
    key: "endpointIdleReturnSeconds",
    workers: ["gateway"],
    type: "int",
    default: "30",
    min: 10,
    max: 3600,
    source:
      "The plan's idle return of leased allowance, 30 s without a call (docs/cloudflare-native.md section 2.6): not much longer than the 10 s after which " +
      "a hibernatable Durable Object may leave memory (C19), long enough to avoid leasing and returning back and forth. Minimum: those 10 s. Maximum: the stream total.",
    doc:
      "A shard with no permit in use and no request for this long gives its lease back down to one standing permit (ENDPOINT_STANDING_RETURN_SECONDS); " +
      "before that it keeps what it held, so a request after an eviction needs no root call.",
  },
  {
    name: "ENDPOINT_STANDING_RETURN_SECONDS",
    key: "endpointStandingReturnSeconds",
    workers: ["gateway"],
    type: "int",
    default: "3600",
    min: 10,
    max: 3600,
    source:
      "ACCOUNT_STANDING_RETURN_MS's source, the same hour: the 90th percentile of the measured human think time between turns, 3,070 s " +
      "(perf-agent-load/model/wm2/workload_spec_v2.json session_process.tables.think, branch perf/agent-load-20261015), rounded up to the " +
      "longest stream, the owner's keep-warm decision of 2026-10-29 (docs/request-path-availability.md M2; it was 12 minutes). An endpoint shard that " +
      "returned everything after ENDPOINT_IDLE_RETURN_SECONDS made the first request after a pause wait for a borrow from the route's root: two " +
      "Durable Objects in a row on the request path, each possibly cold. Measured on staging 2026-10-22 07:35-08:01Z with a request every ~12 s: an " +
      "object's call waited 1.9-3.2 s now and then before or while it ran (a nonce object 3.2 s before it started, an endpoint shard 1.95 s with its root " +
      "answering in 13 ms), past ENDPOINT_ACQUIRE_WAIT_MS (1.5 s), and the request was refused 503 (docs/cloudflare-native/gateway.md section 14). A " +
      "standing permit another region needs is recalled within that region's wait (ReportReply `recalled`). Minimum: ENDPOINT_IDLE_RETURN_SECONDS' " +
      "minimum. Maximum: an hour, as the account's.",
    doc:
      "How long a shard with no permit in use keeps its standing permits after its idle return, as many as it had in use at once in its last busy " +
      "spell (at least one, at most what the root grants), so the first requests after a pause, a burst of them too, are served without a call to " +
      "the route's root. At least ENDPOINT_IDLE_RETURN_SECONDS (a cross check).",
  },
  {
    name: "ENDPOINT_SHARD_TARGET_RPS",
    key: "endpointShardTargetRps",
    workers: ["gateway"],
    type: "int",
    default: "350",
    min: 50,
    max: 1000,
    source:
      "A third of the measured single-shard ceiling of ~1,060 requests a second (m0/raw/shard-capacity-k1-gm20-20261017.jsonl, docs/cloudflare-native.md " +
      "section 2.6). Maximum: that ceiling, rounded down. Minimum: the 62 a second per shard of 2,000 a second over 32 shards (scaling.md section 2).",
    doc: "Permits issued per second per shard above which the root doubles the endpoint's shards per region.",
  },
  {
    name: "ENDPOINT_SHARD_MAX",
    key: "endpointShardMax",
    workers: ["gateway"],
    type: "int",
    default: "32",
    min: 1,
    max: 32,
    check: powerOfTwo,
    source:
      "As ACCOUNT_SHARD_COUNT: K = 32 is the largest shard count measured (2,992 requests a second, no errors, m0/raw/shard-ws2k-k32-20261017.jsonl). " +
      "Powers of two only: the count changes only by doubling (scaling.md section 5).",
    doc: "The most endpoint shards per region. The root never asks for more shards than the endpoint has permits.",
  },
  {
    name: "ENDPOINT_ROOT_CALL_TIMEOUT_MS",
    key: "endpointRootCallTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 250,
    max: 5000,
    source:
      "A Durable Object call across regions took 156-229 ms at the median (scaling.md section 1, m0/raw/dolat-online-20261017.jsonl); the default is " +
      "about four times the slowest. Minimum: just above it. Maximum: the server waits at most 5 s on a rate-limited upstream before retrying " +
      "(inference.rs:4711-4716).",
    doc:
      "How long a request waits for the endpoint root: a borrow when its shard has no permit to give, or the probe lease of an endpoint in recovery; " +
      "and, before it asks a route again, the rest its own failure filed at that route's root (so the next attempt's answer ends it, as the server's). " +
      "The wait also ends at the caller's answerBy (when the gateway stops waiting), so a borrow that lands later stays in the shard's lease. " +
      "Then the shard answers busy (or breaker_recovering) and stops waiting on the root for a report interval, as it does after a report " +
      "whose call failed; a cold pass's one repeat (awaitLease) still waits on the report in flight, and sends a failed one again at most " +
      "once a report interval per shard. A shard also waits at most this long for the root to take a probe's result, an answer that ends " +
      "rests, and a probe's answer or departure: a root that does not answer holds no release (docs/request-path-availability.md M3).",
  },
  {
    name: "ENDPOINT_ACQUIRE_WAIT_MS",
    key: "endpointAcquireWaitMs",
    workers: ["gateway"],
    type: "int",
    default: "1500",
    min: 100,
    max: 5500,
    source:
      "The same wait as one admission attempt (ACCOUNT_ADMIT_ATTEMPT_MS: today's GRAY_CREDIT_ADMIT_ATTEMPT_MS = 1500, " +
      "deploy/runtime/compose.production.yaml:101), the other call of the request path to a regional shard that may wait for its root: the " +
      "root wait (ENDPOINT_ROOT_CALL_TIMEOUT_MS, 1 s) leaves 0.5 s for the call to the shard, a same-region call taking 2-5 ms (scaling.md " +
      "section 1). Maximum: the root wait's maximum with the same margin. It does not cover a new shard's first borrow (production, " +
      "gray.requests_v2 and durableObjectsInvocationsAdaptiveGroups for gray-cf-prod-gateway, 2026-10-22/23: a new shard starts at least " +
      "0.2-0.66 s after the call, then runs 0.94-1.56 s wall; an apac report to a cold wnam root takes p50 0.56-0.70 s). That case is covered " +
      "by answerBy and the one cold repeat (docs/cloudflare-native/gateway.md section 14), not by a longer wait, so failover to another " +
      "operator stays fast.",
    doc:
      "How long the gateway waits for an endpoint shard's permit (acquire), cut to what is left of the request's wait for an answer; it counts " +
      "towards the time to first token. A permit that arrives later is handed back at once. A route passed over because its permit was still " +
      "being borrowed is asked once more, after every other operator, when more than this wait is left (the cold repeat).",
  },
  // Retries (docs/cloudflare-native/gateway.md section 5; the server's GRAY_RETRY_*,
  // crates/gray-gateway/src/config/requests.rs, and docs/runtime-operations.md "Retries"). Each default is
  // a source's value, named beside it, as the server names it.
  {
    name: "RETRY_MAX_ATTEMPTS",
    key: "retryMaxAttempts",
    workers: ["gateway"],
    type: "int",
    default: "3",
    min: 1,
    max: 5,
    source:
      "GRAY_RETRY_MAX_ATTEMPTS, default 3 (config/requests.rs): AWS `max_attempts` 3 (AWS SDKs and Tools Reference Guide, \"Retry behavior\"); " +
      "the Anthropic and OpenAI SDKs' `DEFAULT_MAX_RETRIES` 2. Maximum: gRPC A6 treats `maxAttempts` above 5 as 5.",
    doc: "Upstream attempts per request, the first included; 1 turns retries off",
  },
  {
    name: "RETRY_SAME_OPERATOR",
    key: "retrySameOperator",
    workers: ["gateway"],
    type: "int",
    default: "1",
    min: 0,
    max: 2,
    source: "GRAY_RETRY_SAME_OPERATOR, default 1 (config/requests.rs): Envoy's `num_retries` default of 1 (route_components.proto); 2 is the SDKs' two retries.",
    doc: "Repeats per request at an operator already tried (another of its routes or the same one); 0 stops every same-operator attempt",
  },
  {
    name: "RETRY_SECOND_OPINION",
    key: "retrySecondOpinion",
    workers: ["gateway"],
    type: "int",
    default: "1",
    min: 0,
    max: 1,
    source: "GRAY_RETRY_SECOND_OPINION, default 1 (config/requests.rs): an on/off switch for one same-operator repeat of a refusal, within RETRY_SAME_OPERATOR (Envoy's 1).",
    doc: "Second opinions per request: one same-operator repeat of a refusal when no other operator can take the request; 0 stops refusal re-sampling",
  },
  {
    name: "RETRY_BACKOFF_MS",
    key: "retryBackoffMs",
    workers: ["gateway"],
    type: "int",
    default: "500",
    min: 1,
    max: 20000,
    source: "GRAY_RETRY_BACKOFF_MS, default 500 (config/requests.rs): the SDKs' `INITIAL_RETRY_DELAY` 0.5 s (`_constants.py`). Maximum: AWS's backoff cap of 20 s.",
    doc: "The first wait before a same-operator attempt; it doubles per repeat up to RETRY_BACKOFF_MAX_MS, less up to 25 % jitter",
  },
  {
    name: "RETRY_BACKOFF_MAX_MS",
    key: "retryBackoffMaxMs",
    workers: ["gateway"],
    type: "int",
    default: "8000",
    min: 1,
    max: 20000,
    source: "GRAY_RETRY_BACKOFF_MAX_MS, default 8000 (config/requests.rs): the SDKs' `MAX_RETRY_DELAY` 8 s (`_constants.py`). Maximum: AWS's backoff cap of 20 s.",
    doc: "The longest backoff before a same-operator attempt",
  },
  {
    name: "RETRY_AFTER_MAX_SECONDS",
    key: "retryAfterMaxSeconds",
    workers: ["gateway"],
    type: "int",
    default: "5",
    min: 0,
    max: 120,
    source:
      "GRAY_RETRY_AFTER_MAX_SECONDS, default 5 (config/requests.rs): AWS clamps a server-stated delay to at most its backoff plus 5,000 ms " +
      "(botocore `_RETRY_AFTER_MAX_ADDITIONAL` 5). Maximum: the OpenAI SDK's `MAX_RETRY_AFTER_DELAY` of 120 s, beyond which it does not retry at all.",
    doc: "The longest delay an upstream states that Gray waits before asking it again; a longer one goes to another operator at once, or back to the client",
  },
  {
    name: "RETRY_BUDGET_TOKENS",
    key: "retryBudgetTokens",
    workers: ["gateway"],
    type: "int",
    default: "500",
    min: 1,
    max: 1000,
    source: "GRAY_RETRY_BUDGET_TOKENS, default 500 (config/requests.rs): AWS's retry quota of 500. Maximum: gRPC A6 bounds `maxTokens` to (0, 1000].",
    doc:
      "Each workspace's retry budget at each route; a request served by its first attempt adds 1, a same-operator retry takes its cost, and one " +
      "that is served gets it back",
  },
  {
    name: "RETRY_TRANSIENT_COST",
    key: "retryTransientCost",
    workers: ["gateway"],
    type: "int",
    default: "14",
    min: 1,
    max: 1000,
    source: "GRAY_RETRY_TRANSIENT_COST, default 14 (config/requests.rs): AWS's 14 per transient retry (standard retry mode). At most RETRY_BUDGET_TOKENS (a cross check).",
    doc: "What a same-operator retry after a server error, a broken connection or a refusal takes from the budget",
  },
  {
    name: "RETRY_THROTTLED_COST",
    key: "retryThrottledCost",
    workers: ["gateway"],
    type: "int",
    default: "5",
    min: 1,
    max: 1000,
    source: "GRAY_RETRY_THROTTLED_COST, default 5 (config/requests.rs): AWS's 5 per throttled retry (standard retry mode). At most RETRY_BUDGET_TOKENS (a cross check).",
    doc: "What a same-operator retry after a rate limit takes from the budget",
  },
  {
    name: "RETRY_CONCURRENCY_PERCENT",
    key: "retryConcurrencyPercent",
    workers: ["gateway"],
    type: "int",
    default: "20",
    min: 0,
    max: 100,
    source: "GRAY_RETRY_CONCURRENCY_PERCENT, default 20 (config/requests.rs): Envoy's `RetryBudget` `budget_percent` 20 % of the active requests (circuit_breaker.proto).",
    doc: "The share of a route's slots in use that same-operator retries may take at once",
  },
  {
    name: "RETRY_CONCURRENCY_MIN",
    key: "retryConcurrencyMin",
    workers: ["gateway"],
    type: "int",
    default: "3",
    min: 0,
    max: 100000,
    source:
      "GRAY_RETRY_CONCURRENCY_MIN, default 3 (config/requests.rs): Envoy's `RetryBudget` `min_retry_concurrency` 3 (circuit_breaker.proto). Maximum: an " +
      "offer's largest max_concurrency (crates/gray-control/src/provider_applications.rs:378, 1..=100000): no route has more slots, so a larger minimum " +
      "bounds nothing more. The server's bound by GRAY_MAX_INFLIGHT has no Worker counterpart: an isolate has no process-wide slot count.",
    platform:
      "At most an offer's largest max_concurrency, 100,000 (no route has more slots), where the server's bound is its semaphore's (tokio " +
      "Semaphore::MAX_PERMITS), which a Worker has no counterpart of, checked against GRAY_MAX_INFLIGHT.",
    doc: "The fewest same-operator retries at a route that may run at once, whatever its load",
  },
  // Rests (the server's config/requests.rs "rests"; docs/runtime-operations.md "Rests"; @gray/errors rests.ts): how
  // long a route that failed for a known cause is passed over. The defaults are magpie's constants
  // (github.com/yetone/magpie, src/internal/gateway/routing.go), with the reasons its comments give; the key's is the
  // lead's. Each is at most a calendar month (31 days), the longest allowance window a vendor states.
  {
    name: "REST_RATE_MAX_SECONDS",
    key: "restRateMaxSeconds",
    workers: ["gateway"],
    type: "int",
    default: "3600",
    min: 1,
    max: 2678400,
    source: "GRAY_REST_RATE_MAX_SECONDS, default 3600 (config/requests.rs): magpie's `longestWait`, \"the most a vendor's own 'try again at' is trusted\". At most 31 days.",
    doc:
      "The longest rest a rate limit gets from the reset its upstream states (Retry-After, a rate-limit reset header, its error's text); a rate " +
      "limit that states none keeps the circuit alone",
  },
  {
    name: "REST_QUOTA_SECONDS",
    key: "restQuotaSeconds",
    workers: ["gateway"],
    type: "int",
    default: "900",
    min: 1,
    max: 2678400,
    source: "GRAY_REST_QUOTA_SECONDS, default 900 (config/requests.rs): magpie's `quotaRest`, \"out of quota, with no word of when it resets\". At most 31 days.",
    doc: "How long an endpoint (or only its model, when the upstream names it) rests after its allowance was used up, when the upstream states no reset",
  },
  {
    name: "REST_QUOTA_MAX_SECONDS",
    key: "restQuotaMaxSeconds",
    workers: ["gateway"],
    type: "int",
    default: "691200",
    min: 1,
    max: 2678400,
    source:
      "GRAY_REST_QUOTA_MAX_SECONDS, default 691200 (config/requests.rs): magpie's `longestQuota`, \"a week's window, and a day over\", so that a reset " +
      "time read wrong does not bench the account. At most 31 days.",
    doc: "The longest rest a used-up allowance gets from the reset its upstream states",
  },
  {
    name: "REST_CREDIT_SECONDS",
    key: "restCreditSeconds",
    workers: ["gateway"],
    type: "int",
    default: "1800",
    min: 1,
    max: 2678400,
    source: "GRAY_REST_CREDIT_SECONDS, default 1800 (config/requests.rs): magpie's `creditRest`, \"out of credit: until someone tops it up\". At most 31 days.",
    doc: "How long an endpoint rests after its upstream refused its balance or payment (402, insufficient balance)",
  },
  {
    name: "REST_AUTH_SECONDS",
    key: "restAuthSeconds",
    workers: ["gateway"],
    type: "int",
    default: "1800",
    min: 1,
    max: 2678400,
    source: "GRAY_REST_AUTH_SECONDS, default 1800 (config/requests.rs): the lead's 30 minutes (2026-10-21); a key refused rests until the key changes, which makes new routes at once, or this long. At most 31 days.",
    doc: "How long an endpoint rests after its upstream refused its key (401, invalid key); a rotated key or a changed configuration serves at once",
  },
  {
    name: "REST_RESTRICTED_SECONDS",
    key: "restRestrictedSeconds",
    workers: ["gateway"],
    type: "int",
    default: "7200",
    min: 1,
    max: 2678400,
    source: "GRAY_REST_RESTRICTED_SECONDS, default 7200 (config/requests.rs): magpie's `restrictedRest`, an account its vendor restricted \"is out until the vendor lifts it, which takes an appeal, not a wait\". At most 31 days.",
    doc: "How long an endpoint rests after its upstream account was suspended or banned by its vendor",
  },
  {
    name: "ERROR_TEXT_FALLBACK",
    key: "errorTextFallback",
    workers: ["gateway"],
    type: "enum",
    values: ERROR_TEXT_FALLBACK_MODES,
    default: "on",
    source:
      "GRAY_ERROR_TEXT_FALLBACK, default on (config/requests.rs): the owner's decision of 2026-10-29 that suppliers' failures are read by " +
      "error codes, with the words as a fallback until no endpoint needs them (docs/supplier-error-codes.md, \"Removing the text fallback\").",
    doc:
      "Whether a supplier's failure that no error code decides is read by its message's words, the legacy reading (docs/supplier-error-codes.md): " +
      "on reads them and records each failure they decided as legacy_text; off reads codes and statuses only, so an uncoded failure keeps its " +
      "circuit alone and rests nothing",
  },
  {
    name: "UPSTREAM_ATTEMPT_SECONDS",
    key: "upstreamAttemptSeconds",
    workers: ["gateway"],
    type: "int",
    default: "0",
    shown: "unset",
    min: 0,
    max: 3599,
    source:
      "GRAY_UPSTREAM_ATTEMPT_SECONDS, unset by default (config/requests.rs; opt-in, like Envoy's `per_try_timeout`, which has no default); 0 here is " +
      "unset. Below UPSTREAM_HEADER_MS when set (a cross check): an attempt bound as long as the whole wait for an answer bounds nothing. " +
      "GRAY_UPSTREAM_CONNECT_SECONDS has no counterpart: a Worker's fetch has no connect timeout of its own (a refused connection fails at once, a " +
      "hanging one is bounded by the attempt's deadline).",
    platform:
      "Unset is written 0 here, the default of an int var, where the server's reader leaves the value out (from 1); at most 3,599, under the " +
      "longest UPSTREAM_HEADER_MS (an hour), where the server bounds it by its own header bound in a check between the two (from any u64).",
    doc:
      "Bounds a streamed attempt until its first bytes after the response headers, while an operator not yet tried can take the request and the " +
      "route's measured time to first token is not longer; shorter than the wait for the response headers",
  },
  {
    name: "ENDPOINT_RECOVERY_WAIT_MS",
    key: "endpointRecoveryWaitMs",
    workers: ["gateway"],
    type: "int",
    default: "10000",
    min: 1,
    max: 3600000,
    source:
      "The server's RankingConfig::recovery_wait_ms, 10,000 (crates/gray-gateway/src/ranking.rs, 1a52b95b): a probe still out after it is no evidence " +
      "of failure. At most the probe lease, ENDPOINT_PROBE_LEASE_SECONDS (a cross check, as the server's config check).",
    doc:
      "How long the recovery probe of an endpoint holds back requests with nowhere else to go, from when it went out: then they go on as trials (and at " +
      "once when it answered); a probe that fails ends their wait with 503 all_endpoints_in_recovery.",
  },
  // The tool gate: workers/packages/trust, docs/cloudflare-native/trust.md.
  {
    name: "TRUST_REGEX_COMPILE_MAX_BYTES",
    key: "trustRegexCompileMaxBytes",
    workers: ["gateway"],
    type: "int",
    default: "10485760",
    min: 10485760,
    max: 16777216,
    source:
      "10 MiB, measured in a fresh instance of the engine's build (workers/vendor/rregex-nowee; docs/cloudflare-native/trust.md section 3): the " +
      "patterns of real tool schemas peak at 64 KiB, a Unicode `.` at 320 KiB, x{65535} (the largest counted repetition Rust accepts) at 9.3 MiB, " +
      "so every trust-schema fixture decides as Rust; ^\\p{L}{150}$ (which Rust accepts) at 20.5 MiB, and patterns Rust refuses for size at up to " +
      "50 MiB before refusing. Any engine instance holds at most its start (1.44 MiB), the compiled-pattern cache (16 MiB), one compile and one " +
      "search's caches (4.25 MiB, regex's defaults): 31.7 MiB at this budget. Minimum: the default, since below it x{65535} would be refused " +
      "(whether a pattern parses no longer depends on the budget). Maximum: the cache, so every pattern a budget allows can be kept.",
    doc:
      "The most memory one compile of a tool schema's regex may take. A new pattern that needs more than 1 MiB is compiled first in a fresh " +
      "engine instance whose memory can grow by this much; a pattern that needs more is refused like one past Rust's size limit " +
      "(trust_invalid_tool_schema at admission). Compiled patterns are kept in a bounded cache that frees what falls out.",
  },
  {
    name: "TRUST_SCHEMA_COMPILE_BUDGET_MS",
    key: "trustSchemaCompileBudgetMs",
    workers: ["gateway"],
    type: "int",
    default: "1500",
    min: 250,
    max: 30000,
    source:
      "Estimated, not timed (Workers' clock does not move during CPU work): the tool gate counts a schema's values and charges each the most " +
      "a value of its draft took to compile, 300 us (draft 4) to 1,200 us (2019-09), measured in Node 26 (docs/cloudflare-native/trust.md " +
      "section 4.3). The largest real-shaped tool schema of the trust-schema fixtures estimates 10.3 ms (measured 3.3 ms); 1,500 ms lets a " +
      "request declare 128 of them, OpenAI's documented cap on functions per request, and holds an isolate at most that long per request. " +
      "Minimum: 22 such tools (the 22-tool request of trust.md 4.3) estimate 226 ms. Maximum: the Workers CPU limit's default, 30 s per " +
      "request (C1).",
    doc:
      "The estimated time to compile one request's declared tool schemas. A compile blocks every other request of the isolate while it runs; " +
      "past this the request is refused trust_tool_schemas_too_complex before anything is compiled. The Rust gate has no such bound.",
  },
  {
    name: "TRUST_SCHEMA_CACHE_SUBSCHEMAS",
    key: "trustSchemaCacheSubschemas",
    workers: ["gateway"],
    type: "int",
    default: "1600",
    min: 1024,
    max: 26214,
    source:
      "A compiled validator holds 0.7 KiB (empty subschemas) to 2.5 KiB (real-shaped tool schemas, 19.6 KiB for about 8 values) per value of its " +
      "schema, measured in Node 26 (docs/cloudflare-native/trust.md section 4.3): 1,600 values is at most 4 MiB of the isolate's 128 MB (C1). " +
      "Minimum: the 128 calls one answer may carry (MAX_TOOLS, trust.rs line 31), each to a different real-shaped tool of about 8 values. " +
      "Maximum: 64 MiB at 2.5 KiB, half the isolate.",
    doc:
      "How many schema values (JSON objects and booleans) the compiled validators kept across requests may hold. What falls out is compiled " +
      "again when an answer calls its tool.",
  },
  {
    name: "TRUST_VERDICT_CACHE_KEY_UNITS",
    key: "trustVerdictCacheKeyUnits",
    workers: ["gateway"],
    type: "int",
    default: "1048576",
    min: 65536,
    max: 8388608,
    source:
      "1 Mi UTF-16 units of keys, about 2 MiB of the isolate's 128 MB (C1), for each of three maps: schema verdicts, pattern translations, " +
      "patterns the regex build refused (docs/cloudflare-native/trust.md section 4.3). Minimum: one schema at the 64 KiB limit " +
      "(trust.rs MAX_SCHEMA_BYTES). Maximum: 16 MiB each.",
    doc:
      "The bound of each of the tool gate's maps of verdicts by schema or pattern text. Agents send the same tool schemas with every request; " +
      "what falls out is worked out again.",
  },
  {
    name: "ISOLATE_TABLE_ENTRIES",
    key: "isolateTableEntries",
    workers: ["gateway"],
    type: "int",
    default: "4096",
    min: 64,
    max: 65536,
    source:
      "Memory: an entry of these tables takes about 110 bytes of heap with its key (measured 2026-10-19: 109 bytes with lru-cache 11.5.3, " +
      "92 with a Map, 41-character keys built as the gateway builds them, Node 26.10, the V8 of workerd), so a table of 4,096 holds about " +
      "0.45 MB and the three about 1.3 MB of the isolate's 128 MB (C1). An entry that falls out costs no call: a count is learned again " +
      "from the next answer (the shard a count of 1 points at, index 0, always exists and answers with the count). Maximum: about 21 MB " +
      "for the three, a sixth of the isolate.",
    doc:
      "The most entries each of the gateway isolate's learned tables keeps, the least recently used going first: K per workspace and " +
      "region (@gray/account ShardCountTable), shards per endpoint and region, and the home shards a degraded admission alerted " +
      "(gateway/src/tables.ts). Without a bound they would grow with every workspace and endpoint an isolate ever served.",
  },
  {
    name: "TRUST_POLICY",
    key: "trustPolicy",
    workers: ["gateway"],
    type: "text",
    default: "{}",
    textCheck: jsonDocumentProblem,
    source:
      "The server's tool gate policy, the JSON document of GRAY_TRUST_POLICY_FILE read with serde_json (crates/gray-gateway/src/config/mod.rs:460); " +
      "unset there it is the policy's Default, which `{}` reads as: enforce mode, tools authorised by the request's own declarations, no " +
      "secret markers (docs/cloudflare-native/trust.md section 2). Kept as a deploy-time document, as the server keeps a file. Here only " +
      "its JSON is checked; the gateway compiles it with @gray/trust at an isolate's first request, and a document the server would refuse " +
      "fails every request rather than serving without the gate.",
    doc:
      "The tool gate's policy (workers/gateway/src/trust.ts): mode (enforce, audit, off), allowed tools with their operator schemas, URL and " +
      "command rules, secret markers.",
  },
  {
    name: "CONTINUATION_BUCKETS",
    key: "continuationBuckets",
    workers: ["gateway"],
    type: "int",
    default: "256",
    min: 1,
    max: 1024,
    check: powerOfTwo,
    source:
      "Storage: a binding takes about 240 bytes in a store's SQLite (measured in workerd with random ids, " +
      "workers/packages/continuation/test/workerd/store.test.ts); one object holds at most 10 GB (C20). Sized for the upper-bound shape " +
      "(docs/cloudflare-native.md section 10, shape B: busy all day): a workspace at 2,000 requests a second (the owner's figure, " +
      "docs/cloudflare-native.md section 0), every reply a stored Responses reply, binds 5.2 billion in the 30 days a binding lives, " +
      "about 1.24 TB: 125 buckets at the hard limit. A new count takes full effect only after those 30 days (old bindings stay in their " +
      "buckets until they expire), so a bucket must be able to take twice its load meanwhile: at most half the limit, 249 buckets, " +
      "rounded up to 256 (4.9 GB each in that shape). A bucket that fills refuses bindings, which are best effort (continuation 404 later). " +
      "Calls: at most four a request (two references looked up, two bound), 8,000 a second, against a third (scaling.md section 5's rule) " +
      "of the about 930 calls a second a single object took with writes (E3-3, m0/raw/hot-one-object-20261017.jsonl) need 26; storage " +
      "decides. Maximum: four times the default; each further power of two adds one call to every lookup that misses. " +
      "Powers of two only: a bucket's references then split between it and one new bucket when the count doubles.",
    doc:
      "Continuation stores per workspace and region (@gray/continuation). A binding goes to bucket SHA-256(kind, reference) mod this count; a " +
      "lookup that misses also asks the reference's bucket under every other power of two up to the maximum, so the count can change " +
      "without losing bindings.",
  },
  {
    name: "CONTINUATION_CALL_TIMEOUT_MS",
    key: "continuationCallTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 100,
    max: 3000,
    source:
      "A Durable Object call across regions took 156-229 ms at the median (E3-2, scaling.md section 1), and a " +
      "lookup that misses asks the other regions; 1 s leaves room for a slow one (the account root's calls, measured to 3 s in the staging " +
      "soak r4, wait longer: ACCOUNT_ROOT_CALL_TIMEOUT_MS). It bounds a whole lookup (the local store, then on a miss " +
      "the other stores in parallel, on one deadline) and a whole binding; a request's references are looked up in parallel, so a request " +
      "waits at most this long here. Minimum: 20 times the 2-5 ms of a same-region call. Maximum: the 3 s a request may spend on admission " +
      "before dispatch (ACCOUNT_ADMIT_BUDGET_MS default).",
    doc:
      "How long the gateway waits for a continuation lookup (the local store and, on a miss, the other stores, on one deadline) or a " +
      "binding. A lookup with no answer is 503 continuation_lookup_unavailable; a binding " +
      "with no answer is left unbound (best effort, as in the server version).",
  },
  {
    name: "TOOL_CALL_ID_MINTING",
    key: "toolCallIdMinting",
    workers: ["gateway"],
    type: "enum",
    values: ["off", "on"],
    default: "off",
    source:
      "The server's GRAY_TOOL_CALL_ID_MINTING (crates/gray-gateway/src/config/tool_call_ids.rs, default off; docs/design/tool-call-ids.md " +
      "\"Rollout\"): a build that restores handles ships with it off, and it is turned on once every region runs one. The server runs it on " +
      "in production since #69 (a7ee93d0, deploy/runtime/compose.production.yaml); this deployment turns it on only after it restores every " +
      "handle the server issued (docs/cloudflare-native/tool-call-ids.md section 6).",
    doc:
      "Whether the gateway issues handles in place of tool-call ids not every client passes back intact; off still restores the handles issued " +
      "before. Turn it on only once every region runs a gateway that restores them",
  },
  {
    name: "TOOL_CALL_ID_CACHE_BYTES",
    key: "toolCallIdCacheBytes",
    workers: ["gateway"],
    type: "int",
    default: "4194304",
    min: 0,
    max: 16777216,
    source:
      "The server keeps up to 64 MiB of handles a process (GRAY_TOOL_CALL_ID_CACHE_MIB, crates/gray-gateway/src/config/tool_call_ids.rs) at " +
      "about 200 bytes a handle. An isolate has 128 MB in all (C1), of which the answers in flight may hold ANSWER_HELD_MAX_BYTES (64 MiB) " +
      "and a parse BODY_PARSE_MAX_BYTES at 2.36 times (m0/memory.md): 4 MiB holds about 20,000 handles, the conversations an isolate served " +
      "in its last minutes, and the maximum keeps the cache at an eighth of the isolate. 0: no cache, every lookup asks its shards.",
    doc:
      "Bytes of an isolate's memory for tool-call id handles it looked up or issued in the last ten minutes, so that a conversation's next " +
      "turn served by the same isolate asks no shard (each entry weighed by its strings, its original and a fixed overhead).",
  },
  {
    name: "TOOL_CALL_ID_CALL_TIMEOUT_MS",
    key: "toolCallIdCallTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 100,
    max: 3000,
    source:
      "As CONTINUATION_CALL_TIMEOUT_MS: a Durable Object call across regions took 156-229 ms at the median (E3-2, scaling.md section 1), and a " +
      "handle a request sends back may live in the region that issued it; 1 s leaves room for a slow one. A request's shards are asked in " +
      "parallel on one deadline, so a lookup or a write waits at most this long. Minimum: 20 times the 2-5 ms of a same-region call. Maximum: " +
      "the 3 s a request may spend on admission before dispatch (ACCOUNT_ADMIT_BUDGET_MS default).",
    doc:
      "How long the gateway waits for a request's tool-call id shards: a lookup with no answer is 503 tool_call_id_lookup_unavailable before " +
      "any provider sees the request; a write with no answer fails the answer with tool_call_id_store_unavailable, not charged.",
  },
  // The model APIs and video jobs (workers/packages/media, workers/gateway/src/media.ts and
  // src/workflows/video-job.ts; docs/cloudflare-native/media.md). The server values cited are
  // crates/gray-gateway/src/inference.rs, apis/images.rs, apis/video.rs, apis/video/poll.rs and
  // apis/video/content.rs.
  {
    name: "MEDIA_RESPONSE_BYTES",
    key: "mediaResponseBytes",
    // The console's model-API checks read an answer under the same bound (@gray/verifier `ServingBounds`).
    workers: ["gateway", "console"],
    type: "int",
    default: "33554432",
    min: 1048576,
    max: 33554432,
    source:
      "Today's server value, 32 MiB (inference.rs MEDIA_RESPONSE_LIMIT), which the server marks picked, not sourced (docs/limits.md, open items). " +
      "Maximum: not raised before E2 measures what an isolate holds (128 MB per isolate, C1; docs/cloudflare-native.md section 3). Minimum: " +
      "one embedding at the widest `dimensions` still fits (16,384 floats at 33 bytes each plus the item and envelope bytes, apis/embeddings.rs " +
      "MAX_DIMENSIONS, FLOAT_BYTES, ITEM_BYTES, ENVELOPE_BYTES, about 0.5 MiB); below it the embeddings API would refuse every request.",
    doc:
      "The largest answer the model APIs read whole: speech audio, embeddings, image answers with their inlined downloads, transcriptions, " +
      "video creates excepted (1 MiB, a contract constant shared with the admission probe). It also sizes the largest embeddings batch. " +
      "The console's checks read a speech or image answer under the same bound, so that admission reads what serving reads: set it alike on both.",
  },
  {
    name: "MEDIA_DOWNLOAD_BYTES",
    key: "mediaDownloadBytes",
    // The console's image checks download an answer's media under the same budget.
    workers: ["gateway", "console"],
    type: "int",
    default: "25165824",
    min: 1048576,
    max: 25165824,
    source:
      "Today's server value, 24 MiB (apis/images.rs DOWNLOAD_LIMIT: the base64 of the downloads then stays within the 32 MiB answer limit, " +
      "a cross check here). Maximum: the server value, for the same reason as MEDIA_RESPONSE_BYTES. Minimum: one 1024x1024 PNG, the size " +
      "every OpenAI image model offers (a few MB), still downloads.",
    doc:
      "Most bytes downloaded for one answer's URL-only images, which the gateway inlines so the customer never sees a vendor URL. The console's " +
      "image checks download an answer's images under the same budget, as serving would before it delivered the answer: set it alike on both.",
  },
  {
    name: "MEDIA_DOWNLOAD_REDIRECTS",
    key: "mediaDownloadRedirects",
    // The console's image checks follow as many.
    workers: ["gateway", "console"],
    type: "int",
    default: "3",
    min: 0,
    max: 20,
    source:
      "Today's server value (apis/images.rs MAX_REDIRECTS; each hop is vetted again). Maximum: the Fetch standard's own limit of 20 redirects " +
      "(https://fetch.spec.whatwg.org/#http-redirect-fetch, step 5).",
    doc:
      "Redirects followed by hand when downloading one image or a video result; each hop passes the egress rules again. The console's image " +
      "checks follow as many when they download an answer's images: set it alike on both.",
  },
  {
    name: "MEDIA_JOB_POLL_START_MS",
    key: "mediaJobPollStartMs",
    workers: ["gateway"],
    type: "int",
    default: "250",
    min: 250,
    max: 2500,
    source:
      "Today's server value (apis/images.rs POLL_START). Range: the server value to ten times it; faster would poll vendors harder than the " +
      "server ever has, slower keeps a finished image waiting longer within the request's deadline.",
    doc: "The first pause between two polls of a vendor's image job (fal, Kling) inside one images request; it doubles up to MEDIA_JOB_POLL_MAX_MS.",
  },
  {
    name: "MEDIA_JOB_POLL_MAX_MS",
    key: "mediaJobPollMaxMs",
    workers: ["gateway"],
    type: "int",
    default: "2000",
    min: 250,
    max: 20000,
    source: "Today's server value (apis/images.rs POLL_MAX). Range: as MEDIA_JOB_POLL_START_MS, up to ten times the server value.",
    doc: "The longest pause between two polls of a vendor's image job inside one images request.",
  },
  {
    name: "VIDEO_POLL_INTERVAL_MS",
    key: "videoPollIntervalMs",
    workers: ["gateway"],
    type: "int",
    default: "5000",
    min: 1000,
    max: 60000,
    source:
      "Today's server cadence: the reconciler advances every pending video job every 5 s (crates/gray-gateway/src/main.rs:101-117). Minimum: " +
      "the server's least time between two polls of one job (apis/video/poll.rs POLL_INTERVAL_MS, 1 s). Maximum: a minute, so a finished " +
      "job is settled within a minute. A cross check keeps one job's polls within the steps a Workflow instance may take.",
    doc: "How long a video job's Workflow sleeps between two upstream polls.",
  },
  {
    name: "VIDEO_POLL_MIN_MS",
    key: "videoPollMinMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 1000,
    max: 60000,
    source:
      "Today's server value (apis/video/poll.rs POLL_INTERVAL_MS: least time between two upstream polls of one job). Range: as " +
      "VIDEO_POLL_INTERVAL_MS, and at most it (a cross check).",
    doc:
      "The least time between two upstream polls of one job, whoever polls: a customer's GET /v1/videos/{id} polls when the last poll is " +
      "this old, the Workflow otherwise.",
  },
  {
    name: "VIDEO_JOB_TTL_SECONDS",
    key: "videoJobTtlSeconds",
    workers: ["gateway"],
    type: "int",
    default: "21600",
    min: 600,
    max: 21600,
    source:
      "Today's server value, 6 hours (apis/video.rs JOB_TTL_SECONDS). Maximum: the server value; with VIDEO_POLL_INTERVAL_MS at 5 s it takes " +
      "at most 8,644 Workflow steps, under the 10,000 a Workflow instance takes by default (https://developers.cloudflare.com/workflows/reference/limits/, " +
      "docs/cloudflare-native/research/cloudflare-facts.md section 3); a cross check holds that. Minimum: the 10 minutes of " +
      "VIDEO_MISSING_GRACE_SECONDS, so a missing job can fail as missing before it expires.",
    doc: "A video job not finished this long after creation fails as `expired` after one last poll, and its hold is released.",
  },
  {
    name: "VIDEO_WATCHDOG_MS",
    key: "videoWatchdogMs",
    workers: ["gateway"],
    type: "int",
    default: "60000",
    min: 5000,
    max: 60000,
    source:
      "The server settles a finished job within its reconciler's 5 s (crates/gray-gateway/src/main.rs:101-117) for as long as the job is " +
      "pending; VIDEO_POLL_INTERVAL_MS's maximum keeps a finished job settled within a minute. The watchdog bounds a lost Workflow to " +
      "the same minute. Minimum: the server's 5 s. Maximum: that minute.",
    doc:
      "While a video job's hold is pending, its record (VideoJobDO) checks this often that the job's Workflow exists and has not " +
      "stopped, and starts or restarts it otherwise.",
  },
  {
    name: "VIDEO_STEP_RETRIES",
    key: "videoStepRetries",
    workers: ["gateway"],
    type: "int",
    default: "5",
    min: 0,
    max: 10000,
    source:
      "The Workflows default step retry limit, 5 (https://developers.cloudflare.com/workflows/build/sleeping-and-retrying/, read " +
      "2026-10-17). Maximum: the 10,000 retries per step that page allows. Zero is allowed: an instance whose step ran out of retries " +
      "is restarted by the watchdog (VIDEO_WATCHDOG_MS).",
    doc: "How often a video job Workflow step (register, poll, settle) is retried before it fails.",
  },
  {
    name: "VIDEO_STEP_RETRY_DELAY_MS",
    key: "videoStepRetryDelayMs",
    workers: ["gateway"],
    type: "int",
    default: "10000",
    min: 1000,
    max: 60000,
    source:
      "The Workflows default first retry delay, 10 s, doubling (https://developers.cloudflare.com/workflows/build/sleeping-and-retrying/, " +
      "read 2026-10-17). Minimum: the server's least time between two polls of one job (VIDEO_POLL_MIN_MS's 1 s). Maximum: a minute, " +
      "within which a finished job should be settled (VIDEO_POLL_INTERVAL_MS source).",
    doc: "The first wait before a failed video job Workflow step is retried; each further retry waits twice as long.",
  },
  {
    name: "VIDEO_STEP_TIMEOUT_MS",
    key: "videoStepTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "600000",
    min: 60000,
    max: 600000,
    source:
      "The Workflows default step timeout, 10 minutes (https://developers.cloudflare.com/workflows/build/sleeping-and-retrying/, read " +
      "2026-10-17); a step's own calls are bounded below it (the poll's 15 s exchange, VIDEO_POLL_TIMEOUT_MS; the settlement's account " +
      "calls, ACCOUNT_ADMIT_BUDGET_MS each). Minimum: a settle step settles and may then release, each within the admission budget, " +
      "whose maximum is 30 s: 2 x 30 s. Maximum: the default.",
    doc: "How long one attempt of a video job Workflow step may run before it counts as failed.",
  },
  {
    name: "VIDEO_MISSING_POLLS",
    key: "videoMissingPolls",
    workers: ["gateway"],
    type: "int",
    default: "3",
    min: 1,
    max: 100,
    source:
      "Today's server value (apis/video/poll.rs MAX_POLL_FAILURES). Maximum: a hundred, still within the polls of one job at the longest " +
      "interval and TTL.",
    doc: "A job the upstream keeps answering \"no such job\" (404 or 410) for fails after this many answers in a row, over VIDEO_MISSING_GRACE_SECONDS.",
  },
  {
    name: "VIDEO_MISSING_GRACE_SECONDS",
    key: "videoMissingGraceSeconds",
    workers: ["gateway"],
    type: "int",
    default: "600",
    min: 60,
    max: 3600,
    source:
      "Today's server value (apis/video/poll.rs MISSING_GRACE_SECONDS: a job just created, or a briefly misrouting upstream, can answer 404 for " +
      "a moment). Range: a minute to an hour; at most VIDEO_JOB_TTL_SECONDS (a cross check).",
    doc: "How long an upstream must keep answering \"no such job\" before the job fails as `upstream_job_missing`.",
  },
  {
    name: "VIDEO_CONTENT_BYTES",
    key: "videoContentBytes",
    workers: ["gateway"],
    type: "int",
    default: "536870912",
    min: 1048576,
    max: 536870912,
    source:
      "Today's server value, 512 MiB (apis/video/content.rs CONTENT_LIMIT). The bytes stream through and are not held, so the isolate's " +
      "128 MB (C1) does not bound it. Maximum: the server value.",
    doc: "The largest finished video the gateway proxies; a longer transfer is cut off.",
  },
  {
    name: "VIDEO_CONTENT_HEADERS_MS",
    key: "videoContentHeadersMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 1000,
    max: 120000,
    source: "Today's server value (apis/video/content.rs HEADERS_TIMEOUT). Range: one second to two minutes.",
    doc: "The longest wait for an upstream's response headers when fetching a finished video or one of its content steps.",
  },
  {
    name: "VIDEO_CONTENT_IDLE_MS",
    key: "videoContentIdleMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 1000,
    max: 120000,
    source: "Today's server value (apis/video/content.rs IDLE_TIMEOUT). Range: one second to two minutes.",
    doc: "The longest wait for the next chunk of a finished video's bytes.",
  },
  {
    name: "VIDEO_CONTENT_TOTAL_MS",
    key: "videoContentTotalMs",
    workers: ["gateway"],
    type: "int",
    default: "600000",
    min: 10000,
    max: 1200000,
    source:
      "Today's server value, 10 minutes (apis/video/content.rs TOTAL_TIMEOUT). Maximum: 20 minutes, what a Worker request keeps when the runtime " +
      "is updated (C1, C18 in docs/cloudflare-native.md section 5.6).",
    doc: "The longest whole download of a finished video.",
  },
  {
    name: "VIDEO_CONTENT_HOPS",
    key: "videoContentHops",
    workers: ["gateway"],
    type: "int",
    default: "3",
    min: 1,
    max: 20,
    source:
      "Today's server value (apis/video/content.rs MAX_HOPS: vendor content steps and redirects followed at most). Maximum: the Fetch " +
      "standard's 20 redirects, as MEDIA_DOWNLOAD_REDIRECTS.",
    doc: "Vendor content steps (a JSON answer naming the next call) and redirects followed at most to reach a finished video's bytes.",
  },
  // Snapshot, projection, request index and reconciliation: gray-jobs (workers/jobs,
  // docs/cloudflare-native/jobs.md), and the gateway's side of the snapshot (@gray/snapshot).
  {
    name: "CONFIG_REBUILD_MS",
    key: "configRebuildMs",
    workers: ["jobs"],
    type: "int",
    default: "2000",
    min: 500,
    max: 30000,
    source:
      "Today's snapshot refresh runs every 2 s (crates/gray-gateway/src/background.rs:67; docs/cloudflare-native.md sections 2.2 and 4.1). " +
      "The maximum is half of the gateway's alert age (CONFIG_ALERT_AGE_MS, 60 s by default, the server's REFRESH_TTL, " +
      "crates/gray-gateway/src/inference.rs:120), so one failed rebuild never raises the stale-snapshot alert. The minimum keeps a rebuild, a " +
      "fixed number of queries at about 6 ms each near the database (docs/cloudflare-native/m0/database.md), from running back to back.",
    doc: "How often ConfigDO rebuilds the key, route and offer snapshot from PostgreSQL. A new version is published only when the content changed.",
  },
  {
    name: "JOBS_LOCATION_HINT",
    key: "jobsLocationHint",
    // The gateway (the snapshot's last source) and the console (publish, operations, the chain reader's
    // and the grants' state) reach ConfigDO and the RoundDOs too, and whichever call comes first places
    // the object for good (C51): staging's ConfigDO and all six RoundDOs were created in Singapore by a
    // call without a hint and rebuilt across the Pacific (docs/cloudflare-native/gateway.md section 14).
    workers: ["jobs", "gateway", "console"],
    type: "enum",
    values: LOCATION_HINTS,
    default: "wnam",
    source:
      "The database is TencentDB in Silicon Valley, 3 ms from AWS us-west-1 (docs/infrastructure-plan.md:58); wnam is the location hint " +
      "for western North America (C51). Placement does not apply to Durable Objects, which run where they were created (C9). Measured " +
      "2026-10-22: a new wnam object is in SJC, 2-3 ms from a Worker there; staging's ConfigDO, created without a hint in Singapore, is 167 ms " +
      "from SJC and took 3.3 s per rebuild (gateway.md section 14).",
    doc:
      "Where gray-jobs' objects that query PostgreSQL are created: ConfigDO (every CONFIG_REBUILD_MS), SchedulerDO (the reconciliation) and " +
      "the RoundDOs (the background ledger: the chain reader, the hourly rounds, the mints and grants, debt mode's readings). The gateway " +
      "and the console pass the same hint on every call they make to ConfigDO and the RoundDOs, so none of them can create one elsewhere; " +
      "the production check holds the three equal.",
  },
  {
    name: "CONFIG_REPLICA_CHECK_MS",
    key: "configReplicaCheckMs",
    workers: ["jobs"],
    type: "int",
    default: "2000",
    min: 250,
    max: 30000,
    source:
      "docs/cloudflare-native.md section 2.4, step 1: the version is checked at most every 2 s, as today's refresh runs. The maximum is half " +
      "of the gateway's alert age (CONFIG_ALERT_AGE_MS, 60 s by default, the server's REFRESH_TTL, crates/gray-gateway/src/inference.rs:120), " +
      "as for CONFIG_REBUILD_MS.",
    doc:
      "How long a regional ConfigReplicaDO answers from its copy before it asks ConfigDO for the current version again. It asks only when " +
      "an isolate asks it, so an idle region costs nothing.",
  },
  {
    name: "CONFIG_REPLICAS_PER_REGION",
    key: "configReplicasPerRegion",
    workers: ["gateway"],
    type: "int",
    default: "4",
    min: 1,
    max: 32,
    source:
      "docs/cloudflare-native.md section 4.1: 300 isolates checking every 2 s make 150 calls a second (research/map-control.md), and 2-4 " +
      "replicas per region suffice [estimated]; one object takes about 1,000 calls a second (scaling.md section 1). The maximum is the largest " +
      "shard count measured (ACCOUNT_SHARD_COUNT).",
    doc: "How many ConfigReplicaDO copies each region has; an isolate draws one at random when it starts and keeps it for its life.",
  },
  {
    name: "CONFIG_CALL_TIMEOUT_MS",
    key: "configCallTimeoutMs",
    workers: ["gateway", "jobs"],
    type: "int",
    default: "5000",
    min: 250,
    max: 20000,
    source:
      "A Durable Object call across regions took 156-229 ms at the median (scaling.md section 1, m0/raw/dolat-online-20261017.jsonl). A " +
      "snapshot check can also carry the snapshot, up to SNAPSHOT_MAX_BYTES (16 MiB), whose transfer time is not measured yet [estimated; E7 in " +
      "staging]; 5 s is over 20 times the slowest median. Minimum: just above that median. Maximum: an isolate tries three sources in one " +
      "check (its replica, the next one, ConfigDO), and three of these fit in the alert age's 60 s default (CONFIG_ALERT_AGE_MS), so hung " +
      "replicas alone never raise the stale-snapshot alert while ConfigDO answers.",
    doc:
      "How long one call of the snapshot plane may take before it is given up: an isolate's check (then the next source is tried), a " +
      "replica's sync with ConfigDO, and each publication ConfigDO sends to an account or endpoint root (sent again after the next rebuild).",
  },
  {
    name: "CONFIG_HEDGE_MS",
    key: "configHedgeMs",
    workers: ["gateway"],
    type: "int",
    default: "1000",
    min: 50,
    max: 20000,
    source:
      "The slowest healthy replica call measured, a new object's start included: SJC to the wnam replicas 6-46 ms, a new object 0.2-0.66 s " +
      "before it runs (docs/cloudflare-native/gateway.md section 14); 1 s is above both, so a healthy replica is never hedged " +
      "(docs/request-path-availability.md section 4.2, M4). Minimum: above the slowest same-region replica call measured (46 ms). Maximum: " +
      "CONFIG_CALL_TIMEOUT_MS's; cross checks keep it at most CONFIG_CALL_TIMEOUT_MS (a later hedge is the next source in turn) and every " +
      "source of a check asked within REQUEST_PRE_BUDGET_MS.",
    doc:
      "How long an isolate's snapshot check waits for a source before it also asks the next one: its replica, after this the region's next " +
      "replica, after twice this ConfigDO, the first answer that serves taking the check (a source that fails or cannot serve it is followed " +
      "at once). A new isolate's read of the writer's copy in Workers KV is joined by the replicas after this long too " +
      "(docs/request-path-availability.md section 4.2, M4 and M5).",
  },
  {
    name: "CONFIG_PUBLISH_CONCURRENCY",
    key: "configPublishConcurrency",
    workers: ["jobs"],
    type: "int",
    default: "16",
    min: 1,
    max: 64,
    source:
      "Each publication goes to another object (a workspace's account root, a capacity's endpoint root), and one object takes about 1,000 " +
      "calls a second (scaling.md section 1), so the receivers are not the bound. At the 156-229 ms median of a call across regions (scaling.md " +
      "section 1) 16 in flight send about 70 a second, so a first publication of 1,000 keys takes about 15 s of rebuilds, revocations first " +
      "[estimated]. The maximum keeps ConfigDO's own pending calls few.",
    doc: "How many publications ConfigDO has in flight at once after a rebuild (revocations first, then withdrawals, then the rest).",
  },
  {
    name: "JOBS_STATEMENT_TIMEOUT_MS",
    key: "jobsStatementTimeoutMs",
    workers: ["jobs"],
    type: "int",
    default: "15000",
    // The served-value trigger's SET lock_timeout = '1s' (workers/db/migrations/0051_served_value_at_settlement.sql)
    // depends on this: its handler catches every error but this timeout's (57014), so the statement must outlast the
    // trigger's lock wait by a margin, or a count waiting on its row rolls the settlement back (review r8 whole-PR
    // finding 1).
    min: 5000,
    max: 300000,
    source:
      "The server gives one settlement write 5 s and a request waits 15 s for its completion (AnswerLimits, crates/gray-ledger/src/usage.rs:" +
      "194-216); a projection message of a few hundred items fits the 15 s many times over, and a statement past it is stuck behind a lock " +
      "and is better retried. The maximum is well inside the 15 minutes a queue consumer may run (C33). The minimum, 5 s, keeps the " +
      "statement well past the served-value trigger's 1 s lock_timeout (workers/db/migrations/0051_served_value_at_settlement.sql), whose " +
      "handler catches every error but statement_timeout's (57014): a count that waits on its row gives up first, and its settlement stands.",
    doc: "statement_timeout, set with SET LOCAL in every transaction of gray-jobs (never a session SET: Hyperdrive does not keep sessions, m0/database.md).",
  },
  {
    name: "ROUTE_ACTIVITY_SLOTS",
    key: "routeActivitySlots",
    workers: ["jobs"],
    type: "int",
    default: "8",
    min: 1,
    max: 64,
    source:
      "The request-index consumer adds each batch's routes to route_activity and model_demand in the batch's transaction " +
      "(workers/db/migrations/0026_route_activity.sql), holding a busy route's row from the upsert to the commit; Queues runs up to 250 " +
      "consumer invocations at once (developers.cloudflare.com/queues/platform/limits/, read 2026-10-17). A batch takes one slot at random, " +
      "so 8 slots let about 8 transactions of one route commit without waiting for each other, and the console reads at most 8 rows a " +
      "route and 8 a model-minute [estimated]. The maximum keeps the console's reads small.",
    doc: "How many rows the request-index consumer spreads one route's activity and one model-minute's demand over (route_activity, model_demand `slot`).",
  },
  {
    name: "QUEUE_RETRY_BASE_SECONDS",
    key: "queueRetryBaseSeconds",
    workers: ["jobs"],
    type: "int",
    default: "2",
    min: 1,
    max: 60,
    source: "Durable Object alarms retry from 2 s with exponential back-off (C22); the queue consumers start their back-off at the same 2 s.",
    doc:
      "A message whose processing failed (PostgreSQL away, a deadlock) is retried after this many seconds, doubling per attempt. The " +
      "reconciliation backs off the same way after a failed step or a workspace it could not read.",
  },
  {
    name: "QUEUE_RETRY_MAX_SECONDS",
    key: "queueRetryMaxSeconds",
    workers: ["jobs"],
    type: "int",
    default: "600",
    min: 60,
    max: 86400,
    source:
      "Queues allow at most 100 retries and a retry delay of up to 24 hours (C33, developers.cloudflare.com/queues/platform/limits/, read " +
      "2026-10-17). At 10 minutes a message survives about 16 hours of PostgreSQL outage before it goes to the dead letter queue, longer " +
      "than a failover or an overnight maintenance window. The maximum is the 24-hour delay limit.",
    doc: "The longest wait between two attempts at a message, and between two failed steps of the reconciliation.",
  },
  {
    name: "RECONCILE_INTERVAL_MS",
    key: "reconcileIntervalMs",
    workers: ["jobs"],
    type: "int",
    default: "3600000",
    min: 60000,
    max: 86400000,
    source: "docs/cloudflare-native.md section 5.3: jobs compares the shards, the roots and PostgreSQL every hour. The maximum is a day.",
    doc: "How often the reconciliation pass starts.",
  },
  {
    name: "RECONCILE_WAIT_MS",
    key: "reconcileWaitMs",
    workers: ["jobs"],
    type: "int",
    default: "300000",
    min: 10000,
    max: 3600000,
    source:
      "A shard retries a failed send at most every 60 s (PROJECTION_RETRY_MAX_MS) and a consumer waits at most 60 s to fill a batch (C33), " +
      "so a working pipeline delivers within a couple of minutes; 5 minutes leaves room for retries. The maximum is the reconciliation's own hour.",
    doc:
      "How long the reconciliation waits for PostgreSQL to reach what a shard had written when it was read; past it the shard is reported " +
      "as behind.",
  },
  {
    name: "RECONCILE_STEP_MS",
    key: "reconcileStepMs",
    workers: ["jobs"],
    type: "int",
    default: "60000",
    min: 1000,
    max: 600000,
    source:
      "An alarm may run for 15 minutes (C1); a step stops starting new workspaces after this long and the next alarm continues, so one pass " +
      "never nears the limit. The maximum is two thirds of it.",
    doc: "How long one alarm of the reconciliation pass works before it schedules the next.",
  },
  // ---------------------------------------------------------------- gray-console and gray-identity
  {
    name: "ORIGIN",
    key: "origin",
    workers: ["console", "identity"],
    type: "text",
    textCheck: originProblem,
    source:
      "Required, no default: GRAY_ORIGIN of the server (crates/gray-gateway/src/config/mod.rs:331-343), the same rule: an http(s) origin " +
      "without user, path, query or fragment. HTTPS outside DEPLOY_ENV local is checked by the console (workers/console/src/settings.ts).",
    platform:
      "Required everywhere, where the server defaults to http://127.0.0.1:4173 outside production: that is a local run of the server's binary with " +
      "its console's dev port, and a Worker has no such run; each wrangler environment, local included, names it in its vars.",
    doc:
      "The console's address: people sign in there and a wallet's sign-in message names its host, a write to /api/v1 must come from it (Origin), " +
      "its session cookie is always Secure (a __Host- cookie), so a browser keeps it over https, or over http at localhost or 127.0.0.1 in Chromium and Firefox, " +
      "and Gray's texts link to its pages",
  },
  {
    name: "API_ORIGIN",
    key: "apiOrigin",
    workers: ["console"],
    type: "text",
    textCheck: originProblem,
    source:
      "Required, no default: GRAY_API_ORIGIN of the server (crates/gray-gateway/src/config/origins.rs), required in production there, the same " +
      "rule: an http(s) origin without user, path, query or fragment. The Workers name it everywhere, as they name ORIGIN: an address is never " +
      "guessed. HTTPS outside DEPLOY_ENV local, and ORIGIN itself or another host name, are checked by the console (workers/console/src/settings.ts).",
    platform:
      "Required everywhere, where the server defaults to GRAY_ORIGIN outside production: each wrangler environment, local included, names it in its " +
      "vars, as it names ORIGIN.",
    doc:
      "The model API's address: every base URL Gray gives clients names it. On another host name than ORIGIN, that host serves only the model API, " +
      "ORIGIN's host serves the console and none of the model API, and the console's pages call the model API there across origins",
  },
  {
    name: "ADMIN_WALLETS",
    key: "adminWallets",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: walletListProblem,
    source: "GRAY_ADMIN_WALLETS of the server (crates/gray-gateway/src/config/mod.rs:371-376): comma-separated, empty by default (no global admin).",
    doc: "Wallets that become global administrators when they sign in (control_admins). The deploy task also syncs the table to this list.",
  },
  {
    name: "ACCESS_TEAM_DOMAIN",
    key: "accessTeamDomain",
    // The content Worker verifies an operator's Access JWT itself, with the console's settings (docs/cloudflare-native/content.md 5.2).
    workers: ["console", "content"],
    type: "text",
    default: "",
    textCheck: accessDomainProblem,
    source:
      "docs/cloudflare-native.md section 7: a Worker with static assets gets no ctx.access, so the console verifies Cf-Access-Jwt-Assertion itself. " +
      "The issuer is https://<team>.cloudflareaccess.com (Cloudflare Access docs, validating JWTs, read 2026-10-17). Empty: no Access check, " +
      "allowed only with DEPLOY_ENV local (workers/console/src/settings.ts).",
    doc: "The Access team domain (<team>.cloudflareaccess.com) whose JWT every console page and /api call must carry. Set with ACCESS_AUD.",
  },
  {
    name: "ACCESS_AUD",
    key: "accessAud",
    workers: ["console", "content"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^[0-9a-f]{64}$/.test(v) ? null : "is not an Access application audience tag (64 lowercase hex digits)"),
    source: "The Access application's AUD tag (64 hex digits, Cloudflare Access docs, validating JWTs, read 2026-10-17); the console application of deploy/terraform-edge/main.tf:183.",
    doc: "The audience the Access JWT must name. Set with ACCESS_TEAM_DOMAIN.",
  },
  {
    name: "IDENTITY_TIMEOUT_MS",
    key: "identityTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "20000",
    min: 1000,
    max: 60000,
    source:
      "The server's client for the identity bridge times out after 20 s (crates/gray-gateway/src/state.rs, reqwest timeout); the bridge itself " +
      "gives a verification 15 s (server/moss-identity/server.mjs timeoutMs). Maximum: a minute, past which a browser sign-in has long given up.",
    doc: "How long the console waits for the identity Worker to issue a challenge or verify a signature; then the sign-in answers 503.",
  },
  {
    name: "IDENTITY_VERIFY_TIMEOUT_MS",
    key: "identityVerifyTimeoutMs",
    workers: ["identity"],
    type: "int",
    default: "15000",
    min: 1000,
    max: 60000,
    source: "server/moss-identity/server.mjs: timeoutMs = 15000, after which the bridge answers 504 TIMEOUT. Maximum as IDENTITY_TIMEOUT_MS.",
    doc: "How long the identity Worker waits for the wallet verifier (which may ask the chain) before it answers TIMEOUT.",
  },
  {
    name: "MOSS_NETWORK",
    key: "mossNetwork",
    workers: ["console", "identity"],
    type: "enum",
    values: ["testnet", "mainnet"],
    default: "testnet",
    source: "GRAY_MOSS_NETWORK of the server (crates/gray-gateway/src/config/mod.rs:298-303), testnet by default; testnet is chain 6343, mainnet 4326.",
    doc: "The MegaETH network of checkout and wallet sign-in. Its chain id is the credit chain's unless CREDIT_CHAIN_ID says otherwise.",
  },
  {
    name: "MOSS_DESTINATION",
    key: "mossDestination",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: optionalAddressProblem,
    source: "GRAY_MOSS_DESTINATION of the server (crates/gray-gateway/src/config/mod.rs:344), unset by default (checkout unavailable).",
    doc: "The address checkout pays to.",
  },
  {
    name: "MOSS_TOKEN_ADDRESS",
    key: "mossTokenAddress",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: optionalAddressProblem,
    source: "GRAY_MOSS_TOKEN_ADDRESS of the server (crates/gray-gateway/src/config/mod.rs:345), unset by default (checkout unavailable).",
    doc: "The USDM token checkout pays with.",
  },
  {
    name: "MOSS_TOKEN_DECIMALS",
    key: "mossTokenDecimals",
    workers: ["console"],
    type: "int",
    default: "18",
    min: 6,
    max: 24,
    source:
      "GRAY_MOSS_TOKEN_DECIMALS of the server, 18 by default (crates/gray-gateway/src/config/mod.rs:382-384); checkout accepts 6 to 24 " +
      "(crates/gray-gateway/src/payments.rs configured()).",
    doc: "Decimals of the checkout token.",
  },
  {
    name: "CREDIT_CONTRACT",
    key: "creditContract",
    workers: ["console"],
    type: "text",
    textCheck: (v) => addressProblem(v),
    source:
      "Required, no default: GRAY_CREDIT_CONTRACT of the server (crates/gray-gateway/src/config/onchain.rs:49), required in production there; " +
      "/api/v1/config states it (docs/openapi.json RuntimeConfig.credit.contract is required).",
    platform:
      "Required everywhere, where the server may leave it unset when it runs without a credit client (no GRAY_CREDIT_URL): the console always runs " +
      "beside the credit Workers it calls through its CREDIT_API binding.",
    doc: "The GrayCredit contract that holds customer and provider credit; must equal the credit Workers' CONTRACT_ADDRESS",
  },
  {
    name: "CREDIT_CHAIN_ID",
    key: "creditChainId",
    workers: ["console"],
    type: "text",
    default: "",
    shown: "the chain of MOSS_NETWORK (6343 testnet, 4326 mainnet)",
    textCheck: (v) => (v === "" || /^[1-9][0-9]{0,15}$/.test(v) ? null : "is not a chain id (a decimal integer from 1), or empty for the MOSS network's"),
    source: "GRAY_CREDIT_CHAIN_ID of the server (crates/gray-gateway/src/config/onchain.rs:57-60): the chain of MOSS_NETWORK by default (6343 testnet, 4326 mainnet).",
    platform:
      "Read as text, empty for MOSS_NETWORK's chain, where the server's reader has a number with a derived default; and a JavaScript number in the " +
      "console's signed calls, so at most 16 digits and a safe integer (2^53 - 1, console/src/settings.ts), where the server reads a u64.",
    doc: "The chain id signed into every call to the credit Workers; must equal their CHAIN_ID",
  },
  {
    name: "WELCOME_CREDIT_MICROUSD",
    key: "welcomeCreditMicroUsd",
    workers: ["console"],
    type: "int",
    default: "0",
    min: 0,
    max: 100000000,
    source:
      "GRAY_WELCOME_CREDIT_MICROUSD of the server: 0 (none) by default, at most $100 (MAX_WELCOME_CREDIT_MICROUSD, " +
      "crates/gray-gateway/src/welcome_credit.rs:31), which guards against a mistyped amount.",
    doc: "The one-time welcome credit of every user, recorded at their first sign-in, funded by the platform and minted on chain; 0 grants none",
  },
  {
    name: "WELCOME_CREDIT_DAILY_LIMIT",
    key: "welcomeCreditDailyLimit",
    workers: ["console"],
    type: "int",
    default: "1000",
    min: 1,
    max: 1_000_000,
    source:
      "GRAY_WELCOME_CREDIT_DAILY_LIMIT of the server: 1,000 by default (deploy/runtime/compose.production.yaml sets the same), at least 1 " +
      "(crates/gray-gateway/src/welcome_credit.rs `with_daily_limit`), at most 1,000,000 (config/onchain.rs, on both sides by the product " +
      "lead's decision of 2026-10-23, item 4). No measurement gives the maximum; what it bounds: the welcome credits recorded in one UTC day, " +
      "each funded by the platform. 1,000,000 is the most the credit Workers' funder can pay out in a day at production's welcome credit: " +
      "FUND_DAILY_BUDGET_MICRO is at most 1,000,000,000,000 micro-USD, $1,000,000 a day (workers/credit/src/lib/config.ts), and each grant " +
      "is $1 (WELCOME_CREDIT_MICROUSD 1000000, compose.production.yaml); grants past that wait for the funder's next day anyway. Above it the " +
      "count stops being a limit: a mistyped value lets every sign-in record a grant.",
    doc: "Welcome credits recorded per UTC day, all users together; a sign-in past it is granted at a later sign-in",
  },
  {
    name: "MOSS_RPC_URL",
    key: "mossRpcUrl",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || httpUrlProblem(v) === null ? null : "is not an http(s) URL"),
    source: "GRAY_MOSS_RPC_URL of the server (crates/gray-gateway/src/config/mod.rs:385), unset by default (checkout unavailable: payments.rs `configured`).",
    doc: "The MegaETH JSON-RPC endpoint checkout reads the chain id, the token's decimals and payment receipts from.",
  },
  {
    name: "MOSS_VERIFY_TIMEOUT_MS",
    key: "mossVerifyTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "20000",
    min: 1000,
    max: 25000,
    source:
      "crates/gray-gateway/src/payments.rs verify_claim: the call to MOSS's verifier times out after 20 s, and its outcome is then uncertain. " +
      "Minimum as INTERNAL_CALL_TIMEOUT_MS. Maximum: the call and the 5 s kept to store its answer fit in the 30 s a Worker keeps working " +
      "after its client leaves (C3; workers/console/src/payments/service.ts mossCallFits).",
    doc: "How long a top-up verification waits for MOSS's verifier; past it the payment goes to reconciliation and is never asked again.",
  },
  {
    name: "CHAIN_RPC_TIMEOUT_MS",
    key: "chainRpcTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "15000",
    min: 1000,
    max: 60000,
    source: "crates/gray-gateway/src/payments.rs `rpc`: each JSON-RPC call times out after 15 s (a chain error, 502 chain_unavailable).",
    doc: "How long one call to MOSS_RPC_URL, or to a RELAY_SHARE_RPC_URLS endpoint, may take.",
  },
  {
    name: "SETUP_CLAIMS_PER_NETWORK",
    key: "setupClaimsPerNetwork",
    workers: ["console"],
    type: "int",
    default: "10",
    min: 1,
    max: 1000,
    source:
      "crates/gray-gateway/src/claim_limit.rs FAILED_CLAIMS_PER_NETWORK = 10: a code carries 60 random bits, so the limit only keeps one network " +
      "from spending the database's time; a claim that hands out its key is given back. Maximum: a bound on a mistyped value.",
    doc: "Setup code claims (POST /v1/setup/claim) one client network (an IPv4 address or an IPv6 /64) may make per window that hand out nothing.",
  },
  {
    name: "SETUP_CLAIM_WINDOW_SECONDS",
    key: "setupClaimWindowSeconds",
    workers: ["console"],
    type: "int",
    default: "600",
    min: 60,
    max: 86400,
    source: "crates/gray-gateway/src/claim_limit.rs CLAIM_WINDOW = 600 s (fixed windows). Bounds: a minute to a day.",
    doc: "The fixed window SETUP_CLAIMS_PER_NETWORK counts in; a refused claim is told the seconds until its window ends (retry-after).",
  },
  {
    name: "SETUP_CLAIM_WINDOW_WAIT_MS",
    key: "setupClaimWindowWaitMs",
    workers: ["console"],
    type: "int",
    default: "2000",
    min: 200,
    max: 20000,
    source:
      "Cloudflare's analytics of ClaimWindowDO's calls (durableObjectsInvocationsAdaptiveGroups, read 2026-10-24): all 28 from 2026-10-22 to " +
      "2026-10-24 took 8.5 to 123 ms of wall time, the first call of a new object at most 747.6 ms (HKG, 2026-10-23T09:40:45Z), and one took " +
      "20.6 s on about 1 ms of CPU (HKG, 2026-10-23T16:51:25Z), which a new customer's setup claim waited for until the 20 s bound answered it " +
      "503. The server counts claims in memory and never waits (crates/gray-gateway/src/claim_limit.rs); it lets a claim through uncounted " +
      "when its table is full (TRACKED_KEYS), and a code carries 60 random bits, so the count only protects load. Default: the slowest new " +
      "object's first call with room to spare. Minimum: above the slowest usual call. Maximum: INTERNAL_CALL_TIMEOUT_MS's default.",
    doc:
      "How long a setup code claim (POST /v1/setup/claim, POST /v1/provider-setup/claim) waits for its network's claim window to count it; " +
      "past it, or when the window fails, the claim goes on uncounted.",
  },
  {
    name: "INTERNAL_CALL_TIMEOUT_MS",
    key: "internalCallTimeoutMs",
    workers: ["console", "jobs", "gateway"],
    type: "int",
    default: "20000",
    min: 1000,
    max: 60000,
    source:
      "The server's client for the services it calls (MOSS, the identity bridge) times out after 20 s (crates/gray-gateway/src/state.rs:181); " +
      "the setup scripts agent.md hands an agent wait 60 s for each answer (setup.rs opencode_python, urlopen timeout=60), the maximum here. " +
      "gray-jobs' wait for the console's payment reconciliation is the same call to another service; the server's mint loop waits for that " +
      "step without a limit (background.rs mints), so this bound only keeps the mints going, and a call given up on is not started again " +
      "until it ends, however long the mint period (CREDIT_MINT_SECONDS).",
    doc:
      "How long the console waits for another Gray Worker or object: the account root, the snapshot writer, gray-gateway's setup catalog and " +
      "the claim window of a network. Then the call answers 503; a write that committed says so. In gray-jobs, how long the `mints` object " +
      "waits for the console's payment reconciliation (ConsoleBackground) before it goes on with the mints. In gray-gateway, how long " +
      "`GET /v1/key` waits for the console's key status (its use and its workspace's balance) before it answers 503 " +
      "`billing_admission_unavailable`.",
  },
  // ---------------------------------------------------------------- gray-console, operations side
  {
    name: "DEBT_MODE",
    key: "debtMode",
    workers: ["console"],
    type: "enum",
    values: ["off"],
    default: "off",
    refusal: DEBT_MODE_RULE,
    source:
      "GRAY_DEBT_MODE of the server, off by default, off or auto (crates/gray-gateway/src/config/mod.rs:84-86, debt_mode.rs:60). The Workers " +
      "gateway has no debt mode yet (docs/cloudflare-native/ledger.md section 9, item 5): it holds every request for the most it can cost " +
      "(`expectedCost: null` in inference.ts and apis.ts), and only the console reads this, for the ledger overview. So the Workers take off " +
      "only and refuse auto, which would report a mode no Workers gateway applies: a declared difference, accepted by the product lead " +
      "2026-10-23 (item 5; conformance/README.md, declared differences, the settings-registry replay's DECLARED), and an open equivalence gap " +
      "(docs/cloudflare-native.md 6.7) that closes when the Workers gateway gets debt mode and takes auto.",
    doc:
      "Debt mode (docs/holds-debt-mode.md), which the operators' ledger overview reports: off holds every request for the most it can cost; auto " +
      "lets a gateway whose release has debt mode hold a workspace that paid for credit for what a text request is expected to cost and let it owe " +
      "what its balance cannot cover, and is turned on only once every gateway runs such a release",
  },
  {
    name: "CREDIT_MAX_RELAYER_LANES",
    key: "creditMaxRelayerLanes",
    workers: ["console"],
    type: "int",
    default: "64",
    min: 1,
    max: 1000,
    source:
      "GRAY_CREDIT_MAX_RELAYER_LANES of the server: 64 by default, 1 to 1,000 (crates/gray-gateway/src/config/onchain.rs:602-610); " +
      "it must be at least the credit Workers' RELAYER_LANES.",
    doc:
      "Relayer lanes the operators' lane view asks for, relayer-0 upward, the first one the credit Workers do not have ending the list; must be at " +
      "least their RELAYER_LANES",
  },
  {
    name: "CREDIT_LANE_STATUS_TIMEOUT_MS",
    key: "creditLaneStatusTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "15000",
    min: 1000,
    max: 120000,
    source: "GRAY_CREDIT_LANE_STATUS_TIMEOUT_SECONDS of the server: 15 s, 1 to 120 s (crates/gray-gateway/src/config/onchain.rs:611-619); the credit Worker reads the chain's nonce for each status.",
    doc: "How long one signing lane status call to the credit Workers may take.",
  },
  {
    name: "CREDIT_LANE_RESUME_TIMEOUT_MS",
    key: "creditLaneResumeTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "45000",
    min: 1000,
    max: 300000,
    source: "GRAY_CREDIT_LANE_RESUME_TIMEOUT_SECONDS of the server: 45 s, 1 to 300 s (crates/gray-gateway/src/config/onchain.rs:620-628); a resume is not repeated, so a timeout leaves its outcome unknown.",
    doc: "How long a signing lane resume may take; the console never sends it twice.",
  },
  {
    name: "CREDIT_FUNDER_ADDRESS",
    key: "creditFunderAddress",
    workers: ["console"],
    type: "text",
    default: "",
    shown: "unset (the funder lane's address is read, which needs the operator key)",
    textCheck: optionalAddressProblem,
    source:
      "GRAY_CREDIT_FUNDER_ADDRESS of the server, unset by default (crates/gray-gateway/src/config/onchain.rs:684-691, 876-886): " +
      "the funder lane's address is read instead, which needs the operator key (CREDIT_OPS_KEY).",
    doc:
      "The credit Workers' funding wallet (FUNDER_KEY's address): a funding transfer an operator attaches to a rejected welcome grant must come " +
      "from it; checked against the funder lane when the operator key is held",
  },
  {
    name: "AUTH_KEYS_OPS",
    key: "authKeysOps",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: keyListProblem,
    source:
      "AUTH_KEYS_OPS of the credit Workers (workers/credit/src/lib/config.ts, parseKeyList): the operator's public keys, the one capability " +
      "an operator signs with (the signing lanes' /v1/lanes/*). The same list, the same format and the same signature (canonical.ts), so " +
      "an operator signs the console's emergency revocation as they sign a lane's restart. Empty by default: no operator key, no emergency path.",
    doc:
      "The operator keys (`keyId:<64 hex digits of the Ed25519 public key>`, comma-separated) whose signature the console's emergency " +
      "revocation accepts (POST /api/emergency/revoke-key, docs/cloudflare-native/console-ops.md section 10): it needs no session, so it " +
      "works while PostgreSQL is away. Set it to the credit Workers' AUTH_KEYS_OPS. Empty: that route answers 503.",
  },
  {
    name: "LOUPE_PART_CHARS",
    key: "loupePartChars",
    workers: ["console"],
    type: "int",
    default: "4000",
    min: 200,
    max: 1000000,
    source: "GRAY_LOUPE_PART_CHARS of the server: 4,000 by default, 200 to 1,000,000 (crates/gray-gateway/src/request_log/sessions.rs:79, 118-120).",
    doc: "Each text of a Loupe story's step (what made the agent send a request, and what came back) is cut at this many characters.",
  },
  {
    name: "LOUPE_READ_CONCURRENCY",
    key: "loupeReadConcurrency",
    workers: ["console"],
    type: "int",
    default: "2",
    min: 1,
    max: 8,
    source:
      "GRAY_LOUPE_READ_CONCURRENCY of the server is 8 (1 to 64, crates/gray-gateway/src/request_log/sessions.rs:80, 124-126). A Worker has 128 MB for " +
      "everything it serves at once (docs/cloudflare-native.md section 3, C1) and a story opens records of up to LOUPE_OPEN_MAX_BYTES each, so the " +
      "default opens two at a time and the maximum is 8 x 8 MiB = 64 MiB of content.",
    doc: "How many records' content a Loupe story opens at once.",
  },
  {
    name: "LOUPE_OPEN_MAX_BYTES",
    key: "loupeOpenMaxBytes",
    workers: ["console"],
    type: "int",
    default: "8388608",
    min: 1048576,
    max: 8388608,
    source:
      "Not on the server, which opens every record. 8 MiB (twice the 4 MiB a Worker parses whole, m0/memory.md) keeps LOUPE_READ_CONCURRENCY " +
      "records within the 128 MB isolate (docs/cloudflare-native.md section 3); a record holds up to 32 MiB each way " +
      "(crates/gray-gateway/src/request_log/capture.rs:52 AUTHENTICATED_CAP).",
    doc:
      "A Loupe story shows a request whose stored request and response bytes together exceed this without its content (content_status " +
      "too_large); its request log detail still opens it.",
  },
  {
    name: "LOUPE_QUERY_SECONDS",
    key: "loupeQuerySeconds",
    workers: ["console"],
    type: "int",
    default: "10",
    min: 1,
    max: 120,
    source: "GRAY_LOUPE_QUERY_SECONDS of the server: 10 by default, 1 to 120 (crates/gray-gateway/src/request_log/sessions.rs:81, 130-132).",
    doc: "How long one aggregate query of Loupe's overview or models may run before it is cut off (loupe_query_too_broad).",
  },
  {
    name: "TRANSCRIPT_PARSE_MAX_BYTES",
    key: "transcriptParseMaxBytes",
    workers: ["console"],
    type: "int",
    default: "4194304",
    min: 65536,
    max: 16777216,
    source:
      "Not on the server, which parses every stored body. A Worker parses a body whole up to 4 MiB, where it takes about 5.5 MB " +
      "(docs/cloudflare-native/m0/memory.md, measured 2026-10-17); the maximum keeps one parse under a sixth of the 128 MB isolate.",
    doc: "A request log transcript or Loupe step does not parse a request or response body larger than this; its problems say so.",
  },
  // ---------------------------------------------------------------- gray-console and gray-jobs, the event store
  {
    name: "BASIN_SQL_URL",
    key: "basinSqlUrl",
    workers: ["console", "jobs"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || httpUrlProblem(v) === null ? null : "is not an http(s) URL"),
    source:
      "GRAY_BASIN_SQL_URL of the server (docs/wide-events-operations.md, Gateway settings; deploy/cloudflare-events/provision.mjs prints it): " +
      "Basin SQL's query API, https://api.sql.cloudflarestorage.com/api/v1/accounts/<account id>/basin-sql/query/<bucket> " +
      "(developers.cloudflare.com/basin-sql/query-data, read 2026-10-18). Unset by default: without it the operations investigation's " +
      "reads of customer activity answer 503, as before the event store was wired in, and gray-jobs' hourly records check looks only " +
      "for charged requests without their row (docs/request-path-availability.md 4.2 M9).",
    doc:
      "Where the console (the operations investigation) and gray-jobs (the hourly records check, jobs/src/records-check.ts) query the wide " +
      "events the gateway stores (the Basin Catalog tables of BASIN_SQL_REQUEST_TABLES), with the read-only token in the secret " +
      "BASIN_SQL_TOKEN. https outside DEPLOY_ENV local.",
  },
  {
    name: "BASIN_SQL_WAREHOUSE",
    key: "basinSqlWarehouse",
    workers: ["console", "jobs"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^[A-Za-z0-9_.-]{1,256}$/.test(v) ? null : "is not a warehouse name (letters, digits, _ . -)"),
    source:
      "GRAY_BASIN_SQL_WAREHOUSE of the server: <account id>_<bucket>, sent as `warehouse` with every query when set " +
      "(crates/gray-gateway/src/wide_event/reconcile.rs `with_warehouse`; docs/wide-events-operations.md). Unset sends none, as the query " +
      "API's own example does (basin-sql/query-data).",
    doc: "The Basin Catalog warehouse named in each event store query.",
  },
  {
    name: "BASIN_SQL_REQUEST_TABLES",
    key: "basinSqlRequestTables",
    workers: ["console", "jobs"],
    type: "text",
    default: "gray.requests_v2",
    textCheck: requestTablesProblem,
    source:
      "deploy/cloudflare-events/resources.json: gray.requests_v2 is the table of gray_request_v2, the stream the Cloudflare gateway writes " +
      "(workers/gateway/src/sinks.ts REQUEST_STREAM); gray.requests_v1 is the server gateway's, another environment's workspaces. A later " +
      "request stream (_v3) adds its table here, and the console reads the tables together with UNION ALL (docs/wide-events-operations.md, " +
      "Changing a schema or a sink).",
    doc: "The tables (namespace.table, comma-separated, no repeats) the console and gray-jobs read the gateway's request events from; each has gray_request_v2's columns.",
  },
  {
    name: "BASIN_SQL_TIMEOUT_MS",
    key: "basinSqlTimeoutMs",
    workers: ["console", "jobs"],
    type: "int",
    default: "60000",
    min: 1000,
    max: 120000,
    source:
      "The server gives one Basin SQL query 60 s (crates/gray-gateway/src/wide_event/reconcile.rs QUERY_TIMEOUT). Minimum as " +
      "INTERNAL_CALL_TIMEOUT_MS. Maximum: the production e2e run's Basin SQL client waits 120 s (scripts/e2e/event-store.mjs).",
    doc: "How long one query of the event store may take; past it the read answers 503.",
  },
  // ---------------------------------------------------------------- gray-console, verification
  {
    name: "CHECK_GLOBAL_DAILY_MICROUSD",
    key: "checkGlobalDailyMicroUsd",
    workers: ["console"],
    type: "int",
    default: "50000000",
    min: 0,
    max: 1_000_000_000_000,
    source: "GRAY_CHECK_GLOBAL_DAILY_MICROUSD of the server: $50 a day by default, at most 10^12 (crates/gray-gateway/src/check_budget.rs CheckBudget::new).",
    doc: "What all providers' verification checks together may cost Gray per UTC day, at the providers' own prices; past it no check is sent.",
  },
  {
    name: "CHECK_WORKSPACE_DAILY_MICROUSD",
    key: "checkWorkspaceDailyMicroUsd",
    workers: ["console"],
    type: "int",
    default: "5000000",
    min: 0,
    max: 1_000_000_000_000,
    source: "GRAY_CHECK_WORKSPACE_DAILY_MICROUSD of the server: $5 a day by default, at most 10^12 (crates/gray-gateway/src/check_budget.rs CheckBudget::new).",
    doc: "A provider workspace's daily check budget until it sets its own (PUT /api/v1/provider-check-budget).",
  },
  {
    name: "ALLOW_PRIVATE_UPSTREAMS",
    key: "allowPrivateUpstreams",
    workers: ["console"],
    type: "enum",
    values: PRIVATE_UPSTREAM_SWITCHES,
    default: "0",
    source:
      "GRAY_ALLOW_PRIVATE_UPSTREAMS of the server (crates/gray-gateway/src/config/mod.rs `allow_private_upstreams`): `1` on a development " +
      "gateway, ignored in production; unset, as every deployed console leaves it.",
    doc:
      "A development console's switch: `1` lets provider setup take plain-http upstreams and lets checks reach private addresses, as the " +
      "server's development gateway does (`allowPrivateUpstreams`). Ignored when DEPLOY_ENV is production.",
  },
  {
    name: "CHECK_CONFIRMATION",
    key: "checkConfirmation",
    workers: ["console"],
    type: "enum",
    values: CHECK_CONFIRMATION_MODES,
    default: "on",
    refusal: CHECK_CONFIRMATION_RULE,
    source:
      "GRAY_CHECK_CONFIRMATION of the server, on by default (crates/gray-gateway/src/verification.rs check_confirmation_from_env, release 4): " +
      "the owner's rules that a request that works directly against a relay works through Gray and that a failed capability withdraws only " +
      "itself (2026-10-16), and the prove report of 2026-10-19, which recommended asking a failed check again before withdrawing.",
    doc:
      "Whether a run confirms a capability check's failure before it withdraws what the serving evidence proved. `on`: the check is asked " +
      "once more after the plan, a confirmed withdrawal is checked again five minutes on. `off`, the lever for an incident such as " +
      "confirmations straining a supplier's check budget: a failed check withdraws its capability until the next scheduled check, its report " +
      "names no withdrawal, and no early check follows.",
  },
  {
    name: "PROBE_REQUEST_TIMEOUT_MS",
    key: "probeRequestTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "120000",
    min: 15000,
    max: 120000,
    source:
      "crates/gray-gateway/src/verification.rs VerificationService::new: the server's non-stream limit (GRAY_NON_STREAM_TOTAL_SECONDS, " +
      "1,740 s by default) clamped to 15-120 s, so a reasoning model that answers in forty seconds is admitted; a run gets six times this, " +
      "at most 900 s (the verifier's ceiling).",
    doc: "How long one verification request may wait for its answer.",
  },
  {
    name: "EVIDENCE_REFRESH_SECONDS",
    key: "evidenceRefreshSeconds",
    workers: ["console"],
    type: "int",
    default: "3600",
    min: 40,
    max: 86400,
    source: "GRAY_EVIDENCE_REFRESH_SECONDS of the server: hourly by default, 40 to 86,400 (crates/gray-gateway/src/evidence_schedule.rs, owner decision 2026-10-13).",
    doc: "How often a passing mapping is checked again.",
  },
  {
    name: "EVIDENCE_TTL_SECONDS",
    key: "evidenceTtlSeconds",
    workers: ["console"],
    type: "int",
    default: "5400",
    min: 60,
    max: 86400,
    source: "GRAY_EVIDENCE_TTL_SECONDS of the server: the hourly check plus thirty minutes for it to run, 60 to 86,400 (evidence_schedule.rs).",
    doc: "How long a passing check stays valid; the part beyond EVIDENCE_REFRESH_SECONDS is the time a due check has to run.",
  },
  {
    name: "PAID_EVIDENCE_REFRESH_SECONDS",
    key: "paidEvidenceRefreshSeconds",
    workers: ["console"],
    type: "int",
    default: "21600",
    min: 40,
    max: 86400,
    source:
      "GRAY_PAID_EVIDENCE_REFRESH_SECONDS of the server: six hours, at least EVIDENCE_REFRESH_SECONDS and with the headroom (TTL minus refresh) " +
      "at most 86,400 (evidence_schedule.rs EvidenceSchedule::new).",
    doc: "How often a passing mapping whose check buys a media generation is checked again.",
  },
  {
    name: "EVIDENCE_FLOOR_SECONDS",
    key: "evidenceFloorSeconds",
    // gray-jobs writes the coding-agent results of customer traffic, a refusal outranking a later pass for as long.
    workers: ["console", "jobs"],
    type: "int",
    default: "86400",
    min: 40,
    max: 604800,
    source: "GRAY_EVIDENCE_FLOOR_SECONDS of the server: a day, from EVIDENCE_REFRESH_SECONDS to a week (evidence_schedule.rs).",
    doc: "The longest customer traffic may carry a mapping's pass without a full active check.",
  },
  {
    name: "FAILURE_RECHECK_SECONDS",
    key: "failureRecheckSeconds",
    workers: ["console"],
    type: "int",
    default: "900",
    min: 60,
    max: 86400,
    source: "GRAY_FAILURE_RECHECK_SECONDS of the server: 15 minutes, 60 to 86,400 (evidence_schedule.rs).",
    doc: "The shortest time between an active check and the next one a customer failure asks for.",
  },
  {
    name: "MAINTENANCE_STALL_ALERT_PERCENT",
    key: "maintenanceStallAlertPercent",
    workers: ["console"],
    type: "int",
    default: "33",
    min: 10,
    max: 50,
    source:
      "GRAY_MAINTENANCE_STALL_ALERT_PERCENT of the server: 33, 10 to 50 (crates/gray-gateway/src/config/maintenance.rs; the lapsing and unstarted " +
      "rules are evidence_schedule.rs lapsing_until and unstarted_since, pinned by conformance area check-schedule). " +
      "A share of the schedule's headroom (EVIDENCE_TTL_SECONDS less EVIDENCE_REFRESH_SECONDS, the thirty minutes a due check has to run): " +
      "33 percent is 594 s of the default 1,800, in which the busy backoff (10 s doubling to 120 s with up to 20% jitter, " +
      "crates/gray-gateway/src/maintenance.rs MaintenancePolicy::default, on the 10 s scan) tries a refused job again at least six times, and " +
      "which leaves 1,206 s for the on-call and the check, whose bound is 300 s a mapping. At the minimum (180 s by default) a refusal is " +
      "still tried again three times; at the maximum half the headroom is left. In production no job started from 2026-10-22 22:28Z to " +
      "10-23 02:37Z, with no alert, and every pass lapsed within the evidence lifetime (1.5 h).",
    doc:
      "How near its end a pass in force is said as lapsing unchecked (a maintenance_pass_lapsing warning of the verification scan, every scan) when " +
      "no job runs for it and none started for it since its re-check was due, and how long after its re-check came due such a pass is said as a " +
      "check not started (maintenance_checks_not_started): a percentage of the schedule's headroom (EVIDENCE_TTL_SECONDS less " +
      "EVIDENCE_REFRESH_SECONDS)",
  },
  {
    name: "MODELTRACE_MODELS",
    key: "modeltraceModels",
    // The console plans the rounds and shows each provider its mappings' checks; the jobs apply the routing weight to
    // the snapshot's routes and say per model in the catalog whether it is checked.
    workers: ["console", "jobs"],
    type: "text",
    default: "",
    shown: "unset (none)",
    textCheck: modeltraceModelsProblem,
    source:
      "GRAY_MODELTRACE_MODELS of the server: unset, none (crates/gray-gateway/src/config/maintenance.rs; the rule is mixing.rs CheckedModels, " +
      "@gray/modeltrace CheckedModels, pinned by conformance target modeltrace/checked_models). Decided with the user on 2026-10-30 " +
      "(docs/model-authenticity-workflow.md, \"Which models are checked\"): with no payer for the probes decided, no setting means no spend, " +
      "and listing a few models shows the check while development's cost stays bounded. Each environment fills it from its values " +
      "(modeltraceModels in a staging or developer stack's values.json, workers/production/values.jsonc), empty by default.",
    doc:
      "Which models ModelTrace checks: unset or empty checks none, all checks every model with a genuine baseline, and a comma-separated list " +
      "of Gray model ids checks the listed ones that have one (a listed model without one is reported once, as a warning). A model that is not " +
      "checked runs no rounds and routes as if its routes had no ModelTrace weight; its records and weights are kept, and listing it again " +
      "resumes from the stored weight",
  },
  {
    name: "MODELTRACE_ROUND_INTERVAL_MS",
    key: "modeltraceRoundIntervalMs",
    // The console plans the rounds, sets each record's floor and answers the history's interval.
    workers: ["console"],
    type: "int",
    default: "3600000",
    min: 360000,
    max: 21600000,
    source:
      "GRAY_MODELTRACE_ROUND_INTERVAL_MS of the server: 3,600,000, 360,000 to 21,600,000 (crates/gray-gateway/src/config/maintenance.rs; " +
      "the default and bounds are modeltrace.rs DEFAULT_INTERVAL_MS, MIN_INTERVAL_MS and MAX_INTERVAL_MS, @gray/modeltrace's of the same " +
      "names, pinned by conformance target modeltrace/constants, which test/modeltrace-models.test.ts holds these to). Decided by the owner " +
      "on 2026-11-02 (docs/model-authenticity-workflow.md): an hour, a tenth of the cost of the six minutes of 2026-10-29 (about $12 a day " +
      "for a Claude Sonnet 4.6 binding, $42 for Fable 5). The bounds are those six minutes and six hours, below the twelve hours a round's " +
      "record stands (EVIDENCE_TTL_MS). Since 2026-11-03 the floor of rounds paced by traffic, the hour kept for every binding by the user " +
      "(\"一律 1 小时（和现在一样）\"); each round draws its floor between half of it and all of it (@gray/modeltrace recheckAt).",
    doc:
      "The longest wait between two ModelTrace rounds of a binding: each round draws its binding's next floor uniformly between half of " +
      "this, never under six minutes, and all of it, for every round, one that sent nothing or was put off included, and what the " +
      "provider earns on the binding may bring the next round sooner (MODELTRACE_TRAFFIC_SHARE_BPS). A record keeps the floor it drew " +
      "when the setting changes",
  },
  {
    name: "MODELTRACE_TRAFFIC_SHARE_BPS",
    key: "modeltraceTrafficShareBps",
    // The console plans the rounds and draws each record's threshold of what the provider earns.
    workers: ["console"],
    type: "int",
    default: "100",
    min: 0,
    max: 10000,
    source:
      "GRAY_MODELTRACE_TRAFFIC_SHARE_BPS of the server: 100, 0 to 10,000 (crates/gray-gateway/src/config/maintenance.rs; the default and most " +
      "are modeltrace.rs DEFAULT_TRAFFIC_SHARE_BPS and MAX_TRAFFIC_SHARE_BPS, @gray/modeltrace's of the same names, pinned by conformance " +
      "target modeltrace/constants, which test/modeltrace-models.test.ts holds these to). Decided by the user on 2026-11-03, by money " +
      "(docs/model-authenticity-workflow.md, \"Traffic-paced rounds\": \"譬如 ds4.1 flash 一次探测要 0.3$ 那就是 provider 收入 30 刀就一次探测\"): " +
      "a binding has a round once per hundred times its cost earned on it, so probes cost 1% of what the provider earns there; counted in " +
      "tokens, cheap cache reads against a probe's mostly output tokens made them 2% to 18%. 0 is the hourly floor alone, as before.",
    doc:
      "The share of what a provider earns on a binding that its ModelTrace probes are meant to cost, in basis points: each round draws " +
      "what the provider must have earned on the binding for its next round to be due, its earnings at the round plus the round's cost " +
      "over this share times an Exp(1) draw, and the next round comes then or at its floor (MODELTRACE_ROUND_INTERVAL_MS), whichever is " +
      "first, never within six minutes of the round. 0 turns the traffic trigger off: the floor alone",
  },
  {
    name: "MODELTRACE_LANE_URL",
    key: "modeltraceLaneUrl",
    // The console sends a confidential-lane relay's probes to the lane entry, the only gateway that routes lane relays.
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || originProblem(v) === null ? null : "must be empty or an http(s) origin"),
    source:
      "Decided with the user on 2026-11-03 (docs/model-authenticity-workflow.md, \"Probes are not billed\"): a confidential-lane (TEE) relay " +
      "holds no credential Gray could probe it with, so its probes go through the lane entry (production https://lane.usefallback.com; " +
      "@gray/snapshot routeInMode: the main gateway never routes a lane relay). Unset by default: lane relays have no rounds.",
    doc:
      "The lane entry's origin, to which the console sends the ModelTrace probes of confidential-lane relays (auth lane_relay) as the " +
      "built-in model-check workspace's requests (@gray/modeltrace MODEL_CHECK_WORKSPACE_ID), each with the ticket the console signs for " +
      "it. Empty (the default): lane relays have no rounds",
  },
  {
    name: "WORKSPACE_DELETION_WAIT_MS",
    key: "workspaceDeletionWaitMs",
    workers: ["console"],
    type: "int",
    default: "20000",
    min: 1000,
    max: 60000,
    source:
      "GRAY_WORKSPACE_DELETION_WAIT_MS of the server: 20,000, 1,000 to 60,000 (crates/gray-gateway/src/config/closure.rs). The default is the " +
      "request log's DELETION_WAIT (store.rs), which the console's closure waited before; it leaves the 30 s Workers give waitUntil after the " +
      "answer (C3) to the deletion and its tool-call id walk's first pass (TOOL_CALL_ID_DELETION_WAIT_MS, 15 s). The minimum is a second " +
      "[estimated]: a workspace with a few records is deleted well within it on an idle database, and the end-to-end closing scenario's stall " +
      "case answers deleting with it. The maximum, a minute, is a bound of ours under the 100 s Cloudflare's proxy waits for an origin's answer.",
    doc:
      "How long the request that closes a workspace waits for the deletion of its data (its content keys destroyed, its request log records and " +
      "tool-call ids deleted) before it answers: completed when the deletion finished within it, deleting otherwise; the deletion runs on, and " +
      "the request log's sweep of closed workspaces finishes what it leaves",
  },
  {
    name: "MAINTENANCE_LOCATION_HINT",
    key: "maintenanceLocationHint",
    workers: ["console"],
    type: "enum",
    values: LOCATION_HINTS,
    default: "wnam",
    source:
      "The verification scheduler reads PostgreSQL on every scan (every 10 s, crates/gray-gateway/src/maintenance.rs MaintenancePolicy::default), " +
      "so it lives next to it: TencentDB in Silicon Valley, 3 ms from AWS us-west-1 (docs/infrastructure-plan.md:58), which is western North America.",
    doc: "Where the console's MaintenanceDO, BenchmarkSchedulerDO and AdmissionDO are created (a Durable Object location hint).",
  },
  // ---------------------------------------------------------------- gray-console, provider benchmarks
  {
    name: "BENCHMARK_SUITE",
    key: "benchmarkSuite",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) =>
      v === "" || (new TextEncoder().encode(v).length <= 65_536 && v.trimStart().startsWith("{")) ? null : "is not a benchmark suite manifest (a JSON object of at most 64 KiB)",
    source:
      "GRAY_BENCHMARK_SUITE_FILE of the server, an operator's manifest of at most 64 KiB (crates/gray-gateway/src/benchmarks.rs BenchmarkService::new, " +
      "crates/gray-verifier/src/benchmark.rs MAX_SUITE_BYTES); empty: the server's default, BenchmarkSuite::representative(). The console reads and " +
      "validates it as BenchmarkSuite::from_json does (workers/console/src/settings.ts).",
    doc: "The provider benchmark suite as JSON (version, tasks, samples, concurrency, timeouts, limits); empty runs Gray's representative suite.",
  },
  // A start the Workflows binding refuses (workers/console/src/objects/benchmark-scheduler.ts `refused`): the
  // scheduler starts instances in its alarm handler, so it retries a refused start as Cloudflare retries an alarm
  // handler that threw. The server has no such setting: its worker spawns each job in its own process.
  {
    name: "BENCHMARK_START_RETRY_MS",
    key: "benchmarkStartRetryMs",
    workers: ["console"],
    type: "int",
    default: "2000",
    min: 1000,
    max: 60000,
    source:
      "Durable Object alarms retry a handler that threw from 2 s with exponential back-off (C22, developers.cloudflare.com/durable-objects/api/alarms/, " +
      "read 2026-04-21), and the benchmark scheduler starts instances in its alarm. The minimum is the scheduler's tick (TICK_MS, 1 s): it claims at " +
      "most once a tick, so a shorter wait is the next tick. The maximum is QUEUE_RETRY_BASE_SECONDS' 60 s, the other back-off that starts at C22's 2 s.",
    doc:
      "How long the benchmark scheduler waits after the Workflows binding refused a job's start (BENCHMARK.create threw) before it claims a job " +
      "again; the job is back in the queue, and each further refusal of it doubles the wait, up to BENCHMARK_START_RETRY_MAX_MS.",
  },
  {
    name: "BENCHMARK_START_RETRY_MAX_MS",
    key: "benchmarkStartRetryMaxMs",
    workers: ["console"],
    type: "int",
    default: "64000",
    min: 1000,
    max: 3600000,
    source:
      "C22: an alarm is retried at most 6 times from 2 s, doubling, so its longest wait is the sixth retry's, 64 s. The minimum is the scheduler's " +
      "tick (TICK_MS, 1 s). The maximum is an hour, the shortest time between two runs of one binding that someone asks for (MANUAL_INTERVAL_MS, " +
      "workers/console/src/benchmarks/service.ts): no job is claimed while the scheduler waits.",
    doc: "The longest the benchmark scheduler waits after a refused start, also after the refusal that ends the job.",
  },
  {
    name: "BENCHMARK_START_ATTEMPTS",
    key: "benchmarkStartAttempts",
    workers: ["console"],
    type: "int",
    default: "7",
    min: 1,
    max: 101,
    source:
      "C22: an alarm handler that threw is run at most 7 times, the first run and 6 retries. 1 ends a job at its first refusal, as the scheduler did " +
      "before 2026-10-23 (as worker_error). The maximum is a message's first delivery and the 100 retries Queues allow (C33, " +
      "developers.cloudflare.com/queues/platform/limits/, read 2026-10-17), the most any Cloudflare retry policy Gray follows allows.",
    doc:
      "The refusal of a benchmark job's start at which the job ends as failed with the reason workflow_unavailable (provider_benchmark_jobs." +
      "start_failures, workers/db/migrations/0025_benchmark_start_failures.sql); every refusal before it puts the job back in the queue.",
  },
  // ---------------------------------------------------------------- gray-console, relay stacks
  {
    name: "LANE_STACK_USAGE_KEEP_DAYS",
    key: "laneStackUsageKeepDays",
    workers: ["console"],
    type: "int",
    default: "8",
    min: 8,
    max: 400,
    source:
      "The used counters of a relay account's limit windows come from lane_stack_usage (S31, workers/db/migrations/0029_lane_stack.sql), and the " +
      "longest window an account may name is 7 days (LANE_STACK_WINDOW_MAX_SECONDS, @gray/control: the weekly limits of the Claude and Codex " +
      "subscriptions), so the minimum keeps 7 days and the day in progress. 8 as model_demand keeps its minutes (gray_model_demand_expire_v1). " +
      "The maximum is about 13 months, beyond which a minute table of a busy relay stops being small [estimated].",
    doc:
      "How many days of usage per relay account and model a relay stack's panel can read (lane_stack_usage); the console's cron deletes older " +
      "minutes a page at a time.",
  },
  {
    name: "LANE_STACK_PROXY_CHECK_EXPIRY_MS",
    key: "laneStackProxyCheckExpiryMs",
    workers: ["console"],
    type: "int",
    default: "120000",
    min: 65000,
    max: 3600000,
    source:
      "Coordinator decision 2026-10-29. Egress caps a proxied connect at 60 s (proxyConnectCap, deploy/tee/egress/server.go), and the lane " +
      "polls stack.proxy_checks every LANE_STACK_POLL_MS (5000 ms by default, driven by the relay container's 5 s version polls, S21): 120 s " +
      "covers one check and several polls with margin. The minimum is the cap and one poll (65 s), below which a check the VM is still " +
      "running expires; the maximum, an hour, is longer than a panel waits for an answer [estimated].",
    doc:
      "How long a relay stack's proxy check the panel queued waits for the relay's VM to answer (lane_stack_proxy_checks); past it the check " +
      "reads expired, frees its slot for a new check of that proxy and vendor, and a result that arrives later is dropped.",
  },
  {
    name: "LANE_STACK_TRACE_KEEP_DAYS",
    key: "laneStackTraceKeepDays",
    workers: ["console"],
    type: "int",
    default: "8",
    min: 1,
    max: 31,
    source:
      "S46 (docs/confidential-lane-supply-implementation.md section 9a): a relay's per-request traces (lane_stack_traces, migration 0032) " +
      "are kept as its usage minutes are by default (LANE_STACK_USAGE_KEEP_DAYS, 8) and at most a month: a trace is per request, so it is the " +
      "largest of the panel's tables [estimated].",
    doc:
      "How many days a relay stack's per-request traces (each vendor attempt of a stack request, read by Gray's request id) are kept; the " +
      "console's cron deletes older ones a page at a time.",
  },
  {
    name: "LANE_STACK_TEST_EXPIRY_MS",
    key: "laneStackTestExpiryMs",
    workers: ["console"],
    type: "int",
    default: "120000",
    min: 65000,
    max: 3600000,
    source:
      "S44: as LANE_STACK_PROXY_CHECK_EXPIRY_MS. Egress caps a whole account test at 60 s (proxyConnectCap, deploy/tee/egress/server.go) " +
      "and the lane polls stack.tests every LANE_STACK_POLL_MS (5000 ms by default): 120 s covers one test and several polls with margin. The " +
      "minimum is the cap and one poll (65 s), below which a test the VM is still running expires; the maximum, an hour, is longer than a " +
      "panel waits for an answer [estimated].",
    doc:
      "How long an account test the panel queued (or the test schedule made) waits for the relay's VM to answer (lane_stack_tests); past " +
      "it the test reads expired, no longer counts toward the 64 pending, and a result that arrives later is dropped.",
  },
  {
    name: "LANE_STACK_EJECTION",
    key: "laneStackEjection",
    workers: ["console"],
    type: "enum",
    values: LANE_STACK_EJECTION_MODES,
    default: "enforce",
    source:
      "docs/design/relay-ejection.md: the owner's rule (\"Once Gray detects a non-compliant change to a request or an answer, it " +
      "automatically takes your CVM out of routing\") is `enforce`. `record` is the coordinator's switch of 2026-11-09, so a fault in " +
      "Gray's own detection can be stopped by a configuration change instead of a release.",
    doc:
      "What the console does when a relay's VM reports a non-compliant change (stack.report `violation`). `enforce`: records it in " +
      "lane_stack_ejections, quarantines every stack endpoint of the relay (no snapshot routes to it, and the VM's configuration lists no " +
      "route) and opens the relay's `relay_ejected` alert, until an operator restores it. `record`: records it and opens the " +
      "`relay_violation` alert, and leaves the relay routing. A change of mode applies to the next violation; an ejection already made " +
      "stays until an operator restores it.",
  },
  {
    name: "RELAY_SHARE_RPC_URLS",
    key: "relayShareRpcUrls",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: relayShareRpcUrlsProblem,
    source:
      "docs/design/relay-no-always-on-host.md H5 and 13.11: Gray releases its share of a relay's record keys only for a compose hash " +
      "effective on the relay's contract on Base (`GrayRelayAppAuth.effective`). Two endpoints of different providers that must agree, " +
      "as the provisioner's and the relay tool's chain checks read it (13.4, P4); one is accepted, so a deployment can start with one. " +
      "Unset by default: the share service answers unavailable until an environment names its chain. A URL that carries an API key is " +
      "set as a secret of the same name, as MOSS_RPC_URL is.",
    doc:
      "One or two comma-separated JSON-RPC endpoints of the chain the relays' contracts are on (Base). The share service asks every one " +
      "with eth_call whether the VM's compose hash is effective on the relay's contract, and releases the share only when every one says " +
      "yes; one that cannot be read makes the answer unavailable, which the VM retries. Empty: the share service is off.",
  },
  {
    name: "RELAY_SHARE_CHAIN_ID",
    key: "relayShareChainId",
    workers: ["console"],
    type: "int",
    default: "8453",
    min: 1,
    max: 9007199254740991,
    source: "docs/design/relay-no-always-on-host.md H2: the relays' contracts are on Base, chain 8453 (Base Sepolia, 84532, for a test chain).",
    doc:
      "The chain the relays' contracts are on: every RELAY_SHARE_RPC_URLS endpoint must answer it (eth_chainId) before its contract read " +
      "counts, and a phase-2 pairing's terms and guardian part name it (RELAY_PHASE2_RELAYS).",
  },
  {
    name: "RELAY_PHASE2_RELAYS",
    key: "relayPhase2Relays",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: relayPhase2RelaysProblem,
    source:
      "docs/design/relay-no-always-on-host.md 13.11 P5a: phase 2 (the relay's own contract on Base, Deploy on Base's KMS, Gray's relayer) " +
      "is built switched off; turning it on for a relay or for every relay is the owner's decision (13.9, 13.10), and P8 moves the relays.",
    doc:
      "Which relays pair and deploy in phase 2: empty (none, the default), `*` (every relay) or relay ids separated by commas. For such a " +
      "relay POST /v1/lane-stack/pair/chain answers the chain terms, its pairing takes the guardian part, and Deploy deploys its contract and " +
      "provisions on the relays' chain's KMS. Takes effect only with RELAY_CHAIN_PROPOSER set and a current phase-2 release profile for " +
      "the relay; a relay without either pairs and deploys as in phase 1.",
  },
  {
    name: "RELAY_CHAIN_PROPOSER",
    key: "relayChainProposer",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: optionalAddressProblem,
    source:
      "docs/design/relay-no-always-on-host.md H3, H11, 13.8: Gray's release proposer, an offline key, is every relay's contract's " +
      "immutable `proposer` and part of its CREATE2 address (C12). Unset by default: no relay pairs in phase 2.",
    doc:
      "Gray's release proposer address (0x and 40 hex digits). A phase-2 pairing's terms name it, and the console recomputes the relay's " +
      "contract address with it. Changing it changes the address of every contract not yet deployed: relays paired before then pair again.",
  },
  {
    name: "RELAY_CHAIN_DSTACK_KMS",
    key: "relayChainDstackKms",
    workers: ["console"],
    type: "text",
    default: "0x2f83172A49584C017F2B256F0FB2Dca14126Ba9C",
    textCheck: addressProblem,
    source: "docs/design/relay-no-always-on-host.md 13.2: Phala's DstackKms on Base (v0.6.1), read with phala-deploy.mjs nodes on 2026-11-09.",
    doc: "Phala's DstackKms on the relays' chain, which a phase-2 pairing's terms name for the kit's chain checks (`registeredApps`).",
  },
  {
    name: "RELAY_CHAIN_KMS_IDS",
    key: "relayChainKmsIds",
    workers: ["console"],
    type: "text",
    default: "kms_kpw4DwWL,kms_23e2EjXz",
    textCheck: kmsIdListProblem,
    source:
      "docs/design/relay-no-always-on-host.md 13.2: Phala's Base KMS records on our nodes, kms-base-prod9 (kms_kpw4DwWL) and " +
      "kms-base-prod5 (kms_23e2EjXz), read on 2026-11-09; A1 step 0 provisioned on the first.",
    doc:
      "The Phala KMS ids (`kms_…`, comma-separated) on the relays' chain: a phase-2 release profile must name one of them as its kms_id " +
      "and a phase-1 profile none, so a phase-2 VM is provisioned on an on-chain KMS and a phase-1 VM never is.",
  },
  {
    name: "RELAY_CHAIN_KIT_RPC_URLS",
    key: "relayChainKitRpcUrls",
    workers: ["console"],
    type: "text",
    default: "https://mainnet.base.org,https://base-rpc.publicnode.com",
    textCheck: kitRpcUrlsProblem,
    source:
      "docs/design/relay-no-always-on-host.md 13.3, 13.11 P4a: the relay's tool checks its contract on two endpoints of different " +
      "providers that must agree. Base's own public endpoint and PublicNode's, both keyless; the relay may name others in its kit's " +
      "`chain.rpc` [chosen 2026-11-09, replaceable].",
    doc:
      "The two Base JSON-RPC endpoints (different origins, no key in them: the relay's kit stores them) a phase-2 pairing's terms give " +
      "gray-assistant for its `chain.rpc`.",
  },
  {
    name: "LANE_STACK_TEST_KEEP_DAYS",
    key: "laneStackTestKeepDays",
    workers: ["console"],
    type: "int",
    default: "8",
    min: 1,
    max: 31,
    source:
      "S46: a relay's account tests are kept 8 days, as its usage minutes and traces; at most a month, as the traces [estimated].",
    doc: "How many days a relay stack's account tests and their results are kept; the console's cron deletes older ones a page at a time.",
  },
  {
    name: "LANE_STACK_DEBUG_SHARE_KEEP_DAYS",
    key: "laneStackDebugShareKeepDays",
    workers: ["console"],
    type: "int",
    default: "30",
    min: 1,
    max: 90,
    source:
      "Relay debug sharing (docs/design/relay-debug-sharing.md section 7; decided 2026-11-09): a share's metadata (lane_stack_debug_shares, " +
      "migration 0055) is kept 30 days after its last report, so the customer's request detail and the relay's trace lookup still mark a " +
      "request shared well after the VM let its record go; at most 90 days, the longest usage range a customer reads [estimated].",
    doc:
      "How many days the metadata of a request a customer authorized for debugging at a relay is kept after the relay's VM last reported it " +
      "(never the record, which only the VM holds); the console's cron deletes older rows a page at a time.",
  },
  {
    name: "LANE_STACK_VM_PAYER",
    key: "laneStackVmPayer",
    workers: ["console"],
    type: "enum",
    values: ["gray", "relay"],
    default: "gray",
    source:
      "The owner's decision of 2026-10-29 (docs/relay-stack-provisioner.md P7): Gray pays for relay VMs at first, each relay within the VM " +
      "quota Gray's operators approve, and who pays is configuration. An operator's quota decision may name the payer for one relay.",
    doc:
      "Who pays for a relay-stack VM when Gray's operator approves a relay's VM quota without naming a payer: `gray`, or `relay`. The payer is " +
      "written on the quota and on each VM's usage rows (lane_stack_vm_usage), which a Delete keeps as the billing record.",
  },
  {
    name: "LANE_STACK_AUTO_VM_QUOTA",
    key: "laneStackAutoVmQuota",
    workers: ["console"],
    type: "enum",
    values: ["off", "on"],
    default: "off",
    source:
      "The owner's decision of 2026-11-02: while Gray tests relay stacks, a relay's first VM is approved at once (one VM, " +
      "LANE_STACK_AUTO_VM_INSTANCE_TYPE, paid by Gray), within LANE_STACK_AUTO_VM_MAX. Off, the default, is the operator's decision alone " +
      "(docs/relay-stack-provisioner.md P7); the deployments turn it on in their values.",
    doc:
      "Whether a relay stack's VM quota request is approved at once when the relay has none approved, no operator refused it, and fewer than " +
      "LANE_STACK_AUTO_VM_MAX automatically approved VMs are not deleted; otherwise it waits for Gray's operators.",
  },
  {
    name: "LANE_STACK_AUTO_VM_INSTANCE_TYPE",
    key: "laneStackAutoVmInstanceType",
    workers: ["console"],
    type: "text",
    default: "tdx.large",
    textCheck: (v) => (/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(v) ? null : "is not a Phala instance type (tdx.large)"),
    source:
      "The owner's decision of 2026-11-02: an automatically approved relay VM is a tdx.large (8 GB).",
    doc: "The Phala instance type an automatically approved relay VM quota names (LANE_STACK_AUTO_VM_QUOTA).",
  },
  {
    name: "LANE_STACK_AUTO_VM_MAX",
    key: "laneStackAutoVmMax",
    workers: ["console"],
    type: "int",
    default: "4",
    min: 0,
    max: 13,
    source:
      "Phala's account allows 13 instances and 48 GB (the owner's brief of 2026-11-02); a tdx.large is 8 GB. Gray's own lanes used 16 GB on " +
      "2026-11-03 (the production entry and staging lane tdx.medium, the production test relay's stack tdx.large), so four automatically " +
      "approved relay VMs (32 GB) fill the account; more needs a larger Phala quota. The maximum is the account's instance limit.",
    doc:
      "The most automatically approved relay VM quotas whose relay has not deleted its VM, across the platform; past it a request waits for " +
      "Gray's operators.",
  },
  {
    name: "LANE_STACK_ALERT_FROM",
    key: "laneStackAlertFrom",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^[A-Za-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}$/.test(v) ? null : "is not an e-mail address"),
    source:
      "docs/relay-stack-provisioner.md P10: relay alerts go out through Cloudflare Email Service's send_email binding (ALERT_EMAIL), whose " +
      "sender must be an address of an onboarded domain and is the binding's allowed_sender_addresses (developers.cloudflare.com/email-service, " +
      "read 2026-10-29). Empty: no e-mail is sent; the panel says e-mail alerts are off and webhooks still work.",
    doc: "The sender of relay-stack alert and confirmation e-mails (one of ALERT_EMAIL's allowed sender addresses); empty turns e-mail alerts off.",
  },
  {
    name: "LANE_STACK_EJECTION_CONTACT",
    key: "laneStackEjectionContact",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) =>
      v === "" || (v.length <= 2048 && v.startsWith("https://") && httpUrlProblem(v) === null) || /^[A-Za-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}$/.test(v)
        ? null
        : "is not an https link or an e-mail address",
    source:
      "docs/design/relay-ejection.md: only Gray's operators restore an ejected relay. The owner has not chosen the channel relays reach " +
      "them by yet (2026-11-09), so it is configuration: empty until then, and the panel and the alert say that Gray reviews every ejection.",
    doc:
      "Where an ejected relay asks Gray to restore it: a support link (https) or an e-mail address, shown in the relay's panel and its " +
      "relay_ejected alert. Empty: no contact is shown; they say \"Gray reviews every ejection; you will hear from us\".",
  },
  {
    name: "LANE_STACK_TUNNEL_ZONE",
    key: "laneStackTunnelZone",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || tunnelZoneProblem(v) === null ? null : "is not a relays zone (a lower-case DNS name of two or more labels)"),
    source:
      "docs/relay-tunnel.md: every relay's name is <label>.<relays zone> (@gray/control/tunnel tunnelName), and the zone is configuration " +
      "everywhere: terraform-edge's relay_tunnel_zone, the rendezvous plugin, and here, where the panel links to a relay's page through its " +
      "tunnel. Empty: this deployment runs no rendezvous, and the panel has no tunnel address to link to.",
    doc:
      "The relays zone of Gray's tunnel rendezvous (the same value as terraform-edge's relay_tunnel_zone): the console names each relay's tunnel " +
      "origin, https://<label>.<zone>, beside its agent status, so the panel can link to the relay's own page there. Empty: none.",
  },
  {
    name: "LANE_STACK_ENTRY_ORIGIN",
    key: "laneStackEntryOrigin",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || entryOriginProblem(v) === null ? null : "is not an https origin (https://lane.usefallback.com, no port, path or trailing slash)"),
    source:
      "docs/design/relay-outbound-only.md sections 5 and 6: an outbound-only relay stack VM has no public name; its health is read through " +
      "the entry's public route GET <entry>/v1/peer/relays/<relay>/healthz (R4), which answers the VM's /healthz with x-gray-peer-keyset and " +
      "x-gray-peer-sessions. The entry is the environment's: lane.usefallback.com in production, lane-staging.usefallback.com on staging " +
      "(section 4). Empty: the relay panel shows no session line.",
    doc: "The environment's entry origin, whose health route the relay panel reads for an outbound-only relay's sessions. Empty: none is read.",
  },
  {
    name: "LANE_STACK_ENTRY_TIMEOUT_MS",
    key: "laneStackEntryTimeoutMs",
    workers: ["console"],
    type: "int",
    default: "10000",
    min: 1000,
    max: 30000,
    source:
      "gray-lane-watch's LANE_WATCH_FETCH_TIMEOUT_MS (default 10 000, bounds 1 000 to 30 000): the same GET of the same public entry route " +
      "(docs/design/relay-outbound-only.md section 5, GET <entry>/v1/peer/relays/<relay>/healthz) from another Worker. The panel reads it every " +
      "30 s (the frontend's LIVE_INTERVAL_MS), so the maximum stays at that interval.",
    doc: "How long the relay panel's sessions read waits for the entry's health route (LANE_STACK_ENTRY_ORIGIN) before it says the entry did not answer.",
  },
  {
    name: "LANE_STACK_OUTBOUND_MIN_KIT",
    key: "laneStackOutboundMinKit",
    workers: ["console"],
    type: "text",
    default: "1.1.0",
    textCheck: (v) => (/^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/.test(v) ? null : "is not a kit version (major.minor.patch, such as 1.1.0)"),
    source:
      "docs/design/relay-outbound-only.md section 9 step 3 and decision R10 (taken 2026-11-05): a relay's VM moves to an outbound-only release " +
      "only once its gray-relay reports, in its agent status's agent_version, a kit at or above the first with the tunnel transport, or its " +
      "gray-relay cannot reach the moved VM and its accounts stop at the lease end. The design names kit 1.1.0 (section 9 step 2); the number " +
      "is set when that kit is released, so it is configuration.",
    doc:
      "The lowest gray-relay kit version (agent status agent_version) whose relay may Deploy an outbound-only release (one whose VM takes no " +
      "inbound connection). Below it, or with no version reported, Deploy is refused with lane_stack_provision_kit_outdated.",
  },
  {
    name: "LANE_STACK_ROLLOUT_MIN_KIT",
    key: "laneStackRolloutMinKit",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/.test(v) ? null : "is empty or a kit version (major.minor.patch, such as 1.2.0)"),
    source:
      "docs/design/relay-zero-downtime.md: a relay's image rollout boots the new image in a second VM and moves the relay to it once it serves, " +
      "which needs a gray-relay that seals that VM before it adopts its app (and keeps the old one sealed while it drains); an older one " +
      "revokes the old VM as soon as the new boot gets its token. The number is the first kit with it, set once that kit is released and the " +
      "entry serves the boots route, so it is configuration; empty until then.",
    doc:
      "The lowest gray-relay kit version (agent status agent_version) whose relay's signed rollouts and rollbacks run without downtime (a " +
      "second VM, then the first drains and goes). Empty: none do; every rollout restarts the VM with the new image, as before.",
  },
  {
    name: "LANE_STACK_RELEASE_MOVES",
    key: "laneStackReleaseMoves",
    workers: ["console"],
    type: "enum",
    values: LANE_STACK_RELEASE_MOVE_MODES,
    default: "off",
    source:
      "docs/design/relay-release-zero-downtime.md: the owner's request of 2026-11-09 (a relay must not stop each time it takes a Gray " +
      "release). The moves run on the rollout's mechanisms (LANE_STACK_ROLLOUT_MIN_KIT) and start by themselves, so they are switched on " +
      "after the console, the provisioner and the first release that names each VM's key are out; off until then.",
    doc:
      "`on`: the console's minute pass moves each relay's running VM to the newest Gray release the relay accepted, without downtime (a " +
      "second instance of its Phala app given that release, then the first drains and goes), when the rollout gate holds for the relay " +
      "and the release can be moved to (docs/design/relay-release-zero-downtime.md section 2). `off`: no move; an accepted release waits " +
      "for a Delete and Deploy, as before.",
  },
  {
    name: "LANE_STACK_RELEASE_MOVE_RETRY_MS",
    key: "laneStackReleaseMoveRetryMs",
    workers: ["console"],
    type: "int",
    default: "21600000",
    min: 600000,
    max: 604800000,
    source:
      "docs/design/relay-release-zero-downtime.md: a failed move cost about 5 minutes of a second VM (Phala's replica after about 82 s and " +
      "an instance's compose update in about 117 s, measured 2026-11-09, then the boot watch); every 6 hours is 20 minutes of a VM a day " +
      "for a release that cannot boot, and a transient refusal (capacity) waits at most that long. At least 10 minutes (two moves never " +
      "overlap a relay's drain bound of 15), at most a week.",
    doc:
      "How long after a failed move of a relay's VM to a Gray release (LANE_STACK_RELEASE_MOVES) the console tries that release again. A " +
      "newer release the relay accepts is moved to at once.",
  },
  {
    name: "LANE_STACK_RELEASE_LIST",
    key: "laneStackReleaseList",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || (v.length <= 2048 && httpUrlProblem(v) === null) ? null : "is not an http(s) URL of at most 2048 characters"),
    source:
      "docs/confidential-lane-supply-implementation.md S57: the pairing answers gray-relay the values its operator used to copy, the relay " +
      "stacks' signed release list first (deploy/tee/release/release.mjs: each environment's stack list, a list of its own beside the default " +
      "app's; lane-watch's LANE_WATCH_STACK_LISTS watches the same URL). Empty: the answer's release is null and the operator names the list.",
    doc: "The relay stacks' signed release list Gray publishes (gray-relay's lane.release_list), which POST /v1/lane-stack/pair answers; empty: none is answered.",
  },
  {
    name: "LANE_STACK_RELEASE_PUBLIC_KEY",
    key: "laneStackReleasePublicKey",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^[0-9a-f]{64}$/.test(v) ? null : "is not an Ed25519 public key (64 lower-case hex digits)"),
    source:
      "deploy/tee/release/environments.json release_public_key: the environment's release key signs its stack list as its default list " +
      "(release.mjs, S1/S54). S57: the pairing answers it beside the list.",
    doc: "The Ed25519 key LANE_STACK_RELEASE_LIST is signed with (gray-relay's lane.release_public_key); required with a list.",
  },
  {
    name: "LANE_STACK_RELEASE_FRESHNESS_PUBLIC_KEY",
    key: "laneStackReleaseFreshnessPublicKey",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^[0-9a-f]{64}$/.test(v) ? null : "is not an Ed25519 public key (64 lower-case hex digits)"),
    source:
      "deploy/tee/release/environments.json release_freshness_public_key: the online key the lane-freshness Worker signs every list's " +
      "freshness document with (docs/tee-lane-decisions.md D134), never the release key. S57: the pairing answers it beside the list.",
    doc: "The Ed25519 key of the release list's freshness documents (gray-relay's lane.release_freshness_public_key); empty: none is answered.",
  },
  {
    name: "LANE_STACK_TUNNEL_SERVER",
    key: "laneStackTunnelServer",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || tunnelServerProblem(v) === null ? null : "is not host:port (a lower-case host name and a port from 1 to 65535)"),
    source:
      "docs/relay-tunnel.md and deploy/rendezvous/README.md: each relay's frpc dials the rendezvous's frps at its server name (gray-relay's " +
      "tunnel.server, host:port). S57: the pairing answers it with LANE_STACK_TUNNEL_ZONE. Empty: the answer's tunnel is null.",
    doc: "The tunnel rendezvous's frps as gray-relay's tunnel.server takes it (host:port); the pairing answers it only with LANE_STACK_TUNNEL_ZONE. Empty: none.",
  },
  {
    name: "LANE_STACK_AGENT_IMAGE",
    key: "laneStackAgentImage",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || agentImageProblem(v) === null ? null : "is not an image pinned by digest (<registry>/<path>[:<tag>]@sha256:<64 lower-case hex digits>)"),
    source:
      "deploy/relay/GUIDE.en.md section 2, From the published image: gray-relay is published as an image (deploy/relay/image/) whose " +
      "`init --pair` writes the kit and its compose.yaml, so a relay's host needs Docker only. Each release names a new image, so the " +
      "reference is configuration, pinned by its digest so that every relay that pairs runs the bytes Gray published. Empty: the " +
      "panel's command is `gray-relay init --pair`, for a host that built gray-relay from the repository.",
    doc:
      "The gray-relay image the relay page's pairing commands run (docker run <image> init --pair, then docker compose up -d), pinned by " +
      "digest: <registry>/<path>:<tag>@sha256:<64 hex> or <registry>/<path>@sha256:<64 hex>. Empty: the command is gray-relay init --pair.",
  },
  {
    name: "RELAY_KIT_URL",
    key: "relayKitUrl",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || kitUrlProblem(v) === null ? null : "is not an https URL of the kit's archive (https://<host>[:<port>]/<path>, no query, fragment or user)"),
    source:
      "deploy/relay/kit/AGENTS.md and README.md: a relay ports its software to the integration standard with its coding agent, from the " +
      "kit. Set up's Build your image copies instructions that download the kit from this URL and check it with RELAY_KIT_SHA256 " +
      "before the agent follows its stages 1 to 3. Each kit release names a new archive, so the URL is configuration. Empty: the kit is " +
      "not published, and the instructions start from the standard.",
    doc:
      "The published relay kit's archive (deploy/relay/kit) that Set up's agent instructions download, an https URL without query or " +
      "fragment; set with RELAY_KIT_SHA256. Empty: the kit is not published yet.",
  },
  {
    name: "RELAY_KIT_SHA256",
    key: "relayKitSha256",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || /^[0-9a-f]{64}$/.test(v) ? null : "is not a SHA-256 digest (64 lower-case hex digits)"),
    source:
      "The agent instructions check the downloaded kit against its SHA-256 before anything in it runs, so a changed archive is refused " +
      "(RELAY_KIT_URL). Empty: with RELAY_KIT_URL, the kit is not published.",
    doc: "The SHA-256 of RELAY_KIT_URL's archive, 64 lower-case hex digits, which the agent instructions check; set with RELAY_KIT_URL.",
  },
  {
    name: "RELAY_STANDARD_URL",
    key: "relayStandardUrl",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || kitUrlProblem(v) === null ? null : "is not an https URL of the published standard (https://<host>[:<port>]/<path>, no query, fragment or user)"),
    source:
      "docs/relay-integration-standard.en.md: what a relay's image must do. Set up's Build your image links it as Read the standard, " +
      "and its agent instructions start from it while the kit is not published. Where it is published is configuration. Empty: it is not " +
      "published yet.",
    doc: "Where the relay integration standard (docs/relay-integration-standard.en.md) is published, an https URL without query or fragment. Empty: not yet.",
  },
  {
    name: "RELAY_CONFORMANCE_IMAGE",
    key: "relayConformanceImage",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || agentImageProblem(v) === null ? null : "is not an image pinned by digest (<registry>/<path>[:<tag>]@sha256:<64 lower-case hex digits>)"),
    source:
      "deploy/relay/kit/AGENTS.md stage 2 and deploy/relay/conformance/README.md: the relay's image passes Gray's conformance tool before " +
      "it is pushed. The agent instructions name the published tool image, pinned by its digest so that every relay checks with the bytes " +
      "Gray published. Empty: the instructions build the tool from the kit's conformance directory.",
    doc:
      "The conformance tool image the agent instructions run (AGENTS.md stage 2), pinned by digest: <registry>/<path>[:<tag>]@sha256:<64 hex>. " +
      "Empty: the agent builds it from the kit.",
  },
  // ---------------------------------------------------------------- gray-console, provider admission
  {
    name: "PROVIDER_ADMISSION_POLICY",
    key: "providerAdmissionPolicy",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) =>
      v === "" || (new TextEncoder().encode(v).length <= 65_536 && v.trimStart().startsWith("{")) ? null : "is not an admission policy (a JSON object of at most 64 KiB)",
    source:
      "GRAY_PROVIDER_ADMISSION_FILE of the server, at most 64 KiB (crates/gray-gateway/src/provider_admission.rs AdmissionConfig::from_env); empty: " +
      "AdmissionConfig::default(), the permissionless-v1 policy production runs. The console reads and validates it as AdmissionConfig::validate does " +
      "(workers/console/src/provider/admission.ts); the deploy task installs the policy's row and the admission actor " +
      "(workers/db/README.md).",
    doc: "The automatic admission policy as JSON (version and optional per-model rules); empty admits any valid, verified quote under permissionless-v1.",
  },
  {
    name: "PROVIDER_ADMISSION_TARIFFS",
    key: "providerAdmissionTariffs",
    workers: ["console"],
    type: "text",
    default: "",
    textCheck: (v) => (v === "" || (new TextEncoder().encode(v).length <= 65_536 && v.trimStart().startsWith("{")) ? null : "is not a pricing file (a JSON object of at most 64 KiB)"),
    source:
      "The server's GRAY_PRICING_FILE (crates/gray-gateway/src/config/mod.rs pricing), which the admission policy's hash binds " +
      "(provider_admission.rs ProviderAdmissionService::new); unset in production (docs/prepaid-billing.md, Pricing file). The console reads it only for that hash.",
    doc: "The server's optional pricing file as JSON, only so that the admission policy's hash matches the row the deploy task installed.",
  },
  // The background ledger's rows (src/ledger.ts).
  // Request content (docs/cloudflare-native/content.md section 3.9): the gateway seals each request's
  // content into R2 as it streams; the content Worker (workers/content) holds the identities and reads.
  {
    name: "CONTENT_ISOLATE_MAX_BYTES",
    key: "contentIsolateMaxBytes",
    workers: ["gateway"],
    type: "int",
    default: "16777216",
    min: 4194304,
    max: 67108864,
    source:
      "docs/cloudflare-native/content.md 3.2 (an allocation, to be set from E2): of an isolate's 128 MB (C1), the gateway's own largest blocks at " +
      "once (a held answer of ANSWER_HELD_MAX_BYTES 64 MiB, a tier B body of 24 MiB, a snapshot of up to 16 MiB) leave about 24 MiB; content " +
      "takes two thirds of that. Range 4-64 MiB (content.md 3.9).",
    doc:
      "The most bytes the request content writers of one isolate hold together: the frames they keep, the blocks waiting to be compressed and " +
      "sealed, the sealed chunks waiting for their upload and the piece being uploaded, a body's rest copied out. Past 75% the writers with the " +
      "most sealed bytes upload early; a writer that cannot get room stops storing that part (truncated, capture_budget), and one that cannot open " +
      "stores nothing (shed). The request itself is always served.",
  },
  {
    name: "CONTENT_PIECE_BYTES",
    key: "contentPieceBytes",
    workers: ["gateway"],
    type: "int",
    default: "1048832",
    min: 262208,
    max: 4195328,
    check: (n) => (n % 65552 === 0 ? null : `${n} is not a whole number of age chunks (65,552 bytes each)`),
    source:
      "docs/cloudflare-native/content.md 3.2 and 9: 16 age chunks (16 x 65,552 bytes, about 1 MiB); the load test's average sealed request " +
      "(133-200 KB) and a heavy Claude Code request's median (about 0.68 MB) are both one PUT. Range 4-64 chunks; the format allows at most 64 " +
      "chunks in a piece (content.md 4.3).",
    doc: "A piece of this many sealed bytes is written to R2 once it is sealed; what is left at the end goes into the tail object. Whole age chunks only.",
  },
  {
    name: "CONTENT_PUT_TIMEOUT_MS",
    key: "contentPutTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "30000",
    min: 1000,
    max: 30000,
    source:
      "docs/cloudflare-native/content.md 3.3: the platform's 30 s for waitUntil (developers.cloudflare.com/workers/runtime-apis/context/): a PUT " +
      "that does not fit in the end window is not worth waiting for mid-stream either. To be set from E-C1's p99.",
    doc: "The longest one PUT of a piece or of the tail object is waited for (never past the content deadline). The R2 binding takes no AbortSignal: a late answer is not waited for, and an orphan it leaves is swept.",
  },
  {
    name: "CONTENT_TAIL_RESERVE_MS",
    key: "contentTailReserveMs",
    workers: ["gateway"],
    type: "int",
    default: "7000",
    min: 2000,
    max: 10000,
    source:
      "docs/request-path-availability.md 4.2 M9: what the record needs after the content, one send that does not answer (SINK_SEND_TIMEOUT_MS, " +
      "3 s), one retry of it (3 s) and one put of the record to the R2 outbox (1 s): 7 s. With 3 s (content.md 3.6, the settlement's reserve " +
      "until 2026-10-30) a content tail slowed by R2 left the index row one try and no retry (#164's retry starts only while 4 s are left). " +
      "At least two send timeouts and a second for the put (a cross check). To be revisited with the Queue send's p99 from E-C1.",
    doc:
      "The content deadline is the end of the answer plus the platform's 30 s less this: then the content work stops, the content is failed " +
      "with `deadline` if it was not written, and the index row, the wide event and the point are sent, a failed send retried or written to " +
      "the R2 outbox within what is left (sinks.ts `emitRecord`).",
  },
  {
    name: "INDEX_SEND_RETRY_MS",
    key: "indexSendRetryMs",
    workers: ["gateway"],
    type: "int",
    default: "100",
    min: 50,
    max: 5000,
    source:
      "Cloudflare's exponential backoff for a failed platform call, 100 ms doubling with each failure (developers.cloudflare.com/" +
      "durable-objects/best-practices/error-handling, read 2026-10-29; the account shards' SHARD_RETRY_BASE_MS). Queues documents a send " +
      "that throws past the per-queue throughput (5,000 messages a second) 'until your producer falls below the limit' " +
      "(developers.cloudflare.com/queues/platform/limits, read 2026-10-29), and no backoff of its own. Staging 2026-10-29 13:50:06-13:50:32Z " +
      "(shard-verify run A): 18 index sends failed with `Error` in a 26 s platform window and their request records were lost; nothing sent " +
      "them again.",
    doc:
      "After a send of a request's index row to the request-index Queue that failed with an error the gateway waits this long and sends it " +
      "again, doubling the wait each time up to INDEX_SEND_RETRY_MAX_MS, while the next try can still end (SINK_SEND_TIMEOUT_MS) with the " +
      "outbox put's share left before the platform's 30 s after the answer end (AFTER_CLIENT_LEFT_MS); then the row goes to the R2 outbox. " +
      "A send that does not answer is not tried again: it goes to the outbox at once.",
  },
  {
    name: "INDEX_SEND_RETRY_MAX_MS",
    key: "indexSendRetryMaxMs",
    workers: ["gateway"],
    type: "int",
    default: "4000",
    min: 250,
    max: 10000,
    source:
      "ctx.waitUntil() extends a request 'for up to 30 seconds after the response is sent or the client disconnects', shared by all its " +
      "waitUntil calls, after which they are cancelled (developers.cloudflare.com/workers/runtime-apis/context, read 2026-10-29). With the " +
      "first wait at 100 ms, a cap of 4 s gives about ten tries within the 26 s a try may start in (a send timeout and the outbox put's share kept back for the last one), " +
      "the last ones 4 s apart, so a failure window like staging's 26 s at 13:50Z (INDEX_SEND_RETRY_MS) still meets a try after it ends for " +
      "a request that finished in its first seconds. Maximum: a third of the 30 s. At least INDEX_SEND_RETRY_MS (a cross check).",
    doc: "The longest wait between two sends of one index row.",
  },
  {
    name: "SINK_SEND_TIMEOUT_MS",
    key: "sinkSendTimeoutMs",
    workers: ["gateway"],
    type: "int",
    default: "3000",
    min: 500,
    max: 4500,
    source:
      "docs/request-path-availability.md 4.2 M9. Queues documents no time limit on a send (developers.cloudflare.com/queues/platform/limits, " +
      "read 2026-10-29) and Workers set none on a subrequest (developers.cloudflare.com/workers/platform/limits/#subrequests): a send that " +
      "hung waited until the platform cancelled the request's waitUntil at 30 s and its record was lost without a log line. 3 s: the longest " +
      "one platform call the request path waits for (ACCOUNT_ADMIT_BUDGET_MS: the measured 3,056 ms root-call maximum, soak r4); a healthy " +
      "send answers in milliseconds (its p99 is E-C1's to measure, docs/cloudflare-native/content.md 13), so the bound only turns a hang into " +
      "a failure. At most half of CONTENT_TAIL_RESERVE_MS less a second (a cross check), so the reserve holds a send, a retry and the put.",
    doc:
      "How long the gateway waits for one send of a request's index row (Queue) or wide event (Pipelines). A send that has not answered by " +
      "then is given up, not tried again (it keeps its connection until it settles, outbound.ts), and the record goes to the R2 outbox " +
      "(sinks.ts `emitRecord`); the send may still land, and gray-jobs keeps the row once, readers the event once (its id).",
  },
  {
    name: "CONTENT_REQUEST_BLOCK_BYTES",
    key: "contentRequestBlockBytes",
    workers: ["gateway"],
    type: "int",
    default: "262144",
    min: 65536,
    max: 1048576,
    source:
      "docs/cloudflare-native/content.md 3.9 and 13 (measured in local workerd 2026-10-18): deflate in 256 KiB blocks compresses within 0.5-1.8% " +
      "of the whole; 64 KiB blocks lose 2.2-7.0%. Maximum: the request record's 1 MiB (content.md 4.2).",
    doc: "The request body is sealed in records of this many bytes, compressed one at a time.",
  },
  {
    name: "CONTENT_DEFLATE_LEVEL",
    key: "contentDeflateLevel",
    workers: ["gateway"],
    type: "int",
    default: "6",
    min: 1,
    max: 9,
    source: "zlib's default level; docs/cloudflare-native/content.md 13 (measured 2026-10-18): level 6 takes 2.5-6.5 times level 1's time for 7-22% better ratios.",
    doc: "The deflate level of every content record.",
  },
  {
    name: "CONTENT_RECIPIENT_KEYS",
    key: "contentRecipientKeys",
    workers: ["gateway"],
    type: "text",
    default: "",
    textCheck: (v) => {
      if (v === "") return null;
      const seen = new Set<string>();
      for (const entry of v.split(",").map((e) => e.trim()).filter((e) => e !== "")) {
        const at = entry.indexOf(":");
        if (at <= 0) return "each entry is kid:base64";
        const kid = entry.slice(0, at);
        if (seen.has(kid)) return `key ${kid} appears twice`;
        seen.add(kid);
        if (!/^[A-Za-z0-9+/]{43}=$/.test(entry.slice(at + 1))) return `key ${kid} is not base64 of 32 bytes`;
      }
      return null;
    },
    source:
      "docs/cloudflare-native/content.md 2.7: the public halves of the content Worker's signing keys, `kid:base64(32-byte Ed25519 public key)`, " +
      "the form of jobs' SNAPSHOT_VERIFYING_KEYS; both keys of a rotation at once (6.2). Empty: no record verifies, no content is sealed.",
    doc:
      "The keys the gateway verifies recipient records with, once per isolate and record. A record that does not verify, or that names a key not " +
      "here, is never sealed to: the content is failed with recipient_invalid and a security alert is logged.",
  },
  {
    name: "CONTENT_KEY_LEAD_DAYS",
    key: "contentKeyLeadDays",
    workers: ["content"],
    type: "int",
    default: "7",
    min: 2,
    max: 31,
    source:
      "docs/cloudflare-native/content.md 2.5: the content Worker or its hourly top-up may stop for a week without a day lacking its identity, at " +
      "8 rows per workspace; the identity functions refuse a day past today + 31 (the maximum).",
    doc: "How many days ahead of today the content Worker keeps an identity made for every workspace with a usable key and for the anonymous scope.",
  },
  {
    name: "CONTENT_READ_MAX_BYTES",
    key: "contentReadMaxBytes",
    workers: ["content"],
    type: "int",
    default: "50331648",
    min: 16777216,
    max: 100663296,
    source:
      "docs/cloudflare-native/content.md 5.4: an open takes the tail, two pieces, one record and a little more by the object's directory: about " +
      "3.4-4.1 MiB for objects of the default piece size, so about ten at once; the format's worst (64-chunk pieces) about 13 MiB. Range 16-96 MiB.",
    doc: "The most bytes the opens of one content Worker isolate hold together, reserved per open from its directory; an open that does not fit waits a little, then is refused with 503.",
  },
  {
    name: "CONTENT_OPEN_WAIT_MS",
    key: "contentOpenWaitMs",
    workers: ["content", "console"],
    type: "int",
    default: "5000",
    min: 0,
    max: 30000,
    source: "docs/cloudflare-native/content.md 5.4 (an open that does not fit its read budget waits a little, then 503 so the client retries); the 30 s a request has after its client leaves bounds it.",
    doc: "How long an open waits for room in its isolate's read budget (CONTENT_READ_MAX_BYTES in the content Worker, CONSOLE_CONTENT_READ_MAX_BYTES in the console) before it is refused.",
  },
  {
    name: "CONSOLE_CONTENT_READ_MAX_BYTES",
    key: "consoleContentReadMaxBytes",
    workers: ["console"],
    type: "int",
    default: "50331648",
    min: 16777216,
    max: 100663296,
    source:
      "docs/cloudflare-native/content.md 5.4 and 8: a request log detail keeps each part up to TRANSCRIPT_PARSE_MAX_BYTES (4 MiB) and parses one " +
      "part at a time (about 1.3 times its bytes, m0/memory.md: 1.25-1.36 measured), about 13 MiB an open; a Loupe open about 18.4 MiB " +
      "(LOUPE_OPEN_MAX_BYTES and its parse), so the default Loupe concurrency of 2 fits. 48 MiB of the 128 MB isolate; range 16-96 MiB.",
    doc:
      "The most bytes of opened request content one console isolate keeps at once (GRC3 details and Loupe steps, reserved per open before the " +
      "content Worker is asked); an open that does not fit waits up to CONTENT_OPEN_WAIT_MS, then a detail answers 503 and a Loupe step shows " +
      "its content as unreadable.",
  },
  {
    name: "CONTENT_STATEMENT_TIMEOUT_MS",
    key: "contentStatementTimeoutMs",
    workers: ["content"],
    type: "int",
    default: "10000",
    min: 1000,
    max: 60000,
    source: "The jobs Worker's JOBS_STATEMENT_TIMEOUT_MS bounds (a statement that runs longer is a stuck lock or a missing index, not work).",
    doc: "SET LOCAL statement_timeout of the content Worker's transactions.",
  },
  ...ledgerSettings(LOCATION_HINTS),
];

/** The server's GRAY_ORIGIN rule (crates/gray-gateway/src/config/mod.rs:331-343), parsed by the platform's URL parser. */
export function originProblem(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "is not a URL";
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return "must be an http or https origin";
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || url.pathname !== "/") {
    return "must be an origin, without user, path, query or fragment";
  }
  if (value !== url.origin && value !== `${url.origin}/`) return "must be written as an origin (scheme://host[:port])";
  return null;
}

/** An http or https URL the platform's parser reads. */
/**
 * Why a relays zone is not one (docs/relay-tunnel.md), else null: the WHATWG URL parser must read it as a host as it is
 * (lower case, no port, path or user), of two or more labels, short enough for a 63-octet label in front (RFC 1035).
 * The console checks each relay's name with @gray/control/tunnel's stricter rules as well.
 */
export function tunnelZoneProblem(value: string): string | null {
  if (value.length < 3 || value.length > 189 || !value.includes(".")) return "length or labels";
  try {
    return new URL(`https://${value}/`).hostname === value ? null : "not a host as written";
  } catch {
    return "not a host";
  }
}

/**
 * Why `value` is not an entry origin (LANE_STACK_ENTRY_ORIGIN), or null: an https origin as the URL parser writes it,
 * a DNS name of two or more labels with no port, path, query or trailing slash.
 */
export function entryOriginProblem(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.origin !== value || url.port !== "") return "not an https origin as written";
    return tunnelZoneProblem(url.hostname);
  } catch {
    return "not a URL";
  }
}

/**
 * Why a tunnel server is not `host:port` as gray-relay's `tunnel.server` and @gray/control/stack-pairing's answer take
 * it, else null: a lower-case host the URL parser reads as written, and a port from 1 to 65535.
 */
export function tunnelServerProblem(value: string): string | null {
  const m = /^([a-z0-9.-]{1,253}):([0-9]{1,5})$/.exec(value);
  if (m === null) return "not host:port";
  const port = Number(m[2]);
  if (port < 1 || port > 65_535) return "port";
  return tunnelZoneProblem(m[1]!) === null ? null : "host";
}

// An image reference as distribution/reference (reference.go, the grammar Docker and OCI registry clients parse)
// defines it: name [":" tag] "@" digest. The registry is required and is a domain (a dot or a port in it, or
// localhost), as that grammar reads a first component only then as a registry and not as a Docker Hub path.
const IMAGE_DOMAIN_COMPONENT = "(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])";
const IMAGE_REGISTRY = `(?:${IMAGE_DOMAIN_COMPONENT}(?:\\.${IMAGE_DOMAIN_COMPONENT})+(?::[0-9]+)?|${IMAGE_DOMAIN_COMPONENT}:[0-9]+|localhost)`;
const IMAGE_PATH_COMPONENT = "[a-z0-9]+(?:(?:[_.]|__|[-]+)[a-z0-9]+)*";
const PINNED_AGENT_IMAGE = new RegExp(`^(${IMAGE_REGISTRY}/${IMAGE_PATH_COMPONENT}(?:/${IMAGE_PATH_COMPONENT})*)(?::[\\w][\\w.-]{0,127})?@sha256:[0-9a-f]{64}$`);

/**
 * Why `value` is not a gray-relay image pinned by its digest, `<registry>/<path>:<tag>@sha256:<64 hex>` or
 * `<registry>/<path>@sha256:<64 hex>`, else null. The name is at most 255 characters (reference.go NameTotalLengthMax).
 * No character the grammar allows is one a shell reads, so the panel's pairing commands carry the reference as it is.
 */
export function agentImageProblem(value: string): string | null {
  const m = PINNED_AGENT_IMAGE.exec(value);
  if (m === null) return "not <registry>/<path>[:<tag>]@sha256:<64 hex>";
  return m[1]!.length <= 255 ? null : "name longer than 255 characters";
}

// An https URL of a file: a host name, an optional port and a path of the characters RFC 3986 leaves unreserved (and
// `/` and `%`), none of which a shell reads, so the agent instructions carry it as it is.
const KIT_URL = /^https:\/\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?::[0-9]{1,5})?\/[A-Za-z0-9._~%/-]*$/;

/** Why `value` is not the https URL of the relay kit's archive (RELAY_KIT_URL), else null. */
export function kitUrlProblem(value: string): string | null {
  if (!KIT_URL.test(value)) return "not https://<host>[:<port>]/<path>";
  try {
    return new URL(value).href === value ? null : "not written as the URL parser writes it";
  } catch {
    return "not a URL";
  }
}

export function httpUrlProblem(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? null : "must be http or https";
  } catch {
    return "is not a URL";
  }
}

/** RELAY_SHARE_RPC_URLS: empty, or one or two distinct comma-separated http(s) URLs. */
export function relayShareRpcUrlsProblem(value: string): string | null {
  if (value === "") return null;
  const urls = value.split(",").map((url) => url.trim());
  if (urls.length > 2) return "names more than two endpoints";
  if (new Set(urls).size !== urls.length) return "names one endpoint twice";
  for (const url of urls) {
    const problem = url === "" ? "has an empty entry" : httpUrlProblem(url);
    if (problem !== null) return problem;
  }
  return null;
}

/** RELAY_PHASE2_RELAYS: empty, `*`, or relay ids (LANE_RELAY_ID_PATTERN's characters) separated by commas. */
export function relayPhase2RelaysProblem(value: string): string | null {
  if (value === "" || value === "*") return null;
  const ids = value.split(",").map((id) => id.trim());
  if (ids.some((id) => !/^[A-Za-z0-9._:-]{1,128}$/.test(id))) return "is not empty, * or relay ids separated by commas";
  if (new Set(ids).size !== ids.length) return "names one relay twice";
  return null;
}

/** Whether RELAY_PHASE2_RELAYS's value names `relayId` (or every relay). */
export function relayOnPhase2(value: string, relayId: string): boolean {
  if (value === "*") return true;
  return value !== "" && value.split(",").some((id) => id.trim() === relayId);
}

/** RELAY_CHAIN_KMS_IDS: Phala KMS ids (`kms_…`), comma-separated, at least one. */
export function kmsIdListProblem(value: string): string | null {
  const ids = value.split(",").map((id) => id.trim());
  if (ids.some((id) => !/^kms_[A-Za-z0-9]{1,64}$/.test(id))) return "is not Phala KMS ids (kms_…) separated by commas";
  return new Set(ids).size === ids.length ? null : "names one KMS twice";
}

/** RELAY_CHAIN_KIT_RPC_URLS: exactly two http(s) URLs of different origins, with no user or password in them. */
export function kitRpcUrlsProblem(value: string): string | null {
  const urls = value.split(",").map((url) => url.trim());
  if (urls.length !== 2) return "does not name exactly two endpoints";
  const origins: string[] = [];
  for (const url of urls) {
    const problem = url === "" ? "has an empty entry" : httpUrlProblem(url);
    if (problem !== null) return problem;
    const parsed = new URL(url);
    if (parsed.username !== "" || parsed.password !== "") return "names a user or password in a URL";
    origins.push(parsed.origin);
  }
  return origins[0] === origins[1] ? "names one origin twice" : null;
}

/** An EVM address (0x and 40 hex digits, any case). */
export function addressProblem(value: string): string | null {
  return /^0x[0-9a-fA-F]{40}$/.test(value) ? null : "is not an EVM address (0x and 40 hex digits)";
}

function optionalAddressProblem(value: string): string | null {
  return value === "" ? null : addressProblem(value);
}

/**
 * BASIN_SQL_REQUEST_TABLES: one or more Basin Catalog tables, `namespace.table` with the entity names
 * deploy/cloudflare-events/plan.mjs accepts (letters, digits, underscores), comma-separated, no repeats.
 */
function requestTablesProblem(value: string): string | null {
  const tables = value.split(",").map((t) => t.trim());
  if (tables.some((t) => !/^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$/.test(t))) return "names a table that is not namespace.table (letters, digits, underscores)";
  if (new Set(tables).size !== tables.length) return "names a table twice";
  return null;
}

/** gray-control's wallet rule (lib.rs wallet()): an EVM address, or a non-EVM identity of 1 to 256 characters without control characters. */
/** A JSON document (its shape is the reader's to check: TRUST_POLICY is compiled by @gray/trust). */
function jsonDocumentProblem(value: string): string | null {
  try {
    JSON.parse(value);
    return null;
  } catch {
    return "is not JSON";
  }
}

function walletListProblem(value: string): string | null {
  for (const entry of value.split(",").map((w) => w.trim()).filter((w) => w !== "")) {
    // eslint-disable-next-line no-control-regex
    if (entry.length > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(entry)) return `${JSON.stringify(entry.slice(0, 64))} is not a wallet`;
  }
  return null;
}

/**
 * A list of public keys, `keyId:<64 hex digits>` entries separated by commas (an entry's key may start with
 * 0x): the credit Workers' AUTH_KEYS_* format and rule (workers/credit/src/lib/config.ts `parseKeyList`).
 * Throws on a malformed entry; "" is no key.
 */
export function keyListOf(value: string): Map<string, string> {
  const keys = new Map<string, string>();
  for (const part of value.split(",")) {
    const item = part.trim();
    if (item === "") continue;
    const sep = item.indexOf(":");
    const kid = sep > 0 ? item.slice(0, sep) : "";
    const hex = item.slice(sep + 1).toLowerCase().replace(/^0x/, "");
    if (sep <= 0 || !/^[A-Za-z0-9._-]{1,64}$/.test(kid) || !/^[0-9a-f]{64}$/.test(hex)) throw new Error(`malformed public key entry for key id ${JSON.stringify(kid)}`);
    keys.set(kid, hex);
  }
  return keys;
}

function keyListProblem(value: string): string | null {
  try {
    keyListOf(value);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function accessDomainProblem(value: string): string | null {
  if (value === "") return null;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(value) ? null : "is not an Access team domain (<team>.cloudflareaccess.com)";
}


export type Value = number | string;
export interface Problem {
  readonly name: string;
  readonly message: string;
  /** A rule between two vars (`CrossCheck`): both, the one whose bound it is first. */
  readonly names?: readonly [string, string];
}

/** A bound between two vars, which the rows' own bounds cannot state. */
/**
 * The least of CONTENT_TAIL_RESERVE_MS that two send timeouts must leave for the record's put to the R2 outbox
 * (docs/request-path-availability.md 4.2 M9: 3 + 3 + 1 s). One put of at most a Queue message's 128 KB to the content
 * bucket, which the request already writes; R2's put latency is E-C1's to measure (docs/cloudflare-native/content.md 13).
 */
export const OUTBOX_PUT_SHARE_MIN_MS = 1_000;

export interface CrossCheck {
  readonly workers: readonly WorkerName[];
  /** The vars, the one whose bound it is first. */
  readonly names: readonly [string, string];
  /** The problem, or null; called only when both vars parsed. */
  readonly check: (a: number, b: number) => string | null;
  readonly source: string;
}

export const CROSS_CHECKS: readonly CrossCheck[] = [
  {
    workers: ["alerts"],
    names: ["ALERT_DELIVERY_RETRY_MS", "ALERT_DELIVERY_RETRY_MAX_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ALERT_DELIVERY_RETRY_MAX_MS (${b})`),
    source: "The first wait before a page is sent again doubles up to the longest one; a first wait above it would be cut at once.",
  },
  {
    workers: ["alerts"],
    names: ["ALERT_DELIVERY_RETRY_MAX_MS", "ALERT_DELIVERY_GIVE_UP_MS"],
    check: (a, b) => (a < b ? null : `${a} must be below ALERT_DELIVERY_GIVE_UP_MS (${b})`),
    source: "A page is tried more than once before the router gives it up.",
  },
  {
    workers: ["console"],
    names: ["BENCHMARK_START_RETRY_MS", "BENCHMARK_START_RETRY_MAX_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most BENCHMARK_START_RETRY_MAX_MS (${b})`),
    source: "The first wait after a refused benchmark start doubles up to the longest one; a first wait above it would be cut at once.",
  },
  {
    workers: ["console"],
    names: ["EVIDENCE_REFRESH_SECONDS", "EVIDENCE_TTL_SECONDS"],
    check: (a, b) => (a < b ? null : `${a} must be below EVIDENCE_TTL_SECONDS (${b})`),
    source: "A due check needs headroom inside the pass it renews (crates/gray-gateway/src/evidence_schedule.rs EvidenceSchedule::new).",
  },
  {
    workers: ["console"],
    names: ["PAID_EVIDENCE_REFRESH_SECONDS", "EVIDENCE_REFRESH_SECONDS"],
    check: (a, b) => (a >= b ? null : `${a} must be at least EVIDENCE_REFRESH_SECONDS (${b})`),
    source: "A paid check is never re-bought more often than the hourly one runs (evidence_schedule.rs EvidenceSchedule::new).",
  },
  {
    workers: ["console"],
    names: ["EVIDENCE_FLOOR_SECONDS", "EVIDENCE_REFRESH_SECONDS"],
    check: (a, b) => (a >= b ? null : `${a} must be at least EVIDENCE_REFRESH_SECONDS (${b})`),
    source: "The floor may not ask for full checks more often than the re-check does (evidence_schedule.rs EvidenceSchedule::new).",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_ROOT_CALL_TIMEOUT_MS", "ACCOUNT_ADMIT_BUDGET_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_ADMIT_BUDGET_MS (${b})`),
    source:
      "A shard's call to the root serves the admits that wait for it, the gateway's later attempts on the same shard included; past the " +
      "admission budget none of them is left, and a call that hangs longer only keeps the next ones from asking afresh " +
      "(ACCOUNT_ROOT_CALL_TIMEOUT_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["PEER_DOWN_MS", "PEER_DOWN_MAX_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most PEER_DOWN_MAX_MS (${b})`),
    source: "A down peer's first rest doubles up to the longest (docs/confidential-lane-stack-routing.md section 4.7, row 1); a first rest above it would be cut at once.",
  },
  {
    workers: ["gateway"],
    names: ["PEER_DOWN_MAX_MS", "PEER_RECHECK_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most PEER_RECHECK_MS (${b})`),
    source: "A peer down for a transient fault (a dial, a list, a hello it could not get) is never rested longer than one refused on its evidence (PEER_DOWN_MAX_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["PEER_RENEW_MS", "PEER_CALL_MS"],
    check: (a, b) => (a >= 4 * b ? null : `${a} must be at least four PEER_CALL_MS (4 x ${b})`),
    source:
      "A renewal is at most four background calls (the attestation, the pin push, the challenge, the hello), each bounded by " +
      "PEER_CALL_MS, and the old pin serves only until it lapses: the renewal starts early enough to end before (PEER_RENEW_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["INDEX_SEND_RETRY_MS", "INDEX_SEND_RETRY_MAX_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most INDEX_SEND_RETRY_MAX_MS (${b})`),
    source: "The first wait doubles up to the longest (INDEX_SEND_RETRY_MAX_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["SINK_SEND_TIMEOUT_MS", "CONTENT_TAIL_RESERVE_MS"],
    check: (a, b) => (2 * a + OUTBOX_PUT_SHARE_MIN_MS <= b ? null : `twice ${a} and ${OUTBOX_PUT_SHARE_MIN_MS} ms must fit in CONTENT_TAIL_RESERVE_MS (${b})`),
    source:
      "The reserve after the content holds a send that does not answer, one retry and the put to the R2 outbox (CONTENT_TAIL_RESERVE_MS " +
      "source); the put's share is what the two sends leave, at least OUTBOX_PUT_SHARE_MIN_MS.",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_VERSION_CHECK_MS", "ACCOUNT_LEASE_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_LEASE_MS (${b})`),
    source: "An active shard's background check renews its lease before the lease runs out (ACCOUNT_LEASE_MS doc).",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_IDLE_RETURN_MS", "ACCOUNT_STANDING_RETURN_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_STANDING_RETURN_MS (${b})`),
    source: "The standing allowance is what the idle return keeps; it goes back after the longer idle (ACCOUNT_STANDING_RETURN_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["ENDPOINT_IDLE_RETURN_SECONDS", "ENDPOINT_STANDING_RETURN_SECONDS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ENDPOINT_STANDING_RETURN_SECONDS (${b})`),
    source: "The standing permit is what the idle return keeps; it goes back after the longer idle (ENDPOINT_STANDING_RETURN_SECONDS source).",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_VERSION_CHECK_MS", "ACCOUNT_KEY_LIST_MAX_AGE_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_KEY_LIST_MAX_AGE_MS (${b})`),
    source: "An active shard's background check renews the key list before it is too old for a key's admit (ACCOUNT_KEY_LIST_MAX_AGE_MS doc).",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_KEY_LIST_MAX_AGE_MS", "ACCOUNT_LEASE_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_LEASE_MS (${b})`),
    source: "Past the lease a shard admits nothing without the root, so a longer key-list age would change nothing (ACCOUNT_KEY_LIST_MAX_AGE_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_STANDING_RETURN_MS", "ACCOUNT_LEASE_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_LEASE_MS (${b})`),
    source:
      "A standing allowance spares the first request after a pause a call to the root only while the shard's lease still runs; past the lease " +
      "that request asks the root anyway (ACCOUNT_STANDING_RETURN_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["ANSWER_MARGIN_MS", "ACCOUNT_ADMIT_ATTEMPT_MS"],
    check: (a, b) => (a < b ? null : `${a} must be below ACCOUNT_ADMIT_ATTEMPT_MS (${b})`),
    source: "A shard answers by the attempt's wait less the margin: a margin as long as the wait leaves the shard no time to wait for its root.",
  },
  {
    workers: ["gateway"],
    names: ["LANE_BRIDGE_ANSWER_MARGIN_MS", "ACCOUNT_ADMIT_ATTEMPT_MS"],
    check: (a, b) => (a < b ? null : `${a} must be below ACCOUNT_ADMIT_ATTEMPT_MS (${b})`),
    source: "The lane tells the bridge the attempt's wait less the margin: a margin as long as the wait leaves the shard nothing to wait with.",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_ADMIT_ATTEMPT_MS", "ACCOUNT_ADMIT_BUDGET_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ACCOUNT_ADMIT_BUDGET_MS (${b})`),
    source: "An attempt is part of the budget (ACCOUNT_ADMIT_ATTEMPT_MS source), as in today's server (deploy/runtime/compose.production.yaml:101-102).",
  },
  {
    workers: ["gateway"],
    names: ["ACCOUNT_HOLD_MARGIN_MS", "ACCOUNT_ADMIT_BUDGET_MS"],
    check: (a, b) => (a >= b ? null : `${a} must be at least ACCOUNT_ADMIT_BUDGET_MS (${b})`),
    source: "The margin covers the gateway's settlement retries, which run for up to the admission budget (ACCOUNT_HOLD_MARGIN_MS source).",
  },
  {
    workers: ["gateway"],
    names: ["PROJECTION_RETRY_MAX_MS", "PROJECTION_INTERVAL_MS"],
    check: (a, b) => (a >= b ? null : `${a} must be at least PROJECTION_INTERVAL_MS (${b})`),
    source: "The back-off starts at the projection interval and doubles; a cap below the interval would retry faster than a working shard sends.",
  },
  {
    workers: ["jobs"],
    names: ["QUEUE_RETRY_MAX_SECONDS", "QUEUE_RETRY_BASE_SECONDS"],
    check: (a, b) => (a >= b ? null : `${a} must be at least QUEUE_RETRY_BASE_SECONDS (${b})`),
    source: "The back-off starts at the base and doubles up to the maximum.",
  },
  {
    workers: ["gateway"],
    names: ["CONFIG_CALL_TIMEOUT_MS", "CONFIG_ALERT_AGE_MS"],
    check: (a, b) => (3 * a <= b ? null : `three calls of ${a} must fit in CONFIG_ALERT_AGE_MS (${b})`),
    source:
      "One check asks up to three sources (@gray/snapshot SNAPSHOT_SOURCES), each for up to this long, the last at most twice CONFIG_HEDGE_MS " +
      "(at most this long, a cross check) after the first: it ends before the copy crosses the alert age, so replicas that hang never raise the " +
      "stale alert while ConfigDO answers (CONFIG_CALL_TIMEOUT_MS source). The alert age is at most CONFIG_MAX_AGE_MS, so the check also ends " +
      "before the refusal, which this bound kept before the owner's decision of 2026-10-18.",
  },
  {
    workers: ["gateway"],
    names: ["CONFIG_HEDGE_MS", "CONFIG_CALL_TIMEOUT_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most CONFIG_CALL_TIMEOUT_MS (${b})`),
    source: "A source not answered within its call timeout is given up and the next one asked at once: a hedge after that never comes.",
  },
  {
    workers: ["gateway"],
    names: ["CONFIG_HEDGE_MS", "REQUEST_PRE_BUDGET_MS"],
    check: (a, b) => (2 * a < b ? null : `twice ${a} must be less than REQUEST_PRE_BUDGET_MS (${b})`),
    source:
      "A check asks ConfigDO, its last source, twice CONFIG_HEDGE_MS after the first (docs/request-path-availability.md section 4.2, M4): a " +
      "request that waits for the check must see that call made within its budget, or a stalled region's replicas would refuse it with ConfigDO well.",
  },
  {
    workers: ["gateway", "jobs"],
    names: ["CONFIG_ALERT_AGE_MS", "CONFIG_MAX_AGE_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most CONFIG_MAX_AGE_MS (${b})`),
    source: "The alert says a copy is old while it is still served (CONFIG_ALERT_AGE_MS source); past CONFIG_MAX_AGE_MS nothing is served.",
  },
  {
    workers: ["gateway"],
    names: ["AFFINITY_ENTRIES_PER_WORKSPACE", "AFFINITY_WORKSPACES"],
    check: (a, b) => (a * b <= 163_840 ? null : `${a} entries for each of AFFINITY_WORKSPACES (${b}) are more than 163,840, a quarter of the isolate's memory`),
    source:
      "The isolate's affinity map at about 200 bytes an entry (AFFINITY_ENTRIES_PER_WORKSPACE source) takes at most a quarter of the isolate's " +
      "128 MB (C1): 163,840 entries, about 32 MB, beside the bodies a request holds (BODY_PARSE_MAX_BYTES, BODY_RAW_MAX_BYTES sources).",
  },
  {
    workers: ["gateway"],
    names: ["BODY_PARSE_MAX_BYTES", "BODY_RAW_MAX_BYTES"],
    check: (a, b) => (a <= b ? null : `${a} must be at most BODY_RAW_MAX_BYTES (${b})`),
    source: "Tier A ends where tier B starts (docs/cloudflare-native.md section 3): a parse limit above the raw limit would leave no tier B.",
  },
  {
    workers: ["jobs"],
    names: ["CONFIG_REBUILD_MS", "CONFIG_ALERT_AGE_MS"],
    check: (a, b) => (2 * a <= b ? null : `two rebuilds of ${a} must fit in CONFIG_ALERT_AGE_MS (${b})`),
    source:
      "One failed rebuild never raises the stale-snapshot alert (CONFIG_REBUILD_MS source): the snapshot is at most two intervals old when " +
      "a single rebuild has failed, and ConfigDO alerts past CONFIG_ALERT_AGE_MS.",
  },
  {
    workers: ["gateway"],
    names: ["ANSWER_PRIME_BYTES", "BODY_PARSE_MAX_BYTES"],
    check: (a, b) => (a <= b ? null : `${a} must be at most BODY_PARSE_MAX_BYTES (${b})`),
    source:
      "The bytes a non-streaming answer waits with before it starts are held whole, like a tier A body (ANSWER_PRIME_BYTES source). An answer can " +
      "still wait longer than that while the tool gate holds its first entry (a type that comes after the content, as a relay that sorts keys writes " +
      "it), while a call comes first, or while a top-level key that can make it an error is read; ANSWER_HELD_MAX_BYTES bounds that.",
  },
  {
    workers: ["gateway"],
    names: ["CONFIG_VERSION_CHECK_MS", "CONFIG_ALERT_AGE_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most CONFIG_ALERT_AGE_MS (${b})`),
    source:
      "The version check keeps a well-served copy confirmed before it crosses the alert age (CONFIG_VERSION_CHECK_MS source), and so before " +
      "the refusal (CONFIG_ALERT_AGE_MS is at most CONFIG_MAX_AGE_MS), the bound this check kept before the owner's decision of 2026-10-18.",
  },
  {
    workers: ["gateway"],
    names: ["ENDPOINT_ROOT_CALL_TIMEOUT_MS", "ENDPOINT_ACQUIRE_WAIT_MS"],
    check: (a, b) => (a < b ? null : `${a} must be below ENDPOINT_ACQUIRE_WAIT_MS (${b})`),
    source:
      "A shard waits for its root inside the gateway's wait for the permit; a root wait as long as the gateway's leaves no time for a warm " +
      "shard to answer, and every borrowed permit would arrive after the gateway gave up (ENDPOINT_ACQUIRE_WAIT_MS source). The shard also " +
      "ends the wait at the gateway's answerBy, which bounds a shard that started late (gateway.md section 14).",
  },
  {
    workers: ["gateway"],
    names: ["REST_RATE_MAX_SECONDS", "REST_QUOTA_MAX_SECONDS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most REST_QUOTA_MAX_SECONDS (${b}), a used-up allowance's longest rest`),
    source: "A rate limit, which passes sooner, rests no longer than a used-up allowance may (config/requests.rs `rests`).",
  },
  {
    workers: ["gateway"],
    names: ["REST_QUOTA_SECONDS", "REST_QUOTA_MAX_SECONDS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most REST_QUOTA_MAX_SECONDS (${b}), a used-up allowance's longest rest`),
    source: "A used-up allowance that states no reset rests no longer than one that does (config/requests.rs `rests`).",
  },
  {
    workers: ["gateway"],
    names: ["RETRY_BACKOFF_MS", "RETRY_BACKOFF_MAX_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most RETRY_BACKOFF_MAX_MS (${b})`),
    source: "The backoff starts at the first value and doubles up to the second (GRAY_RETRY_BACKOFF_MS must be at most GRAY_RETRY_BACKOFF_MAX_MS, config/requests.rs).",
  },
  {
    workers: ["gateway"],
    names: ["RETRY_TRANSIENT_COST", "RETRY_BUDGET_TOKENS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most RETRY_BUDGET_TOKENS (${b}): a retry that costs more than a full budget can never be paid`),
    source: "config/requests.rs `retries`: a retry that costs more than a full budget can never be paid.",
  },
  {
    workers: ["gateway"],
    names: ["RETRY_THROTTLED_COST", "RETRY_BUDGET_TOKENS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most RETRY_BUDGET_TOKENS (${b}): a retry that costs more than a full budget can never be paid`),
    source: "config/requests.rs `retries`: a retry that costs more than a full budget can never be paid.",
  },
  {
    workers: ["gateway"],
    names: ["UPSTREAM_ATTEMPT_SECONDS", "UPSTREAM_HEADER_MS"],
    check: (a, b) => (a === 0 || a * 1000 < b ? null : `${a} seconds must be below UPSTREAM_HEADER_MS (${b} ms): an attempt bound as long as the whole wait for an answer bounds nothing`),
    source: "GRAY_UPSTREAM_ATTEMPT_SECONDS must be less than GRAY_UPSTREAM_HEADER_SECONDS (config/requests.rs).",
  },
  {
    workers: ["gateway"],
    names: ["ENDPOINT_BREAKER_MIN_SAMPLES", "ENDPOINT_BREAKER_MAX_SAMPLES"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ENDPOINT_BREAKER_MAX_SAMPLES (${b})`),
    source: "A rate needs its least count of samples kept; the server's EndpointRanker::new refuses max_samples_per_endpoint below minimum_samples (ranking.rs).",
  },
  {
    workers: ["gateway"],
    names: ["ENDPOINT_BREAKER_HALF_LIFE_SECONDS", "ENDPOINT_BREAKER_STALE_SECONDS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most ENDPOINT_BREAKER_STALE_SECONDS (${b})`),
    source: "The server's EndpointRanker::new refuses stale_after_ms below half_life_ms (ranking.rs).",
  },
  {
    workers: ["gateway"],
    names: ["ENDPOINT_RECOVERY_WAIT_MS", "ENDPOINT_PROBE_LEASE_SECONDS"],
    check: (a, b) => (a <= b * 1000 ? null : `${a} must be at most ENDPOINT_PROBE_LEASE_SECONDS (${b} s)`),
    source: "A probe's lease bounds how long it is out; the server's EndpointRanker::new refuses recovery_wait_ms above recovery_lease_ms (ranking.rs).",
  },
  {
    workers: ["gateway"],
    names: ["STREAM_KEEPALIVE_MS", "UPSTREAM_SILENCE_MS"],
    check: (a, b) => (a < b ? null : `${a} must be below UPSTREAM_SILENCE_MS (${b})`),
    source: "A keep-alive covers an upstream's silence; one no sooner than the silence limit would never be written before the stream fails.",
  },
  {
    workers: ["gateway", "console"],
    names: ["MEDIA_DOWNLOAD_BYTES", "MEDIA_RESPONSE_BYTES"],
    check: (a, b) => (Math.ceil(a / 3) * 4 <= b ? null : `the base64 of ${a} bytes is above MEDIA_RESPONSE_BYTES (${b})`),
    source: "Inlined downloads are sent back as base64 within the answer limit (apis/images.rs DOWNLOAD_LIMIT): 24 MiB of images is 32 MiB of base64.",
  },
  {
    workers: ["gateway"],
    names: ["MEDIA_JOB_POLL_START_MS", "MEDIA_JOB_POLL_MAX_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most MEDIA_JOB_POLL_MAX_MS (${b})`),
    source: "The pause starts at the first value and doubles up to the second (apis/images.rs POLL_START, POLL_MAX).",
  },
  {
    workers: ["gateway"],
    names: ["VIDEO_POLL_MIN_MS", "VIDEO_POLL_INTERVAL_MS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most VIDEO_POLL_INTERVAL_MS (${b})`),
    source: "The Workflow's own polls are due after the interval; a least time above it would make every scheduled poll find the job not yet due.",
  },
  {
    workers: ["gateway"],
    names: ["VIDEO_JOB_TTL_SECONDS", "VIDEO_POLL_INTERVAL_MS"],
    check: (a, b) => {
      const steps = videoWorkflowSteps(a, b);
      return steps <= WORKFLOW_MAX_STEPS ? null : `a job polled every ${b} ms for ${a} s takes ${steps} Workflow steps, above ${WORKFLOW_MAX_STEPS}`;
    },
    source:
      "A Workflow instance takes at most 10,000 steps by default (https://developers.cloudflare.com/workflows/reference/limits/, read 2026-09-21 in " +
      "docs/cloudflare-native/research/cloudflare-facts.md section 3; workers-sdk workflows-shared DEFAULT_STEP_LIMIT, as miniflare runs it). " +
      "videoWorkflowSteps counts what a video job's Workflow takes at most (workers/gateway/src/workflows/video-job.ts).",
  },
  {
    workers: ["gateway"],
    names: ["VIDEO_MISSING_GRACE_SECONDS", "VIDEO_JOB_TTL_SECONDS"],
    check: (a, b) => (a <= b ? null : `${a} must be at most VIDEO_JOB_TTL_SECONDS (${b})`),
    source: "A job the upstream no longer reports should fail as missing, which a grace period longer than the job's life never lets happen.",
  },
  ...LEDGER_CROSS_CHECKS,
];

/** A bound between two text vars (CrossCheck's, for values that are not numbers). */
export interface TextCrossCheck {
  readonly workers: readonly WorkerName[];
  /** The vars, the one whose bound it is first. */
  readonly names: readonly [string, string];
  /** The problem, or null; called only when both vars parsed. */
  readonly check: (a: string, b: string) => string | null;
  readonly source: string;
}

export const TEXT_CROSS_CHECKS: readonly TextCrossCheck[] = [
  {
    workers: ["console"],
    names: ["LANE_STACK_RELEASE_LIST", "LANE_STACK_RELEASE_PUBLIC_KEY"],
    check: (a, b) => (a === "" || b !== "" ? null : "needs LANE_STACK_RELEASE_PUBLIC_KEY: gray-relay checks the list with its key"),
    source: "A relay accepts a release list only with the key it is signed with (deploy/tee/release/release.mjs, S11a); a list answered without it could not be read.",
  },
  {
    workers: ["console"],
    names: ["LANE_STACK_RELEASE_FRESHNESS_PUBLIC_KEY", "LANE_STACK_RELEASE_PUBLIC_KEY"],
    check: (a, b) => (a === "" || a !== b ? null : "is LANE_STACK_RELEASE_PUBLIC_KEY; the freshness key is a key of its own (D134)"),
    source: "docs/tee-lane-decisions.md D134: the online freshness key is never the offline release key (release.mjs refuses an environment whose two are one).",
  },
  {
    workers: ["console"],
    names: ["RELAY_KIT_URL", "RELAY_KIT_SHA256"],
    check: (a, b) => ((a === "") === (b === "") ? null : a === "" ? "is empty while RELAY_KIT_SHA256 is set; set both or neither" : "needs RELAY_KIT_SHA256: the agent instructions check the kit with it"),
    source: "The agent instructions download the kit only with the SHA-256 they check it against (RELAY_KIT_SHA256); a digest without a URL names nothing.",
  },
];

/**
 * The most steps a Workflow instance takes by default (https://developers.cloudflare.com/workflows/reference/limits/,
 * docs/cloudflare-native/research/cloudflare-facts.md section 3).
 */
export const WORKFLOW_MAX_STEPS = 10_000;

/**
 * `idle_in_transaction_session_timeout` of every transaction a Worker opens on PostgreSQL (`SET LOCAL` at its
 * `BEGIN`; never a session `SET`: Hyperdrive pools in transaction mode, docs/cloudflare-native/m0/database.md),
 * in ms: Hyperdrive ends any one statement after 60 s (https://developers.cloudflare.com/hyperdrive/platform/
 * limits/, docs/cloudflare-native/research/cloudflare-facts.md section 3). A Worker's transaction sends its
 * statements one after another, so one that has sent nothing for as long as a statement may run has no code
 * left to end it: an invocation that stopped mid-transaction (a client gone more than the 30 s waitUntil
 * allows, an exceeded limit, an isolate replaced) while the pool kept its server connection. PostgreSQL then
 * ends that session, which rolls the transaction back and frees its locks, the schema's write lock among them
 * (main 89b01024 found such a transaction holding a lock without end). A safeguard: real Hyperdrive cannot be
 * tried locally, and a closed client connection ends its transaction where it reaches the server.
 */
export const PG_IDLE_IN_TRANSACTION_MS = 60_000;

/** What a Worker sends after `BEGIN` in the same round trip: the transaction's idle limit (`PG_IDLE_IN_TRANSACTION_MS`). */
export const PG_TRANSACTION_SETTINGS = `SET LOCAL idle_in_transaction_session_timeout = ${PG_IDLE_IN_TRANSACTION_MS}`;

/**
 * The steps a video job's Workflow takes at most (workers/gateway/src/workflows/video-job.ts):
 * `register`, a sleep and a poll per interval until the job expires (the last poll at the deadline),
 * one more pair when a customer's read took the poll that was due, and `settle`. Sleeps are counted
 * although the local engine counts only `step.do` (workers-sdk workflows-shared), to stay on the safe
 * side of the documented limit.
 */
export function videoWorkflowSteps(ttlSeconds: number, pollIntervalMs: number): number {
  return 1 + 2 * (Math.ceil((ttlSeconds * 1000) / pollIntervalMs) + 1) + 1;
}

export class ConfigError extends Error {
  readonly problems: readonly Problem[];
  constructor(worker: WorkerName, problems: readonly Problem[]) {
    super(`gray-${worker} configuration is invalid: ${problems.map((p) => `${p.name}: ${p.message}`).join("; ")}`);
    this.name = "ConfigError";
    this.problems = problems;
  }
}

export function settingsFor(worker: WorkerName): readonly SettingSpec[] {
  return SETTINGS.filter((row) => row.workers.includes(worker));
}

/** Plain base-10 digits, leading zeros allowed, as the server reads a number (config/env.rs `plain_number`). */
const DECIMAL = /^[0-9]+$/;

function parseValue(row: SettingSpec, text: string): { ok: true; value: Value } | { ok: false; message: string } {
  if (row.type === "text") {
    const problem = row.textCheck ? row.textCheck(text) : "has no rule (a text row needs textCheck)";
    return problem === null ? { ok: true, value: text } : { ok: false, message: problem };
  }
  if (row.type === "enum") {
    return row.values?.includes(text) ? { ok: true, value: text } : { ok: false, message: row.refusal ?? `${JSON.stringify(text)} is not one of ${row.values?.join(", ")}` };
  }
  if (!DECIMAL.test(text)) return { ok: false, message: `${JSON.stringify(text)} is not a decimal integer` };
  const n = Number(text);
  if (!Number.isSafeInteger(n)) return { ok: false, message: `${text} is above the maximum ${Number.MAX_SAFE_INTEGER}` };
  if (row.min !== undefined && n < row.min) return { ok: false, message: `${n} is below the minimum ${row.min}` };
  if (row.max !== undefined && n > row.max) return { ok: false, message: `${n} is above the maximum ${row.max}` };
  const problem = row.check?.(n) ?? null;
  return problem === null ? { ok: true, value: n } : { ok: false, message: problem };
}

/**
 * verification.rs `check_confirmation`: what CHECK_CONFIRMATION set to `value` (undefined: unset) means, as the
 * console's configuration reads it: unset, empty and `on` confirm, `off` does not, and any other value is refused.
 */
export function checkConfirmation(value: string | undefined): { readonly ok: true; readonly on: boolean } | { readonly ok: false; readonly error: string } {
  const row = SETTINGS.find((r) => r.name === "CHECK_CONFIRMATION")!;
  const parsed = parseValue(row, value === undefined || value === "" ? row.default! : value);
  return parsed.ok ? { ok: true, on: parsed.value === "on" } : { ok: false, error: parsed.message };
}

/**
 * Parses every var of `worker` (a pure function). Unset or "" takes the default; a var without a
 * default is required. Names the table does not know are ignored (env also holds bindings).
 */
export function parseSettings(worker: WorkerName, env: Readonly<Record<string, unknown>>): { values: Record<string, Value>; problems: Problem[] } {
  const values: Record<string, Value> = {};
  const problems: Problem[] = [];
  for (const row of settingsFor(worker)) {
    const raw = env[row.name];
    if (raw !== undefined && typeof raw !== "string") {
      problems.push({ name: row.name, message: "must be a string" });
      continue;
    }
    const text = raw === undefined || raw === "" ? row.default : raw;
    if (text === undefined) {
      problems.push({ name: row.name, message: "required" });
      continue;
    }
    const parsed = parseValue(row, text);
    if (parsed.ok) values[row.key] = parsed.value;
    else problems.push({ name: row.name, message: parsed.message });
  }
  const byName = new Map(settingsFor(worker).map((row) => [row.name, row.key]));
  for (const cross of CROSS_CHECKS) {
    if (!cross.workers.includes(worker)) continue;
    const [a, b] = cross.names.map((name) => values[byName.get(name) ?? ""]);
    if (typeof a !== "number" || typeof b !== "number") continue;
    const problem = cross.check(a, b);
    if (problem !== null) problems.push({ name: cross.names[0], message: problem, names: cross.names });
  }
  for (const cross of TEXT_CROSS_CHECKS) {
    if (!cross.workers.includes(worker)) continue;
    const [a, b] = cross.names.map((name) => values[byName.get(name) ?? ""]);
    if (typeof a !== "string" || typeof b !== "string") continue;
    const problem = cross.check(a, b);
    if (problem !== null) problems.push({ name: cross.names[0], message: problem, names: cross.names });
  }
  return { values, problems };
}

export interface GatewayConfig {
  readonly deployEnv: DeployEnv;
  readonly accountShardCount: number;
  readonly accountShardTargetRps: number;
  readonly settleBatchMs: number;
  readonly accountAllowanceSeconds: number;
  readonly accountAllowanceMinMicroUsd: number;
  readonly accountLowWaterPercent: number;
  readonly accountIdleReturnMs: number;
  readonly accountStandingReturnMs: number;
  readonly accountVersionCheckMs: number;
  readonly accountLeaseMs: number;
  readonly accountKeyListMaxAgeMs: number;
  readonly accountClientKeyFallback: ClientKeyFallbackSetting;
  readonly accountLimitGrantPercent: number;
  readonly accountHoldMarginMs: number;
  readonly accountReplayCacheMs: number;
  readonly accountShardFloorMicroUsd: number;
  readonly accountRootCallTimeoutMs: number;
  readonly accountAdmitAttemptMs: number;
  readonly accountAdmitBudgetMs: number;
  /** REQUEST_PRE_BUDGET_MS, REQUEST_POST_BUDGET_MS: the request's two phase deadlines on Gray's own dependencies (gateway/src/budget.ts). */
  readonly requestPreBudgetMs: number;
  readonly requestPostBudgetMs: number;
  /** ANSWER_MARGIN_MS: how much before the gateway's wait ends a shard waiting on its root answers. */
  readonly answerMarginMs: number;
  /** ACCOUNT_MINUTE_CEILING_CHUNKS: the chunks of a key's minute share an account shard writes ahead (`countedUpTo`). */
  readonly accountMinuteCeilingChunks: number;
  readonly projectionIntervalMs: number;
  readonly projectionRetryMaxMs: number;
  readonly endpointRootLocationHint: LocationHint;
  readonly streamTotalSeconds: number;
  readonly bodyParseMaxBytes: number;
  readonly bodyRawMaxBytes: number;
  /** AFFINITY_ENTRIES_PER_WORKSPACE, AFFINITY_WORKSPACES: the bounds of the isolate's cache affinity map. */
  readonly affinityEntriesPerWorkspace: number;
  readonly affinityWorkspaces: number;
  readonly answerHeldMaxBytes: number;
  readonly answerPrimeBytes: number;
  readonly usageMissing: UsageMissingRule;
  readonly imageUsageUnsplit: ImageUsageUnsplit;
  readonly translationFallback: TranslationFallback;
  readonly requestBodyMs: number;
  readonly upstreamHeaderMs: number;
  readonly upstreamSilenceMs: number;
  readonly nonStreamTotalMs: number;
  readonly streamHeadersMs: number;
  /** LANE_SCHEDULER_PICK_MS (D109'): the lane's pick budget; each forward carries what is left of it as `budget_ms` (D122'). */
  readonly laneSchedulerPickMs: number;
  /** LANE_ROUTE_WARM_MS (M13): how long the lane keeps asking a route's shard to hold its standing permit as the route goes live. */
  readonly laneRouteWarmMs: number;
  /** LANE_BRIDGE_ANSWER_MARGIN_MS (M14): what of an admission attempt's wait the lane keeps for the way back from the bridge. */
  readonly laneBridgeAnswerMarginMs: number;
  /** LANE_STACK_POLL_MS (S28): a relay-stack lane's bridge poll and table re-push interval. */
  readonly laneStackPollMs: number;
  /** LANE_STACK_REPORT_MIN_MS (S42): the shortest interval between two stack.report calls carrying a change. */
  readonly laneStackReportMinMs: number;
  /** LANE_STACK_REPORT_HEARTBEAT_MS (S42): stack.report's interval when nothing changed. */
  readonly laneStackReportHeartbeatMs: number;
  /**
   * PEER_PROBE_MS, PEER_DOWN_MS, PEER_DOWN_MAX_MS, PEER_RECHECK_MS, PEER_RENEW_MS, PEER_CALL_MS (routing PR 9): an entry's peer
   * registry's probe interval, backoff, recheck of a refused peer, renewal lead and background call bound (lane `peer-client.ts`).
   */
  readonly peerProbeMs: number;
  readonly peerDownMs: number;
  readonly peerDownMaxMs: number;
  readonly peerRecheckMs: number;
  readonly peerRenewMs: number;
  readonly peerCallMs: number;
  /** PEER_FOLLOW_UP_MS (routing PR 9): the longest an entry asks a stack VM about an attempt the hop left unknown. */
  readonly peerFollowUpMs: number;
  /** LANE_POLICY_FUEL_PER_MS (F2 D128): the lane's policy sandbox throughput, for the policy step's budget. */
  readonly lanePolicyFuelPerMs: number;
  /** LANE_POLICY_OVERHEAD_MS (F2 D128): the fixed cost around one policy run, for the policy step's budget. */
  readonly lanePolicyOverheadMs: number;
  readonly streamKeepAliveMs: number;
  readonly streamClientStallMs: number;
  readonly configVersionCheckMs: number;
  readonly configMaxAgeMs: number;
  readonly configAlertAgeMs: number;
  readonly alertGroupMs: number;
  readonly platformFeeBps: number;
  readonly gatewayFallbackRegion: LocationHint;
  /** Where ConfigDO and the RoundDOs are created: gray-jobs' JOBS_LOCATION_HINT, which every caller passes. */
  readonly jobsLocationHint: LocationHint;
  /** The console's origin whose pages may call the model API cross-origin; "" for none (workers/gateway/src/cors.ts). */
  readonly consoleOrigin: string;
  readonly endpointReportMs: number;
  readonly endpointBreakerFailureThreshold: number;
  readonly endpointBreakerMinSamples: number;
  readonly endpointBreakerFailureRatePercent: number;
  readonly endpointBreakerHalfLifeSeconds: number;
  readonly endpointBreakerStaleSeconds: number;
  readonly endpointBreakerMaxSamples: number;
  readonly endpointBreakerCooldownSeconds: number;
  readonly endpointProbeLeaseSeconds: number;
  readonly endpointRecoverySuccesses: number;
  readonly endpointHealthSaveMs: number;
  readonly endpointHealthCheckpointMs: number;
  readonly endpointUnobservedWorkSeconds: number;
  readonly endpointPermitHeadroomPercent: number;
  readonly endpointIdleReturnSeconds: number;
  readonly endpointStandingReturnSeconds: number;
  readonly endpointShardTargetRps: number;
  readonly endpointShardMax: number;
  readonly endpointRootCallTimeoutMs: number;
  readonly endpointAcquireWaitMs: number;
  readonly retryMaxAttempts: number;
  readonly retrySameOperator: number;
  readonly retrySecondOpinion: number;
  readonly retryBackoffMs: number;
  readonly retryBackoffMaxMs: number;
  readonly retryAfterMaxSeconds: number;
  readonly retryBudgetTokens: number;
  readonly retryTransientCost: number;
  readonly retryThrottledCost: number;
  readonly retryConcurrencyPercent: number;
  readonly retryConcurrencyMin: number;
  /** REST_*: how long a route that failed for a known cause is passed over (@gray/errors rests.ts). */
  readonly restRateMaxSeconds: number;
  readonly restQuotaSeconds: number;
  readonly restQuotaMaxSeconds: number;
  readonly restCreditSeconds: number;
  readonly restAuthSeconds: number;
  readonly restRestrictedSeconds: number;
  /** ERROR_TEXT_FALLBACK: whether a failure no code decides is read by its words (@gray/errors `readRest`). */
  readonly errorTextFallback: ErrorTextFallback;
  /** UPSTREAM_ATTEMPT_SECONDS; 0: no attempt bound. */
  readonly upstreamAttemptSeconds: number;
  readonly endpointRecoveryWaitMs: number;
  readonly trustRegexCompileMaxBytes: number;
  readonly trustSchemaCompileBudgetMs: number;
  readonly trustSchemaCacheSubschemas: number;
  readonly trustVerdictCacheKeyUnits: number;
  /** ISOLATE_TABLE_ENTRIES: each learned table of the gateway's isolate (gateway/src/tables.ts). */
  readonly isolateTableEntries: number;
  /** TRUST_POLICY: the tool gate's policy, JSON text. */
  readonly trustPolicy: string;
  readonly continuationBuckets: number;
  readonly continuationCallTimeoutMs: number;
  /** TOOL_CALL_ID_MINTING. */
  readonly toolCallIdMinting: "off" | "on";
  readonly toolCallIdCacheBytes: number;
  readonly toolCallIdCallTimeoutMs: number;
  readonly mediaResponseBytes: number;
  readonly mediaDownloadBytes: number;
  readonly mediaDownloadRedirects: number;
  readonly mediaJobPollStartMs: number;
  readonly mediaJobPollMaxMs: number;
  readonly videoPollIntervalMs: number;
  readonly videoPollMinMs: number;
  readonly videoJobTtlSeconds: number;
  readonly videoWatchdogMs: number;
  readonly videoStepRetries: number;
  readonly videoStepRetryDelayMs: number;
  readonly videoStepTimeoutMs: number;
  readonly videoMissingPolls: number;
  readonly videoMissingGraceSeconds: number;
  readonly videoContentBytes: number;
  readonly videoContentHeadersMs: number;
  readonly videoContentIdleMs: number;
  readonly videoContentTotalMs: number;
  readonly videoContentHops: number;
  readonly configReplicasPerRegion: number;
  readonly configCallTimeoutMs: number;
  readonly configHedgeMs: number;
  readonly internalCallTimeoutMs: number;
  readonly contentIsolateMaxBytes: number;
  readonly contentPieceBytes: number;
  readonly contentPutTimeoutMs: number;
  readonly contentTailReserveMs: number;
  readonly indexSendRetryMs: number;
  readonly indexSendRetryMaxMs: number;
  readonly sinkSendTimeoutMs: number;
  readonly contentRequestBlockBytes: number;
  readonly contentDeflateLevel: number;
  /** CONTENT_RECIPIENT_KEYS, `kid:base64[,kid:base64]`; "" for none. */
  readonly contentRecipientKeys: string;
}

export interface JobsConfig extends LedgerJobsConfig {
  readonly deployEnv: DeployEnv;
  readonly endpointRootLocationHint: LocationHint;
  readonly configRebuildMs: number;
  readonly configAlertAgeMs: number;
  readonly alertGroupMs: number;
  readonly internalCallTimeoutMs: number;
  readonly jobsLocationHint: LocationHint;
  readonly configReplicaCheckMs: number;
  readonly configCallTimeoutMs: number;
  readonly configPublishConcurrency: number;
  readonly jobsStatementTimeoutMs: number;
  /** ROUTE_ACTIVITY_SLOTS: the slots of route_activity and model_demand (request-index.ts). */
  readonly routeActivitySlots: number;
  readonly queueRetryBaseSeconds: number;
  readonly queueRetryMaxSeconds: number;
  readonly reconcileIntervalMs: number;
  readonly reconcileWaitMs: number;
  readonly reconcileStepMs: number;
  /** How long a refusal of the coding-agent check outranks a later pass when either came from traffic (the console's floor). */
  readonly evidenceFloorSeconds: number;
  /** PLATFORM_FEE_BPS: the public catalog's customer prices (ConfigDO `catalog`). */
  readonly platformFeeBps: number;
  /** CONFIG_MAX_AGE_MS: past it since the last complete rebuild, the public catalog lists nothing (ConfigDO `catalog`). */
  readonly configMaxAgeMs: number;
  /** BASIN_SQL_URL: the wide events the records check reads (records-check.ts); "" when unset: only charged requests are checked. */
  readonly basinSqlUrl: string;
  /** "" when unset. */
  readonly basinSqlWarehouse: string;
  /** Comma-separated `namespace.table`. */
  readonly basinSqlRequestTables: string;
  readonly basinSqlTimeoutMs: number;
  /**
   * MODELTRACE_MODELS as given ("" when unset): which models ModelTrace checks, read by @gray/modeltrace
   * `CheckedModels.parse`. The snapshot routes only a checked model at its ModelTrace weight, and the catalog says per
   * model whether it is checked.
   */
  readonly modeltraceModels: string;
}
export { LEDGER_JOBS_KEYS, type LedgerJobsConfig } from "./ledger.ts";

export interface ConsoleConfig {
  readonly deployEnv: DeployEnv;
  readonly endpointRootLocationHint: LocationHint;
  /** GATEWAY_FALLBACK_REGION: a new workspace's home region when its request names no continent (`requestRegion`). */
  readonly gatewayFallbackRegion: LocationHint;
  /** Where ConfigDO and the RoundDOs are created: gray-jobs' JOBS_LOCATION_HINT, which every caller passes. */
  readonly jobsLocationHint: LocationHint;
  readonly origin: string;
  /** The model API's origin; `origin` itself in the one-origin setup. */
  readonly apiOrigin: string;
  /** Comma-separated; workers/console reads it as a list. */
  readonly adminWallets: string;
  readonly accessTeamDomain: string;
  readonly accessAud: string;
  readonly identityTimeoutMs: number;
  readonly mossNetwork: "testnet" | "mainnet";
  readonly mossDestination: string;
  readonly mossTokenAddress: string;
  readonly mossTokenDecimals: number;
  readonly creditContract: string;
  /** "" for the MOSS network's chain. */
  readonly creditChainId: string;
  readonly platformFeeBps: number;
  readonly welcomeCreditMicroUsd: number;
  readonly welcomeCreditDailyLimit: number;
  /** "" when unset. */
  readonly mossRpcUrl: string;
  readonly mossVerifyTimeoutMs: number;
  readonly chainRpcTimeoutMs: number;
  readonly setupClaimsPerNetwork: number;
  readonly setupClaimWindowSeconds: number;
  readonly setupClaimWindowWaitMs: number;
  readonly internalCallTimeoutMs: number;
  /** LANE_STACK_USAGE_KEEP_DAYS: the days of lane_stack_usage the console keeps and reads. */
  readonly laneStackUsageKeepDays: number;
  /** LANE_STACK_VM_PAYER: who pays for a relay VM unless the operator's quota decision names the payer. */
  readonly laneStackVmPayer: "gray" | "relay";
  /** LANE_STACK_AUTO_VM_QUOTA: whether a relay's first VM quota is approved at once (owner, 2026-11-02). */
  readonly laneStackAutoVmQuota: "off" | "on";
  /** LANE_STACK_AUTO_VM_INSTANCE_TYPE: the instance type an automatic quota names. */
  readonly laneStackAutoVmInstanceType: string;
  /** LANE_STACK_AUTO_VM_MAX: the most automatically approved, not deleted relay VMs. */
  readonly laneStackAutoVmMax: number;
  /** LANE_STACK_ALERT_FROM: the sender of relay alert e-mails; empty: none sent. */
  readonly laneStackAlertFrom: string;
  /** LANE_STACK_TUNNEL_ZONE: the relays zone of Gray's tunnel rendezvous; empty: none. */
  readonly laneStackTunnelZone: string;
  /** LANE_STACK_ENTRY_ORIGIN: the entry whose health route shows an outbound-only relay's sessions (docs/design/relay-outbound-only.md 5); empty: none. */
  readonly laneStackEntryOrigin: string;
  /** LANE_STACK_ENTRY_TIMEOUT_MS: the relay panel's bound on one read of the entry's health route. */
  readonly laneStackEntryTimeoutMs: number;
  /** LANE_STACK_OUTBOUND_MIN_KIT: the lowest gray-relay kit an outbound-only release may boot for (R10). */
  readonly laneStackOutboundMinKit: string;
  /** LANE_STACK_ROLLOUT_MIN_KIT: the lowest gray-relay kit whose rollouts run without downtime; empty: none. */
  readonly laneStackRolloutMinKit: string;
  /** LANE_STACK_RELEASE_MOVES: whether the console moves running VMs to the relay's newest accepted release. */
  readonly laneStackReleaseMoves: LaneStackReleaseMoveMode;
  /** LANE_STACK_RELEASE_MOVE_RETRY_MS: how long after a failed move to a release the console tries it again. */
  readonly laneStackReleaseMoveRetryMs: number;
  /** LANE_STACK_RELEASE_LIST (S57): the relay stacks' signed release list the pairing answers; empty: none. */
  readonly laneStackReleaseList: string;
  /** LANE_STACK_RELEASE_PUBLIC_KEY: the list's signing key, 64 hex; empty: none. */
  readonly laneStackReleasePublicKey: string;
  /** LANE_STACK_RELEASE_FRESHNESS_PUBLIC_KEY: the list's freshness key, 64 hex; empty: none. */
  readonly laneStackReleaseFreshnessPublicKey: string;
  /** LANE_STACK_TUNNEL_SERVER (S57): the rendezvous's frps, host:port; empty: none. */
  readonly laneStackTunnelServer: string;
  /** LANE_STACK_AGENT_IMAGE: the gray-relay image the panel's pairing commands run, pinned by digest; empty: gray-relay init. */
  readonly laneStackAgentImage: string;
  /** RELAY_KIT_URL: the published relay kit's archive, an https URL; empty: not published. */
  readonly relayKitUrl: string;
  /** RELAY_KIT_SHA256: the kit archive's SHA-256, 64 lower-case hex; empty with RELAY_KIT_URL. */
  readonly relayKitSha256: string;
  /** RELAY_STANDARD_URL: where the relay integration standard is published, an https URL; empty: not yet. */
  readonly relayStandardUrl: string;
  /** RELAY_CONFORMANCE_IMAGE: the conformance tool image, pinned by digest; empty: built from the kit. */
  readonly relayConformanceImage: string;
  /** LANE_STACK_PROXY_CHECK_EXPIRY_MS: how long a queued proxy check waits for the VM's answer before it expires. */
  readonly laneStackProxyCheckExpiryMs: number;
  /** LANE_STACK_TRACE_KEEP_DAYS (S46): the days of lane_stack_traces the console keeps. */
  readonly laneStackTraceKeepDays: number;
  /** LANE_STACK_TEST_EXPIRY_MS (S44): how long a queued account test waits for the VM's answer before it expires. */
  readonly laneStackTestExpiryMs: number;
  /** LANE_STACK_TEST_KEEP_DAYS (S46): the days of lane_stack_tests the console keeps. */
  readonly laneStackTestKeepDays: number;
  /** LANE_STACK_DEBUG_SHARE_KEEP_DAYS: the days of lane_stack_debug_shares the console keeps after a share's last report. */
  readonly laneStackDebugShareKeepDays: number;
  /** LANE_STACK_EJECTION: whether a relay's reported violation takes it out of routing (docs/design/relay-ejection.md). */
  readonly laneStackEjection: LaneStackEjectionMode;
  readonly laneStackEjectionContact: string;
  /** RELAY_SHARE_RPC_URLS: "" when unset, else one or two comma-separated http(s) URLs. */
  readonly relayShareRpcUrls: string;
  readonly relayShareChainId: number;
  /** RELAY_PHASE2_RELAYS: "", "*" or relay ids (relayOnPhase2 reads it). */
  readonly relayPhase2Relays: string;
  /** RELAY_CHAIN_PROPOSER: Gray's release proposer address; "" when unset (no phase-2 pairing). */
  readonly relayChainProposer: string;
  readonly relayChainDstackKms: string;
  /** RELAY_CHAIN_KMS_IDS: the Phala KMS ids on the relays' chain, comma-separated. */
  readonly relayChainKmsIds: string;
  /** RELAY_CHAIN_KIT_RPC_URLS: the two endpoints a phase-2 pairing gives gray-assistant, comma-separated. */
  readonly relayChainKitRpcUrls: string;
  /** Always off on Workers (DEBT_MODE_RULE). */
  readonly debtMode: "off";
  readonly creditFailureAdvances: "off" | "on";
  readonly creditMaxRelayerLanes: number;
  readonly creditLaneStatusTimeoutMs: number;
  readonly creditLaneResumeTimeoutMs: number;
  /** "" when unset. */
  readonly creditFunderAddress: string;
  /** "" when unset: `keyListOf` reads it. */
  readonly authKeysOps: string;
  readonly loupePartChars: number;
  readonly loupeReadConcurrency: number;
  readonly loupeOpenMaxBytes: number;
  readonly loupeQuerySeconds: number;
  readonly transcriptParseMaxBytes: number;
  readonly consoleContentReadMaxBytes: number;
  readonly contentOpenWaitMs: number;
  /** "" when unset: the event store is not configured. */
  readonly basinSqlUrl: string;
  /** "" when unset. */
  readonly basinSqlWarehouse: string;
  /** Comma-separated `namespace.table`. */
  readonly basinSqlRequestTables: string;
  readonly basinSqlTimeoutMs: number;
  /** The gateway's CONFIG_MAX_AGE_MS: the operations investigation reports when the current snapshot expires. */
  readonly configMaxAgeMs: number;
  readonly checkGlobalDailyMicroUsd: number;
  readonly checkWorkspaceDailyMicroUsd: number;
  readonly checkConfirmation: CheckConfirmation;
  /** ALLOW_PRIVATE_UPSTREAMS, as set; `allowPrivateUpstreams` says whether it applies. */
  readonly allowPrivateUpstreams: PrivateUpstreamSwitch;
  readonly probeRequestTimeoutMs: number;
  /** The gateway's MEDIA_RESPONSE_BYTES, MEDIA_DOWNLOAD_BYTES and MEDIA_DOWNLOAD_REDIRECTS: a model-API check reads and downloads as serving does. */
  readonly mediaResponseBytes: number;
  readonly mediaDownloadBytes: number;
  readonly mediaDownloadRedirects: number;
  readonly evidenceRefreshSeconds: number;
  readonly evidenceTtlSeconds: number;
  readonly paidEvidenceRefreshSeconds: number;
  readonly evidenceFloorSeconds: number;
  readonly failureRecheckSeconds: number;
  readonly maintenanceStallAlertPercent: number;
  /**
   * MODELTRACE_MODELS as given ("" when unset): which models ModelTrace checks, read by @gray/modeltrace
   * `CheckedModels.parse`. Maintenance plans rounds only for a checked model, and a provider sees a model check only of one.
   */
  readonly modeltraceModels: string;
  /**
   * MODELTRACE_ROUND_INTERVAL_MS: the longest wait between two rounds of a binding, the floor each round draws below it
   * (@gray/modeltrace `recheckAt`).
   */
  readonly modeltraceRoundIntervalMs: number;
  /**
   * MODELTRACE_TRAFFIC_SHARE_BPS: the share of what a provider earns on a binding that its probes are meant to cost, in
   * basis points (@gray/modeltrace `recheckServed`); 0 turns the traffic trigger off, the floor alone.
   */
  readonly modeltraceTrafficShareBps: number;
  /** MODELTRACE_LANE_URL: the lane entry's origin for confidential-lane relays' probes; "" when unset: they have no rounds. */
  readonly modeltraceLaneUrl: string;
  /** WORKSPACE_DELETION_WAIT_MS: how long a workspace's closure waits for its data's deletion before it answers. */
  readonly workspaceDeletionWaitMs: number;
  readonly maintenanceLocationHint: LocationHint;
  /** "" for the representative suite. */
  readonly benchmarkSuite: string;
  readonly benchmarkStartRetryMs: number;
  readonly benchmarkStartRetryMaxMs: number;
  readonly benchmarkStartAttempts: number;
  readonly providerAdmissionPolicy: string;
  readonly providerAdmissionTariffs: string;
}

export interface IdentityConfig {
  readonly deployEnv: DeployEnv;
  readonly origin: string;
  readonly identityVerifyTimeoutMs: number;
  readonly mossNetwork: "testnet" | "mainnet";
}

/** gray-alerts, the alert router (workers/alerts). */
export interface AlertsConfig {
  readonly deployEnv: DeployEnv;
  readonly alertPaging: AlertPaging;
  readonly alertGroupMs: number;
  readonly alertRunbookUrl: string;
  readonly alertDeliveryRetryMs: number;
  readonly alertDeliveryRetryMaxMs: number;
  readonly alertDeliveryTimeoutMs: number;
  readonly alertDeliveryGiveUpMs: number;
  readonly alertKeyRetentionMs: number;
}

/** gray-content's vars (workers/content). */
export interface ContentConfig {
  readonly deployEnv: DeployEnv;
  readonly contentKeyLeadDays: number;
  readonly contentReadMaxBytes: number;
  readonly contentOpenWaitMs: number;
  readonly contentStatementTimeoutMs: number;
  readonly accessTeamDomain: string;
  readonly accessAud: string;
}

function parseFor(worker: WorkerName, env: Readonly<Record<string, unknown>>): Readonly<Record<string, Value>> {
  const { values, problems } = parseSettings(worker, env);
  if (problems.length > 0) throw new ConfigError(worker, problems);
  return Object.freeze(values);
}

export function parseGatewayConfig(env: Readonly<Record<string, unknown>>): GatewayConfig {
  return parseFor("gateway", env) as unknown as GatewayConfig;
}

export function parseJobsConfig(env: Readonly<Record<string, unknown>>): JobsConfig {
  return parseFor("jobs", env) as unknown as JobsConfig;
}

/**
 * The server's `allow_private_upstreams`: ALLOW_PRIVATE_UPSTREAMS is `1` and this is not production. Provider setup
 * then takes plain-http upstreams (`plain_http`), and checks may reach private addresses (the probe policy's
 * `allowPrivateNetwork`).
 */
export function allowPrivateUpstreams(config: Pick<ConsoleConfig, "allowPrivateUpstreams" | "deployEnv">): boolean {
  return config.allowPrivateUpstreams === "1" && config.deployEnv !== "production";
}

export function parseConsoleConfig(env: Readonly<Record<string, unknown>>): ConsoleConfig {
  return parseFor("console", env) as unknown as ConsoleConfig;
}

export function parseIdentityConfig(env: Readonly<Record<string, unknown>>): IdentityConfig {
  return parseFor("identity", env) as unknown as IdentityConfig;
}

export function parseAlertsConfig(env: Readonly<Record<string, unknown>>): AlertsConfig {
  return parseFor("alerts", env) as unknown as AlertsConfig;
}

export function parseContentConfig(env: Readonly<Record<string, unknown>>): ContentConfig {
  return parseFor("content", env) as unknown as ContentConfig;
}

const gatewayCache = new WeakMap<object, GatewayConfig>();
const jobsCache = new WeakMap<object, JobsConfig>();
const consoleCache = new WeakMap<object, ConsoleConfig>();
const identityCache = new WeakMap<object, IdentityConfig>();
const alertsCache = new WeakMap<object, AlertsConfig>();
const contentCache = new WeakMap<object, ContentConfig>();

/** `parseGatewayConfig`, once per env object (an isolate, or a Durable Object's env). Frozen. */
export function gatewayConfig(env: object): GatewayConfig {
  let cfg = gatewayCache.get(env);
  if (!cfg) {
    cfg = parseGatewayConfig(env as Readonly<Record<string, unknown>>);
    gatewayCache.set(env, cfg);
  }
  return cfg;
}

/** `parseJobsConfig`, once per env object. Frozen. */
export function jobsConfig(env: object): JobsConfig {
  let cfg = jobsCache.get(env);
  if (!cfg) {
    cfg = parseJobsConfig(env as Readonly<Record<string, unknown>>);
    jobsCache.set(env, cfg);
  }
  return cfg;
}

/** `parseConsoleConfig`, once per env object. Frozen. */
export function consoleConfig(env: object): ConsoleConfig {
  let cfg = consoleCache.get(env);
  if (!cfg) {
    cfg = parseConsoleConfig(env as Readonly<Record<string, unknown>>);
    consoleCache.set(env, cfg);
  }
  return cfg;
}

/** `parseIdentityConfig`, once per env object. Frozen. */
export function identityConfig(env: object): IdentityConfig {
  let cfg = identityCache.get(env);
  if (!cfg) {
    cfg = parseIdentityConfig(env as Readonly<Record<string, unknown>>);
    identityCache.set(env, cfg);
  }
  return cfg;
}

/** `parseAlertsConfig`, once per env object. Frozen. */
export function alertsConfig(env: object): AlertsConfig {
  let cfg = alertsCache.get(env);
  if (!cfg) {
    cfg = parseAlertsConfig(env as Readonly<Record<string, unknown>>);
    alertsCache.set(env, cfg);
  }
  return cfg;
}

/** `parseContentConfig`, once per env object. Frozen. */
export function contentConfig(env: object): ContentConfig {
  let cfg = contentCache.get(env);
  if (!cfg) {
    cfg = parseContentConfig(env as Readonly<Record<string, unknown>>);
    contentCache.set(env, cfg);
  }
  return cfg;
}
