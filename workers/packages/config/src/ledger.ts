import type { CrossCheck, SettingSpec } from "./index.ts";

/**
 * The vars of gray-jobs' background ledger: the chain reader, the hourly rounds and their payments,
 * the mints, the welcome grants, debt mode's readings, and how the jobs call the credit Workers
 * (workers/jobs/src/chain, docs/cloudflare-native/ledger.md). Each row is the server's setting of the
 * same meaning (crates/gray-gateway/src/config/onchain.rs, `GRAY_` dropped) with its default and
 * bounds, unless its source says otherwise. Secrets (the RPC URL, the signing keys) are not here:
 * they are read where they are used.
 *
 * Kept apart from index.ts so that the lines adding rows do not edit the same lines; index.ts
 * appends these to SETTINGS and JobsConfig extends LedgerJobsConfig.
 */

const ONCHAIN = "crates/gray-gateway/src/config/onchain.rs";
const hex = (bytes: number) => (value: string) =>
  value.length === 2 + 2 * bytes && value.startsWith("0x") && [...value.slice(2)].every((c) => "0123456789abcdef".includes(c.toLowerCase()))
    ? null
    : `${JSON.stringify(value)} is not 0x and ${2 * bytes} hex digits`;
const orNone = (check: (value: string) => string | null) => (value: string) => (value === "none" ? null : check(value));

/** The rows; `locationHints` is index.ts's list, passed in so this module imports no value from it. */
export function ledgerSettings(locationHints: readonly string[]): readonly SettingSpec[] {
  return [
    {
      // Named as the credit Workers name it (workers/credit/src/lib/config.ts CHAIN_ID), not GRAY_CREDIT_CHAIN_ID's
      // CREDIT_CHAIN_ID: that row is the console's (the chain its runtime config states), and a name means one row.
      name: "CHAIN_ID",
      key: "chainId",
      workers: ["jobs"],
      type: "int",
      default: "0",
      min: 0,
      max: Number.MAX_SAFE_INTEGER,
      source:
        `${ONCHAIN} GRAY_CREDIT_CHAIN_ID; the server takes it from GRAY_MOSS_NETWORK (6343 testnet, 4326 mainnet), the jobs from this var, which must equal ` +
        "the credit Workers' CHAIN_ID (every signed call carries it, workers/credit/src/lib/auth.ts). 0 is the jobs' own default: the chain is not read " +
        "until an environment names its chain (and its RPC, the secret CHAIN_RPC_URL).",
      doc: "Chain id of the credit contract; part of every signed call to the credit Workers. 0: the chain reader, the rounds, the mints and the grants stay off.",
    },
    {
      // As the credit Workers name it (CONTRACT_ADDRESS); CREDIT_CONTRACT is the console's row.
      name: "CONTRACT_ADDRESS",
      key: "contractAddress",
      workers: ["jobs"],
      type: "text",
      default: "none",
      textCheck: orNone(hex(20)),
      source:
        `${ONCHAIN} GRAY_CREDIT_CONTRACT (required with the credit Workers), which must equal the credit Workers' CONTRACT_ADDRESS; "none" is the jobs' ` +
        "default, an environment without the chain.",
      doc: "GrayCredit's address (contracts/deployments/<chainId>.json). Required whenever CHAIN_ID is set.",
    },
    {
      name: "CREDIT_START_BLOCK",
      key: "creditStartBlock",
      workers: ["jobs"],
      type: "int",
      default: "0",
      min: 0,
      max: Number.MAX_SAFE_INTEGER,
      source: `${ONCHAIN} GRAY_CREDIT_START_BLOCK (default 0; deployBlock of the deployment record, required in production).`,
      platform: "At most 2^53 - 1, where the server takes any u64: the jobs' chain reader counts blocks in JavaScript numbers, exact up to there.",
      doc: "The block the contract was deployed in (deployBlock of the deployment record), from which its events are read; required in production",
    },
    {
      name: "CHAIN_MULTICALL3",
      key: "chainMulticall3",
      workers: ["jobs"],
      type: "text",
      default: "0xca11bde05977b3631167028862be2a173976ca11",
      textCheck: orNone(hex(20)),
      source: `${ONCHAIN} GRAY_CHAIN_MULTICALL3: Multicall3's address on most chains (crates/gray-credit/src/abi.rs MULTICALL3).`,
      doc: "Where Multicall3 is; none reads views one call each, and so does an address without code",
    },
    {
      name: "CREDIT_CODE_HASH",
      key: "creditCodeHash",
      workers: ["jobs"],
      type: "text",
      default: "none",
      shown: "unset",
      textCheck: orNone(hex(32)),
      source: `${ONCHAIN} GRAY_CREDIT_CODE_HASH (unset by default; codeHash of the deployment record).`,
      doc: "keccak256 of the contract's code (codeHash of the deployment record); when set, nothing is read from a contract with other code",
    },
    {
      name: "CHAIN_LOG_BLOCKS",
      key: "chainLogBlocks",
      workers: ["jobs"],
      type: "int",
      default: "2000",
      min: 1,
      max: 100000,
      source: `${ONCHAIN} GRAY_CHAIN_LOG_BLOCKS: 2,000, from 1 to 100,000.`,
      doc: "Blocks per eth_getLogs",
    },
    {
      name: "CHAIN_MAX_PAGES",
      key: "chainMaxPages",
      workers: ["jobs"],
      type: "int",
      default: "50",
      min: 1,
      max: 10000,
      source: `${ONCHAIN} GRAY_CHAIN_MAX_PAGES: 50, from 1 to 10,000.`,
      doc: "Log pages one scan reads; with CHAIN_LOG_BLOCKS it sets how fast the chain reader catches up after a pause",
    },
    {
      name: "CHAIN_SCAN_SECONDS",
      key: "chainScanSeconds",
      workers: ["jobs"],
      type: "int",
      default: "60",
      min: 5,
      max: 3600,
      source: `${ONCHAIN} GRAY_CHAIN_SCAN_SECONDS: 60, from 5 to 3,600.`,
      doc: "Period of the chain pass: the scan of latest, the final blocks, the rounds and their payments",
    },
    {
      name: "CHAIN_RPC_TIMEOUT_SECONDS",
      key: "chainRpcTimeoutSeconds",
      workers: ["jobs"],
      type: "int",
      default: "15",
      min: 1,
      max: 120,
      source: `${ONCHAIN} GRAY_CHAIN_RPC_TIMEOUT_SECONDS: 15, from 1 to 120.`,
      doc: "Timeout of each JSON-RPC request to the node",
    },
    {
      name: "CHAIN_MULTICALL_BATCH",
      key: "chainMulticallBatch",
      workers: ["jobs"],
      type: "int",
      default: "200",
      min: 1,
      max: 1000,
      source: `${ONCHAIN} GRAY_CHAIN_MULTICALL_BATCH: 200, from 1 to 1,000.`,
      doc: "Calls per aggregate3",
    },
    {
      name: "CHAIN_RPC_BATCH",
      key: "chainRpcBatch",
      workers: ["jobs"],
      type: "int",
      default: "100",
      min: 1,
      max: 1000,
      source: `${ONCHAIN} GRAY_CHAIN_RPC_BATCH: 100, from 1 to 1,000.`,
      doc: "eth_calls sent together without Multicall3",
    },
    {
      name: "CREDIT_MAX_ROUNDS_PER_PASS",
      key: "creditMaxRoundsPerPass",
      workers: ["jobs"],
      type: "int",
      default: "48",
      min: 1,
      max: 720,
      source: `${ONCHAIN} GRAY_CREDIT_MAX_ROUNDS_PER_PASS: 48, from 1 to 720.`,
      doc: "Hourly rounds opened per pass while catching up",
    },
    {
      name: "CREDIT_MATCH_BATCH",
      key: "creditMatchBatch",
      workers: ["jobs"],
      type: "int",
      default: "200",
      min: 1,
      max: 1000,
      source: `${ONCHAIN} GRAY_CREDIT_MATCH_BATCH: 200, from 1 to 1,000.`,
      doc: "Unexamined entries fetched per matching batch",
    },
    {
      name: "CREDIT_EXCEPTION_RECHECK_PAGES",
      key: "creditExceptionRecheckPages",
      workers: ["jobs"],
      type: "int",
      default: "5",
      min: 1,
      max: 1000,
      source: `${ONCHAIN} GRAY_CREDIT_EXCEPTION_RECHECK_PAGES: 5, from 1 to 1,000.`,
      doc: "Pages of 100 exception entries examined again once per round",
    },
    {
      name: "CREDIT_PAY_RETRY_SECONDS",
      key: "creditPayRetrySeconds",
      workers: ["jobs"],
      type: "int",
      default: "3600",
      min: 300,
      max: 86400,
      source: `${ONCHAIN} GRAY_CREDIT_PAY_RETRY_SECONDS: 3,600, from 300 to 86,400.`,
      doc: "Wait before a round the payer gave up on or lost is submitted again",
    },
    {
      name: "CREDIT_UNPAID_ALERT_HOURS",
      key: "creditUnpaidAlertHours",
      workers: ["jobs"],
      type: "int",
      default: "6",
      min: 1,
      max: 8760,
      source: `${ONCHAIN} GRAY_CREDIT_UNPAID_ALERT_HOURS: 6, from 1 to 8,760.`,
      doc: "Age after which a closed round that is still paying is alerted",
    },
    {
      name: "CREDIT_UNPAID_ALERT_REPEAT_SECONDS",
      key: "creditUnpaidAlertRepeatSeconds",
      workers: ["jobs"],
      type: "int",
      default: "3600",
      min: 60,
      max: 86400,
      source: `${ONCHAIN} GRAY_CREDIT_UNPAID_ALERT_REPEAT_SECONDS: 3,600, from 60 to 86,400.`,
      doc: "Repeat period of that alert, and of the alert on a credit event still not delivered to its account",
    },
    {
      name: "CREDIT_FAILURE_ADVANCES",
      key: "creditFailureAdvances",
      // The console's operators' ledger overview reports it beside the jobs' rounds that act on it.
      workers: ["console", "jobs"],
      type: "enum",
      values: ["off", "on"],
      default: "off",
      source: `${ONCHAIN} GRAY_CREDIT_FAILURE_ADVANCES: off by default, so a deploy never starts paying from the pool (docs/holds-debt-mode.md 4.7).`,
      doc:
        "Whether a round also advances, from the pool's spare money, what suppliers are owed for charges Gray failed to put on chain (no debt " +
        "reported for them), not only for charges their customers owe; the first round after it is turned on advances every such charge waiting, so " +
        "look at GET /api/v1/ops/ledger/uncharged first (docs/holds-debt-mode.md 4.7)",
    },
    {
      name: "CREDIT_ACCOUNT_MODE",
      key: "creditAccountMode",
      workers: ["jobs"],
      type: "enum",
      values: ["server", "root"],
      default: "server",
      source:
        "The credit Workers' ACCOUNT_MODE (workers/credit/src/lib/config.ts), default server there too: an environment names the same mode on both sides. " +
        "The server version's chain reader has no such setting: its AccountDO reads the balance from the event alone.",
      doc:
        "`root`: the credit Workers' AccountDO is an account root, which takes a Minted event as a top-up and needs to know whether an order paid for it " +
        "(paid credit raises the debt allowance) or not (a welcome grant, an operator's mint): the scan then says so with each Minted event it pushes.",
    },
    {
      name: "CREDIT_MINT_SECONDS",
      key: "creditMintSeconds",
      workers: ["jobs"],
      type: "int",
      default: "15",
      min: 1,
      max: 300,
      source: `${ONCHAIN} GRAY_CREDIT_MINT_SECONDS: 15, from 1 to 300.`,
      doc: "Period of the mint pass: the verified top-ups handed to the minter and followed until they are on chain",
    },
    {
      name: "CREDIT_MINT_LOST_WAIT_SECONDS",
      key: "creditMintLostWaitSeconds",
      workers: ["jobs"],
      type: "int",
      default: "600",
      min: 60,
      max: 86400,
      source: `${ONCHAIN} GRAY_CREDIT_MINT_LOST_WAIT_SECONDS: 600, from 60 to 86,400.`,
      doc: "Quiet time before a submitted mint the minter no longer knows is handed over again",
    },
    {
      name: "CREDIT_MINT_BATCH",
      key: "creditMintBatch",
      workers: ["jobs"],
      type: "int",
      default: "100",
      min: 1,
      max: 1000,
      source: `${ONCHAIN} GRAY_CREDIT_MINT_BATCH: 100, from 1 to 1,000.`,
      doc: "Pending mints driven per mint pass, and recorded credit events delivered again per chain pass",
    },
    {
      name: "CREDIT_FUND_LOST_WAIT_SECONDS",
      key: "creditFundLostWaitSeconds",
      workers: ["jobs"],
      type: "int",
      default: "600",
      min: 60,
      max: 86400,
      source: `${ONCHAIN} GRAY_CREDIT_FUND_LOST_WAIT_SECONDS: 600, from 60 to 86,400.`,
      doc:
        "Wait from the funder's first not_found for a grant it had, or one its storage cannot prove it never got, before the grant is rejected as " +
        "funding_lost; it is never funded again",
    },
    {
      name: "CREDIT_GRANT_FOLLOW_SECONDS",
      key: "creditGrantFollowSeconds",
      workers: ["jobs"],
      type: "int",
      default: "2",
      min: 1,
      max: 60,
      source: `${ONCHAIN} GRAY_CREDIT_GRANT_FOLLOW_SECONDS: 2, from 1 to 60.`,
      doc: "Period of the grant pass while a credit grant is on its way; otherwise it runs with the mint pass",
    },
    {
      name: "CREDIT_GRANT_BATCH",
      key: "creditGrantBatch",
      workers: ["jobs"],
      type: "int",
      default: "100",
      min: 1,
      max: 1000,
      source: `${ONCHAIN} GRAY_CREDIT_GRANT_BATCH: 100, from 1 to 1,000.`,
      doc: "Credit grants driven per grant pass",
    },
    {
      name: "CREDIT_BACKGROUND_RETRIES",
      key: "creditBackgroundRetries",
      workers: ["jobs"],
      type: "int",
      default: "3",
      min: 0,
      max: 10,
      source: `${ONCHAIN} GRAY_CREDIT_BACKGROUND_RETRIES (crates/gray-credit/src/client.rs RetryPolicy::BACKGROUND): 3, from 0 to 10.`,
      doc: "Retries of a call of the background work to the credit Workers: push-event, leaves, reconciled, mint, mint-status, pay, pay-status, fund-status",
    },
    {
      name: "CREDIT_BACKGROUND_BUDGET_MS",
      key: "creditBackgroundBudgetMs",
      workers: ["jobs"],
      type: "int",
      default: "12000",
      min: 100,
      max: 120000,
      source: `${ONCHAIN} GRAY_CREDIT_BACKGROUND_BUDGET_MS: 12,000, from 100 to 120,000; under the 15 s of the mint pass.`,
      doc: "Total time of such a call across its retries; less than CREDIT_MINT_SECONDS and CHAIN_SCAN_SECONDS",
    },
    {
      name: "CREDIT_BACKGROUND_ATTEMPT_MS",
      key: "creditBackgroundAttemptMs",
      workers: ["jobs"],
      type: "int",
      default: "8000",
      min: 50,
      max: 120000,
      source: `${ONCHAIN} GRAY_CREDIT_BACKGROUND_ATTEMPT_MS: 8,000, from 50 to 120,000 (client.rs explains the 8 s: a cold object, a 2 MB payer body, one 5 s chain read).`,
      doc: "Timeout of one such attempt; a slower minter or payer answer ends as outcome unknown",
    },
    {
      name: "CREDIT_BACKGROUND_BACKOFF_MS",
      key: "creditBackgroundBackoffMs",
      workers: ["jobs"],
      type: "int",
      default: "25",
      min: 0,
      max: 120000,
      source: `${ONCHAIN} GRAY_CREDIT_BACKGROUND_BACKOFF_MS: 25, from 0 to 120,000.`,
      doc: "Pause before its first retry; doubles after each (a Worker's retry hint wins)",
    },
    {
      name: "CREDIT_UNREACHABLE_RETRY_AFTER_MS",
      key: "creditUnreachableRetryAfterMs",
      workers: ["jobs"],
      type: "int",
      default: "250",
      min: 50,
      max: 10000,
      source:
        "workers/credit/src/lib/config.ts DO_UNREACHABLE_RETRY_AFTER_MS: 250, from 50 to 10,000: the retry hint gray-credit-api gives when the object a call names threw; " +
        "the jobs call the object without the entry Worker and take the same hint.",
      doc: "The wait before retrying a call whose credit object threw instead of answering.",
    },
    {
      name: "CREDIT_ACCOUNT_LOCATION_HINT",
      key: "creditAccountLocationHint",
      workers: ["jobs"],
      type: "enum",
      values: locationHints,
      default: "wnam",
      source:
        "workers/credit wrangler.api.jsonc env.testnet ACCOUNT_LOCATION_HINT (wnam, the gateway's region, docs/onchain-credit.md 4.3): an account object the jobs " +
        "reach first (a Minted event before any admission) must be created where the credit Worker would create it.",
      doc: "locationHint of every AccountDO stub the jobs make with CREDIT_ACCOUNT_MODE server; equals the credit environment's ACCOUNT_LOCATION_HINT. " +
        "With root, an AccountDO is a workspace's account root, created in the workspace's home region (control_workspaces.home_region, which the jobs read for each workspace). " +
        "Affects only objects not created yet.",
    },
    {
      name: "CREDIT_SIGNER_LOCATION_HINT",
      key: "creditSignerLocationHint",
      workers: ["jobs"],
      type: "enum",
      values: locationHints,
      default: "wnam",
      source: "workers/credit wrangler.api.jsonc env.testnet SIGNER_LOCATION_HINT (wnam): the signing objects live in one region, wherever their first call came from.",
      doc: "locationHint of every MinterDO, PayerDO and FunderDO stub the jobs make; equals the credit environment's SIGNER_LOCATION_HINT.",
    },
    {
      name: "DEBT_REFRESH_SECONDS",
      key: "debtRefreshSeconds",
      workers: ["jobs"],
      type: "int",
      default: "2",
      min: 1,
      max: 30,
      source:
        "crates/gray-gateway/src/background.rs: debt mode's readings (who paid, the breaker) are read as often as the snapshot, every 2 s; a reading older than a " +
        "minute counts as an open breaker (debt_mode.rs STALE), so the maximum leaves two readings a minute.",
      doc: "Period of debt mode's readings (paid funding and the circuit breaker), published to the gateway's config snapshot.",
    },
    {
      name: "DEBT_STATISTICS_SECONDS",
      key: "debtStatisticsSeconds",
      workers: ["jobs"],
      type: "int",
      default: "60",
      min: 10,
      max: 3600,
      source: "crates/gray-gateway/src/background.rs Periods::for_credit: debt mode's slower numbers (the overview, the answer lengths) once a minute.",
      doc: "Period of debt mode's slower numbers: what waits to be advanced, the requests a rollback waits for, the answer lengths.",
    },
    {
      name: "LEDGER_PAGE_ROWS",
      key: "ledgerPageRows",
      workers: ["jobs"],
      type: "int",
      default: "10000",
      min: 1000,
      max: 50000,
      source:
        "The Cloudflare database's segmented scans (docs/cloudflare-native/database.md 5.1 item 6: every statement far under Hyperdrive's 60 s, D20). " +
        "Measured 2026-10-18 on the local PostgreSQL 17.11, 200,000 rows, pages of 10,000 (workers/db/bench/pages.ts, docs/cloudflare-native/database-impl.md " +
        "section 6): the slowest page, a paid payout's charges, took 82 µs a row, so 10,000 rows 0.8 s, about 1.4 s at the 1.7x of a cloud vCPU (database.md " +
        "5.1). Minimum: fewer rows only add round trips. Maximum: the database functions' own bound (gray_page_limit_v1), about 7 s in the cloud.",
      doc: "Rows one statement of the round's and the maintenance's paged scans reads (owed accruals, advances, payouts, write-off, missing charges).",
    },
    {
      name: "LEDGER_MAINTENANCE_SECONDS",
      key: "ledgerMaintenanceSeconds",
      workers: ["jobs"],
      type: "int",
      default: "3600",
      min: 60,
      max: 86400,
      source:
        "Beside the hourly rounds (docs/cloudflare-native/ledger.md 2): the write-off works in days (an uncharged charge is written off after 30 days, owner " +
        "2026-10-18) and the idempotency keys expire after 90 days, so once an hour is far finer than either; the partition check behind it warns days ahead " +
        "(database.md 7: ledger below 3 weeks, request logs below 7 days). Maximum: a day.",
      doc: "Period of the ledger maintenance: the write-off of uncharged charges, the expiry of client idempotency keys, the check of the partitions made ahead.",
    },
    ...PARTITION_LINES.map(
      (line): SettingSpec => ({
        name: line.name,
        key: line.key,
        workers: ["jobs"],
        type: "int",
        default: String(line.default),
        min: 1,
        max: line.premakeMax,
        source:
          `${PARTITION_LINES_SOURCE} This line: ${line.what} ${line.default} ${line.unit}. Maximum: the most ${line.table} can be made ahead, the upper bound of ` +
          `cf_settings ${line.premakeSetting} (${line.premakeMax}, workers/db/migrations/0002_settings.sql). The setting's own value may be lower (default ` +
          `${line.premakeDefault}): a line above it counts as that value, since premake never makes more and the alert would never stop, and the maintenance ` +
          `logs partition_lines_above_premake (workers/jobs/src/ledger/maintenance.ts partitionAlert).`,
        doc: `Partitions of ${line.table} made ahead of the current one below which the ledger maintenance logs partitions_short at level ${line.level} (${line.unit}).`,
      }),
    ),
  ];
}

/**
 * The lines of database.md section 7's "future partitions" signal, one var each (the section asks for
 * every line to be a setting). `gray_partitions_ahead_v1` counts the whole periods made after the one
 * holding now: the ledger tables' are weeks, request_logs' days.
 */
const PARTITION_LINES_SOURCE =
  "docs/cloudflare-native/database.md section 7, the future partitions: the ledger tables warn with fewer than 3 weeks made ahead and wake someone with " +
  "fewer than 1; request_logs warn below 7 days and wake someone below 3. The section's lines are a starting point, tuned to what staging and production " +
  "show. No DEFAULT partition (database.md 3.4 item 5), so a period without its partition refuses its rows. Minimum 1: at 0 the alert would come only once " +
  "the current period's partition is missing, when its rows are already refused.";
const PARTITION_LINES = [
  { name: "LEDGER_PARTITIONS_WARN_WEEKS", key: "ledgerPartitionsWarnWeeks", table: "the ledger tables", what: "warn below", default: 3, unit: "weeks", level: "warn", premakeSetting: "ledger_premake_weeks", premakeDefault: 4, premakeMax: 52 },
  { name: "LEDGER_PARTITIONS_PAGE_WEEKS", key: "ledgerPartitionsPageWeeks", table: "the ledger tables", what: "wake someone below", default: 1, unit: "weeks", level: "alert", premakeSetting: "ledger_premake_weeks", premakeDefault: 4, premakeMax: 52 },
  { name: "REQUEST_LOG_PARTITIONS_WARN_DAYS", key: "requestLogPartitionsWarnDays", table: "request_logs", what: "warn below", default: 7, unit: "days", level: "warn", premakeSetting: "request_log_premake_days", premakeDefault: 14, premakeMax: 366 },
  { name: "REQUEST_LOG_PARTITIONS_PAGE_DAYS", key: "requestLogPartitionsPageDays", table: "request_logs", what: "wake someone below", default: 3, unit: "days", level: "alert", premakeSetting: "request_log_premake_days", premakeDefault: 14, premakeMax: 366 },
] as const;

export interface LedgerJobsConfig {
  readonly chainId: number;
  readonly contractAddress: string;
  readonly creditStartBlock: number;
  readonly chainMulticall3: string;
  readonly creditCodeHash: string;
  readonly chainLogBlocks: number;
  readonly chainMaxPages: number;
  readonly chainScanSeconds: number;
  readonly chainRpcTimeoutSeconds: number;
  readonly chainMulticallBatch: number;
  readonly chainRpcBatch: number;
  readonly creditMaxRoundsPerPass: number;
  readonly creditMatchBatch: number;
  readonly creditExceptionRecheckPages: number;
  readonly creditPayRetrySeconds: number;
  readonly creditUnpaidAlertHours: number;
  readonly creditUnpaidAlertRepeatSeconds: number;
  readonly creditFailureAdvances: "off" | "on";
  readonly creditAccountMode: "server" | "root";
  readonly creditMintSeconds: number;
  readonly creditMintLostWaitSeconds: number;
  readonly creditMintBatch: number;
  readonly creditFundLostWaitSeconds: number;
  readonly creditGrantFollowSeconds: number;
  readonly creditGrantBatch: number;
  readonly creditBackgroundRetries: number;
  readonly creditBackgroundBudgetMs: number;
  readonly creditBackgroundAttemptMs: number;
  readonly creditBackgroundBackoffMs: number;
  readonly creditUnreachableRetryAfterMs: number;
  readonly creditAccountLocationHint: string;
  readonly creditSignerLocationHint: string;
  readonly debtRefreshSeconds: number;
  readonly debtStatisticsSeconds: number;
  readonly ledgerPageRows: number;
  readonly ledgerMaintenanceSeconds: number;
  readonly ledgerPartitionsWarnWeeks: number;
  readonly ledgerPartitionsPageWeeks: number;
  readonly requestLogPartitionsWarnDays: number;
  readonly requestLogPartitionsPageDays: number;
}

/** The jobs config's defaults (the ledger part), for tests. */
export const LEDGER_JOBS_KEYS: readonly (keyof LedgerJobsConfig)[] = [
  "chainId",
  "contractAddress",
  "creditStartBlock",
  "chainMulticall3",
  "creditCodeHash",
  "chainLogBlocks",
  "chainMaxPages",
  "chainScanSeconds",
  "chainRpcTimeoutSeconds",
  "chainMulticallBatch",
  "chainRpcBatch",
  "creditMaxRoundsPerPass",
  "creditMatchBatch",
  "creditExceptionRecheckPages",
  "creditPayRetrySeconds",
  "creditUnpaidAlertHours",
  "creditUnpaidAlertRepeatSeconds",
  "creditFailureAdvances",
  "creditAccountMode",
  "creditMintSeconds",
  "creditMintLostWaitSeconds",
  "creditMintBatch",
  "creditFundLostWaitSeconds",
  "creditGrantFollowSeconds",
  "creditGrantBatch",
  "creditBackgroundRetries",
  "creditBackgroundBudgetMs",
  "creditBackgroundAttemptMs",
  "creditBackgroundBackoffMs",
  "creditUnreachableRetryAfterMs",
  "creditAccountLocationHint",
  "creditSignerLocationHint",
  "debtRefreshSeconds",
  "debtStatisticsSeconds",
  "ledgerPageRows",
  "ledgerMaintenanceSeconds",
  "ledgerPartitionsWarnWeeks",
  "ledgerPartitionsPageWeeks",
  "requestLogPartitionsWarnDays",
  "requestLogPartitionsPageDays",
];

/**
 * The bounds between two of these vars the server checks at start (onchain.rs, the end of
 * `validate_chain_tuning`, lines 1150-1196); index.ts appends them to CROSS_CHECKS.
 */
export const LEDGER_CROSS_CHECKS: readonly CrossCheck[] = [
  ...(["CREDIT_MINT_SECONDS", "CHAIN_SCAN_SECONDS"] as const).map(
    (period): CrossCheck => ({
      workers: ["jobs"],
      names: ["CREDIT_BACKGROUND_BUDGET_MS", period],
      check: (budgetMs, seconds) => (budgetMs < seconds * 1000 ? null : `${budgetMs} ms must be less than ${period} (${seconds} s)`),
      source: `${ONCHAIN}:1150-1164: a background call stays inside the period of each loop that drives it (RetryPolicy::BACKGROUND), so one stuck call does not cost a pass.`,
    }),
  ),
  ...(["CREDIT_FUND_LOST_WAIT_SECONDS", "CREDIT_MINT_LOST_WAIT_SECONDS"] as const).map(
    (wait): CrossCheck => ({
      workers: ["jobs"],
      names: [wait, "CREDIT_MINT_SECONDS"],
      check: (waitSeconds, mintSeconds) => (waitSeconds >= mintSeconds ? null : `${waitSeconds} s must not be less than CREDIT_MINT_SECONDS (${mintSeconds} s)`),
      source:
        `${ONCHAIN}:1175-1195 refuses to start otherwise: a mint the minter no longer knows (a grant's funding the funder no longer knows) ` +
        "is asked about for at least one mint period before it is handed over again (rejected as funding_lost), chain.rs `mint_lost_wait`.",
    }),
  ),
  ...(
    [
      ["LEDGER_PARTITIONS_PAGE_WEEKS", "LEDGER_PARTITIONS_WARN_WEEKS"],
      ["REQUEST_LOG_PARTITIONS_PAGE_DAYS", "REQUEST_LOG_PARTITIONS_WARN_DAYS"],
    ] as const
  ).map(
    ([page, warn]): CrossCheck => ({
      workers: ["jobs"],
      names: [page, warn],
      check: (pageAt, warnAt) => (pageAt <= warnAt ? null : `${pageAt} must be at most ${warn} (${warnAt})`),
      source:
        "docs/cloudflare-native/database.md section 7: a table wakes someone below a line under the one it warns below (ledger 1 and 3 weeks, request_logs 3 and 7 " +
        "days), so the warning comes first; a waking line above the warning line would never warn.",
    }),
  ),
];
