/**
 * Debt mode's reading as the gateway holds it (docs/holds-debt-mode.md 3.4, crates/gray-gateway/src/debt_mode.rs):
 * the circuit breaker, when it was read, and the slower numbers. gray-jobs' RoundDO `debt` reads it from
 * the ledger every DEBT_REFRESH_SECONDS (the slower numbers every DEBT_STATISTICS_SECONDS) and hands it to
 * ConfigDO (`putDebtMode`); the regional ConfigReplicaDOs serve it to gateway isolates (`debtMode`), as
 * they serve the snapshot, so no single object answers every isolate (docs/cloudflare-native.md 2.2, 4.1).
 *
 * What each workspace paid for credit, which the server's reading also carries (`paid`, its exposure
 * limit), stays out: in the Cloudflare version the workspace's account root holds it (each `Minted`
 * event is pushed to it with `paid`, workers/credit/src/api/account-root.ts), and a shard holds
 * `max(H, M - discount left)` with the discount the root granted it (docs/cloudflare-native.md 5.2).
 * The map grows with every paying workspace; the isolates never need it.
 */

/** The circuit breaker as debt mode read it (gray-ledger debt.rs `debt_breaker`). */
export interface DebtBreaker {
  /** The UTC day (days since the epoch) the reading is of. */
  readonly day: number;
  /** Bad debt of the day, Gray's failure advances included (microusd). */
  readonly badDebtMicrousd: number;
  readonly failureAdvancesMicrousd: number;
  /** The previous day's fee income from workspaces that paid for credit, net of refunds and reclaims (microusd). */
  readonly feePreviousDayMicrousd: number;
  /** Bad debt above the previous day's fee income: every request is held for its worst case. */
  readonly open: boolean;
}

/** Gray's own answer lengths for one client and model (debt_mode.rs `learned_of`). */
export interface LearnedLength {
  readonly client: string;
  readonly model: string;
  /** Answers of every workspace but the one with the most. */
  readonly others: number;
  /** Their 99.9th percentile in output tokens; null when it falls among answers a limit Gray wrote cut short. */
  readonly p999: number | null;
}

/** Debt mode's slower numbers (debt_mode.rs `refresh_statistics`). */
export interface DebtStatisticsView {
  readonly readAtMs: number;
  /** What waits to be advanced to suppliers (microusd). */
  readonly waitingMicrousd: number;
  /** The requests a rollback waits for. */
  readonly unsettledRequests: number;
  /** The discount in flight (microusd). */
  readonly inflightDiscountMicrousd: number;
  readonly learned: readonly LearnedLength[];
}

export interface DebtModeView {
  /** When the breaker was read (ms). */
  readonly readAtMs: number;
  readonly breaker: DebtBreaker;
  /** Null until the first pass of the slower numbers. */
  readonly statistics: DebtStatisticsView | null;
}

/**
 * A reading this old counts as an open breaker: every request is then held for its worst case
 * (debt_mode.rs `STALE`, 60 s, the REFRESH_TTL keys and routes have).
 */
export const DEBT_MODE_STALE_MS = 60_000;

/** Debt mode applies: a reading that is at most DEBT_MODE_STALE_MS old and whose breaker is closed (debt_mode.rs `terms`). */
export function debtModeClosed(view: DebtModeView | null, nowMs: number): boolean {
  return view !== null && !view.breaker.open && nowMs - view.readAtMs <= DEBT_MODE_STALE_MS;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const count = (v: unknown, what: string): number => {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new TypeError(`${what} is not a non-negative safe integer`);
  return v;
};

/**
 * Checks a reading that crosses an RPC boundary (ConfigDO's `putDebtMode`) and keeps only the view's
 * fields: a reading with `paid` is accepted and the map dropped.
 */
export function parseDebtModeView(raw: unknown): DebtModeView {
  if (!isRecord(raw)) throw new TypeError("a debt mode reading is an object");
  const b = raw.breaker;
  if (!isRecord(b) || typeof b.open !== "boolean") throw new TypeError("breaker is not a breaker reading");
  const breaker: DebtBreaker = {
    day: count(b.day, "breaker.day"),
    badDebtMicrousd: count(b.badDebtMicrousd, "breaker.badDebtMicrousd"),
    failureAdvancesMicrousd: count(b.failureAdvancesMicrousd, "breaker.failureAdvancesMicrousd"),
    feePreviousDayMicrousd: count(b.feePreviousDayMicrousd, "breaker.feePreviousDayMicrousd"),
    open: b.open,
  };
  let statistics: DebtStatisticsView | null = null;
  const s = raw.statistics;
  if (s !== null && s !== undefined) {
    if (!isRecord(s) || !Array.isArray(s.learned)) throw new TypeError("statistics is not debt mode's slower numbers");
    statistics = {
      readAtMs: count(s.readAtMs, "statistics.readAtMs"),
      waitingMicrousd: count(s.waitingMicrousd, "statistics.waitingMicrousd"),
      unsettledRequests: count(s.unsettledRequests, "statistics.unsettledRequests"),
      inflightDiscountMicrousd: count(s.inflightDiscountMicrousd, "statistics.inflightDiscountMicrousd"),
      learned: s.learned.map((l: unknown, i: number) => {
        if (!isRecord(l) || typeof l.client !== "string" || typeof l.model !== "string") throw new TypeError(`statistics.learned[${i}] is not an answer length`);
        return { client: l.client, model: l.model, others: count(l.others, `statistics.learned[${i}].others`), p999: l.p999 === null ? null : count(l.p999, `statistics.learned[${i}].p999`) };
      }),
    };
  }
  return { readAtMs: count(raw.readAtMs, "readAtMs"), breaker, statistics };
}
