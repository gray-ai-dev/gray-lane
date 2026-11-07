/**
 * API key spend periods, at UTC boundaries; weeks start on Monday. A port of
 * crates/gray-ledger/src/key_limits.rs (`SpendPeriod::start`, `SpendPeriod::end`), which the
 * gateway uses today to tell AccountDO which period a request counts in. A request counts in the
 * period of its admission, whenever it ends (workers/credit/src/api/account-do.ts `finalizeCharge`).
 */

/** The periods a key's spend limit can have (crates/gray-control/src/lib.rs:92 KEY_SPEND_PERIODS). */
export const SPEND_PERIODS = ["never", "day", "week", "month"] as const;
export type SpendPeriod = (typeof SPEND_PERIODS)[number];

export function isSpendPeriod(v: unknown): v is SpendPeriod {
  return typeof v === "string" && (SPEND_PERIODS as readonly string[]).includes(v);
}

const DAY_MS = 86_400_000;

/** Start of the period containing `atMs` (Unix ms); 0 for `never`. */
export function periodStart(period: SpendPeriod, atMs: number): number {
  if (period === "never") return 0;
  const at = new Date(Math.max(0, atMs));
  const day = Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate());
  if (period === "day") return day;
  if (period === "week") return day - ((at.getUTCDay() + 6) % 7) * DAY_MS;
  return Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), 1);
}

/** End of the period containing `atMs`, when the limit starts over; null for `never`. */
export function periodEnd(period: SpendPeriod, atMs: number): number | null {
  if (period === "never") return null;
  const start = periodStart(period, atMs);
  if (period === "day") return start + DAY_MS;
  if (period === "week") return start + 7 * DAY_MS;
  const s = new Date(start);
  // Date.UTC carries month 12 into January of the next year.
  return Date.UTC(s.getUTCFullYear(), s.getUTCMonth() + 1, 1);
}

/** Whether `start` is where a period of this kind begins. */
export function isPeriodStart(period: SpendPeriod, start: number): boolean {
  return Number.isSafeInteger(start) && start >= 0 && periodStart(period, start) === start;
}
