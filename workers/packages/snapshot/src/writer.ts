import type { CurrentAnswer } from "./cache.ts";
import type { DebtModeView } from "./debt.ts";

/** What one rebuild of the snapshot did (ConfigDO `rebuild`). */
export interface RebuildResult {
  readonly ok: boolean;
  readonly version: number;
  readonly changed: boolean;
  readonly refreshedAt: number;
  /**
   * What this rebuild sent to the roots. `withdrawalsFailed` counts the failed withdrawals among `failed`: a
   * route the snapshot no longer has that its endpoint root still serves until a later rebuild reaches it;
   * the console answers a withdrawing change "saved, not yet in effect" on it.
   */
  readonly published: { readonly keys: number; readonly capacities: number; readonly failed: number; readonly pending: number; readonly withdrawalsFailed: number };
  readonly error?: string;
}

/** The public catalog as GET /api/v1/catalog answers it (JSON text), with when the snapshot it lists was built (ms). */
export interface CatalogAnswer {
  readonly text: string;
  readonly builtAt: number;
}

/**
 * The calls other Workers make on the snapshot's writer, gray-jobs' ConfigDO (the object named `config`).
 * ConfigDO `implements` it and its callers type their stub with `ConfigWriterRpc`, so a call a caller makes that
 * the object does not have is a compile error: until 2026-10-23 the console called `catalog()`, which no version
 * of ConfigDO had, and every public catalog was empty while the console's tests passed against a stand-in.
 */
export interface ConfigWriter {
  /** A rebuild from PostgreSQL now; the console asks for one after a write the gateway reads. */
  rebuild(): Promise<RebuildResult>;
  /** The public catalog worked out at the call (crates/gray-gateway/src/inference.rs `public_catalog`); null before the first rebuild. */
  catalog(): Promise<CatalogAnswer | null>;
  /** The version and the time of the last complete rebuild; the snapshot when `have` is behind. */
  current(have: number, confirmedAfter?: number): CurrentAnswer;
  /** Debt mode's last reading, or null before the first since the object started. */
  debtMode(): DebtModeView | null;
}

/** A Durable Object stub's view of `T`: each call answers a promise of what the method returns. */
export type Remote<T> = { readonly [K in keyof T]: T[K] extends (...args: infer A) => infer R ? (...args: A) => Promise<Awaited<R>> : never };

/** The snapshot writer as its callers reach it, through a stub. */
export type ConfigWriterRpc = Remote<ConfigWriter>;
