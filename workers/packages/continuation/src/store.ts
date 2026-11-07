/**
 * The continuation store: one Durable Object per workspace, region and bucket, named
 * `workspace/region/bucket` and created in its region (docs/cloudflare-native.md section 4.1: Responses
 * continuation state lives in Cloudflare, 30 days, not in PostgreSQL). It replaces the server
 * version's `responses_continuations` table (crates/gray-gateway/src/continuation.rs): a reference
 * binds to the endpoint that created it, a repeated write resets its expiry, an expired binding stops
 * resolving at once, and expired rows are deleted in bounded batches.
 *
 * The object takes no request-path decision of its own: `lookup` and `bind` read and write one row,
 * and the gateway (`pinContinuation`, `bindContinuation`) decides what the answers mean. Pure code
 * apart from the Durable Object state it is handed.
 */
import { utf8Length } from "@gray/protocol";
import { MAX_REFERENCE_BYTES, type ReferenceKind } from "./references.ts";

/** Providers keep stored responses for 30 days by default (continuation.rs `TTL_SECONDS`; docs/data-retention.md, "Responses continuation bindings"). */
export const CONTINUATION_TTL_MS = 30 * 24 * 3600 * 1000;
/** Rows deleted per statement (continuation.rs `PURGE_BATCH`; docs/data-retention.md). */
export const PURGE_BATCH = 10_000;
/**
 * The least time between two purges of one object: the server version purges every 600 seconds
 * (background.rs `CONTINUATION_PURGE_PERIOD`, which docs/data-retention.md states), so an expired
 * row is deleted within ten minutes of its expiry, never as an exact deadline.
 */
export const PURGE_INTERVAL_MS = 600_000;
/**
 * The longest endpoint id a binding stores: offer endpoint ids are 1-128 bytes
 * (provider_offers.rs, the offer check), so a longer one is a caller's bug. Rust's bind has no
 * check of its own; it only ever receives such ids.
 */
export const MAX_ENDPOINT_ID_BYTES = 128;
/**
 * The longest model a binding stores: a routable model is at most 256 bytes (model_records.rs
 * `valid_model`, provider_admission.rs, provider_offers.rs), and only a routed request binds.
 */
export const MAX_MODEL_BYTES = 256;

export interface StoreDeps {
  /** Unix milliseconds. */
  readonly clock: () => number;
}

export interface LookupInput {
  readonly kind: ReferenceKind;
  readonly reference: string;
}

/** An input this object refuses: a bug in the caller, never a client's mistake (as @gray/account answers `bad_request`). */
export interface Refused {
  readonly ok: false;
  readonly code: "bad_request";
  readonly message: string;
}

export type LookupAnswer =
  | { readonly ok: true; readonly found: true; readonly endpoint: string; readonly model: string; readonly createdAt: number }
  | { readonly ok: true; readonly found: false }
  | Refused;

export interface BindInput {
  readonly kind: ReferenceKind;
  readonly reference: string;
  readonly endpoint: string;
  readonly model: string;
  /**
   * A copy of a binding another store holds (a lookup found it there, client.ts `resolve`): when that binding was made,
   * from which the copy expires as the binding does, and it never replaces a binding made later. Absent: a reply's own
   * binding, made now. A store of a Worker version before it ignores it and binds as made now.
   */
  readonly createdAt?: number;
}

export type BindAnswer = { readonly ok: true; readonly expiresAt: number } | Refused;

class InvalidContinuationInput extends Error {}

function refused(error: unknown): Refused {
  if (!(error instanceof InvalidContinuationInput)) throw error;
  return { ok: false, code: "bad_request", message: error.message };
}

const SCHEMA = [
  // WITHOUT ROWID: the primary key is the table, so a binding writes the table row and its expiry
  // index entry, and nothing else.
  "CREATE TABLE IF NOT EXISTS continuations (kind TEXT NOT NULL, reference TEXT NOT NULL, endpoint TEXT NOT NULL, model TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (kind, reference)) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS continuations_expiry ON continuations (expires_at)",
];

function record(input: unknown): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new InvalidContinuationInput("expected an object");
  return input as Record<string, unknown>;
}

function kindOf(value: unknown): ReferenceKind {
  if (value !== "response" && value !== "conversation") throw new InvalidContinuationInput("kind must be response or conversation");
  return value;
}

function label(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || value === "" || utf8Length(value) > max) throw new InvalidContinuationInput(`${name} must be a non-empty string of at most ${max} bytes`);
  return value;
}

export class ContinuationStore {
  private readonly ctx: DurableObjectState;
  private readonly sql: SqlStorage;
  private readonly clock: () => number;

  /**
   * Whether the table exists. It is created by the first binding, not by the object: a lookup that
   * misses asks up to one object per bucket count and per region (client.ts), and an object that was
   * only asked keeps no storage.
   */
  private ready: boolean;

  constructor(ctx: DurableObjectState, deps: StoreDeps) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.clock = deps.clock;
    this.ready = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'continuations'").one().n > 0;
  }

  private createTable(): void {
    if (this.ready) return;
    for (const statement of SCHEMA) this.sql.exec(statement);
    this.ready = true;
  }

  /** The endpoint a live reference is bound to. */
  lookup(input: unknown): LookupAnswer {
    let kind: ReferenceKind;
    let reference: string;
    try {
      const o = record(input);
      kind = kindOf(o.kind);
      reference = label(o.reference, "reference", MAX_REFERENCE_BYTES);
    } catch (error) {
      return refused(error);
    }
    if (!this.ready) return { ok: true, found: false };
    const row = this.sql
      .exec<{ endpoint: string; model: string; created_at: number }>(
        "SELECT endpoint, model, created_at FROM continuations WHERE kind = ? AND reference = ? AND expires_at > ?",
        kind,
        reference,
        this.clock(),
      )
      .toArray()[0];
    return row === undefined ? { ok: true, found: false } : { ok: true, found: true, endpoint: row.endpoint, model: row.model, createdAt: row.created_at };
  }

  /**
   * Binds a reference to the endpoint that served it, for 30 days from now; a repeated write moves
   * the binding and resets its expiry (the server version's upsert). A copy of a binding made elsewhere
   * (`createdAt`) keeps that binding's time and expiry, is not kept once expired, and replaces only an
   * expired row or one made earlier. The answer comes after the write is durable (the object's output gate).
   */
  async bind(input: unknown): Promise<BindAnswer> {
    let kind: ReferenceKind;
    let reference: string;
    let endpoint: string;
    let model: string;
    let copiedFrom: number | undefined;
    try {
      const o = record(input);
      kind = kindOf(o.kind);
      reference = label(o.reference, "reference", MAX_REFERENCE_BYTES);
      endpoint = label(o.endpoint, "endpoint", MAX_ENDPOINT_ID_BYTES);
      model = label(o.model, "model", MAX_MODEL_BYTES);
      if (o.createdAt !== undefined && !(Number.isSafeInteger(o.createdAt) && (o.createdAt as number) >= 0)) throw new InvalidContinuationInput("createdAt must be a time in milliseconds");
      copiedFrom = o.createdAt as number | undefined;
    } catch (error) {
      return refused(error);
    }
    const now = this.clock();
    // Another store's clock may be ahead of this one's: a copy is never dated after now.
    const createdAt = copiedFrom === undefined ? now : Math.min(copiedFrom, now);
    const expiresAt = createdAt + CONTINUATION_TTL_MS;
    if (expiresAt <= now) return { ok: true, expiresAt };
    this.createTable();
    this.sql.exec(
      "INSERT INTO continuations (kind, reference, endpoint, model, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT (kind, reference) DO UPDATE SET endpoint = excluded.endpoint, model = excluded.model, created_at = excluded.created_at, expires_at = excluded.expires_at" +
        (copiedFrom === undefined ? "" : " WHERE continuations.expires_at <= ? OR continuations.created_at < excluded.created_at"),
      ...[kind, reference, endpoint, model, createdAt, expiresAt, ...(copiedFrom === undefined ? [] : [now])],
    );
    await this.schedule(now);
    return { ok: true, expiresAt };
  }

  /** Deletes the expired bindings in batches, then schedules the next purge. */
  async alarm(): Promise<{ deleted: number }> {
    if (!this.ready) return { deleted: 0 };
    const now = this.clock();
    let deleted = 0;
    for (;;) {
      this.sql.exec(
        "DELETE FROM continuations WHERE (kind, reference) IN (SELECT kind, reference FROM continuations WHERE expires_at <= ? LIMIT ?)",
        now,
        PURGE_BATCH,
      );
      const batch = this.sql.exec<{ n: number }>("SELECT changes() AS n").one().n;
      deleted += batch;
      if (batch < PURGE_BATCH) break;
    }
    this.alarmSet = false;
    await this.schedule(now + PURGE_INTERVAL_MS);
    return { deleted };
  }

  /** Whether an alarm is pending; unknown until read (memory does not survive an eviction). */
  private alarmSet: boolean | undefined;

  /**
   * Keeps one alarm pending while rows remain: at the earliest expiry, but not before `earliest`
   * (after a purge, PURGE_INTERVAL_MS later), and a pending alarm is never moved.
   */
  private async schedule(earliest: number): Promise<void> {
    if (this.alarmSet === undefined) this.alarmSet = (await this.ctx.storage.getAlarm()) !== null;
    if (this.alarmSet) return;
    const next = this.sql.exec<{ at: number | null }>("SELECT MIN(expires_at) AS at FROM continuations").one().at;
    if (next === null) return;
    await this.ctx.storage.setAlarm(Math.max(next, earliest));
    this.alarmSet = true;
  }

  /** Rows and storage, for tests and operators. */
  stats(): { rows: number; databaseSize: number } {
    const rows = this.ready ? this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM continuations").one().n : 0;
    return { rows, databaseSize: this.sql.databaseSize };
  }
}
