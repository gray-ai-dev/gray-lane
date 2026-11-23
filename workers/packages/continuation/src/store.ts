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
/** Default TTL for encrypted zero-retention continuation state (2 hours). */
export const CONTINUATION_STATE_TTL_MS = 2 * 3600 * 1000;
/** Maximum allowed TTL for encrypted zero-retention continuation state (24 hours). */
export const CONTINUATION_STATE_MAX_TTL_MS = 24 * 3600 * 1000;
/** Maximum UTF-8 byte length of one sealed continuation state blob (fits base64url AES-256-GCM of up to 512 KiB plaintext). */
export const MAX_SEALED_STATE_BYTES = 700_000;
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
  | { readonly ok: true; readonly found: true; readonly endpoint: string; readonly model: string; readonly createdAt: number; readonly sealed?: string }
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
  /** Optional encrypted zero-retention continuation state (opaque ciphertext sealed inside the entry TEE). */
  readonly sealed?: string | null;
  /** Optional TTL in milliseconds for `sealed` (defaults to CONTINUATION_STATE_TTL_MS, max CONTINUATION_STATE_MAX_TTL_MS). */
  readonly stateTtlMs?: number;
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
  "CREATE TABLE IF NOT EXISTS continuation_states (kind TEXT NOT NULL, reference TEXT NOT NULL, sealed TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (kind, reference)) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS continuation_states_expiry ON continuation_states (expires_at)",
];

function record(input: unknown): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new InvalidContinuationInput("expected an object");
  return input as Record<string, unknown>;
}

function kindOf(value: unknown): ReferenceKind {
  if (value !== "response" && value !== "conversation" && value !== "item") throw new InvalidContinuationInput("kind must be response, conversation, or item");
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
   * Whether the tables exist. They are created by the first binding, not by the object: a lookup
   * that misses asks up to one object per bucket count and per region (client.ts), and an object
   * that was only asked keeps no storage. `statesReady` is tracked separately so an object created
   * before `continuation_states` existed upgrades cleanly on its next write without mutating on read.
   */
  private ready: boolean;
  private statesReady: boolean;

  constructor(ctx: DurableObjectState, deps: StoreDeps) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.clock = deps.clock;
    const existing = new Set(
      this.sql
        .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('continuations', 'continuation_states')")
        .toArray()
        .map((row) => row.name),
    );
    this.ready = existing.has("continuations");
    this.statesReady = existing.has("continuation_states");
  }

  private createTable(): void {
    if (this.ready && this.statesReady) return;
    for (const statement of SCHEMA) this.sql.exec(statement);
    this.ready = true;
    this.statesReady = true;
  }

  /** The endpoint a live reference is bound to, and its live sealed state if any. */
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
    const now = this.clock();
    const row = this.sql
      .exec<{ endpoint: string; model: string; created_at: number }>(
        "SELECT endpoint, model, created_at FROM continuations WHERE kind = ? AND reference = ? AND expires_at > ?",
        kind,
        reference,
        now,
      )
      .toArray()[0];
    if (row === undefined) return { ok: true, found: false };
    const state = this.statesReady
      ? this.sql
          .exec<{ sealed: string }>(
            "SELECT sealed FROM continuation_states WHERE kind = ? AND reference = ? AND expires_at > ?",
            kind,
            reference,
            now,
          )
          .toArray()[0]
      : undefined;
    return state === undefined
      ? { ok: true, found: true, endpoint: row.endpoint, model: row.model, createdAt: row.created_at }
      : { ok: true, found: true, endpoint: row.endpoint, model: row.model, createdAt: row.created_at, sealed: state.sealed };
  }

  /**
   * Binds a reference to the endpoint that served it, for 30 days from now; a repeated write moves
   * the binding and resets its expiry (the server version's upsert). A copy of a binding made elsewhere
   * (`createdAt`) keeps that binding's time and expiry, is not kept once expired, and replaces only an
   * expired row or one made earlier. When `sealed` is provided, stores the opaque encrypted
   * zero-retention state under a separate shorter expiry (`stateTtlMs` or 2 hours). The answer comes
   * after the write is durable (the object's output gate).
   */
  async bind(input: unknown): Promise<BindAnswer> {
    let kind: ReferenceKind;
    let reference: string;
    let endpoint: string;
    let model: string;
    let copiedFrom: number | undefined;
    let sealed: string | undefined;
    let stateTtlMs: number | undefined;
    try {
      const o = record(input);
      kind = kindOf(o.kind);
      reference = label(o.reference, "reference", MAX_REFERENCE_BYTES);
      endpoint = label(o.endpoint, "endpoint", MAX_ENDPOINT_ID_BYTES);
      model = label(o.model, "model", MAX_MODEL_BYTES);
      if (o.createdAt !== undefined && !(Number.isSafeInteger(o.createdAt) && (o.createdAt as number) >= 0)) throw new InvalidContinuationInput("createdAt must be a time in milliseconds");
      copiedFrom = o.createdAt as number | undefined;
      if (o.sealed !== undefined && o.sealed !== null) {
        sealed = label(o.sealed, "sealed", MAX_SEALED_STATE_BYTES);
      }
      if (o.stateTtlMs !== undefined) {
        if (typeof o.stateTtlMs !== "number" || !Number.isSafeInteger(o.stateTtlMs) || o.stateTtlMs <= 0 || o.stateTtlMs > CONTINUATION_STATE_MAX_TTL_MS) {
          throw new InvalidContinuationInput(`stateTtlMs must be a positive integer of at most ${CONTINUATION_STATE_MAX_TTL_MS}`);
        }
        stateTtlMs = o.stateTtlMs;
      }
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
    let stateExpiresAt: number | undefined;
    if (sealed !== undefined) {
      stateExpiresAt = now + (stateTtlMs ?? CONTINUATION_STATE_TTL_MS);
      this.sql.exec(
        "INSERT INTO continuation_states (kind, reference, sealed, expires_at) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT (kind, reference) DO UPDATE SET sealed = excluded.sealed, expires_at = excluded.expires_at",
        kind,
        reference,
        sealed,
        stateExpiresAt,
      );
    }
    await this.schedule(now, stateExpiresAt);
    return { ok: true, expiresAt };
  }

  /** Deletes expired bindings and expired sealed states in batches, then schedules the next purge. */
  async alarm(): Promise<{ deleted: number }> {
    if (!this.ready && !this.statesReady) return { deleted: 0 };
    const now = this.clock();
    let deleted = 0;
    if (this.ready) {
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
    }
    if (this.statesReady) {
      for (;;) {
        this.sql.exec(
          "DELETE FROM continuation_states WHERE (kind, reference) IN (SELECT kind, reference FROM continuation_states WHERE expires_at <= ? LIMIT ?)",
          now,
          PURGE_BATCH,
        );
        const batch = this.sql.exec<{ n: number }>("SELECT changes() AS n").one().n;
        deleted += batch;
        if (batch < PURGE_BATCH) break;
      }
    }
    this.alarmAtMs = null;
    await this.schedule(now + PURGE_INTERVAL_MS);
    return { deleted };
  }

  /** Pending alarm timestamp in ms; unknown until read (memory does not survive an eviction). */
  private alarmAtMs: number | null | undefined;

  /**
   * Keeps one alarm pending while rows remain: at the earliest expiry across bindings and sealed
   * states, but not before `earliest` (after a purge, PURGE_INTERVAL_MS later). A pending alarm is
   * moved earlier only when a newly written sealed state expires before it.
   */
  private async schedule(earliest: number, sooner?: number): Promise<void> {
    if (this.alarmAtMs === undefined) this.alarmAtMs = await this.ctx.storage.getAlarm();
    if (this.alarmAtMs !== null) {
      if (sooner !== undefined) {
        const target = Math.max(sooner, earliest);
        if (target < this.alarmAtMs) {
          await this.ctx.storage.setAlarm(target);
          this.alarmAtMs = target;
        }
      }
      return;
    }
    const nextBinding = this.ready ? this.sql.exec<{ at: number | null }>("SELECT MIN(expires_at) AS at FROM continuations").one().at : null;
    const nextState = this.statesReady ? this.sql.exec<{ at: number | null }>("SELECT MIN(expires_at) AS at FROM continuation_states").one().at : null;
    const next = nextBinding === null ? nextState : nextState === null ? nextBinding : Math.min(nextBinding, nextState);
    if (next === null) return;
    const target = Math.max(next, earliest);
    await this.ctx.storage.setAlarm(target);
    this.alarmAtMs = target;
  }

  /** Rows and storage, for tests and operators. */
  stats(): { rows: number; databaseSize: number } {
    const rows = this.ready ? this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM continuations").one().n : 0;
    return { rows, databaseSize: this.sql.databaseSize };
  }
}
