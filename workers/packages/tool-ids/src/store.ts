/**
 * Where a handle's row lives on Cloudflare: one Durable Object per workspace, region and shard
 * (`ToolCallIdDO`, named by @gray/tool-ids `shardName`), in place of the server's two tables
 * (crates/gray-ledger/src/tool_call_ids.rs `tool_call_ids` and `tool_call_id_contents`). The
 * semantics are the server's (docs/design/tool-call-ids.md "Storage"):
 *
 * - a label row per handle: its kind (1 an upstream id, 2 an id the translation layer composed),
 *   its issuer, the protocol of the answer that issued it, and for an upstream id of at most 64
 *   bytes the id itself; written once (a handle stored already keeps the request that first issued
 *   it), kept through an Activity deletion, deleted when the workspace closes;
 * - a content row for a longer upstream id and every composed id: sealed by the gateway (@gray/
 *   tool-ids `seal`), with the key month and generation and the arrival of the latest request that
 *   issued it; storing it again replaces it only for a later arrival, and an Activity deletion
 *   removes the contents last issued before its cut;
 * - the cut: a write for a request that arrived before it stores its labels and no content, and
 *   says so (`blocked`); a closed workspace stores nothing more.
 *
 * Writes are idempotent, so a write sent again (a retry, a replay) changes nothing. The object takes
 * no decision of the request path: the gateway decides what the rows mean. Pure code apart from the
 * Durable Object state it is handed; SQLite-backed objects keep a value of at most 2 MB and bind at
 * most 100 parameters a statement (Cloudflare's Durable Object SQL limits), so a content is kept in
 * pieces of CONTENT_PIECE_BYTES and statements bind one row at a time.
 */

/** Rows deleted per call of a deletion, as the server deletes per transaction (store.rs `DELETE_CHUNK`); the caller calls again while `done` is false. */
export const DELETE_CHUNK = 5_000;
/** The most bytes of one sealed content in one row: under the 2 MB a Durable Object's SQLite keeps in one value. */
export const CONTENT_PIECE_BYTES = 1_000_000;
/** Handles per lookup statement: under the 100 parameters one statement binds (the workspace is one more). */
const LOOKUP_BATCH = 90;
/** The longest label: an upstream id of at most 64 bytes (@gray/tool-ids MAX_LABEL_BYTES). */
const MAX_LABEL_BYTES = 64;

export interface LabelRow {
  readonly handle: string;
  readonly kind: 1 | 2;
  /** 32 hex digits. */
  readonly issuer: string;
  /** The upstream protocol of the answer that issued it. */
  readonly issuedProtocol: string;
  /** An upstream id of at most 64 bytes; for kind 2 the composed id's own id; null when only the content holds the value. */
  readonly label: string | null;
}

export interface ContentRow {
  readonly handle: string;
  /** Nonce, AES-256-GCM ciphertext and tag (@gray/tool-ids `seal`). */
  readonly sealed: Uint8Array;
  /** The content key's month (`yyyymm`) and generation. */
  readonly keyMonth: number;
  readonly keyGeneration: number;
}

export interface StoredRow {
  readonly label: LabelRow;
  readonly content: ContentRow | null;
}

export interface WriteInput {
  readonly workspace: string;
  /** When the request arrived: a cut after it covers it. */
  readonly arrivalMs: number;
  readonly requestId: string;
  readonly createdMs: number;
  readonly labels: readonly LabelRow[];
  readonly contents: readonly ContentRow[];
}

/** One label of a server's database as the cutover imports it, with the request that first issued it. */
export interface ImportedLabel extends LabelRow {
  readonly firstRequestId: string;
  readonly createdMs: number;
}

/** One content of a server's database, sealed again under this deployment's key, with its arrival. */
export interface ImportedContent extends ContentRow {
  readonly arrivalMs: number;
}

/** An input this object refuses: a bug in the caller, never a client's mistake. */
export interface Refused {
  readonly ok: false;
  readonly code: "bad_request";
  readonly message: string;
}

/**
 * A lookup's rows, and `rest`: the handles asked for whose rows were left out to keep the answer within
 * the `maxBytes` it was given (`rowBytes`), for a later call; a handle without a row is in neither.
 */
export type LookupAnswer = { readonly ok: true; readonly rows: StoredRow[]; readonly rest: string[] } | Refused;
export type WriteAnswer = { readonly ok: true; readonly blocked: boolean; readonly closed: boolean } | Refused;
export type DeleteAnswer = { readonly ok: true; readonly deleted: number; readonly done: boolean } | Refused;

/** An input that is not what a caller of this object sends (shard.ts shares the checks). */
export class Invalid extends Error {}

/** The answer to an Invalid input; anything else is rethrown. */
export function refused(error: unknown): Refused {
  if (!(error instanceof Invalid)) throw error;
  return { ok: false, code: "bad_request", message: error.message };
}

export function record(input: unknown): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new Invalid("expected an object");
  return input as Record<string, unknown>;
}

export function text(value: unknown, name: string, max = 4096): string {
  if (typeof value !== "string" || value === "" || value.length > max) throw new Invalid(`${name} must be a non-empty string`);
  return value;
}

export function integer(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Invalid(`${name} must be an integer`);
  return value;
}

const encoder = new TextEncoder();

/**
 * What one row brings into the memory of whoever reads it, as an answer's size is counted (`maxBytes`):
 * its strings and its sealed content.
 */
export function rowBytes(row: StoredRow): number {
  const l = row.label;
  return l.handle.length + (l.label?.length ?? 0) + l.issuer.length + l.issuedProtocol.length + (row.content === null ? 0 : row.content.sealed.length);
}

/** An optional `maxBytes`: at least 1 when given; none means no bound. */
export function maxBytesOf(value: unknown): number {
  if (value === undefined) return Number.POSITIVE_INFINITY;
  const n = integer(value, "maxBytes");
  if (n < 1) throw new Invalid("maxBytes must be at least 1");
  return n;
}

export function label(value: unknown): LabelRow {
  const o = record(value);
  const handle = text(o.handle, "handle", 64);
  if (handle.length !== 33) throw new Invalid("handle must be 33 characters");
  const kind = o.kind;
  if (kind !== 1 && kind !== 2) throw new Invalid("kind must be 1 or 2");
  const issuer = text(o.issuer, "issuer", 32);
  if (!/^[0-9a-f]{32}$/.test(issuer)) throw new Invalid("issuer must be 32 hex digits");
  const issuedProtocol = text(o.issuedProtocol, "issuedProtocol", 64);
  let l: string | null = null;
  if (o.label !== null && o.label !== undefined) {
    l = text(o.label, "label", MAX_LABEL_BYTES);
    if (encoder.encode(l).length > MAX_LABEL_BYTES) throw new Invalid("label must be at most 64 bytes");
  }
  return { handle, kind, issuer, issuedProtocol, label: l };
}

export function content(value: unknown): ContentRow {
  const o = record(value);
  const handle = text(o.handle, "handle", 64);
  if (!(o.sealed instanceof Uint8Array) || o.sealed.length < 12) throw new Invalid("sealed must be bytes");
  return { handle, sealed: o.sealed, keyMonth: integer(o.keyMonth, "keyMonth"), keyGeneration: integer(o.keyGeneration, "keyGeneration") };
}

export function list<T>(value: unknown, name: string, each: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Invalid(`${name} must be an array`);
  return value.map(each);
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS labels (workspace TEXT NOT NULL, handle TEXT NOT NULL, kind INTEGER NOT NULL, issuer TEXT NOT NULL, issued_protocol TEXT NOT NULL, label TEXT, first_request_id TEXT NOT NULL, created_ms INTEGER NOT NULL, PRIMARY KEY (workspace, handle)) WITHOUT ROWID",
  "CREATE TABLE IF NOT EXISTS contents (workspace TEXT NOT NULL, handle TEXT NOT NULL, key_month INTEGER NOT NULL, key_generation INTEGER NOT NULL, arrival_ms INTEGER NOT NULL, pieces INTEGER NOT NULL, PRIMARY KEY (workspace, handle)) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS contents_arrival ON contents (workspace, arrival_ms)",
  // A rowid table: its values are large (SQLite keeps WITHOUT ROWID for small rows).
  "CREATE TABLE IF NOT EXISTS content_pieces (workspace TEXT NOT NULL, handle TEXT NOT NULL, seq INTEGER NOT NULL, piece BLOB NOT NULL, UNIQUE (workspace, handle, seq))",
  "CREATE TABLE IF NOT EXISTS cuts (workspace TEXT PRIMARY KEY, before_ms INTEGER NOT NULL, closed INTEGER NOT NULL) WITHOUT ROWID",
];

export class ToolCallIdStore {
  private readonly ctx: DurableObjectState;
  private readonly sql: SqlStorage;
  /** The tables exist: an object only ever asked keeps no storage (a lookup that misses writes nothing). */
  private ready: boolean;

  constructor(ctx: DurableObjectState) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.ready = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'labels'").one().n > 0;
  }

  private createTables(): void {
    if (this.ready) return;
    for (const statement of SCHEMA) this.sql.exec(statement);
    this.ready = true;
  }

  private cut(workspace: string): { readonly beforeMs: number; readonly closed: boolean } | null {
    const row = this.sql.exec<{ before_ms: number; closed: number }>("SELECT before_ms, closed FROM cuts WHERE workspace = ?", workspace).toArray()[0];
    return row === undefined ? null : { beforeMs: row.before_ms, closed: row.closed !== 0 };
  }

  /**
   * The stored rows of `handles` of `workspace`; handles without a row are left out (`fetch`). With
   * `maxBytes`, the rows (`rowBytes`) stop before they would pass it, and the handles left are `rest`:
   * a content is measured before it is read, so a row left out is never read here.
   */
  lookup(input: unknown): LookupAnswer {
    let workspace: string;
    let handles: string[];
    let maxBytes: number;
    try {
      const o = record(input);
      workspace = text(o.workspace, "workspace");
      handles = list(o.handles, "handles", (h) => text(h, "handle", 64));
      maxBytes = maxBytesOf(o.maxBytes);
    } catch (error) {
      return refused(error);
    }
    if (!this.ready || handles.length === 0) return { ok: true, rows: [], rest: [] };
    const rows: StoredRow[] = [];
    const rest: string[] = [];
    let bytes = 0;
    for (let i = 0; i < handles.length; i += LOOKUP_BATCH) {
      const batch = handles.slice(i, i + LOOKUP_BATCH);
      if (rest.length > 0) {
        rest.push(...batch);
        continue;
      }
      const found = this.sql
        .exec<{ handle: string; kind: number; issuer: string; issued_protocol: string; label: string | null; key_month: number | null; key_generation: number | null; pieces: number | null; sealed_bytes: number | null }>(
          `SELECT l.handle, l.kind, l.issuer, l.issued_protocol, l.label, c.key_month, c.key_generation, c.pieces, (SELECT SUM(length(p.piece)) FROM content_pieces p WHERE p.workspace = l.workspace AND p.handle = l.handle) AS sealed_bytes FROM labels l LEFT JOIN contents c ON c.workspace = l.workspace AND c.handle = l.handle WHERE l.workspace = ? AND l.handle IN (${batch.map(() => "?").join(",")})`,
          workspace,
          ...batch,
        )
        .toArray();
      for (const row of found) {
        const labelRow: LabelRow = { handle: row.handle, kind: row.kind === 2 ? 2 : 1, issuer: row.issuer, issuedProtocol: row.issued_protocol, label: row.label };
        const hasContent = row.pieces !== null && row.key_month !== null && row.key_generation !== null;
        const size = rowBytes({ label: labelRow, content: null }) + (hasContent ? (row.sealed_bytes ?? 0) : 0);
        if (rest.length > 0 || bytes + size > maxBytes) {
          rest.push(row.handle);
          continue;
        }
        bytes += size;
        let contentRow: ContentRow | null = null;
        if (hasContent) {
          const pieces = this.sql
            .exec<{ piece: ArrayBuffer }>("SELECT piece FROM content_pieces WHERE workspace = ? AND handle = ? ORDER BY seq", workspace, row.handle)
            .toArray()
            .map((p) => new Uint8Array(p.piece));
          contentRow = { handle: row.handle, sealed: join(pieces), keyMonth: row.key_month!, keyGeneration: row.key_generation! };
        }
        rows.push({ label: labelRow, content: contentRow });
      }
    }
    return { ok: true, rows, rest };
  }

  /**
   * Stores the rows one answer issued (`write_in`): its labels whatever the cut, its contents only
   * when no cut covers the request (`blocked` says one did); nothing once the workspace closed.
   * Answers after the write is durable (the object's output gate).
   */
  write(input: unknown): WriteAnswer {
    let w: WriteInput;
    try {
      const o = record(input);
      w = {
        workspace: text(o.workspace, "workspace"),
        arrivalMs: integer(o.arrivalMs, "arrivalMs"),
        requestId: text(o.requestId, "requestId"),
        createdMs: integer(o.createdMs, "createdMs"),
        labels: list(o.labels, "labels", label),
        contents: list(o.contents, "contents", content),
      };
    } catch (error) {
      return refused(error);
    }
    return this.store(
      w.workspace,
      w.labels.map((l) => ({ ...l, firstRequestId: w.requestId, createdMs: w.createdMs })),
      w.contents.map((c) => ({ ...c, arrivalMs: w.arrivalMs })),
      w.arrivalMs,
    );
  }

  /** The cutover's import of a server's rows (docs/cloudflare-native/tool-call-ids.md section 6): each with its own request and arrival. */
  import(input: unknown): WriteAnswer {
    let workspace: string;
    let labels: ImportedLabel[];
    let contents: ImportedContent[];
    try {
      const o = record(input);
      workspace = text(o.workspace, "workspace");
      labels = list(o.labels, "labels", (v) => {
        const r = record(v);
        return { ...label(v), firstRequestId: text(r.firstRequestId, "firstRequestId"), createdMs: integer(r.createdMs, "createdMs") };
      });
      contents = list(o.contents, "contents", (v) => ({ ...content(v), arrivalMs: integer(record(v).arrivalMs, "arrivalMs") }));
    } catch (error) {
      return refused(error);
    }
    return this.store(workspace, labels, contents, null);
  }

  /** `arrivalMs` null: each content's own arrival is checked against the cut (an import). */
  private store(workspace: string, labels: readonly ImportedLabel[], contents: readonly ImportedContent[], arrivalMs: number | null): WriteAnswer {
    if (labels.length === 0 && contents.length === 0) return { ok: true, blocked: false, closed: false };
    this.createTables();
    return this.ctx.storage.transactionSync(() => {
      const cut = this.cut(workspace);
      if (cut?.closed === true) return { ok: true as const, blocked: true, closed: true };
      for (const l of labels) {
        this.sql.exec(
          "INSERT INTO labels (workspace, handle, kind, issuer, issued_protocol, label, first_request_id, created_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (workspace, handle) DO NOTHING",
          workspace,
          l.handle,
          l.kind,
          l.issuer,
          l.issuedProtocol,
          l.label,
          l.firstRequestId,
          l.createdMs,
        );
      }
      if (contents.length === 0) return { ok: true as const, blocked: false, closed: false };
      let blocked = false;
      for (const c of contents) {
        const arrival = arrivalMs ?? c.arrivalMs;
        if (cut !== null && cut.beforeMs > arrival) {
          blocked = true;
          continue;
        }
        const pieces = Math.max(1, Math.ceil(c.sealed.length / CONTENT_PIECE_BYTES));
        this.sql.exec(
          "INSERT INTO contents (workspace, handle, key_month, key_generation, arrival_ms, pieces) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (workspace, handle) DO UPDATE SET key_month = excluded.key_month, key_generation = excluded.key_generation, arrival_ms = excluded.arrival_ms, pieces = excluded.pieces WHERE excluded.arrival_ms > contents.arrival_ms",
          workspace,
          c.handle,
          c.keyMonth,
          c.keyGeneration,
          arrival,
          pieces,
        );
        if (this.sql.exec<{ n: number }>("SELECT changes() AS n").one().n === 0) continue;
        this.sql.exec("DELETE FROM content_pieces WHERE workspace = ? AND handle = ?", workspace, c.handle);
        for (let seq = 0; seq < pieces; seq++) {
          this.sql.exec("INSERT INTO content_pieces (workspace, handle, seq, piece) VALUES (?, ?, ?, ?)", workspace, c.handle, seq, c.sealed.subarray(seq * CONTENT_PIECE_BYTES, (seq + 1) * CONTENT_PIECE_BYTES));
        }
      }
      return { ok: true as const, blocked, closed: false };
    });
  }

  /**
   * An Activity deletion's cut (`delete_contents_before`): recorded first, so a later write for a
   * request before it stores no content, then at most DELETE_CHUNK contents last issued before it go;
   * `done` once none is left. Labels stay.
   */
  deleteBefore(input: unknown): DeleteAnswer {
    let workspace: string;
    let beforeMs: number;
    try {
      const o = record(input);
      workspace = text(o.workspace, "workspace");
      beforeMs = integer(o.beforeMs, "beforeMs");
    } catch (error) {
      return refused(error);
    }
    this.createTables();
    return this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO cuts (workspace, before_ms, closed) VALUES (?, ?, 0) ON CONFLICT (workspace) DO UPDATE SET before_ms = max(cuts.before_ms, excluded.before_ms)", workspace, beforeMs);
      const doomed = this.sql
        .exec<{ handle: string }>("SELECT handle FROM contents WHERE workspace = ? AND arrival_ms < ? ORDER BY arrival_ms LIMIT ?", workspace, beforeMs, DELETE_CHUNK)
        .toArray()
        .map((r) => r.handle);
      for (const handle of doomed) {
        this.sql.exec("DELETE FROM content_pieces WHERE workspace = ? AND handle = ?", workspace, handle);
        this.sql.exec("DELETE FROM contents WHERE workspace = ? AND handle = ?", workspace, handle);
      }
      return { ok: true as const, deleted: doomed.length, done: doomed.length < DELETE_CHUNK };
    });
  }

  /**
   * The workspace closed (`delete_workspace`): from now on nothing is stored for it, and its labels
   * and contents go, DELETE_CHUNK rows a call; `done` once none is left.
   */
  close(input: unknown): DeleteAnswer {
    let workspace: string;
    let atMs: number;
    try {
      const o = record(input);
      workspace = text(o.workspace, "workspace");
      atMs = integer(o.atMs, "atMs");
    } catch (error) {
      return refused(error);
    }
    this.createTables();
    return this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO cuts (workspace, before_ms, closed) VALUES (?, ?, 1) ON CONFLICT (workspace) DO UPDATE SET before_ms = max(cuts.before_ms, excluded.before_ms), closed = 1", workspace, atMs);
      let deleted = 0;
      const contents = this.sql
        .exec<{ handle: string }>("SELECT handle FROM contents WHERE workspace = ? LIMIT ?", workspace, DELETE_CHUNK)
        .toArray()
        .map((r) => r.handle);
      for (const handle of contents) {
        this.sql.exec("DELETE FROM content_pieces WHERE workspace = ? AND handle = ?", workspace, handle);
        this.sql.exec("DELETE FROM contents WHERE workspace = ? AND handle = ?", workspace, handle);
      }
      deleted += contents.length;
      const room = DELETE_CHUNK - deleted;
      if (room > 0) {
        const labels = this.sql
          .exec<{ handle: string }>("SELECT handle FROM labels WHERE workspace = ? LIMIT ?", workspace, room)
          .toArray()
          .map((r) => r.handle);
        for (const handle of labels) this.sql.exec("DELETE FROM labels WHERE workspace = ? AND handle = ?", workspace, handle);
        deleted += labels.length;
      }
      return { ok: true as const, deleted, done: deleted < DELETE_CHUNK };
    });
  }

  /** Rows and storage, for tests and operators. */
  stats(): { readonly labels: number; readonly contents: number; readonly pieces: number; readonly cut: number | null; readonly closed: boolean; readonly databaseSize: number } {
    if (!this.ready) return { labels: 0, contents: 0, pieces: 0, cut: null, closed: false, databaseSize: this.sql.databaseSize };
    const count = (table: string) => this.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`).one().n;
    const cut = this.sql.exec<{ before_ms: number; closed: number }>("SELECT before_ms, closed FROM cuts LIMIT 1").toArray()[0];
    return { labels: count("labels"), contents: count("contents"), pieces: count("content_pieces"), cut: cut?.before_ms ?? null, closed: (cut?.closed ?? 0) !== 0, databaseSize: this.sql.databaseSize };
  }
}

function join(pieces: readonly Uint8Array[]): Uint8Array {
  if (pieces.length === 1) return pieces[0]!;
  let length = 0;
  for (const p of pieces) length += p.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const p of pieces) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
