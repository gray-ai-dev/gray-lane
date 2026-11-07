/**
 * The deletions of one workspace's tool-call id rows, as a job (docs/cloudflare-native/
 * tool-call-ids.md section 4; `ToolCallIdDeletionDO`, one object per workspace): the server deletes
 * them in the request log's deletion, and a sweep finishes what a run left (crates/gray-gateway/src/
 * request_log/store.rs); here they are in every shard of every region, so a deletion is a fan-out
 * over all of them that must reach each one, however long that takes.
 *
 * - `request` records what is to be deleted, durably, before anything else: the workspace closed
 *   (everything goes, and nothing is stored for it again), or an Activity deletion's cut (contents
 *   last issued before it go, labels stay). A closure covers every cut; a later cut covers an earlier
 *   one. Asking again for what is recorded changes nothing, so the console and the jobs Worker's sweep
 *   may both ask.
 * - A pass calls every shard not done yet for the current request until it says it is done
 *   (@gray/tool-ids `deleteToolCallIds`, each call idempotent), and notes the ones done. One that is
 *   not done when the pass's time runs out is called again by the next pass, which the object's alarm
 *   runs, sooner at first and then every fifteen minutes, until all are done.
 *
 * Pure code apart from the Durable Object state, the shards (`DeletionLocator`) and the clock it is
 * handed: the gateway's object wires them.
 */
import { type CallTimers, type DeletionLocator, deleteToolCallIds } from "./client.ts";
import { everyShard } from "./shards.ts";
import { Invalid, integer, record, type Refused, refused, text } from "./store.ts";

/** How long a pass may run: within the 30 seconds a Worker has after its client leaves (C3), as the console's closure is waited for. */
export const PASS_MS = 25_000;
/** Shards called at once in a pass: calls between objects are no request's connections (gateway.md section 10). */
const PARALLEL = 32;
/** The first wait before a pass after one that did not finish, doubled each time up to the longest. */
const RETRY_FIRST_MS = 30_000;
const RETRY_LONGEST_MS = 15 * 60_000;

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS deletion (id INTEGER PRIMARY KEY CHECK (id = 1), workspace TEXT NOT NULL, closed_at_ms INTEGER, before_ms INTEGER, generation INTEGER NOT NULL, requested_ms INTEGER NOT NULL, done_ms INTEGER, passes INTEGER NOT NULL, deleted INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS shards_done (generation INTEGER NOT NULL, name TEXT NOT NULL, PRIMARY KEY (generation, name)) WITHOUT ROWID",
];

/** What is asked: the workspace closed at `closedAtMs`, or an Activity deletion's cut `beforeMs`; `waitMs`: how long to run the first pass before answering (0: answer at once). */
export interface DeletionRequest {
  readonly workspace: string;
  readonly closedAtMs?: number;
  readonly beforeMs?: number;
  readonly waitMs?: number;
}

export interface DeletionStatus {
  readonly ok: true;
  readonly workspace: string | null;
  readonly closedAtMs: number | null;
  readonly beforeMs: number | null;
  /** All shards done for what is recorded now. */
  readonly done: boolean;
  readonly doneMs: number | null;
  readonly shardsLeft: number;
  readonly passes: number;
  readonly deleted: number;
}

type Row = {
  readonly workspace: string;
  readonly closed_at_ms: number | null;
  readonly before_ms: number | null;
  readonly generation: number;
  readonly done_ms: number | null;
  readonly passes: number;
  readonly deleted: number;
};

export class ToolCallIdDeletion {
  private readonly ctx: DurableObjectState;
  private readonly sql: SqlStorage;
  private readonly locate: DeletionLocator;
  private readonly clock: () => number;
  private readonly timers: CallTimers | undefined;
  private running: Promise<void> | null = null;

  /** `timers`: where a shard call's deadline runs, the platform's when absent (a test holds them, test/workerd/worker.ts). */
  constructor(ctx: DurableObjectState, locate: DeletionLocator, clock: () => number = Date.now, timers?: CallTimers) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.locate = locate;
    this.clock = clock;
    this.timers = timers;
    for (const statement of SCHEMA) this.sql.exec(statement);
  }

  private row(): Row | null {
    return this.sql.exec<Row>("SELECT workspace, closed_at_ms, before_ms, generation, done_ms, passes, deleted FROM deletion WHERE id = 1").toArray()[0] ?? null;
  }

  /** Records a deletion (see the file comment), runs a first pass for up to `waitMs`, and answers how it stands. */
  async request(input: unknown): Promise<DeletionStatus | Refused> {
    let r: { workspace: string; closedAtMs: number | null; beforeMs: number | null; waitMs: number };
    try {
      const o = record(input);
      const closedAtMs = o.closedAtMs === undefined ? null : integer(o.closedAtMs, "closedAtMs");
      const beforeMs = o.beforeMs === undefined ? null : integer(o.beforeMs, "beforeMs");
      if ((closedAtMs === null) === (beforeMs === null)) throw new Invalid("exactly one of closedAtMs and beforeMs");
      const waitMs = o.waitMs === undefined ? 0 : integer(o.waitMs, "waitMs");
      if (waitMs < 0 || waitMs > PASS_MS) throw new Invalid(`waitMs must be 0 to ${PASS_MS}`);
      r = { workspace: text(o.workspace, "workspace"), closedAtMs, beforeMs, waitMs };
      const before = this.row();
      if (before !== null && before.workspace !== r.workspace) throw new Invalid("this object deletes another workspace's rows");
    } catch (error) {
      return refused(error);
    }
    const now = this.clock();
    const changed = this.ctx.storage.transactionSync(() => {
      const before = this.row();
      if (before === null) {
        this.sql.exec("INSERT INTO deletion (id, workspace, closed_at_ms, before_ms, generation, requested_ms, done_ms, passes, deleted) VALUES (1, ?, ?, ?, 1, ?, NULL, 0, 0)", r.workspace, r.closedAtMs, r.beforeMs, now);
        return true;
      }
      // A closure covers every cut, and stays; a later cut covers an earlier one.
      if (before.closed_at_ms !== null) return false;
      if (r.closedAtMs !== null) {
        this.sql.exec("UPDATE deletion SET closed_at_ms = ?, generation = generation + 1, requested_ms = ?, done_ms = NULL WHERE id = 1", r.closedAtMs, now);
        return true;
      }
      if (before.before_ms !== null && before.before_ms >= r.beforeMs!) return false;
      this.sql.exec("UPDATE deletion SET before_ms = ?, generation = generation + 1, requested_ms = ?, done_ms = NULL WHERE id = 1", r.beforeMs, now);
      return true;
    });
    if (changed || this.row()?.done_ms === null) {
      // The alarm runs the passes; the first may run now as well.
      await this.ctx.storage.setAlarm(now);
      if (r.waitMs > 0) await this.pass(r.waitMs);
    }
    return this.status();
  }

  /** How the recorded deletion stands. */
  status(): DeletionStatus {
    const row = this.row();
    if (row === null) return { ok: true, workspace: null, closedAtMs: null, beforeMs: null, done: true, doneMs: null, shardsLeft: 0, passes: 0, deleted: 0 };
    const done = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM shards_done WHERE generation = ?", row.generation).one().n;
    const total = everyShard(row.workspace).length;
    return {
      ok: true,
      workspace: row.workspace,
      closedAtMs: row.closed_at_ms,
      beforeMs: row.before_ms,
      done: row.done_ms !== null,
      doneMs: row.done_ms,
      shardsLeft: row.done_ms !== null ? 0 : total - done,
      passes: row.passes,
      deleted: row.deleted,
    };
  }

  /** The alarm: a pass, and the next alarm if it did not finish. */
  async alarm(): Promise<void> {
    await this.pass(PASS_MS);
  }

  /** One pass of at most `budgetMs` (one at a time: a pass asked for while one runs waits for it). */
  private async pass(budgetMs: number): Promise<void> {
    if (this.running !== null) return this.running;
    this.running = this.run(budgetMs).finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async run(budgetMs: number): Promise<void> {
    const row = this.row();
    if (row === null || row.done_ms !== null) return;
    const generation = row.generation;
    const done = new Set(this.sql.exec<{ name: string }>("SELECT name FROM shards_done WHERE generation = ?", generation).toArray().map((r) => r.name));
    const left = everyShard(row.workspace).filter((s) => !done.has(s.name));
    const at = row.closed_at_ms !== null ? { closedAtMs: row.closed_at_ms } : { beforeMs: row.before_ms! };
    const result = await deleteToolCallIds(this.locate, row.workspace, at, this.clock, this.clock() + budgetMs, PARALLEL, left, this.timers);
    const now = this.clock();
    const finished = this.ctx.storage.transactionSync(() => {
      for (const name of result.done) this.sql.exec("INSERT INTO shards_done (generation, name) VALUES (?, ?) ON CONFLICT DO NOTHING", generation, name);
      this.sql.exec("UPDATE deletion SET passes = passes + 1, deleted = deleted + ? WHERE id = 1", result.deleted);
      const current = this.row()!;
      // A request recorded during the pass starts over: its own pass is the next one.
      if (current.generation !== generation || result.unfinished > 0) return false;
      this.sql.exec("UPDATE deletion SET done_ms = ? WHERE id = 1", now);
      this.sql.exec("DELETE FROM shards_done");
      return true;
    });
    if (finished) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const passes = this.row()!.passes;
    const changedSince = this.row()!.generation !== generation;
    const wait = changedSince ? 0 : Math.min(RETRY_LONGEST_MS, RETRY_FIRST_MS * 2 ** Math.min(20, passes - 1));
    if (result.unfinished > 0) console.warn(JSON.stringify({ event: "tool_call_id_deletion", outcome: "unfinished", shards: result.unfinished, workspace_id: row.workspace, next_ms: wait }));
    await this.ctx.storage.setAlarm(now + wait);
  }
}
