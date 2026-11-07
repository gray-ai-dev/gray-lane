/**
 * The gateway's side of the handle store (docs/cloudflare-native/tool-call-ids.md section 1): a
 * request reaches its handles' rows through one call to the entry shard of its conversation
 * (shards.ts `entryOf`), which asks the home shards itself (shard.ts); a request without handles asks
 * nothing. And the deletions' side: every shard of a workspace, as a deletion runs over them
 * (deletion.ts). Pure code: the calls go through the locator the caller hands in (the request's
 * connections, outbound.ts; a deletion's own calls).
 */
import { durableObjectReset, type LocationHint } from "@gray/config";
import { FIND_MAX_BYTES, type FindAnswer, type IssueAnswer, type IssuedRow } from "./shard.ts";
import { everyShard, type ShardPlace } from "./shards.ts";
import type { DeleteAnswer, StoredRow } from "./store.ts";

/** What the gateway calls on an entry shard (`ToolCallIdDO`). */
export interface ToolCallIdRpc {
  find(input: { readonly workspace: string; readonly handles: readonly string[]; readonly self: string; readonly anchor: string; readonly timeoutMs: number; readonly maxBytes?: number }): Promise<FindAnswer>;
  issue(input: {
    readonly workspace: string;
    readonly arrivalMs: number;
    readonly requestId: string;
    readonly createdMs: number;
    readonly rows: readonly IssuedRow[];
    readonly self: string;
    readonly anchor: string;
    readonly timeoutMs: number;
  }): Promise<IssueAnswer>;
}

/** What a deletion calls on a shard. */
export interface ToolCallIdDeletions {
  deleteBefore(input: { readonly workspace: string; readonly beforeMs: number }): Promise<DeleteAnswer>;
  close(input: { readonly workspace: string; readonly atMs: number }): Promise<DeleteAnswer>;
}

/** A fresh stub for a shard, created with its region as its location hint. */
export type ToolCallIdLocator = (name: string, hint: LocationHint) => ToolCallIdRpc;

class Timeout extends Error {}

/**
 * The two timer calls a gateway call's deadline makes: the platform's when absent (production). A test hands a held
 * clock (@gray/faults `HeldClock`), so "no answer within the deadline" is its clock's.
 */
export interface CallTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** `promise`, or a Timeout after `ms` on `timers` (the platform's when absent); a late answer is ignored. */
function within<T>(promise: Promise<T>, ms: number, timers?: CallTimers): Promise<T> {
  let timer: unknown = null;
  promise.catch(() => {});
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      const fire = () => reject(new Timeout(`no answer within ${ms} ms`));
      timer = timers === undefined ? setTimeout(fire, ms) : timers.setTimeout(fire, ms);
    }),
  ]).finally(() => {
    if (timer === null) return;
    if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
    else timers.clearTimeout(timer);
  });
}

/**
 * The deadline an entry shard gets for the home shards it asks, out of the gateway's `timeoutMs`: a
 * tenth less, so that it answers which shard did not answer before the gateway stops waiting.
 */
export function entryTimeout(timeoutMs: number): number {
  return Math.max(1, Math.floor(timeoutMs * 0.9));
}

export type LookupResult = { readonly ok: true; readonly rows: StoredRow[]; readonly rest: readonly string[]; readonly asked: number } | { readonly ok: false; readonly unanswered: readonly string[] };

/**
 * The stored rows of `handles` of `workspace`, through the entry shard `entry` of the conversation
 * `anchor`: one call, `timeoutMs` in all. No answer (or a refusal, a bug here) makes the lookup
 * unavailable: nothing is sent upstream then (`tool_call_id_lookup_unavailable`). The answer holds at
 * most `maxBytes` of rows (at most FIND_MAX_BYTES, shard.ts); the handles whose rows it left out are
 * `rest`, for another call.
 */
export async function lookupRows(
  locate: ToolCallIdLocator,
  entry: ShardPlace,
  workspace: string,
  anchor: string,
  handles: readonly string[],
  timeoutMs: number,
  maxBytes: number = FIND_MAX_BYTES,
  timers?: CallTimers,
  clock: () => number = Date.now,
): Promise<LookupResult> {
  if (handles.length === 0) return { ok: true, rows: [], rest: [], asked: 0 };
  const answer = await onceMoreAfterReset((ms) => locate(entry.name, entry.hint).find({ workspace, handles, self: entry.name, anchor, timeoutMs: entryTimeout(ms), maxBytes: Math.max(1, Math.min(FIND_MAX_BYTES, Math.floor(maxBytes))) }), timeoutMs, timers, clock);
  if (answer === null) return { ok: false, unanswered: [entry.name] };
  if (answer.ok) return { ok: true, rows: answer.rows, rest: answer.rest, asked: answer.asked };
  return { ok: false, unanswered: "unanswered" in answer ? answer.unanswered : [entry.name] };
}

/**
 * One call to an entry shard within `timeoutMs`, or null when it did not answer or failed. A shard reset under the call
 * (a deploy, a storage reset) restarts at once with its storage, and its rows live there alone: it is asked once more,
 * on a new stub, within what is left (docs/request-path-availability.md M4).
 */
async function onceMoreAfterReset<T>(call: (ms: number) => Promise<T>, timeoutMs: number, timers: CallTimers | undefined, clock: () => number): Promise<T | null> {
  const deadline = clock() + timeoutMs;
  for (let tries = 0; ; tries++) {
    const left = deadline - clock();
    try {
      return await within(call(left), left, timers);
    } catch (error) {
      if (tries > 0 || !durableObjectReset(error) || deadline - clock() <= 0) return null;
    }
  }
}

export interface RowsToWrite {
  readonly workspace: string;
  readonly arrivalMs: number;
  readonly requestId: string;
  readonly createdMs: number;
  readonly rows: readonly IssuedRow[];
}

export type WriteResult = { readonly ok: true; readonly blocked: boolean; readonly closed: boolean; readonly asked: number } | { readonly ok: false; readonly unanswered: readonly string[] };

/**
 * Stores the rows of one answer through the entry shard `entry` of the conversation `anchor`: one call,
 * `timeoutMs` in all. Every home shard must answer: a handle the client may hold is always stored. A
 * write sent again changes nothing (the store's own rule), so a caller may repeat one that did not answer.
 */
export async function writeRows(locate: ToolCallIdLocator, entry: ShardPlace, anchor: string, rows: RowsToWrite, timeoutMs: number, timers?: CallTimers, clock: () => number = Date.now): Promise<WriteResult> {
  if (rows.rows.length === 0) return { ok: true, blocked: false, closed: false, asked: 0 };
  const answer = await onceMoreAfterReset((ms) => locate(entry.name, entry.hint).issue({ ...rows, self: entry.name, anchor, timeoutMs: entryTimeout(ms) }), timeoutMs, timers, clock);
  if (answer === null) return { ok: false, unanswered: [entry.name] };
  if (answer.ok) return { ok: true, blocked: answer.blocked, closed: answer.closed, asked: answer.asked };
  return { ok: false, unanswered: "unanswered" in answer ? answer.unanswered : [entry.name] };
}

/** A shard of a deletion: its name and region, with the calls it answers. */
export type DeletionLocator = (name: string, hint: LocationHint) => ToolCallIdDeletions;

export interface DeletionResult {
  /** Rows deleted in all. */
  readonly deleted: number;
  /** The shards done, by name. */
  readonly done: readonly string[];
  /** Shards that did not answer or were not done when the time ran out: a later run deletes what they keep. */
  readonly unfinished: number;
}

/**
 * The tool-call id rows a deletion covers, in `shards` of `workspace` (by default every shard of every
 * region, @gray/tool-ids `everyShard`): with `beforeMs`, an Activity deletion's cut (contents last
 * issued before it go, labels stay, and a write for a request before it stores no content); without it
 * the workspace closed (everything goes, and nothing is stored for it again). Each shard is called
 * until it says it is done, `parallel` at a time, until `deadline` (epoch ms); calling again finishes
 * what is left, since each call is idempotent (the cut only grows). A call that does not answer ends at
 * the deadline on `timers` (the platform's when absent; a test hands its own, so the deadline is its).
 */
export async function deleteToolCallIds(
  locate: DeletionLocator,
  workspace: string,
  at: { readonly beforeMs: number } | { readonly closedAtMs: number },
  clock: () => number,
  deadline: number,
  parallel = 16,
  shards: readonly ShardPlace[] = everyShard(workspace),
  timers?: CallTimers,
): Promise<DeletionResult> {
  let deleted = 0;
  const done: string[] = [];
  let next = 0;
  const worker = async () => {
    for (let i = next++; i < shards.length; i = next++) {
      const shard = shards[i]!;
      let finished = false;
      while (!finished && clock() < deadline) {
        try {
          const call = locate(shard.name, shard.hint);
          // A shard that does not answer is given up at the deadline; the next run calls it again.
          const asked = "beforeMs" in at ? call.deleteBefore({ workspace, beforeMs: at.beforeMs }) : call.close({ workspace, atMs: at.closedAtMs });
          const answer = await within(asked, deadline - clock(), timers);
          if (!answer.ok) break;
          deleted += answer.deleted;
          finished = answer.done;
        } catch {
          break;
        }
      }
      if (finished) done.push(shard.name);
    }
  };
  await Promise.all(Array.from({ length: Math.min(parallel, shards.length) }, worker));
  return { deleted, done, unfinished: shards.length - done.length };
}
