import { parseObjectKey } from "./keys.ts";

/**
 * The content bucket's deletion queue (`request_content_deletions`, docs/cloudflare-native/content.md 7),
 * as the console and gray-jobs both write it and gray-jobs runs it. A row is a single object, every
 * object under a prefix, or (`before_ms`) the GRC3 objects under a day's prefix whose request started
 * before that time, by the time in their keys: keys sort by it within a day (keys.ts), so a deletion
 * before a time lists the day from its start and stops at the first key at or after it, and needs no
 * index row (the rows of a day three months old are archived).
 */

/**
 * Queues `$1` (target), `$2` (whether it is a prefix), `$3` (created_ms), `$4` (before_ms, or null). A
 * target queued again is due at once, and a deletion of the whole prefix takes the place of one of a
 * part of it, never the other way.
 */
export const QUEUE_DELETION_SQL =
  "INSERT INTO request_content_deletions(target,prefix,created_ms,before_ms) VALUES($1,$2,$3,$4) ON CONFLICT(target,prefix) DO UPDATE SET next_attempt_ms=0," +
  "before_ms=CASE WHEN request_content_deletions.before_ms IS NULL OR excluded.before_ms IS NULL THEN NULL ELSE greatest(request_content_deletions.before_ms,excluded.before_ms) END";

const PIECE_SUFFIX = /\.p\d{6}$/;

/** The base key of a stored object: the tail object's key itself, or a piece's (`B.p000001` is `B`'s). Null for a key that is not GRC3's. */
export function baseKeyOf(key: string): string | null {
  const base = key.replace(PIECE_SUFFIX, "");
  return parseObjectKey(base) === null ? null : base;
}

/** What a stored object's key says of its request: its id and when it started. Null for a key that is not GRC3's. */
export function objectRequest(key: string): { readonly base: string; readonly requestId: string; readonly startedMs: number } | null {
  const base = key.replace(PIECE_SUFFIX, "");
  const parsed = parseObjectKey(base);
  return parsed === null ? null : { base, requestId: parsed.requestId, startedMs: parsed.startedMs };
}
