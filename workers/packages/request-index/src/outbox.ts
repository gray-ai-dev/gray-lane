/**
 * The records outbox (docs/request-path-availability.md 4.2 M9): a request's index row or wide event that its sink (the
 * request-index Queue, the Pipelines stream) did not take within the platform's 30 s after the answer is written to R2
 * instead, one create-only object per request and kind in the content bucket, which the request already writes. gray-jobs
 * drains the prefix every minute through the same writers as the sinks' consumers (workers/jobs/src/outbox.ts), and
 * deletes each object once its record is written; a lifecycle rule removes what is left after
 * OUTBOX_LIFECYCLE_DAYS (workers/production/src/layout.ts, workers/staging/src/config.ts CONTENT_LIFECYCLE).
 *
 * The key names the request's arrival day and its id, so every put of one record names one object (a second put of the
 * same bytes is `same`). Readers keep a record once whichever way it came: the index consumer's insert is `ON CONFLICT
 * DO NOTHING`, and the wide event's readers de-duplicate on its `event_id`, the request id.
 *
 * Pure code, no `cloudflare:*` import.
 */

/** Every outbox object's key starts with this; no other object of the content bucket does (content/, anon/, spool/). */
export const OUTBOX_PREFIX = "outbox/";

/** What an outbox object holds: a request-index message (`index`), or the request's wide event (`events`). */
export const OUTBOX_KINDS = ["index", "events"] as const;
export type OutboxKind = (typeof OUTBOX_KINDS)[number];

/**
 * How long an outbox object may stay before R2's lifecycle rule removes it, in days: a week, the design's figure
 * (M9), seven times the gray-jobs drain's longest plausible outage of a day (a database or Pipelines away); the
 * request-index Queue keeps a message about 16 hours of retries (docs/cloudflare-native/jobs.md 2.3).
 */
export const OUTBOX_LIFECYCLE_DAYS = 7;

/** The format of an `events` object: `{format, events}`, `events` the records as the gateway sends them to its stream. */
export const OUTBOX_EVENTS_FORMAT = 1;

/** An `events` object's body. */
export interface OutboxEvents {
  readonly format: typeof OUTBOX_EVENTS_FORMAT;
  readonly events: readonly Record<string, unknown>[];
}

/** A request id as the outbox keys take it: the gateway's ids (32 lowercase hex digits) and nothing a key could be bent by. */
const REQUEST_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The prefix of one kind's objects. */
export function outboxPrefix(kind: OutboxKind): string {
  return `${OUTBOX_PREFIX}${kind}/`;
}

/**
 * The key of a request's record of `kind`: `outbox/<kind>/<yyyy>/<mm>/<dd>/<request id>`, the UTC day of the request's
 * arrival. Throws a RangeError for a time or an id it cannot name.
 */
export function outboxKey(kind: OutboxKind, startedMs: number, requestId: string): string {
  if (!REQUEST_ID.test(requestId)) throw new RangeError("an outbox key needs a request id of letters, digits, _ and -");
  if (!Number.isSafeInteger(startedMs) || startedMs < 0) throw new RangeError("an outbox key needs the request's arrival in ms");
  const d = new Date(startedMs);
  const pad = (n: number, width: number) => String(n).padStart(width, "0");
  return `${outboxPrefix(kind)}${pad(d.getUTCFullYear(), 4)}/${pad(d.getUTCMonth() + 1, 2)}/${pad(d.getUTCDate(), 2)}/${requestId}`;
}

/** The kind an outbox key names, or null for a key that is not one. */
export function outboxKindOf(key: string): OutboxKind | null {
  for (const kind of OUTBOX_KINDS) if (key.startsWith(outboxPrefix(kind))) return kind;
  return null;
}

/** An `events` object's body as the gateway writes it. */
export function outboxEvents(events: readonly Record<string, unknown>[]): OutboxEvents {
  return { format: OUTBOX_EVENTS_FORMAT, events };
}

export class MalformedOutboxEvents extends Error {
  constructor(why: string) {
    super(`outbox events: ${why}`);
    this.name = "MalformedOutboxEvents";
  }
}

/** The records of a parsed `events` object; throws MalformedOutboxEvents for anything else. */
export function parseOutboxEvents(body: unknown): Record<string, unknown>[] {
  if (body === null || typeof body !== "object" || Array.isArray(body)) throw new MalformedOutboxEvents("not an object");
  const o = body as { format?: unknown; events?: unknown };
  if (o.format !== OUTBOX_EVENTS_FORMAT) throw new MalformedOutboxEvents(`unknown format ${String(o.format)}`);
  if (!Array.isArray(o.events)) throw new MalformedOutboxEvents("no events");
  return o.events.map((e, i) => {
    if (e === null || typeof e !== "object" || Array.isArray(e)) throw new MalformedOutboxEvents(`event ${i} is not an object`);
    return e as Record<string, unknown>;
  });
}
