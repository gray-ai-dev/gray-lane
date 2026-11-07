import type { BatchItem, ProjectionBatch, ProjectionMessage } from "./protocol.ts";
import { utf8Length } from "./validate.ts";

/**
 * Settlement batches on their way to PostgreSQL (docs/cloudflare-native.md 5.3): the shard hands
 * its written batches to a Queue producer, one or more batches per message, and the jobs consumer
 * calls gray_project_completions_v1 per message. Delivery is at least once, so the projection is
 * idempotent by request key.
 *
 * Queue limits (C33, https://developers.cloudflare.com/queues/platform/limits/, read 2026-10-17):
 * a message is at most 128 KB; `sendBatch` takes at most 100 messages and 256 KB.
 */
export const QUEUE_MESSAGE_MAX_BYTES = 128_000;
export const QUEUE_SEND_MAX_MESSAGES = 100;
export const QUEUE_SEND_MAX_BYTES = 256_000;

/** One item must fit a message with room for the envelope: half the message limit. */
export const MAX_ITEM_BYTES = QUEUE_MESSAGE_MAX_BYTES / 2;

/**
 * A batch row holds at most 2 MB (C20, durable-objects/platform/limits: row size); a shard writes
 * its pending settlements early when they reach half of that.
 */
export const BATCH_MAX_BYTES = 1_000_000;

/** The producer side of a Queue binding (`Queue<ProjectionMessage>`), or a test double. */
export interface ProjectionQueue {
  sendBatch(messages: Iterable<{ body: ProjectionMessage; contentType?: "json" }>): Promise<unknown>;
}

export interface StoredBatch {
  readonly seq: number;
  readonly at: number;
  readonly items: readonly BatchItem[];
}

const size = (m: ProjectionMessage) => utf8Length(JSON.stringify(m));

/**
 * The messages for `batches` (in order), each within the message limit. A batch too large for one
 * message is split into parts. Sizes are added up from each item's JSON once: an array's JSON is
 * its items' JSON joined by commas inside brackets.
 */
export function projectionMessages(shard: string, batches: readonly StoredBatch[]): ProjectionMessage[] {
  const messageBase = size({ format: 1, shard, batches: [] });
  const joined = (sizes: readonly number[]) => sizes.reduce((a, b) => a + b, 0) + Math.max(0, sizes.length - 1);
  const batchSize = (b: ProjectionBatch, itemSizes: readonly number[]) => utf8Length(JSON.stringify({ ...b, items: [] })) + joined(itemSizes);

  const out: ProjectionMessage[] = [];
  let current: ProjectionBatch[] = [];
  let currentSizes: number[] = [];
  const flush = () => {
    if (current.length) out.push({ format: 1, shard, batches: current });
    current = [];
    currentSizes = [];
  };
  for (const b of batches) {
    const itemSizes = b.items.map((item) => utf8Length(JSON.stringify(item)));
    const whole: ProjectionBatch = { seq: b.seq, part: 0, parts: 1, at: b.at, items: b.items };
    const wholeSize = batchSize(whole, itemSizes);
    if (messageBase + joined([...currentSizes, wholeSize]) <= QUEUE_MESSAGE_MAX_BYTES) {
      current.push(whole);
      currentSizes.push(wholeSize);
      continue;
    }
    flush();
    if (messageBase + wholeSize <= QUEUE_MESSAGE_MAX_BYTES) {
      current.push(whole);
      currentSizes.push(wholeSize);
      continue;
    }
    // Split into parts of as many items as fit. The header is sized with the largest part numbers
    // the batch can need, so the final numbering never makes a part longer than measured.
    const header = utf8Length(JSON.stringify({ seq: b.seq, part: b.items.length, parts: b.items.length, at: b.at, items: [] }));
    const parts: BatchItem[][] = [];
    let part: BatchItem[] = [];
    let partSizes: number[] = [];
    b.items.forEach((item, i) => {
      if (part.length > 0 && messageBase + header + joined([...partSizes, itemSizes[i]!]) > QUEUE_MESSAGE_MAX_BYTES) {
        parts.push(part);
        part = [];
        partSizes = [];
      }
      part.push(item);
      partSizes.push(itemSizes[i]!);
    });
    if (part.length) parts.push(part);
    parts.forEach((items, i) => out.push({ format: 1, shard, batches: [{ seq: b.seq, part: i, parts: parts.length, at: b.at, items }] }));
  }
  flush();
  return out;
}

/** Messages grouped for `sendBatch`: at most 100 and 256 KB per call. */
export function sendGroups(messages: readonly ProjectionMessage[]): ProjectionMessage[][] {
  const groups: ProjectionMessage[][] = [];
  let group: ProjectionMessage[] = [];
  let bytes = 0;
  for (const m of messages) {
    const n = size(m);
    if (group.length > 0 && (group.length === QUEUE_SEND_MAX_MESSAGES || bytes + n > QUEUE_SEND_MAX_BYTES)) {
      groups.push(group);
      group = [];
      bytes = 0;
    }
    group.push(m);
    bytes += n;
  }
  if (group.length) groups.push(group);
  return groups;
}
