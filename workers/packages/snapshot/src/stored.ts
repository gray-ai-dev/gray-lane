import { SNAPSHOT_FORMAT, type Snapshot } from "./snapshot.ts";
import { decodeSnapshot } from "./storage.ts";

/**
 * The snapshot's last-known-good copy in Workers KV (docs/request-path-availability.md 4.2, M5): ConfigDO writes the
 * encoded snapshot (`encodeSnapshot`) under STORED_SNAPSHOT_KEY after it saves each new version, with what the
 * version's answers carry as the value's KV metadata (`StoredSnapshotMeta`); a gateway isolate with no copy, or one
 * whose routes lapsed, reads it before it asks the replicas, and serves it under the age rules every copy is served
 * under (CONFIG_ALERT_AGE_MS, CONFIG_MAX_AGE_MS, counted from its own `refreshedAt`). KV is eventually consistent: a
 * read elsewhere may see the previous value for up to 60 s or more (developers.cloudflare.com/kv/concepts/how-kv-works/,
 * read 2026-10-29), which the age rules and the confirmation of unknown keys already cover.
 *
 * The key names the snapshot format, so a writer of another format writes elsewhere; a value a gateway cannot read (a
 * metadata it does not know, bytes that do not decode, a snapshot of another format or version) is absent to it
 * (`readStoredSnapshot`), never an error: the isolate asks the replicas, as it did before the copy existed (I6).
 */

/** The KV key of this format's copy. */
export const STORED_SNAPSHOT_KEY = `snapshot/${SNAPSHOT_FORMAT}`;

/**
 * Workers KV takes one write a second per key (developers.cloudflare.com/kv/platform/limits/, read 2026-10-29):
 * ConfigDO leaves a version that comes sooner to its next rebuild.
 */
export const STORED_SNAPSHOT_WRITE_INTERVAL_MS = 1_000;

/** The shortest expiration KV takes, in seconds (the same limits page). */
export const KV_MIN_EXPIRATION_TTL_SECONDS = 60;

/** What the copy's KV metadata says of it: what a replica's answer says of its version (`CurrentAnswer`). */
export interface StoredSnapshotMeta {
  readonly format: typeof SNAPSHOT_FORMAT;
  readonly version: number;
  /** ConfigDO's last complete rebuild when it wrote the copy (ms). */
  readonly refreshedAt: number;
  /** When ConfigDO wrote it: the writer's version is its current one by definition (ms). */
  readonly confirmedAt: number;
}

/** The metadata ConfigDO writes with `snapshot`. */
export function storedSnapshotMeta(snapshot: Snapshot, refreshedAt: number, confirmedAt: number): StoredSnapshotMeta {
  return { format: SNAPSHOT_FORMAT, version: snapshot.version, refreshedAt, confirmedAt };
}

/**
 * How long KV keeps the copy, in seconds: CONFIG_MAX_AGE_MS, past which no isolate serves it anyway (its `refreshedAt`
 * is at most the time it was written), and at least KV's shortest. A writer that stops writing (a format left behind)
 * leaves nothing in KV for longer than a copy could be served.
 */
export function storedSnapshotTtlSeconds(maxAgeMs: number): number {
  return Math.max(KV_MIN_EXPIRATION_TTL_SECONDS, Math.ceil(maxAgeMs / 1000));
}

/** What `readStoredSnapshot` makes of KV's answer; `snapshot` null: no newer than the reader's version, not decoded. */
export type StoredSnapshot =
  | { readonly ok: true; readonly snapshot: Snapshot | null; readonly meta: StoredSnapshotMeta }
  | { readonly ok: false; readonly reason: "absent" | "unreadable"; readonly detail?: string };

const time = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** The metadata as this build reads it, or null: another format, or fields it does not know. */
export function storedSnapshotMetaOf(raw: unknown): StoredSnapshotMeta | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const m = raw as Record<string, unknown>;
  if (m.format !== SNAPSHOT_FORMAT || !time(m.version) || m.version < 1 || !time(m.refreshedAt) || !time(m.confirmedAt)) return null;
  return { format: SNAPSHOT_FORMAT, version: m.version, refreshedAt: m.refreshedAt, confirmedAt: m.confirmedAt };
}

/**
 * What KV answered for STORED_SNAPSHOT_KEY (`getWithMetadata` as bytes), as this build reads it. `have`: the version
 * the caller holds; a copy no newer is not decoded (its metadata says all the caller needs). Absent: no value.
 * Unreadable: a metadata of another format, bytes that do not decode, or a snapshot whose format or version is not
 * the metadata's; the caller treats it as absent.
 */
export function readStoredSnapshot(value: ArrayBuffer | null, metadata: unknown, have = 0): StoredSnapshot {
  if (value === null) return { ok: false, reason: "absent" };
  const meta = storedSnapshotMetaOf(metadata);
  if (meta === null) return { ok: false, reason: "unreadable", detail: "metadata" };
  if (meta.version <= have) return { ok: true, snapshot: null, meta };
  let snapshot: Snapshot;
  try {
    snapshot = decodeSnapshot(new Uint8Array(value));
  } catch (error) {
    return { ok: false, reason: "unreadable", detail: error instanceof Error ? error.message : String(error) };
  }
  if (snapshot === null || typeof snapshot !== "object" || snapshot.format !== SNAPSHOT_FORMAT || snapshot.version !== meta.version) {
    return { ok: false, reason: "unreadable", detail: "snapshot" };
  }
  return { ok: true, snapshot, meta };
}
