import { parseSerde, toJsonString, type Json } from "@gray/json";
import type { Snapshot } from "@gray/snapshot";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { asBigint, asNumber, integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import { BRIDGE_PATHS, SNAPSHOT_TARGET, bridgeCall, type BridgeCall } from "./ops.ts";
import { decodeSchedulerBody, encodeSchedulerBody } from "./scheduler.ts";

/** The judge pair the bridge applies to its answers (`AgeJudgement`, bridge-3). */
export interface SnapshotJudge {
  readonly now: bigint;
  readonly ageMs: bigint;
}

/**
 * The snapshot op (design v2 section D, M19; bridge-3): `current(have, confirmedAfter, judge)`
 * answered with the raw `@gray/snapshot` `Snapshot`, bounded in size. The bridge asks the region's
 * replicas and then ConfigDO, applies `confirmed_after` and the judge pair itself (`currentFor`,
 * from `@gray/snapshot`), and serves the newest answer that passes — or the best one it saw. The
 * CVM maps the document with `gatewaySnapshotOf` and its cache decides whether the copy is too old.
 *
 * The request is a GET; `have`, `confirmed_after` and the judge pair `judge_now`/`judge_age_ms`
 * are the path's query, which the canonical string covers (signing.ts), so a signed read cannot be
 * replayed with another value. `confirmed_after` is omitted when it is null, and the judge pair is
 * both present or both absent; the gateway asks without either when it has nothing to judge.
 *
 * `SNAPSHOT_RESPONSE_MAX_BYTES` bounds the answer before it is parsed: the snapshot holds every key
 * and route, so a malformed or runaway document must be refused by its size, not buffered. 8 MiB is
 * the lane's largest bound of a document's own (the scheduler forward's answer is 512 bytes after D27), and a
 * gateway snapshot of the sizes Gray serves today is well under it.
 *
 * The ranking members (r16, workers/lane-bridge IMPLEMENTATION_NOTES.md "The snapshot read"). The request path's source
 * says in the query that it takes them (`ranking=word`), or what it holds of the ranking feed when the snapshot cache
 * asks for the feed's changes (`ranking=all`: nothing; `ranking=since&ranking_epoch=<epoch>&ranking_seq=<n>`: its
 * `FeedHave`). The bridge passes the replica's word on: `ranking`, the replica's `FeedAnswer` for `all` and `since`
 * (`snapshotRankingSchema`: its sample columns as base64 of their little-endian bytes, the measures' width named), and
 * `ranking_failing_since`, whenever the replica that answered keeps a copy of the collector. A read that names none of
 * them is the read of before r16, byte for byte, and its answer carries neither, so a lane of an earlier release (whose
 * answer schema is strict) never meets one. The ranking part of an answer (the bytes its two members add) has its own
 * bound, `RANKING_ANSWER_MAX_BYTES`; past it the bridge leaves `ranking` out (`snapshotAnswerBytes`).
 */
export const SNAPSHOT_RESPONSE_MAX_BYTES = 8 * 1024 * 1024;

/**
 * The most bytes the ranking members add to a snapshot answer (r16): 32 MiB. A whole answer at the feed's bound (4,096
 * keys of 128 samples) is about 16.3 MB of data (@gray/routing `feedAnswerBytes`) and about 22 MB so encoded; one whose
 * keys also hold many failures is about 37 MB, past it, and is left out (the bridge alerts `lane_bridge_ranking_left_out`).
 * Gray's feed is far below that (docs/cloudflare-native/endpoint.md section 12). The snapshot keeps its own bound beside it.
 */
export const RANKING_ANSWER_MAX_BYTES = 32 * 1024 * 1024;

/** The most bytes a `snapshot.current` answer has: the snapshot's bound and the ranking part's (wire.ts `bridgeResponseMaxBytes`). */
export const SNAPSHOT_RANKING_RESPONSE_MAX_BYTES = SNAPSHOT_RESPONSE_MAX_BYTES + RANKING_ANSWER_MAX_BYTES;

/**
 * The ranking collector's epoch as a read names it (`ranking_epoch`) and an answer carries it: the collector's
 * `crypto.randomUUID()` (workers/gateway/src/objects/endpoint-ranking.ts), or a test's short name. URL-unreserved
 * characters only, so the signed query carries it as it is, with nothing to escape.
 */
export const RANKING_EPOCH_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/** What a read says of the ranking feed: the replica's word only, the whole feed, or its changes since a `FeedHave`. */
export const SNAPSHOT_RANKING_ASKS = ["word", "all", "since"] as const;
export type SnapshotRankingAsk = (typeof SNAPSHOT_RANKING_ASKS)[number];

/** What a caller holds of the ranking feed (@gray/routing `FeedHave`): the collector's epoch and its last change's number. */
export interface SnapshotFeedHave {
  readonly epoch: string;
  readonly seq: number;
}

const epochSchema = z.string().regex(RANKING_EPOCH_PATTERN);

/**
 * The integers of a `current` call: `have`, an optional `confirmed_after`, and the optional judge
 * pair `judge_now`/`judge_age_ms` (bridge-3). The judge pair is both present or both absent: one
 * without the other describes no judgement, and a reader must not guess which half was meant.
 * The ranking members (r16) are absent, or `ranking` is one of `SNAPSHOT_RANKING_ASKS`, with `ranking_epoch` and
 * `ranking_seq` exactly when it is `since`. `ranking_records` (r17, docs/utility-routing.md "The feed"): `1` from an entry
 * that takes the roots' long records and each key's circuit with the feed's changes, only beside a ranking ask; a bridge
 * answers them to no other read. `ranking_est` (r24): `1` from an entry that takes each record's estimate (`est`), only
 * beside `ranking_records`; a bridge writes the member to no other read.
 */
export const snapshotCurrentRequestSchema = z
  .object({
    have: uintSchema,
    confirmed_after: uintSchema.nullable(),
    judge_now: uintSchema.nullable().optional(),
    judge_age_ms: uintSchema.nullable().optional(),
    ranking: z.enum(SNAPSHOT_RANKING_ASKS).optional(),
    ranking_epoch: epochSchema.optional(),
    ranking_seq: uintSchema.optional(),
    ranking_records: z.literal("1").optional(),
    ranking_est: z.literal("1").optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const now = value.judge_now ?? null;
    const age = value.judge_age_ms ?? null;
    if ((now === null) !== (age === null)) ctx.addIssue({ code: "custom", path: ["judge_now"], message: "judge_now and judge_age_ms are both present or both absent" });
    const since = value.ranking === "since";
    if (since !== (value.ranking_epoch !== undefined) || since !== (value.ranking_seq !== undefined)) {
      ctx.addIssue({ code: "custom", path: ["ranking"], message: "ranking=since names ranking_epoch and ranking_seq, and no other read names them" });
    }
    if (value.ranking_records !== undefined && value.ranking === undefined) {
      ctx.addIssue({ code: "custom", path: ["ranking_records"], message: "ranking_records comes with a ranking ask" });
    }
    if (value.ranking_est !== undefined && value.ranking_records === undefined) {
      ctx.addIssue({ code: "custom", path: ["ranking_est"], message: "ranking_est comes with ranking_records" });
    }
  });
export type SnapshotCurrentRequest = z.infer<typeof snapshotCurrentRequestSchema>;

/** The judge pair of a request, or null when the caller passes neither. */
export function snapshotJudgeOf(request: SnapshotCurrentRequest): SnapshotJudge | null {
  const now = request.judge_now ?? null;
  const age = request.judge_age_ms ?? null;
  return now === null || age === null ? null : { now, ageMs: age };
}

/**
 * The ranking members of a read for what its caller holds of the feed (`SnapshotSource.current`'s `ranking`): `word`
 * for undefined (the replica's word on the feed, no changes), `all` for null (nothing held), `since` for a have. A have
 * this wire cannot name (an epoch outside RANKING_EPOCH_PATTERN, a number that is not a safe non-negative integer) asks
 * for `all`, which an answer of another epoch would bring anyway: a ranking value never fails a snapshot read.
 */
export function snapshotRankingRequestOf(have: SnapshotFeedHave | null | undefined): Pick<SnapshotCurrentRequest, "ranking" | "ranking_epoch" | "ranking_seq"> {
  if (have === undefined) return { ranking: "word" };
  if (have === null || !RANKING_EPOCH_PATTERN.test(have.epoch) || !Number.isSafeInteger(have.seq) || have.seq < 0) return { ranking: "all" };
  return { ranking: "since", ranking_epoch: have.epoch, ranking_seq: BigInt(have.seq) };
}

/**
 * The replica's third argument for a read (gray-jobs `ConfigReplicaDO.current`'s `ranking`): undefined for `word` and
 * for a read without the ranking members (the replica's word only, as before r16), null for `all`, the caller's have
 * for `since`.
 */
export function snapshotRankingHaveOf(request: SnapshotCurrentRequest): SnapshotFeedHave | null | undefined {
  if (request.ranking === "all") return null;
  if (request.ranking !== "since" || request.ranking_epoch === undefined || request.ranking_seq === undefined) return undefined;
  return { epoch: request.ranking_epoch, seq: asNumber(request.ranking_seq, "ranking_seq") };
}

/** The query of one `current` call, in a fixed order: the integers, then the ranking members (r16). */
export function snapshotCurrentQuery(request: SnapshotCurrentRequest): string {
  const parsed = snapshotCurrentRequestSchema.parse(request);
  const parts = [`have=${parsed.have}`];
  if (parsed.confirmed_after !== null) parts.push(`confirmed_after=${parsed.confirmed_after}`);
  const judge = snapshotJudgeOf(parsed);
  if (judge !== null) parts.push(`judge_now=${judge.now}`, `judge_age_ms=${judge.ageMs}`);
  if (parsed.ranking !== undefined) parts.push(`ranking=${parsed.ranking}`);
  if (parsed.ranking === "since") parts.push(`ranking_epoch=${parsed.ranking_epoch}`, `ranking_seq=${parsed.ranking_seq}`);
  if (parsed.ranking_records !== undefined) parts.push("ranking_records=1");
  if (parsed.ranking_est !== undefined) parts.push("ranking_est=1");
  return parts.join("&");
}

/** The call of one `current` request: the GET whose path carries the integers. */
export function snapshotCurrentCall(request: SnapshotCurrentRequest): BridgeCall {
  return bridgeCall("snapshot.current", SNAPSHOT_TARGET, `${BRIDGE_PATHS["snapshot.current"]}?${snapshotCurrentQuery(request)}`);
}

/** The names a snapshot read's query may carry: before r16's, then the ranking members. */
const SNAPSHOT_PARAMETERS: ReadonlySet<string> = new Set(["have", "confirmed_after", "judge_now", "judge_age_ms", "ranking", "ranking_epoch", "ranking_seq", "ranking_records", "ranking_est"]);

/**
 * Read a `current` request from its query; refuses another name. A repeated name reads as its first
 * occurrence: the canonical query (`snapshotCurrentQuery`) writes each name once, and only the
 * signing client builds it, so a repeat is a malformed caller rather than a second value to bind.
 * The ranking members are in the request only when the query names them, so a read without them is
 * the document of before r16.
 */
export function snapshotCurrentRequestOf(search: string): SnapshotCurrentRequest {
  const params = new URLSearchParams(search);
  const integer = (name: string): bigint | null => {
    const text = params.get(name);
    if (text === null) return null;
    if (!/^[0-9]{1,16}$/.test(text)) throw new BridgeWireError("invalid_document", name, `${name} is a decimal integer`);
    return BigInt(text);
  };
  const have = integer("have");
  if (have === null) throw new BridgeWireError("invalid_document", "have", "have is a decimal integer");
  const after = integer("confirmed_after");
  const judgeNow = integer("judge_now");
  const judgeAge = integer("judge_age_ms");
  for (const key of params.keys()) {
    if (!SNAPSHOT_PARAMETERS.has(key)) throw new BridgeWireError("unknown_field", key, `the snapshot read has no parameter ${key}`);
  }
  const ask = params.get("ranking");
  if (ask !== null && !(SNAPSHOT_RANKING_ASKS as readonly string[]).includes(ask)) throw new BridgeWireError("invalid_document", "ranking", "ranking is word, all or since");
  const epoch = params.get("ranking_epoch");
  if (epoch !== null && !RANKING_EPOCH_PATTERN.test(epoch)) throw new BridgeWireError("invalid_document", "ranking_epoch", "ranking_epoch is 1 to 128 URL-unreserved characters");
  const seq = integer("ranking_seq");
  const records = params.get("ranking_records");
  if (records !== null && records !== "1") throw new BridgeWireError("invalid_document", "ranking_records", "ranking_records is 1");
  const est = params.get("ranking_est");
  if (est !== null && est !== "1") throw new BridgeWireError("invalid_document", "ranking_est", "ranking_est is 1");
  const request = {
    have,
    confirmed_after: after,
    judge_now: judgeNow,
    judge_age_ms: judgeAge,
    ...(ask === null ? {} : { ranking: ask }),
    ...(epoch === null ? {} : { ranking_epoch: epoch }),
    ...(seq === null ? {} : { ranking_seq: seq }),
    ...(records === null ? {} : { ranking_records: "1" as const }),
    ...(est === null ? {} : { ranking_est: "1" as const }),
  };
  const parsed = snapshotCurrentRequestSchema.safeParse(request);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new BridgeWireError("invalid_document", issue?.path.map(String).join(".") || "judge_now", issue?.message ?? "a snapshot parameter is invalid");
  }
  return parsed.data;
}

// ------------------------------------------------------------------------------------------------- the ranking feed

/**
 * A rank key's samples as a feed answer carries them (@gray/routing `FeedColumns`): `flags.length` samples, oldest first;
 * `nAt` their run numbers then their times; `measures` their latencies, times to first token (none: 0xFFFFFFFF in a
 * Uint32Array, NaN in a Float64Array) and output tokens; `flags` bit 0 success, bit 1 repeat.
 */
export interface SnapshotRankingColumns {
  readonly nAt: Float64Array;
  readonly measures: Uint32Array | Float64Array;
  readonly flags: Uint8Array;
}

/** One rank key of a feed answer (@gray/routing `FeedKey`); a failure's kind is checked by the reader's base. */
export interface SnapshotRankingKey {
  readonly key: string;
  readonly whole: boolean;
  readonly firstN: number;
  readonly samples: SnapshotRankingColumns;
  readonly failures?: readonly (readonly [atMs: number, failure: string])[];
  readonly lastObserved: number | null;
  readonly trial: {
    readonly windowStarted: number | null;
    readonly samples: number;
    readonly failures: number;
    readonly stableWindows: number;
    readonly graduated: boolean;
  };
  /** The key's circuit (r17, @gray/routing `FeedCircuit`), in an answer to a read that asked for the records. */
  readonly circuit?: { readonly open: boolean; readonly until: number | null; readonly probe: boolean };
}

/** A root's long-record summary in a feed answer (r17, @gray/routing `RecordSummary`). */
export interface SnapshotRecordSummary {
  readonly s: number;
  readonly f: number;
  readonly tokens: number;
  readonly decodeMs: number;
  readonly ttftP50: number | null;
  readonly ttftP90: number | null;
  readonly ttftP99: number | null;
  readonly ttftCount: number;
  readonly tpsCount: number;
  readonly at: number | null;
  /**
   * The root's estimate (r24, @gray/routing `RecordSummary.est`), in an answer to a read that asked for it (`ranking_est`):
   * its points, its typical time to first token and its decode speed (null while not published), and its revision.
   */
  readonly est?: SnapshotRecordEstimate;
}

/** A record's estimate in a feed answer (r24): `n` points, `ttftMs` and `tps` (null: not published), revision `rev`. */
export interface SnapshotRecordEstimate {
  readonly n: number;
  readonly ttftMs: number | null;
  readonly tps: number | null;
  readonly rev: number;
}

/**
 * A replica's answer of the ranking feed (@gray/routing `FeedAnswer`, the shape of `v`), in the form the lane's ranking
 * base takes it (`RankingBase.apply`, which checks it as it checks a replica's answer on the main gateway:
 * `feedAnswerValid`, each key `feedKeyValid`).
 */
export interface SnapshotRanking {
  readonly v: number;
  readonly epoch: string;
  readonly seq: number;
  readonly asOf: number;
  readonly full: boolean;
  readonly keys: readonly SnapshotRankingKey[];
  readonly removed: readonly string[];
  /** The roots' records changed since the reader's have, and the roots whose record went (r17), when the read asked. */
  readonly records?: readonly { readonly root: string; readonly summary: SnapshotRecordSummary }[];
  readonly removedRecords?: readonly string[];
}

/**
 * What the writer of a feed answer carries: the records and circuits (r17) only to a read that asked (`ranking_records`),
 * and each record's estimate (r24) only to one that asked for it too (`ranking_est`).
 */
export interface SnapshotRankingOptions {
  readonly records?: boolean;
  readonly est?: boolean;
}

/** The measures' width on the wire: 32-bit unsigned integers, or 64-bit floats for a key with a value past 32 bits. */
export const RANKING_MEASURES_TYPES = ["u32", "f64"] as const;

/**
 * The wire form of `SnapshotRanking`: integers as bigints (M27), each typed array as canonical standard base64 of its
 * little-endian bytes (an empty one is ""), and the measures' width named (`measures_type`). Strict, as every document.
 */
/** A float of a record's summary: finite, not negative (`@gray/json` writes a JS number as one, `0.0` included). */
const amountSchema = z.number().finite().min(0);

/** A record's summary on the wire (r17): its counts and time integers (M27), its sums and quantiles floats. */
const recordSummarySchema = z
  .object({
    s: amountSchema,
    f: amountSchema,
    tokens: amountSchema,
    decode_ms: amountSchema,
    ttft_p50: amountSchema.nullable(),
    ttft_p90: amountSchema.nullable(),
    ttft_p99: amountSchema.nullable(),
    ttft_count: uintSchema,
    tps_count: uintSchema,
    at: uintSchema.nullable(),
    est: z.object({ n: uintSchema, ttft_ms: amountSchema.nullable(), tps: amountSchema.nullable(), rev: uintSchema }).strict().optional(),
  })
  .strict();

export const snapshotRankingSchema = z
  .object({
    v: uintSchema,
    epoch: epochSchema,
    seq: uintSchema,
    as_of: uintSchema,
    full: z.boolean(),
    keys: z.array(
      z
        .object({
          key: z.string(),
          whole: z.boolean(),
          first_n: uintSchema,
          samples: z.object({ n_at: z.string(), measures: z.string(), measures_type: z.enum(RANKING_MEASURES_TYPES), flags: z.string() }).strict(),
          failures: z.array(z.tuple([uintSchema, z.string()])).optional(),
          last_observed: uintSchema.nullable(),
          trial: z.object({ window_started: uintSchema.nullable(), samples: uintSchema, failures: uintSchema, stable_windows: uintSchema, graduated: z.boolean() }).strict(),
          circuit: z.object({ open: z.boolean(), until: uintSchema.nullable(), probe: z.boolean() }).strict().optional(),
        })
        .strict(),
    ),
    removed: z.array(z.string()),
    records: z.array(z.object({ root: z.string(), summary: recordSummarySchema }).strict()).optional(),
    removed_records: z.array(z.string()).optional(),
  })
  .strict();
export type SnapshotRankingDto = z.infer<typeof snapshotRankingSchema>;

const LITTLE_ENDIAN = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;

/** The little-endian bytes of a typed array's own view (not the rest of its buffer). */
function littleEndianBytes(view: Float64Array | Uint32Array | Uint8Array): Uint8Array {
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  const size = view.BYTES_PER_ELEMENT;
  if (LITTLE_ENDIAN || size === 1) return bytes;
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += size) for (let j = 0; j < size; j++) out[i + j] = bytes[i + size - 1 - j]!;
  return out;
}

/**
 * A typed array of `size`-byte elements over the little-endian bytes of a decoded column (`base64Of`: a buffer of its
 * own, from offset 0), or a throw naming `field`. A big-endian platform swaps each element's bytes in place first.
 */
function typedOf<T>(bytes: Uint8Array<ArrayBuffer>, size: number, make: (buffer: ArrayBuffer) => T, field: string): T {
  if (bytes.length % size !== 0) throw new BridgeWireError("invalid_document", field, `ranking ${field}: ${bytes.length} bytes are not whole ${size}-byte values`);
  if (!LITTLE_ENDIAN && size > 1) for (let i = 0; i < bytes.length; i += size) bytes.subarray(i, i + size).reverse();
  return make(bytes.buffer);
}

/** A column's bytes: canonical standard base64 ("" for none), decoded into a buffer of their own. */
function base64Of(text: string, field: string): Uint8Array<ArrayBuffer> {
  const bytes = text === "" ? new Uint8Array(0) : decodeSchedulerBody(text);
  if (bytes === null) throw new BridgeWireError("invalid_document", field, `ranking ${field} is not canonical standard base64`);
  // `decodeSchedulerBody` writes into a new array of exactly the bytes; a copy keeps that true whatever it returns.
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && bytes.buffer instanceof ArrayBuffer ? (bytes as Uint8Array<ArrayBuffer>) : new Uint8Array(bytes);
}

/** A non-negative safe integer of a feed answer as the wire's bigint, or a throw naming `field`. */
function feedCount(value: unknown, field: string): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new BridgeWireError("invalid_document", field, `ranking ${field} is a non-negative safe integer`);
  return BigInt(value);
}

function feedObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value) || ArrayBuffer.isView(value)) throw new BridgeWireError("invalid_document", field, `ranking ${field} is an object`);
  return value as Record<string, unknown>;
}

function feedFlag(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new BridgeWireError("invalid_document", field, `ranking ${field} is a boolean`);
  return value;
}

function feedText(value: unknown, field: string): string {
  if (typeof value !== "string") throw new BridgeWireError("invalid_document", field, `ranking ${field} is a string`);
  return value;
}

function feedAmount(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new BridgeWireError("invalid_document", field, `ranking ${field} is a finite number of at least 0`);
  return value;
}

/**
 * A root's summary as the wire writes it (r17), or a throw naming the field. `est` (r24, a read that asked): its estimate
 * too, when it has one.
 */
function recordSummaryDtoOf(value: unknown, field: string, est: boolean): z.infer<typeof recordSummarySchema> {
  const r = feedObject(value, field);
  const quantile = (v: unknown, name: string) => (v === null ? null : feedAmount(v, `${field}.${name}`));
  return {
    s: feedAmount(r.s, `${field}.s`),
    f: feedAmount(r.f, `${field}.f`),
    tokens: feedAmount(r.tokens, `${field}.tokens`),
    decode_ms: feedAmount(r.decodeMs, `${field}.decodeMs`),
    ttft_p50: quantile(r.ttftP50, "ttftP50"),
    ttft_p90: quantile(r.ttftP90, "ttftP90"),
    ttft_p99: quantile(r.ttftP99, "ttftP99"),
    ttft_count: feedCount(r.ttftCount, `${field}.ttftCount`),
    tps_count: feedCount(r.tpsCount, `${field}.tpsCount`),
    at: r.at === null ? null : feedCount(r.at, `${field}.at`),
    ...(est && r.est !== undefined ? { est: estimateDtoOf(r.est, `${field}.est`) } : {}),
  };
}

/** A record's estimate as the wire writes it (r24), or a throw naming the field. */
function estimateDtoOf(value: unknown, field: string): { n: bigint; ttft_ms: number | null; tps: number | null; rev: bigint } {
  const e = feedObject(value, field);
  return {
    n: feedCount(e.n, `${field}.n`),
    ttft_ms: e.ttftMs === null ? null : feedAmount(e.ttftMs, `${field}.ttftMs`),
    tps: e.tps === null ? null : feedAmount(e.tps, `${field}.tps`),
    rev: feedCount(e.rev, `${field}.rev`),
  };
}

/** A key's circuit as the wire writes it (r17), or a throw naming the field. */
function circuitDtoOf(value: unknown, field: string): { open: boolean; until: bigint | null; probe: boolean } {
  const c = feedObject(value, field);
  return { open: feedFlag(c.open, `${field}.open`), until: c.until === null ? null : feedCount(c.until, `${field}.until`), probe: feedFlag(c.probe, `${field}.probe`) };
}

/**
 * The wire form of a replica's feed answer, as the bridge writes it. Only its shape is checked here (the types the wire
 * carries, the epoch's characters); what the values mean (the columns' lengths, the run numbers' order, a failure's
 * kind, the feed's bounds) is the lane's ranking base's to check, as the main gateway's base checks a replica's answer.
 * A value of another shape throws: the bridge then leaves `ranking` out. `options.records` (a read that asked,
 * `ranking_records`, r17): the roots' records, the roots whose record went and each key's circuit go too, when the answer
 * has them; otherwise none of them, which a lane of r16 (strict) would refuse. `options.est` (with `records`, a read that
 * named `ranking_est`, r24): each record's estimate too, which a lane of r23 (strict) would refuse.
 */
export function snapshotRankingDtoOf(value: unknown, options: SnapshotRankingOptions = {}): SnapshotRankingDto {
  const a = feedObject(value, "answer");
  const records = options.records === true;
  const est = records && options.est === true;
  const epoch = feedText(a.epoch, "epoch");
  if (!RANKING_EPOCH_PATTERN.test(epoch)) throw new BridgeWireError("invalid_document", "epoch", "ranking epoch is 1 to 128 URL-unreserved characters");
  if (!Array.isArray(a.keys)) throw new BridgeWireError("invalid_document", "keys", "ranking keys is an array");
  if (!Array.isArray(a.removed)) throw new BridgeWireError("invalid_document", "removed", "ranking removed is an array");
  return {
    v: feedCount(a.v, "v"),
    epoch,
    seq: feedCount(a.seq, "seq"),
    as_of: feedCount(a.asOf, "asOf"),
    full: feedFlag(a.full, "full"),
    keys: (a.keys as unknown[]).map((entry, i) => {
      const k = feedObject(entry, `keys.${i}`);
      const samples = feedObject(k.samples, `keys.${i}.samples`);
      const { nAt, measures, flags } = samples;
      if (!(nAt instanceof Float64Array) || !(measures instanceof Uint32Array || measures instanceof Float64Array) || !(flags instanceof Uint8Array)) {
        throw new BridgeWireError("invalid_document", `keys.${i}.samples`, "ranking samples are a Float64Array, a Uint32Array or Float64Array and a Uint8Array");
      }
      const trial = feedObject(k.trial, `keys.${i}.trial`);
      if (k.failures !== undefined && !Array.isArray(k.failures)) throw new BridgeWireError("invalid_document", `keys.${i}.failures`, "ranking failures are an array");
      return {
        key: feedText(k.key, `keys.${i}.key`),
        whole: feedFlag(k.whole, `keys.${i}.whole`),
        first_n: feedCount(k.firstN, `keys.${i}.firstN`),
        samples: {
          n_at: encodeSchedulerBody(littleEndianBytes(nAt)),
          measures: encodeSchedulerBody(littleEndianBytes(measures)),
          measures_type: measures instanceof Uint32Array ? ("u32" as const) : ("f64" as const),
          flags: encodeSchedulerBody(littleEndianBytes(flags)),
        },
        ...(k.failures === undefined
          ? {}
          : {
              failures: (k.failures as unknown[]).map((failure, j): [bigint, string] => {
                if (!Array.isArray(failure) || failure.length !== 2) throw new BridgeWireError("invalid_document", `keys.${i}.failures.${j}`, "ranking failure is [atMs, kind]");
                return [feedCount(failure[0], `keys.${i}.failures.${j}`), feedText(failure[1], `keys.${i}.failures.${j}`)];
              }),
            }),
        last_observed: k.lastObserved === null ? null : feedCount(k.lastObserved, `keys.${i}.lastObserved`),
        trial: {
          window_started: trial.windowStarted === null ? null : feedCount(trial.windowStarted, `keys.${i}.trial.windowStarted`),
          samples: feedCount(trial.samples, `keys.${i}.trial.samples`),
          failures: feedCount(trial.failures, `keys.${i}.trial.failures`),
          stable_windows: feedCount(trial.stableWindows, `keys.${i}.trial.stableWindows`),
          graduated: feedFlag(trial.graduated, `keys.${i}.trial.graduated`),
        },
        ...(records && k.circuit !== undefined ? { circuit: circuitDtoOf(k.circuit, `keys.${i}.circuit`) } : {}),
      };
    }),
    removed: (a.removed as unknown[]).map((key, i) => feedText(key, `removed.${i}`)),
    ...(records && a.records !== undefined ? { records: recordsDtoOf(a.records, est) } : {}),
    ...(records && a.removedRecords !== undefined ? { removed_records: textsOf(a.removedRecords, "removedRecords") } : {}),
  };
}

function recordsDtoOf(value: unknown, est: boolean): z.infer<typeof snapshotRankingSchema>["records"] {
  if (!Array.isArray(value)) throw new BridgeWireError("invalid_document", "records", "ranking records is an array");
  return (value as unknown[]).map((entry, i) => {
    const r = feedObject(entry, `records.${i}`);
    return { root: feedText(r.root, `records.${i}.root`), summary: recordSummaryDtoOf(r.summary, `records.${i}.summary`, est) };
  });
}

function textsOf(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new BridgeWireError("invalid_document", field, `ranking ${field} is an array`);
  return (value as unknown[]).map((text, i) => feedText(text, `${field}.${i}`));
}

const UTF8 = new TextEncoder();

/** What every key of a written feed answer has whatever its values: its members' names, its punctuation, its least values. */
const KEY_FIXED_BYTES = toJsonString({
  first_n: 0n,
  key: "",
  last_observed: 0n,
  samples: { flags: "", measures: "", measures_type: "u32", n_at: "" },
  trial: { failures: 0n, graduated: true, samples: 0n, stable_windows: 0n, window_started: 0n },
  whole: true,
} as unknown as Json).length;

/** What a key's circuit adds at the least (r17): its member, the shortest values, the comma before it. */
const CIRCUIT_FIXED_BYTES = toJsonString({ circuit: { open: true, probe: true, until: 0n } } as unknown as Json).length - 1;

/** What a root's record adds at the least (r17): its members, the shortest values (`0.0` a float, `0` an integer), a comma. */
const RECORD_FIXED_BYTES =
  toJsonString({ root: "", summary: { at: 0n, decode_ms: 0, f: 0, s: 0, tokens: 0, tps_count: 0n, ttft_count: 0n, ttft_p50: 0, ttft_p90: 0, ttft_p99: 0 } } as unknown as Json).length + 1;

/** What a record's estimate adds at the least (r24): its member, the shortest values (`null` is not shorter than `0.0`), a comma. */
const EST_FIXED_BYTES = toJsonString({ est: { n: 0n, rev: 0n, tps: 0, ttft_ms: 0 } } as unknown as Json).length - 1;

/**
 * A lower bound of the bytes a replica's feed answer comes to once written (`snapshotRankingDtoOf`, then `toJsonString`),
 * from its typed arrays' lengths and its texts alone, nothing encoded: @gray/routing `feedAnswerBytes`' accounting of a
 * key (its columns' bytes and its text), each column as base64 (4 characters per 3 bytes), each key's fixed members
 * (`KEY_FIXED_BYTES`), and each removed key's text. A ranking part past RANKING_ANSWER_MAX_BYTES by it is past it
 * written, so the bridge leaves it out without building its strings (r16); one within it is written and measured
 * (`snapshotAnswerBytes`). 0 for a value of no feed answer's shape, which the writer refuses. `options.records`: what
 * the records, the roots whose record went and the circuits add (r17), as the writer writes them for a read that asked;
 * `options.est` with it, what each record's estimate adds (r24).
 */
export function snapshotRankingBytesAtLeast(value: unknown, options: SnapshotRankingOptions = {}): number {
  if (typeof value !== "object" || value === null) return 0;
  const { keys, removed, records, removedRecords } = value as { readonly keys?: unknown; readonly removed?: unknown; readonly records?: unknown; readonly removedRecords?: unknown };
  let bytes = 0;
  if (Array.isArray(keys)) {
    for (const entry of keys as unknown[]) {
      if (typeof entry !== "object" || entry === null) continue;
      const { key, samples, circuit } = entry as { readonly key?: unknown; readonly samples?: unknown; readonly circuit?: unknown };
      bytes += KEY_FIXED_BYTES + (typeof key === "string" ? UTF8.encode(key).length : 0);
      if (options.records === true && circuit !== undefined) bytes += CIRCUIT_FIXED_BYTES;
      if (typeof samples !== "object" || samples === null) continue;
      const { nAt, measures, flags } = samples as { readonly nAt?: unknown; readonly measures?: unknown; readonly flags?: unknown };
      for (const column of [nAt, measures, flags]) if (ArrayBuffer.isView(column)) bytes += 4 * Math.ceil(column.byteLength / 3);
    }
  }
  if (Array.isArray(removed)) for (const key of removed as unknown[]) if (typeof key === "string") bytes += UTF8.encode(key).length + 2;
  if (options.records === true) {
    if (Array.isArray(records)) {
      for (const entry of records as unknown[]) {
        const { root, summary } = typeof entry === "object" && entry !== null ? (entry as { readonly root?: unknown; readonly summary?: unknown }) : {};
        bytes += RECORD_FIXED_BYTES + (typeof root === "string" ? UTF8.encode(root).length : 0);
        if (options.est === true && typeof summary === "object" && summary !== null && (summary as { readonly est?: unknown }).est !== undefined) bytes += EST_FIXED_BYTES;
      }
    }
    if (Array.isArray(removedRecords)) for (const root of removedRecords as unknown[]) if (typeof root === "string") bytes += UTF8.encode(root).length + 2;
  }
  return bytes;
}

/** A feed answer read from the wire: the columns back to typed arrays. A column that is not canonical base64 of whole values throws. */
export function snapshotRankingOf(dto: SnapshotRankingDto): SnapshotRanking {
  return {
    v: asNumber(dto.v, "v"),
    epoch: dto.epoch,
    seq: asNumber(dto.seq, "seq"),
    asOf: asNumber(dto.as_of, "as_of"),
    full: dto.full,
    keys: dto.keys.map((k, i) => {
      const field = `keys.${i}.samples`;
      const wide = k.samples.measures_type === "f64";
      return {
        key: k.key,
        whole: k.whole,
        firstN: asNumber(k.first_n, "first_n"),
        samples: {
          nAt: typedOf(base64Of(k.samples.n_at, `${field}.n_at`), 8, (b) => new Float64Array(b), `${field}.n_at`),
          measures: wide ? typedOf(base64Of(k.samples.measures, `${field}.measures`), 8, (b) => new Float64Array(b), `${field}.measures`) : typedOf(base64Of(k.samples.measures, `${field}.measures`), 4, (b) => new Uint32Array(b), `${field}.measures`),
          flags: typedOf(base64Of(k.samples.flags, `${field}.flags`), 1, (b) => new Uint8Array(b), `${field}.flags`),
        },
        ...(k.failures === undefined ? {} : { failures: k.failures.map(([at, kind]) => [asNumber(at, "failures"), kind] as const) }),
        lastObserved: k.last_observed === null ? null : asNumber(k.last_observed, "last_observed"),
        trial: {
          windowStarted: k.trial.window_started === null ? null : asNumber(k.trial.window_started, "window_started"),
          samples: asNumber(k.trial.samples, "trial.samples"),
          failures: asNumber(k.trial.failures, "trial.failures"),
          stableWindows: asNumber(k.trial.stable_windows, "stable_windows"),
          graduated: k.trial.graduated,
        },
        ...(k.circuit === undefined ? {} : { circuit: { open: k.circuit.open, until: k.circuit.until === null ? null : asNumber(k.circuit.until, "circuit.until"), probe: k.circuit.probe } }),
      };
    }),
    removed: [...dto.removed],
    ...(dto.records === undefined
      ? {}
      : {
          records: dto.records.map((r) => ({
            root: r.root,
            summary: {
              s: r.summary.s,
              f: r.summary.f,
              tokens: r.summary.tokens,
              decodeMs: r.summary.decode_ms,
              ttftP50: r.summary.ttft_p50,
              ttftP90: r.summary.ttft_p90,
              ttftP99: r.summary.ttft_p99,
              ttftCount: asNumber(r.summary.ttft_count, "ttft_count"),
              tpsCount: asNumber(r.summary.tps_count, "tps_count"),
              at: r.summary.at === null ? null : asNumber(r.summary.at, "at"),
              ...(r.summary.est === undefined ? {} : { est: { n: asNumber(r.summary.est.n, "est.n"), ttftMs: r.summary.est.ttft_ms, tps: r.summary.est.tps, rev: asNumber(r.summary.est.rev, "est.rev") } }),
            },
          })),
        }),
    ...(dto.removed_records === undefined ? {} : { removedRecords: [...dto.removed_records] }),
  };
}

// ------------------------------------------------------------------------------------------------- the answer

/**
 * What the bridge answers and what the CVM's remote source returns: the version, when it was last
 * rebuilt and confirmed, and the raw snapshot when the caller is behind. It matches the gateway's
 * `SnapshotAnswer` (`workers/gateway/src/snapshot.ts`) except that `snapshot` is `@gray/snapshot`'s
 * document: the remote source maps it with `gatewaySnapshotOf`.
 */
export interface RawSnapshotAnswer {
  readonly version: number;
  readonly refreshedAt: number;
  /** Absent when the source did not say, as `SnapshotAnswer.confirmedAt` is optional. */
  readonly confirmedAt?: number;
  readonly snapshot: Snapshot | null;
  /** The ranking feed's changes since what the read held (`ranking=all|since`), when the replica that answered had them (r16). */
  readonly ranking?: SnapshotRanking;
  /**
   * A `ranking` member this build could not read (not `snapshotRankingSchema`'s, or a column that is not canonical base64
   * of whole values), as it came off the wire, and why (review r16 finding 3): the snapshot is read all the same, and the
   * lane hands the value to its ranking base, which counts it unreadable as the main gateway's base counts a replica's
   * answer it cannot read (`RankingBase.apply`; its `ranking_stale` comes once that lasts past the alert age).
   */
  readonly rankingUnreadable?: { readonly value: unknown; readonly reason: string };
  /** Since when the answering replica's syncs with the collector fail (null: they work): to a read that takes the ranking members, from a replica that keeps a copy (r16). */
  readonly rankingFailingSince?: number | null;
}

/**
 * The wire form: the same answer with bigint integers and the snapshot as a JSON value. `ranking` is any value at the
 * envelope, read on its own (`snapshotAnswerOf`), so a ranking the lane cannot read never costs it the snapshot.
 */
export const snapshotAnswerSchema = z
  .object({
    version: uintSchema,
    refreshed_at: uintSchema,
    confirmed_at: uintSchema.nullable(),
    snapshot: z.unknown(),
    ranking: z.unknown().optional(),
    ranking_failing_since: uintSchema.nullable().optional(),
  })
  .strict();

export type SnapshotAnswerDto = z.infer<typeof snapshotAnswerSchema>;

const CONTENT_ARRAYS = ["keys", "routes", "capacities", "quotaLimits", "preferences", "routingDefaults", "registered", "mapped", "contentRecipients"] as const;

/**
 * A light structural check of the snapshot value: an object of format 1 with the members every
 * reader of `Snapshot` indexes (the arrays, the translation document, the version/digest/builtAt).
 * The deep shape belongs to `@gray/snapshot`; this only stops a document that is not a snapshot at
 * all from reaching the gateway as if it were one.
 */
function snapshotOfValue(value: unknown): Snapshot {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new BridgeWireError("invalid_document", "snapshot", "the snapshot is not an object");
  const snapshot = value as Record<string, unknown>;
  if (snapshot.format !== 1n) throw new BridgeWireError("invalid_document", "snapshot.format", "a snapshot is format 1");
  if (typeof snapshot.digest !== "string" || typeof snapshot.version !== "bigint" || typeof snapshot.builtAt !== "bigint") {
    throw new BridgeWireError("invalid_document", "snapshot", "a snapshot names its version, digest and builtAt");
  }
  if (snapshot.translation !== null && typeof snapshot.translation !== "string") throw new BridgeWireError("invalid_document", "snapshot.translation");
  for (const key of CONTENT_ARRAYS) {
    if (!Array.isArray(snapshot[key])) throw new BridgeWireError("invalid_document", `snapshot.${key}`, `a snapshot carries ${key} as an array`);
  }
  return numbersOfJson(snapshot, "snapshot") as Snapshot;
}

/**
 * The DO-facing answer of a wire answer: bigints back to numbers, the snapshot back to `Snapshot`, the ranking's columns
 * to typed arrays. A ranking that does not read is `rankingUnreadable`, the rest of the answer as it is (review r16
 * finding 3); a snapshot that does not read still throws.
 */
export function snapshotAnswerOf(dto: SnapshotAnswerDto): RawSnapshotAnswer {
  const answer: RawSnapshotAnswer = {
    version: asNumber(dto.version, "version"),
    refreshedAt: asNumber(dto.refreshed_at, "refreshed_at"),
    snapshot: dto.snapshot === null ? null : snapshotOfValue(dto.snapshot),
  };
  return {
    ...answer,
    ...(dto.confirmed_at === null ? {} : { confirmedAt: asNumber(dto.confirmed_at, "confirmed_at") }),
    ...(dto.ranking === undefined ? {} : rankingOfWire(dto.ranking)),
    ...(dto.ranking_failing_since === undefined ? {} : { rankingFailingSince: dto.ranking_failing_since === null ? null : asNumber(dto.ranking_failing_since, "ranking_failing_since") }),
  };
}

/** A `ranking` member read on its own: the feed answer, or the value as it came and why it does not read. */
function rankingOfWire(value: unknown): Pick<RawSnapshotAnswer, "ranking" | "rankingUnreadable"> {
  const parsed = snapshotRankingSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return { rankingUnreadable: { value, reason: `ranking ${issue?.path.map(String).join(".") || "(root)"}: ${issue?.message ?? "not the wire shape"}` } };
  }
  try {
    return { ranking: snapshotRankingOf(parsed.data) };
  } catch (error) {
    return { rankingUnreadable: { value, reason: error instanceof Error ? error.message : String(error) } };
  }
}

/** The wire answer of a DO-facing answer: integers to bigints, the snapshot to a JSON value, the ranking members only when given. */
export function snapshotAnswerDtoOf(answer: RawSnapshotAnswer, options: SnapshotRankingOptions = {}): SnapshotAnswerDto {
  return {
    version: asBigint(answer.version, "version"),
    refreshed_at: asBigint(answer.refreshedAt, "refreshedAt"),
    confirmed_at: answer.confirmedAt === undefined ? null : asBigint(answer.confirmedAt, "confirmedAt"),
    snapshot: answer.snapshot === null ? null : integersOfJson(answer.snapshot, "snapshot"),
    ...(answer.ranking === undefined ? {} : { ranking: snapshotRankingDtoOf(answer.ranking, options) }),
    ...(answer.rankingFailingSince === undefined ? {} : { ranking_failing_since: answer.rankingFailingSince === null ? null : asBigint(answer.rankingFailingSince, "rankingFailingSince") }),
  };
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The two bounds of a snapshot answer's bytes: the answer without its ranking members, and what those add. */
export interface SnapshotAnswerBounds {
  readonly snapshotBytes: number;
  readonly rankingBytes: number;
}

const SNAPSHOT_ANSWER_BOUNDS: SnapshotAnswerBounds = { snapshotBytes: SNAPSHOT_RESPONSE_MAX_BYTES, rankingBytes: RANKING_ANSWER_MAX_BYTES };

/** A snapshot answer's bytes as the bridge writes them, and whether the ranking was left out. */
export interface SnapshotAnswerBytes {
  readonly bytes: Uint8Array;
  /** What the ranking part came to when it was past its bound and `ranking` was left out (the bridge logs it); else null. */
  readonly rankingLeftOut: number | null;
}

/**
 * The bytes of one snapshot answer: the answer without its ranking members within `bounds.snapshotBytes`
 * (SNAPSHOT_RESPONSE_MAX_BYTES; past it a throw, as before r16), and the bytes the two ranking members add within
 * `bounds.rankingBytes` (RANKING_ANSWER_MAX_BYTES). Past that the answer goes without `ranking`, still with
 * `ranking_failing_since`, and says how large the part was. An answer without the ranking members is written once and
 * is the text of before r16.
 */
export function snapshotAnswerBytes(dto: SnapshotAnswerDto, bounds: SnapshotAnswerBounds = SNAPSHOT_ANSWER_BOUNDS): SnapshotAnswerBytes {
  const { ranking, ranking_failing_since: failingSince, ...rest } = dto;
  const plain = ENCODER.encode(toJsonString(rest as unknown as Json));
  if (plain.byteLength > bounds.snapshotBytes) throw new BridgeWireError("body_too_large", null, `the snapshot answer is over ${bounds.snapshotBytes} bytes`);
  if (ranking === undefined && failingSince === undefined) return { bytes: plain, rankingLeftOut: null };
  const whole = ENCODER.encode(toJsonString(dto as unknown as Json));
  const part = whole.byteLength - plain.byteLength;
  if (part <= bounds.rankingBytes) return { bytes: whole, rankingLeftOut: null };
  const { ranking: _left, ...without } = dto;
  return { bytes: ENCODER.encode(toJsonString(without as unknown as Json)), rankingLeftOut: part };
}

/** The bytes of one snapshot answer within both bounds (`snapshotAnswerBytes`); a throw when either is passed. */
export function snapshotAnswerText(dto: SnapshotAnswerDto): Uint8Array {
  const written = snapshotAnswerBytes(dto);
  if (written.rankingLeftOut !== null) throw new BridgeWireError("body_too_large", "ranking", `the snapshot answer's ranking is over ${RANKING_ANSWER_MAX_BYTES} bytes`);
  return written.bytes;
}

/** Read a snapshot answer: size first (SNAPSHOT_RANKING_RESPONSE_MAX_BYTES), then strict UTF-8, serde JSON and the envelope schema. */
export function snapshotAnswerOfText(bytes: Uint8Array): SnapshotAnswerDto {
  if (bytes.byteLength > SNAPSHOT_RANKING_RESPONSE_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the snapshot answer is over ${SNAPSHOT_RANKING_RESPONSE_MAX_BYTES} bytes`);
  let text: string;
  try {
    text = DECODER.decode(bytes);
  } catch {
    throw new BridgeWireError("invalid_document", null, "the snapshot answer is not UTF-8");
  }
  let value: unknown;
  try {
    value = parseSerde(text);
  } catch {
    throw new BridgeWireError("invalid_document", null, "the snapshot answer is not JSON");
  }
  const parsed = snapshotAnswerSchema.safeParse(value);
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the snapshot answer is not its wire shape");
  return parsed.data;
}
