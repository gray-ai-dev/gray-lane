import { parseSerde, toJsonString, type Json } from "@gray/json";
import type { Snapshot } from "@gray/snapshot";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { asBigint, asNumber, integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import { BRIDGE_PATHS, SNAPSHOT_TARGET, bridgeCall, type BridgeCall } from "./ops.ts";

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
 * the lane's largest wire bound (the scheduler forward's answer is 512 bytes after D27), and a
 * gateway snapshot of the sizes Gray serves today is well under it.
 */
export const SNAPSHOT_RESPONSE_MAX_BYTES = 8 * 1024 * 1024;

/**
 * The integers of a `current` call: `have`, an optional `confirmed_after`, and the optional judge
 * pair `judge_now`/`judge_age_ms` (bridge-3). The judge pair is both present or both absent: one
 * without the other describes no judgement, and a reader must not guess which half was meant.
 */
export const snapshotCurrentRequestSchema = z
  .object({
    have: uintSchema,
    confirmed_after: uintSchema.nullable(),
    judge_now: uintSchema.nullable().optional(),
    judge_age_ms: uintSchema.nullable().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const now = value.judge_now ?? null;
    const age = value.judge_age_ms ?? null;
    if ((now === null) !== (age === null)) ctx.addIssue({ code: "custom", path: ["judge_now"], message: "judge_now and judge_age_ms are both present or both absent" });
  });
export type SnapshotCurrentRequest = z.infer<typeof snapshotCurrentRequestSchema>;

/** The judge pair of a request, or null when the caller passes neither. */
export function snapshotJudgeOf(request: SnapshotCurrentRequest): SnapshotJudge | null {
  const now = request.judge_now ?? null;
  const age = request.judge_age_ms ?? null;
  return now === null || age === null ? null : { now, ageMs: age };
}

/** The query of one `current` call, in a fixed order, digits only. */
export function snapshotCurrentQuery(request: SnapshotCurrentRequest): string {
  const parsed = snapshotCurrentRequestSchema.parse(request);
  const parts = [`have=${parsed.have}`];
  if (parsed.confirmed_after !== null) parts.push(`confirmed_after=${parsed.confirmed_after}`);
  const judge = snapshotJudgeOf(parsed);
  if (judge !== null) parts.push(`judge_now=${judge.now}`, `judge_age_ms=${judge.ageMs}`);
  return parts.join("&");
}

/** The call of one `current` request: the GET whose path carries the integers. */
export function snapshotCurrentCall(request: SnapshotCurrentRequest): BridgeCall {
  return bridgeCall("snapshot.current", SNAPSHOT_TARGET, `${BRIDGE_PATHS["snapshot.current"]}?${snapshotCurrentQuery(request)}`);
}

/**
 * Read a `current` request from its query; refuses another name. A repeated name reads as its first
 * occurrence: the canonical query (`snapshotCurrentQuery`) writes each name once, and only the
 * signing client builds it, so a repeat is a malformed caller rather than a second value to bind.
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
    if (key !== "have" && key !== "confirmed_after" && key !== "judge_now" && key !== "judge_age_ms") throw new BridgeWireError("unknown_field", key, `the snapshot read has no parameter ${key}`);
  }
  const request = { have, confirmed_after: after, judge_now: judgeNow, judge_age_ms: judgeAge };
  const parsed = snapshotCurrentRequestSchema.safeParse(request);
  if (!parsed.success) throw new BridgeWireError("invalid_document", "judge_now", parsed.error.issues[0]?.message ?? "a snapshot parameter is invalid");
  return parsed.data;
}

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
}

/** The wire form: the same answer with bigint integers and the snapshot as a JSON value. */
export const snapshotAnswerSchema = z
  .object({
    version: uintSchema,
    refreshed_at: uintSchema,
    confirmed_at: uintSchema.nullable(),
    snapshot: z.unknown(),
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

/** The DO-facing answer of a wire answer: bigints back to numbers, the snapshot back to `Snapshot`. */
export function snapshotAnswerOf(dto: SnapshotAnswerDto): RawSnapshotAnswer {
  const answer: RawSnapshotAnswer = {
    version: asNumber(dto.version, "version"),
    refreshedAt: asNumber(dto.refreshed_at, "refreshed_at"),
    snapshot: dto.snapshot === null ? null : snapshotOfValue(dto.snapshot),
  };
  return dto.confirmed_at === null ? answer : { ...answer, confirmedAt: asNumber(dto.confirmed_at, "confirmed_at") };
}

/** The wire answer of a DO-facing answer: integers to bigints, the snapshot to a JSON value. */
export function snapshotAnswerDtoOf(answer: RawSnapshotAnswer): SnapshotAnswerDto {
  return {
    version: asBigint(answer.version, "version"),
    refreshed_at: asBigint(answer.refreshedAt, "refreshedAt"),
    confirmed_at: answer.confirmedAt === undefined ? null : asBigint(answer.confirmedAt, "confirmedAt"),
    snapshot: answer.snapshot === null ? null : integersOfJson(answer.snapshot, "snapshot"),
  };
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The bytes of one snapshot answer, within `SNAPSHOT_RESPONSE_MAX_BYTES`. */
export function snapshotAnswerText(dto: SnapshotAnswerDto): Uint8Array {
  const text = toJsonString(dto as unknown as Json);
  const bytes = ENCODER.encode(text);
  if (bytes.byteLength > SNAPSHOT_RESPONSE_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the snapshot answer is over ${SNAPSHOT_RESPONSE_MAX_BYTES} bytes`);
  return bytes;
}

/** Read a snapshot answer: size first, then strict UTF-8, serde JSON and the envelope schema. */
export function snapshotAnswerOfText(bytes: Uint8Array): SnapshotAnswerDto {
  if (bytes.byteLength > SNAPSHOT_RESPONSE_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the snapshot answer is over ${SNAPSHOT_RESPONSE_MAX_BYTES} bytes`);
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
