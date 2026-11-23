import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { asBigint, asNumber, uintSchema } from "./ints.ts";

/**
 * `continuation.pin` and `continuation.bind`: which route issued a Responses reply, shared by every lane VM that
 * admits requests (the entry's replicas; a relay stack VM that serves customers directly).
 *
 * A Responses request that continues an earlier response (`previous_response_id`, `conversation`, or
 * `input[].type = "item_reference"`) is delivered to the software that answered that response: a relay's own software
 * in its VM, or a provider's API on an endpoint route. Gray keeps no plaintext conversation. It records where a reply
 * came from so that the follow-up goes back there and nowhere else, whichever replica receives it, and optionally holds
 * opaque ciphertext sealed inside the entry TEE for zero-retention continuation (`sealed`, with a shorter expiry). One
 * pin row per reference: the reference's hash, the endpoint that served the reply, the model, and when it was made
 * (`@gray/continuation` `ContinuationStore`). The lane hashes each id inside its VM (`@gray/continuation`
 * `hashedReference`, SHA-256 over a domain line, the workspace, the kind and the id), so the bridge and the store hold
 * `sha256:<hex>`.
 *
 * `continuation.bind` is called once a reply's `response` object is read, `continuation.pin` before a follow-up is
 * routed. The bridge keeps the rows in objects of its own, one per workspace and bucket (`LaneContinuationDO`), and
 * resolves a pin as the API Worker's gateway does (`@gray/continuation` `pinReferences`).
 *
 * The answers of a pin: `pinned` with the endpoint every reference is bound to (and any live `sealed` entries for
 * zero-retention continuation); `missing` when one is not bound (never bound, expired after the store's 30 days, or
 * another workspace's); `conflict` when two references are bound to different endpoints; `unavailable` when a store
 * gave no answer in time. The lane maps them to the API Worker's errors (`continuation_not_found`,
 * `continuation_endpoint_conflict`, `continuation_lookup_unavailable`).
 *
 * The target is `continuation/<workspace id>`, so a signature over one workspace's call never verifies as another's.
 * A relay stack VM whose relay takes Gray's entries only (`backend`) may call neither: its entry pins and binds.
 */

/** The prefix of the target a call signs: `continuation/<workspace id>`. */
export const CONTINUATION_TARGET_PREFIX = "continuation/";
/** A workspace or endpoint id, as the account and endpoint documents spell it. */
export const CONTINUATION_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
/** A hashed reference, as `@gray/continuation` `hashedReference` writes it (the gateway's tests hold the two equal). */
export const CONTINUATION_REFERENCE_PATTERN = /^sha256:[0-9a-f]{64}$/;
/** The most hashed references one `continuation.pin` or `continuation.bind` document may carry. */
export const CONTINUATION_MAX_REFERENCES = 256;
/** The longest model a binding stores (`@gray/continuation` MAX_MODEL_BYTES bounds it in bytes; this bounds the wire's string). */
export const CONTINUATION_MODEL_MAX_LENGTH = 256;
/** The longest encrypted zero-retention state blob a single reference may carry (matches `@gray/continuation` MAX_SEALED_STATE_BYTES). */
export const CONTINUATION_STATE_MAX_LENGTH = 700_000;
/** The longest TTL in milliseconds for encrypted zero-retention continuation state (24 hours). */
export const CONTINUATION_STATE_MAX_TTL_MS = 24 * 3600 * 1000;
/** Request body limit for `continuation.bind` carrying sealed zero-retention state (2 MiB). */
export const CONTINUATION_BIND_MAX_BYTES = 2 * 1024 * 1024;

const UTF8 = new TextEncoder();

const id = z.string().regex(CONTINUATION_ID_PATTERN, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const referenceKind = z.enum(["response", "conversation", "item"]);
const hashedReferenceSchema = z.string().regex(CONTINUATION_REFERENCE_PATTERN, "a hashed reference is sha256: and 64 lower hex");
const sealedStateSchema = z
  .string()
  .min(1)
  .max(CONTINUATION_STATE_MAX_LENGTH)
  .refine((value) => value.isWellFormed() && UTF8.encode(value).byteLength <= CONTINUATION_STATE_MAX_LENGTH, `a well-formed string of at most ${CONTINUATION_STATE_MAX_LENGTH} UTF-8 bytes`);
const reference = z.object({ kind: referenceKind, reference: hashedReferenceSchema }).strict();
const bindReference = z.object({ kind: referenceKind, reference: hashedReferenceSchema, sealed: sealedStateSchema.optional() }).strict();
const sealedHitSchema = z.object({ kind: referenceKind, reference: hashedReferenceSchema, sealed: sealedStateSchema }).strict();
const references = z.array(reference).min(1).max(CONTINUATION_MAX_REFERENCES);
const bindReferences = z.array(bindReference).min(1).max(CONTINUATION_MAX_REFERENCES);
const model = z
  .string()
  .min(1)
  .max(CONTINUATION_MODEL_MAX_LENGTH)
  .refine((value) => value.isWellFormed(), "a string of Unicode scalar values");
const stateTtlMsSchema = uintSchema.min(1n, "state_ttl_ms must be positive").max(BigInt(CONTINUATION_STATE_MAX_TTL_MS), `state_ttl_ms is at most ${CONTINUATION_STATE_MAX_TTL_MS}`);

export const continuationPinRequestSchema = z.object({ workspace_id: id, references }).strict();
export type ContinuationPinRequestDto = z.infer<typeof continuationPinRequestSchema>;

export const continuationPinAnswerSchema = z.union([
  z.object({ outcome: z.literal("pinned"), endpoint_id: id, sealed: z.array(sealedHitSchema).max(CONTINUATION_MAX_REFERENCES).optional() }).strict(),
  z.object({ outcome: z.enum(["missing", "conflict", "unavailable"]) }).strict(),
]);
export type ContinuationPinAnswerDto = z.infer<typeof continuationPinAnswerSchema>;

export const continuationBindRequestSchema = z.object({ workspace_id: id, endpoint_id: id, model, references: bindReferences, state_ttl_ms: stateTtlMsSchema.optional() }).strict();
export type ContinuationBindRequestDto = z.infer<typeof continuationBindRequestSchema>;

export const continuationBindAnswerSchema = z.object({ bound: uintSchema, failed: uintSchema }).strict();
export type ContinuationBindAnswerDto = z.infer<typeof continuationBindAnswerSchema>;

/** One reference kind (`@gray/continuation`'s `ReferenceKind`). */
export type ContinuationReferenceKind = "response" | "conversation" | "item";

/** One hashed reference, as `@gray/continuation`'s `Reference`. */
export interface ContinuationReference {
  readonly kind: ContinuationReferenceKind;
  readonly reference: string;
}

/** One hashed reference to bind, optionally carrying encrypted zero-retention state. */
export interface ContinuationBindReference extends ContinuationReference {
  readonly sealed?: string;
}

/** One live encrypted zero-retention continuation state returned by `continuation.pin`. */
export interface ContinuationSealedHit {
  readonly kind: ContinuationReferenceKind;
  readonly reference: string;
  readonly sealed: string;
}

/** What a pin found, as the lane and the bridge hold it. */
export type ContinuationPin =
  | { readonly outcome: "pinned"; readonly endpointId: string; readonly sealed?: readonly ContinuationSealedHit[] }
  | { readonly outcome: "missing" | "conflict" | "unavailable" };

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

/** `continuation/<workspace id>`, the target a call for `workspaceId` signs. */
export function continuationTarget(workspaceId: string): string {
  if (!CONTINUATION_ID_PATTERN.test(workspaceId)) throw new BridgeWireError("invalid_target", null, "a workspace id is 1-128 characters of [A-Za-z0-9_.:-]");
  return `${CONTINUATION_TARGET_PREFIX}${workspaceId}`;
}

export function continuationPinRequestDtoOf(input: { readonly workspaceId: string; readonly references: readonly ContinuationReference[] }): ContinuationPinRequestDto {
  return checked(continuationPinRequestSchema, { workspace_id: input.workspaceId, references: input.references.map((ref) => ({ kind: ref.kind, reference: ref.reference })) });
}

export function continuationPinAnswerDtoOf(pin: ContinuationPin): ContinuationPinAnswerDto {
  if (pin.outcome !== "pinned") return checked(continuationPinAnswerSchema, { outcome: pin.outcome });
  return checked(continuationPinAnswerSchema, {
    outcome: "pinned",
    endpoint_id: pin.endpointId,
    ...(pin.sealed === undefined || pin.sealed.length === 0 ? {} : { sealed: pin.sealed.map((entry) => ({ kind: entry.kind, reference: entry.reference, sealed: entry.sealed })) }),
  });
}

export function continuationPinOf(dto: ContinuationPinAnswerDto): ContinuationPin {
  if (dto.outcome !== "pinned") return { outcome: dto.outcome };
  return dto.sealed === undefined || dto.sealed.length === 0
    ? { outcome: "pinned", endpointId: dto.endpoint_id }
    : { outcome: "pinned", endpointId: dto.endpoint_id, sealed: dto.sealed.map((entry) => ({ kind: entry.kind, reference: entry.reference, sealed: entry.sealed })) };
}

export function continuationBindRequestDtoOf(input: {
  readonly workspaceId: string;
  readonly endpointId: string;
  readonly model: string;
  readonly references: readonly ContinuationBindReference[];
  readonly stateTtlMs?: number;
}): ContinuationBindRequestDto {
  return checked(continuationBindRequestSchema, {
    workspace_id: input.workspaceId,
    endpoint_id: input.endpointId,
    model: input.model,
    references: input.references.map((ref) => ({
      kind: ref.kind,
      reference: ref.reference,
      ...(ref.sealed === undefined ? {} : { sealed: ref.sealed }),
    })),
    ...(input.stateTtlMs === undefined ? {} : { state_ttl_ms: asBigint(input.stateTtlMs, "state_ttl_ms") }),
  });
}

export function continuationBindAnswerDtoOf(result: { readonly bound: number; readonly failed: number }): ContinuationBindAnswerDto {
  return { bound: asBigint(result.bound, "bound"), failed: asBigint(result.failed, "failed") };
}

export function continuationBoundOf(dto: ContinuationBindAnswerDto): { readonly bound: number; readonly failed: number } {
  return { bound: asNumber(dto.bound, "bound"), failed: asNumber(dto.failed, "failed") };
}
