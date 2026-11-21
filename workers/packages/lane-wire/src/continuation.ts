import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { asBigint, asNumber, uintSchema } from "./ints.ts";

/**
 * `continuation.pin` and `continuation.bind`: which route issued a Responses reply, shared by every lane VM that
 * admits requests (the entry's replicas; a relay stack VM that serves customers directly).
 *
 * A Responses request that continues an earlier response (`previous_response_id`, `conversation`) is delivered to the
 * software that answered that response: a relay's own software in its VM, or a provider's API on an endpoint route.
 * Gray keeps no conversation. It records where a reply came from so that the follow-up goes back there and nowhere
 * else, whichever replica receives it. One row per reference: the reference's hash, the endpoint that served the reply,
 * the model, and when it was made (the store's own columns, `@gray/continuation` `ContinuationStore`). No prompt, no
 * answer, and no response id: the lane hashes each id inside its VM (`@gray/continuation` `hashedReference`,
 * SHA-256 over a domain line, the workspace, the kind and the id), so the bridge and the store hold `sha256:<hex>`.
 *
 * `continuation.bind` is called once a reply's `response` object is read, `continuation.pin` before a follow-up is
 * routed. The bridge keeps the rows in objects of its own, one per workspace and bucket (`LaneContinuationDO`), and
 * resolves a pin as the API Worker's gateway does (`@gray/continuation` `pinReferences`).
 *
 * The answers of a pin: `pinned` with the endpoint every reference is bound to; `missing` when one is not bound (never
 * bound, expired after the store's 30 days, or another workspace's); `conflict` when two references are bound to
 * different endpoints; `unavailable` when a store gave no answer in time. The lane maps them to the API Worker's
 * errors (`continuation_not_found`, `continuation_endpoint_conflict`, `continuation_lookup_unavailable`).
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
/** A request names at most its `previous_response_id` and its `conversation`; a reply creates at most its id and its conversation's. */
export const CONTINUATION_MAX_REFERENCES = 2;
/** The longest model a binding stores (`@gray/continuation` MAX_MODEL_BYTES bounds it in bytes; this bounds the wire's string). */
export const CONTINUATION_MODEL_MAX_LENGTH = 256;

const id = z.string().regex(CONTINUATION_ID_PATTERN, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const reference = z.object({ kind: z.enum(["response", "conversation"]), reference: z.string().regex(CONTINUATION_REFERENCE_PATTERN, "a hashed reference is sha256: and 64 lower hex") }).strict();
const references = z.array(reference).min(1).max(CONTINUATION_MAX_REFERENCES);
const model = z
  .string()
  .min(1)
  .max(CONTINUATION_MODEL_MAX_LENGTH)
  .refine((value) => value.isWellFormed(), "a string of Unicode scalar values");

export const continuationPinRequestSchema = z.object({ workspace_id: id, references }).strict();
export type ContinuationPinRequestDto = z.infer<typeof continuationPinRequestSchema>;

export const continuationPinAnswerSchema = z.union([
  z.object({ outcome: z.literal("pinned"), endpoint_id: id }).strict(),
  z.object({ outcome: z.enum(["missing", "conflict", "unavailable"]) }).strict(),
]);
export type ContinuationPinAnswerDto = z.infer<typeof continuationPinAnswerSchema>;

export const continuationBindRequestSchema = z.object({ workspace_id: id, endpoint_id: id, model, references }).strict();
export type ContinuationBindRequestDto = z.infer<typeof continuationBindRequestSchema>;

export const continuationBindAnswerSchema = z.object({ bound: uintSchema, failed: uintSchema }).strict();
export type ContinuationBindAnswerDto = z.infer<typeof continuationBindAnswerSchema>;

/** One hashed reference, as `@gray/continuation`'s `Reference`. */
export interface ContinuationReference {
  readonly kind: "response" | "conversation";
  readonly reference: string;
}

/** What a pin found, as the lane and the bridge hold it. */
export type ContinuationPin = { readonly outcome: "pinned"; readonly endpointId: string } | { readonly outcome: "missing" | "conflict" | "unavailable" };

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
  return checked(continuationPinAnswerSchema, pin.outcome === "pinned" ? { outcome: "pinned", endpoint_id: pin.endpointId } : { outcome: pin.outcome });
}

export function continuationPinOf(dto: ContinuationPinAnswerDto): ContinuationPin {
  return dto.outcome === "pinned" ? { outcome: "pinned", endpointId: dto.endpoint_id } : { outcome: dto.outcome };
}

export function continuationBindRequestDtoOf(input: { readonly workspaceId: string; readonly endpointId: string; readonly model: string; readonly references: readonly ContinuationReference[] }): ContinuationBindRequestDto {
  return checked(continuationBindRequestSchema, {
    workspace_id: input.workspaceId,
    endpoint_id: input.endpointId,
    model: input.model,
    references: input.references.map((ref) => ({ kind: ref.kind, reference: ref.reference })),
  });
}

export function continuationBindAnswerDtoOf(result: { readonly bound: number; readonly failed: number }): ContinuationBindAnswerDto {
  return { bound: asBigint(result.bound, "bound"), failed: asBigint(result.failed, "failed") };
}

export function continuationBoundOf(dto: ContinuationBindAnswerDto): { readonly bound: number; readonly failed: number } {
  return { bound: asNumber(dto.bound, "bound"), failed: asNumber(dto.failed, "failed") };
}
