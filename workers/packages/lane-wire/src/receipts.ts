import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { decodeSchedulerBody, encodeSchedulerBody } from "./scheduler.ts";

/**
 * `receipts.put` and `receipts.get` (docs/design/persisted-receipts.md section 4): the entry's sealed receipt objects in
 * the bridge's R2 bucket (LANE_RECEIPTS), so a receipt outlives the boot and the replica that served it.
 *
 * Two kinds of object, both sealed inside the entry: one per receipt (`r/v1/<hex HMAC>`) and one per attestation
 * report, content addressed (`a/v1/<hex HMAC>`). The names are HMACs under a key only the entry holds, so the bridge
 * and anyone who reads the bucket cannot map a receipt id to its object. The bridge stores and answers the sealed bytes
 * as they are, with the entry's key id (`kid`) as the object's only custom metadata; it never opens them.
 *
 * - A put carries 1 to RECEIPTS_PUT_MAX_OBJECTS objects in a body of at most RECEIPTS_PUT_MAX_BYTES, each at most
 *   RECEIPT_OBJECT_MAX_BYTES, and answers which names it stored and which R2 would not write.
 * - A get names 1 to RECEIPTS_GET_MAX_KEYS objects and answers each in the order asked, null for one R2 does not hold.
 *   An R2 error fails the whole call (`object_unavailable`): it never reads as a missing object.
 *
 * Only an entry's key may make either call. The target is the one name `receipts`.
 */

/** The one target both ops sign. */
export const RECEIPTS_TARGET = "receipts";
/** The most objects one put carries (the entry flushes at 32 receipts, each with up to a few attestation objects). */
export const RECEIPTS_PUT_MAX_OBJECTS = 64;
/** The request body bound of `receipts.put`. */
export const RECEIPTS_PUT_MAX_BYTES = 4 * 1024 * 1024;
/** The most sealed bytes one object may have (a receipt with its peers' inner receipts, or an attestation report). */
export const RECEIPT_OBJECT_MAX_BYTES = 256 * 1024;
/** The most names one get asks for. */
export const RECEIPTS_GET_MAX_KEYS = 8;
/** An object's name: `r/` (a receipt) or `a/` (an attestation), the format, and a 32-byte HMAC in lower hex. */
export const RECEIPT_OBJECT_KEY_PATTERN = /^[ra]\/v1\/[0-9a-f]{64}$/;
/** The entry key's id: the first 8 bytes of its derived kid, in lower hex. */
export const RECEIPT_OBJECT_KID_PATTERN = /^[0-9a-f]{16}$/;

/** One sealed object as the entry and the bridge hold it. */
export interface ReceiptObject {
  readonly key: string;
  readonly kid: string;
  readonly sealed: Uint8Array;
}

const keySchema = z.string().regex(RECEIPT_OBJECT_KEY_PATTERN, "r/v1/ or a/v1/ and 64 lower hex");
const kidSchema = z.string().regex(RECEIPT_OBJECT_KID_PATTERN, "16 lower hex");
const SEALED_MAX_LENGTH = Math.ceil(RECEIPT_OBJECT_MAX_BYTES / 3) * 4;
const sealedSchema = z.string().superRefine((text, ctx) => {
  const bytes = text.length > SEALED_MAX_LENGTH ? null : decodeSchedulerBody(text);
  if (bytes === null || bytes.length === 0 || bytes.length > RECEIPT_OBJECT_MAX_BYTES) {
    ctx.addIssue({ code: "custom", message: `canonical standard base64 of 1 to ${RECEIPT_OBJECT_MAX_BYTES} bytes` });
  }
});
const objectSchema = z.object({ key: keySchema, kid: kidSchema, sealed: sealedSchema }).strict();
const distinct = (keys: readonly string[]): boolean => new Set(keys).size === keys.length;

export const receiptsPutRequestSchema = z
  .object({ objects: z.array(objectSchema).min(1).max(RECEIPTS_PUT_MAX_OBJECTS) })
  .strict()
  .refine((value) => distinct(value.objects.map((o) => o.key)), "each object's name once");
export type ReceiptsPutRequestDto = z.infer<typeof receiptsPutRequestSchema>;

export const receiptsPutAnswerSchema = z.object({ stored: z.array(keySchema).max(RECEIPTS_PUT_MAX_OBJECTS), failed: z.array(keySchema).max(RECEIPTS_PUT_MAX_OBJECTS) }).strict();
export type ReceiptsPutAnswerDto = z.infer<typeof receiptsPutAnswerSchema>;

export const receiptsGetRequestSchema = z
  .object({ keys: z.array(keySchema).min(1).max(RECEIPTS_GET_MAX_KEYS) })
  .strict()
  .refine((value) => distinct(value.keys), "each name once");
export type ReceiptsGetRequestDto = z.infer<typeof receiptsGetRequestSchema>;

export const receiptsGetAnswerSchema = z.object({ objects: z.array(objectSchema.nullable()).max(RECEIPTS_GET_MAX_KEYS) }).strict();
export type ReceiptsGetAnswerDto = z.infer<typeof receiptsGetAnswerSchema>;

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

function objectDtoOf(object: ReceiptObject): { key: string; kid: string; sealed: string } {
  if (object.sealed.byteLength === 0 || object.sealed.byteLength > RECEIPT_OBJECT_MAX_BYTES) {
    throw new BridgeWireError("body_too_large", "sealed", `a sealed object is 1 to ${RECEIPT_OBJECT_MAX_BYTES} bytes`);
  }
  return { key: object.key, kid: object.kid, sealed: encodeSchedulerBody(object.sealed) };
}

function objectOf(dto: { readonly key: string; readonly kid: string; readonly sealed: string }): ReceiptObject {
  const sealed = decodeSchedulerBody(dto.sealed);
  if (sealed === null) throw new BridgeWireError("invalid_document", "sealed", "a sealed object is canonical standard base64");
  return { key: dto.key, kid: dto.kid, sealed };
}

/** The members of a put document beside its objects' own: `{"objects":[` ... `]}`, and a comma and the braces of each. */
function putBodyBytes(objects: readonly { key: string; kid: string; sealed: string }[]): number {
  // {"key":"<key>","kid":"<kid>","sealed":"<sealed>"}: 31 bytes of members and quotes around the three strings.
  return 14 + objects.reduce((sum, o, i) => sum + (i === 0 ? 0 : 1) + 31 + o.key.length + o.kid.length + o.sealed.length, 0);
}

/** A put of `objects`, checked before it is signed: the wire's form, and the op's body bound (`body_too_large`). */
export function receiptsPutRequestDtoOf(objects: readonly ReceiptObject[]): ReceiptsPutRequestDto {
  const dtos = objects.map(objectDtoOf);
  if (putBodyBytes(dtos) > RECEIPTS_PUT_MAX_BYTES) throw new BridgeWireError("body_too_large", "objects", `a receipts.put body is at most ${RECEIPTS_PUT_MAX_BYTES} bytes`);
  return checked(receiptsPutRequestSchema, { objects: dtos });
}

/** A put's objects as the bridge stores them: the sealed bytes decoded. */
export function receiptsPutObjectsOf(dto: ReceiptsPutRequestDto): ReceiptObject[] {
  return dto.objects.map(objectOf);
}

export function receiptsPutAnswerDtoOf(result: { readonly stored: readonly string[]; readonly failed: readonly string[] }): ReceiptsPutAnswerDto {
  return checked(receiptsPutAnswerSchema, { stored: [...result.stored], failed: [...result.failed] });
}

export function receiptsPutResultOf(dto: ReceiptsPutAnswerDto): { stored: string[]; failed: string[] } {
  return { stored: [...dto.stored], failed: [...dto.failed] };
}

/** A get of `keys`, checked before it is signed. */
export function receiptsGetRequestDtoOf(keys: readonly string[]): ReceiptsGetRequestDto {
  return checked(receiptsGetRequestSchema, { keys: [...keys] });
}

export function receiptsGetAnswerDtoOf(objects: readonly (ReceiptObject | null)[]): ReceiptsGetAnswerDto {
  return checked(receiptsGetAnswerSchema, { objects: objects.map((o) => (o === null ? null : objectDtoOf(o))) });
}

/** A get's answer as the entry reads it: one entry per name asked, in that order, null for one R2 does not hold. */
export function receiptObjectsOf(dto: ReceiptsGetAnswerDto): (ReceiptObject | null)[] {
  return dto.objects.map((o) => (o === null ? null : objectOf(o)));
}
