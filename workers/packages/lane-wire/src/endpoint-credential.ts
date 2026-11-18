import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { MAX_SAFE_INTEGER } from "./ints.ts";

/**
 * `endpoint.credential` (docs/design/lane-provider-routes.md section 3.2): the confidential lane's entry asks for one
 * provider endpoint's API key, sealed to an X25519 key it made for that one request, so the key reaches the CVM without
 * the master key entering it and without crossing the bridge in clear. Only an entry's key may call it: a relay stack
 * VM's key is refused before the nonce is spent, as for `acme.challenge` and `entry.role`.
 *
 * The request names the endpoint, the credential generation the entry's snapshot names for it, and the reply key, 32
 * bytes of X25519 public key as 64 lower hex (as `stack.vault.share`'s `ephemeral_public_key`). The target is
 * `endpoint-credential/<endpoint id>`, so a signature over one endpoint's call never verifies as another's.
 *
 * The answer echoes the endpoint and the generation and carries one HPKE base-mode message
 * (`@gray/relay-connector/endpoint-credential`): `algo` names the suite (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM, the relay credential intake's `x25519-hpke-base-sha256-aes256gcm`), `enc` is the 32-byte encapsulated
 * key and `ciphertext` the AEAD output (the key's bytes and the 16-byte tag), both lower hex. The HPKE info and AAD bind
 * the endpoint and the generation, so an answer for another endpoint or generation does not open; the entry still
 * checks the echo before it opens anything.
 */

/** The prefix of the target a call signs: `endpoint-credential/<endpoint id>`. */
export const ENDPOINT_CREDENTIAL_TARGET_PREFIX = "endpoint-credential/";
/** The HPKE suite of the answer, as the relay credential intake names it (`@gray/relay-connector` RELAY_INTAKE_ALGO). */
export const ENDPOINT_CREDENTIAL_ALGO = "x25519-hpke-base-sha256-aes256gcm";
/**
 * The longest key the answer carries, in bytes: the console's bound on a stored endpoint credential (a registration or
 * a rotation refuses a longer one, `provider/endpoints.ts`).
 */
export const ENDPOINT_CREDENTIAL_MAX_BYTES = 65_536;
/** An endpoint id, as `endpoint.*`'s other documents spell it. */
export const ENDPOINT_CREDENTIAL_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

const id = z.string().regex(ENDPOINT_CREDENTIAL_ID_PATTERN, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const generation = z.bigint().min(1n).max(MAX_SAFE_INTEGER);
const key32 = z.string().regex(/^[0-9a-f]{64}$/, "32 bytes as lower hex");
// At least one byte of key and the tag; at most the longest key and the tag. The length is bounded before the pattern
// runs, and the pattern is one character class, so a long string costs a linear scan.
const ciphertext = z
  .string()
  .min(2 * 17)
  .max(2 * (ENDPOINT_CREDENTIAL_MAX_BYTES + 16))
  .regex(/^[0-9a-f]+$/, "lower hex")
  .refine((text) => text.length % 2 === 0, "whole bytes of lower hex");

export const endpointCredentialRequestSchema = z.object({ endpoint_id: id, credential_generation: generation, reply_key: key32 }).strict();
export type EndpointCredentialRequestDto = z.infer<typeof endpointCredentialRequestSchema>;

export const endpointCredentialAnswerSchema = z
  .object({ endpoint_id: id, credential_generation: generation, algo: z.literal(ENDPOINT_CREDENTIAL_ALGO), enc: key32, ciphertext })
  .strict();
export type EndpointCredentialAnswerDto = z.infer<typeof endpointCredentialAnswerSchema>;

/** One sealed key as the console answers it and the entry reads it: numbers, not the wire's bigints. */
export interface EndpointCredentialSealed {
  readonly endpointId: string;
  readonly generation: number;
  readonly enc: string;
  readonly ciphertext: string;
}

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

function generationOf(value: number): bigint {
  if (!Number.isSafeInteger(value) || value < 1) throw new BridgeWireError("invalid_document", "credential_generation", "credential_generation: a whole number from 1");
  return BigInt(value);
}

/** `endpoint-credential/<endpoint id>`, the target a call for `endpointId` signs. */
export function endpointCredentialTarget(endpointId: string): string {
  if (!ENDPOINT_CREDENTIAL_ID_PATTERN.test(endpointId)) throw new BridgeWireError("invalid_target", null, "an endpoint id is 1-128 characters of [A-Za-z0-9_.:-]");
  return `${ENDPOINT_CREDENTIAL_TARGET_PREFIX}${endpointId}`;
}

/** The wire request: the endpoint, the generation the entry's snapshot names, and the reply key as lower hex. */
export function endpointCredentialRequestDtoOf(input: { readonly endpointId: string; readonly generation: number; readonly replyKey: string }): EndpointCredentialRequestDto {
  return checked(endpointCredentialRequestSchema, { endpoint_id: input.endpointId, credential_generation: generationOf(input.generation), reply_key: input.replyKey });
}

/** The console's sealed answer as the wire's. */
export function endpointCredentialAnswerDtoOf(sealed: EndpointCredentialSealed): EndpointCredentialAnswerDto {
  return checked(endpointCredentialAnswerSchema, {
    endpoint_id: sealed.endpointId,
    credential_generation: generationOf(sealed.generation),
    algo: ENDPOINT_CREDENTIAL_ALGO,
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
  });
}

/** The wire answer as the entry reads it. */
export function endpointCredentialOf(dto: EndpointCredentialAnswerDto): EndpointCredentialSealed {
  return { endpointId: dto.endpoint_id, generation: Number(dto.credential_generation), enc: dto.enc, ciphertext: dto.ciphertext };
}
