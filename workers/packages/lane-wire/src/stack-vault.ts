import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { uintSchema } from "./ints.ts";
import { LANE_BRIDGE_KEY_ID_PATTERN } from "./signing.ts";
import { STACK_WIRE_ID_PATTERN } from "./stack-rules.ts";

/**
 * `stack.vault.get` and `stack.vault.put` (docs/design/relay-no-always-on-host.md §3.1 and 13.4, decision H6): Gray's
 * ciphertext copy of a relay stack VM's sealed records, kept so that a node move, a lost disk or a second instance of
 * the same app recovers without the relay. A record is `@gray/relay-connector/vault`'s `serializeRecord` text: its header
 * in clear, its body sealed under keys only the TEE derives; Gray stores it and cannot open it.
 *
 * **One pair per (relay, app)** (P7-4, 13.4): the boot box (`boot`), the vault (`vault`) and the vault sealed for the
 * previous image (`vault_prev`), stored and replaced together, as the VM's disk commits a boot box and the vault it needs
 * as one pair (vault-disk.mjs, #482). `get` answers the pair with its version (version 0 and no pair when Gray holds
 * none). `put` carries the whole pair and the pair version the VM built it on (`base_version`): Gray stores it only when
 * its own current version is that one (compare-and-swap, one condition for the three records), as version
 * `base_version + 1`, and answers `stored: true` with it; otherwise `stored: false` with Gray's current version, and the
 * VM reads the newest pair and decides again (13.4, "Two instances, one vault"). A restore therefore only ever reads a
 * pair one VM had committed on its disk, never one half of an update. The bridge answers a key only for its own relay
 * (LANE_BRIDGE_STACK_RELAYS), as the other `stack.*` ops; the console refuses an app that is not the relay's and a pair
 * whose records do not fit it (a header naming another relay, app or format, a boot box with an image or a vault
 * without one, or a record whose version is below the one Gray's pair holds), as `vault_record_refused`.
 */

/** The records of a pair (`@gray/relay-connector/vault` `RecordKind`, and P7's `vault_prev`, a vault-format record). */
export const STACK_VAULT_KINDS = ["boot", "vault", "vault_prev"] as const;
export type StackVaultKind = (typeof STACK_VAULT_KINDS)[number];

/** A dstack app id: 40 lower hex, no `0x` (the relay's contract address on an on-chain KMS). */
export const STACK_VAULT_APP_ID_PATTERN = /^[0-9a-f]{40}$/;

/**
 * The longest record, in characters: 1 MiB. A record is JCS text of hex and the header's checked words, so printable
 * ASCII (the schema holds it to that): characters are bytes.
 */
export const STACK_VAULT_RECORD_MAX_CHARS = 1024 * 1024;

/**
 * `stack.vault.put`'s request body bound (`bridgeRequestMaxBytes`): three records as JSON strings, where a quote or a
 * backslash is written as two bytes, so at most twice their characters each, and the rest of the document.
 */
export const STACK_VAULT_PUT_MAX_BYTES = 3 * 2 * STACK_VAULT_RECORD_MAX_CHARS + 8 * 1024;

const id = z.string().regex(STACK_WIRE_ID_PATTERN);
const appId = z.string().regex(STACK_VAULT_APP_ID_PATTERN);
const record = z.string().min(1).max(STACK_VAULT_RECORD_MAX_CHARS).regex(/^[ -~]+$/);

/** A pair: each record, or null for one the VM's disk does not hold. */
export const stackVaultPairSchema = z.object({ boot: record.nullable(), vault: record.nullable(), vault_prev: record.nullable() }).strict();
export type StackVaultPair = z.infer<typeof stackVaultPairSchema>;

export const stackVaultGetRequestSchema = z.object({ relay_id: id, app_id: appId }).strict();
export type StackVaultGetRequestDto = z.infer<typeof stackVaultGetRequestSchema>;

/** Version 0 with no pair when Gray holds none; a stored pair's version is at least 1. */
/**
 * P7 (13.4, the final mark): `final_from` is the bridge key of the draining instance whose final put Gray's pair carries
 * (absent when none): the retiring instance's last version, uploaded once nothing of its own is left to write.
 */
export const stackVaultGetAnswerSchema = z
  .object({ version: uintSchema, pair: stackVaultPairSchema.nullable(), final_from: z.string().regex(LANE_BRIDGE_KEY_ID_PATTERN).optional() })
  .strict()
  .refine((a) => (a.version === 0n) === (a.pair === null), { message: "version 0 is no pair, and a pair has a version", path: ["version"] });
export type StackVaultGetAnswerDto = z.infer<typeof stackVaultGetAnswerSchema>;

/** P7: `final: true` is a draining instance's final mark; the bridge names the calling key as its `final_from`. */
export const stackVaultPutRequestSchema = z.object({ relay_id: id, app_id: appId, base_version: uintSchema, pair: stackVaultPairSchema, final: z.literal(true).optional() }).strict();
export type StackVaultPutRequestDto = z.infer<typeof stackVaultPutRequestSchema>;

export const stackVaultPutAnswerSchema = z.object({ stored: z.boolean(), version: uintSchema }).strict();
export type StackVaultPutAnswerDto = z.infer<typeof stackVaultPutAnswerSchema>;

/** Gray's pair as the console answers it and the VM reads it: JS numbers. */
export interface StackVaultCopy {
  readonly version: number;
  readonly pair: StackVaultPair | null;
  /** P7: the draining key whose final mark Gray's pair carries; none when absent or null. */
  readonly finalFrom?: string | null;
}

/** A put's outcome as the console answers it and the VM reads it: whether it was stored, and Gray's pair version now. */
export interface StackVaultPutResult {
  readonly stored: boolean;
  readonly version: number;
}

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

function wireUint(value: number, field: string): bigint {
  if (!Number.isSafeInteger(value) || value < 0) throw new BridgeWireError("invalid_document", field, `${field}: ${value} is not a non-negative safe integer`);
  return BigInt(value);
}

/** The wire request of a get. */
export function stackVaultGetRequestDtoOf(relayId: string, appId: string): StackVaultGetRequestDto {
  return checked(stackVaultGetRequestSchema, { relay_id: relayId, app_id: appId });
}

/** The wire request of a put: the whole pair, built on Gray's pair version `baseVersion` (0: Gray held none). */
export function stackVaultPutRequestDtoOf(relayId: string, appId: string, baseVersion: number, pair: StackVaultPair, final = false): StackVaultPutRequestDto {
  return checked(stackVaultPutRequestSchema, { relay_id: relayId, app_id: appId, base_version: wireUint(baseVersion, "base_version"), pair, ...(final ? { final: true } : {}) });
}

/** The console's pair as the get's wire answer. */
export function stackVaultGetAnswerDtoOf(copy: StackVaultCopy): StackVaultGetAnswerDto {
  return checked(stackVaultGetAnswerSchema, { version: wireUint(copy.version, "version"), pair: copy.pair, ...((copy.finalFrom ?? null) === null ? {} : { final_from: copy.finalFrom }) });
}

/** The console's put outcome as the wire answer. */
export function stackVaultPutAnswerDtoOf(result: StackVaultPutResult): StackVaultPutAnswerDto {
  return checked(stackVaultPutAnswerSchema, { stored: result.stored, version: wireUint(result.version, "version") });
}

/** The get's wire answer with JS numbers (the schema bounds the version to a safe integer). */
export function stackVaultCopyOf(dto: StackVaultGetAnswerDto): StackVaultCopy {
  return { version: Number(dto.version), pair: dto.pair, finalFrom: dto.final_from ?? null };
}

/** The put's wire answer with JS numbers. */
export function stackVaultPutResultOf(dto: StackVaultPutAnswerDto): StackVaultPutResult {
  return { stored: dto.stored, version: Number(dto.version) };
}

// ---------------------------------------------------------------------------------------------
// stack.vault.share_nonce and stack.vault.share: Gray's share (decision H5)
// ---------------------------------------------------------------------------------------------

/**
 * `stack.vault.share_nonce` and `stack.vault.share` (docs/design/relay-no-always-on-host.md §3.1, H5 and 13.11): Gray's
 * 32-byte share of the relay's record keys (`S_gray`, `@gray/relay-connector/vault-share`), released only to a VM whose
 * TDX quote Gray verified, sealed to an X25519 key the VM made for the request.
 *
 * Freshness is a nonce Gray issued: `share_nonce` answers one for (relay, app), `issued_ms` (8 bytes, big-endian) ‖ 16
 * random bytes ‖ an HMAC-SHA256 tag over the relay, the app and the first 24 bytes under Gray's share secret, as lower hex
 * (STACK_VAULT_SHARE_NONCE_PATTERN). Gray stores nothing: it checks the tag and that the nonce is at most
 * STACK_VAULT_SHARE_NONCE_TTL_MS old. The quote's report data binds the nonce, so a quote is at most that old when Gray
 * answers it; a VM-chosen time could not show that. A nonce is not single-use: an answer sealed again within the window
 * goes to the same quote-bound key, which only that VM holds.
 *
 * `share` carries the quote (hex), the event log as the guest agent's `GetQuote` answers it (JSON text), the X25519
 * public key and the nonce. The bridge verifies the quote and replays the log; the console checks the nonce, the relay
 * and its app, and the compose hash on the relay's contract, and answers `sealed`: `enc ‖ ciphertext`, 80 bytes as lower
 * hex. Any check that fails is `vault_share_refused` (403), which the VM does not retry with the same quote.
 */

/** A Gray-issued share nonce: 56 bytes as lower hex (8 bytes of `issued_ms`, 16 random, a 32-byte tag). */
export const STACK_VAULT_SHARE_NONCE_PATTERN = /^[0-9a-f]{112}$/;
/** How long a share nonce is accepted after Gray issued it: a quote takes about a second; 5 minutes is slack for retries. */
export const STACK_VAULT_SHARE_NONCE_TTL_MS = 5 * 60_000;
/** The longest quote, in hex characters: 32 KiB of quote (a TDX v4 quote with its PCK chain is about 5 KiB). */
export const STACK_VAULT_SHARE_QUOTE_MAX_CHARS = 64 * 1024;
/** The longest event log, in characters (dstack's log of a stack boot is tens of KiB). */
export const STACK_VAULT_SHARE_EVENT_LOG_MAX_CHARS = 256 * 1024;
/** `stack.vault.share`'s request body bound: the quote, the event log as a JSON string (escapes at most double it), the rest. */
export const STACK_VAULT_SHARE_MAX_BYTES = STACK_VAULT_SHARE_QUOTE_MAX_CHARS + 2 * STACK_VAULT_SHARE_EVENT_LOG_MAX_CHARS + 4 * 1024;
/** The sealed share on the wire: 80 bytes as lower hex (`@gray/relay-connector/vault-share` VAULT_SHARE_SEALED_BYTES). */
export const STACK_VAULT_SHARE_SEALED_PATTERN = /^[0-9a-f]{160}$/;

const shareNonce = z.string().regex(STACK_VAULT_SHARE_NONCE_PATTERN);

export const stackVaultShareNonceRequestSchema = z.object({ relay_id: id, app_id: appId }).strict();
export type StackVaultShareNonceRequestDto = z.infer<typeof stackVaultShareNonceRequestSchema>;

export const stackVaultShareNonceAnswerSchema = z.object({ nonce: shareNonce }).strict();
export type StackVaultShareNonceAnswerDto = z.infer<typeof stackVaultShareNonceAnswerSchema>;

export const stackVaultShareRequestSchema = z
  .object({
    relay_id: id,
    app_id: appId,
    quote: z.string().min(2).max(STACK_VAULT_SHARE_QUOTE_MAX_CHARS).regex(/^(?:[0-9a-f]{2})+$/),
    event_log: z.string().min(2).max(STACK_VAULT_SHARE_EVENT_LOG_MAX_CHARS),
    ephemeral_public_key: z.string().regex(/^[0-9a-f]{64}$/),
    nonce: shareNonce,
  })
  .strict();
export type StackVaultShareRequestDto = z.infer<typeof stackVaultShareRequestSchema>;

export const stackVaultShareAnswerSchema = z.object({ sealed: z.string().regex(STACK_VAULT_SHARE_SEALED_PATTERN) }).strict();
export type StackVaultShareAnswerDto = z.infer<typeof stackVaultShareAnswerSchema>;

/** The wire request of a share nonce. */
export function stackVaultShareNonceRequestDtoOf(relayId: string, appId: string): StackVaultShareNonceRequestDto {
  return checked(stackVaultShareNonceRequestSchema, { relay_id: relayId, app_id: appId });
}

/** The wire request of a share: the quote as hex, the event log as the guest agent answered it. */
export function stackVaultShareRequestDtoOf(relayId: string, appId: string, quote: string, eventLog: string, ephemeralPublicKey: string, nonce: string): StackVaultShareRequestDto {
  return checked(stackVaultShareRequestSchema, { relay_id: relayId, app_id: appId, quote, event_log: eventLog, ephemeral_public_key: ephemeralPublicKey, nonce });
}

/** The console's nonce as the wire answer. */
export function stackVaultShareNonceAnswerDtoOf(nonce: string): StackVaultShareNonceAnswerDto {
  return checked(stackVaultShareNonceAnswerSchema, { nonce });
}

/** The console's sealed share as the wire answer. */
export function stackVaultShareAnswerDtoOf(sealed: string): StackVaultShareAnswerDto {
  return checked(stackVaultShareAnswerSchema, { sealed });
}
