import { bytesToLowerHex, ed25519Sign, ed25519Verify, isDigestField, jcsBytes, lowerHexBytes, receiptDocumentSchema } from "@gray/attest";
import { parseSerde, toJsonString, type Json } from "@gray/json";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { uintSchema } from "./ints.ts";
import { LANE_ROUTE_NAME_PATTERN, laneReportedUsageSchema } from "./records.ts";
import { decodeSchedulerBody, encodeSchedulerBody } from "./scheduler.ts";
import type { BridgeSigner } from "./signing.ts";
import { STACK_FAULT_WHYS } from "./stack-health.ts";
import { STACK_VIOLATION_REQUEST_ID_PATTERN } from "./stack-report.ts";
import { stackTraceSchema } from "./stack-trace.ts";

/**
 * The peer hop (docs/confidential-lane-stack-routing.md section 4.5): what an entry lane sends a relay's stack VM
 * through its egress, and what the stack VM's lane answers. Both ends are Gray's lane in workerd; egress carries the
 * bytes and reads none of these documents (it adds its own `x-gray-peer-sent` and `x-gray-peer-spki`, PR 3).
 *
 * - **The envelope** (`x-gray-peer: v1.<base64url>.<128 hex>`): the request's facts the stack VM checks before it
 *   registers anything at its egress, signed by the entry's per-boot receipt key. The base64url payload is exactly the
 *   envelope's JCS bytes (`@gray/attest` `jcsBytes`, RFC 8785), so one envelope has one spelling, and the signature is
 *   over a domain line and those bytes: `gray-lane-peer/v1\n` for an inference request, `gray-lane-peer-attempts/v1\n`
 *   for the late-facts follow-up (`GET /v1/peer/attempts/<rid>`), so neither can be presented as the other.
 * - **The frames** of the answer, `text/event-stream`: `head` once (`{status, stream, headers?}`), `data` (standard
 *   base64 of the next released bytes), `end` once and last (`{outcome, dialed, served_attempt, attempts,
 *   relay_account_id, usage, code, receipt, trace?, checks?, receipt_refused?, vendor_event?, relay_status?}`). Between
 *   them the stack VM writes `PEER_COMMENT`, which is not a frame. `checks`, `receipt_refused`, `vendor_event`,
 *   `relay_status` and `head.headers` (`error_headers`) go only to an entry that named them in `PEER_READS_HEADER`.
 * - **A refusal** of checks 1 to 6 (`peer_*`, `route_unconfigured`, `foreign_relay`): an HTTP 4xx whose body is
 *   `{code, dialed: false}`, before any frame; the status is `PEER_REFUSAL_STATUS`'s.
 * - **The attempts answer**: `{state, receipt, trace?}` from the stack VM's memory (`trace` once done, to an entry
 *   that named `attempts_trace`).
 *
 * The frame and answer documents follow the package's integer rule (ints.ts): integers are bigints, written by
 * `@gray/json`'s `toJsonString` and read by its serde reader. The envelope's integers are bigints too; JCS writes a
 * bigint as its digits.
 */

/** The request header that carries the signed envelope. */
export const PEER_HEADER = "x-gray-peer";
/**
 * Gray's public request id (`x-request-id`) beside the envelope, outside it (docs/design/relay-ejection.md section 3):
 * the stack VM names it when it reports a violation, so the relay and Gray find the request. The hop is TLS to the
 * attested VM; the value is shown, never used to decide, and a stack VM older than it ignores it.
 */
export const PEER_REQUEST_ID_HEADER = "x-gray-peer-request-id";

/** The request id `headers` carry in PEER_REQUEST_ID_HEADER, or null when there is none or it is not one (32 lower hex). */
export function peerRequestIdOf(headers: Headers): string | null {
  const value = headers.get(PEER_REQUEST_ID_HEADER);
  return value !== null && STACK_VIOLATION_REQUEST_ID_PATTERN.test(value) ? value : null;
}

/**
 * The `end` members an entry names beside the envelope, outside it, when it reads them (docs/error-rates.md, r14): a
 * comma-separated list of `PEER_END_READS`' words. `end` is strict on the entry, so a stack VM puts such a member in
 * only for an entry that named it: an older entry sends none and gets the `end` it reads. The envelope cannot say it,
 * since an older stack VM refuses a member its strict schema does not know (`peer_malformed`), while it ignores a
 * header, as it ignores PEER_REQUEST_ID_HEADER. The hop is TLS to the attested VM, and the value only chooses whether
 * two closed words are added to `end`: at worst an attempt is not counted.
 */
export const PEER_READS_HEADER = "x-gray-peer-reads";
/**
 * The optional `end` members an entry may name: `checks`, the attempt's two answer checks (r14), in the words of
 * `PEER_CHECKS_WORDS`. A read word names its member together with the member's words: `end` is strict on the entry, so
 * a word added to either check needs a new read word (`checks_v2`) that names the new lists, and to an entry that named
 * `checks` alone a stack VM sends a word outside `PEER_CHECKS_WORDS` as null.
 *
 * `receipt_refused`: why a dialed attempt's `end` has no receipt (the receipt grammar refused the one the stack VM wrote),
 * so the entry still gets the attempt's outcome, usage and trace. To an entry that did not name it, such an `end` cannot
 * be sent (a dialed attempt has its receipt), and the hop ends without one.
 *
 * `vendor_event`: the vendor's own error event that ended its stream before the stack VM's commit (an Anthropic `error`
 * after `message_start`), so the entry answers it as the main gateway answers an upstream's in-band error, and does not
 * count it against the relay.
 *
 * `attempts_trace`: named on the follow-up (`GET /v1/peer/attempts/<rid>`), the attempt's trace in the answer once it is
 * done, for an entry that let go of the hop before `end` came (its own limit, the client gone): the entry's row keeps the
 * relay's trace and its attempt.
 *
 * `error_headers`: allowlisted lower-case vendor error response headers (`PEER_ERROR_HEADERS`) carried on a non-200
 * `vendor_error` `head` frame (`head.headers`), so the entry drives rest classification and passes `Retry-After` /
 * `Content-Type` to the client. Sent only to an entry that named `error_headers` in `PEER_READS_HEADER`: an older
 * entry's strict `peerHeadSchema` refuses a `head` that carries `headers`.
 *
 * `relay_status`: the status the relay's container answered a token count with, when it answered an error before any
 * vendor call (`not_dialed`, `relay_error_status`), so the entry reads a container without a count path (404, 405 or
 * 501, docs/relay-integration-standard.en.md section 2) as a route without a counter, not as its failure.
 *
 * `gate_refused`: `end.code` `PEER_GATE_REFUSED` on a `relay_failed` end, when the stack VM's trust gate refused the
 * vendor's answer before anything of it was released, so the entry answers it as a local stack attempt's
 * (`upstream_trust_policy_rejected`) and does not count it as the relay's transport failure. An entry that did not name
 * it gets `relay_transport` there, as before: its strict `end` refuses a code it does not know.
 *
 * `gate_cut`: `end.code` `PEER_GATE_REFUSED` on a `cut` end, when the stack VM's trust gate refused the vendor's answer
 * after part of it was released (a streamed tool call whose frames came after the commit), so the entry ends the client's
 * stream with `upstream_trust_policy_rejected`, as a local stack attempt's, and not as the upstream's broken stream. A
 * word of its own: an entry that named `gate_refused` alone refuses that code on a `cut` end, and gets `entry_internal`
 * there, as before.
 */
export const PEER_END_READS = ["checks", "receipt_refused", "vendor_event", "attempts_trace", "error_headers", "relay_status", "gate_refused", "gate_cut"] as const;
export type PeerEndRead = (typeof PEER_END_READS)[number];

/**
 * The words the `checks` read names, frozen with it: r14's `ToolCallCheck` and `OutputCheck` (@gray/protocol
 * answer-checks.ts). `end.checks` is read in these, whatever the gateway's lists hold later (test/peer.test.ts fails
 * when they change, so the change comes with its read word).
 */
export const PEER_CHECKS_WORDS = Object.freeze({
  tool_call_check: Object.freeze(["none", "ok", "invalid_json", "schema_mismatch", "undeclared", "missing_name", "refused", "truncated"] as const),
  output_check: Object.freeze(["not_requested", "ok", "invalid_json", "schema_mismatch_strict", "schema_mismatch_loose", "excluded", "unknown"] as const),
});

/** The longest PEER_READS_HEADER value read: every word of a few generations, with room. */
const PEER_READS_MAX_LENGTH = 256;

/** The words of PEER_END_READS that `headers` name in PEER_READS_HEADER; none without it, past its bound, or for an unknown word. */
export function peerReadsOf(headers: Headers): ReadonlySet<PeerEndRead> {
  const value = headers.get(PEER_READS_HEADER);
  const out = new Set<PeerEndRead>();
  if (value === null || value.length > PEER_READS_MAX_LENGTH) return out;
  for (const word of value.split(",")) {
    const read = word.trim();
    if ((PEER_END_READS as readonly string[]).includes(read)) out.add(read as PeerEndRead);
  }
  return out;
}

/** The envelope header's version, its first dot-separated part. */
export const PEER_HEADER_VERSION = "v1";

/** The signature's domain line per use: an inference request, or the late-facts follow-up. */
export const PEER_DOMAINS = Object.freeze({ request: "gray-lane-peer/v1\n", attempts: "gray-lane-peer-attempts/v1\n" } as const);
export type PeerEnvelopeUse = keyof typeof PEER_DOMAINS;

/** Section 4.5 check 3: `issued_ms` within this of the stack VM's clock, either side. */
export const PEER_ISSUED_SKEW_MS = 120_000;

/**
 * The longest `budget_ms` an envelope may name: STREAM_TOTAL_SECONDS' maximum (`@gray/config`, 3600 s), the most a
 * request can run on the entry.
 */
export const PEER_BUDGET_MAX_MS = 3_600_000n;

/** The largest attempt number (`n`) and attempt count: the trace's attempt bound (stack-trace.ts), an i32. */
export const PEER_ATTEMPT_MAX = 2_147_483_647n;

/** The protocols a stack route speaks (the lane's `stackPlan`): the client paths `/v1/messages`, `/v1/chat/completions`, `/v1/responses`. */
export const PEER_PROTOCOLS = ["anthropic_messages", "open_ai_chat", "open_ai_responses"] as const;
export type PeerProtocol = (typeof PEER_PROTOCOLS)[number];

const hex32 = z.string().regex(/^[0-9a-f]{32}$/);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
/** A keyset digest as the keyset headers carry it (`x-aci-keyset-digest`): `sha256:<64 lower hex>`. */
const keysetDigest = z.string().refine((value) => isDigestField(value), { message: "a keyset digest is sha256:<64 lower-case hex>" });
/** An endpoint id or a model name: 1 to 256 printable ASCII characters without space (records.ts `LANE_ROUTE_NAME_PATTERN`). */
const name = z.string().regex(LANE_ROUTE_NAME_PATTERN);

/** The envelope (section 4.5): no workspace, key or customer identity. */
export const peerEnvelopeSchema = z
  .object({
    /** The stack VM's keyset digest: the peer the entry attested and pinned. */
    aud: keysetDigest,
    /** The entry's keyset digest: names the receipt key the stack VM verified at hello. */
    entry: keysetDigest,
    /** The entry's request id. */
    rid: hex32,
    /** The entry's attempt number within the request, from 1. */
    n: uintSchema.min(1n).max(PEER_ATTEMPT_MAX),
    /** The entry's outer receipt id (`rcpt_<32 hex>`), or null when the request makes none. */
    receipt_id: z.string().regex(/^rcpt_[0-9a-f]{32}$/).nullable(),
    route: z.object({ endpoint: name, protocol: z.enum(PEER_PROTOCOLS), model: name }).strict(),
    /** SHA-256 of the request body as sent (the client's exact bytes; the empty body's for the follow-up). */
    received_sha256: hex64,
    issued_ms: uintSchema,
    budget_ms: uintSchema.min(1n).max(PEER_BUDGET_MAX_MS),
    nonce: hex32,
    /**
     * The request's conversation id at the route's relay (relay standard v1.7 `X-Gray-Conversation`), derived by the
     * entry under its own per-boot key; absent exactly when the client named no session.
     */
    conversation: hex32.optional(),
    /**
     * The customer chose relays that change nothing (routing preference `relay_changes: "exclude"`,
     * docs/relay-request-changes.md): the stack VM registers the request without `relay_changes`, so egress refuses any
     * change of the relay's own. Absent otherwise. It names a preference, not a customer.
     */
    relay_changes: z.literal("exclude").optional(),
    /**
     * True for an Anthropic token-counting request (`POST /v1/messages/count_tokens`); absent on generation calls so
     * existing generation envelopes remain wire-compatible and older stack VMs reject unknown count_tokens hops with
     * `peer_malformed`.
     */
    count_tokens: z.literal(true).optional(),
  })
  .strict();
export type PeerEnvelopeDto = z.infer<typeof peerEnvelopeSchema>;

/**
 * The longest `x-gray-peer` value read: twice the largest envelope's (two 256-character names of escaped characters,
 * every other member at its longest; `test/peer.test.ts` builds it), so a header never costs the stack VM more than a
 * few KiB before its signature is checked.
 */
export const PEER_HEADER_MAX_LENGTH = 6144;

/** One read envelope: the document, its JCS bytes as they travelled, and the 64-byte signature. */
export interface ReadPeerEnvelope {
  readonly envelope: PeerEnvelopeDto;
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
}

/** What `checkPeerEnvelope` refuses with: section 4.5's check 1 and the header that is not an envelope. */
export type PeerEnvelopeRefusal = "peer_malformed" | "peer_unknown";

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The bytes the signature covers: the use's domain line, then the envelope's JCS bytes. */
export function peerSigningInput(use: PeerEnvelopeUse, payload: Uint8Array): Uint8Array {
  const domain = ENCODER.encode(PEER_DOMAINS[use]);
  const out = new Uint8Array(domain.length + payload.length);
  out.set(domain, 0);
  out.set(payload, domain.length);
  return out;
}

/** The envelope's JCS bytes; the document is checked first, so a value that is not an envelope throws. */
export function peerEnvelopeBytes(envelope: PeerEnvelopeDto): Uint8Array {
  const parsed = peerEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") || null, "the peer envelope is not its wire shape");
  return jcsBytes(parsed.data as unknown as Json);
}

/** Unpadded base64url (RFC 4648 section 5) of `bytes`. */
export function base64Url(bytes: Uint8Array): string {
  return encodeSchedulerBody(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The bytes of canonical unpadded base64url, or null for any other spelling (padding, the standard alphabet, a non-zero tail). */
export function base64UrlBytes(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const standard = text.replaceAll("-", "+").replaceAll("_", "/");
  return decodeSchedulerBody(standard + "=".repeat((4 - (standard.length % 4)) % 4));
}

/** The `x-gray-peer` value of `envelope` for `use`, signed by the entry's receipt key. */
export async function signPeerEnvelope(use: PeerEnvelopeUse, envelope: PeerEnvelopeDto, signer: BridgeSigner): Promise<string> {
  const payload = peerEnvelopeBytes(envelope);
  const message = peerSigningInput(use, payload);
  const signature = signer instanceof Uint8Array ? await ed25519Sign(signer, message) : typeof signer === "function" ? await signer(message) : await signer.sign(message);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new BridgeWireError("bad_signature", null, "the signer did not return a 64-byte Ed25519 signature");
  return `${PEER_HEADER_VERSION}.${base64Url(payload)}.${bytesToLowerHex(signature)}`;
}

/**
 * Read an `x-gray-peer` value without verifying it: the version, canonical base64url, strict UTF-8, serde JSON, the
 * envelope's schema, and payload bytes that are exactly the envelope's JCS form. Null for anything else (`peer_malformed`).
 */
export function readPeerEnvelope(header: string | null): ReadPeerEnvelope | null {
  if (header === null || header.length > PEER_HEADER_MAX_LENGTH) return null;
  const parts = header.split(".");
  if (parts.length !== 3 || parts[0] !== PEER_HEADER_VERSION || !/^[0-9a-f]{128}$/.test(parts[2]!)) return null;
  const payload = base64UrlBytes(parts[1]!);
  if (payload === null || payload.length === 0) return null;
  let value: Json;
  try {
    value = parseSerde(DECODER.decode(payload));
  } catch {
    return null;
  }
  const parsed = peerEnvelopeSchema.safeParse(value);
  if (!parsed.success) return null;
  const canonical = jcsBytes(parsed.data as unknown as Json);
  if (canonical.length !== payload.length || canonical.some((byte, index) => byte !== payload[index])) return null;
  return { envelope: parsed.data, payload, signature: lowerHexBytes(parts[2]!)! };
}

/**
 * Section 4.5 check 1: the header is an envelope (`peer_malformed` otherwise), and its signature verifies under the
 * receipt key the stack VM recorded for the envelope's `entry` at hello (`peer_unknown` for an entry it has not
 * verified, or another signature). `keyFor` answers that key, or null.
 */
export async function checkPeerEnvelope(
  header: string | null,
  use: PeerEnvelopeUse,
  keyFor: (entry: string) => Uint8Array | null,
): Promise<{ readonly ok: true; readonly envelope: PeerEnvelopeDto } | { readonly ok: false; readonly code: PeerEnvelopeRefusal }> {
  const read = readPeerEnvelope(header);
  if (read === null) return { ok: false, code: "peer_malformed" };
  const key = keyFor(read.envelope.entry);
  if (key === null || key.length !== 32) return { ok: false, code: "peer_unknown" };
  const verified = await ed25519Verify(key, peerSigningInput(use, read.payload), read.signature);
  return verified ? { ok: true, envelope: read.envelope } : { ok: false, code: "peer_unknown" };
}

// ------------------------------------------------------------------------------------------------- refusals

/**
 * The stack VM's refusals before any frame (section 4.5 checks 1 to 6, and the header that is not an envelope), each
 * with its status. None registers anything at egress, so every one is `dialed: false`.
 */
export const PEER_REFUSAL_STATUS = Object.freeze({
  /** The `x-gray-peer` header is missing or not an envelope, or the follow-up's path names another rid. */
  peer_malformed: 400,
  /** Check 1: no entry the stack VM verified signed it (or it rebooted and lost its table): hello again. */
  peer_unknown: 401,
  /** Check 2: `aud` is another keyset's digest. */
  peer_audience: 403,
  /** Checks 3 and 4: `issued_ms` outside the window, a nonce seen, or `(entry, rid, n)` seen. */
  peer_replayed: 409,
  /** Check 5: the body's SHA-256 is not `received_sha256`. */
  peer_body_mismatch: 400,
  /** Check 6: the stack configuration has no such route of its relay. */
  route_unconfigured: 404,
  /** Check 6: the route is another relay's. */
  foreign_relay: 403,
} as const);
export type PeerRefusalCode = keyof typeof PEER_REFUSAL_STATUS;
export const PEER_REFUSAL_CODES = Object.keys(PEER_REFUSAL_STATUS) as [PeerRefusalCode, ...PeerRefusalCode[]];

export const peerRefusalSchema = z.object({ code: z.enum(PEER_REFUSAL_CODES), dialed: z.literal(false) }).strict();
export type PeerRefusalDto = z.infer<typeof peerRefusalSchema>;

// ------------------------------------------------------------------------------------------------- frames

/** The three frame events, in the order a hop answer carries them (`data` any number of times). */
export const PEER_FRAME_EVENTS = ["head", "data", "end"] as const;
export type PeerFrameEvent = (typeof PEER_FRAME_EVENTS)[number];

/** The stack VM's hop comment while nothing else is due (section 4.5): the lane's own keep-alive comment bytes. */
export const PEER_COMMENT: Uint8Array = ENCODER.encode(": keep-alive\n\n");

/**
 * The most bytes one `data` frame carries, and the longest `head` or `end` JSON: `@gray/protocol`'s
 * SSE_BUFFER_KEEP_BYTES (64 KiB), so no hop frame grows the entry's frame buffer past what it keeps. A released event
 * larger than that goes in several `data` frames; the entry passes the bytes on as they come. An `end` with an S26
 * receipt of the largest attempt count is a few KiB.
 */
export const PEER_FRAME_MAX_BYTES = 64 * 1024;

/** The lower-case vendor error response headers that may cross the peer hop on a non-200 `head` frame. */
export const PEER_ERROR_HEADERS = ["retry-after", "retry-after-ms", "x-should-retry", "content-type"] as const;
export type PeerErrorHeader = (typeof PEER_ERROR_HEADERS)[number];

/** The longest value of one allowlisted vendor error header carried on a `head` frame. */
export const PEER_ERROR_HEADER_MAX_LENGTH = 256;

/** Header value characters: visible ASCII and HTAB, bounded length, never CR, LF, NUL, or other controls. */
const PEER_ERROR_HEADER_VALUE = /^[\t\x20-\x7e]{1,256}$/;

export const peerErrorHeadersSchema = z
  .object({
    "retry-after": z.string().regex(PEER_ERROR_HEADER_VALUE).optional(),
    "retry-after-ms": z.string().regex(PEER_ERROR_HEADER_VALUE).optional(),
    "x-should-retry": z.string().regex(PEER_ERROR_HEADER_VALUE).optional(),
    "content-type": z.string().regex(PEER_ERROR_HEADER_VALUE).optional(),
  })
  .strict();
export type PeerErrorHeadersDto = z.infer<typeof peerErrorHeadersSchema>;

/**
 * Picks the allowlisted lower-case vendor error headers from `headers`, strips CR/LF and outer whitespace,
 * drops values outside `PEER_ERROR_HEADER_VALUE` (empty, controls, non-ASCII, or past 256 bytes), and returns
 * them in `PEER_ERROR_HEADERS` order, or undefined when none remain.
 */
export function peerErrorHeadersOf(headers: Readonly<Record<string, string>>): PeerErrorHeadersDto | undefined {
  const lowered = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) lowered.set(name.toLowerCase(), value);
  const out: Partial<Record<PeerErrorHeader, string>> = {};
  let count = 0;
  for (const name of PEER_ERROR_HEADERS) {
    const raw = lowered.get(name);
    if (raw === undefined) continue;
    const cleaned = raw.replace(/[\r\n]+/g, "").trim();
    if (!PEER_ERROR_HEADER_VALUE.test(cleaned)) continue;
    out[name] = cleaned;
    count += 1;
  }
  return count === 0 ? undefined : out;
}

export const peerHeadSchema = z
  .object({
    status: uintSchema.min(200n).max(599n),
    stream: z.boolean(),
    /**
     * Allowlisted vendor error headers (`PEER_ERROR_HEADERS`), carried only on a non-streaming error `head`
     * (status >= 400, stream false) to an entry that named `error_headers` in `PEER_READS_HEADER`.
     */
    headers: peerErrorHeadersSchema.optional(),
  })
  .strict()
  .superRefine((head, ctx) => {
    if (head.headers === undefined) return;
    if (head.status < 400n || head.stream) {
      ctx.addIssue({ code: "custom", path: ["headers"], message: "headers are carried only on a non-streaming error head" });
    } else if (Object.keys(head.headers).length === 0) {
      ctx.addIssue({ code: "custom", path: ["headers"], message: "headers must not be empty" });
    }
  });
export type PeerHeadDto = z.infer<typeof peerHeadSchema>;

/**
 * How the attempt ended (section 4.7's rows):
 * - `served`: the answer was released whole;
 * - `vendor_error`: the vendor's own error answer was released (S24 `error_body`);
 * - `relay_failed`: a vendor was dialed and nothing can be released (`lane_relay_failed`, or `upstream_trust_policy_rejected` for `PEER_GATE_REFUSED`; no other route);
 * - `cut`: bytes were released, then the answer could not go on (Gray's error frame on the entry, `upstream_trust_policy_rejected` for `PEER_GATE_REFUSED`);
 * - `not_dialed`: no vendor attempt was dialed (S25): the entry may try another route.
 */
export const PEER_END_OUTCOMES = ["served", "vendor_error", "relay_failed", "cut", "not_dialed"] as const;
export type PeerEndOutcome = (typeof PEER_END_OUTCOMES)[number];

/** Why an attempt was not made: the lane's `stackPlan` codes a backend can still meet after its envelope checks. */
export const PEER_PLAN_CODES = ["config_unready", "no_relay_binding", "body_not_held", "upstream_not_official", "protocol", "stream_options_unusable", "body_over_stack_limit", "stack_rewrite_refused"] as const;
/**
 * The stack VM's trust gate refused the vendor's answer: before its commit (`relay_failed`: a vendor was dialed, nothing
 * was released; sent only to an entry that named `gate_refused`), or after it (`cut`: sent only to an entry that named
 * `gate_cut`). Not a fault of the relay's container or of egress, so not one of `STACK_FAULT_WHYS`, which the trace,
 * egress and the console's health lists read as one.
 */
export const PEER_GATE_REFUSED = "upstream_trust_policy_rejected";
/** `end.code`: a plan code, the closed word of what failed (`STACK_FAULT_WHYS`, the trace's), or `PEER_GATE_REFUSED`. */
export const PEER_END_CODES = [...PEER_PLAN_CODES, ...STACK_FAULT_WHYS, PEER_GATE_REFUSED] as const;

/** An S26 receipt document, as the stack VM serves it (`@gray/attest` `receiptDocumentSchema`; the value is kept as sent). */
const receiptValue = z.record(z.string(), z.unknown()).refine((value) => receiptDocumentSchema.safeParse(value).success, { message: "not an ACI receipt document" });

export const peerEndSchema = z
  .object({
    outcome: z.enum(PEER_END_OUTCOMES),
    /** S25, from the stack VM's egress feed: a vendor attempt was dialed for this request. */
    dialed: z.boolean(),
    /** The relay's attempt (egress `n`) whose answer was released, or null. */
    served_attempt: uintSchema.min(1n).max(PEER_ATTEMPT_MAX).nullable(),
    /** The vendor attempts dialed. */
    attempts: uintSchema.max(PEER_ATTEMPT_MAX),
    /** The relay account of the last attempt dialed (S27), or null. */
    relay_account_id: z.string().regex(/^[\x21-\x7e]{1,128}$/).nullable(),
    /** What the vendor reported, as `safe_usage_counters` keeps it (records.ts), or null when no answer reported any. */
    usage: laneReportedUsageSchema.nullable(),
    /** Null when the answer was the vendor's (served, vendor_error); otherwise why. */
    code: z.enum(PEER_END_CODES).nullable(),
    /** The stack VM's signed S26 receipt for this attempt (the inner receipt, section 4.8), or null when it made none. */
    receipt: receiptValue.nullable(),
    /**
     * The attempt's S43 trace (stack-trace.ts): its one call to the relay's container, offsets from the call's start,
     * absent when it made none (a plan code before egress) or from a stack VM that predates it. The entry writes it in its
     * index row, as a stack VM serving a client directly writes its own (section 4.10).
     */
    trace: stackTraceSchema.optional(),
    /**
     * The attempt's two answer checks (docs/error-rates.md, r14), which the stack VM computes with the gate code the entry
     * runs, so the entry records them for the attempt (it never sees the bytes of an answer the stack VM refused): null
     * where the attempt is not counted. Absent from a stack VM before it, and sent only to an entry that named it in
     * PEER_READS_HEADER: an entry before it refuses an `end` that carries it. In the words `checks` names
     * (`PEER_CHECKS_WORDS`), r14's, never a later word.
     */
    checks: z.object({ tool_call_check: z.enum(PEER_CHECKS_WORDS.tool_call_check).nullable(), output_check: z.enum(PEER_CHECKS_WORDS.output_check).nullable() }).strict().optional(),
    /**
     * Why a dialed attempt has no receipt: the receipt grammar's problem (`@gray/attest` `EventLogProblem`, e.g.
     * `served_digest_mismatch`) or `receipt_failed`, a closed lower-case word, never content. Present exactly when a
     * dialed attempt's `receipt` is null, and sent only to an entry that named it in PEER_READS_HEADER: an entry before it
     * refuses an `end` that carries it, and one without a receipt.
     */
    receipt_refused: z
      .string()
      .regex(/^[a-z][a-z_]{0,63}$/)
      .optional(),
    /**
     * The vendor's own error event that ended its stream before the stack VM's commit (`relay_failed`: nothing of it was
     * released), as the vendor sent it: the entry classifies it as the main gateway classifies an upstream's in-band error.
     * Sent only to an entry that named `vendor_event` in PEER_READS_HEADER.
     */
    vendor_event: z.record(z.string(), z.unknown()).optional(),
    /**
     * The status the relay's container answered a token count with, an error before any vendor call (`not_dialed`,
     * `relay_error_status`). Sent only to an entry that named `relay_status` in PEER_READS_HEADER.
     */
    relay_status: uintSchema.min(100n).max(599n).optional(),
  })
  .strict()
  .superRefine((end, ctx) => {
    const issue = (path: string, message: string) => ctx.addIssue({ code: "custom", path: [path], message });
    const dialed = end.outcome !== "not_dialed";
    if (end.dialed !== dialed) issue("dialed", "dialed is false exactly when the outcome is not_dialed");
    const answered = end.outcome === "served" || end.outcome === "vendor_error" || end.outcome === "cut";
    if ((end.served_attempt !== null) !== answered) issue("served_attempt", "an attempt served exactly when bytes of it were released");
    if (end.served_attempt !== null && end.served_attempt > end.attempts) issue("served_attempt", "the served attempt is one of the attempts dialed");
    if (!dialed && (end.attempts !== 0n || end.relay_account_id !== null || end.usage !== null)) issue("attempts", "an attempt not dialed has no attempts, account or usage");
    if ((end.code === null) !== (end.outcome === "served" || end.outcome === "vendor_error")) issue("code", "a code names why exactly when the answer is not the vendor's");
    if (dialed && end.receipt === null && end.receipt_refused === undefined) issue("receipt", "a dialed attempt has its receipt, or says why not (receipt_refused)");
    if (end.receipt_refused !== undefined && (!dialed || end.receipt !== null)) issue("receipt_refused", "receipt_refused names why a dialed attempt has no receipt");
    if (end.vendor_event !== undefined && end.outcome !== "relay_failed") issue("vendor_event", "vendor_event names the vendor's error that ended an answer nothing of which was released");
    if (end.relay_status !== undefined && (end.outcome !== "not_dialed" || end.code !== "relay_error_status")) issue("relay_status", "relay_status names the container's error before any vendor call");
    if (end.code === PEER_GATE_REFUSED && end.outcome !== "relay_failed" && end.outcome !== "cut") issue("code", "a gate refusal is of a dialed answer");
  });
export type PeerEndDto = z.infer<typeof peerEndSchema>;

/** One frame as the entry reads it. */
export type PeerFrame =
  | { readonly event: "head"; readonly head: PeerHeadDto }
  | { readonly event: "data"; readonly bytes: Uint8Array }
  | { readonly event: "end"; readonly end: PeerEndDto };

function checkedDocument<T>(schema: z.ZodType<T>, value: unknown, what: string): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue === undefined ? null : issue.path.map(String).join(".") || null;
    throw new BridgeWireError("invalid_document", field, `the ${what} is not its wire shape: ${field ?? "(root)"}: ${issue?.message ?? "invalid"}`);
  }
  return parsed.data;
}

/** One frame's SSE bytes (`event: <name>\ndata: <text>\n\n`); a document is checked, and a frame over the bound throws. */
export function encodePeerFrame(frame: PeerFrame): Uint8Array {
  let data: string;
  if (frame.event === "data") {
    if (frame.bytes.length === 0 || frame.bytes.length > PEER_FRAME_MAX_BYTES) throw new BridgeWireError("body_too_large", "data", `a data frame carries 1 to ${PEER_FRAME_MAX_BYTES} bytes`);
    data = encodeSchedulerBody(frame.bytes);
  } else {
    const value = frame.event === "head" ? checkedDocument(peerHeadSchema, frame.head, "head frame") : checkedDocument(peerEndSchema, frame.end, "end frame");
    data = toJsonString(value as unknown as Json);
    if (ENCODER.encode(data).length > PEER_FRAME_MAX_BYTES) throw new BridgeWireError("body_too_large", frame.event, `a ${frame.event} frame is over ${PEER_FRAME_MAX_BYTES} bytes`);
  }
  return ENCODER.encode(`event: ${frame.event}\ndata: ${data}\n\n`);
}

/**
 * One frame from its SSE event (`@gray/protocol`'s decoder hands the event name and the data): the name is one of the
 * three, a `data` frame is canonical standard base64 of 1 to `PEER_FRAME_MAX_BYTES` bytes, `head` and `end` their
 * strict documents. Anything else throws `BridgeWireError`.
 */
export function parsePeerFrame(event: string | null, data: string): PeerFrame {
  if (event === "data") {
    const bytes = data.length > Math.ceil(PEER_FRAME_MAX_BYTES / 3) * 4 ? null : decodeSchedulerBody(data);
    if (bytes === null || bytes.length === 0 || bytes.length > PEER_FRAME_MAX_BYTES) throw new BridgeWireError("invalid_document", "data", `a data frame is canonical standard base64 of 1 to ${PEER_FRAME_MAX_BYTES} bytes`);
    return { event, bytes };
  }
  if (event !== "head" && event !== "end") throw new BridgeWireError("invalid_document", "event", "a hop frame is head, data or end");
  if (ENCODER.encode(data).length > PEER_FRAME_MAX_BYTES) throw new BridgeWireError("body_too_large", event, `a ${event} frame is over ${PEER_FRAME_MAX_BYTES} bytes`);
  let value: Json;
  try {
    value = parseSerde(data);
  } catch {
    throw new BridgeWireError("invalid_document", event, `the ${event} frame is not JSON`);
  }
  return event === "head" ? { event, head: checkedDocument(peerHeadSchema, value, "head frame") } : { event, end: checkedDocument(peerEndSchema, value, "end frame") };
}

// ------------------------------------------------------------------------------------------------- the attempts answer

/** `GET /v1/peer/attempts/<rid>`'s states: the stack VM never saw it, registered its rid, dialed a vendor, or ended it. */
export const PEER_ATTEMPT_STATES = ["unknown", "registered", "dialed", "done"] as const;
export type PeerAttemptState = (typeof PEER_ATTEMPT_STATES)[number];

export const peerAttemptsAnswerSchema = z
  .object({
    state: z.enum(PEER_ATTEMPT_STATES),
    receipt: receiptValue.nullable(),
    /** The attempt's S43 trace once it is done, to an entry that named `attempts_trace` in PEER_READS_HEADER. */
    trace: stackTraceSchema.optional(),
  })
  .strict()
  .refine((answer) => answer.receipt === null || answer.state === "done", { message: "only an attempt that is done has its receipt", path: ["receipt"] })
  .refine((answer) => answer.trace === undefined || answer.state === "done", { message: "only an attempt that is done has its trace", path: ["trace"] });
export type PeerAttemptsAnswerDto = z.infer<typeof peerAttemptsAnswerSchema>;

/** The answer's body: `@gray/json` text of the checked document. */
export function encodePeerAttemptsAnswer(answer: PeerAttemptsAnswerDto): Uint8Array {
  return ENCODER.encode(toJsonString(checkedDocument(peerAttemptsAnswerSchema, answer, "attempts answer") as unknown as Json));
}

/** Read an answer: bounded, strict UTF-8, serde JSON, the strict document. Throws `BridgeWireError`. */
export function parsePeerAttemptsAnswer(body: Uint8Array): PeerAttemptsAnswerDto {
  if (body.length > PEER_FRAME_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the attempts answer is over ${PEER_FRAME_MAX_BYTES} bytes`);
  let value: Json;
  try {
    value = parseSerde(DECODER.decode(body));
  } catch {
    throw new BridgeWireError("invalid_document", null, "the attempts answer is not JSON");
  }
  return checkedDocument(peerAttemptsAnswerSchema, value, "attempts answer");
}

/** A refusal's body. */
export function encodePeerRefusal(code: PeerRefusalCode): Uint8Array {
  return ENCODER.encode(toJsonString({ code, dialed: false }));
}

/** Read a refusal's body. Throws `BridgeWireError`. */
export function parsePeerRefusal(body: Uint8Array): PeerRefusalDto {
  if (body.length > 1024) throw new BridgeWireError("body_too_large", null, "a peer refusal is over 1024 bytes");
  let value: Json;
  try {
    value = parseSerde(DECODER.decode(body));
  } catch {
    throw new BridgeWireError("invalid_document", null, "the peer refusal is not JSON");
  }
  return checkedDocument(peerRefusalSchema, value, "peer refusal");
}
