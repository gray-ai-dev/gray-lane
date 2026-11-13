import { get, isObject, setMember, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { jcsBytes } from "./canonical.ts";
import { bytesToLowerHex, isDigestField, isLowerHexOf, sha256BareHex, sha256Digest, utf8Bytes } from "./digest.ts";
import { isU64, u64Schema } from "./integers.ts";
import { stackEventsChainStart } from "./stack-hash.ts";

/**
 * The receipt event vocabulary (ACI spec §7.3–§7.5) plus Gray's three implementation-specific
 * events: `relay_policy.applied`, `relay_policy.refused` and `request.modified`.
 *
 * Events are flat objects: `type` plus type-specific fields, in the array order (§7.3). Services MAY
 * add events with implementation-specific types and verifiers ignore types they do not recognize
 * (§7.4, Appendix B) — that is the extension point `relay_policy.applied` and `relay_policy.refused`
 * use. They never reuse a required type, and the signature covers the whole document, so a verifier
 * that knows nothing about them still verifies the receipt.
 *
 * Where the extension events sit: after `request.received`, before `request.forwarded` when the
 * request was forwarded (Gray's own rewrites run first, then the relay policy's appends), and before
 * `response.returned`. A `relay_policy.refused` receipt has no `request.forwarded` at all, and no
 * `request.modified` event either (nothing was forwarded to declare).
 * [`checkEventLog`] enforces exactly that and is what both the builder's `finalize` and the receipt
 * verifier run.
 *
 * A relay-stack receipt (plan S26, "receipt v2") records each upstream call the relay's container
 * made as one attempt group: `attempt.started`, the attempt's `request.modified` ops, its
 * `relay_stack.appended` (when the relay appended), its `relay_stack.changed` (when the relay changed the
 * request itself: the changed paths and headers, docs/relay-request-changes.md), `request.forwarded` with the call's method, path,
 * query digest and its body's JCS digest, then `upstream.response`; or `attempt.started` then `attempt.refused`.
 * No event names or fingerprints the relay's account or proxy ([`STACK_RELAY_IDENTITY_MEMBERS`]).
 * `response.returned` gains the client-side digests. When the entry's record of the relay's calls stopped
 * before egress's `done`, an attempt it left open ends `unrecorded` and `relay_stack.feed_incomplete`
 * stands before `response.returned`. The two required events keep their ACI shape
 * (`body_hash`) and gain members, so a verifier that knows none of this still reads them. A receipt is
 * a stack receipt when it carries any of these events or members ([`isStackEventLog`]), and then
 * [`checkEventLog`] holds it to the attempt grammar instead of the single-forward rules above.
 */

/** §7.4 required event types — reserved, never extension types. */
export const EVENT_REQUEST_RECEIVED = "request.received";
export const EVENT_REQUEST_FORWARDED = "request.forwarded";
export const EVENT_UPSTREAM_VERIFIED = "upstream.verified";
export const EVENT_RESPONSE_RETURNED = "response.returned";

/** Gray's relay-policy extension events (implementation-specific types, §7.4). */
export const EVENT_RELAY_POLICY_APPLIED = "relay_policy.applied";
export const EVENT_RELAY_POLICY_REFUSED = "relay_policy.refused";

/**
 * Gray's declared-rewrite extension event: one `request.modified` per byte-level op Gray applied to
 * the customer's request before the relay's appends. It is an implementation-specific type
 * (§7.4), never one of the four reserved ones, and it sits after `request.received` and before
 * `relay_policy.applied` and `request.forwarded`.
 */
export const EVENT_REQUEST_MODIFIED = "request.modified";

/** The closed op vocabulary of `request.modified` (one event per op, in application order). */
export const REQUEST_MODIFIED_OPS = Object.freeze(["set_member", "insert_member", "remove_member"] as const);

export type RequestModifiedOp = (typeof REQUEST_MODIFIED_OPS)[number];

/** The four types no extension may use (§7.4: `MUST NOT reuse the required types`). */
export const REQUIRED_EVENT_TYPES: readonly string[] = Object.freeze([
  EVENT_REQUEST_RECEIVED,
  EVENT_REQUEST_FORWARDED,
  EVENT_UPSTREAM_VERIFIED,
  EVENT_RESPONSE_RETURNED,
]);

/**
 * Where an appended template text goes, per protocol (shared wire shape with the policy host):
 * `system_start` / `system_end` in Anthropic Messages, `instructions_before` / `instructions_after`
 * in OpenAI Chat Completions and Responses.
 */
export const RELAY_APPEND_POSITIONS = Object.freeze([
  "system_start",
  "system_end",
  "instructions_before",
  "instructions_after",
] as const);

export type RelayAppendPosition = (typeof RELAY_APPEND_POSITIONS)[number];

/** One appended template text: which registered template, where, and the digest of its bytes. */
export interface RelayAppend {
  readonly template_id: string;
  readonly position: RelayAppendPosition;
  /** SHA-256 of the template text's UTF-8 bytes, bare lowercase hex. */
  readonly text_sha256: string;
}

/** The `relay_policy.applied` event: the module allowed the request and added these texts. */
export interface RelayPolicyAppliedEvent {
  readonly type: typeof EVENT_RELAY_POLICY_APPLIED;
  /** SHA-256 of the module that ran, bare lowercase hex. */
  readonly module_sha256: string;
  /** Relay-declared, monotone policy version. */
  readonly policy_version: bigint;
  readonly appended: readonly RelayAppend[];
}

/** The `relay_policy.refused` event: the module blocked the request; no text is recorded. */
export interface RelayPolicyRefusedEvent {
  readonly type: typeof EVENT_RELAY_POLICY_REFUSED;
  readonly module_sha256: string;
  readonly policy_version: bigint;
  /** The closed host-side reason code (§7.5-style fixed vocabulary; e.g. `blocked`). */
  readonly reason_code: string;
}

/** The reason code the shared wire shape names for a policy block. */
export const RELAY_REFUSAL_BLOCKED = "blocked";

/**
 * The one refusal-code vocabulary of a `relay_policy.refused` event, shared by every package that
 * builds or checks one:
 *
 * - `blocked` and `append_limit` are the module's own block reasons (`@gray/lane`'s closed
 *   `PolicyReasonCode`);
 * - `policy_unavailable` is the host's fixed answer when the module could not run at all
 *   (`@gray/relay-policy`'s `POLICY_UNAVAILABLE`), and it travels in the same receipt field.
 *
 * `@gray/lane` imports this list for its builder, so the lane and the receipt cannot disagree about
 * a code one of them emits. It is a closed set on purpose: a reason code is signed evidence, not a
 * free-form diagnostic string. The receipt schema and {@link relayPolicyRefusedEvent} enforce it.
 */
export const RELAY_POLICY_REASON_CODES = Object.freeze(["blocked", "append_limit", "policy_unavailable"] as const);

export type RelayPolicyReasonCode = (typeof RELAY_POLICY_REASON_CODES)[number];

/** Whether `value` is one of the one refusal-code vocabulary. */
export function isRelayPolicyReasonCode(value: unknown): value is RelayPolicyReasonCode {
  return typeof value === "string" && (RELAY_POLICY_REASON_CODES as readonly string[]).includes(value);
}

/**
 * One declared rewrite of the request body: a JSON Pointer path and the value written (or the
 * digest of that value when the event does not carry it). `declared_in` names the published lane
 * rewrite policy that allowed the op, e.g. `gray-lane-rewrites-v1`.
 */
export interface RequestModifiedEvent {
  readonly type: "request.modified";
  readonly op: RequestModifiedOp;
  /** RFC 6901, absolute: `/model`, `/stream_options/include_usage`. */
  readonly path: string;
  /** The value a set/insert writes. Exactly one of `value` and `value_sha256` is present. */
  readonly value?: Json;
  /** SHA-256 of the UTF-8 bytes of `toJsonString(value)` for a value the event does not carry. */
  readonly value_sha256?: string;
  /** The lane rewrite policy that allows the op, e.g. `gray-lane-rewrites-v1`. */
  readonly declared_in: string;
}

const hex32 = z.string().regex(/^[0-9a-f]{64}$/, "32 bytes as lowercase hex (Appendix A)");
const digestField = z.string().regex(/^sha256:[0-9a-f]{64}$/, "sha256: plus 32 bytes of lowercase hex (Appendix A)");
// The shared wire shape's `policy_version` is a u64, and it is the same rule @gray/lane imports
// (its `requirePolicyVersion`), so the two packages cannot disagree about a version one signs.
const policyVersionSchema = u64Schema;
const reasonCodeSchema = z.enum(RELAY_POLICY_REASON_CODES);

/** `template_id`, `position`, `text_sha256` — the shared wire shape of one append. */
export const relayAppendSchema = z.object({
  template_id: z.string().min(1),
  position: z.enum(RELAY_APPEND_POSITIONS),
  text_sha256: hex32,
});

export const relayPolicyAppliedSchema = z.object({
  type: z.literal(EVENT_RELAY_POLICY_APPLIED),
  module_sha256: hex32,
  policy_version: policyVersionSchema,
  appended: z.array(relayAppendSchema),
});

export const relayPolicyRefusedSchema = z.object({
  type: z.literal(EVENT_RELAY_POLICY_REFUSED),
  module_sha256: hex32,
  policy_version: policyVersionSchema,
  reason_code: reasonCodeSchema,
});

const modifiedPathSchema = z.string().min(1).max(256).regex(/^\//, "an absolute JSON Pointer starts with /");
const declaredInSchema = z.string().regex(/^[a-z][a-z0-9._-]{0,127}$/, "a lower_case policy id");
const modifiedValueSchema = z.union([z.string(), z.boolean(), z.bigint(), z.record(z.string(), z.unknown())]);

/**
 * `request.modified`: one op, its RFC 6901 path, its value (or value digest), and the policy id.
 * `remove_member` carries neither value; `set_member` and `insert_member` carry exactly one.
 */
export const requestModifiedSchema = z
  .object({
    type: z.literal(EVENT_REQUEST_MODIFIED),
    op: z.enum(REQUEST_MODIFIED_OPS),
    path: modifiedPathSchema,
    value: modifiedValueSchema.optional(),
    value_sha256: hex32.optional(),
    declared_in: declaredInSchema,
  })
  .superRefine((event, ctx) => {
    if (event.op === "remove_member") {
      if (event.value !== undefined || event.value_sha256 !== undefined) {
        ctx.addIssue({ code: "custom", path: ["value"], message: "remove_member carries no value" });
      }
      return;
    }
    if ((event.value === undefined) === (event.value_sha256 === undefined)) {
      ctx.addIssue({ code: "custom", path: ["value"], message: "exactly one of value and value_sha256 is required" });
    }
  });

/**
 * Gray's relay-stack extension events (plan S26), one group per upstream attempt. Never one of the
 * four reserved types: `request.forwarded` and `response.returned` keep their types and gain members.
 */
export const EVENT_ATTEMPT_STARTED = "attempt.started";
export const EVENT_RELAY_STACK_APPENDED = "relay_stack.appended";
/**
 * The relay's own changes to the request in one attempt (docs/relay-request-changes.md): what egress's
 * check found besides the declared ops and appends, as the changed body paths and header names with
 * their byte counts. At most one per attempt, after its `relay_stack.appended`, and only when the
 * relay changed something; an attempt without it forwarded the request as Gray declared it.
 */
export const EVENT_RELAY_STACK_CHANGED = "relay_stack.changed";
export const EVENT_UPSTREAM_RESPONSE = "upstream.response";
export const EVENT_ATTEMPT_REFUSED = "attempt.refused";
/**
 * The entry's record of the relay's calls stops here (S26): egress may have recorded attempts after the
 * last one listed. At most one, after every attempt group and right before `response.returned`.
 */
export const EVENT_RELAY_STACK_FEED_INCOMPLETE = "relay_stack.feed_incomplete";
/**
 * The stack VM served this receipt's request for an entry over the peer hop (docs/confidential-lane-stack-routing.md
 * §4.8): the entry's keyset digest, its outer receipt id and its request id and attempt number, so an inner receipt
 * belongs to exactly one outer request. At most once, right after `request.received` (§7.3 keeps that one first).
 */
export const EVENT_PEER_ENTRY = "peer.entry";
/**
 * The entry's outer receipt of a request it forwarded to a relay's stack VM (docs/confidential-lane-stack-routing.md
 * §4.8): per peer attempt, `peer.forwarded` (the envelope's digest, and that the entry verified the peer it went to),
 * then `peer.answered` (the hop's `head` and `end`) or `peer.failed` (the hop gave no answer). Each names the peer by a
 * commitment (`peerCommitment`), never by its relay or its origin.
 */
export const EVENT_PEER_FORWARDED = "peer.forwarded";
export const EVENT_PEER_ANSWERED = "peer.answered";
export const EVENT_PEER_FAILED = "peer.failed";

/** The members that make a `request.forwarded` the per-attempt form. */
export const STACK_FORWARDED_MEMBERS = Object.freeze(["method", "path", "query_sha256", "body_jcs_sha256"] as const);

/** The members that make a `response.returned` the stack form. */
export const STACK_RETURNED_MEMBERS = Object.freeze(["status", "events_sha256", "body_sha256", "dropped", "replaced_error", "served_attempt", "served_as"] as const);

/**
 * How the served attempt's answer reached the client when it is not the vendor's events or body as
 * they were (S32): `codex_terminal_response` is a buffered Codex request (D129), whose client got the
 * `response` of the stream's terminal event as JSON; `client_left` is a stream the client left before
 * its end, so it got a prefix of the attempt's events, which the chain cannot prove (not tied).
 * Absent for the direct case.
 */
export const STACK_SERVED_AS = Object.freeze(["codex_terminal_response", "client_left"] as const);

export type StackServedAs = (typeof STACK_SERVED_AS)[number];

/** The vendor path of a Codex call as egress records it (route `/chatgpt`, S16): the only D129 route. */
export const STACK_CODEX_RESPONSES_PATH = "/backend-api/codex/responses";

/**
 * How egress saw an attempt's vendor answer end (the feed's `end.reason`, S17); `entry_closed` is the
 * entry ending the rid (an S24 mismatch, the client leaving, the hold bound), written by egress for each
 * attempt still in flight at the DELETE; `egress_limit` is egress cutting the answer because its stack
 * memory budget (`-stack-max-bytes`) ran out, after which the entry fails closed.
 */
export const STACK_EGRESS_END_REASONS = Object.freeze(["eof", "vendor_reset", "relay_closed", "timeout", "entry_closed", "egress_limit"] as const);

/**
 * An `upstream.response`'s `end_reason`: egress's, or `unrecorded` when egress's end record for the
 * attempt never reached the entry (its feed refused a record or ended before `done`, S26): how the
 * vendor's answer ended is unknown, and the receipt says so (`relay_stack.feed_incomplete` follows).
 * Egress never writes `unrecorded`.
 */
export const STACK_END_REASONS = Object.freeze([...STACK_EGRESS_END_REASONS, "unrecorded"] as const);

export type StackEndReason = (typeof STACK_END_REASONS)[number];

/**
 * Why the entry's record of a container call stopped before egress's `done` (`relay_stack.feed_incomplete`):
 * `record_refused`, egress sent a feed record the entry could not accept (malformed, out of order, or a
 * value the receipt cannot carry), and nothing after it was read; `feed_ended`, the feed ended or was
 * given up before `done` (egress unreachable, no DELETE succeeded before the rid expired).
 */
export const STACK_FEED_INCOMPLETE_REASONS = Object.freeze(["record_refused", "feed_ended"] as const);

export type StackFeedIncompleteReason = (typeof STACK_FEED_INCOMPLETE_REASONS)[number];

/**
 * The codes of an `attempt.refused` that egress's checks gave before it read the body to the end or
 * dialed (S16; `deploy/tee/egress/stack_relay.go`): the attempt has no `request.forwarded`.
 * `egress_limit` is here too: egress refuses a call its stack memory budget cannot hold while it reads
 * the call's headers or body, or when the budget cannot hold the `attempt` record itself, which is then
 * not written (`stackRequest.begin`). S32 adds `stack_header_refused` (a forwarded header outside the
 * route's allowlist or not the client's value, checked before the body) and widens `stack_route_refused`
 * to a query or vendor that is not the registered one. Account health adds `stack_account_cooling` (S40:
 * the account, or the account and the upstream model, cools under a rule egress enforces; refused after
 * the route check, before the body) and S32a `stack_identity_mismatch` (a client-identity header the
 * account registers, sent with another value; it names the header as `stack_header_refused` does).
 */
export const STACK_CHECK_REFUSAL_CODES = Object.freeze([
  "stack_credential_unknown",
  "egress_spec_refused",
  "stack_route_refused",
  "egress_body_too_large",
  "egress_body_invalid",
  "stack_rewrite_refused",
  "egress_limit",
  "stack_header_refused",
  "stack_account_cooling",
  "stack_identity_mismatch",
] as const);

/** The refusals that name the refused header (its name only): S32's and S32a's header checks. */
export const STACK_HEADER_REFUSAL_CODES = Object.freeze(["stack_header_refused", "stack_identity_mismatch"] as const);

/**
 * The codes of an `attempt.refused` after egress accepted the call and wrote its `attempt` record,
 * when the vendor was never reached (D72's pre-connect codes, and a request egress could not build):
 * the attempt has a `request.forwarded` and no `upstream.response`.
 */
export const STACK_DIAL_REFUSAL_CODES = Object.freeze(["egress_connect_failed", "egress_proxy_failed", "egress_tls_failed", "egress_internal"] as const);

export type StackRefusalCode = (typeof STACK_CHECK_REFUSAL_CODES)[number] | (typeof STACK_DIAL_REFUSAL_CODES)[number];

/**
 * Why the entry did not release a container event (S24): `usage` is a synthesised usage-only event
 * (dropped, the stream goes on); `unmatched` is an event with no feed record at its position (the
 * stream ends with Gray's error frame). Keep-alive comments are not events and are not listed.
 */
export const STACK_DROPPED_KINDS = Object.freeze(["usage", "unmatched"] as const);

export type StackDroppedKind = (typeof STACK_DROPPED_KINDS)[number];

/** The seven methods egress forwards (`routes.go`; design §12.1). */
export const STACK_FORWARDED_METHODS = Object.freeze(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const);

const attemptNumberSchema = u64Schema.min(1n, "attempts are numbered from 1");
// egress's validRawPath (routes.go): no raw space, control byte or backslash; S16 then pins it to a route.
const vendorPathSchema = z.string().regex(/^\/[^\u0000- \u007f\\]*$/, "an absolute path without spaces, control characters or backslashes");
const httpStatusSchema = z.bigint().min(100n, "an HTTP status is 100..599").max(599n, "an HTTP status is 100..599");

/**
 * `attempt.started`: attempt `n` (1, 2, … in log order). It names no relay account and no proxy (the
 * owner's decision of 2026-10-29: a customer's receipt does not reveal which of the relay's accounts
 * served it); egress's feed and Gray's own records keep them. [`STACK_RELAY_IDENTITY_MEMBERS`].
 */
export const attemptStartedSchema = z.object({
  type: z.literal(EVENT_ATTEMPT_STARTED),
  n: attemptNumberSchema,
});

/**
 * The members a relay-stack receipt never carries, per event type, because they name or fingerprint the
 * relay's account (owner, 2026-10-29): `attempt.started`'s `account_id` and `proxy_id`, and
 * `request.forwarded`'s `headers_sha256`, the digest of the header lines sent to the vendor, which hold
 * the account's credential and so are the same for every call one API-key account makes. The grammar
 * refuses a log that carries one (`stack_relay_identity`), so no producer can put one back.
 */
export const STACK_RELAY_IDENTITY_MEMBERS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  [EVENT_ATTEMPT_STARTED]: Object.freeze(["account_id", "proxy_id"]),
  [EVENT_REQUEST_FORWARDED]: Object.freeze(["headers_sha256"]),
});

/** `relay_stack.appended`: the registered texts the relay appended in attempt `n` (S18's `RelayAppend`s). */
export const relayStackAppendedSchema = z.object({
  type: z.literal(EVENT_RELAY_STACK_APPENDED),
  n: attemptNumberSchema,
  appended: z.array(relayAppendSchema).min(1, "the event is written only when the relay appended"),
});

/** The ops of a `relay_stack.changed` entry, RFC 6902's three that change a value. */
export const RELAY_CHANGE_OPS = Object.freeze(["add", "remove", "replace"] as const);

export type RelayChangeOp = (typeof RELAY_CHANGE_OPS)[number];

/** Whether a `relay_stack.changed` event carries the changed values (`included`) or only their sizes. */
export const RELAY_CHANGE_VALUES = Object.freeze(["included", "omitted"] as const);

export type RelayChangeValues = (typeof RELAY_CHANGE_VALUES)[number];

/**
 * One changed body value: an RFC 6902 op at an RFC 6901 path (any depth; a path names the relay's own
 * member names, so it is bounded like a refusal path, S32: 256 UTF-16 units), the UTF-8 bytes of the
 * comparison form (RFC 8785 with number tokens as written, as `body_jcs_sha256`) of the value it removed
 * and of the one it added, and, when the event includes values, the added value as that comparison-form
 * text. The value is text, not a JSON value, because an ACI document holds neither a float nor a
 * non-ASCII member name, and a relay's value may hold both.
 */
export interface RelayBodyChange {
  readonly op: RelayChangeOp;
  readonly path: string;
  readonly removed_bytes: bigint;
  readonly added_bytes: bigint;
  readonly value_jcs?: string;
}

/** One changed header sent to the vendor: its lower-case name, the bytes of the value removed and added, and the added value when the event includes values. */
export interface RelayHeaderChange {
  readonly op: RelayChangeOp;
  readonly name: string;
  readonly removed_bytes: bigint;
  readonly added_bytes: bigint;
  readonly value?: string;
}

/**
 * The relay's changes in one attempt, as egress's check reports them (its `attempt` record's `changed`):
 * the listed body and header entries, the body's added and removed bytes in all (the listed entries and
 * the `omitted` ones), the number of entries the record leaves out to stay within the receipt's budget,
 * and whether the listed entries carry their values.
 */
export interface RelayStackChanges {
  readonly body: readonly RelayBodyChange[];
  readonly headers: readonly RelayHeaderChange[];
  readonly added_bytes: bigint;
  readonly removed_bytes: bigint;
  readonly omitted: bigint;
  readonly values: RelayChangeValues;
}

/** An RFC 6901 pointer of one or more tokens, `~` only as `~0` or `~1`, at most 256 UTF-16 units, well-formed text. */
const relayChangePathSchema = z
  .string()
  .max(256)
  .regex(/^(\/([^~/]|~[01])*)+$/, "an absolute RFC 6901 JSON Pointer (~ only as ~0 or ~1)")
  .refine((path) => path.isWellFormed(), "a path is well-formed text");
// RFC 9110 token characters, lower case: the name egress sent, as Go's header map holds it lower-cased.
const relayHeaderNameSchema = z.string().regex(/^[!#$%&'*+.^_`|~0-9a-z-]{1,256}$/, "a lower-case header name of 1 to 256 token characters");
const wellFormedText = z.string().refine((text) => text.isWellFormed(), "well-formed text");

/** The byte rules every entry keeps: `add` removes nothing, `remove` adds nothing and carries no value; a value's bytes are `added_bytes`. */
function checkChangeEntry(entry: { op: RelayChangeOp; removed_bytes: bigint; added_bytes: bigint }, value: string | undefined, ctx: z.RefinementCtx): void {
  if (entry.op === "add" && entry.removed_bytes !== 0n) ctx.addIssue({ code: "custom", path: ["removed_bytes"], message: "an add removes nothing" });
  if (entry.op === "remove" && entry.added_bytes !== 0n) ctx.addIssue({ code: "custom", path: ["added_bytes"], message: "a remove adds nothing" });
  if (entry.op === "remove" && value !== undefined) ctx.addIssue({ code: "custom", path: ["op"], message: "a remove carries no value" });
  if (value !== undefined && BigInt(utf8Bytes(value).length) !== entry.added_bytes) {
    ctx.addIssue({ code: "custom", path: ["added_bytes"], message: "added_bytes is the UTF-8 length of the value carried" });
  }
}

export const relayBodyChangeSchema = z
  .object({
    op: z.enum(RELAY_CHANGE_OPS),
    path: relayChangePathSchema,
    removed_bytes: u64Schema,
    added_bytes: u64Schema,
    value_jcs: wellFormedText.optional(),
  })
  .strict()
  .superRefine((entry, ctx) => {
    checkChangeEntry(entry, entry.value_jcs, ctx);
    // A JSON value's text is at least one byte: a body add or replace adds one, a remove or replace removes one.
    if (entry.op !== "remove" && entry.added_bytes === 0n) ctx.addIssue({ code: "custom", path: ["added_bytes"], message: "a body add or replace adds a value of at least one byte" });
    if (entry.op !== "add" && entry.removed_bytes === 0n) ctx.addIssue({ code: "custom", path: ["removed_bytes"], message: "a body remove or replace removes a value of at least one byte" });
  });

export const relayHeaderChangeSchema = z
  .object({
    op: z.enum(RELAY_CHANGE_OPS),
    name: relayHeaderNameSchema,
    removed_bytes: u64Schema,
    added_bytes: u64Schema,
    value: wellFormedText.optional(),
  })
  .strict()
  .superRefine((entry, ctx) => checkChangeEntry(entry, entry.value, ctx));

/**
 * `relay_stack.changed`: the relay's own changes in attempt `n` ([`RelayStackChanges`]). Applied in order
 * (RFC 6902) to the customer's body after the attempt's `request.modified` ops and `relay_stack.appended`
 * texts, the body entries give the forwarded body whose comparison form `body_jcs_sha256` digests; each
 * top-level member is changed by the declared ops and appends or by these entries, never by both. The
 * event lists something (an entry, or an `omitted` count); with `values: included` every add and replace
 * carries its value, with `omitted` none does. When nothing is omitted the totals are the listed body
 * entries' sums; otherwise at least those.
 */
export const relayStackChangedSchema = z
  .object({
    type: z.literal(EVENT_RELAY_STACK_CHANGED),
    n: attemptNumberSchema,
    body: z.array(relayBodyChangeSchema),
    headers: z.array(relayHeaderChangeSchema),
    added_bytes: u64Schema,
    removed_bytes: u64Schema,
    omitted: u64Schema,
    values: z.enum(RELAY_CHANGE_VALUES),
  })
  .strict()
  .superRefine((event, ctx) => {
    if (event.body.length + event.headers.length === 0 && event.omitted === 0n) {
      ctx.addIssue({ code: "custom", path: ["body"], message: "the event is written only when the relay changed something" });
    }
    const entries: readonly [string, number, RelayChangeOp, string | undefined][] = [
      ...event.body.map((entry, index): [string, number, RelayChangeOp, string | undefined] => ["body", index, entry.op, entry.value_jcs]),
      ...event.headers.map((entry, index): [string, number, RelayChangeOp, string | undefined] => ["headers", index, entry.op, entry.value]),
    ];
    for (const [list, index, op, value] of entries) {
      if (event.values === "omitted" && value !== undefined) ctx.addIssue({ code: "custom", path: [list, index], message: "values: omitted carries no value" });
      if (event.values === "included" && op !== "remove" && value === undefined) ctx.addIssue({ code: "custom", path: [list, index], message: "values: included carries every added value" });
    }
    const names = new Set<string>();
    event.headers.forEach((entry, index) => {
      if (names.has(entry.name)) ctx.addIssue({ code: "custom", path: ["headers", index, "name"], message: "each header is listed once" });
      names.add(entry.name);
    });
    const added = event.body.reduce((sum, entry) => sum + entry.added_bytes, 0n);
    const removed = event.body.reduce((sum, entry) => sum + entry.removed_bytes, 0n);
    const exact = event.omitted === 0n;
    if (exact ? event.added_bytes !== added : event.added_bytes < added) {
      ctx.addIssue({ code: "custom", path: ["added_bytes"], message: exact ? "added_bytes is the body entries' sum" : "added_bytes is at least the listed body entries' sum" });
    }
    if (exact ? event.removed_bytes !== removed : event.removed_bytes < removed) {
      ctx.addIssue({ code: "custom", path: ["removed_bytes"], message: exact ? "removed_bytes is the body entries' sum" : "removed_bytes is at least the listed body entries' sum" });
    }
  });

/**
 * `request.forwarded.tls_hello`, present only when the call was made in a vendor tunnel (egress's `attempt` record's
 * `tls_hello`): `relay` says the TLS handshake egress made with the vendor had the shape the relay's software showed
 * it (cipher suites, extensions and their order), learned before the relay could hold any customer request; absent,
 * the handshake was egress's own.
 */
export const STACK_TLS_HELLOS = Object.freeze(["relay"] as const);

export type StackTlsHello = (typeof STACK_TLS_HELLOS)[number];

/**
 * The per-attempt `request.forwarded`: §7.4's `body_hash` (`sha256:` + the feed's `body_sha256`, the
 * bytes the relay's call carried to egress) plus the call's method, vendor path, the SHA-256 of its
 * raw query (egress's `query_sha256`), and `body_jcs_sha256`, the SHA-256 of the body's RFC 8785 form:
 * egress accepts a body equal by value to the customer's replay (S18), so this is the digest a customer
 * recomputes; `body_hash` is reported. Egress's `headers_sha256` stays in its feed record: it covers the
 * relay's credential header, so in a receipt it would tell the relay's accounts apart.
 */
export const stackRequestForwardedSchema = z.object({
  type: z.literal(EVENT_REQUEST_FORWARDED),
  body_hash: digestField,
  method: z.enum(STACK_FORWARDED_METHODS),
  path: vendorPathSchema,
  query_sha256: hex32,
  body_jcs_sha256: hex32,
  tls_hello: z.enum(STACK_TLS_HELLOS).optional(),
});

/**
 * `upstream.response`: what egress saw of the vendor's answer. `status` and `headers_sha256` (of the
 * allowlisted response headers, [`stackHeadersSha256`]) are null when no response head arrived; then
 * there is no content digest either. `events_sha256` (the chain over the feed's event digests) for an
 * uncoded event stream, `body_sha256` (the feed's `body` digest) for another answer egress held whole,
 * neither when egress could not digest it (a coded or oversized answer, or one it cut at `egress_limit`:
 * egress has no digest of what it did not finish). An `unrecorded` end never carries `events_sha256`
 * (the chain of the events recorded so far is not the answer's); it carries `body_sha256` when egress's
 * `body` record arrived, which egress writes once it held the whole body.
 */
export const upstreamResponseSchema = z
  .object({
    type: z.literal(EVENT_UPSTREAM_RESPONSE),
    status: httpStatusSchema.nullable(),
    headers_sha256: hex32.nullable(),
    events_sha256: hex32.optional(),
    body_sha256: hex32.optional(),
    end_reason: z.enum(STACK_END_REASONS),
  })
  .superRefine((event, ctx) => {
    if (event.events_sha256 !== undefined && event.body_sha256 !== undefined) {
      ctx.addIssue({ code: "custom", path: ["body_sha256"], message: "at most one of events_sha256 and body_sha256" });
    }
    if ((event.status === null) !== (event.headers_sha256 === null)) {
      ctx.addIssue({ code: "custom", path: ["headers_sha256"], message: "headers_sha256 is null exactly when status is" });
    }
    if (event.status === null && (event.events_sha256 !== undefined || event.body_sha256 !== undefined)) {
      ctx.addIssue({ code: "custom", path: ["status"], message: "an answer with no response head has no content digest" });
    }
    if (event.end_reason === "egress_limit" && (event.events_sha256 !== undefined || event.body_sha256 !== undefined)) {
      ctx.addIssue({ code: "custom", path: ["end_reason"], message: "an answer egress cut at egress_limit has no content digest" });
    }
    if (event.end_reason === "unrecorded" && event.events_sha256 !== undefined) {
      ctx.addIssue({ code: "custom", path: ["end_reason"], message: "an answer whose end is unrecorded has no events digest" });
    }
  });

/** `relay_stack.feed_incomplete`: the entry's record of the relay's calls stopped before egress's `done`, and why. */
export const relayStackFeedIncompleteSchema = z.object({
  type: z.literal(EVENT_RELAY_STACK_FEED_INCOMPLETE),
  reason: z.enum(STACK_FEED_INCOMPLETE_REASONS),
});

/** `peer.entry`: the entry a stack VM served the request for (§4.8), as the envelope named it (`@gray/lane-wire` peer.ts). */
export const peerEntrySchema = z
  .object({
    type: z.literal(EVENT_PEER_ENTRY),
    keyset_digest: z.string().refine((value) => isDigestField(value), "the entry's keyset digest is sha256: plus 32 bytes of lowercase hex"),
    receipt_id: z.string().regex(/^rcpt_[0-9a-f]{32}$/, "an outer receipt id is rcpt_ and 32 lowercase hex").nullable(),
    rid: z.string().regex(/^[0-9a-f]{32}$/, "the entry's request id is 32 lowercase hex"),
    n: attemptNumberSchema,
  })
  .strict();

/**
 * Why a peer attempt had no answer (`peer.failed`): egress's six hop codes (deploy/tee/egress README "Peer mode"), the
 * stack VM's refusals before any frame (`@gray/lane-wire` PEER_REFUSAL_STATUS), an answer that is not the hop's wire
 * (`peer_invalid`), and an attempt the entry ended itself before an answer (`peer_aborted`: its bound, or its client left).
 */
export const PEER_FAILED_CODES = Object.freeze([
  "peer_unpinned",
  "peer_connect_failed",
  "peer_tls_failed",
  "peer_pin_mismatch",
  "peer_failed_after_send",
  "peer_timeout",
  // The outbound-only channel (docs/design/relay-outbound-only.md section 3.7): nothing sent, egress answers 502.
  "peer_session_missing",
  "peer_session_refused",
  "peer_malformed",
  "peer_unknown",
  "peer_audience",
  "peer_replayed",
  "peer_body_mismatch",
  "route_unconfigured",
  "foreign_relay",
  "peer_invalid",
  "peer_aborted",
] as const);
export type PeerFailedCode = (typeof PEER_FAILED_CODES)[number];

/** A peer commitment (`peerCommitment`): 32 bytes as lowercase hex. */
const peerCommitmentSchema = hex32;

/** `peer.forwarded`: the entry's attempt `n` went to a peer it verified (L1), with the envelope whose digest this is. */
export const peerForwardedSchema = z
  .object({
    type: z.literal(EVENT_PEER_FORWARDED),
    n: attemptNumberSchema,
    envelope_sha256: hex32,
    /** The entry verified the peer against the environment's stack list before it sent the attempt (section 4.3). Always true. */
    peer_verified: z.literal(true),
  })
  .strict();

/**
 * `peer.answered`: the hop answered attempt `n`. `status` is its `head`'s; `dialed` its `end`'s, or the follow-up's when
 * the hop ended without one, null when neither said; `inner` the digest of the stack VM's receipt when `end` carried one.
 * `peer` commits to the peer's facts and that receipt (`peerCommitment`).
 */
export const peerAnsweredSchema = z
  .object({
    type: z.literal(EVENT_PEER_ANSWERED),
    n: attemptNumberSchema,
    status: httpStatusSchema,
    dialed: z.boolean().nullable(),
    inner: z.object({ receipt_id: z.string().regex(/^rcpt_[0-9a-f]{32}$/, "an inner receipt id is rcpt_ and 32 lowercase hex"), receipt_sha256: hex32 }).strict().nullable(),
    peer: peerCommitmentSchema,
  })
  .strict();

/** `peer.failed`: attempt `n` got no answer from the hop; `sent` is whether a byte of it may have reached the peer. */
export const peerFailedSchema = z
  .object({
    type: z.literal(EVENT_PEER_FAILED),
    n: attemptNumberSchema,
    code: z.enum(PEER_FAILED_CODES),
    sent: z.boolean(),
    peer: peerCommitmentSchema,
  })
  .strict();

// The header a header refusal (`STACK_HEADER_REFUSAL_CODES`) names: its name only, never a value, lower case as egress writes it,
// an RFC 9110 token (net/http admits no other name), at most 256 bytes (egress's stackRefusedHeaderMax).
const refusedHeaderSchema = z.string().regex(/^[!#$%&'*+.^_`|~0-9a-z-]{1,256}$/, "a lower-case HTTP header name of 1-256 token characters");

/**
 * `attempt.refused`: egress refused attempt `n` (the vendor was never reached); `path` only for a rewrite
 * refusal, `header` (the refused header's name) only for a header refusal (`STACK_HEADER_REFUSAL_CODES`).
 */
export const attemptRefusedSchema = z
  .object({
    type: z.literal(EVENT_ATTEMPT_REFUSED),
    n: attemptNumberSchema,
    code: z.enum([...STACK_CHECK_REFUSAL_CODES, ...STACK_DIAL_REFUSAL_CODES]),
    path: modifiedPathSchema.optional(),
    header: refusedHeaderSchema.optional(),
  })
  .superRefine((event, ctx) => {
    if (event.path !== undefined && event.code !== "stack_rewrite_refused") {
      ctx.addIssue({ code: "custom", path: ["path"], message: "only a stack_rewrite_refused names a path" });
    }
    if (event.header !== undefined && !(STACK_HEADER_REFUSAL_CODES as readonly string[]).includes(event.code)) {
      ctx.addIssue({ code: "custom", path: ["header"], message: "only a stack_header_refused or a stack_identity_mismatch names a header" });
    }
  });

const droppedSchema = z.object({ seq: u64Schema, kind: z.enum(STACK_DROPPED_KINDS) });

// What a client that left before any answer received: no event (the chain's h_0; keep-alive comments are
// not events) or no body (S19's digest of zero bytes, which are not JSON).
const NO_EVENTS_SHA256 = bytesToLowerHex(stackEventsChainStart());
const NO_BODY_SHA256 = sha256BareHex(new Uint8Array(0));

/**
 * The stack `response.returned`: §7.4's `body_hash` of the exact bytes the client got, plus the
 * status the client got, exactly one of `events_sha256` (the chain over the S19 digests of every
 * event written to the client, Gray's own error frame included; Gray's keep-alives are SSE comments,
 * not events) and `body_sha256` (S19's body digest of a non-stream answer), the container events the
 * entry did not release (`seq` is the event's 0-based position in the container's answer, ascending),
 * whether the client's answer is or ends in Gray's own error (`replaced_error`: Gray's fixed error, or
 * its error frame after released events), and the attempt whose events, body or vendor error the client
 * got (S32): `served_attempt` is its `n`, null when the client got only Gray's own error
 * (`replaced_error`) or left before any answer (`client_left`, then `events_sha256` is the empty chain or
 * `body_sha256` the digest of no bytes); `served_as` is present only for an un-replaced answer that is not
 * the vendor's events or body as they were (`STACK_SERVED_AS`): a Codex terminal response is a served
 * body, an answer the client left mid-way is the events or the body prefix it got (S19's body digest of
 * the bytes sent, the raw digest whenever that prefix is not a whole JSON text).
 */
export const stackResponseReturnedSchema = z
  .object({
    type: z.literal(EVENT_RESPONSE_RETURNED),
    body_hash: digestField,
    status: httpStatusSchema,
    events_sha256: hex32.optional(),
    body_sha256: hex32.optional(),
    dropped: z.array(droppedSchema),
    replaced_error: z.boolean(),
    served_attempt: attemptNumberSchema.nullable(),
    served_as: z.enum(STACK_SERVED_AS).optional(),
  })
  .superRefine((event, ctx) => {
    if ((event.events_sha256 === undefined) === (event.body_sha256 === undefined)) {
      ctx.addIssue({ code: "custom", path: ["events_sha256"], message: "exactly one of events_sha256 and body_sha256" });
    }
    if (event.served_attempt === null && !event.replaced_error && event.served_as !== "client_left") {
      ctx.addIssue({
        code: "custom",
        path: ["served_attempt"],
        message: "served_attempt is null only when the client got Gray's own error (replaced_error: true) or left before any answer (client_left)",
      });
    }
    if (event.served_as !== undefined && event.replaced_error) {
      ctx.addIssue({ code: "custom", path: ["served_as"], message: "served_as names how an un-replaced answer reached the client" });
    }
    if (event.served_as === "codex_terminal_response" && (event.served_attempt === null || event.body_sha256 === undefined)) {
      ctx.addIssue({ code: "custom", path: ["served_as"], message: "a codex_terminal_response is a served body" });
    }
    if (
      event.served_as === "client_left" &&
      event.served_attempt === null &&
      ((event.events_sha256 !== undefined && event.events_sha256 !== NO_EVENTS_SHA256) || (event.body_sha256 !== undefined && event.body_sha256 !== NO_BODY_SHA256))
    ) {
      ctx.addIssue({ code: "custom", path: ["served_as"], message: "a client that left before any answer received no event and no body" });
    }
    if (event.dropped.length > 0 && event.events_sha256 === undefined) {
      ctx.addIssue({ code: "custom", path: ["dropped"], message: "only an event stream drops events" });
    }
    event.dropped.forEach((entry, index) => {
      const previous = event.dropped[index - 1];
      if (previous !== undefined && entry.seq <= previous.seq) {
        ctx.addIssue({ code: "custom", path: ["dropped", index, "seq"], message: "dropped events are listed once each, in ascending seq" });
      }
    });
  });

/** The §7.5 verified form: a session carries every verification detail. */
export const upstreamVerifiedSchema = z.object({
  type: z.literal(EVENT_UPSTREAM_VERIFIED),
  result: z.literal("verified"),
  required: z.boolean(),
  model_id: z.string(),
  session_id: hex32,
});

/** The §7.5 failed form: `reason` instead of a session, plus the optional upstream label. */
export const upstreamVerificationFailedSchema = z.object({
  type: z.literal(EVENT_UPSTREAM_VERIFIED),
  result: z.literal("failed"),
  required: z.boolean(),
  model_id: z.string(),
  reason: z.string().min(1),
  upstream_name: z.string().min(1).optional(),
});

export const bodyHashEventSchema = z.object({
  type: z.enum([EVENT_REQUEST_RECEIVED, EVENT_REQUEST_FORWARDED, EVENT_RESPONSE_RETURNED] as [string, ...string[]]),
  body_hash: digestField,
});

/** `sha256:` plus lowercase hex of the exact bytes (§7.4: hashed over bytes actually observed). */
export function bodyHash(body: Uint8Array | string): string {
  return sha256Digest(typeof body === "string" ? utf8Bytes(body) : body);
}

/** §7.4 `request.received`: the request body the workload processed. */
export function requestReceivedEvent(hash: string): JsonObject {
  return { type: EVENT_REQUEST_RECEIVED, body_hash: hash };
}

/** §7.4 `request.forwarded`: the exact bytes used for inference after any service-side rewrite. */
export function requestForwardedEvent(hash: string): JsonObject {
  return { type: EVENT_REQUEST_FORWARDED, body_hash: hash };
}

/** §7.4 `response.returned`: the exact response bytes emitted on the wire (raw SSE framing included). */
export function responseReturnedEvent(hash: string): JsonObject {
  return { type: EVENT_RESPONSE_RETURNED, body_hash: hash };
}

/** §7.5 verified form: the event cites the content-addressed attested session (§8). */
export function upstreamVerifiedEvent(input: {
  readonly modelId: string;
  readonly required: boolean;
  readonly sessionId: string;
}): JsonObject {
  if (!isLowerHexOf(input.sessionId, 32)) throw new Error("session_id is bare 64-hex (§8)");
  return {
    type: EVENT_UPSTREAM_VERIFIED,
    result: "verified",
    required: input.required,
    model_id: input.modelId,
    session_id: input.sessionId,
  };
}

/** §7.5 failed form: required verification failed or no enforceable binding existed. */
export function upstreamVerificationFailedEvent(input: {
  readonly modelId: string;
  readonly required: boolean;
  readonly reason: string;
  readonly upstreamName?: string;
}): JsonObject {
  if (input.reason === "") throw new Error("a failed upstream verification names a reason (§7.5)");
  const event: JsonObject = {
    type: EVENT_UPSTREAM_VERIFIED,
    result: "failed",
    required: input.required,
    model_id: input.modelId,
    reason: input.reason,
  };
  if (input.upstreamName !== undefined && input.upstreamName !== "") setMember(event, "upstream_name", input.upstreamName);
  return event;
}

/** The `relay_policy.applied` event object (the shared wire shape, canonicalized on signing). */
export function relayPolicyAppliedEvent(input: {
  readonly moduleSha256: string;
  readonly policyVersion: bigint;
  readonly appended: readonly RelayAppend[];
}): JsonObject {
  if (!isLowerHexOf(input.moduleSha256, 32)) throw new Error("module_sha256 is 32 bytes as lowercase hex");
  if (!isU64(input.policyVersion)) throw new Error("policy_version is a u64 (0 ..= 2^64 - 1)");
  return {
    type: EVENT_RELAY_POLICY_APPLIED,
    module_sha256: input.moduleSha256,
    policy_version: input.policyVersion,
    appended: input.appended.map((append) => {
      if (append.template_id === "") throw new Error("a registered template_id is required");
      if (!isLowerHexOf(append.text_sha256, 32)) throw new Error("text_sha256 is 32 bytes as lowercase hex");
      if (!RELAY_APPEND_POSITIONS.includes(append.position)) throw new Error(`unknown append position ${append.position}`);
      return { template_id: append.template_id, position: append.position, text_sha256: append.text_sha256 };
    }),
  };
}

/** The `relay_policy.refused` event object: the module blocked the request, no text recorded. */
export function relayPolicyRefusedEvent(input: {
  readonly moduleSha256: string;
  readonly policyVersion: bigint;
  readonly reasonCode: string;
}): JsonObject {
  if (!isLowerHexOf(input.moduleSha256, 32)) throw new Error("module_sha256 is 32 bytes as lowercase hex");
  if (!isU64(input.policyVersion)) throw new Error("policy_version is a u64 (0 ..= 2^64 - 1)");
  if (!isRelayPolicyReasonCode(input.reasonCode)) throw new Error(`not a reason code: ${String(input.reasonCode)}`);
  return {
    type: EVENT_RELAY_POLICY_REFUSED,
    module_sha256: input.moduleSha256,
    policy_version: input.policyVersion,
    reason_code: input.reasonCode,
  };
}

/**
 * The `request.modified` event object: one declared op, its path, and its value (or the SHA-256 of
 * the serialized value when the event does not carry it). Throws on a shape no receipt may carry.
 */
export function requestModifiedEvent(input: {
  readonly op: RequestModifiedOp;
  readonly path: string;
  readonly value?: Json;
  readonly valueSha256?: string;
  readonly declaredIn: string;
}): JsonObject {
  if (!REQUEST_MODIFIED_OPS.includes(input.op)) throw new Error(`unknown request.modified op: ${String(input.op)}`);
  if (!modifiedPathSchema.safeParse(input.path).success || !input.path.isWellFormed()) throw new Error("path is an absolute JSON Pointer of at most 256 characters");
  if (!declaredInSchema.safeParse(input.declaredIn).success) throw new Error(`not a lane rewrite policy id: ${input.declaredIn}`);
  if (input.op === "remove_member") {
    if (input.value !== undefined || input.valueSha256 !== undefined) throw new Error("remove_member carries no value");
  } else if ((input.value === undefined) === (input.valueSha256 === undefined)) {
    throw new Error("exactly one of value and value_sha256 is required");
  }
  if (input.valueSha256 !== undefined && !isLowerHexOf(input.valueSha256, 32)) {
    throw new Error("value_sha256 is 32 bytes as lowercase hex");
  }
  if (input.value !== undefined && !isModifiedValue(input.value)) {
    throw new Error("a request.modified value is a string, boolean, integer, or the small declared object; not a number, null or array");
  }
  const event: JsonObject = { type: EVENT_REQUEST_MODIFIED, op: input.op, path: input.path, declared_in: input.declaredIn };
  if (input.value !== undefined) setMember(event, "value", input.value);
  if (input.valueSha256 !== undefined) setMember(event, "value_sha256", input.valueSha256);
  return event;
}

/** The values a `request.modified` event may carry: no floats (JCS refuses them), null or arrays. */
export function isModifiedValue(value: unknown): value is Json {
  if (typeof value === "string") return value.isWellFormed();
  if (typeof value === "boolean" || typeof value === "bigint") return true;
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  for (const key of Object.keys(value)) {
    if (!key.isWellFormed()) return false;
    // ACI's canonical form (JCS on the ACI subset) allows ASCII member names only; refuse a value
    // whose object key the signer would refuse, not at finalize time.
    if (!/^[\u0000-\u007f]*$/.test(key)) return false;
    if (!isModifiedValue((value as Record<string, unknown>)[key])) return false;
  }
  return true;
}

/** `attempt.started` for attempt `n` (the receipt's own numbering, 1, 2, … in log order); no account, no proxy. */
export function attemptStartedEvent(input: { readonly n: bigint }): JsonObject {
  return shaped(attemptStartedSchema, { type: EVENT_ATTEMPT_STARTED, n: input.n });
}

/** `relay_stack.appended`: the relay's appends in attempt `n`, as S18 reported them. */
export function relayStackAppendedEvent(input: { readonly n: bigint; readonly appended: readonly RelayAppend[] }): JsonObject {
  return shaped(relayStackAppendedSchema, {
    type: EVENT_RELAY_STACK_APPENDED,
    n: input.n,
    appended: input.appended.map((append) => ({ template_id: append.template_id, position: append.position, text_sha256: append.text_sha256 })),
  });
}

/**
 * `relay_stack.changed`: the relay's own changes in attempt `n`, as egress's check reported them
 * (its `attempt` record's `changed`). Members are copied one by one, so nothing else reaches the receipt.
 */
export function relayStackChangedEvent(input: { readonly n: bigint; readonly changed: RelayStackChanges }): JsonObject {
  const { changed } = input;
  return shaped(relayStackChangedSchema, {
    type: EVENT_RELAY_STACK_CHANGED,
    n: input.n,
    body: changed.body.map((entry) => {
      const written: JsonObject = { op: entry.op, path: entry.path, removed_bytes: entry.removed_bytes, added_bytes: entry.added_bytes };
      if (entry.value_jcs !== undefined) setMember(written, "value_jcs", entry.value_jcs);
      return written;
    }),
    headers: changed.headers.map((entry) => {
      const written: JsonObject = { op: entry.op, name: entry.name, removed_bytes: entry.removed_bytes, added_bytes: entry.added_bytes };
      if (entry.value !== undefined) setMember(written, "value", entry.value);
      return written;
    }),
    added_bytes: changed.added_bytes,
    removed_bytes: changed.removed_bytes,
    omitted: changed.omitted,
    values: changed.values,
  });
}

/**
 * The per-attempt `request.forwarded` from egress's `attempt` record: `bodySha256` is its bare-hex
 * `body_sha256`, written as §7.4's `body_hash` (`sha256:` + hex); `bodyJcsSha256` its
 * `body_jcs_sha256`.
 */
export function stackRequestForwardedEvent(input: {
  readonly method: string;
  readonly path: string;
  readonly querySha256: string;
  readonly bodySha256: string;
  readonly bodyJcsSha256: string;
  /** The record's `tls_hello`, when it has one ([`STACK_TLS_HELLOS`]). */
  readonly tlsHello?: StackTlsHello;
}): JsonObject {
  const event: JsonObject = {
    type: EVENT_REQUEST_FORWARDED,
    body_hash: `sha256:${input.bodySha256}`,
    method: input.method,
    path: input.path,
    query_sha256: input.querySha256,
    body_jcs_sha256: input.bodyJcsSha256,
  };
  if (input.tlsHello !== undefined) setMember(event, "tls_hello", input.tlsHello);
  return shaped(stackRequestForwardedSchema, event);
}

/** `upstream.response`: the vendor's status, header digest, content digest (if any) and how it ended. */
export function upstreamResponseEvent(input: {
  readonly status: bigint | null;
  readonly headersSha256: string | null;
  readonly eventsSha256?: string;
  readonly bodySha256?: string;
  readonly endReason: StackEndReason;
}): JsonObject {
  const event: JsonObject = { type: EVENT_UPSTREAM_RESPONSE, status: input.status, headers_sha256: input.headersSha256, end_reason: input.endReason };
  if (input.eventsSha256 !== undefined) setMember(event, "events_sha256", input.eventsSha256);
  if (input.bodySha256 !== undefined) setMember(event, "body_sha256", input.bodySha256);
  return shaped(upstreamResponseSchema, event);
}

/** `attempt.refused`: egress refused attempt `n` before the vendor; `path` only for `stack_rewrite_refused`. */
export function attemptRefusedEvent(input: { readonly n: bigint; readonly code: StackRefusalCode; readonly path?: string; readonly header?: string }): JsonObject {
  const event: JsonObject = { type: EVENT_ATTEMPT_REFUSED, n: input.n, code: input.code };
  if (input.path !== undefined) {
    if (!input.path.isWellFormed()) throw new Error("attempt.refused: path is not well-formed text");
    setMember(event, "path", input.path);
  }
  if (input.header !== undefined) setMember(event, "header", input.header);
  return shaped(attemptRefusedSchema, event);
}

/** `peer.entry`: the entry this stack VM served the request for, as its envelope named it (§4.8). */
export function peerEntryEvent(input: { readonly keysetDigest: string; readonly receiptId: string | null; readonly rid: string; readonly n: bigint }): JsonObject {
  return shaped(peerEntrySchema, { type: EVENT_PEER_ENTRY, keyset_digest: input.keysetDigest, receipt_id: input.receiptId, rid: input.rid, n: input.n });
}

/**
 * The facts a peer commitment covers (section 4.8, pending the owner's decision whether receipts name the serving relay):
 * the stack VM's keyset digest, the compose hash, OS image and relay image its attestation proved, and the digest of its
 * inner receipt for the attempt (null when none came). The relay id and the VM's origin are not facts of their own here:
 * the keyset digest names one boot of one relay's VM, which its attestation states.
 */
export interface PeerCommitmentFacts {
  readonly keysetDigest: string;
  readonly composeHash: string;
  readonly osImageHash: string;
  readonly relayImage: string;
  readonly innerReceiptSha256: string | null;
}

/** The domain of a peer commitment's preimage. */
export const PEER_COMMITMENT_DOMAIN = "gray-lane-peer-commitment/v1";

/**
 * The preimage of a peer commitment: the facts as one JCS document under PEER_COMMITMENT_DOMAIN. A receipt that names the
 * relay later carries this document beside the commitment, and a verifier recomputes the commitment from it.
 */
export function peerCommitmentPreimage(facts: PeerCommitmentFacts): JsonObject {
  return {
    domain: PEER_COMMITMENT_DOMAIN,
    keyset_digest: facts.keysetDigest,
    compose_hash: facts.composeHash,
    os_image_hash: facts.osImageHash,
    relay_image: facts.relayImage,
    inner_receipt_sha256: facts.innerReceiptSha256,
  };
}

/** A peer commitment: SHA-256 of the preimage's JCS bytes, 64 lowercase hex. */
export function peerCommitment(facts: PeerCommitmentFacts): string {
  return sha256BareHex(jcsBytes(peerCommitmentPreimage(facts)));
}

/** `peer.forwarded`: the entry's attempt `n` went to a peer it verified, under the envelope `envelopeSha256` names. */
export function peerForwardedEvent(input: { readonly n: bigint; readonly envelopeSha256: string }): JsonObject {
  return shaped(peerForwardedSchema, { type: EVENT_PEER_FORWARDED, n: input.n, envelope_sha256: input.envelopeSha256, peer_verified: true });
}

/** `peer.answered`: the hop's answer to attempt `n`. */
export function peerAnsweredEvent(input: { readonly n: bigint; readonly status: bigint; readonly dialed: boolean | null; readonly inner: { readonly receiptId: string; readonly receiptSha256: string } | null; readonly peer: string }): JsonObject {
  return shaped(peerAnsweredSchema, {
    type: EVENT_PEER_ANSWERED,
    n: input.n,
    status: input.status,
    dialed: input.dialed,
    inner: input.inner === null ? null : { receipt_id: input.inner.receiptId, receipt_sha256: input.inner.receiptSha256 },
    peer: input.peer,
  });
}

/** `peer.failed`: attempt `n` had no answer from the hop. */
export function peerFailedEvent(input: { readonly n: bigint; readonly code: PeerFailedCode; readonly sent: boolean; readonly peer: string }): JsonObject {
  return shaped(peerFailedSchema, { type: EVENT_PEER_FAILED, n: input.n, code: input.code, sent: input.sent, peer: input.peer });
}

/** `relay_stack.feed_incomplete`: the entry's record of the relay's calls stops here, and why. */
export function relayStackFeedIncompleteEvent(input: { readonly reason: StackFeedIncompleteReason }): JsonObject {
  return shaped(relayStackFeedIncompleteSchema, { type: EVENT_RELAY_STACK_FEED_INCOMPLETE, reason: input.reason });
}

/** The stack `response.returned`: §7.4's raw `body_hash` plus the client-side stack members. */
export function stackResponseReturnedEvent(input: {
  readonly bodyHash: string;
  readonly status: bigint;
  readonly eventsSha256?: string;
  readonly bodySha256?: string;
  readonly dropped: readonly { readonly seq: bigint; readonly kind: StackDroppedKind }[];
  readonly replacedError: boolean;
  readonly servedAttempt: bigint | null;
  readonly servedAs?: StackServedAs;
}): JsonObject {
  const event: JsonObject = {
    type: EVENT_RESPONSE_RETURNED,
    body_hash: input.bodyHash,
    status: input.status,
    dropped: input.dropped.map((entry) => ({ seq: entry.seq, kind: entry.kind })),
    replaced_error: input.replacedError,
    served_attempt: input.servedAttempt,
  };
  if (input.eventsSha256 !== undefined) setMember(event, "events_sha256", input.eventsSha256);
  if (input.bodySha256 !== undefined) setMember(event, "body_sha256", input.bodySha256);
  if (input.servedAs !== undefined) setMember(event, "served_as", input.servedAs);
  return shaped(stackResponseReturnedSchema, event);
}

/** `event` if it matches `schema`; throws otherwise. The constructors use the checker's own schemas. */
function shaped(schema: z.ZodType, event: JsonObject): JsonObject {
  const parsed = schema.safeParse(event);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`).join("; ");
    throw new Error(`${String(get(event, "type"))}: ${issues}`);
  }
  return event;
}

/**
 * Whether `events` is a relay-stack log: it carries an attempt event (`attempt.started`,
 * `relay_stack.appended`, `relay_stack.changed`, `upstream.response`, `attempt.refused`), `relay_stack.feed_incomplete`, or a
 * `request.forwarded` / `response.returned` with a stack member.
 */
export function isStackEventLog(events: readonly Json[]): boolean {
  return events.some((event) => {
    const type = eventType(event);
    if (
      type === EVENT_ATTEMPT_STARTED ||
      type === EVENT_RELAY_STACK_APPENDED ||
      type === EVENT_RELAY_STACK_CHANGED ||
      type === EVENT_UPSTREAM_RESPONSE ||
      type === EVENT_ATTEMPT_REFUSED ||
      type === EVENT_RELAY_STACK_FEED_INCOMPLETE
    ) {
      return true;
    }
    if (type === EVENT_REQUEST_FORWARDED) return hasAnyMember(event, STACK_FORWARDED_MEMBERS);
    if (type === EVENT_RESPONSE_RETURNED) return hasAnyMember(event, STACK_RETURNED_MEMBERS);
    return false;
  });
}

function hasAnyMember(event: Json, names: readonly string[]): boolean {
  return names.some((name) => get(event, name) !== undefined);
}

/** The `type` of an event object, or undefined when it is not an event at all. */
export function eventType(event: Json): string | undefined {
  const type = isObject(event) ? get(event, "type") : undefined;
  return typeof type === "string" ? type : undefined;
}

/** A reason an event log is not a valid §7 event log. */
export type EventLogProblem =
  | "invalid_event_log"
  | "first_event_must_be_request_received"
  | "missing_required_event"
  | "invalid_event"
  | "refused_receipt_forwarded"
  | "applied_receipt_not_forwarded"
  | "duplicate_policy_outcome"
  | "policy_outcome_position"
  | "modified_without_forwarded"
  | "modified_position"
  // Relay-stack receipts (S26):
  | "stack_event_repeated"
  | "returned_not_last"
  | "stack_relay_policy"
  | "stack_v1_event"
  | "attempt_number"
  | "attempt_order"
  | "attempt_incomplete"
  | "outside_attempt"
  | "attempt_refused_code"
  | "stack_relay_identity"
  | "stack_returned_without_vendor"
  | "egress_limit_not_replaced"
  | "served_attempt_missing"
  | "served_attempt_not_eof"
  | "served_status_mismatch"
  | "served_client_left_mismatch"
  | "served_digest_mismatch"
  | "served_codex_mismatch"
  | "feed_incomplete_position"
  | "unrecorded_without_feed_incomplete"
  | "peer_entry_position"
  // An entry's outer receipt of a forwarded request (docs/confidential-lane-stack-routing.md §4.8):
  | "peer_foreign_event"
  | "peer_order"
  | "peer_served_attempt";

export interface EventLogIssue {
  readonly code: EventLogProblem;
  readonly message: string;
}

/**
 * Check an event log against §7.3–§7.5 and Gray's relay-policy rules:
 *
 * 1. it is a non-empty array of flat event objects with a string `type`;
 * 2. the first event is `request.received` (§7.3);
 * 3. `request.received` and `response.returned` are present (§7.4);
 * 4. `request.forwarded` is required unless the receipt is a refusal — an `upstream.verified`
 *    `failed` + `required: true` (§7.5, PAG's rule) or a `relay_policy.refused` (Gray's addition);
 * 5. `relay_policy.refused` and `request.forwarded` never appear together: a refusal forwarded
 *    nothing;
 * 6. `relay_policy.applied` always appears with `request.forwarded`;
 * 7. at most one `relay_policy.*` event, and never one of each;
 * 8. a `relay_policy.*` event sits after `request.received` and before `request.forwarded` (when
 *    present) and `response.returned`;
 * 9. every `request.modified` event sits after `request.received`, before `relay_policy.applied`
 *    and `request.forwarded`, and a forwarded receipt that declares modifications has a
 *    `request.forwarded` event (a refusal forwarded nothing, so it cannot declare one);
 * 10. every known event matches its shape; unknown types are accepted (verifiers ignore them, §7.4).
 *
 * A relay-stack log ([`isStackEventLog`]) keeps rules 1, 2 and 10 and replaces 3–9 with the attempt
 * grammar of [`checkStackOrder`].
 */
export function checkEventLog(events: readonly Json[]): readonly EventLogIssue[] {
  const issues: EventLogIssue[] = [];
  const stack = isStackEventLog(events);
  const types: (string | undefined)[] = [];
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index] as Json;
    const type = eventType(event);
    types.push(type);
    if (type === undefined) {
      issues.push({ code: "invalid_event_log", message: `event ${index} is not an object with a string type` });
      continue;
    }
    const problem = checkEvent(event, type);
    if (problem !== null) issues.push({ code: "invalid_event", message: `event ${index} (${type}): ${problem}` });
  }
  if (events.length === 0) {
    issues.push({ code: "invalid_event_log", message: "the event log is empty" });
    return issues;
  }
  if (types[0] !== EVENT_REQUEST_RECEIVED) {
    issues.push({ code: "first_event_must_be_request_received", message: `first event is ${String(types[0])}` });
  }
  if (isPeerEventLog(events)) {
    checkPeerOrder(events, types, issues);
    return issues;
  }
  if (stack) {
    checkStackOrder(events, types, issues);
    return issues;
  }

  const received = types.indexOf(EVENT_REQUEST_RECEIVED);
  const forwarded = types.indexOf(EVENT_REQUEST_FORWARDED);
  const returned = types.indexOf(EVENT_RESPONSE_RETURNED);
  const policyIndexes = types.flatMap((type, index) =>
    type === EVENT_RELAY_POLICY_APPLIED || type === EVENT_RELAY_POLICY_REFUSED ? [index] : [],
  );
  const modifiedIndexes = types.flatMap((type, index) => (type === EVENT_REQUEST_MODIFIED ? [index] : []));
  const appliedIndex = types.indexOf(EVENT_RELAY_POLICY_APPLIED);
  const refused = policyIndexes.some((index) => types[index] === EVENT_RELAY_POLICY_REFUSED);
  const applied = types.some((type) => type === EVENT_RELAY_POLICY_APPLIED);
  const upstreamFailedRequired = events.some((event) => {
    if (eventType(event) !== EVENT_UPSTREAM_VERIFIED) return false;
    return get(event, "result") === "failed" && get(event, "required") === true;
  });

  if (returned < 0) issues.push({ code: "missing_required_event", message: `missing ${EVENT_RESPONSE_RETURNED}` });
  if (forwarded < 0 && !refused && !upstreamFailedRequired) {
    issues.push({ code: "missing_required_event", message: `missing ${EVENT_REQUEST_FORWARDED}` });
  }
  if (refused && forwarded >= 0) {
    issues.push({ code: "refused_receipt_forwarded", message: "a relay_policy.refused receipt has no request.forwarded (§7.5)" });
  }
  if (applied && forwarded < 0) {
    issues.push({ code: "applied_receipt_not_forwarded", message: "relay_policy.applied without request.forwarded" });
  }
  if (policyIndexes.length > 1) {
    issues.push({ code: "duplicate_policy_outcome", message: "more than one relay_policy.* event" });
  }
  if (modifiedIndexes.length > 0 && forwarded < 0) {
    issues.push({ code: "modified_without_forwarded", message: "request.modified without request.forwarded" });
  }
  for (const index of modifiedIndexes) {
    if (received >= 0 && index < received) {
      issues.push({ code: "modified_position", message: "request.modified precedes request.received" });
    }
    if (appliedIndex >= 0 && index > appliedIndex) {
      issues.push({ code: "modified_position", message: "request.modified follows relay_policy.applied" });
    }
    if (forwarded >= 0 && index > forwarded) {
      issues.push({ code: "modified_position", message: "request.modified follows request.forwarded" });
    }
    if (returned >= 0 && index > returned) {
      issues.push({ code: "modified_position", message: "request.modified follows response.returned" });
    }
  }
  for (const index of policyIndexes) {
    const type = types[index];
    if (received >= 0 && index < received) {
      issues.push({ code: "policy_outcome_position", message: `${String(type)} precedes request.received` });
    }
    if (forwarded >= 0 && index > forwarded) {
      issues.push({ code: "policy_outcome_position", message: `${String(type)} follows request.forwarded` });
    }
    if (returned >= 0 && index > returned) {
      issues.push({ code: "policy_outcome_position", message: `${String(type)} follows response.returned` });
    }
  }
  return issues;
}

/** Whether `events` is an entry's outer receipt of a forwarded request: it carries a `peer.forwarded`, `peer.answered` or `peer.failed`. */
export function isPeerEventLog(events: readonly Json[]): boolean {
  return events.some((event) => {
    const type = eventType(event);
    return type === EVENT_PEER_FORWARDED || type === EVENT_PEER_ANSWERED || type === EVENT_PEER_FAILED;
  });
}

/**
 * The outer receipt's grammar (docs/confidential-lane-stack-routing.md §4.8), each violation with its own code:
 *
 *     request.received
 *     ( peer.forwarded  ( peer.answered | peer.failed ) )+
 *     response.returned                                                (the relay-stack form)
 *
 * - the attempts are the entry's own numbers, never falling (an attempt at another kind of route between two peer
 *   attempts is not in this receipt; a number repeats for the relay's next origin), and each `peer.forwarded` is
 *   answered by the next event, of the same `n` (`peer_order`);
 * - no event of another grammar is in it: the attempt's own record is the stack VM's inner receipt (`peer_foreign_event`);
 * - `response.returned` is once and last, and its `served_attempt` is an attempt the hop answered (`peer_served_attempt`).
 */
function checkPeerOrder(events: readonly Json[], types: readonly (string | undefined)[], issues: EventLogIssue[]): void {
  const push = (code: EventLogProblem, message: string): void => {
    issues.push({ code, message });
  };
  const returned = types.flatMap((type, index) => (type === EVENT_RESPONSE_RETURNED ? [index] : []));
  if (types.filter((type) => type === EVENT_REQUEST_RECEIVED).length > 1) push("stack_event_repeated", "request.received appears more than once");
  if (returned.length === 0) push("missing_required_event", `missing ${EVENT_RESPONSE_RETURNED}`);
  if (returned.length > 1) push("stack_event_repeated", "response.returned appears more than once");
  if (returned.length > 0 && returned.at(-1) !== events.length - 1) push("returned_not_last", "response.returned is not the last event");
  const answered = new Set<bigint>();
  let last = 0n;
  let open: bigint | null = null;
  for (let index = 1; index < events.length; index += 1) {
    const type = types[index];
    const event = events[index] as Json;
    if (type === EVENT_RESPONSE_RETURNED) continue;
    if (type !== EVENT_PEER_FORWARDED && type !== EVENT_PEER_ANSWERED && type !== EVENT_PEER_FAILED) {
      push("peer_foreign_event", `event ${index} (${String(type)}) is not in an outer receipt's grammar`);
      continue;
    }
    const n = get(event, "n");
    if (typeof n !== "bigint") continue;
    if (type === EVENT_PEER_FORWARDED) {
      if (open !== null) push("peer_order", `attempt ${open} has no answer before attempt ${n} was forwarded`);
      // The same number again is the relay's next origin, tried within the attempt after a dial that sent nothing.
      if (n < last) push("peer_order", `attempt ${n} does not follow attempt ${last}`);
      last = n;
      open = n;
      continue;
    }
    if (open !== n) push("peer_order", `event ${index} (${type}) answers attempt ${n}, which is not the one forwarded last`);
    else if (type === EVENT_PEER_ANSWERED) answered.add(n);
    open = null;
  }
  if (open !== null) push("peer_order", `attempt ${open} has no answer`);
  if (last === 0n) push("peer_order", "an outer receipt forwards at least one attempt");
  const served = returned.length === 0 ? undefined : get(events[returned.at(-1)!] as Json, "served_attempt");
  if (typeof served === "bigint" && !answered.has(served)) push("peer_served_attempt", `served_attempt ${served} is not an attempt the hop answered`);
}

/** Where an open attempt group is: what its last grammar event was. */
type AttemptStage = "started" | "modified" | "appended" | "changed" | "forwarded";

/** The grammar event an attempt stage was reached by, for an order message. */
const STAGE_EVENTS: Readonly<Record<AttemptStage, string>> = Object.freeze({
  started: EVENT_ATTEMPT_STARTED,
  modified: EVENT_REQUEST_MODIFIED,
  appended: EVENT_RELAY_STACK_APPENDED,
  changed: EVENT_RELAY_STACK_CHANGED,
  forwarded: EVENT_REQUEST_FORWARDED,
});

/**
 * The relay-stack attempt grammar (plan S26), each violation with its own code:
 *
 *     request.received
 *     peer.entry?
 *     ( attempt.started  request.modified*  relay_stack.appended?  relay_stack.changed?  request.forwarded  upstream.response
 *     | attempt.started  request.modified*  relay_stack.appended?  relay_stack.changed?  request.forwarded  attempt.refused   (a dial code)
 *     | attempt.started  attempt.refused                                                                                        (a check code) )*
 *     relay_stack.feed_incomplete?
 *     response.returned
 *
 * - a stack VM's receipt of a request an entry forwarded (§4.8) names the entry once, in `peer.entry` right after
 *   `request.received` (`peer_entry_position`, `stack_event_repeated`);
 * - `request.received` is first (checked by the caller) and once, `response.returned` once and the
 *   last event of the log (`stack_event_repeated`, `returned_not_last`, `missing_required_event`);
 * - attempts are numbered 1..k in log order, and an attempt's `relay_stack.appended`,
 *   `relay_stack.changed` and `attempt.refused` carry its number (`attempt_number`);
 * - inside a group the events come in the order above (`attempt_order`), a group ends with
 *   `upstream.response` or `attempt.refused` before the next group or `response.returned`
 *   (`attempt_incomplete`), and no group event stands outside a group (`outside_attempt`);
 * - an `attempt.refused` after `request.forwarded` names a dial code (egress accepted the call and
 *   could not reach the vendor) and one straight after `attempt.started` a check code
 *   (`attempt_refused_code`);
 * - no `attempt.started` names the relay's account or proxy and no `request.forwarded` carries
 *   `headers_sha256` ([`STACK_RELAY_IDENTITY_MEMBERS`], `stack_relay_identity`): a receipt does not
 *   reveal which of the relay's accounts served it (owner, 2026-10-29); a refusal's code says on its own
 *   when egress knew no credential (`stack_credential_unknown`);
 * - no `relay_policy.*` (S23: no policy module runs for a stack relay; `stack_relay_policy`), and every
 *   `request.forwarded` and `response.returned` has the stack form (`stack_v1_event`);
 * - when no attempt got a response head from the vendor, the client got Gray's fixed error, so
 *   `replaced_error` is true (`stack_returned_without_vendor`);
 * - when egress ran out of its stack memory budget (an `upstream.response` ending `egress_limit`, or an
 *   `attempt.refused` with code `egress_limit`), the entry failed closed and released no later answer,
 *   so `replaced_error` is true (`egress_limit_not_replaced`), unless the client had left
 *   (`served_as: client_left`) the attempt the cut hit, or an earlier one;
 * - when nothing was replaced, the client's answer is tied to the served attempt (S32): that attempt
 *   is in the log with an `upstream.response` (`served_attempt_missing`) that ended `eof`
 *   (`served_attempt_not_eof`), and `response.returned`'s `events_sha256` equals its `events_sha256`,
 *   or its `body_sha256` the attempt's `body_sha256` (`served_digest_mismatch`; a vendor error the
 *   client got is that attempt's body, status ≥ 400). A stream Gray ended with its error frame names
 *   the attempt whose events it released but is not tied (`replaced_error`). A buffered Codex
 *   answer (`served_as: codex_terminal_response`) is the terminal event's `response`, which no digest
 *   determines: the attempt must be a Codex call whose answer was an event stream
 *   (`served_codex_mismatch`). A tied answer's `status` is the attempt's (`served_status_mismatch`).
 *   A body is tied by its digest even when the attempt's end is `unrecorded`: egress writes its `body`
 *   record once it held the whole body.
 *   A client that left before any answer (`client_left` with no served attempt) is exempt from
 *   `stack_returned_without_vendor` and `egress_limit_not_replaced`: it got nothing.
 *   An answer the client left mid-way (`served_as: client_left`) is not tied: for events, its attempt
 *   answered with an event stream (an answer cut at `egress_limit` has no digest and counts by its
 *   response head); for a body, with a body egress digested (a non-stream answer is released only once
 *   its digest matched, S24), or as a Codex call with an event stream (a buffered Codex request, D129,
 *   gets the terminal response's JSON); else `served_client_left_mismatch`. The attempt may have ended for any
 *   reason (when the client leaves, the container may close its egress call at any moment, so
 *   `relay_closed` and `vendor_reset` happen), its end unrecorded included (then, as for a cut, only its
 *   response head is known);
 * - when the entry's record of the relay's calls stopped before egress's `done`, `relay_stack.feed_incomplete`
 *   says so once, after every attempt group (`feed_incomplete_position`); an attempt whose end is
 *   `unrecorded` is one that record left open, so the event follows it (`unrecorded_without_feed_incomplete`).
 *
 * Other types (`upstream.verified`, unknown extensions) are not part of the grammar and may stand
 * anywhere between `request.received` and `response.returned`, as §7.4 lets extensions stand.
 */
function checkStackOrder(events: readonly Json[], types: readonly (string | undefined)[], issues: EventLogIssue[]): void {
  const push = (code: EventLogProblem, message: string): void => {
    issues.push({ code, message });
  };
  const indexesOf = (type: string): number[] => types.flatMap((entry, index) => (entry === type ? [index] : []));

  if (indexesOf(EVENT_REQUEST_RECEIVED).length > 1) push("stack_event_repeated", "request.received appears more than once");
  const returned = indexesOf(EVENT_RESPONSE_RETURNED);
  if (returned.length === 0) push("missing_required_event", `missing ${EVENT_RESPONSE_RETURNED}`);
  if (returned.length > 1) push("stack_event_repeated", "response.returned appears more than once");
  if (returned.length > 0 && returned.at(-1) !== events.length - 1) push("returned_not_last", "response.returned is not the last event");
  if (types.some((type) => type === EVENT_RELAY_POLICY_APPLIED || type === EVENT_RELAY_POLICY_REFUSED)) {
    push("stack_relay_policy", "a relay-stack receipt carries no relay_policy.* event (S23)");
  }

  const entries = indexesOf(EVENT_PEER_ENTRY);
  if (entries.length > 1) push("stack_event_repeated", "peer.entry appears more than once");
  if (entries.some((index) => index !== 1)) push("peer_entry_position", "peer.entry is the event right after request.received (§4.8)");

  let open: { n: bigint | null; stage: AttemptStage } | null = null;
  let next = 1n;
  let vendorAnswered = false;
  // Where the entry's record of the relay's calls stopped (relay_stack.feed_incomplete), and the
  // upstream.response events whose end it never recorded (`unrecorded`).
  let feedIncompleteAt: number | null = null;
  const unrecordedAt: number[] = [];
  // The attempts whose call or answer egress cut at its memory budget (egress_limit).
  const egressLimitedAt: bigint[] = [];
  // Per attempt number: its forwarded path and its upstream.response, for the served-attempt tie.
  const attemptsByNumber = new Map<bigint, { path: Json | undefined; upstream: Json | undefined }>();
  const sameAttempt = (index: number, type: string): void => {
    const n = get(events[index] as Json, "n");
    if (open !== null && open.n !== null && n !== open.n) {
      push("attempt_number", `${type} at event ${index} names attempt ${String(n)} inside attempt ${String(open.n)}`);
    }
  };
  const outside = (index: number, type: string): void => push("outside_attempt", `${type} at event ${index} is outside an attempt`);
  const close = (): void => {
    open = null;
  };

  for (let index = 0; index < events.length; index += 1) {
    const type = types[index];
    const event = events[index] as Json;
    if ((type === EVENT_REQUEST_FORWARDED && !hasAnyMember(event, STACK_FORWARDED_MEMBERS)) || (type === EVENT_RESPONSE_RETURNED && !hasAnyMember(event, STACK_RETURNED_MEMBERS))) {
      push("stack_v1_event", `event ${index} (${type}) has the single-forward form in a relay-stack receipt`);
    }
    const identity = type !== undefined && Object.hasOwn(STACK_RELAY_IDENTITY_MEMBERS, type) ? STACK_RELAY_IDENTITY_MEMBERS[type]!.filter((name) => get(event, name) !== undefined) : [];
    if (identity.length > 0) push("stack_relay_identity", `event ${index} (${type}) carries ${identity.join(", ")}, which names or fingerprints the relay's account`);
    switch (type) {
      case EVENT_ATTEMPT_STARTED: {
        if (open !== null) {
          push("attempt_incomplete", `attempt ${String(open.n)} has no upstream.response or attempt.refused before event ${index}`);
          close();
        }
        if (feedIncompleteAt !== null) push("feed_incomplete_position", `attempt.started at event ${index} follows relay_stack.feed_incomplete, after which nothing was recorded`);
        const n = get(event, "n");
        const number = typeof n === "bigint" ? n : null;
        if (number !== next) push("attempt_number", `attempt.started at event ${index} is attempt ${String(n)}, expected ${next}`);
        // Count on from the number written, so one gap is one issue rather than one per later attempt.
        next = (number ?? next) + 1n;
        open = { n: number, stage: "started" };
        if (number !== null && !attemptsByNumber.has(number)) attemptsByNumber.set(number, { path: undefined, upstream: undefined });
        break;
      }
      case EVENT_REQUEST_MODIFIED:
        if (open === null) outside(index, type);
        else if (open.stage !== "started" && open.stage !== "modified") push("attempt_order", `request.modified at event ${index} follows ${STAGE_EVENTS[open.stage]}`);
        else open.stage = "modified";
        break;
      case EVENT_RELAY_STACK_APPENDED:
        if (open === null) {
          outside(index, type);
          break;
        }
        sameAttempt(index, type);
        if (open.stage !== "started" && open.stage !== "modified") push("attempt_order", `relay_stack.appended at event ${index} follows ${open.stage === "appended" ? "another relay_stack.appended" : STAGE_EVENTS[open.stage]}`);
        else open.stage = "appended";
        break;
      case EVENT_RELAY_STACK_CHANGED:
        if (open === null) {
          outside(index, type);
          break;
        }
        sameAttempt(index, type);
        if (open.stage === "changed" || open.stage === "forwarded") push("attempt_order", `relay_stack.changed at event ${index} follows ${open.stage === "changed" ? "another relay_stack.changed" : STAGE_EVENTS[open.stage]}`);
        else open.stage = "changed";
        break;
      case EVENT_REQUEST_FORWARDED:
        if (open === null) outside(index, type);
        else if (open.stage === "forwarded") push("attempt_order", `a second request.forwarded at event ${index} in attempt ${String(open.n)}`);
        else {
          open.stage = "forwarded";
          const record = open.n === null ? undefined : attemptsByNumber.get(open.n);
          if (record !== undefined) record.path = get(event, "path");
        }
        break;
      case EVENT_UPSTREAM_RESPONSE:
        if (open === null) {
          outside(index, type);
          break;
        }
        if (open.stage !== "forwarded") push("attempt_order", `upstream.response at event ${index} comes before request.forwarded`);
        else if (get(event, "status") !== null && get(event, "status") !== undefined) vendorAnswered = true;
        if (get(event, "end_reason") === "egress_limit") egressLimitedAt.push(open.n ?? 0n);
        if (get(event, "end_reason") === "unrecorded") unrecordedAt.push(index);
        if (open.stage === "forwarded" && open.n !== null) {
          const record = attemptsByNumber.get(open.n);
          if (record !== undefined) record.upstream = event;
        }
        close();
        break;
      case EVENT_ATTEMPT_REFUSED: {
        if (open === null) {
          outside(index, type);
          break;
        }
        sameAttempt(index, type);
        const code = get(event, "code");
        if (open.stage === "modified" || open.stage === "appended" || open.stage === "changed") {
          push("attempt_order", `attempt.refused at event ${index} follows the attempt's ops but no request.forwarded`);
        } else if (open.stage === "forwarded" && !(STACK_DIAL_REFUSAL_CODES as readonly unknown[]).includes(code)) {
          push("attempt_refused_code", `attempt.refused at event ${index} follows request.forwarded but ${String(code)} is not a dial failure`);
        } else if (open.stage === "started" && !(STACK_CHECK_REFUSAL_CODES as readonly unknown[]).includes(code)) {
          push("attempt_refused_code", `attempt.refused at event ${index} has no request.forwarded but ${String(code)} is not a check refusal`);
        }
        if (code === "egress_limit") egressLimitedAt.push(open.n ?? 0n);
        close();
        break;
      }
      case EVENT_RELAY_STACK_FEED_INCOMPLETE:
        if (open !== null) {
          push("attempt_incomplete", `attempt ${String(open.n)} has no upstream.response or attempt.refused before relay_stack.feed_incomplete at event ${index}`);
          close();
        }
        if (feedIncompleteAt !== null) push("feed_incomplete_position", `relay_stack.feed_incomplete appears again at event ${index}`);
        else feedIncompleteAt = index;
        break;
      case EVENT_RESPONSE_RETURNED:
        if (open !== null) {
          push("attempt_incomplete", `attempt ${String(open.n)} has no upstream.response or attempt.refused before response.returned`);
          close();
        }
        break;
      default:
        break;
    }
  }
  if (open !== null) {
    push("attempt_incomplete", `attempt ${String((open as { n: bigint | null }).n)} is not closed`);
    close();
  }
  for (const index of unrecordedAt) {
    if (feedIncompleteAt === null || feedIncompleteAt < index) {
      push("unrecorded_without_feed_incomplete", `upstream.response at event ${index} ends unrecorded, but no relay_stack.feed_incomplete follows to say the record stopped`);
    }
  }

  const last = returned.at(-1);
  // A client that left before any answer (client_left, no served attempt) got nothing: neither rule below
  // applies, and the attempts stay as they happened.
  const leftEarly = last !== undefined && get(events[last] as Json, "served_as") === "client_left" && get(events[last] as Json, "served_attempt") === null;
  if (last !== undefined && !leftEarly && !vendorAnswered && get(events[last] as Json, "replaced_error") === false) {
    push("stack_returned_without_vendor", "no attempt got a response from the vendor, so the client's answer is Gray's error (replaced_error: true)");
  }
  // A client that left (client_left) never got Gray's error: a budget cut of the attempt it left, or of a
  // later one, came after it was gone, at a time the entry does not control. A cut of an earlier attempt
  // is not exempt: the entry fails closed on it, so it released nothing after it.
  const leftAt = last === undefined || get(events[last] as Json, "served_as") !== "client_left" ? undefined : get(events[last] as Json, "served_attempt");
  const leftBeforeCut = leftEarly || (typeof leftAt === "bigint" && egressLimitedAt.every((n) => n >= leftAt));
  if (last !== undefined && egressLimitedAt.length > 0 && !leftBeforeCut && get(events[last] as Json, "replaced_error") === false) {
    push("egress_limit_not_replaced", "egress ran out of its memory budget (egress_limit) and the entry fails closed, so the client's answer is Gray's error (replaced_error: true)");
  }
  if (last !== undefined) checkServedAttempt(events[last] as Json, attemptsByNumber, push);
}

/** The S32 tie of a `response.returned` whose answer was not replaced to the attempt that served it. */
function checkServedAttempt(
  returned: Json,
  attempts: ReadonlyMap<bigint, { path: Json | undefined; upstream: Json | undefined }>,
  push: (code: EventLogProblem, message: string) => void,
): void {
  const served = get(returned, "served_attempt");
  if (get(returned, "replaced_error") !== false || typeof served !== "bigint") return;
  const upstream = attempts.get(served)?.upstream;
  if (upstream === undefined) {
    push("served_attempt_missing", `response.returned names attempt ${served}, which has no upstream.response in the log`);
    return;
  }
  const end = get(upstream, "end_reason");
  if (get(returned, "served_as") === "client_left") {
    // The client got a prefix of the attempt's answer. Not tied, so how the attempt ended does not
    // matter: the container may close its egress call at any moment once the client left.
    // An answer egress cut at its budget carries no digest, nor does one whose end the entry never
    // recorded (an event stream's chain), so only its response head is known.
    const headOnly = (end === "egress_limit" || end === "unrecorded") && get(upstream, "status") !== null;
    if (get(returned, "events_sha256") !== undefined) {
      if (get(upstream, "events_sha256") === undefined && !headOnly) {
        push("served_client_left_mismatch", `attempt ${served} did not answer with an event stream, so a client cannot have left it mid-stream`);
      }
    } else {
      // A non-stream answer is released only once egress's body digest matched it (S24), so a body the
      // client left mid-way is one egress digested whole, which has a response head. A buffered Codex
      // request (D129) gets the terminal response's JSON once every event matched: a Codex call answered
      // with events.
      const body = get(upstream, "body_sha256") !== undefined;
      const codex = attempts.get(served)?.path === STACK_CODEX_RESPONSES_PATH && (get(upstream, "events_sha256") !== undefined || (end === "unrecorded" && headOnly));
      if (!body && !codex) {
        push("served_client_left_mismatch", `attempt ${served} did not answer with a body egress digested, nor is it a Codex event stream, so a client cannot have left it mid-body`);
      }
    }
    return;
  }
  // A body is tied by egress's `body` digest, written once egress held the whole body, so an unrecorded
  // end does not untie it; an event stream's tie needs its recorded `eof`.
  const bodyTied = end === "unrecorded" && get(returned, "body_sha256") !== undefined && get(returned, "served_as") === undefined;
  if (end !== "eof" && !bodyTied) {
    push("served_attempt_not_eof", `attempt ${served} served the answer but its upstream.response ended ${String(end)}, not eof`);
    return;
  }
  if (get(returned, "served_as") === "codex_terminal_response") {
    if (attempts.get(served)?.path !== STACK_CODEX_RESPONSES_PATH || get(upstream, "events_sha256") === undefined) {
      push("served_codex_mismatch", `attempt ${served} is not a Codex call answered by an event stream, so it cannot serve a codex_terminal_response`);
    }
  } else {
    const member = get(returned, "events_sha256") !== undefined ? "events_sha256" : "body_sha256";
    if (get(upstream, member) === undefined || get(upstream, member) !== get(returned, member)) {
      push("served_digest_mismatch", `response.returned's ${member} is not attempt ${served}'s upstream.response ${member}`);
    }
  }
  if (get(returned, "status") !== get(upstream, "status")) {
    push("served_status_mismatch", `the client got status ${String(get(returned, "status"))}, attempt ${served}'s vendor answered ${String(get(upstream, "status"))}`);
  }
}

/**
 * The shape problem of one event, or null when it has its type's shape (unknown types have none to
 * check, §7.4): the per-event part of [`checkEventLog`], for a producer that validates each event it
 * builds from egress's feed before it adds it (S32) rather than catching a constructor's throw.
 */
export function checkEventShape(event: Json): string | null {
  const type = eventType(event);
  if (type === undefined) return "not an object with a string type";
  return checkEvent(event, type);
}

/** The shape problem of one known event, or null (unknown types are accepted as they are). */
function checkEvent(event: Json, type: string): string | null {
  let schemas: readonly z.ZodType[];
  if (type === EVENT_REQUEST_FORWARDED && hasAnyMember(event, STACK_FORWARDED_MEMBERS)) {
    schemas = [stackRequestForwardedSchema];
  } else if (type === EVENT_RESPONSE_RETURNED && hasAnyMember(event, STACK_RETURNED_MEMBERS)) {
    schemas = [stackResponseReturnedSchema];
  } else if (type === EVENT_REQUEST_RECEIVED || type === EVENT_REQUEST_FORWARDED || type === EVENT_RESPONSE_RETURNED) {
    schemas = [bodyHashEventSchema];
  } else if (type === EVENT_ATTEMPT_STARTED) {
    schemas = [attemptStartedSchema];
  } else if (type === EVENT_RELAY_STACK_APPENDED) {
    schemas = [relayStackAppendedSchema];
  } else if (type === EVENT_RELAY_STACK_CHANGED) {
    schemas = [relayStackChangedSchema];
  } else if (type === EVENT_UPSTREAM_RESPONSE) {
    schemas = [upstreamResponseSchema];
  } else if (type === EVENT_ATTEMPT_REFUSED) {
    schemas = [attemptRefusedSchema];
  } else if (type === EVENT_RELAY_STACK_FEED_INCOMPLETE) {
    schemas = [relayStackFeedIncompleteSchema];
  } else if (type === EVENT_PEER_ENTRY) {
    schemas = [peerEntrySchema];
  } else if (type === EVENT_PEER_FORWARDED) {
    schemas = [peerForwardedSchema];
  } else if (type === EVENT_PEER_ANSWERED) {
    schemas = [peerAnsweredSchema];
  } else if (type === EVENT_PEER_FAILED) {
    schemas = [peerFailedSchema];
  } else if (type === EVENT_UPSTREAM_VERIFIED) {
    schemas = [upstreamVerifiedSchema, upstreamVerificationFailedSchema];
  } else if (type === EVENT_RELAY_POLICY_APPLIED) {
    schemas = [relayPolicyAppliedSchema];
  } else if (type === EVENT_RELAY_POLICY_REFUSED) {
    schemas = [relayPolicyRefusedSchema];
  } else if (type === EVENT_REQUEST_MODIFIED) {
    schemas = [requestModifiedSchema];
  } else {
    return null;
  }
  const results = schemas.map((schema) => schema.safeParse(event));
  const failure = results.find((result) => !result.success);
  if (failure === undefined) return null;
  if (results.some((result) => result.success)) {
    // §7.5: a failed event carries `reason` *instead of* a session.
    const failsWithSession = get(event, "result") === "failed" && get(event, "session_id") !== undefined;
    return failsWithSession ? "a failed upstream.verified event carries no session_id" : null;
  }
  // A value outside a closed set names the value too, so a receipt from a newer service that uses a value
  // this verifier does not know fails with that value in the message.
  return failure.error.issues
    .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}${issue.code === "invalid_value" ? ` (this receipt has ${shownValue(valueAt(event, issue.path))})` : ""}`)
    .join("; ");
}

function valueAt(event: Json, path: readonly PropertyKey[]): Json | undefined {
  let value: Json | undefined = event;
  for (const key of path) {
    if (value === undefined || value === null || typeof value !== "object") return undefined;
    value = Array.isArray(value) ? value[Number(key)] : get(value, String(key));
  }
  return value;
}

function shownValue(value: Json | undefined): string {
  if (value === undefined) return "nothing";
  if (typeof value === "string") {
    const quoted = JSON.stringify(value);
    return quoted.length > 80 ? `${quoted.slice(0, 77)}..."` : quoted;
  }
  if (value === null || typeof value !== "object") return String(value);
  return Array.isArray(value) ? "an array" : "an object";
}

/** The first event of `type` in the log, or undefined. */
export function findEvent(events: readonly Json[], type: string): Json | undefined {
  return events.find((event) => eventType(event) === type);
}

/** Every event of `type` in the log, in order. */
export function findEvents(events: readonly Json[], type: string): readonly Json[] {
  return events.filter((event) => eventType(event) === type);
}
