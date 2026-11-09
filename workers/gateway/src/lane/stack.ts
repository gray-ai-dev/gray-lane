import {
  RELAY_APPEND_POSITIONS,
  RELAY_CHANGE_OPS,
  RELAY_CHANGE_VALUES,
  STACK_EGRESS_END_REASONS,
  attemptRefusedEvent,
  attemptStartedEvent,
  bodyHash,
  checkEventLog,
  relayStackAppendedEvent,
  relayStackChangedEvent,
  requestModifiedEvent,
  requestReceivedEvent,
  stackEventsSha256,
  stackHeadersSha256,
  stackRequestForwardedEvent,
  stackResponseReturnedEvent,
  upstreamResponseEvent,
  type ReceiptBuilder,
  type RelayAppend,
  type RelayChangeOp,
  type RelayStackChanges,
  type RequestModifiedOp,
  type StackDroppedKind,
  type StackEndReason,
  type StackFeedIncompleteReason,
  type StackRefusalCode,
  type StackServedAs,
} from "@gray/attest";
import { ApiError, ERROR_BODY_LIMIT } from "@gray/errors";
import { get, isObject, parseStrict, parseStrictBytes, type Json, type JsonObject } from "@gray/json";
import { DEFAULT_MAX_ITEMS, DEFAULT_MAX_TOTAL_BYTES, GRAY_LANE_REWRITES_V1, isPositionForProtocol, stackBodyDigest, stackEventDigest, stackStoreOff, type LaneProtocol } from "@gray/lane";
import {
  STACK_ATTEMPT_CLASSES,
  STACK_VENDOR_CODES,
  STACK_VIOLATION_BODY_FIELD_PATTERN,
  STACK_VIOLATION_HEADER_FIELD_PATTERN,
  type StackAttemptClass,
  type StackFaultBy,
  type StackFaultWhy,
  type StackVendorCode,
} from "@gray/lane-wire";
import type { StackTrace, StackTraceAttempt } from "@gray/request-index";
import { SseDecoder, SseFrames, type SseEvent } from "@gray/protocol";
import type { StreamTimers } from "../client.ts";
import { bytesBase64 } from "../crypto.ts";
import type { StackRelayAppend, StackRelayConfig, StackRelayRoute, StackVendor, StackViolationFound } from "./stack-config.ts";
import { STACK_CONVERSATION_HEADER, STACK_ROUTE_MODEL_HEADER } from "./stack-rewrite.ts";

/**
 * The entry's stack mode (docs/confidential-lane-supply-implementation.md S22–S27): one call to the
 * relay's own container is one `InferenceRun` attempt, and what of the container's answer reaches the
 * client is decided here, event by event, against the record of what the vendor sent.
 *
 * A call, in order (S23):
 *
 * 1. `PUT /v1/stack/requests/{rid}` on egress's control API: the client's bytes, raw query and
 *    behaviour headers, the route's vendor, the conversation's affinity token (S32a), the `RewriteSpec`
 *    the route's mapping and the relay's config allow, the attempt count and the request's deadline
 *    (S15, S32).
 * 2. `GET /v1/stack/requests/{rid}/events`: the feed of S17 records, read in the background for the
 *    whole call ({@link StackFeed}), each record checked against the receipt's shapes as it comes.
 * 3. `POST http://10.231.10.3:3000/<the protocol's path>?<the client's query>` on `RELAY` with the
 *    client's body with the required changes applied (`stack-rewrite.ts`), a few of its headers ({@link stackRelayHeaders}), `authorization: Bearer
 *    <inbound_token>` and `X-Gray-Request: <rid>`.
 *
 * The answer (S24). Nothing the container makes up may reach the client: an event is released only
 * when the feed holds an `event` record with the same S19 digest at the next position of the current
 * attempt, and what is released is Gray's own framing (`event:` with the event's type, its `data` text
 * as the container sent it, split into `data:` lines, a blank line). The container's own framing, its
 * `id`/`retry` fields and comments never reach the client; its data text does, verbatim, because an
 * honest container's is the vendor's own (re-serialising it would change bytes for nothing, and JCS
 * rounds an integer past 2^53). A non-stream answer is released as the container's body bytes once
 * their S19 digest (JCS) equals the feed's `body` record. Which of the two the answer is comes from
 * egress's `response` record (`stream`, S21b), never from the container's headers, all of which are
 * ignored; a container whose answer is the other kind fails closed.
 *
 * What the container may add and Gray drops: comments (the decoder never makes them events) and one
 * usage-only Chat chunk (`"choices":[]` with `usage`, the measured new-api behaviour the relay standard
 * names). A retry inside the container is followed (a new `attempt` record resets the position) only
 * while nothing of the answer was released. Anything else ends the answer: a mismatched, injected,
 * dropped or reordered event, a new attempt after a released event, an SSE field other than
 * `event`/`data`/`id`/`retry` (`@gray/protocol` `SseDecoder`, the decoder the conformance tool uses), or
 * an event whose record does not arrive within the hold bound (UPSTREAM_SILENCE_MS; ERROR_BODY_WAIT_MS
 * when nothing the feed shows can record it, `#match`).
 *
 * The receipt (S26) is written from the feeds of a request's calls and what its client got
 * ({@link addStackReceipt}).
 *
 * When the container's answer cannot be released (an error status, a fault before the first event,
 * a transport failure) the feed decides what the client gets ({@link StackCall.outcome}): the vendor's
 * own status and body when the last vendor attempt answered an error (`error_body`), Gray's fixed
 * `lane_relay_failed` when a vendor attempt was dialed and nothing of it can be released, and "not
 * dialed" when no attempt reached a vendor, which is the only case another route may be tried (S25).
 * "Not dialed" is decided only once the rid ended at egress (DELETE) and the feed reached `done` (S32):
 * until then the container may still make a vendor call egress accepts.
 */

/** The relay container's origin on `relay_in` (S2, S4 `GRAY_RELAY_LISTEN`); `RELAY` is bound to it. */
export const STACK_RELAY_ORIGIN = "http://10.231.10.3:3000";

/**
 * The control API's origin on the `EGRESS` binding. Egress routes `/v1/stack/` before any Host rule
 * (deploy/tee/egress/server.go `ServeHTTP`), so the host only names the call in workerd's own logs.
 */
export const STACK_EGRESS_ORIGIN = "http://egress";

/** The header that carries the rid through the container to egress (S16, S21.3). */
export const STACK_REQUEST_HEADER = "x-gray-request";

/** The lane's fixed error for a relay container whose answer Gray cannot release (S24). */
export const LANE_RELAY_FAILED = "lane_relay_failed";

/** The fault word, and the attempt's recorded code, of a container's decline before any vendor call (`relayDeclined`). */
export const RELAY_DECLINED = "relay_declined";

/** 502 `lane_relay_failed`: the container failed, or answered what its vendor attempts do not show. */
export function laneRelayFailed(): ApiError {
  return new ApiError(502, LANE_RELAY_FAILED).withMessage(
    "The relay's software did not return its provider's answer as the provider sent it, so Gray did not pass it on. Nothing it made up reached you; retry the request.",
  );
}

/**
 * Gray's keep-alive on a stack relay's stream (S32): an SSE comment for every protocol, where the main
 * lane gives an Anthropic client the API's own `ping` event (client.ts `keepAliveFrame`). Comments are
 * not events (S19), so the client's chain stays the vendor's.
 */
export const STACK_KEEP_ALIVE: Uint8Array = new TextEncoder().encode(": keep-alive\n\n");

/** The path each protocol is served at on the container (the relay standard, rule 1). */
export const STACK_RELAY_PATHS: Readonly<Record<LaneProtocol, string>> = Object.freeze({
  anthropic_messages: "/v1/messages",
  open_ai_chat: "/v1/chat/completions",
  open_ai_responses: "/v1/responses",
});

/**
 * The protocol's behaviour headers (S32): they change output limits, context, tools and price, so egress
 * requires each forwarded one to be the client's value plus only what the credential form needs, and the
 * registration carries them as the client sent them.
 */
const STACK_BEHAVIOUR_HEADERS: Readonly<Record<LaneProtocol, readonly string[]>> = Object.freeze({
  anthropic_messages: ["anthropic-version", "anthropic-beta"],
  open_ai_chat: ["openai-beta"],
  open_ai_responses: ["openai-beta"],
});

/**
 * The client headers the container is sent (S23's allowlist): the protocol's behaviour headers and the
 * two a relay may need to answer like the vendor (`accept`) or to present the client it serves
 * (`user-agent`, the relay standard's example request). Never the client's credential, its session
 * ids, its address, or anything Gray adds.
 */
const STACK_CLIENT_HEADERS: Readonly<Record<LaneProtocol, readonly string[]>> = Object.freeze({
  anthropic_messages: ["accept", "user-agent", ...STACK_BEHAVIOUR_HEADERS.anthropic_messages],
  open_ai_chat: ["accept", "user-agent", ...STACK_BEHAVIOUR_HEADERS.open_ai_chat],
  open_ai_responses: ["accept", "user-agent", ...STACK_BEHAVIOUR_HEADERS.open_ai_responses],
});

/**
 * The headers of the container call: the allowlisted client headers, the inbound token, the rid, the config route it
 * serves (`X-Gray-Route-Model`: the body's `model` is the upstream one, `stack-rewrite.ts`) and the request's
 * conversation (`X-Gray-Conversation`, absent when the client named no session).
 */
export function stackRelayHeaders(client: Headers, protocol: LaneProtocol, inboundToken: string, rid: string, routeModel: string, conversation?: string): Headers {
  const headers = new Headers({ "content-type": "application/json" });
  for (const name of STACK_CLIENT_HEADERS[protocol]) {
    const value = client.get(name);
    if (value !== null) headers.set(name, value);
  }
  headers.set("authorization", `Bearer ${inboundToken}`);
  headers.set(STACK_REQUEST_HEADER, rid);
  headers.set(STACK_ROUTE_MODEL_HEADER, routeModel);
  if (conversation !== undefined) headers.set(STACK_CONVERSATION_HEADER, conversation);
  return headers;
}

/**
 * The client headers an entry forwards over the peer hop (docs/confidential-lane-stack-routing.md section 4.5): every
 * header the stack VM's attempt reads from its request (`stackRelayHeaders`, whose list holds `stackBehaviourHeaders`'),
 * and no other: never the client's credential.
 */
export function stackPeerHeaders(client: Headers, protocol: LaneProtocol): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of STACK_CLIENT_HEADERS[protocol]) {
    const value = client.get(name);
    if (value !== null) out[name] = value;
  }
  return out;
}

/**
 * The registration's `headers` (S32): the behaviour headers the client sent and the container is sent,
 * under their lowercase names, each value as fetch's `Headers` reads it (a repeated header joined with
 * ", "). A header of another protocol never reaches the container, so it is not registered either.
 */
export function stackBehaviourHeaders(client: Headers, protocol: LaneProtocol): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of STACK_BEHAVIOUR_HEADERS[protocol]) {
    const value = client.get(name);
    if (value !== null) out[name] = value;
  }
  return out;
}

/**
 * The client's raw query (S32), without its `?`: sliced out of the request's URL text rather than
 * rebuilt through `URL`, so no escape is decoded or re-encoded (as `egressUrlOf` keeps a path); "" when
 * there is none.
 */
export function stackRawQuery(url: string): string {
  const at = url.indexOf("?");
  if (at < 0) return "";
  const hash = url.indexOf("#", at);
  return url.slice(at + 1, hash < 0 ? undefined : hash);
}

// ---------------------------------------------------------------------------------------------
// The registration (S15, S18, S23).
// ---------------------------------------------------------------------------------------------

/** S18's `RewriteSpec`, as the entry registers it. */
export interface StackRewriteSpec {
  readonly model: { readonly to: string };
  readonly cap?: { readonly field: string; readonly max: number };
  readonly set?: readonly { readonly path: string; readonly value: Json }[];
  readonly remove?: readonly string[];
  readonly append?: readonly StackRelayAppend[];
  /**
   * The receipt describes the relay's own changes (`relay_stack.changed`), so egress accepts them (docs/relay-request-
   * changes.md). Absent for a customer who chose relays that change nothing: egress then refuses any body change and
   * sends the vendor Gray's own headers.
   */
  readonly relay_changes?: true;
}

/**
 * The `RewriteSpec` of one stack route (S23): the route's upstream model; the config route's cap,
 * exactly as the relay was told it (C2-config's rule: never a per-request lower one, since the relay
 * can only obey its config); the sets egress requires (`store: false` on every OpenAI Chat and Responses route, so
 * nothing is stored under the relay's account, and on an OpenAI-compatible vendor's route whose row says it stores
 * (`stackStoreOff`; a vendor without stored completions is sent no `store` of Gray's); D129's Codex `stream: true` on a `chatgpt_codex` route; Chat's
 * `include_usage` on a stream, which Gray bills by); every removal
 * the published v1 policy lets a relay make for the protocol (the relay standard's rule 4 table); and
 * the relay's registered appends at the protocol's two positions. Egress refuses a spec whose append
 * names another protocol's position, so the appends are filtered by protocol, never rewritten. With
 * `relay_changes` the relay's own changes are accepted and described in the receipt, unless the customer opted out.
 */
export function stackRewriteSpec(input: {
  readonly protocol: LaneProtocol;
  readonly upstreamModel: string;
  readonly route: StackRelayRoute;
  readonly stream: boolean;
  readonly appends: readonly StackRelayAppend[];
  /** False for a customer who chose relays that change nothing (routing preference `relay_changes: "exclude"`). */
  readonly relayChanges: boolean;
}): StackRewriteSpec {
  const { protocol } = input;
  const set: { path: string; value: Json }[] = [];
  // No OpenAI request is stored under a relay's account (docs/relay-request-changes.md P2), Codex's included (D129).
  if ((protocol === "open_ai_chat" || protocol === "open_ai_responses") && stackStoreOff(input.route.vendor)) set.push({ path: "/store", value: false });
  if (protocol === "open_ai_responses" && input.route.vendor === "chatgpt_codex") set.push({ path: "/stream", value: true });
  if (protocol === "open_ai_chat" && input.stream) set.push({ path: "/stream_options/include_usage", value: true });
  const remove = GRAY_LANE_REWRITES_V1.protocols[protocol].filter((rule) => rule.op === "remove_member").map((rule) => rule.path);
  const append = input.appends.filter((entry) => isPositionForProtocol(protocol, entry.position));
  return {
    model: { to: input.upstreamModel },
    ...(input.route.cap === null ? {} : { cap: { field: input.route.cap.field, max: input.route.cap.max } }),
    ...(set.length === 0 ? {} : { set }),
    ...(remove.length === 0 ? {} : { remove }),
    ...(append.length === 0 ? {} : { append }),
    ...(input.relayChanges ? { relay_changes: true as const } : {}),
  };
}

/**
 * The config route a snapshot route is served by (section 8): the same requested model, protocol and
 * vendor, and the same upstream model, or null. A route whose config entry is missing or names another
 * upstream model is one the relay's container would route differently from Gray's snapshot (a version
 * between the two), so no attempt goes there.
 */
export function stackRouteOf(config: StackRelayConfig, route: { readonly model: string; readonly upstreamModel: string; readonly protocol: LaneProtocol; readonly vendor: StackVendor }): StackRelayRoute | null {
  return config.routes.find((r) => r.requested_model === route.model && r.protocol === route.protocol && r.vendor === route.vendor && r.upstream_model === route.upstreamModel) ?? null;
}

/**
 * The prompt bytes a relay's appends can add to one request of `protocol` (the hold's reserve, design
 * v2 §C.4 as the sealed-credential lane applies it): its DEFAULT_MAX_ITEMS largest templates at the
 * protocol's positions, at most DEFAULT_MAX_TOTAL_BYTES — egress's append limits, whose defaults are
 * these constants (S18, the parity test in deploy/tee/egress).
 */
export function stackAppendReserveBytes(protocol: LaneProtocol, appends: readonly StackRelayAppend[]): number {
  const largest = appends
    .filter((entry) => isPositionForProtocol(protocol, entry.position))
    .map((entry) => entry.bytes)
    .sort((left, right) => right - left)
    .slice(0, DEFAULT_MAX_ITEMS)
    .reduce((total, bytes) => total + bytes, 0);
  return Math.min(largest, DEFAULT_MAX_TOTAL_BYTES);
}

/** A rid: 128 random bits in lower hex (§1). */
export function newStackRid(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

// ---------------------------------------------------------------------------------------------
// The feed (S17).
// ---------------------------------------------------------------------------------------------

/** One vendor attempt of the call as the feed reports it. */
export interface StackFeedAttempt {
  readonly n: number;
  /** The `attempt` record: absent for a call refused before egress accepted it. */
  accepted: {
    readonly accountId: string;
    readonly proxyId: string | null;
    readonly method: string;
    readonly path: string;
    readonly querySha256: string;
    readonly headersSha256: string;
    readonly bodySha256: string;
    /** SHA-256 of the forwarded body's JCS form (S26 `body_jcs_sha256`). */
    readonly bodyJcsSha256: string;
    /** The `request.modified` ops egress reported (S18), as written. */
    readonly ops: readonly JsonObject[];
    readonly appended: readonly RelayAppend[];
    /**
     * The relay's own changes egress reported (its record's `changed`, docs/relay-request-changes.md), or null when
     * it changed nothing outside the declared rules: the receipt's `relay_stack.changed`.
     */
    readonly changed: RelayStackChanges | null;
  } | null;
  /**
   * The `refused` record: before acceptance (a check code, with the account egress resolved, null for
   * `stack_credential_unknown`), or after it (a dial code: the vendor was never reached, D72).
   */
  refused: { readonly code: string; readonly path: string | null; readonly header: string | null; readonly accountId: string | null; readonly proxyId: string | null } | null;
  /**
   * The `response` record. `stream` is egress's own decision whether it digests the answer event by event
   * (S17, S21b): the one source of whether the container's answer is read as a stream.
   */
  response: { readonly status: number; readonly headers: Readonly<Record<string, string>>; readonly stream: boolean } | null;
  /** The S19 digests of the vendor's events, in `seq` order. */
  readonly events: string[];
  body: { readonly digest: string; readonly bytes: number } | null;
  errorBody: Uint8Array | null;
  /**
   * The body egress forwarded to the vendor, the relay's changes included (`forwarded`, asked for by a backend's
   * registration only: docs/design/relay-debug-sharing.md): its bytes, or null bytes when egress left them out for its
   * budget; null without the record.
   */
  forwarded: { readonly bytes: Uint8Array | null; readonly size: number } | null;
  end: { readonly reason: StackEndReason; readonly bytes: number } | null;
  /**
   * How the call ended (S34 `STACK_ATTEMPT_CLASSES`), as egress wrote it on the last record (`end` or
   * `refused`), and the vendor error's code egress read (S35, `end` only; null for a 2xx answer).
   */
  class: StackAttemptClass | null;
  vendorCode: StackVendorCode | null;
  /** The entry's clock as it took the attempt's first record, its `response` and its last record (S43). */
  readonly at: number;
  responseAt: number | null;
  endedAt: number | null;
}

const LOWER_HEX_32 = /^[0-9a-f]{64}$/;

/**
 * The largest body a `forwarded` record carries: egress's -max-body-bytes, the lane's BODY_PARSE_MAX_BYTES (4 MiB): a
 * body over it is refused before it is forwarded (`egress_body_too_large`).
 */
export const STACK_FORWARDED_MAX_BYTES = 4 * 1024 * 1024;

/**
 * The most bytes of one feed line: the largest record is a `forwarded` one, base64 of at most
 * STACK_FORWARDED_MAX_BYTES with a few members around it; without it, an `error_body`, base64 of at most
 * ERROR_BODY_LIMIT (64 KiB, S17) bytes (twice the limit covers the base64 and the record). An `attempt` record with its
 * ops and appends is far smaller.
 */
const FEED_LINE_MAX = Math.max(2 * ERROR_BODY_LIMIT, 4 * Math.ceil(STACK_FORWARDED_MAX_BYTES / 3) + 1024);

/**
 * One rid's records, as the background reader takes them. Egress is Gray's own program, so a record
 * that does not parse, names an attempt out of order or numbers an event out of sequence is a broken
 * feed (`broken`), and nothing is released from a broken feed. So is a record the receipt could not
 * carry (S32): each attempt's receipt events are built as its records come, with `@gray/attest`'s own
 * constructors (the event shapes and their bounds), and an attempt's whole group is held to the
 * receipt's attempt grammar (`checkEventLog`) once its last record is in. A record that would not sign
 * fails the answer at once. A refused record changes nothing (the attempt stays as the records before
 * it left it) and nothing after it is read, so the receipt carries what came before, an attempt it
 * left open ending `unrecorded`, and says where its record stopped (`incomplete`, S26).
 */
export class StackFeed {
  readonly attempts = new Map<number, StackFeedAttempt>();
  /**
   * The attempt of the newest `attempt` record, whatever its number (S24, S32: a new `attempt` record
   * resets the position while nothing was released, and is a fault after a release).
   */
  current: StackFeedAttempt | null = null;
  /** `done` arrived: the rid ended at egress. */
  done = false;
  /** The reader stopped (after `done`, or the feed's connection ended). */
  closed = false;
  broken = false;
  /**
   * Why the record stopped before `done` (S26 `relay_stack.feed_incomplete`): a record was refused, or
   * the feed ended or was given up first; null while it may still reach `done`.
   */
  incomplete: StackFeedIncompleteReason | null = null;
  /**
   * An attempt ended `egress_limit` or was refused with it: egress's stack memory budget ran out, cutting
   * a vendor answer or refusing a call before the vendor. From then on the request ends with Gray's error,
   * whatever a later attempt answers, and no other route is tried (S24, S25, S26).
   */
  limited: StackFeedAttempt | null = null;
  #wake: Promise<void>;
  #notify!: () => void;
  /** Stamps each record as it is taken (S43's trace times). */
  readonly #clock: () => number;

  constructor(clock: () => number) {
    this.#clock = clock;
    this.#wake = new Promise<void>((resolve) => (this.#notify = resolve));
  }

  /** Resolves at the next record or state change. */
  get changed(): Promise<void> {
    return this.#wake;
  }

  #changed(): void {
    this.#notify();
    this.#wake = new Promise<void>((resolve) => (this.#notify = resolve));
  }

  /** The reader stopped; a feed that stopped before `done` is broken. */
  close(broken: boolean): void {
    if (broken && !this.done) {
      this.broken = true;
      this.incomplete ??= "feed_ended";
    }
    this.closed = true;
    this.#changed();
  }

  /** One NDJSON line, parsed strictly; a malformed record breaks the feed and changes nothing. */
  takeLine(line: string): void {
    if (this.broken) return;
    try {
      this.#takeWhole(parseStrict(line));
    } catch {
      this.broken = true;
      this.incomplete ??= "record_refused";
    }
    this.#changed();
  }

  /**
   * One record, taken whole or not at all: an attempt is restored to what the records before left it
   * when this one fails its parse or its receipt check, and an attempt the record created is dropped.
   */
  #takeWhole(record: Json): void {
    // A few attempts at most (`attempts_max`), each a handful of members: copied whole.
    const saved = [...this.attempts.values()].map((attempt) => [attempt, { ...attempt }] as const);
    const { current, limited } = this;
    try {
      const attempt = this.#take(record);
      if (attempt !== null) checkReceiptGroup(attempt);
    } catch (error) {
      const known = new Set(saved.map(([attempt]) => attempt.n));
      for (const n of [...this.attempts.keys()]) if (!known.has(n)) this.attempts.delete(n);
      for (const [attempt, copy] of saved) Object.assign(attempt, copy);
      this.current = current;
      this.limited = limited;
      throw error;
    }
  }

  #attempt(n: number): StackFeedAttempt {
    if (n < 1) throw new Error("n");
    let found = this.attempts.get(n);
    if (found === undefined) {
      found = { n, accepted: null, refused: null, response: null, events: [], body: null, errorBody: null, forwarded: null, end: null, class: null, vendorCode: null, at: this.#clock(), responseAt: null, endedAt: null };
      this.attempts.set(n, found);
    }
    return found;
  }

  /** Takes one record; the attempt whose receipt group it changed, or null (`done`, an event's digest). */
  #take(record: Json): StackFeedAttempt | null {
    if (!isObject(record)) throw new Error("record");
    const t = get(record, "t");
    if (t === "done") {
      // Egress writes `end` for every attempt still in flight before `done` (S17): one left open is a
      // record the receipt could not close.
      if (!this.settled) throw new Error("done");
      this.done = true;
      return null;
    }
    const n = num(get(record, "n"));
    const attempt = this.#attempt(n);
    switch (t) {
      case "attempt": {
        if (attempt.accepted !== null || attempt.refused !== null) throw new Error("attempt twice");
        const proxy = get(record, "proxy_id");
        const ops = get(record, "ops");
        const appended = get(record, "appended");
        if (!Array.isArray(ops) || !ops.every(isObject) || !Array.isArray(appended)) throw new Error("ops");
        attempt.accepted = {
          accountId: stackId(get(record, "account_id")),
          proxyId: proxy === null ? null : stackId(proxy),
          method: str(get(record, "method")),
          path: str(get(record, "path")),
          querySha256: hex32(get(record, "query_sha256")),
          headersSha256: hex32(get(record, "headers_sha256")),
          bodySha256: hex32(get(record, "body_sha256")),
          bodyJcsSha256: hex32(get(record, "body_jcs_sha256")),
          ops: ops as JsonObject[],
          appended: appended.map(relayAppend),
          changed: relayChanges(get(record, "changed")),
        };
        this.current = attempt;
        return attempt;
      }
      case "refused": {
        if (attempt.refused !== null || attempt.response !== null) throw new Error("refused twice");
        const path = get(record, "path");
        const header = get(record, "header");
        const account = get(record, "account_id");
        const proxy = get(record, "proxy_id");
        attempt.refused = {
          code: str(get(record, "code")),
          path: path === undefined ? null : str(path),
          // S32: the header a `stack_header_refused` names (its name, never its value).
          header: header === undefined ? null : str(header),
          // A refusal after acceptance names the attempt record's account; one before it names the
          // account egress resolved, or none (`stack_credential_unknown`, or an egress before S26's change).
          accountId: attempt.accepted?.accountId ?? (account === undefined || account === null ? null : stackId(account)),
          proxyId: attempt.accepted?.proxyId ?? (proxy === undefined || proxy === null ? null : stackId(proxy)),
        };
        attempt.class = attemptClass(get(record, "class"));
        attempt.endedAt = this.#clock();
        // Egress's memory budget refused the call before the vendor: memory pressure, the same rule as a cut.
        if (attempt.refused.code === "egress_limit") this.limited ??= attempt;
        return attempt;
      }
      case "response": {
        if (attempt.accepted === null || attempt.response !== null) throw new Error("response");
        const headers = get(record, "headers");
        if (!isObject(headers)) throw new Error("headers");
        const out: Record<string, string> = {};
        for (const [name, value] of Object.entries(headers)) out[name] = str(value);
        const stream = get(record, "stream");
        if (typeof stream !== "boolean") throw new Error("stream");
        attempt.response = { status: num(get(record, "status")), headers: out, stream };
        attempt.responseAt = this.#clock();
        return attempt;
      }
      case "event": {
        if (attempt.response === null || num(get(record, "seq")) !== attempt.events.length) throw new Error("event");
        attempt.events.push(hex32(get(record, "digest")));
        return null;
      }
      case "body": {
        if (attempt.response === null || attempt.body !== null) throw new Error("body");
        attempt.body = { digest: hex32(get(record, "digest")), bytes: num(get(record, "bytes")) };
        return null;
      }
      case "forwarded": {
        // Right after the attempt's own record, before its vendor call (egress `recordForwarded`).
        if (attempt.accepted === null || attempt.forwarded !== null || attempt.response !== null) throw new Error("forwarded");
        const size = num(get(record, "bytes"));
        const omitted = get(record, "omitted");
        if (omitted === true) {
          attempt.forwarded = { bytes: null, size };
          return null;
        }
        // An empty body's base64 is "", which egress leaves out (`omitempty`).
        const b64 = get(record, "b64");
        const bytes = b64 === undefined && size === 0 ? new Uint8Array(0) : base64Bytes(str(b64));
        if (bytes.length !== size || size > STACK_FORWARDED_MAX_BYTES) throw new Error("forwarded");
        attempt.forwarded = { bytes, size };
        return null;
      }
      case "error_body": {
        if (attempt.response === null || attempt.errorBody !== null) throw new Error("error_body");
        attempt.errorBody = base64Bytes(str(get(record, "b64")));
        return null;
      }
      case "end": {
        if (attempt.accepted === null || attempt.end !== null) throw new Error("end");
        const reason = str(get(record, "reason"));
        // Egress's own reasons only: `unrecorded` is the entry's, for an end that never came.
        if (!(STACK_EGRESS_END_REASONS as readonly string[]).includes(reason)) throw new Error("reason");
        attempt.end = { reason: reason as StackEndReason, bytes: num(get(record, "bytes")) };
        attempt.class = attemptClass(get(record, "class"));
        attempt.vendorCode = vendorCode(get(record, "vendor_code"));
        attempt.endedAt = this.#clock();
        if (reason === "egress_limit") this.limited ??= attempt;
        return attempt;
      }
      default:
        throw new Error("type");
    }
  }

  /** Every accepted attempt has its last record (`end` or `refused`). */
  get settled(): boolean {
    for (const attempt of this.attempts.values()) if (attempt.accepted !== null && attempt.end === null && attempt.refused === null) return false;
    return true;
  }

  /**
   * The attempts that reached a vendor (S25: "dialed"): accepted and not refused before the vendor
   * connection (D72's pre-connect codes come as `refused` after `attempt`). An accepted attempt with no
   * last record yet counts as dialed: Gray cannot tell, and another route may follow only when it can.
   */
  dialed(): StackFeedAttempt[] {
    return [...this.attempts.values()].filter((attempt) => attempt.accepted !== null && attempt.refused === null).sort((left, right) => left.n - right.n);
  }
}

/** A record's integer: `parseStrict` reads an integer as serde_json does, a bigint. */
function num(value: Json | undefined): number {
  const n = typeof value === "bigint" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) throw new Error("number");
  return n;
}

function str(value: Json | undefined): string {
  if (typeof value !== "string") throw new Error("string");
  return value;
}

/**
 * An account or proxy id as egress writes it (`validStackID`, stack_control.go: 1-128 bytes of printable
 * ASCII without space). The receipt no longer carries it, so its check is the feed's own: the id still
 * goes into Gray's records (`relay_account_id`).
 */
function stackId(value: Json | undefined): string {
  const text = str(value);
  if (!/^[\x21-\x7e]{1,128}$/.test(text)) throw new Error("id");
  return text;
}

/** S34's class on egress's last record of an attempt: a word of the closed list. */
function attemptClass(value: Json | undefined): StackAttemptClass {
  const text = str(value);
  if (!(STACK_ATTEMPT_CLASSES as readonly string[]).includes(text)) throw new Error("class");
  return text as StackAttemptClass;
}

/** S35's vendor code on egress's `end`: a word of the closed list, or null (a 2xx answer). */
function vendorCode(value: Json | undefined): StackVendorCode | null {
  if (value === null) return null;
  const text = str(value);
  if (!(STACK_VENDOR_CODES as readonly string[]).includes(text)) throw new Error("vendor_code");
  return text as StackVendorCode;
}

function hex32(value: Json | undefined): string {
  const text = str(value);
  if (!LOWER_HEX_32.test(text)) throw new Error("digest");
  return text;
}

function relayAppend(value: Json): RelayAppend {
  if (!isObject(value)) throw new Error("appended");
  const position = str(get(value, "position"));
  if (!(RELAY_APPEND_POSITIONS as readonly string[]).includes(position)) throw new Error("position");
  return { template_id: str(get(value, "template_id")), position: position as RelayAppend["position"], text_sha256: hex32(get(value, "text_sha256")) };
}

/**
 * An `attempt` record's `changed` (egress stack_changes.go): absent when the relay changed nothing. Its shape is read
 * here and its bounds by `relayStackChangedEvent` when the attempt's group is checked (`checkReceiptGroup`).
 */
function relayChanges(value: Json | undefined): RelayStackChanges | null {
  if (value === undefined) return null;
  if (!isObject(value)) throw new Error("changed");
  const list = (member: string): Json[] => {
    const items = get(value, member);
    if (!Array.isArray(items) || !items.every(isObject)) throw new Error("changed");
    return items;
  };
  const bytes = (entry: Json, member: string): bigint => {
    const n = get(entry, member);
    if (typeof n !== "bigint" || n < 0n) throw new Error("changed");
    return n;
  };
  const op = (entry: Json): RelayChangeOp => {
    const text = str(get(entry, "op"));
    if (!(RELAY_CHANGE_OPS as readonly string[]).includes(text)) throw new Error("changed");
    return text as RelayChangeOp;
  };
  const optional = (entry: Json, member: string): string | undefined => {
    const text = get(entry, member);
    return text === undefined ? undefined : str(text);
  };
  const values = str(get(value, "values"));
  if (!(RELAY_CHANGE_VALUES as readonly string[]).includes(values)) throw new Error("changed");
  return {
    body: list("body").map((entry) => {
      const valueJcs = optional(entry, "value_jcs");
      return { op: op(entry), path: str(get(entry, "path")), removed_bytes: bytes(entry, "removed_bytes"), added_bytes: bytes(entry, "added_bytes"), ...(valueJcs === undefined ? {} : { value_jcs: valueJcs }) };
    }),
    headers: list("headers").map((entry) => {
      const text = optional(entry, "value");
      return { op: op(entry), name: str(get(entry, "name")), removed_bytes: bytes(entry, "removed_bytes"), added_bytes: bytes(entry, "added_bytes"), ...(text === undefined ? {} : { value: text }) };
    }),
    added_bytes: bytes(value, "added_bytes"),
    removed_bytes: bytes(value, "removed_bytes"),
    omitted: bytes(value, "omitted"),
    values: values as RelayStackChanges["values"],
  };
}

function base64Bytes(text: string): Uint8Array {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index += 1) out[index] = raw.charCodeAt(index);
  return out;
}

// ---------------------------------------------------------------------------------------------
// One call.
// ---------------------------------------------------------------------------------------------

/** What a call needs from the request path. */
export interface StackCallInput {
  readonly rid: string;
  /** The snapshot endpoint the call serves (one InferenceRun attempt's route), for the trace (S43). */
  readonly endpointId: string;
  readonly protocol: LaneProtocol;
  /** The client's bytes, exactly as received (S15 `received`): what egress is registered, whatever the container is sent. */
  readonly received: Uint8Array;
  /** The bytes the container is sent: the client's with the required changes applied (`stack-rewrite.ts` `stackRequestBody`). */
  readonly forwarded: Uint8Array;
  /** The client's raw query without its `?` ({@link stackRawQuery}), registered and sent to the container (S32). */
  readonly query: string;
  /** The client's behaviour headers ({@link stackBehaviourHeaders}), registered (S32). */
  readonly behaviourHeaders: Readonly<Record<string, string>>;
  /** The route's vendor, registered: egress refuses an account of another (S32 `stack_route_refused`). */
  readonly vendor: StackVendor;
  /**
   * The request's conversation-affinity token at the relay (`affinity.ts` `deriveAffinity`, 32 lower hex),
   * registered as `conversation` (S32a): egress derives the vendor's session ids from it, so a conversation
   * keeps one session id for the boot. Absent when the client named no session (egress makes one per rid).
   */
  readonly conversation?: string;
  readonly rewrite: StackRewriteSpec;
  /** Section 8 `limits.attempts_max`: what egress enforces, as the relay was told (S15). */
  /**
   * Ask egress for each accepted call's forwarded body (`forwarded` records, docs/design/relay-debug-sharing.md): a
   * backend's call, whose debug record the stack VM keeps. Absent: none, as before.
   */
  readonly captureForwarded?: boolean;
  readonly attemptsMax: number;
  /** The request's deadline, Unix seconds rounded up (S15: TTL = request deadline). */
  readonly expiresAt: number;
  readonly headers: Headers;
  readonly egress: (url: string, init: RequestInit) => Promise<Response>;
  readonly relay: (url: string, init: RequestInit) => Promise<Response>;
  /** The attempt's: its deadline and the client's leaving end the call. */
  readonly signal: AbortSignal;
  readonly timers: StreamTimers;
  readonly clock: () => number;
  /**
   * How long a container event or body waits for its record (S24): UPSTREAM_SILENCE_MS. While an
   * event waits the client is sent nothing, which is upstream silence to it, and the stream would be
   * cut at that silence anyway; egress writes each record before it hands the bytes to the relay
   * (deploy/tee/egress/server.go `forward`), so a legitimate wait is the feed's own delivery.
   */
  readonly holdMs: number;
  /** How long a failed call waits for egress's last records before the outcome is read: ERROR_BODY_WAIT_MS. */
  readonly settleMs: number;
  /** How long a call waits for the container's first upstream call (S21b): UPSTREAM_HEADER_MS. */
  readonly queueMs: number;
  /**
   * The most of a non-stream answer read, and of a stream's bytes after its last complete SSE frame (S32):
   * ANSWER_HELD_MAX_BYTES (egress's `-stack-max-answer-bytes` is the same row).
   */
  readonly answerMaxBytes: number;
  /**
   * The waits between DELETEs that failed (S32: retried until one succeeds or the rid expires): the
   * gateway's own retry backoff, RETRY_BACKOFF_MS doubling up to RETRY_BACKOFF_MAX_MS.
   */
  readonly deleteBackoffMs: number;
  readonly deleteBackoffMaxMs: number;
  /** Where a failed DELETE is reported (one JSON line each); `console.warn` by default. */
  readonly log?: (line: Readonly<Record<string, string | number | null>>) => void;
}

/** Why a call's answer was not released, for the record and the error frame. */
export interface StackFault {
  /**
   * `relay`: the container's doing (S24), its closing its egress call before the vendor's end
   * (`relay_closed`) included; `vendor`: the vendor's stream itself was cut (`vendor_reset`, the only
   * end reason that is the vendor's, S32); `egress`: egress cut a vendor answer at its memory budget
   * (`egress_limit`), after which nothing of the request is released (S24, S26); `gray`: Gray's own
   * ending of the rid (`timeout`, `entry_closed`). `relay` and `egress` end the request with the lane's
   * own `lane_relay_failed`; `gray` as Gray's own bound does.
   */
  readonly by: StackFaultBy;
  /** A closed, content-free word (`@gray/lane-wire` STACK_FAULT_WHYS, the trace's): what failed, never a value. */
  readonly why: StackFaultWhy;
}

/**
 * A closed call's non-compliant change, if any, to `sink` (docs/design/relay-ejection.md). Never fails the answer: a
 * defect in reading the record is logged and the call stands as it ended.
 */
export function reportViolation(call: StackCall, sink: ((found: StackViolationFound) => void) | undefined, rid: string): void {
  if (sink === undefined) return;
  try {
    const found = call.violation();
    if (found !== null) sink(found);
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event: "lane_stack_violation_failed", rid, error: error instanceof Error ? error.name : "error" }));
  }
}

/** A body's S19 digest, or null when it has none (not one JSON text). */
function bodyDigestOrNull(bytes: Uint8Array): string | null {
  try {
    return stackBodyDigest(bytes);
  } catch {
    return null;
  }
}

/**
 * The container's decline (docs/relay-integration-standard.en.md rule 1): its software does not take this request (a
 * client it does not serve, every account full or cooling), answered before any vendor call, so the entry gives it to
 * the next route without counting a failure against this one. Two forms, each a status and the error code of a
 * `{"error":"<code>"}` body as Gray's own answers carry it: 503 `relay_declined`, and 429 `stack_account_cooling`,
 * egress's cooling refusal passed on (the relay keeping Gray's own cooling rules). The form alone decides nothing: a
 * decline is one only when the feed shows no vendor attempt dialed (`decided`, S25); after a vendor call it is an
 * error like any.
 */
const DECLINE_CODES: ReadonlyMap<number, string> = new Map([
  [503, RELAY_DECLINED],
  [429, "stack_account_cooling"],
]);

/** The most of a container's error body read for its decline: a short JSON object (egress's cooling refusal is under 200 bytes). */
const DECLINE_READ_MAX_BYTES = 4096;

/** Whether a container's error answer, `status` and its whole body (null when longer than read), is a decline's form (`DECLINE_CODES`). */
export function relayDeclined(status: number, body: Uint8Array | null): boolean {
  const code = DECLINE_CODES.get(status);
  if (code === undefined || body === null) return false;
  try {
    const value = parseStrictBytes(body);
    return isObject(value) && get(value, "error") === code;
  } catch {
    return false;
  }
}

/**
 * `body` whole when it ends within `max` bytes; null when it is longer, or its read failed. Bounded in time by the
 * call's own bounds, which end the container's call (`close`).
 */
async function readAtMost(body: ReadableStream<Uint8Array> | null, max: number): Promise<Uint8Array | null> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const read = await reader.read();
      if (read.done) break;
      size += read.value.byteLength;
      if (size > max) return null;
      chunks.push(read.value);
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

/** What a failed call's client gets (S24, S25), from the feed alone. */
export type StackOutcome =
  /** The last vendor attempt answered an error: its status and body, with its allowlisted headers. */
  | { readonly kind: "vendor_error"; readonly attempt: StackFeedAttempt; readonly status: number; readonly body: Uint8Array; readonly headers: Readonly<Record<string, string>> }
  /**
   * A vendor attempt was dialed and nothing of it can be released: `lane_relay_failed`, no other route.
   * `attempt` is null when no attempt is in the feed but egress could not confirm that none was dialed
   * (the DELETE or the feed's `done` never came, S32).
   */
  | { readonly kind: "relay_failed"; readonly attempt: StackFeedAttempt | null }
  /** No attempt reached a vendor: another route may be tried (S25). */
  | { readonly kind: "not_dialed" };

/** How `send` ended: a released answer, the outcome of a failure, or the attempt's own end (deadline, client). */
export type StackSent = { readonly kind: "answered"; readonly response: Response } | { readonly kind: "failed"; readonly outcome: StackOutcome } | { readonly kind: "aborted" };

/** Thrown inside the call when the answer cannot be released. */
class StackFaultError extends Error {
  override readonly name = "StackFaultError";
  readonly fault: StackFault;
  constructor(fault: StackFault) {
    super(`stack answer refused: ${fault.why}`);
    this.fault = fault;
  }
}

const utf8 = new TextEncoder();

export class StackCall {
  readonly rid: string;
  readonly feed: StackFeed;
  /** The endpoint the call serves and the model egress names it by (`rewrite.model.to`), for the trace (S43). */
  readonly endpointId: string;
  readonly upstreamModel: string;
  /** The entry's clock when the call was made. */
  readonly startedAt: number;
  /** Egress took the registration: the rid must be ended (`close`). */
  registered = false;
  /** Why the answer was not released, when it was not. */
  fault: StackFault | null = null;
  /** How many container events were released to the client. */
  released = 0;
  /**
   * The container events not released (S24, S26 `dropped`): their 0-based position in the container's
   * answer, and `usage` (a synthesised usage chunk, the stream goes on) or `unmatched` (no record at its
   * position; the stream ends).
   */
  readonly dropped: { readonly seq: number; readonly kind: StackDroppedKind }[] = [];
  /**
   * The feed attempt whose answer the client got (S32 `served_attempt`): the attempt whose events or body
   * were released, or whose vendor error was returned; null when the client got only Gray's own error.
   */
  served: StackFeedAttempt | null = null;
  /** The container's answer is a stream (released event by event) rather than one body. */
  streamed = false;

  readonly #input: StackCallInput;
  readonly #feedAbort = new AbortController();
  /**
   * Ends the container's call. Not the attempt's signal: when the attempt ends (the client left, its
   * bound) the rid is ended at egress first (`close`), and the container's call after that.
   */
  readonly #relayAbort = new AbortController();
  #feedRead: Promise<void> = Promise.resolve();
  #feedReader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  #container: ReadableStreamDefaultReader<Uint8Array> | null = null;
  #closing: Promise<void> | null = null;
  /** The container was sent the rid: from then on it may make vendor calls (S32). */
  #relayCalled = false;
  /** Why the entry ended the container's call before its answer (the queue bound, egress's budget, the end bound). */
  #stopped: "queued_unrecorded" | "egress_limit" | "relay_end_bound" | null = null;
  /** The current attempt the feed shows ended, and when the container's answer must be over by (`#endBound`). */
  #ended: { readonly attempt: StackFeedAttempt; readonly by: number } | null = null;
  /** The current attempt the position counts in, and the position (S24). */
  #matching: StackFeedAttempt | null = null;
  #position = 0;
  /** The container event the stream stopped at (its S19 digest, where it stood), for `violation`. */
  #unmatched: {
    readonly why: "event_mismatch" | "event_unrecorded" | "event_hold_bound";
    readonly digest: string;
    readonly attempt: StackFeedAttempt | null;
    readonly position: number;
    readonly released: number;
  } | null = null;
  /** The S19 digest of a non-stream body that was not the record's (`body_mismatch`), for `violation`. */
  #unmatchedBody: string | null = null;

  constructor(input: StackCallInput) {
    this.rid = input.rid;
    this.feed = new StackFeed(input.clock);
    this.endpointId = input.endpointId;
    this.upstreamModel = input.rewrite.model.to;
    this.startedAt = input.clock();
    this.#input = input;
    if (input.signal.aborted) void this.close();
    else input.signal.addEventListener("abort", () => void this.close(), { once: true });
  }

  /** Registers the rid, opens the feed, calls the container and reads its answer as far as its release starts. */
  async send(): Promise<StackSent> {
    const input = this.#input;
    try {
      const registered = await input.egress(`${STACK_EGRESS_ORIGIN}/v1/stack/requests/${this.rid}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          protocol: input.protocol,
          received_b64: bytesBase64(input.received),
          query: input.query,
          headers: input.behaviourHeaders,
          vendor: input.vendor,
          ...(input.conversation === undefined ? {} : { conversation: input.conversation }),
          rewrite: input.rewrite,
          attempts_max: input.attemptsMax,
          expires_at: input.expiresAt,
          ...(input.captureForwarded === true ? { forwarded: true } : {}),
        }),
        signal: input.signal,
      });
      await registered.body?.cancel().catch(() => {});
      // A refusal (`stack_requests_full`, a malformed spec) reached no vendor: another route may go.
      if (registered.status !== 204) return { kind: "failed", outcome: { kind: "not_dialed" } };
      this.registered = true;
      const feed = await input.egress(`${STACK_EGRESS_ORIGIN}/v1/stack/requests/${this.rid}/events`, { method: "GET", signal: this.#feedAbort.signal });
      if (feed.status !== 200 || feed.body === null) {
        await feed.body?.cancel().catch(() => {});
        return { kind: "failed", outcome: { kind: "not_dialed" } };
      }
      this.#feedRead = this.#readFeed(feed.body);
      if (input.signal.aborted) return { kind: "aborted" };
      let response: Response | null = null;
      let stream: boolean;
      const stopQueueBound = this.#queueBound();
      const path = `${STACK_RELAY_PATHS[input.protocol]}${input.query === "" ? "" : `?${input.query}`}`;
      try {
        this.#relayCalled = true;
        response = await input.relay(`${STACK_RELAY_ORIGIN}${path}`, { method: "POST", headers: input.headers, body: input.forwarded, signal: this.#relayAbort.signal, redirect: "manual" });
        if (response.status < 200 || response.status > 299) {
          // A container's own error never reaches the client (S24): the vendor's, or Gray's fixed one. Its decline
          // (`relayDeclined`) is named apart; whether it is one is the feed's to say (no vendor dialed, `decided`).
          const declined = DECLINE_CODES.has(response.status) && relayDeclined(response.status, await readAtMost(response.body, DECLINE_READ_MAX_BYTES));
          await response.body?.cancel().catch(() => {});
          return { kind: "failed", outcome: await this.#failed({ by: "relay", why: declined ? RELAY_DECLINED : "relay_error_status" }) };
        }
        if (response.body === null) return { kind: "failed", outcome: await this.#failed({ by: "relay", why: "relay_no_body" }) };
        // S21b: every header the container answered with is ignored; whether its answer is a stream is
        // egress's record of the vendor's answer.
        stream = await this.#answerIsStream(this.#relayAbort.signal);
      } catch (error) {
        await response?.body?.cancel().catch(() => {});
        if (input.signal.aborted) throw error;
        if (this.#stopped !== null) return { kind: "failed", outcome: await this.#failed(this.#stopped === "egress_limit" ? null : { by: "relay", why: this.#stopped }) };
        if (error instanceof StackFaultError) throw error;
        // The container's connection failed: what it did before is the feed's to say.
        return { kind: "failed", outcome: await this.#failed({ by: "relay", why: "relay_transport" }) };
      } finally {
        stopQueueBound();
      }
      // A container that answers a body where the vendor streamed, or the other way round, fails closed:
      // its body is no SSE the decoder takes, or its digest is not the feed's `body`.
      if (stream) {
        this.streamed = true;
        return { kind: "answered", response: new Response(this.#verifiedStream(response!.body!), { status: 200, headers: { "content-type": "text/event-stream" } }) };
      }
      return await this.#verifiedBody(response!.body!);
    } catch (error) {
      if (input.signal.aborted) return { kind: "aborted" };
      // Nothing but a fault leaves the call (S24): before the container had the rid, egress's control API
      // failed (Gray's own; no vendor can have been dialed); after it, a failure of the entry's own.
      const fault: StackFault = error instanceof StackFaultError ? error.fault : this.#relayCalled ? { by: "gray", why: "entry_internal" } : { by: "gray", why: "egress_control" };
      return { kind: "failed", outcome: await this.#failed(fault) };
    }
  }

  /**
   * S21a/S21b: a relay may hold a request while every account of its is busy, and the entry waits for its
   * first upstream call as long as it waits for any upstream's first answer (UPSTREAM_HEADER_MS). A call
   * with no vendor attempt in the feed by then (nothing recorded, or only refusals), answered or not, is
   * ended there; once egress accepted an attempt, the attempt's own bound governs the wait. The feed,
   * not the container, also says when the call is over (S32, `#endBound`): a cut at egress's budget ends
   * it as soon as the feed has it (the container's retries are not waited for), and a container that has
   * not answered within ERROR_BODY_WAIT_MS of its current attempt's end is not waited for either. Each
   * way the rid is ended first and the container's call after it (`close`).
   */
  #queueBound(): () => void {
    const { timers, queueMs, clock } = this.#input;
    const watch = new AbortController();
    const stop = (why: "queued_unrecorded" | "egress_limit" | "relay_end_bound"): void => {
      this.#stopped ??= why;
      void this.close();
    };
    const timer = timers.setTimeout(() => {
      if (this.feed.dialed().length === 0) stop("queued_unrecorded");
    }, queueMs);
    void (async () => {
      while (!this.feed.closed) {
        const over = this.#endBound();
        if (over === "limited") return stop("egress_limit");
        if (over !== null && over <= clock()) return stop("relay_end_bound");
        await this.#next(over === null ? queueMs : over - clock(), watch.signal);
      }
    })().catch(() => {});
    return () => {
      watch.abort();
      timers.clearTimeout(timer);
    };
  }

  /**
   * S32 (the C3 harness's finding): when the container's answer must be over, by the feed. A relay that
   * pipes the vendor's answer may never end its own response when egress breaks its call, so the
   * container is not trusted to finish: `limited` once egress cut an answer at its budget (the call ends
   * at once, failing closed), the time ERROR_BODY_WAIT_MS after the feed first showed the current attempt
   * ended (`end` or `refused`: the container has the vendor's whole answer and delivers the rest of it
   * within that, or a retry's `attempt` record comes, which egress writes before it dials), or null.
   */
  #endBound(): "limited" | number | null {
    if (this.feed.limited !== null) return "limited";
    const current = this.feed.current;
    if (current === null || (current.end === null && current.refused === null)) {
      this.#ended = null;
      return null;
    }
    if (this.#ended?.attempt !== current) this.#ended = { attempt: current, by: this.#input.clock() + this.#input.settleMs };
    return this.#ended.by;
  }

  /**
   * One read of the container's answer, over once the feed says the call is (`#endBound`): egress's cut
   * at its budget (`egress_limit`), or a container that did not finish within ERROR_BODY_WAIT_MS of its
   * attempt's end (`relay_end_bound`, the container's fault). The read left pending is cancelled with
   * the call (`close`).
   */
  async #readContainer(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<ReadableStreamReadResult<Uint8Array>> {
    const { clock, timers } = this.#input;
    const read = reader.read().then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    );
    for (;;) {
      const over = this.#endBound();
      if (over === "limited") throw new StackFaultError({ by: "egress", why: "egress_limit" });
      // The bound is a timer, so bytes the container already sent are read even when it has passed.
      let timer: unknown = null;
      const next = await Promise.race([
        read,
        this.feed.changed.then(() => "changed" as const),
        ...(over === null ? [] : [new Promise<"bound">((resolve) => (timer = timers.setTimeout(() => resolve("bound"), Math.max(0, over - clock()))))]),
      ]);
      timers.clearTimeout(timer);
      if (next === "changed") continue;
      if (next === "bound") throw new StackFaultError({ by: "relay", why: "relay_end_bound" });
      if ("error" in next) throw await this.#readFault();
      return next.result;
    }
  }

  /**
   * The fault of a container read that failed (C3's cut race): a relay breaks its own response when
   * egress cuts its call, and that can reach the entry before egress's `end` (`egress_limit`) does. The
   * feed is given ERROR_BODY_WAIT_MS to say so: egress's cut is `egress_limit`, anything else (the
   * current attempt ended otherwise, the feed ended, the bound passed) the container's
   * (`relay_transport`); both end the request with S24's 502. A read the entry broke itself (`close`)
   * is the entry's own ending.
   */
  async #readFault(): Promise<StackFaultError> {
    const { clock, settleMs } = this.#input;
    if (this.#closing !== null) return new StackFaultError({ by: "gray", why: "entry_closed" });
    const until = clock() + settleMs;
    for (;;) {
      if (this.feed.limited !== null) return new StackFaultError({ by: "egress", why: "egress_limit" });
      const current = this.feed.current;
      if (this.feed.closed || this.feed.broken || (current !== null && (current.end !== null || current.refused !== null))) break;
      const left = until - clock();
      if (left <= 0) break;
      if (!(await this.#next(left, null))) break;
    }
    return new StackFaultError({ by: "relay", why: "relay_transport" });
  }

  /**
   * Whether the container's answer is to be read as a stream (S21b): the `stream` of egress's `response`
   * record for the current attempt, once one is there. A success decides at once. A current attempt that
   * ended without one (an error, a refusal before the dial) may still be followed by the container's
   * retry, whose `attempt` record egress wrote before it dialed: that is waited for up to the settle
   * bound, as for an event nothing can record (`#match`), and then the ended attempt's own answer decides.
   * The wait has no bound of its own beyond that: the attempt's bound and the queue bound end it.
   */
  async #answerIsStream(signal: AbortSignal): Promise<boolean> {
    const { clock, settleMs } = this.#input;
    let ended: { readonly attempt: StackFeedAttempt; readonly until: number } | null = null;
    for (;;) {
      if (this.feed.broken) throw new StackFaultError({ by: "relay", why: "feed_invalid" });
      if (this.feed.limited !== null) throw new StackFaultError({ by: "egress", why: "egress_limit" });
      const current = this.feed.current;
      const response = current?.response ?? null;
      if (current !== null && response !== null && response.status >= 200 && response.status <= 299) return response.stream;
      if (current !== null && (current.end !== null || current.refused !== null)) {
        const since: { readonly attempt: StackFeedAttempt; readonly until: number } = ended !== null && ended.attempt === current ? ended : { attempt: current, until: clock() + settleMs };
        ended = since;
        if (clock() >= since.until) {
          if (response === null) throw new StackFaultError({ by: "relay", why: "no_vendor_answer" });
          return response.stream;
        }
      } else {
        ended = null;
      }
      if (this.feed.closed) throw new StackFaultError({ by: "relay", why: "no_vendor_answer" });
      await this.#next(ended === null ? settleMs : Math.max(0, ended.until - clock()), signal);
    }
  }

  /**
   * The outcome after the answer failed before it committed (S25): egress gets ERROR_BODY_WAIT_MS to
   * write the last records, and the feed decides. A fault the release found is kept; a failure of the
   * vendor's own answer the request path found (a stream with no terminal event, D129) is none.
   */
  async failedAfterAnswer(): Promise<StackOutcome> {
    return this.#failed(null);
  }

  async #failed(fault: StackFault | null): Promise<StackOutcome> {
    // A cut at egress's budget decides the outcome and is the cause of what the container did after it;
    // the feed is not waited for (`close` still reads it through `done` for the receipt).
    if (this.feed.limited === null) {
      if (fault !== null) this.fault ??= fault;
      await this.#settle(this.#input.settleMs);
    }
    if (this.feed.limited !== null) this.fault ??= { by: "egress", why: "egress_limit" };
    const outcome = await this.decided();
    // Only the vendor's own error is an answer the client gets from an attempt (S32 `served_attempt`).
    if (outcome.kind === "vendor_error") this.served = outcome.attempt;
    return outcome;
  }

  /**
   * The outcome a failed call's client gets (S25, S32), with "not dialed" confirmed: once the container
   * had the rid it may still make a vendor call egress accepts (a container that answered 500 and then
   * dialed), so a feed showing no dialed attempt is read again after the rid ended at egress (`close`)
   * and only a feed that reached `done` says no vendor was dialed; one that did not is `relay_failed`.
   */
  async decided(): Promise<StackOutcome> {
    if (this.outcome().kind !== "not_dialed" || !this.#relayCalled) return this.outcome();
    await this.close();
    const outcome = this.outcome();
    return outcome.kind === "not_dialed" && !this.feed.done ? { kind: "relay_failed", attempt: null } : outcome;
  }

  /** What the client gets for a call whose answer is not released, from the feed as it stands (S24, S25). */
  outcome(): StackOutcome {
    // A cut at egress's budget ends the request with Gray's error, whatever followed it.
    if (this.feed.limited !== null) return { kind: "relay_failed", attempt: this.feed.limited };
    const dialed = this.feed.dialed();
    const last = dialed.at(-1);
    if (last === undefined) return { kind: "not_dialed" };
    const response = last.response;
    if (response !== null && response.status >= 400 && last.errorBody !== null) return { kind: "vendor_error", attempt: last, status: response.status, body: last.errorBody, headers: response.headers };
    return { kind: "relay_failed", attempt: last };
  }

  /**
   * The relay account of the attempt the client's answer came from: the attempt released, or whose error
   * was returned. The record names it when that answer ended the request: charged, or a vendor error the
   * client was served (S27, S32).
   */
  get accountId(): string | null {
    return this.served?.accepted?.accountId ?? null;
  }

  /**
   * Why this call's record of vendor attempts is incomplete (S26 `relay_stack.feed_incomplete`), read
   * after `close`: the container had the rid, so egress may have accepted calls, and the feed did not
   * reach `done` (a refused record, or a feed that ended or was given up first). Null when the record is
   * whole: `done` came, or the container never had the rid (no attempt can exist).
   */
  get recordIncomplete(): StackFeedIncompleteReason | null {
    if (!this.#relayCalled || this.feed.done) return null;
    return this.feed.incomplete ?? "feed_ended";
  }

  /**
   * The non-compliant change this call shows (docs/design/relay-ejection.md section 1), read after `close`; null when
   * none. Only Gray's own record decides:
   *
   * - **request**: egress refused a call of the rid `422 stack_rewrite_refused` with a path, or `stack_header_refused`,
   *   and the rid was registered with `relay_changes: true`. Those refusals are then only at a kept limit (P1-P4, P6),
   *   which the relay standard names. On a rid without it (the customer's opt-out, which the container is not told) a
   *   refusal is the customer's choice, not a violation; a refusal without a path is not a kept limit (a forwarded body
   *   that is not one JSON object, a member name past the receipt bound, a check of Gray's own that failed).
   * - **answer**: the S24 check stopped at a container event or body, and egress's whole record (the feed reached
   *   `done`) does not hold its digest where the container put it: once an event was released, the matched attempt's
   *   event at the same position; before any, any attempt's first event; a body, any attempt's `body` or `error_body`.
   *   A lag in reading the feed therefore never counts, and a record that is not whole decides nothing.
   */
  violation(): StackViolationFound | null {
    if (this.#input.rewrite.relay_changes === true) {
      for (const attempt of [...this.feed.attempts.values()].sort((left, right) => left.n - right.n)) {
        const refused = attempt.refused;
        if (refused === null) continue;
        if (refused.code === "stack_rewrite_refused" && refused.path !== null && refused.path !== "") {
          const field = `/${refused.path.split("/")[1] ?? ""}`;
          if (STACK_VIOLATION_BODY_FIELD_PATTERN.test(field)) return { kind: "request", code: "stack_rewrite_refused", field };
        }
        if (refused.code === "stack_header_refused" && refused.header !== null && STACK_VIOLATION_HEADER_FIELD_PATTERN.test(refused.header)) {
          return { kind: "request", code: "stack_header_refused", field: refused.header };
        }
      }
    }
    if (!this.feed.done || this.feed.broken) return null;
    const unmatched = this.#unmatched;
    if (unmatched !== null) {
      const vendors =
        unmatched.released > 0
          ? unmatched.attempt?.events[unmatched.position] === unmatched.digest
          : [...this.feed.attempts.values()].some((attempt) => attempt.events[0] === unmatched.digest);
      if (!vendors) return { kind: "answer", code: unmatched.why, field: null };
    }
    const body = this.#unmatchedBody;
    if (body !== null) {
      const vendors = [...this.feed.attempts.values()].some((attempt) => attempt.body?.digest === body || (attempt.errorBody !== null && bodyDigestOrNull(attempt.errorBody) === body));
      if (!vendors) return { kind: "answer", code: "body_mismatch", field: null };
    }
    return null;
  }

  /**
   * Ends the call: the rid at egress first (S32), which cancels its vendor calls and writes `end`
   * (`entry_closed`, Gray's own ending) for each attempt still in flight before `done`; then the
   * container's connection (the relay standard promises relays that Gray closes it when it ends an
   * answer). A DELETE that fails is reported and tried again until one succeeds or the rid expires
   * (`#endRid`). The feed is read through `done` (at most ERROR_BODY_WAIT_MS after the rid ended) so
   * the receipt has every attempt's end.
   */
  close(): Promise<void> {
    this.#closing ??= this.#close().catch((error: unknown) => {
      (this.#input.log ?? ((line) => console.warn(JSON.stringify(line))))({ level: "warn", event: "lane_stack_close_failed", rid: this.rid, error: error instanceof Error ? error.name : typeof error });
    });
    return this.#closing;
  }

  async #close(): Promise<void> {
    const ended = this.registered ? this.#endRid() : null;
    if (ended !== null) await ended.tried;
    this.#relayAbort.abort("entry_closed");
    await this.#container?.cancel().catch(() => {});
    if (ended !== null) {
      await ended.done;
      const until = this.#input.clock() + this.#input.settleMs;
      while (!this.feed.closed) {
        const left = until - this.#input.clock();
        if (left <= 0 || !(await this.#next(left, null))) break;
      }
    }
    this.#feedAbort.abort();
    await this.#feedReader?.cancel().catch(() => {});
    await this.#feedRead.catch(() => {});
  }

  /**
   * `DELETE /v1/stack/requests/{rid}` until egress answers that the rid ended: 204, or 403
   * `stack_request_unknown` when it had ended already (its expiry, or egress's own end). Any other answer
   * or a failed connection is reported and tried again after the backoff, until the rid's expiry, when
   * egress ends it itself. `tried` settles after the first try, `done` with whether one succeeded.
   */
  #endRid(): { readonly tried: Promise<void>; readonly done: Promise<boolean> } {
    const { egress, clock, timers, expiresAt, deleteBackoffMs, deleteBackoffMaxMs } = this.#input;
    const log = this.#input.log ?? ((line) => console.warn(JSON.stringify(line)));
    let first!: () => void;
    const tried = new Promise<void>((resolve) => (first = resolve));
    const done = (async () => {
      let wait = deleteBackoffMs;
      for (let tries = 1; ; tries += 1) {
        const status = await egress(`${STACK_EGRESS_ORIGIN}/v1/stack/requests/${this.rid}`, { method: "DELETE" }).then(
          async (answer) => {
            await answer.body?.cancel().catch(() => {});
            return answer.status;
          },
          () => null,
        );
        first();
        if (status === 204 || status === 403) return true;
        log({ level: "warn", event: "lane_stack_delete_failed", rid: this.rid, status, tries });
        const left = expiresAt * 1000 - clock();
        if (left <= 0) return false;
        await new Promise<void>((resolve) => timers.setTimeout(resolve, Math.min(wait, left)));
        wait = Math.min(wait * 2, deleteBackoffMaxMs);
      }
    })();
    return { tried, done };
  }

  async #readFeed(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    this.#feedReader = reader;
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
    let pending = "";
    let broken = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        pending += decoder.decode(value, { stream: true });
        for (let at = pending.indexOf("\n"); at >= 0; at = pending.indexOf("\n")) {
          const line = pending.slice(0, at);
          pending = pending.slice(at + 1);
          if (line.length > 0) this.feed.takeLine(line);
        }
        if (pending.length > FEED_LINE_MAX) {
          broken = true;
          break;
        }
      }
      if (pending.length > 0) broken = true;
    } catch {
      broken = !this.feed.done;
    } finally {
      await reader.cancel().catch(() => {});
      this.feed.close(broken || !this.feed.done);
    }
  }

  /**
   * Waits for the next feed change, at most `ms`; false when the time ran out. Throws when `signal`
   * (the attempt's, unless the caller outlives it) ends first.
   */
  async #next(ms: number, signal: AbortSignal | null = this.#input.signal): Promise<boolean> {
    const { timers } = this.#input;
    if (signal?.aborted === true) throw signal.reason ?? new Error("aborted");
    let timer: unknown = null;
    let onAbort: () => void = () => {};
    try {
      return await Promise.race([
        this.feed.changed.then(() => true),
        new Promise<boolean>((resolve) => (timer = timers.setTimeout(() => resolve(false), Math.max(0, ms)))),
        new Promise<boolean>((_, reject) => {
          if (signal === null) return;
          onAbort = () => reject(signal.reason ?? new Error("aborted"));
          signal.addEventListener("abort", onAbort, { once: true });
        }),
      ]);
    } finally {
      timers.clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  /** Waits until every accepted attempt has its last record, the feed ends, or `ms` passes. */
  async #settle(ms: number): Promise<void> {
    const until = this.#input.clock() + ms;
    try {
      while (!this.feed.settled && !this.feed.closed && !this.feed.broken) {
        const left = until - this.#input.clock();
        if (left <= 0 || !(await this.#next(left))) return;
      }
    } catch {
      // The attempt ended meanwhile: the feed as it is decides.
    }
  }

  /**
   * The container's stream, released event by event (S24). The pull loop reads the container, splits it
   * into frames (`SseFrames`, the splitter the gateway's own relay reads native streams with) and decodes
   * each with `SseDecoder.pushFrame`, and for each event waits for its record; a released event is written
   * in Gray's framing of its data text. The bytes after the last complete frame are what the entry holds
   * of an event not yet whole: past ANSWER_HELD_MAX_BYTES (an endless `data:` line) the answer is the
   * container's fault (`relay_stream_invalid`, S32), as the decoder alone has no bound. Any fault errors
   * the stream (the request path ends it with Gray's error frame) and closes the call.
   */
  #verifiedStream(body: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
    const reader = body.getReader();
    this.#container = reader;
    const frames = new SseFrames();
    const decoder = new SseDecoder();
    let pending: SseEvent[] = [];
    /** A fault the read found after the events before it in the same chunk: thrown once they are matched. */
    let failure: StackFaultError | null = null;
    let seq = 0;
    let ended = false;
    let cancelled = false;
    return new ReadableStream<Uint8Array>(
      {
        pull: async (controller) => {
          try {
            for (;;) {
              const event = pending.shift();
              if (event !== undefined) {
                const index = seq;
                seq += 1;
                if ((await this.#match(event, index)) === "release") {
                  if (!cancelled) controller.enqueue(sseBytes(event));
                  return;
                }
                continue;
              }
              if (failure !== null) throw failure;
              if (ended) {
                await this.#endOfStream();
                if (!cancelled) controller.close();
                return;
              }
              const read = await this.#readContainer(reader);
              if (read.done) {
                ended = true;
                // What follows the last blank line: a comment, or an event cut off (the decoder's refusal).
                pending = decodeOrFault(() => [...decoder.push(frames.rest()), ...decoder.finish()]);
                continue;
              }
              frames.push(read.value);
              const decoded: SseEvent[] = [];
              try {
                for (let frame = frames.nextFrame(); frame !== undefined; frame = frames.nextFrame()) decoded.push(...decodeOrFault(() => decoder.pushFrame(frame)));
                if (frames.length > this.#input.answerMaxBytes) throw new StackFaultError({ by: "relay", why: "relay_stream_invalid" });
              } catch (error) {
                failure = error as StackFaultError;
              }
              pending = decoded;
            }
          } catch (error) {
            if (cancelled) return;
            // The attempt's own end (a client that left, Gray's bound) is nobody's fault but its own; any other
            // failure that is not already a fault is the entry's own. The stream errors with a fault only.
            const aborted = this.#input.signal.aborted;
            const fault = error instanceof StackFaultError ? error : new StackFaultError(aborted ? { by: "gray", why: "attempt_ended" } : { by: "gray", why: "entry_internal" });
            if (!aborted) this.fault ??= fault.fault;
            controller.error(fault);
            void this.close();
          }
        },
        cancel: async () => {
          cancelled = true;
          await this.close();
        },
      },
      { highWaterMark: 0 },
    );
  }

  /**
   * One container event against the feed: `release`, `drop`, or a fault (thrown).
   *
   * The wait for a record has two bounds. While the current attempt can still record an event (it has
   * not ended and its answer is a stream), the event is held up to the hold bound. When nothing the
   * feed shows can record one (no attempt accepted yet, or the current one ended or answered a body),
   * only a newer `attempt` record could make the event the vendor's, and egress writes that record
   * before it dials (S17), at least one vendor round trip before any vendor byte exists: the wait is
   * then the settle bound (ERROR_BODY_WAIT_MS), so a container that makes an event up fails in seconds,
   * not at the silence limit.
   */
  async #match(event: SseEvent, seq: number): Promise<"release" | "drop"> {
    const { clock, holdMs, settleMs, protocol } = this.#input;
    const digest = stackEventDigest(utf8.encode(event.event ?? ""), utf8.encode(event.data));
    const started = clock();
    // The relay standard allows one usage-only chunk.
    const droppable = !this.dropped.some((entry) => entry.kind === "usage") && usageOnly(protocol, event);
    const drop = (): "drop" => {
      this.dropped.push({ seq, kind: "usage" });
      return "drop";
    };
    const unmatched = (why: StackFaultWhy): never => {
      this.dropped.push({ seq, kind: "unmatched" });
      // Where the stream stopped, for `violation` to hold against the whole record once the rid ended.
      if (why === "event_mismatch" || why === "event_unrecorded" || why === "event_hold_bound") this.#unmatched ??= { why, digest, attempt: this.#matching, position: this.#position, released: this.released };
      throw new StackFaultError({ by: "relay", why });
    };
    for (;;) {
      if (this.feed.broken) unmatched("feed_invalid");
      // A cut at egress's budget ends the answer, a retry after it included (S24, S26).
      if (this.feed.limited !== null) throw new StackFaultError({ by: "egress", why: "egress_limit" });
      const current = this.feed.current;
      if (current !== null && current !== this.#matching) {
        // S24: a new attempt resets the position only while nothing of this answer was released; after
        // that the client cannot take back what it got, and two attempts joined would corrupt it.
        if (this.released > 0) unmatched("attempt_after_release");
        this.#matching = current;
        this.#position = 0;
      }
      const recorded = current?.events[this.#position];
      if (current !== null && recorded !== undefined) {
        if (recorded === digest) {
          this.#position += 1;
          this.released += 1;
          this.served = current;
          return "release";
        }
        if (droppable) return drop();
        unmatched("event_mismatch");
      }
      const recordable = current !== null && current.end === null && current.refused === null && (current.response === null || current.response.stream);
      // A usage chunk with nothing left to match is the container's own: dropped without a wait.
      if (!recordable && droppable) return drop();
      if (this.feed.closed) unmatched("event_unrecorded");
      const left = started + (recordable ? holdMs : settleMs) - clock();
      if (left <= 0 || !(await this.#next(left))) {
        if (droppable) return drop();
        unmatched(recordable ? "event_hold_bound" : "event_unrecorded");
      }
    }
  }

  /**
   * The container's stream ended: the current attempt's `end` must come (within the hold bound), and
   * every event it recorded must have been released. An end other than `eof` is whose its reason says
   * (`endFault`): a vendor stream that was itself cut ends as an upstream cut does.
   */
  async #endOfStream(): Promise<void> {
    const until = this.#input.clock() + this.#input.holdMs;
    for (;;) {
      if (this.feed.broken) throw new StackFaultError({ by: "relay", why: "feed_invalid" });
      if (this.feed.limited !== null) throw new StackFaultError({ by: "egress", why: "egress_limit" });
      const current = this.#matching;
      if (current === null) throw new StackFaultError({ by: "relay", why: "no_event" });
      // S24: a new attempt after a released event ends the answer, relayed or not.
      if (this.feed.current !== current) throw new StackFaultError({ by: "relay", why: "attempt_after_release" });
      if (current.end !== null) {
        // Every event the vendor sent must have reached the client (a dropped trailing `[DONE]` or
        // `message_stop` included): the client's chain is then the vendor's (S24, S32).
        if (this.#position < current.events.length) throw new StackFaultError({ by: "relay", why: "event_missing" });
        if (current.end.reason !== "eof") throw new StackFaultError(endFault(current.end.reason));
        return;
      }
      if (this.feed.closed) throw new StackFaultError({ by: "relay", why: "event_unrecorded" });
      const left = until - this.#input.clock();
      if (left <= 0 || !(await this.#next(left))) throw new StackFaultError({ by: "relay", why: "end_hold_bound" });
    }
  }

  /**
   * A non-stream answer (S24): read whole (at most ANSWER_HELD_MAX_BYTES), its digest compared with the
   * `body` record of the newest attempt once the feed settled (within the hold bound). Released as its
   * bytes as the container sent them, with the vendor's status and content type; a vendor error the container passed on
   * with a success status is the vendor's error.
   */
  async #verifiedBody(body: ReadableStream<Uint8Array>): Promise<StackSent> {
    const reader = body.getReader();
    this.#container = reader;
    const chunks: Uint8Array[] = [];
    let length = 0;
    for (;;) {
      const read = await this.#readContainer(reader);
      if (read.done) break;
      length += read.value.length;
      if (length > this.#input.answerMaxBytes) throw new StackFaultError({ by: "relay", why: "answer_too_large" });
      chunks.push(read.value);
    }
    this.#container = null;
    const bytes = concat(chunks, length);
    await this.#settle(this.#input.holdMs);
    if (this.feed.broken) throw new StackFaultError({ by: "relay", why: "feed_invalid" });
    if (this.feed.limited !== null) throw new StackFaultError({ by: "egress", why: "egress_limit" });
    const target = this.feed.dialed().at(-1);
    if (target === undefined || target.body === null || target.response === null) throw new StackFaultError({ by: "relay", why: "body_unrecorded" });
    const digest = stackBodyDigest(bytes);
    if (target.body.digest !== digest) {
      this.#unmatchedBody = digest;
      throw new StackFaultError({ by: "relay", why: "body_mismatch" });
    }
    this.served = target;
    if (target.response.status < 200 || target.response.status > 299) {
      this.fault ??= { by: "relay", why: "relay_error_as_success" };
      return { kind: "failed", outcome: { kind: "vendor_error", attempt: target, status: target.response.status, body: target.errorBody ?? bytes, headers: target.response.headers } };
    }
    return { kind: "answered", response: new Response(bytes, { status: target.response.status, headers: { "content-type": target.response.headers["content-type"] ?? "application/json" } }) };
  }
}

/**
 * Whose an attempt's ending other than `eof` is (S32): only `vendor_reset` is the vendor's; `relay_closed`
 * (the container closed its egress call first) is the relay's; `timeout` and `entry_closed` are Gray's own
 * ending of the rid; `egress_limit` is egress's budget.
 */
function endFault(reason: Exclude<StackEndReason, "eof">): StackFault {
  switch (reason) {
    case "vendor_reset":
      return { by: "vendor", why: reason };
    case "timeout":
    case "entry_closed":
      return { by: "gray", why: reason };
    case "egress_limit":
      return { by: "egress", why: reason };
    case "relay_closed":
      return { by: "relay", why: reason };
    case "unrecorded":
      // The entry's own word for an end that never came: never on a feed record (`#take` refuses it).
      return { by: "gray", why: "entry_internal" };
  }
}

/** The decoder's own refusal (an unknown field, a line that is not UTF-8, a cut event) is the container's fault. */
function decodeOrFault(decode: () => SseEvent[]): SseEvent[] {
  try {
    return decode();
  } catch {
    throw new StackFaultError({ by: "relay", why: "relay_stream_invalid" });
  }
}

/**
 * A usage-only Chat chunk (the relay standard, rule 4: `"choices":[]` with `usage`): the one event a
 * container may add, which Gray drops. Only Chat has one; the other protocols' usage rides in their own
 * events.
 */
export function usageOnly(protocol: LaneProtocol, event: SseEvent): boolean {
  if (protocol !== "open_ai_chat" || event.event !== null) return false;
  let value: Json;
  try {
    value = parseStrict(event.data);
  } catch {
    return false;
  }
  if (!isObject(value)) return false;
  const choices = get(value, "choices");
  return Array.isArray(choices) && choices.length === 0 && isObject(get(value, "usage"));
}

/** Gray's framing of a released event: its type, and its data text as the container sent it, in `data` lines. */
function sseBytes(event: SseEvent): Uint8Array {
  const lines = event.data.split("\n").map((line) => `data: ${line}\n`);
  return utf8.encode(`${event.event === null ? "" : `event: ${event.event}\n`}${lines.join("")}\n`);
}

function concat(chunks: readonly Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The trace (S43).
// ---------------------------------------------------------------------------------------------

/**
 * A stack request's trace (S43), from its calls once they are closed (each feed read through `done`):
 * one entry per call to the container (one InferenceRun attempt), with the endpoint it served, egress's
 * name for its model (`rewrite.model.to`), when it started and why its answer was not released
 * (`StackFault`, both words), and one entry per vendor call egress recorded for it, in egress's order.
 * `at_ms` and `first_byte_ms` are offsets from the request's start (`first_byte_ms` when the `response`
 * record came); `ms` is the vendor call's own length, from its first record to its last. An accepted
 * call whose last record never came (the feed stopped first, S26 `unrecorded`) has no class of egress's:
 * it is `gray_ended`, Gray's own ending, with no `end`. No rid, no receipt id, nothing of a body. The
 * bounds (8 calls of 8 attempts, 4 KiB) are applied where the row leaves the VM (`fitStackTrace`).
 * Null for a request that made no stack call.
 */
export function stackTraceOf(input: { readonly relayId: string; readonly requestStart: number; readonly calls: readonly StackCall[] }): StackTrace | null {
  if (input.calls.length === 0) return null;
  const offset = (at: number): number => Math.max(0, at - input.requestStart);
  return {
    relay_id: input.relayId,
    truncated: false,
    calls: input.calls.map((call) => ({
      endpoint_id: call.endpointId,
      upstream_model: call.upstreamModel,
      at_ms: offset(call.startedAt),
      fault: call.fault === null ? null : { by: call.fault.by, why: call.fault.why },
      attempts: [...call.feed.attempts.values()]
        .filter((attempt) => attempt.accepted !== null || attempt.refused !== null)
        .sort((left, right) => left.n - right.n)
        .map((attempt) => traceAttempt(attempt, offset)),
    })),
  };
}

/**
 * An entry's trace (S43) of a request it routed over the peer hop (docs/confidential-lane-stack-routing.md section
 * 4.10): the calls the relays' stack VMs traced in their `end` frames, in attempt order, each moved from offsets of its
 * own start to offsets of the entry's request start, so the row reads as the stack VM's own row of a direct client
 * would. A row carries one relay's trace: that of the relay of the last traced attempt. A route of another relay
 * before it dialed no vendor (S25, the only failure the entry goes on after), and its calls are left out; so is a
 * trace that names another relay than the one the entry pinned the peer for. Null when no `end` carried a trace.
 */
export function peerTraceOf(input: { readonly requestStart: number; readonly calls: readonly { readonly relayId: string; readonly startedAt: number; readonly trace: StackTrace | null }[] }): StackTrace | null {
  const traced = input.calls.filter((call) => call.trace !== null && call.trace.relay_id === call.relayId);
  const relayId = traced.at(-1)?.relayId;
  if (relayId === undefined) return null;
  const own = traced.filter((call) => call.relayId === relayId);
  return {
    relay_id: relayId,
    truncated: own.some((call) => call.trace!.truncated),
    calls: own.flatMap((call) => {
      const by = Math.max(0, call.startedAt - input.requestStart);
      return call.trace!.calls.map((c) => ({
        ...c,
        at_ms: c.at_ms + by,
        attempts: c.attempts.map((a) => ({ ...a, at_ms: a.at_ms + by, first_byte_ms: a.first_byte_ms === null ? null : a.first_byte_ms + by })),
      }));
    }),
  };
}

function traceAttempt(attempt: StackFeedAttempt, offset: (at: number) => number): StackTraceAttempt {
  const { accepted, refused, response, end } = attempt;
  return {
    n: attempt.n,
    account_id: accepted?.accountId ?? refused?.accountId ?? null,
    proxy_id: accepted?.proxyId ?? refused?.proxyId ?? null,
    class: attempt.class ?? "gray_ended",
    code: refused?.code ?? null,
    status: response?.status ?? null,
    vendor_code: attempt.vendorCode,
    end: end?.reason ?? null,
    bytes: end?.bytes ?? null,
    at_ms: offset(attempt.at),
    first_byte_ms: attempt.responseAt === null ? null : offset(attempt.responseAt),
    ms: attempt.endedAt === null ? null : Math.max(0, attempt.endedAt - attempt.at),
  };
}

// ---------------------------------------------------------------------------------------------
// The receipt (S26).
// ---------------------------------------------------------------------------------------------

/** What the client got, for `response.returned` (S26). */
export interface StackReturned {
  /** §7.4's `body_hash`: `sha256:` and the SHA-256 of the exact bytes written to the client. */
  readonly bodyHash: string;
  /** The status the client got (a stream's is 200). */
  readonly status: number;
  /** The chain over the S19 digest of every event written to the client, Gray's error frame included. */
  readonly eventsSha256: string | null;
  /** S19's body digest of the non-stream answer the client got. */
  readonly bodySha256: string | null;
  /** The client's answer is or ends in Gray's own error (its fixed error, or its error frame after released events). */
  readonly replacedError: boolean;
  /**
   * How the served attempt's answer reached the client when it is not its events or body as they were
   * (S32): a buffered Codex answer (`codex_terminal_response`), a stream the client left (`client_left`).
   */
  readonly servedAs?: StackServedAs;
  /** The client left before any event or body reached it (S32 `client_left`): no attempt served it. */
  readonly leftBeforeAnswer?: boolean;
  /** The client's whole body is Gray's own error (`replacedError`): no attempt's bytes reached it, so none served it. */
  readonly grayErrorOnly?: boolean;
}

/**
 * The relay-stack receipt events of one request (S26), written with `@gray/attest`'s builders: after
 * `request.received`, one group per vendor attempt of every call, in call order and egress's order
 * within a call, numbered 1..k across the receipt (a call S25 makes at the next route numbers on), and
 * `response.returned` last with the container events the last call did not release and the attempt
 * that served the client (S32 `served_attempt`: the last call's, null when the client got only Gray's
 * own error).
 *
 * A call whose record stopped before egress's `done` (`recordIncomplete`: a refused record, or a feed
 * that ended or was given up first, the DELETE never succeeding before the rid expired) is written as far
 * as it goes: an accepted attempt it left with no `end` gets `upstream.response` with the entry's
 * `unrecorded` (never a reason egress did not write), and `relay_stack.feed_incomplete` follows the
 * call's groups. Such a call is always the request's last: another route follows only a call whose feed
 * reached `done` with no vendor dialed (S25, `decided`).
 */
export function addStackReceipt(
  builder: ReceiptBuilder,
  input: { readonly receivedHash: string; readonly peerEntry?: Parameters<ReceiptBuilder["addPeerEntry"]>[0]; readonly calls: readonly StackCall[]; readonly returned: StackReturned },
): void {
  builder.addRequestReceivedHash(input.receivedHash);
  // Backend mode (docs/confidential-lane-stack-routing.md section 4.8): the entry this VM served the request for.
  if (input.peerEntry !== undefined) builder.addPeerEntry(input.peerEntry);
  const last = input.calls.at(-1);
  let n = 0n;
  let servedAttempt: bigint | null = null;
  for (const call of input.calls) {
    for (const attempt of [...call.feed.attempts.values()].sort((left, right) => left.n - right.n)) {
      if (attempt.accepted === null && attempt.refused === null) continue;
      n += 1n;
      // Every accepted attempt of a whole record ends with an `end` record, Gray's own DELETE included
      // (`entry_closed`); only a record that stopped first leaves one open.
      if (writeStackAttempt(builder, attempt, n) === "open") builder.addUpstreamResponse(upstreamResponseOf(attempt, "unrecorded"));
      if (call === last && attempt === call.served) servedAttempt = n;
    }
    const incomplete = call.recordIncomplete;
    if (incomplete !== null) builder.addRelayStackFeedIncomplete({ reason: incomplete });
  }
  const returned = input.returned;
  builder.addStackResponseReturned({
    bodyHash: returned.bodyHash,
    status: BigInt(returned.status),
    ...(returned.eventsSha256 !== null ? { eventsSha256: returned.eventsSha256 } : returned.bodySha256 !== null ? { bodySha256: returned.bodySha256 } : {}),
    dropped: returned.eventsSha256 === null ? [] : (last?.dropped ?? []).map((entry) => ({ seq: BigInt(entry.seq), kind: entry.kind })),
    replacedError: returned.replacedError,
    servedAttempt: returned.leftBeforeAnswer === true || returned.grayErrorOnly === true ? null : servedAttempt,
    ...(returned.servedAs === undefined ? {} : { servedAs: returned.servedAs }),
  });
}

/** The receipt methods an attempt's group is written with: a `ReceiptBuilder`'s, or the feed's check (S32). */
type StackGroupWriter = Pick<ReceiptBuilder, "addAttemptStarted" | "addRequestModified" | "addRelayStackAppended" | "addRelayStackChanged" | "addStackRequestForwarded" | "addUpstreamResponse" | "addAttemptRefused">;

/**
 * One attempt's group, numbered `n` (S26): `attempt.started`, the attempt's `request.modified` ops and
 * `relay_stack.appended` (as egress's S18 check reported them), `relay_stack.changed` (the relay's own changes, when
 * egress reported any), `request.forwarded` (the call egress
 * accepted), then `upstream.response` or, for a call egress accepted and could not dial,
 * `attempt.refused` with its dial code. A call egress refused before accepting it is `attempt.started`
 * and `attempt.refused` with its check code. An accepted attempt with no last record yet stops after
 * `request.forwarded` (`open`). The group names no relay account or proxy and carries no digest of the
 * forwarded header lines, which hold the account's credential (owner, 10-29): the feed's account stays
 * Gray's own (`relay_account_id`, the relay's panel).
 */
function writeStackAttempt(writer: StackGroupWriter, attempt: StackFeedAttempt, n: bigint): "open" | "closed" {
  const { accepted, refused } = attempt;
  const refusal =
    refused === null ? null : { n, code: refused.code as StackRefusalCode, ...(refused.path === null ? {} : { path: refused.path }), ...(refused.header === null ? {} : { header: refused.header }) };
  if (accepted === null) {
    writer.addAttemptStarted({ n });
    writer.addAttemptRefused(refusal!);
    return "closed";
  }
  writer.addAttemptStarted({ n });
  for (const op of accepted.ops) writer.addRequestModified(modifiedOf(op));
  if (accepted.appended.length > 0) writer.addRelayStackAppended({ n, appended: accepted.appended });
  // The relay's own changes (docs/relay-request-changes.md), between its appends and the call egress forwarded.
  if (accepted.changed !== null) writer.addRelayStackChanged({ n, changed: accepted.changed });
  writer.addStackRequestForwarded({
    method: accepted.method,
    path: accepted.path,
    querySha256: accepted.querySha256,
    bodySha256: accepted.bodySha256,
    bodyJcsSha256: accepted.bodyJcsSha256,
  });
  if (refusal !== null) {
    writer.addAttemptRefused(refusal);
    return "closed";
  }
  if (attempt.end === null) return "open";
  writer.addUpstreamResponse(upstreamResponseOf(attempt, attempt.end.reason));
  return "closed";
}

/**
 * An attempt's `upstream.response`. An answer egress cut at its budget has no digest of its content
 * (`egress_limit`); one whose end the entry never got (`unrecorded`) keeps only a body digest, which egress
 * writes once it held the whole body, never the chain of the events recorded so far.
 */
function upstreamResponseOf(attempt: StackFeedAttempt, endReason: StackEndReason): Parameters<ReceiptBuilder["addUpstreamResponse"]>[0] {
  const { response } = attempt;
  const digest =
    response === null || endReason === "egress_limit" || (endReason === "unrecorded" && response.stream)
      ? {}
      : response.stream
        ? { eventsSha256: stackEventsSha256(attempt.events) }
        : attempt.body === null
          ? {}
          : { bodySha256: attempt.body.digest };
  return {
    status: response === null ? null : BigInt(response.status),
    headersSha256: response === null ? null : stackHeadersSha256(Object.entries(response.headers)),
    ...digest,
    endReason,
  };
}

const EMPTY_BODY_HASH = bodyHash(new Uint8Array(0));

/**
 * S32: the receipt events an attempt's records make so far, built with `@gray/attest`'s own event
 * constructors (each checks its event's shape and bounds and throws what the receipt could not carry);
 * a response head before the attempt's end, as its `upstream.response` will carry it; and once the
 * attempt has its last record, its whole group under the receipt's attempt grammar (`checkEventLog`),
 * as attempt 1 of a log that ends in Gray's own error, which asks nothing of the group.
 */
function checkReceiptGroup(attempt: StackFeedAttempt): void {
  const events: JsonObject[] = [];
  const writer: StackGroupWriter = {
    addAttemptStarted: (input) => void events.push(attemptStartedEvent(input)),
    addRequestModified: (input) => void events.push(requestModifiedEvent(input)),
    addRelayStackAppended: (input) => void events.push(relayStackAppendedEvent(input)),
    addRelayStackChanged: (input) => void events.push(relayStackChangedEvent(input)),
    addStackRequestForwarded: (input) => void events.push(stackRequestForwardedEvent(input)),
    addUpstreamResponse: (input) => void events.push(upstreamResponseEvent(input)),
    addAttemptRefused: (input) => void events.push(attemptRefusedEvent(input)),
  };
  if (writeStackAttempt(writer, attempt, 1n) === "open") {
    if (attempt.response !== null) upstreamResponseEvent(upstreamResponseOf(attempt, "eof"));
    return;
  }
  const returned = stackResponseReturnedEvent({ bodyHash: EMPTY_BODY_HASH, status: 502n, bodySha256: "0".repeat(64), dropped: [], replacedError: true, servedAttempt: null });
  const issues = checkEventLog([requestReceivedEvent(EMPTY_BODY_HASH), ...events, returned]);
  if (issues.length > 0) throw new Error(`the receipt cannot carry attempt ${attempt.n}: ${issues[0]!.code}`);
}

/** One `request.modified` op of egress's `attempt` record (S18), as the builder takes it. */
function modifiedOf(op: JsonObject): { readonly op: RequestModifiedOp; readonly path: string; readonly value?: Json; readonly declaredIn: string } {
  const value = get(op, "value");
  return { op: str(get(op, "op")) as RequestModifiedOp, path: str(get(op, "path")), ...(value === undefined ? {} : { value }), declaredIn: str(get(op, "declared_in")) };
}
