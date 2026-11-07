/**
 * When a model request is sent again after a failed upstream attempt, and where
 * (crates/gray-gateway/src/retry.rs; docs/runtime-operations.md "Retries"), held to the fixtures of
 * area `retry`. Pure: the gateway's dispatcher (workers/gateway/src/inference.ts) applies it, and the
 * endpoint shards keep the state it reads (@gray/endpoint retry.ts: budgets, retry concurrency and the
 * second-opinion gates).
 *
 * Every failure before the answer commits gets one `Class` (classify.ts), and the class decides which
 * tiers may follow:
 *
 * - **A**, another operator: at once, without waiting and without budget. An independent operator is an
 *   independent failure domain, and moving there takes load off the supplier in trouble.
 * - **B**, another route of an operator already tried, and **C**, the route already tried: only when A
 *   has nothing eligible. They wait first, the SDKs' backoff or the delay the upstream stated, holding
 *   nothing on the route; they are paid from the workspace's retry budget at the target route (AWS's
 *   retry quota) and limited by the route's retry concurrency (Envoy's retry budget).
 *
 * A refusal of the request gets at most one more attempt: another operator, or one "second opinion" at
 * the same operator, gated per refusal signature on Envoy's ejection schedule. Nothing is sent again once
 * any of the answer reached the client or anything was charged, and every wait ends inside the request's
 * deadlines. Every number has its source beside it; the tunable ones are settings (@gray/config,
 * `RETRY_*`).
 */
import { asArray, asStr, asU64, get, isObject, type Json } from "@gray/json";
import { type Protocol, isKeepAlive } from "@gray/protocol";
import { type Class, type Outcome, possibleWork } from "./classify.ts";
import { rustTrim } from "./upstream.ts";

/**
 * The share of a backoff that jitter may take off: the SDKs' `_calculate_retry_timeout` multiplies by
 * `1 - 0.25 * random()` (anthropic-sdk-python and openai-python `_base_client.py`).
 */
const JITTER = 0.25;

/** The retry settings (@gray/config `RETRY_*`, the server's `GRAY_RETRY_*`). */
export interface RetryConfig {
  /** Upstream attempts per request, the first included. */
  readonly maxAttempts: number;
  /** Repeats per request at an operator already tried. */
  readonly sameOperator: number;
  /** Same-operator repeats of a refusal per request. */
  readonly secondOpinion: number;
  readonly backoffMs: number;
  readonly backoffMaxMs: number;
  /** The longest stated delay Gray waits. */
  readonly retryAfterMaxMs: number;
  readonly budgetTokens: number;
  readonly transientCost: number;
  readonly throttledCost: number;
  readonly concurrencyPercent: number;
  readonly concurrencyMin: number;
}

/** The server's registered defaults (config/requests.rs), each a source's value (@gray/config has the sources). */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: 3,
  sameOperator: 1,
  secondOpinion: 1,
  backoffMs: 500,
  backoffMaxMs: 8000,
  retryAfterMaxMs: 5000,
  budgetTokens: 500,
  transientCost: 14,
  throttledCost: 5,
  concurrencyPercent: 20,
  concurrencyMin: 3,
};

/**
 * What a same-operator attempt after this failure takes from the workspace's budget at its route:
 * nothing after a refused connection, which nothing reached (gRPC A6 does not count transparent retries
 * for throttling), the throttling cost after a rate limit, and the transient cost otherwise (AWS standard
 * retry mode).
 */
export function classCost(cls: Class, config: RetryConfig): number {
  if (cls === "connect") return 0;
  if (cls === "throttled") return config.throttledCost;
  return config.transientCost;
}

/**
 * What a repeat at an operator already tried could do to the supplier, by what the request asks of it:
 * - `generation`: text generation, embeddings, rerank, System One and counts;
 * - `no_work_proven`: a request whose failed attempt may have cost the supplier a generation or left state
 *   behind (images, audio, video, a Gemini or Chat request that asks for image or audio output, one an
 *   image model's route may answer with an image, a Responses request that names a conversation): repeated
 *   at its operator only after a failure that proves no work was done, and after one that may have done
 *   work it goes at most once more, to another operator;
 * - `side_effect`: a request that declares a tool the upstream runs itself (web search, code execution, a
 *   remote MCP server ...): after a failure that may have done work, at any operator, nothing is sent again.
 */
export type Scope = "generation" | "no_work_proven" | "side_effect";

/** The output modalities a text generation body names, when it names any: Gemini `responseModalities` under either spelling, Chat `modalities`. */
function modalities(protocol: Protocol, body: Json): string[] | undefined {
  let named: Json[] | undefined;
  if (protocol === "gemini") {
    for (const config of ["generationConfig", "generation_config"]) {
      const value = get(body, config);
      if (value === undefined) continue;
      for (const key of ["responseModalities", "response_modalities"]) {
        const list = asArray(get(value, key));
        if (list !== undefined) {
          named = list;
          break;
        }
      }
      if (named !== undefined) break;
    }
  } else if (protocol === "open_ai_chat") {
    named = asArray(get(body, "modalities"));
  } else {
    return undefined;
  }
  if (named === undefined) return undefined;
  return named.map(asStr).filter((m): m is string => m !== undefined);
}

/** Whether an output modality is media: an image or audio. */
function media(modality: string): boolean {
  const lower = modality.toLowerCase();
  return lower === "image" || lower === "audio";
}

/**
 * Whether the body declares a tool other than a client function, or remote MCP servers. Client functions
 * are Chat and Responses `function` and `custom`, an Anthropic tool with no `type` or `custom`, and Gemini
 * `functionDeclarations`; every other tool counts, conservatively.
 */
function serverTools(protocol: Protocol, body: Json): boolean {
  const servers = get(body, "mcp_servers");
  if (servers !== undefined && servers !== null) return true;
  const tools = asArray(get(body, "tools")) ?? [];
  return tools.some((tool) => {
    if (protocol === "gemini") return isObject(tool) && Object.keys(tool).some((k) => k !== "functionDeclarations" && k !== "function_declarations");
    const type = asStr(get(tool, "type"));
    if (protocol === "anthropic_messages") return !(type === undefined || type === "custom");
    return !(type === "function" || type === "custom");
  });
}

/** The scope of a request of `protocol` with `body`, read before any translation (`Scope::of`). */
export function scopeOf(protocol: Protocol, body: Json): Scope {
  if (serverTools(protocol, body)) return "side_effect";
  let isMedia: boolean;
  switch (protocol) {
    case "open_ai_image_generations":
    case "open_ai_image_edits":
    case "open_ai_speech":
    case "open_ai_transcriptions":
    case "open_ai_translations":
    case "open_ai_videos":
      isMedia = true;
      break;
    case "open_ai_responses": {
      const conversation = get(body, "conversation");
      isMedia = conversation !== undefined && conversation !== null;
      break;
    }
    default:
      isMedia = modalities(protocol, body)?.some(media) ?? false;
  }
  return isMedia ? "no_work_proven" : "generation";
}

/**
 * The scope once the routes that may serve the request are known (`Scope::with_routes`): `imageRoutes`,
 * one of them proved image output on a text generation API, as a Gemini image model's route does. Such a
 * model answers with an image unless the request asks for words alone, so a request that does not may
 * cost the supplier an image, as a media request does.
 */
export function scopeWithRoutes(scope: Scope, protocol: Protocol, body: Json, imageRoutes: boolean): Scope {
  const asked = modalities(protocol, body);
  const wordsOnly = asked !== undefined && asked.length > 0 && !asked.some(media);
  return scope === "generation" && imageRoutes && !wordsOnly ? "no_work_proven" : scope;
}

/** Why no further attempt was made (the request log's `retry_stop`), in the server's order (`Stop::ALL`). */
export const STOPS = [
  "served",
  "class",
  "attempts",
  "operator_cap",
  "deadline",
  "time_left",
  "client_left",
  "client_retrying",
  "budget",
  "retry_concurrency",
  "circuit",
  "capacity",
  "quota",
  "dispatch_budget",
  "price",
  "should_retry_false",
  "retry_after_too_long",
  "possible_work",
  "side_effect",
  "gate",
  "held_refusal",
  "unvouched_tool_ids",
  "request_body_limit",
  // The only routes left were of suppliers whose upstream account a vendor's block holds the request's client
  // and tool shape off: their gate paused, or its one re-test lease out on another attempt.
  "account_block",
  "no_route",
  "committed",
  "invariant",
] as const;
export type Stop = (typeof STOPS)[number];

/**
 * The stop a route skipped at dispatch gives (`Stop::of_skip`): its acquisition label, or the stop whose
 * label the dispatcher skipped it with; a label no stop has is `no_route`.
 */
export function stopOfSkip(label: string): Stop {
  if (label === "price_above_bound") return "price";
  return (STOPS as readonly string[]).includes(label) ? (label as Stop) : "no_route";
}

/**
 * The label of a lane route's scheduler pick that did not answer within LANE_SCHEDULER_PICK_MS (D30's
 * `lane_account_unavailable` with D111(d)'s cause): the lane's other cold pass (retry.rs `LANE_PICK_TIMEOUT`).
 */
export const LANE_PICK_TIMEOUT = "lane_account_unavailable:scheduler_timeout";

/**
 * Whether a route passed over before anything was sent was passed on a cold path, so one more try at it may
 * well be served (retry.rs `is_cold_pass`): a `capacity` pass whose permit was still being borrowed
 * (`borrowing`: the endpoint shard did not answer within the wait, its call failed on something other than an
 * overloaded object, or it answered busy while a borrow may still come), or a lost lane pick. The server's
 * permits are in-process, so it passes `borrowing` false for every pass and never has one.
 */
export function isColdPass(label: string, borrowing: boolean): boolean {
  return (label === "capacity" && borrowing) || label === LANE_PICK_TIMEOUT;
}

/** What decides whether a request repeats its cold pass (retry.rs `ColdRepeat`). */
export interface ColdRepeat {
  /** Upstream attempts any model of the request has sent. */
  readonly sent: number;
  /** The request's one cold repeat already went. */
  readonly repeated: boolean;
  readonly clientGone: boolean;
  /** What is left of the request's time for an answer, in ms (negative once it passed). */
  readonly roomMs: number;
  /** What the repeat needs before it can send: ENDPOINT_ACQUIRE_WAIT_MS, plus LANE_SCHEDULER_PICK_MS for a route that picks an account. */
  readonly needMs: number;
}

/**
 * Whether the request asks the route of its earliest cold pass once more, as its first attempt again, where the
 * dispatcher would otherwise stop (retry.rs `cold_repeat_allowed`): nothing sent upstream by any model of the
 * request, no cold repeat yet (once per request), the client still there, and more time left for an answer than
 * the repeat's waits, so a repeat that goes reaches its send before the deadline.
 */
export function coldRepeatAllowed(c: ColdRepeat): boolean {
  return c.sent === 0 && !c.repeated && !c.clientGone && c.roomMs > c.needMs;
}

/** What followed a failed attempt (the request log's `retry_next`, and the `kind` of the retry metrics). */
export type Next = "other_operator" | "same_operator" | "same_route" | "second_opinion" | "none";
/** The kinds a retry metric names, in the server's order (`Next::KINDS`). */
export const NEXT_KINDS: readonly Next[] = ["other_operator", "same_operator", "same_route", "second_opinion"];

/**
 * How an operator already tried may be asked again: an ordinary repeat (of another of its routes, and of
 * the same route when `sameRoute`), one second opinion of a refusal through the gate of its signature, or
 * one repeat of a refusal the upstream itself marked `x-should-retry: true`, outside the gate.
 */
export type Repeat = { readonly kind: "ordinary"; readonly sameRoute: boolean } | { readonly kind: "second_opinion" } | { readonly kind: "should_retry" };

/** Whether another operator may be tried after `outcome` (tier A); the stop when not. */
export function otherOperator(outcome: Outcome, scope: Scope): Stop | null {
  if (outcome.class === "final_refusal" && outcome.referenced) return "class";
  if (scope === "side_effect" && possibleWork(outcome)) return "side_effect";
  return null;
}

/** What the operators already tried allow of the request's history so far. */
export interface Repeats {
  /** Same-operator attempts made at the operator, second opinions included. */
  readonly atOperator: number;
  /** Second opinions made in the request; a repeat the upstream asked for with `x-should-retry: true` is not one. */
  readonly secondOpinions: number;
}

export type SameOperator = { readonly ok: true; readonly repeat: Repeat } | { readonly ok: false; readonly stop: Stop };

/** Whether the operator whose attempt failed with `outcome` may be asked again (tiers B and C), and how. */
export function sameOperator(outcome: Outcome, scope: Scope, config: RetryConfig, clientRetrying: boolean, repeats: Repeats): SameOperator {
  const cls = outcome.class;
  let repeat: Repeat;
  switch (cls) {
    case "connect":
    case "transport":
    case "server_error":
    case "throttled":
    case "no_image":
      repeat = { kind: "ordinary", sameRoute: true };
      break;
    case "credential":
    case "route_fault":
      repeat = { kind: "ordinary", sameRoute: false };
      break;
    case "refusal":
      repeat = outcome.shouldRetry === true ? { kind: "should_retry" } : { kind: "second_opinion" };
      break;
    default:
      return { ok: false, stop: "class" };
  }
  if (scope !== "generation") {
    // Only what proves that no work was done: a refused connection, a rate limit stated by an HTTP status,
    // a refusal the upstream itself said can be repeated, or an image route's answer that it drew no image.
    // Nothing proves it after a 2xx, an in-band error included.
    const noWork = !outcome.answered && repeat.kind !== "second_opinion" && (cls === "connect" || cls === "throttled" || cls === "refusal" || cls === "no_image");
    if (!noWork) return { ok: false, stop: scope === "side_effect" ? "side_effect" : "possible_work" };
  }
  if (outcome.shouldRetry === false) return { ok: false, stop: "should_retry_false" };
  if (clientRetrying) return { ok: false, stop: "client_retrying" };
  if (repeats.atOperator >= config.sameOperator) return { ok: false, stop: "operator_cap" };
  if (repeat.kind === "second_opinion" && repeats.secondOpinions >= config.secondOpinion) return { ok: false, stop: "operator_cap" };
  if (outcome.retryAfterMs !== undefined && outcome.retryAfterMs > config.retryAfterMaxMs) return { ok: false, stop: "retry_after_too_long" };
  return { ok: true, repeat };
}

export type Wait = { readonly ok: true; readonly ms: number } | { readonly ok: false; readonly stop: Stop };

/**
 * The wait before the `n`-th repeat at an operator (from 0): the delay the upstream stated, or the SDKs'
 * backoff `min(base * 2^n, max) * (1 - 0.25u)` with `u` uniform in [0, 1) (`INITIAL_RETRY_DELAY` 0.5 s,
 * `MAX_RETRY_DELAY` 8 s). A stated delay above the cap rules the operator out (`retry_after_too_long`).
 */
export function waitMs(outcome: Outcome, n: number, config: RetryConfig, u: number): Wait {
  if (outcome.retryAfterMs !== undefined) return outcome.retryAfterMs > config.retryAfterMaxMs ? { ok: false, stop: "retry_after_too_long" } : { ok: true, ms: outcome.retryAfterMs };
  const base = Math.min(config.backoffMs * 2 ** Math.min(n, 31), config.backoffMaxMs);
  const clamped = Math.min(Math.max(u, 0), 1);
  return { ok: true, ms: base * (1 - JITTER * clamped) };
}

/**
 * The least time a buffered attempt must have before the request's deadline: the route's latency p95 (from
 * 20 successful samples), and for a same-operator attempt after a transport failure or a server error the
 * failed attempt's own elapsed time, which is measured and so applies without samples. A stream needs
 * none: its deadline is long.
 */
export function timeLeftNeededMs(outcome: Outcome | undefined, p95Ms: number | undefined, stream: boolean, sameOperatorAttempt: boolean): number {
  if (stream) return 0;
  const elapsed = outcome !== undefined && sameOperatorAttempt && (outcome.class === "transport" || outcome.class === "server_error") ? outcome.elapsedMs : 0;
  return Math.max(p95Ms ?? 0, elapsed);
}

/**
 * The most same-operator attempts a route may have at once (waiting, in flight or held as unobserved
 * work): Envoy's `RetryBudget`, `max(min_retry_concurrency, budget_percent of the active requests)`,
 * rounded down. The base is the route's slots in use.
 */
export function concurrencyLimit(used: number, config: RetryConfig): number {
  return Math.max(config.concurrencyMin, Math.floor((config.concurrencyPercent * used) / 100));
}

/** Whether `text` is of Unicode White_Space alone (`char::is_whitespace`), the empty string included. */
const ALL_WHITE = /^\p{White_Space}*$/u;

/** Whether `v` carries no text: absent, null, or a string of whitespace alone, the empty one included (`retry::blank`). */
export function blank(v: Json | undefined): boolean {
  if (v === undefined || v === null) return true;
  return typeof v === "string" && ALL_WHITE.test(v);
}

/**
 * Whether `v` is text of whitespace alone, the empty string included: what an event that exists to carry text
 * carries when it is blank. Absent or null there is a shape the protocol does not have, which commits.
 */
function blankText(v: Json | undefined): boolean {
  return typeof v === "string" && ALL_WHITE.test(v);
}

/** Whether `v` carries nothing at all: absent, null, a blank string, or an empty array or object. */
function nothing(v: Json | undefined): boolean {
  if (Array.isArray(v)) return v.length === 0;
  if (isObject(v)) return Object.keys(v).length === 0;
  return blank(v);
}

/**
 * What a 2xx stream has shown before its commit: which frames are preamble, which the gateway's prime holds
 * without committing, so that a failure before the first frame with content stays retryable
 * (`retry::Preamble`).
 *
 * The list is closed: any other frame commits, so a server-run tool frame, an unknown event type or a future
 * one never permits a retry. Preamble is a keep-alive, a frame that opens the answer or an output item before
 * any of its content, and text made of whitespace alone (Unicode White_Space) together with the frames that
 * open, close or repeat that blank text: some relays send a blank placeholder message at once, before the
 * answer (yylx's `" "` on `/v1/responses`, 2026-10-18; owner direction of 2026-10-19). Held frames are
 * released in order, exactly as received, once a frame with content arrives: non-blank text, a tool call, a
 * refusal, a signature, an image, a finish reason or an unknown event.
 *
 * Feed every native payload of the stream in order: the Messages API names only an index when a block
 * stops, so the tracker remembers which blocks have been blank throughout.
 */
export class Preamble {
  private readonly protocol: Protocol;
  /** Messages blocks opened blank and blank since. */
  private readonly blankBlocks: bigint[] = [];

  constructor(protocol: Protocol) {
    this.protocol = protocol;
  }

  /** Whether `frame`, the next native payload of the stream, is preamble. */
  holds(frame: Json): boolean {
    // A keep-alive carries nothing of the answer; what is one is @gray/protocol's to say (`isKeepAlive`), as
    // the decoder, the gate and the relay read it.
    if (isKeepAlive(this.protocol, frame)) return true;
    const kind = asStr(get(frame, "type"));
    switch (this.protocol) {
      case "anthropic_messages":
        return this.messages(kind, frame);
      case "open_ai_chat":
        return chatPreamble(frame);
      case "open_ai_responses":
        return responsesPreamble(kind, frame);
      case "gemini":
        return geminiPreamble(frame);
      default:
        return false;
    }
  }

  private messages(kind: string | undefined, frame: Json): boolean {
    const index = asU64(get(frame, "index"));
    switch (kind) {
      case "message_start":
        return true;
      case "content_block_start": {
        const block = get(frame, "content_block");
        const type = asStr(get(block, "type"));
        const held = type === "text" ? blank(get(block, "text")) && nothing(get(block, "citations")) : type === "thinking" ? blank(get(block, "thinking")) && nothing(get(block, "signature")) : false;
        if (held && index !== undefined) this.blankBlocks.push(index);
        return held;
      }
      case "content_block_delta": {
        const delta = get(frame, "delta");
        const type = asStr(get(delta, "type"));
        // A block whose start had content committed the stream.
        if (type === "text_delta") return blankText(get(delta, "text"));
        if (type === "thinking_delta") return blankText(get(delta, "thinking"));
        return false;
      }
      case "content_block_stop":
        return index !== undefined && this.blankBlocks.includes(index);
      default:
        return false;
    }
  }
}

/**
 * Whether one decoded frame of a 2xx stream is preamble read alone (`retry::is_preamble`: `Preamble::holds`
 * on a fresh tracker). The conformance area's reader; serving feeds one `Preamble` every frame.
 */
export function isPreamble(protocol: Protocol, frame: Json): boolean {
  return new Preamble(protocol).holds(frame);
}

/**
 * A Chat chunk is preamble when every choice has no finish reason and its delta carries no tool call, refusal
 * or audio and only blank text; a chunk without choices only when it carries usage alone.
 */
function chatPreamble(frame: Json): boolean {
  const choices = asArray(get(frame, "choices"));
  if (choices === undefined) return false;
  // A usage-only chunk.
  if (choices.length === 0) return isObject(frame) && Object.hasOwn(frame, "usage");
  return choices.every((choice) => {
    const delta = get(choice, "delta");
    if (!isObject(delta)) return false;
    return (
      blank(get(choice, "finish_reason")) &&
      Object.entries(delta).every(([key, value]) => (key === "role" ? true : key === "content" || key === "reasoning_content" || key === "reasoning" ? blank(value) : nothing(value)))
    );
  });
}

/** A Responses output text part that is blank, with no annotations. */
function blankTextPart(part: Json | undefined): boolean {
  return asStr(get(part, "type")) === "output_text" && blank(get(part, "text")) && nothing(get(part, "annotations"));
}

/** A Responses message item with no content, or content of blank text parts alone. */
function blankMessage(item: Json | undefined): boolean {
  const parts = asArray(get(item, "content"));
  return parts === undefined || parts.every(blankTextPart);
}

function responsesPreamble(kind: string | undefined, frame: Json): boolean {
  switch (kind) {
    case "response.created":
    case "response.queued":
    case "response.in_progress":
      return true;
    case "response.output_item.added": {
      const item = get(frame, "item");
      const type = asStr(get(item, "type"));
      return type === "message" ? blankMessage(item) : type === "reasoning";
    }
    case "response.content_part.added":
    case "response.content_part.done":
      return blankTextPart(get(frame, "part"));
    case "response.reasoning_summary_part.added":
    case "response.reasoning_summary_part.done":
      return blank(get(get(frame, "part"), "text"));
    case "response.output_text.delta":
      return blankText(get(frame, "delta"));
    case "response.output_text.done":
      return blankText(get(frame, "text")) && nothing(get(frame, "annotations"));
    case "response.reasoning_summary_text.delta":
    case "response.reasoning_text.delta":
      return blankText(get(frame, "delta"));
    case "response.reasoning_summary_text.done":
    case "response.reasoning_text.done":
      return blankText(get(frame, "text"));
    // A message item that ends blank. A reasoning item's end carries its id and `encrypted_content`, which the
    // client passes back: it commits.
    case "response.output_item.done": {
      const item = get(frame, "item");
      return asStr(get(item, "type")) === "message" && blankMessage(item);
    }
    default:
      return false;
  }
}

/**
 * A Gemini chunk is preamble when it carries no prompt feedback and every candidate has no finish reason,
 * grounding or citations, and parts of blank text alone (a thought's flag beside it).
 */
function geminiPreamble(frame: Json): boolean {
  if (get(frame, "promptFeedback") !== undefined) return false;
  const candidates = asArray(get(frame, "candidates")) ?? [];
  const absent = (v: Json | undefined) => v === undefined || v === null;
  return candidates.every((candidate) => {
    if (!absent(get(candidate, "finishReason")) || !absent(get(candidate, "groundingMetadata")) || !absent(get(candidate, "citationMetadata"))) return false;
    const parts = asArray(get(get(candidate, "content"), "parts"));
    return (
      parts === undefined ||
      parts.every((part) => isObject(part) && Object.entries(part).every(([key, value]) => (key === "text" ? blankText(value) : key === "thought" ? typeof value === "boolean" || value === null : false)))
    );
  });
}

/**
 * Whether the client marked this request as its own retry: the Anthropic and OpenAI SDKs send
 * `x-stainless-retry-count`, 0 on the first try and n on the n-th retry (`_build_headers`). Gray then adds
 * no same-operator attempt, which the client's own retries already are. The value is read as Rust's
 * `u64::from_str` reads a trimmed one: an optional `+` and digits within u64.
 */
export function clientRetrying(value: string | null): boolean {
  if (value === null) return false;
  const text = rustTrim(value);
  if (!/^\+?[0-9]+$/.test(text)) return false;
  const n = BigInt(text);
  return n >= 1n && n <= 0xffff_ffff_ffff_ffffn;
}

/** The shape of a plan that bounds its attempts. */
export interface PlanShape {
  /** The eligible operators. */
  readonly operators: number;
  /** A continuation pin restricts the request to one endpoint. */
  readonly pinned: boolean;
  /** `allow_fallbacks`: other operators may serve. */
  readonly otherOperators: boolean;
  readonly clientRetrying: boolean;
}

/**
 * The most upstream attempts a request could make under its plan: one per operator plus its repeats, at
 * most `maxAttempts`. Every scope may repeat after a failure that proves no work was done, so this bounds
 * them all; the request log's `retry_stop` says why a request made fewer.
 */
export function attemptsAllowed(shape: PlanShape, config: RetryConfig): number {
  const same = shape.clientRetrying ? 0 : config.sameOperator;
  const operators = shape.pinned || !shape.otherOperators ? 1 : Math.max(shape.operators, 1);
  return Math.min(config.maxAttempts, (1 + same) * operators);
}

/**
 * What a token count does after a failed attempt (crates/gray-gateway/src/count_tokens.rs, the count
 * loop and `attempt`), for when the Cloudflare gateway counts tokens (docs/cloudflare-native/gateway.md
 * 13.4): up to `maxAttempts` counts, none waited for and no budget taken, since a count leaves no ranking
 * observation that could refill one.
 * - `rejected`: only a refusal every provider would give ends the count (`count_tokens_request_rejected`):
 *   a final one, or a refusal with nothing that makes it the provider's (no server code, no
 *   `x-should-retry: true` of the upstream's own), and never after tool-call ids the route cannot know
 *   (`unvouched`), which may be what it refused;
 * - `repeat`: a refused connection, which nothing reached, is repeated once on its route at once (gRPC's
 *   transparent retry; `repeatedConnect` says it was already);
 * - `next`: anything else goes to the next route, the issuer's first, another operator's before the failed
 *   one's, and only that operator's when the customer refused fallbacks. A flagged conversation is the
 *   supplier's account, so the next route counts.
 */
export function countStep(outcome: Outcome, unvouched: boolean, repeatedConnect: boolean): "rejected" | "repeat" | "next" {
  const refused = outcome.class === "final_refusal" || (outcome.class === "refusal" && !outcome.serverCode && outcome.shouldRetry !== true);
  if (refused && !unvouched) return "rejected";
  if (outcome.class === "connect" && !repeatedConnect) return "repeat";
  return "next";
}
