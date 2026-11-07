/**
 * What an upstream's failure before the answer committed was (crates/gray-gateway/src/upstream_errors.rs
 * `classify`, `classify_event`, and the classes and in-band statuses of crates/gray-gateway/src/retry.rs),
 * held to the fixtures `classify-*` and `classify-event-*` of area `upstream-errors`. Every failure gets
 * exactly one `Class`; which attempts a class allows next is the retry module's (dispatch.ts).
 *
 * | Class | Recognised by |
 * |---|---|
 * | `server_error` | 500, 502, 503, 408, 409, other 5xx except 501, 504, 505, 524, 529 |
 * | `timeout` | 504; 524 (Cloudflare: the origin did not answer within its 125 s read timeout); `timeout_error`; Google `DEADLINE_EXCEEDED`; the attempt bound or silence before commit |
 * | `throttled` | 429 not coded as a quota; 529; on any 4xx a throttling code (`THROTTLING_CODES`) |
 * | `credential` | 401, 402, 403; a body showing the provider's own key, credit or account refused (`providerFault`); a 429 coded as a quota |
 * | `route_fault` | a 404 of the model mapping; a relay without a channel for the model; 3xx; 405, 410, 415, 451, 501, 505 and the other 4xx not listed here; a 413 or `request_too_large` of a body the attempt's restored tool-call ids made longer than their handles (`restoredTooLarge`, which blames neither the route nor the request) |
 * | `no_image` | on an attempt that asked for an image, a relay's 451 saying that no image was drawn and to retry (@gray/protocol `madeNoImage`) |
 * | `account_request` | on any error status, in-band included, a message that opens as a vendor's block of a kind of request on the supplier's account (`accountBlock`: "this request pattern was previously flagged as third-party", "third-party apps now draw from extra usage") |
 * | `refusal` | 400 and 422 with none of the signals above or below, including a server code on a 4xx (`serverCode`) |
 * | `final_refusal` | a context overflow (code or wording), any other 413, a content-policy code, a 400 or 422 with upstream `x-should-retry: false`, a 404 `previous_response_not_found` (`referenced`) |
 *
 * Statuses follow the SDKs (anthropic-sdk-python and openai-python `_should_retry`: 408, 409, 429 and
 * every 5xx) with three refinements: 504 and 524 say the upstream may still be working, so they are never
 * repeated where they happened; 529 and the overload codes shed load before any work and are a rate limit;
 * 501 and 505 would fail the same way again on their route (RFC 9110), so they are route faults. Codes
 * decide before the status for throttling and after it for server failures (OpenCode's
 * `classifyProviderFailure`). Wording never makes a failure retryable by itself.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { asStr, asU64, get, type Json, toJsonString, utf8Length } from "@gray/json";
import { madeNoImage, type Protocol } from "@gray/protocol";
import { ApiError } from "./api-error.ts";
import { CONTRACT_THROTTLING, readRest, sameRest, type RestReading } from "./rests.ts";
import {
  accountRefused,
  ACCOUNT_CODES,
  type AccountBlock,
  accountState,
  credentialRefused,
  diagnose,
  failed,
  isContextOverflow,
  namesWhatTheRequestReferenced,
  noImage,
  OVERFLOW_CODES,
  opensBlock,
  providerFault,
  providerMessage,
  quotesTheRequest,
  rateLimited,
  refused,
  rustTrim,
  serverCodedRefusal,
  shouldRetryHeader,
  statedDelay,
  retryInfo,
  clean,
  upstreamUnavailable,
  type HeaderReader,
  type RefusalContext,
} from "./upstream.ts";

/** What an upstream failure before commit was; `label` names it in the request log as `retry_class`. */
export type Class =
  /** No connection: DNS, TCP, TLS or the connect timeout. Nothing reached the server. */
  | "connect"
  /** The connection broke after the request was written, before the answer committed: whether the upstream did work is unknown. */
  | "transport"
  /** The upstream may still be working: 504, 524, `timeout_error`, `DEADLINE_EXCEEDED`, the attempt bound, or silence before commit. */
  | "timeout"
  /** 500, 502, 503, 408, 409 and the other 5xx but 501, 504, 505, 524, 529. */
  | "server_error"
  /** A rate limit or an overload that sheds load before work. */
  | "throttled"
  /** The provider's own key, credit or account was refused. */
  | "credential"
  /** The route cannot serve the request: a mapping 404, no channel, a redirect, an unsupported method or version, a stream of the wrong type. */
  | "route_fault"
  /**
   * The upstream vendor blocked a kind of request on the supplier's account, which serves all of its routes:
   * it flagged the request pattern, or takes no requests of third-party apps on the account's plan. Another
   * operator at once, never the same one; it counts against the route only through the block's gate
   * (the gateway's account-block gates).
   */
  | "account_request"
  /** The request refused with nothing that marks it final. */
  | "refusal"
  /** A refusal no repeat can change: a context overflow, 413, a content policy, `x-should-retry: false`, or a 404 for something only that upstream holds. */
  | "final_refusal"
  /** A 2xx that is not a valid answer. */
  | "answer_defect"
  /** An image route's upstream made no image for the request and said to send it again: nothing was drawn, done or billed. */
  | "no_image";

/** Every class, in the server's order (`Class::ALL`). */
export const CLASSES: readonly Class[] = ["connect", "transport", "timeout", "server_error", "throttled", "credential", "route_fault", "account_request", "refusal", "final_refusal", "answer_defect", "no_image"];

/** Whether the upstream may have done work for a failed attempt. */
export type Work = "no" | "unknown" | "yes";

/** How a failure counts against its route when it counts at all (ranking's `AttemptFailure`). */
export type AttemptFailure = "transport" | "timeout" | "rejected" | "rate_limited" | "protocol";

/**
 * The `disposition` the request log records for an attempt that failed with an HTTP status (or a mapped
 * in-band one): `credential` also covers `account_request`, and `failure` a refusal that carries a server
 * code. Undefined for a failure without a status.
 */
export function classDisposition(cls: Class, status: number | undefined, serverCode: boolean): string | undefined {
  if (status === undefined) return undefined;
  switch (cls) {
    case "connect":
    case "transport":
    case "answer_defect":
      return undefined;
    case "timeout":
    case "server_error":
    case "no_image":
      return "failure";
    case "throttled":
      return "rate_limited";
    case "credential":
    case "account_request":
      return "credential";
    case "route_fault":
      return status === 404 ? "request_unless_failover" : "failure";
    case "refusal":
      return serverCode ? "failure" : "request";
    case "final_refusal":
      return "request";
  }
}

/**
 * How the failure counts against its route when it counts at all: the refusal classes count only once
 * another attempt serves the request, and an image the upstream did not draw never does.
 */
export function classFailure(cls: Class): AttemptFailure | undefined {
  switch (cls) {
    case "connect":
    case "transport":
      return "transport";
    case "timeout":
      return "timeout";
    case "server_error":
    case "credential":
    case "route_fault":
      return "rejected";
    case "throttled":
      return "rate_limited";
    case "answer_defect":
      return "protocol";
    default:
      return undefined;
  }
}

export function classWork(cls: Class): Work {
  switch (cls) {
    case "transport":
    case "server_error":
      return "unknown";
    case "timeout":
    case "answer_defect":
      return "yes";
    default:
      return "no";
  }
}

/** A refusal class: `refusal`, `final_refusal` or `account_request`. */
export function isRefusal(cls: Class): boolean {
  return cls === "refusal" || cls === "final_refusal" || cls === "account_request";
}

/** One failed attempt, as the dispatcher decides from it (`retry::Outcome`). */
export interface Outcome {
  readonly class: Class;
  /** The HTTP status, or the status an in-band error maps to. */
  readonly status: number | undefined;
  /** Set when the failure was an error event in a 2xx answer (or a buffered 2xx whose body is an error object), to the status it maps to. */
  readonly inBandStatus: number | undefined;
  /** The upstream had answered 2xx when the attempt failed: after a 2xx nothing proves that no work was done, whatever the class. */
  readonly answered: boolean;
  /** The delay the upstream stated (`retry-after-ms`, `retry-after`, Google `RetryInfo`), uncapped, in milliseconds. */
  readonly retryAfterMs: number | undefined;
  /** The upstream's `x-should-retry`. */
  readonly shouldRetry: boolean | undefined;
  /**
   * The failure is evidence against the route, which brings its next check forward: a status no request
   * causes (a redirect, 401 to 403, 408, 409, the 4xx the route's configuration answers), or a provider
   * fault the body states in a machine code. Never a rate limit, a refusal of the request, a 5xx, or a
   * fault read from wording alone.
   */
  readonly blamesRoute: boolean;
  /** A 4xx refusal that carries a server code (`api_error`, `server_error`, `internal`, `unavailable` ...). */
  readonly serverCode: boolean;
  /** A 404 for something only this upstream holds (`previous_response_not_found`). */
  readonly referenced: boolean;
  /**
   * The upstream refused the size of the body (a 413 or `request_too_large`) after the attempt sent the
   * originals of tool-call ids in place of the client's shorter handles: a route fault that counts neither
   * against the route nor as the request's refusal.
   */
  readonly restoredTooLarge: boolean;
  /** The first machine code of the error body (`error.code`, else `error.type`, else `error.status`), lower-cased. */
  readonly code: string | undefined;
  /** The refusal's signature (SHA-256, hex), for the second-opinion gate. */
  readonly signature: string | undefined;
  /** The vendor's block on the supplier's account that made the failure an `account_request` (`accountBlock`). */
  readonly accountBlock: AccountBlock | undefined;
  /**
   * What the failure says about its route's rest, for the two classes read finer (rests.ts `readRest`): a rate
   * limit, and a refused credential or account. It changes nothing the retry rules decide.
   */
  readonly rest: RestReading | undefined;
  /**
   * The message's words, not a code or the status, decided how the failure is handled (ERROR_TEXT_FALLBACK's legacy
   * reading): its class (a provider fault read from its opening) or its rest (rests.ts `sameRest` of the reading with
   * and without them). The request log records it as `legacy_text`, beside the supplier's endpoint.
   */
  readonly legacyText: boolean;
  /** How long the attempt ran before it failed. */
  readonly elapsedMs: number;
}

/** An outcome of `cls` that carries nothing else: a connection failure, a timeout or an answer defect (`Outcome::bare`). */
export function bareOutcome(cls: Class, elapsedMs: number): Outcome {
  return {
    class: cls,
    status: undefined,
    inBandStatus: undefined,
    answered: false,
    retryAfterMs: undefined,
    shouldRetry: undefined,
    blamesRoute: false,
    serverCode: false,
    referenced: false,
    restoredTooLarge: false,
    code: undefined,
    signature: undefined,
    accountBlock: undefined,
    rest: undefined,
    legacyText: false,
    elapsedMs,
  };
}

/** The upstream may have done work: after a 2xx, or a class whose work is not "no" (`Outcome::possible_work`). */
export function possibleWork(outcome: Outcome): boolean {
  return outcome.answered || classWork(outcome.class) !== "no";
}

const utf8 = new TextEncoder();

/**
 * A refusal's signature (`Signature::of`): SHA-256 over the upstream status, the first machine code of
 * the body and the message stem, each part preceded by its length as a little-endian u64, so that the
 * second-opinion gate keeps kinds of refusal apart while quoted values and numbers of one request do not
 * split a kind. `message` is the provider's message as Gray cleans it for the client. The stem is that
 * message lower-cased and cut at its first quote (`"`, `'` or `` ` ``), each run of ASCII digits written
 * `#` and each run of white space one space, trimmed. A character scan, not a parser.
 */
export function signatureOf(status: number, code: string | undefined, message: string): string {
  const lower = message.toLowerCase();
  const quote = lower.search(/["'`]/);
  const cut = quote === -1 ? lower : lower.slice(0, quote);
  let stem = "";
  let digits = false;
  let space = false;
  for (const c of cut) {
    const unit = c.charCodeAt(0);
    if (unit >= 0x30 && unit <= 0x39) {
      if (!digits) stem += "#";
      digits = true;
      space = false;
    } else if (c.length === 1 && WHITE.test(c)) {
      if (!space) stem += " ";
      space = true;
      digits = false;
    } else {
      stem += c;
      digits = false;
      space = false;
    }
  }
  const hash = sha256.create();
  for (const part of [String(status), code ?? "", rustTrim(stem)]) {
    const bytes = utf8.encode(part);
    const length = new Uint8Array(8);
    new DataView(length.buffer).setBigUint64(0, BigInt(bytes.length), true);
    hash.update(length);
    hash.update(bytes);
  }
  return bytesToHex(hash.digest());
}

const WHITE = /^\p{White_Space}$/u;

/** `sha256:<hex>`, as operations health and the request log show a signature. */
export function signatureReference(signature: string): string {
  return `sha256:${signature}`;
}

/**
 * OpenCode's `SERVER_CODES` (packages/ai/src/provider-error.ts at 4397ee44d038), without the overload
 * codes, which are throttling (`THROTTLING_CODES`); and Google's `INTERNAL` and `UNAVAILABLE`.
 */
export const SERVER_CODES: readonly string[] = ["api_error", "internal_error", "internalserverexception", "modelstreamerrorexception", "server_error", "serviceunavailableexception", "internal", "unavailable"];
/**
 * Codes that mean a rate limit or an overload whatever the status: AWS matches the error code first, and
 * OpenCode treats `rate_limit` codes as a rate limit. Google's `RESOURCE_EXHAUSTED` is one unless it is a quota.
 */
export const THROTTLING_CODES: readonly string[] = ["rate_limit_error", "rate_limit_exceeded", "overloaded_error", "server_is_overloaded", "slow_down", "throttlingexception", "too_many_requests", "resource_exhausted"];
/** OpenCode's `INVALID_REQUEST_CODES`. */
const INVALID_REQUEST_CODES: readonly string[] = ["model_not_found", "invalid_prompt", "invalid_request", "invalid_request_error", "validationexception"];
/** OpenCode's `CONTENT_POLICY_CODES`: deterministic refusals, final as an overflow is. */
export const CONTENT_POLICY_CODES: readonly string[] = ["content_filter", "content_moderation", "responsibleaipolicyviolation", "content_policy_violation", "image_content_policy_violation", "refusal"];

/**
 * The codes of the Responses API's `ResponseError` that are the request's own fault: every documented code
 * but `server_error`, `rate_limit_exceeded` and `vector_store_timeout` (openai-python
 * `types/responses/response_error.py` at 2e39db79), and `cyber_policy`, a policy refusal the ChatGPT
 * backend sends and Codex reads as one (codex-rs codex-api/src/sse/responses.rs at 283f3438).
 */
const RESPONSE_REQUEST_CODES: readonly string[] = [
  "invalid_prompt",
  "data_residency_mismatch",
  "bio_policy",
  "misalignment_policy_violation",
  "invalid_image",
  "invalid_image_format",
  "invalid_base64_image",
  "invalid_image_url",
  "image_too_large",
  "image_too_small",
  "image_parse_error",
  "image_content_policy_violation",
  "invalid_image_mode",
  "image_file_too_large",
  "unsupported_image_media_type",
  "empty_image_file",
  "failed_to_download_image",
  "image_file_not_found",
  // Codex.
  "cyber_policy",
];

/**
 * Whether an error code is one `classify` reads for itself at 400: a context overflow, a content-policy
 * refusal, or the provider's own account. An in-band error that carries no status is mapped to 400 for it,
 * so that it is read as it would be with that status.
 */
export function codedAt400(code: string): boolean {
  return OVERFLOW_CODES.includes(code) || CONTENT_POLICY_CODES.includes(code) || ACCOUNT_CODES.includes(code) || accountState(code);
}

/**
 * The status the codes of an in-band error that carries no numeric status map to: a rate limit (and the
 * contract's used-up allowances), a server error (OpenCode's `SERVER_CODES`, the overload codes and the
 * contract's `overloaded`), 400 for a request OpenCode or the contract reads as invalid and for a code
 * classification reads for itself at 400, else 502, a server error, as OpenCode retries what it cannot
 * classify.
 */
function codedStatus(codes: readonly string[]): number {
  if (codes.some((c) => c.startsWith("rate_limit") || c === "quota_exhausted" || c === "model_quota_exhausted")) return 429;
  if (codes.some((c) => SERVER_CODES.includes(c) || c === "overloaded_error" || c === "server_is_overloaded" || c === "slow_down" || c === "overloaded")) return 500;
  if (codes.some((c) => INVALID_REQUEST_CODES.includes(c) || c === "request_invalid" || c === "model_unavailable" || codedAt400(c))) return 400;
  return 502;
}

/** `Value::pointer` for a path of keys. */
function at(value: Json | undefined, ...keys: string[]): Json | undefined {
  let current = value;
  for (const key of keys) current = get(current, key);
  return current;
}

const lowered = (value: Json | undefined): string | undefined => asStr(value)?.toLowerCase();

/**
 * The HTTP status an in-band error maps to (`retry::in_band_status`): an error event in a stream before
 * commit, or a buffered 2xx whose body is an error object. After a 200 no status contradicts the code, so
 * the code decides; an unknown shape is 502, a server error.
 */
export function inBandStatus(protocol: Protocol, payload: Json): number {
  const numeric = (code: Json | undefined): number | undefined => {
    const n = asU64(code);
    return n !== undefined && n >= 400n && n <= 599n ? Number(n) : undefined;
  };
  switch (protocol) {
    // docs.claude.com/en/api/errors: the error types and their statuses.
    case "anthropic_messages":
      switch (lowered(at(payload, "error", "type"))) {
        case "invalid_request_error":
          return 400;
        case "authentication_error":
          return 401;
        case "billing_error":
          return 402;
        case "permission_error":
          return 403;
        case "not_found_error":
          return 404;
        case "conflict_error":
          return 409;
        case "request_too_large":
          return 413;
        case "rate_limit_error":
          return 429;
        case "api_error":
          return 500;
        case "timeout_error":
          return 504;
        case "overloaded_error":
          return 529;
        default:
          return 502;
      }
    case "open_ai_chat": {
      const error = get(payload, "error");
      const code = numeric(get(error, "code"));
      if (code !== undefined) return code;
      return codedStatus([lowered(get(error, "code")), lowered(get(error, "type"))].filter((c): c is string => c !== undefined));
    }
    case "open_ai_responses": {
      const code = lowered(at(payload, "response", "error", "code") ?? get(payload, "code") ?? at(payload, "error", "code"));
      // The error object's own type, as the ChatGPT backend sends one (Codex reads `type` beside `code`);
      // an `error` event's `type` is the event's.
      const kind = lowered(at(payload, "response", "error", "type") ?? at(payload, "error", "type"));
      if (code === "server_error") return 500;
      if (code === "rate_limit_exceeded") return 429;
      if (code === "vector_store_timeout") return 504;
      if (code !== undefined && RESPONSE_REQUEST_CODES.includes(code)) return 400;
      // A code the API does not document, such as a relay's own `stream_timeout` after 189 s without an
      // answer (yylx, 2026-10-17), is read as an unknown Chat code is.
      return codedStatus([code, kind].filter((c): c is string => c !== undefined));
    }
    // google.rpc.Code: INTERNAL 500, UNAVAILABLE 503, DEADLINE_EXCEEDED 504.
    case "gemini": {
      const error = get(payload, "error");
      const code = numeric(get(error, "code"));
      if (code !== undefined) return code;
      switch (asStr(get(error, "status"))) {
        case "INTERNAL":
          return 500;
        case "UNAVAILABLE":
          return 503;
        case "DEADLINE_EXCEEDED":
          return 504;
        case "RESOURCE_EXHAUSTED":
          return 429;
        case "INVALID_ARGUMENT":
        case "FAILED_PRECONDITION":
        case "OUT_OF_RANGE":
          return 400;
        case "UNAUTHENTICATED":
          return 401;
        case "PERMISSION_DENIED":
          return 403;
        case "NOT_FOUND":
          return 404;
        default:
          return 502;
      }
    }
    default:
      return 502;
  }
}

/** Whether a buffered 2xx body is an error object rather than an answer (`retry::is_error_body`). */
export function isErrorBody(protocol: Protocol, payload: Json): boolean {
  const error = get(payload, "error");
  return (error !== undefined && error !== null) || (protocol === "open_ai_responses" && get(payload, "status") === "failed");
}

/** What `classify` words a refusal with: the client's model, the route's upstream model and endpoint, the restored ids, and whether the attempt asked for an image. */
export interface ClassifyContext extends RefusalContext {
  /** The attempt asked its route for an image, by an HTTP request whose status says how it failed: only then is a relay's answer that it drew none read as such. */
  readonly image: boolean;
  /** ERROR_TEXT_FALLBACK: whether a failure no code decides is read by its words (the legacy reading); absent is on, the default. */
  readonly textFallback?: boolean;
}

/** An attempt's classified failure, and what the client is told if no further attempt gets past it. */
export interface Classified {
  readonly outcome: Outcome;
  readonly error: ApiError;
}

/**
 * The outcome of an attempt the upstream answered with an error `status`, `headers` and `body` after
 * `elapsedMs`, and what the client is told if no further attempt gets past it (`classify`). `nowMs` is the
 * clock an HTTP-date `retry-after` counts from.
 */
export function classify(status: number, headers: HeaderReader, body: Uint8Array, context: ClassifyContext, elapsedMs: number, nowMs: number): Classified {
  const code = status;
  const text = context.textFallback ?? true;
  const shouldRetry = shouldRetryHeader(headers);
  const retryAfterMs = statedDelay(headers, nowMs) ?? (code === 429 ? retryInfo(body) : undefined);
  const { message, codes } = providerMessage(body);
  const opening = rustTrim(message ?? "").toLowerCase();
  const has = (set: readonly string[]) => codes.some((c) => set.includes(c));
  const block = opensBlock(opening);
  let blamesRoute = false;
  let serverCode = false;
  let referenced = false;
  // A plain 404 is passed on as the provider said it, once no route serves.
  let passedOn = false;
  // The provider fault that decided the class was read from the message's words.
  let faultWords = false;
  // A throttling code decides before the status on any 4xx, unless it is coded as an exhausted quota.
  const throttling = codes.some((c) => THROTTLING_CODES.includes(c) || CONTRACT_THROTTLING.includes(c) || c.includes("rate_limit"));
  // A size refusal of a body the attempt made longer than its client sent it, by sending the originals of
  // tool-call ids in place of the client's handles: another route, sent the handles, may take the request.
  const restoredTooLarge = (code === 413 || has(["request_too_large"])) && context.restored.some(([original, handle]) => utf8Length(original) > utf8Length(handle));
  let cls: Class;
  if (code >= 400 && block !== undefined) {
    // On any error status, in-band included: an in-band error of a type the protocol does not know (yylx's
    // `"<nil>"`) maps to 502.
    cls = "account_request";
  } else if (code >= 300 && code <= 399) {
    blamesRoute = true;
    cls = "route_fault";
  } else if (code >= 400 && code <= 499 && code !== 429 && throttling && providerFault("rate_limited", body, text) === undefined) {
    cls = "throttled";
  } else if (restoredTooLarge) {
    cls = "route_fault";
  } else if (code >= 401 && code <= 403) {
    blamesRoute = true;
    cls = "credential";
  } else if (code === 404 && namesWhatTheRequestReferenced(body)) {
    referenced = true;
    cls = "final_refusal";
  } else if (code === 404) {
    const fault = providerFault("request_unless_failover", body, text);
    if (fault !== undefined) {
      blamesRoute = fault.coded;
      faultWords = fault.words;
      cls = fault.disposition === "credential" ? "credential" : "route_fault";
    } else {
      passedOn = true;
      cls = "route_fault";
    }
  } else if (code === 408 || code === 409) {
    blamesRoute = true;
    cls = "server_error";
  } else if (code === 413) {
    cls = "final_refusal";
  } else if (code === 429) {
    const fault = providerFault("rate_limited", body, text);
    if (fault !== undefined && fault.disposition === "credential") {
      blamesRoute = fault.coded;
      cls = "credential";
    } else {
      cls = "throttled";
    }
  } else if (code === 400 || code === 422) {
    // The provider's own account or a relay without a channel is the provider's failure, final or not; a
    // refusal of the request is final when no repeat can change it.
    const fault = providerFault("request", body, text);
    if (fault !== undefined) {
      blamesRoute = fault.coded;
      faultWords = fault.words;
      cls = fault.disposition === "credential" ? "credential" : "route_fault";
    } else if (shouldRetry === false || has(OVERFLOW_CODES) || isContextOverflow(opening) || has(CONTENT_POLICY_CODES)) {
      cls = "final_refusal";
    } else {
      serverCode = has(SERVER_CODES);
      cls = "refusal";
    }
  } else if (code === 451 && context.image && madeNoImage(code, body)) {
    cls = "no_image";
  } else if (code >= 400 && code <= 499) {
    blamesRoute = true;
    cls = "route_fault";
  } else if (code === 504 || code === 524) {
    cls = "timeout";
  } else if (code === 529) {
    cls = "throttled";
  } else if (code === 501 || code === 505) {
    cls = "route_fault";
  } else {
    cls = "server_error";
  }
  const cleaned = message === undefined ? undefined : clean(message, context.model, context.upstreamModel, context.endpoint, context.restored);
  const signature = isRefusal(cls) ? signatureOf(code, codes[0], cleaned ?? "") : undefined;
  // What the failure says about its route's rest (`rests`): a rate limit, and a refused credential or account,
  // read finer. A rest takes the route out, so it is evidence against the route as `blamesRoute` is: a refusal
  // read from the wording of a 400 or a 404 alone rests nothing, since a provider's message can quote the request
  // and nothing a customer sends may take a supplier's route out. A rate limit's status or code is the upstream's own.
  // Anthropic's own words for the account out of credit or disabled, at the opening of a 4xx, are read as a refused
  // account's whatever the class (`opensAccountRest`), while the words are read at all. The reading without the
  // words says whether they changed the rest (`legacyText`).
  const accountRest = text && opensAccountRest(code, opening);
  const read = cls === "throttled" || blamesRoute;
  const failure = { status: code, headers, body, retryAfterMs, codes, opening, models: [context.upstreamModel, context.model] as const, said: cleaned, nowMs };
  const rest = read || accountRest ? readRest({ ...failure, class: accountRest ? "credential" : cls }, text) : undefined;
  const plain = !text ? rest : read ? readRest({ ...failure, class: cls }, false) : undefined;
  const legacyText = text && (faultWords || !sameRest(rest, plain));
  const model = context.model;
  let error: ApiError;
  switch (cls as Class) {
    case "connect":
    case "transport":
    case "timeout":
      error = upstreamUnavailable();
      break;
    case "throttled":
      error = rateLimited(retryAfterMs);
      break;
    case "credential":
      error = credentialRefused(model);
      break;
    case "account_request":
      // Only a block makes the class.
      error = accountRefused(model, block ?? "flagged");
      break;
    case "route_fault":
      error = passedOn || restoredTooLarge ? refused(status, body, context) : failed(model, status, retryAfterMs);
      break;
    case "server_error":
    case "answer_defect":
      error = failed(model, status, retryAfterMs);
      break;
    case "refusal":
      error = serverCode ? serverCodedRefusal(status, model) : refused(status, body, context);
      break;
    case "no_image":
      error = noImage(model, retryAfterMs);
      break;
    case "final_refusal":
      error = refused(status, body, context);
      break;
  }
  return {
    outcome: {
      class: cls,
      status: code,
      inBandStatus: undefined,
      answered: false,
      retryAfterMs,
      shouldRetry,
      blamesRoute,
      serverCode,
      referenced,
      restoredTooLarge,
      code: codes[0],
      signature,
      accountBlock: cls === "account_request" ? block : undefined,
      rest,
      legacyText,
      elapsedMs,
    },
    error,
  };
}

/**
 * How Anthropic opens its own refusal of the supplier's account out of credit or disabled, which it sends itself,
 * not only through relays, as a 400 `invalid_request_error` with no code (`ACCOUNT_REST_OPENINGS`; the texts
 * sub2api acts on).
 */
const ACCOUNT_REST_OPENINGS: readonly string[] = ["your credit balance is too low to access the anthropic api", "this organization has been disabled"];

/**
 * Whether a 4xx's message, trimmed and lower-cased, opens as Anthropic's own refusal of the supplier's account
 * and does not quote the request (`opens_account_rest`): evidence for its route's rest, read as a refused
 * account's, whatever its status and class (lead decision of 2026-10-22). Only the opening counts, as for a block.
 */
function opensAccountRest(status: number, opening: string): boolean {
  return status >= 400 && status <= 499 && !quotesTheRequest(opening) && ACCOUNT_REST_OPENINGS.some((o) => opening.startsWith(o));
}

const NO_HEADERS: HeaderReader = () => null;

/**
 * The body of an in-band error `payload`, as an error status's body would be (`event_error`): a Responses
 * `response.failed` event carries its error in the response; any other event or body is its own. What
 * `classifyEvent` classifies, and what an error a 2xx carried is read as wherever its words are read.
 */
export function eventError(payload: Json): Json {
  const response = get(payload, "response");
  return response !== undefined && get(payload, "type") === "response.failed" ? response : payload;
}

/**
 * `classify` for an in-band error (`classify_event`): an error event in a 2xx stream before its answer
 * committed, or a buffered 2xx whose body is an error object. It is classified as the status it maps to
 * (`inBandStatus`), with the event's error as the body (`eventError`).
 */
export function classifyEvent(protocol: Protocol, payload: Json, context: ClassifyContext, elapsedMs: number, nowMs: number): Classified {
  const status = inBandStatus(protocol, payload);
  const classified = classify(status, NO_HEADERS, utf8.encode(toJsonString(eventError(payload))), context, elapsedMs, nowMs);
  return { outcome: { ...classified.outcome, inBandStatus: status, answered: true }, error: classified.error };
}

/** The bytes an in-band error is read from as a refusal (`in_band_bytes`): its error, as `classifyEvent` reads it. */
export function inBandBytes(payload: Json): Uint8Array {
  return utf8.encode(toJsonString(eventError(payload)));
}

/** What an upstream refused an attempt with, as the coding-agent evidence reads it (`RefusedWith`): an error status and its body, or an in-band error's payload. */
export type RefusedWith = { readonly status: number; readonly body: Uint8Array } | { readonly inBand: Json };

/**
 * The result of the route's coding-agent check a refusal is (`inference::agent_refusal`): when the request is
 * OpenCode's own agent turn and the refusal, classified as `outcome`, is the vendor's block on third-party coding
 * agents, the API's words as a check's refusal is read (`diagnose`; an in-band error's from its error,
 * `inBandBytes`), `message` undefined when it says none; for any other refusal, undefined.
 */
export function agentRefusal(opencodeAgent: boolean, outcome: Outcome, refused: RefusedWith): { readonly message: string | undefined } | undefined {
  if (!opencodeAgent || outcome.accountBlock !== "third_party_apps") return undefined;
  const diagnosis = "inBand" in refused ? diagnose(200, inBandBytes(refused.inBand)) : diagnose(refused.status, refused.body);
  return { message: diagnosis.message };
}

/** Seconds to send as `Retry-After` for a stated delay in milliseconds: rounded up, never 0 (`retry::retry_after_seconds`). */
export function retryAfterSeconds(delayMs: number): bigint {
  const seconds = Math.ceil(Math.floor(delayMs) / 1000);
  return BigInt(Math.max(1, seconds));
}

/**
 * Whether every failure a request met was a rate limit: its client then gets 429 with the smallest delay
 * any upstream stated, rather than the last failure's error (`retry::all_throttled`).
 */
export function allThrottled(classes: readonly Class[]): boolean {
  return classes.length > 0 && classes.every((c) => c === "throttled");
}

