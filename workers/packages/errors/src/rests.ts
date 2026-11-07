import { asArray, asStr, compareUtf8, get, isObject, JsonError, parseSerdeBytes, type Json } from "@gray/json";
import type { Class } from "./classify.ts";
import { B, D, DOT, LINE_START, NOT_S, S } from "./rust-regex.ts";
import { spanMs } from "./span.ts";
import { accountState, providerMessage, retryDelay, rustF64, rustTrim, type HeaderReader } from "./upstream.ts";

/**
 * How long a route that failed rests, by why it failed (crates/gray-gateway/src/rests.rs; docs/runtime-operations.md,
 * "Rests"). `readRest` reads a failure's cause and the reset its upstream stated; `decideRest` turns that reading
 * into a rest's length and scope under the REST_* settings. Pure: a conformance replay drives both with JSON.
 *
 * Only two classes are read finer, without changing what retries do for either: a rate limit (`throttled`) is
 * `rate` (a short limit or an overload) or `quota` (an allowance used up until a reset), or `credit` when it says
 * the balance is spent, or nothing when the request alone is larger than the limit. A refused credential or account
 * (`credential`) is `credit`, `quota`, `auth` (the key refused) or `restricted` (the account suspended or banned by
 * its vendor). Every other failure keeps its circuit alone, and a refusal of the request rests nothing.
 *
 * Codes decide first (docs/supplier-error-codes.md): Gray's own contract codes (`CONTRACT_CODES`), then the codes
 * vendors document and relay programs send (`codedCause`), then the status (`statusCause`). The structured reset
 * goes first too: the error's `resets_at` or `resets_in_seconds`, then the stated delay, then the rate-limit reset
 * headers. The words of the message are a legacy fallback (ERROR_TEXT_FALLBACK, on by default): they decide only
 * what no code says, and `sameRest` tells whether they changed the rest, which the request log records as
 * `legacy_text`. The words are magpie's (github.com/yetone/magpie, src/internal/gateway/routing.go), each other source
 * named beside its words in the Rust; a body's strings are matched as JSON decodes them. Only the provider's own error
 * object is read, never the rest of the body: a Responses `response.failed` event carries the request's
 * `instructions`, `tools` and `metadata`, and nothing a customer writes may decide a supplier's rest.
 *
 * Every pattern is the Rust one, written with `rust-regex.ts`'s pieces so that it reads as Rust's `regex`
 * crate reads it (Unicode `\b`, `\d`, `\s`; `.` stopping at `\n` only).
 */

/** Why a route rests (`RestCause`), by the name the request log, events and operations health give it. */
export const REST_CAUSES = ["rate", "quota", "credit", "auth", "restricted"] as const;
export type RestCause = (typeof REST_CAUSES)[number];

/** What a rest covers (`RestScope`): the route that failed, every route of its endpoint's model, or of the endpoint. */
export const REST_SCOPES = ["route", "model", "endpoint"] as const;
export type RestScope = (typeof REST_SCOPES)[number];

/**
 * What a failure says about its route's rest (`Reading`): its cause, the reset its upstream stated (uncapped, in
 * milliseconds; fractions of one kept), whether its text names the route's model or a pool of models, and its
 * message as the client would be shown it.
 */
export interface RestReading {
  readonly cause: RestCause;
  readonly resetMs: number | undefined;
  readonly modelNamed: boolean;
  readonly said: string | undefined;
}

/** A rest decided from a reading (`Decided`): its cause, what it covers, how long it runs, and whether the upstream stated that. */
export interface DecidedRest {
  readonly cause: RestCause;
  readonly scope: RestScope;
  readonly lengthMs: number;
  readonly stated: boolean;
}

/** The REST_* settings (`RestConfig`), in milliseconds. */
export interface RestConfig {
  readonly rateMaxMs: number;
  readonly quotaMs: number;
  readonly quotaMaxMs: number;
  readonly creditMs: number;
  readonly authMs: number;
  readonly restrictedMs: number;
}

/**
 * The rest a reading gets (`decide`), as magpie's `restAfter` gives each cause its own:
 * - `rate`: the stated reset, at most REST_RATE_MAX_SECONDS; none without one, so the circuit alone decides. Its
 *   scope is the route.
 * - `quota`: the stated reset, at most REST_QUOTA_MAX_SECONDS, else REST_QUOTA_SECONDS; the endpoint, or only its
 *   model when the text names the model or a pool of models.
 * - `credit`, `auth` and `restricted`: their own settings, whatever reset is stated; the endpoint.
 */
export function decideRest(reading: RestReading, config: RestConfig): DecidedRest | undefined {
  const cause = reading.cause;
  let lengthMs: number;
  let stated: boolean;
  switch (cause) {
    case "rate":
      if (reading.resetMs === undefined) return undefined;
      [lengthMs, stated] = [Math.min(reading.resetMs, config.rateMaxMs), true];
      break;
    case "quota":
      [lengthMs, stated] = reading.resetMs === undefined ? [config.quotaMs, false] : [Math.min(reading.resetMs, config.quotaMaxMs), true];
      break;
    case "credit":
      [lengthMs, stated] = [config.creditMs, false];
      break;
    case "auth":
      [lengthMs, stated] = [config.authMs, false];
      break;
    case "restricted":
      [lengthMs, stated] = [config.restrictedMs, false];
      break;
  }
  const scope: RestScope = cause === "rate" ? "route" : cause === "quota" && reading.modelNamed ? "model" : "endpoint";
  return { cause, scope, lengthMs, stated };
}

/** What `readRest` reads a failure from, as `classify` hands it over. */
export interface RestFailure {
  readonly class: Class;
  readonly status: number;
  readonly headers: HeaderReader;
  readonly body: Uint8Array;
  /** The delay the headers (or Google's `RetryInfo`) stated (`statedDelay`), in milliseconds. */
  readonly retryAfterMs: number | undefined;
  /** The body's machine codes, lower-cased, and its message's opening, trimmed and lower-cased, as `classify` reads them. */
  readonly codes: readonly string[];
  readonly opening: string;
  /** The route's upstream and requested models. */
  readonly models: readonly [string, string];
  /** The message as the client would be shown it. */
  readonly said: string | undefined;
  readonly nowMs: number;
}

/**
 * The reading of a failure (`read`): undefined for a class not read finer, or a rate limit the request alone is
 * larger than. `text` is ERROR_TEXT_FALLBACK: off, the words are never read, and a failure no code or status reads
 * keeps its circuit alone.
 */
export function readRest(f: RestFailure, text: boolean): RestReading | undefined {
  if (f.class !== "throttled" && f.class !== "credential") return undefined;
  const value = serdeValue(f.body);
  const error = value === undefined ? undefined : errorObject(value);
  // Google's `RetryInfo` of a body its OpenAI-compatible endpoint wraps in an array, which the headers' reading does not reach.
  const retryAfterMs = f.retryAfterMs ?? (error === undefined ? undefined : retryDelay(error));
  const stated = resetsFields(error, f.nowMs) ?? retryAfterMs;
  const contract = contractCause(f.codes);
  if (contract !== undefined) {
    if (contract.cause === undefined) return undefined;
    return { cause: contract.cause, resetMs: stated ?? headerReset(f.headers, f.nowMs), modelNamed: contract.model, said: f.said };
  }
  const coded = codedCause(f.class, f.codes, error);
  if (!text) {
    const cause = coded?.cause ?? statusCause(f.class, f.status);
    return cause === undefined ? undefined : { cause, resetMs: stated ?? headerReset(f.headers, f.nowMs), modelNamed: coded?.model === true, said: f.said };
  }
  const words = wordsOf(error, value, f.body);
  const cause = coded !== undefined ? coded.cause : f.class === "throttled" ? throttled(f.status, words) : credential(f.status, f.opening, words);
  if (cause === undefined) return undefined;
  return { cause, resetMs: stated ?? wordsReset(words, f.nowMs) ?? headerReset(f.headers, f.nowMs), modelNamed: coded?.model === true || modelNamed(words, f.models), said: f.said };
}

/**
 * Whether two readings rest a route alike (`same_rest`): the same cause, the same reset for a rate limit or a quota
 * (the other causes rest their own lengths), and the same scope for a quota. A rate limit that states no reset rests
 * nothing, as no reading does. `classify` compares the reading with and without the words: when they differ, the
 * words decided the rest (`Outcome.legacyText`).
 */
export function sameRest(a: RestReading | undefined, b: RestReading | undefined): boolean {
  const effect = (r: RestReading | undefined) => (r === undefined || (r.cause === "rate" && r.resetMs === undefined) ? undefined : r);
  const [x, y] = [effect(a), effect(b)];
  if (x === undefined || y === undefined) return x === y;
  if (x.cause !== y.cause) return false;
  if ((x.cause === "rate" || x.cause === "quota") && x.resetMs !== y.resetMs) return false;
  return x.cause !== "quota" || x.modelNamed === y.modelNamed;
}

/**
 * Gray's error contract (docs/supplier-error-codes.md, `CONTRACT_CODES`): the code a supplier sends in `error.code`
 * (or as a Gemini `ErrorInfo` detail's `reason`), compared lower-cased, one per failure it can state. Each decides
 * its failure outright, before any other code and without its words.
 */
export const CONTRACT_CODES = [
  "rate_limited",
  "quota_exhausted",
  "model_quota_exhausted",
  "balance_exhausted",
  "account_suspended",
  "credential_refused",
  "overloaded",
  "model_unavailable",
  "request_invalid",
  "request_too_large",
] as const;
export type ContractCode = (typeof CONTRACT_CODES)[number];

/** The contract's codes of a rate limit or a used-up allowance, which make a failure a rate limit on any 4xx (`CONTRACT_THROTTLING`). */
export const CONTRACT_THROTTLING: readonly string[] = ["rate_limited", "quota_exhausted", "model_quota_exhausted", "overloaded"];
/** The contract's codes of the supplier's own account, which make a failure a refused credential on any 4xx (`CONTRACT_ACCOUNT`). */
export const CONTRACT_ACCOUNT: readonly string[] = ["balance_exhausted", "account_suspended", "credential_refused"];

/** What a contract code says of a route's rest (`contract_cause`): its cause (none for one that rests nothing) and whether it is the model's alone. */
function contractCause(codes: readonly string[]): { readonly cause: RestCause | undefined; readonly model: boolean } | undefined {
  const code = CONTRACT_CODES.find((c) => codes.includes(c));
  switch (code) {
    case undefined:
      return undefined;
    case "rate_limited":
    case "overloaded":
      return { cause: "rate", model: false };
    case "quota_exhausted":
      return { cause: "quota", model: false };
    case "model_quota_exhausted":
      return { cause: "quota", model: true };
    case "balance_exhausted":
      return { cause: "credit", model: false };
    case "account_suspended":
      return { cause: "restricted", model: false };
    case "credential_refused":
      return { cause: "auth", model: false };
    // The request's own, or the route's: no rest.
    case "model_unavailable":
    case "request_invalid":
    case "request_too_large":
      return { cause: undefined, model: false };
  }
}

/** The codes of Google's quota windows (`upstream_errors::QUOTA_WINDOW_CODES`): a 429 that carries one is a rate limit. */
export const QUOTA_WINDOW_CODES: readonly string[] = ["resource_exhausted", "google.rpc.retryinfo", "google.rpc.quotafailure"];

/** Codes of an account its vendor or relay suspended (`RESTRICTED_CODES`), besides the account-state codes (`accountState`). */
const RESTRICTED_CODES: readonly string[] = ["consumer_suspended", "gcp_suspended", "account_state_invalid", "deactivated_workspace", "user_inactive"];
/** Codes of a balance or payment refused (`CREDIT_CODES`), before the allowances' codes. */
const CREDIT_CODES: readonly string[] = [
  "credit_balance_exhausted",
  "billing_error",
  "billing_disabled",
  "billing_not_active",
  "insufficient_balance",
  "insufficient_user_quota",
  "pre_consume_token_quota_failed",
  "api_key_quota_exhausted",
  "subscription_not_found",
  "subscription_invalid",
];
/** Codes of an allowance used up until a reset (`QUOTA_CODES`). */
const QUOTA_CODES: readonly string[] = ["usage_limit_reached", "usage_limit_exceeded", "organization_spend_limit_exceeded", "project_spend_limit_exceeded", "organization_usage_limit_exceeded"];
/** Codes of an allowance of the route's model alone used up (`MODEL_QUOTA_CODES`). */
const MODEL_QUOTA_CODES: readonly string[] = ["model_cooldown"];
/** OpenAI's broad billing type (`BROAD_CREDIT_CODES`), after every finer code. */
const BROAD_CREDIT_CODES: readonly string[] = ["insufficient_quota"];
/** Codes of a key refused (`AUTH_CODES`). */
const AUTH_CODES: readonly string[] = [
  "invalid_api_key",
  "authentication_error",
  "api_key_invalid",
  "api_key_expired",
  "api_key_service_blocked",
  "api_key_http_referrer_blocked",
  "api_key_ip_address_blocked",
  "api_key_android_app_blocked",
  "api_key_ios_app_blocked",
  "access_token_expired",
  "credentials_missing",
  "unauthenticated",
  "api_key_disabled",
  "api_key_required",
  "upstream_authentication_required",
];
/** Codes of a short limit or an overload (`RATE_CODES`). */
const RATE_CODES: readonly string[] = ["slow_down", "overloaded_error", "server_is_overloaded", "resource_quota_exceeded", "gateway_concurrency_limit", "gateway_queue_full", "invalid_auth_rate_limited"];

/**
 * What a vendor's or relay program's code says of a route's rest (`coded_cause`), in this order: Google's quota
 * windows (a rate limit only), an account restricted, a balance, an allowance, OpenAI's broad billing type, a key
 * refused, a short limit. Undefined when no code here is in the body: a code such as `rate_limit_exceeded` or
 * `permission_error`, which vendors send for more than one cause, decides nothing.
 */
function codedCause(cls: Class, codes: readonly string[], error: Json | undefined): { readonly cause: RestCause; readonly model: boolean } | undefined {
  const has = (set: readonly string[]) => codes.some((c) => set.includes(c));
  if (cls === "throttled" && (has(QUOTA_WINDOW_CODES) || (error !== undefined && googleWindow(error)))) return { cause: "rate", model: false };
  if (has(RESTRICTED_CODES) || codes.some(accountState)) return { cause: "restricted", model: false };
  if (has(CREDIT_CODES)) return { cause: "credit", model: false };
  if (has(QUOTA_CODES)) return { cause: "quota", model: false };
  if (has(MODEL_QUOTA_CODES)) return { cause: "quota", model: true };
  if (has(BROAD_CREDIT_CODES)) return { cause: "credit", model: false };
  if (has(AUTH_CODES)) return { cause: "auth", model: false };
  if (has(RATE_CODES)) return { cause: "rate", model: false };
  return undefined;
}

/** What the status alone says (`status_cause`): a rate limit is a rate limit; a 402 a balance, a 401 a key; any other refusal nothing. */
function statusCause(cls: Class, status: number): RestCause | undefined {
  if (cls === "throttled") return "rate";
  return status === 402 ? "credit" : status === 401 ? "auth" : undefined;
}

/** What a provoked error answer was asked for (`Expected`): a key refused, or a request refused. */
export type AnswerExpected = "credential" | "request";

/**
 * How an error answer a setup probe provoked is coded (`Coding`, docs/supplier-error-codes.md section 6): with the
 * contract's code for what it answered (`contract`), a code Gray reads for it from vendors and relay programs
 * (`known`), or neither (`none`).
 */
export type AnswerCodingKind = "contract" | "known" | "none";

/** A provoked answer as the probe reports it (`AnswerCoding`): its status, its code, how it is coded and the warning, null when it is the contract's. */
export interface AnswerCoding {
  readonly status: number | null;
  readonly code: string | null;
  readonly coding: AnswerCodingKind;
  readonly warning: string | null;
}

/**
 * Codes of a request refused that Gray reads (`REQUEST_CODES`): OpenAI's and Anthropic's `invalid_request_error`,
 * Google's `INVALID_ARGUMENT`, new-api's `invalid_request` (controller/relay.go at e835b1bf), one-api's
 * `invalid_text_request` (relay/controller/text.go at 8df4a267), and OpenCode's `invalid_prompt` and
 * `validationexception`.
 */
const REQUEST_CODES: readonly string[] = ["invalid_request_error", "invalid_argument", "invalid_request", "invalid_text_request", "invalid_prompt", "validationexception"];

/**
 * How a provoked error answer is coded (`answer_coding`): `expected` is what it was asked for, a key that cannot be
 * valid (`credential`) or an empty request (`request`); `status` its HTTP status, null when none came; `body` what it
 * said. Its code is the contract's for that when present, else the first Gray reads for it, else its first code.
 */
export function answerCoding(expected: AnswerExpected, status: number | null, body: Uint8Array): AnswerCoding {
  // An empty code (new-api's middleware sends `code: ""`) is none.
  const codes = providerMessage(body).codes.filter((c) => c !== "");
  const contract = expected === "credential" ? "credential_refused" : "request_invalid";
  const known = expected === "credential" ? AUTH_CODES : REQUEST_CODES;
  const code = codes.find((c) => c === contract) ?? codes.find((c) => known.includes(c)) ?? codes[0] ?? null;
  const coding: AnswerCodingKind = code === contract ? "contract" : code !== null && known.includes(code) ? "known" : "none";
  const asked = expected === "credential" ? "A request with a key that cannot be valid" : "A request with an empty body";
  const wanted = expected === "credential" ? "401 and the code credential_refused" : "400 and the code request_invalid";
  let warning: string | null;
  if (coding === "contract") warning = null;
  else if (status === null) warning = `${asked} got no answer, so Gray could not see its error code. Answer it with ${wanted} (Error answers).`;
  else if (coding === "known") warning = `${asked} was answered with HTTP ${status} and the code ${code}, which Gray reads; Gray's own answer is ${wanted} (Error answers).`;
  else
    warning = `${asked} was answered with HTTP ${status} and ${code === null ? "no error code" : `the code ${code}, which Gray does not read`}: Gray reads such an answer from its words until 2027-04-30, then by its status alone. Answer it with ${wanted} (Error answers).`;
  return { status, code, coding, warning };
}

/** How a message about a key refused opens (`AUTH_OPENINGS`). */
const AUTH_OPENINGS: readonly string[] = ["api key not valid", "api key expired", "incorrect api key provided", "invalid x-api-key"];

const rx = (source: string, flags = "iu") => new RegExp(source, flags);
/**
 * Rust's `{word}.*` on one line, as a gap V8 scans in linear time: the characters of the line up to the next `word`.
 * Rust's regex crate is linear in the text; V8's backtracking engine rescanned the rest of a 64 KiB line once per
 * `word` in it (0.35-0.4 s for a supplier's body of one word repeated, 2026-10-25). A test answers the same: when the
 * line holds the second part after a later `word` too, the match from that later `word` finds it.
 */
const lineAfter = (word: string) => `(?:(?!${word})${DOT})*`;

/** magpie's `brokeWords`: the balance itself is spent. */
const BROKE = rx(`insufficient${DOT}?(?:balance|credit|fund)|${B}credits? (?:are )?exhausted${B}|余额不足|欠费|请充值`);
/** magpie's `creditWords`, without "suspended" and "账户…停". */
const CREDIT = rx(`insufficient${DOT}?(?:balance|credit|fund)|balance|credit|billing|payment|arrear|overdue|余额|欠费|充值|账户${lineAfter("账户")}不足`);
/** magpie's `usedUpWords`: the plan's allowance is used for now. */
const USED_UP = rx(`quota|usage${DOT}?limit|out of budget|budget (?:exceeded|exhausted)|limit${DOT}?reached|hit your ${lineAfter("hit your ")}limit|limit${DOT}{0,24}resets|exceeded${lineAfter("exceeded")}(?:plan|limit)|额度|用量|套餐|上限`);
/** magpie's `rateWords`: a short limit, per second or minute. */
const RATE = rx(`rate${DOT}?limit|too many requests|per${DOT}?(?:second|sec|minute|min)${B}|${B}[rt]pm${B}|频率|太频繁`);
/** magpie's `plannedWords`: the plan's own allowance, rate words or not. */
const PLANNED = rx(`quota|usage${DOT}?limit|hit your ${lineAfter("hit your ")}limit|limit${DOT}{0,24}resets|per${DOT}?(?:day|week|month)|daily|weekly|monthly|额度|用量|套餐|限额已用完`);
/** An upstream's load, not the plan's. */
const LOAD = rx(`负载|饱和|繁忙|overload|over capacity|server is busy`);
/** Claude Code's "usage limit reached|<unix>". */
const QUOTA_WORDS = rx(`limit reached\\|${D}{10}${B}`);
/**
 * Google's quota windows in its words, per minute or per day alike (the Rust's `(?im)`: `^` at each line's start). The
 * space after a line's start stops at the next newline: Rust's `\s*` would run on into the lines below, which V8
 * rescanned from every line start (2 s for a 64 KiB body of newlines, 2026-10-25), and a phrase after such a run is
 * also the phrase after its last line's start, so a test answers the same.
 */
const GOOGLE_WINDOW = rx(`${LINE_START}(?:(?!\n)${S})*(?:you exceeded your current quota|resource has been exhausted)|${B}quota exceeded for (?:quota )?metric${B}|${B}[a-z0-9-]+\\.googleapis\\.com/`);
/** A per-second or per-minute window, however it is spelled. */
const SHORT_WINDOW = rx(`per[${S}_-]?(?:second|minute)|per[${S}_-]?(?:sec|min)${B}|${B}[rt]p[ms]${B}|每分钟|每秒`);
/** OpenAI's refusal of a request larger than the limit itself. */
const TOO_LARGE = rx(`${B}request too large${B}|${B}tokens must be reduced${B}`);
/** OpenAI's "Limit 30000, Requested 36412". */
const LIMIT_REQUESTED = rx(`${B}limit:?${S}*([${D},]+)${S}*,${S}*requested:?${S}*([${D},]+)`, "giu");
/** What vendors leave off a model's id when they name it: a date or version suffix. */
const VERSION_SUFFIX = rx(`(?:-${D}{4}-${D}{2}-${D}{2}|-${D}{8}|@${D}{8}|-${D}{3,4}|-latest)$`, "u");
/** OpenAI's "Rate limit reached for <model> in organization <org> on …". */
const ORGANIZATION_MODEL = rx(`${B}for ${NOT_S}+ in organization${B}`);
/** An account its vendor suspended or banned, with the account as the subject. */
const RESTRICTED = rx(
  `(?:account|organi[sz]ation|workspace|账号|账户|帐号|帐户)[^.。!！]{0,60}?(?:suspend|banned|terminated|disabled|deactivated|restricted|violat|terms of service|封禁|停用|禁用|限制使用|冻结)`,
);
/** magpie's `otherModels` and `clineFreeLimit`: the limit is one model's. */
const OTHER_MODELS = rx(`switch(?:ing)? to (?:the )?other models?|切换(?:到)?其他模型`);
const FREE_LIMIT = rx(`free limit reached on model`);
/** magpie's `resetsWhen`: a reset time with a whole date and time and its offset, then 重置, punctuation or the end. */
const ZONED = rx(
  `(?:${B}resets? at|将在|将于)${S}*(${D}{4}-${D}{1,2}-${D}{1,2})[ T](${D}{1,2}:${D}{2}:${D}{2})${S}*(?:UTC|GMT)([+-])(${D}{1,2})(?::?(${D}{2}))?(?:${S}*(?:重置|[,.;，。；])|${S}*$)`,
);
/** magpie's `zhipuResets`, with the Chinese forms: a time with no zone, Beijing's. */
const BEIJING = rx(`(?:${B}your limit will reset at|您的限额将在|将在|将于)${S}*(${D}{4}-${D}{1,2}-${D}{1,2})[ T](${D}{1,2}:${D}{2}(?::${D}{2})?)(${S}*${NOT_S}?)`);
/** magpie's `resetsInWords`, and a wait stated in words (Gemini's "Please retry in 41.596s.", OpenAI's "Please try again in 6m0s."). */
const RESETS_IN = rx(
  `${B}(?:resets? in|retry in|try again in)${S}+((?:${D}+${S}*(?:days?|d|hours?|hrs?|hr|h|minutes?|mins?|min|m|seconds?|secs?|sec|s)${B}[${S},]*)+|(?:${D}+(?:\\.${D}+)?(?:ms|h|m|s))+${B})`,
);
/** Claude Code's "usage limit reached|<unix>". */
const LIMIT_REACHED = rx(`limit reached\\|(${D}{10})${B}`);

/** `serde_json::from_slice::<Value>(body).ok()`. */
function serdeValue(body: Uint8Array): Json | undefined {
  try {
    return parseSerdeBytes(body);
  } catch (error) {
    if (error instanceof JsonError) return undefined;
    throw error;
  }
}

/** A body Google's OpenAI-compatible endpoint wraps in an array, as its first item (`items.first().unwrap_or(value)`). */
function firstItem(value: Json): Json {
  return Array.isArray(value) && value.length > 0 ? (value as readonly Json[])[0]! : value;
}

/**
 * The provider's error in a JSON body (`error_object`): its `error` member, or the body itself when it has none.
 * A body Google's OpenAI-compatible endpoint wraps in an array is read as its first item.
 */
function errorObject(value: Json): Json {
  const first = firstItem(value);
  // An `error` member that is null is the error read, as `Value::get` gives it.
  const error = get(first, "error");
  return error === undefined ? first : error;
}

/**
 * The words of an error body (`words_of`): the strings of its error object, decoded, one to a line (an object's
 * members in key order, as serde_json's map keeps them), and the body's own `message`, `msg` and `detail` beside
 * an `error` that is no object; a body that is not JSON as it is.
 */
function wordsOf(error: Json | undefined, value: Json | undefined, body: Uint8Array): string {
  if (error === undefined || value === undefined) return LOSSY.decode(body);
  const out: string[] = [];
  const walk = (v: Json): void => {
    if (typeof v === "string") out.push(v, "\n");
    else if (Array.isArray(v)) for (const item of v as readonly Json[]) walk(item);
    else if (isObject(v)) for (const key of Object.keys(v).sort(compareUtf8)) walk((v as Readonly<Record<string, Json>>)[key]!);
  };
  walk(error);
  if (!isObject(error)) {
    const first = firstItem(value);
    for (const key of ["message", "msg", "detail"]) {
      const text = get(first, key);
      if (typeof text === "string") walk(text);
    }
  }
  return out.join("");
}

const LOSSY = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/**
 * Whether a failure's words name the route's model (`model_named`): the upstream or the requested model as written,
 * or without an organization's or `models/` prefix and a date or version suffix; OpenAI's "… for <model> in
 * organization …"; magpie's `otherModels` and `clineFreeLimit`.
 */
export function modelNamed(words: string, models: readonly [string, string]): boolean {
  const lower = words.toLowerCase();
  const named = (name: string) => [...name].length >= 4 && lower.includes(name);
  return (
    models.some((m) => {
      const model = rustTrim(m).toLowerCase();
      const bare = model.slice(model.lastIndexOf("/") + 1);
      const base = bare.replace(VERSION_SUFFIX, "");
      return named(model) || named(bare) || named(base);
    }) ||
    ORGANIZATION_MODEL.test(words) ||
    OTHER_MODELS.test(words) ||
    FREE_LIMIT.test(words)
  );
}

/** A rate limit's cause by its words, which no code decided, undefined when it is the request's own (`throttled`), in the Rust's order. */
function throttled(status: number, words: string): RestCause | undefined {
  if (TOO_LARGE.test(words) || requestedOverLimit(words)) return undefined;
  const planned = PLANNED.test(words);
  if (GOOGLE_WINDOW.test(words)) return "rate";
  if (BROKE.test(words)) return "credit";
  if (QUOTA_WORDS.test(words)) return "quota";
  if (status >= 500) return "rate";
  if (ZONED.test(words)) return "quota";
  if (SHORT_WINDOW.test(words) || ((RATE.test(words) || LOAD.test(words)) && !planned)) return "rate";
  if (USED_UP.test(words) || planned) return "quota";
  return "rate";
}

/** A u64 written in ASCII digits (`str::parse::<u64>`), as a bigint; undefined for anything else. */
function u64(text: string): bigint | undefined {
  if (!/^\+?[0-9]+$/.test(text)) return undefined;
  const n = BigInt(text);
  return n <= 0xffff_ffff_ffff_ffffn ? n : undefined;
}

/** OpenAI's "Limit 30000, Requested 36412" (`requested_over_limit`): the request alone asks for more than the limit allows. */
function requestedOverLimit(words: string): boolean {
  for (const found of words.matchAll(LIMIT_REQUESTED)) {
    const limit = u64(found[1]!.replaceAll(",", ""));
    const requested = u64(found[2]!.replaceAll(",", ""));
    if (limit !== undefined && requested !== undefined && requested > limit) return true;
  }
  return false;
}

/** Google's quota window in its error object (`google_window`): `RESOURCE_EXHAUSTED`, or a `QuotaFailure` or `RetryInfo` detail. */
function googleWindow(error: Json): boolean {
  const status = asStr(get(error, "status"));
  if (status !== undefined && status.toLowerCase() === "resource_exhausted" && /^[\x00-\x7f]*$/.test(status)) return true;
  return (asArray(get(error, "details")) ?? []).some((d) => {
    const kind = asStr(get(d, "@type"));
    return kind !== undefined && (kind.endsWith("google.rpc.QuotaFailure") || kind.endsWith("google.rpc.RetryInfo"));
  });
}

/** A refused credential's cause by its words, which no code decided, undefined when they say nothing finer (`credential`), in the Rust's order. */
function credential(status: number, opening: string, words: string): RestCause | undefined {
  const creditWords = CREDIT.test(words);
  if (BROKE.test(words)) return "credit";
  if (RESTRICTED.test(words)) return "restricted";
  if (status === 402 && USED_UP.test(words) && !creditWords) return "quota";
  if (status === 402 || creditWords) return "credit";
  if (USED_UP.test(words)) return "quota";
  if (status === 401 || AUTH_OPENINGS.some((o) => opening.startsWith(o))) return "auth";
  return undefined;
}

/**
 * The reset an upstream's words state (`words_reset`), in milliseconds, read only when neither its error's fields nor
 * its stated delay say one, and before the rate-limit reset headers, since the words name the limit that refused:
 * Claude Code's line, a time with its zone, one without, "resets in …". A time past, or zero, states none.
 */
function wordsReset(words: string, nowMs: number): number | undefined {
  return limitReached(words, nowMs) ?? zoned(words, nowMs) ?? beijing(words, nowMs) ?? resetsIn(words);
}

/** A header's value as `HeaderValue::to_str` reads it: visible ASCII, space and tab; trimmed. */
function headerValue(value: string): string | undefined {
  return /^[\t -~]*$/.test(value) ? value.trim() : undefined;
}

/**
 * The reset of the limit that refused, among the `*ratelimit*reset*` headers (`header_reset`): the latest of those
 * whose limit is spent (its `…remaining…` header 0, or its `…status…` header `rejected`), else the soonest. A field
 * repeated is one value each, as Rust's map holds them (the platform joins them with ", ").
 */
export function headerReset(headers: HeaderReader, nowMs: number): number | undefined {
  const resets: (readonly [string, number])[] = [];
  for (const name of headers.names?.() ?? []) {
    if (!(name.includes("ratelimit") && name.includes("reset"))) continue;
    const joined = headers(name);
    if (joined === null) continue;
    for (const field of joined.split(",")) {
      const text = headerValue(field);
      const reset = text === undefined ? undefined : resetValue(text, nowMs);
      if (reset !== undefined) resets.push([name, reset]);
    }
  }
  const first = (name: string): string | undefined => {
    const joined = headers(name);
    return joined === null ? undefined : headerValue(joined.split(",")[0]!);
  };
  const spent = (name: string) => rustF64(first(name.replace("reset", "remaining")) ?? "x") === 0 || first(name.replace("reset", "status"))?.toLowerCase() === "rejected";
  const spentResets = resets.filter(([name]) => spent(name)).map(([, reset]) => reset);
  if (spentResets.length > 0) return Math.max(...spentResets);
  return resets.length === 0 ? undefined : Math.min(...resets.map(([, reset]) => reset));
}

/** One reset header's value (`reset_value`): an RFC 3339 time, Unix seconds, or a duration. */
function resetValue(value: string, nowMs: number): number | undefined {
  const at = rfc3339(value);
  if (at !== undefined) return until(at, nowMs);
  if (/^[+-]?[0-9]+$/.test(value)) {
    const n = BigInt(value);
    return n >= -(2n ** 63n) && n < 2n ** 63n ? unixSeconds(Number(n), nowMs) : spanMs(value);
  }
  return spanMs(value);
}

/**
 * chrono's `DateTime::parse_from_rfc3339`, in Unix milliseconds (fractions of one kept): `YYYY-MM-DD`, then `T`,
 * `t` or a space, `hh:mm:ss`, an optional fraction, and `Z`, `z` or `±hh:mm`; a leap second (`60`) is the next
 * second's start.
 */
function rfc3339(text: string): number | undefined {
  const found = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:([Zz])|([+\-−])([0-9]{2}):([0-9]{2}))$/.exec(text);
  if (found === null) return undefined;
  const [year, month, day, hour, minute, second] = found.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const fraction = found[7] === undefined ? 0 : Number(`0.${found[7].slice(0, 9)}`);
  if (found[8] === undefined && (Number(found[10]) > 23 || Number(found[11]) > 59)) return undefined;
  const offsetMinutes = found[8] !== undefined ? 0 : (found[9] === "+" ? 1 : -1) * (Number(found[10]) * 60 + Number(found[11]));
  const at = wallClock(year, month, day, hour, minute, second, true);
  return at === undefined ? undefined : at - offsetMinutes * 60_000 + fraction * 1000;
}

/**
 * A wall-clock time's Unix milliseconds at UTC, or undefined when the date or the time does not exist; `leap`
 * allows second 60 (chrono's leap second, which counts as the next minute's start).
 */
function wallClock(year: number, month: number, day: number, hour: number, minute: number, second: number, leap: boolean): number | undefined {
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > (leap ? 60 : 59)) return undefined;
  const at = Date.UTC(year, month - 1, day, hour, minute, Math.min(second, 59));
  const date = new Date(at);
  // Date.UTC treats years 0 to 99 as 1900 to 1999.
  if (year < 100) date.setUTCFullYear(year);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return undefined;
  return date.getTime() + (second === 60 ? 1000 : 0);
}

/** A reset at Unix `seconds` (`unix_seconds`): a time from 2001 (1e9) to 5138 (1e11); outside them, such as milliseconds, none. */
function unixSeconds(seconds: number, nowMs: number): number | undefined {
  return seconds >= 1_000_000_000 && seconds < 100_000_000_000 ? until(seconds * 1000, nowMs) : undefined;
}

/** `until`: from `nowMs` to `atMs`, when that is after now. */
function until(atMs: number, nowMs: number): number | undefined {
  const ms = atMs - nowMs;
  return ms > 0 ? ms : undefined;
}

function limitReached(words: string, nowMs: number): number | undefined {
  const found = LIMIT_REACHED.exec(words);
  const seconds = found === null ? undefined : u64(found[1]!);
  return seconds === undefined ? undefined : unixSeconds(Number(seconds), nowMs);
}

/** The ChatGPT backend's `resets_at` and `resets_in_seconds` in the error object (`resets_fields`). */
function resetsFields(error: Json | undefined, nowMs: number): number | undefined {
  if (error === undefined) return undefined;
  const at = get(error, "resets_at");
  // `as_i64`: an integer within i64.
  const atReset = typeof at === "bigint" && at >= -(2n ** 63n) && at < 2n ** 63n ? unixSeconds(Number(at), nowMs) : undefined;
  if (atReset !== undefined) return atReset;
  const inSeconds = get(error, "resets_in_seconds");
  return typeof inSeconds === "bigint" && inSeconds > 0n && inSeconds <= 0xffff_ffff_ffff_ffffn ? Number(inSeconds) * 1000 : undefined;
}

function zoned(words: string, nowMs: number): number | undefined {
  const found = ZONED.exec(words);
  if (found === null) return undefined;
  const hours = asciiInt(found[4]!);
  const minutes = found[5] === undefined ? 0 : asciiInt(found[5]);
  if (hours === undefined || minutes === undefined || hours > 14 || minutes > 59) return undefined;
  const sign = found[3] === "-" ? -1 : 1;
  return writtenAt(found[1]!, found[2]!, sign * (hours * 60 + minutes), nowMs);
}

function beijing(words: string, nowMs: number): number | undefined {
  const found = BEIJING.exec(words);
  if (found === null) return undefined;
  // A zone after the time, or more of the time: not this form, and a zone it cannot read states nothing.
  const after = (found[3] ?? "").replace(new RegExp(`^${S}+`, "u"), "");
  if (/^[A-Za-z0-9:+\-(]/.test(after)) return undefined;
  return writtenAt(found[1]!, found[2]!, 8 * 60, nowMs);
}

/** A number in ASCII digits as `str::parse::<i32>` reads one, or undefined. */
function asciiInt(text: string): number | undefined {
  return /^[+-]?[0-9]+$/.test(text) && Math.abs(Number(text)) <= 2_147_483_647 ? Number(text) : undefined;
}

/**
 * A date and a time of day as written, at `offsetMinutes` east of UTC (`written_at`, chrono's
 * `%Y-%m-%d %H:%M:%S`, else `%Y-%m-%d %H:%M`): a date or a time that does not exist states nothing.
 */
function writtenAt(date: string, time: string, offsetMinutes: number, nowMs: number): number | undefined {
  const d = /^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})$/.exec(date);
  const t = /^([0-9]{1,2}):([0-9]{2})(?::([0-9]{2}))?$/.exec(time);
  if (d === null || t === null) return undefined;
  const at = wallClock(Number(d[1]), Number(d[2]), Number(d[3]), Number(t[1]), Number(t[2]), t[3] === undefined ? 0 : Number(t[3]), true);
  return at === undefined ? undefined : until(at - offsetMinutes * 60_000, nowMs);
}

function resetsIn(words: string): number | undefined {
  const found = RESETS_IN.exec(words);
  if (found === null) return undefined;
  return spanMs(found[1]!.replace(/[, \n]+$/, ""));
}
