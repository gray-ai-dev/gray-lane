/// <reference path="./luxon.d.ts" />
/**
 * What a client is told when no attempt gets past an upstream's failure, and the readers and wordings
 * that decide it (crates/gray-gateway/src/upstream_errors.rs, held to the fixtures of area
 * `upstream-errors`; `classify` itself is classify.ts).
 *
 * - a refusal of the request (`refusal`, `final_refusal`) is passed on as a direct call would have
 *   returned it: the provider's status, coded `context_length_exceeded` for an overflow and
 *   `provider_request_rejected` otherwise, with the provider's message cleaned of anything that
 *   identifies the provider, its account or a relay (`refused`). A refusal that carries a server code
 *   gets Gray's sentence instead of the relay's "try again later" (`serverCodedRefusal`). A 404 of the
 *   mapping is passed on the same way.
 * - a block on the supplier's account: `502 upstream_account_refused`, final, in Gray's words for the
 *   block (`accountRefused`);
 * - a rate limit: `429 upstream_rate_limited` with the provider's own `retry-after`, and none when it
 *   stated none (`rateLimited`);
 * - no image drawn: `502 upstream_no_image`, which the client may send again (`noImage`);
 * - the provider's own account: `502 upstream_auth_failed`;
 * - any other failure: `502 upstream_rejected` with the provider's status (`failed`), or
 *   `502 upstream_unavailable` when no upstream answered.
 *
 * Text is handled as Rust handles it: trimming and splitting on Unicode White_Space, counting
 * characters as code points, lengths in UTF-8 bytes, invalid UTF-8 replaced as
 * `String::from_utf8_lossy` replaces it, and the patterns written with Rust regex's Unicode classes
 * (`\w`, `\d`, `\s`, `\b`) spelled out as Unicode properties. Redaction finds the matches of
 * Rust's one pattern without running it as one V8 pattern (`replaceIdentifiers`), so that its time
 * stays linear in the message as Rust's engine is, on any provider's error body.
 */
import { asArray, asStr, get, item, JsonError, parseSerdeBytes, utf8Length, type Json } from "@gray/json";
import { madeNoImage } from "@gray/protocol";
import { DateTime, Settings } from "luxon";
import { ApiError } from "./api-error.ts";
import { B, D, NOT_S, S, W, W_INNER } from "./rust-regex.ts";

// The three values below are the server's own constants (upstream_errors.rs `ERROR_BODY_LIMIT`,
// `ERROR_BODY_WAIT`, `MESSAGE_LIMIT`), chosen there without an external source; they are kept so the
// two versions answer alike.

/** The most of a provider's error body Gray reads: 64 KiB (server value). */
export const ERROR_BODY_LIMIT = 64 * 1024;
/**
 * The longest Gray waits for a provider's error body, within the request's deadline: 10 s (server
 * value). An error body is small, and a provider that sends the status and then stalls must not hold
 * the request and its failover until the deadline.
 */
export const ERROR_BODY_WAIT_MS = 10_000;
/** The longest provider message passed on, in characters: 600 (server value). */
export const MESSAGE_LIMIT = 600;
/**
 * A block the upstream vendor put on the supplier's upstream account for a kind of request, which every route
 * of that supplier shares (upstream_errors.rs `AccountBlock`): `flagged`, the vendor flagged the request pattern
 * on the account, "up to 1 hour" by its own wording; `third_party_apps`, the vendor takes no requests of
 * third-party apps on the account's plan, with no stated end. The label is the name operations, metrics and the
 * client's `metadata.account_block` give it.
 */
export type AccountBlock = "flagged" | "third_party_apps";

/** Every block, in the server's order (`AccountBlock::ALL`). */
export const ACCOUNT_BLOCKS: readonly AccountBlock[] = ["flagged", "third_party_apps"];

/**
 * How a message opens when the upstream vendor refuses a kind of request on the supplier's account, each with
 * the evidence it was taken from (`ACCOUNT_BLOCK_OPENINGS`). Only the opening of the trimmed, lower-cased
 * message is compared, so a quote inside another message never matches. New wording goes here, with its
 * evidence; unknown wording stays a refusal.
 */
const ACCOUNT_BLOCK_OPENINGS: readonly (readonly [string, AccountBlock])[] = [
  // yylx, 2026-10-15: "This request pattern was previously flagged as third-party by Anthropic. Check
  // claude.ai/settings/usage, or wait up to 1 hour for the automatic block to expire."
  ["this request pattern was previously flagged as third-party", "flagged"],
  // yylx, 2026-10-18, on every OpenCode tool turn of its Claude models (requests 6cbbdffc, 045d0f63,
  // 310b8db2): "Third-party apps now draw from extra usage, not plan limits. Ask your workspace admin to add
  // more and keep going." It served OpenCode's title requests, and on 2026-10-19 the same turns again.
  ["third-party apps now draw from extra usage", "third_party_apps"],
];
/** Codes of a request longer than the context window. */
export const OVERFLOW_CODES: readonly string[] = ["context_length_exceeded", "model_context_window_exceeded", "request_too_large"];

/** What to do with one error status. */
export type Disposition =
  /** Tell the client now (400, 413, 422). */
  | "request"
  /** Try another route, then tell the client (404). */
  | "request_unless_failover"
  /** The provider refused Gray's credential or account (401, 402, 403). */
  | "credential"
  /** The provider is rate limiting (429). */
  | "rate_limited"
  /** Anything else: the provider failed. */
  | "failure";

export function disposition(status: number): Disposition {
  if (status === 400 || status === 413 || status === 422) return "request";
  if (status === 404) return "request_unless_failover";
  if (status >= 401 && status <= 403) return "credential";
  if (status === 429) return "rate_limited";
  return "failure";
}

/** An error body that shows the provider's own failure rather than the request's. */
export interface ProviderFault {
  /** How the attempt is handled instead. */
  readonly disposition: Disposition;
  /**
   * The body states it in a machine code, which no request can put there. A fault read from the
   * wording of the message alone still fails over, but is not held against the route.
   */
  readonly coded: boolean;
  /** The message's words decided it (ERROR_TEXT_FALLBACK's legacy reading): with the fallback off it is none. */
  readonly words: boolean;
}

const WHITE_SPACE = String.raw`\p{White_Space}`;
const TRIM = new RegExp(`^${WHITE_SPACE}+|${WHITE_SPACE}+$`, "gu");
const SPACES = new RegExp(`${WHITE_SPACE}+`, "u");

/** `str::trim`: Unicode White_Space at both ends (a BOM is not white space; U+0085 is). */
export function rustTrim(text: string): string {
  return text.replace(TRIM, "");
}

const lossy = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** `String::from_utf8_lossy`: each maximal invalid subpart becomes U+FFFD; a BOM stays. */
export function utf8Lossy(bytes: Uint8Array): string {
  return lossy.decode(bytes);
}

/** `serde_json::from_slice::<Value>(body).ok()`. */
function serdeValue(body: Uint8Array): Json | undefined {
  try {
    return parseSerdeBytes(body);
  } catch (error) {
    if (error instanceof JsonError) return undefined;
    throw error;
  }
}

/**
 * The message of an error body in any of the common shapes (`error.message`; `error` as a string;
 * `message`; `detail`; `errors[0].message`), or the body itself when it is short plain text (at most
 * `MESSAGE_LIMIT` bytes, not markup); and the machine codes it states, lowercased: codes, types and
 * statuses, and each Google `error.details` entry's `reason` and `@type` (without its
 * `type.googleapis.com/` prefix).
 */
export function providerMessage(body: Uint8Array): { readonly message: string | undefined; readonly codes: readonly string[] } {
  const value = serdeValue(body);
  if (value === undefined) {
    const text = rustTrim(utf8Lossy(body));
    const plain = text.length > 0 && !text.startsWith("<") && utf8Length(text) <= MESSAGE_LIMIT;
    return { message: plain ? text : undefined, codes: [] };
  }
  const error = get(value, "error");
  const candidates: (Json | undefined)[] = [get(error, "message"), error, get(value, "message"), get(value, "detail"), get(item(get(value, "errors"), 0), "message")];
  const message = candidates.map(asStr).find((text) => text !== undefined);
  const codes: string[] = [get(error, "code"), get(error, "type"), get(error, "status"), get(value, "code"), get(value, "type")]
    .map(asStr)
    .filter((code): code is string => code !== undefined)
    .map((code) => code.toLowerCase());
  const details = asArray(get(error, "details"));
  if (details !== undefined) {
    for (const detail of details) {
      const reason = asStr(get(detail, "reason"));
      if (reason !== undefined) codes.push(reason.toLowerCase());
    }
    for (const detail of details) {
      const kind = asStr(get(detail, "@type"));
      if (kind !== undefined) codes.push((kind.split("/").pop() ?? kind).toLowerCase());
    }
  }
  return { message, codes };
}

/** Phrases providers use for a request longer than the context window (Rust `.` is any character but `\n`). */
const OVERFLOW = new RegExp(
  [
    "prompt is too long",
    "input is too long",
    "context[_ ]length[_ ]exceeded",
    "context[_ ]window",
    "maximum context length",
    "context length is only",
    "longer than the model'?s context",
    "exceeds the (?:model'?s )?(?:maximum )?(?:context|input)",
    "input token count[^\\n]*exceeds",
    "too many (?:input )?tokens",
    "reduce the length of the messages",
  ].join("|"),
  "iu",
);

export function isContextOverflow(message: string): boolean {
  return OVERFLOW.test(message);
}

/** Codes of the provider's own key, credit, quota or account refused upstream (`providerFault`). */
export const ACCOUNT_CODES: readonly string[] = [
  // Google ErrorInfo reasons and statuses.
  "api_key_invalid",
  "api_key_expired",
  "api_key_service_blocked",
  "consumer_suspended",
  "service_disabled",
  "billing_disabled",
  "failed_precondition",
  "permission_denied",
  "unauthenticated",
  // OpenAI and Anthropic. `usage_not_included` is how the ChatGPT backend refuses an account whose plan
  // does not include the use (Codex: `is_usage_not_included`); behind a relay, that is the provider's account.
  "invalid_api_key",
  "insufficient_quota",
  "usage_not_included",
  "billing_not_active",
  "billing_error",
  "authentication_error",
  "permission_error",
  "deactivated_workspace",
  // new-api and sub2api.
  "insufficient_user_quota",
  "pre_consume_token_quota_failed",
  "api_key_quota_exhausted",
  "insufficient_balance",
  "api_key_disabled",
  // Gray's error contract (rests.ts `CONTRACT_ACCOUNT`).
  "balance_exhausted",
  "account_suspended",
  "credential_refused",
];
/**
 * Codes of a route that does not serve the model (`MODEL_MISSING_CODES`): OpenAI's and the relays' `model_not_found`,
 * new-api's `model_price_error` (the relay has no price for the model, relay/request_billing.go) and the contract's
 * `model_unavailable`.
 */
const MODEL_MISSING_CODES: readonly string[] = ["model_not_found", "model_price_error", "model_unavailable"];
/** How vendors and relays begin a message about the provider's own account, for bodies without a code for it. */
const ACCOUNT_OPENINGS: readonly string[] = [
  "your credit balance is too low",
  "this organization has been disabled",
  "your organization has been disabled",
  "identity verification is required",
  "you exceeded your current quota",
  "the security token included in the request is invalid",
  "your account is not authorized",
  "operation not allowed",
  "api key not valid",
  "api key expired",
  "user location is not supported",
  "gemini api free tier is not available",
  "api key 额度已用完",
  "用户额度不足",
];
/** How a relay without a channel or account for the model begins it. */
const UNAVAILABLE_OPENINGS: readonly string[] = ["no available channel", "no available accounts", "no provider serves model"];
/** Wording that shows a message quotes the request. */
const QUOTES_THE_REQUEST: readonly string[] = ["unrecognized request argument", "unknown parameter", "unknown name", "extra inputs are not permitted", "additional properties", "invalid value", "invalid schema"];

/** Whether a lower-cased message quotes the request (`quotes_the_request`): its wording then decides nothing about the provider. */
export function quotesTheRequest(message: string): boolean {
  return QUOTES_THE_REQUEST.some((q) => message.includes(q));
}

/** A code that names an account's state: `{subject}_{state}` or `{state}_{subject}`, such as `account_deactivated`. */
export function accountState(code: string): boolean {
  for (const subject of ["workspace", "account", "organization", "org"]) {
    for (const state of ["deactivated", "disabled", "suspended"]) {
      if (code === `${subject}_${state}` || code === `${state}_${subject}`) return true;
    }
  }
  return false;
}

/**
 * How to treat an error body that shows the provider's own failure rather than the request's, for a
 * status `disposition` would pass on to the client or call a rate limit: `credential` when the
 * provider's key, credit, quota or account was refused upstream, `failure` when a relay has no
 * channel or account for the model; undefined for anything else, a context overflow included. A
 * 429 becomes `credential` only by an explicit code for an exhausted quota or credit, and never
 * when it names a quota window. Codes decide first; wording (`text`, ERROR_TEXT_FALLBACK) counts only
 * when no code does, only at the very start of the message, and never in a message that quotes the
 * request, and such a fault is not `coded`.
 */
export function providerFault(disposition: Disposition, body: Uint8Array, text: boolean): ProviderFault | undefined {
  if (disposition !== "request" && disposition !== "request_unless_failover" && disposition !== "rate_limited") return undefined;
  const read = providerMessage(body);
  const message = rustTrim(read.message ?? "").toLowerCase();
  const codes = read.codes;
  const overflow = codes.some((c) => OVERFLOW_CODES.includes(c)) || isContextOverflow(message);
  if (overflow) return undefined;
  const accountCoded = codes.some((c) => ACCOUNT_CODES.includes(c) || accountState(c));
  if (disposition === "rate_limited") {
    const quotaWindow = codes.some((c) => c === "resource_exhausted" || c === "google.rpc.retryinfo" || c === "google.rpc.quotafailure");
    return accountCoded && !quotaWindow ? { disposition: "credential", coded: true, words: false } : undefined;
  }
  if (accountCoded) return { disposition: "credential", coded: true, words: false };
  if (codes.some((c) => MODEL_MISSING_CODES.includes(c))) return { disposition: "failure", coded: true, words: false };
  if (!text) return undefined;
  // Anthropic's 404 `not_found_error`, whose words alone say it is the model it does not serve ("model: …").
  if (codes.includes("not_found_error") && message.startsWith("model:")) return { disposition: "failure", coded: true, words: true };
  if (quotesTheRequest(message)) return undefined;
  if (ACCOUNT_OPENINGS.some((o) => message.startsWith(o))) return { disposition: "credential", coded: false, words: true };
  // new-api: "当前分组 {group} 下对于模型 {model} 无可用渠道"; sub2api: `Model "{model}" is not supported by
  // any configured account in this group`.
  const unavailable =
    UNAVAILABLE_OPENINGS.some((o) => message.startsWith(o)) ||
    (message.startsWith("当前分组") && message.includes("无可用渠道")) ||
    (message.startsWith('model "') && message.includes('" is not supported by any configured account'));
  return unavailable ? { disposition: "failure", coded: false, words: true } : undefined;
}

/**
 * The block an upstream error `body` states, when it opens as the vendor's refusal of a kind of request on the
 * supplier's account does (`account_block`): a block on that account, which serves all of the supplier's
 * routes, not a verdict on the request or the route. The one classifier of it, for serving, checks and the
 * coding-agent proof.
 */
export function accountBlock(body: Uint8Array): AccountBlock | undefined {
  return opensBlock(rustTrim(providerMessage(body).message ?? "").toLowerCase());
}

/**
 * Whether an upstream error `body` is the vendor's refusal of a request pattern it flagged on the supplier's
 * account, for up to an hour by its own wording (`account_flagged`): the one block a check's refusal carries a
 * pass through.
 */
export function accountFlagged(body: Uint8Array): boolean {
  return accountBlock(body) === "flagged";
}

/** The block a lowercased, trimmed provider message opens with (`opens_block`). */
export function opensBlock(opening: string): AccountBlock | undefined {
  return ACCOUNT_BLOCK_OPENINGS.find(([words]) => opening.startsWith(words))?.[1];
}

/**
 * Whether a 404's body says that something the request itself names does not exist, rather than the model
 * or the path Gray sent it to: OpenAI's Responses API answers `previous_response_not_found` for a
 * `previous_response_id` it does not hold, which no other provider's account holds either.
 */
export function namesWhatTheRequestReferenced(body: Uint8Array): boolean {
  return providerMessage(body).codes.includes("previous_response_not_found");
}

/**
 * How an upstream response's headers are read: the value of a header, as the platform's `Headers.get`
 * gives it (repeated fields joined with ", "), or null; and, for a reader that has them, every header's
 * name, lower-cased (`names`), which the rests' reset headers are found by (`HeaderMap::iter`).
 */
export interface HeaderReader {
  (name: string): string | null;
  readonly names?: () => Iterable<string>;
}

/** A reader of a `Headers` object. */
export function headerReader(headers: Headers): HeaderReader {
  return Object.assign((name: string) => headers.get(name), { names: () => headers.keys() });
}

/** Visible ASCII, space and tab: what `HeaderValue::to_str` accepts. */
const VISIBLE_ASCII = /^[\t -~]*$/;

/**
 * A header's text as Rust reads the first field of that name (`HeaderMap::get`, then `to_str`, then
 * `trim`): undefined when absent or not visible ASCII. A Workers `Headers.get` joins repeated fields with
 * ", "; when the joined text is not one value `accept` takes, the first field is read: the text before the
 * first comma when `accept` takes it, else, for a value with commas of its own (an HTTP date has one), the
 * text before the second comma.
 */
function headerText(headers: HeaderReader, name: string, accept: (text: string) => boolean): string | undefined {
  const joined = headers(name);
  if (joined === null || !VISIBLE_ASCII.test(joined)) return undefined;
  const whole = rustTrim(joined);
  if (accept(whole) || !whole.includes(",")) return whole;
  const parts = whole.split(",");
  const first = rustTrim(parts[0] as string);
  if (accept(first) || parts.length < 3) return first;
  return rustTrim(parts.slice(0, 2).join(","));
}

/** The upstream's `x-should-retry`, which the SDKs and OpenCode obey before their own status rules. */
export function shouldRetryHeader(headers: HeaderReader): boolean | undefined {
  const value = headerText(headers, "x-should-retry", (text) => /^(true|false)$/i.test(text));
  if (value === undefined) return undefined;
  if (value.toLowerCase() === "true") return true;
  if (value.toLowerCase() === "false") return false;
  return undefined;
}

/**
 * Rust's `str::parse::<f64>` grammar (core::num::dec2flt): an optional sign, then `inf`, `infinity` or
 * `nan` in any case, or digits with an optional fraction and exponent; no white space.
 */
const RUST_F64 = /^[+-]?(?:inf|infinity|nan|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?)$/i;

export function rustF64(text: string): number | undefined {
  if (!RUST_F64.test(text)) return undefined;
  const bare = text.replace(/^[+-]/, "").toLowerCase();
  if (bare === "nan") return Number.NaN;
  if (bare === "inf" || bare === "infinity") return text.startsWith("-") ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY;
  return Number(text);
}

/** 2^64: `Duration::try_from_secs_f64` refuses this many seconds and more. */
const DURATION_SECONDS_LIMIT = 18446744073709551616;

/**
 * A positive, finite number of seconds as milliseconds, rounded to the nanosecond as
 * `Duration::try_from_secs_f64` rounds it; undefined for zero or less, NaN, infinity, or more seconds than
 * a `Duration` holds.
 */
function positiveMs(seconds: number): number | undefined {
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds >= DURATION_SECONDS_LIMIT) return undefined;
  const nanos = seconds * 1e9;
  return nanos <= Number.MAX_SAFE_INTEGER ? Math.round(nanos) / 1e6 : seconds * 1000;
}

/**
 * chrono's RFC 2822 parser (`DateTime::parse_from_rfc2822`) reads two-digit years 0..=49 as 20xx and
 * 50..=99 as 19xx; luxon reads a year above its cutoff (`Settings.twoDigitCutoffYear`, a global) as 19xx.
 * The cutoff is set to chrono's only for the parse and restored after it, so no other luxon user in the
 * same Worker sees it changed.
 */
const CHRONO_TWO_DIGIT_CUTOFF = 49;

function fromRfc2822(text: string): DateTime {
  const previous = Settings.twoDigitCutoffYear;
  Settings.twoDigitCutoffYear = CHRONO_TWO_DIGIT_CUTOFF;
  try {
    return DateTime.fromRFC2822(text);
  } finally {
    Settings.twoDigitCutoffYear = previous;
  }
}

/**
 * The day, month and zone names chrono compares without case, in the case luxon's parser takes them.
 * `UT` is written `GMT`: both are +0000 (RFC 2822 section 4.3, and chrono), and luxon 3.7.2 matches `UT`
 * but has no offset for it, so it would refuse the date.
 */
const RFC2822_NAMES: ReadonlyMap<string, string> = new Map([
  ...["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "GMT", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT", "Z"].map((name) => [name.toLowerCase(), name] as const),
  ["ut", "GMT"] as const,
]);

/**
 * The delay the provider's headers state, in milliseconds, in this order (the SDKs'
 * `_parse_retry_after_header`): `retry-after-ms`, `retry-after` in seconds (decimals allowed), `retry-after`
 * as an HTTP date counted from `nowMs` (luxon's RFC 2822 parser, its names in any case as chrono takes
 * them). A value of zero or less, or a date in the past, states none. Uncapped: clients bound their own
 * waits (`stated_delay`).
 */
export function statedDelay(headers: HeaderReader, nowMs: number): number | undefined {
  const ms = headerText(headers, "retry-after-ms", (text) => rustF64(text) !== undefined);
  const msValue = ms === undefined ? undefined : rustF64(ms);
  if (msValue !== undefined) return positiveMs(msValue / 1000);
  const value = headerText(headers, "retry-after", (text) => rustF64(text) !== undefined || fromRfc2822(text.replace(/[A-Za-z]+/g, (word) => RFC2822_NAMES.get(word.toLowerCase()) ?? word)).isValid);
  if (value === undefined) return undefined;
  const seconds = rustF64(value);
  if (seconds !== undefined) return positiveMs(seconds);
  const named = value.replace(/[A-Za-z]+/g, (word) => RFC2822_NAMES.get(word.toLowerCase()) ?? word);
  const at = fromRfc2822(named);
  if (!at.isValid) return undefined;
  return positiveMs((at.toMillis() - Math.floor(nowMs)) / 1000);
}

/** Google's `google.rpc.RetryInfo.retryDelay` in an error body, in milliseconds: a protobuf `Duration` in JSON, seconds with an `s` (`"35s"`, `"1.5s"`). */
export function retryInfo(body: Uint8Array): number | undefined {
  return retryDelay(get(serdeValue(body), "error"));
}

/** `retry_delay`: `retryInfo` of an error object already read, its `details`' `RetryInfo`. */
export function retryDelay(error: Json | undefined): number | undefined {
  const details = asArray(get(error, "details"));
  if (details === undefined) return undefined;
  for (const detail of details) {
    const kind = asStr(get(detail, "@type"));
    if (kind === undefined || !kind.endsWith("google.rpc.RetryInfo")) continue;
    const delay = asStr(get(detail, "retryDelay"));
    if (delay === undefined || !delay.endsWith("s")) continue;
    const seconds = rustF64(delay.slice(0, -1));
    if (seconds === undefined) continue;
    // `find_map` takes the first entry that parses; the filter after it applies to that one only.
    return Number.isFinite(seconds) && seconds > 0 ? positiveMs(seconds) : undefined;
  }
  return undefined;
}

/** Seconds to send as `Retry-After` for a delay in milliseconds: rounded up, never 0 (`retry::retry_after_seconds`). */
function retrySeconds(delayMs: number): bigint {
  return BigInt(Math.max(1, Math.ceil(Math.floor(delayMs) / 1000)));
}

/**
 * `429 upstream_rate_limited`: every route that could serve the request was rate limited. It carries the
 * provider's own `retry-after`, rounded up to seconds, and none when the provider stated none: Anthropic
 * documents a 429 without one as a spend cap that keeps failing, and an invented wait misinforms the client.
 */
export function rateLimited(retryAfterMs: number | undefined): ApiError {
  const error = new ApiError(429, "upstream_rate_limited").withMeta("limit_source", "provider_rate_limit");
  if (retryAfterMs === undefined) {
    return error
      .withMessage("Every provider that could serve this request is rate limiting it, and none said for how long. Retry later, or choose another model.")
      .withMeta("remedy_hint", "Retry later, or choose another model.");
  }
  const seconds = retrySeconds(retryAfterMs);
  return error
    .withMessage(`Every provider that could serve this request is rate limiting it. Retry in ${seconds} seconds.`)
    .withMeta("remedy_hint", "Retry after retry-after, or choose another model.")
    .withRetryAfter(seconds);
}

/** `502 upstream_auth_failed`: the provider's upstream refused Gray's credential or the provider's account. */
export function credentialRefused(model: string): ApiError {
  return new ApiError(502, "upstream_auth_failed").withMessage(
    `The provider serving \`${model}\` could not use its own upstream account (its credentials, credit or standing were refused), and no other provider could take the request. This is not a problem with your API key or your Gray balance; retry later, or choose another model.`,
  );
}

/**
 * `502 upstream_account_refused`: the upstream vendor refused this request on the supplier's account
 * (`block`), and no other provider could take it. Final now (`x-should-retry: false`): the same request fails
 * the same way until the block lifts. The vendor's text, which names its own console, its internal names or
 * "your workspace admin", is never passed on; `metadata.account_block` names the block. A flagged pattern is
 * told in the catalog's sentence (catalog.ts, docs/api-errors.md), naming the model: the vendor flags a kind
 * of request on the account, not one conversation, so a new conversation of the kind fares no better.
 */
export function accountRefused(model: string, block: AccountBlock): ApiError {
  const message =
    block === "flagged"
      ? `The provider serving \`${model}\` cannot take this request on its upstream account right now (\`metadata.account_block\` names why), and no other provider could take it. Sending it again now fails the same way: choose another model, or retry later.`
      : `The provider serving \`${model}\` does not take requests from third-party apps such as coding agents on its upstream account right now, and no other provider of \`${model}\` could take this one. Sending it again now fails the same way: choose another model (GET /v1/models lists them), or retry later.`;
  return new ApiError(502, "upstream_account_refused").withMessage(message).withMeta("account_block", block).noRetry();
}

/** `502 upstream_rejected` with the provider's status, and the provider's own `retry-after` when it sent one. */
export function failed(model: string, status: number, retryAfterMs?: number): ApiError {
  const error = new ApiError(502, "upstream_rejected")
    .withMessage(`The provider serving \`${model}\` failed (HTTP ${status}), and no other provider could take the request. Retry in a moment.`)
    .withMeta("provider_status", BigInt(status));
  return retryAfterMs === undefined ? error : error.withRetryAfter(retrySeconds(retryAfterMs));
}

/** The code of an image the upstream did not draw: the client's error and the failed attempt's in the request log. */
export const NO_IMAGE = "upstream_no_image";

/**
 * `502 upstream_no_image`: the provider's upstream drew no image for the request and said to send it
 * again, and no further attempt got past it. Nothing was drawn, so nothing is charged. It carries the
 * provider's own `retry-after` when it stated one; the dispatcher gives it one otherwise.
 */
export function noImage(model: string, retryAfterMs: number | undefined): ApiError {
  const error = new ApiError(502, NO_IMAGE).withMessage(
    `The provider serving \`${model}\` drew no image for this request and said to send it again. You are not charged. Send the request again; if it keeps failing, change the prompt or the reference images.`,
  );
  return retryAfterMs === undefined ? error : error.withRetryAfter(retrySeconds(retryAfterMs));
}

/**
 * A refusal whose body carries a server code (a relay's `api_error` 400 "Upstream request failed ...
 * Please try again later"): the provider's status, in Gray's words. The relay's advice to try again is
 * wrong there: replays of such a refusal were refused the same way (2026-10-15).
 */
export function serverCodedRefusal(status: number, model: string): ApiError {
  return new ApiError(status, "provider_request_rejected")
    .withMessage(
      `The provider serving \`${model}\` refused the request (HTTP ${status}) and reported it as a failure of its own, without saying what in the request it refused. Sending the same request again is likely to be refused the same way.`,
    )
    .withMeta("provider_status", BigInt(status));
}

/** `502 upstream_unavailable`: no upstream answered. */
export function upstreamUnavailable(): ApiError {
  return new ApiError(502, "upstream_unavailable");
}

/** What identifies a route's provider in its messages: its name and base URL. */
export interface EndpointNames {
  readonly name: string;
  readonly baseUrl: string;
}

/**
 * What a refusal is worded with: the model the client asked for, the upstream model the route sent and
 * the route's endpoint, whose names `clean` removes, and the (original, handle) pairs of the tool-call ids
 * the attempt sent in place of the client's handles, which `clean` names by their handles.
 */
export interface RefusalContext {
  readonly model: string;
  readonly upstreamModel: string;
  readonly endpoint: EndpointNames;
  readonly restored: readonly (readonly [string, string])[];
}

/**
 * The client's error for a provider's refusal of the request itself: the provider's status,
 * `request_body_limit` (413) for a size refusal, `context_length_exceeded` for a context overflow and
 * `provider_request_rejected` otherwise, with the provider's message cleaned by `clean`, which names a
 * tool-call id the attempt sent in place of the client's handle by that handle.
 */
export function refused(status: number, body: Uint8Array, context: RefusalContext): ApiError {
  const model = context.model;
  const read = providerMessage(body);
  const message = read.message === undefined ? undefined : clean(read.message, model, context.upstreamModel, context.endpoint, context.restored);
  // A 413 (or an explicit `request_too_large`) is a byte-size limit, not a context-window overflow.
  const tooLarge = status === 413 || read.codes.includes("request_too_large");
  const overflow = !tooLarge && status !== 404 && (read.codes.some((c) => OVERFLOW_CODES.includes(c)) || (message !== undefined && isContextOverflow(message)));
  let error: ApiError;
  if (tooLarge) {
    error = new ApiError(413, "request_body_limit").withMessage(
      message !== undefined
        ? `The request to \`${model}\` is larger than the provider serving it accepts. Send a smaller request. The provider said: ${message}`
        : `The request to \`${model}\` is larger than the provider serving it accepts. Send a smaller request.`,
    );
  } else if (overflow) {
    error = new ApiError(status, "context_length_exceeded").withMessage(
      message !== undefined
        ? `The request is longer than the context window of \`${model}\` (context_length_exceeded). Shorten or compact the conversation, then retry. The provider said: ${message}`
        : `The request is longer than the context window of \`${model}\` (context_length_exceeded). Shorten or compact the conversation, then retry.`,
    );
  } else {
    error = new ApiError(status, "provider_request_rejected").withMessage(
      message !== undefined
        ? `The provider serving \`${model}\` refused the request: ${message}`
        : `The provider serving \`${model}\` refused the request as invalid (HTTP ${status}), without saying why. Check the request against the API reference.`,
    );
  }
  return error.withMeta("provider_status", BigInt(status));
}

/** What a provider's error answer tells the provider itself: why a check of its endpoint was refused. */
export interface Diagnosis {
  /** The upstream's own message, redacted. Shown as data, never acted on. */
  readonly message: string | undefined;
  /**
   * `account`: its own key, credit, quota or account was refused; `model_unavailable`: a relay has no
   * channel for the model; `no_image`: the upstream drew no image and said to retry (@gray/protocol `madeNoImage`).
   */
  readonly fault: "account" | "model_unavailable" | "no_image" | undefined;
}

/** Reads a check's refusal for the endpoint's provider. `status` is the answer's HTTP status (200 for the error event of a stream). */
export function diagnose(status: number, body: Uint8Array): Diagnosis {
  const known = Number.isInteger(status) && status >= 100 && status <= 999 ? status : 502;
  const base = disposition(known);
  // The error event of a stream that answered 200 is read as a refusal of the request.
  const read: Disposition = base === "failure" && known >= 200 && known <= 299 ? "request" : base;
  // Advice to the supplier only, which routes nothing: the words are read whatever ERROR_TEXT_FALLBACK says.
  const fault = providerFault(read, body, true)?.disposition;
  const message = providerMessage(body).message;
  return {
    message: message === undefined ? undefined : redact(message),
    fault: madeNoImage(known, body) ? "no_image" : fault === "credential" ? "account" : fault === "failure" ? "model_unavailable" : read === "credential" ? "account" : undefined,
  };
}

/** Rust `regex::escape` for a literal in a `u` pattern: only the syntax characters are escaped. */
function escapeLiteral(text: string): string {
  return text.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function hostOf(url: string): string | undefined {
  try {
    const host = new URL(url).hostname;
    return host.length > 0 ? host : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The provider's message as it can be passed on: a tool-call id Gray sent in place of the client's handle
 * named by that handle (`restored`: original and handle), so the client sees an id it sent; the routed
 * upstream model named as the model the client asked for; the endpoint's name and host (each of at least
 * three characters) replaced, in any case; then `redact`. The names are replaced in the provider's own
 * text only, never inside a handle. Undefined when nothing is left.
 */
export function clean(original: string, model: string, upstreamModel: string, endpoint: EndpointNames, restored: readonly (readonly [string, string])[] = []): string | undefined {
  const message = withoutRequestIds(original);
  const names: RegExp[] = [];
  for (const raw of [endpoint.name, hostOf(endpoint.baseUrl)]) {
    if (raw === undefined) continue;
    const name = rustTrim(raw);
    if ([...name].length >= 3) names.push(new RegExp(escapeLiteral(name), "giu"));
  }
  const rename = (part: string): string => {
    let text = part;
    if (upstreamModel.length > 0 && upstreamModel !== model) text = text.replaceAll(upstreamModel, () => model);
    for (const name of names) text = text.replace(name, () => "the provider");
    return text;
  };
  let text = "";
  let at = 0;
  for (const [start, end, handle] of quotedOriginals(message, restored)) {
    text += rename(message.slice(at, start)) + handle;
    at = end;
  }
  text += rename(message.slice(at));
  return redact(text);
}

/**
 * `message` without a parenthesis that names a request id, with whatever name a relay gives its own system
 * before it, and the white space before the parenthesis: yylx appends "(luban request id: req_…) (request id:
 * 2026…)" to the vendor's text (2026-10-18). `redact` would leave "(luban [redacted])" behind, and the relay's
 * internal name with it. Replaced as Rust's `replace_all` does: leftmost matches, each search from the end of
 * the last. Linear in the message: every `(` is tried once with a bounded pattern, and the closing `)` is the
 * first after it, found once per match.
 */
export function withoutRequestIds(message: string): string {
  let out = "";
  let from = 0;
  for (let open = message.indexOf("(", from); open !== -1; open = message.indexOf("(", open + 1)) {
    REQUEST_ID_OPENING.lastIndex = open;
    if (!REQUEST_ID_OPENING.test(message)) continue;
    const close = message.indexOf(")", REQUEST_ID_OPENING.lastIndex);
    // No `)` after it: none after any later `(` either.
    if (close === -1) break;
    // The white space right before the parenthesis belongs to the match (`\s*`), not before the last match's end.
    let start = open;
    while (start > from && WHITE_UNIT.test(message[start - 1]!)) start -= 1;
    out += message.slice(from, start);
    from = close + 1;
    open = close;
  }
  return out + message.slice(from);
}


/** Whether a code unit may be part of an id: an ASCII letter or digit, `_` or `-`. */
function idUnit(unit: number | undefined): boolean {
  return unit !== undefined && ((unit >= 0x30 && unit <= 0x39) || (unit >= 0x41 && unit <= 0x5a) || (unit >= 0x61 && unit <= 0x7a) || unit === 0x5f || unit === 0x2d);
}

/**
 * Where `message` quotes an original Gray sent in place of a handle (`restored`: original and handle), with
 * that handle, in order (`quoted_originals`). An occurrence counts only standing on its own: no letter,
 * digit, `_` or `-` right before or after it, so a short original (`call_1`, `0`) is not found inside a
 * longer id or a number. Where several start at one place, the longest counts. A repeated original is
 * searched once, with its first handle. The work is a substring search per original that can be in the
 * message (one no longer than it), every place it stands found, overlapping ones included.
 */
function quotedOriginals(message: string, restored: readonly (readonly [string, string])[]): [number, number, string][] {
  const searched = new Set<string>();
  const found: [number, number, string][] = [];
  for (const [original, handle] of restored) {
    if (original.length === 0 || original.length > message.length || searched.has(original)) continue;
    searched.add(original);
    for (let start = message.indexOf(original); start !== -1; start = message.indexOf(original, start + 1)) {
      const end = start + original.length;
      if (!idUnit(start > 0 ? message.charCodeAt(start - 1) : undefined) && !idUnit(end < message.length ? message.charCodeAt(end) : undefined)) found.push([start, end, handle]);
    }
  }
  found.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const taken: [number, number, string][] = [];
  let end = 0;
  for (const occurrence of found) {
    if (occurrence[0] >= end) {
      end = occurrence[1];
      taken.push(occurrence);
    }
  }
  return taken;
}


/**
 * The start of a parenthesis that names a request id, with whatever name a relay gives its own system before
 * it (`without_request_ids`, Rust `(?i)\s*\((?:[\p{L}\w\- ]{1,32}\s)?request[ _\-]?id\b[^)]*\)`), matched
 * from one `(` only: a sticky pattern whose every part but the tail is bounded, so each try reads at most a few
 * dozen characters. The tail, `[^)]*\)`, is found with `indexOf`.
 */
const REQUEST_ID_OPENING = new RegExp(String.raw`\((?:[\p{L}${W_INNER}\- ]{1,32}${S})?request[ _\-]?id${B}`, "iuy");

/** One UTF-16 unit of Unicode White_Space (every White_Space character is in the BMP). */
const WHITE_UNIT = /^\p{White_Space}$/u;

/** A URL's scheme character; the first is a letter (`[a-z]`, without case). */
const URL_SCHEME = String.raw`[a-z0-9+.\-]`;
/** What follows a URL's scheme. */
const URL_TAIL = String.raw`://${NOT_S}+`;
/** A URL; it needs `://` in the text. */
const URL_PATTERN = String.raw`[a-z]${URL_SCHEME}*${URL_TAIL}`;
/** An e-mail address's local character. */
const EMAIL_LOCAL = String.raw`[${W_INNER}.+\-]`;
/** What follows an e-mail address's local part. */
const EMAIL_TAIL = String.raw`@[${W_INNER}\-]+(?:\.[${W_INNER}\-]+)+`;
/** An e-mail address; it needs `@` in the text. */
const EMAIL_PATTERN = String.raw`${EMAIL_LOCAL}+${EMAIL_TAIL}`;
/** IP addresses, bearer tokens, keys, UUIDs, request and account identifiers, long tokens. */
const OTHER_PATTERNS = [
  String.raw`${B}(?:${D}{1,3}\.){3}${D}{1,3}(?::${D}+)?${B}`,
  String.raw`${B}bearer${S}+${NOT_S}+`,
  String.raw`${B}(?:sk|rk|pk|ak)[\-_][a-z0-9_\-]{8,}`,
  String.raw`${B}gray_key_[0-9a-f]+`,
  String.raw`${B}AIza[0-9a-z_\-]{20,}`,
  String.raw`${B}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}${B}`,
  String.raw`${B}(?:req|request|msg|chatcmpl|resp|org|user|acct|account|proj|project|key|sess|trace)[_\-][a-z0-9]{6,}[a-z0-9_\-]*`,
  String.raw`${B}(?:request|trace|correlation)[ _\-]?id${B}${S}*[:=]?${S}*[a-z0-9_\-]{6,}`,
  String.raw`${B}[a-z0-9_\-]{32,}${B}`,
];

/** Gray's own tool-call handle, which redaction keeps: the client sent it, and it names the call that failed. */
const HANDLE_PATTERN = String.raw`${B}gtc1_[a-z0-9][0-9a-z]{27}${B}`;

/**
 * Rust `redact`'s pattern, alternatives in its order, with the `i` flag: the handle (kept), URL, e-mail,
 * then the others. `redact` finds the same leftmost-first matches without running it as one pattern.
 */
export const REDACT_PATTERN = [HANDLE_PATTERN, URL_PATTERN, EMAIL_PATTERN, ...OTHER_PATTERNS].join("|");

const OTHERS = new RegExp(OTHER_PATTERNS.join("|"), "giu");
const HANDLES = new RegExp(HANDLE_PATTERN, "giu");
const URL_RUNS = new RegExp(String.raw`(?<!${URL_SCHEME})${URL_SCHEME}+`, "giu");
const URL_NOT_FIRST = /[0-9+.\-]*/uy;
const EMAIL_RUNS = new RegExp(String.raw`(?<!${EMAIL_LOCAL})${EMAIL_LOCAL}+`, "giu");
const EMAIL_TAIL_AT = new RegExp(EMAIL_TAIL, "yiu");
const WHITE_SPACE_AT = new RegExp(WHITE_SPACE, "gu");

/** A match: where it starts and where it ends, in UTF-16 units. */
type Span = readonly [number, number];

/** A run of an alternative's characters: where it starts and ends, and where a match in it ends (null: none; undefined: not read yet). */
interface Run {
  readonly start: number;
  readonly end: number;
  matchEnd: number | null | undefined;
}

/**
 * The leftmost matches of the URL or the e-mail alternative, found in time linear in the text. Each
 * has the shape `first run* tail`, where `run` takes every `first` character and no character the
 * tail starts with (`:` and `@`). So it matches at a position exactly when that position holds a
 * `first` character inside a maximal run of `run` characters that the tail follows, and the match
 * always ends where that tail match ends: every start inside one run succeeds or fails alike.
 * A backtracking engine tries the alternative at each start and scans to the run's end each time,
 * quadratic in a long run; here the runs are listed once by the pattern engine, and a run's tail is
 * read once, only when a search reaches a run with a character that can start a match.
 */
class RunAlternative {
  private readonly runs: Run[] = [];
  private next = 0;
  private readonly text: string;
  /** Where a match in the run ending at `end` ends, or undefined when the tail does not follow. */
  private readonly tail: (end: number) => number | undefined;
  /** Skips the run characters that cannot start a match; undefined when every one can. */
  private readonly notFirst: RegExp | undefined;

  constructor(text: string, runs: RegExp, tail: (end: number) => number | undefined, notFirst: RegExp | undefined) {
    this.text = text;
    this.tail = tail;
    this.notFirst = notFirst;
    runs.lastIndex = 0;
    for (let run = runs.exec(text); run !== null; run = runs.exec(text)) this.runs.push({ start: run.index, end: run.index + run[0].length, matchEnd: undefined });
  }

  /** The leftmost match starting at `from` or later; `from` never decreases between calls. */
  find(from: number): Span | null {
    for (; this.next < this.runs.length; this.next += 1) {
      const run = this.runs[this.next] as Run;
      if (run.end <= from) continue;
      let first = Math.max(run.start, from);
      if (this.notFirst !== undefined) {
        this.notFirst.lastIndex = first;
        this.notFirst.test(this.text);
        first = this.notFirst.lastIndex;
      }
      if (first >= run.end) continue;
      if (run.matchEnd === undefined) run.matchEnd = this.tail(run.end) ?? null;
      if (run.matchEnd !== null) return [first, run.matchEnd];
    }
    return null;
  }
}

/** The URL alternative's matches in `text`. */
function urlAlternative(text: string): RunAlternative {
  // `://` then `\S+`, which ends at the next white space. Many tails can share one stretch without
  // white space, so the last white space found is kept and reused for every tail inside its stretch.
  let searchedFrom = Number.POSITIVE_INFINITY;
  let space = text.length;
  const nextSpace = (from: number): number => {
    if (from < searchedFrom || from > space) {
      WHITE_SPACE_AT.lastIndex = from;
      const hit = WHITE_SPACE_AT.exec(text);
      searchedFrom = from;
      space = hit === null ? text.length : hit.index;
    }
    return space;
  };
  const tail = (end: number): number | undefined => {
    if (!text.startsWith("://", end)) return undefined;
    const stop = nextSpace(end + 3);
    return stop > end + 3 ? stop : undefined;
  };
  return new RunAlternative(text, URL_RUNS, tail, URL_NOT_FIRST);
}

/** The e-mail alternative's matches in `text`. A tail reads only the run after its `@`, so tails never overlap. */
function emailAlternative(text: string): RunAlternative {
  const tail = (end: number): number | undefined => {
    EMAIL_TAIL_AT.lastIndex = end;
    return EMAIL_TAIL_AT.test(text) ? EMAIL_TAIL_AT.lastIndex : undefined;
  };
  return new RunAlternative(text, EMAIL_RUNS, tail, undefined);
}

/**
 * `message` with every match of `REDACT_PATTERN` replaced by `[redacted]`, as Rust's `Regex::replace_all`
 * replaces them: the leftmost match, and at one position the first alternative that matches there, then
 * the next search from its end; a match of the handle alternative is written back unchanged. The URL and
 * e-mail alternatives are found by `RunAlternative`, the handle and the others by a pattern each (V8 scans
 * those in linear time: each needs a word boundary or a literal to start), and the leftmost of the four
 * wins, the earlier alternative on a tie. Each search only moves forward, and an answer is reused while it
 * lies ahead of the next search.
 */
export function replaceIdentifiers(message: string): string {
  const urls = message.includes("://") ? urlAlternative(message) : undefined;
  const emails = message.includes("@") ? emailAlternative(message) : undefined;
  const handles = /gtc1_/i.test(message);
  if (urls === undefined && emails === undefined && !handles) return message.replace(OTHERS, "[redacted]");
  let out = "";
  let from = 0;
  let handle: Span | null | undefined = handles ? undefined : null;
  let url: Span | null | undefined;
  let email: Span | null | undefined;
  let other: Span | null | undefined;
  for (;;) {
    if (handle === undefined || (handle !== null && handle[0] < from)) {
      HANDLES.lastIndex = from;
      const hit = HANDLES.exec(message);
      handle = hit === null ? null : [hit.index, hit.index + hit[0].length];
    }
    if (urls !== undefined && (url === undefined || (url !== null && url[0] < from))) url = urls.find(from);
    if (emails !== undefined && (email === undefined || (email !== null && email[0] < from))) email = emails.find(from);
    if (other === undefined || (other !== null && other[0] < from)) {
      OTHERS.lastIndex = from;
      const hit = OTHERS.exec(message);
      other = hit === null ? null : [hit.index, hit.index + hit[0].length];
    }
    let pick: Span | null = null;
    for (const span of [handle, url, email, other]) if (span !== undefined && span !== null && (pick === null || span[0] < pick[0])) pick = span;
    if (pick === null) break;
    out += message.slice(from, pick[0]) + (pick === handle ? message.slice(pick[0], pick[1]) : "[redacted]");
    from = pick[1];
  }
  return out + message.slice(from);
}
const ALPHANUMERIC = /[\p{Alphabetic}\p{N}]/u;

/**
 * `message` with URLs, e-mail and IP addresses, keys, bearer tokens, UUIDs and request,
 * organization, account and project identifiers removed; white space collapsed; at most
 * `MESSAGE_LIMIT` characters (then an ellipsis). Undefined when nothing is left.
 */
export function redact(message: string): string | undefined {
  const replaced = replaceIdentifiers(message);
  let text = replaced.split(SPACES).filter((word) => word.length > 0).join(" ");
  const characters = [...text];
  if (characters.length > MESSAGE_LIMIT) text = `${characters.slice(0, MESSAGE_LIMIT).join("")}…`;
  const substance = text.replaceAll("[redacted]", "");
  return ALPHANUMERIC.test(substance) ? text : undefined;
}
