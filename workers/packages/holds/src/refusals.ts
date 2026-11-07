/**
 * The refusals a hold answers with, with their amounts (crates/gray-gateway/src/inference.rs
 * `account_in_debt`, `insufficient_balance`, `key_spend_limit`, `memory_refusal` for an answer), and the
 * key's requests per minute (`RateLimitRejection`).
 */
import { ApiError, dollars, usd } from "@gray/errors";

/**
 * 402 `account_in_debt` (docs/holds-debt-mode.md 4.6): the workspace owes `debt`. Only a top-up
 * clears it, so it is a 402, not a 503 a client retries. The message names the debt exactly and what
 * clears it rounded up to the cent.
 */
export function accountInDebt(debt: bigint | undefined): ApiError {
  let error = new ApiError(402, "account_in_debt").withMeta("limit_source", "workspace_debt").withMeta("remedy_hint", "Add credits: the debt is paid first, and the rest becomes available balance.");
  if (debt !== undefined) {
    const owed = debt > 0n ? debt : 0n;
    const cleared = ((owed + 9_999n) / 10_000n) * 10_000n;
    error = error
      .withMessage(
        `This workspace owes ${dollars(owed)}: a request cost more than Gray held for it, and the balance could not cover the difference. Add at least ${dollars(cleared)} of credits to clear it; anything above that becomes available balance. Requests resume once the top-up is on chain, usually within a minute.`,
      )
      .withMeta("debt_usd", Number(debt) / 1_000_000);
  }
  return error;
}

/**
 * 402 `insufficient_allocated_budget`: the workspace cannot hold what a request needs reserved; with
 * the amounts when they are known, and the output cap that was tried. `held`: `needed` is what debt
 * mode holds the request for, below what it can cost (docs/holds-debt-mode.md 3.5).
 */
export function insufficientBalance(needed: bigint, available: bigint | undefined, outputTokens: number | undefined, held: boolean): ApiError {
  let error = new ApiError(402, "insufficient_allocated_budget")
    .withMeta("limit_source", "workspace_balance")
    .withMeta("remedy_hint", "Add credits, or lower max_tokens so the request can cost less.")
    .withMeta("required_usd", Number(needed) / 1_000_000);
  if (available !== undefined) {
    const output = outputTokens === undefined ? "" : ` with ${outputTokens} output tokens`;
    const needs = held ? "needs a hold of" : "can cost up to";
    error = error
      .withMessage(`Your workspace has ${usd(available)} available, and this request${output} ${needs} ${usd(needed)}. Add credits, or lower \`max_tokens\` so the request can cost less.`)
      .withMeta("available_usd", Number(available) / 1_000_000);
  }
  return error;
}

// chrono 0.4.45's date range (`NaiveDate::MIN` and `MAX`, naive/date/mod.rs `MIN_YEAR`/`MAX_YEAR`),
// inside JavaScript's (`Date` holds +-8.64e15 ms, years -271821 to 275760).
const CHRONO_MIN_YEAR = -262143;
const CHRONO_MAX_YEAR = 262142;
const JS_DATE_LIMIT_SECONDS = 8_640_000_000_000n;

const two = (n: number) => String(n).padStart(2, "0");

/**
 * `rfc3339(at)`: Unix seconds as chrono writes them (`to_rfc3339_opts(Secs, true)`), e.g.
 * `2026-10-18T00:00:00Z`; years outside 0..=9999 with their sign and at least four digits
 * (`+10000`, `-0001`; chrono formatting.rs `write_rfc3339`); undefined outside chrono's range.
 */
export function rfc3339(seconds: bigint): string | undefined {
  if (seconds > JS_DATE_LIMIT_SECONDS || seconds < -JS_DATE_LIMIT_SECONDS) return undefined;
  const at = new Date(Number(seconds) * 1000);
  const year = at.getUTCFullYear();
  if (year < CHRONO_MIN_YEAR || year > CHRONO_MAX_YEAR) return undefined;
  const yearText = year >= 0 && year <= 9999 ? String(year).padStart(4, "0") : `${year < 0 ? "-" : "+"}${String(Math.abs(year)).padStart(4, "0")}`;
  return `${yearText}-${two(at.getUTCMonth() + 1)}-${two(at.getUTCDate())}T${two(at.getUTCHours())}:${two(at.getUTCMinutes())}:${two(at.getUTCSeconds())}Z`;
}

const I64_MAX = (1n << 63n) - 1n;

/**
 * 429 `key_rate_limit` (inference.rs `RateLimitRejection`, `key_rate_limit`): the key has sent the `limit`
 * requests its minute allows; one can pass again in `retryAfter` seconds (at least 1), counted from `nowSeconds`
 * (Unix seconds), which `metadata.resets_at` and `x-ratelimit-reset` name. The server's sum saturates at
 * i64::MAX, past which chrono names no date (`resets_at` null).
 */
export function keyRateLimit(limit: bigint, retryAfter: bigint, nowSeconds: bigint): ApiError {
  const sum = nowSeconds + retryAfter;
  const resetsAt = sum > I64_MAX ? I64_MAX : sum;
  return new ApiError(429, "key_rate_limit")
    .withMessage(`This API key allows ${limit} requests per minute and has used them. Retry in ${retryAfter} seconds, or raise the key's limit.`)
    .withMeta("limit_source", "key_rate_limit")
    .withMeta("remedy_hint", "Wait for retry-after, or raise the key's requests-per-minute limit.")
    .withMeta("resets_at", rfc3339(resetsAt) ?? null)
    .withRetryAfter(retryAfter)
    .withHeader("x-ratelimit-limit", limit.toString())
    .withHeader("x-ratelimit-remaining", "0")
    .withHeader("x-ratelimit-reset", resetsAt.toString());
}

/**
 * 429 `key_spend_limit`: the key's spend limit for its period cannot hold the request.
 * `retry-after` and `x-gray-key-limit-reset` (Unix seconds) name the end of the period (`resetMs`);
 * a lifetime limit has no end and sends neither. `limit` is the key's amount and period as its record
 * states them; `room` what the key has left of it and what the request needs held, when known.
 * `nowMs` is the clock the `retry-after` is counted from.
 */
export function keySpendLimit(resetMs: bigint | undefined, limit: { readonly amount: bigint; readonly period: string | undefined } | undefined, room: { readonly left: bigint; readonly needed: bigint } | undefined, nowMs: bigint): ApiError {
  const stated = limit === undefined ? "" : limit.period !== undefined && limit.period !== "never" ? ` of ${usd(limit.amount)} per ${limit.period}` : ` of ${usd(limit.amount)}`;
  const lifetime = resetMs !== undefined ? "" : "lifetime ";
  let error = new ApiError(429, "key_spend_limit").withMeta("limit_source", "key_spend_limit");
  let head: string;
  if (room !== undefined && room.left > 0n) {
    error = error.withMeta("remaining_usd", Number(room.left) / 1_000_000).withMeta("required_usd", Number(room.needed) / 1_000_000);
    head = `This request can cost up to ${usd(room.needed)}, and this API key has ${usd(room.left)} left of its ${lifetime}spend limit${stated}. Lower \`max_tokens\` so the request can cost less, or raise or remove the limit`;
  } else if (room !== undefined) {
    head = `This API key reached its ${lifetime}spend limit${stated}. Raise or remove the limit to continue`;
  } else {
    head = `This API key reached its ${lifetime}spend limit${stated}, or has less of it left than this request can cost. Lower \`max_tokens\` so the request can cost less, or raise or remove the limit`;
  }
  const lower = room === undefined || room.left > 0n ? "Lower max_tokens, or raise or remove the key's spend limit" : "Raise or remove the key's spend limit";
  if (resetMs === undefined) return error.withMessage(`${head}.`).withMeta("remedy_hint", `${lower}.`);
  const waitMs = resetMs - nowMs > 1n ? resetMs - nowMs : 1n;
  const retryAfter = (waitMs + 999n) / 1000n;
  const resetsAt = rfc3339(resetMs / 1000n);
  return error
    .withMessage(`${head}; it resets at ${(resetsAt ?? "the end of the period").replace(/Z+$/, "").replaceAll("T", " ")} UTC.`)
    .withMeta("remedy_hint", `${lower}, or wait until it resets.`)
    .withMeta("resets_at", resetsAt ?? null)
    .withRetryAfter(retryAfter > 1n ? retryAfter : 1n)
    .withHeader("x-gray-key-limit-reset", (resetMs / 1000n).toString());
}

/**
 * 400 `gateway_memory_insufficient`: the answer a request may get needs more memory than the gateway
 * gives one request (`memory_refusal(Refusal::Never, MemoryPart::Answer)`).
 */
export function answerMemoryRefusal(): ApiError {
  return new ApiError(400, "gateway_memory_insufficient").withMeta("limit_source", "gateway_memory");
}
