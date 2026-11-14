/**
 * Answers that end as no API of their vendor ends one, which the chain between Gray and the vendor is to blame
 * for (the owner's rule of 2026-11-11: an answer is charged as its vendor charges a direct customer, and is free
 * and its supplier's failure only when the fault is the supplier's or a relay's). There are three:
 *
 * - A buffered answer whose primary choice has no stop reason and that reported no output token. The vendors'
 *   own buffered answers always carry one (Anthropic's `stop_reason` "is always non-null" there; OpenAI's
 *   `finish_reason` is required), so it comes from a relay that joined a stream cut short into one body. A
 *   stream without one is incomplete already (`ProtocolStreamDecoder`).
 * - A Chat answer whose primary choice finished with `error` or `failed`, values OpenAI's `finish_reason` enum
 *   does not have: a relay's mark of a failed generation, sent without the error object that fails one
 *   (`parseProviderError`, the stream decoder's error event).
 * - A Gemini candidate stopped for `PUP_LIMITED_DISABLED`: the supplier's account is limited or disabled for
 *   Prohibited Use Policy violations (generativelanguage v1beta `FinishReason`). `mapFinish` reads it as a
 *   policy stop and refusal.ts leaves it out of the model's refusals for being the provider's fault; here it is
 *   that fault.
 *
 * Each is refused uncharged as its supplier's failure, after the gateway's own checks of the answer and before
 * its usage is charged. Nothing else is: an unknown stop reason, a stop with no output, the model's refusal and
 * a vendor's own error stop (Gemini's `MALFORMED_FUNCTION_CALL` and the rest) are billed as their usage says.
 */
import { type Json, asArray, asStr, asU64, get } from "@gray/json";
import { rustTrim } from "./text.ts";
import type { FinishReason, Protocol } from "./types.ts";

/** Why an answer's end is its chain's failure. */
export type AnswerEndReason = "upstream_finish_missing" | "upstream_finish_error" | "upstream_account_limited";

/** The failure an answer's end is: the public code its request fails with, its kind, and Gray's words for it. */
export interface AnswerEndFailure {
  readonly code: "invalid_upstream_response" | "upstream_error";
  /**
   * Which of the three ends it is. The gateway reads it only to tell the supplier's account apart; the request's
   * release names `code`, which the request log's error category is read from (jobs projection.ts).
   */
  readonly reason: AnswerEndReason;
  readonly why: string;
}

/** The Chat stop reasons a relay marks a failed generation with (OpenRouter's mid-stream error ends a stream with `error`). */
const CHAT_FAILED: readonly string[] = ["error", "failed"];
/** Gemini's stop for an account limited or disabled under its Prohibited Use Policy. */
export const GEMINI_ACCOUNT_LIMITED = "PUP_LIMITED_DISABLED";
/**
 * Whether `stop`, as `protocol`'s field names it, stands for none, as the protocol's stream reads it: a blank stop
 * reason refuses a stream of any of them, and Chat and Gemini read `FINISH_REASON_UNSPECIFIED` as a choice not
 * finished (`ProtocolStreamDecoder`); an Anthropic stream bills that value as an unknown stop, so it is one here too.
 */
function unsetStop(protocol: Protocol, stop: string): boolean {
  return rustTrim(stop) === "" || (protocol !== "anthropic_messages" && stop === "FINISH_REASON_UNSPECIFIED");
}

/** Whether `value`, at `position` among its siblings, is the primary choice or candidate: index 0, or first when it has no index (`primary_alternative`). */
function primary(value: Json, position: number): boolean {
  const index = get(value, "index");
  return index === undefined ? position === 0 : asU64(index) === 0n;
}

/**
 * What an answer's stop reasons have shown of its chain's failure, fed the body of a buffered answer or the native
 * payload of each event of a streamed one (as `GeminiRefusal` is): a Chat primary choice finished with a relay's
 * failure mark, or a Gemini candidate stopped for its account. Either fails the answer whatever its usage says.
 */
export class AnswerEnd {
  readonly protocol: Protocol;
  private chatFailed: string | undefined;
  private accountLimited = false;

  constructor(protocol: Protocol) {
    this.protocol = protocol;
  }

  /** Notes one answer body or stream event's payload. */
  observe(payload: Json): void {
    if (this.protocol === "open_ai_chat") {
      (asArray(get(payload, "choices")) ?? []).forEach((choice, position) => {
        if (!primary(choice, position)) return;
        const reason = asStr(get(choice, "finish_reason"));
        if (reason !== undefined && CHAT_FAILED.includes(reason)) this.chatFailed ??= reason;
      });
    } else if (this.protocol === "gemini") {
      for (const candidate of asArray(get(payload, "candidates")) ?? []) {
        if (asStr(get(candidate, "finishReason")) === GEMINI_ACCOUNT_LIMITED) this.accountLimited = true;
      }
    }
  }

  /** The failure what was observed is, whatever the answer's usage says. */
  failure(): AnswerEndFailure | undefined {
    if (this.accountLimited) {
      return { code: "upstream_error", reason: "upstream_account_limited", why: `a candidate stopped for ${GEMINI_ACCOUNT_LIMITED}: the provider's account is limited or disabled for Prohibited Use Policy violations` };
    }
    if (this.chatFailed !== undefined) {
      return { code: "invalid_upstream_response", reason: "upstream_finish_error", why: `the answer finished with finish_reason "${this.chatFailed}", which the Chat API does not have, and no error object` };
    }
    return undefined;
  }

  /** `failure` of a buffered answer's body alone. */
  static of(protocol: Protocol, body: Json): AnswerEndFailure | undefined {
    const end = new AnswerEnd(protocol);
    end.observe(body);
    return end.failure();
  }
}

/** The stop reason a buffered answer's primary choice names in its API's own field, if it names one (Responses ends by its `status`). */
function primaryStop(protocol: Protocol, body: Json): string | undefined {
  const first = (values: Json | undefined, key: string): string | undefined => {
    const list = asArray(values) ?? [];
    for (let i = 0; i < list.length; i++) if (primary(list[i]!, i)) return asStr(get(list[i], key));
    return undefined;
  };
  switch (protocol) {
    case "open_ai_chat":
      return first(get(body, "choices"), "finish_reason");
    case "anthropic_messages":
      return asStr(get(body, "stop_reason"));
    case "gemini":
      return first(get(body, "candidates"), "finishReason");
    default:
      return undefined;
  }
}

/**
 * Whether a buffered answer ended with no stop reason: `finish` (its `parseResponse` projection) is none (a
 * missing or null one, or a Responses answer still queued, in progress or cancelled), or its API's field names
 * a value that stands for none (`unsetStop`).
 */
export function unfinished(protocol: Protocol, body: Json, finish: FinishReason | null): boolean {
  if (finish === null) return true;
  const stop = primaryStop(protocol, body);
  return stop !== undefined && unsetStop(protocol, stop);
}

/** The failure an `unfinished` buffered answer is when it reported no output token (its reasoning counted). */
export const UNFINISHED_EMPTY: AnswerEndFailure = Object.freeze({
  code: "invalid_upstream_response",
  reason: "upstream_finish_missing",
  why: "the answer has no stop reason and reported no output tokens",
});
