/**
 * An image upstream's answer that it made no image for a request and that the request may be sent
 * again (crates/gray-protocol/src/no_image.rs, `made_no_image`). yylx answered Nano Banana 2
 * `generateContent` requests so on 2026-10-17:
 *
 *     HTTP 451
 *     {"error":{"code":451,"message":"upstream returned no image for this request, please retry; if it keeps failing, try adjusting the prompt or reference images","status":"FAILED_PRECONDITION"}}
 *
 * The sentence is the account's behind the relay (sub2api passes a Gemini account's error through
 * unchanged when it neither repeats nor fails over for the status), and nothing is billed for it:
 * no image was drawn. Its codes alone would say the opposite: Google's `FAILED_PRECONDITION` says
 * not to retry until the system state is fixed, and HTTP 451 is a refusal for legal reasons (RFC
 * 7725). What makes this answer one to send again is the relay's own advice, so it is recognised by
 * all of its signals: the status, the Google error's `code` and `status`, and a message that opens
 * with the relay's statement and its retry hint. A message only opens so when the relay wrote it: it
 * quotes nothing of the request.
 */
import { asStr, asU64, get, JsonError, parseSerdeBytes, type Json } from "@gray/json";
import { isRustWhitespace } from "./text.ts";

/** The HTTP status, which the Google error repeats as its `code`. */
const STATUS = 451;
/** The Google error's `status`. */
const GOOGLE_STATUS = "FAILED_PRECONDITION";
/** How the message opens, lower-cased: the relay's statement and its retry hint. */
const OPENING = "upstream returned no image for this request, please retry";

/** Rust's `str::trim_start`. */
function trimStart(text: string): string {
  let start = 0;
  while (start < text.length && isRustWhitespace(text.charCodeAt(start))) start += 1;
  return text.slice(start);
}

/**
 * Whether an upstream that answered an image request with `status` and `body` made no image and
 * said to send the request again (by every signal of the module comment).
 */
export function madeNoImage(status: number, body: Uint8Array): boolean {
  if (status !== STATUS) return false;
  let value: Json;
  try {
    value = parseSerdeBytes(body);
  } catch (error) {
    if (error instanceof JsonError) return false;
    throw error;
  }
  const error = get(value, "error");
  const message = asStr(get(error, "message"));
  return asU64(get(error, "code")) === BigInt(STATUS) && asStr(get(error, "status")) === GOOGLE_STATUS && message !== undefined && trimStart(message).toLowerCase().startsWith(OPENING);
}
