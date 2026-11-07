/**
 * `AdapterError` (crates/gray-media-adapters/src/error.rs): every failure the adapters report. None
 * of them carries a credential. Thrown where Rust returns `Err`; `message` is the Rust `Display`
 * text (the `thiserror` attributes).
 */
import { cleanText } from "./text.ts";

export type AdapterErrorDetail =
  /** An OpenAI parameter, or a value of one, this vendor cannot honour (`param` or `param=value`). The gateway answers 400. */
  | { readonly kind: "unsupported"; readonly param: string }
  /** The OpenAI request is malformed: missing prompt, wrong JSON type, out-of-range number, oversized or non-base64 image. */
  | { readonly kind: "invalid_request"; readonly message: string }
  /** The request left out a parameter the vendor has no default for (the OpenAI name). The gateway answers 400 and names it. */
  | { readonly kind: "missing_parameter"; readonly param: string }
  /** The operation does not exist for this vendor, or a poll was asked for without a job. */
  | { readonly kind: "unsupported_operation"; readonly message: string }
  /** The stored credential has the wrong shape. Never includes the credential itself. */
  | { readonly kind: "invalid_credential"; readonly message: string }
  /** The vendor reported an error; `code` and `message` are the vendor's, cleaned (`cleanText`). */
  | { readonly kind: "vendor"; readonly status: number; readonly code: string; readonly message: string }
  /**
   * The model refused the request for its content: a blocked prompt, or a generation it stopped for
   * safety, recitation or no image (Gemini's `promptFeedback.blockReason`, a candidate's refusal
   * `finishReason`). The request's own outcome, as a 4xx refusal is: the gateway answers 400 with the
   * reason, uncharged, and holds it neither for nor against the route. `reason` and `message` are the
   * vendor's, cleaned as for `vendor`.
   */
  | { readonly kind: "refused"; readonly reason: string; readonly message: string }
  /** The vendor answered success but the body does not match its documented shape, or lacks the billing evidence required. */
  | { readonly kind: "malformed_response"; readonly message: string }
  /** A bound was exceeded (response body, decoded audio, job id). */
  | { readonly kind: "too_large"; readonly what: string };

function display(detail: AdapterErrorDetail): string {
  switch (detail.kind) {
    case "unsupported":
      return `unsupported parameter: ${detail.param}`;
    case "invalid_request":
      return `invalid request: ${detail.message}`;
    case "missing_parameter":
      return `required parameter missing: ${detail.param}`;
    case "unsupported_operation":
      return `operation not supported by vendor: ${detail.message}`;
    case "invalid_credential":
      return `invalid credential: ${detail.message}`;
    case "vendor":
      return `vendor error (http ${detail.status}): ${detail.code}: ${detail.message}`;
    case "refused":
      return `refused by the model: ${detail.reason}: ${detail.message}`;
    case "malformed_response":
      return `malformed vendor response: ${detail.message}`;
    case "too_large":
      return `too large: ${detail.what}`;
  }
}

export class AdapterError extends Error {
  override readonly name = "AdapterError";
  readonly detail: AdapterErrorDetail;

  constructor(detail: AdapterErrorDetail) {
    super(display(detail));
    this.detail = detail;
  }
}

/** `AdapterError::vendor`: the vendor's code and message, cleaned. */
export function vendorError(status: number, code: string, message: string): AdapterError {
  return new AdapterError({ kind: "vendor", status, code: cleanText(code), message: cleanText(message) });
}

/** `AdapterError::refused`: the model's reason and message, cleaned. */
export function refusedError(reason: string, message: string): AdapterError {
  return new AdapterError({ kind: "refused", reason: cleanText(reason), message: cleanText(message) });
}

/** `AdapterError::unsupported`: a parameter by name. */
export function unsupported(param: string): AdapterError {
  return new AdapterError({ kind: "unsupported", param: cleanText(param) });
}

/** `AdapterError::unsupported_value`: `param=value`, the value cleaned and cut to 64 characters plus `...`. */
export function unsupportedValue(param: string, value: string): AdapterError {
  let shown = cleanText(value);
  const chars = Array.from(shown);
  if (chars.length > 64) shown = `${chars.slice(0, 64).join("")}...`;
  return new AdapterError({ kind: "unsupported", param: `${param}=${shown}` });
}

export function invalid(message: string): AdapterError {
  return new AdapterError({ kind: "invalid_request", message });
}

export function malformed(message: string): AdapterError {
  return new AdapterError({ kind: "malformed_response", message });
}

export function invalidCredential(message: string): AdapterError {
  return new AdapterError({ kind: "invalid_credential", message });
}

export function missingParameter(param: string): AdapterError {
  return new AdapterError({ kind: "missing_parameter", param });
}

export function unsupportedOperation(message: string): AdapterError {
  return new AdapterError({ kind: "unsupported_operation", message });
}

export function tooLarge(what: string): AdapterError {
  return new AdapterError({ kind: "too_large", what });
}
