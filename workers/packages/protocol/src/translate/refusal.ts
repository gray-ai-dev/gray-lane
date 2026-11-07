/**
 * Stable refusal and failure codes of cross-protocol translation, and the refusal itself
 * (crates/gray-protocol/src/translate/mod.rs, `code` and `Refusal`). Request refusals are client
 * errors (HTTP 400); response failures are upstream errors (HTTP 502).
 */

export const TRANSLATION_CODES = {
  BUILTIN_TOOL: "translation_unsupported_builtin_tool",
  CONTINUATION: "translation_unsupported_continuation",
  CANDIDATES: "translation_unsupported_candidates",
  LOGPROBS: "translation_unsupported_logprobs",
  AUDIO: "translation_unsupported_audio",
  FILE: "translation_unsupported_file",
  IMAGE_URL: "translation_unsupported_image_url",
  VALUE: "translation_unsupported_value",
  FEATURE: "translation_unsupported_feature",
  INVALID: "translation_invalid_request",
  /** The upstream produced tool arguments the client protocol cannot carry. */
  UPSTREAM_ARGUMENTS: "translation_invalid_upstream_arguments",
  /** The upstream produced output outside the translation contract. */
  UPSTREAM: "translation_invalid_upstream",
} as const;

export type TranslationCode = (typeof TRANSLATION_CODES)[keyof typeof TRANSLATION_CODES];

const code = TRANSLATION_CODES;

function sentence(c: TranslationCode): string {
  switch (c) {
    case code.BUILTIN_TOOL:
      return "built-in or server tools cannot be translated";
    case code.CONTINUATION:
      return "stored state and continuations cannot be translated";
    case code.CANDIDATES:
      return "more than one candidate cannot be translated";
    case code.LOGPROBS:
      return "log probabilities cannot be translated";
    case code.AUDIO:
      return "audio cannot be translated";
    case code.FILE:
      return "files and documents cannot be translated";
    case code.IMAGE_URL:
      return "this image reference cannot be translated";
    case code.VALUE:
      return "this value has no equivalent in the target protocol";
    case code.FEATURE:
      return "this feature cannot be translated";
    case code.UPSTREAM_ARGUMENTS:
      return "upstream tool arguments are not a JSON object";
    case code.UPSTREAM:
      return "upstream output cannot be translated";
    default:
      return "invalid request for translation";
  }
}

/**
 * Why a request or response cannot be translated. Thrown where Rust returns `Err(Refusal)`;
 * `message` is the Rust `message` field (`"<sentence>: <param>"`), and `toString` gives the
 * `Display` text.
 */
export class Refusal extends Error {
  override readonly name = "Refusal";
  readonly code: TranslationCode;
  /** The client field at fault, as a JSON path-like name. */
  readonly param: string;

  constructor(c: TranslationCode, param: string) {
    super(`${sentence(c)}: ${param}`);
    this.code = c;
    this.param = param;
  }

  override toString(): string {
    return `${this.code} (${this.message})`;
  }
}
