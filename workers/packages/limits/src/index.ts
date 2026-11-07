/**
 * @gray/limits: the size limits of a model request and of its answer, per protocol
 * (crates/gray-gateway/src/limits.rs, held to the conformance fixtures of area `limits`).
 *
 * Each value is a fact with a source, not a setting: a request limit is what the API Gray serves
 * accepts, from that API's documentation, so Gray never refuses a body the provider would take; an
 * answer limit follows from the request's own output bound and the API's documented event shapes,
 * with the largest values measured on real answers. docs/limits.md is the register of every value,
 * its source and how to measure it again (sources read on 2026-10-15).
 *
 * Sizes and token counts are `bigint` (Rust u64 and usize) and saturate at u64::MAX where the Rust
 * code saturates. A request body is a `Json` value of @gray/json: numbers as serde_json reads them,
 * so `5` (an integer) and `5.0` (a float) stay apart.
 */
import { asArray, asBool, asStr, asU64, get, isObject, serializedLength, type Json } from "@gray/json";
import { type Protocol, geminiField as protocolGeminiField } from "@gray/protocol";

export const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `u64::saturating_add`. */
export function saturatingAdd(a: bigint, b: bigint): bigint {
  const sum = a + b;
  return sum > U64_MAX ? U64_MAX : sum;
}

/** `u64::saturating_mul`. */
export function saturatingMul(a: bigint, b: bigint): bigint {
  const product = a * b;
  return product > U64_MAX ? U64_MAX : product;
}

/** `u64::saturating_sub`. */
export function saturatingSub(a: bigint, b: bigint): bigint {
  return a > b ? a - b : 0n;
}

/** `u64::div_ceil`. */
export function divCeil(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}

const MIB = 1024n * 1024n;

/**
 * Anthropic Messages (`/v1/messages`) and Token Counting (`/v1/messages/count_tokens`): "Messages,
 * Token Counting: 32 MB"; above it the API answers 413 `request_too_large`
 * (https://platform.claude.com/docs/en/api/overview, "Request size limits", and
 * https://platform.claude.com/docs/en/api/errors). Taken in MiB, the larger reading, so Gray never
 * refuses what the API accepts.
 */
export const ANTHROPIC_REQUEST_BYTES = 32n * MIB;
/**
 * OpenAI Chat Completions and Responses: "Request size: Up to 512 MB total payload per request"
 * (https://developers.openai.com/api/docs/guides/images-vision, "Limits").
 */
export const OPENAI_REQUEST_BYTES = 512n * MIB;
/**
 * Gemini `generateContent`, `streamGenerateContent` and `countTokens`: inline data "100 MB per
 * request or payload (50 MB for PDFs)" (https://ai.google.dev/gemini-api/docs/file-input-methods;
 * the Files guide states the same). The image-understanding guide still says 20 MB; the larger
 * value is taken, so a body Google accepts is never refused here.
 */
export const GEMINI_REQUEST_BYTES = 100n * MIB;
/**
 * The largest body a request to `protocol` may send. The other model APIs (embeddings, rerank, image
 * generation and edits, speech, transcription and translation, video, System One) state no size for
 * a request body: their providers bound what a request asks, and enforce it themselves (OpenAI API
 * reference 2.3.0: an embeddings request at most 2,048 inputs of 8,192 tokens and 300,000 tokens in
 * all; an image edit at most 16 images of under 50 MB and a mask of under 4 MB; speech at most 4,096
 * characters of input and of instructions; a video prompt at most 32,000 characters). So Gray sets no
 * size of its own for them (u64::MAX, as the server's `usize::MAX`): a provider refuses what it does
 * not take, and that refusal reaches the client as it would a direct call.
 */
export function requestLimit(protocol: Protocol): bigint {
  switch (protocol) {
    case "anthropic_messages":
      return ANTHROPIC_REQUEST_BYTES;
    case "open_ai_chat":
    case "open_ai_responses":
      return OPENAI_REQUEST_BYTES;
    case "gemini":
      return GEMINI_REQUEST_BYTES;
    default:
      return U64_MAX;
  }
}

/** Whose limit `requestLimit` is, in the sentence a 413 states. Only the text generation APIs have one. */
export function requestLimitSource(protocol: Protocol): string {
  switch (protocol) {
    case "anthropic_messages":
      return "the limit of Anthropic's Messages API (32 MB)";
    case "open_ai_chat":
    case "open_ai_responses":
      return "the limit of OpenAI's API (512 MB per request)";
    case "gemini":
      return "the limit of the Gemini API (100 MB per request)";
    default:
      return "the limit of this API";
  }
}

/**
 * The most answer-text bytes one output token has taken, as streamed JSON-escaped strings (text,
 * thinking and tool input), in hundredths of a byte: 4.59 B, the largest of 17,183 answers of at
 * least 1,000 output tokens in local Claude Code transcripts (p50 0.97, p99 2.77). Measured for the
 * request-size design (docs/limits.md, section 4).
 */
export const TEXT_BYTES_PER_TOKEN_HUNDREDTHS = 459n;

/**
 * The wire bytes of one streamed event that carries a single output token with empty text: the
 * largest documented event shape of each API.
 * - Anthropic: a `content_block_delta` with an `input_json_delta`, as the streaming guide writes it:
 *   138 B (https://platform.claude.com/docs/en/build-with-claude/streaming).
 * - Chat: a `chat.completion.chunk` with one tool-call argument delta, `usage: null` and
 *   `obfuscation`: 376 B (OpenAI API reference, chat streaming).
 * - Responses: a `response.output_text.delta` with its item id, indexes, sequence number,
 *   `logprobs` and `obfuscation`: 269 B (OpenAI API reference, Responses streaming events).
 * - Gemini: a `GenerateContentResponse` chunk with one part, its candidate fields, `usageMetadata`
 *   and `modelVersion`: 349 B (https://ai.google.dev/api/generate-content).
 */
export function tokenEventBytes(protocol: Protocol): bigint {
  switch (protocol) {
    case "anthropic_messages":
      return 138n;
    case "open_ai_chat":
      return 376n;
    case "open_ai_responses":
      return 269n;
    case "gemini":
      return 349n;
    default:
      return 0n;
  }
}

/**
 * How many times an answer's text crosses the wire. Responses repeats every token's text after its
 * deltas: in `response.output_text.done` (or `response.function_call_arguments.done`),
 * `response.content_part.done`, `response.output_item.done` and `response.completed` (OpenAI API
 * reference, Responses streaming events). The other APIs send it once.
 */
export function textRepeats(protocol: Protocol): bigint {
  return protocol === "open_ai_responses" ? 5n : 1n;
}

/**
 * The most wire bytes one output token of `protocol` can take: `tokenEventBytes` plus
 * `TEXT_BYTES_PER_TOKEN_HUNDREDTHS` for each time the text is sent, rounded up. Anthropic 143,
 * Chat 381, Responses 292, Gemini 354.
 */
export function bytesPerToken(protocol: Protocol): bigint {
  return tokenEventBytes(protocol) + divCeil(TEXT_BYTES_PER_TOKEN_HUNDREDTHS * textRepeats(protocol), 100n);
}

/**
 * What an answer sends besides its tokens, measured: the largest `response_bytes - bytes per token
 * x output_tokens` of the successful streams on the test machine (read-only SQL of `request_logs`,
 * 2026-10-15; Anthropic n=34 taken at 135 B per token, Chat n=4, Gemini n=7). Responses has its own
 * rule (`RESPONSES_FIXED_BYTES` and `answerEchoBytes`).
 */
export function fixedAnswerBytes(protocol: Protocol): bigint {
  switch (protocol) {
    case "anthropic_messages":
      return 1_232n;
    case "open_ai_chat":
      return 629n;
    case "gemini":
      return 614n;
    case "open_ai_responses":
      return RESPONSES_FIXED_BYTES;
    default:
      return 0n;
  }
}

/**
 * Responses: what its answers sent beyond 292 B per output token and three copies of the whole
 * request body, at most (n=25, the same query). The rest of its fixed part is the request echo.
 */
export const RESPONSES_FIXED_BYTES = 5_227n;

/**
 * How many times a Responses stream repeats the request's own fields: `response.created`,
 * `response.in_progress` and `response.completed` each carry the whole response object, which
 * echoes `instructions`, `tools` and the other request settings (OpenAI API reference, Responses
 * streaming events).
 */
export const RESPONSES_ECHOES = 3n;

/**
 * The request fields a `protocol` answer echoes, in bytes: for Responses, `RESPONSES_ECHOES` times
 * the serialized size of every top-level field of `body` but `input`; for the other APIs nothing.
 */
export function answerEchoBytes(protocol: Protocol, body: Json): bigint {
  if (protocol !== "open_ai_responses" || !isObject(body)) return 0n;
  let echoed = 0n;
  for (const key of Object.keys(body)) {
    if (key === "input") continue;
    // `"key":value,`
    echoed += jsonLen(key) + 1n + jsonLen(body[key] as Json) + 1n;
  }
  return RESPONSES_ECHOES * echoed;
}

/** The serialized size of `value`, as serde_json writes it (@gray/json `serializedLength`). */
export function jsonLen(value: Json): bigint {
  return serializedLength(value);
}

/**
 * The most base64 bytes one output token of an image answer can take: 34,063 B. The largest image
 * per token in the Gemini image-generation table is 3.1 Pro Image at 4K, 21:9: 6336x2688 pixels for
 * 2,000 tokens (https://ai.google.dev/gemini-api/docs/image-generation). Taken as an uncompressed
 * 8-bit RGB PNG (3 bytes a pixel), times 4/3 for base64.
 */
export const IMAGE_BYTES_PER_TOKEN = 34_063n;
/** The thought signature beside a generated image: 621 KiB, measured beside a 1K image from `gemini-3.1-flash-image` (commit c84e4013). */
export const IMAGE_SIGNATURE_BYTES = 621n * 1024n;
/**
 * The most base64 bytes one output token of an audio answer can take: 3,200 B. OpenAI's PCM output
 * is 24 kHz 16-bit samples (https://developers.openai.com/api/docs/guides/text-to-speech) at one
 * audio token per 50 ms (https://developers.openai.com/api/docs/guides/realtime-costs): 2,400 B a
 * token, times 4/3 for base64. Gemini's speech is the same PCM at 32 tokens a second, 2,000 B a
 * token in base64, so OpenAI's is the larger. Read 2026-10-15.
 */
export const AUDIO_BYTES_PER_TOKEN = 3_200n;
/**
 * The most alternatives a logprobs request may ask for at each output token: OpenAI's
 * `top_logprobs` is "an integer between 0 and 20", Gemini's `logprobs` "must be in the range of
 * [0, 20]" (https://ai.google.dev/api/generate-content). Read 2026-10-15.
 */
export const MAX_TOP_LOGPROBS = 20n;
/** One OpenAI logprobs alternative with its comma and a logprob of at most 24 characters: 59 B, before its token's text. */
export const OPENAI_LOGPROB_BYTES = 59n;
/** The chosen token's own entry: an alternative's 59 B and its `,"top_logprobs":[]` (18 B). */
export const OPENAI_CHOSEN_LOGPROB_BYTES = 77n;
/** What a Chat chunk carries for logprobs: `"logprobs":{"content":[],"refusal":null}` and its comma, 41 B. */
export const CHAT_LOGPROBS_BYTES = 41n;
/** One Gemini logprobs candidate with a token id of at most 10 digits and a log probability of at most 24 characters: 76 B, before its token's text. */
export const GEMINI_LOGPROB_BYTES = 76n;
/** What a Gemini chunk carries for logprobs: `logprobsResult` with `avgLogprobs` and two doubles, 144 B. */
export const GEMINI_LOGPROBS_CHUNK_BYTES = 144n;
/** Each Gemini decoding step's `{"candidates":[]}` with its comma, 18 B. */
export const GEMINI_LOGPROBS_STEP_BYTES = 18n;

/**
 * The most wire bytes the logprobs of one output token add when a request asks for `top`
 * alternatives (held to `MAX_TOP_LOGPROBS`): Chat 1,780 B at 20, Responses 8,695 B, Gemini 1,855 B
 * (limits.rs `logprob_bytes_per_token` gives the sums).
 */
export function logprobBytesPerToken(protocol: Protocol, top: bigint): bigint {
  const held = top < MAX_TOP_LOGPROBS ? top : MAX_TOP_LOGPROBS;
  const text = TEXT_BYTES_PER_TOKEN_HUNDREDTHS;
  const openai = (chosen: bigint) => chosen * 100n + 5n * text + held * (OPENAI_LOGPROB_BYTES * 100n + 5n * text);
  let hundredths: bigint;
  switch (protocol) {
    case "open_ai_chat":
      hundredths = CHAT_LOGPROBS_BYTES * 100n + openai(OPENAI_CHOSEN_LOGPROB_BYTES);
      break;
    case "open_ai_responses":
      hundredths = textRepeats(protocol) * openai(OPENAI_CHOSEN_LOGPROB_BYTES);
      break;
    case "gemini":
      hundredths = (GEMINI_LOGPROBS_CHUNK_BYTES + GEMINI_LOGPROBS_STEP_BYTES) * 100n + (held + 1n) * (GEMINI_LOGPROB_BYTES * 100n + text);
      break;
    default:
      hundredths = 0n;
  }
  return divCeil(hundredths, 100n);
}

/**
 * What the answer to one request takes on the wire: the most bytes of each output token, and what
 * it sends besides its tokens.
 */
export class AnswerBytes {
  readonly perToken: bigint;
  readonly fixed: bigint;
  constructor(perToken: bigint, fixed: bigint) {
    this.perToken = perToken;
    this.fixed = fixed;
  }

  /** The answer to `body`, a request of `protocol`; `images` that it may carry generated images. */
  static of(protocol: Protocol, body: Json, images: boolean): AnswerBytes {
    let perToken = bytesPerToken(protocol);
    if (images && IMAGE_BYTES_PER_TOKEN > perToken) perToken = IMAGE_BYTES_PER_TOKEN;
    if (requestsAudio(protocol, body)) perToken = saturatingAdd(perToken, AUDIO_BYTES_PER_TOKEN);
    const top = logprobsRequested(protocol, body);
    if (top !== undefined) perToken = saturatingAdd(perToken, logprobBytesPerToken(protocol, top));
    const fixed = saturatingAdd(saturatingAdd(fixedAnswerBytes(protocol), answerEchoBytes(protocol, body)), images ? IMAGE_SIGNATURE_BYTES : 0n);
    return new AnswerBytes(perToken, fixed);
  }

  /** The most bytes an answer of at most `outputBound` tokens may take. */
  limit(outputBound: bigint): bigint {
    return saturatingAdd(saturatingMul(outputBound, this.perToken), this.fixed);
  }

  /** The most output tokens whose answer is at most `bytes`; 0 when not one fits. */
  tokensWithin(bytes: bigint): bigint {
    return saturatingSub(bytes, this.fixed) / (this.perToken > 0n ? this.perToken : 1n);
  }
}

/**
 * The most bytes the answer to one request may take on the wire, from the most tokens it may
 * produce (`outputBound`: the output its credit hold covers, plus the serving endpoints' declared
 * allowance, times its candidate count). A stream or body past it is the upstream's failure
 * (`upstream_stream_limit`, `upstream_body_limit`), never a valid answer.
 */
export function answerLimit(protocol: Protocol, outputBound: bigint, body: Json, images: boolean): bigint {
  return AnswerBytes.of(protocol, body, images).limit(outputBound);
}

/**
 * gray_protocol `gemini_field(...).ok().flatten()` (@gray/protocol `geminiField`): the member under
 * either spelling; undefined when both are present, when it is absent, and when it is `null`, which
 * Google's JSON mapping reads as unset.
 */
export function geminiField(object: Json | undefined, name: string): Json | undefined {
  if (object === undefined) return undefined;
  const found = protocolGeminiField(object, name);
  return found.error === undefined ? found.value : undefined;
}

/**
 * The `top_logprobs` a request asks for, when it asks for logprobs at all: OpenAI Chat
 * `logprobs: true` with `top_logprobs`, Responses `include` naming output-text logprobs or a present
 * `top_logprobs`, Gemini `generationConfig.responseLogprobs` with `logprobs`. Anthropic has none.
 * A value that is not a u64 (a float, a negative number) reads as 0, as `Value::as_u64` does.
 */
export function logprobsRequested(protocol: Protocol, body: Json): bigint | undefined {
  switch (protocol) {
    case "open_ai_chat":
      return asBool(get(body, "logprobs")) === true ? (asU64(get(body, "top_logprobs")) ?? 0n) : undefined;
    case "open_ai_responses": {
      const include = asArray(get(body, "include"));
      const asked = (include?.some((entry) => asStr(entry)?.includes("logprobs") === true) ?? false) || get(body, "top_logprobs") !== undefined;
      return asked ? (asU64(get(body, "top_logprobs")) ?? 0n) : undefined;
    }
    case "gemini": {
      const config = geminiField(body, "generationConfig");
      if (config === undefined) return undefined;
      const on = asBool(geminiField(config, "responseLogprobs")) === true;
      // `logprobs` has no camelCase form; it is read directly, as the server reads it.
      return on ? (asU64(get(config, "logprobs")) ?? 0n) : undefined;
    }
    default:
      return undefined;
  }
}

/** `str::eq_ignore_ascii_case`: equal once ASCII letters are folded; nothing else is folded. */
export function eqIgnoreAsciiCase(a: string, b: string): boolean {
  const fold = (s: string) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());
  return a.length === b.length && fold(a) === fold(b);
}

function names(value: Json | undefined, wanted: string): boolean {
  return asArray(value)?.some((entry) => {
    const text = asStr(entry);
    return text !== undefined && eqIgnoreAsciiCase(text, wanted);
  }) ?? false;
}

/** Whether a request asks for audio output: Chat `modalities` naming `audio`, Gemini `generationConfig.responseModalities` naming `AUDIO`. */
export function requestsAudio(protocol: Protocol, body: Json): boolean {
  switch (protocol) {
    case "open_ai_chat":
      return names(get(body, "modalities"), "audio");
    case "gemini":
      return names(geminiField(geminiField(body, "generationConfig"), "responseModalities"), "audio");
    default:
      return false;
  }
}

/** Whether a Gemini request asks for image output itself (`generationConfig.responseModalities` naming `IMAGE`, under its JSON or proto name). */
export function requestsImages(protocol: Protocol, body: Json): boolean {
  if (protocol !== "gemini") return false;
  return names(geminiField(geminiField(body, "generationConfig"), "responseModalities"), "image");
}
