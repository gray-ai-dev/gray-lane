/**
 * OpenAI-compatible embeddings (`POST /v1/embeddings`), billed by input tokens only
 * (crates/gray-gateway/src/apis/embeddings.rs, whose module docs give every rule's reason).
 *
 * Request: `model`; `input` (a string, strings, one token array or token arrays; at most 2,048
 * inputs, none empty, token arrays of at most 32,768 u32 ids); optional `encoding_format` and
 * `dimensions`; `user` dropped. Bound: token arrays exactly, a string by its UTF-8 length plus 32
 * tokens of template overhead. A batch whose honest answer could exceed the response limit is
 * refused before dispatch. Response: one embedding per input of the asked encoding and width, usage
 * counters that agree. The model the answer names is not read: an upstream can print any name, and an
 * upgraded model answers under a new one (main 2c165fb7, the owner's rule of 2026-10-16).
 */
import { ApiError } from "@gray/errors";
import { ZERO_COUNTERS } from "@gray/protocol";
import { type Json, type JsonObject, get, isObject } from "@gray/json";
import { type Billed, UsageError, apiError, checkMetered, invalid, jsonModel, metered, missing, optionalCounter, capabilityUnproved, preferProvingAll, strictJson } from "./common.ts";
import type { Answered } from "./images.ts";
import { readUpstream } from "./read.ts";
import type { ApiRequest, MediaRoute, Received } from "./types.ts";

/** Most inputs one request may embed (OpenAI's limit). */
export const MAX_INPUTS = 2048;
/** Longest token array one input may carry. */
export const MAX_INPUT_TOKENS = 32_768;
/** Widest embedding a request may ask for. */
export const MAX_DIMENSIONS = 16_384n;
/** Tokens a service may add to each string it tokenizes ([CLS]/[SEP], <s>/</s>, a prefix). */
export const STRING_OVERHEAD = 32n;
/** Widest embedding assumed for a model whose width is unseen and a request without `dimensions`: OpenAI's widest. */
export const ASSUMED_DIMENSIONS = 3072n;
/** Longest JSON float of an f32 embedding as services print it, with its separator and indentation. */
const FLOAT_BYTES = 33n;
/** A pretty-printed data item around its embedding. */
const ITEM_BYTES = 128n;
/** The envelope around the data: `object`, `model` and `usage`. */
const ENVELOPE_BYTES = 4096n;

const FIELDS = ["model", "input", "encoding_format", "dimensions", "user"];

/**
 * The width of the last valid answer without `dimensions`, by requested model: one entry per routed
 * embedding model this isolate has answered (the server keeps one per process).
 */
const WIDTHS = new Map<string, bigint>();

/** What a request asks for, and so what its answer must hold. */
export interface Expected {
  readonly inputs: number;
  readonly inputTokens: bigint;
  readonly base64: boolean;
  readonly dimensions: bigint | undefined;
}

export function decodeEmbeddings(received: Received, responseBytes: number): ApiRequest {
  if (received.kind !== "json") throw invalid("invalid_protocol_request");
  const model = jsonModel(received.value);
  let body: JsonObject;
  let expected: Expected;
  try {
    [body, expected] = read(received.value);
  } catch (error) {
    if (typeof error === "string") throw invalid(error);
    throw error;
  }
  const width = expected.dimensions ?? WIDTHS.get(model) ?? ASSUMED_DIMENSIONS;
  const max = maxInputs(width, expected.base64, responseBytes);
  if (BigInt(expected.inputs) > max) throw tooLarge(width, max, expected.base64, responseBytes);
  return {
    model,
    stream: false,
    selectors: [],
    bound: { inputTokens: expected.inputTokens, outputTokens: 0n, units: 0n },
    body: { kind: "json", value: body },
  };
}

/** `read`: the body readied for forwarding (`user` and unset options dropped). Throws the client error code as a string. */
function read(value: Json): [JsonObject, Expected] {
  if (!isObject(value)) throw "invalid_protocol_request";
  if (Object.keys(value).some((k) => !FIELDS.includes(k))) throw "unsupported_request_field";
  const fields: JsonObject = {};
  for (const key of Object.keys(value)) fields[key] = value[key] as Json;
  const user = fields.user;
  delete fields.user;
  if (user !== undefined && typeof user !== "string" && user !== null) throw "invalid_protocol_request";
  for (const key of ["encoding_format", "dimensions"]) if (Object.hasOwn(fields, key) && fields[key] === null) delete fields[key];
  return [fields, expectedOf(fields)];
}

/** `Expected::of`: reads a decoded request body; throws the client error code as a string. */
export function expectedOf(body: Json): Expected {
  const INVALID = "invalid_protocol_request";
  const format = get(body, "encoding_format");
  let base64: boolean;
  if (format === undefined || format === "float") base64 = false;
  else if (format === "base64") base64 = true;
  else throw "unsupported_encoding_format";
  const d = get(body, "dimensions");
  let dimensions: bigint | undefined;
  if (d !== undefined) {
    if (typeof d !== "bigint" || d < 1n || d > MAX_DIMENSIONS) throw INVALID;
    dimensions = d;
  }
  const input = get(body, "input");
  if (input === undefined) throw INVALID;
  const [inputs, inputTokens] = inputsOf(input);
  return { inputs, inputTokens, base64, dimensions };
}

/** `inputs`: the number of inputs and the most tokens they can bill. */
function inputsOf(input: Json): [number, bigint] {
  const INVALID = "invalid_protocol_request";
  const utf8 = new TextEncoder();
  const text = (s: string) => {
    if (s.length === 0) throw INVALID;
    return BigInt(utf8.encode(s).length) + STRING_OVERHEAD;
  };
  const tokenArray = (ids: Json[]) => {
    if (ids.length === 0 || ids.length > MAX_INPUT_TOKENS) throw INVALID;
    if (!ids.every((id) => typeof id === "bigint" && id >= 0n && id <= 0xffff_ffffn)) throw INVALID;
    return BigInt(ids.length);
  };
  if (typeof input === "string") return [1, text(input)];
  if (!Array.isArray(input) || input.length === 0) throw INVALID;
  if (input.every((i) => typeof i === "bigint" || typeof i === "number")) return [1, tokenArray(input)];
  if (input.length > MAX_INPUTS) throw "too_many_inputs";
  const strings = typeof input[0] === "string";
  let tokens = 0n;
  for (const item of input) {
    if (typeof item === "string" && strings) tokens += text(item);
    else if (Array.isArray(item) && !strings) tokens += tokenArray(item);
    else throw INVALID;
  }
  return [input.length, tokens];
}

/**
 * `max_inputs`: the most inputs whose honest answer fits the response limit: each embedding `width`
 * wide, a float at most 33 bytes long, base64 four characters per three bytes of f32.
 */
export function maxInputs(width: bigint, base64: boolean, responseBytes: number): bigint {
  const embedding = base64 ? ((width * 4n + 2n) / 3n) * 4n : width * FLOAT_BYTES;
  return (BigInt(responseBytes) - ENVELOPE_BYTES) / (embedding + ITEM_BYTES);
}

function tooLarge(width: bigint, max: bigint, base64: boolean, responseBytes: number): ApiError {
  const hint = base64 ? "set a smaller `dimensions`" : 'set a smaller `dimensions`, or ask for `"encoding_format": "base64"`';
  const message =
    `The answer could exceed the gateway's ${Math.floor(responseBytes / 1048576)} MiB response limit: at ${width} ` +
    `dimensions a request may embed at most ${max} inputs. Split the batch, ${hint}.`;
  return new ApiError(400, "embedding_batch_too_large", { message });
}

/**
 * `serviceable`: an option shape (base64 embeddings, a chosen number of dimensions) is a capability a
 * provider claims and a check proves, and a request that needs one goes to a route that proved it,
 * never to one whose check withdrew it (`preferProvingAll`). Where no route proved it the request is
 * served as before by the routes that never claimed it; where every route claimed it and none proved
 * it, it is refused (400 `unsupported_capability`), as a chat request needing a capability no route
 * proved is. A request in the default shape is unaffected.
 */
export function serviceableEmbeddings(api: ApiRequest, routes: readonly MediaRoute[]): MediaRoute[] {
  if (api.body.kind !== "json") return [...routes];
  let expected: Expected;
  try {
    expected = expectedOf(api.body.value);
  } catch {
    return [...routes];
  }
  // Each shape's claim, what a refusal calls it, and the field asking it.
  const needed: (readonly [string, string, string])[] = [];
  if (expected.base64) needed.push(["embedding_base64", "base64 embeddings", "encoding_format"]);
  if (expected.dimensions !== undefined) needed.push(["embedding_dimensions", "a chosen number of dimensions", "dimensions"]);
  const sorted = preferProvingAll(
    routes,
    needed.map(([claim]) => claim),
  );
  if (sorted.proof !== "withdrawn") return sorted.routes;
  throw capabilityUnproved(
    api.model,
    needed.map(([, name]) => name),
    needed[0]![2],
  );
}

export interface EmbeddingsAttempt {
  readonly billsUnits: boolean;
  readonly deadlineMs: number;
  readonly responseBytes: number;
}

/**
 * The checks and metering of an embeddings answer (`respond`), on its shape (`embeddingsShapeOf` of
 * the parsed answer, or what a streamed answer's projection counts of it without holding a vector):
 * one embedding per input of the asked encoding and width, usage counters that agree. Throws the
 * answer's refusal as an ApiError.
 */
export function embeddingsAnswer(api: ApiRequest, shape: EmbeddingsShape, billsUnits: boolean): Billed {
  let expected: Expected | undefined;
  if (api.body.kind === "json") {
    try {
      expected = expectedOf(api.body.value);
    } catch {
      expected = undefined;
    }
  }
  if (expected === undefined) throw apiError(502, "invalid_upstream_response");
  const width = widthOfShape(expected, shape);
  if (width === undefined) throw apiError(502, "invalid_upstream_response");
  const usage = shape.usage;
  const present = usage !== undefined && usage !== null ? usage : undefined;
  if (present === undefined) return missing("usage missing");
  let inputTokens: bigint | undefined;
  try {
    inputTokens = inputUsage(present);
  } catch {
    throw apiError(502, "billing_usage_invalid");
  }
  if (inputTokens === undefined) return missing("usage.prompt_tokens missing", present);
  if (inputTokens === 0n) throw apiError(502, "billing_usage_invalid");
  const m = { counters: { ...ZERO_COUNTERS, input_tokens: inputTokens }, raw: present, unit: undefined };
  checkMetered("open_ai_embeddings", api.bound, m, billsUnits);
  if (expected.dimensions === undefined && WIDTHS.get(api.model) !== width) WIDTHS.set(api.model, width);
  return metered(m);
}

/** `respond`: one embedding per input, agreeing usage; the body goes back as received. */
export async function respondEmbeddings(api: ApiRequest, _route: MediaRoute, upstream: Response, attempt: EmbeddingsAttempt): Promise<Answered> {
  const bytes = await readUpstream(upstream, attempt.responseBytes, attempt.deadlineMs);
  const billed = embeddingsAnswer(api, embeddingsShapeOf(strictJson(bytes)), attempt.billsUnits);
  return { body: bytes, contentType: "application/json", billed };
}

/** An embedding as the width check reads it: a list of `count` numbers, base64 text of `bytes` decoded bytes (undefined: not base64), or anything else. */
export type EmbeddingShape = { readonly kind: "numbers"; readonly count: number } | { readonly kind: "base64"; readonly bytes: bigint | undefined } | { readonly kind: "other" };

/** An embeddings answer as its checks read it: the top-level `object` and `usage`, and each item's `index`, `object` and embedding shape (`data` undefined when it is not a list). */
export interface EmbeddingsShape {
  readonly object: Json | undefined;
  readonly usage: Json | undefined;
  readonly data: readonly { readonly index: Json | undefined; readonly object: Json | undefined; readonly embedding: EmbeddingShape }[] | undefined;
}

/** The shape of one embedding value. */
export function embeddingShape(value: Json | undefined): EmbeddingShape {
  if (Array.isArray(value)) return value.every((v) => typeof v === "bigint" || typeof v === "number") ? { kind: "numbers", count: value.length } : { kind: "other" };
  if (typeof value === "string") return { kind: "base64", bytes: base64Len(value) };
  return { kind: "other" };
}

/** The shape of a parsed embeddings answer. */
export function embeddingsShapeOf(value: Json): EmbeddingsShape {
  const data = get(value, "data");
  return {
    object: get(value, "object"),
    usage: get(value, "usage"),
    data: Array.isArray(data) ? data.map((item) => ({ index: get(item, "index"), object: get(item, "object"), embedding: embeddingShape(get(item, "embedding")) })) : undefined,
  };
}

/** `Expected::width`: the embeddings' width when the answer carries exactly one well-formed embedding per input, all of one width. */
export function widthOf(expected: Expected, value: Json): bigint | undefined {
  return widthOfShape(expected, embeddingsShapeOf(value));
}

/** `Expected::width` on an answer's shape. */
export function widthOfShape(expected: Expected, shape: EmbeddingsShape): bigint | undefined {
  const tag = (o: Json | undefined, want: string) => o === undefined || o === want;
  const data = shape.data;
  if (data === undefined || !tag(shape.object, "list") || data.length !== expected.inputs) return undefined;
  const seen = new Array<boolean>(data.length).fill(false);
  let width = expected.dimensions;
  for (const item of data) {
    const index = item.index;
    if (typeof index !== "bigint" || index < 0n || index >= BigInt(seen.length)) return undefined;
    const i = Number(index);
    if (seen[i] === true || !tag(item.object, "embedding")) return undefined;
    seen[i] = true;
    const embedding = item.embedding;
    let len: bigint;
    if (embedding.kind === "numbers" && !expected.base64) {
      len = BigInt(embedding.count);
    } else if (embedding.kind === "base64" && expected.base64) {
      const bytes = embedding.bytes;
      if (bytes === undefined || bytes % 4n !== 0n) return undefined;
      len = bytes / 4n;
    } else {
      return undefined;
    }
    if (len === 0n || (width !== undefined && width !== len)) return undefined;
    width = len;
  }
  return width;
}

/** `base64_len`: the decoded length of standard base64 text, padded or not; undefined when it is not base64. */
export function base64Len(text: string): bigint | undefined {
  const digits = text.replace(/=+$/, "");
  const padding = text.length - digits.length;
  if (padding > 2 || (padding > 0 && text.length % 4 !== 0) || digits.length % 4 === 1) return undefined;
  if (!/^[A-Za-z0-9+/]*$/.test(digits)) return undefined;
  return (BigInt(digits.length) * 3n) / 4n;
}

/**
 * `input_usage`: the input tokens of an input-only usage object: `prompt_tokens`, `total_tokens` and
 * `input_tokens`, whichever are reported, must agree, and `completion_tokens`/`output_tokens` must
 * be zero. Undefined when neither `prompt_tokens` nor `total_tokens` is reported.
 */
export function inputUsage(usage: Json): bigint | undefined {
  if (!isObject(usage)) throw new UsageError("usage must be an object");
  for (const key of ["completion_tokens", "output_tokens"]) {
    const n = optionalCounter(usage, key);
    if (n !== undefined && n > 0n) throw new UsageError(`usage.${key} must be zero`);
  }
  let tokens: bigint | undefined;
  for (const key of ["prompt_tokens", "total_tokens", "input_tokens"]) {
    const count = optionalCounter(usage, key);
    if (count === undefined) continue;
    if (tokens !== undefined && tokens !== count) throw new UsageError("input usage counters disagree");
    tokens = count;
  }
  const evidenced = optionalCounter(usage, "prompt_tokens") !== undefined || optionalCounter(usage, "total_tokens") !== undefined;
  return evidenced ? tokens : undefined;
}

/** For tests: forget the widths learned so far. */
export function forgetWidths(): void {
  WIDTHS.clear();
}

/** For tests: `learn_width`. */
export function learnWidth(model: string, width: bigint): void {
  WIDTHS.set(model, width);
}
