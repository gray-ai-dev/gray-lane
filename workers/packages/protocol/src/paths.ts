/**
 * Which API a request path names, and the Gemini paths' own parts: `Protocol::from_path`,
 * `endpoint_path`, `billing_unit`, `multipart` and `modality` (crates/gray-protocol/src/lib.rs), and
 * the gateway's reading of `/v1beta/models/{model}:{method}` (crates/gray-gateway/src/inference.rs
 * `router`, `gemini_without_models_segment` and `forward_traced`; count_tokens.rs).
 *
 * Paths are the request's path as received, without its query: the gateway reads the model out of
 * it as it is written, never decoded.
 */
import type { Protocol } from "./types.ts";

/** `Modality`: what a protocol produces (the serde names). */
export type Modality = "text" | "embeddings" | "image" | "audio" | "video";

const SUFFIXES: readonly (readonly [string, Protocol])[] = [
  ["/systemone", "system_one"],
  ["/embeddings", "open_ai_embeddings"],
  ["/rerank", "rerank"],
  ["/images/generations", "open_ai_image_generations"],
  ["/images/edits", "open_ai_image_edits"],
  ["/audio/speech", "open_ai_speech"],
  ["/audio/transcriptions", "open_ai_transcriptions"],
  ["/audio/translations", "open_ai_translations"],
  ["/videos", "open_ai_videos"],
];

/** `Protocol::from_path`: the stable suffixes of the HTTP surface; anything after `?` is ignored. */
export function protocolFromPath(path: string): Protocol | undefined {
  const query = path.indexOf("?");
  const p = query >= 0 ? path.slice(0, query) : path;
  if (p.endsWith("/chat/completions")) return "open_ai_chat";
  if (p.endsWith("/responses")) return "open_ai_responses";
  if (p.endsWith("/messages")) return "anthropic_messages";
  if (p.endsWith(":generateContent") || p.endsWith(":streamGenerateContent")) return "gemini";
  return SUFFIXES.find(([suffix]) => p.endsWith(suffix))?.[1];
}

/** `Protocol::endpoint_path`: the path a protocol's requests are sent to (Gemini's names the model and the method). */
export function endpointPath(protocol: Protocol, model: string | undefined, stream: boolean): string {
  switch (protocol) {
    case "open_ai_chat":
      return "/v1/chat/completions";
    case "open_ai_responses":
      return "/v1/responses";
    case "anthropic_messages":
      return "/v1/messages";
    case "gemini":
      return `/v1beta/models/${model ?? "model"}:${stream ? "streamGenerateContent" : "generateContent"}`;
    case "system_one":
      return "/v1/systemone";
    case "open_ai_embeddings":
      return "/v1/embeddings";
    case "rerank":
      return "/v1/rerank";
    case "open_ai_image_generations":
      return "/v1/images/generations";
    case "open_ai_image_edits":
      return "/v1/images/edits";
    case "open_ai_speech":
      return "/v1/audio/speech";
    case "open_ai_transcriptions":
      return "/v1/audio/transcriptions";
    case "open_ai_translations":
      return "/v1/audio/translations";
    case "open_ai_videos":
      return "/v1/videos";
  }
}

/** `Protocol::modality`. */
export function modality(protocol: Protocol): Modality {
  switch (protocol) {
    case "open_ai_chat":
    case "open_ai_responses":
    case "anthropic_messages":
    case "gemini":
    case "system_one":
      return "text";
    case "open_ai_embeddings":
    case "rerank":
      return "embeddings";
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return "image";
    case "open_ai_speech":
    case "open_ai_transcriptions":
    case "open_ai_translations":
      return "audio";
    case "open_ai_videos":
      return "video";
  }
}

/**
 * `Protocol::billing_unit`: the non-token unit an offer may price for the protocol (the ledger's
 * billing unit and native usage key); undefined for token-only protocols.
 */
export function billingUnit(protocol: Protocol): "images" | "characters" | "seconds" | "requests" | undefined {
  switch (protocol) {
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return "images";
    case "open_ai_speech":
      return "characters";
    case "open_ai_transcriptions":
    case "open_ai_translations":
    case "open_ai_videos":
      return "seconds";
    case "rerank":
      return "requests";
    default:
      return undefined;
  }
}

/** `Protocol::multipart`: requests are `multipart/form-data` rather than JSON. */
export function isMultipart(protocol: Protocol): boolean {
  return protocol === "open_ai_image_edits" || protocol === "open_ai_transcriptions" || protocol === "open_ai_translations";
}

const MODELS_PREFIX = "/v1beta/models/";

/**
 * What `POST /v1beta/models/{*path}` serves (inference.rs `router`, count_tokens.rs
 * `gemini_or_forward`): `:countTokens` is counted; every other method goes to inference, which
 * serves `:generateContent` and `:streamGenerateContent` (`protocolFromPath`) and answers any other
 * path `unsupported_protocol`.
 */
export function geminiMethod(path: string): "count_tokens" | "generate" | "stream_generate" | "unsupported" {
  if (path.endsWith(":countTokens")) return "count_tokens";
  if (path.endsWith(":streamGenerateContent")) return "stream_generate";
  if (path.endsWith(":generateContent")) return "generate";
  return "unsupported";
}

/**
 * The model a Gemini generation path names (`forward_traced`): what follows `/v1beta/models/` up to
 * its last `:`. Undefined for a path outside `/v1beta/models/` or without a method.
 */
export function geminiPathModel(path: string): string | undefined {
  if (!path.startsWith(MODELS_PREFIX)) return undefined;
  const rest = path.slice(MODELS_PREFIX.length);
  const colon = rest.lastIndexOf(":");
  return colon >= 0 ? rest.slice(0, colon) : undefined;
}

/** A Gemini generation streams when its method is `:streamGenerateContent` (`forward_traced`). */
export function geminiStreams(path: string): boolean {
  return path.endsWith(":streamGenerateContent");
}

/** The model of a Gemini count path, `/v1beta/models/{model}:countTokens` (count_tokens.rs `count`). */
export function geminiCountModel(path: string): string | undefined {
  if (!path.startsWith(MODELS_PREFIX) || !path.endsWith(":countTokens")) return undefined;
  return path.slice(MODELS_PREFIX.length, path.length - ":countTokens".length);
}

/**
 * `gemini_without_models_segment`: the Google provider of the AI SDK (and so opencode 1.x) leaves
 * out `models/` for a model id that contains a slash, `POST /v1beta/google/gemini-x:generateContent`.
 * Such a path (after `/v1beta/`, a `/` and a `:`) is served as `/v1beta/models/{rest}`, its query
 * kept; any other path under `/v1beta` is one Gray has no API at (undefined).
 */
export function geminiWithoutModelsSegment(path: string, query: string | undefined): string | undefined {
  const rest = path.startsWith("/v1beta/") ? path.slice("/v1beta/".length) : "";
  if (!rest.includes("/") || !rest.includes(":")) return undefined;
  return query === undefined ? `${MODELS_PREFIX}${rest}` : `${MODELS_PREFIX}${rest}?${query}`;
}

/**
 * `gemini_method_path` (crates/gray-protocol/src/lib.rs): the path a Gemini call takes at a mapping's
 * native path, which names the model and its method (`/v1beta/models/gemini-2.5-flash:generateContent`),
 * with `method` in place of the method it names: `generateContent` for a buffered answer,
 * `streamGenerateContent` for a stream, `countTokens` for a count. Undefined when the path's last
 * segment names no model with a generation method: Gray could not tell the upstream which method it
 * calls. Registration refuses such a path (@gray/control `GEMINI_PATH_RULE`), a check of a stored one
 * sends nothing (@gray/verifier), and serving builds its calls from it, so the path a check proved is
 * the path every call takes.
 */
export function geminiMethodPath(nativePath: string, method: string): string | undefined {
  const colon = nativePath.lastIndexOf(":");
  if (colon < 0) return undefined;
  const prefix = nativePath.slice(0, colon);
  const named = nativePath.slice(colon + 1);
  const model = prefix.slice(prefix.lastIndexOf("/") + 1);
  if (model.length === 0 || (named !== "generateContent" && named !== "streamGenerateContent")) return undefined;
  return `${prefix}:${method}`;
}

/**
 * `gemini_operation_url` (crates/gray-gateway/src/inference.rs): a Gemini route's URL for one attempt's
 * method: the mapping's path with `generateContent` or `streamGenerateContent` in place of the method
 * it names (`geminiMethodPath`; the model segment comes only from the administrator-reviewed mapping),
 * and for a stream the query `alt=sse` in place of any other. Undefined when the path names no model
 * with a generation method (the attempt fails with 502 `invalid_native_mapping`) or the URL does not
 * parse. The URL is the WHATWG parser's, which the url crate implements: the path is read and set as
 * serialized.
 */
export function geminiOperationUrl(routeUrl: string, stream: boolean): string | undefined {
  let url: URL;
  try {
    url = new URL(routeUrl);
  } catch {
    return undefined;
  }
  const path = geminiMethodPath(url.pathname, stream ? "streamGenerateContent" : "generateContent");
  if (path === undefined) return undefined;
  url.pathname = path;
  if (stream) url.search = "alt=sse";
  return url.href;
}

/** A model as `GET /v1beta/models` lists it (crates/gray-gateway/src/model_catalog.rs `gemini_model_value`). */
export interface GeminiModel {
  readonly name: string;
  readonly displayName: string;
  readonly supportedGenerationMethods: readonly string[];
}

/**
 * Whether the Workers' gateway serves token counting (`POST /v1/messages/count_tokens`, Gemini's
 * `:countTokens`): not yet, it answers both 404 (conformance/README.md, the open equivalence gap
 * "token 计数"). Until it does, nothing it lists names counting (decision 4 of 2026-10-24, declared
 * in conformance/README.md): the follow-up PR that implements counting after release 4 sets this
 * and lists `countTokens` as the server does.
 */
export const TOKEN_COUNTING_SERVED = false;

/**
 * `gemini_model_value`: `models/{id}`, its id as the display name, and the methods Gray serves for
 * it: generation always, `countTokens` only on a natively served model, and only once this gateway
 * counts (`TOKEN_COUNTING_SERVED`; the server, which counts, lists it for every native model).
 */
export function geminiModelValue(id: string, native: boolean): GeminiModel {
  const methods = ["generateContent", "streamGenerateContent"];
  if (native && TOKEN_COUNTING_SERVED) methods.push("countTokens");
  return { name: `models/${id}`, displayName: id, supportedGenerationMethods: methods };
}
