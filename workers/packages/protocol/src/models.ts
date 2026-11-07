import { type Json, type JsonObject, isObject, utf8Length } from "@gray/json";
import type { Protocol } from "./types.ts";

/**
 * A customer's explicit list of fallback models, OpenRouter's `models` (crates/gray-gateway/src/
 * model_fallbacks.rs, main #29), held to the `models-*` cases of conformance area `request`.
 *
 * Gray serves the exact model a request names and never substitutes another on its own. A request may
 * instead list the models it accepts, in its own order: `"model": "a", "models": ["b", "c"]` asks for `a`
 * and allows `b`, then `c`. As on OpenRouter, `model` comes first and `models` follows it; a request
 * without `model` asks for the first model of `models`. A model named twice keeps its first place. The
 * list is the customer's: Gray never reorders it, and a model is tried only after every model before it
 * had no eligible provider or failed every attempt it was allowed (the gateway's model loop).
 *
 * The field is read on the generation APIs whose body names the model: OpenAI Chat Completions, OpenAI
 * Responses and Anthropic Messages. A Gemini request names its model in the path, so its body is left as
 * it is.
 */

/**
 * The most models one request may list, the requested model included: the requested model and three
 * fallbacks, the most OpenRouter's Anthropic `fallbacks` takes (openrouter.ai/docs/guides/routing/
 * model-fallbacks; model_fallbacks.rs MAX_MODELS). Every model tried is admitted and reserved on its own,
 * all within the request's one deadline.
 */
export const MAX_MODELS = 4;
/** The longest model id a list may carry, in UTF-8 bytes (the ledger's bound, model_fallbacks.rs MAX_MODEL_BYTES). */
export const MAX_MODEL_BYTES = 512;

/** Rust's `char::is_control`: the Unicode general category Cc (U+0000 to U+001F and U+007F to U+009F). */
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

/**
 * Reads and removes `models` from a request body (`take`), and returns every model the request accepts in
 * the customer's order, the requested one first. An empty list means the request stated none and asks for
 * its `model` alone. A body that names no `model` gets the first listed one, so the request parses as a
 * request for it. The field is removed before the body is parsed or forwarded, because first-party APIs
 * reject unknown body fields. `body` is changed in place; `"invalid_models"` refuses the request (400).
 */
export function takeModels(body: Json, protocol: Protocol): readonly string[] | "invalid_models" {
  if (protocol !== "open_ai_chat" && protocol !== "open_ai_responses" && protocol !== "anthropic_messages") return [];
  if (!isObject(body)) return [];
  const object = body as JsonObject;
  if (!Object.hasOwn(object, "models")) return [];
  const listed = object.models;
  delete object.models;
  if (listed === null || listed === undefined) return [];
  if (!Array.isArray(listed)) return "invalid_models";
  const requested = Object.hasOwn(object, "model") ? object.model : null;
  // A malformed `model` is the protocol parser's to refuse.
  if (requested !== null && requested !== undefined && typeof requested !== "string") return [];
  const models: string[] = [];
  for (const model of [...(typeof requested === "string" ? [requested] : []), ...listed]) {
    if (typeof model !== "string") return "invalid_models";
    if (model.length === 0 || utf8Length(model) > MAX_MODEL_BYTES || CONTROL.test(model)) return "invalid_models";
    if (!models.includes(model)) models.push(model);
  }
  if (models.length > MAX_MODELS) return "invalid_models";
  // `entry("model").or_insert`: a body without a model (or with a null one, which Rust's entry keeps) gets the first.
  if (!Object.hasOwn(object, "model") && models.length > 0) object.model = models[0]!;
  // `models` named nothing but the requested model: nothing to fall back to, which is a request for that model alone.
  if (models.length === 1) return [];
  return models;
}
