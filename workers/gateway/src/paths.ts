import { geminiPathModel, geminiWithoutModelsSegment } from "@gray/protocol";
import type { Served } from "./inference.ts";

/**
 * The paths of the generation APIs this gateway serves, with the server's unprefixed aliases
 * (crates/gray-gateway/src/inference.rs `router`; text_completeness.rs
 * `unprefixed_aliases_reach_the_same_handlers`): Chat Completions, Responses, Messages, and Gemini's
 * `POST /v1beta/models/{model}:generateContent` and `:streamGenerateContent`, whose path names the
 * model. A Gemini path without the `models/` segment (`/v1beta/google/gemini-x:generateContent`,
 * the AI SDK's for a model id with a slash) is served as the path with it
 * (`gemini_without_models_segment`). Token counting (`/v1/messages/count_tokens`, Gemini's
 * `:countTokens`) is another endpoint and not served here yet.
 */
export function servedProtocol(method: string, path: string): Served | null {
  if (method !== "POST") return null;
  if (path === "/v1/chat/completions" || path === "/chat/completions") return { protocol: "open_ai_chat", pathModel: null };
  if (path === "/v1/responses" || path === "/responses") return { protocol: "open_ai_responses", pathModel: null };
  if (path === "/v1/messages" || path === "/messages") return { protocol: "anthropic_messages", pathModel: null };
  const gemini = path.startsWith("/v1beta/models/") ? path : geminiWithoutModelsSegment(path, undefined);
  if (gemini === undefined || !(gemini.endsWith(":generateContent") || gemini.endsWith(":streamGenerateContent"))) return null;
  const model = geminiPathModel(gemini);
  return model === undefined ? null : { protocol: "gemini", pathModel: model };
}

/**
 * The agent and provider setup, which gray-console serves (it has the database a claim needs) on the API Worker's host,
 * and a relay stack's public routes (its pull-token reports and its appended texts,
 * docs/confidential-lane-supply-implementation.md S13 and section 10), which read and write the console's tables too.
 * None carries a prompt or a model's answer. The API Worker sends them to the console (index.ts `forwardSetup`); the
 * confidential entry forwards them to the API Worker (lane/api-forward.ts `forwardedPath`). Both read this one rule.
 */
export function isSetupPath(path: string): boolean {
  return path.startsWith("/v1/setup/") || path.startsWith("/v1/provider-setup/") || path.startsWith("/v1/lane-stack/");
}
