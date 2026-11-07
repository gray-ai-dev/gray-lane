import type { BilledInput } from "@gray/holds";
import { type Json, asStr, get, isArray, pointer } from "@gray/json";
import { type CanonicalRequest, anthropicBlockBreakpoint, anthropicCacheControls } from "@gray/protocol";

/**
 * What a request, as sent upstream, can be billed at (crates/gray-gateway/src/routing.rs
 * `BilledInput::of`): whether its input may be billed at a cache-write rate, at the 1-hour rate, at
 * an image or audio rate, and whether an upstream may bill a write it was not asked for. The
 * reservation prices the request's own input at the dearest of these (@gray/holds
 * `reserveRequestInput`).
 *
 * - A cache write is billed only where the request states one: a cache key, a `cache_control`
 *   breakpoint where the upstream reads one (Anthropic's places, or an OpenAI-compatible relay's), or
 *   OpenAI's implicit write, which every Chat request gets unless it is explicit-only
 *   (`prompt_cache_options.mode` `explicit`) and places no breakpoint.
 * - A 1-hour write only for an Anthropic breakpoint whose `ttl` is not absent or `5m`.
 * - Content is text only when every block is proven to be; Anthropic reports no modality split, so
 *   its media never raises the rate.
 */
export function billedInputOf(request: CanonicalRequest, body: Json): BilledInput {
  const protocol = request.protocol;
  const anthropic = protocol === "anthropic_messages" ? anthropicCacheControls(body) : [];
  const openAi = protocol === "open_ai_chat" || protocol === "open_ai_responses";
  const implicitWrite = openAi && !(explicitOnly(body) && !explicitBreakpoint(body) && !relayBreakpoint(body));
  const cacheWrite =
    protocol !== "gemini" &&
    (request.cache_hints?.write === true || anthropic.length > 0 || implicitWrite || (protocol !== "anthropic_messages" && relayBreakpoint(body)));
  const cacheWrite1h = anthropic.some((marker) => {
    const ttl = get(marker, "ttl");
    return ttl !== undefined && ttl !== null && asStr(ttl) !== "5m";
  });
  const stated = (key: string) => {
    const value = get(body, key);
    return value !== undefined && value !== null;
  };
  const continuation = stated("previous_response_id") || stated("conversation");
  const referenced =
    (protocol === "open_ai_chat" && items(body, "messages").some((m) => notNull(get(m, "audio")))) || (protocol === "open_ai_responses" && stated("prompt"));
  const geminiFunctionParts =
    protocol === "gemini" &&
    items(body, "contents").some((content) =>
      items(content, "parts").some((part) => {
        const response = get(part, "functionResponse");
        return response !== undefined && notNull(get(response, "parts"));
      }),
    );
  const media =
    protocol !== "anthropic_messages" &&
    (continuation ||
      referenced ||
      geminiFunctionParts ||
      request.messages.some((m) =>
        m.content.some((block) => {
          switch (block.type) {
            case "text":
            case "reasoning":
            case "tool_use":
              return false;
            // A Gemini `response` is JSON data, never media.
            case "tool_result":
              return protocol !== "gemini" && !textOutput(block.content);
            default:
              return true;
          }
        }),
      ));
  return { cacheWrite, cacheWrite1h, media, unaskedWrite: protocol === "anthropic_messages" };
}

function notNull(v: Json | undefined): boolean {
  return v !== undefined && v !== null;
}

function items(v: Json | undefined, field: string): readonly Json[] {
  const list = get(v, field);
  return isArray(list) ? list : [];
}

/** Tool output in the shapes the text protocols give it: a string, or a list of text parts. */
function textOutput(content: Json): boolean {
  if (content === null || typeof content === "string") return true;
  if (!isArray(content)) return false;
  return content.every((item) => {
    if (typeof item === "string") return true;
    const typ = asStr(get(item, "type"));
    return typ === "text" || typ === "input_text" || typ === "output_text";
  });
}

/**
 * An OpenAI-compatible relay takes a breakpoint where Anthropic does, in its own shapes: on the
 * request, on a message or Responses input item, on the content parts it holds (and the blocks they
 * nest), and on a tool or its `function`; never inside a tool's `parameters`, a response schema or a
 * tool call's arguments.
 */
function relayBreakpoint(body: Json): boolean {
  const statedOn = (v: Json | undefined) => notNull(get(v, "cache_control"));
  return (
    statedOn(body) ||
    [...items(body, "messages"), ...items(body, "input")].some(
      (item) =>
        statedOn(item) ||
        ["content", "output"].some((held) => {
          const value = get(item, held);
          return value !== undefined && anthropicBlockBreakpoint(value);
        }),
    ) ||
    items(body, "tools").some((tool) => statedOn(tool) || statedOn(get(tool, "function")))
  );
}

/** OpenAI's own breakpoint marks a content part of a message or of a Responses input item. */
function explicitBreakpoint(body: Json): boolean {
  return ["messages", "input"].some((field) =>
    items(body, field).some((item) => {
      const content = get(item, "content");
      return isArray(content) && content.some((part) => notNull(get(part, "prompt_cache_breakpoint")));
    }),
  );
}

function explicitOnly(body: Json): boolean {
  return asStr(pointer(body, "/prompt_cache_options/mode")) === "explicit";
}
