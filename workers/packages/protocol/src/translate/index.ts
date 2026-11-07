/**
 * Cross-protocol translation among OpenAI Chat, OpenAI Responses, Anthropic Messages and Gemini
 * `generateContent` (crates/gray-protocol/src/translate/mod.rs; the contract is
 * docs/design/cross-protocol-translation.md).
 *
 * A client request in protocol A is decoded into a small IR, refusing every feature that has no
 * faithful rendering, and encoded as a protocol B request. The B response (or stream) is decoded
 * back into the IR and rendered in A. Nothing here inspects trust or bills: the gateway treats the
 * B request and B response exactly like a native B call, and only then translates.
 *
 * Every function throws a `Refusal` where Rust returns `Err(Refusal)`.
 */
import { type Json, type JsonObject, isArray, isObject } from "@gray/json";
import { type Protocol, isGeneration } from "../types.ts";
import { decodeRequest } from "./decode.ts";
import { encodeRequest } from "./encode.ts";
import { Refusal, TRANSLATION_CODES } from "./refusal.ts";
import { type ResponseContext, decodeResponse, mintedReasoningId, renderResponse } from "./response.ts";
import { Carrier, splitId } from "./carrier.ts";

export { applyOutputCap } from "./encode.ts";
export { Refusal, TRANSLATION_CODES, type TranslationCode } from "./refusal.ts";
export type { ResponseContext } from "./response.ts";
export { StreamTranslator, TRANSLATOR_CALL_BYTES, TRANSLATOR_OP_BYTES, errorFrame } from "./stream.ts";

/**
 * `tool_call_id_inner`: the id a client-visible tool call id is made from, without the data this
 * layer carries on it (a Gemini thought signature, a reasoning carrier): the id itself when it carries
 * none. The gateway stores what an id carries apart from the id, under a handle (@gray/tool-ids).
 */
export function toolCallIdInner(id: string): string {
  return splitId(id).id;
}

/**
 * `scrub_native`: takes out of a native request `body` of `protocol` what only a translation can read: the
 * continuation data a translated turn left in the client's conversation (`Carrier`), which the protocol's own
 * upstream would refuse or misread. A Responses client that a model's translated route served (the implied Responses
 * fallback, docs/design/cross-protocol-translation.md) sends that turn's reasoning back as an input `reasoning` item
 * this layer made: one whose `encrypted_content` is a carrier (`gr1.<origin>.`), or, for reasoning that came with
 * nothing to carry (a Gemini thought, which Gemini signs only on a call), one with no `encrypted_content` and the id
 * this layer minted for it (`mintedReasoningId`), which no provider stored. Neither is anything a provider issued;
 * when a later turn goes to a native Responses route, each such item is dropped, in place. Returns what was dropped,
 * as a translation reports it (`reasoning_signature`), empty when nothing was. Other protocols, and a Responses body
 * without such an item, are left as they are: a provider's own reasoning item, encrypted or a reference to one it
 * stored, is kept.
 */
export function scrubNative(protocol: Protocol, body: Json): string[] {
  if (protocol !== "open_ai_responses" || !isObject(body)) return [];
  const input = body.input;
  if (!isArray(input)) return [];
  const madeHere = (item: Json): boolean => {
    if (!isObject(item) || item.type !== "reasoning") return false;
    const encrypted = item.encrypted_content;
    if (typeof encrypted === "string") return Carrier.decode(encrypted) !== undefined;
    // serde's `as_str` reads a value that is no string as none: such an item is judged by its id.
    return typeof item.id === "string" && mintedReasoningId(item.id);
  };
  const kept = input.filter((item) => !madeHere(item));
  if (kept.length === input.length) return [];
  input.splice(0, input.length, ...kept);
  return ["reasoning_signature"];
}

/** An upstream request body and the advisory client fields it does not carry. */
export interface TranslatedRequest {
  /** Send it as `toJsonString(body)`, the bytes Rust's serde_json writes. */
  readonly body: JsonObject;
  /** Sorted, deduplicated names (the design doc's advisory list). */
  readonly dropped: readonly string[];
  /**
   * The client's output cap as the decoder read it, which `body` carries in the target's field.
   * The native parse of the client body may not see it (Gemini accepts snake_case field names),
   * so admission must take the cap from here.
   */
  readonly outputCap: bigint | undefined;
  /** A Chat client asked for the final usage chunk; see `ResponseContext.streamUsage`. */
  readonly streamUsage: boolean;
}

/**
 * Decodes `body` as a protocol `from` request and encodes it for `to`. `pathModel` is the model
 * named by a Gemini URL. `stream` is the client's stream mode as the gateway resolved it (a Gemini
 * client states it in the URL, the others in the body); it decides the upstream stream mode.
 */
export function translateRequest(from: Protocol, to: Protocol, body: Json, pathModel: string | undefined, stream: boolean): TranslatedRequest {
  if (from === to || !isGeneration(from) || !isGeneration(to)) throw new Refusal(TRANSLATION_CODES.FEATURE, "protocol");
  const request = decodeRequest(from, body, pathModel);
  request.stream = stream;
  const encoded = encodeRequest(to, request);
  return {
    body: encoded,
    dropped: [...request.dropped].sort(),
    outputCap: request.maxTokens,
    streamUsage: request.streamUsage,
  };
}

/** Checks that a client request can be decoded at all, independently of any target: refusals that hold for every target surface before routing. */
export function checkRequest(from: Protocol, body: Json, pathModel: string | undefined): void {
  if (!isGeneration(from)) throw new Refusal(TRANSLATION_CODES.FEATURE, "protocol");
  decodeRequest(from, body, pathModel);
}

/** Translates a complete upstream response body into the client protocol. */
export function translateResponse(upstream: Protocol, client: Protocol, body: Json, ctx: ResponseContext): JsonObject {
  return renderResponse(client, upstream, decodeResponse(upstream, body, ctx), ctx);
}
