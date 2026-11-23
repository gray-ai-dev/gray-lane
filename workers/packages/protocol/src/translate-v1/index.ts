/**
 * `gray-lane-translation-v1`: the request translation Gray's entry signed receipts under before
 * `gray-lane-translation-v2`, frozen so that a verifier still replays those receipts
 * (docs/design/lane-provider-routes.md section 10, @gray/lane `replayTranslated`).
 *
 * decode.ts, encode.ts, ir.ts and carrier.ts are protocol/src/translate's files at Gray's source commit 5e6d0e4cf, the
 * one gray-lane-verify 1.5.0 was released from, with only their imports changed: the refusal, `rustTrim` and the
 * protocol names are the live ones (../translate/refusal.ts, ../text.ts, ../types.ts), unchanged since. Never edit these
 * files. The live translation (../translate) is the newest policy's; when its output changes, that change is a new
 * policy id and the previous output is frozen the same way. @gray/lane's translation vectors
 * (packages/lane/test/translation-vectors.test.ts) pin the bytes each id writes.
 */
import type { Json, JsonObject } from "@gray/json";
import { type Protocol, isGeneration } from "../types.ts";
import { Refusal, TRANSLATION_CODES } from "../translate/refusal.ts";
import { decodeRequest } from "./decode.ts";
import { applyOutputCap, encodeRequest } from "./encode.ts";

/** What `translateRequestV1` gives: the translated body and the client fields it does not carry. */
export interface TranslatedRequestV1 {
  readonly body: JsonObject;
  /** Sorted, deduplicated names. */
  readonly dropped: readonly string[];
}

/** gray-lane-translation-v1's `translateRequest` (protocol/src/translate/index.ts at 5e6d0e4cf), body and dropped names. */
export function translateRequestV1(from: Protocol, to: Protocol, body: Json, pathModel: string | undefined, stream: boolean): TranslatedRequestV1 {
  if (from === to || !isGeneration(from) || !isGeneration(to)) throw new Refusal(TRANSLATION_CODES.FEATURE, "protocol");
  const request = decodeRequest(from, body, pathModel);
  request.stream = stream;
  const encoded = encodeRequest(to, request);
  return { body: encoded, dropped: [...request.dropped].sort() };
}

/** gray-lane-translation-v1's `applyOutputCap`. */
export const applyOutputCapV1: (protocol: Protocol, body: Json, cap: number) => string[] = applyOutputCap;
