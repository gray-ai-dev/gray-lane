/**
 * Native token counting, Anthropic `POST /v1/messages/count_tokens` and Gemini
 * `POST /v1beta/models/{model}:countTokens` (crates/gray-gateway/src/count_tokens.rs): the parts
 * that decide nothing about routes or money. Nothing is generated, reserved or billed; only the
 * count fields of a provider reply reach the client.
 *
 * The gateway: `countTarget` refuses a malformed count (400 `invalid_protocol_request`);
 * `inspectedCountRequest` is what the request trust gate inspects; each attempt sends the body as
 * the client sent it with `countOverlay` written over it, to `countUpstreamPath` of the route's URL;
 * a 2xx reply passes `countReply` (else the attempt is `count_tokens_unavailable`; a 400 or 413 is
 * `count_tokens_request_rejected`).
 */
import { type Json, type JsonObject, asStr, cloneJson, get, isArray, isObject, setMember } from "@gray/json";
import { geminiCountModel, geminiMethodPath } from "./paths.ts";
import { type CanonicalRequest, parseRequest } from "./request.ts";
import { ProtocolError, type Protocol, invalidRequest } from "./types.ts";

/**
 * The largest count reply read: 64 KiB. Picked, not sourced in the server version
 * (count_tokens.rs `REPLY_LIMIT`, docs/limits.md open items): a count reply is a few numbers.
 */
export const COUNT_REPLY_LIMIT = 64 * 1024;

/**
 * The model a count names, when the body is well formed: Gemini's from its path, with `contents`
 * (an array) or a whole `generateContentRequest` (an object); Anthropic's `model`, with `messages`
 * (an array). Undefined is 400 `invalid_protocol_request`.
 */
export function countTarget(protocol: Protocol, path: string, body: Json): string | undefined {
  let model: string | undefined;
  let wellFormed: boolean;
  if (protocol === "gemini") {
    model = geminiCountModel(path);
    wellFormed = isArray(get(body, "contents")) || isObject(get(body, "generateContentRequest"));
  } else {
    model = asStr(get(body, "model"));
    wellFormed = isArray(get(body, "messages"));
  }
  return model !== undefined && model.length > 0 && wellFormed ? model : undefined;
}

/**
 * `inspected_request`: the count body as inference's request gate inspects it. A Gemini body
 * carries either `contents` or a whole `generateContentRequest`, never both; the inner request is
 * parsed without its `model` (the gateway replaces it), and the outer body may carry nothing else.
 */
export function inspectedCountRequest(protocol: Protocol, model: string, body: Json): CanonicalRequest {
  const inner = protocol === "gemini" ? get(body, "generateContentRequest") : undefined;
  if (inner === undefined) return parseRequest(protocol, protocol === "gemini" ? model : null, body);
  if (!isObject(inner) || !isObject(body) || Object.keys(body).length !== 1) {
    throw invalidRequest(protocol, "generateContentRequest must be the only field");
  }
  const copy: JsonObject = {};
  for (const key of Object.keys(inner)) if (key !== "model") setMember(copy, key, inner[key] as Json);
  return parseRequest(protocol, model, copy);
}

/**
 * The count path of a route's URL path: Gemini's `:countTokens` in place of the generation method the
 * path names, by the one rule every Gemini call follows (`geminiMethodPath`, count_tokens.rs `send`;
 * undefined when the path names no model with a generation method, an unavailable attempt); otherwise
 * `/count_tokens` appended.
 */
export function countUpstreamPath(protocol: Protocol, upstreamPath: string): string | undefined {
  if (protocol === "gemini") return geminiMethodPath(upstreamPath, "countTokens");
  return `${upstreamPath.replace(/\/+$/, "")}/count_tokens`;
}

/**
 * What a count attempt writes over the client's body: the upstream model, from the reviewed mapping
 * only. Gemini names the model in the path, so only a `generateContentRequest` is rewritten (its
 * `model` becomes `models/{upstream}`); Anthropic's `model` is replaced.
 */
export function countOverlay(protocol: Protocol, body: Json, upstreamModel: string): readonly [string, Json] | undefined {
  if (protocol !== "gemini") return ["model", upstreamModel];
  const inner = get(body, "generateContentRequest");
  if (!isObject(inner)) return undefined;
  const copy = cloneJson(inner) as JsonObject;
  setMember(copy, "model", `models/${upstreamModel}`);
  return ["generateContentRequest", copy];
}

/** A Gemini modality name a count reply may carry: 1 to 32 of `A-Z` and `_`. */
const MODALITY = /^[A-Z_]{1,32}$/;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * `counts`: the count fields of a native reply, rebuilt from validated values only (undefined when
 * the reply is not a valid count). Anthropic `{input_tokens}`; Gemini `{totalTokens,
 * cachedContentTokenCount?, promptTokensDetails?, cacheTokensDetails?}` with each detail
 * `{modality, tokenCount?}` (proto3 JSON omits zero counts).
 */
export function countReply(protocol: Protocol, reply: Json): JsonObject | undefined {
  const u64 = (v: Json | undefined): bigint | undefined => (typeof v === "bigint" && v >= 0n && v <= U64_MAX ? v : undefined);
  if (protocol !== "gemini") {
    const input = u64(get(reply, "input_tokens"));
    return input === undefined ? undefined : { input_tokens: input };
  }
  const total = u64(get(reply, "totalTokens"));
  if (total === undefined) return undefined;
  const out: JsonObject = { totalTokens: total };
  const cached = get(reply, "cachedContentTokenCount");
  if (cached !== undefined) {
    const n = u64(cached);
    if (n === undefined) return undefined;
    out.cachedContentTokenCount = n;
  }
  for (const key of ["promptTokensDetails", "cacheTokensDetails"]) {
    const details = get(reply, key);
    if (details === undefined) continue;
    if (!isArray(details)) return undefined;
    const kept: JsonObject[] = [];
    for (const detail of details) {
      const modality = asStr(get(detail, "modality"));
      if (modality === undefined || !MODALITY.test(modality)) return undefined;
      const entry: JsonObject = { modality };
      const count = get(detail, "tokenCount");
      if (count !== undefined) {
        const n = u64(count);
        if (n === undefined) return undefined;
        entry.tokenCount = n;
      }
      kept.push(entry);
    }
    out[key] = kept;
  }
  return out;
}

export { ProtocolError };
