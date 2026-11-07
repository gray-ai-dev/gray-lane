/**
 * Rerank (`POST /v1/rerank`, crates/gray-gateway/src/apis/rerank.rs): one query scored against a
 * list of documents, in the request shape Cohere, Jina and Voyage share. Billed per search unit (or
 * request) on routes that set a unit price, else by input tokens.
 *
 * Request: `model`; `query`, a non-empty string; `documents`, 1 to 1,000 non-empty strings or
 * `{"text"}` objects; optional `top_n` (Cohere, Jina) or `top_k` (Voyage), not both;
 * `return_documents`; `max_chunks_per_doc` (Cohere v1); `truncation` (Voyage). An optional field
 * sent as `null` is dropped. Anything else is refused and never forwarded.
 *
 * Forwarded (`forwardedRerank`): what every service takes. The limit is never sent (the whole
 * ranking is asked for and cut here), `truncation: true` is dropped, a `{"text"}` document goes as
 * its text.
 *
 * Bound: a string costs at most its UTF-8 length in tokens. Token-billed rerankers bill the query
 * once per document plus the documents; Cohere bills a search unit per 100 chunks of 500 tokens
 * less the query. With `q` the query's bytes plus 16, the input bound is `Σ q + bytes(d)` and the
 * unit bound `⌈Σ chunks(d) / 100⌉`, at least one.
 *
 * Answer: a list under `results` or `data`, not both, ranking each requested document at most
 * once with a numeric `relevance_score`. The model it names, if any, is not read (Cohere names none,
 * and an upgraded model answers under a new name; main 2c165fb7). The body goes back as received
 * unless it ranks more documents than the client's limit: then it is cut to the best-scored,
 * re-serialized as serde_json writes it.
 */
import { type Json, type JsonObject, get, isObject, toJsonString } from "@gray/json";
import { ZERO_COUNTERS, nestedCounter } from "@gray/protocol";
import { type Billed, apiError, checkMetered, invalid, jsonModel, metered, missing, strictJson, UsageError } from "./common.ts";
import { inputUsage } from "./embeddings.ts";
import type { Answered } from "./images.ts";
import { readUpstream } from "./read.ts";
import type { ApiRequest, Bound, MediaRoute, Metered, Received } from "./types.ts";

/** Most documents one request may rank (Cohere's and Voyage's limit). */
export const MAX_DOCUMENTS = 1000;
/** Largest `max_chunks_per_doc` a request may set. */
export const MAX_CHUNKS_PER_DOC = 1000n;
/** Tokens a service adds to each query-document pair (`[CLS]`, `[SEP]`...). */
const PAIR_OVERHEAD = 16n;
/** Cohere's chunk length, query included. */
const CHUNK_TOKENS = 500n;
/** Chunks one Cohere search unit covers. */
const DOCUMENTS_PER_UNIT = 100n;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

const FIELDS = ["model", "query", "documents", "top_n", "top_k", "return_documents", "max_chunks_per_doc", "truncation"];
const OPTIONS = ["top_n", "top_k", "return_documents", "max_chunks_per_doc", "truncation"];

/** The parts of a rerank request its bound and answer depend on (`Rerank`). */
export interface RerankRequest {
  readonly query: string;
  readonly documents: readonly string[];
  /** `top_n` or `top_k`: the most results the client's answer carries. */
  readonly top: bigint | undefined;
  readonly maxChunks: bigint | undefined;
}

const utf8 = new TextEncoder();
const bytes = (s: string) => BigInt(utf8.encode(s).length);
const saturating = (n: bigint) => (n > U64_MAX ? U64_MAX : n);

/** `document_text`: a non-empty string, or an object whose only field is a non-empty `text`. */
function documentText(document: Json): string | undefined {
  let text: Json | undefined;
  if (typeof document === "string") text = document;
  else if (isObject(document) && Object.keys(document).length === 1) text = get(document, "text");
  return typeof text === "string" && text.length > 0 ? text : undefined;
}

/** `Rerank::of`: the request's parts; throws the client error code as a string. */
export function rerankOf(body: Json): RerankRequest {
  const INVALID = "invalid_protocol_request";
  const query = get(body, "query");
  if (typeof query !== "string" || query.length === 0) throw INVALID;
  const documents = get(body, "documents");
  if (!Array.isArray(documents) || documents.length === 0) throw INVALID;
  if (documents.length > MAX_DOCUMENTS) throw "too_many_documents";
  const texts: string[] = [];
  for (const document of documents) {
    const text = documentText(document);
    if (text === undefined) throw INVALID;
    texts.push(text);
  }
  const positive = (key: string, max: bigint): bigint | undefined => {
    const n = get(body, key);
    if (n === undefined) return undefined;
    if (typeof n !== "bigint" || n < 1n || n > max) throw INVALID;
    return n;
  };
  const topN = positive("top_n", U64_MAX);
  const topK = positive("top_k", U64_MAX);
  if (topN !== undefined && topK !== undefined) throw INVALID;
  for (const key of ["return_documents", "truncation"]) {
    const flag = get(body, key);
    if (flag !== undefined && typeof flag !== "boolean") throw INVALID;
  }
  return { query, documents: texts, top: topN ?? topK, maxChunks: positive("max_chunks_per_doc", MAX_CHUNKS_PER_DOC) };
}

/** `Rerank::bound`: the most input tokens and search units the request can bill; no output. */
export function rerankBound(request: RerankRequest): Bound {
  const query = saturating(bytes(request.query) + PAIR_OVERHEAD);
  const chunk = CHUNK_TOKENS > query ? CHUNK_TOKENS - query : 1n;
  let chunks = 0n;
  let tokens = 0n;
  for (const document of request.documents) {
    const len = bytes(document);
    let pieces = (len + chunk - 1n) / chunk;
    if (pieces < 1n) pieces = 1n;
    if (request.maxChunks !== undefined && pieces > request.maxChunks) pieces = request.maxChunks;
    chunks = saturating(chunks + pieces);
    tokens = saturating(saturating(tokens + query) + len);
  }
  const units = (chunks + DOCUMENTS_PER_UNIT - 1n) / DOCUMENTS_PER_UNIT;
  return { inputTokens: tokens, outputTokens: 0n, units: units < 1n ? 1n : units };
}

/** `read`: the body readied for forwarding (unset options dropped); throws the client error code as a string. */
function read(value: Json): [JsonObject, RerankRequest] {
  if (!isObject(value)) throw "invalid_protocol_request";
  if (Object.keys(value).some((k) => !FIELDS.includes(k))) throw "unsupported_request_field";
  const fields: JsonObject = {};
  for (const key of Object.keys(value)) if (!(OPTIONS.includes(key) && value[key] === null)) fields[key] = value[key] as Json;
  return [fields, rerankOf(fields)];
}

/** `decode`. */
export function decodeRerank(received: Received): ApiRequest {
  if (received.kind !== "json") throw invalid("invalid_protocol_request");
  const model = jsonModel(received.value);
  let body: JsonObject;
  let request: RerankRequest;
  try {
    [body, request] = read(received.value);
  } catch (error) {
    if (typeof error === "string") throw invalid(error);
    throw error;
  }
  return { model, stream: false, selectors: [], bound: rerankBound(request), body: { kind: "json", value: body } };
}

/** `forwarded`: the body in the options every service takes (no limit, no `truncation: true`, `{"text"}` documents as text). */
export function forwardedRerank(body: JsonObject): JsonObject {
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(body)) {
    if (key === "top_n" || key === "top_k") continue;
    if (key === "truncation" && value === true) continue;
    out[key] = value;
  }
  const documents = out.documents;
  if (Array.isArray(documents)) {
    out.documents = documents.map((document) => {
      const text = get(document, "text");
      return isObject(document) && text !== undefined ? text : document;
    });
  }
  return out;
}

/** `answered_by`: the answer ranks only this request's documents, each at most once. */
export function rerankAnsweredBy(request: RerankRequest, value: Json): boolean {
  const results = get(value, "results");
  const data = get(value, "data");
  const list = results !== undefined && data === undefined ? results : results === undefined && data !== undefined ? data : undefined;
  if (!Array.isArray(list) || list.length === 0 || list.length > request.documents.length) return false;
  const seen = new Array<boolean>(request.documents.length).fill(false);
  return list.every((item) => {
    const index = get(item, "index");
    if (typeof index !== "bigint" || index < 0n || index >= BigInt(seen.length)) return false;
    const i = Number(index);
    if (seen[i] === true) return false;
    seen[i] = true;
    const score = get(item, "relevance_score");
    if (typeof score !== "bigint" && typeof score !== "number") return false;
    const document = get(item, "document");
    return document === undefined || document === null || typeof document === "string" || isObject(document);
  });
}

/** `f64::total_cmp`: numeric order, with -0.0 below 0.0 (JSON has no NaN). */
function totalCmp(a: number, b: number): number {
  if (a < b) return -1;
  if (a > b) return 1;
  if (Object.is(a, -0) && Object.is(b, 0)) return -1;
  if (Object.is(a, 0) && Object.is(b, -0)) return 1;
  return 0;
}

/**
 * `limited`: an answer that ranks more than `top` documents, cut to the `top` it scored best, best
 * first (a stable sort: ties keep the service's order), written as serde_json writes it. Undefined
 * for any other answer, which goes back as received.
 */
export function limitedRerank(value: Json, top: bigint): Uint8Array | undefined {
  if (!isObject(value)) return undefined;
  const key = get(value, "results") !== undefined ? "results" : "data";
  const list = get(value, key);
  if (!Array.isArray(list) || BigInt(list.length) <= top) return undefined;
  const score = (item: Json) => {
    const s = get(item, "relevance_score");
    return typeof s === "number" ? s : typeof s === "bigint" ? Number(s) : Number.NEGATIVE_INFINITY;
  };
  const sorted = [...list].sort((a, b) => totalCmp(score(b), score(a))).slice(0, Number(top));
  return utf8.encode(toJsonString({ ...value, [key]: sorted }));
}

/** `search_units`: Cohere's `meta.billed_units.search_units`, if reported; throws on a malformed one. */
export function searchUnits(value: Json): bigint | undefined {
  const meta = get(value, "meta");
  if (meta === undefined || meta === null) return undefined;
  if (!isObject(meta)) throw new UsageError("meta must be an object");
  try {
    return nestedCounter(meta, "billed_units", "search_units");
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
}

export interface RerankAttempt {
  readonly billsUnits: boolean;
  readonly deadlineMs: number;
  readonly responseBytes: number;
}

/**
 * The checks and metering of a rerank answer (`respond`, on the parsed answer, or on the projection a
 * streamed answer keeps of it: the ranking's indexes and scores, `meta`/`usage`): what it is billed
 * by, and whether the client's limit cuts it (`cut`: the ranking ranks more than the client's
 * `top_n`/`top_k`). Throws the answer's refusal as an ApiError.
 */
export function rerankAnswer(api: ApiRequest, value: Json, billsUnits: boolean): { readonly billed: Billed; readonly cut: boolean } {
  let request: RerankRequest | undefined;
  if (api.body.kind === "json") {
    try {
      request = rerankOf(api.body.value);
    } catch {
      request = undefined;
    }
  }
  if (request === undefined) throw apiError(502, "invalid_upstream_response");
  if (!rerankAnsweredBy(request, value)) throw apiError(502, "invalid_upstream_response");
  let billed: Billed;
  if (billsUnits) {
    let units: bigint | undefined;
    try {
      units = searchUnits(value);
    } catch {
      throw apiError(502, "billing_usage_invalid");
    }
    if (units === undefined) units = 1n;
    else if (units === 0n) throw apiError(502, "billing_usage_invalid");
    billed = metered({ counters: { ...ZERO_COUNTERS, units }, raw: { requests: units }, unit: "requests" });
  } else {
    const usage = get(value, "usage");
    const present = usage === undefined || usage === null ? undefined : usage;
    if (present === undefined) {
      billed = missing("usage missing");
    } else {
      let tokens: bigint | undefined;
      try {
        tokens = inputUsage(present);
      } catch {
        throw apiError(502, "billing_usage_invalid");
      }
      if (tokens === 0n) throw apiError(502, "billing_usage_invalid");
      billed = tokens === undefined ? missing("usage.prompt_tokens missing", present) : metered({ counters: { ...ZERO_COUNTERS, input_tokens: tokens }, raw: present, unit: undefined });
    }
  }
  if (billed.kind === "metered") checkMetered("rerank", api.bound, billed.metered, billsUnits);
  // As `limitedRerank` reads the ranking: `results` when the answer has it, else `data`.
  const results = get(value, get(value, "results") !== undefined ? "results" : "data");
  const cut = request.top !== undefined && Array.isArray(results) && BigInt(results.length) > request.top;
  return { billed, cut };
}

/** Whether a rerank request's answer may be cut to the client's limit (`top_n`/`top_k` below its documents): such an answer is read whole. */
export function rerankMayCut(api: ApiRequest): boolean {
  if (api.body.kind !== "json") return false;
  try {
    const request = rerankOf(api.body.value);
    return request.top !== undefined && request.top < BigInt(request.documents.length);
  } catch {
    return false;
  }
}

/** `respond`: the ranking checked and metered by the meter the route prices, cut to the client's limit. */
export async function respondRerank(api: ApiRequest, _route: MediaRoute, upstream: Response, attempt: RerankAttempt): Promise<Answered> {
  const body = await readUpstream(upstream, attempt.responseBytes, attempt.deadlineMs);
  const value = strictJson(body);
  const { billed } = rerankAnswer(api, value, attempt.billsUnits);
  const top = api.body.kind === "json" ? rerankOf(api.body.value).top : undefined;
  const cut = top === undefined ? undefined : limitedRerank(value, top);
  return { body: cut ?? body, contentType: "application/json", billed };
}
