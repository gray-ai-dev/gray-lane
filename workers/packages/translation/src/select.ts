/**
 * Choosing the translation of a request that has no native route, and carrying it through
 * admission and dispatch (crates/gray-gateway/src/inference.rs: `select_translation`,
 * `Translated`, and the steps of `forward` that touch it).
 *
 * The translation-specific steps, their order and which refusal wins are ported here; what needs
 * the gateway's state (the live routes, capability, the customer's filter, region, pricing) comes
 * in through `routes` and `judge`, so the precedence of the answers stays Rust's whatever route
 * type the gateway uses.
 */
import { ApiError } from "@gray/errors";
import { type Json, type JsonObject, toJsonString } from "@gray/json";
import { jsonLen, requestLimit, requestLimitSource } from "@gray/limits";
import {
  type CanonicalRequest,
  type CanonicalResponse,
  type Protocol,
  ProtocolError,
  Refusal,
  type ResponseContext,
  type TranslatedRequest,
  applyOutputCap,
  checkRequest,
  translateRequest,
} from "@gray/protocol";
import { refusalError, translationHeaders, upstreamContract } from "./http.ts";
import { StreamStage, translateBody } from "./stage.ts";
import type { Rule } from "./targets.ts";

/**
 * How Rust's error texts name an API (`protocol_title`, crates/gray-gateway/src/inference.rs).
 */
export function protocolTitle(protocol: Protocol): string {
  switch (protocol) {
    case "open_ai_chat":
      return "the OpenAI Chat Completions API (/v1/chat/completions)";
    case "open_ai_responses":
      return "the OpenAI Responses API (/v1/responses)";
    case "anthropic_messages":
      return "the Anthropic Messages API (/v1/messages)";
    case "gemini":
      return "the Gemini API (/v1beta/models/...)";
    case "system_one":
      return "the System One API (/v1/systemone)";
    case "open_ai_embeddings":
      return "the embeddings API (/v1/embeddings)";
    case "rerank":
      return "the rerank API (/v1/rerank)";
    case "open_ai_image_generations":
      return "the image generation API (/v1/images/generations)";
    case "open_ai_image_edits":
      return "the image edits API (/v1/images/edits)";
    case "open_ai_speech":
      return "the speech API (/v1/audio/speech)";
    case "open_ai_transcriptions":
      return "the transcription API (/v1/audio/transcriptions)";
    case "open_ai_translations":
      return "the audio translation API (/v1/audio/translations)";
    case "open_ai_videos":
      return "the video API (/v1/videos)";
  }
}

/**
 * 413 `request_body_limit` for a request whose translation for `upstream` is larger than that API
 * takes (`translated_body_refusal`): its client's API took the body, and the API that would serve it
 * would not.
 */
export function translatedBodyRefusal(upstream: Protocol, translatedBytes: bigint): ApiError {
  const limit = requestLimit(upstream);
  return new ApiError(413, "request_body_limit")
    .withMessage(
      `This model is served through ${protocolTitle(upstream)}: translated for it, the request is ${translatedBytes} bytes, larger than ${limit} bytes, ${requestLimitSource(upstream)}. Send a smaller request.`,
    )
    .withMeta("limit_bytes", limit);
}

const utf8 = new TextEncoder();

/**
 * The translation chosen for a request (Rust's `Translated`, without the price bound, which is the
 * gateway's and comes back from `judge`). One per request: every route of the plan shares its
 * upstream protocol, so failover never changes protocol.
 */
export class Translation {
  /** The protocol the client spoke. */
  readonly client: Protocol;
  /** The protocol every route of the plan speaks. */
  readonly upstream: Protocol;
  /** The upstream body. `writeOutputCap` changes it in place; send `upstreamBytes()`. */
  readonly body: JsonObject;
  /**
   * The serialized size of `body` before any cap was written: checked against the upstream API's
   * body limit (the hold counts the body's prompt units instead).
   */
  readonly bodyBytes: bigint;
  /**
   * The upstream contract (`upstream_contract`): capability, trust and billing read it. Re-read by
   * `refreshContract` once admission has settled the cap.
   */
  contract: CanonicalRequest;
  /** Advisory client fields the upstream body does not carry, each named once. */
  readonly dropped: string[];
  /** The client's output cap as the translation decoded it; admission takes it (`admissionOutputCap`). */
  readonly outputCap: bigint | undefined;
  /** A Chat client asked for the final usage chunk (`ResponseContext.streamUsage`). */
  readonly streamUsage: boolean;

  constructor(client: Protocol, upstream: Protocol, translated: TranslatedRequest, bodyBytes: bigint, contract: CanonicalRequest) {
    this.client = client;
    this.upstream = upstream;
    this.body = translated.body;
    this.bodyBytes = bodyBytes;
    this.contract = contract;
    this.dropped = [...translated.dropped];
    this.outputCap = translated.outputCap;
    this.streamUsage = translated.streamUsage;
  }

  /**
   * Writes a cap Gray chose into the upstream body with the upstream protocol's field
   * (`apply_output_cap`), keeping an Anthropic thinking budget below it. A refit writes the cap
   * again, and each field it drops is named once.
   */
  writeOutputCap(cap: number): void {
    for (const field of applyOutputCap(this.upstream, this.body, cap)) {
      if (!this.dropped.includes(field)) this.dropped.push(field);
    }
  }

  /**
   * Re-reads the upstream contract from the final upstream body, so routing, trust and billing
   * checks see exactly what is sent. `outputCap` is the cap admission settled on when the client
   * stated one or Gray wrote one (Rust's `client_cap || written`), else null. Returns 400
   * `translation_invalid_request` when the upstream's own parser refuses the body, else null.
   */
  refreshContract(model: string, stream: boolean, outputCap: number | null): ApiError | null {
    let contract: CanonicalRequest;
    try {
      contract = upstreamContract(this.upstream, model, this.body, stream);
    } catch (error) {
      if (error instanceof ProtocolError) return new ApiError(400, "translation_invalid_request");
      throw error;
    }
    this.contract = outputCap === null ? contract : { ...contract, max_output_tokens: outputCap };
    return null;
  }

  /**
   * The client headers a translated request does not forward: none of the client's protocol
   * headers reach the upstream, and an Anthropic client's `anthropic-beta` is named as dropped.
   * Call once, before dispatch, with the client request's headers.
   */
  noteClientHeaders(headers: Headers): void {
    if (this.client === "anthropic_messages" && headers.has("anthropic-beta")) this.dropped.push("anthropic_beta");
  }

  /** The upstream request body as serde_json writes it. */
  upstreamBytes(): Uint8Array {
    return utf8.encode(toJsonString(this.body));
  }

  /** The headers that mark the response as translated (`mark_response`). */
  headers(): Record<string, string> {
    return translationHeaders(this.upstream, this.dropped);
  }

  /** What generated ids and labels in the client answer take: the request id, now in Unix seconds, the model. */
  context(requestId: string, createdSeconds: bigint, model: string): ResponseContext {
    return { requestId, created: createdSeconds < 0n ? 0n : createdSeconds, model, streamUsage: this.streamUsage };
  }

  /** The client side of a translated stream, fed with the tool gate's inspected events. */
  stage(ctx: ResponseContext): StreamStage {
    return new StreamStage(this.upstream, this.client, ctx);
  }

  /** A buffered upstream answer, natively parsed and inspected, as the client's bytes (`translate_body`). Throws a TranslationFailure. */
  translateAnswer(payload: Json, parsed: CanonicalResponse, ctx: ResponseContext): Uint8Array {
    return translateBody(this.upstream, this.client, payload, parsed, ctx);
  }
}

/** What the gateway says about one target, after the translation itself passed. */
export type Verdict<T> =
  /** Serve the request through this target: `value` is the gateway's (routes, price bound). */
  | { readonly kind: "serve"; readonly value: T }
  /** No route of the target is capable of the upstream contract: missing supply, nothing recorded. */
  | { readonly kind: "skip" }
  /** The customer's own filter left the target no route. */
  | { readonly kind: "excluded" }
  /** The target cannot serve the request for this reason (region, pricing). */
  | { readonly kind: "failed"; readonly error: ApiError };

export interface SelectOptions<R, T> {
  /** The protocol the client spoke. */
  readonly client: Protocol;
  /** The client body as the gateway parsed it. */
  readonly body: Json;
  /** The model a Gemini client's path names. */
  readonly pathModel: string | undefined;
  /** The requested model (the native parse's `model`). */
  readonly model: string;
  /** The client's stream mode as the gateway resolved it. */
  readonly stream: boolean;
  /** The upstream protocols to try, in order: an operator's rule's, or the implied fallback's (`translationTargets`). */
  readonly upstreams: readonly Protocol[];
  /** The rule that listed `upstreams` (`translationTargets`); `operator` when left out. */
  readonly rule?: Rule;
  /** The live routes of the model under an upstream protocol (unexpired, same requested model). */
  routes(upstream: Protocol): readonly R[];
  /**
   * The gateway's checks of one target, in Rust's order: keep the routes capable of
   * `translation.contract` (none: `skip`); then the customer's filter, when it is not the default
   * (none left: `excluded`); then the caller's region and the prices (an error: `failed`).
   */
  judge(translation: Translation, routes: readonly R[]): Verdict<T> | Promise<Verdict<T>>;
  /** The answer when no target had a route at all (`model_resolution::unrouted`). */
  unrouted(): ApiError;
}

export type Selection<T> = { readonly ok: true; readonly translation: Translation; readonly value: T } | { readonly ok: false; readonly error: ApiError };

/**
 * `select_translation_with`: the first upstream protocol of the rule's list (`o.rule`: an operator's, or the implied
 * Responses fallback, `translationTargets`) that can serve the request. Call it only when the request has no native
 * route. Under an operator's rule a refusal that holds for every target is a 400 before anything is reserved.
 * Otherwise, per target in order: a target without routes is skipped; a translation refusal is kept (the first one);
 * a body the upstream's parser refuses (400 `translation_invalid_request`) or a body larger than its API takes (413)
 * is kept as the target's failure; then `judge`. How many tools a request declares is its provider's to decide
 * (main's 2dcdb334): Gray cannot know what a relay's route takes, so the count is not checked. When no target serves:
 * the first refusal, else the first failure, else 400 `routing_filter_excluded_all` when the customer's filter
 * emptied a target, else `unrouted()`. Under the implied rule (decision (b) of 2026-10-23) a refusal of the
 * translation is no answer: one of the request itself (`checkRequest`) answers `unrouted()` at once, one of a target
 * (`translateRequest`) skips that target as if it had no capable route; the answer is then the first failure, the
 * filter's, or `unrouted()`, as without the rule, so the rule never turns today's answer into a translation refusal.
 */
export async function selectTranslation<R, T>(o: SelectOptions<R, T>): Promise<Selection<T>> {
  const implied = o.rule === "implied";
  try {
    checkRequest(o.client, o.body, o.pathModel);
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, error: implied ? o.unrouted() : refusalError(error) };
    throw error;
  }
  let refused: Refusal | undefined;
  let failed: ApiError | undefined;
  let excluded = false;
  for (const upstream of o.upstreams) {
    const routes = o.routes(upstream);
    if (routes.length === 0) continue;
    let translated: TranslatedRequest;
    try {
      translated = translateRequest(o.client, upstream, o.body, o.pathModel, o.stream);
    } catch (error) {
      if (!(error instanceof Refusal)) throw error;
      if (!implied) refused ??= error;
      continue;
    }
    let contract: CanonicalRequest;
    try {
      contract = upstreamContract(upstream, o.model, translated.body, o.stream);
    } catch (error) {
      if (!(error instanceof ProtocolError)) throw error;
      failed ??= new ApiError(400, "translation_invalid_request");
      continue;
    }
    // The upstream executes the translated request, so its API's body size applies. How many tools
    // it declares is the provider's to decide: Gray forwards the request and passes a refusal on.
    const bodyBytes = jsonLen(translated.body);
    if (bodyBytes > requestLimit(upstream)) {
      failed ??= translatedBodyRefusal(upstream, bodyBytes);
      continue;
    }
    const translation = new Translation(o.client, upstream, translated, bodyBytes, contract);
    const verdict = await o.judge(translation, routes);
    switch (verdict.kind) {
      case "serve":
        return { ok: true, translation, value: verdict.value };
      case "skip":
        continue;
      case "excluded":
        excluded = true;
        continue;
      case "failed":
        failed ??= verdict.error;
        continue;
    }
  }
  if (refused !== undefined) return { ok: false, error: refusalError(refused) };
  if (failed !== undefined) return { ok: false, error: failed };
  if (excluded) return { ok: false, error: new ApiError(400, "routing_filter_excluded_all") };
  return { ok: false, error: o.unrouted() };
}

const U32_MAX = 4_294_967_295n;

/**
 * The output cap admission uses for a translated request: the one the upstream body carries. The
 * native parse of the client body can miss it (a Gemini client may spell it in snake_case), and a
 * missed cap would be replaced by the affordable one. `native` is the native parse's
 * `max_output_tokens`; `decoded` is `Translation.outputCap`. Equal: kept. Missed by the native
 * parse: the decoded cap, which must be a positive u32. Anything else is 400
 * `translation_invalid_request`.
 */
export function admissionOutputCap(native: number | null, decoded: bigint | undefined): { readonly ok: true; readonly cap: number | null } | { readonly ok: false; readonly error: ApiError } {
  if (native === null ? decoded === undefined : decoded === BigInt(native)) return { ok: true, cap: native };
  if (native === null && decoded !== undefined && decoded > 0n && decoded <= U32_MAX) return { ok: true, cap: Number(decoded) };
  return { ok: false, error: new ApiError(400, "translation_invalid_request") };
}
