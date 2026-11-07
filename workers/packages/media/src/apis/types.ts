/**
 * The model APIs beyond chat generation: image generation and edits, speech, transcription and
 * translation, embeddings and video (crates/gray-gateway/src/apis/mod.rs). Each API module turns a
 * client request into an `ApiRequest` (the model, its unit-price selectors, a bound on what it can
 * consume, the body to forward) and meters its upstream answer into a `Metered` usage. The shared
 * stages (authentication, routing, the reservation, ranking, failover, settlement) are the
 * gateway's; this package only decides what is specific to each API.
 */
import { type UsageCounters } from "@gray/protocol";
import type { Json, JsonObject } from "@gray/json";
import type { UpstreamAuth } from "../types.ts";
import type { GeminiImageBody, GeminiOfferTerms } from "./gemini-images.ts";

/**
 * One multipart form field. Fields without a file name are UTF-8 text. A file the gateway does not
 * hold in this object is deferred: `data` is only its first DEFERRED_HEAD_BYTES (what the decoders
 * sniff), `size` its whole length and `marker` the token the gateway replaces with the rest of it
 * when it sends a request that carries it (docs/cloudflare-native/media.md 2.1: uploads stream, no
 * upload is ever held whole).
 */
export interface FormPart {
  readonly name: string;
  readonly fileName: string | undefined;
  readonly contentType: string | undefined;
  readonly data: Uint8Array;
  /** The whole length of a deferred file; absent when `data` is the whole field. */
  readonly size?: number;
  /** A deferred file's marker: `GRAYDEFERRED` and 32 lowercase hex digits (base64's alphabet, a multiple of four characters). */
  readonly marker?: string;
}

/**
 * The bytes of a deferred file that are held (`FormPart.data`): what the decoders read of an upload
 * (images.rs sniffs the first 48 bytes, `SNIFF_BYTES`; a type signature needs 12), and a multiple of
 * three, so the base64 of the head is the start of the base64 of the whole file.
 */
export const DEFERRED_HEAD_BYTES = 48;

/** A deferred file's marker as the gateway writes it: never part of a client's base64 (the gateway draws its 128 random bits per file). */
export const DEFERRED_MARKER = /GRAYDEFERRED[0-9a-f]{32}/;

/** A field's whole length: a deferred file's `size`, else its bytes. */
export function partSize(part: FormPart): number {
  return part.size ?? part.data.length;
}

/** Whether the field's bytes are held elsewhere (`data` is only its head). */
export function isDeferred(part: FormPart): boolean {
  return part.marker !== undefined && part.size !== undefined;
}

const BASE64_CHUNK = 0x8000;

function base64Of(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += BASE64_CHUNK) binary += String.fromCharCode(...bytes.subarray(i, i + BASE64_CHUNK));
  return btoa(binary);
}

/**
 * Standard base64 of a field's whole bytes. A deferred file's is the base64 of its head followed by
 * its marker: the gateway replaces the marker with the base64 of the rest when it sends the request
 * (the head is a multiple of three bytes, so the two encodings join into the whole file's). The
 * vendor adapters check such a string's alphabet and length and sniff its first 64 characters, which
 * the head's encoding is.
 */
export function partBase64(part: FormPart): string {
  if (!isDeferred(part)) return base64Of(part.data);
  return `${base64Of(part.data.subarray(0, DEFERRED_HEAD_BYTES))}${part.marker}`;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** `FormPart::text`: the text of a field without a file name; undefined for a file or invalid UTF-8. */
export function partText(part: FormPart): string | undefined {
  if (part.fileName !== undefined) return undefined;
  try {
    return strictUtf8.decode(part.data);
  } catch {
    return undefined;
  }
}

/** A client body as received: one JSON value, or a multipart form's fields in order. */
export type Received = { readonly kind: "json"; readonly value: Json } | { readonly kind: "form"; readonly parts: readonly FormPart[] };

/**
 * The request body as forwarded, before the upstream model is set: a JSON object, a form's fields in
 * order, or a Gemini client's own `generateContent` request for an image model, sent to an image
 * route's Gemini API as it came (gemini-images.ts).
 */
export type ApiBody = { readonly kind: "json"; readonly value: JsonObject } | { readonly kind: "multipart"; readonly parts: readonly FormPart[] } | GeminiImageBody;

/**
 * Upper bounds on what a request can consume; `undefined` means the request does not bound that
 * component (the reservation is then the whole per-request ceiling, unless every eligible route
 * prices that component at zero).
 */
export interface Bound {
  readonly inputTokens: bigint | undefined;
  readonly outputTokens: bigint | undefined;
  /** Billing units of the protocol (`billingUnit`). */
  readonly units: bigint | undefined;
}

export const UNBOUNDED: Bound = { inputTokens: undefined, outputTokens: undefined, units: undefined };

/** A decoded API request. */
export interface ApiRequest {
  /**
   * The deferred files whose markers the body carries (a video's `input_reference` sent as a form
   * file is in its JSON body as a `data:` URI ending in the file's marker): what sends the request
   * finds each marker's file by.
   */
  readonly deferred?: readonly FormPart[];
  /** The requested (customer-facing) model. */
  readonly model: string;
  /** The upstream answers as a stream rather than one body. */
  readonly stream: boolean;
  /** Unit-price selectors, most specific first, e.g. `["1024x1024:high", "1024x1024"]`; the offer's `*` price applies when none matches. */
  readonly selectors: readonly string[];
  readonly bound: Bound;
  readonly body: ApiBody;
}

/** What an answer consumed, ready for settlement. */
export interface Metered {
  readonly counters: UsageCounters;
  /** Native usage counters, or `{unit: count}` for units Gray counts itself; recorded as evidence. */
  readonly raw: Json;
  /** The billing unit `counters.units` counts; undefined for token usage. */
  readonly unit: "images" | "seconds" | "characters" | "requests" | undefined;
}

/**
 * A route as the media APIs read it: the endpoint, its model mapping, the credential, and the price
 * the gateway found for this request's selectors. The gateway builds these from its route snapshot.
 */
export interface MediaRoute {
  readonly endpointId: string;
  readonly providerWorkspace: string;
  /** The endpoint's base URL, which carries the vendor's API version (`.../v1`, `.../v1beta`). */
  readonly baseUrl: string;
  /** The protocol's upstream URL on an OpenAI-compatible route (`{base}/images/generations`, ...). */
  readonly url: string;
  readonly auth: UpstreamAuth;
  readonly credential: string;
  /** The capabilities the endpoint states (`streaming`, `timed_transcripts`, `embedding_base64`, ...). */
  readonly capabilities: readonly string[];
  readonly upstreamModel: string;
  /** The mapping's vendor adapter (`gemini`, `volcengine`, `minimax`, `kling`, `fal`); undefined for an OpenAI-compatible API. */
  readonly adapter: string | undefined;
  /**
   * Whether the price this route has for the request (`priced_rate`) sets a unit price; undefined
   * when the route is unpriced (pricing then refuses it).
   */
  readonly billsUnits: boolean | undefined;
  /**
   * The capabilities the route's probe report proved of the endpoint's claims for its API, as claim
   * words (`catalog::capability_words` of the route's capabilities: `embedding_base64`,
   * `timed_transcripts`, ...). A request in an option shape goes to a route that proved it, never to one
   * whose check withdrew it (`preferProvingAll`).
   */
  readonly proved: readonly string[];
  /**
   * What the route's per-image offer says of a Gemini client's answer beyond its images; undefined on a
   * route priced by tokens or without an offer (gemini-images.ts `retainPriced`).
   */
  readonly geminiTerms?: GeminiOfferTerms;
}

/** The two clocks the APIs read: unix seconds (vendor tokens, `created`) and milliseconds (deadlines). */
export interface Clock {
  nowMs(): number;
}

export const SYSTEM_CLOCK: Clock = { nowMs: () => Date.now() };

export function nowUnix(clock: Clock): bigint {
  return BigInt(Math.floor(clock.nowMs() / 1000));
}
