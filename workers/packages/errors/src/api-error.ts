/**
 * One public API error and how it is rendered (crates/gray-gateway/src/public_errors.rs): the
 * catalog sentence or the error's own, its help link, the retry advice, and the body in the shape
 * of the API the client called, with the request id in the body and in `x-request-id`.
 *
 * - OpenAI and every other API: `{"error":{"type":"gateway_error","code","message","category",
 *   "request_id","param"?,"metadata"?}}`;
 * - Anthropic Messages (`/v1/messages*`): `{"type":"error","error":{"type":<Anthropic error type>,
 *   "message","code","category","request_id",...},"request_id"}`;
 * - Gemini (`/v1beta/*`): `{"error":{"code":<HTTP status>,"message","status":<RPC status>,
 *   "details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":<code>,"domain",
 *   "metadata":{...}}],"request_id",...}}`.
 *
 * Bodies are written as serde_json writes them (@gray/json `toJsonString`): a metadata value that
 * is a Rust integer is a `bigint`, a Rust f64 a `number`.
 */
import { toJsonString, type SerdeObject, type SerdeValue } from "@gray/json";
import { catalog, helpSentence, type Help } from "./catalog.ts";
import { errorCategory } from "./category.ts";

/** The error format of the API a path belongs to. */
export type Shape = "gateway" | "anthropic" | "google";

/**
 * request_log.rs `is_public`: the paths of Gray's public API, the model API's: `/v1` and `/v1beta` with everything under
 * them, and the unprefixed `/chat/completions`, `/responses`, `/messages` and `/models`.
 */
export function isPublicPath(path: string): boolean {
  return ["/v1", "/v1beta"].some((prefix) => path === prefix || path.startsWith(`${prefix}/`)) || ["/chat/completions", "/responses", "/messages", "/models"].includes(path);
}

/** The shape of the API `path` belongs to (`Shape::of`). */
export function shapeOf(path: string): Shape {
  if (path.startsWith("/v1beta/") || path === "/v1beta") return "google";
  if (path.startsWith("/v1/messages") || path.startsWith("/messages")) return "anthropic";
  return "gateway";
}

/** Anthropic's error type for a status, as its API documents them. */
export function anthropicType(status: number): string {
  switch (status) {
    case 400:
    case 422:
      return "invalid_request_error";
    case 409:
      return "conflict_error";
    case 401:
      return "authentication_error";
    case 402:
      return "billing_error";
    case 403:
      return "permission_error";
    case 404:
    case 410:
      return "not_found_error";
    case 413:
      return "request_too_large";
    case 429:
      return "rate_limit_error";
    case 408:
    case 504:
      return "timeout_error";
    case 503:
    case 529:
      return "overloaded_error";
    default:
      return "api_error";
  }
}

/** The google.rpc status Google's APIs pair with an HTTP status. */
export function googleStatus(status: number): string {
  switch (status) {
    case 400:
    case 413:
    case 422:
      return "INVALID_ARGUMENT";
    case 401:
      return "UNAUTHENTICATED";
    case 402:
      return "FAILED_PRECONDITION";
    case 403:
      return "PERMISSION_DENIED";
    case 404:
    case 410:
      return "NOT_FOUND";
    case 405:
    case 501:
      return "UNIMPLEMENTED";
    case 408:
    case 504:
      return "DEADLINE_EXCEEDED";
    case 409:
      return "ABORTED";
    case 429:
      return "RESOURCE_EXHAUSTED";
    case 502:
    case 503:
      return "UNAVAILABLE";
    default:
      return "INTERNAL";
  }
}

/**
 * The origins errors name (`public_errors::Origins`, docs/configuration.md "Origins"), each without a trailing
 * slash: the console's, where the help links lead (ORIGIN), and the model API's (API_ORIGIN), which
 * `GET /v1/models` and the Gemini `ErrorInfo` domain name.
 */
export interface Origins {
  readonly console: string;
  readonly api: string;
  /** The model API's host, with its port when it names one. */
  readonly apiDomain: string;
}

/**
 * `Origins::new`: each URL serialized (`url::Url::as_str`, the WHATWG serialization) without its trailing
 * slashes, and the model API's host and port (`url::Position::BeforeHost..AfterPort`, the WHATWG `host`).
 */
export function publicOrigins(console: string, api: string): Origins {
  const plain = (url: URL) => url.href.replace(/\/+$/, "");
  const apiUrl = new URL(api);
  return { console: plain(new URL(console)), api: plain(apiUrl), apiDomain: apiUrl.host };
}

/** `Origins::unknown`: before a public route renders an error, which knows the origins. */
export const UNKNOWN_ORIGINS: Origins = Object.freeze({ console: "", api: "", apiDomain: "" });

/** `public_errors::no_api`: 404 `unsupported_protocol`, no API answers `method` at `path`. */
export function noApi(method: string, path: string): ApiError {
  return new ApiError(404, "unsupported_protocol").withMessage(
    `There is no API at \`${method} ${path}\` on Gray. The OpenAI and Anthropic APIs are under \`/v1\`, the Gemini API under \`/v1beta\`.`,
  );
}

/**
 * `public_errors::unmatched` with `405`: 405 `unsupported_protocol`, an API path asked with a method it does not take.
 * Its answer carries `allow` ([`allowOf`]).
 */
export function wrongMethod(method: string, path: string): ApiError {
  return new ApiError(405, "unsupported_protocol").withMessage(`\`${path}\` does not take \`${method}\` requests; the \`allow\` header lists the methods it takes.`);
}

/**
 * The `allow` header of a [`wrongMethod`] answer as axum writes it: the path's methods in the order its route registers
 * them, `HEAD` right after `GET` (a GET route answers HEAD), joined by `,` without spaces.
 */
export function allowOf(methods: readonly string[]): string {
  return methods.flatMap((method) => (method === "GET" ? ["GET", "HEAD"] : [method])).join(",");
}

/**
 * `public_errors::elsewhere`: a model API request on the console's host when the model API has a host of its own,
 * 404 `unsupported_protocol` naming where the model API is (`api`, without a trailing slash).
 */
export function elsewhere(method: string, path: string, api: string): ApiError {
  return new ApiError(404, "unsupported_protocol").withMessage(
    `There is no API at \`${method} ${path}\` on this address: Gray's model API is at ${api}. The OpenAI and Anthropic APIs are under \`${api}/v1\`, the Gemini API under \`${api}/v1beta\`.`,
  );
}

/** An error as the client receives it. */
export interface RenderedError {
  readonly status: number;
  /** `content-type`, `x-should-retry`, and `retry-after`, `x-request-id` and extra headers when set. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

interface Fields {
  readonly message?: string | undefined;
  readonly help?: Help | null | undefined;
  readonly param?: string | undefined;
  readonly metadata?: Readonly<Record<string, SerdeValue>> | undefined;
  readonly retryAfter?: bigint | undefined;
  readonly headers?: Readonly<Record<string, string>> | undefined;
  readonly retry?: boolean | undefined;
}

/** A header value Rust's `HeaderValue::from_str` accepts: no control character but tab. */
const HEADER_VALUE = /^[\t -~\u0080-\u{10ffff}]*$/u;

/**
 * One public API error. Build it with the constructor and the `with*` methods (each returns a new
 * error, as Rust's builder returns `Self`), and render it with `render`.
 */
export class ApiError {
  readonly status: number;
  readonly code: string;
  /** Replaces the catalog sentence when the error has specifics to name. */
  readonly ownMessage: string | undefined;
  /** Replaces the catalog's help link when set; `null` drops it. */
  readonly help: Help | null | undefined;
  /** The request field at fault. */
  readonly param: string | undefined;
  /** Machine-readable details under `error.metadata`. */
  readonly metadata: Readonly<Record<string, SerdeValue>>;
  /** Seconds before a retry can succeed, sent as `retry-after`. */
  readonly retryAfter: bigint | undefined;
  /** Headers the response carries besides the error's own (`x-gray-key-limit-reset`). */
  readonly extraHeaders: Readonly<Record<string, string>>;
  /** Whether a repeat of the request can succeed, when the gateway knows better than the status (`noRetry`). */
  readonly retry: boolean | undefined;

  constructor(status: number, code: string, fields: Fields = {}) {
    this.status = status;
    this.code = code;
    this.ownMessage = fields.message;
    this.help = fields.help;
    this.param = fields.param;
    this.metadata = fields.metadata ?? {};
    this.retryAfter = fields.retryAfter;
    this.extraHeaders = fields.headers ?? {};
    this.retry = fields.retry;
  }

  private with(fields: Fields): ApiError {
    return new ApiError(this.status, this.code, {
      message: this.ownMessage,
      help: this.help,
      param: this.param,
      metadata: this.metadata,
      retryAfter: this.retryAfter,
      headers: this.extraHeaders,
      retry: this.retry,
      ...fields,
    });
  }

  /** The sentence to send instead of the catalog's. */
  withMessage(message: string): ApiError {
    return this.with({ message });
  }

  /** The help link to send instead of the catalog's; `null` sends none. */
  withHelp(help: Help | null): ApiError {
    return this.with({ help });
  }

  withParam(param: string): ApiError {
    return this.with({ param });
  }

  /** A machine-readable detail under `error.metadata`; a key set twice keeps the last value. */
  withMeta(key: string, value: SerdeValue): ApiError {
    return this.with({ metadata: { ...this.metadata, [key]: value } });
  }

  /** Seconds before a retry can succeed, at least one. */
  withRetryAfter(seconds: bigint): ApiError {
    return this.with({ retryAfter: seconds > 1n ? seconds : 1n });
  }

  withHeader(name: string, value: string): ApiError {
    return this.with({ headers: { ...this.extraHeaders, [name]: value } });
  }

  /**
   * A repeat of the same request cannot succeed now, whatever the status says: `x-should-retry:
   * false`, which the OpenAI and Anthropic SDKs and OpenCode obey before their status rules.
   */
  noRetry(): ApiError {
    return this.with({ retry: false });
  }

  /** A sentence said after the message (the catalog's, unless one replaced it). */
  note(sentence: string): ApiError {
    return this.with({ message: `${this.ownMessage ?? catalog(this.code)[0]} ${sentence}` });
  }

  /** The message: the error's own sentence or the catalog's, and the help sentence after it. */
  text(origins: Origins): string {
    const [sentence, catalogHelp] = catalog(this.code);
    let text = this.ownMessage ?? sentence;
    const help = this.help === undefined ? catalogHelp : this.help;
    if (help !== null) text += ` ${helpSentence(help, origins)}`;
    return text;
  }

  /**
   * Whether repeating the same request can succeed: rate limits and gateway or provider failures
   * yes, a spend limit, a duplicate and everything the caller must change no, and no whenever the
   * gateway said so (`noRetry`). A stored routing default the gateway cannot read is a 503, since the
   * request is not at fault, but only an admin saving the default again lifts it: a retry cannot pass
   * (product lead, 2026-10-23, release 4 decision 12).
   */
  shouldRetry(): boolean {
    if (this.retry !== undefined) return this.retry;
    switch (this.code) {
      case "key_spend_limit":
      case "request_already_admitted":
      case "account_frozen":
      case "gateway_memory_insufficient":
      case "routing_default_invalid":
        return false;
      default:
        return this.status === 408 || this.status === 429 || (this.status >= 500 && this.status <= 599);
    }
  }

  /** The body in the shape of the API the client called. */
  body(shape: Shape, origins: Origins, requestId?: string): SerdeObject {
    const message = this.text(origins);
    const category = errorCategory(this.code);
    const extend = (error: Record<string, SerdeValue>) => {
      if (requestId !== undefined) error.request_id = requestId;
      if (this.param !== undefined) error.param = this.param;
      if (Object.keys(this.metadata).length > 0) error.metadata = this.metadata;
      return error;
    };
    switch (shape) {
      case "gateway":
        return { error: extend({ type: "gateway_error", code: this.code, message, category }) };
      case "anthropic": {
        const body: Record<string, SerdeValue> = {
          type: "error",
          error: extend({ type: anthropicType(this.status), message, code: this.code, category }),
        };
        if (requestId !== undefined) body.request_id = requestId;
        return body;
      }
      case "google": {
        const info: Record<string, SerdeValue> = { category };
        if (requestId !== undefined) info.request_id = requestId;
        const domain = origins.apiDomain;
        return {
          error: extend({
            code: BigInt(this.status),
            message,
            status: googleStatus(this.status),
            details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: this.code, domain, metadata: info }],
          }),
        };
      }
    }
  }

  /**
   * The response a client receives: by default the gateway's own shape with no origins and no request
   * id (`ApiError::into_response`); a public route renders it in the client's shape with the origins and
   * the request id (`public_errors::finish`).
   */
  render(options: { readonly shape?: Shape; readonly origins?: Origins; readonly requestId?: string } = {}): RenderedError {
    const { shape = "gateway", origins = UNKNOWN_ORIGINS, requestId } = options;
    const headers: Record<string, string> = {
      ...this.extraHeaders,
      "content-type": "application/json",
      "x-should-retry": this.shouldRetry() ? "true" : "false",
    };
    if (this.retryAfter !== undefined) headers["retry-after"] = this.retryAfter.toString();
    if (requestId !== undefined && HEADER_VALUE.test(requestId)) headers["x-request-id"] = requestId;
    return { status: this.status, headers, body: toJsonString(this.body(shape, origins, requestId)) };
  }
}
