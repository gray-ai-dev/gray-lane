/**
 * `gray-relay-method-v1`: the format of a relay's registered change method (docs/relay-changes-v2.md §2.2–§2.4).
 *
 * A method is one public JSON document. Egress applies the method bound to an account to the entry's body E
 * (`applyMethod`), the console checks a document before it registers it (`validateMethod`), and the verifier
 * replays it from a receipt. The TypeScript code here and egress's Go code are held to one set of shared vectors
 * (`deploy/tee/egress/testdata/method-vectors.json`, written by `generate-method-vectors.mjs`).
 *
 * This module holds the closed lists and limits, and the shape of a checked method. Every value a method writes into
 * a body is kept as its comparison-form text (RFC 8785 with each number token as written, `stackCanonical`'s form),
 * so a method's `0.70` is written as `0.70` and its digest covers exactly those bytes.
 */
import type { LaneProtocol } from "../protocol.ts";

/** The one format this code reads. A new op or position is a new format version. */
export const RELAY_METHOD_FORMAT = "gray-relay-method-v1";

/** The structural limits of §2.4, with §2.2's per-op limits. */
export const METHOD_LIMITS = Object.freeze({
  /** The document's comparison form, in UTF-8 bytes. */
  documentBytes: 16 * 1024,
  nameMinLength: 1,
  nameMaxLength: 64,
  texts: 8,
  textMinBytes: 1,
  textMaxBytes: 4096,
  textsTotalBytes: 8192,
  textIdMaxLength: 64,
  rules: 16,
  opsPerRule: 32,
  /** Conditions per `when`, every `not` and its operand counted. */
  conditionsPerWhen: 8,
  /** Any listed set: `protocols`, a condition's list, `equals_any`, `map.cases`, header tokens. */
  listedSet: 16,
  pathTokens: 8,
  /** UTF-16 code units, as the receipt's pointers. */
  pathLength: 256,
  /** A `set` value's comparison form. */
  valueBytes: 1024,
  /** Any string inside a `set` value (its UTF-8 bytes): longer text belongs in `texts`. */
  valueStringBytes: 64,
  /** A `remove_elements` scalar's comparison form. */
  scalarBytes: 128,
  /** A map case's key, and a condition's listed string. */
  listedStringBytes: 512,
  headerOps: 16,
  headerValueMinBytes: 1,
  headerValueMaxBytes: 512,
  headerNameMaxLength: 64,
  /** Active methods per relay (the console's check, §2.4 "per relay"). */
  activePerRelay: 8,
});

/** Where `insert_text`, `move` and `copy` put text, per protocol (§2.2 "Positions"). */
export const METHOD_POSITIONS_BY_PROTOCOL = Object.freeze({
  anthropic_messages: Object.freeze(["system_start", "system_end"] as const),
  open_ai_chat: Object.freeze(["instructions_before", "instructions_after"] as const),
  open_ai_responses: Object.freeze(["instructions_before", "instructions_after", "input_start"] as const),
}) satisfies Readonly<Record<LaneProtocol, readonly string[]>>;

/** Every position of the format. */
export const METHOD_POSITIONS = Object.freeze(["system_start", "system_end", "instructions_before", "instructions_after", "input_start"] as const);
export type MethodPosition = (typeof METHOD_POSITIONS)[number];

/** The content members `move` and `copy` read text from, per protocol (Chat has none). */
export const METHOD_TEXT_SOURCES = Object.freeze({
  anthropic_messages: Object.freeze(["/system"]),
  open_ai_chat: Object.freeze([] as string[]),
  open_ai_responses: Object.freeze(["/instructions"]),
}) satisfies Readonly<Record<LaneProtocol, readonly string[]>>;

/** The arrays `remove_elements` removes from. */
export const METHOD_ELEMENT_ARRAYS = Object.freeze(["/messages", "/input", "/system", "/tools"] as const);

/**
 * The content members (§2.4): the model reads them, so `set`, `clamp` and `map` never write at or under them. They
 * change only through `insert_text`, `move`/`copy` and removals.
 */
export const METHOD_CONTENT_MEMBERS = Object.freeze(["system", "messages", "input", "instructions", "tools", "tool_choice", "response_format", "text", "prompt"] as const);

/** The client headers a condition or map may read: the names the entry forwards (§2.2 "Conditions"). */
export const METHOD_CLIENT_HEADERS = Object.freeze(["user-agent", "accept", "anthropic-version", "anthropic-beta", "openai-beta"] as const);
export type MethodClientHeader = (typeof METHOD_CLIENT_HEADERS)[number];

/** The facts a `map` chooses by: the route's two models, E's `stream`, or a client header. */
export type MethodMapFact = "requested_model" | "upstream_model" | "stream" | MethodClientHeader;

/** The comma-list headers `add_tokens`/`remove_tokens` edit. */
export const METHOD_TOKEN_HEADERS = Object.freeze(["anthropic-beta", "openai-beta"] as const);

/**
 * Header names a method may not touch (§2.3): the credential headers of every route, P6's account headers, egress's
 * own framing and hop-by-hop headers. `x-gray-*` is refused by prefix.
 */
export const METHOD_REFUSED_HEADERS = Object.freeze([
  // credentials (every route's form: S15, stack_identity.go stackCredentialHeaders)
  "authorization",
  "x-api-key",
  "chatgpt-account-id",
  // P6
  "cookie",
  "proxy-authorization",
  "openai-organization",
  "openai-project",
  // egress's own (P5)
  "content-type",
  "content-encoding",
  "content-length",
  "accept-encoding",
  "host",
  // hop-by-hop (RFC 9110 §7.6.1)
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
] as const);

/**
 * The kept limits a method's paths may not reach (§2.4 "kept limits", P1–P4, P7), as top-level member names per
 * protocol. Every protocol keeps `model`, `models` and `stream` (P3, P4) and every member whose name starts with
 * `prompt_cache` (P7). `open_ai_chat` keeps the union of every OpenAI-compatible vendor's kept members besides its own,
 * since a method names protocols, not vendors.
 */
export const METHOD_KEPT_MEMBERS = Object.freeze({
  anthropic_messages: Object.freeze(["model", "models", "stream", "container", "mcp_servers"]),
  open_ai_chat: Object.freeze(["model", "models", "stream", "store", "web_search_options"]),
  open_ai_responses: Object.freeze(["model", "models", "stream", "store", "background", "conversation"]),
}) satisfies Readonly<Record<LaneProtocol, readonly string[]>>;

/** Kept paths below the top level (P4: Chat's `stream_options.include_usage`). An op at, under or above one is refused. */
export const METHOD_KEPT_PATHS = Object.freeze({
  anthropic_messages: Object.freeze([] as string[][]),
  open_ai_chat: Object.freeze([["stream_options", "include_usage"]]),
  open_ai_responses: Object.freeze([] as string[][]),
}) satisfies Readonly<Record<LaneProtocol, readonly (readonly string[])[]>>;

/** Top-level names starting with this are kept on every protocol (P7). */
export const METHOD_KEPT_PREFIX = "prompt_cache";

/** A member of this name is kept at any depth (P7): no path names it, no written value holds it, no removal drops one. */
export const METHOD_KEPT_ANY_DEPTH = "cache_control";

/** A value of a method, as its comparison-form text and the UTF-8 length of that text. */
export interface MethodValue {
  readonly json: string;
  readonly bytes: number;
}

/** A parsed RFC 6901 path: `*` stands for every index of an array. */
export interface MethodPath {
  readonly text: string;
  readonly tokens: readonly string[];
}

export type MethodMap = {
  readonly fact: MethodMapFact;
  /** By the fact's value (`stream` as `"true"`/`"false"`). */
  readonly cases: ReadonlyMap<string, MethodValue>;
  readonly default?: MethodValue;
};

export type MethodOp =
  | { readonly op: "insert_text"; readonly text: string; readonly at: MethodPosition }
  | { readonly op: "set"; readonly path: MethodPath; readonly value: MethodValue; readonly whenAbsent: boolean }
  | { readonly op: "set"; readonly path: MethodPath; readonly map: MethodMap; readonly whenAbsent: boolean }
  | { readonly op: "clamp"; readonly path: MethodPath; readonly max: bigint; readonly min?: bigint }
  | { readonly op: "remove"; readonly path: MethodPath }
  | {
      readonly op: "remove_elements";
      readonly path: MethodPath;
      readonly member: MethodPath;
      /** The listed scalars as comparison-form text, or `present`. */
      readonly equalsAny?: readonly string[];
      readonly present?: true;
    }
  | { readonly op: "move" | "copy"; readonly from: MethodPath; readonly at: MethodPosition };

export type MethodCondition =
  | { readonly kind: "protocol"; readonly values: readonly string[] }
  | { readonly kind: "requested_model"; readonly values: readonly string[] }
  | { readonly kind: "upstream_model"; readonly values: readonly string[] }
  | { readonly kind: "stream"; readonly value: boolean }
  | { readonly kind: "client_header"; readonly name: MethodClientHeader; readonly match: "equals_any" | "prefix_any" | "has_token"; readonly values: readonly string[] }
  | { readonly kind: "present"; readonly path: MethodPath }
  | { readonly kind: "absent"; readonly path: MethodPath }
  | { readonly kind: "is"; readonly path: MethodPath; readonly type: MethodJsonType }
  | { readonly kind: "not"; readonly condition: MethodCondition };

export const METHOD_JSON_TYPES = Object.freeze(["string", "number", "boolean", "null", "object", "array"] as const);
export type MethodJsonType = (typeof METHOD_JSON_TYPES)[number];

export interface MethodRule {
  readonly when: readonly MethodCondition[];
  readonly ops: readonly MethodOp[];
}

export type MethodHeaderOp =
  | { readonly op: "set"; readonly name: string; readonly value: string }
  | { readonly op: "set"; readonly name: string; readonly map: { readonly fact: MethodMapFact; readonly cases: ReadonlyMap<string, string>; readonly default?: string } }
  | { readonly op: "remove"; readonly name: string }
  | { readonly op: "add_tokens" | "remove_tokens"; readonly name: string; readonly tokens: readonly string[] };

/** A checked method: what `validateMethod` answers and `applyMethod` runs. */
export interface RelayMethod {
  readonly format: typeof RELAY_METHOD_FORMAT;
  readonly name: string;
  readonly version: number;
  readonly protocols: readonly LaneProtocol[];
  readonly texts: ReadonlyMap<string, string>;
  readonly rules: readonly MethodRule[];
  readonly headers: readonly MethodHeaderOp[];
  /** The client headers any condition or map reads, sorted: the facts a receipt carries for a replay. */
  readonly readsHeaders: readonly MethodClientHeader[];
  /** The document's comparison form (RFC 8785, number tokens as written): what is published and hashed. */
  readonly canonical: string;
  /** SHA-256 of `canonical`'s UTF-8 bytes, lower hex: the method's identity. */
  readonly sha256: string;
}

/** One body change a method made, as the receipt lists it (§2.7): an RFC 6902 path with byte counts, never a value. */
export interface MethodOpRecord {
  readonly op: "add" | "remove" | "replace";
  readonly path: string;
  /** UTF-8 length of the removed value's comparison form. */
  readonly removed_bytes: number;
  /** UTF-8 length of the added value's comparison form. */
  readonly added_bytes: number;
  /** The registered text it placed (`insert_text`). */
  readonly text?: string;
  /** The customer's content member it placed (`move`, `copy`). */
  readonly from?: string;
}

/** One header change a method made, against the headers egress built before it. */
export interface MethodHeaderRecord {
  readonly op: "add" | "remove" | "replace";
  readonly name: string;
  readonly removed_bytes: number;
  readonly added_bytes: number;
}

/** Why a document is not a method this format allows. Closed: the console shows it and egress's Go code uses the same. */
export const METHOD_REFUSAL_CODES = Object.freeze([
  "method_json",
  "method_size",
  "method_format",
  "method_shape",
  "method_name",
  "method_version",
  "method_protocols",
  "method_texts",
  "method_text_unknown",
  "method_limits",
  "method_op",
  "method_path",
  "method_kept",
  "method_content",
  "method_position",
  "method_source",
  "method_value",
  "method_condition",
  "method_header",
  "method_header_refused",
  "method_digest",
] as const);
export type MethodRefusalCode = (typeof METHOD_REFUSAL_CODES)[number];

/** Whether `value` is one of the closed refusal codes. */
export function isMethodRefusalCode(value: unknown): value is MethodRefusalCode {
  return typeof value === "string" && (METHOD_REFUSAL_CODES as readonly string[]).includes(value);
}

/** Whether `position` exists for `protocol`. */
export function isMethodPositionFor(protocol: LaneProtocol, position: string): position is MethodPosition {
  return (METHOD_POSITIONS_BY_PROTOCOL[protocol] as readonly string[]).includes(position);
}

/** RFC 6901 token escaping, for the concrete paths a receipt names. */
export function escapePointerToken(token: string): string {
  return token.replaceAll("~", "~0").replaceAll("/", "~1");
}

/** A concrete path from its tokens. */
export function pointerOf(tokens: readonly string[]): string {
  return tokens.map((token) => `/${escapePointerToken(token)}`).join("");
}
