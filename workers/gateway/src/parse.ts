import { ApiError } from "@gray/errors";
import { type Json, type JsonObject, readSerdeBytes } from "@gray/json";
import {
  type BodyLayout,
  type CanonicalRequest,
  type ClientBody,
  type LayoutListener,
  MEMBER_HELD_BYTES,
  type MemberSpan,
  type Protocol,
  ProtocolError,
  ScrubScan,
  ScrubSpansTooMany,
  type ScrubSpan,
  TooManyMembers,
  conversationFields,
  exactStrings,
  locateMembers,
  memberHeldBytes,
  parseClientBody,
  parseRequest,
  takeModels,
} from "@gray/protocol";
import { Tokenizer, TokenType } from "@streamparser/json";
import type { Body } from "./body.ts";
import { PlainCursor, SpoolBroken } from "./spool.ts";

/**
 * A request body as the gateway reads it, by tier (body.ts). Every tier reads JSON as the Rust
 * gateway does (`from_slice_metered`): the last of several equal keys wins.
 *
 * - A: the whole body (`parseClientBody`). A body whose keys collapsed is sent as serde_json writes
 *   its value, never as the client's bytes (`serializeOverlaid`), so the upstream reads what Gray read.
 * - B and C: the top-level layout, and the top-level members other than the conversation parsed from
 *   their spans. A top-level key given twice keeps its last member; a member whose own keys collapsed
 *   is resent as serde_json writes it (`collapsed`). The conversation is forwarded unread: the hold
 *   bounds its input by the context window, and a route must be able to take media, since the
 *   gateway cannot tell there is none.
 */
export interface ParsedRequest {
  readonly tier: Body["tier"];
  /** Tier A: the whole body. B and C: the members other than the conversation (which reads as empty). */
  readonly value: Json;
  readonly canonical: CanonicalRequest;
  /**
   * Where each top-level member sits in the client's bytes, one member per key; null for a tier A
   * body whose keys collapsed (it is re-serialised, not spliced).
   */
  readonly layout: BodyLayout | null;
  /** Tier A and B: the bytes and the parse `serializeOverlaid` sends. */
  readonly body: ClientBody | null;
  /** Tier B and C: members whose nested keys collapsed, by key, to send as serde_json writes them. */
  readonly collapsed: ReadonlyMap<string, Json>;
  /** The conversation was read (tier A): its media and its input bound are known. */
  readonly whole: boolean;
  /**
   * Tier B and C: the conversation members cut down to the elements that may state a cache breakpoint
   * (`BreakpointScan`), by key: an array of those elements in their order, or the member's whole value when it
   * is an object. What the request can be billed at reads them as it reads a whole body (inference.ts
   * `billed`). Null where they were more than the scan holds, or one did not read: then every cache-write
   * rate may apply. Tier A: empty, the whole value holds them.
   */
  readonly breakpoints: JsonObject | null;
  /**
   * The models the customer accepts, in its order, the requested one first (`models`, @gray/protocol
   * `takeModels`, main #29); empty for a request that listed none, which asks for its `model` alone.
   */
  readonly models: readonly string[];
  /** The body named `models`: the field is left out of every upstream body (first-party APIs refuse unknown fields). */
  readonly strip: boolean;
  /**
   * Tier B and C of a Responses body: the byte spans of its `input` items only a translation reads (`ScrubScan`, the
   * server's `scrub_native` of any size), which a native request does not send. Tier A: empty, the whole value is
   * scrubbed (inference.ts `scrubbed`).
   */
  readonly scrubbed: readonly ScrubSpan[];
}

/**
 * What the request path takes out of the read body before anything else reads it, in the server's order
 * (inference.rs `forward_traced`): the customer's routing preference (`Preference::take`, which removes the
 * `provider` member), before the fallback models and the protocol's own parse. Its refusal refuses the body.
 */
export type TakeFromBody = (value: Json) => ApiError | null;

/**
 * Takes the customer's fallback models out of `value` before it is parsed (model_fallbacks.rs `take`):
 * a body without a `model` asks for the first listed one. 400 `invalid_models` for a list that is not an
 * array of 1 to 4 distinct model ids of at most 512 bytes without control characters.
 */
function withModels(protocol: Protocol, value: Json): { readonly models: readonly string[]; readonly strip: boolean } | ApiError {
  const strip = (protocol === "open_ai_chat" || protocol === "open_ai_responses" || protocol === "anthropic_messages") && value !== null && typeof value === "object" && !Array.isArray(value) && Object.hasOwn(value, "models");
  const models = takeModels(value, protocol);
  if (models === "invalid_models") return new ApiError(400, "invalid_models");
  return { models, strip };
}

export const PROTOCOL_TITLES: Partial<Record<Protocol, string>> = {
  open_ai_chat: "the OpenAI Chat Completions API (/v1/chat/completions)",
  open_ai_responses: "the OpenAI Responses API (/v1/responses)",
  anthropic_messages: "the Anthropic Messages API (/v1/messages)",
  gemini: "the Gemini API (/v1beta/models/...)",
};

/** 400 `invalid_protocol_request` naming what the parser found wrong (a field, a type, a role; never the content). */
export function invalidProtocolRequest(protocol: Protocol, error: ProtocolError): ApiError {
  const detail = error.detail.kind === "invalid_request" ? error.detail.message : error.message;
  return new ApiError(400, "invalid_protocol_request")
    .withMessage(`The request body is not a valid request for ${PROTOCOL_TITLES[protocol] ?? protocol}: ${detail}.`)
    .withHelp("docs");
}

function refusal(protocol: Protocol, error: unknown): ApiError {
  if (error instanceof ProtocolError) {
    if (error.detail.kind === "invalid_request" && error.detail.message === "invalid JSON") return new ApiError(400, "invalid_json");
    return invalidProtocolRequest(protocol, error);
  }
  return new ApiError(400, "invalid_json");
}

/**
 * The layout with one member per key, the last of each: serde_json keeps the last of several equal
 * keys, and the splice then sends only that one.
 */
function lastOfEach(layout: BodyLayout): BodyLayout {
  const last = new Map<string, number>();
  layout.members.forEach((m, i) => last.set(m.key, i));
  if (last.size === layout.members.length) return layout;
  return { open: layout.open, close: layout.close, members: layout.members.filter((m, i) => last.get(m.key) === i) };
}

/**
 * A body of tier A or B, held as bytes. A tier B body's top-level members are held as records while
 * its layout is read, at most `heldMax` bytes of them (`memberHeldBytes`; BODY_PARSE_MAX_BYTES, the most
 * of one document the gateway parses whole): a body naming more is refused with 413 (`membersTooMany`).
 */
export function parseHeld(protocol: Protocol, tier: "A" | "B", bytes: Uint8Array, modelPath: string | null, heldMax: number = Number.MAX_SAFE_INTEGER, take: TakeFromBody | null = null): ParsedRequest | ApiError {
  if (tier === "A") {
    let body: ClientBody;
    try {
      body = parseClientBody(protocol, bytes);
    } catch (error) {
      return refusal(protocol, error);
    }
    const taken = take?.(body.value) ?? null;
    if (taken !== null) return taken;
    const listed = withModels(protocol, body.value);
    if (listed instanceof ApiError) return listed;
    let canonical: CanonicalRequest;
    try {
      canonical = parseRequest(protocol, modelPath, body.value);
    } catch (error) {
      return refusal(protocol, error);
    }
    let layout: BodyLayout | null = null;
    if (!body.duplicateKeys) {
      try {
        layout = locateMembers(bytes);
      } catch {
        return new ApiError(400, "invalid_json");
      }
    }
    return { tier, value: body.value, canonical, layout, body, collapsed: new Map(), whole: true, breakpoints: {}, scrubbed: [], ...listed };
  }
  const scan = BreakpointScan.of(protocol, heldMax);
  const scrub = ScrubScan.of(protocol, heldMax);
  let layout: BodyLayout;
  let scrubbed: ScrubSpan[];
  try {
    layout = lastOfEach(locateMembers(bytes, heldMax, listeners(scan?.listen, scrub?.listen)));
    scrubbed = scrub?.spans(layout) ?? [];
  } catch (error) {
    if (error instanceof TooManyMembers) return membersTooMany(error.limit);
    if (error instanceof ScrubSpansTooMany) return scrubbedTooMany(error.limit);
    return new ApiError(400, "invalid_json");
  }
  const breakpoints = scan === null ? {} : scan.read(layout, (span) => bytes.subarray(span.start, span.end));
  return fromMembers(protocol, tier, layout, (m) => bytes.subarray(m.valueStart, m.valueEnd), modelPath, bytes, take, breakpoints, scrubbed);
}

/** One listener that hands each token to every one given, in order. */
function listeners(...each: (LayoutListener | undefined)[]): LayoutListener | undefined {
  const given = each.filter((l): l is LayoutListener => l !== undefined);
  if (given.length <= 1) return given[0];
  return (token, value, offset) => {
    for (const listen of given) listen(token, value, offset);
  };
}

/** One element of a conversation member (or its whole value) that may state a cache breakpoint, by byte offsets. */
export interface ElementSpan {
  /** The member's key, and where it starts (`MemberSpan.keyStart`): of two equal keys only the last is read. */
  readonly key: string;
  readonly member: number;
  /** The member's value is an array and this is one of its elements; else it is the whole value, an object. */
  readonly element: boolean;
  readonly start: number;
  readonly end: number;
}

/**
 * The keys a cache breakpoint is read from, by protocol (`BilledInput::of`, billed.ts): Anthropic's
 * `cache_control` (`anthropic_cache_controls`), and on Chat and Responses an OpenAI-compatible relay's
 * `cache_control` and OpenAI's own `prompt_cache_breakpoint`. Gemini states none.
 */
function breakpointKeys(protocol: Protocol): readonly string[] {
  switch (protocol) {
    case "anthropic_messages":
      return ["cache_control"];
    case "open_ai_chat":
    case "open_ai_responses":
      return ["cache_control", "prompt_cache_breakpoint"];
    default:
      return [];
  }
}

/**
 * The elements of a body's conversation members (`conversationFields`) that may state a cache breakpoint, found
 * while the layout scan tokenizes a body too large to parse whole (tier B and C): each element of a member that is
 * an array, or a member's whole value when it is an object, that holds a string equal to a key a breakpoint is
 * read from (`breakpointKeys`, as the tokenizer decodes it, so an escaped key counts too). Every other element
 * holds no such key anywhere, so a rule that reads breakpoints (billed.ts `billedInputOf`) reads the same of the
 * conversation cut down to these elements as of the whole one, which the server reads (`BilledInput::of`).
 *
 * Their records and bytes are held up to `heldMax` in all (BODY_PARSE_MAX_BYTES, the most of one document the
 * gateway parses whole), past which none is kept and `read` answers null. A member scalar (a string `system`)
 * holds no breakpoint any rule reads.
 */
export class BreakpointScan {
  readonly spans: ElementSpan[] = [];
  private depth = 0;
  private expectKey = false;
  /** The top-level member being read: its key and offset, whether it is a conversation member, and its value's shape. */
  private member: { key: string; at: number; conversation: boolean; shape: "pending" | "array" | "object" | "done" } | null = null;
  /** The element (or whole object) being read: where it started, and whether it holds a breakpoint key. */
  private start = -1;
  private flagged = false;
  private held = 0;
  private overflow = false;
  private readonly fields: readonly string[];
  private readonly keys: readonly string[];
  private readonly heldMax: number;

  private constructor(fields: readonly string[], keys: readonly string[], heldMax: number) {
    this.fields = fields;
    this.keys = keys;
    this.heldMax = heldMax;
  }

  /** The scan of a `protocol` body, or null where no breakpoint is read (Gemini). */
  static of(protocol: Protocol, heldMax: number): BreakpointScan | null {
    const keys = breakpointKeys(protocol);
    return keys.length === 0 ? null : new BreakpointScan(conversationFields(protocol), keys, heldMax);
  }

  /** The layout scan's listener (`LayoutListener`): every token it reads, in order. */
  readonly listen: LayoutListener = (token, value, offset) => {
    const m = this.member;
    switch (token) {
      case TokenType.LEFT_BRACE:
      case TokenType.LEFT_BRACKET:
        if (this.depth === 0) {
          this.expectKey = true;
        } else if (this.depth === 1 && m !== null && m.conversation) {
          // A member's value opens: an array's elements are read one by one, an object whole.
          m.shape = token === TokenType.LEFT_BRACKET ? "array" : "object";
          if (m.shape === "object") this.begin(offset);
        } else if (this.depth === 2 && m !== null && m.shape === "array" && this.start < 0) {
          this.begin(offset);
        }
        this.depth += 1;
        return;
      case TokenType.RIGHT_BRACE:
      case TokenType.RIGHT_BRACKET:
        this.depth -= 1;
        if (this.depth === 1 && m !== null && m.conversation) {
          if (m.shape === "array" && this.start >= 0) this.end(offset);
          else if (m.shape === "object") this.end(offset + 1);
          m.shape = "done";
        }
        return;
      case TokenType.COMMA:
        if (this.depth === 1) {
          this.member = null;
          this.expectKey = true;
        } else if (this.depth === 2 && m !== null && m.shape === "array" && this.start >= 0) {
          this.end(offset);
        }
        return;
      case TokenType.STRING:
        if (this.depth === 1 && this.expectKey) {
          this.member = { key: value as string, at: offset, conversation: this.fields.includes(value as string), shape: "pending" };
          this.expectKey = false;
          return;
        }
        if (this.depth >= 2 && m !== null && m.conversation && m.shape !== "done") {
          if (this.depth === 2 && m.shape === "array" && this.start < 0) this.begin(offset);
          if (this.keys.includes(value as string)) this.flagged = true;
        }
        return;
      case TokenType.COLON:
        return;
      default:
        // A number, true, false or null: an element of its own at the array's level.
        if (this.depth === 2 && m !== null && m.shape === "array" && this.start < 0) this.begin(offset);
        return;
    }
  };

  private begin(offset: number): void {
    this.start = offset;
    this.flagged = false;
  }

  private end(end: number): void {
    const m = this.member;
    if (this.flagged && m !== null && !this.overflow) {
      this.held += MEMBER_HELD_BYTES + (end - this.start);
      if (this.held > this.heldMax) this.overflow = true;
      else this.spans.push({ key: m.key, member: m.at, element: m.shape === "array", start: this.start, end });
    }
    this.start = -1;
    this.flagged = false;
  }

  /** The flagged elements of the members `layout` keeps (the last of equal keys, `lastOfEach`), in body order. */
  wanted(layout: BodyLayout): ElementSpan[] {
    if (this.overflow) return [];
    const kept = new Set(layout.members.map((m) => m.keyStart));
    return this.spans.filter((span) => kept.has(span.member));
  }

  /**
   * The conversation members of `layout` cut down to their flagged elements (`wanted`), each read as serde_json
   * reads it from `bytesOf`; null past what the scan holds, or for an element that does not read (serde's own
   * limits; the server would have refused the body).
   */
  read(layout: BodyLayout, bytesOf: (span: ElementSpan) => Uint8Array): JsonObject | null {
    if (this.overflow) return null;
    const out: Record<string, Json> = {};
    for (const span of this.wanted(layout)) {
      let value: Json;
      try {
        let bytes = bytesOf(span);
        let end = bytes.length;
        while (end > 0 && isWhitespace(bytes[end - 1])) end -= 1;
        bytes = bytes.subarray(0, end);
        value = readSerdeBytes(bytes).value;
      } catch {
        return null;
      }
      if (!span.element) {
        out[span.key] = value;
        continue;
      }
      const list = out[span.key];
      if (Array.isArray(list)) list.push(value);
      else out[span.key] = [value];
    }
    return out;
  }
}

/**
 * The members other than the conversation, parsed as serde_json reads them, and the canonical
 * projection with an empty conversation. A member is parsed on its own, so its depth counts from the
 * member and not from the body: a member nested exactly 127 levels deep is read here, where the Rust
 * gateway refuses the whole body at 128 (serde_json's limit). Bodies this large never come that close.
 */
function fromMembers(protocol: Protocol, tier: "B" | "C", layout: BodyLayout, span: (m: MemberSpan) => Uint8Array, modelPath: string | null, bytes: Uint8Array | null, take: TakeFromBody | null, breakpoints: JsonObject | null, scrubbed: readonly ScrubSpan[]): ParsedRequest | ApiError {
  const conversation = conversationFields(protocol);
  const value: JsonObject = {};
  const collapsed = new Map<string, Json>();
  for (const m of layout.members) {
    if (conversation.includes(m.key)) continue;
    try {
      const read = readSerdeBytes(span(m));
      value[m.key] = read.value;
      if (read.duplicateKeys) collapsed.set(m.key, read.value);
    } catch (error) {
      return refusal(protocol, error);
    }
  }
  const taken = take?.(value) ?? null;
  if (taken !== null) return taken;
  // A member the take removed is never sent again as serde_json writes it.
  if (!Object.hasOwn(value, "provider")) collapsed.delete("provider");
  const listed = withModels(protocol, value);
  if (listed instanceof ApiError) return listed;
  collapsed.delete("models");
  let canonical: CanonicalRequest;
  try {
    canonical = parseRequest(protocol, modelPath, { ...value, ...emptyConversation(protocol) });
  } catch (error) {
    return refusal(protocol, error);
  }
  const body: ClientBody | null = bytes === null ? null : { bytes, value, duplicateKeys: false };
  return { tier, value, canonical, layout, body, collapsed, whole: false, breakpoints, scrubbed, ...listed };
}

/**
 * The conversation a projection of a body not read whole stands in for its own (`fromMembers`): an empty list in
 * the field each protocol's parser reads it from. A Responses body names its turns in `input` and a Gemini body in
 * `contents`; both are refused without them, so an empty `messages` refused every Responses and Gemini generation
 * body above BODY_PARSE_MAX_BYTES with 400 invalid_protocol_request, where the server parses the whole body.
 */
function emptyConversation(protocol: Protocol): JsonObject {
  switch (protocol) {
    case "open_ai_responses":
      return { input: [] };
    case "gemini":
      return { contents: [] };
    default:
      return { messages: [] };
  }
}

/**
 * A string or number of a tier C body longer than the scan holds (`locateMembersStream`): the body is
 * refused with 413, Gray's own limit (`parseStored`).
 */
export class TokenTooLong extends Error {
  override readonly name = "TokenTooLong";
  readonly limit: number;
  constructor(limit: number) {
    super(`a JSON value of the body is longer than ${limit} bytes`);
    this.limit = limit;
  }
}

/**
 * The layout scan's tokenizer. The scan never reads a number's value, so a number is not parsed
 * (`parseNumber`, the tokenizer's documented override): the partial tokens below would otherwise
 * parse a long number again at every chunk. Its strings are read by @gray/protocol's `exactStrings`
 * builder: the library's own drops a U+FEFF at the start of a decoded piece, and a member key
 * `"\uFEFFmodel"` read as `"model"` would let the layout splice the route's model into the wrong
 * member while the upstream reads the other.
 */
class LayoutTokenizer extends Tokenizer {
  constructor() {
    super({ stringBufferSize: 0, emitPartialTokens: true });
    exactStrings(this);
  }

  protected override parseNumber(): number {
    return 0;
  }
}

/** The most the layout scan hands its tokenizer at once (the chunk workerd's own body streams deliver, upstream.ts UPSTREAM_BODY_CHUNK_BYTES). */
export const LAYOUT_WRITE_BYTES = 4096;

/**
 * The layout of a body too large to hold (tier C), read from its stored object with the same
 * tokenizer `locateMembers` uses, fed chunk by chunk. The tokenizer assembles each string (and each
 * number) whole before it hands it over, so the longest one is what the scan holds at once: a base64
 * image of tens of MB, or one string as long as the API's own limit (512 MiB for OpenAI). That is
 * bounded: the tokenizer reports the value it is in the middle of at the end of every write of at most
 * LAYOUT_WRITE_BYTES (`emitPartialTokens`), and a value longer than `tokenMax` bytes ends the scan with `TokenTooLong`
 * before more of it is held. `parseStored` sets `tokenMax` to BODY_RAW_MAX_BYTES, the most of one
 * body the gateway holds anyway (tier B). Its members are held as records until the scan ends, at most
 * `heldMax` bytes of them (`memberHeldBytes`): past that none is kept, and the scan ends with
 * `TooManyMembers` once the chunk is read.
 */
export async function locateMembersStream(stream: ReadableStream<Uint8Array>, tokenMax: number = Number.MAX_SAFE_INTEGER, heldMax: number = Number.MAX_SAFE_INTEGER, listen?: LayoutListener): Promise<BodyLayout> {
  let depth = 0;
  let open = -1;
  let close = -1;
  const members: MemberSpan[] = [];
  let key: { key: string; start: number } | undefined;
  let colon = -1;
  // Whitespace around a value is trimmed from its span later, by reading the value's own bytes:
  // here the span runs from after the colon to the separator.
  const pending: { key: string; keyStart: number; from: number; to: number }[] = [];
  let held = 0;
  const finish = (separator: number) => {
    if (key === undefined || colon < 0) throw new Error("body layout: member without key or colon");
    held += memberHeldBytes(key.key);
    if (held <= heldMax) pending.push({ key: key.key, keyStart: key.start, from: colon + 1, to: separator });
    key = undefined;
    colon = -1;
  };
  const tokenizer = new LayoutTokenizer();
  /** Bytes handed to the tokenizer so far: a value in progress spans from its offset to here. */
  let written = 0;
  // Noted here and thrown after `write` returns: the tokenizer swallows what its partial number
  // tokens' callback throws.
  let tooLong = false;
  tokenizer.onToken = ({ token, value, offset, partial }) => {
    if (partial === true) {
      if ((token === TokenType.STRING || token === TokenType.NUMBER) && written - offset > tokenMax) tooLong = true;
      return;
    }
    listen?.(token, value, offset);
    switch (token) {
      case TokenType.LEFT_BRACE:
      case TokenType.LEFT_BRACKET:
        if (depth === 0) {
          if (token !== TokenType.LEFT_BRACE) throw new Error("body layout: not an object");
          open = offset;
        }
        depth += 1;
        return;
      case TokenType.RIGHT_BRACE:
      case TokenType.RIGHT_BRACKET:
        depth -= 1;
        if (depth === 0) {
          if (key !== undefined) finish(offset);
          close = offset;
        }
        return;
      case TokenType.COMMA:
        if (depth === 1) finish(offset);
        return;
      case TokenType.COLON:
        if (depth === 1) colon = offset;
        return;
      case TokenType.STRING:
        if (depth === 1 && key === undefined) key = { key: value as string, start: offset };
        return;
      default:
        return;
    }
  };
  tokenizer.onError = (error) => {
    throw error;
  };
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      // At most LAYOUT_WRITE_BYTES a write: a value longer than tokenMax is then always seen in progress
      // (a partial token) before it is held whole, whatever size the chunks come in (a decrypted spool's
      // are 64 KiB).
      for (let at = 0; at < value.length; at += LAYOUT_WRITE_BYTES) {
        const slice = value.subarray(at, Math.min(value.length, at + LAYOUT_WRITE_BYTES));
        written += slice.length;
        tokenizer.write(slice);
        if (tooLong) throw new TokenTooLong(tokenMax);
        if (held > heldMax) throw new TooManyMembers(heldMax);
      }
    }
  } catch (error) {
    reader.cancel().catch(() => {});
    throw error;
  }
  if (open < 0 || close < 0) throw new Error("body layout: not a complete object");
  for (const p of pending) members.push({ key: p.key, keyStart: p.keyStart, valueStart: p.from, valueEnd: p.to });
  return { open, close, members };
}

/**
 * 413 for a tier C body with a value longer than the gateway holds of one (Gray's limit, not the
 * API's): the server reads a body within its memory budget and answers a body it cannot hold the
 * same way, `request_body_limit` with `limit_source` `gateway_memory` (inference.rs `memory_refusal`).
 */
export function valueTooLong(limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage(
      `One string or number in this request body is longer than ${limit} bytes, the most of one value Gray holds while it reads a body this large. Send a file this large by URL or through the provider's file API, or split it.`,
    )
    .withMeta("limit_bytes", BigInt(limit))
    .withMeta("limit_source", "gateway_memory");
}

/**
 * 413 for a Responses body too large to parse whole that names more reasoning items only a translation reads than
 * Gray holds the places of while it reads the body (`ScrubSpansTooMany`): Gray's limit, as for too many top-level
 * fields (`membersTooMany`); the server parses such a body under its memory budget (`memory_refusal`).
 */
export function scrubbedTooMany(limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage(
      `This request body's input carries so many reasoning items from earlier translated turns that Gray would hold more than ${limit} bytes of their places while it reads a body this large. Send fewer of them.`,
    )
    .withMeta("limit_bytes", BigInt(limit))
    .withMeta("limit_source", "gateway_memory");
}

/**
 * 413 for a body too large to parse whole whose top-level members take more than `limit` bytes to hold
 * while its layout is read (`TooManyMembers`): Gray's limit, as for one value too long (`valueTooLong`).
 * The server parses such a body under its memory budget and refuses it the same way once the parse
 * needs more than the budget grants (`from_slice_metered`, inference.rs `memory_refusal`).
 */
export function membersTooMany(limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage(
      `This request body has so many top-level fields that Gray would hold more than ${limit} bytes of their names and places while it reads a body this large. Send fewer fields.`,
    )
    .withMeta("limit_bytes", BigInt(limit))
    .withMeta("limit_source", "gateway_memory");
}

/** JSON whitespace (RFC 8259): what may sit between a colon or comma and a value. */
function isWhitespace(b: number | undefined): boolean {
  return b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;
}

/** A member span with the whitespace around its value removed, given the value's bytes. */
function trimmed(m: MemberSpan, bytes: Uint8Array): { member: MemberSpan; bytes: Uint8Array } {
  let start = 0;
  let end = bytes.length;
  while (start < end && isWhitespace(bytes[start])) start++;
  while (end > start && isWhitespace(bytes[end - 1])) end--;
  return { member: { ...m, valueStart: m.valueStart + start, valueEnd: m.valueStart + end }, bytes: bytes.subarray(start, end) };
}

/**
 * A tier C body: its layout from the stored object, read through once from its start (`open`: spool.ts
 * `spoolPlaintext`, decrypted as it is read; no value longer than `tokenMax` bytes, see
 * `locateMembersStream`), then the members other than the conversation, at most `smallMax` bytes in all,
 * read in order on a second pass from the start (a sealed spool reads only from its start). A spool that is
 * gone, cut short or not what was stored is 503 `request_body_store_unavailable`, never the client's error.
 */
export async function parseStored(
  protocol: Protocol,
  open: () => Promise<ReadableStream<Uint8Array> | null>,
  smallMax: number,
  modelPath: string | null,
  tokenMax: number = Number.MAX_SAFE_INTEGER,
  take: TakeFromBody | null = null,
): Promise<ParsedRequest | ApiError> {
  const unavailable = () => new ApiError(503, "request_body_store_unavailable");
  let layout: BodyLayout;
  const scan = BreakpointScan.of(protocol, smallMax);
  const scrub = ScrubScan.of(protocol, smallMax);
  let scrubbed: ScrubSpan[];
  try {
    const plain = await open();
    if (plain === null) return unavailable();
    // Its members held as records within what a document parsed whole may take (`smallMax`), the conversation's
    // elements that may state a cache breakpoint within as much again (`BreakpointScan`), and the places of the
    // reasoning items only a translation reads within as much again (`ScrubScan`).
    layout = lastOfEach(await locateMembersStream(plain, tokenMax, smallMax, listeners(scan?.listen, scrub?.listen)));
    scrubbed = scrub?.spans(layout) ?? [];
  } catch (error) {
    if (error instanceof TokenTooLong) return valueTooLong(error.limit);
    if (error instanceof TooManyMembers) return membersTooMany(error.limit);
    if (error instanceof ScrubSpansTooMany) return scrubbedTooMany(error.limit);
    if (error instanceof SpoolBroken) return unavailable();
    return new ApiError(400, "invalid_json");
  }
  const conversation = conversationFields(protocol);
  let total = 0;
  for (const m of layout.members) {
    if (conversation.includes(m.key)) continue;
    total += m.valueEnd - m.valueStart;
    if (total > smallMax) {
      return new ApiError(413, "request_body_limit").withMessage(
        `The fields of this request other than its conversation are larger than ${smallMax} bytes, which Gray reads of a request this large.`,
      );
    }
  }
  // The members other than the conversation, and the conversation's elements that may state a cache breakpoint
  // (which lie inside conversation members, never inside another member), read in the body's order: the cursor
  // only moves forward.
  const wanted = scan?.wanted(layout) ?? [];
  const reads: ({ readonly member: MemberSpan } | { readonly span: ElementSpan })[] = [
    ...layout.members.filter((m) => !conversation.includes(m.key)).map((member) => ({ member })),
    ...wanted.map((span) => ({ span })),
  ];
  const startOf = (r: (typeof reads)[number]) => ("member" in r ? r.member.valueStart : r.span.start);
  reads.sort((a, b) => startOf(a) - startOf(b));
  const read = new Map<string, Uint8Array>();
  const trimmedOf = new Map<string, MemberSpan>();
  const spanBytes = new Map<ElementSpan, Uint8Array>();
  let cursor: PlainCursor | null = null;
  try {
    for (const r of reads) {
      if (cursor === null) {
        const again = await open();
        if (again === null) return unavailable();
        cursor = new PlainCursor(again);
      }
      if ("span" in r) {
        await cursor.skipTo(r.span.start);
        spanBytes.set(r.span, await cursor.take(r.span.end - r.span.start));
        continue;
      }
      const m = r.member;
      await cursor.skipTo(m.valueStart);
      const t = trimmed(m, await cursor.take(m.valueEnd - m.valueStart));
      trimmedOf.set(m.key, t.member);
      read.set(t.member.key, t.bytes);
    }
  } catch (error) {
    if (error instanceof SpoolBroken) return unavailable();
    throw error;
  } finally {
    await cursor?.cancel();
  }
  // Conversation members keep their untrimmed spans: they are copied, never parsed or replaced.
  const members = layout.members.map((m) => trimmedOf.get(m.key) ?? m);
  const exact: BodyLayout = { open: layout.open, close: layout.close, members };
  const breakpoints = scan === null ? {} : scan.read(layout, (span) => spanBytes.get(span) ?? new Uint8Array(0));
  return fromMembers(protocol, "C", exact, (m) => read.get(m.key) ?? new Uint8Array(0), modelPath, null, take, breakpoints, scrubbed);
}
