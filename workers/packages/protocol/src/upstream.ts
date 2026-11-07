/**
 * The upstream body of an attempt: the client's bytes with a few top-level fields replaced,
 * removed or added (crates/gray-gateway/src/upstream.rs `Overlay`, and `cap_overlay` and
 * `attempt_overlay` in inference.rs): the upstream model, the output cap, the usage option of a
 * Chat stream, and the end-user identifiers left out.
 *
 * Unlike the Rust gateway, which writes its own serialisation of the parse with the overlay merged
 * in (`serialize_overlaid`, keys sorted), the bytes are spliced (docs/cloudflare-native.md 2.3
 * rule 7 and 6.2): every member the overlay does not touch is sent as the client wrote it, so a
 * large integer, a number's spelling or a key order is never changed. The member positions come
 * from @streamparser/json's tokenizer (the streaming JSON library the plan names), run over a body
 * that @gray/json has already parsed and validated; the parse decides what the body means, the
 * tokenizer only where its top-level members are. The upstream reads the same JSON value Rust
 * would send, written differently.
 *
 * The one exception is a body in which two equal keys of one object collapsed into the last
 * (`ClientBody.duplicateKeys`): its bytes say more than the parse Gray inspected, so it is written
 * as Rust writes every body, serde_json's serialisation of the parse with the overlay applied,
 * byte for byte (json fixtures `client-body-*`).
 */
import { Tokenizer, TokenType } from "@streamparser/json";
import { type Json, type JsonObject, cloneJson, get, isObject, setMember, toJsonString } from "@gray/json";
import type { Protocol } from "./types.ts";
import { type ClientBody, geminiKey, geminiObjectMut } from "./request.ts";
import { exactStrings } from "./answer-scan.ts";

/** One top-level member of an object body, by byte offsets into the body. */
export interface MemberSpan {
  readonly key: string;
  /** The key's opening quote. */
  readonly keyStart: number;
  /** The first byte of the value, after the colon and any whitespace. */
  readonly valueStart: number;
  /** One past the value's last byte (whitespace before the next comma excluded). */
  readonly valueEnd: number;
}

/** Where an object body's braces and top-level members are. */
export interface BodyLayout {
  readonly open: number;
  readonly close: number;
  readonly members: readonly MemberSpan[];
}

function isWhitespace(b: number | undefined): boolean {
  return b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;
}

/**
 * What a layout scan holds of one top-level member besides its key's characters: the member's record,
 * in a list or a map. Measured in V8 (Node 26.10, 2026-10-19): about 90 bytes a member in a list and
 * 125 in a map keyed by its name, a short key included. A body is only bytes, and `{"a":0,"b":0,...}`
 * names a member every six of them: 1.5 million members of 17.5 MiB held as records took 300-460 MiB
 * of an isolate's 128 MB.
 */
export const MEMBER_HELD_BYTES = 128;

/** What a layout scan holds of one member: its record and its key's characters (UTF-16, two bytes each at most). */
export function memberHeldBytes(key: string): number {
  return MEMBER_HELD_BYTES + 2 * key.length;
}

/**
 * A body with more top-level members than a layout scan holds (`heldMax` bytes of them, counted by
 * `memberHeldBytes`): the scan stops keeping them at that point and this is thrown once the bytes
 * handed to it are read.
 */
export class TooManyMembers extends Error {
  override readonly name = "TooManyMembers";
  readonly limit: number;
  constructor(limit: number) {
    super(`the top-level members of the body take more than ${limit} bytes to hold`);
    this.limit = limit;
  }
}

/** Hears every token a layout scan reads, in order, before the scan acts on it (`locateMembers`'s `listen`). */
export type LayoutListener = (token: TokenType, value: unknown, offset: number) => void;

/**
 * The layout of `bytes`, a JSON object `parseClientBody` read without duplicate keys (so it is
 * valid, and each top-level key appears once), or a body too large to parse whole. Throws if the
 * tokenizer disagrees, and `TooManyMembers` when its members take more than `heldMax` bytes to hold
 * (`memberHeldBytes`, every member counted, a repeated key too). `listen` hears each token the scan
 * reads, so a caller learns more of a body too large to parse whole in the same pass.
 */
export function locateMembers(bytes: Uint8Array, heldMax: number = Number.MAX_SAFE_INTEGER, listen?: LayoutListener): BodyLayout {
  let depth = 0;
  let open = -1;
  let close = -1;
  const members: MemberSpan[] = [];
  let key: { key: string; start: number } | undefined;
  let colon = -1;
  let held = 0;
  const finish = (separator: number) => {
    if (key === undefined || colon < 0) throw new Error("body layout: member without key or colon");
    let start = colon + 1;
    while (start < separator && isWhitespace(bytes[start])) start += 1;
    let end = separator;
    while (end > start && isWhitespace(bytes[end - 1])) end -= 1;
    held += memberHeldBytes(key.key);
    // Past the bound no member is kept; the scan reads on only to throw after `write`.
    if (held <= heldMax) members.push({ key: key.key, keyStart: key.start, valueStart: start, valueEnd: end });
    key = undefined;
    colon = -1;
  };
  // Every string read whole and exactly (`exactStrings`): the library's own builder drops a U+FEFF at the start of a
  // string, which would read a key `"\uFEFFinput"` as `"input"`, and a listener's values likewise.
  const tokenizer = new Tokenizer({ stringBufferSize: 0 });
  exactStrings(tokenizer);
  tokenizer.onToken = ({ token, value, offset }) => {
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
  tokenizer.write(bytes);
  if (held > heldMax) throw new TooManyMembers(heldMax);
  if (open < 0 || close < 0) throw new Error("body layout: not a complete object");
  return { open, close, members };
}

/**
 * `Overlay`: top-level fields a body is sent with in place of its own. `set` adds or replaces a
 * field, `remove` leaves it out; a later call for the same key replaces an earlier one.
 */
export class Overlay {
  private readonly entries = new Map<string, Json | undefined>();

  set(key: string, value: Json): void {
    this.entries.set(key, value);
  }

  remove(key: string): void {
    this.entries.set(key, undefined);
  }

  /** The field `key` as `body` is sent with this overlay. */
  field(body: Json, key: string): Json | undefined {
    return this.entries.has(key) ? this.entries.get(key) : get(body, key);
  }

  /** The edits, by key: a value to send, or undefined to leave the field out. */
  edits(): ReadonlyMap<string, Json | undefined> {
    return this.entries;
  }

  clone(): Overlay {
    const copy = new Overlay();
    for (const [key, value] of this.entries) copy.entries.set(key, value);
    return copy;
  }

  /** `body` as one value with the overlay applied (what Rust serialises and sends). */
  apply(body: Json): Json {
    if (!isObject(body)) return body;
    const whole = cloneJson(body) as JsonObject;
    for (const [key, value] of this.entries) {
      if (value === undefined) delete whole[key];
      else setMember(whole, key, value);
    }
    return whole;
  }

  /**
   * `without_end_user_ids`: this overlay without the caller-supplied end-user identifiers of
   * `body`: OpenAI's `user`, `safety_identifier` and `metadata`, Anthropic's `metadata.user_id`.
   * They are stable across sessions and let a provider link one person's requests; the provider's
   * customer is Gray, not the end user. `prompt_cache_key`, `store` and continuation references
   * stay.
   */
  withoutEndUserIds(protocol: Protocol, body: Json): Overlay {
    if (protocol === "anthropic_messages") {
      const metadata = this.field(body, "metadata");
      if (isObject(metadata) && Object.hasOwn(metadata, "user_id")) {
        const kept = cloneJson(metadata) as JsonObject;
        delete kept.user_id;
        if (Object.keys(kept).length === 0) this.remove("metadata");
        else this.set("metadata", kept);
      }
    } else if (openAiFamily(protocol)) {
      for (const field of OPENAI_LINKING_FIELDS) {
        if (this.field(body, field) !== undefined) this.remove(field);
      }
    }
    return this;
  }
}

/** Caller-supplied identifiers OpenAI attaches to the provider account's records. */
export const OPENAI_LINKING_FIELDS: readonly string[] = ["user", "safety_identifier", "metadata"];

/** OpenAI-shaped JSON APIs that accept OpenAI's end-user tagging fields. */
export function openAiFamily(protocol: Protocol): boolean {
  switch (protocol) {
    case "open_ai_chat":
    case "open_ai_responses":
    case "open_ai_embeddings":
    case "open_ai_image_generations":
    case "open_ai_image_edits":
    case "open_ai_speech":
    case "open_ai_transcriptions":
    case "open_ai_translations":
    case "open_ai_videos":
      return true;
    default:
      return false;
  }
}

const encoder = new TextEncoder();

/**
 * `serialize_overlaid`: the bytes of `body` sent with `overlay`. The JSON value sent is the overlay
 * applied to the body's parse.
 *
 * - A body without duplicate keys is spliced: each top-level member the overlay does not name
 *   copied as the client wrote it, a replaced member written with its new value (serde_json's
 *   form), a removed member left out, and each new member added before the closing brace. Without
 *   edits it is the client's bytes. `layout` is `locateMembers(body.bytes)`, which a request
 *   computes once for all its attempts; it is computed here when not given.
 * - A body whose equal keys collapsed is written as serde_json writes the parse with the overlay
 *   applied, which is what the Rust gateway sends (`layout` is not used): the client's bytes,
 *   which an upstream could read differently, are never sent.
 */
export function serializeOverlaid(body: ClientBody, overlay: Overlay, layout?: BodyLayout): Uint8Array {
  if (body.duplicateKeys) return encoder.encode(toJsonString(overlay.apply(body.value)));
  const edits = overlay.edits();
  if (edits.size === 0) return body.bytes;
  const spans = layout ?? locateMembers(body.bytes);
  const bytes = body.bytes;
  const segments: Uint8Array[] = [];
  const seen = new Set<string>();
  for (const member of spans.members) {
    seen.add(member.key);
    if (!edits.has(member.key)) {
      segments.push(bytes.subarray(member.keyStart, member.valueEnd));
      continue;
    }
    const value = edits.get(member.key);
    if (value === undefined) continue;
    const head = bytes.subarray(member.keyStart, member.valueStart);
    const replaced = encoder.encode(toJsonString(value));
    const joined = new Uint8Array(head.length + replaced.length);
    joined.set(head, 0);
    joined.set(replaced, head.length);
    segments.push(joined);
  }
  for (const [key, value] of edits) {
    if (value === undefined || seen.has(key)) continue;
    segments.push(encoder.encode(`${JSON.stringify(key)}:${toJsonString(value)}`));
  }
  const prefix = bytes.subarray(0, spans.open + 1);
  const suffix = bytes.subarray(spans.close);
  let length = prefix.length + suffix.length + Math.max(segments.length - 1, 0);
  for (const s of segments) length += s.length;
  const out = new Uint8Array(length);
  let at = 0;
  out.set(prefix, at);
  at += prefix.length;
  segments.forEach((s, i) => {
    if (i > 0) out[at++] = 0x2c;
    out.set(s, at);
    at += s.length;
  });
  out.set(suffix, at);
  return out;
}

/**
 * `cap_overlay`: writes the output cap Gray chose into `overlay`, under the field the body uses:
 * Chat's `max_completion_tokens` when the client sent that, else `max_tokens`; inside Gemini's
 * `generationConfig` under the client's spelling, so the upstream never sees both spellings.
 * Returns the error code of a config that cannot hold it.
 */
export function capOverlay(protocol: Protocol, body: Json, cap: number, overlay: Overlay): "invalid_generation_config" | undefined {
  switch (protocol) {
    case "open_ai_chat":
      overlay.set(get(body, "max_completion_tokens") !== undefined ? "max_completion_tokens" : "max_tokens", BigInt(cap));
      return undefined;
    case "open_ai_responses":
      overlay.set("max_output_tokens", BigInt(cap));
      return undefined;
    case "anthropic_messages":
      overlay.set("max_tokens", BigInt(cap));
      return undefined;
    case "gemini": {
      // The cap joins the config under the spelling the client used, one started when it sent none
      // or null (`gemini_object_mut`, 4525f20f), so the upstream never sees generation_config beside
      // a second generationConfig. The client's parse is not touched: the config is a copy.
      const key = geminiKey(body, "generationConfig");
      if (key.error !== undefined) return "invalid_generation_config";
      const holder: JsonObject = {};
      const existing = get(body, key.key as string);
      if (existing !== undefined) setMember(holder, key.key as string, cloneJson(existing));
      const config = geminiObjectMut(holder, "generationConfig");
      if (config.error !== undefined) return "invalid_generation_config";
      const field = geminiKey(config.object as JsonObject, "maxOutputTokens");
      if (field.error !== undefined) return "invalid_generation_config";
      setMember(config.object as JsonObject, field.key as string, BigInt(cap));
      overlay.set(key.key as string, config.object as JsonObject);
      return undefined;
    }
    default:
      throw new Error("cap_overlay: generation protocols only");
  }
}

/**
 * `attempt_overlay`: what one attempt sends besides the request's own overlay: the route's
 * upstream model (Gemini names it in the URL), and for a Chat stream the option that asks for its
 * final usage (`stream_options.include_usage`).
 */
export function attemptOverlay(
  protocol: Protocol,
  stream: boolean,
  body: Json,
  base: Overlay,
  upstreamModel: string,
): Overlay | "invalid_stream_options" {
  const overlay = base.clone();
  if (protocol !== "gemini") overlay.set("model", upstreamModel);
  if (protocol === "open_ai_chat" && stream) {
    const current = overlay.field(body, "stream_options");
    const options = current === undefined ? {} : cloneJson(current);
    if (!isObject(options)) return "invalid_stream_options";
    setMember(options, "include_usage", true);
    overlay.set("stream_options", options);
  }
  return overlay;
}
