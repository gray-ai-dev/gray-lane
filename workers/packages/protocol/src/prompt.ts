/**
 * A prompt as its upstream caches and bills it: the units it is made of, in prompt order, each
 * without the cache markers that do not change what is cached or billed
 * (crates/gray-protocol/src/prompt.rs). The input bound a request is held for counts and hashes
 * these units (src/reservation.ts).
 */
import { sha256 } from "@noble/hashes/sha2";
import { type Json, type JsonObject, asStr, compareUtf8, get, isArray, isObject, toJsonString } from "@gray/json";
import type { Protocol } from "./types.ts";
import { type Counting, type UnitMedia, scan, scanFields } from "./images.ts";
import { anthropicBlockBreakpoint, geminiField } from "./request.ts";

/** A unit as the body holds it (never a copy of it). */
type Unit =
  | { readonly kind: "value"; readonly value: Json }
  /** A string where its protocol takes blocks: one text block `{"type": kind, "text": text}`. */
  | { readonly kind: "text"; readonly type: string; readonly text: string }
  /** An OpenAI Chat message's fields other than its `content`. */
  | { readonly kind: "message_fields"; readonly fields: JsonObject }
  /** A Responses string `input`: `{"type": "message", "role": "user", "content": text}`. */
  | { readonly kind: "user_message"; readonly text: string };

/** A prompt unit's serialisation: its length in bytes (which bounds its tokens) and its SHA-256. */
export interface UnitDigest {
  readonly len: number;
  readonly sha256: Uint8Array;
}

/** Which cache markers a value is written without (`Markers` in prompt.rs). */
type Markers = "kept" | "anthropic" | "anthropic_source" | "openai" | "openai_function";

function markersOf(protocol: Protocol): Markers {
  switch (protocol) {
    case "anthropic_messages":
      return "anthropic";
    case "open_ai_chat":
    case "open_ai_responses":
      return "openai";
    default:
      return "kept";
  }
}

function drops(markers: Markers, key: string): boolean {
  switch (markers) {
    case "anthropic":
    case "openai_function":
      return key === "cache_control";
    case "openai":
      return key === "cache_control" || key === "prompt_cache_breakpoint";
    default:
      return false;
  }
}

function within(markers: Markers, key: string): Markers {
  if ((markers === "anthropic" || markers === "anthropic_source") && key === "content") return "anthropic";
  if (markers === "anthropic" && key === "source") return "anthropic_source";
  if (markers === "openai" && (key === "content" || key === "output")) return "openai";
  if (markers === "openai" && key === "function") return "openai_function";
  return "kept";
}

function item(markers: Markers): Markers {
  return markers === "anthropic" || markers === "openai" ? markers : "kept";
}

/**
 * `write_unit`: compact JSON with every object's keys in order (UTF-8 byte order), without the
 * cache markers of `markers`: `serde_json::to_vec(&canonical(&unmarked(..)))`.
 */
function writeUnit(out: string[], value: Json, markers: Markers): void {
  if (isObject(value)) {
    writeObject(out, value, markers, []);
  } else if (isArray(value)) {
    out.push("[");
    value.forEach((v, i) => {
      if (i > 0) out.push(",");
      writeUnit(out, v, item(markers));
    });
    out.push("]");
  } else {
    out.push(toJsonString(value));
  }
}

function writeObject(out: string[], map: JsonObject, markers: Markers, skip: readonly string[]): void {
  const keys = Object.keys(map)
    .filter((key) => !drops(markers, key) && !skip.includes(key))
    .sort(compareUtf8);
  out.push("{");
  keys.forEach((key, i) => {
    if (i > 0) out.push(",");
    out.push(JSON.stringify(key), ":");
    writeUnit(out, map[key] as Json, within(markers, key));
  });
  out.push("}");
}

const encoder = new TextEncoder();

/** One unit of a prompt, in the order the upstream reads the prompt. */
export class PromptBlock {
  /** Where the unit sits: its hash covers this and the unit without its cache markers. */
  readonly place: Json;
  private readonly unit: Unit;
  /** Anthropic: the block is marked as a cache breakpoint (`anthropicBlockBreakpoint`). */
  readonly breakpoint: boolean;
  /** Anthropic: `tool_use` or `tool_result`; a run of either kind is one lookback position. */
  readonly run: string | undefined;
  private readonly protocol: Protocol;

  constructor(protocol: Protocol, place: Json, unit: Unit) {
    this.protocol = protocol;
    this.place = place;
    this.unit = unit;
    if (unit.kind === "value" && protocol === "anthropic_messages") {
      this.breakpoint = anthropicBlockBreakpoint(unit.value);
      const kind = asStr(get(unit.value, "type"));
      this.run = kind === "tool_use" || kind === "tool_result" ? kind : undefined;
    } else {
      this.breakpoint = false;
      this.run = undefined;
    }
  }

  /** The unit when the body holds it as one value. */
  value(): Json | undefined {
    return this.unit.kind === "value" ? this.unit.value : undefined;
  }

  /** What the unit holds besides text (`image_tokens::scan`). */
  media(counting: Counting): UnitMedia {
    switch (this.unit.kind) {
      case "value":
        return scan(this.unit.value, counting);
      case "message_fields":
        return scanFields(this.unit.fields, counting, "content");
      default:
        return scan(null, counting);
    }
  }

  /** Whether automatic caching may place its breakpoint here (not thinking, not empty text). */
  eligible(): boolean {
    let kind: string | undefined;
    let text: string | undefined;
    switch (this.unit.kind) {
      case "value":
        if (isObject(this.unit.value)) {
          kind = asStr(get(this.unit.value, "type"));
          text = asStr(get(this.unit.value, "text"));
        }
        break;
      case "text":
        kind = this.unit.type;
        text = this.unit.text;
        break;
      case "message_fields":
        kind = asStr(get(this.unit.fields, "type"));
        text = asStr(get(this.unit.fields, "text"));
        break;
      case "user_message":
        kind = "message";
        break;
    }
    return kind !== "thinking" && kind !== "redacted_thinking" && !(kind === "text" && text === "");
  }

  /** The bytes the unit is hashed and counted as: `[place, unit]`, compact, keys in order. */
  serialized(): Uint8Array {
    const out: string[] = ["["];
    writeUnit(out, this.place, "kept");
    out.push(",");
    const markers = markersOf(this.protocol);
    switch (this.unit.kind) {
      case "value":
        writeUnit(out, this.unit.value, markers);
        break;
      case "text":
        out.push('{"text":', JSON.stringify(this.unit.text), ',"type":', JSON.stringify(this.unit.type), "}");
        break;
      case "message_fields":
        writeObject(out, this.unit.fields, markers, ["content"]);
        break;
      case "user_message":
        out.push('{"content":', JSON.stringify(this.unit.text), ',"role":"user","type":"message"}');
        break;
    }
    out.push("]");
    return encoder.encode(out.join(""));
  }

  digest(): UnitDigest {
    const bytes = this.serialized();
    return { len: bytes.length, sha256: sha256(bytes) };
  }
}

/**
 * `hash_setting`: a request setting as the request's shape hashes it: the length of
 * `[key, value]` (compact, keys in order, without `skip` fields of an object value) as 8 bytes,
 * then those bytes.
 */
export function hashSetting(shape: ReturnType<typeof sha256.create>, key: string, value: Json, skip: readonly string[]): void {
  const out: string[] = ["[", JSON.stringify(key), ","];
  if (isObject(value)) writeObject(out, value, "kept", skip);
  else writeUnit(out, value, "kept");
  out.push("]");
  const bytes = encoder.encode(out.join(""));
  shape.update(u64le(bytes.length));
  shape.update(bytes);
}

/** `setting_len`: the length of `[key, value]` as compact JSON. */
export function settingLen(key: string, value: Json): number {
  return encoder.encode(`[${JSON.stringify(key)},${toJsonString(value)}]`).length;
}

/** A u64 as 8 little-endian bytes (Rust's `to_le_bytes`). */
export function u64le(value: number | bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
}

/** `unit_fields`: the fields of a request body that hold its prompt units. */
export function unitFields(protocol: Protocol): readonly string[] {
  switch (protocol) {
    case "anthropic_messages":
      return ["tools", "system", "messages"];
    case "open_ai_chat":
      return ["tools", "messages"];
    case "open_ai_responses":
      return ["instructions", "tools", "input"];
    case "gemini":
      return ["systemInstruction", "system_instruction", "tools", "contents"];
    default:
      return [];
  }
}

/** How many positions Anthropic's cache lookup checks per breakpoint (platform.claude.com, Prompt caching). */
export const ANTHROPIC_LOOKBACK_POSITIONS = 20;
/** How many blocks Anthropic lets a request mark as breakpoints ("up to 4 cache breakpoints"). */
export const ANTHROPIC_MAX_BREAKPOINTS = 4;

export interface AnthropicCache {
  /** The blocks a cache entry is written at. */
  readonly writes: number[];
  /** For each block up to the last write, whether a lookup reads the entry ending there. */
  readonly reads: boolean[];
}

/**
 * `anthropic_cache`: where an Anthropic request writes its cache and what a lookup reads, by
 * Anthropic's automatic prefix checking. Undefined when it writes nothing (no breakpoint, or more
 * than Anthropic takes).
 */
export function anthropicCache(blocks: readonly PromptBlock[], body: Json): AnthropicCache | undefined {
  const writes: number[] = [];
  blocks.forEach((block, index) => {
    if (block.breakpoint) writes.push(index);
  });
  if (writes.length > ANTHROPIC_MAX_BREAKPOINTS) return undefined;
  const automatic = get(body, "cache_control");
  if (automatic !== undefined && automatic !== null) {
    for (let index = blocks.length - 1; index >= 0; index -= 1) {
      if ((blocks[index] as PromptBlock).eligible()) {
        writes.push(index);
        break;
      }
    }
  }
  if (writes.length === 0) return undefined;
  const last = Math.max(...writes);
  const reads = new Array<boolean>(last + 1).fill(false);
  for (const breakpoint of writes) {
    let index = breakpoint;
    let positions = 1;
    for (;;) {
      reads[index] = true;
      if (index === 0) break;
      const run = (blocks[index] as PromptBlock).run;
      if (run === undefined || (blocks[index - 1] as PromptBlock).run !== run) {
        positions += 1;
        if (positions > ANTHROPIC_LOOKBACK_POSITIONS) break;
      }
      index -= 1;
    }
  }
  return { writes, reads };
}

/**
 * `prompt_blocks`: a prompt of `protocol` as its upstream reads it, unit by unit:
 * - Anthropic: each tool, each system block, each content block of each message;
 * - OpenAI Chat: each tool; each message's fields other than `content`, then each content part;
 * - OpenAI Responses: the instructions, each tool, each input item;
 * - Gemini: each part of the system instruction, each tool, each part of each content.
 */
export function promptBlocks(protocol: Protocol, body: Json): PromptBlock[] {
  const blocks: PromptBlock[] = [];
  const push = (place: Json, content: Json | undefined, type: string) => {
    if (content === undefined || content === null) return;
    if (typeof content === "string") blocks.push(new PromptBlock(protocol, place, { kind: "text", type, text: content }));
    else if (isArray(content)) for (const block of content) blocks.push(new PromptBlock(protocol, place, { kind: "value", value: block }));
    else blocks.push(new PromptBlock(protocol, place, { kind: "value", value: content }));
  };
  const items = (field: string): Json[] => {
    const value = get(body, field);
    return isArray(value) ? value : [];
  };
  const role = (message: Json): Json => get(message, "role") ?? null;
  switch (protocol) {
    case "anthropic_messages":
      push("tools", get(body, "tools"), "text");
      push("system", get(body, "system"), "text");
      items("messages").forEach((message, index) => push(["message", BigInt(index), role(message)], get(message, "content"), "text"));
      break;
    case "open_ai_chat":
      push("tools", get(body, "tools"), "text");
      items("messages").forEach((message, index) => {
        const place: Json = ["message", BigInt(index), role(message)];
        if (isObject(message)) blocks.push(new PromptBlock(protocol, place, { kind: "message_fields", fields: message }));
        push(place, get(message, "content"), "text");
      });
      break;
    case "open_ai_responses": {
      push("instructions", get(body, "instructions"), "input_text");
      push("tools", get(body, "tools"), "input_text");
      const input = get(body, "input");
      if (typeof input === "string") {
        blocks.push(new PromptBlock(protocol, ["input", 0n], { kind: "user_message", text: input }));
      } else if (isArray(input)) {
        input.forEach((entry, index) => push(["input", BigInt(index)], entry, "input_text"));
      } else {
        push(["input", 0n], input, "input_text");
      }
      break;
    }
    case "gemini": {
      const system = geminiField(body, "systemInstruction");
      const content = system.error === undefined ? system.value : undefined;
      if (isObject(content) && Object.hasOwn(content, "parts")) push("system", get(content, "parts"), "text");
      else push("system", content, "text");
      push("tools", get(body, "tools"), "text");
      items("contents").forEach((entry, index) => {
        const place: Json = ["content", BigInt(index), role(entry)];
        const parts = get(entry, "parts");
        // A content without parts is billed as what it holds.
        push(place, parts !== undefined ? parts : entry, "text");
      });
      break;
    }
    default:
      break;
  }
  return blocks;
}
