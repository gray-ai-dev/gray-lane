import type { OpencodeThinking } from "@gray/control";
import { asArray, asStr, get, isObject, pointer, toJsonString, type Json, type JsonObject } from "@gray/json";
import type { Protocol } from "@gray/protocol";
import anthropicMessages from "../fixtures/opencode-2.0.27/anthropic_messages.json" with { type: "json" };
import gemini from "../fixtures/opencode-2.0.27/gemini.json" with { type: "json" };
import manifestJson from "../fixtures/opencode-2.0.27/manifest.json" with { type: "json" };
import openAiChat from "../fixtures/opencode-2.0.27/open_ai_chat.json" with { type: "json" };
import openAiResponses from "../fixtures/opencode-2.0.27/open_ai_responses.json" with { type: "json" };

/**
 * The coding-agent check's shape (coding-agent.ts): OpenCode 2's fixtures as the check reads them, and
 * whether a customer's request is of that shape and which thinking it carries. A module of its own, as
 * `@gray/verifier/coding-agent-shape`, so that the gateway's traffic evidence (the lane bundle) reads it
 * without loading the check itself.
 */

/** `OpencodeThinking::field`: the `thinking` field of the Messages request; undefined for `none`. */
export function thinkingField(thinking: OpencodeThinking): JsonObject | undefined {
  switch (thinking) {
    case "disabled":
      return { type: "disabled" };
    case "adaptive":
      return { type: "adaptive", block_binding: { prefix_mismatch_behavior: "drop_block" } };
    case "none":
      return undefined;
  }
}

/**
 * `thinking_of`: the thinking a customer's request `body` of `protocol`, of this shape, carries: one of the
 * variants OpenCode sends; null for any other `thinking` on the Messages API, which is no request Gray's
 * configuration has OpenCode send.
 */
export function thinkingOf(protocol: Protocol, body: Json): OpencodeThinking | null {
  if (protocol !== "anthropic_messages") return "none";
  const sent = get(body, "thinking");
  for (const thinking of ["disabled", "adaptive", "none"] as const) {
    const field = thinkingField(thinking);
    if (field === undefined ? sent === undefined : sent !== undefined && toJsonString(sent) === toJsonString(field)) return thinking;
  }
  return null;
}

/** A fixture as stored: integers as JSON numbers, read into `Json` (integers as bigint, as serde_json reads them). */
function json(value: unknown): Json {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : value;
  if (Array.isArray(value)) return value.map(json);
  const out: JsonObject = {};
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) Object.defineProperty(out, key, { value: json(v), enumerable: true, writable: true, configurable: true });
  return out;
}

/** One API's request as OpenCode sends it, with placeholders (`Fixture`). */
export interface Fixture {
  readonly protocol: Protocol;
  /** The headers of OpenCode's request that Gray forwards to a relay. */
  readonly headers: readonly (readonly [string, string])[];
  readonly body: JsonObject;
}

export interface Shape {
  /** The neutral values of the machine and the day (manifest.json). */
  readonly neutral: ReadonlyMap<string, string>;
  readonly fixtures: readonly Fixture[];
}

let shapeData: Shape | null = null;

export function shape(): Shape {
  if (shapeData !== null) return shapeData;
  const fixture = (protocol: Protocol, stored: unknown): Fixture => {
    const f = json(stored);
    const headers = get(f, "headers");
    return {
      protocol,
      headers: isObject(headers) ? Object.entries(headers).map(([name, value]) => [name, String(value)] as const) : [],
      body: get(f, "body") as JsonObject,
    };
  };
  const neutral = get(json(manifestJson), "neutral");
  shapeData = {
    neutral: new Map(isObject(neutral) ? Object.entries(neutral).map(([k, v]) => [k, String(v)] as const) : []),
    fixtures: [
      fixture("anthropic_messages", anthropicMessages),
      fixture("open_ai_responses", openAiResponses),
      fixture("gemini", gemini),
      fixture("open_ai_chat", openAiChat),
    ],
  };
  return shapeData;
}

/** `fixture`: the fixture of `protocol`; null for an API OpenCode does not call. */
export function fixture(protocol: Protocol): Fixture | null {
  return shape().fixtures.find((f) => f.protocol === protocol) ?? null;
}

/**
 * `system_text`: the system text of a request `body` of `protocol`, every part OpenCode wrote in order; null when
 * it has none of that form.
 */
export function systemText(protocol: Protocol, body: Json): string | null {
  const texts: (string | undefined)[] = [];
  switch (protocol) {
    case "anthropic_messages": {
      const system = asArray(get(body, "system"));
      if (system === undefined) return null;
      for (const block of system) texts.push(asStr(get(block, "text")));
      break;
    }
    case "open_ai_responses":
      texts.push(asStr(get(body, "instructions")));
      break;
    case "gemini": {
      const parts = asArray(pointer(body, "/systemInstruction/parts"));
      if (parts === undefined) return null;
      for (const part of parts) texts.push(asStr(get(part, "text")));
      break;
    }
    case "open_ai_chat": {
      const messages = asArray(get(body, "messages"));
      if (messages === undefined) return null;
      for (const m of messages) if (get(m, "role") === "system") texts.push(asStr(get(m, "content")));
      break;
    }
    default:
      return null;
  }
  if (texts.length === 0 || texts.some((t) => t === undefined)) return null;
  return texts.join("");
}

/**
 * `fits`: whether `text` is `template` with each `{{NAME}}` of it replaced by text without a line break.
 */
function fits(template: string, text: string): boolean {
  const literals: string[] = [];
  let rest = template;
  for (;;) {
    const start = rest.indexOf("{{");
    if (start < 0) break;
    const length = rest.slice(start).indexOf("}}");
    if (length < 0) break;
    literals.push(rest.slice(0, start));
    rest = rest.slice(start + length + 2);
  }
  literals.push(rest);
  if (!text.startsWith(literals[0]!)) return false;
  let remaining = text.slice(literals[0]!.length);
  for (let i = 1; i < literals.length; i++) {
    const literal = literals[i]!;
    const last = i === literals.length - 1;
    let at: number;
    if (last) {
      if (!remaining.endsWith(literal)) return false;
      at = remaining.length - literal.length;
    } else if (literal === "") {
      at = 0;
    } else {
      at = remaining.indexOf(literal);
      if (at < 0) return false;
    }
    if (remaining.slice(0, at).includes("\n")) return false;
    remaining = remaining.slice(at + literal.length);
    if (last) return true;
  }
  return remaining === "";
}

/**
 * `matches`: whether a customer's request `body` of `protocol` is this shape's: its tool list is the fixture's,
 * as JSON, and its system text is the fixture's with each placeholder standing for one line's worth of anything.
 * A request that a relay served or refused is then evidence for this check's result, and only then.
 */
export function matchesShape(protocol: Protocol, body: Json): boolean {
  const f = fixture(protocol);
  if (f === null) return false;
  const tools = get(body, "tools");
  const own = get(f.body, "tools");
  if (tools === undefined || own === undefined || toJsonString(tools) !== toJsonString(own)) return false;
  const template = systemText(protocol, f.body);
  const text = systemText(protocol, body);
  return template !== null && text !== null && fits(template, text);
}
