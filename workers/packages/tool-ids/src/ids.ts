/**
 * Tool-call ids: where each protocol carries them, which of them every client passes back intact,
 * and which ones each protocol documents as valid (crates/gray-protocol/src/tool_ids.rs; the limits
 * and their sources are docs/design/tool-call-ids.md section "The limits"):
 *
 * - OpenAI Chat enforces at most 40 characters on `tool_calls[].id` and `tool_call_id` (the API's
 *   own error, quoted in anomalyco/opencode#12653 and Portkey-AI/gateway#1062; OpenCode 2.0.27 cuts
 *   every id to 40 characters for `openai/` models).
 * - Anthropic Messages: `tool_use.id` and `tool_result.tool_use_id` match `^[a-zA-Z0-9_-]+$`.
 * - OpenAI Responses: `FunctionCallOutputItemParam.call_id` has `maxLength: 64`.
 * - Gemini: `functionCall.id` and `functionResponse.id` are strings without a stated limit.
 *
 * Pure code: the conformance area `tool-ids` holds it to the Rust output.
 */
import { type Json, get, isArray, isObject } from "@gray/json";
import { type Protocol, geminiKey } from "@gray/protocol";

/** The longest id every client keeps: OpenAI Chat's enforced limit. */
export const MAX_CLIENT_ID_CHARS = 40;
/**
 * The longest tool id a protocol documents (OpenAI Responses `call_id`): up to this many bytes an
 * upstream id is an identifier (a label), beyond it it is treated as content.
 */
export const MAX_LABEL_BYTES = 64;
/** OpenAI Responses `FunctionCallOutputItemParam.call_id` `maxLength`. */
const MAX_RESPONSES_CALL_ID_CHARS = 64;

function anthropicCode(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) || code === 0x5f || code === 0x2d;
}

/** Every UTF-16 unit of `text` is one of `[A-Za-z0-9_-]` (so `text` is ASCII and its units are its bytes). */
function anthropicText(text: string): boolean {
  for (let i = 0; i < text.length; i++) if (!anthropicCode(text.charCodeAt(i))) return false;
  return true;
}

/**
 * `client_safe`: whether every client passes `id` back as it is: 1 to 40 characters of
 * `[A-Za-z0-9_-]`, the strictest length (OpenAI Chat) with the strictest alphabet (Anthropic).
 */
export function clientSafe(id: string): boolean {
  return id.length > 0 && id.length <= MAX_CLIENT_ID_CHARS && anthropicText(id);
}

/** Unicode scalar values in `text` (Rust's `chars().count()`). */
function scalars(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/**
 * `fits`: whether `protocol` documents `value` as a valid tool id: Anthropic's pattern, and
 * Responses' 64-character `call_id`. The other protocols state no format, so any non-empty id fits.
 */
export function fits(protocol: Protocol, value: string): boolean {
  if (value.length === 0) return false;
  if (protocol === "anthropic_messages") return anthropicText(value);
  if (protocol === "open_ai_responses") return scalars(value) <= MAX_RESPONSES_CALL_ID_CHARS;
  return true;
}

/** Whether a call's id or its result's. */
export type Role = "call" | "result";

/** One step of a path into a JSON value: an object key or an array index. */
export type Step = string | number;

/** Where one tool-call id is: a path into a JSON value whose end is a string. */
export interface Site {
  readonly path: readonly Step[];
  readonly role: Role;
}

/** The value at `path` of `value`, or undefined. */
export function walk(value: Json | undefined, path: readonly Step[]): Json | undefined {
  let at = value;
  for (const step of path) {
    if (typeof step === "number") at = isArray(at) ? at[step] : undefined;
    else at = get(at, step);
    if (at === undefined) return undefined;
  }
  return at;
}

/** The id at `site` of `value`. */
export function siteValue(site: Site, value: Json): string | undefined {
  const found = walk(value, site.path);
  return typeof found === "string" ? found : undefined;
}

/** Sets the id at `site` of `value`; false when the site holds no string. */
export function setSite(site: Site, value: Json, id: string): boolean {
  if (site.path.length === 0) return false;
  const parent = walk(value, site.path.slice(0, -1));
  const last = site.path[site.path.length - 1]!;
  if (typeof last === "number") {
    if (!isArray(parent) || typeof parent[last] !== "string") return false;
    parent[last] = id;
    return true;
  }
  if (!isObject(parent) || typeof get(parent, last) !== "string") return false;
  Object.defineProperty(parent, last, { value: id, writable: true, enumerable: true, configurable: true });
  return true;
}

/** `path` as a JSON pointer (RFC 6901), for logs and alerts. */
export function pointer(path: readonly Step[]): string {
  let out = "";
  for (const step of path) out += `/${typeof step === "number" ? String(step) : step.replaceAll("~", "~0").replaceAll("/", "~1")}`;
  return out;
}

/** Collects the sites under one JSON value (Rust's `Sites`). */
class Sites {
  readonly found: Site[] = [];
  private readonly path: Step[] = [];

  /** The member `key` of `value`, entering it when present. */
  key(value: Json, key: string): Json | undefined {
    const found = get(value, key);
    if (found === undefined) return undefined;
    this.path.push(key);
    return found;
  }

  up(): void {
    this.path.pop();
  }

  /** The string at `key` of `value`, when there is one. */
  id(value: Json, key: string, role: Role): void {
    if (typeof get(value, key) === "string") this.found.push({ path: [...this.path, key], role });
  }

  /** Calls `each` with every element of the array at `key` of `value`. */
  each(value: Json, key: string, each: (sites: Sites, item: Json) => void): void {
    const items = get(value, key);
    if (!isArray(items)) return;
    this.path.push(key);
    items.forEach((item, index) => {
      this.path.push(index);
      each(this, item);
      this.path.pop();
    });
    this.path.pop();
  }

  /** The Gemini field `name` (camelCase) under whichever spelling is present (`gemini_key`). */
  gemini(value: Json, name: string): Json | undefined {
    const found = geminiKey(value, name);
    if (found.key === undefined) return undefined;
    return this.key(value, found.key);
  }

  geminiParts(content: Json): void {
    this.each(content, "parts", (sites, part) => {
      if (sites.gemini(part, "functionCall") !== undefined) {
        sites.id(walkTop(part, sites, "functionCall"), "id", "call");
        sites.up();
      }
      if (sites.gemini(part, "functionResponse") !== undefined) {
        sites.id(walkTop(part, sites, "functionResponse"), "id", "result");
        sites.up();
      }
    });
  }

  chatToolCalls(message: Json): void {
    this.each(message, "tool_calls", (sites, call) => sites.id(call, "id", "call"));
  }

  /** A Responses item: its `call_id`, a call's or a call output's. */
  responsesItem(item: Json): void {
    const kind = get(item, "type");
    this.id(item, "call_id", typeof kind === "string" && kind.endsWith("_output") ? "result" : "call");
  }

  anthropicBlock(block: Json): void {
    const kind = get(block, "type");
    // Server tools (`server_tool_use`, `*_tool_result`, `mcp_*`) keep Anthropic's own ids, which the
    // provider resolves itself.
    if (kind === "tool_use") this.id(block, "id", "call");
    else if (kind === "tool_result") this.id(block, "tool_use_id", "result");
  }
}

/** The member a `Sites.gemini` call entered: the key it pushed is the last step of the path. */
function walkTop(part: Json, sites: Sites, name: string): Json {
  const found = geminiKey(part, name);
  return get(part, found.key as string) as Json;
}

/** `request_sites`: the tool-call ids of a request body of `protocol`, in body order. */
export function requestSites(protocol: Protocol, body: Json): Site[] {
  const sites = new Sites();
  switch (protocol) {
    case "open_ai_chat":
      sites.each(body, "messages", (s, message) => {
        s.chatToolCalls(message);
        if (get(message, "role") === "tool") s.id(message, "tool_call_id", "result");
      });
      break;
    case "open_ai_responses":
      sites.each(body, "input", (s, item) => s.responsesItem(item));
      break;
    case "anthropic_messages":
      sites.each(body, "messages", (s, message) => s.each(message, "content", (s2, block) => s2.anthropicBlock(block)));
      break;
    case "gemini":
      sites.each(body, "contents", (s, content) => s.geminiParts(content));
      break;
    default:
      break;
  }
  return sites.found;
}

/** `response_sites`: the tool-call ids of a whole (non-stream) answer of `protocol`. */
export function responseSites(protocol: Protocol, body: Json): Site[] {
  const sites = new Sites();
  switch (protocol) {
    case "open_ai_chat":
      sites.each(body, "choices", (s, choice) => {
        const message = s.key(choice, "message");
        if (message !== undefined) {
          s.chatToolCalls(message);
          s.up();
        }
      });
      break;
    case "open_ai_responses":
      sites.each(body, "output", (s, item) => s.responsesItem(item));
      break;
    case "anthropic_messages":
      sites.each(body, "content", (s, block) => s.anthropicBlock(block));
      break;
    case "gemini":
      sites.each(body, "candidates", (s, candidate) => {
        const content = s.key(candidate, "content");
        if (content !== undefined) {
          s.geminiParts(content);
          s.up();
        }
      });
      break;
    default:
      break;
  }
  return sites.found;
}

/** `event_sites`: the tool-call ids of one stream event (the JSON of one SSE frame) of `protocol`. */
export function eventSites(protocol: Protocol, event: Json): Site[] {
  const sites = new Sites();
  switch (protocol) {
    case "open_ai_chat":
      sites.each(event, "choices", (s, choice) => {
        const delta = s.key(choice, "delta");
        if (delta !== undefined) {
          s.chatToolCalls(delta);
          s.up();
        }
        // Not in the chunk schema, but relays send whole messages in chunks too.
        const message = s.key(choice, "message");
        if (message !== undefined) {
          s.chatToolCalls(message);
          s.up();
        }
      });
      break;
    case "open_ai_responses": {
      // `response.output_item.added` and `.done`.
      const item = sites.key(event, "item");
      if (item !== undefined) {
        sites.responsesItem(item);
        sites.up();
      }
      // `response.function_call_arguments.*`, when it names the call.
      sites.id(event, "call_id", "call");
      // The snapshot of `response.queued`, `.created`, `.in_progress`, `.completed`, `.incomplete` and `.failed`.
      const response = sites.key(event, "response");
      if (response !== undefined) {
        sites.each(response, "output", (s, entry) => s.responsesItem(entry));
        sites.up();
      }
      break;
    }
    case "anthropic_messages":
      if (get(event, "type") === "content_block_start") {
        const block = sites.key(event, "content_block");
        if (block !== undefined) {
          sites.anthropicBlock(block);
          sites.up();
        }
      }
      break;
    case "gemini":
      return responseSites(protocol, event);
    default:
      break;
  }
  return sites.found;
}
