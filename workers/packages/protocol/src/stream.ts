/**
 * Native protocol stream contracts (`parse_stream_event` and `ProtocolStreamDecoder` in
 * crates/gray-protocol/src/stream.rs).
 *
 * Semantic events come with the original JSON event (`native`), so opaque reasoning, provider
 * extensions, annotations and detailed usage survive decoding. Every event payload is parsed
 * strictly (@gray/json `parseStrict`): a duplicate key, which another parser could read differently from the
 * inspected value, invalidates the frame.
 */
import { geminiBlockFinish, mapFinish } from "./finish.ts";
import {
  type Json,
  type JsonObject,
  asBool,
  asStr,
  asU64,
  at,
  cloneJson,
  get,
  isArray,
  isObject,
  jsonEqual,
  parseStrict,
  pointer,
  setMember,
  toJsonString,
} from "@gray/json";
import { PROJECTION_NODE_BYTES } from "./answer-projection.ts";
import { jsonHeapBytes, stringHeapBytes } from "./heap.ts";
import { geminiField } from "./request.ts";
import { type SseEvent, SseDecoder } from "./sse.ts";
import { rustTrim } from "./text.ts";
import {
  type CanonicalEvent,
  type FinishReason,
  type Protocol,
  type Usage,
  ProtocolError,
  ZERO_USAGE,
  invalidResponse,
  notGeneration,
  streamState,
} from "./types.ts";
import { parseUsage } from "./usage.ts";

const invalid = invalidResponse;

function string(v: Json | undefined, key: string, p: Protocol): string {
  const s = asStr(get(v, key));
  if (s === undefined) throw invalid(p, `${key} must be a string`);
  return s;
}

/**
 * `responses_delta`: the `delta` of a Responses delta event, empty when the event has none. A relay
 * that writes these events from a Go struct with `omitempty` leaves out an empty delta (sub2api says
 * so of its own events: apicompat/responses_stream_event_wire.go at b0a02a33); yylx sent a first
 * `response.function_call_arguments.delta` without one on 10 of 18 streamed gpt-6.1-sol answers
 * (2026-10-17), and OpenCode 2.0.27 ran their calls. A delta that is there must be a string.
 */
function responsesDelta(v: Json): string {
  return get(v, "delta") === undefined ? "" : string(v, "delta", "open_ai_responses");
}

function optionalString(v: Json | undefined, key: string, p: Protocol): string | null {
  const member = get(v, key);
  if (member === undefined || member === null) return null;
  if (typeof member === "string") return member;
  throw invalid(p, `${key} must be a string or null`);
}

function optionalFinishReason(v: Json | undefined, key: string, p: Protocol): string | null {
  const value = optionalString(v, key, p);
  if (value !== null && rustTrim(value) === "") throw invalid(p, `${key} must not be empty`);
  return value;
}

/** `gemini_field(v, name)` with its error as an invalid response of `p`: a null is unset. */
function geminiFieldOr(v: Json, name: string, p: Protocol): Json | undefined {
  const found = geminiField(v, name);
  if (found.error !== undefined) throw invalid(p, found.error);
  return found.value;
}

function index(v: Json | undefined, key: string, p: Protocol): bigint {
  const n = asU64(get(v, key));
  if (n === undefined) throw invalid(p, `${key} must be a non-negative integer`);
  return n;
}

function object(v: Json | undefined, p: Protocol, name: string): JsonObject {
  if (!isObject(v)) throw invalid(p, `${name} must be an object`);
  return v;
}

function argumentsOf(v: Json | undefined, key: string, p: Protocol): Json {
  return argumentValue(string(v, key, p));
}

/**
 * Tool arguments are model output. Invalid JSON is still a valid native string; keeping it
 * neither validates it nor authorizes running the tool. Duplicate keys make the text ambiguous
 * across client parsers, so it is not an object either.
 */
export function argumentValue(raw: string): Json {
  try {
    return parseStrict(raw);
  } catch {
    return raw;
  }
}

/** `argument_text`: arguments as the text a Chat or Responses client receives: the text itself when it is not JSON, else the JSON. */
export function argumentText(args: Json): string {
  return typeof args === "string" ? args : toJsonString(args);
}

/**
 * `responses_argument_site`: where a Responses stream event carries text of a function call's
 * arguments, as the keys leading to it: an argument delta's `delta`, and the arguments a
 * `response.output_item.added` gives the call it adds. Undefined for any other event, and where
 * that text is empty: a client reads nothing there.
 */
export function responsesArgumentSite(payload: Json): readonly string[] | undefined {
  let path: readonly string[];
  let text: Json | undefined;
  switch (asStr(get(payload, "type"))) {
    case "response.function_call_arguments.delta":
      path = DELTA_SITE;
      text = get(payload, "delta");
      break;
    case "response.output_item.added":
      if (asStr(pointer(payload, "/item/type")) !== "function_call") return undefined;
      path = ADDED_ITEM_SITE;
      text = pointer(payload, "/item/arguments");
      break;
    default:
      return undefined;
  }
  return typeof text === "string" && text !== "" ? path : undefined;
}

/** The two paths of `responsesArgumentSite`, one value each: a held stream keeps one for each of its argument frames (@gray/protocol `RepairSites`). */
const DELTA_SITE: readonly string[] = Object.freeze(["delta"]);
const ADDED_ITEM_SITE: readonly string[] = Object.freeze(["item", "arguments"]);

/**
 * `responses_complete_call`: the function call a Responses stream event states the complete
 * arguments of, and whether it is the call's done item (the statement clients run: Codex and the
 * AI SDK run each `response.output_item.done` item) rather than its
 * `response.function_call_arguments.done`. The call is the event's own `output_index`, as the
 * decoder refuses a call's event whose index and item id name different items. Undefined for any
 * other event.
 */
export function responsesCompleteCall(payload: Json): { readonly call: bigint; readonly doneItem: boolean } | undefined {
  let doneItem: boolean;
  switch (asStr(get(payload, "type"))) {
    case "response.function_call_arguments.done":
      doneItem = false;
      break;
    case "response.output_item.done":
      if (asStr(pointer(payload, "/item/type")) !== "function_call") return undefined;
      doneItem = true;
      break;
    default:
      return undefined;
  }
  const call = asU64(get(payload, "output_index"));
  return call === undefined ? undefined : { call, doneItem };
}

/** The marker of the heartbeat some relays send in a Responses stream (`isKeepAlive`). */
const RESPONSES_HEARTBEAT = "SSE-Keep-Alive";

/**
 * `is_keep_alive`: whether a native stream event is a keep-alive: it carries nothing of the answer,
 * and any number of them may come before the stream's terminal event.
 *
 * On the Messages API it is Anthropic's `ping`, of which a stream "may also include any number"
 * (Anthropic streaming documentation). On the Responses API it is one of two events relays send
 * between real ones:
 *
 * - the heartbeat a relay makes itself: a `response.output_text.delta` for an output item named
 *   `SSE-Keep-Alive` that the stream never adds, with an empty delta at indexes 0, the key
 *   `SSE-Keep-Alive` set to `true`, and nothing else (exactly 6 fields). yylx sent exactly that
 *   before `response.created` (2026-10-17), and clients skip it by that shape (Cherry Studio's patch
 *   of `@ai-sdk/open-responses` 1.0.34);
 * - the `keepalive` event, `{"type": "keepalive"}` with at most an integer `sequence_number`, which
 *   yylx passed on from its upstream while a gpt-6.1-sol stream waited in a queue (2026-10-17).
 *   sub2api reads that type as a transport heartbeat, Codex skips event types it does not handle.
 *
 * An event that differs from them in anything is read as what it claims to be. No other API
 * documents a keep-alive event: theirs are SSE comments, which carry no event at all.
 */
export function isKeepAlive(protocol: Protocol, payload: Json): boolean {
  if (!isObject(payload)) return false;
  switch (protocol) {
    case "anthropic_messages":
      return asStr(get(payload, "type")) === "ping";
    case "open_ai_responses": {
      const keys = Object.keys(payload);
      const heartbeat =
        keys.length === 6 &&
        asStr(get(payload, "type")) === "response.output_text.delta" &&
        asStr(get(payload, "item_id")) === RESPONSES_HEARTBEAT &&
        asBool(get(payload, RESPONSES_HEARTBEAT)) === true &&
        asStr(get(payload, "delta")) === "" &&
        asU64(get(payload, "output_index")) === 0n &&
        asU64(get(payload, "content_index")) === 0n;
      const keepalive =
        asStr(get(payload, "type")) === "keepalive" &&
        keys.every((key) => key === "type" || (key === "sequence_number" && asU64(get(payload, key)) !== undefined));
      return heartbeat || keepalive;
    }
    default:
      return false;
  }
}

/** Choices or candidates by index (their position when they carry none), in index order. */
function alternatives(values: Json[], p: Protocol): Map<bigint, Json> {
  const indexed = new Map<bigint, Json>();
  values.forEach((value, position) => {
    object(value, p, "choice/candidate");
    const i = get(value, "index") !== undefined ? index(value, "index", p) : BigInt(position);
    if (indexed.has(i)) throw invalid(p, "duplicate choice/candidate index");
    indexed.set(i, value);
  });
  return new Map([...indexed.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** `raw_usage`: where each protocol puts the usage object of a stream event. */
export function rawUsage(p: Protocol, v: Json): Json | undefined {
  let usage: Json | undefined;
  switch (p) {
    case "open_ai_responses":
      usage = pointer(v, "/response/usage");
      if (usage === undefined) usage = get(v, "usage");
      break;
    case "anthropic_messages":
      usage = pointer(v, "/message/usage");
      if (usage === undefined) usage = get(v, "usage");
      break;
    case "gemini":
      usage = get(v, "usageMetadata");
      break;
    case "open_ai_chat":
      usage = get(v, "usage");
      break;
    default:
      usage = undefined;
  }
  return usage === null ? undefined : usage;
}

/** A provider error carried in a stream event: its message and code. */
function errorDetails(v: Json): { message: string; code: string | null } | undefined {
  const typ = asStr(get(v, "type"));
  let error = get(v, "error");
  if (error === null) error = undefined;
  if (error === undefined) {
    const nested = pointer(v, "/response/error");
    if (nested !== undefined && nested !== null) error = nested;
  }
  if (error === undefined && (typ === "error" || typ === "response.failed")) error = v;
  if (error === undefined) return undefined;
  const message = asStr(get(error, "message")) ?? asStr(error) ?? "provider stream failed";
  let code = get(error, "code");
  if (code === null) code = undefined;
  if (code === undefined) code = get(error, "status");
  if (code === undefined) code = get(error, "type");
  return {
    message,
    code: code === undefined ? null : typeof code === "string" ? code : toJsonString(code),
  };
}

/**
 * `parse_stream_event`: the semantics of one native payload, without claiming stream
 * completeness. Use `ProtocolStreamDecoder` at transport boundaries for ordering and EOF.
 */
export function parseStreamEvent(protocol: Protocol, payload: string): CanonicalEvent[] {
  if (rustTrim(payload) === "[DONE]") {
    if (protocol === "open_ai_chat") return [{ type: "done" }];
    throw invalid(protocol, "[DONE] is only a Chat Completions terminal marker");
  }
  let v: Json;
  try {
    v = parseStrict(payload);
  } catch (error) {
    throw invalid(protocol, error instanceof Error ? error.message : "invalid JSON");
  }
  object(v, protocol, "event");
  const events: CanonicalEvent[] = [];
  const details = errorDetails(v);
  if (details !== undefined) {
    const usage = rawUsage(protocol, v);
    if (usage !== undefined) events.push({ type: "usage", usage: parseUsage(protocol, usage) });
    events.push({ type: "error", message: details.message, code: details.code });
    events.push({ type: "native", protocol, payload: v });
    return events;
  }
  switch (protocol) {
    case "open_ai_chat":
      parseChat(v, events);
      break;
    case "open_ai_responses":
      parseResponses(v, events);
      break;
    case "anthropic_messages":
      parseAnthropic(v, events);
      break;
    case "gemini":
      parseGemini(v, events);
      break;
    default:
      throw notGeneration(protocol);
  }
  events.push({ type: "native", protocol, payload: v });
  return events;
}

function parseChat(v: Json, out: CanonicalEvent[]): void {
  const p: Protocol = "open_ai_chat";
  const choices = get(v, "choices");
  if (!isArray(choices)) throw invalid(p, "choices must be an array");
  const choice = alternatives(choices, p).get(0n);
  if (choice !== undefined) {
    object(choice, p, "choice");
    const delta = get(choice, "delta");
    if (delta !== undefined && delta !== null) {
      object(delta, p, "delta");
      const text = optionalString(delta, "content", p);
      if (text !== null) out.push({ type: "text_delta", text });
      for (const key of ["reasoning_content", "reasoning"]) {
        const reasoning = optionalString(delta, key, p);
        if (reasoning !== null) out.push({ type: "reasoning_delta", text: reasoning });
      }
      const tools = get(delta, "tool_calls");
      if (tools !== undefined && tools !== null) {
        if (!isArray(tools)) throw invalid(p, "tool_calls must be an array");
        for (const tool of tools) {
          const i = index(tool, "index", p);
          const fn = get(tool, "function") ?? null;
          if (fn !== null) object(fn, p, "function");
          const id = optionalString(tool, "id", p);
          const name = optionalString(fn, "name", p);
          const args = optionalString(fn, "arguments", p) ?? "";
          out.push({ type: "tool_call_delta", index: i, id, name, arguments: args });
        }
      }
      const legacy = get(delta, "function_call");
      if (legacy !== undefined && legacy !== null) {
        object(legacy, p, "function_call");
        const name = optionalString(legacy, "name", p);
        const args = optionalString(legacy, "arguments", p) ?? "";
        out.push({ type: "tool_call_delta", index: 0n, id: null, name, arguments: args });
      }
    }
    const reason = optionalFinishReason(choice, "finish_reason", p);
    if (reason !== null) out.push({ type: "finish", reason: mapFinish(reason) });
  }
  const usage = rawUsage(p, v);
  if (usage !== undefined) out.push({ type: "usage", usage: parseUsage(p, usage) });
}

function parseResponses(v: Json, out: CanonicalEvent[]): void {
  const p: Protocol = "open_ai_responses";
  if (isKeepAlive(p, v)) return;
  const typ = string(v, "type", p);
  switch (typ) {
    case "response.output_text.delta":
    case "response.refusal.delta":
      out.push({ type: "text_delta", text: responsesDelta(v) });
      break;
    case "response.reasoning_summary_text.delta":
    case "response.reasoning_text.delta":
      out.push({ type: "reasoning_delta", text: responsesDelta(v) });
      break;
    case "response.output_item.added": {
      const item = get(v, "item");
      if (item === undefined) throw invalid(p, "item is required");
      object(item, p, "item");
      if (asStr(get(item, "type")) === "function_call") {
        const i = index(v, "output_index", p);
        const id = optionalString(item, "call_id", p);
        const name = optionalString(item, "name", p);
        const args = optionalString(item, "arguments", p) ?? "";
        out.push({ type: "tool_call_delta", index: i, id, name, arguments: args });
      }
      break;
    }
    case "response.function_call_arguments.delta": {
      const i = index(v, "output_index", p);
      const id = optionalString(v, "call_id", p);
      const name = optionalString(v, "name", p);
      const args = responsesDelta(v);
      out.push({ type: "tool_call_delta", index: i, id, name, arguments: args });
      break;
    }
    case "response.function_call_arguments.done": {
      const i = index(v, "output_index", p);
      const id = optionalString(v, "call_id", p);
      const name = optionalString(v, "name", p);
      const args = argumentsOf(v, "arguments", p);
      out.push({ type: "tool_call_complete", index: i, id, name, arguments: args });
      break;
    }
    case "response.output_item.done": {
      const item = get(v, "item");
      if (item === undefined) throw invalid(p, "item is required");
      object(item, p, "item");
      if (asStr(get(item, "type")) === "function_call") {
        const i = index(v, "output_index", p);
        const id = optionalString(item, "call_id", p);
        const name = optionalString(item, "name", p);
        const args = argumentsOf(item, "arguments", p);
        out.push({ type: "tool_call_complete", index: i, id, name, arguments: args });
      }
      break;
    }
    case "response.completed":
    case "response.incomplete": {
      const usage = rawUsage(p, v);
      if (usage !== undefined) out.push({ type: "usage", usage: parseUsage(p, usage) });
      const reason: FinishReason =
        typ === "response.completed"
          ? "stop"
          : mapFinish(asStr(pointer(v, "/response/incomplete_details/reason")) ?? "unknown");
      out.push({ type: "finish", reason });
      out.push({ type: "done" });
      break;
    }
    default:
      break; // Opaque or new event types are carried in `native`, never discarded.
  }
}

function parseAnthropic(v: Json, out: CanonicalEvent[]): void {
  const p: Protocol = "anthropic_messages";
  switch (string(v, "type", p)) {
    case "message_start": {
      const usage = rawUsage(p, v);
      if (usage !== undefined) out.push({ type: "usage", usage: parseUsage(p, usage) });
      break;
    }
    case "content_block_start": {
      const i = index(v, "index", p);
      const block = get(v, "content_block");
      if (block === undefined) throw invalid(p, "content_block is required");
      switch (string(block, "type", p)) {
        case "text": {
          const text = optionalString(block, "text", p);
          if (text !== null && text !== "") out.push({ type: "text_delta", text });
          break;
        }
        case "thinking": {
          const text = optionalString(block, "thinking", p);
          if (text !== null && text !== "") out.push({ type: "reasoning_delta", text });
          const signature = optionalString(block, "signature", p);
          if (signature !== null && signature !== "") out.push({ type: "reasoning_signature", index: i, signature });
          break;
        }
        case "tool_use":
        case "server_tool_use": {
          let input = get(block, "input");
          if (input === null) input = undefined;
          if (input !== undefined) object(input, p, "tool input");
          const id = string(block, "id", p);
          const name = string(block, "name", p);
          const args = isObject(input) && Object.keys(input).length > 0 ? toJsonString(input) : "";
          out.push({ type: "tool_call_delta", index: i, id, name, arguments: args });
          break;
        }
        // The rest of the documented ContentBlock union (redacted_thinking, the hosted tool
        // results, container_upload, fallback, connector_text) is kept verbatim in `native`:
        // none is documented with a text or signature field this decoder could read.
        default:
          break;
      }
      break;
    }
    case "content_block_delta": {
      const i = index(v, "index", p);
      const delta = get(v, "delta");
      if (delta === undefined) throw invalid(p, "delta is required");
      switch (string(delta, "type", p)) {
        case "text_delta":
          out.push({ type: "text_delta", text: string(delta, "text", p) });
          break;
        case "thinking_delta":
          out.push({ type: "reasoning_delta", text: string(delta, "thinking", p) });
          break;
        case "signature_delta":
          out.push({ type: "reasoning_signature", index: i, signature: string(delta, "signature", p) });
          break;
        case "input_json_delta":
          out.push({ type: "tool_call_delta", index: i, id: null, name: null, arguments: string(delta, "partial_json", p) });
          break;
        // citations_delta annotates the text block it arrives with; kept in `native`.
        default:
          break;
      }
      break;
    }
    case "message_delta": {
      const usage = rawUsage(p, v);
      if (usage !== undefined) out.push({ type: "usage", usage: parseUsage(p, usage) });
      const delta = get(v, "delta");
      if (delta !== undefined) {
        const reason = optionalFinishReason(delta, "stop_reason", p);
        if (reason !== null) out.push({ type: "finish", reason: mapFinish(reason) });
      }
      break;
    }
    case "message_stop":
      out.push({ type: "done" });
      break;
    default:
      break;
  }
}

function parseGemini(v: Json, out: CanonicalEvent[]): void {
  const p: Protocol = "gemini";
  // `candidates: null` is no candidates, as Google's JSON mapping reads a null (`geminiField`):
  // yylx ends some streams with a chunk of only `"candidates": null` and the final usage
  // (2026-10-17).
  const candidates = geminiFieldOr(v, "candidates", p);
  if (candidates !== undefined) {
    if (!isArray(candidates)) throw invalid(p, "candidates must be an array");
    const candidate = alternatives(candidates, p).get(0n);
    if (candidate !== undefined) {
      object(candidate, p, "candidate");
      const parts = pointer(candidate, "/content/parts");
      if (parts !== undefined) {
        if (!isArray(parts)) throw invalid(p, "parts must be an array");
        parts.forEach((part, position) => {
          const i = BigInt(position);
          object(part, p, "part");
          const text = optionalString(part, "text", p);
          if (text !== null) {
            out.push(asBool(get(part, "thought")) === true ? { type: "reasoning_delta", text } : { type: "text_delta", text });
          }
          const signature = optionalString(part, "thoughtSignature", p);
          if (signature !== null) out.push({ type: "reasoning_signature", index: i, signature });
          const call = get(part, "functionCall");
          if (call !== undefined) {
            object(call, p, "functionCall");
            const given = get(call, "args");
            const args = given === undefined ? {} : given;
            object(args, p, "functionCall.args");
            const id = optionalString(call, "id", p);
            const name = string(call, "name", p);
            out.push({ type: "tool_call_complete", index: i, id, name, arguments: args });
          }
        });
      }
      const reason = optionalFinishReason(candidate, "finishReason", p);
      if (reason !== null && reason !== "FINISH_REASON_UNSPECIFIED") out.push({ type: "finish", reason: mapFinish(reason) });
    }
  }
  const blocked = geminiBlockFinish(v);
  if (blocked !== undefined) out.push({ type: "finish", reason: blocked });
  const usage = rawUsage(p, v);
  if (usage !== undefined) out.push({ type: "usage", usage: parseUsage(p, usage) });
}

interface ToolState {
  id: string | null;
  name: string | null;
  /** The argument fragments so far; let go once the call is complete. */
  arguments: string;
  /** The `input` of an Anthropic tool_use block start; undefined when absent (null is kept). Let go once the call is complete. */
  initialArguments: Json | undefined;
  complete: Json | undefined;
  /** The heap bytes of `arguments`, `initialArguments` and `complete` (`retainedBytes`). */
  textHeap: number;
  initialHeap: number;
  completeHeap: number;
}

interface ItemState {
  readonly id: string | null;
  readonly kind: string;
  closed: boolean;
}

/**
 * What an argument fragment costs the decoder beyond its characters: the fragment's own string header
 * and the rope node it is joined with. Measured in workerd (gateway/measure/answer-heap.ts,
 * 2026-10-19): 10,000 fragments of 64 characters joined into one string held 976,708 bytes, 33.7 a
 * fragment beyond its characters.
 */
export const STREAM_FRAGMENT_BYTES = 34;

/**
 * What the decoder keeps for each call (its `ToolState`, map entry and index) and for each output item
 * or content block (its `ItemState`, map entry and index). Measured in workerd
 * (gateway/measure/answer-heap.ts, 2026-10-19, 16 streams of 128 calls whose arguments are `{}`):
 * Chat's decoders held 286,268 bytes, 139.8 a call (its id, name and arguments included, which are
 * weighed on their own as well); Responses' 780,044, 380.9 a call with its item: 141 an item.
 */
export const STREAM_CALL_BYTES = 140;
export const STREAM_ITEM_BYTES = 144;

function compareBigint(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * `ProtocolStreamDecoder`: the stateful transport contract. A provider error is thrown with its
 * full native body; the usage accumulated so far stays readable on that path too.
 */
export class ProtocolStreamDecoder {
  readonly protocol: Protocol;
  private readonly sse = new SseDecoder();
  private started = false;
  private finishSeen = false;
  private terminal = false;
  private eof = false;
  private failure: ProtocolError | null = null;
  private currentUsage: Usage = ZERO_USAGE;
  private accumulatedUsage: JsonObject = {};
  private readonly items = new Map<bigint, ItemState>();
  private readonly tools = new Map<bigint, ToolState>();
  private readonly alternatives = new Map<bigint, boolean>();
  private sequence: bigint | null = null;
  private nextGeminiPart = 0n;
  /** What the decoder keeps of the stream so far, in heap bytes (`retainedBytes`). */
  private kept = 0;

  constructor(protocol: Protocol) {
    this.protocol = protocol;
  }

  /**
   * What the decoder keeps of the stream so far, in the heap (the gateway weighs it with the frames a
   * stream holds, relay.ts): each call's argument fragments until the call is complete
   * (`STREAM_FRAGMENT_BYTES` a fragment beyond its characters), then its complete arguments
   * (`jsonHeapBytes`; the trust gate and a translator keep the same value, not a copy), the input a
   * call started with until then, and each call's and each item's state (`STREAM_CALL_BYTES`,
   * `STREAM_ITEM_BYTES`).
   */
  retainedBytes(): number {
    return this.kept + this.sse.capacity;
  }

  /** A call's id or name, kept from its first statement on: its string, once. */
  private identity(current: string | null, merged: string | null): void {
    if (current === null && merged !== null) this.kept += PROJECTION_NODE_BYTES.string + stringHeapBytes(merged);
  }

  /** The output item or content block at `i` is now `item`. */
  private setItem(i: bigint, item: ItemState): void {
    const weigh = (state: ItemState | undefined) => (state === undefined ? 0 : STREAM_ITEM_BYTES + (state.id === null ? 0 : PROJECTION_NODE_BYTES.string + stringHeapBytes(state.id)));
    this.kept += weigh(item) - weigh(this.items.get(i));
    this.items.set(i, item);
  }

  /** The arguments call `i` starts with (an Anthropic tool_use block's `input`, a Responses call added whole). */
  private setInitialArguments(i: bigint, value: Json | undefined): void {
    const tool = this.tool(i);
    const heap = value === undefined ? 0 : jsonHeapBytes(value);
    this.kept += heap - tool.initialHeap;
    tool.initialHeap = heap;
    tool.initialArguments = value;
  }

  /** The usage accumulated from every usage object so far. */
  usage(): Usage {
    return this.currentUsage;
  }

  /** The native usage object accumulated so far (later counters merged over earlier ones). Never
   * changed afterwards: the next usage frame builds a new object. */
  rawUsage(): Json {
    return this.accumulatedUsage;
  }

  /** The Responses `sequence_number` an event added after the decoded ones takes. */
  nextSequenceNumber(): bigint {
    if (this.sequence === null) return 0n;
    return this.sequence === 18446744073709551615n ? this.sequence : this.sequence + 1n;
  }

  isTerminal(): boolean {
    return this.terminal;
  }

  /**
   * Every accepted event. If a later frame of the same chunk fails, the next push or finish
   * throws that error. Always finish a stream at EOF, even after a native terminal marker.
   */
  push(bytes: Uint8Array): CanonicalEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.eof) throw this.stateError("bytes after EOF");
    const frames = this.sse.push(bytes);
    const out: CanonicalEvent[] = [];
    for (const frame of frames) {
      try {
        out.push(...this.pushEvent(frame));
      } catch (error) {
        if (!(error instanceof ProtocolError)) throw error;
        this.failure = error;
        if (out.length === 0) throw error;
        return out;
      }
    }
    return out;
  }

  /** `SseDecoder.pushFrame` for one complete frame: its events now, or an error, never later. */
  pushFrame(frame: Uint8Array): CanonicalEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.eof) throw this.stateError("bytes after EOF");
    const out: CanonicalEvent[] = [];
    for (const event of this.sse.pushFrame(frame)) {
      try {
        out.push(...this.pushEvent(event));
      } catch (error) {
        if (error instanceof ProtocolError) this.failure = error;
        throw error;
      }
    }
    return out;
  }

  pushEvent(frame: SseEvent): CanonicalEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.terminal || this.eof) {
      // A keep-alive after the terminal event carries nothing, as one before it does, and is read
      // as nothing: the answer has ended. Anthropic documents that a stream "may also include any
      // number" of pings, and yylx sent them after `message_stop` every 10 s or so for up to 47 s
      // before it closed the stream (2026-10-17). Anything else after the terminal event, and
      // anything after EOF, fails the stream.
      if (!this.eof && this.trailingKeepAlive(frame)) return [];
      throw this.stateError("event after terminal state");
    }
    let events = parseStreamEvent(this.protocol, frame.data);
    const nativeEvent = events.find((e) => e.type === "native");
    const native = nativeEvent?.type === "native" ? nativeEvent.payload : undefined;
    if (native !== undefined) {
      const name = frame.event;
      if (
        name !== null &&
        name !== "" &&
        name !== "message" &&
        (this.protocol === "anthropic_messages" || this.protocol === "open_ai_responses") &&
        asStr(get(native, "type")) !== name
      ) {
        throw this.stateError("SSE event name does not match payload type");
      }
      this.mergeUsage(native);
      const details = errorDetails(native);
      if (details !== undefined) {
        this.terminal = true;
        const error = new ProtocolError({
          kind: "provider",
          protocol: this.protocol,
          message: details.message,
          code: details.code,
          body: native,
        });
        this.failure = error;
        throw error;
      }
    }
    switch (this.protocol) {
      case "open_ai_chat":
        this.chatOrder(native, events);
        break;
      case "anthropic_messages":
        this.anthropicOrder(native as Json, events);
        break;
      case "open_ai_responses":
        this.responsesOrder(native as Json, events);
        break;
      case "gemini": {
        this.alternativeOrder(native as Json);
        const shift = this.nextGeminiPart;
        events = events.map((e) =>
          e.type === "tool_call_complete" || e.type === "reasoning_signature" ? { ...e, index: e.index + shift } : e,
        );
        const candidates = get(native, "candidates");
        if (isArray(candidates)) {
          const primary = alternatives(candidates, this.protocol).get(0n);
          if (primary !== undefined) {
            const parts = pointer(primary, "/content/parts");
            this.nextGeminiPart += BigInt(isArray(parts) ? parts.length : 0);
          }
        }
        break;
      }
      default:
        throw notGeneration(this.protocol);
    }
    events = this.trackTools(events);
    if (this.protocol === "open_ai_chat") {
      const position = events.findIndex((e) => e.type === "finish");
      if (position >= 0) {
        const completed = this.completeOpenTools();
        events.splice(position, 0, ...completed);
      }
    }
    return events.map((event) => {
      if (event.type === "usage") return { type: "usage", usage: this.currentUsage };
      if (event.type === "finish") this.finishSeen = true;
      else if (event.type === "done") this.terminal = true;
      return event;
    });
  }

  finish(): CanonicalEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.eof) return [];
    const frames = this.sse.finish();
    const out: CanonicalEvent[] = [];
    for (const frame of frames) out.push(...this.pushEvent(frame));
    if (this.protocol === "gemini") {
      const states = [...this.alternatives.values()];
      if (states.some((finished) => !finished)) {
        throw states.some((finished) => finished)
          ? this.stateError("EOF before every observed Gemini candidate finished")
          : new ProtocolError({ kind: "incomplete_stream" });
      }
      if (this.alternatives.size > 0 || this.finishSeen) {
        this.terminal = true;
        out.push({ type: "done" });
      }
    }
    if (!this.terminal) throw new ProtocolError({ kind: "incomplete_stream" });
    this.eof = true;
    return out;
  }

  /** `trailing_keep_alive`: `frame` is a keep-alive of this protocol (`isKeepAlive`) under its own event name, if it has one. */
  private trailingKeepAlive(frame: SseEvent): boolean {
    let v: Json;
    try {
      v = parseStrict(frame.data);
    } catch {
      return false;
    }
    if (!isKeepAlive(this.protocol, v)) return false;
    const name = frame.event;
    return name === null || name === "" || name === "message" || asStr(get(v, "type")) === name;
  }

  private stateError(message: string): ProtocolError {
    return streamState(this.protocol, message);
  }

  private mergeUsage(v: Json): void {
    const usage = rawUsage(this.protocol, v);
    if (usage === undefined) return;
    parseUsage(this.protocol, usage);
    // Copied, not merged in place: a caller may still hold the object `rawUsage()` returned.
    this.accumulatedUsage = mergeJson(cloneJson(this.accumulatedUsage), usage) as JsonObject;
    this.currentUsage = parseUsage(this.protocol, this.accumulatedUsage);
  }

  private chatOrder(native: Json | undefined, events: CanonicalEvent[]): void {
    if (native !== undefined) this.alternativeOrder(native);
    if (events.some((e) => e.type === "done") && (this.alternatives.size === 0 || [...this.alternatives.values()].some((f) => !f))) {
      throw this.stateError("Chat [DONE] before every observed choice finished");
    }
  }

  private alternativeOrder(v: Json): void {
    const chat = this.protocol === "open_ai_chat";
    const key = chat ? "choices" : "candidates";
    const reasonKey = chat ? "finish_reason" : "finishReason";
    const contentKey = chat ? "delta" : "content";
    const values = chat ? get(v, key) : geminiFieldOr(v, key, this.protocol);
    if (values === undefined) return;
    if (!isArray(values)) throw invalid(this.protocol, `${key} must be an array`);
    for (const [i, choice] of alternatives(values, this.protocol)) {
      const reason = optionalFinishReason(choice, reasonKey, this.protocol);
      const finished = reason !== null && reason !== "" && reason !== "FINISH_REASON_UNSPECIFIED";
      const content = get(choice, contentKey);
      const hasContent =
        isObject(content) &&
        Object.keys(content).some((k) => {
          const member = content[k] as Json;
          return member !== null && member !== "" && (!isArray(member) || member.length > 0);
        });
      if (this.alternatives.get(i) === true && (finished || hasContent)) {
        throw this.stateError(`content or repeated finish after choice/candidate ${i} finished`);
      }
      this.alternatives.set(i, (this.alternatives.get(i) ?? false) || finished);
    }
  }

  private anthropicOrder(v: Json, events: CanonicalEvent[]): void {
    const p = this.protocol;
    const typ = string(v, "type", p);
    if (isKeepAlive(p, v)) return;
    if (typ === "message_start") {
      if (this.started) throw this.stateError("duplicate message_start");
      const message = get(v, "message");
      if (message === undefined) throw invalid(p, "message is required");
      object(message, p, "message");
      this.started = true;
      return;
    }
    if (!this.started) throw this.stateError("event before message_start");
    const open = () => [...this.items.values()].some((item) => !item.closed);
    switch (typ) {
      case "content_block_start": {
        if (this.finishSeen || open()) {
          throw this.stateError("content block starts after finish or before previous block stopped");
        }
        const i = index(v, "index", p);
        if (this.items.has(i)) throw this.stateError("reused content block index");
        const kind = string(at(v, "content_block"), "type", p);
        if (kind === "tool_use" || kind === "server_tool_use") {
          this.setInitialArguments(i, get(at(v, "content_block"), "input"));
        }
        this.setItem(i, { id: null, kind, closed: false });
        break;
      }
      case "content_block_delta":
      case "content_block_stop": {
        const i = index(v, "index", p);
        const item = this.items.get(i);
        if (item === undefined) throw this.stateError("content block event before start");
        if (item.closed) throw this.stateError("content block event after stop");
        if (typ === "content_block_delta") {
          const deltaKind = string(at(v, "delta"), "type", p);
          let valid: boolean;
          switch (deltaKind) {
            case "text_delta":
              valid = item.kind === "text";
              break;
            case "thinking_delta":
            case "signature_delta":
              valid = item.kind === "thinking";
              break;
            case "input_json_delta":
              valid = item.kind === "tool_use" || item.kind === "server_tool_use";
              break;
            // citations_delta annotates the text block it arrives with, and a block type this
            // decoder does not model constrains nothing.
            default:
              valid = true;
          }
          if (!valid) throw this.stateError("delta type does not match content block");
        } else {
          item.closed = true;
          if (this.tools.has(i)) events.unshift(this.completeTool(i));
        }
        break;
      }
      case "message_delta":
        if (open()) throw this.stateError("message_delta before content block stop");
        break;
      case "message_stop":
        if (!this.finishSeen || open()) throw this.stateError("message_stop before stop_reason or content block stop");
        break;
      default:
        break;
    }
  }

  private responsesOrder(v: Json, events: CanonicalEvent[]): void {
    const p = this.protocol;
    const typ = string(v, "type", p);
    // A keep-alive is not part of the response, so it neither opens it nor belongs to one of its items.
    if (isKeepAlive(p, v)) return;
    const sequenceValue = get(v, "sequence_number");
    if (sequenceValue !== undefined) {
      const sequence = asU64(sequenceValue);
      if (sequence === undefined) throw invalid(p, "sequence_number must be a non-negative integer");
      // The stream's own order is the order of its events; a number that goes back is an event out
      // of that order. One repeated is not: yylx sent an empty text delta and then the first real
      // one under the same number, on 2 of 31 gpt-6.1-sol streams of one journey (2026-10-17),
      // which clients read as they come.
      if (this.sequence !== null && sequence < this.sequence) throw this.stateError("sequence_number went back");
      this.sequence = sequence;
    }
    if (typ === "response.created" || typ === "response.queued") {
      if (this.started && typ === "response.created") throw this.stateError("duplicate response.created");
      this.started = true;
      return;
    }
    if (!this.started) throw this.stateError("event before response.created");
    switch (typ) {
      case "response.output_item.added": {
        const i = index(v, "output_index", p);
        // An index whose item is done may take a new item, as a relay that misnumbers its items
        // gives it one (`responseItem`); not one still open, and not a done function call's,
        // whose index keys its arguments.
        const previous = this.items.get(i);
        if (previous !== undefined && (!previous.closed || previous.kind === "function_call")) {
          throw this.stateError("reused output_index");
        }
        const item = at(v, "item");
        const id = optionalString(item, "id", p);
        const kind = string(item, "type", p);
        this.setItem(i, { id, kind, closed: false });
        this.addedCallSnapshot(i, item, events);
        break;
      }
      case "response.output_item.done": {
        const i = this.responseItem(v, events);
        const kind = string(at(v, "item"), "type", p);
        const item = this.items.get(i) as ItemState;
        if (item.closed) {
          // The same item's done event again, its id and type as the first: a repeat, which adds
          // nothing. Clients read each done item for itself (the AI SDK, Codex); a call repeated
          // with other arguments is the tool tracking's and the trust gate's to judge.
          const id = asStr(pointer(v, "/item/id"));
          if (item.id !== null && item.id === id && item.kind === kind) return;
          throw this.stateError("output event after output_item.done");
        }
        if (kind !== item.kind) throw this.stateError("output item type changed before completion");
        item.closed = true;
        break;
      }
      case "response.completed":
        if ([...this.items.values()].some((item) => !item.closed)) {
          throw this.stateError("response.completed before output_item.done");
        }
        this.validateResponseStatus(v, "completed");
        break;
      case "response.incomplete":
        this.validateResponseStatus(v, "incomplete");
        break;
      default:
        if (get(v, "output_index") !== undefined) {
          const i = this.responseItem(v, events);
          const item = this.items.get(i) as ItemState;
          if (item.closed) throw this.stateError("output event after output_item.done");
          if (typ.startsWith("response.function_call_arguments.") && item.kind !== "function_call") {
            throw this.stateError("function arguments for a non-function output item");
          }
        }
    }
  }

  /**
   * `added_call_snapshot`: a function call a Responses stream adds with its whole arguments already
   * in the item. OpenAI adds the item with `arguments: ""` and builds them with deltas; a sub2api
   * relay (yylx, 2026-10-15) adds it with the complete arguments and then sends them again as one
   * delta and in both `done` events. Arguments that are already a complete JSON object cannot be
   * continued by a delta, so they are the call's snapshot and not its first fragment: kept for a
   * call that gets no delta, and left out of the deltas (clients that run the call read the
   * arguments from the deltas and the `done` events, never from the added item). Counted as a
   * fragment, they would make every such call's deltas read its arguments twice. Arguments that are
   * not yet a complete object stay the first fragment, which later deltas continue.
   */
  private addedCallSnapshot(i: bigint, item: Json, events: CanonicalEvent[]): void {
    if (asStr(get(item, "type")) !== "function_call") return;
    const text = asStr(get(item, "arguments"));
    if (text === undefined) return;
    let snapshot: Json;
    try {
      snapshot = parseStrict(text);
    } catch {
      return;
    }
    if (!isObject(snapshot)) return;
    this.setInitialArguments(i, snapshot);
    for (let k = 0; k < events.length; k += 1) {
      const event = events[k] as CanonicalEvent;
      if (event.type === "tool_call_delta" && event.index === i) events[k] = { ...event, arguments: "" };
    }
  }

  private validateResponseStatus(v: Json, expected: string): void {
    const response = get(v, "response");
    if (response === undefined) throw invalid(this.protocol, "terminal response object is required");
    object(response, this.protocol, "response");
    const status = get(response, "status");
    if (status !== undefined) {
      if (typeof status !== "string") throw invalid(this.protocol, "response.status must be a string");
      if (status !== expected) throw this.stateError("terminal event does not match response.status");
    }
  }

  /**
   * `response_item`: the index of the output item a Responses event belongs to, with the event's
   * canonical tool events moved to it. That is the item its `output_index` names, unless the item id
   * the event carries is another item's: then it is that item's, as clients take an event's item
   * from its id (the AI SDK matches text to its item by `item_id`) and read each done item as it is.
   * A relay serving gpt-6.1-sol for yylx (2026-10-17) numbered events apart from their items: the
   * done event of a message added at index 1 came at 0, a reasoning item's index. An id that names
   * no single item, and an index that names no item and comes without an id, still fail the stream.
   * So does an event whose index and id do not name the same function call: clients key a call's
   * argument deltas by their index (openai-python, the AI SDK), so a call's event at another item's
   * index, or another item's event at a call's index, would give such a client one call's arguments
   * under another call's name, a pairing the trust gate never inspected.
   */
  private responseItem(v: Json, events: CanonicalEvent[]): bigint {
    const i = index(v, "output_index", this.protocol);
    let incoming = get(v, "item_id");
    if (incoming === undefined) incoming = pointer(v, "/item/id");
    const incomingId = asStr(incoming);
    const withId = (id: string): bigint | undefined => {
      let found: bigint | undefined;
      for (const [index, item] of this.items) {
        if (item.id !== id) continue;
        if (found !== undefined) return undefined;
        found = index;
      }
      return found;
    };
    const current = this.items.get(i);
    let named: bigint;
    if (current !== undefined && incomingId !== undefined && current.id !== null && current.id !== incomingId) {
      const other = withId(incomingId);
      if (other === undefined) throw this.stateError("item_id does not match output_index");
      named = other;
    } else if (current !== undefined) {
      named = i;
    } else if (incomingId !== undefined) {
      const other = withId(incomingId);
      if (other === undefined) throw this.stateError("output event before output_item.added");
      named = other;
    } else {
      throw this.stateError("output event before output_item.added");
    }
    const call = (index: bigint): boolean => this.items.get(index)?.kind === "function_call";
    if (named !== i && (call(i) || call(named))) throw this.stateError("item_id does not match output_index");
    if (named !== i) {
      for (let k = 0; k < events.length; k += 1) {
        const event = events[k] as CanonicalEvent;
        if ((event.type === "tool_call_delta" || event.type === "tool_call_complete") && event.index === i) events[k] = { ...event, index: named };
      }
    }
    return named;
  }

  private tool(i: bigint): ToolState {
    let tool = this.tools.get(i);
    if (tool === undefined) {
      tool = { id: null, name: null, arguments: "", initialArguments: undefined, complete: undefined, textHeap: 0, initialHeap: 0, completeHeap: 0 };
      this.tools.set(i, tool);
      this.kept += STREAM_CALL_BYTES;
    }
    return tool;
  }

  private trackTools(events: CanonicalEvent[]): CanonicalEvent[] {
    const keep: CanonicalEvent[] = [];
    for (const event of events) {
      if (event.type === "tool_call_delta") {
        const tool = this.tool(event.index);
        if (tool.complete !== undefined) throw this.stateError("tool delta after completed arguments");
        const [id, name] = [tool.id, tool.name];
        tool.id = mergeIdentity(tool.id, event.id, this.protocol, "tool id");
        tool.name = mergeIdentity(tool.name, event.name, this.protocol, "tool name");
        this.identity(id, tool.id);
        this.identity(name, tool.name);
        if (event.arguments !== "") {
          tool.arguments += event.arguments;
          const heap = stringHeapBytes(event.arguments) + STREAM_FRAGMENT_BYTES;
          tool.textHeap += heap;
          this.kept += heap;
        }
        keep.push({ ...event, id: event.id ?? tool.id, name: event.name ?? tool.name });
      } else if (event.type === "tool_call_complete") {
        const tool = this.tool(event.index);
        const [id, name] = [tool.id, tool.name];
        tool.id = mergeIdentity(tool.id, event.id, this.protocol, "tool id");
        tool.name = mergeIdentity(tool.name, event.name, this.protocol, "tool name");
        this.identity(id, tool.id);
        this.identity(name, tool.name);
        // Responses repeats the completed item after arguments.done.
        if (tool.complete !== undefined && jsonEqual(tool.complete, event.arguments)) continue;
        // A final native snapshot is authoritative, also when it repairs an earlier value. The
        // fragments and the input the call started with are no longer read (a fragment after this
        // fails the stream), so they are let go.
        tool.complete = event.arguments;
        tool.arguments = "";
        tool.initialArguments = undefined;
        const heap = jsonHeapBytes(event.arguments);
        this.kept += heap - tool.textHeap - tool.initialHeap - tool.completeHeap;
        tool.textHeap = 0;
        tool.initialHeap = 0;
        tool.completeHeap = heap;
        keep.push({ ...event, id: event.id ?? tool.id, name: event.name ?? tool.name });
      } else {
        keep.push(event);
      }
    }
    return keep;
  }

  private completeTool(i: bigint): CanonicalEvent {
    const tool = this.tools.get(i) as ToolState;
    const args = tool.arguments === "" ? (tool.initialArguments === undefined ? "" : cloneJson(tool.initialArguments)) : argumentValue(tool.arguments);
    return { type: "tool_call_complete", index: i, id: tool.id, name: tool.name, arguments: args };
  }

  private completeOpenTools(): CanonicalEvent[] {
    const out: CanonicalEvent[] = [];
    for (const i of [...this.tools.keys()].sort(compareBigint)) {
      if ((this.tools.get(i) as ToolState).complete === undefined) out.push(this.completeTool(i));
    }
    return this.trackTools(out);
  }
}

function mergeIdentity(current: string | null, incoming: string | null, protocol: Protocol, field: string): string | null {
  if (incoming === null) return current;
  if (current !== null && current !== incoming) {
    throw streamState(protocol, `conflicting ${field} for the same index`);
  }
  return incoming;
}

/**
 * `merge_json`: folds a later usage frame into the usage accumulated so far. A null in the later
 * frame means "not reported in this frame", not "measured as nothing": Anthropic documents its
 * cache counters as `number or null`, and a `message_delta` may carry them as null after
 * `message_start` reported the real count. So a null never replaces a value already seen, as
 * Anthropic's own SDK accumulates `message_delta` usage; a null for a counter not yet seen is kept.
 */
export function mergeJson(destination: Json, source: Json): Json {
  if (isObject(destination) && isObject(source)) {
    for (const key of Object.keys(source)) {
      const current = Object.hasOwn(destination, key) ? (destination[key] as Json) : null;
      setMember(destination, key, mergeJson(current, source[key] as Json));
    }
    return destination;
  }
  return source === null ? destination : cloneJson(source);
}
