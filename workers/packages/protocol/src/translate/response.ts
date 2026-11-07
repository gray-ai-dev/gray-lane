/**
 * Complete (non-stream) upstream responses into the IR, and the IR into a client response
 * (crates/gray-protocol/src/translate/response.rs).
 */
import { type Json, type JsonObject, asStr, get, isArray, isObject, parseStrict, pointer, toJsonString } from "@gray/json";
import { rustTrim } from "../text.ts";
import type { Protocol } from "../types.ts";
import { Carrier, carrierId, signedId } from "./carrier.ts";
import { type Call, type Output, type Response, type Thought, finishWithCalls } from "./ir.ts";
import { Refusal, TRANSLATION_CODES as code } from "./refusal.ts";
import {
  anthropicFinish,
  chatFinish,
  geminiFinish,
  readUsage,
  renderAnthropicFinish,
  renderChatFinish,
  renderGeminiFinish,
  renderResponsesFinish,
  renderUsage,
  responsesFinish,
} from "./usage.ts";

/** Values a translated response needs that no upstream response provides. */
export interface ResponseContext {
  /** Seeds generated ids (Gemini calls without one, response item ids). */
  readonly requestId: string;
  /** Unix seconds (u64), for `created` / `created_at`. */
  readonly created: bigint;
  /** Model label when the upstream response has none. */
  readonly model: string;
  /** A Chat client stream ends with the `choices: []` usage chunk only when the client set `stream_options.include_usage`. */
  readonly streamUsage: boolean;
}

function upstream(param: string): Refusal {
  return new Refusal(code.UPSTREAM, param);
}

function s(v: Json | undefined, key: string): string | undefined {
  return asStr(get(v, key));
}

function isAsciiAlphanumeric(c: string): boolean {
  return /^[A-Za-z0-9]$/.test(c);
}

/** Letters and digits of the request id, for generated ids. */
export function idSeed(ctx: ResponseContext): string {
  let seed = "";
  for (const c of ctx.requestId) {
    if (seed.length === 24) break;
    if (isAsciiAlphanumeric(c)) seed += c;
  }
  return seed === "" ? "gray" : seed;
}

/**
 * `reasoning_item_id`: the id of a reasoning item this layer renders for a Responses client: `rs_<seed>_<n>`, the
 * request id's seed (`idSeed`) and the item's output index. No provider issues such an id (OpenAI's are `rs_` and
 * hex alone), which `mintedReasoningId` reads.
 */
export function reasoningItemId(seed: string, n: number | bigint): string {
  return `rs_${seed}_${n}`;
}

/** `minted_reasoning_id`: whether `id` is one `reasoningItemId` makes: `rs_`, a seed of one to 24 ASCII letters and digits (`idSeed`), `_` and an output index. */
export function mintedReasoningId(id: string): boolean {
  if (!id.startsWith("rs_")) return false;
  const rest = id.slice(3);
  const split = rest.indexOf("_");
  if (split < 0) return false;
  const seed = rest.slice(0, split);
  const n = rest.slice(split + 1);
  return seed.length >= 1 && seed.length <= 24 && /^[A-Za-z0-9]+$/.test(seed) && /^[0-9]+$/.test(n);
}

/** An id for a Gemini call that came without one. */
export function geminiCallId(ctx: ResponseContext, n: number): string {
  const seed = idSeed(ctx);
  return `call_${seed.slice(0, Math.min(seed.length, 16))}_${n}`;
}

/** `id` when it already has the client's prefix, else a prefixed id. */
export function nativeId(prefix: string, id: string, ctx: ResponseContext): string {
  if (id.startsWith(prefix)) return id;
  let tail = "";
  for (const c of id) if (isAsciiAlphanumeric(c)) tail += c;
  return `${prefix}${tail === "" ? idSeed(ctx) : tail}`;
}

/** `decode`: an upstream response body of `protocol` as the IR, or a Refusal (`translation_invalid_upstream`). */
export function decodeResponse(protocol: Protocol, body: Json, ctx: ResponseContext): Response {
  const raw = protocol === "gemini" ? get(body, "usageMetadata") : get(body, "usage");
  const response: Response = {
    id: "",
    model: "",
    output: [],
    finish: "other",
    stopSequence: undefined,
    usage: readUsage(protocol, isObject(raw) ? raw : {}),
  };
  switch (protocol) {
    case "open_ai_chat":
      decodeChat(body, response);
      break;
    case "open_ai_responses":
      decodeResponses(body, response);
      break;
    case "anthropic_messages":
      decodeAnthropic(body, response);
      break;
    case "gemini":
      decodeGemini(body, response, ctx);
      break;
    default:
      throw upstream("protocol");
  }
  response.finish = finishWithCalls(
    response.finish,
    response.output.some((o) => o.kind === "call"),
  );
  return response;
}

function decodeChat(body: Json, r: Response): void {
  r.id = s(body, "id") ?? "";
  r.model = s(body, "model") ?? "";
  const choices = get(body, "choices");
  if (!isArray(choices) || choices.length !== 1) throw upstream("choices");
  const choice = choices[0] as Json;
  const m = get(choice, "message");
  if (m === undefined) throw upstream("message");
  for (const key of ["reasoning_content", "reasoning"]) {
    const t = s(m, key);
    if (t !== undefined && t !== "") r.output.push({ kind: "reasoning", thought: { text: t, carrier: Carrier.empty("open_ai_chat") } });
  }
  const content = get(m, "content");
  if (typeof content === "string") {
    if (content !== "") r.output.push({ kind: "text", text: content });
  } else if (isArray(content)) {
    for (const part of content) {
      const t = s(part, "text") ?? s(part, "refusal");
      if (t !== undefined) r.output.push({ kind: "text", text: t });
    }
  }
  const refusal = s(m, "refusal");
  if (refusal !== undefined && refusal !== "") r.output.push({ kind: "text", text: refusal });
  const audio = get(m, "audio");
  if (audio !== undefined && audio !== null) throw upstream("message.audio");
  const calls = get(m, "tool_calls");
  for (const call of isArray(calls) ? calls : []) {
    const typ = s(call, "type");
    if (typ !== undefined && typ !== "function") throw upstream("message.tool_calls");
    const f = get(call, "function");
    if (f === undefined) throw upstream("tool_calls");
    const id = s(call, "id");
    if (id === undefined) throw upstream("tool_calls.id");
    const name = s(f, "name");
    if (name === undefined) throw upstream("tool_calls.name");
    r.output.push({ kind: "call", call: { id, name, arguments: s(f, "arguments") ?? "", signature: undefined } });
  }
  r.finish = chatFinish(s(choice, "finish_reason") ?? "stop");
}

function decodeResponses(body: Json, r: Response): void {
  r.id = s(body, "id") ?? "";
  r.model = s(body, "model") ?? "";
  const items = get(body, "output");
  if (!isArray(items)) throw upstream("output");
  for (const item of items) {
    switch (s(item, "type")) {
      case "reasoning":
        r.output.push({ kind: "reasoning", thought: responsesThought(item) });
        break;
      case "message": {
        const content = get(item, "content");
        for (const part of isArray(content) ? content : []) {
          const typ = s(part, "type");
          if (typ === "output_text") r.output.push({ kind: "text", text: s(part, "text") ?? "" });
          else if (typ === "refusal") r.output.push({ kind: "text", text: s(part, "refusal") ?? "" });
          else throw upstream("output.message.content");
        }
        break;
      }
      case "function_call": {
        const id = s(item, "call_id");
        if (id === undefined) throw upstream("output.call_id");
        const name = s(item, "name");
        if (name === undefined) throw upstream("output.name");
        r.output.push({ kind: "call", call: { id, name, arguments: s(item, "arguments") ?? "", signature: undefined } });
        break;
      }
      default:
        throw upstream("output.type");
    }
  }
  r.finish = responsesFinish(s(body, "status") ?? "completed", asStr(pointer(body, "/incomplete_details/reason")));
}

/** A Responses reasoning item: its summary text, and its encrypted content as the carrier. */
export function responsesThought(item: Json): Thought {
  const summary = get(item, "summary");
  const parts: string[] = [];
  for (const p of isArray(summary) ? summary : []) {
    const t = s(p, "text");
    if (t !== undefined) parts.push(t);
  }
  const text = parts.join("\n\n");
  const e = s(item, "encrypted_content");
  return { text: text === "" ? undefined : text, carrier: e === undefined ? undefined : new Carrier("open_ai_responses", { e }) };
}

function decodeAnthropic(body: Json, r: Response): void {
  r.id = s(body, "id") ?? "";
  r.model = s(body, "model") ?? "";
  const blocks = get(body, "content");
  if (!isArray(blocks)) throw upstream("content");
  for (const b of blocks) {
    switch (s(b, "type")) {
      case "text":
        r.output.push({ kind: "text", text: s(b, "text") ?? "" });
        break;
      case "thinking": {
        const text = s(b, "thinking") ?? "";
        r.output.push({
          kind: "reasoning",
          thought: { text: text === "" ? undefined : text, carrier: new Carrier("anthropic_messages", { t: text, s: s(b, "signature") ?? "" }) },
        });
        break;
      }
      case "redacted_thinking":
        r.output.push({ kind: "reasoning", thought: { text: undefined, carrier: new Carrier("anthropic_messages", { r: s(b, "data") ?? "" }) } });
        break;
      case "tool_use": {
        const given = get(b, "input");
        const input = given === undefined ? {} : given;
        const id = s(b, "id");
        if (id === undefined) throw upstream("content.id");
        const name = s(b, "name");
        if (name === undefined) throw upstream("content.name");
        r.output.push({ kind: "call", call: { id, name, arguments: toJsonString(input), signature: undefined } });
        break;
      }
      default:
        throw upstream("content.type");
    }
  }
  r.finish = anthropicFinish(s(body, "stop_reason") ?? "end_turn");
  r.stopSequence = s(body, "stop_sequence");
}

function decodeGemini(body: Json, r: Response, ctx: ResponseContext): void {
  r.id = s(body, "responseId") ?? "";
  r.model = s(body, "modelVersion") ?? "";
  const list = get(body, "candidates");
  const candidates = isArray(list) ? list : [];
  if (candidates.length === 0) {
    if (pointer(body, "/promptFeedback/blockReason") !== undefined) {
      r.finish = "content_filter";
      return;
    }
    throw upstream("candidates");
  }
  if (candidates.length > 1) throw upstream("candidates");
  const candidate = candidates[0] as Json;
  let calls = 0;
  const parts = pointer(candidate, "/content/parts");
  for (const part of isArray(parts) ? parts : []) {
    const f = get(part, "functionCall");
    if (f !== undefined) {
      const stated = get(f, "args");
      const args = stated === undefined ? {} : stated;
      const given = s(f, "id");
      const id = given !== undefined && given !== "" ? given : geminiCallId(ctx, calls);
      const name = s(f, "name");
      if (name === undefined) throw upstream("functionCall.name");
      r.output.push({ kind: "call", call: { id, name, arguments: toJsonString(args), signature: s(part, "thoughtSignature") } });
      calls += 1;
      continue;
    }
    const t = s(part, "text");
    if (t !== undefined) {
      if (get(part, "thought") === true) {
        if (t !== "") r.output.push({ kind: "reasoning", thought: { text: t, carrier: undefined } });
      } else if (t !== "") {
        r.output.push({ kind: "text", text: t });
      }
    } else if (isObject(part) && Object.keys(part).every((k) => k === "thoughtSignature")) {
      // A bare signature part carries nothing a client needs.
    } else {
      throw upstream("content.parts");
    }
  }
  r.finish = geminiFinish(s(candidate, "finishReason") ?? "STOP");
}

// ----------------------------------------------------------------------------------- Render ----

/** The reasoning carriers a Chat client carries on its first call id: one carrier, or a `{"b": [...]}` list of several payloads. */
export function chatCarrier(carriers: readonly Carrier[]): Carrier | undefined {
  const kept = carriers.filter((c) => !c.isEmpty());
  if (kept.length === 0) return undefined;
  if (kept.length === 1) return kept[0];
  return new Carrier((kept[0] as Carrier).origin, { b: kept.map((c) => c.payload) });
}

/** The client id of a call: its signature, and the turn's carrier on the first. */
export function clientCallId(call: Pick<Call, "id" | "signature">, carrier: Carrier | undefined): string {
  const id = signedId(call.id, call.signature);
  return carrier !== undefined ? carrierId(id, carrier) : id;
}

/** The JSON object an Anthropic or Gemini client gets as call arguments. */
export function argumentsObject(args: Json): JsonObject {
  if (isObject(args)) return args;
  if (typeof args === "string") {
    if (rustTrim(args) === "") return {};
    let value: Json;
    try {
      value = parseStrict(args);
    } catch {
      throw new Refusal(code.UPSTREAM_ARGUMENTS, "arguments");
    }
    if (isObject(value)) return value;
  }
  throw new Refusal(code.UPSTREAM_ARGUMENTS, "arguments");
}

/** `render`: the IR as a client response of `client`. */
export function renderResponse(client: Protocol, upstreamProtocol: Protocol, r: Response, ctx: ResponseContext): JsonObject {
  const model = r.model === "" ? ctx.model : r.model;
  const id = r.id === "" ? idSeed(ctx) : r.id;
  const usage = renderUsage(client, r.usage);
  switch (client) {
    case "open_ai_chat": {
      let text = "";
      const reasoning: string[] = [];
      const carriers: Carrier[] = [];
      for (const o of r.output) {
        if (o.kind === "text") text += o.text;
        if (o.kind === "reasoning") {
          if (o.thought.text !== undefined) reasoning.push(o.thought.text);
          if (o.thought.carrier !== undefined) carriers.push(o.thought.carrier);
        }
      }
      let carrier = chatCarrier(carriers);
      const calls: Json[] = [];
      for (const o of r.output) {
        if (o.kind !== "call") continue;
        calls.push({ id: clientCallId(o.call, carrier), type: "function", function: { name: o.call.name, arguments: o.call.arguments } });
        carrier = undefined;
      }
      const message: JsonObject = { role: "assistant", content: text === "" && calls.length > 0 ? null : text };
      if (reasoning.length > 0) message.reasoning_content = reasoning.join("\n\n");
      if (calls.length > 0) message.tool_calls = calls;
      return {
        id: nativeId("chatcmpl-", id, ctx),
        object: "chat.completion",
        created: ctx.created,
        model,
        choices: [{ index: 0n, message, finish_reason: renderChatFinish(r.finish), logprobs: null }],
        usage,
      };
    }
    case "open_ai_responses": {
      const seed = idSeed(ctx);
      const items: JsonObject[] = [];
      r.output.forEach((o: Output, n: number) => {
        if (o.kind === "reasoning") {
          items.push(responsesReasoningItem(reasoningItemId(seed, n), o.thought));
        } else if (o.kind === "text") {
          const last = items[items.length - 1];
          const part = { type: "output_text", text: o.text, annotations: [] };
          if (last !== undefined && last.type === "message") (last.content as Json[]).push(part);
          else items.push({ type: "message", id: `msg_${seed}_${n}`, status: "completed", role: "assistant", content: [part] });
        } else {
          items.push({
            type: "function_call",
            id: `fc_${seed}_${n}`,
            call_id: clientCallId(o.call, undefined),
            name: o.call.name,
            arguments: o.call.arguments,
            status: "completed",
          });
        }
      });
      const [status, incomplete] = renderResponsesFinish(r.finish);
      return {
        id: nativeId("resp_", id, ctx),
        object: "response",
        created_at: ctx.created,
        status,
        incomplete_details: incomplete,
        error: null,
        model,
        output: items,
        usage,
      };
    }
    case "anthropic_messages": {
      const content: Json[] = [];
      for (const o of r.output) {
        if (o.kind === "text") content.push({ type: "text", text: o.text });
        else if (o.kind === "reasoning") {
          const block = anthropicThinking(o.thought, upstreamProtocol);
          if (block !== undefined) content.push(block);
        } else {
          content.push({ type: "tool_use", id: clientCallId(o.call, undefined), name: o.call.name, input: argumentsObject(o.call.arguments) });
        }
      }
      return {
        id: nativeId("msg_", id, ctx),
        type: "message",
        role: "assistant",
        model,
        content,
        stop_reason: renderAnthropicFinish(r.finish),
        stop_sequence: r.stopSequence ?? null,
        usage,
      };
    }
    case "gemini": {
      const parts: Json[] = [];
      for (const o of r.output) {
        if (o.kind === "text") parts.push({ text: o.text });
        else if (o.kind === "reasoning") {
          const p: JsonObject = { text: o.thought.text ?? "", thought: true };
          const c = o.thought.carrier;
          if (c !== undefined && !c.isEmpty()) p.thoughtSignature = c.encodeBytes();
          if (o.thought.text !== undefined || Object.hasOwn(p, "thoughtSignature")) parts.push(p);
        } else {
          parts.push({ functionCall: { id: o.call.id, name: o.call.name, args: argumentsObject(o.call.arguments) } });
        }
      }
      if (parts.length === 0) parts.push({ text: "" });
      return {
        candidates: [{ content: { role: "model", parts }, finishReason: renderGeminiFinish(r.finish), index: 0n }],
        usageMetadata: usage,
        modelVersion: model,
        responseId: id,
      };
    }
    default:
      throw upstream("protocol");
  }
}

export function responsesReasoningItem(id: string, th: Thought): JsonObject {
  const item: JsonObject = { type: "reasoning", id, summary: th.text === undefined ? [] : [{ type: "summary_text", text: th.text }] };
  if (th.carrier !== undefined) item.encrypted_content = th.carrier.encode();
  return item;
}

/** An Anthropic client's thinking block for reasoning from another protocol. */
export function anthropicThinking(th: Thought, upstreamProtocol: Protocol): JsonObject | undefined {
  const signature = (th.carrier ?? Carrier.empty(upstreamProtocol)).encode();
  if (th.text !== undefined) return { type: "thinking", thinking: th.text, signature };
  if (th.carrier !== undefined) return { type: "redacted_thinking", data: signature };
  return undefined;
}
