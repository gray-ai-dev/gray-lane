/**
 * Incremental stream translation (crates/gray-protocol/src/translate/stream.rs). The upstream
 * stream is decoded by the native `ProtocolStreamDecoder` (which validates it); the translator
 * turns each frame's canonical events and native payload into operations, and a client encoder
 * turns operations into client SSE bytes as they arrive.
 *
 * The bytes are what Rust writes: every JSON payload is `toJsonString` (serde_json's
 * `Value::to_string`: keys in byte order, integers as integers).
 */
import { type Json, type JsonObject, asStr, asU64, get, isArray, isObject, pointer, toJsonString } from "@gray/json";
import { PROJECTION_NODE_BYTES } from "../answer-projection.ts";
import { jsonHeapBytes, stringHeapBytes } from "../heap.ts";
import { STREAM_FRAGMENT_BYTES, argumentText, mergeJson, rawUsage } from "../stream.ts";
import type { CanonicalEvent, Protocol } from "../types.ts";
import { Carrier } from "./carrier.ts";
import { type Finish, type Thought, finishFromCanonical, finishWithCalls } from "./ir.ts";
import { Refusal, TRANSLATION_CODES as code } from "./refusal.ts";
import {
  type ResponseContext,
  anthropicThinking,
  argumentsObject,
  chatCarrier,
  clientCallId,
  geminiCallId,
  idSeed,
  nativeId,
  reasoningItemId,
  responsesReasoningItem,
  responsesThought,
} from "./response.ts";
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

function upstream(param: string): Refusal {
  return new Refusal(code.UPSTREAM, param);
}

type Op =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "reasoning"; readonly text: string }
  /** Ends a reasoning segment, with its opaque continuation data. */
  | { readonly kind: "reasoning_end"; readonly carrier: Carrier | undefined }
  | { readonly kind: "tool_start"; readonly key: bigint; readonly id: string; readonly name: string; readonly signature: string | undefined }
  | { readonly kind: "tool_args"; readonly key: bigint; readonly delta: string }
  | { readonly kind: "tool_end"; readonly key: bigint; readonly arguments: Json }
  | { readonly kind: "done" };

interface SeenTool {
  started: boolean;
  ended: boolean;
}

/**
 * What the translator keeps for each call (its upstream `SeenTool` and its client `ClientTool`, their
 * map entries and indexes) beyond their strings. Measured in workerd (gateway/measure/answer-heap.ts,
 * 2026-10-19, 16 streams of 128 calls whose arguments are `{}`, the translator kept with the decoder
 * against the decoder alone): 138.1 bytes a call translated to Messages, 135.2 to Chat (a Responses
 * client's items are weighed on their own).
 */
export const TRANSLATOR_CALL_BYTES = 140;

/** What an operation it queues while another call is open keeps beyond its strings: an object in a list, at the costs of the projection's nodes. */
export const TRANSLATOR_OP_BYTES = PROJECTION_NODE_BYTES.object + PROJECTION_NODE_BYTES.item;

/** What a queued operation keeps beyond `TRANSLATOR_OP_BYTES` (a complete call's arguments are the decoder's value, weighed there). */
function opHeap(op: Op): number {
  switch (op.kind) {
    case "text":
    case "reasoning":
      return TRANSLATOR_OP_BYTES + stringHeapBytes(op.text);
    case "tool_args":
      return TRANSLATOR_OP_BYTES + stringHeapBytes(op.delta);
    case "tool_start":
      return TRANSLATOR_OP_BYTES + stringHeapBytes(op.id) + stringHeapBytes(op.name) + (op.signature === undefined ? 0 : stringHeapBytes(op.signature));
    case "reasoning_end":
      return TRANSLATOR_OP_BYTES + (op.carrier === undefined ? 0 : carrierHeap(op.carrier));
    default:
      return TRANSLATOR_OP_BYTES;
  }
}

/** What a carrier keeps: its payload. */
function carrierHeap(carrier: Carrier): number {
  return PROJECTION_NODE_BYTES.object + jsonHeapBytes(carrier.payload);
}

/** A new string of `text` (its header and characters). */
function stringHeap(text: string): number {
  return PROJECTION_NODE_BYTES.string + stringHeapBytes(text);
}

/** A tool call as the client sees it. */
interface ClientTool {
  /** Chat `index`, Responses `output_index`, Anthropic block index. */
  index: bigint;
  itemId: string;
  callId: string;
  name: string;
  arguments: string;
  streamed: boolean;
}

function clientTool(fields: Partial<ClientTool>): ClientTool {
  return { index: 0n, itemId: "", callId: "", name: "", arguments: "", streamed: false, ...fields };
}

type Open = "text" | "thinking" | "tool";

const utf8 = new TextEncoder();

/** Translates one upstream stream into one client stream. */
export class StreamTranslator {
  private readonly upstream: Protocol;
  private readonly client: Protocol;
  private readonly ctx: ResponseContext;
  // Upstream state.
  private id = "";
  private model = "";
  private rawUsage: Json = {};
  private finish: Finish | undefined;
  private stopSequence: string | undefined;
  private readonly tools = new Map<bigint, SeenTool>();
  private readonly thinking = new Map<bigint, [string, string]>();
  private readonly reasoningText = new Map<bigint, boolean>();
  /** The ids of the Responses reasoning items already ended: a relay may send an item's done event again. */
  private readonly reasoningEnded = new Set<string>();
  private geminiParts = 0n;
  private geminiCalls = 0;
  // Operation ordering.
  private active: bigint | undefined;
  private queue: Op[] = [];
  private reasoningOpen = false;
  private calls = 0;
  private done = false;
  // Client state.
  private started = false;
  private sequence = 0n;
  private readonly clientTools = new Map<bigint, ClientTool>();
  private readonly carriers: Carrier[] = [];
  private open: [Open, bigint] | undefined;
  private openId = "";
  private openText = "";
  private nextIndex = 0n;
  private readonly items: Json[] = [];
  /** What the translator keeps, in heap bytes (`retainedBytes`); the queue's and the open text's part of it on their own. */
  private kept = 0;
  private queueHeap = 0;
  private openTextHeap = 0;
  private readonly thinkingHeap = new Map<bigint, number>();

  constructor(upstreamProtocol: Protocol, client: Protocol, ctx: ResponseContext) {
    this.upstream = upstreamProtocol;
    this.client = client;
    this.ctx = ctx;
  }

  /**
   * What the translator keeps of the stream so far, in the heap (the gateway weighs it with the frames
   * a stream holds, relay.ts): the operations queued while another call is open, each call's state and
   * the arguments text its client is given, a thinking block's text until it ends, the carriers a Chat
   * client's first call takes, and for a Responses client the open item's text and every item it ends
   * with (its terminal event repeats them). Strings at `stringHeapBytes`, each join at
   * `STREAM_FRAGMENT_BYTES`, values at `jsonHeapBytes`, the rest measured (`TRANSLATOR_CALL_BYTES`,
   * `TRANSLATOR_OP_BYTES`). A complete call's arguments are the decoder's value, weighed there.
   */
  retainedBytes(): number {
    return this.kept;
  }

  /** `text` joined onto a string the translator keeps: what the join adds. */
  private static joined(text: string): number {
    return text === "" ? 0 : STREAM_FRAGMENT_BYTES + stringHeapBytes(text);
  }

  private pushItem(item: Json): void {
    this.items.push(item);
    this.kept += PROJECTION_NODE_BYTES.item + jsonHeapBytes(item);
  }

  /** `text` joined onto the open Responses item's text. */
  private openTextJoined(text: string): void {
    const heap = StreamTranslator.joined(text);
    this.openTextHeap += heap;
    this.kept += heap;
  }

  /** A call as its client sees it: its own strings (its ids are new; its state is `TRANSLATOR_CALL_BYTES`, counted with its upstream state). */
  private setClientTool(key: bigint, tool: ClientTool): void {
    this.clientTools.set(key, tool);
    this.kept += stringHeap(tool.itemId) + stringHeap(tool.callId) + stringHeap(tool.name);
  }

  /** The next Responses `sequence_number`, for an error frame. */
  sequenceNumber(): bigint {
    return this.sequence;
  }

  /** Whether the client stream has its terminal frames. */
  isDone(): boolean {
    return this.done;
  }

  /**
   * `streams_call_arguments`: whether the client gets each call's arguments as the upstream streams
   * them, else whole, from the complete call, once it completes. A Responses upstream's complete
   * call is its done item, the one the Responses API's own clients run (Codex and the AI SDK run
   * each `response.output_item.done` item and never its argument deltas), and a relay's deltas may
   * fall short of it: yylx's gpt-6.1-sol sent only the end of each call's arguments as deltas on 10
   * of 18 streams (2026-10-17), which built into a client's call would be no call at all. The
   * gateway holds a translated stream from its first call to its end (`StreamStage.releasable`), so
   * the client gets the call no later for it.
   */
  streamsCallArguments(): boolean {
    return this.upstream !== "open_ai_responses";
  }

  /**
   * Translates events returned by the upstream `ProtocolStreamDecoder` (from `push`, `pushFrame`
   * or `finish`), returning the client bytes they produce. Each native frame's events end with
   * its `native` event. Throws a Refusal for upstream output outside the translation contract.
   */
  push(events: readonly CanonicalEvent[]): Uint8Array {
    const out: string[] = [];
    let rest = events;
    while (rest.length > 0) {
      const position = rest.findIndex((e) => e.type === "native");
      const end = position < 0 ? rest.length : position + 1;
      this.pushFrame(rest.slice(0, end), out);
      rest = rest.slice(end);
    }
    return utf8.encode(out.join(""));
  }

  private pushFrame(events: readonly CanonicalEvent[], out: string[]): void {
    const nativeEvent = events.find((e) => e.type === "native");
    const native = nativeEvent?.type === "native" ? nativeEvent.payload : undefined;
    if (native !== undefined) this.metadata(native);
    const ops: Op[] = [];
    let canonicalFinish: Finish | undefined;
    for (const event of events) {
      switch (event.type) {
        case "text_delta":
          if (event.text !== "") ops.push({ kind: "text", text: event.text });
          break;
        case "reasoning_delta":
          if (event.text !== "") ops.push({ kind: "reasoning", text: event.text });
          break;
        case "tool_call_delta":
          this.startTool(event.index, event.id, event.name, undefined, ops);
          if (event.arguments !== "" && this.streamsCallArguments()) ops.push({ kind: "tool_args", key: event.index, delta: event.arguments });
          break;
        case "tool_call_complete": {
          if (this.tools.get(event.index)?.ended === true) continue;
          const signature = native !== undefined ? this.geminiSignature(native, event.index) : undefined;
          this.startTool(event.index, event.id, event.name, signature, ops);
          this.seen(event.index).ended = true;
          ops.push({ kind: "tool_end", key: event.index, arguments: event.arguments });
          break;
        }
        case "finish":
          canonicalFinish = finishFromCanonical(event.reason);
          break;
        case "done":
          ops.push({ kind: "done" });
          break;
        case "error":
          throw upstream("error");
        default:
          break;
      }
    }
    if (native !== undefined) {
      const done = ops.findIndex((o) => o.kind === "done");
      const extra: Op[] = [];
      this.nativeOps(native, extra);
      // Native operations belong before the terminal operation.
      if (done >= 0) ops.splice(done, 0, ...extra);
      else ops.push(...extra);
    }
    if (this.finish === undefined) this.finish = canonicalFinish;
    for (const op of ops) this.emit(op, out);
  }

  private seen(key: bigint): SeenTool {
    let seen = this.tools.get(key);
    if (seen === undefined) {
      seen = { started: false, ended: false };
      this.tools.set(key, seen);
      this.kept += TRANSLATOR_CALL_BYTES;
    }
    return seen;
  }

  private metadata(v: Json): void {
    let id: Json | undefined;
    let model: Json | undefined;
    switch (this.upstream) {
      case "open_ai_chat":
        id = get(v, "id");
        model = get(v, "model");
        break;
      case "open_ai_responses":
        id = pointer(v, "/response/id");
        model = pointer(v, "/response/model");
        break;
      case "anthropic_messages":
        id = pointer(v, "/message/id");
        model = pointer(v, "/message/model");
        break;
      default:
        id = get(v, "responseId");
        model = get(v, "modelVersion");
    }
    if (this.id === "" && typeof id === "string") this.id = id;
    if (this.model === "" && typeof model === "string") this.model = model;
    const u = rawUsage(this.upstream, v);
    if (u !== undefined) this.rawUsage = mergeJson(this.rawUsage, u);
  }

  private startTool(key: bigint, id: string | null, name: string | null, signature: string | undefined, ops: Op[]): void {
    const seen = this.seen(key);
    if (seen.started) return;
    seen.started = true;
    if (name === null || name === "") throw upstream("tool name");
    let callId: string;
    if (id !== null && id !== "") {
      callId = id;
    } else {
      this.geminiCalls += 1;
      callId = geminiCallId(this.ctx, this.geminiCalls - 1);
    }
    this.calls += 1;
    ops.push({ kind: "tool_start", key, id: callId, name, signature });
  }

  private static geminiPartsOf(v: Json): Json[] | undefined {
    const candidates = get(v, "candidates");
    if (!isArray(candidates)) return undefined;
    const primary = candidates.find((c, position) => {
      const i = asU64(get(c, "index"));
      return i === undefined ? position === 0 : i === 0n;
    });
    if (primary === undefined) return undefined;
    const parts = pointer(primary, "/content/parts");
    return isArray(parts) ? parts : undefined;
  }

  private geminiSignature(v: Json, index: bigint): string | undefined {
    if (this.upstream !== "gemini") return undefined;
    if (index < this.geminiParts) return undefined;
    const local = index - this.geminiParts;
    const parts = StreamTranslator.geminiPartsOf(v);
    if (parts === undefined || local >= BigInt(parts.length)) return undefined;
    return asStr(get(parts[Number(local)], "thoughtSignature"));
  }

  /** Operations only the native payload carries, and the upstream finish. */
  private nativeOps(v: Json, ops: Op[]): void {
    const typ = asStr(get(v, "type")) ?? "";
    switch (this.upstream) {
      case "open_ai_chat": {
        const reason = asStr(pointer(v, "/choices/0/finish_reason"));
        if (reason !== undefined) this.finish = chatFinish(reason);
        break;
      }
      case "open_ai_responses": {
        const outputIndex = () => asU64(get(v, "output_index")) ?? 0n;
        switch (typ) {
          case "response.output_item.added": {
            const itemType = asStr(pointer(v, "/item/type"));
            if (itemType === "reasoning") this.reasoningText.set(outputIndex(), false);
            else if (itemType !== "message" && itemType !== "function_call") throw upstream("output_item.type");
            break;
          }
          case "response.reasoning_summary_text.delta":
          case "response.reasoning_text.delta":
            this.reasoningText.set(outputIndex(), true);
            break;
          case "response.reasoning_summary_part.added": {
            const i = outputIndex();
            if ((asU64(get(v, "summary_index")) ?? 0n) > 0n && this.reasoningText.get(i) === true) ops.push({ kind: "reasoning", text: "\n\n" });
            break;
          }
          // The decoder reads a reasoning item's done event sent again, its id and type as before,
          // as a repeat that adds nothing (yylx, 2026-10-17): the item ends once, so a client does
          // not get its reasoning twice nor send it back twice.
          case "response.output_item.done": {
            const item = get(v, "item") ?? null;
            if (asStr(get(item, "type")) !== "reasoning") break;
            const id = asStr(get(item, "id"));
            if (id !== undefined) {
              if (this.reasoningEnded.has(id)) break;
              this.reasoningEnded.add(id);
              this.kept += TRANSLATOR_OP_BYTES + stringHeap(id);
            }
            ops.push({ kind: "reasoning_end", carrier: responsesThought(item).carrier });
            break;
          }
          case "response.completed":
          case "response.incomplete":
            this.finish = responsesFinish(
              asStr(pointer(v, "/response/status")) ?? typ.replace(/^(?:response\.)+/, ""),
              asStr(pointer(v, "/response/incomplete_details/reason")),
            );
            break;
          default:
            break;
        }
        break;
      }
      case "anthropic_messages": {
        const i = asU64(get(v, "index")) ?? 0n;
        switch (typ) {
          case "content_block_start": {
            const block = get(v, "content_block") ?? null;
            const blockType = asStr(get(block, "type"));
            if (blockType === "text" || blockType === "tool_use") {
              // Carried by the canonical events.
            } else if (blockType === "thinking") {
              const state: [string, string] = [asStr(get(block, "thinking")) ?? "", asStr(get(block, "signature")) ?? ""];
              const heap = TRANSLATOR_OP_BYTES + stringHeap(state[0]) + stringHeap(state[1]);
              this.kept += heap - (this.thinkingHeap.get(i) ?? 0);
              this.thinkingHeap.set(i, heap);
              this.thinking.set(i, state);
            } else if (blockType === "redacted_thinking") {
              ops.push({ kind: "reasoning_end", carrier: new Carrier("anthropic_messages", { r: asStr(get(block, "data")) ?? "" }) });
            } else {
              throw upstream("content_block.type");
            }
            break;
          }
          case "content_block_delta": {
            const state = this.thinking.get(i);
            if (state !== undefined) {
              const deltaType = asStr(pointer(v, "/delta/type"));
              let text = "";
              if (deltaType === "thinking_delta") {
                text = asStr(pointer(v, "/delta/thinking")) ?? "";
                state[0] += text;
              } else if (deltaType === "signature_delta") {
                text = asStr(pointer(v, "/delta/signature")) ?? "";
                state[1] += text;
              }
              const heap = StreamTranslator.joined(text);
              this.kept += heap;
              this.thinkingHeap.set(i, (this.thinkingHeap.get(i) ?? 0) + heap);
            }
            break;
          }
          case "content_block_stop": {
            const state = this.thinking.get(i);
            if (state !== undefined) {
              this.thinking.delete(i);
              this.kept -= this.thinkingHeap.get(i) ?? 0;
              this.thinkingHeap.delete(i);
              ops.push({ kind: "reasoning_end", carrier: new Carrier("anthropic_messages", { t: state[0], s: state[1] }) });
            }
            break;
          }
          case "message_delta": {
            const reason = asStr(pointer(v, "/delta/stop_reason"));
            if (reason !== undefined) this.finish = anthropicFinish(reason);
            const stop = asStr(pointer(v, "/delta/stop_sequence"));
            if (stop !== undefined) this.stopSequence = stop;
            break;
          }
          default:
            break;
        }
        break;
      }
      default: {
        const parts = StreamTranslator.geminiPartsOf(v);
        if (parts !== undefined) {
          for (const part of parts) {
            const known = isObject(part) && Object.keys(part).every((k) => ["text", "thought", "thoughtSignature", "functionCall"].includes(k));
            if (!known) throw upstream("content.parts");
          }
          this.geminiParts += BigInt(parts.length);
        }
        const reason = asStr(pointer(v, "/candidates/0/finishReason"));
        if (reason !== undefined && reason !== "FINISH_REASON_UNSPECIFIED") this.finish = geminiFinish(reason);
        if (pointer(v, "/promptFeedback/blockReason") !== undefined) this.finish = "content_filter";
      }
    }
  }

  /** Orders operations for the client: one tool call at a time (others queue until it ends), and reasoning closed before anything else. */
  private emit(op: Op, out: string[]): void {
    if (this.active !== undefined) {
      const own = (op.kind === "tool_args" || op.kind === "tool_end") && op.key === this.active;
      if (!own) {
        if (op.kind === "done") throw upstream("tool call without completion");
        this.queue.push(op);
        const heap = opHeap(op);
        this.queueHeap += heap;
        this.kept += heap;
        return;
      }
    }
    if (this.reasoningOpen && op.kind !== "reasoning" && op.kind !== "reasoning_end") {
      const carrier = this.upstream === "open_ai_chat" ? Carrier.empty("open_ai_chat") : undefined;
      this.clientOp({ kind: "reasoning_end", carrier }, out);
    }
    let ended: bigint | undefined;
    if (op.kind === "tool_start") this.active = op.key;
    else if (op.kind === "tool_end") ended = op.key;
    this.clientOp(op, out);
    if (ended !== undefined && ended === this.active) {
      this.active = undefined;
      const queued = this.queue;
      this.queue = [];
      this.kept -= this.queueHeap;
      this.queueHeap = 0;
      for (const next of queued) this.emit(next, out);
    }
  }

  private clientOp(op: Op, out: string[]): void {
    if (this.done) return;
    if (op.kind === "reasoning") this.reasoningOpen = true;
    else if (op.kind === "reasoning_end") this.reasoningOpen = false;
    if (!this.started) {
      this.started = true;
      this.start(out);
    }
    switch (this.client) {
      case "open_ai_chat":
        this.chat(op, out);
        break;
      case "open_ai_responses":
        this.responses(op, out);
        break;
      case "anthropic_messages":
        this.anthropic(op, out);
        break;
      default:
        this.gemini(op, out);
    }
  }

  private modelLabel(): string {
    return this.model === "" ? this.ctx.model : this.model;
  }

  private rawId(): string {
    return this.id === "" ? idSeed(this.ctx) : this.id;
  }

  private finalFinish(): Finish {
    return finishWithCalls(this.finish ?? "other", this.calls > 0);
  }

  private tool(key: bigint): ClientTool {
    const tool = this.clientTools.get(key);
    if (tool === undefined) throw new Error("started tool");
    return tool;
  }

  private start(out: string[]): void {
    switch (this.client) {
      case "open_ai_chat":
        data(out, this.chatChunk({ role: "assistant", content: "" }, null));
        break;
      case "open_ai_responses":
        this.event(out, "response.created", { response: this.responsesObject("in_progress", null, null) });
        break;
      case "anthropic_messages":
        this.event(out, "message_start", {
          message: {
            id: nativeId("msg_", this.rawId(), this.ctx),
            type: "message",
            role: "assistant",
            model: this.modelLabel(),
            content: [],
            stop_reason: null,
            stop_sequence: null,
            usage: { input_tokens: 0n, output_tokens: 0n },
          },
        });
        break;
      default:
        break;
    }
  }

  // ------------------------------------------------------------------------------ Chat --

  private chatChunk(delta: Json, finish: Json): JsonObject {
    return {
      id: nativeId("chatcmpl-", this.rawId(), this.ctx),
      object: "chat.completion.chunk",
      created: this.ctx.created,
      model: this.modelLabel(),
      choices: [{ index: 0n, delta, finish_reason: finish }],
    };
  }

  private chat(op: Op, out: string[]): void {
    switch (op.kind) {
      case "text":
        data(out, this.chatChunk({ content: op.text }, null));
        break;
      case "reasoning":
        data(out, this.chatChunk({ reasoning_content: op.text }, null));
        break;
      case "reasoning_end":
        if (op.carrier !== undefined) {
          this.carriers.push(op.carrier);
          this.kept += PROJECTION_NODE_BYTES.item + carrierHeap(op.carrier);
        }
        break;
      case "tool_start": {
        const index = BigInt(this.clientTools.size);
        const carrier = index === 0n ? chatCarrier(this.carriers) : undefined;
        const callId = clientCallId({ id: op.id, signature: op.signature }, carrier);
        const delta = { tool_calls: [{ index, id: callId, type: "function", function: { name: op.name, arguments: "" } }] };
        data(out, this.chatChunk(delta, null));
        this.setClientTool(op.key, clientTool({ index }));
        break;
      }
      case "tool_args": {
        const tool = this.tool(op.key);
        tool.streamed = true;
        data(out, this.chatChunk({ tool_calls: [{ index: tool.index, function: { arguments: op.delta } }] }, null));
        break;
      }
      case "tool_end": {
        const tool = this.tool(op.key);
        if (!tool.streamed) {
          const text = argumentText(op.arguments);
          if (text !== "") data(out, this.chatChunk({ tool_calls: [{ index: tool.index, function: { arguments: text } }] }, null));
        }
        break;
      }
      case "done": {
        data(out, this.chatChunk({}, renderChatFinish(this.finalFinish())));
        // Only a client that asked for it gets the usage chunk, as natively; the upstream is always
        // asked, for billing.
        if (this.ctx.streamUsage) {
          const chunk = this.chatChunk({}, null);
          chunk.choices = [];
          chunk.usage = renderUsage("open_ai_chat", readUsage(this.upstream, this.rawUsage));
          data(out, chunk);
        }
        out.push("data: [DONE]\n\n");
        this.done = true;
        break;
      }
    }
  }

  // ------------------------------------------------------------------------- Responses --

  private responsesObject(status: string, incomplete: Json, usage: Json): JsonObject {
    return {
      id: nativeId("resp_", this.rawId(), this.ctx),
      object: "response",
      created_at: this.ctx.created,
      status,
      incomplete_details: incomplete,
      error: null,
      model: this.modelLabel(),
      output: [...this.items],
      usage,
    };
  }

  private event(out: string[], typ: string, payload: JsonObject): void {
    payload.type = typ;
    if (this.client === "open_ai_responses") {
      payload.sequence_number = this.sequence;
      this.sequence += 1n;
    }
    out.push(`event: ${typ}\ndata: ${toJsonString(payload)}\n\n`);
  }

  private responsesClose(out: string[], carrier: Carrier | undefined): void {
    const open = this.open;
    if (open === undefined) return;
    this.open = undefined;
    const [kind, index] = open;
    const id = this.openId;
    const text = this.openText;
    this.openId = "";
    this.openText = "";
    this.kept -= this.openTextHeap;
    this.openTextHeap = 0;
    if (kind === "text") {
      const part = { type: "output_text", text, annotations: [] };
      this.event(out, "response.output_text.done", { item_id: id, output_index: index, content_index: 0n, text });
      this.event(out, "response.content_part.done", { item_id: id, output_index: index, content_index: 0n, part });
      const item = { type: "message", id, status: "completed", role: "assistant", content: [part] };
      this.event(out, "response.output_item.done", { output_index: index, item });
      this.pushItem(item);
    } else if (kind === "thinking") {
      const part = { type: "summary_text", text };
      this.event(out, "response.reasoning_summary_text.done", { item_id: id, output_index: index, summary_index: 0n, text });
      this.event(out, "response.reasoning_summary_part.done", { item_id: id, output_index: index, summary_index: 0n, part });
      const item = responsesReasoningItem(id, { text: text === "" ? undefined : text, carrier });
      this.event(out, "response.output_item.done", { output_index: index, item });
      this.pushItem(item);
    }
  }

  private responsesOpen(out: string[], kind: Open): void {
    if (this.open?.[0] === kind) return;
    this.responsesClose(out, undefined);
    const index = this.nextIndex;
    this.nextIndex += 1n;
    const seed = idSeed(this.ctx);
    this.open = [kind, index];
    if (kind === "text") {
      this.openId = `msg_${seed}_${index}`;
      const item = { type: "message", id: this.openId, status: "in_progress", role: "assistant", content: [] };
      this.event(out, "response.output_item.added", { output_index: index, item });
      this.event(out, "response.content_part.added", {
        item_id: this.openId,
        output_index: index,
        content_index: 0n,
        part: { type: "output_text", text: "", annotations: [] },
      });
    } else if (kind === "thinking") {
      this.openId = reasoningItemId(seed, index);
      const item = { type: "reasoning", id: this.openId, summary: [] };
      this.event(out, "response.output_item.added", { output_index: index, item });
      this.event(out, "response.reasoning_summary_part.added", {
        item_id: this.openId,
        output_index: index,
        summary_index: 0n,
        part: { type: "summary_text", text: "" },
      });
    }
  }

  private responses(op: Op, out: string[]): void {
    switch (op.kind) {
      case "text": {
        this.responsesOpen(out, "text");
        const index = (this.open as [Open, bigint])[1];
        this.openText += op.text;
        this.openTextJoined(op.text);
        this.event(out, "response.output_text.delta", { item_id: this.openId, output_index: index, content_index: 0n, delta: op.text });
        break;
      }
      case "reasoning": {
        this.responsesOpen(out, "thinking");
        const index = (this.open as [Open, bigint])[1];
        this.openText += op.text;
        this.openTextJoined(op.text);
        this.event(out, "response.reasoning_summary_text.delta", { item_id: this.openId, output_index: index, summary_index: 0n, delta: op.text });
        break;
      }
      case "reasoning_end":
        if (this.open?.[0] === "thinking") {
          this.responsesClose(out, op.carrier);
        } else if (op.carrier !== undefined) {
          this.responsesClose(out, undefined);
          const index = this.nextIndex;
          this.nextIndex += 1n;
          const id = reasoningItemId(idSeed(this.ctx), index);
          const item = responsesReasoningItem(id, { text: undefined, carrier: op.carrier });
          this.event(out, "response.output_item.added", { output_index: index, item: { type: "reasoning", id, summary: [] } });
          this.event(out, "response.output_item.done", { output_index: index, item });
          this.pushItem(item);
        }
        break;
      case "tool_start": {
        this.responsesClose(out, undefined);
        const index = this.nextIndex;
        this.nextIndex += 1n;
        const callId = clientCallId({ id: op.id, signature: op.signature }, undefined);
        const itemId = `fc_${idSeed(this.ctx)}_${index}`;
        this.event(out, "response.output_item.added", {
          output_index: index,
          item: { type: "function_call", id: itemId, call_id: callId, name: op.name, arguments: "", status: "in_progress" },
        });
        this.setClientTool(op.key, clientTool({ index, itemId, callId, name: op.name }));
        break;
      }
      case "tool_args": {
        const tool = this.tool(op.key);
        tool.streamed = true;
        tool.arguments += op.delta;
        this.kept += StreamTranslator.joined(op.delta);
        this.event(out, "response.function_call_arguments.delta", { item_id: tool.itemId, output_index: tool.index, delta: op.delta });
        break;
      }
      case "tool_end": {
        const tool = this.tool(op.key);
        if (!tool.streamed) {
          tool.arguments = argumentText(op.arguments);
          this.kept += stringHeap(tool.arguments);
          if (tool.arguments !== "") {
            this.event(out, "response.function_call_arguments.delta", { item_id: tool.itemId, output_index: tool.index, delta: tool.arguments });
          }
        }
        const item = {
          type: "function_call",
          id: tool.itemId,
          call_id: tool.callId,
          name: tool.name,
          arguments: tool.arguments,
          status: "completed",
        };
        this.event(out, "response.function_call_arguments.done", {
          item_id: tool.itemId,
          output_index: tool.index,
          name: tool.name,
          arguments: tool.arguments,
        });
        this.event(out, "response.output_item.done", { output_index: tool.index, item });
        this.pushItem(item);
        break;
      }
      case "done": {
        this.responsesClose(out, undefined);
        const [status, incomplete] = renderResponsesFinish(this.finalFinish());
        const usage = renderUsage("open_ai_responses", readUsage(this.upstream, this.rawUsage));
        const response = this.responsesObject(status, incomplete, usage);
        this.event(out, status === "completed" ? "response.completed" : "response.incomplete", { response });
        this.done = true;
        break;
      }
    }
  }

  // ------------------------------------------------------------------------- Anthropic --

  private anthropicClose(out: string[]): void {
    const open = this.open;
    if (open === undefined) return;
    this.open = undefined;
    const [kind, index] = open;
    if (kind === "thinking") {
      const signature = Carrier.empty(this.upstream).encode();
      this.event(out, "content_block_delta", { index, delta: { type: "signature_delta", signature } });
    }
    this.event(out, "content_block_stop", { index });
  }

  private anthropicOpen(out: string[], kind: Open, block: Json): bigint {
    if (this.open !== undefined) {
      const [open, index] = this.open;
      if (open === kind && kind !== "tool") return index;
    }
    this.anthropicClose(out);
    const index = this.nextIndex;
    this.nextIndex += 1n;
    this.open = [kind, index];
    this.event(out, "content_block_start", { index, content_block: block });
    return index;
  }

  private anthropic(op: Op, out: string[]): void {
    switch (op.kind) {
      case "text": {
        const index = this.anthropicOpen(out, "text", { type: "text", text: "" });
        this.event(out, "content_block_delta", { index, delta: { type: "text_delta", text: op.text } });
        break;
      }
      case "reasoning": {
        const index = this.anthropicOpen(out, "thinking", { type: "thinking", thinking: "", signature: "" });
        this.event(out, "content_block_delta", { index, delta: { type: "thinking_delta", thinking: op.text } });
        break;
      }
      case "reasoning_end": {
        if (this.open !== undefined && this.open[0] === "thinking") {
          const index = this.open[1];
          const signature = (op.carrier ?? Carrier.empty(this.upstream)).encode();
          this.event(out, "content_block_delta", { index, delta: { type: "signature_delta", signature } });
          this.open = undefined;
          this.event(out, "content_block_stop", { index });
        } else {
          const thought: Thought = { text: undefined, carrier: op.carrier };
          const block = anthropicThinking(thought, this.upstream);
          if (block !== undefined) {
            this.anthropicOpen(out, "tool", block);
            this.anthropicClose(out);
          }
        }
        break;
      }
      case "tool_start": {
        const callId = clientCallId({ id: op.id, signature: op.signature }, undefined);
        const index = this.anthropicOpen(out, "tool", { type: "tool_use", id: callId, name: op.name, input: {} });
        this.setClientTool(op.key, clientTool({ index }));
        break;
      }
      case "tool_args": {
        const tool = this.tool(op.key);
        tool.streamed = true;
        tool.arguments += op.delta;
        this.kept += StreamTranslator.joined(op.delta);
        this.event(out, "content_block_delta", { index: tool.index, delta: { type: "input_json_delta", partial_json: op.delta } });
        break;
      }
      case "tool_end": {
        const tool = this.tool(op.key);
        if (tool.streamed) {
          argumentsObject(tool.arguments);
        } else {
          const object = argumentsObject(op.arguments);
          if (Object.keys(object).length > 0) {
            this.event(out, "content_block_delta", {
              index: tool.index,
              delta: { type: "input_json_delta", partial_json: toJsonString(object) },
            });
          }
        }
        this.anthropicClose(out);
        break;
      }
      case "done": {
        this.anthropicClose(out);
        const usage = renderUsage("anthropic_messages", readUsage(this.upstream, this.rawUsage));
        const delta = { stop_reason: renderAnthropicFinish(this.finalFinish()), stop_sequence: this.stopSequence ?? null };
        this.event(out, "message_delta", { delta, usage });
        this.event(out, "message_stop", {});
        this.done = true;
        break;
      }
    }
  }

  // ---------------------------------------------------------------------------- Gemini --

  private geminiChunk(parts: Json): JsonObject {
    return {
      candidates: [{ content: { role: "model", parts }, index: 0n }],
      modelVersion: this.modelLabel(),
      responseId: this.rawId(),
    };
  }

  private gemini(op: Op, out: string[]): void {
    switch (op.kind) {
      case "text":
        data(out, this.geminiChunk([{ text: op.text }]));
        break;
      case "reasoning":
        data(out, this.geminiChunk([{ text: op.text, thought: true }]));
        break;
      case "reasoning_end":
        if (op.carrier !== undefined && !op.carrier.isEmpty()) {
          data(out, this.geminiChunk([{ text: "", thought: true, thoughtSignature: op.carrier.encodeBytes() }]));
        }
        break;
      case "tool_start":
        this.setClientTool(op.key, clientTool({ callId: op.id, name: op.name }));
        break;
      case "tool_args": {
        const tool = this.tool(op.key);
        tool.streamed = true;
        tool.arguments += op.delta;
        this.kept += StreamTranslator.joined(op.delta);
        break;
      }
      case "tool_end": {
        const tool = this.tool(op.key);
        const args = tool.streamed ? argumentsObject(tool.arguments) : argumentsObject(op.arguments);
        data(out, this.geminiChunk([{ functionCall: { id: tool.callId, name: tool.name, args } }]));
        break;
      }
      case "done": {
        const chunk = this.geminiChunk([{ text: "" }]);
        ((chunk.candidates as JsonObject[])[0] as JsonObject).finishReason = renderGeminiFinish(this.finalFinish());
        chunk.usageMetadata = renderUsage("gemini", readUsage(this.upstream, this.rawUsage));
        data(out, chunk);
        this.done = true;
        break;
      }
    }
  }
}

function data(out: string[], payload: Json): void {
  out.push(`data: ${toJsonString(payload)}\n\n`);
}

/** `error_frame`: the client protocol's native error frame for a stream that fails after bytes were released. */
export function errorFrame(client: Protocol, failure: string, sequenceNumber: bigint): Uint8Array {
  const out: string[] = [];
  switch (client) {
    case "open_ai_chat":
      data(out, { error: { message: failure, type: "upstream_error", code: failure } });
      break;
    case "open_ai_responses":
      out.push(
        `event: error\ndata: ${toJsonString({ type: "error", code: failure, message: failure, param: null, sequence_number: sequenceNumber })}\n\n`,
      );
      break;
    case "anthropic_messages":
      out.push(`event: error\ndata: ${toJsonString({ type: "error", error: { type: "api_error", message: failure } })}\n\n`);
      break;
    default:
      data(out, { error: { code: 502n, message: failure, status: "UNAVAILABLE" } });
  }
  return utf8.encode(out.join(""));
}
