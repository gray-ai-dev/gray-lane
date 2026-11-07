/**
 * Upstream request encoders (crates/gray-protocol/src/translate/encode.rs). Each one renders the
 * whole IR or refuses: a feature the target cannot carry is either an advisory drop (recorded in
 * `Request.dropped`) or a refusal, never a silent loss.
 *
 * Integers in the bodies are `bigint`, so `toJsonString` writes them as serde_json does.
 */
import { type Json, type JsonObject, asU64, get, isObject, parseStrict, pointer, setMember } from "@gray/json";
import { rustTrim } from "../text.ts";
import type { Protocol } from "../types.ts";
import {
  type Call,
  type Image,
  type JsonNumber,
  type Part,
  type Request,
  type Thought,
  imageUrl,
  reasoningBudget,
  reasoningEffort,
  resultHasImage,
  resultText,
} from "./ir.ts";
import { Refusal, TRANSLATION_CODES as code } from "./refusal.ts";

/** Default output cap when the client gave none and the target requires one (encode.rs `DEFAULT_MAX_TOKENS`). */
const DEFAULT_MAX_TOKENS = 4096n;
/** Anthropic's smallest thinking budget (encode.rs `MIN_THINKING_BUDGET`). */
const MIN_THINKING_BUDGET = 1024n;
/** Gemini's skip value for a function call that has no thought signature. */
export const SKIP_SIGNATURE = "skip_thought_signature_validator";

function feature(param: string): Refusal {
  return new Refusal(code.FEATURE, param);
}

/** `request`: renders the IR as a request body of `to`, or throws a Refusal. */
export function encodeRequest(to: Protocol, req: Request): JsonObject {
  switch (to) {
    case "open_ai_chat":
      return chat(req);
    case "open_ai_responses":
      return responses(req);
    case "anthropic_messages":
      return anthropic(req);
    case "gemini":
      return gemini(req);
    default:
      throw feature("protocol");
  }
}

function origin(thought: Thought): Protocol | undefined {
  return thought.carrier?.origin;
}

function put(o: JsonObject, key: string, v: Json | undefined): void {
  if (v !== undefined) setMember(o, key, v);
}

function argumentsObject(call: Call): JsonObject {
  if (rustTrim(call.arguments) === "") return {};
  let value: Json;
  try {
    value = parseStrict(call.arguments);
  } catch {
    throw new Refusal(code.INVALID, `tool_calls.${call.id}.arguments`);
  }
  if (!isObject(value)) throw new Refusal(code.INVALID, `tool_calls.${call.id}.arguments`);
  return value;
}

function dropUnsigned(req: Request, keep: Protocol): void {
  const lost = req.turns.some((t) => t.parts.some((p) => p.kind === "reasoning" && origin(p.thought) !== keep));
  if (lost) req.dropped.add("reasoning_signature");
}

function droppedSampling(req: Request, names: readonly string[]): void {
  for (const name of names) {
    let present = false;
    switch (name) {
      case "seed":
        present = req.seed !== undefined;
        break;
      case "presence_penalty":
        present = req.presencePenalty !== undefined;
        break;
      case "frequency_penalty":
        present = req.frequencyPenalty !== undefined;
        break;
      case "top_k":
        present = req.topK !== undefined;
        break;
      case "prompt_cache_key":
        present = req.promptCacheKey !== undefined;
        break;
      case "prompt_cache_retention":
        present = req.promptCacheRetention !== undefined;
        break;
    }
    if (present) req.dropped.add(name);
  }
}

function resultErrors(req: Request): void {
  if (req.turns.some((t) => t.parts.some((p) => p.kind === "result" && p.result.isError))) req.dropped.add("tool_result_is_error");
}

function texts(parts: readonly Part[]): string {
  return parts
    .filter((p): p is { kind: "text"; text: string } => p.kind === "text")
    .map((p) => p.text)
    .join("\n\n");
}

// ------------------------------------------------------------------------------------- Chat ----

function chat(req: Request): JsonObject {
  dropUnsigned(req, "open_ai_chat");
  droppedSampling(req, ["top_k"]);
  resultErrors(req);
  const messages: Json[] = [];
  for (const s of req.system) messages.push({ role: "system", content: s });
  for (const turn of req.turns) {
    switch (turn.role) {
      case "system":
        messages.push({ role: "system", content: texts(turn.parts) });
        break;
      case "user": {
        const parts: JsonObject[] = [];
        for (const part of turn.parts) {
          switch (part.kind) {
            case "result":
              if (resultHasImage(part.result)) throw feature("messages.tool_result.image");
              messages.push({ role: "tool", tool_call_id: part.result.id, content: resultText(part.result, "\n") });
              break;
            case "text":
              parts.push({ type: "text", text: part.text });
              break;
            case "image":
              parts.push({ type: "image_url", image_url: { url: imageUrl(part.image) } });
              break;
            case "call":
            case "reasoning":
              throw new Refusal(code.INVALID, "messages");
          }
        }
        if (parts.length === 0) break;
        const only = parts.length === 1 ? (parts[0] as JsonObject) : undefined;
        const content: Json = only !== undefined && get(only, "type") === "text" ? (get(only, "text") ?? null) : parts;
        messages.push({ role: "user", content });
        break;
      }
      case "assistant": {
        const m: JsonObject = { role: "assistant" };
        const text = turn.parts
          .filter((p): p is { kind: "text"; text: string } => p.kind === "text")
          .map((p) => p.text)
          .join("");
        const reasoning: string[] = [];
        const calls: Json[] = [];
        for (const p of turn.parts) {
          if (p.kind === "reasoning" && origin(p.thought) === "open_ai_chat" && p.thought.text !== undefined) reasoning.push(p.thought.text);
          if (p.kind === "call") {
            calls.push({ id: p.call.id, type: "function", function: { name: p.call.name, arguments: p.call.arguments } });
          }
        }
        if (turn.parts.some((p) => p.kind === "image" || p.kind === "result")) throw new Refusal(code.INVALID, "messages");
        m.content = text === "" && calls.length > 0 ? null : text;
        if (reasoning.length > 0) m.reasoning_content = reasoning.join("");
        if (calls.length > 0) m.tool_calls = calls;
        messages.push(m);
        break;
      }
    }
  }
  const o: JsonObject = { model: req.model, messages };
  if (req.tools.length > 0) {
    o.tools = req.tools.map((t) => {
      const f: JsonObject = { name: t.name };
      put(f, "description", t.description);
      f.parameters = t.parameters;
      put(f, "strict", t.strict);
      return { type: "function", function: f };
    });
  }
  if (req.toolChoice !== undefined) {
    const c = req.toolChoice;
    o.tool_choice = c.kind === "named" ? { type: "function", function: { name: c.name } } : c.kind;
  }
  if (req.tools.length > 0) put(o, "parallel_tool_calls", req.parallelToolCalls);
  const format = req.format;
  if (format !== undefined) {
    if (format.kind === "text") o.response_format = { type: "text" };
    else if (format.kind === "json_object") o.response_format = { type: "json_object" };
    else {
      const s: JsonObject = { name: format.name, schema: format.schema };
      put(s, "strict", format.strict);
      put(s, "description", format.description);
      o.response_format = { type: "json_schema", json_schema: s };
    }
  }
  if (req.reasoning !== undefined) {
    if (req.reasoning.kind === "disabled") req.dropped.add("reasoning");
    else o.reasoning_effort = reasoningEffort(req.reasoning) ?? null;
  }
  putNumber(o, "temperature", req.temperature);
  putNumber(o, "top_p", req.topP);
  putNumber(o, "seed", req.seed);
  putNumber(o, "presence_penalty", req.presencePenalty);
  putNumber(o, "frequency_penalty", req.frequencyPenalty);
  if (req.stop.length > 0) {
    if (req.stop.length > 4) throw new Refusal(code.VALUE, "stop");
    o.stop = [...req.stop];
  }
  put(o, "max_completion_tokens", req.maxTokens);
  if (req.stream) {
    o.stream = true;
    o.stream_options = { include_usage: true };
  }
  put(o, "prompt_cache_key", req.promptCacheKey);
  put(o, "prompt_cache_retention", req.promptCacheRetention);
  return o;
}

function putNumber(o: JsonObject, key: string, v: JsonNumber | undefined): void {
  if (v !== undefined) setMember(o, key, v);
}

// -------------------------------------------------------------------------------- Responses ----

function responsesParts(parts: readonly Part[]): JsonObject[] {
  const out: JsonObject[] = [];
  for (const p of parts) {
    if (p.kind === "text") out.push({ type: "input_text", text: p.text });
    else if (p.kind === "image") out.push({ type: "input_image", image_url: imageUrl(p.image), detail: "auto" });
  }
  return out;
}

function responses(req: Request): JsonObject {
  dropUnsigned(req, "open_ai_responses");
  droppedSampling(req, ["seed", "presence_penalty", "frequency_penalty", "top_k"]);
  resultErrors(req);
  if (req.stop.length > 0) throw feature("stop");
  const input: Json[] = [];
  const o: JsonObject = { model: req.model };
  if (req.system.length === 1) {
    o.instructions = req.system[0] as string;
  } else if (req.system.length > 1) {
    input.push({ type: "message", role: "system", content: req.system.map((s) => ({ type: "input_text", text: s })) });
  }
  for (const turn of req.turns) {
    switch (turn.role) {
      case "system":
        input.push({ type: "message", role: "system", content: responsesParts(turn.parts) });
        break;
      case "user": {
        for (const part of turn.parts) {
          if (part.kind !== "result") continue;
          const r = part.result;
          const output: Json = resultHasImage(r)
            ? r.content.map((c): Json =>
                c.kind === "text" ? { type: "input_text", text: c.text } : { type: "input_image", image_url: imageUrl(c.image), detail: "auto" },
              )
            : resultText(r, "\n");
          input.push({ type: "function_call_output", call_id: r.id, output });
        }
        const parts = responsesParts(turn.parts);
        if (parts.length > 0) input.push({ type: "message", role: "user", content: parts });
        break;
      }
      case "assistant":
        for (const part of turn.parts) {
          switch (part.kind) {
            case "text":
              if (part.text !== "") input.push({ type: "message", role: "assistant", content: part.text });
              break;
            case "call":
              input.push({ type: "function_call", call_id: part.call.id, name: part.call.name, arguments: part.call.arguments });
              break;
            case "reasoning": {
              const c = part.thought.carrier;
              if (c === undefined || c.origin !== "open_ai_responses") break;
              const t = part.thought.text;
              const summary: Json[] = t !== undefined && t !== "" ? [{ type: "summary_text", text: t }] : [];
              const item: JsonObject = { type: "reasoning", summary };
              const e = c.getStr("e");
              if (e !== undefined) item.encrypted_content = e;
              input.push(item);
              break;
            }
            case "image":
            case "result":
              throw new Refusal(code.INVALID, "input");
          }
        }
        break;
    }
  }
  o.input = input;
  if (req.tools.length > 0) {
    o.tools = req.tools.map((t) => {
      const f: JsonObject = { type: "function", name: t.name };
      put(f, "description", t.description);
      f.parameters = t.parameters;
      // Responses defaults `strict` to true, which rejects many ordinary schemas; the other
      // protocols default to false.
      f.strict = t.strict ?? false;
      return f;
    });
  }
  if (req.toolChoice !== undefined) {
    const c = req.toolChoice;
    o.tool_choice = c.kind === "named" ? { type: "function", name: c.name } : c.kind;
  }
  if (req.tools.length > 0) put(o, "parallel_tool_calls", req.parallelToolCalls);
  const format = req.format;
  if (format !== undefined) {
    let f: JsonObject;
    if (format.kind === "text") f = { type: "text" };
    else if (format.kind === "json_object") f = { type: "json_object" };
    else {
      f = { type: "json_schema", name: format.name, schema: format.schema, strict: format.strict ?? false };
      put(f, "description", format.description);
    }
    o.text = { format: f };
  }
  if (req.reasoning !== undefined) {
    if (req.reasoning.kind === "disabled") {
      req.dropped.add("reasoning");
    } else {
      o.reasoning = { effort: reasoningEffort(req.reasoning) ?? null, summary: "auto" };
      o.include = ["reasoning.encrypted_content"];
    }
  }
  putNumber(o, "temperature", req.temperature);
  putNumber(o, "top_p", req.topP);
  put(o, "max_output_tokens", req.maxTokens);
  o.store = false;
  if (req.stream) o.stream = true;
  put(o, "prompt_cache_key", req.promptCacheKey);
  put(o, "prompt_cache_retention", req.promptCacheRetention);
  return o;
}

// -------------------------------------------------------------------------------- Anthropic ----

function anthropicImage(i: Image): JsonObject {
  return i.kind === "data"
    ? { type: "image", source: { type: "base64", media_type: i.mediaType, data: i.data } }
    : { type: "image", source: { type: "url", url: i.url } };
}

/** The native thinking block an Anthropic carrier stands for. */
function anthropicThinking(th: Thought): JsonObject | undefined {
  const c = th.carrier;
  if (c === undefined || c.origin !== "anthropic_messages") return undefined;
  const data = c.getStr("r");
  if (data !== undefined) return { type: "redacted_thinking", data };
  const signature = c.getStr("s");
  if (signature === undefined) return undefined;
  const text = c.getStr("t") ?? th.text ?? "";
  return { type: "thinking", thinking: text, signature };
}

/** Merges consecutive messages of one role (each protocol alternates). */
function mergeRoles(messages: Array<[string, Json[]]>): Array<[string, Json[]]> {
  const out: Array<[string, Json[]]> = [];
  for (const [role, parts] of messages) {
    if (parts.length === 0) continue;
    const last = out[out.length - 1];
    if (last !== undefined && last[0] === role) last[1].push(...parts);
    else out.push([role, parts]);
  }
  return out;
}

function asF64(n: JsonNumber): number {
  return typeof n === "bigint" ? Number(n) : n;
}

function anthropic(req: Request): JsonObject {
  dropUnsigned(req, "anthropic_messages");
  droppedSampling(req, ["seed", "presence_penalty", "frequency_penalty", "prompt_cache_key", "prompt_cache_retention"]);
  const messages: Array<[string, Json[]]> = [];
  for (const turn of req.turns) {
    const blocks: Json[] = [];
    switch (turn.role) {
      case "system":
        throw feature("messages.system");
      case "user":
        for (const part of turn.parts) {
          if (part.kind !== "result") continue;
          const r = part.result;
          const b: JsonObject = { type: "tool_result", tool_use_id: r.id };
          b.content = resultHasImage(r)
            ? r.content.map((c): Json => (c.kind === "text" ? { type: "text", text: c.text } : anthropicImage(c.image)))
            : resultText(r, "\n");
          if (r.isError) b.is_error = true;
          blocks.push(b);
        }
        for (const part of turn.parts) {
          if (part.kind === "text" && part.text !== "") blocks.push({ type: "text", text: part.text });
          else if (part.kind === "image") blocks.push(anthropicImage(part.image));
        }
        break;
      case "assistant":
        for (const part of turn.parts) {
          switch (part.kind) {
            case "text":
              if (part.text !== "") blocks.push({ type: "text", text: part.text });
              break;
            case "reasoning": {
              const block = anthropicThinking(part.thought);
              if (block !== undefined) blocks.push(block);
              break;
            }
            case "call":
              blocks.push({ type: "tool_use", id: part.call.id, name: part.call.name, input: argumentsObject(part.call) });
              break;
            case "image":
            case "result":
              throw new Refusal(code.INVALID, "messages");
          }
        }
        break;
    }
    messages.push([turn.role === "assistant" ? "assistant" : "user", blocks]);
  }
  const o: JsonObject = { model: req.model };
  if (req.system.length > 0) o.system = req.system.map((s) => ({ type: "text", text: s }));
  o.messages = mergeRoles(messages).map(([role, content]) => ({ role, content }));
  const maxTokens = req.maxTokens ?? DEFAULT_MAX_TOKENS;
  o.max_tokens = maxTokens;
  if (req.tools.length > 0) {
    if (req.tools.some((t) => t.strict === true)) req.dropped.add("tool_strict");
    o.tools = req.tools.map((t) => {
      const f: JsonObject = { name: t.name };
      put(f, "description", t.description);
      f.input_schema = t.parameters;
      return f;
    });
    const c = req.toolChoice;
    const choice: JsonObject =
      c === undefined || c.kind === "auto"
        ? { type: "auto" }
        : c.kind === "required"
          ? { type: "any" }
          : c.kind === "none"
            ? { type: "none" }
            : { type: "tool", name: c.name };
    if (req.parallelToolCalls === false && choice.type !== "none") choice.disable_parallel_tool_use = true;
    if (req.toolChoice !== undefined || req.parallelToolCalls === false) o.tool_choice = choice;
  } else if (req.toolChoice?.kind === "required" || req.toolChoice?.kind === "named") {
    throw new Refusal(code.INVALID, "tool_choice");
  }
  if (req.reasoning !== undefined) {
    if (req.reasoning.kind === "disabled") o.thinking = { type: "disabled" };
    else o.thinking = { type: "enabled", budget_tokens: reasoningBudget(req.reasoning) ?? MIN_THINKING_BUDGET };
  }
  for (const d of fitThinking(o, maxTokens)) req.dropped.add(d);
  // Decided here, not after the gateway's output cap: that cap only lowers the budget or removes
  // thinking, never enables it, and a refusal here lets the gateway try the rule's next upstream
  // protocol.
  if (pointer(o, "/thinking/type") === "enabled") thinkingConflicts(req);
  const format = req.format;
  if (format?.kind === "json_object") throw feature("response_format");
  if (format?.kind === "json_schema") o.output_config = { format: { type: "json_schema", schema: format.schema } };
  if (req.temperature !== undefined && asF64(req.temperature) > 1) throw new Refusal(code.VALUE, "temperature");
  // Anthropic's current models reject a request that sets both temperature and top_p, which the
  // other protocols allow. A value of 1 asks for no change, so that one is left out and reported:
  // the upstream then applies its own default, which is not 1 on every model. Two real settings
  // cannot both be kept, and dropping one would change the client's sampling.
  const unset = (n: JsonNumber) => asF64(n) === 1;
  let temperature = req.temperature;
  let topP = req.topP;
  if (temperature !== undefined && topP !== undefined) {
    if (unset(topP)) {
      req.dropped.add("top_p");
      topP = undefined;
    } else if (unset(temperature)) {
      req.dropped.add("temperature");
      temperature = undefined;
    } else {
      throw new Refusal(code.VALUE, "top_p");
    }
  }
  putNumber(o, "temperature", temperature);
  putNumber(o, "top_p", topP);
  putNumber(o, "top_k", req.topK);
  if (req.stop.length > 0) o.stop_sequences = [...req.stop];
  if (req.stream) o.stream = true;
  return o;
}

/**
 * Refuses what Anthropic rejects while extended thinking is enabled: forced tool use, a
 * temperature other than 1, any `top_k`, and `top_p` below 0.95.
 */
function thinkingConflicts(req: Request): void {
  if (req.toolChoice?.kind === "required" || req.toolChoice?.kind === "named") throw feature("tool_choice");
  if (req.temperature !== undefined && asF64(req.temperature) !== 1) throw new Refusal(code.VALUE, "temperature");
  if (req.topK !== undefined) throw new Refusal(code.VALUE, "top_k");
  if (req.topP !== undefined && asF64(req.topP) < 0.95) throw new Refusal(code.VALUE, "top_p");
}

/** Keeps an Anthropic thinking budget below `max_tokens`, removing thinking when the cap cannot hold the minimum budget. */
function fitThinking(body: JsonObject, maxTokens: bigint): string[] {
  const budget = asU64(pointer(body, "/thinking/budget_tokens"));
  if (budget === undefined) return [];
  if (maxTokens <= MIN_THINKING_BUDGET) {
    delete body.thinking;
    return ["reasoning"];
  }
  const thinking = body.thinking as JsonObject;
  if (budget >= maxTokens) thinking.budget_tokens = maxTokens - 1n;
  else if (budget < MIN_THINKING_BUDGET) thinking.budget_tokens = MIN_THINKING_BUDGET;
  return [];
}

// ----------------------------------------------------------------------------------- Gemini ----

function gemini(req: Request): JsonObject {
  dropUnsigned(req, "gemini");
  droppedSampling(req, ["prompt_cache_key", "prompt_cache_retention"]);
  if (req.parallelToolCalls === false && req.tools.length > 0) throw feature("parallel_tool_calls");
  const contents: Array<[string, Json[]]> = [];
  for (const turn of req.turns) {
    const parts: Json[] = [];
    switch (turn.role) {
      case "system":
        throw feature("messages.system");
      case "user":
        for (const part of turn.parts) {
          if (part.kind !== "result") continue;
          const r = part.result;
          if (resultHasImage(r)) throw feature("tool_result.image");
          if (r.name === undefined) throw new Refusal(code.INVALID, "tool_result.name");
          const text = resultText(r, "\n");
          let response: Json;
          if (r.isError) {
            response = { error: text };
          } else {
            let parsed: Json | undefined;
            try {
              parsed = parseStrict(text);
            } catch {
              parsed = undefined;
            }
            response = isObject(parsed) ? parsed : { output: text };
          }
          parts.push({ functionResponse: { name: r.name, response } });
        }
        for (const part of turn.parts) {
          if (part.kind === "text") parts.push({ text: part.text });
          else if (part.kind === "image") {
            if (part.image.kind === "url") throw new Refusal(code.IMAGE_URL, "image_url");
            parts.push({ inlineData: { mimeType: part.image.mediaType, data: part.image.data } });
          }
        }
        break;
      case "assistant": {
        const signed = turn.parts.some((p) => p.kind === "call" && p.call.signature !== undefined);
        for (const part of turn.parts) {
          switch (part.kind) {
            case "text":
              if (part.text !== "") parts.push({ text: part.text });
              break;
            case "reasoning":
              break;
            case "call": {
              const p: JsonObject = { functionCall: { name: part.call.name, args: argumentsObject(part.call) } };
              if (part.call.signature !== undefined) p.thoughtSignature = part.call.signature;
              else if (!signed) p.thoughtSignature = SKIP_SIGNATURE;
              parts.push(p);
              break;
            }
            case "image":
            case "result":
              throw new Refusal(code.INVALID, "contents");
          }
        }
        break;
      }
    }
    contents.push([turn.role === "assistant" ? "model" : "user", parts]);
  }
  const o: JsonObject = {};
  if (req.system.length > 0) o.systemInstruction = { parts: req.system.map((s) => ({ text: s })) };
  o.contents = mergeRoles(contents).map(([role, parts]) => ({ role, parts }));
  if (req.tools.length > 0) {
    if (req.tools.some((t) => t.strict === true)) req.dropped.add("tool_strict");
    const declarations = req.tools.map((t) => {
      const f: JsonObject = { name: t.name };
      put(f, "description", t.description);
      f.parametersJsonSchema = t.parameters;
      return f;
    });
    o.tools = [{ functionDeclarations: declarations }];
  }
  const choice = req.toolChoice;
  if (choice !== undefined) {
    if (req.tools.length === 0 && choice.kind !== "none" && choice.kind !== "auto") throw new Refusal(code.INVALID, "tool_choice");
    if (req.tools.length > 0) {
      const config: JsonObject =
        choice.kind === "auto"
          ? { mode: "AUTO" }
          : choice.kind === "required"
            ? { mode: "ANY" }
            : choice.kind === "none"
              ? { mode: "NONE" }
              : { mode: "ANY", allowedFunctionNames: [choice.name] };
      o.toolConfig = { functionCallingConfig: config };
    }
  }
  const g: JsonObject = {};
  putNumber(g, "temperature", req.temperature);
  putNumber(g, "topP", req.topP);
  putNumber(g, "topK", req.topK);
  putNumber(g, "seed", req.seed);
  putNumber(g, "presencePenalty", req.presencePenalty);
  putNumber(g, "frequencyPenalty", req.frequencyPenalty);
  put(g, "maxOutputTokens", req.maxTokens);
  if (req.stop.length > 0) {
    if (req.stop.length > 5) throw new Refusal(code.VALUE, "stop");
    g.stopSequences = [...req.stop];
  }
  const format = req.format;
  if (format?.kind === "json_object") {
    g.responseMimeType = "application/json";
  } else if (format?.kind === "json_schema") {
    g.responseMimeType = "application/json";
    g.responseJsonSchema = format.schema;
  }
  if (req.reasoning !== undefined) {
    if (req.reasoning.kind === "disabled") g.thinkingConfig = { thinkingBudget: 0n };
    else g.thinkingConfig = { thinkingBudget: reasoningBudget(req.reasoning) ?? null, includeThoughts: true };
  }
  if (Object.keys(g).length > 0) o.generationConfig = g;
  return o;
}

// ------------------------------------------------------------------------------- Output cap ----

const U32_MAX = 4294967295;

/**
 * `apply_output_cap`: sets the output cap of an upstream body with the protocol's own field, and
 * keeps an Anthropic thinking budget below it. Changes `body` in place; returns advisory drops.
 */
export function applyOutputCap(protocol: Protocol, body: Json, cap: number): string[] {
  if (!Number.isInteger(cap) || cap < 0 || cap > U32_MAX) throw new RangeError("the output cap is a u32");
  const value = BigInt(cap);
  if (!isObject(body)) return [];
  switch (protocol) {
    case "open_ai_chat":
      if (Object.hasOwn(body, "max_tokens") && !Object.hasOwn(body, "max_completion_tokens")) body.max_tokens = value;
      else body.max_completion_tokens = value;
      return [];
    case "open_ai_responses":
      body.max_output_tokens = value;
      return [];
    case "anthropic_messages":
      body.max_tokens = value;
      return fitThinking(body, value);
    case "gemini": {
      if (!Object.hasOwn(body, "generationConfig")) body.generationConfig = {};
      const g = body.generationConfig;
      if (isObject(g)) g.maxOutputTokens = value;
      return [];
    }
    default:
      return [];
  }
}
