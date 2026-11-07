/**
 * Strict client request decoders (crates/gray-protocol/src/translate/decode.rs). Every top-level
 * field is either mapped into the IR, dropped as an advisory hint (recorded), or refused. Unknown
 * fields are refused: silently ignoring one could change what the model does.
 *
 * Fields are visited in serde_json's order (UTF-8 byte order of the keys, its Map being a
 * BTreeMap), so when a body has two refusable fields the same one is reported as in Rust.
 */
import { type Json, type JsonObject, asU64, get, isArray, isObject, setMember, sortedKeys, toJsonString } from "@gray/json";
import { rustTrim } from "../text.ts";
import type { Protocol } from "../types.ts";
import { Carrier, splitId } from "./carrier.ts";
import {
  type Format,
  type Image,
  type JsonNumber,
  type Part,
  type Reasoning,
  type Request,
  type ResultPart,
  type Thought,
  type Tool,
  type Turn,
  emptyRequest,
  normalizedEffort,
} from "./ir.ts";
import { Refusal, TRANSLATION_CODES as code } from "./refusal.ts";

function invalid(param: string): Refusal {
  return new Refusal(code.INVALID, param);
}

function feature(param: string): Refusal {
  return new Refusal(code.FEATURE, param);
}

/** `present`: a JSON null counts as absent. */
function present(v: Json | undefined): Json | undefined {
  return v === null ? undefined : v;
}

function obj(v: Json | undefined, param: string): JsonObject {
  if (!isObject(v)) throw invalid(param);
  return v;
}

function arr(v: Json | undefined, param: string): Json[] {
  if (!isArray(v)) throw invalid(param);
  return v;
}

function text(v: Json | undefined, param: string): string {
  if (typeof v !== "string") throw invalid(param);
  return v;
}

function number(v: Json | undefined, param: string): JsonNumber | undefined {
  const p = present(v);
  if (p === undefined) return undefined;
  if (typeof p === "bigint" || typeof p === "number") return p;
  throw invalid(param);
}

function uint(v: Json | undefined, param: string): bigint | undefined {
  const p = present(v);
  if (p === undefined) return undefined;
  const n = asU64(p);
  if (n === undefined) throw invalid(param);
  return n;
}

function boolean(v: Json | undefined, param: string): boolean | undefined {
  const p = present(v);
  if (p === undefined) return undefined;
  if (typeof p !== "boolean") throw invalid(param);
  return p;
}

function stopList(v: Json | undefined, param: string): string[] {
  const p = present(v);
  if (p === undefined) return [];
  if (typeof p === "string") return [p];
  if (isArray(p)) return p.map((s) => text(s, param));
  throw invalid(param);
}

function effortValue(v: string, param: string): Reasoning {
  if (v === "none") return { kind: "disabled" };
  const e = normalizedEffort(v);
  if (e === undefined) throw new Refusal(code.VALUE, param);
  return { kind: "effort", effort: e };
}

/** The members of an object in serde_json's order. */
function members(o: JsonObject): Array<[string, Json]> {
  return sortedKeys(o).map((k) => [k, o[k] as Json]);
}

function has(o: JsonObject, key: string): boolean {
  return Object.hasOwn(o, key);
}

/**
 * A data URL or an https URL; anything else (plain http, file ids, other schemes) is refused, so
 * no provider fetches an image in cleartext.
 */
function imageUrl(url: string, param: string): Image {
  if (url.startsWith("data:")) {
    const rest = url.slice(5);
    const comma = rest.indexOf(",");
    if (comma < 0) throw invalid(param);
    const meta = rest.slice(0, comma);
    const data = rest.slice(comma + 1);
    if (!meta.endsWith(";base64")) throw new Refusal(code.IMAGE_URL, param);
    const mediaType = meta.slice(0, meta.length - ";base64".length);
    if (!mediaType.startsWith("image/")) throw new Refusal(code.IMAGE_URL, param);
    return { kind: "data", mediaType, data };
  }
  if (url.startsWith("https://")) return { kind: "url", url };
  throw new Refusal(code.IMAGE_URL, param);
}

function detail(v: Json | undefined, req: Request): void {
  const d = present(v);
  if (d !== undefined && d !== "auto") req.dropped.add("image_detail");
}

/** `request`: decodes a client request of `protocol` into the IR, or throws a Refusal. */
export function decodeRequest(protocol: Protocol, body: Json, pathModel: string | undefined): Request {
  const o = obj(body, "body");
  let model: string;
  const m = present(get(o, "model"));
  if (m !== undefined) {
    model = text(m, "model");
  } else {
    if (pathModel === undefined) throw invalid("model");
    model = pathModel;
  }
  if (rustTrim(model) === "") throw invalid("model");
  const req = emptyRequest(model);
  switch (protocol) {
    case "open_ai_chat":
      chat(o, req);
      break;
    case "open_ai_responses":
      responses(o, req);
      break;
    case "anthropic_messages":
      anthropic(o, req);
      break;
    case "gemini":
      gemini(o, req);
      break;
    default:
      throw feature("protocol");
  }
  resolveNames(req.turns);
  return req;
}

/** Gemini answers a call by name: give each result the name of its call. */
function resolveNames(turns: Turn[]): void {
  const names = new Map<string, string>();
  for (const turn of turns) {
    for (const part of turn.parts) {
      if (part.kind === "call") names.set(part.call.id, part.call.name);
      else if (part.kind === "result" && part.result.name === undefined) part.result.name = names.get(part.result.id);
    }
  }
}

function functionTool(f: JsonObject, param: string): Tool {
  for (const key of sortedKeys(f)) {
    if (!["name", "description", "parameters", "strict"].includes(key)) throw feature(`${param}.${key}`);
  }
  const name = text(get(f, "name"), `${param}.name`);
  const d = present(get(f, "description"));
  const description = d === undefined ? undefined : text(d, `${param}.description`);
  const parameters = present(get(f, "parameters")) ?? { type: "object" };
  const strict = boolean(get(f, "strict"), `${param}.strict`);
  return { name, description, parameters, strict };
}

function jsonSchemaFormat(f: JsonObject, param: string): Format {
  const schema = present(get(f, "schema"));
  if (schema === undefined) throw invalid(`${param}.schema`);
  const n = present(get(f, "name"));
  const name = n === undefined ? "output" : text(n, `${param}.name`);
  const strict = boolean(get(f, "strict"), `${param}.strict`);
  const d = present(get(f, "description"));
  return { kind: "json_schema", name, schema, strict, description: typeof d === "string" ? d : undefined };
}

// ------------------------------------------------------------------------------------- Chat ----

function chat(o: JsonObject, req: Request): void {
  for (const [k, value] of members(o)) {
    const v = present(value);
    switch (k) {
      case "model":
      case "messages":
      case "user":
      case "safety_identifier":
      case "metadata":
        break;
      case "stream":
        req.stream = boolean(v, k) ?? false;
        break;
      case "stream_options":
        if (v !== undefined) {
          const options = obj(v, k);
          if (Object.keys(options).some((key) => key !== "include_usage")) req.dropped.add("stream_options");
          req.streamUsage = boolean(get(options, "include_usage"), "stream_options.include_usage") ?? false;
        }
        break;
      case "max_tokens":
      case "max_completion_tokens": {
        const n = uint(v, k);
        if (n !== undefined) {
          if (req.maxTokens !== undefined) throw invalid(k);
          req.maxTokens = n;
        }
        break;
      }
      case "temperature":
        req.temperature = number(v, k);
        break;
      case "top_p":
        req.topP = number(v, k);
        break;
      case "seed":
        req.seed = number(v, k);
        break;
      case "presence_penalty":
        req.presencePenalty = number(v, k);
        break;
      case "frequency_penalty":
        req.frequencyPenalty = number(v, k);
        break;
      case "stop":
        req.stop = stopList(v, k);
        break;
      case "n": {
        const n = uint(v, k);
        if (n !== undefined && n !== 1n) throw new Refusal(code.CANDIDATES, k);
        break;
      }
      case "logprobs":
        if (boolean(v, k) === true) throw new Refusal(code.LOGPROBS, k);
        break;
      case "top_logprobs":
        if (v !== undefined) throw new Refusal(code.LOGPROBS, k);
        break;
      case "tools":
        if (v !== undefined) {
          arr(v, k).forEach((item, i) => {
            const param = `tools[${i}]`;
            const t = obj(item, param);
            const typ = get(t, "type");
            if (typeof typ !== "string") throw invalid(`${param}.type`);
            if (typ !== "function") throw new Refusal(code.BUILTIN_TOOL, param);
            if (Object.keys(t).some((key) => key !== "type" && key !== "function")) throw feature(param);
            const fn = get(t, "function");
            if (fn === undefined) throw invalid(`${param}.function`);
            req.tools.push(functionTool(obj(fn, param), `${param}.function`));
          });
        }
        break;
      case "tool_choice":
        if (v === undefined) {
          req.toolChoice = undefined;
        } else if (typeof v === "string") {
          if (v === "auto") req.toolChoice = { kind: "auto" };
          else if (v === "none") req.toolChoice = { kind: "none" };
          else if (v === "required") req.toolChoice = { kind: "required" };
          else throw new Refusal(code.VALUE, k);
        } else if (isObject(v)) {
          const typ = get(v, "type");
          if (typ === "function") req.toolChoice = { kind: "named", name: text(get(get(v, "function"), "name"), k) };
          else if (typ === "custom") throw new Refusal(code.BUILTIN_TOOL, k);
          else throw feature(k);
        } else {
          throw invalid(k);
        }
        break;
      case "parallel_tool_calls":
        req.parallelToolCalls = boolean(v, k);
        break;
      case "response_format":
        if (v === undefined) {
          req.format = undefined;
        } else {
          const f = obj(v, k);
          const typ = get(f, "type");
          if (typ === "text") req.format = { kind: "text" };
          else if (typ === "json_object") req.format = { kind: "json_object" };
          else if (typ === "json_schema") {
            const schema = get(f, "json_schema");
            if (schema === undefined) throw invalid("response_format.json_schema");
            req.format = jsonSchemaFormat(obj(schema, "response_format.json_schema"), "response_format.json_schema");
          } else throw new Refusal(code.VALUE, k);
        }
        break;
      case "reasoning_effort":
        req.reasoning = v === undefined ? undefined : effortValue(text(v, k), k);
        break;
      case "prompt_cache_key":
        req.promptCacheKey = v;
        break;
      case "prompt_cache_retention":
        req.promptCacheRetention = v;
        break;
      case "service_tier":
      case "verbosity":
        if (v !== undefined) req.dropped.add(k === "verbosity" ? "verbosity" : "service_tier");
        break;
      case "store":
        if (boolean(v, k) === true) throw new Refusal(code.CONTINUATION, k);
        break;
      case "modalities":
        if (v !== undefined && arr(v, k).some((mode) => mode !== "text")) throw new Refusal(code.AUDIO, k);
        break;
      case "audio":
        if (v !== undefined) throw new Refusal(code.AUDIO, k);
        break;
      case "web_search_options":
        if (v !== undefined) throw new Refusal(code.BUILTIN_TOOL, k);
        break;
      default:
        if (v !== undefined) throw feature(k);
    }
  }
  const messagesValue = get(o, "messages");
  if (messagesValue === undefined) throw invalid("messages");
  const messages = arr(messagesValue, "messages");
  let leading = true;
  messages.forEach((value, i) => {
    const p = `messages[${i}]`;
    const m = obj(value, p);
    const role = text(get(m, "role"), `${p}.role`);
    if (present(get(m, "name")) !== undefined) req.dropped.add("message_name");
    if (role === "system" || role === "developer") {
      const texts = chatTexts(get(m, "content"), `${p}.content`);
      if (leading) req.system.push(...texts);
      else req.turns.push({ role: "system", parts: texts.map((t): Part => ({ kind: "text", text: t })) });
      return;
    }
    leading = false;
    switch (role) {
      case "user": {
        const parts: Part[] = [];
        const content = present(get(m, "content"));
        if (typeof content === "string") {
          parts.push({ kind: "text", text: content });
        } else if (isArray(content)) {
          content.forEach((item, j) => {
            const pp = `${p}.content[${j}]`;
            const part = obj(item, pp);
            const typ = get(part, "type");
            if (typ === "text") {
              parts.push({ kind: "text", text: text(get(part, "text"), pp) });
            } else if (typ === "image_url") {
              const image = get(part, "image_url");
              if (image === undefined) throw invalid(pp);
              const url = typeof image === "string" ? image : text(get(image, "url"), pp);
              detail(get(image, "detail"), req);
              parts.push({ kind: "image", image: imageUrl(url, pp) });
            } else if (typ === "input_audio") {
              throw new Refusal(code.AUDIO, pp);
            } else if (typ === "file") {
              throw new Refusal(code.FILE, pp);
            } else {
              throw feature(pp);
            }
          });
        } else {
          throw invalid(`${p}.content`);
        }
        req.turns.push({ role: "user", parts });
        break;
      }
      case "assistant": {
        for (const key of ["audio", "function_call"]) {
          if (present(get(m, key)) !== undefined) {
            throw key === "audio" ? new Refusal(code.AUDIO, `${p}.audio`) : feature(`${p}.function_call`);
          }
        }
        let parts: Part[] = [];
        for (const key of ["reasoning_content", "reasoning"]) {
          const r = present(get(m, key));
          if (r !== undefined) parts.push({ kind: "reasoning", thought: { text: text(r, `${p}.${key}`), carrier: undefined } });
        }
        const content = present(get(m, "content"));
        if (content === undefined) {
          // nothing
        } else if (typeof content === "string") {
          if (content !== "") parts.push({ kind: "text", text: content });
        } else if (isArray(content)) {
          content.forEach((item, j) => {
            const pp = `${p}.content[${j}]`;
            const part = obj(item, pp);
            const typ = get(part, "type");
            if (typ === "text") parts.push({ kind: "text", text: text(get(part, "text"), pp) });
            else if (typ === "refusal") parts.push({ kind: "text", text: text(get(part, "refusal"), pp) });
            else throw feature(pp);
          });
        } else {
          throw invalid(`${p}.content`);
        }
        const refusal = present(get(m, "refusal"));
        if (refusal !== undefined) parts.push({ kind: "text", text: text(refusal, `${p}.refusal`) });
        const calls = present(get(m, "tool_calls"));
        if (calls !== undefined) {
          arr(calls, `${p}.tool_calls`).forEach((item, j) => {
            const pp = `${p}.tool_calls[${j}]`;
            const call = obj(item, pp);
            const typ = get(call, "type");
            if (typeof typ === "string" && typ !== "function") throw new Refusal(code.BUILTIN_TOOL, pp);
            const f = get(call, "function");
            if (f === undefined) throw invalid(pp);
            const split = splitId(text(get(call, "id"), `${pp}.id`));
            if (split.carrier !== undefined) {
              // The turn's reasoning rode on its first call id.
              parts = parts.filter((part) => part.kind !== "reasoning");
              carrierThoughts(split.carrier).forEach((thought, k) => parts.splice(k, 0, { kind: "reasoning", thought }));
            }
            const name = text(get(f, "name"), `${pp}.function.name`);
            const args = text(get(f, "arguments"), `${pp}.function.arguments`);
            parts.push({ kind: "call", call: { id: split.id, name, arguments: args, signature: split.signature } });
          });
        }
        req.turns.push({ role: "assistant", parts });
        break;
      }
      case "tool": {
        const id = splitId(text(get(m, "tool_call_id"), `${p}.tool_call_id`)).id;
        const content = chatTexts(get(m, "content"), `${p}.content`).map((t): ResultPart => ({ kind: "text", text: t }));
        req.turns.push({ role: "user", parts: [{ kind: "result", result: { id, name: undefined, content, isError: false } }] });
        break;
      }
      case "function":
        throw feature(`${p}.role`);
      default:
        throw invalid(`${p}.role`);
    }
  });
}

/** The reasoning blocks of a Chat client's carrier: one, or a `{"b": [...]}` list of payloads. */
function carrierThoughts(carrier: Carrier): Thought[] {
  const list = Object.hasOwn(carrier.payload, "b") ? carrier.payload.b : undefined;
  const carriers = isArray(list) ? list.filter(isObject).map((p) => new Carrier(carrier.origin, p)) : [carrier];
  return carriers.map((c) => ({ text: c.getStr("t"), carrier: c }));
}

/** Text-only content: a string or an array of text parts. */
function chatTexts(v: Json | undefined, param: string): string[] {
  const p = present(v);
  if (p === undefined) return [];
  if (typeof p === "string") return [p];
  if (isArray(p)) {
    return p.map((part, i) => {
      const pp = `${param}[${i}]`;
      const typ = get(part, "type");
      if (typ === "text" || typ === "input_text") return text(get(part, "text"), pp);
      throw feature(pp);
    });
  }
  throw invalid(param);
}

// -------------------------------------------------------------------------------- Responses ----

const RESPONSES_BUILTIN_ITEMS: readonly string[] = [
  "web_search_call",
  "file_search_call",
  "computer_call",
  "computer_call_output",
  "code_interpreter_call",
  "image_generation_call",
  "local_shell_call",
  "local_shell_call_output",
  "shell_call",
  "shell_call_output",
  "apply_patch_call",
  "apply_patch_call_output",
  "mcp_list_tools",
  "mcp_approval_request",
  "mcp_approval_response",
  "mcp_call",
  "custom_tool_call",
  "custom_tool_call_output",
];

function responses(o: JsonObject, req: Request): void {
  for (const [k, value] of members(o)) {
    const v = present(value);
    switch (k) {
      case "model":
      case "input":
      case "instructions":
      case "metadata":
      case "user":
      case "safety_identifier":
        break;
      case "stream":
        req.stream = boolean(v, k) ?? false;
        break;
      case "stream_options":
        if (v !== undefined && (!isObject(v) || Object.keys(v).length > 0)) req.dropped.add("stream_options");
        break;
      case "max_output_tokens":
        req.maxTokens = uint(v, k);
        break;
      case "temperature":
        req.temperature = number(v, k);
        break;
      case "top_p":
        req.topP = number(v, k);
        break;
      case "parallel_tool_calls":
        req.parallelToolCalls = boolean(v, k);
        break;
      case "tools":
        if (v !== undefined) {
          arr(v, k).forEach((item, i) => {
            const param = `tools[${i}]`;
            const t = obj(item, param);
            if (get(t, "type") !== "function") throw new Refusal(code.BUILTIN_TOOL, param);
            const f: JsonObject = {};
            for (const key of Object.keys(t)) if (key !== "type") setMember(f, key, t[key] as Json);
            req.tools.push(functionTool(f, param));
          });
        }
        break;
      case "tool_choice":
        if (v === undefined) {
          req.toolChoice = undefined;
        } else if (typeof v === "string") {
          if (v === "auto") req.toolChoice = { kind: "auto" };
          else if (v === "none") req.toolChoice = { kind: "none" };
          else if (v === "required") req.toolChoice = { kind: "required" };
          else throw new Refusal(code.VALUE, k);
        } else if (isObject(v)) {
          const typ = get(v, "type");
          if (typ === "function") req.toolChoice = { kind: "named", name: text(get(v, "name"), k) };
          else if (typ === "allowed_tools") throw feature(k);
          else throw new Refusal(code.BUILTIN_TOOL, k);
        } else {
          throw invalid(k);
        }
        break;
      case "text":
        if (v !== undefined) {
          for (const [tk, tv] of members(obj(v, k))) {
            if (tk === "format") {
              const f = present(tv);
              if (f === undefined) {
                req.format = undefined;
              } else {
                const fo = obj(f, "text.format");
                const typ = get(fo, "type");
                if (typ === "text") req.format = { kind: "text" };
                else if (typ === "json_object") req.format = { kind: "json_object" };
                else if (typ === "json_schema") req.format = jsonSchemaFormat(fo, "text.format");
                else throw new Refusal(code.VALUE, "text.format");
              }
            } else if (tk === "verbosity") {
              if (tv !== null) req.dropped.add("verbosity");
            } else {
              throw feature(`text.${tk}`);
            }
          }
        }
        break;
      case "reasoning":
        if (v !== undefined) {
          for (const [rk, rv] of members(obj(v, k))) {
            if (rk === "effort") {
              const e = present(rv);
              req.reasoning = e === undefined ? undefined : effortValue(text(e, "reasoning.effort"), "reasoning.effort");
            } else if (rk !== "summary" && rk !== "generate_summary") {
              throw feature(`reasoning.${rk}`);
            }
          }
        }
        break;
      case "include":
        if (v !== undefined) {
          for (const item of arr(v, k)) {
            if (item === "reasoning.encrypted_content") continue;
            if (item === "message.output_text.logprobs") throw new Refusal(code.LOGPROBS, k);
            throw feature(k);
          }
        }
        break;
      case "store":
        if (boolean(v, k) === true) throw new Refusal(code.CONTINUATION, k);
        break;
      case "previous_response_id":
      case "conversation":
        if (v !== undefined) throw new Refusal(code.CONTINUATION, k);
        break;
      case "prompt_cache_key":
        req.promptCacheKey = v;
        break;
      case "prompt_cache_retention":
        req.promptCacheRetention = v;
        break;
      case "service_tier":
        if (v !== undefined) req.dropped.add("service_tier");
        break;
      case "truncation":
        if (typeof v === "string") {
          if (v === "auto") req.dropped.add("truncation");
          else if (v !== "disabled") throw new Refusal(code.VALUE, k);
        }
        break;
      case "top_logprobs":
        if (v !== undefined && asU64(v) !== 0n) throw new Refusal(code.LOGPROBS, k);
        break;
      case "background":
        if (boolean(v, k) === true) throw feature(k);
        break;
      default:
        if (v !== undefined) throw feature(k);
    }
  }
  const instructions = present(get(o, "instructions"));
  if (instructions !== undefined) req.system.push(text(instructions, "instructions"));
  let leading = true;
  const input = present(get(o, "input"));
  if (typeof input === "string") {
    req.turns.push({ role: "user", parts: [{ kind: "text", text: input }] });
  } else if (isArray(input)) {
    input.forEach((value, i) => {
      const p = `input[${i}]`;
      const item = obj(value, p);
      const typeValue = get(item, "type");
      const typ = typeof typeValue === "string" ? typeValue : "message";
      let role: Turn["role"];
      let part: Part;
      switch (typ) {
        case "message": {
          const r = text(get(item, "role"), `${p}.role`);
          if (r === "system" || r === "developer") {
            const texts = responsesContent(get(item, "content"), p, req).map((c) => {
              if (c.kind !== "text") throw feature(`${p}.content`);
              return c.text;
            });
            if (leading) req.system.push(...texts);
            else req.turns.push({ role: "system", parts: texts.map((t): Part => ({ kind: "text", text: t })) });
            return;
          }
          let messageRole: "user" | "assistant";
          if (r === "user") messageRole = "user";
          else if (r === "assistant") messageRole = "assistant";
          else throw invalid(`${p}.role`);
          leading = false;
          const parts = responsesContent(get(item, "content"), p, req);
          if (messageRole === "assistant" && parts.some((c) => c.kind === "image")) throw invalid(`${p}.content`);
          req.turns.push({ role: messageRole, parts });
          return;
        }
        case "function_call": {
          const split = splitId(text(get(item, "call_id"), `${p}.call_id`));
          const name = text(get(item, "name"), `${p}.name`);
          const args = text(get(item, "arguments"), `${p}.arguments`);
          role = "assistant";
          part = { kind: "call", call: { id: split.id, name, arguments: args, signature: split.signature } };
          break;
        }
        case "function_call_output": {
          const id = splitId(text(get(item, "call_id"), `${p}.call_id`)).id;
          const output = present(get(item, "output"));
          let content: ResultPart[];
          if (typeof output === "string") {
            content = [{ kind: "text", text: output }];
          } else if (isArray(output)) {
            content = responsesContent(output, `${p}.output`, req).map((c): ResultPart => {
              if (c.kind === "text") return { kind: "text", text: c.text };
              if (c.kind === "image") return { kind: "image", image: c.image };
              throw feature(`${p}.output`);
            });
          } else {
            throw invalid(`${p}.output`);
          }
          role = "user";
          part = { kind: "result", result: { id, name: undefined, content, isError: false } };
          break;
        }
        case "reasoning": {
          const s = present(get(item, "summary"));
          const summary = s === undefined ? "" : arr(s, `${p}.summary`).map((x) => text(get(x, "text"), `${p}.summary`)).join("\n\n");
          const encrypted = get(item, "encrypted_content");
          role = "assistant";
          part = {
            kind: "reasoning",
            thought: { text: summary === "" ? undefined : summary, carrier: typeof encrypted === "string" ? Carrier.decode(encrypted) : undefined },
          };
          break;
        }
        case "item_reference":
          throw new Refusal(code.CONTINUATION, p);
        default:
          if (RESPONSES_BUILTIN_ITEMS.includes(typ) || typ.startsWith("mcp_")) throw new Refusal(code.BUILTIN_TOOL, p);
          throw feature(`${p}.type`);
      }
      leading = false;
      req.turns.push({ role, parts: [part] });
    });
  } else {
    throw invalid("input");
  }
  // Responses lists one assistant step as several items.
  const merged: Turn[] = [];
  for (const turn of req.turns) {
    const last = merged[merged.length - 1];
    if (last !== undefined && last.role === "assistant" && turn.role === "assistant") last.parts.push(...turn.parts);
    else merged.push(turn);
  }
  req.turns = merged;
}

function responsesContent(v: Json | undefined, p: string, req: Request): Part[] {
  const c = present(v);
  if (typeof c === "string") return [{ kind: "text", text: c }];
  if (!isArray(c)) throw invalid(`${p}.content`);
  return c.map((item, j): Part => {
    const pp = `${p}.content[${j}]`;
    const part = obj(item, pp);
    const typ = get(part, "type");
    switch (typ) {
      case "input_text":
      case "output_text":
      case "text":
        return { kind: "text", text: text(get(part, "text"), pp) };
      case "refusal":
        return { kind: "text", text: text(get(part, "refusal"), pp) };
      case "input_image": {
        detail(get(part, "detail"), req);
        const url = present(get(part, "image_url"));
        if (url === undefined) throw new Refusal(code.IMAGE_URL, pp);
        return { kind: "image", image: imageUrl(text(url, pp), pp) };
      }
      case "input_file":
        throw new Refusal(code.FILE, pp);
      case "input_audio":
        throw new Refusal(code.AUDIO, pp);
      default:
        throw feature(pp);
    }
  });
}

// -------------------------------------------------------------------------------- Anthropic ----

const ANTHROPIC_BUILTIN_BLOCKS: readonly string[] = [
  "server_tool_use",
  "web_search_tool_result",
  "web_fetch_tool_result",
  "code_execution_tool_result",
  "bash_code_execution_tool_result",
  "text_editor_code_execution_tool_result",
  "tool_search_tool_result",
  "mcp_tool_use",
  "mcp_tool_result",
  "container_upload",
];

function anthropic(o: JsonObject, req: Request): void {
  let adaptive = false;
  let effortHint: string | undefined;
  for (const [k, value] of members(o)) {
    const v = present(value);
    switch (k) {
      case "model":
      case "messages":
      case "system":
      case "metadata":
        break;
      case "stream":
        req.stream = boolean(v, k) ?? false;
        break;
      case "max_tokens":
        req.maxTokens = uint(v, k);
        break;
      case "temperature":
        req.temperature = number(v, k);
        break;
      case "top_p":
        req.topP = number(v, k);
        break;
      case "top_k":
        req.topK = number(v, k);
        break;
      case "stop_sequences":
        req.stop = stopList(v, k);
        break;
      case "tools":
        if (v !== undefined) {
          arr(v, k).forEach((item, i) => {
            const param = `tools[${i}]`;
            const t = obj(item, param);
            const typ = get(t, "type");
            if ((typeof typ === "string" && typ !== "custom") || (typ !== undefined && !has(t, "input_schema"))) {
              throw new Refusal(code.BUILTIN_TOOL, param);
            }
            const f: JsonObject = {};
            for (const [tk, tv] of members(t)) {
              switch (tk) {
                case "type":
                  break;
                case "cache_control":
                  req.dropped.add("cache_control");
                  break;
                case "input_schema":
                  setMember(f, "parameters", tv);
                  break;
                case "name":
                case "description":
                case "strict":
                  setMember(f, tk, tv);
                  break;
                default:
                  throw feature(`${param}.${tk}`);
              }
            }
            if (!has(f, "parameters")) throw invalid(`${param}.input_schema`);
            req.tools.push(functionTool(f, param));
          });
        }
        break;
      case "tool_choice":
        if (v !== undefined) {
          const c = obj(v, k);
          const typ = get(c, "type");
          if (typ === "auto") req.toolChoice = { kind: "auto" };
          else if (typ === "any") req.toolChoice = { kind: "required" };
          else if (typ === "none") req.toolChoice = { kind: "none" };
          else if (typ === "tool") req.toolChoice = { kind: "named", name: text(get(c, "name"), k) };
          else throw new Refusal(code.VALUE, k);
          if (boolean(get(c, "disable_parallel_tool_use"), k) === true) req.parallelToolCalls = false;
        }
        break;
      case "thinking":
        if (v !== undefined) {
          const t = obj(v, k);
          const typ = get(t, "type");
          if (typ === "enabled") {
            const budget = uint(get(t, "budget_tokens"), "thinking.budget_tokens");
            if (budget === undefined) throw invalid("thinking.budget_tokens");
            req.reasoning = { kind: "budget", budget };
          } else if (typ === "disabled") {
            req.reasoning = { kind: "disabled" };
          } else if (typ === "adaptive") {
            adaptive = true;
            req.reasoning = undefined;
          } else {
            throw new Refusal(code.VALUE, k);
          }
          if (Object.keys(t).some((key) => key !== "type" && key !== "budget_tokens")) throw feature(k);
        }
        break;
      case "output_config":
      case "output_format":
        if (v !== undefined) {
          const c = obj(v, k);
          let format: Json | undefined;
          let effort: Json | undefined;
          if (k === "output_format") {
            format = v;
          } else {
            for (const ck of sortedKeys(c)) {
              if (ck !== "format" && ck !== "effort") throw feature(`${k}.${ck}`);
            }
            format = present(get(c, "format"));
            effort = present(get(c, "effort"));
          }
          if (format !== undefined) {
            const f = obj(format, k);
            if (get(f, "type") === "json_schema") req.format = jsonSchemaFormat(f, k);
            else throw new Refusal(code.VALUE, k);
          }
          if (effort !== undefined) effortHint = text(effort, "output_config.effort");
        }
        break;
      case "service_tier":
        if (v !== undefined) req.dropped.add("service_tier");
        break;
      case "container":
      case "mcp_servers":
        if (v !== undefined) throw new Refusal(code.BUILTIN_TOOL, k);
        break;
      default:
        if (v !== undefined) throw feature(k);
    }
  }
  if (adaptive) {
    req.reasoning = effortHint !== undefined ? effortValue(effortHint, "output_config.effort") : { kind: "effort", effort: "high" };
  } else if (effortHint !== undefined) {
    req.dropped.add("effort");
  }
  const system = present(get(o, "system"));
  if (system === undefined) {
    // nothing
  } else if (typeof system === "string") {
    req.system.push(system);
  } else if (isArray(system)) {
    system.forEach((value, i) => {
      const p = `system[${i}]`;
      const b = obj(value, p);
      if (get(b, "type") !== "text") throw feature(p);
      anthropicBlockExtras(b, p, req, ["type", "text"]);
      req.system.push(text(get(b, "text"), p));
    });
  } else {
    throw invalid("system");
  }
  const messagesValue = get(o, "messages");
  if (messagesValue === undefined) throw invalid("messages");
  arr(messagesValue, "messages").forEach((value, i) => {
    const p = `messages[${i}]`;
    const m = obj(value, p);
    const r = text(get(m, "role"), `${p}.role`);
    let role: "user" | "assistant";
    if (r === "user") role = "user";
    else if (r === "assistant") role = "assistant";
    else throw invalid(`${p}.role`);
    const parts: Part[] = [];
    const content = get(m, "content");
    if (typeof content === "string") {
      parts.push({ kind: "text", text: content });
    } else if (isArray(content)) {
      content.forEach((block, j) => {
        const pp = `${p}.content[${j}]`;
        parts.push(anthropicBlock(obj(block, pp), role, pp, req));
      });
    } else {
      throw invalid(`${p}.content`);
    }
    req.turns.push({ role, parts });
  });
}

function anthropicBlockExtras(b: JsonObject, p: string, req: Request, known: readonly string[]): void {
  for (const key of sortedKeys(b)) {
    if (key === "cache_control") req.dropped.add("cache_control");
    else if (key === "citations") {
      if (present(get(b, "citations")) !== undefined) req.dropped.add("citations");
    } else if (!known.includes(key)) throw feature(`${p}.${key}`);
  }
}

function anthropicImage(b: JsonObject, p: string): Image {
  const source = get(b, "source");
  if (source === undefined) throw invalid(p);
  const typ = get(source, "type");
  if (typ === "base64") {
    const mediaType = text(get(source, "media_type"), p);
    return { kind: "data", mediaType, data: text(get(source, "data"), p) };
  }
  if (typ === "url") return imageUrl(text(get(source, "url"), p), p);
  if (typ === "file") throw new Refusal(code.IMAGE_URL, p);
  throw invalid(p);
}

function anthropicBlock(b: JsonObject, role: "user" | "assistant", p: string, req: Request): Part {
  const typ = text(get(b, "type"), `${p}.type`);
  const only = (r: "user" | "assistant") => {
    if (role !== r) throw invalid(p);
  };
  switch (typ) {
    case "text":
      anthropicBlockExtras(b, p, req, ["type", "text"]);
      return { kind: "text", text: text(get(b, "text"), p) };
    case "image":
      only("user");
      anthropicBlockExtras(b, p, req, ["type", "source"]);
      return { kind: "image", image: anthropicImage(b, p) };
    case "document":
      throw new Refusal(code.FILE, p);
    case "tool_use": {
      only("assistant");
      anthropicBlockExtras(b, p, req, ["type", "id", "name", "input"]);
      const split = splitId(text(get(b, "id"), p));
      const input = get(b, "input");
      if (!isObject(input)) throw invalid(p);
      const name = text(get(b, "name"), p);
      return { kind: "call", call: { id: split.id, name, arguments: toJsonString(input), signature: split.signature } };
    }
    case "tool_result": {
      only("user");
      anthropicBlockExtras(b, p, req, ["type", "tool_use_id", "content", "is_error"]);
      const c = present(get(b, "content"));
      let content: ResultPart[];
      if (c === undefined) {
        content = [];
      } else if (typeof c === "string") {
        content = [{ kind: "text", text: c }];
      } else if (isArray(c)) {
        content = c.map((item, j): ResultPart => {
          const pp = `${p}.content[${j}]`;
          const block = obj(item, pp);
          const t = get(block, "type");
          if (t === "text") {
            anthropicBlockExtras(block, pp, req, ["type", "text"]);
            return { kind: "text", text: text(get(block, "text"), pp) };
          }
          if (t === "image") {
            anthropicBlockExtras(block, pp, req, ["type", "source"]);
            return { kind: "image", image: anthropicImage(block, pp) };
          }
          if (t === "document") throw new Refusal(code.FILE, pp);
          throw feature(pp);
        });
      } else {
        throw invalid(p);
      }
      const id = splitId(text(get(b, "tool_use_id"), p)).id;
      const isError = boolean(get(b, "is_error"), p) ?? false;
      return { kind: "result", result: { id, name: undefined, content, isError } };
    }
    case "thinking": {
      only("assistant");
      anthropicBlockExtras(b, p, req, ["type", "thinking", "signature"]);
      const thinking = text(get(b, "thinking"), p);
      const signature = get(b, "signature");
      return { kind: "reasoning", thought: { text: thinking, carrier: typeof signature === "string" ? Carrier.decode(signature) : undefined } };
    }
    case "redacted_thinking": {
      only("assistant");
      const data = get(b, "data");
      return { kind: "reasoning", thought: { text: undefined, carrier: typeof data === "string" ? Carrier.decode(data) : undefined } };
    }
    default:
      if (ANTHROPIC_BUILTIN_BLOCKS.includes(typ)) throw new Refusal(code.BUILTIN_TOOL, p);
      throw feature(p);
  }
}

// ----------------------------------------------------------------------------------- Gemini ----

/** `system_instruction` → `systemInstruction`: Gemini's JSON accepts both. */
export function camel(key: string): string {
  let out = "";
  let upper = false;
  for (const c of key) {
    if (c === "_" && out !== "") {
      upper = true;
    } else if (upper) {
      out += c.toUpperCase();
      upper = false;
    } else {
      out += c;
    }
  }
  return out;
}

/** The object's fields under their camelCase names; two names for one field are invalid. */
function fields(o: JsonObject, p: string): JsonObject {
  const out: JsonObject = {};
  for (const [k, v] of members(o)) {
    const name = camel(k);
    if (has(out, name)) throw invalid(`${p}.${k}`);
    setMember(out, name, v);
  }
  return out;
}

/** Gemini's OpenAPI schema subset to JSON Schema: lowercase types, `nullable` as a `null` type, and no `propertyOrdering`. */
export function jsonSchema(schema: Json): Json {
  if (!isObject(schema)) return schema;
  const out: JsonObject = {};
  const nullable = get(schema, "nullable") === true;
  for (const [k, v] of members(schema)) {
    switch (k) {
      case "nullable":
      case "propertyOrdering":
        break;
      case "type": {
        const t = typeof v === "string" ? v.toLowerCase() : v;
        setMember(out, k, nullable ? [t, "null"] : t);
        break;
      }
      case "properties":
      case "$defs":
      case "definitions":
        if (isObject(v)) {
          const props: JsonObject = {};
          for (const [name, s] of members(v)) setMember(props, name, jsonSchema(s));
          setMember(out, k, props);
        } else {
          setMember(out, k, v);
        }
        break;
      case "items":
      case "additionalProperties":
      case "not":
        setMember(out, k, jsonSchema(v));
        break;
      case "anyOf":
      case "oneOf":
      case "allOf":
      case "prefixItems":
        setMember(out, k, isArray(v) ? v.map(jsonSchema) : v);
        break;
      default:
        setMember(out, k, v);
    }
  }
  return out;
}

const I64_MIN = -9223372036854775808n;
const I64_MAX = 9223372036854775807n;

function gemini(body: JsonObject, req: Request): void {
  const o = fields(body, "body");
  for (const [k, value] of members(o)) {
    const v = present(value);
    switch (k) {
      case "model":
      case "contents":
      case "systemInstruction":
      case "labels":
        break;
      case "tools":
        if (v !== undefined) {
          arr(v, k).forEach((item, i) => {
            const param = `tools[${i}]`;
            const t = fields(obj(item, param), param);
            for (const [tk, tv] of members(t)) {
              if (tk !== "functionDeclarations") throw new Refusal(code.BUILTIN_TOOL, `${param}.${tk}`);
              arr(tv, param).forEach((fv, j) => {
                const fp = `${param}.functionDeclarations[${j}]`;
                const f = fields(obj(fv, fp), fp);
                const declared: JsonObject = {};
                for (const [fk, value2] of members(f)) {
                  switch (fk) {
                    case "name":
                    case "description":
                      setMember(declared, fk, value2);
                      break;
                    case "parameters":
                      setMember(declared, fk, jsonSchema(value2));
                      break;
                    case "parametersJsonSchema":
                      setMember(declared, "parameters", value2);
                      break;
                    case "response":
                    case "responseJsonSchema":
                      req.dropped.add("tool_response_schema");
                      break;
                    default:
                      throw feature(`${fp}.${fk}`);
                  }
                }
                if (has(f, "parameters") && has(f, "parametersJsonSchema")) throw invalid(fp);
                req.tools.push(functionTool(declared, fp));
              });
            }
          });
        }
        break;
      case "toolConfig":
        if (v !== undefined) {
          const c = fields(obj(v, k), k);
          for (const [ck, cv] of members(c)) {
            if (ck !== "functionCallingConfig") throw feature(`toolConfig.${ck}`);
            const f = fields(obj(cv, "toolConfig.functionCallingConfig"), k);
            const n = present(get(f, "allowedFunctionNames"));
            const names = n === undefined ? [] : arr(n, "allowedFunctionNames").map((x) => text(x, "allowedFunctionNames"));
            for (const fk of sortedKeys(f)) {
              if (fk !== "mode" && fk !== "allowedFunctionNames") throw feature(`toolConfig.functionCallingConfig.${fk}`);
            }
            const modeValue = get(f, "mode");
            const mode = typeof modeValue === "string" ? modeValue : "AUTO";
            if ((mode === "AUTO" || mode === "MODE_UNSPECIFIED" || mode === "VALIDATED") && names.length === 0) req.toolChoice = { kind: "auto" };
            else if (mode === "ANY" && names.length === 0) req.toolChoice = { kind: "required" };
            else if (mode === "ANY" && names.length === 1) req.toolChoice = { kind: "named", name: names[0] as string };
            else if (mode === "NONE" && names.length === 0) req.toolChoice = { kind: "none" };
            else throw feature("toolConfig.functionCallingConfig");
          }
        }
        break;
      case "generationConfig":
        if (v !== undefined) geminiGeneration(fields(obj(v, k), k), req);
        break;
      case "safetySettings":
        if (v !== undefined) req.dropped.add("safety_settings");
        break;
      case "cachedContent":
        if (v !== undefined) throw new Refusal(code.CONTINUATION, k);
        break;
      default:
        if (v !== undefined) throw feature(k);
    }
  }
  const systemInstruction = present(get(o, "systemInstruction"));
  if (systemInstruction !== undefined) {
    const s = fields(obj(systemInstruction, "systemInstruction"), "systemInstruction");
    const parts = present(get(s, "parts"));
    if (parts !== undefined) {
      arr(parts, "systemInstruction.parts").forEach((value, i) => {
        const p = `systemInstruction.parts[${i}]`;
        const part = fields(obj(value, p), p);
        if (Object.keys(part).some((key) => key !== "text")) throw feature(p);
        req.system.push(text(get(part, "text"), p));
      });
    }
  }
  const contentsValue = get(o, "contents");
  if (contentsValue === undefined) throw invalid("contents");
  // Calls not yet answered, oldest first: results without an id answer the first open call of the same name.
  const open: Array<[string, string]> = [];
  const answered = new Map<string, string>();
  arr(contentsValue, "contents").forEach((value, i) => {
    const p = `contents[${i}]`;
    const content = fields(obj(value, p), p);
    const roleValue = get(content, "role");
    const r = typeof roleValue === "string" ? roleValue : "user";
    let role: "user" | "assistant";
    if (r === "user" || r === "function") role = "user";
    else if (r === "model") role = "assistant";
    else throw invalid(`${p}.role`);
    const parts: Part[] = [];
    let generated = 0;
    const partsValue = get(content, "parts");
    if (partsValue === undefined) throw invalid(p);
    arr(partsValue, p).forEach((partValue, j) => {
      const pp = `${p}.parts[${j}]`;
      const part = fields(obj(partValue, pp), pp);
      const sig = get(part, "thoughtSignature");
      const signature = typeof sig === "string" ? sig : undefined;
      for (const key of sortedKeys(part)) {
        if (!["text", "thought", "thoughtSignature", "functionCall", "functionResponse", "inlineData", "fileData"].includes(key)) {
          throw key === "executableCode" || key === "codeExecutionResult" ? new Refusal(code.BUILTIN_TOOL, pp) : feature(`${pp}.${key}`);
        }
      }
      if (has(part, "text")) {
        const t = text(get(part, "text"), pp);
        if (get(part, "thought") === true) {
          if (role !== "assistant") throw invalid(pp);
          parts.push({
            kind: "reasoning",
            thought: { text: t === "" ? undefined : t, carrier: signature === undefined ? undefined : Carrier.decodeBytes(signature) },
          });
        } else {
          parts.push({ kind: "text", text: t });
        }
      } else if (has(part, "functionCall")) {
        if (role !== "assistant") throw invalid(pp);
        const f = fields(obj(get(part, "functionCall"), pp), pp);
        const name = text(get(f, "name"), `${pp}.functionCall.name`);
        const idValue = present(get(f, "id"));
        let id: string;
        if (idValue !== undefined) {
          id = splitId(text(idValue, pp)).id;
        } else {
          generated += 1;
          id = `gm_${i}_${generated - 1}`;
        }
        const args = present(get(f, "args")) ?? {};
        if (!isObject(args)) throw invalid(`${pp}.functionCall.args`);
        open.push([id, name]);
        parts.push({ kind: "call", call: { id, name, arguments: toJsonString(args), signature: undefined } });
      } else if (has(part, "functionResponse")) {
        if (role !== "user") throw invalid(pp);
        const f = fields(obj(get(part, "functionResponse"), pp), pp);
        for (const key of sortedKeys(f)) {
          if (!["id", "name", "response"].includes(key)) throw feature(`${pp}.functionResponse.${key}`);
        }
        const name = text(get(f, "name"), `${pp}.functionResponse.name`);
        const idValue = present(get(f, "id"));
        let id: string;
        if (idValue !== undefined) {
          id = splitId(text(idValue, pp)).id;
          const position = open.findIndex(([openId]) => openId === id);
          const known = position >= 0 ? (open.splice(position, 1)[0] as [string, string])[1] : answered.get(id);
          if (known !== name) throw invalid(`${pp}.functionResponse`);
        } else {
          const position = open.findIndex(([, openName]) => openName === name);
          if (position < 0) throw invalid(`${pp}.functionResponse`);
          id = (open.splice(position, 1)[0] as [string, string])[0];
        }
        answered.set(id, name);
        const response = present(get(f, "response"));
        if (response === undefined) throw invalid(`${pp}.functionResponse.response`);
        const only = (key: string): string | undefined => {
          if (!isObject(response) || Object.keys(response).length !== 1) return undefined;
          const value2 = get(response, key);
          return typeof value2 === "string" ? value2 : undefined;
        };
        let textContent: string;
        let isError = false;
        const output = only("output");
        const error = only("error");
        if (output !== undefined) {
          textContent = output;
        } else if (error !== undefined) {
          textContent = error;
          isError = true;
        } else {
          textContent = toJsonString(response);
        }
        parts.push({ kind: "result", result: { id, name, content: [{ kind: "text", text: textContent }], isError } });
      } else if (has(part, "inlineData")) {
        const d = fields(obj(get(part, "inlineData"), pp), pp);
        const media = text(get(d, "mimeType"), pp);
        if (media.startsWith("image/")) {
          parts.push({ kind: "image", image: { kind: "data", mediaType: media, data: text(get(d, "data"), pp) } });
        } else if (media.startsWith("audio/")) {
          throw new Refusal(code.AUDIO, pp);
        } else {
          throw new Refusal(code.FILE, pp);
        }
      } else if (has(part, "fileData")) {
        throw new Refusal(code.FILE, pp);
      } else if (signature !== undefined) {
        // A bare signature part: the reasoning carrier of the turn.
        parts.push({ kind: "reasoning", thought: { text: undefined, carrier: Carrier.decodeBytes(signature) } });
      } else {
        throw feature(pp);
      }
    });
    req.turns.push({ role, parts });
  });
}

function geminiGeneration(g: JsonObject, req: Request): void {
  let mime: string | undefined;
  let schema: Json | undefined;
  for (const [k, value] of members(g)) {
    const v = present(value);
    const p = `generationConfig.${k}`;
    switch (k) {
      case "temperature":
        req.temperature = number(v, p);
        break;
      case "topP":
        req.topP = number(v, p);
        break;
      case "topK":
        req.topK = number(v, p);
        break;
      case "seed":
        req.seed = number(v, p);
        break;
      case "presencePenalty":
        req.presencePenalty = number(v, p);
        break;
      case "frequencyPenalty":
        req.frequencyPenalty = number(v, p);
        break;
      case "maxOutputTokens":
        req.maxTokens = uint(v, p);
        break;
      case "stopSequences":
        req.stop = stopList(v, p);
        break;
      case "candidateCount": {
        const n = uint(v, p);
        if (n !== undefined && n !== 1n) throw new Refusal(code.CANDIDATES, p);
        break;
      }
      case "responseLogprobs":
        if (boolean(v, p) === true) throw new Refusal(code.LOGPROBS, p);
        break;
      case "logprobs":
        if (v !== undefined) throw new Refusal(code.LOGPROBS, p);
        break;
      case "speechConfig":
        if (v !== undefined) throw new Refusal(code.AUDIO, p);
        break;
      case "responseModalities":
        if (v !== undefined) {
          for (const mode of arr(v, p)) {
            if (mode === "TEXT") continue;
            if (mode === "AUDIO") throw new Refusal(code.AUDIO, p);
            throw feature(p);
          }
        }
        break;
      case "responseMimeType":
        mime = v === undefined ? undefined : text(v, p);
        break;
      case "responseSchema":
        if (v !== undefined) schema = jsonSchema(v);
        break;
      case "responseJsonSchema":
        if (v !== undefined) schema = v;
        break;
      case "thinkingConfig":
        if (v !== undefined) {
          const t = fields(obj(v, p), p);
          for (const [tk, tv] of members(t)) {
            if (tk === "thinkingBudget") {
              const n = typeof tv === "bigint" && tv >= I64_MIN && tv <= I64_MAX ? tv : undefined;
              if (n === 0n) req.reasoning = { kind: "disabled" };
              else if (n === -1n) req.reasoning = { kind: "effort", effort: "medium" };
              else if (n !== undefined && n > 0n) req.reasoning = { kind: "budget", budget: n };
              else throw new Refusal(code.VALUE, `${p}.${tk}`);
            } else if (tk === "thinkingLevel") {
              req.reasoning = effortValue(text(tv, p).toLowerCase(), `${p}.${tk}`);
            } else if (tk !== "includeThoughts") {
              throw feature(`${p}.${tk}`);
            }
          }
        }
        break;
      case "mediaResolution":
        if (v !== undefined) req.dropped.add("media_resolution");
        break;
      default:
        if (v !== undefined) throw feature(p);
    }
  }
  if (has(g, "responseSchema") && has(g, "responseJsonSchema")) throw invalid("generationConfig.responseSchema");
  if ((mime === undefined || mime === "text/plain") && schema === undefined) req.format = undefined;
  else if (mime === "application/json" && schema === undefined) req.format = { kind: "json_object" };
  else if (mime === "application/json" && schema !== undefined) {
    req.format = { kind: "json_schema", name: "output", schema, strict: undefined, description: undefined };
  } else throw new Refusal(code.VALUE, "generationConfig.responseMimeType");
}

