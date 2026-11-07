/**
 * Buffered (non-stream) native answers: `parse_response_shared` and `parse_provider_error`
 * (crates/gray-protocol/src/response.rs). The primary choice or candidate is projected for routing
 * and accounting; every choice, id, annotation, signature and detail stays in the body, which is
 * what the client is sent.
 */
import { geminiBlockFinish, mapFinish } from "./finish.ts";
import { type Json, asStr, asU64, get, isArray, isObject, pointer, toJsonString } from "@gray/json";
import { type ContentBlock, blocks, geminiField, requestArgumentValue } from "./request.ts";
import { type FinishReason, type Protocol, type Usage, ProtocolError, invalidResponse, notGeneration } from "./types.ts";
import { bufferedUsage, parseUsage } from "./usage.ts";

export interface ToolCall {
  readonly id: string;
  readonly name: string;
  readonly arguments: Json;
}

/** `CanonicalResponse` without `raw_body` (the parsed body travels beside it). */
export interface CanonicalResponse {
  readonly protocol: Protocol;
  readonly model: string;
  readonly content: readonly ContentBlock[];
  readonly tool_calls: readonly ToolCall[];
  readonly finish_reason: FinishReason | null;
  readonly usage: Usage | null;
}

const bad = invalidResponse;

/** `response_error`: a request-side parsing error read from an answer is an invalid response. */
function asResponseError<T>(p: Protocol, run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (error instanceof ProtocolError && error.detail.kind === "invalid_request") throw bad(p, error.detail.message);
    throw error;
  }
}

/**
 * `parse_provider_error`: a native provider error with its whole envelope, or undefined. It does
 * not classify retry eligibility or expose diagnostics to clients.
 */
export function parseProviderError(protocol: Protocol, body: Json): ProtocolError | undefined {
  let error = get(body, "error");
  if (error === null) error = undefined;
  if (error === undefined) {
    const nested = pointer(body, "/response/error");
    if (nested !== undefined && nested !== null) error = nested;
  }
  const status = asStr(get(body, "status"));
  const typ = asStr(get(body, "type"));
  const failed = status === "failed" || typ === "error" || typ === "response.failed";
  if (error === undefined && !failed) return undefined;
  const e = error ?? body;
  const message = asStr(get(e, "message")) ?? asStr(e) ?? "provider reported an error";
  // `code`, else `type`, else `status`; a present null ends the search with no code.
  let code = get(e, "code");
  if (code === undefined) code = get(e, "type");
  if (code === undefined) code = get(e, "status");
  return new ProtocolError({
    kind: "provider",
    protocol,
    message,
    code: code === undefined || code === null ? null : typeof code === "string" ? code : toJsonString(code),
    body,
  });
}

/** `primary_alternative`: the choice or candidate of index 0 (its position when it has none). */
function primaryAlternative(values: Json[], p: Protocol): Json | undefined {
  const indexes = new Set<bigint>();
  let primary: Json | undefined;
  values.forEach((value, position) => {
    if (!isObject(value)) throw bad(p, "choice/candidate must be an object");
    const given = get(value, "index");
    let index: bigint;
    if (given === undefined) {
      index = BigInt(position);
    } else {
      const n = asU64(given);
      if (n === undefined) throw bad(p, "choice/candidate index must be a non-negative integer");
      index = n;
    }
    if (indexes.has(index)) throw bad(p, "duplicate choice/candidate index");
    indexes.add(index);
    if (index === 0n) primary = value;
  });
  if (values.length > 0 && primary === undefined) throw bad(p, "non-stream response has no primary choice/candidate");
  return primary;
}

function usageOf(p: Protocol, body: Json): Usage | null {
  const usage = bufferedUsage(p, body);
  return usage === undefined ? null : parseUsage(p, usage);
}

/** `parse_response_shared`: the canonical projection of a buffered native answer. */
export function parseResponse(protocol: Protocol, body: Json): CanonicalResponse {
  const p = protocol;
  if (!isObject(body)) throw bad(p, "response must be an object");
  const providerError = parseProviderError(p, body);
  if (providerError !== undefined) throw providerError;
  let content: ContentBlock[] = [];
  let finishReason: FinishReason | null;
  let usage: Usage | null;
  switch (p) {
    case "open_ai_chat": {
      const choices = get(body, "choices");
      if (!isArray(choices)) throw bad(p, "choices must be an array");
      const first = primaryAlternative(choices, p);
      if (first === undefined) throw bad(p, "non-stream response has no choices");
      const message = get(first, "message");
      if (!isObject(message)) throw bad(p, "choice.message must be an object");
      content = asResponseError(p, () => blocks(get(message, "content"), p));
      let reasoning = get(message, "reasoning_content");
      if (reasoning === undefined) reasoning = get(message, "reasoning");
      if (reasoning !== undefined) {
        content.push(
          typeof reasoning === "string"
            ? { type: "reasoning", text: reasoning, signature: null, opaque: null }
            : { type: "native", protocol: p, value: reasoning },
        );
      }
      const calls = get(message, "tool_calls");
      if (calls !== undefined && calls !== null) {
        if (!isArray(calls)) throw bad(p, "message.tool_calls must be an array");
        for (const t of calls) {
          if (get(t, "function") !== undefined) {
            const id = asResponseError(p, () => requireString(get(t, "id"), "tool_call.id", p));
            const name = asResponseError(p, () => requireString(pointer(t, "/function/name"), "tool_call.name", p));
            const input = asResponseError(p, () => requestArgumentValue(pointer(t, "/function/arguments"), p));
            content.push({ type: "tool_use", id, name, input });
          } else {
            content.push({ type: "native", protocol: p, value: t });
          }
        }
      }
      const refusal = get(message, "refusal");
      if (refusal !== undefined && refusal !== null) {
        content.push({ type: "native", protocol: p, value: { type: "refusal", refusal } });
      }
      const reason = asStr(get(first, "finish_reason"));
      finishReason = reason === undefined ? null : mapFinish(reason);
      usage = usageOf(p, body);
      break;
    }
    case "open_ai_responses": {
      const items = get(body, "output");
      if (!isArray(items)) throw bad(p, "output must be an array");
      for (const entry of items) {
        if (!isObject(entry)) throw bad(p, "output item must be an object");
        const typ = asStr(get(entry, "type"));
        if (typ === "message") {
          content.push(...asResponseError(p, () => blocks(get(entry, "content"), p)));
        } else if (typ === "function_call") {
          const id = asResponseError(p, () => requireString(get(entry, "call_id"), "function_call.call_id", p));
          const name = asResponseError(p, () => requireString(get(entry, "name"), "function_call.name", p));
          const input = asResponseError(p, () => requestArgumentValue(get(entry, "arguments"), p));
          content.push({ type: "tool_use", id, name, input });
        } else if (typ === "reasoning") {
          content.push(...asResponseError(p, () => blocks([entry], p)));
        } else if (typ !== undefined) {
          content.push({ type: "native", protocol: p, value: entry });
        } else {
          throw bad(p, "output item.type missing");
        }
      }
      const status = asStr(get(body, "status"));
      if (status === "completed") {
        finishReason = content.some((b) => b.type === "tool_use") ? "tool_call" : "stop";
      } else if (status === "incomplete") {
        const reason = asStr(pointer(body, "/incomplete_details/reason"));
        finishReason = reason === undefined ? "unknown" : mapFinish(reason);
      } else if (status === "in_progress" || status === "queued" || status === "cancelled") {
        finishReason = null;
      } else if (status !== undefined) {
        finishReason = "unknown";
      } else {
        throw bad(p, "response.status missing");
      }
      usage = usageOf(p, body);
      break;
    }
    case "anthropic_messages": {
      const value = get(body, "content");
      if (!isArray(value)) throw bad(p, "content must be an array");
      content = asResponseError(p, () => blocks(value, p));
      const reason = asStr(get(body, "stop_reason"));
      finishReason = reason === undefined ? null : mapFinish(reason);
      usage = usageOf(p, body);
      break;
    }
    case "gemini": {
      // A null is unset, as Google's JSON mapping reads it (`geminiField`).
      const found = geminiField(body, "candidates");
      if (found.error !== undefined) throw bad(p, found.error);
      const candidates = found.value;
      if (candidates !== undefined) {
        if (!isArray(candidates)) throw bad(p, "candidates must be an array");
        const first = primaryAlternative(candidates, p);
        if (first !== undefined) {
          content = asResponseError(p, () => blocks(pointer(first, "/content/parts"), p));
          const reason = asStr(get(first, "finishReason"));
          finishReason = reason === undefined ? null : mapFinish(reason);
        } else {
          const blocked = geminiBlockFinish(body);
          if (blocked === undefined) throw bad(p, "response has no candidates or blocking reason");
          finishReason = blocked;
        }
      } else {
        const blocked = geminiBlockFinish(body);
        if (blocked === undefined) throw bad(p, "response requires candidates or promptFeedback.blockReason");
        finishReason = blocked;
      }
      usage = usageOf(p, body);
      break;
    }
    default:
      throw notGeneration(p);
  }
  const named = get(body, "model");
  const model = asStr(named !== undefined ? named : get(body, "modelVersion")) ?? "";
  const toolCalls: ToolCall[] = [];
  for (const block of content) {
    if (block.type === "tool_use") toolCalls.push({ id: block.id, name: block.name, arguments: block.input });
  }
  return { protocol: p, model, content, tool_calls: toolCalls, finish_reason: finishReason, usage };
}

function requireString(v: Json | undefined, name: string, p: Protocol): string {
  const s = asStr(v);
  if (s === undefined) throw new ProtocolError({ kind: "invalid_request", protocol: p, message: `${name} must be a string` });
  return s;
}
