import { bindsThinking, capabilitiesFromClaims, CODING_AGENT_SHAPE, opencodeThinking as opencodeThinkingOf, thinkingSent, type Capabilities, type OpencodeThinking } from "@gray/control";
import { asArray, asStr, get, isObject, parseSerde, pointer, toJsonString, type Json, type JsonObject } from "@gray/json";
import { ProtocolStreamDecoder, SseDecoder, type CanonicalEvent, type FinishReason, type Protocol } from "@gray/protocol";
import { compileSchema, type JsonSchema } from "json-schema-library";
import anthropicMessages from "../../../../crates/gray-verifier/fixtures/opencode-2.0.27/anthropic_messages.json" with { type: "json" };
import gemini from "../../../../crates/gray-verifier/fixtures/opencode-2.0.27/gemini.json" with { type: "json" };
import manifestJson from "../../../../crates/gray-verifier/fixtures/opencode-2.0.27/manifest.json" with { type: "json" };
import openAiChat from "../../../../crates/gray-verifier/fixtures/opencode-2.0.27/open_ai_chat.json" with { type: "json" };
import openAiResponses from "../../../../crates/gray-verifier/fixtures/opencode-2.0.27/open_ai_responses.json" with { type: "json" };
import { billingRules, fail, inputBound, mergeUsage, NO_USAGE, REASONING_OUTPUT_LIMIT, Refusal, rustTrim, streamError, unclear, usage, type Challenge, type ProbeUsage, type Verdict } from "./native.ts";
import type { CheckBound } from "./runner.ts";
import type { CheckResult } from "./report.ts";
import type { ProbeTarget } from "./target.ts";

/**
 * The coding-agent check (crates/gray-verifier/src/coding_agent.rs): one request shaped like OpenCode 2's own
 * first agent turn, its system prompt and tool list byte for byte, with a fresh challenge.
 *
 * Gray's route checks send its own short prompts, so they cannot see a relay that refuses requests it
 * recognises as a coding agent's: yylx answered all three of OpenCode's first agent turns on
 * `claude-haiku-5.5` with 400 "Third-party apps now draw from extra usage, not plan limits...", direct too,
 * while it served OpenCode's title requests and every check (2026-10-18). This check is how Gray learns which
 * routes serve OpenCode's agent: OpenCode's default model is chosen only among them.
 *
 * It never decides a route. Its result is a client check (`ProbeReport.client_checks`), which route status,
 * proven capabilities and admission never read: a refusing route keeps serving every other request.
 *
 * The fixtures (crates/gray-verifier/fixtures/opencode-2.0.27/, captured by scripts/capture-opencode-shape.mjs
 * from OpenCode itself, never from a customer's request; OpenCode's MIT licence is in their NOTICE) keep
 * OpenCode's text and fields and mark what identifies a model, a machine, a day or a session; the check fills
 * those with the mapping's Gray model and neutral values, its own challenge as the user's turn, a fresh cache key
 * and the output limit of a tools check. They are read here as the Rust crate reads them, not copied.
 */

/** The shape this release checks (`SHAPE`): OpenCode's version. A result is kept per shape. */
export const SHAPE = CODING_AGENT_SHAPE;

/** The provider ID OpenCode writes in its model block for a Gray model: `gray`, as `GET /v1/setup/opencode.json` defines it. */
const PROVIDER_ID = "gray";

/**
 * `ClientModel`: what a mapping is called in OpenCode's model block (its Gray model ID and its catalog name, as
 * `GET /v1/setup/opencode.json` names it), and whether the route proved reasoning, which decides whether Gray's
 * configuration lets OpenCode ask the model to reason (`opencodeThinking`).
 */
export interface ClientModel {
  readonly id: string;
  readonly name: string;
  readonly reasoning: boolean;
}

/** The beta OpenCode adds to `anthropic-beta` with `block_binding`. */
const BINDING_BETA = "thinking-binding-controls-2026-08-01";

/** `OpencodeThinking::field`: the `thinking` field of the Messages request; undefined for `none`. */
function thinkingField(thinking: OpencodeThinking): JsonObject | undefined {
  switch (thinking) {
    case "disabled":
      return { type: "disabled" };
    case "adaptive":
      return { type: "adaptive", block_binding: { prefix_mismatch_behavior: "drop_block" } };
    case "none":
      return undefined;
  }
}

/** `thinking_sent` and `binds_thinking`: the pure rule lives in @gray/control (opencode-thinking.ts), which the gateway's catalog reads too. */
export { bindsThinking, thinkingSent };

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

/** `opencode_thinking` of a check's `model` (@gray/control `opencodeThinking`). */
export function opencodeThinking(model: ClientModel): OpencodeThinking {
  return opencodeThinkingOf(model);
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

interface Shape {
  /** The neutral values of the machine and the day (manifest.json). */
  readonly neutral: ReadonlyMap<string, string>;
  readonly fixtures: readonly Fixture[];
}

let shapeData: Shape | null = null;

function shape(): Shape {
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
 * `applies`: whether a mapping of `protocol` on an endpoint claiming `claimed` gets the check: a generation API
 * OpenCode calls (Anthropic Messages, Responses, Gemini, Chat), on an endpoint that claims tools, as every
 * OpenCode agent turn declares them, and not image output: a model that answers with images is no coding
 * agent's default.
 */
export function codingAgentApplies(protocol: Protocol, claimed: Capabilities): boolean {
  return claimed.tools && !claimed.image_output && fixture(protocol) !== null;
}

/**
 * The gateway's `applies` (crates/gray-gateway/src/coding_agent.rs): whether a mapping of `protocol` on an endpoint
 * whose configuration claims `claims` gets the check (`codingAgentApplies`); claims that do not read as capabilities
 * (`Capabilities::from_claims`: an unknown claim) get none.
 */
export function codingAgentAppliesToClaims(protocol: Protocol, claims: readonly string[]): boolean {
  try {
    return codingAgentApplies(protocol, capabilitiesFromClaims(claims));
  } catch {
    return false;
  }
}

/** `user_turn`: the challenge's order number alone, named as every check names it. */
export function userTurn(c: Challenge): string {
  return `Reply with only the number of order ${c.nonce}, nothing else.`;
}

/**
 * `fill`: `value` with every placeholder filled: `{{OUTPUT_LIMIT}}` as the number `limit`, each other `{{NAME}}` inside
 * a string by `values`, in their order: a filled value that itself carries placeholder text is filled again by the
 * names after its own.
 */
function fill(value: Json, values: ReadonlyMap<string, string>, limit: number): Json {
  if (typeof value === "string") {
    if (value === "{{OUTPUT_LIMIT}}") return BigInt(limit);
    if (!value.includes("{{")) return value;
    let text = value;
    for (const [name, filled] of values) text = text.replaceAll(`{{${name}}}`, filled);
    return text;
  }
  if (Array.isArray(value)) return value.map((item) => fill(item, values, limit));
  if (isObject(value)) {
    const out: JsonObject = {};
    for (const [key, v] of Object.entries(value)) Object.defineProperty(out, key, { value: fill(v as Json, values, limit), enumerable: true, writable: true, configurable: true });
    return out;
  }
  return value;
}

/** `cache_key`: a fresh `prompt_cache_key` shaped as OpenCode's session ids are (`ses_` and 26 characters). */
export function cacheKey(): string {
  return `ses_${crypto.randomUUID().replaceAll("-", "").slice(0, 26)}`;
}

/**
 * `opencode_request`: OpenCode's request on `protocol` for the Gray model `model` with the user's turn
 * `turn`, as the check fills it: its body without a `model` field, with the thinking OpenCode asks the model for
 * on the Messages API, and the headers of it Gray forwards. Null for an API OpenCode does not call.
 */
export function opencodeRequest(protocol: Protocol, model: ClientModel, turn: string, key: string): { body: JsonObject; headers: [string, string][] } | null {
  const f = fixture(protocol);
  if (f === null) return null;
  const values = new Map(shape().neutral);
  values.set("MODEL_NAME", model.name);
  values.set("PROVIDER_ID", PROVIDER_ID);
  values.set("MODEL_ID", model.id);
  values.set("USER_TURN", turn);
  values.set("CACHE_KEY", key);
  // In name order, as Rust's `BTreeMap` of them iterates (the names are ASCII).
  const ordered = new Map([...values].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  const body = fill(f.body, ordered, REASONING_OUTPUT_LIMIT) as JsonObject;
  const headers = f.headers.map(([name, value]) => [name, value] as [string, string]);
  const thinking = thinkingSent(protocol, model.id, model.reasoning);
  const field = thinkingField(thinking);
  if (field !== undefined) Object.defineProperty(body, "thinking", { value: field, enumerable: true, writable: true, configurable: true });
  if (thinking === "adaptive") for (const h of headers) if (h[0] === "anthropic-beta") h[1] = `${h[1]},${BINDING_BETA}`;
  return { body, headers };
}

/** `request`: the body and forwarded headers of one draw of the check of `target` (its `model` the upstream model) for the Gray model `model`. */
export function codingAgentRequest(target: ProbeTarget, model: ClientModel, c: Challenge, key: string): { body: JsonObject; headers: [string, string][] } | null {
  const built = opencodeRequest(target.protocol, model, userTurn(c), key);
  if (built === null) return null;
  // As every check asks the upstream model; Gemini names it in the path.
  if (target.protocol !== "gemini") Object.defineProperty(built.body, "model", { value: target.model, enumerable: true, writable: true, configurable: true });
  return built;
}

/**
 * `bound`: what one draw of the check of `target` may bill at most: its body's bound with the declared allowance,
 * and the output limit of a tools check with the declared output allowance. Every draw's body has the same
 * length: the order number and the cache key have fixed lengths.
 */
export function codingAgentBound(target: ProbeTarget, model: ClientModel, c: Challenge): CheckBound | null {
  const built = codingAgentRequest(target, model, c, cacheKey());
  if (built === null) return null;
  return { kind: "coding_agent", input: inputBound(target, built.body), output: REASONING_OUTPUT_LIMIT + target.declared.output_overhead_tokens, units: 0, size: null };
}

/** `declared_tools`: the tools a fixture declares, each by name with its argument schema. */
function declaredTools(protocol: Protocol): [string, Json][] {
  const f = fixture(protocol);
  if (f === null) return [];
  const tools = asArray(get(f.body, "tools")) ?? [];
  const named = (tool: Json | undefined, schema: string): [string, Json] | null => {
    const name = asStr(get(tool ?? null, "name"));
    return name === undefined ? null : [name, get(tool ?? null, schema) ?? {}];
  };
  const out: ([string, Json] | null)[] = [];
  switch (protocol) {
    case "anthropic_messages":
      for (const t of tools) out.push(named(t, "input_schema"));
      break;
    case "open_ai_responses":
      for (const t of tools) out.push(named(t, "parameters"));
      break;
    case "open_ai_chat":
      for (const t of tools) out.push(named(get(t, "function"), "parameters"));
      break;
    case "gemini":
      for (const t of tools) for (const d of asArray(get(t, "functionDeclarations")) ?? []) out.push(named(d, get(d, "parametersJsonSchema") !== undefined ? "parametersJsonSchema" : "parameters"));
      break;
    default:
      break;
  }
  return out.filter((x): x is [string, Json] => x !== null);
}

/** A `Json` value as plain JavaScript, for the schema library. */
function plain(value: Json): unknown {
  if (typeof value === "bigint") return Number(value);
  if (Array.isArray(value)) return value.map(plain);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v as Json)]));
  return value;
}

/**
 * `valid_call`: whether `args`, a tool call's arguments as the stream decoder keeps them, are what tool `name`
 * of `protocol`'s fixture accepts: a declared tool, and arguments its schema validates. Rust validates with the
 * jsonschema crate and Gray's `uniqueItems` (gray-verifier `json_schema`); here json-schema-library 11.6.6, the
 * library @gray/trust's tool gate is built on, validates the fixtures' plain schemas the same way (types, required,
 * minimum, minItems and the like). Its `uniqueItems` compares every pair by value (fast-deep-equal on plain values:
 * `0` and `-0`, `1` and `1.0` equal), at every length, as Rust's does; no fixture tool declares it.
 */
export function validCall(protocol: Protocol, name: string | null | undefined, args: Json): boolean {
  if (name === null || name === undefined || !isObject(args)) return false;
  const declared = declaredTools(protocol).find(([n]) => n === name);
  if (declared === undefined) return false;
  try {
    return compileSchema(plain(declared[1]) as JsonSchema).validate(plain(args)).valid;
  } catch {
    return false;
  }
}

/**
 * `judge`: the verdict on a streamed answer `bytes` of the check of challenge `c` on `protocol`, and the usage it
 * reported. It passes when the stream reached its terminal event with its usage (where `requireUsage`), and its
 * text carries the order number or it called the fixture's declared tools only, each with arguments their schema
 * accepts: a served agent turn either way. Text without the number, or a call of an undeclared tool or with
 * refused arguments, is a `challenge_mismatch`, which another draw may change. An error event in the stream is
 * an unclear answer here; the caller reads the refusal from it (`streamRefusal`).
 */
export function judge(protocol: Protocol, bytes: Uint8Array, c: Challenge, requireUsage: boolean): { verdict: Verdict | null; usage: ProbeUsage } {
  let usageResult: ProbeUsage = { ...NO_USAGE };
  const refuse = (v: Verdict): never => {
    throw new Refusal(v);
  };
  const run = (): Verdict | null => {
    const frames = (() => {
      const d = new SseDecoder();
      try {
        return d.push(bytes).concat(d.finish());
      } catch (error) {
        return refuse(streamError(error));
      }
    })();
    let anthropicUsage: JsonObject = {};
    for (const frame of frames) {
      // Rust's `str::trim` (Unicode White_Space): a BOM before `[DONE]` is no end marker.
      if (rustTrim(frame.data) === "[DONE]") continue;
      let v: Json;
      try {
        v = parseSerde(frame.data);
      } catch {
        return refuse(fail("malformed_json"));
      }
      if (get(v, "error") !== undefined || get(v, "type") === "error") return refuse(unclear("upstream_unavailable"));
      switch (protocol) {
        case "open_ai_chat": {
          const choices = asArray(get(v, "choices"));
          if (choices === undefined || choices.length > 1) refuse(fail("invalid_stream"));
          if (isObject(get(v, "usage"))) usageResult = usage(protocol, v);
          break;
        }
        case "open_ai_responses":
          if (get(v, "type") === "response.completed") {
            try {
              usageResult = usage(protocol, get(v, "response") ?? null);
            } catch (error) {
              if (!(error instanceof Refusal)) throw error;
              if (requireUsage || error.verdict[0] === "fail") throw error;
            }
          }
          break;
        case "anthropic_messages": {
          const type = asStr(get(v, "type"));
          if (type === "message_start") {
            const u = pointer(v, "/message/usage");
            if (u !== undefined) anthropicUsage = mergeUsage(anthropicUsage, u);
          } else if (type === "message_delta") {
            const u = get(v, "usage");
            if (u !== undefined) anthropicUsage = mergeUsage(anthropicUsage, u);
            if (["input_tokens", "output_tokens"].every((k) => typeof anthropicUsage[k] === "bigint" && (anthropicUsage[k] as bigint) >= 0n && (anthropicUsage[k] as bigint) <= 0xffff_ffff_ffff_ffffn)) {
              usageResult = usage(protocol, { usage: anthropicUsage });
            }
          }
          break;
        }
        case "gemini": {
          const candidates = asArray(get(v, "candidates"));
          if (candidates !== undefined && candidates.length > 1) refuse(fail("invalid_stream"));
          if (get(v, "usageMetadata") !== undefined) usageResult = usage(protocol, v);
          break;
        }
        default:
          refuse(fail("invalid_stream"));
      }
    }
    const decoder = new ProtocolStreamDecoder(protocol);
    let events: CanonicalEvent[];
    try {
      events = decoder.push(bytes).concat(decoder.finish());
    } catch (error) {
      return refuse(streamError(error));
    }
    billingRules(protocol, decoder.rawUsage());
    let text = "";
    const calls = new Map<number, { name: string | null; args: Json | undefined }>();
    const finishes: FinishReason[] = [];
    for (const event of events) {
      if (event.type === "text_delta") text += event.text;
      else if (event.type === "tool_call_delta" || event.type === "tool_call_complete") {
        const index = Number(event.index);
        const call = calls.get(index) ?? { name: null, args: undefined };
        call.name = call.name ?? event.name ?? null;
        if (event.type === "tool_call_complete") call.args = event.arguments;
        calls.set(index, call);
      } else if (event.type === "finish") finishes.push(event.reason);
    }
    if (finishes.length === 0) return refuse(fail("missing_terminal"));
    if (finishes.some((r) => r !== "stop" && r !== "tool_call")) return refuse(unclear("missing_terminal"));
    if (requireUsage && !usageResult.complete) return refuse(unclear("missing_usage"));
    if (text.includes(c.nonce)) return null;
    const servedByTools = calls.size > 0 && [...calls.values()].every((call) => call.args !== undefined && validCall(protocol, call.name, call.args));
    return servedByTools ? null : fail("challenge_mismatch");
  };
  try {
    return { verdict: run(), usage: usageResult };
  } catch (error) {
    if (error instanceof Refusal) return { verdict: error.verdict, usage: usageResult };
    throw error;
  }
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

/**
 * `not_sent`: the result of a check that was planned and not sent: its budget lease was refused, or the time left
 * for it ran out first. Inconclusive, with no challenge and no usage: it cost nothing.
 */
export function notSent(code: CheckResult["code"]): CheckResult {
  return { kind: "coding_agent", retired_model_label: null, first_try: null, status: "inconclusive", code, duration_ms: 0, http_status: null, challenge_hash: "", response_hash: null, usage: { ...NO_USAGE } };
}

/** Every placeholder name a fixture may carry (`PLACEHOLDERS`). */
export const PLACEHOLDERS = ["MODEL_NAME", "PROVIDER_ID", "MODEL_ID", "DATE", "WORKING_DIRECTORY", "WORKSPACE_ROOT", "GIT_REPO", "PLATFORM", "USER_TURN", "CACHE_KEY", "OUTPUT_LIMIT"] as const;
