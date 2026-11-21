/**
 * The published lane rewrite policy: which byte-level ops Gray may apply to a request, per
 * protocol. It is data, so an auditor can read the closed set without reading the implementation,
 * and both the gateway and the customer's verifier run the same check.
 *
 * `gray-lane-rewrites-v1.json` is the published form of the same document; `GRAY_LANE_REWRITES_V1`
 * is its literal copy in the package (the workspace's packages export TypeScript source and do not
 * parse JSON at runtime). `test/policy.test.ts` holds the two to one value in Node and in workerd,
 * so the mirror cannot drift.
 *
 * A policy rule is `{op, path, value?}`. `remove_member` has no value rule; `set_member` and
 * `insert_member` have one of:
 * - `{kind: "string", min_bytes, max_bytes, forbid_control}` — a model id: non-empty, at most 512
 *   UTF-8 bytes, no C0 controls or DEL;
 * - `{kind: "integer", min, max}` — Gray's output cap, a u32 at least 1;
 * - `{kind: "const", value}` — a fixed value, e.g. `{"include_usage": true}`, the Responses
 *   `stream: true` a Codex route's request is sent with (D129), or the `store: false` every OpenAI stack route's
 *   Chat and Responses request is sent with (docs/relay-request-changes.md: no vendor-side storage under a relay's
 *   account).
 *
 * `remove_member /provider` takes out the customer's routing preference stated in the body (docs/design/one-address.md),
 * which the gateway reads and the vendor would refuse; it was added after gray-lane-verify 1.0.0, whose copy of this
 * policy refuses it, so that verifier fails such a receipt rather than passing it.
 *
 * The policy bounds the *shape* of a declaration, not which of two allowed ops the gateway chose
 * for a particular request: that choice is the request path's (for example, a cap is `set_member`
 * when the client wrote the field and `insert_member` when it did not). The signed event log says
 * exactly which one ran, and replay proves the bytes.
 *
 * `gray-lane-rewrites-v2` (docs/design/standard-media-at-entry.md section 2.4) is a second document, published
 * beside v1 as `gray-lane-rewrites-v2.json` with its literal copy `GRAY_LANE_REWRITES_V2`. It keeps v1's rules for
 * the three text APIs and lists the standard APIs the entry serves on a provider's own API (`REWRITE_APIS`): for a
 * JSON body `set_member /model` and the removal of `user`, `safety_identifier`, `metadata` and `provider`; for a
 * form `set_form_field model` and `remove_form_field user`, whose path is the field's name. A video create keeps
 * `metadata`, where a provider's own parameters travel. v1 is not changed by it: an event names the document that
 * allows it (`declared_in`), and a verifier that carries v1 alone fails an event that names v2.
 */
import { toJsonString, type Json } from "@gray/json";
import type { Protocol } from "@gray/protocol";
import { REQUEST_MODIFIED_OPS, isFormFieldName, isFormOp, isModifiedValue, type RequestModifiedFormOp, type RequestModifiedMemberOp, type RequestModifiedOp } from "@gray/attest";
import { parseJsonPointer } from "./pointer.ts";
import { LaneError } from "./refusal.ts";
import { LANE_PROTOCOLS, type LaneProtocol } from "./protocol.ts";
import { utf8Length } from "./utf8.ts";

/** The ops a `request.modified` event may name, re-exported from the receipt package. */
export const LANE_REWRITE_OPS: readonly RequestModifiedOp[] = REQUEST_MODIFIED_OPS;

/** One value constraint of a rule. */
export type RewriteValueRule =
  | { readonly kind: "string"; readonly min_bytes: number; readonly max_bytes: number; readonly forbid_control: boolean }
  | { readonly kind: "integer"; readonly min: number; readonly max: number }
  | { readonly kind: "const"; readonly value: Json };

/** One allowed op and path for one protocol. */
export interface RewriteRule {
  readonly op: RequestModifiedMemberOp;
  readonly path: string;
  /** Absent exactly for `remove_member`. */
  readonly value?: RewriteValueRule;
}

/** One allowed form op and field name for one API (gray-lane-rewrites-v2). */
export interface FormRewriteRule {
  readonly op: RequestModifiedFormOp;
  /** The field's name, never a JSON Pointer. */
  readonly path: string;
  /** Absent exactly for `remove_form_field`; a form field's value is text. */
  readonly value?: Extract<RewriteValueRule, { readonly kind: "string" }>;
}

/** A rule of gray-lane-rewrites-v2: on a JSON body's member or on a form's field. */
export type ApiRewriteRule = RewriteRule | FormRewriteRule;

/**
 * The APIs gray-lane-rewrites-v2 lists (@gray/protocol's names): the lane's three text APIs, and the standard APIs the
 * entry serves on a provider's own API (docs/design/standard-media-at-entry.md section 2.1).
 */
export type RewriteApi =
  | LaneProtocol
  | Extract<
      Protocol,
      | "open_ai_embeddings"
      | "rerank"
      | "open_ai_image_generations"
      | "open_ai_image_edits"
      | "open_ai_speech"
      | "open_ai_transcriptions"
      | "open_ai_translations"
      | "open_ai_videos"
      | "system_one"
    >;

/** v2's APIs, in the order the document lists them. */
export const REWRITE_APIS: readonly RewriteApi[] = Object.freeze([
  ...LANE_PROTOCOLS,
  "open_ai_embeddings",
  "rerank",
  "open_ai_image_generations",
  "open_ai_image_edits",
  "open_ai_speech",
  "open_ai_transcriptions",
  "open_ai_translations",
  "open_ai_videos",
  "system_one",
] as const);

/** Whether `value` is one of v2's APIs. */
export function isRewriteApi(value: unknown): value is RewriteApi {
  return typeof value === "string" && (REWRITE_APIS as readonly string[]).includes(value);
}

/** The whole v2 document: v1's shape, over more APIs, with form rules beside member rules. */
export interface LaneRewritePolicyV2 {
  readonly id: string;
  readonly version: number;
  readonly protocols: Readonly<Record<RewriteApi, readonly ApiRewriteRule[]>>;
}

/** The whole published document. */
export interface LaneRewritePolicy {
  readonly id: string;
  readonly version: number;
  readonly protocols: Readonly<Record<LaneProtocol, readonly RewriteRule[]>>;
}

const CONTROL = /[\u0000-\u001f\u007f]/;
const POLICY_ID = /^[a-z][a-z0-9._-]{0,127}$/;

const MODEL_STRING = { kind: "string", min_bytes: 1, max_bytes: 512, forbid_control: true } as const;
const OUTPUT_CAP = { kind: "integer", min: 1, max: 4_294_967_295 } as const;
const INCLUDE_USAGE = { kind: "const", value: true } as const;
const STREAM_OPTIONS_ON = { kind: "const", value: { include_usage: true } } as const;
/** D129: a Codex route's upstream request streams (the only form chatgpt.com's Codex backend takes); no OpenAI stack request is stored. */
const STREAM_ON = { kind: "const", value: true } as const;
const STORE_OFF = { kind: "const", value: false } as const;

const RAW_POLICY: unknown = {
  id: "gray-lane-rewrites-v1",
  version: 1,
  protocols: {
    anthropic_messages: [
      { op: "set_member", path: "/model", value: MODEL_STRING },
      { op: "insert_member", path: "/model", value: MODEL_STRING },
      { op: "remove_member", path: "/models" },
      { op: "remove_member", path: "/provider" },
      { op: "set_member", path: "/max_tokens", value: OUTPUT_CAP },
      { op: "insert_member", path: "/max_tokens", value: OUTPUT_CAP },
      { op: "remove_member", path: "/metadata/user_id" },
    ],
    open_ai_chat: [
      { op: "set_member", path: "/model", value: MODEL_STRING },
      { op: "insert_member", path: "/model", value: MODEL_STRING },
      { op: "remove_member", path: "/models" },
      { op: "remove_member", path: "/provider" },
      { op: "set_member", path: "/max_tokens", value: OUTPUT_CAP },
      { op: "insert_member", path: "/max_tokens", value: OUTPUT_CAP },
      { op: "set_member", path: "/max_completion_tokens", value: OUTPUT_CAP },
      { op: "remove_member", path: "/user" },
      { op: "remove_member", path: "/safety_identifier" },
      { op: "remove_member", path: "/metadata" },
      { op: "insert_member", path: "/stream_options", value: STREAM_OPTIONS_ON },
      { op: "set_member", path: "/stream_options/include_usage", value: INCLUDE_USAGE },
      { op: "insert_member", path: "/stream_options/include_usage", value: INCLUDE_USAGE },
      { op: "set_member", path: "/store", value: STORE_OFF },
      { op: "insert_member", path: "/store", value: STORE_OFF },
    ],
    open_ai_responses: [
      { op: "set_member", path: "/model", value: MODEL_STRING },
      { op: "insert_member", path: "/model", value: MODEL_STRING },
      { op: "remove_member", path: "/models" },
      { op: "remove_member", path: "/provider" },
      { op: "set_member", path: "/max_output_tokens", value: OUTPUT_CAP },
      { op: "insert_member", path: "/max_output_tokens", value: OUTPUT_CAP },
      { op: "remove_member", path: "/user" },
      { op: "remove_member", path: "/safety_identifier" },
      { op: "remove_member", path: "/metadata" },
      { op: "set_member", path: "/stream", value: STREAM_ON },
      { op: "insert_member", path: "/stream", value: STREAM_ON },
      { op: "set_member", path: "/store", value: STORE_OFF },
      { op: "insert_member", path: "/store", value: STORE_OFF },
    ],
  },
};

/** The policy the verifier uses when the caller names none. */
export const GRAY_LANE_REWRITES_V1: LaneRewritePolicy = validateRewritePolicy(RAW_POLICY);

/** `declared_in` of every event this policy allows. */
export const GRAY_LANE_REWRITES_V1_ID = GRAY_LANE_REWRITES_V1.id;

/** What Gray changes in a JSON body of a standard API: the provider's name for the model, and what names the end user or routes. */
const API_JSON_RULES = [
  { op: "set_member", path: "/model", value: MODEL_STRING },
  { op: "remove_member", path: "/user" },
  { op: "remove_member", path: "/safety_identifier" },
  { op: "remove_member", path: "/metadata" },
  { op: "remove_member", path: "/provider" },
] as const;
/** The same in a form: its routing preference is a header, so there is no `provider` field to take out. */
const API_FORM_RULES = [
  { op: "set_form_field", path: "model", value: MODEL_STRING },
  { op: "remove_form_field", path: "user" },
] as const;

const RAW_POLICY_V2: unknown = {
  id: "gray-lane-rewrites-v2",
  version: 2,
  protocols: {
    ...(RAW_POLICY as { readonly protocols: Record<string, unknown> }).protocols,
    open_ai_embeddings: API_JSON_RULES,
    rerank: API_JSON_RULES,
    open_ai_image_generations: API_JSON_RULES,
    open_ai_image_edits: API_FORM_RULES,
    open_ai_speech: API_JSON_RULES,
    open_ai_transcriptions: API_FORM_RULES,
    open_ai_translations: API_FORM_RULES,
    // A video create is JSON or a form, and keeps `metadata`: the provider's own parameters (the standard's clause 11.12).
    open_ai_videos: [...API_JSON_RULES.filter((rule) => rule.path !== "/metadata"), ...API_FORM_RULES],
    system_one: API_JSON_RULES,
  },
};

/** gray-lane-rewrites-v2: v1's rules for the three text APIs, and the standard APIs' (docs/design/standard-media-at-entry.md section 2.4). */
export const GRAY_LANE_REWRITES_V2: LaneRewritePolicyV2 = validateRewritePolicyV2(RAW_POLICY_V2);

/** `declared_in` of every event v2 allows. */
export const GRAY_LANE_REWRITES_V2_ID = "gray-lane-rewrites-v2" as const;
if (GRAY_LANE_REWRITES_V2.id !== GRAY_LANE_REWRITES_V2_ID) throw new LaneError("lane/policy", "gray-lane-rewrites-v2's id");

/**
 * v2's rules for the lane's three text APIs as a policy of v1's shape, for the replay of a text request whose ops
 * name v2 (`replayForwarded`, `applyDeclaredChanges`). They are v1's rules under v2's id.
 */
export const GRAY_LANE_REWRITES_V2_TEXT: LaneRewritePolicy = validateRewritePolicy({
  id: GRAY_LANE_REWRITES_V2.id,
  version: GRAY_LANE_REWRITES_V2.version,
  protocols: Object.fromEntries(LANE_PROTOCOLS.map((protocol) => [protocol, GRAY_LANE_REWRITES_V2.protocols[protocol]])),
});

/** The rule of `policy` that allows `op` on `path` for `api`, or undefined. */
export function apiRewriteRuleFor(
  policy: LaneRewritePolicyV2,
  api: RewriteApi,
  op: { readonly op: RequestModifiedOp; readonly path: string },
): ApiRewriteRule | undefined {
  return policy.protocols[api].find((rule) => rule.op === op.op && rule.path === op.path);
}

/** The rule that allows `op` on `path` for `protocol`, or undefined. */
export function rewriteRuleFor(
  policy: LaneRewritePolicy,
  protocol: LaneProtocol,
  op: { readonly op: RequestModifiedOp; readonly path: string },
): RewriteRule | undefined {
  return policy.protocols[protocol].find((rule) => rule.op === op.op && rule.path === op.path);
}

/** Whether `value` satisfies a rule's value constraint. `remove_member` and `remove_form_field` require `undefined`. */
export function ruleAllowsValue(rule: ApiRewriteRule, value: Json | undefined): boolean {
  if (rule.op === "remove_member" || rule.op === "remove_form_field") return value === undefined;
  if (rule.value === undefined || value === undefined) return false;
  switch (rule.value.kind) {
    case "string": {
      if (typeof value !== "string" || !value.isWellFormed()) return false;
      const bytes = utf8Length(value);
      if (bytes < rule.value.min_bytes || bytes > rule.value.max_bytes) return false;
      return !rule.value.forbid_control || !CONTROL.test(value);
    }
    case "integer":
      return typeof value === "bigint" && value >= BigInt(rule.value.min) && value <= BigInt(rule.value.max);
    case "const":
      if (!isModifiedValue(value)) return false;
      try {
        return toJsonString(value) === toJsonString(rule.value.value);
      } catch {
        return false;
      }
  }
}

/**
 * Validate a policy document and return its typed form. Throws `LaneError` for a document the lane
 * cannot run; the published constant is validated at module load, so a bad edit fails the build's
 * first import, and the tests can run the same check over the JSON mirror.
 */
export function validateRewritePolicy(value: unknown): LaneRewritePolicy {
  const root = record(value, "the policy");
  const id = root.id;
  if (typeof id !== "string" || !POLICY_ID.test(id)) throw new LaneError("lane/policy", "the policy id is not a lower-case policy id");
  const version = integer(root.version);
  if (version === undefined || version < 1n || version > 0x7fff_ffffn) throw new LaneError("lane/policy", "the policy version is not a positive integer");
  const protocols = record(root.protocols, "the policy protocols");
  const names = Object.keys(protocols).sort();
  const expected = [...LANE_PROTOCOLS].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    throw new LaneError("lane/policy", "the policy must have exactly the lane's three protocols");
  }
  const parsed: Record<string, readonly RewriteRule[]> = {};
  for (const protocol of LANE_PROTOCOLS) {
    const list = protocols[protocol];
    if (!Array.isArray(list)) throw new LaneError("lane/policy", `the ${protocol} rules are not an array`);
    const seen = new Set<string>();
    const rules: RewriteRule[] = [];
    for (const entry of list) rules.push(parseRule(entry, protocol, seen));
    parsed[protocol] = rules;
  }
  return { id, version: Number(version), protocols: parsed as Record<LaneProtocol, readonly RewriteRule[]> };
}

/**
 * Validate a document of v2's shape and return its typed form: exactly `REWRITE_APIS`, each rule a member rule as in
 * v1 or a form rule (`set_form_field` with a string rule, `remove_form_field` with none, the path a field name). The
 * three text APIs are JSON, so a form rule there is refused. Throws `LaneError`, as `validateRewritePolicy` does.
 */
export function validateRewritePolicyV2(value: unknown): LaneRewritePolicyV2 {
  const root = record(value, "the policy");
  const id = root.id;
  if (typeof id !== "string" || !POLICY_ID.test(id)) throw new LaneError("lane/policy", "the policy id is not a lower-case policy id");
  const version = integer(root.version);
  if (version === undefined || version < 1n || version > 0x7fff_ffffn) throw new LaneError("lane/policy", "the policy version is not a positive integer");
  const protocols = record(root.protocols, "the policy protocols");
  const names = Object.keys(protocols).sort();
  const expected = [...REWRITE_APIS].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    throw new LaneError("lane/policy", "the policy must have exactly the APIs of gray-lane-rewrites-v2");
  }
  const parsed: Record<string, readonly ApiRewriteRule[]> = {};
  for (const api of REWRITE_APIS) {
    const list = protocols[api];
    if (!Array.isArray(list)) throw new LaneError("lane/policy", `the ${api} rules are not an array`);
    const text = (LANE_PROTOCOLS as readonly string[]).includes(api);
    const seen = new Set<string>();
    const rules: ApiRewriteRule[] = [];
    for (const entry of list) {
      if (!isFormOp(record(entry, `a ${api} rule`).op)) rules.push(parseRule(entry, api, seen));
      else if (text) throw new LaneError("lane/policy", `a form rule in ${api}, whose body is JSON`);
      else rules.push(parseFormRule(entry, api, seen));
    }
    parsed[api] = rules;
  }
  return { id, version: Number(version), protocols: parsed as Record<RewriteApi, readonly ApiRewriteRule[]> };
}

function parseFormRule(value: unknown, api: string, seen: Set<string>): FormRewriteRule {
  const rule = record(value, `a ${api} rule`);
  const op = rule.op;
  if (op !== "set_form_field" && op !== "remove_form_field") throw new LaneError("lane/policy", `unknown rewrite op in ${api}`);
  if (!isFormFieldName(rule.path)) throw new LaneError("lane/policy", `a ${api} form rule's path is not a field name`);
  const identity = `${op} ${rule.path}`;
  if (seen.has(identity)) throw new LaneError("lane/policy", `a ${api} rule is repeated`);
  seen.add(identity);
  if (op === "remove_form_field") {
    if (rule.value !== undefined) throw new LaneError("lane/policy", `the ${api} removal rule carries a value`);
    return { op, path: rule.path };
  }
  if (rule.value === undefined) throw new LaneError("lane/policy", `the ${api} ${op} rule has no value`);
  const valueRule = parseValueRule(rule.value, api);
  if (valueRule.kind !== "string") throw new LaneError("lane/policy", `the ${api} ${op} rule's value is not a string rule: a form field is text`);
  return { op, path: rule.path, value: valueRule };
}

function parseRule(value: unknown, protocol: string, seen: Set<string>): RewriteRule {
  const rule = record(value, `a ${protocol} rule`);
  const op = rule.op;
  if (op !== "set_member" && op !== "insert_member" && op !== "remove_member") {
    throw new LaneError("lane/policy", `unknown rewrite op in ${protocol}`);
  }
  if (typeof rule.path !== "string") throw new LaneError("lane/policy", `a ${protocol} rule has no path`);
  if (!parseJsonPointer(rule.path).ok) throw new LaneError("lane/policy", `a ${protocol} rule has an unsupported path`);
  const identity = `${op} ${rule.path}`;
  if (seen.has(identity)) throw new LaneError("lane/policy", `a ${protocol} rule is repeated`);
  seen.add(identity);
  if (op === "remove_member") {
    if (rule.value !== undefined) throw new LaneError("lane/policy", `the ${protocol} removal rule carries a value`);
    return { op, path: rule.path };
  }
  if (rule.value === undefined) throw new LaneError("lane/policy", `the ${protocol} ${op} rule has no value`);
  return { op, path: rule.path, value: parseValueRule(rule.value, protocol) };
}

function parseValueRule(value: unknown, protocol: string): RewriteValueRule {
  const rule = record(value, `a ${protocol} value rule`);
  if (rule.kind === "string") {
    const min = integer(rule.min_bytes);
    const max = integer(rule.max_bytes);
    if (min === undefined || max === undefined || min < 0n || max < min || max > 1_000_000n) {
      throw new LaneError("lane/policy", `a ${protocol} string rule has bad bounds`);
    }
    if (typeof rule.forbid_control !== "boolean") throw new LaneError("lane/policy", `a ${protocol} string rule has no forbid_control`);
    return { kind: "string", min_bytes: Number(min), max_bytes: Number(max), forbid_control: rule.forbid_control };
  }
  if (rule.kind === "integer") {
    const min = integer(rule.min);
    const max = integer(rule.max);
    if (min === undefined || max === undefined || min > max) throw new LaneError("lane/policy", `a ${protocol} integer rule has bad bounds`);
    if (min < BigInt(Number.MIN_SAFE_INTEGER) || max > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new LaneError("lane/policy", `a ${protocol} integer rule is outside the exact integer range`);
    }
    return { kind: "integer", min: Number(min), max: Number(max) };
  }
  if (rule.kind === "const") {
    if (!isModifiedValue(rule.value)) throw new LaneError("lane/policy", `a ${protocol} const rule has a value no event may carry`);
    try {
      toJsonString(rule.value);
    } catch {
      throw new LaneError("lane/policy", `a ${protocol} const rule has a value the writer refuses`);
    }
    return { kind: "const", value: rule.value };
  }
  throw new LaneError("lane/policy", `unknown value-rule kind in ${protocol}`);
}

function record(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new LaneError("lane/policy", `${what} is not an object`);
  return value as Record<string, unknown>;
}

function integer(value: unknown): bigint | undefined {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  return undefined;
}
