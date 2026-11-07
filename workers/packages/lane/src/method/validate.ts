/**
 * `validateMethod`: the registration checks of docs/relay-changes-v2.md §2.4, and the parse of a method document into
 * the `RelayMethod` that `applyMethod` runs.
 *
 * The checks are structural: Gray reads no text for meaning. The console runs them at registration, egress runs the
 * same ones in Go when it loads a document, and the shared vectors hold every refusal with its code. A refusal names
 * a closed code and a fixed sentence; it never echoes the document.
 *
 * **Reading.** The document is strict UTF-8 and strict JSON as the lane reads a body (`stackJsonTree`: serde_json's
 * reading, no duplicate member at any depth). Its identity is SHA-256 of its comparison form (RFC 8785 with every
 * number token as written: `body_jcs_sha256`'s form), so a value a method writes reaches the body exactly as the
 * published document spells it. The format is closed: a member the format does not name is a refusal.
 */
import { parseStrict } from "@gray/json";
import { OPENAI_COMPATIBLE_VENDORS } from "../vendors.ts";
import { isLaneProtocol, type LaneProtocol } from "../protocol.ts";
import { refusal, type Refusal } from "../refusal.ts";
import { sha256Hex } from "../sha256.ts";
import { stackJsonTree, stackTreeText, type StackJsonTree } from "../stack-digest.ts";
import { isMethodClientHeader } from "./facts.ts";
import {
  METHOD_CONTENT_MEMBERS,
  METHOD_ELEMENT_ARRAYS,
  METHOD_JSON_TYPES,
  METHOD_KEPT_ANY_DEPTH,
  METHOD_KEPT_MEMBERS,
  METHOD_KEPT_PATHS,
  METHOD_KEPT_PREFIX,
  METHOD_LIMITS,
  METHOD_REFUSED_HEADERS,
  METHOD_TEXT_SOURCES,
  METHOD_TOKEN_HEADERS,
  RELAY_METHOD_FORMAT,
  isMethodPositionFor,
  type MethodClientHeader,
  type MethodCondition,
  type MethodHeaderOp,
  type MethodJsonType,
  type MethodMap,
  type MethodMapFact,
  type MethodOp,
  type MethodPath,
  type MethodPosition,
  type MethodRefusalCode,
  type MethodRule,
  type MethodValue,
  type RelayMethod,
} from "./format.ts";

export interface ValidateMethodOptions {
  /** The sha256 the document is named by (egress's load, a receipt's replay): a different digest is `method_digest`. */
  readonly sha256?: string;
  /** The name's last registered version: the document's must be greater (`method_version`). */
  readonly lastVersion?: number;
}

export type ValidateMethodResult = { readonly ok: true; readonly method: RelayMethod } | Refusal<MethodRefusalCode>;

const ENCODER = new TextEncoder();
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const NAME = /^[a-z0-9-]+$/;
const TEXT_ID = /^[a-z0-9_-]+$/;
const INTEGER = /^-?(0|[1-9][0-9]*)$/;
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
/** A comma-list token (`assistants=v2`, `context-1m-2025-08-07`): printable ASCII, no space and no comma. */
const HEADER_TOKEN = /^[\x21-\x2b\x2d-\x7e]+$/;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * Check a method document and parse it. `document` is its bytes (or text) as registered; the answer carries the
 * comparison form and sha256 the method is published and named by.
 */
export function validateMethod(document: Uint8Array | string, options: ValidateMethodOptions = {}): ValidateMethodResult {
  try {
    return new Checker(document, options).run();
  } catch (error) {
    if (error instanceof Refused) return refusal(error.code, error.message);
    throw error;
  }
}

/** The kept top-level members of `protocol`: its own, and for Chat every OpenAI-compatible vendor's. */
export function methodKeptMembers(protocol: LaneProtocol): readonly string[] {
  const own = METHOD_KEPT_MEMBERS[protocol];
  if (protocol !== "open_ai_chat") return own;
  const vendors = OPENAI_COMPATIBLE_VENDORS.flatMap((vendor) => vendor.keptMembers);
  return [...new Set([...own, ...vendors])];
}

/** Whether a relay may have one more active method (§2.4 "per relay"). */
export function methodActiveCountAllowed(activeAfter: number): boolean {
  return Number.isInteger(activeAfter) && activeAfter >= 0 && activeAfter <= METHOD_LIMITS.activePerRelay;
}

/** A refusal thrown inside the checker and caught by `validateMethod`. */
class Refused extends Error {
  readonly code: MethodRefusalCode;
  constructor(code: MethodRefusalCode, detail: string) {
    super(detail);
    this.code = code;
  }
}

function fail(code: MethodRefusalCode, detail: string): never {
  throw new Refused(code, detail);
}

type Members = ReadonlyMap<string, StackJsonTree>;

class Checker {
  private readonly protocols: LaneProtocol[] = [];
  private readonly texts = new Map<string, string>();
  private readonly reads = new Set<MethodClientHeader>();
  private readonly document: Uint8Array | string;
  private readonly options: ValidateMethodOptions;

  constructor(document: Uint8Array | string, options: ValidateMethodOptions) {
    this.document = document;
    this.options = options;
  }

  run(): ValidateMethodResult {
    const tree = this.parse();
    const canonical = stackTreeText(tree);
    if (ENCODER.encode(canonical).length > METHOD_LIMITS.documentBytes) fail("method_size", "the method's comparison form is longer than 16 KiB");
    const sha256 = sha256Hex(ENCODER.encode(canonical));
    if (this.options.sha256 !== undefined && this.options.sha256 !== sha256) {
      fail("method_digest", "the method's comparison-form digest differs from the sha256 it is named by");
    }
    const root = objectMembers(tree, "method_json", "the method is not a JSON object");
    const format = root.get("format");
    if (format === undefined || stringOf(format) !== RELAY_METHOD_FORMAT) fail("method_format", "the method's format is not gray-relay-method-v1");
    onlyMembers(root, ["format", "name", "version", "protocols", "texts", "rules", "headers"], "method_shape", "the method holds a member the format does not have");

    const name = stringOf(root.get("name"));
    if (name === undefined || name.length < METHOD_LIMITS.nameMinLength || name.length > METHOD_LIMITS.nameMaxLength || !NAME.test(name)) {
      fail("method_name", "the method's name is not 1 to 64 of a-z, 0-9 and -");
    }
    const version = this.version(root.get("version"));
    this.readProtocols(root.get("protocols"));
    this.readTexts(root.get("texts"));
    const rules = this.readRules(root.get("rules"));
    const headers = this.readHeaders(root.get("headers"));
    return {
      ok: true,
      method: {
        format: RELAY_METHOD_FORMAT,
        name,
        version,
        protocols: this.protocols,
        texts: this.texts,
        rules,
        headers,
        readsHeaders: [...this.reads].sort(),
        canonical,
        sha256,
      },
    };
  }

  private parse(): StackJsonTree {
    let bytes: Uint8Array;
    if (typeof this.document === "string") {
      if (!this.document.isWellFormed()) fail("method_json", "the method text holds a lone surrogate");
      bytes = ENCODER.encode(this.document);
    } else if (this.document instanceof Uint8Array) {
      bytes = this.document;
    } else {
      fail("method_json", "the method is neither bytes nor text");
    }
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail("method_json", "the method starts with a byte order mark");
    try {
      STRICT_UTF8.decode(bytes);
    } catch {
      fail("method_json", "the method is not valid UTF-8");
    }
    const tree = stackJsonTree(bytes);
    if (tree === null) fail("method_json", "the method is not strict JSON");
    return tree;
  }

  private version(value: StackJsonTree | undefined): number {
    const integer = value === undefined ? undefined : integerOf(value);
    if (integer === undefined || integer < 1n || integer > MAX_SAFE) fail("method_version", "the method's version is not an integer of at least 1");
    const version = Number(integer);
    if (this.options.lastVersion !== undefined && version <= this.options.lastVersion) {
      fail("method_version", "the method's version is not greater than its name's last");
    }
    return version;
  }

  private readProtocols(value: StackJsonTree | undefined): void {
    const items = value?.kind === "array" ? value.items : undefined;
    if (items === undefined || items.length === 0) fail("method_protocols", "the method's protocols are not a non-empty list");
    for (const item of items) {
      const protocol = stringOf(item);
      if (!isLaneProtocol(protocol)) fail("method_protocols", "the method lists a protocol that is not a lane protocol");
      if (this.protocols.includes(protocol)) fail("method_protocols", "the method lists a protocol twice");
      this.protocols.push(protocol);
    }
  }

  private readTexts(value: StackJsonTree | undefined): void {
    if (value === undefined) return;
    const members = objectMembers(value, "method_texts", "the method's texts are not an object");
    if (members.size > METHOD_LIMITS.texts) fail("method_texts", "the method has more than 8 texts");
    let total = 0;
    for (const [id, item] of members) {
      if (id.length === 0 || id.length > METHOD_LIMITS.textIdMaxLength || !TEXT_ID.test(id)) {
        fail("method_texts", "a text id is not 1 to 64 of a-z, 0-9, _ and -");
      }
      const text = stringOf(item);
      if (text === undefined) fail("method_texts", "a text is not a string");
      if (text.includes("\u0000")) fail("method_texts", "a text holds NUL");
      const bytes = ENCODER.encode(text).length;
      if (bytes < METHOD_LIMITS.textMinBytes || bytes > METHOD_LIMITS.textMaxBytes) fail("method_texts", "a text is not 1 to 4096 UTF-8 bytes");
      total += bytes;
      this.texts.set(id, text);
    }
    if (total > METHOD_LIMITS.textsTotalBytes) fail("method_texts", "the method's texts are more than 8192 UTF-8 bytes in all");
  }

  private readRules(value: StackJsonTree | undefined): MethodRule[] {
    const items = value?.kind === "array" ? value.items : undefined;
    if (items === undefined) fail("method_shape", "the method's rules are not a list");
    if (items.length > METHOD_LIMITS.rules) fail("method_limits", "the method has more than 16 rules");
    return items.map((item) => {
      const rule = objectMembers(item, "method_shape", "a rule is not an object");
      onlyMembers(rule, ["when", "ops"], "method_shape", "a rule holds a member the format does not have");
      const when = rule.get("when");
      const conditions = when === undefined ? [] : this.readWhen(when);
      const ops = rule.get("ops");
      const opItems = ops?.kind === "array" ? ops.items : undefined;
      if (opItems === undefined) fail("method_shape", "a rule's ops are not a list");
      if (opItems.length > METHOD_LIMITS.opsPerRule) fail("method_limits", "a rule has more than 32 ops");
      return { when: conditions, ops: opItems.map((op) => this.readOp(op)) };
    });
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Conditions.
  // ---------------------------------------------------------------------------------------------------------------

  private readWhen(value: StackJsonTree): MethodCondition[] {
    if (value.kind !== "array") fail("method_condition", "a rule's when is not a list");
    const counter = { count: 0 };
    const conditions = value.items.map((item) => this.readCondition(item, counter));
    if (counter.count > METHOD_LIMITS.conditionsPerWhen) fail("method_limits", "a when has more than 8 conditions");
    return conditions;
  }

  private readCondition(value: StackJsonTree, counter: { count: number }): MethodCondition {
    counter.count += 1;
    if (counter.count > METHOD_LIMITS.conditionsPerWhen) fail("method_limits", "a when has more than 8 conditions");
    const members = objectMembers(value, "method_condition", "a condition is not an object");
    const keys = [...members.keys()];
    if (members.has("client_header")) {
      onlyMembers(members, ["client_header", "equals_any", "prefix_any", "has_token"], "method_condition", "a client_header condition holds another member");
      const name = stringOf(members.get("client_header"));
      if (!isMethodClientHeader(name)) fail("method_condition", "a client_header condition names a header a method may not read");
      const matches = (["equals_any", "prefix_any", "has_token"] as const).filter((match) => members.has(match));
      if (matches.length !== 1) fail("method_condition", "a client_header condition has not exactly one of equals_any, prefix_any, has_token");
      const match = matches[0]!;
      this.reads.add(name);
      return { kind: "client_header", name, match, values: listedStrings(members.get(match)) };
    }
    if (keys.length !== 1) fail("method_condition", "a condition is not one member");
    const kind = keys[0]!;
    const operand = members.get(kind)!;
    switch (kind) {
      case "protocol": {
        const values = listedStrings(operand);
        if (!values.every(isLaneProtocol)) fail("method_condition", "a protocol condition lists a protocol that is not a lane protocol");
        return { kind, values };
      }
      case "requested_model":
      case "upstream_model":
        return { kind, values: listedStrings(operand) };
      case "stream": {
        const flag = booleanOf(operand);
        if (flag === undefined) fail("method_condition", "a stream condition is not true or false");
        return { kind, value: flag };
      }
      case "present":
      case "absent":
        return { kind, path: conditionPath(operand) };
      case "is": {
        const is = objectMembers(operand, "method_condition", "an is condition is not an object");
        onlyMembers(is, ["path", "type"], "method_condition", "an is condition holds another member");
        const type = stringOf(is.get("type"));
        if (type === undefined || !(METHOD_JSON_TYPES as readonly string[]).includes(type)) fail("method_condition", "an is condition's type is not a JSON type");
        const path = is.get("path");
        if (path === undefined) fail("method_condition", "an is condition has no path");
        return { kind, path: conditionPath(path), type: type as MethodJsonType };
      }
      case "not":
        return { kind, condition: this.readCondition(operand, counter) };
      default:
        return fail("method_condition", "a condition is not one the format has");
    }
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Ops.
  // ---------------------------------------------------------------------------------------------------------------

  private readOp(value: StackJsonTree): MethodOp {
    const members = objectMembers(value, "method_op", "an op is not an object");
    const op = stringOf(members.get("op"));
    switch (op) {
      case "insert_text": {
        onlyMembers(members, ["op", "text", "at"], "method_op", "an insert_text op holds another member");
        const text = stringOf(members.get("text"));
        if (text === undefined) fail("method_op", "an insert_text op names no text");
        if (!this.texts.has(text)) fail("method_text_unknown", "an insert_text op names a text the method does not register");
        return { op, text, at: this.position(members.get("at")) };
      }
      case "set": {
        onlyMembers(members, ["op", "path", "value", "map", "when_absent"], "method_op", "a set op holds another member");
        const path = this.writePath(members.get("path"), "set");
        const whenAbsent = members.has("when_absent") ? booleanOf(members.get("when_absent")!) : false;
        if (whenAbsent === undefined) fail("method_op", "a set op's when_absent is not true or false");
        const hasValue = members.has("value");
        if (hasValue === members.has("map")) fail("method_op", "a set op has not exactly one of value and map");
        if (hasValue) return { op, path, value: setValue(members.get("value")!), whenAbsent };
        return { op, path, map: this.readMap(members.get("map")!), whenAbsent };
      }
      case "clamp": {
        onlyMembers(members, ["op", "path", "max", "min"], "method_op", "a clamp op holds another member");
        const path = this.writePath(members.get("path"), "clamp");
        const max = boundOf(members.get("max"));
        const min = members.has("min") ? boundOf(members.get("min")) : undefined;
        if (max === undefined || (members.has("min") && min === undefined)) fail("method_op", "a clamp bound is not a safe integer");
        if (min !== undefined && min > max) fail("method_op", "a clamp's min is greater than its max");
        return min === undefined ? { op, path, max } : { op, path, max, min };
      }
      case "remove": {
        onlyMembers(members, ["op", "path"], "method_op", "a remove op holds another member");
        return { op, path: this.writePath(members.get("path"), "remove") };
      }
      case "remove_elements": {
        onlyMembers(members, ["op", "path", "where"], "method_op", "a remove_elements op holds another member");
        const pathText = stringOf(members.get("path"));
        if (pathText === undefined || !(METHOD_ELEMENT_ARRAYS as readonly string[]).includes(pathText)) {
          fail("method_path", "a remove_elements op's path is not /messages, /input, /system or /tools");
        }
        const path = parsePath(pathText, false);
        if (path === undefined) fail("method_path", "a remove_elements op's path is not a pointer");
        this.checkKept(path, "remove_elements");
        const where = objectMembers(members.get("where") ?? { kind: "text", text: "null" }, "method_op", "a remove_elements op's where is not an object");
        onlyMembers(where, ["member", "equals_any", "present"], "method_op", "a where holds another member");
        const memberText = stringOf(where.get("member"));
        const member = memberText === undefined ? undefined : parsePath(memberText, false);
        if (member === undefined) fail("method_path", "a where's member is not a relative pointer");
        if (where.has("equals_any") === where.has("present")) fail("method_op", "a where has not exactly one of equals_any and present");
        if (where.has("present")) {
          if (booleanOf(where.get("present")!) !== true) fail("method_op", "a where's present is not true");
          return { op, path, member, present: true };
        }
        return { op, path, member, equalsAny: listedScalars(where.get("equals_any")) };
      }
      case "move":
      case "copy": {
        onlyMembers(members, ["op", "from", "at"], "method_op", "a move or copy op holds another member");
        const fromText = stringOf(members.get("from"));
        if (fromText === undefined) fail("method_op", "a move or copy op has no from");
        for (const protocol of this.protocols) {
          if (!METHOD_TEXT_SOURCES[protocol].includes(fromText)) fail("method_source", "a move or copy op's from is not a content member of every listed protocol");
        }
        const from = parsePath(fromText, false);
        if (from === undefined) fail("method_path", "a move or copy op's from is not a pointer");
        return { op, from, at: this.position(members.get("at")) };
      }
      default:
        return fail("method_op", "an op is not one the format has");
    }
  }

  private position(value: StackJsonTree | undefined): MethodPosition {
    const at = stringOf(value);
    if (at === undefined) fail("method_position", "an op has no position");
    for (const protocol of this.protocols) {
      if (!isMethodPositionFor(protocol, at)) fail("method_position", "an op's position does not exist for every listed protocol");
    }
    return at as MethodPosition;
  }

  private readMap(value: StackJsonTree): MethodMap {
    const members = objectMembers(value, "method_op", "a map is not an object");
    onlyMembers(members, ["fact", "cases", "default"], "method_op", "a map holds another member");
    const fact = this.mapFact(members.get("fact"));
    const cases = objectMembers(members.get("cases") ?? { kind: "text", text: "null" }, "method_op", "a map's cases are not an object");
    if (cases.size === 0 || cases.size > METHOD_LIMITS.listedSet) fail("method_limits", "a map has not 1 to 16 cases");
    const values = new Map<string, MethodValue>();
    for (const [key, item] of cases) {
      if (ENCODER.encode(key).length > METHOD_LIMITS.listedStringBytes) fail("method_limits", "a map case is longer than 512 bytes");
      values.set(key, setValue(item));
    }
    const fallback = members.get("default");
    return fallback === undefined ? { fact, cases: values } : { fact, cases: values, default: setValue(fallback) };
  }

  private mapFact(value: StackJsonTree | undefined): MethodMapFact {
    const fact = stringOf(value);
    if (fact === "requested_model" || fact === "upstream_model" || fact === "stream") return fact;
    if (isMethodClientHeader(fact)) {
      this.reads.add(fact);
      return fact;
    }
    return fail("method_op", "a map's fact is not one the format has");
  }

  /** A path an op writes or removes: RFC 6901, `*` for array indexes, outside every kept limit and (for set/clamp) every content member. */
  private writePath(value: StackJsonTree | undefined, op: "set" | "clamp" | "remove"): MethodPath {
    const text = stringOf(value);
    const path = text === undefined ? undefined : parsePath(text, true);
    if (path === undefined) fail("method_path", "an op's path is not a pointer the format accepts");
    this.checkKept(path, op);
    if (op !== "remove" && (METHOD_CONTENT_MEMBERS as readonly string[]).includes(path.tokens[0]!)) {
      fail("method_content", "a set or clamp op writes a content member");
    }
    return path;
  }

  /** §2.4 "kept limits": no op at, under or above a kept path, for any listed protocol. */
  private checkKept(path: MethodPath, op: "set" | "clamp" | "remove" | "remove_elements"): void {
    const tokens = path.tokens;
    if (tokens.includes(METHOD_KEPT_ANY_DEPTH)) fail("method_kept", "an op's path names cache_control, which a method never touches");
    const top = tokens[0]!;
    if (top.startsWith(METHOD_KEPT_PREFIX)) fail("method_kept", "an op's path is a prompt cache member, which a method never touches");
    // Every protocol has kept tool types (Messages, Responses, and Chat through its vendors): /tools only loses elements.
    if (top === "tools" && op !== "remove_elements") fail("method_kept", "an op other than remove_elements reaches /tools");
    for (const protocol of this.protocols) {
      if (methodKeptMembers(protocol).includes(top)) fail("method_kept", "an op's path is at or under a kept member");
      for (const kept of METHOD_KEPT_PATHS[protocol]) {
        const length = Math.min(kept.length, tokens.length);
        if (kept.slice(0, length).every((token, index) => token === tokens[index])) fail("method_kept", "an op's path is at, under or above a kept member");
      }
    }
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Headers (§2.3).
  // ---------------------------------------------------------------------------------------------------------------

  private readHeaders(value: StackJsonTree | undefined): MethodHeaderOp[] {
    if (value === undefined) return [];
    if (value.kind !== "array") fail("method_shape", "the method's headers are not a list");
    if (value.items.length > METHOD_LIMITS.headerOps) fail("method_limits", "the method has more than 16 header ops");
    return value.items.map((item) => this.readHeaderOp(item));
  }

  private readHeaderOp(value: StackJsonTree): MethodHeaderOp {
    const members = objectMembers(value, "method_header", "a header op is not an object");
    const op = stringOf(members.get("op"));
    const name = headerName(members.get("name"));
    switch (op) {
      case "set": {
        onlyMembers(members, ["op", "name", "value", "map"], "method_header", "a header set op holds another member");
        if (members.has("value") === members.has("map")) fail("method_header", "a header set op has not exactly one of value and map");
        if (members.has("value")) return { op, name, value: headerValue(members.get("value")) };
        const map = objectMembers(members.get("map")!, "method_header", "a header map is not an object");
        onlyMembers(map, ["fact", "cases", "default"], "method_header", "a header map holds another member");
        const fact = this.mapFact(map.get("fact"));
        const cases = objectMembers(map.get("cases") ?? { kind: "text", text: "null" }, "method_header", "a header map's cases are not an object");
        if (cases.size === 0 || cases.size > METHOD_LIMITS.listedSet) fail("method_limits", "a header map has not 1 to 16 cases");
        const values = new Map<string, string>();
        for (const [key, item] of cases) {
          if (ENCODER.encode(key).length > METHOD_LIMITS.listedStringBytes) fail("method_limits", "a header map case is longer than 512 bytes");
          values.set(key, headerValue(item));
        }
        const fallback = map.get("default");
        return { op, name, map: fallback === undefined ? { fact, cases: values } : { fact, cases: values, default: headerValue(fallback) } };
      }
      case "remove":
        onlyMembers(members, ["op", "name"], "method_header", "a header remove op holds another member");
        return { op, name };
      case "add_tokens":
      case "remove_tokens": {
        onlyMembers(members, ["op", "name", "tokens"], "method_header", "a header token op holds another member");
        if (!(METHOD_TOKEN_HEADERS as readonly string[]).includes(name)) fail("method_header", "a token op names a header that is not anthropic-beta or openai-beta");
        const tokens = listedStrings(members.get("tokens"), "method_header");
        for (const token of tokens) {
          if (token.length > 128 || !HEADER_TOKEN.test(token)) fail("method_header", "a header token is not 1 to 128 printable ASCII characters without a comma");
        }
        return { op, name, tokens };
      }
      default:
        return fail("method_header", "a header op is not one the format has");
    }
  }
}

// -----------------------------------------------------------------------------------------------------------------
// Tree readers.
// -----------------------------------------------------------------------------------------------------------------

function objectMembers(value: StackJsonTree, code: MethodRefusalCode, detail: string): Members {
  if (value.kind !== "object") fail(code, detail);
  return value.members;
}

function onlyMembers(members: Members, allowed: readonly string[], code: MethodRefusalCode, detail: string): void {
  for (const key of members.keys()) if (!allowed.includes(key)) fail(code, detail);
}

/** A string leaf's decoded value: the leaf is `JSON.stringify`'s text of a string `stackJsonTree` read with `parseStrict`. */
function stringOf(value: StackJsonTree | undefined): string | undefined {
  if (value?.kind !== "text" || !value.text.startsWith('"')) return undefined;
  const decoded = parseStrict(value.text);
  return typeof decoded === "string" ? decoded : undefined;
}

function booleanOf(value: StackJsonTree): boolean | undefined {
  if (value.kind !== "text") return undefined;
  return value.text === "true" ? true : value.text === "false" ? false : undefined;
}

/** A number leaf written as a plain integer (no fraction, no exponent), as a bigint. */
function integerOf(value: StackJsonTree): bigint | undefined {
  if (value.kind !== "text" || !INTEGER.test(value.text)) return undefined;
  return BigInt(value.text);
}

function boundOf(value: StackJsonTree | undefined): bigint | undefined {
  const integer = value === undefined ? undefined : integerOf(value);
  if (integer === undefined || integer > MAX_SAFE || integer < -MAX_SAFE) return undefined;
  return integer;
}

/** A listed set of strings: 1 to 16, each at most 512 UTF-8 bytes. */
function listedStrings(value: StackJsonTree | undefined, code: MethodRefusalCode = "method_condition"): string[] {
  if (value?.kind !== "array" || value.items.length === 0) fail(code, "a listed set is not a non-empty list");
  if (value.items.length > METHOD_LIMITS.listedSet) fail("method_limits", "a listed set has more than 16 values");
  return value.items.map((item) => {
    const text = stringOf(item);
    if (text === undefined || text.length === 0) fail(code, "a listed value is not a non-empty string");
    if (ENCODER.encode(text).length > METHOD_LIMITS.listedStringBytes) fail("method_limits", "a listed value is longer than 512 bytes");
    return text;
  });
}

/** `equals_any`: 1 to 16 scalars, each at most 128 bytes of comparison form. */
function listedScalars(value: StackJsonTree | undefined): string[] {
  if (value?.kind !== "array" || value.items.length === 0) fail("method_op", "an equals_any is not a non-empty list");
  if (value.items.length > METHOD_LIMITS.listedSet) fail("method_limits", "an equals_any has more than 16 values");
  return value.items.map((item) => {
    if (item.kind !== "text") fail("method_op", "an equals_any value is not a scalar");
    if (ENCODER.encode(item.text).length > METHOD_LIMITS.scalarBytes) fail("method_limits", "an equals_any value is longer than 128 bytes");
    return item.text;
  });
}

/** A `set` value: at most 1 KiB of comparison form, every string inside at most 64 bytes, and no cache_control member. */
function setValue(value: StackJsonTree): MethodValue {
  const json = stackTreeText(value);
  const bytes = ENCODER.encode(json).length;
  if (bytes > METHOD_LIMITS.valueBytes) fail("method_value", "a set value is longer than 1 KiB");
  checkValueStrings(value);
  return { json, bytes };
}

function checkValueStrings(value: StackJsonTree): void {
  switch (value.kind) {
    case "text": {
      const text = stringOf(value);
      if (text !== undefined && ENCODER.encode(text).length > METHOD_LIMITS.valueStringBytes) {
        fail("method_value", "a string in a set value is longer than 64 bytes; text belongs in texts");
      }
      return;
    }
    case "array":
      for (const item of value.items) checkValueStrings(item);
      return;
    case "object":
      for (const [name, item] of value.members) {
        if (name === METHOD_KEPT_ANY_DEPTH) fail("method_kept", "a set value holds cache_control, which a method never writes");
        if (ENCODER.encode(name).length > METHOD_LIMITS.valueStringBytes) fail("method_value", "a member name in a set value is longer than 64 bytes");
        checkValueStrings(item);
      }
      return;
  }
}

function conditionPath(value: StackJsonTree): MethodPath {
  const text = stringOf(value);
  const path = text === undefined ? undefined : parsePath(text, false);
  if (path === undefined) fail("method_path", "a condition's path is not a pointer the format accepts");
  return path;
}

/**
 * RFC 6901 as the format allows it: absolute, at most 8 tokens and 256 UTF-16 units, no empty token, `~` only as
 * `~0`/`~1`. With `wildcard`, a token that is exactly `*` stands for every index of an array, never as the first.
 */
export function parsePath(text: string, wildcard: boolean): MethodPath | undefined {
  if (!text.isWellFormed() || !text.startsWith("/") || text.length > METHOD_LIMITS.pathLength) return undefined;
  const raw = text.slice(1).split("/");
  if (raw.length > METHOD_LIMITS.pathTokens) return undefined;
  const tokens: string[] = [];
  for (const [index, part] of raw.entries()) {
    if (part.length === 0) return undefined;
    if (part === "*" && (!wildcard || index === 0)) return undefined;
    if (/~(?![01])/.test(part)) return undefined;
    tokens.push(part.replaceAll("~1", "/").replaceAll("~0", "~"));
  }
  return { text, tokens };
}

function headerName(value: StackJsonTree | undefined): string {
  const name = stringOf(value);
  if (name === undefined || name.length === 0 || name.length > METHOD_LIMITS.headerNameMaxLength || !HEADER_NAME.test(name)) {
    fail("method_header", "a header op's name is not a lower-case header name");
  }
  if ((METHOD_REFUSED_HEADERS as readonly string[]).includes(name) || name.startsWith("x-gray-")) {
    fail("method_header_refused", "a header op names a credential, account, framing or Gray header");
  }
  return name;
}

/** 1 to 512 bytes of printable ASCII, no space at either end (as identity profiles are). */
function headerValue(value: StackJsonTree | undefined): string {
  const text = stringOf(value);
  if (text === undefined || text.length < METHOD_LIMITS.headerValueMinBytes || text.length > METHOD_LIMITS.headerValueMaxBytes) {
    fail("method_header", "a header value is not 1 to 512 bytes");
  }
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) fail("method_header", "a header value is not printable ASCII");
  }
  if (text.startsWith(" ") || text.endsWith(" ")) fail("method_header", "a header value has a space at an end");
  return text;
}
