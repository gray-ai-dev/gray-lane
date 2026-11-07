/**
 * `applyMethod`: V = apply(m, E, facts), docs/relay-changes-v2.md §2.1–§2.3.
 *
 * Egress runs this (in Go) on the entry's body E for the method bound to the account; the verifier runs it to
 * replay a receipt. Both are held to the shared vectors.
 *
 * **Evaluation.** Every `when` reads the facts and E, never an intermediate result. Rules run in order, and within a
 * rule the ops run in order on the current value. An op whose target does not exist, or has another type than it
 * needs, is skipped and not recorded: a method never fails at request time. A body that is not one the lane accepts
 * (strict UTF-8 and JSON, an object, no duplicate member at any depth) is a refusal, as for the entry's own ops.
 *
 * **Bytes.** Ops edit by splices at the offsets the parser reports, as `applyDeclaredChanges` does (and with its
 * helpers): untouched bytes, member order, escapes and number spellings stay as the customer wrote them. A value the
 * method writes is its comparison-form text from the published document.
 *
 * **Concrete paths.** A `*` expands, on the current value, to every index of the array it stands at. The concrete
 * targets of one op are processed last first (reverse document order), so each recorded path is valid when it is
 * replayed in order (an RFC 6902 patch), and a removal never shifts a target still to come.
 *
 * **P7 at request time.** A removal (`remove`, `remove_elements`, `move`'s source) or a `set` (with a value or a
 * map) whose target's current value holds a `cache_control` member at any depth is skipped, so a method never drops
 * or replaces the customer's cache breakpoints. Registration cannot decide this: it depends on the customer's body.
 * (Registration does refuse a `set` value or map value that holds `cache_control` itself.) `move`/`copy` read only a
 * string or an array of plain text parts (`{"type":"text","text":…}` and nothing else).
 */
import { parseStrict } from "@gray/json";
import { getNodeValue, type Node } from "jsonc-parser";
import { developerMessage, escapeFragment, textBlock } from "../append.ts";
import { findMember, hasDuplicateMember, insertIntoObject, nodesOf, parseStrictObject, removeFromObject } from "../changes.ts";
import type { LaneProtocol } from "../protocol.ts";
import { refusal, type Refusal } from "../refusal.ts";
import { decodeUtf8, encodeUtf8, utf8Length, type Utf8RefusalCode } from "../utf8.ts";
import { headerTokens, methodFactsRead, type MethodFacts } from "./facts.ts";
import {
  METHOD_KEPT_ANY_DEPTH,
  pointerOf,
  type MethodClientHeader,
  type MethodCondition,
  type MethodHeaderOp,
  type MethodHeaderRecord,
  type MethodMapFact,
  type MethodOp,
  type MethodOpRecord,
  type MethodPosition,
  type MethodValue,
  type RelayMethod,
} from "./format.ts";

/** What the host hands to `applyMethod` besides E. */
export interface ApplyMethodOptions {
  /**
   * The vendor headers before the method (Gray's set, then the account's identity profile), lower-case names, each
   * once. With them the answer carries the headers after the method's header ops (§2.3).
   */
  readonly headers?: ReadonlyArray<readonly [string, string]>;
}

export interface ApplyMethodOk {
  readonly ok: true;
  /** V: E with the method's ops applied. Equal to E when nothing applied. */
  readonly body: Uint8Array;
  /** The body changes, in the order they were made (the receipt's `ops`). */
  readonly ops: readonly MethodOpRecord[];
  /** Totals over `ops`. */
  readonly addedBytes: number;
  readonly removedBytes: number;
  /** The client header values the method can read, by name (null when not sent): the receipt's `facts`. */
  readonly clientHeaders: Readonly<Partial<Record<MethodClientHeader, string | null>>>;
  /** The headers after the method (only when `options.headers` was given), and the changes made to them. */
  readonly headers?: ReadonlyArray<readonly [string, string]>;
  readonly headerOps: readonly MethodHeaderRecord[];
  /** Whether the method made any change: under `relay_methods: "none"` egress refuses an attempt where it did. */
  readonly changed: boolean;
}

export type ApplyMethodRefusalCode = Utf8RefusalCode | "invalid_json" | "not_an_object" | "duplicate_key" | "method_protocol" | "method_headers";

/**
 * Apply `method` (or none) to E for a request with `facts`. A method that does not list the request's protocol
 * applies nothing.
 */
export function applyMethod(
  entry: Uint8Array,
  method: RelayMethod | null,
  facts: MethodFacts,
  options: ApplyMethodOptions = {},
): ApplyMethodOk | Refusal<ApplyMethodRefusalCode> {
  const decoded = decodeUtf8(entry);
  if (!decoded.ok) return decoded;
  const parsed = parseStrictObject(decoded.text);
  if (!parsed.ok) return refusal(parsed.code === "not_an_object" ? "not_an_object" : "invalid_json", parsed.detail);
  if (hasDuplicateMember(parsed.root)) return refusal("duplicate_key", "the body holds a member name twice");
  try {
    parseStrict(decoded.text);
  } catch {
    return refusal("invalid_json", "the body is not JSON serde_json reads strictly");
  }
  const headersIn = options.headers;
  if (headersIn !== undefined) {
    const names = new Set<string>();
    for (const pair of headersIn) {
      const [name, value] = pair;
      if (typeof name !== "string" || typeof value !== "string" || name !== name.toLowerCase() || names.has(name)) {
        return refusal("method_headers", "the headers are not lower-case names, each once, with string values");
      }
      names.add(name);
    }
  }

  const applies = method !== null && method.protocols.includes(facts.protocol);
  if (!applies) {
    return {
      ok: true,
      body: entry,
      ops: [],
      addedBytes: 0,
      removedBytes: 0,
      clientHeaders: method === null ? {} : methodFactsRead(method.readsHeaders, facts),
      ...(headersIn === undefined ? {} : { headers: headersIn.map(([name, value]) => [name, value] as const) }),
      headerOps: [],
      changed: false,
    };
  }

  const run = new Run(decoded.text, parsed.root, method, facts);
  for (const rule of method.rules) {
    if (!rule.when.every((condition) => run.holds(condition))) continue;
    for (const op of rule.ops) run.apply(op);
  }
  const encoded = encodeUtf8(run.text);
  if (!encoded.ok) throw new Error("lane/method: the result is not well formed text");
  const headers = headersIn === undefined ? undefined : applyHeaderOps(headersIn, method.headers, run);
  const ops = run.records;
  return {
    ok: true,
    body: encoded.bytes,
    ops,
    addedBytes: ops.reduce((sum, op) => sum + op.added_bytes, 0),
    removedBytes: ops.reduce((sum, op) => sum + op.removed_bytes, 0),
    clientHeaders: methodFactsRead(method.readsHeaders, facts),
    ...(headers === undefined ? {} : { headers: headers.headers }),
    headerOps: headers?.records ?? [],
    changed: ops.length > 0 || (headers?.records.length ?? 0) > 0,
  };
}

// -----------------------------------------------------------------------------------------------------------------
// One evaluation.
// -----------------------------------------------------------------------------------------------------------------

const INDEX = /^(0|[1-9][0-9]*)$/;
const INTEGER = /^-?(0|[1-9][0-9]*)$/;

class Run {
  text: string;
  readonly records: MethodOpRecord[] = [];
  private readonly entryText: string;
  private readonly entryRoot: Node;
  private readonly method: RelayMethod;
  private readonly facts: MethodFacts;
  private readonly protocol: LaneProtocol;
  private readonly inserted = new Set<string>();

  constructor(text: string, root: Node, method: RelayMethod, facts: MethodFacts) {
    this.text = text;
    this.entryText = text;
    this.entryRoot = root;
    this.method = method;
    this.facts = facts;
    this.protocol = facts.protocol;
  }

  /** E's `stream` is `true` (absent, or any other value, is false). */
  stream(): boolean {
    const value = memberValue(this.entryRoot, "stream");
    return value?.type === "boolean" && value.value === true;
  }

  /** A fact's value as a map case key, or undefined when there is none. */
  factValue(fact: MethodMapFact): string | undefined {
    switch (fact) {
      case "requested_model":
        return this.facts.requested_model;
      case "upstream_model":
        return this.facts.upstream_model;
      case "stream":
        return this.stream() ? "true" : "false";
      default:
        return this.facts.client_headers[fact];
    }
  }

  holds(condition: MethodCondition): boolean {
    switch (condition.kind) {
      case "protocol":
        return condition.values.includes(this.facts.protocol);
      case "requested_model":
        return condition.values.includes(this.facts.requested_model);
      case "upstream_model":
        return condition.values.includes(this.facts.upstream_model);
      case "stream":
        return this.stream() === condition.value;
      case "client_header": {
        const value = this.facts.client_headers[condition.name];
        if (value === undefined) return false;
        switch (condition.match) {
          case "equals_any":
            return condition.values.includes(value);
          case "prefix_any":
            return condition.values.some((prefix) => value.startsWith(prefix));
          case "has_token": {
            const tokens = headerTokens(value);
            return condition.values.some((token) => tokens.includes(token));
          }
        }
        return false;
      }
      case "present":
        return locate(this.entryRoot, condition.path.tokens)?.value !== undefined;
      case "absent":
        return locate(this.entryRoot, condition.path.tokens)?.value === undefined;
      case "is": {
        const value = locate(this.entryRoot, condition.path.tokens)?.value;
        return value !== undefined && jsonType(value) === condition.type;
      }
      case "not":
        return !this.holds(condition.condition);
    }
  }

  apply(op: MethodOp): void {
    switch (op.op) {
      case "insert_text": {
        if (this.inserted.has(op.text)) return;
        const text = this.method.texts.get(op.text);
        if (text === undefined) return;
        const placed = insertAt(this.text, this.protocol, op.at, [text]);
        if (placed === undefined) return;
        this.inserted.add(op.text);
        this.text = placed.text;
        for (const record of placed.records) this.records.push({ ...record, text: op.text });
        return;
      }
      case "set": {
        const value = "value" in op ? op.value : this.mapValue(op.map);
        if (value === undefined) return;
        for (const target of this.targets(op.path.tokens)) this.setOne(target, value, op.whenAbsent);
        return;
      }
      case "clamp":
        for (const target of this.targets(op.path.tokens)) this.clampOne(target, op.max, op.min);
        return;
      case "remove":
        for (const target of this.targets(op.path.tokens)) this.removeOne(target);
        return;
      case "remove_elements":
        this.removeElements(op);
        return;
      case "move":
      case "copy":
        this.place(op.op, op.from.tokens, op.at);
        return;
    }
  }

  private mapValue(map: { readonly fact: MethodMapFact; readonly cases: ReadonlyMap<string, MethodValue>; readonly default?: MethodValue }): MethodValue | undefined {
    const key = this.factValue(map.fact);
    return (key === undefined ? undefined : map.cases.get(key)) ?? map.default;
  }

  /** The concrete paths of `tokens` on the current value, last first. */
  private targets(tokens: readonly string[]): string[][] {
    const root = this.root();
    const found: string[][] = [];
    expand(root, tokens, 0, [], found);
    return found.reverse();
  }

  private root(): Node {
    const parsed = parseStrictObject(this.text);
    if (!parsed.ok) throw new Error("lane/method: an intermediate body is not strict JSON");
    return parsed.root;
  }

  private setOne(tokens: readonly string[], value: MethodValue, whenAbsent: boolean): void {
    const at = locate(this.root(), tokens);
    if (at === undefined) return;
    const path = pointerOf(tokens);
    if (at.value !== undefined) {
      // P7: a replaced value holding the customer's cache_control (at any depth) is skipped, as a removal is.
      if (whenAbsent || holdsKept(at.value)) return;
      const old = canonOf(this.text, at.value);
      if (old === value.json) return;
      this.text = replaceNode(this.text, at.value, value.json);
      this.records.push({ op: "replace", path, removed_bytes: utf8Length(old), added_bytes: value.bytes });
      return;
    }
    // Absent: only an object member can be added; an array index past the end is skipped.
    if (at.parent.type !== "object") return;
    this.text = insertIntoObject(this.text, at.parent, tokens[tokens.length - 1]!, value.json);
    this.records.push({ op: "add", path, removed_bytes: 0, added_bytes: value.bytes });
  }

  private clampOne(tokens: readonly string[], max: bigint, min: bigint | undefined): void {
    const value = locate(this.root(), tokens)?.value;
    if (value === undefined || value.type !== "number") return;
    const written = this.text.slice(value.offset, value.offset + value.length);
    if (!INTEGER.test(written)) return;
    const current = BigInt(written);
    const next = current > max ? max : min !== undefined && current < min ? min : undefined;
    if (next === undefined) return;
    const json = next.toString();
    this.text = replaceNode(this.text, value, json);
    this.records.push({ op: "replace", path: pointerOf(tokens), removed_bytes: utf8Length(written), added_bytes: utf8Length(json) });
  }

  private removeOne(tokens: readonly string[]): void {
    const at = locate(this.root(), tokens);
    if (at?.value === undefined || holdsKept(at.value)) return;
    const removed = utf8Length(canonOf(this.text, at.value));
    this.text = removeAt(this.text, at);
    this.records.push({ op: "remove", path: pointerOf(tokens), removed_bytes: removed, added_bytes: 0 });
  }

  private removeElements(op: Extract<MethodOp, { op: "remove_elements" }>): void {
    const text = this.text;
    const array = locate(this.root(), op.path.tokens)?.value;
    if (array === undefined || array.type !== "array") return;
    const matches: number[] = [];
    nodesOf(array).forEach((element, index) => {
      const member = locate(element, op.member.tokens)?.value;
      if (member === undefined) return;
      if (op.present === true || op.equalsAny?.includes(canonOf(text, member)) === true) matches.push(index);
    });
    for (const index of matches.reverse()) this.removeOne([...op.path.tokens, String(index)]);
  }

  /** `move` and `copy`: the customer's own text at `from` goes to a position, as `insert_text` would put it. */
  private place(op: "move" | "copy", from: readonly string[], position: MethodPosition): void {
    const at = locate(this.root(), from);
    if (at?.value === undefined) return;
    const texts = plainTexts(at.value);
    if (texts === undefined) return;
    let text = this.text;
    const records: MethodOpRecord[] = [];
    const path = pointerOf(from);
    if (op === "move") {
      records.push({ op: "remove", path, removed_bytes: utf8Length(canonOf(text, at.value)), added_bytes: 0 });
      text = removeAt(text, at);
    }
    const placed = insertAt(text, this.protocol, position, texts);
    // Nowhere to put it: a move does not drop the customer's text.
    if (placed === undefined) return;
    this.text = placed.text;
    for (const record of placed.records) records.push({ ...record, from: path });
    this.records.push(...records);
  }
}

// -----------------------------------------------------------------------------------------------------------------
// Positions.
// -----------------------------------------------------------------------------------------------------------------

type Placed = { readonly text: string; readonly records: Omit<MethodOpRecord, "text" | "from">[] };

/**
 * Put `texts` at `position`, in order, each as `insert_text` puts one. At a start position they go in reverse so they
 * read in order. Undefined when the target has no shape the position can take (the op is skipped).
 */
function insertAt(text: string, protocol: LaneProtocol, position: MethodPosition, texts: readonly string[]): Placed | undefined {
  const start = position === "system_start" || position === "instructions_before" || position === "input_start";
  const order = start ? [...texts].reverse() : texts;
  let current = text;
  const records: Placed["records"][number][] = [];
  for (const item of order) {
    const placed = insertOne(current, protocol, position, item);
    if (placed === undefined) return undefined;
    current = placed.text;
    records.push(placed.record);
  }
  return { text: current, records };
}

function insertOne(text: string, protocol: LaneProtocol, position: MethodPosition, item: string): { text: string; record: Placed["records"][number] } | undefined {
  const parsed = parseStrictObject(text);
  if (!parsed.ok) throw new Error("lane/method: an intermediate body is not strict JSON");
  const root = parsed.root;
  switch (position) {
    case "system_start":
    case "system_end": {
      if (protocol !== "anthropic_messages") return undefined;
      const system = memberValue(root, "system");
      const block = textBlock(item);
      const blockCanon = `{"text":${JSON.stringify(item)},"type":"text"}`;
      if (system === undefined) {
        return { text: addFirstMember(text, root, `"system":[${block}]`), record: added("/system", `[${blockCanon}]`) };
      }
      if (system.type === "string") return growString(text, system, "/system", item, position === "system_start");
      if (system.type === "array") {
        const count = nodesOf(system).length;
        const index = position === "system_start" ? 0 : count;
        return { text: insertElement(text, system, index, block), record: added(`/system/${index}`, blockCanon) };
      }
      return undefined;
    }
    case "instructions_before":
    case "instructions_after": {
      if (protocol === "open_ai_chat") {
        const messages = memberValue(root, "messages");
        if (messages === undefined || messages.type !== "array") return undefined;
        let index = 0;
        if (position === "instructions_after") {
          for (const element of nodesOf(messages)) {
            const role = element.type === "object" ? memberValue(element, "role") : undefined;
            const name = role?.type === "string" ? (role.value as string) : undefined;
            if (name !== "system" && name !== "developer") break;
            index += 1;
          }
        }
        return { text: insertElement(text, messages, index, developerMessage(item)), record: added(`/messages/${index}`, developerCanon(item)) };
      }
      if (protocol === "open_ai_responses") {
        const instructions = memberValue(root, "instructions");
        if (instructions === undefined) {
          return { text: addFirstMember(text, root, `"instructions":${JSON.stringify(item)}`), record: added("/instructions", JSON.stringify(item)) };
        }
        if (instructions.type === "string") return growString(text, instructions, "/instructions", item, position === "instructions_before");
      }
      return undefined;
    }
    case "input_start": {
      if (protocol !== "open_ai_responses") return undefined;
      const input = memberValue(root, "input");
      if (input === undefined) return undefined;
      if (input.type === "array") {
        return { text: insertElement(text, input, 0, developerMessage(item)), record: added("/input/0", developerCanon(item)) };
      }
      if (input.type === "string") {
        const raw = text.slice(input.offset, input.offset + input.length);
        const old = canonOf(text, input);
        const replacement = `[${developerMessage(item)},{"role":"user","content":${raw}}]`;
        const canon = `[${developerCanon(item)},{"content":${old},"role":"user"}]`;
        return {
          text: replaceNode(text, input, replacement),
          record: { op: "replace", path: "/input", removed_bytes: utf8Length(old), added_bytes: utf8Length(canon) },
        };
      }
      return undefined;
    }
  }
}

function added(path: string, canon: string): Placed["records"][number] {
  return { op: "add", path, removed_bytes: 0, added_bytes: utf8Length(canon) };
}

function developerCanon(item: string): string {
  return `{"content":${JSON.stringify(item)},"role":"developer"}`;
}

/** A string member grows at its start or end; the customer's bytes inside it stay as written. */
function growString(text: string, node: Node, path: string, item: string, atStart: boolean): { text: string; record: Placed["records"][number] } {
  const old = node.value as string;
  const offset = atStart ? node.offset + 1 : node.offset + node.length - 1;
  const next = atStart ? `${item}${old}` : `${old}${item}`;
  return {
    text: `${text.slice(0, offset)}${escapeFragment(item)}${text.slice(offset)}`,
    record: { op: "replace", path, removed_bytes: utf8Length(JSON.stringify(old)), added_bytes: utf8Length(JSON.stringify(next)) },
  };
}

/** A new first member of an object (F's rule for an absent `system` or `instructions`). */
function addFirstMember(text: string, object: Node, member: string): string {
  const at = object.offset + 1;
  return `${text.slice(0, at)}${member}${nodesOf(object).length === 0 ? "" : ","}${text.slice(at)}`;
}

/** Insert one element at `index` (0 to the length) of an array: after `[`, or after the element before it. */
function insertElement(text: string, array: Node, index: number, element: string): string {
  const elements = nodesOf(array);
  if (elements.length === 0) return `${text.slice(0, array.offset + 1)}${element}${text.slice(array.offset + 1)}`;
  if (index === 0) return `${text.slice(0, array.offset + 1)}${element},${text.slice(array.offset + 1)}`;
  const before = elements[index - 1]!;
  const at = before.offset + before.length;
  return `${text.slice(0, at)},${element}${text.slice(at)}`;
}

// -----------------------------------------------------------------------------------------------------------------
// Headers (§2.3).
// -----------------------------------------------------------------------------------------------------------------

function applyHeaderOps(
  input: ReadonlyArray<readonly [string, string]>,
  ops: readonly MethodHeaderOp[],
  run: Run,
): { headers: ReadonlyArray<readonly [string, string]>; records: MethodHeaderRecord[] } {
  const headers: [string, string][] = input.map(([name, value]) => [name, value]);
  const records: MethodHeaderRecord[] = [];
  const indexOf = (name: string) => headers.findIndex(([candidate]) => candidate === name);
  const write = (name: string, value: string | undefined) => {
    const index = indexOf(name);
    const old = index < 0 ? undefined : headers[index]![1];
    if (old === value) return;
    if (value === undefined) {
      headers.splice(index, 1);
      records.push({ op: "remove", name, removed_bytes: utf8Length(old!), added_bytes: 0 });
    } else if (old === undefined) {
      headers.push([name, value]);
      records.push({ op: "add", name, removed_bytes: 0, added_bytes: utf8Length(value) });
    } else {
      headers[index] = [name, value];
      records.push({ op: "replace", name, removed_bytes: utf8Length(old), added_bytes: utf8Length(value) });
    }
  };
  for (const op of ops) {
    const index = indexOf(op.name);
    const old = index < 0 ? undefined : headers[index]![1];
    switch (op.op) {
      case "set": {
        if ("value" in op) {
          write(op.name, op.value);
          break;
        }
        const key = run.factValue(op.map.fact);
        const value = (key === undefined ? undefined : op.map.cases.get(key)) ?? op.map.default;
        if (value !== undefined) write(op.name, value);
        break;
      }
      case "remove":
        if (old !== undefined) write(op.name, undefined);
        break;
      case "add_tokens": {
        const tokens = headerTokens(old ?? "");
        const fresh = op.tokens.filter((token, at) => !tokens.includes(token) && op.tokens.indexOf(token) === at);
        if (fresh.length !== 0) write(op.name, [...tokens, ...fresh].join(","));
        break;
      }
      case "remove_tokens": {
        if (old === undefined) break;
        const tokens = headerTokens(old);
        const kept = tokens.filter((token) => !op.tokens.includes(token));
        if (kept.length === tokens.length) break;
        write(op.name, kept.length === 0 ? undefined : kept.join(","));
        break;
      }
    }
  }
  return { headers, records };
}

// -----------------------------------------------------------------------------------------------------------------
// The tree.
// -----------------------------------------------------------------------------------------------------------------

interface Location {
  readonly parent: Node;
  /** The member's property node, for an object parent. */
  readonly property?: Node;
  readonly value?: Node;
}

function memberValue(object: Node, name: string): Node | undefined {
  if (object.type !== "object") return undefined;
  return findMember(object, name)?.children?.[1];
}

/** The child of a container by one token: a member, or an array element by its index. */
function childOf(node: Node, token: string): Node | undefined {
  if (node.type === "object") return memberValue(node, token);
  if (node.type === "array" && INDEX.test(token)) return nodesOf(node)[Number(token)];
  return undefined;
}

/** The parent of the last token and the value there (absent when missing), or undefined when the parent is missing. */
function locate(root: Node, tokens: readonly string[]): Location | undefined {
  let parent = root;
  for (const token of tokens.slice(0, -1)) {
    const next = childOf(parent, token);
    if (next === undefined) return undefined;
    parent = next;
  }
  const last = tokens[tokens.length - 1];
  if (last === undefined) return undefined;
  if (parent.type === "object") {
    const property = findMember(parent, last);
    return property === undefined ? { parent } : { parent, property, value: property.children?.[1] };
  }
  if (parent.type === "array") {
    const value = INDEX.test(last) ? nodesOf(parent)[Number(last)] : undefined;
    return value === undefined ? { parent } : { parent, value };
  }
  return undefined;
}

/** Every concrete path of `tokens` from `node`, in document order; `*` stands for each index of an array. */
function expand(node: Node, tokens: readonly string[], at: number, prefix: string[], out: string[][]): void {
  if (at === tokens.length) {
    out.push(prefix);
    return;
  }
  const token = tokens[at]!;
  if (token === "*") {
    if (node.type !== "array") return;
    nodesOf(node).forEach((child, index) => {
      if (at === tokens.length - 1) out.push([...prefix, String(index)]);
      else expand(child, tokens, at + 1, [...prefix, String(index)], out);
    });
    return;
  }
  if (at === tokens.length - 1) {
    if (node.type === "object" || node.type === "array") out.push([...prefix, token]);
    return;
  }
  const child = childOf(node, token);
  if (child !== undefined) expand(child, tokens, at + 1, [...prefix, token], out);
}

function removeAt(text: string, at: Location): string {
  if (at.property !== undefined) return removeFromObject(text, at.parent, at.property);
  return removeElement(text, at.parent, at.value!);
}

/** Remove one array element and exactly one adjacent comma: `removeFromObject`'s rule for elements. */
function removeElement(text: string, array: Node, element: Node): string {
  const elements = nodesOf(array);
  const index = elements.indexOf(element);
  const next = elements[index + 1];
  if (next !== undefined) return `${text.slice(0, element.offset)}${text.slice(next.offset)}`;
  const previous = elements[index - 1];
  const end = element.offset + element.length;
  if (previous !== undefined) return `${text.slice(0, previous.offset + previous.length)}${text.slice(end)}`;
  return `${text.slice(0, element.offset)}${text.slice(end)}`;
}

function replaceNode(text: string, node: Node, json: string): string {
  return `${text.slice(0, node.offset)}${json}${text.slice(node.offset + node.length)}`;
}

/** The comparison form of a node of `text`: RFC 8785 with number tokens as written (`stackTreeText`'s form). */
function canonOf(text: string, node: Node): string {
  switch (node.type) {
    case "object": {
      const members: [string, string][] = [];
      for (const property of nodesOf(node)) {
        const [key, value] = property.children ?? [];
        if (key === undefined || value === undefined) continue;
        members.push([getNodeValue(key) as string, canonOf(text, value)]);
      }
      members.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
      return `{${members.map(([name, value]) => `${JSON.stringify(name)}:${value}`).join(",")}}`;
    }
    case "array":
      return `[${nodesOf(node).map((item) => canonOf(text, item)).join(",")}]`;
    case "string":
      return JSON.stringify(node.value);
    case "number":
      return text.slice(node.offset, node.offset + node.length);
    case "boolean":
      return node.value === true ? "true" : "false";
    default:
      return "null";
  }
}

/** Whether a value holds a `cache_control` member at any depth (P7). */
function holdsKept(node: Node): boolean {
  if (node.type === "object") {
    for (const property of nodesOf(node)) {
      const [key, value] = property.children ?? [];
      if (key !== undefined && getNodeValue(key) === METHOD_KEPT_ANY_DEPTH) return true;
      if (value !== undefined && holdsKept(value)) return true;
    }
    return false;
  }
  if (node.type === "array") return nodesOf(node).some(holdsKept);
  return false;
}

/** A string, or a non-empty array of plain text parts (`{"type":"text","text":…}` and nothing else): its texts in order. */
function plainTexts(node: Node): string[] | undefined {
  if (node.type === "string") return [node.value as string];
  if (node.type !== "array" || nodesOf(node).length === 0) return undefined;
  const texts: string[] = [];
  for (const element of nodesOf(node)) {
    if (element.type !== "object" || nodesOf(element).length !== 2) return undefined;
    const type = memberValue(element, "type");
    const text = memberValue(element, "text");
    if (type?.type !== "string" || type.value !== "text" || text?.type !== "string") return undefined;
    texts.push(text.value as string);
  }
  return texts;
}

/** The JSON type a condition's `is` names. */
function jsonType(node: Node): string {
  return node.type;
}
