/**
 * `F`, the lane's append function, and the only way bytes are added to a customer's request.
 *
 * F(received_bytes, protocol, appends) -> forwarded_bytes
 *
 * F parses the customer's body just enough to find the one field the appends target, splices the
 * template text (or the JSON elements built from it) into the *text* of the body at offsets the
 * parser reports, and re-encodes. Nothing else is touched: whitespace, member order, escape
 * sequences, number literals (`0.7`, `1e-3`), the customer's own `cache_control` blocks and every
 * other byte stay exactly as received. There is no parse-and-reserialize step, so the
 * "only the declared appends differ" claim of the lane (review.md section 2.3) is a property of the
 * implementation and not a hope about a serializer.
 *
 * The insertion points are structural, and that is the whole byte rule:
 * - inside a JSON string (Anthropic's string `system`, Responses' string `instructions`): right
 *   after the opening quote for a start position, right before the closing quote for an end one, so
 *   the customer's own string bytes remain a contiguous region, verbatim;
 * - inside an array (Anthropic's `system` blocks, Chat Completions' `messages`): right after `[` for
 *   a start position, right before `]` for an end one, with the comma the spliced element needs
 *   (the last leading `system`/`developer` message for `instructions_after`);
 * - a member that is absent (`system`, `instructions`): right after the top-level `{`, as the first
 *   member.
 *
 * So the inserted bytes are always a run at a structural boundary of the original text, and the
 * original text never moves. `insertions` reports where they landed, in UTF-16 code units of the
 * forwarded text, which is what the byte-preservation test removes to recover the received bytes.
 *
 * When the target field is *absent* (`system`, `instructions`, or a Chat `messages` with no leading
 * system/developer message), the start and end positions produce the same bytes for one append: the
 * new member holds the text either way, and the front of `messages` is where both groups go. The
 * recorded `position` is then **descriptive only** — it says which registered position the relay's
 * module selected, not something the bytes prove. Verification recomputes F with the position the
 * receipt records (see `verifyForwarded`), and because both positions produce exactly those bytes,
 * the recomputation matches either way. No content can hide behind this: the appended text and its
 * `text_sha256` are still exactly what the receipt lists. VERIFY.md L-3 records the property; the
 * byte rule is intentionally unchanged (the owner's decision).
 *
 * Rules that F refuses rather than guesses (every one is a typed refusal):
 * - a body that is not strict UTF-8, or starts with a BOM;
 * - a body that is not strict JSON: comments and trailing commas are accepted by jsonc-parser and
 *   refused here, because the lane's parser is the vendor's and a body that two parsers read
 *   differently is not a body the lane can promise anything about;
 * - a duplicate member name in either object F reads: the top-level object and every Chat
 *   Completions `messages` element. The rule is deliberately about the whole object, not only the
 *   member F writes (`system`, `role`): a body whose meaning depends on which of two equal members
 *   a parser picks is not a body this lane can promise anything about, and the vendor's parser is
 *   not the one that decides here. So `{"content":"a","content":"b"}` in a message and a duplicated
 *   `model` at the top level are refused too, at the cost of bodies the vendor would accept. That is
 *   the owner's decision (strict rule kept, VERIFY.md L-2): refuse, do not guess. Nested values F
 *   never reads (content blocks, tool definitions, `metadata`) are not inspected for duplicates.
 * - a target field of a type the position cannot be expressed on (`system: null`, `system: 7`,
 *   `instructions: {"a":1}`, `messages: {}`, a `messages` element that is not an object);
 * - a Chat Completions body with no `messages` array at all;
 * - a position that the request's protocol does not have, or template text with a lone surrogate.
 *
 * Serialization of what is inserted: compact, member order as written in the source below, strings
 * escaped by @gray/json's `toJsonString` — for a well-formed string exactly `JSON.stringify`, the
 * same escape set serde_json writes (`"`, `\`, \b \f \n \r \t, and `\u00XX` lower-case for the other
 * control characters) — so an inserted string reads back as the template text and nothing else.
 *
 * F adds no separators between two templates at the same position: they are appended in the order
 * given, and the record of each is kept in that order. A separator belongs in the template text.
 *
 * The body is checked whether or not there is anything to append: a body two parsers read
 * differently is not a body the lane can promise anything about, so it is refused rather than
 * forwarded. With no appends, every body F accepts is forwarded byte for byte.
 */
import { toJsonString } from "@gray/json";
import { getNodeValue, parseTree, printParseErrorCode, type Node, type ParseError } from "jsonc-parser";
import {
  isLaneProtocol,
  isPosition,
  isPositionForProtocol,
  type LaneProtocol,
  type Position,
} from "./protocol.ts";
import { LaneError, refusal, type Refusal } from "./refusal.ts";
import { textSha256Hex } from "./sha256.ts";
import { decodeUtf8, encodeUtf8 } from "./utf8.ts";

/** One append as the host applies it: the registry's text, and where it goes. */
export interface AppendedText {
  readonly templateId: string;
  readonly position: Position;
  readonly text: string;
}

/** One append as a receipt records it (the shared wire shape's `appended[]` item). */
export interface AppliedRecord {
  readonly template_id: string;
  readonly position: Position;
  readonly text_sha256: string;
}

/** A run of inserted bytes, as an offset and a length in the forwarded text (UTF-16 code units). */
export interface Insertion {
  readonly offset: number;
  readonly length: number;
}

/** What F answers: the forwarded bytes, the records of what was appended, and where it landed. */
export interface AppendOk {
  readonly ok: true;
  readonly forwarded: Uint8Array;
  readonly applied: readonly AppliedRecord[];
  readonly insertions: readonly Insertion[];
}

/** Why F refuses a body. */
export type AppendRefusalCode =
  | "unknown_protocol"
  | "append_shape"
  | "position_protocol"
  | "invalid_text"
  | "bom"
  | "invalid_utf8"
  | "invalid_json"
  | "not_an_object"
  | "duplicate_key"
  | "unexpected_type"
  | "messages_absent";

/** A place the forwarded text gets text inserted, at an offset of the received text. */
interface Splice {
  readonly offset: number;
  readonly text: string;
}

/**
 * F: apply `appends` to `received` for a request of `protocol`, byte-preservingly. In the order
 * given, so a start position puts the first template first and an end position puts it first too.
 */
export function appendTemplates(
  received: Uint8Array,
  protocol: LaneProtocol,
  appends: readonly AppendedText[],
): AppendOk | Refusal<AppendRefusalCode> {
  const malformed = checkAppends(protocol, appends);
  if (malformed !== undefined) return malformed;
  const decoded = decodeUtf8(received);
  if (!decoded.ok) return decoded;
  const text = decoded.text;
  const parsed = parseStrictObject(text);
  if (!parsed.ok) return parsed;
  const root = parsed.root;

  const splices: Splice[] = [];
  switch (protocol) {
    case "anthropic_messages": {
      const bad = planAnthropic(root, appends, splices);
      if (bad !== undefined) return bad;
      break;
    }
    case "open_ai_chat": {
      const bad = planChat(root, appends, splices);
      if (bad !== undefined) return bad;
      break;
    }
    case "open_ai_responses": {
      const bad = planResponses(root, appends, splices);
      if (bad !== undefined) return bad;
      break;
    }
  }

  // Stable sort: two splices at one offset (an empty string with both positions, an empty array)
  // keep the order they were planned in, so a start group always precedes an end group.
  splices.sort((left, right) => left.offset - right.offset);
  let cursor = 0;
  let shifted = 0;
  let forwardedText = "";
  const insertions: Insertion[] = [];
  for (const splice of splices) {
    if (splice.offset < cursor || splice.offset > text.length) {
      throw new LaneError("lane/splice", "a splice is out of order or outside the text");
    }
    forwardedText += text.slice(cursor, splice.offset) + splice.text;
    insertions.push({ offset: splice.offset + shifted, length: splice.text.length });
    shifted += splice.text.length;
    cursor = splice.offset;
  }
  forwardedText += text.slice(cursor);
  const encoded = encodeUtf8(forwardedText);
  if (!encoded.ok) throw new LaneError("lane/encoding", "the forwarded text is not well formed");
  return { ok: true, forwarded: encoded.bytes, applied: appends.map(appendRecord), insertions };
}

/** The receipt record of one append: the wire shape's `{template_id, position, text_sha256}`. */
export function appendRecord(append: AppendedText): AppliedRecord {
  return { template_id: append.templateId, position: append.position, text_sha256: textSha256Hex(append.text) };
}

// ---------------------------------------------------------------------------------------------
// Anthropic Messages: `system`, a string or an array of blocks or absent.
// ---------------------------------------------------------------------------------------------

function planAnthropic(root: Node, appends: readonly AppendedText[], splices: Splice[]): Refusal<AppendRefusalCode> | undefined {
  const startTexts = textsAt(appends, "system_start");
  const endTexts = textsAt(appends, "system_end");
  if (startTexts.length === 0 && endTexts.length === 0) return undefined;
  const system = findMember(root, "system");
  if (system === undefined) {
    // Absent: one new first member holding every block, start group first. Never a type change of
    // an existing member, for the reason review.md section 3.2 gives (a string `system` stays one).
    const blocks = [...startTexts, ...endTexts].map(textBlock);
    addMemberSplice(root, `"system":${inlineArray(blocks)}`, splices);
    return undefined;
  }
  const value = memberValue(system);
  if (value === undefined) return refusal("unexpected_type", "the system member has no value");
  if (value.type === "string") {
    insertIntoString(value, startTexts.join(""), endTexts.join(""), splices);
    return undefined;
  }
  if (value.type === "array") {
    insertIntoArray(value, startTexts.map(textBlock), endTexts.map(textBlock), splices);
    return undefined;
  }
  return refusal("unexpected_type", "system is neither a string nor an array of blocks");
}

// ---------------------------------------------------------------------------------------------
// OpenAI Chat Completions: a new message in `messages`, never an edit of one.
// ---------------------------------------------------------------------------------------------

function planChat(root: Node, appends: readonly AppendedText[], splices: Splice[]): Refusal<AppendRefusalCode> | undefined {
  const before = textsAt(appends, "instructions_before").map(developerMessage);
  const after = textsAt(appends, "instructions_after").map(developerMessage);
  if (before.length === 0 && after.length === 0) return undefined;
  const messages = findMember(root, "messages");
  if (messages === undefined) return refusal("messages_absent", "the request has no messages member to insert a message into");
  const value = memberValue(messages);
  if (value === undefined || value.type !== "array") return refusal("unexpected_type", "messages is not an array");
  const elements = nodesOf(value);
  for (const element of elements) {
    if (element.type !== "object") return refusal("unexpected_type", "a messages element is not an object");
    if (duplicateMember(element) !== undefined) {
      return refusal("duplicate_key", "a messages element holds a member name twice, so its role is not determined");
    }
  }

  // `instructions_after` goes after the last leading system/developer message: before the first
  // message whose role is neither, and at the front when there is no such leading message.
  let last = -1;
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    if (element === undefined) break;
    const role = roleOf(element);
    if (role === "system" || role === "developer") last = index;
    else break;
  }

  if (elements.length === 0) {
    const all = [...before, ...after];
    if (all.length !== 0) splices.push({ offset: value.offset + 1, text: all.join(",") });
    return undefined;
  }
  if (last < 0) {
    const all = [...before, ...after];
    if (all.length !== 0) splices.push({ offset: value.offset + 1, text: `${all.join(",")},` });
    return undefined;
  }
  if (before.length !== 0) splices.push({ offset: value.offset + 1, text: `${before.join(",")},` });
  if (after.length !== 0) {
    const anchor = elements[last];
    if (anchor === undefined) throw new LaneError("lane/anchor", "the leading message vanished");
    splices.push({ offset: anchor.offset + anchor.length, text: `,${after.join(",")}` });
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// OpenAI Responses: `instructions`, a string or absent. `input` is never touched.
// ---------------------------------------------------------------------------------------------

function planResponses(root: Node, appends: readonly AppendedText[], splices: Splice[]): Refusal<AppendRefusalCode> | undefined {
  const start = textsAt(appends, "instructions_before").join("");
  const end = textsAt(appends, "instructions_after").join("");
  if (start.length === 0 && end.length === 0) return undefined;
  const instructions = findMember(root, "instructions");
  if (instructions === undefined) {
    addMemberSplice(root, `"instructions":${toJsonString(`${start}${end}`)}`, splices);
    return undefined;
  }
  const value = memberValue(instructions);
  if (value === undefined || value.type !== "string") {
    return refusal("unexpected_type", "instructions is not a string, and the lane does not convert a field's type");
  }
  insertIntoString(value, start, end, splices);
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// Splices.
// ---------------------------------------------------------------------------------------------

/** Insert escaped text just inside the quotes of a string value: start after the opening quote, end before the closing one. */
function insertIntoString(value: Node, start: string, end: string, splices: Splice[]): void {
  if (start.length !== 0) splices.push({ offset: value.offset + 1, text: escapeFragment(start) });
  if (end.length !== 0) splices.push({ offset: value.offset + value.length - 1, text: escapeFragment(end) });
}

/** Insert elements just inside an array: a start group after `[`, an end group before `]`, with the commas they need. */
function insertIntoArray(array: Node, before: readonly string[], after: readonly string[], splices: Splice[]): void {
  if (before.length === 0 && after.length === 0) return;
  const elements = nodesOf(array);
  if (elements.length === 0) {
    splices.push({ offset: array.offset + 1, text: [...before, ...after].join(",") });
    return;
  }
  if (before.length !== 0) splices.push({ offset: array.offset + 1, text: `${before.join(",")},` });
  if (after.length !== 0) splices.push({ offset: array.offset + array.length - 1, text: `,${after.join(",")}` });
}

/** Insert a member as the first member of an object. */
function addMemberSplice(object: Node, member: string, splices: Splice[]): void {
  const members = nodesOf(object);
  splices.push({ offset: object.offset + 1, text: members.length === 0 ? member : `${member},` });
}

/** `{"type":"text","text":…}` — the block an Anthropic `system` array takes. */
export function textBlock(text: string): string {
  return `{"type":"text","text":${toJsonString(text)}}`;
}

/** `{"role":"developer","content":…}` — the message a Chat Completions `messages` array takes. */
export function developerMessage(text: string): string {
  return `{"role":"developer","content":${toJsonString(text)}}`;
}

function inlineArray(items: readonly string[]): string {
  return `[${items.join(",")}]`;
}

/** The inside of a JSON string literal: what `toJsonString` writes, without the quotes. */
export function escapeFragment(text: string): string {
  const quoted = toJsonString(text);
  return quoted.slice(1, -1);
}

// ---------------------------------------------------------------------------------------------
// Reading the body.
// ---------------------------------------------------------------------------------------------

/** The appends of one position, in the order given. */
function textsAt(appends: readonly AppendedText[], position: Position): string[] {
  return appends.filter((append) => append.position === position).map((append) => append.text);
}

/** Parse `text` as strict JSON and require an object at the top. Comments and trailing commas are refused. */
function parseStrictObject(text: string): { readonly ok: true; readonly root: Node } | Refusal<AppendRefusalCode> {
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false });
  const first = errors[0];
  if (root === undefined || first !== undefined) {
    const why = first === undefined ? "no value" : printParseErrorCode(first.error);
    return refusal("invalid_json", `the body is not strict JSON (${why}); the lane refuses comments, trailing commas and trailing content`);
  }
  if (root.type !== "object") return refusal("not_an_object", "the body is not a JSON object");
  if (duplicateMember(root) !== undefined) {
    return refusal("duplicate_key", "the top-level object holds a member name twice, so the field to append to is not determined");
  }
  return { ok: true, root };
}

/** The members of an object node, or the elements of an array node. */
function nodesOf(node: Node): Node[] {
  return node.children ?? [];
}

/** The property node of `name` in an object node, or `undefined`. Duplicates are refused by the caller. */
function findMember(object: Node, name: string): Node | undefined {
  for (const child of nodesOf(object)) {
    if (child.type !== "property") continue;
    const key = child.children?.[0];
    if (key === undefined) continue;
    const value = getNodeValue(key);
    if (value === name) return child;
  }
  return undefined;
}

/** A property node's value node. */
function memberValue(property: Node): Node | undefined {
  return property.children?.[1];
}

/** A message's `role`, when it is a string. */
function roleOf(element: Node): string | undefined {
  const role = findMember(element, "role");
  if (role === undefined) return undefined;
  const value = memberValue(role);
  if (value === undefined || value.type !== "string") return undefined;
  const name = getNodeValue(value);
  return typeof name === "string" ? name : undefined;
}

/** The first member name written twice in an object, or `undefined`. Escapes are compared decoded. */
function duplicateMember(object: Node): string | undefined {
  const seen = new Set<string>();
  for (const child of nodesOf(object)) {
    if (child.type !== "property") continue;
    const key = child.children?.[0];
    if (key === undefined) continue;
    const name = getNodeValue(key);
    if (typeof name !== "string") continue;
    if (seen.has(name)) return name;
    seen.add(name);
  }
  return undefined;
}

/** Whether the appends are well formed for `protocol`, before any byte is looked at. */
function checkAppends(protocol: LaneProtocol, appends: readonly AppendedText[]): Refusal<AppendRefusalCode> | undefined {
  if (!isLaneProtocol(protocol)) return refusal("unknown_protocol", "the protocol is not one of the lane's three");
  if (!Array.isArray(appends)) return refusal("append_shape", "the appends are not an array");
  for (const append of appends) {
    if (typeof append !== "object" || append === null) return refusal("append_shape", "an append is not an object");
    if (typeof append.templateId !== "string" || append.templateId.length === 0) {
      return refusal("append_shape", "an append has no template id");
    }
    if (!isPosition(append.position)) return refusal("append_shape", "an append names a position that does not exist");
    if (!isPositionForProtocol(protocol, append.position)) {
      return refusal("position_protocol", `the position ${append.position} is not one this protocol has`);
    }
    if (typeof append.text !== "string" || append.text.length === 0) return refusal("invalid_text", "an append has no text");
    if (!append.text.isWellFormed()) {
      return refusal("invalid_text", "an append's text holds a lone surrogate, which has no UTF-8 bytes");
    }
  }
  return undefined;
}
