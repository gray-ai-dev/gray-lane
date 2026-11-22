/**
 * A provider's `video` object as the confidential entry reads it and hands it on (docs/design/standard-media-at-entry.md
 * section 2.7; the provider standard's clauses 11.10 and 11.14).
 *
 * The entry serves OpenAI's video API on a provider's own API and converts nothing: a create's and a retrieve's answer
 * is the provider's object, read whole. Gray reads three members of it and changes three things, at byte offsets:
 *
 * - it reads the top-level `id` (the provider's job id), `status` (OpenAI's `queued`, `in_progress`, `completed`,
 *   `failed`, or new-api's `processing`, `succeeded`, `failed`) and `seconds` (the length of the finished video: a
 *   non-negative JSON number, or a decimal string such as `"5"` or `"5.0"`);
 * - it writes Gray's job id in `id`, so the provider's id never reaches the client;
 * - it writes Gray's job state in `status`, in OpenAI's words, because clients poll by them (openai-python's `poll`
 *   waits only while the status is `queued` or `in_progress`);
 * - it removes every link, wherever it stands in the object, so a client never receives a provider's storage link and
 *   the client's address reaches no provider. A link is a string that starts with `http://` or `https://` (in any
 *   case, after any leading whitespace). A member whose value is a link is removed, in the object itself and in any
 *   object below it, objects that sit in arrays included. An element of an array that is a link is removed from its
 *   array, at any depth; an array left with no element stays as an empty array, under its member's name, so the
 *   object keeps its shape for a client that reads it by type. A link inside a longer text (an error's message) is
 *   neither, and stays.
 *
 * Every other byte reaches the client as the provider sent it. Nothing is serialized again: the object is parsed only
 * to find offsets, a value is replaced in place, and a member or an element is removed with exactly one adjacent
 * comma, by the rule the request's `remove_member` op follows (changes.ts `removeFromObject`). An object that is not strict UTF-8 JSON,
 * holds a member name twice, nests deeper than VIDEO_OBJECT_MAX_DEPTH, or has no string `id` and `status` is not a
 * `video` object Gray hands on (`readVideoObject` answers null): with a name twice, one copy would keep the provider's
 * value after the other was rewritten.
 */
import { toJsonString } from "@gray/json";
import { getNodeValue, type Node } from "jsonc-parser";
import { hasDuplicateMember, nodesOf, parseStrictObject } from "./changes.ts";
import { decodeUtf8, encodeUtf8 } from "./utf8.ts";

/** Gray's job states: OpenAI's status words. */
export const VIDEO_STATES = ["queued", "in_progress", "completed", "failed"] as const;
export type VideoState = (typeof VIDEO_STATES)[number];

/** The provider's `status` words and the job state each one is (section 2.7's table). Any other word is not read. */
const STATE_OF_STATUS: Readonly<Record<string, VideoState>> = Object.freeze({
  queued: "queued",
  in_progress: "in_progress",
  processing: "in_progress",
  completed: "completed",
  succeeded: "completed",
  failed: "failed",
});

/** Gray's job state for a provider's `status`, in either vocabulary; null for a word it does not read. */
export function videoStateOf(status: string): VideoState | null {
  return Object.hasOwn(STATE_OF_STATUS, status) ? (STATE_OF_STATUS[status] as VideoState) : null;
}

/** The provider's job id (clause 11.10): 1 to 256 characters of `[A-Za-z0-9_.:-]`, not `.` or `..`. */
export function isVideoProviderId(id: string): boolean {
  return /^[A-Za-z0-9_.:-]{1,256}$/.test(id) && id !== "." && id !== "..";
}

/**
 * The deepest nesting of an object Gray hands on. A provider's `video` object is a few levels deep; the bound keeps a
 * hostile answer from costing the entry more than one pass over it.
 */
export const VIDEO_OBJECT_MAX_DEPTH = 64;

/**
 * The `seconds` of an object: `absent` (no member, or `null`); the number it gives; or `malformed` (another type, a
 * negative number, a string that is not a decimal number).
 */
export type VideoSeconds = { readonly kind: "absent" } | { readonly kind: "seconds"; readonly seconds: number } | { readonly kind: "malformed" };

/** What Gray reads of a provider's `video` object, and the object as the client gets it. */
export interface VideoObject {
  /** The provider's job id as the object names it. Not checked against clause 11.10 here (`isVideoProviderId`). */
  readonly id: string;
  /** The provider's `status` word. */
  readonly status: string;
  /** Gray's job state for it; null for a word Gray does not read. */
  readonly state: VideoState | null;
  readonly seconds: VideoSeconds;
  /** How many links the client's copy leaves out: members whose value is one, and elements of arrays that are one. */
  readonly links: number;
  /** The object for the client: `id` and `status` written as given, every link removed, every other byte as sent. */
  forClient(id: string, status: VideoState): Uint8Array;
}

/**
 * Whether a member's value or an array's element is a link: a string that starts with `http://` or `https://`, in any
 * case, after any leading whitespace. A text that only holds one further in is not.
 */
export function isHttpUrl(value: unknown): boolean {
  return typeof value === "string" && /^[\t\n\r ]*https?:\/\//i.test(value);
}

/** A decimal number as clause 11.10 writes a string `seconds`: digits, optionally a point and digits. */
const DECIMAL = /^[0-9]+(?:\.[0-9]+)?$/;

function secondsOf(node: Node | undefined): VideoSeconds {
  if (node === undefined || node.type === "null") return { kind: "absent" };
  if (node.type === "number") {
    const value: unknown = getNodeValue(node);
    return typeof value === "number" && !Number.isNaN(value) && value >= 0 ? { kind: "seconds", seconds: value } : { kind: "malformed" };
  }
  if (node.type === "string") {
    const text: unknown = getNodeValue(node);
    return typeof text === "string" && DECIMAL.test(text) ? { kind: "seconds", seconds: Number(text) } : { kind: "malformed" };
  }
  return { kind: "malformed" };
}

/** A span of the object's text to replace: `[start, end)` with `text`. */
interface Edit {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

interface Member {
  readonly name: string;
  readonly property: Node;
  readonly value: Node;
}

function membersOf(object: Node): Member[] | null {
  const out: Member[] = [];
  for (const property of nodesOf(object)) {
    if (property.type !== "property") return null;
    const key = property.children?.[0];
    const value = property.children?.[1];
    const name: unknown = key === undefined ? undefined : getNodeValue(key);
    if (value === undefined || typeof name !== "string") return null;
    out.push({ name, property, value });
  }
  return out;
}

/** One member of an object or one element of an array, as the removal reads it: where it starts and ends, and whether it goes. */
interface Item {
  readonly start: number;
  readonly end: number;
  readonly removed: boolean;
}

/**
 * The spans that take the removed items of one object or one array out. A removed item that is not the last goes with
 * the comma and whitespace up to the next item's start; a removed last item goes with the comma and whitespace after
 * the last item kept, or alone when none is kept, which leaves `{}` or `[]` with the whitespace it had.
 */
function itemRemovals(items: readonly Item[], spans: Edit[]): void {
  let keptEnd: number | null = null;
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index] as Item;
    if (!item.removed) {
      keptEnd = item.end;
      continue;
    }
    const following = items[index + 1];
    if (following !== undefined) spans.push({ start: item.start, end: following.start, text: "" });
    else spans.push({ start: keptEnd ?? item.start, end: item.end, text: "" });
  }
}

const isLink = (node: Node): boolean => node.type === "string" && isHttpUrl(getNodeValue(node));

/**
 * The spans that remove every link under `root`: each member whose value is a link, in every object, and each element
 * that is a link, in every array. `keep` holds the top-level members Gray writes itself. Null when the tree nests
 * deeper than the bound.
 */
function urlRemovals(root: Node, keep: ReadonlySet<Node>): { readonly spans: Edit[]; readonly count: number } | null {
  const spans: Edit[] = [];
  let count = 0;
  const stack: { readonly node: Node; readonly depth: number }[] = [{ node: root, depth: 1 }];
  for (let next = stack.pop(); next !== undefined; next = stack.pop()) {
    const { node, depth } = next;
    if (depth > VIDEO_OBJECT_MAX_DEPTH) return null;
    const items: Item[] = [];
    if (node.type === "array") {
      for (const element of nodesOf(node)) {
        const removed = isLink(element);
        if (removed) count += 1;
        else if (element.type === "object" || element.type === "array") stack.push({ node: element, depth: depth + 1 });
        items.push({ start: element.offset, end: element.offset + element.length, removed });
      }
    } else if (node.type === "object") {
      const members = membersOf(node);
      if (members === null) return null;
      for (const member of members) {
        const removed = !keep.has(member.property) && isLink(member.value);
        if (removed) count += 1;
        else if (member.value.type === "object" || member.value.type === "array") stack.push({ node: member.value, depth: depth + 1 });
        items.push({ start: member.property.offset, end: member.value.offset + member.value.length, removed });
      }
    } else {
      continue;
    }
    itemRemovals(items, spans);
  }
  return { spans, count };
}

/** `text` with `edits` applied: sorted by start, overlapping removals merged. A replacement never overlaps a removal. */
function applyEdits(text: string, edits: readonly Edit[]): string {
  const sorted = [...edits].sort((a, b) => a.start - b.start || a.end - b.end);
  let out = "";
  let at = 0;
  for (const edit of sorted) {
    if (edit.end <= at) continue;
    if (edit.start > at) out += text.slice(at, edit.start);
    out += edit.text;
    at = edit.end;
  }
  return out + text.slice(at);
}

/**
 * Reads `bytes` as a provider's `video` object: null when it is not one Gray reads and hands on (not strict UTF-8 JSON,
 * not an object, a member name twice, nested past the bound, or no string `id` and string `status` at its top level).
 * Never throws.
 */
export function readVideoObject(bytes: Uint8Array): VideoObject | null {
  const decoded = decodeUtf8(bytes);
  if (!decoded.ok) return null;
  const text = decoded.text;
  let root: Node;
  let removals: { readonly spans: Edit[]; readonly count: number } | null;
  let id: Member | undefined;
  let status: Member | undefined;
  let seconds: VideoSeconds;
  try {
    const parsed = parseStrictObject(text);
    if (!parsed.ok) return null;
    root = parsed.root;
    const top = membersOf(root);
    if (top === null) return null;
    id = top.find((member) => member.name === "id");
    status = top.find((member) => member.name === "status");
    if (id === undefined || status === undefined || id.value.type !== "string" || status.value.type !== "string") return null;
    removals = urlRemovals(root, new Set([id.property, status.property]));
    // Checked after the depth bound, which the walk above holds: the duplicate check recurses.
    if (removals === null || hasDuplicateMember(root)) return null;
    seconds = secondsOf(top.find((member) => member.name === "seconds")?.value);
  } catch {
    // A tree the parser or a walk could not finish (its own stack, on input no bound above caught).
    return null;
  }
  const providerId = getNodeValue(id.value) as string;
  const word = getNodeValue(status.value) as string;
  const idSpan = { start: id.value.offset, end: id.value.offset + id.value.length };
  const statusSpan = { start: status.value.offset, end: status.value.offset + status.value.length };
  const spans = removals.spans;
  return {
    id: providerId,
    status: word,
    state: videoStateOf(word),
    seconds,
    links: removals.count,
    forClient(clientId, state) {
      const changed = applyEdits(text, [...spans, { ...idSpan, text: toJsonString(clientId) }, { ...statusSpan, text: toJsonString(state) }]);
      const encoded = encodeUtf8(changed);
      // Strictly decoded text with ASCII written into it is well formed.
      if (!encoded.ok) throw new Error("a video object that was read does not encode");
      return encoded.bytes;
    },
  };
}
