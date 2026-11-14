/**
 * The projection of a non-streaming answer: the part of the document every decision on the answer
 * reads, built from a `StrictJsonScan`'s tokens as they arrive, so the gateway decides on an answer
 * it never held (docs/cloudflare-native/gateway.md section 9).
 *
 * What is kept:
 * - every key, container, number, `true`, `false` and `null`, in document order;
 * - a string of at most KEPT_STRING_UNITS UTF-8 bytes as it is; a longer one as its first
 *   KEPT_STRING_UNITS code units (a surrogate pair is never split) followed by "…";
 * - whole, every string included, the subtrees decisions read by value: the usage (`usage`,
 *   Gemini's `usageMetadata`), and every call: Chat's `choices.*.message.tool_calls` and
 *   `function_call`; Responses' `output.*` `type`, `id`, `call_id`, `name`, `arguments` and
 *   `status`; Anthropic's `content.*` `type`, `id`, `name` and `input`; Gemini's
 *   `candidates.*.content.parts.*.functionCall`;
 * - as an empty container of their kind, the token log probabilities, which no decision reads and
 *   which can hold an object per output token: Chat's `choices.*.logprobs`, Responses'
 *   `output.*.content.*.logprobs`, Gemini's `candidates.*.logprobsResult`.
 *
 * `parseResponse`, `parseProviderError`, `bufferedUsage` and the settlement, the tool gate's
 * `inspectResponse`, and the continuation's `replyReferences` decide the same on the projection as
 * on the whole document: test/answer-projection.test.ts compares them on every response body of the
 * conformance fixtures, and changes every string the projection cuts and every log probability at
 * random to show none of them reads one.
 *
 * An observer hears each token with the path of the value it belongs to (the tool gate decides
 * there what of the answer may go out, @gray/trust `AnswerCallCheck`). Paths are live arrays: copy
 * one to keep it.
 */
import { type Json, type JsonArray, type JsonObject, setMember, utf8Length } from "@gray/json";
import { KEPT_STRING_UNITS, type ScanListener, type ScanString } from "./answer-scan.ts";
import type { Protocol } from "./types.ts";
import { usageKey } from "./usage.ts";

/** A step of a path: an object key or an array index. */
export type PathKey = string | number;

/** How a value is kept: whole (every string in it whole), as an empty container of its kind, or by the default rule. */
export type KeepRule = "whole" | "empty" | "default";

/** Hears the projected tokens, each with the path of its value (`path` of `key` is the object's). */
export interface ProjectionObserver {
  open(path: readonly PathKey[], array: boolean, offset: number): void;
  key(path: readonly PathKey[], key: string, offset: number): void;
  /** A string, number, `true`, `false` or `null`, as kept. */
  value(path: readonly PathKey[], value: Json, offset: number): void;
  /** A container closed; `node` is it as kept. */
  close(path: readonly PathKey[], node: Json, offset: number): void;
  /** A kept string value at `path`, opening at `offset`, runs past the end of a chunk (`ScanListener.stringRuns`). */
  stringRuns?(path: readonly PathKey[], offset: number): void;
}

/**
 * What each node of the projection holds in the heap beyond its JSON text, in bytes: the projection
 * is a parsed document of short strings and structure, and V8 holds structure at many times its text
 * (`[{},{},...]` takes 68 bytes an object for 3 bytes of text). Measured on 2026-10-18 with Node
 * 26.10 (V8 without pointer compression, which workerd enables: an upper bound for it),
 * @streamparser/json 0.0.26, this scan and this projection, as heap retained after a full GC with
 * every container still open, the most of runs of 100,000, 300,000 and 700,000 nodes a shape
 * (test/measure/projection-heap.ts; the gateway's test/workerd/answer.test.ts `MEASURED_HEAP` keeps
 * the whole table and checks every shape's weight against it):
 *
 * | shape, an array of | heap a node |
 * | --- | --- |
 * | `{}` | 68 |
 * | `[]` | 42 |
 * | `0` | 10 |
 * | `"ab"` | 34 |
 * | `{"a":1}` (one shape for all) | 90 |
 * | `{"kN":0}` (a key of its own each: a new hidden class each) | 217 |
 * | `{"a":{"b":[]}}` | 154 |
 * | one object of `"kN":0` members (dictionary mode, with the scan's duplicate-key set) | 116 |
 *
 * Each node is priced so that with its text bytes at the `projection` factor (2.36, the gateway's
 * answer.ts) every shape weighs at least what it was measured to hold:
 * - `item` 20: an array's slot, 8 bytes, with the room V8 leaves when it grows the store (to 1.5
 *   times plus 16) and the old store alive while it is copied (8 + 12);
 * - `object` 56: an object (68 less its slot and its 3 weighed text bytes, rounded up);
 * - `array` 32: an array (42 less its slot and its text, rounded up);
 * - `member` 152: an object member, priced as one whose key makes a new hidden class (217 less the
 *   object, its slot and its text, with room), the dearest kind;
 * - `string` 24: a string's header with its first characters (34 less its slot and its text,
 *   rounded up; its characters are counted with the text bytes);
 * - `number` 16: a heap number (a small integer takes none; all are counted).
 */
export const PROJECTION_NODE_BYTES = { item: 20, object: 56, array: 32, member: 152, string: 24, number: 16 } as const;

const RESPONSES_ITEM_WHOLE: ReadonlySet<PathKey> = new Set(["type", "id", "call_id", "name", "arguments", "status"]);
const ANTHROPIC_BLOCK_WHOLE: ReadonlySet<PathKey> = new Set(["type", "id", "name", "input"]);

const index = (step: PathKey | undefined): boolean => typeof step === "number";

/** The rule of the value at `path`, its parent kept by the default rule. */
export function keepRule(protocol: Protocol, path: readonly PathKey[]): KeepRule {
  const n = path.length;
  const top = path[0];
  if (n === 1 && top === usageKey(protocol)) return "whole";
  switch (protocol) {
    case "open_ai_chat":
      if (top !== "choices" || !index(path[1])) return "default";
      if (n === 4 && path[2] === "message" && (path[3] === "tool_calls" || path[3] === "function_call")) return "whole";
      if (n === 3 && path[2] === "logprobs") return "empty";
      return "default";
    case "open_ai_responses":
      if (top !== "output" || !index(path[1])) return "default";
      if (n === 3 && RESPONSES_ITEM_WHOLE.has(path[2]!)) return "whole";
      if (n === 5 && path[2] === "content" && index(path[3]) && path[4] === "logprobs") return "empty";
      return "default";
    case "anthropic_messages":
      if (n === 3 && top === "content" && index(path[1]) && ANTHROPIC_BLOCK_WHOLE.has(path[2]!)) return "whole";
      return "default";
    case "gemini":
      if (top !== "candidates" || !index(path[1])) return "default";
      if (n === 6 && path[2] === "content" && path[3] === "parts" && index(path[4]) && path[5] === "functionCall") return "whole";
      if (n === 3 && path[2] === "logprobsResult") return "empty";
      return "default";
    default:
      return "default";
  }
}

/**
 * Whether the value at `path` is the answer's text (`AnswerProjectionOptions.wholeText`): Chat
 * `choices.*.message.content`, or its parts' `choices.*.message.content.*.text`, Responses `output.*.content.*.text`,
 * Anthropic `content.*.text`, Gemini `candidates.*.content.parts.*.text`. Its parent is kept by the default rule: none
 * of these is inside a subtree kept whole or emptied.
 */
function textPath(protocol: Protocol, path: readonly PathKey[]): boolean {
  const n = path.length;
  switch (protocol) {
    case "open_ai_chat":
      if (n < 4 || path[0] !== "choices" || !index(path[1]) || path[2] !== "message" || path[3] !== "content") return false;
      // The content as a string, or the text of each of its parts.
      return n === 4 || (n === 6 && index(path[4]) && path[5] === "text");
    case "open_ai_responses":
      return n === 5 && path[0] === "output" && index(path[1]) && path[2] === "content" && index(path[3]) && path[4] === "text";
    case "anthropic_messages":
      return n === 3 && path[0] === "content" && index(path[1]) && path[2] === "text";
    case "gemini":
      return n === 6 && path[0] === "candidates" && index(path[1]) && path[2] === "content" && path[3] === "parts" && index(path[4]) && path[5] === "text";
    default:
      return false;
  }
}

/**
 * The most answer text a projection with `wholeText` keeps whole, in UTF-8 bytes over all its text strings: 256 KiB,
 * the structured output check's limit (@gray/trust src/output.ts `OUTPUT_TEXT_LIMIT`, the traffic evidence's
 * `JSON_TEXT_LIMIT`), past which that check decides nothing (`unknown`). So the option keeps at most this much more
 * text than the projection otherwise would, whatever the answer's size, weighed as every kept byte is (the gateway's
 * `answerWeight`, workers/gateway/src/answer.ts).
 */
const WHOLE_TEXT_BYTES = 256 * 1024;

/** A string kept by the default rule. */
export function keptString(value: ScanString): string {
  if (value.bytes <= KEPT_STRING_UNITS) return value.text;
  let end = Math.min(value.text.length, KEPT_STRING_UNITS);
  const last = value.text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${value.text.slice(0, end)}…`;
}

interface Frame {
  /** The container as kept; null inside an empty one (nothing of it is kept or heard). */
  readonly node: JsonObject | JsonArray | null;
  readonly array: boolean;
  readonly rule: KeepRule;
  /** The key whose value comes next. */
  key: string | undefined;
  /** The index of the next item. */
  index: number;
  /** Members or items so far (a comma before each after the first). */
  count: number;
}

/**
 * How an answer is projected beyond the protocol's keep rules (r14). `wholeText`: the answer's text (Chat
 * `choices.*.message.content` or its parts' `.text`, Responses `output.*.content.*.text`, Anthropic `content.*.text`,
 * Gemini `candidates.*.content.parts.*.text`) is kept whole, its bytes counted as every kept byte is, for the structured
 * output check of a request that asked for JSON (docs/error-rates.md; @gray/trust `outputCheck`). At most `WHOLE_TEXT_BYTES`
 * of text in all: the scan keeps each text whole up to what is left of it (`wholeStringBytes`); the text that would
 * pass it, and every text after, is cut as any long string is, and the check reads a cut text as undecided. Every other
 * string is kept as without the option. A reader that wraps the projection must pass `wholeStringBytes` on, or every
 * text is cut as before.
 */
export interface AnswerProjectionOptions {
  readonly wholeText?: boolean;
}

/** The projection of one answer: a `StrictJsonScan` listener. */
export class AnswerProjection implements ScanListener {
  readonly protocol: Protocol;
  /** The top-level value as kept, once it began. */
  root: Json | undefined = undefined;
  /** The JSON text of what is kept, in bytes: strings and keys with their quotes (and colon), numbers, literals, brackets and commas. */
  bytes = 0;
  /** The key of the top-level member whose value has not completed yet, if any. */
  openTopKey: string | null = null;
  /** What the projection's nodes hold beyond their text (`PROJECTION_NODE_BYTES`), in bytes. */
  nodeBytes = 0;
  /**
   * The projection cut some of the answer's text (`textPath`): a text string past KEPT_STRING_UNITS bytes kept as its
   * prefix, without `wholeText` or once its bound was spent. What is left of the text is then no answer to judge
   * (@gray/trust `outputCheck`'s `textCut`). Every other string it cuts is no text.
   */
  textCut = false;
  private readonly frames: Frame[] = [];
  private readonly path: PathKey[] = [];
  private readonly observer: ProjectionObserver | null;
  /** The text bytes `wholeText` may still keep whole (`WHOLE_TEXT_BYTES`); 0 without the option, and once a text was cut. */
  private textLeft: number;

  constructor(protocol: Protocol, observer: ProjectionObserver | null = null, options: AnswerProjectionOptions = {}) {
    this.protocol = protocol;
    this.observer = observer;
    this.textLeft = options.wholeText === true ? WHOLE_TEXT_BYTES : 0;
  }

  private get top(): Frame | undefined {
    return this.frames[this.frames.length - 1];
  }

  /** The rule of the value about to start in the innermost container (or at the top), or null when it is not kept at all. */
  private ruleOfNext(): KeepRule | null {
    const frame = this.top;
    if (frame === undefined) return keepRule(this.protocol, this.path);
    if (frame.node === null || frame.rule === "empty") return null;
    if (frame.rule === "whole") return "whole";
    this.path.push(this.stepOf(frame));
    const rule = keepRule(this.protocol, this.path);
    this.path.pop();
    return rule;
  }

  private stepOf(frame: Frame): PathKey {
    return frame.array ? frame.index : (frame.key as string);
  }

  /** The value about to start is the answer's text, which `wholeText` keeps whole while its bound lasts (`textPath`). */
  private textNext(): boolean {
    const frame = this.top;
    if (frame === undefined || frame.node === null || frame.rule !== "default") return false;
    this.path.push(this.stepOf(frame));
    const text = textPath(this.protocol, this.path);
    this.path.pop();
    return text;
  }

  /** Puts a completed value into the innermost container; true when it is kept. */
  private insert(value: Json, bytes: number): boolean {
    const frame = this.top;
    if (frame === undefined) {
      this.root = value;
      this.bytes += bytes;
      return true;
    }
    if (frame.node === null || frame.rule === "empty") return false;
    if (frame.array) {
      (frame.node as JsonArray).push(value);
      if (frame.count > 0) this.bytes += 1;
      this.nodeBytes += PROJECTION_NODE_BYTES.item;
    } else {
      this.nodeBytes += PROJECTION_NODE_BYTES.member;
      const key = frame.key as string;
      if (key === "__proto__") setMember(frame.node as JsonObject, key, value);
      else (frame.node as JsonObject)[key] = value;
    }
    this.bytes += bytes;
    return true;
  }

  /** A value of the innermost container completed. */
  private completed(): void {
    const frame = this.top;
    if (frame === undefined) return;
    if (frame.array) {
      frame.count += 1;
      frame.index += 1;
    } else {
      frame.key = undefined;
    }
    if (this.frames.length === 1) this.openTopKey = null;
  }

  /** A string, number or literal; true when it is kept. */
  private scalar(value: Json, bytes: number, offset: number): boolean {
    const frame = this.top;
    const kept = this.insert(value, bytes);
    if (kept && this.observer !== null) {
      if (frame === undefined) this.observer.value(this.path, value, offset);
      else {
        this.path.push(this.stepOf(frame));
        this.observer.value(this.path, value, offset);
        this.path.pop();
      }
    }
    this.completed();
    return kept;
  }

  wholeString(): boolean {
    return this.ruleOfNext() === "whole";
  }

  /** What of the text about to start is kept whole (`AnswerProjectionOptions.wholeText`): what is left of the bound. */
  wholeStringBytes(): number {
    return this.textLeft > 0 && this.textNext() ? this.textLeft : 0;
  }

  stringRuns(offset: number): void {
    if (this.observer?.stringRuns === undefined) return;
    const frame = this.top;
    if (frame === undefined) {
      this.observer.stringRuns(this.path, offset);
      return;
    }
    if (frame.node === null || frame.rule === "empty") return;
    this.path.push(this.stepOf(frame));
    this.observer.stringRuns(this.path, offset);
    this.path.pop();
  }

  open(array: boolean, offset: number): void {
    const parent = this.top;
    const rule = this.ruleOfNext();
    if (parent !== undefined) this.path.push(this.stepOf(parent));
    if (rule === null) {
      this.frames.push({ node: null, array, rule: "empty", key: undefined, index: 0, count: 0 });
      return;
    }
    const node: JsonObject | JsonArray = array ? [] : {};
    this.insert(node, 2);
    this.nodeBytes += array ? PROJECTION_NODE_BYTES.array : PROJECTION_NODE_BYTES.object;
    this.frames.push({ node, array, rule, key: undefined, index: 0, count: 0 });
    this.observer?.open(this.path, array, offset);
  }

  close(offset: number): void {
    const frame = this.frames.pop();
    if (frame === undefined) return;
    if (frame.node !== null) this.observer?.close(this.path, frame.node, offset);
    if (this.frames.length > 0) this.path.pop();
    this.completed();
  }

  key(key: string, bytes: number, offset: number): void {
    const frame = this.top;
    if (frame === undefined) return;
    frame.key = key;
    if (frame.node === null || frame.rule === "empty") return;
    this.bytes += bytes + 3 + (frame.count > 0 ? 1 : 0);
    frame.count += 1;
    if (this.frames.length === 1) this.openTopKey = key;
    this.observer?.key(this.path, key, offset);
  }

  string(value: ScanString, offset: number): void {
    const rule = this.ruleOfNext();
    if (rule === null) {
      this.completed();
      return;
    }
    let kept: string;
    if (this.textLeft > 0 && rule === "default" && this.textNext()) {
      // The answer's text: whole as the scan kept it, within what is left of the bound; one that passed it is cut,
      // and nothing more is kept whole.
      kept = value.whole ? value.text : keptString(value);
      this.textLeft = value.whole || value.bytes <= KEPT_STRING_UNITS ? Math.max(0, this.textLeft - value.bytes) : 0;
    } else {
      kept = rule === "whole" && value.whole ? value.text : keptString(value);
    }
    // Only a string past what the default rule keeps can have been cut; whether it is the answer's text is asked then.
    if (!this.textCut && !value.whole && value.bytes > KEPT_STRING_UNITS && rule === "default" && this.textNext()) this.textCut = true;
    this.nodeBytes += PROJECTION_NODE_BYTES.string;
    this.scalar(kept, (kept === value.text ? value.bytes : utf8Length(kept)) + 2, offset);
  }

  number(source: string, value: bigint | number, offset: number): void {
    if (this.scalar(value, source.length, offset)) this.nodeBytes += PROJECTION_NODE_BYTES.number;
  }

  literal(value: boolean | null, offset: number): void {
    this.scalar(value, value === false ? 5 : 4, offset);
  }
}
