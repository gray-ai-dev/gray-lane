import { TokenType } from "@streamparser/json";
import type { Protocol } from "../types.ts";
import type { BodyLayout, LayoutListener } from "../upstream.ts";
import { Carrier } from "./carrier.ts";
import { mintedReasoningId } from "./response.ts";

/**
 * `scrub_native` (crates/gray-protocol/src/translate/mod.rs; `scrubNative` here) of a body the gateway does not parse
 * whole (a Responses body above BODY_PARSE_MAX_BYTES, which it sends from the client's bytes): the elements of the
 * body's `input` array that this layer made, read from the tokens of the body's layout scan (`LayoutListener`, the
 * same pass that finds its top-level members) as byte spans to take out, each with the separator that went with it,
 * so that what stays is the array's other elements as the client wrote them.
 *
 * An element is one this layer made as `scrubNative` judges it on serde_json's reading of it: an object whose `type`
 * is the string `reasoning` and whose `encrypted_content`, when a string, is a carrier (`Carrier.decode`); when it is
 * absent or no string (serde's `as_str` reads such a value as none), whose `id` is a string this layer mints
 * (`mintedReasoningId`). An object that gives a member more than once is read by its last one, as serde reads it;
 * a member nested deeper is no member of the element. Every string is read as the tokenizer decodes it, exactly
 * (`exactStrings`). Of a body that gives `input` more than once, the last one is the body's (`spans` of the layout
 * the scan made, `lastOfEach`); one that is not an array (a string `input`) has no element to take out.
 *
 * The spans of one array, from its maximal runs of elements to take out: a run with an element after it, from its
 * first element to that element's start (the run and the separators after it); a run at the end of the array after
 * an element that stays, from the separator before it to its last element's end; a whole array, from its first
 * element to its last one's end (`[` and `]` stay). Spans are apart and in the body's order.
 */

/**
 * What one span to take out holds at most: its record of two offsets, its slot in the scan's list and in the list of
 * the `input` member each span is of, and its slot in the list `spans` gives, which parse.ts holds with the scan until
 * the scan is dropped (then the record and that one slot, `ParsedRequest.scrubbed`). Measured on 2026-10-24 (Node
 * 24.22, x64, no pointer compression: Workers' V8 compresses pointers, so it holds less; test/measure/scrub-span-heap.ts,
 * one count per process, every scan in a frame of its own; log r30/blocks-fix/span-heap-3.log): the scan with its spans
 * 67.7 to 75.8 bytes a span from 30,000 to 262,144 spans, cold and warm, 74.2 warm and 80.5 cold at 16,384 (the fixed
 * cost of the code compiled in the window, amortized over fewer spans); the spans alone 49 to 52. 96 leaves room. The
 * limits that apply are BODY_PARSE_MAX_BYTES / 96: 10,922 spans at its minimum (1 MiB), 43,690 at its default (4 MiB).
 */
export const SCRUB_SPAN_HELD_BYTES = 96;

/** A span of a body's bytes to take out, `[start, end)`. */
export interface ScrubSpan {
  readonly start: number;
  readonly end: number;
}

/**
 * A body naming more elements to take out than the scan holds (`heldMax` bytes of their spans, SCRUB_SPAN_HELD_BYTES
 * each): Gray's limit, which the gateway answers as it answers a body whose members it cannot hold.
 */
export class ScrubSpansTooMany extends Error {
  override readonly name = "ScrubSpansTooMany";
  readonly limit: number;
  constructor(limit: number) {
    super(`the reasoning items to take out of the body take more than ${limit} bytes to hold`);
    this.limit = limit;
  }
}

/** What the scan knows of one member of the element object being read: absent, a string (of these words), or another value. */
type TypeSeen = "absent" | "reasoning" | "other";
type EncryptedSeen = "absent" | "carrier" | "string" | "other";

export class ScrubScan {
  private depth = 0;
  /** A top-level key comes next. */
  private expectKey = false;
  /** The top-level member being read: where its key starts, whether it is `input`, and whether its value is an array. */
  private member: { readonly at: number; readonly input: boolean; array: boolean } | null = null;
  /** The element of the `input` array being read: where it started, and whether it is an object; null between elements. */
  private element: { readonly start: number; readonly object: boolean } | null = null;
  /** The separator before the element being read, -1 before the first. */
  private comma = -1;
  // The element object's own members (depth 3), each read by its last occurrence, as serde reads it.
  private expectObjectKey = false;
  private key: string | null = null;
  private type: TypeSeen = "absent";
  private encrypted: EncryptedSeen = "absent";
  private minted = false;
  /** The run of elements to take out being read: its first element's start, the separator before it, its last element's end. */
  private run: { readonly start: number; readonly comma: number; end: number } | null = null;
  /** The spans found, in the body's order, each as `spans` gives it; and the `input` member each is of (its key's offset). */
  private readonly found: ScrubSpan[] = [];
  private readonly foundIn: number[] = [];
  private held = 0;
  private overflow = false;
  private readonly heldMax: number;

  private constructor(heldMax: number) {
    this.heldMax = heldMax;
  }

  /** The scan of a native `protocol` body, or null where nothing is taken out (`scrub_native` reads Responses bodies alone). */
  static of(protocol: Protocol, heldMax: number = Number.MAX_SAFE_INTEGER): ScrubScan | null {
    return protocol === "open_ai_responses" ? new ScrubScan(heldMax) : null;
  }

  /** The layout scan's listener (`LayoutListener`): every token it reads, in order. */
  readonly listen: LayoutListener = (token, value, offset) => {
    switch (token) {
      case TokenType.LEFT_BRACE:
      case TokenType.LEFT_BRACKET:
        if (this.depth === 0) this.expectKey = true;
        else if (this.depth === 1 && this.member !== null && this.member.input) this.member.array = token === TokenType.LEFT_BRACKET;
        else if (this.depth === 2 && this.inArray() && this.element === null) this.begin(offset, token === TokenType.LEFT_BRACE);
        else if (this.depth === 3 && this.inObject() && this.key !== null) this.assign(this.key, null);
        this.depth += 1;
        return;
      case TokenType.RIGHT_BRACE:
      case TokenType.RIGHT_BRACKET:
        this.depth -= 1;
        if (this.depth === 2 && this.inArray() && this.element !== null) this.end(offset + 1);
        else if (this.depth === 1 && this.member !== null && this.member.input && this.member.array) {
          this.close();
          this.member.array = false;
        }
        return;
      case TokenType.COMMA:
        if (this.depth === 1) {
          this.member = null;
          this.expectKey = true;
        } else if (this.depth === 2 && this.inArray()) {
          this.element = null;
          this.comma = offset;
        } else if (this.depth === 3 && this.inObject()) {
          this.expectObjectKey = true;
        }
        return;
      case TokenType.COLON:
        return;
      case TokenType.STRING:
        if (this.depth === 1 && this.expectKey) {
          this.member = { at: offset, input: value === "input", array: false };
          this.expectKey = false;
          this.element = null;
          this.comma = -1;
          this.run = null;
        } else if (this.depth === 2 && this.inArray() && this.element === null) {
          this.begin(offset, false);
        } else if (this.depth === 3 && this.inObject()) {
          if (this.expectObjectKey) {
            this.key = value as string;
            this.expectObjectKey = false;
          } else if (this.key !== null) {
            this.assign(this.key, value as string);
          }
        }
        return;
      default:
        // A number, true, false or null: an element of its own at the array's level, or a member's value.
        if (this.depth === 2 && this.inArray() && this.element === null) this.begin(offset, false);
        else if (this.depth === 3 && this.inObject() && this.key !== null) this.assign(this.key, null);
        return;
    }
  };

  /**
   * The spans to take out of the body's `input`: of the members of `layout` named so, the last one (serde's reading;
   * the gateway's layout keeps only that one, `lastOfEach`). Empty when none. Throws `ScrubSpansTooMany` past what the
   * scan holds.
   */
  spans(layout: BodyLayout): ScrubSpan[] {
    if (this.overflow) throw new ScrubSpansTooMany(this.heldMax);
    let kept: number | undefined;
    for (const m of layout.members) if (m.key === "input") kept = m.keyStart;
    return this.found.filter((_, i) => this.foundIn[i] === kept);
  }

  private inArray(): boolean {
    return this.member !== null && this.member.input && this.member.array;
  }

  private inObject(): boolean {
    return this.inArray() && this.element !== null && this.element.object;
  }

  /** An element of the array begins at `offset`: an object's members are read; any other element stays. */
  private begin(offset: number, object: boolean): void {
    this.element = { start: offset, object };
    if (!object) {
      this.kept(offset);
      return;
    }
    this.expectObjectKey = true;
    this.key = null;
    this.type = "absent";
    this.encrypted = "absent";
    this.minted = false;
  }

  /** The element member `key` reads `value` (a string), or a value that is no string (null). */
  private assign(key: string, value: string | null): void {
    this.key = null;
    switch (key) {
      case "type":
        this.type = value === "reasoning" ? "reasoning" : "other";
        return;
      case "encrypted_content":
        this.encrypted = value === null ? "other" : Carrier.decode(value) !== undefined ? "carrier" : "string";
        return;
      case "id":
        this.minted = value !== null && mintedReasoningId(value);
        return;
      default:
        return;
    }
  }

  /** The element being read ends at `end` (after its closing bracket). */
  private end(end: number): void {
    const element = this.element!;
    if (!element.object) return;
    // `scrub_native`'s `made_here`: a carrier when `encrypted_content` is a string, else an id this layer minted.
    const made = this.type === "reasoning" && (this.encrypted === "carrier" || ((this.encrypted === "absent" || this.encrypted === "other") && this.minted));
    if (!made) {
      this.kept(element.start);
      return;
    }
    if (this.run === null) this.run = { start: element.start, comma: this.comma, end };
    else this.run.end = end;
  }

  /** An element that stays begins at `start`: a run before it goes up to it. */
  private kept(start: number): void {
    const run = this.run;
    if (run === null) return;
    this.run = null;
    this.keep({ start: run.start, end: start });
  }

  /** The array ends: a run at its end goes from the separator before it, or is the whole array's elements. */
  private close(): void {
    const run = this.run;
    if (run === null) return;
    this.run = null;
    this.keep({ start: run.comma >= 0 ? run.comma : run.start, end: run.end });
  }

  private keep(span: ScrubSpan): void {
    if (this.overflow) return;
    this.held += SCRUB_SPAN_HELD_BYTES;
    if (this.held > this.heldMax) {
      this.overflow = true;
      return;
    }
    this.found.push(span);
    this.foundIn.push(this.member!.at);
  }
}

/** `bytes` with `spans` taken out (apart, in order): what a native body is sent as once scrubbed. */
export function withoutSpans(bytes: Uint8Array, spans: readonly ScrubSpan[]): Uint8Array {
  const length = spans.reduce((n, s) => n - (s.end - s.start), bytes.length);
  const out = new Uint8Array(length);
  let at = 0;
  let from = 0;
  for (const s of spans) {
    out.set(bytes.subarray(from, s.start), at);
    at += s.start - from;
    from = s.end;
  }
  out.set(bytes.subarray(from), at);
  return out;
}
