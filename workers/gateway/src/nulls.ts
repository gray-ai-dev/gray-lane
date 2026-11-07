import { KEPT_STRING_UNITS, type Protocol, type ScanListener, type ScanString } from "@gray/protocol";

/**
 * A null `usage.iterations` left out of a non-streaming Anthropic answer as it passes
 * (crates/gray-gateway/src/inference.rs `Admission::drop_nulls` with `Framing::Body`, fec0faa2):
 * clients that read the usage into a typed object refuse a null where they read a list. The answer
 * passes on as it arrives (answer.ts) and is never held whole, so the rule is applied to the one
 * object it touches: from the top-level `usage` key on, the answer's bytes are held until that
 * object has closed and the answer's `type` is known (`heldFrom`); then, when the answer is a
 * `message` (or `message_delta`) whose usage states `iterations` as null, the usage object's bytes
 * are written again without that member (@gray/protocol `editJson`: the member goes with its key and
 * one comma, every other byte as sent) and the rest of the answer goes on. The usage object is a few
 * hundred bytes; the projection, the checks and the charge read the upstream's bytes as they came.
 *
 * It hears the strict scan's tokens beside the projection (`TeeListener`).
 */
export class NullUsageWatch {
  private depth = 0;
  /** The key of the top-level member being read. */
  private topKey: string | null = null;
  /** The key of the `usage` member being read. */
  private usageKey: string | null = null;
  /** The top-level `type`, once read (null when it is not a short string). */
  private type: string | null | undefined;
  /** Where the top-level `usage` key starts: the bytes are held from here until a decision. */
  private holdAt = Number.POSITIVE_INFINITY;
  /** Where the usage object opens and closes. */
  private usageOpen = -1;
  private usageClose = -1;
  private iterationsNull = false;
  private decided = false;
  /** The range of the usage object to write again, once the rule applies; taken once by `take`. */
  private pending: { readonly start: number; readonly end: number } | null = null;

  /** The first byte held for the rule (+Infinity when none). */
  heldFrom(): number {
    return this.decided ? Number.POSITIVE_INFINITY : this.holdAt;
  }

  /** The usage object's range to write again without its null `iterations`, once, when the rule applies. */
  take(): { readonly start: number; readonly end: number } | null {
    const edit = this.pending;
    this.pending = null;
    return edit;
  }

  /** The text ended: a decision still waiting for the answer's `type` is that the rule does not apply. */
  end(): void {
    this.decided = true;
  }

  private decide(): void {
    if (this.decided || this.usageClose < 0) return;
    if (!this.iterationsNull) {
      this.decided = true;
      return;
    }
    if (this.type === undefined) return;
    this.decided = true;
    if (this.type === "message" || this.type === "message_delta") this.pending = { start: this.usageOpen, end: this.usageClose + 1 };
  }

  /**
   * The top-level `usage` is not an object (null, a list, a number, a string, a boolean): it has no
   * member to leave out, so the rule does not apply and nothing more is held (a relay that writes
   * `"usage": null` before the content does not hold the rest of the answer).
   */
  private usageNotObject(): void {
    if (this.usageOpen < 0) this.decided = true;
  }

  open(array: boolean, offset: number): void {
    this.depth += 1;
    if (this.depth === 2 && this.topKey === "usage") {
      if (array) this.usageNotObject();
      else if (this.usageOpen < 0) this.usageOpen = offset;
    }
  }

  close(offset: number): void {
    if (this.depth === 2 && this.topKey === "usage" && this.usageOpen >= 0 && this.usageClose < 0) {
      this.usageClose = offset;
      this.decide();
    }
    this.depth -= 1;
  }

  key(key: string, _bytes: number, offset: number): void {
    if (this.depth === 1) {
      this.topKey = key;
      if (key === "usage" && this.holdAt === Number.POSITIVE_INFINITY) this.holdAt = offset;
    } else if (this.depth === 2 && this.topKey === "usage") {
      this.usageKey = key;
    }
  }

  string(value: ScanString): void {
    if (this.depth === 1 && this.topKey === "type") {
      // A string not kept whole still holds its first KEPT_STRING_UNITS units: all of a short one.
      this.type = value.whole || value.bytes <= KEPT_STRING_UNITS ? value.text : null;
      this.decide();
    } else if (this.depth === 1 && this.topKey === "usage") {
      this.usageNotObject();
    }
  }

  literal(value: boolean | null): void {
    if (this.depth === 1 && this.topKey === "type") {
      this.type = null;
      this.decide();
    } else if (this.depth === 1 && this.topKey === "usage") {
      this.usageNotObject();
    } else if (this.depth === 2 && this.topKey === "usage" && this.usageKey === "iterations" && value === null) {
      this.iterationsNull = true;
    }
  }

  number(): void {
    if (this.depth === 1 && this.topKey === "type") {
      this.type = null;
      this.decide();
    } else if (this.depth === 1 && this.topKey === "usage") {
      this.usageNotObject();
    }
  }
}

/** One scan's tokens to the projection first, then to the null watch; the projection decides what is kept whole. */
export class TeeListener implements ScanListener {
  private readonly first: ScanListener;
  private readonly watch: NullUsageWatch;

  constructor(first: ScanListener, watch: NullUsageWatch) {
    this.first = first;
    this.watch = watch;
  }

  open(array: boolean, offset: number): void {
    this.first.open(array, offset);
    this.watch.open(array, offset);
  }

  close(offset: number): void {
    this.first.close(offset);
    this.watch.close(offset);
  }

  key(key: string, bytes: number, offset: number): void {
    this.first.key(key, bytes, offset);
    this.watch.key(key, bytes, offset);
  }

  string(value: ScanString, offset: number): void {
    this.first.string(value, offset);
    this.watch.string(value);
  }

  number(source: string, value: bigint | number, offset: number): void {
    this.first.number(source, value, offset);
    this.watch.number();
  }

  literal(value: boolean | null, offset: number): void {
    this.first.literal(value, offset);
    this.watch.literal(value);
  }

  wholeString(): boolean {
    return this.first.wholeString();
  }

  stringRuns(offset: number): void {
    this.first.stringRuns?.(offset);
  }
}

/** Whether answers of `protocol` can carry the member the watch leaves out. */
export function watchesNulls(protocol: Protocol): boolean {
  return protocol === "anthropic_messages";
}
