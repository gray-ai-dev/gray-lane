/**
 * The tool-call id sites of a non-streaming answer read as it arrives (the gateway passes such an
 * answer on without holding it, docs/cloudflare-native/gateway.md section 9): the sites
 * `responseSites` finds in a whole answer (crates/gray-protocol/src/tool_ids.rs `response_sites`),
 * each with the byte offset of its string's opening quote, heard from the answer's projection
 * (@gray/protocol `ProjectionObserver`), so each id can be replaced by its handle in the answer's
 * bytes (docs/cloudflare-native/tool-call-ids.md section 3).
 *
 * What a site is may depend on a member that comes after the id: an Anthropic block's `type`, and
 * whether a Gemini part spells a field both ways (`gemini_key`). Such a candidate is held from its
 * opening quote (`heldFrom`) until its block or part says, so no byte of an id that may get a handle
 * goes out before it is decided. An id still arriving at a place a site can be (its string runs past
 * the end of a chunk, `stringRuns`) is held from its opening quote too, until it is whole: the scan
 * would let a string value's first bytes go out before its end, and an id whose first bytes went out
 * as they were could no longer get its handle. The answer's scan refuses repeated keys, so every
 * member is heard once.
 */
import type { Json } from "@gray/json";
import type { PathKey, ProjectionObserver, Protocol } from "@gray/protocol";
import type { Step } from "./ids.ts";

/** One id of the answer at a site: its path, and where its string token opens. */
export interface AnswerSite {
  readonly path: readonly Step[];
  readonly start: number;
}

const GEMINI_FIELDS: Readonly<Record<string, readonly [string, string]>> = {
  functionCall: ["functionCall", "function_call"],
  function_call: ["functionCall", "function_call"],
  functionResponse: ["functionResponse", "function_response"],
  function_response: ["functionResponse", "function_response"],
};

const isIndex = (step: PathKey | undefined): step is number => typeof step === "number";

interface Candidate {
  readonly path: Step[];
  readonly start: number;
  /** Anthropic: the member (`id`, `tool_use_id`); Gemini: the part's field (`functionCall`, ...). */
  readonly name: string;
}

interface Container {
  readonly candidates: Candidate[];
  /** Anthropic: the block's `type` when it is a string; undefined until heard. */
  type?: string | null;
  /** Gemini: the part's keys. */
  readonly keys: Set<string>;
}

/** The sites of one native non-streaming answer of `protocol`. */
export class AnswerSites implements ProjectionObserver {
  private readonly protocol: Protocol;
  /** Open Anthropic blocks and Gemini parts with candidates, by their path's text. */
  private readonly containers = new Map<string, Container>();
  private decided: AnswerSite[] = [];
  /** The opening quote of a string still arriving where a site can be (one string is read at a time), or null. */
  private running: number | null = null;

  constructor(protocol: Protocol) {
    this.protocol = protocol;
  }

  /** The sites decided since the last call, in the order they were decided (each once). */
  take(): AnswerSite[] {
    const out = this.decided;
    this.decided = [];
    return out;
  }

  /** The first byte held: the opening quote of a candidate not decided yet, or of an id still arriving (+Infinity when none). */
  heldFrom(): number {
    let first = this.running ?? Number.POSITIVE_INFINITY;
    for (const c of this.containers.values()) for (const candidate of c.candidates) if (candidate.start < first) first = candidate.start;
    return first;
  }

  /** A string value at `path` runs past the end of a chunk: held from its opening quote while it may be an id at a site. */
  stringRuns(path: readonly PathKey[], offset: number): void {
    if (this.mayBeSite(path)) this.running = offset;
  }

  /** Whether a string at `path` may be an id at a site of this protocol (its block's or part's members not known yet). */
  private mayBeSite(path: readonly PathKey[]): boolean {
    switch (this.protocol) {
      case "open_ai_chat":
        return path.length === 6 && path[0] === "choices" && isIndex(path[1]) && path[2] === "message" && path[3] === "tool_calls" && isIndex(path[4]) && path[5] === "id";
      case "open_ai_responses":
        return path.length === 3 && path[0] === "output" && isIndex(path[1]) && path[2] === "call_id";
      case "anthropic_messages":
        return path.length === 3 && path[0] === "content" && isIndex(path[1]) && (path[2] === "id" || path[2] === "tool_use_id");
      case "gemini":
        return path.length === 7 && path[6] === "id" && this.geminiPart(path.slice(0, 5)) && typeof path[5] === "string" && GEMINI_FIELDS[path[5]] !== undefined;
      default:
        return false;
    }
  }

  private containerOf(path: readonly PathKey[]): Container {
    const name = JSON.stringify(path);
    let found = this.containers.get(name);
    if (found === undefined) {
      found = { candidates: [], keys: new Set() };
      this.containers.set(name, found);
    }
    return found;
  }

  open(): void {}

  key(path: readonly PathKey[], key: string): void {
    if (this.protocol !== "gemini" || !this.geminiPart(path)) return;
    const name = JSON.stringify(path);
    // Keys are noted only for parts that may hold a candidate: a part is opened before its keys, so
    // every part's keys are kept until it closes (a few names each).
    let found = this.containers.get(name);
    if (found === undefined) {
      found = { candidates: [], keys: new Set() };
      this.containers.set(name, found);
    }
    found.keys.add(key);
  }

  value(path: readonly PathKey[], value: Json, offset: number): void {
    // The string that was still arriving is whole now: it is decided below, or held as a candidate.
    if (this.running === offset) this.running = null;
    switch (this.protocol) {
      case "open_ai_chat":
        // `choices.*.message.tool_calls.*.id`
        if (typeof value === "string" && path.length === 6 && path[0] === "choices" && isIndex(path[1]) && path[2] === "message" && path[3] === "tool_calls" && isIndex(path[4]) && path[5] === "id") this.decided.push({ path: [...path], start: offset });
        return;
      case "open_ai_responses":
        // `output.*.call_id`, whatever the item's type (a call's, or a call output's).
        if (typeof value === "string" && path.length === 3 && path[0] === "output" && isIndex(path[1]) && path[2] === "call_id") this.decided.push({ path: [...path], start: offset });
        return;
      case "anthropic_messages": {
        if (path.length !== 3 || path[0] !== "content" || !isIndex(path[1])) return;
        const member = path[2];
        if (member === "type") {
          const block = this.containerOf(path.slice(0, 2));
          block.type = typeof value === "string" ? value : null;
          this.settleBlock(block);
          return;
        }
        if ((member === "id" || member === "tool_use_id") && typeof value === "string") {
          const block = this.containerOf(path.slice(0, 2));
          block.candidates.push({ path: [...path], start: offset, name: member });
          if (block.type !== undefined) this.settleBlock(block);
        }
        return;
      }
      case "gemini": {
        // `candidates.*.content.parts.*.{functionCall,function_call,functionResponse,function_response}.id`
        if (typeof value !== "string" || path.length !== 7 || path[6] !== "id") return;
        const part = path.slice(0, 5);
        if (!this.geminiPart(part) || typeof path[5] !== "string" || GEMINI_FIELDS[path[5]] === undefined) return;
        this.containerOf(part).candidates.push({ path: [...path], start: offset, name: path[5] });
        return;
      }
      default:
        return;
    }
  }

  close(path: readonly PathKey[]): void {
    const name = JSON.stringify(path);
    const found = this.containers.get(name);
    if (found === undefined) return;
    this.containers.delete(name);
    if (this.protocol === "anthropic_messages") {
      // A block whose type never came as a string holds no site (`anthropic_block`).
      if (found.type === undefined) found.type = null;
      this.settleBlock(found);
      return;
    }
    // A Gemini part: a field spelled both ways is the upstream's choice unknown, no site (`gemini_key`).
    for (const c of found.candidates) {
      const [camel, snake] = GEMINI_FIELDS[c.name]!;
      if (!(found.keys.has(camel) && found.keys.has(snake))) this.decided.push({ path: c.path, start: c.start });
    }
    this.decided.sort((a, b) => a.start - b.start);
  }

  /** An Anthropic block whose type is known: `tool_use.id` and `tool_result.tool_use_id` are sites, every other candidate goes. */
  private settleBlock(block: Container): void {
    if (block.type === undefined) return;
    for (const c of block.candidates) {
      if ((block.type === "tool_use" && c.name === "id") || (block.type === "tool_result" && c.name === "tool_use_id")) this.decided.push({ path: c.path, start: c.start });
    }
    block.candidates.length = 0;
  }

  /** `candidates.<i>.content.parts.<j>`. */
  private geminiPart(path: readonly PathKey[]): boolean {
    return path.length === 5 && path[0] === "candidates" && isIndex(path[1]) && path[2] === "content" && path[3] === "parts" && isIndex(path[4]);
  }
}
