/**
 * The tool-call id sites of a request body with their byte offsets, read from the body's bytes as
 * they stream (tier C bodies are never held whole, tier B conversations are never parsed): the
 * same sites `requestSites` finds in a parsed body (crates/gray-protocol/src/tool_ids.rs
 * `request_sites`), so each attempt can put an original in place of a handle by its offsets while
 * every other byte goes as the client sent it (docs/cloudflare-native/tool-call-ids.md section 3).
 *
 * Only the member that holds the sites is read: Chat's and Anthropic's `messages`, Responses'
 * `input`, Gemini's `contents`. The lexing is @streamparser/json 0.0.26's Tokenizer (the gateway's
 * streaming JSON library, the one `locateMembersStream` reads tier C layouts with), its strings read
 * whole and exactly by @gray/protocol's `exactStrings`; a string's end is the tokenizer's own count
 * of its raw bytes (its `escapedCharsByteLength` and its builder's `byteLength`, the offset it
 * advances by once the token is handed over).
 *
 * What a site is depends on members that may come after the id (`role`, `type`): a candidate waits
 * in its element until the element closes. Where an object repeats a key, serde_json keeps the last
 * value while the bytes keep both: the scan reports every occurrence that holds an id, so every one
 * the upstream may read is rewritten; a discriminator (`role`, `type`) is the last one, as serde
 * reads it. Only ids `wanted` accepts are reported (the gateway asks for handles), so what the scan
 * keeps stays small whatever the body holds.
 */
import { type Protocol, exactStrings } from "@gray/protocol";
import { Tokenizer, TokenType } from "@streamparser/json";
import type { Role, Step } from "./ids.ts";

/** One id at a site, and where its string token is (from its opening quote to after its closing one). */
export interface ByteSite {
  readonly path: readonly Step[];
  readonly role: Role;
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

/**
 * A Responses call item's `id` members, to leave out for a route of another issuer than the call's:
 * the byte spans to remove (`[start, end)`, apart and in order), each member with the comma that
 * separated it, so that what stays is the item's other members as written. An object may give `id`
 * more than once (serde reads the last); every one goes.
 */
export interface ItemId {
  /** The call's `call_id` site (its `start`): the last one the item gives, the one serde reads. */
  readonly callStart: number;
  readonly spans: readonly { readonly start: number; readonly end: number }[];
}

/**
 * The spans that take the members at `removed` (indices, ascending) out of an object whose members
 * are `members`, keeping the others with the separators between them: the members before the first
 * kept one go up to its key, every later run of removed members from the end of the member before it.
 */
export function memberRemovals(members: readonly { readonly keyStart: number; readonly valueEnd: number }[], removed: readonly number[]): { start: number; end: number }[] {
  if (removed.length === 0) return [];
  const gone = new Set(removed);
  const kept = members.findIndex((_, i) => !gone.has(i));
  if (kept < 0) return [{ start: members[0]!.keyStart, end: members[members.length - 1]!.valueEnd }];
  const spans: { start: number; end: number }[] = [];
  if (kept > 0) spans.push({ start: members[0]!.keyStart, end: members[kept]!.keyStart });
  for (let i = kept + 1; i < members.length; i++) {
    if (!gone.has(i)) continue;
    let last = i;
    while (last + 1 < members.length && gone.has(last + 1)) last++;
    spans.push({ start: members[i - 1]!.valueEnd, end: members[last]!.valueEnd });
    i = last;
  }
  return spans;
}

export interface ScannedSites {
  readonly sites: ByteSite[];
  readonly items: ItemId[];
}

/** The member of a request of `protocol` that holds its tool-call ids, or null for a protocol without any. */
export function siteMember(protocol: Protocol): string | null {
  switch (protocol) {
    case "open_ai_chat":
    case "anthropic_messages":
      return "messages";
    case "open_ai_responses":
      return "input";
    case "gemini":
      return "contents";
    default:
      return null;
  }
}

/** What a container is to the scan. */
type Kind =
  | "list" // the member's array: messages, input items, contents
  | "element" // a message, an input item, a content
  | "calls" // Chat `tool_calls`
  | "call" // one Chat tool call
  | "blocks" // Anthropic `content`
  | "block" // one Anthropic block
  | "parts" // Gemini `parts`
  | "part" // one Gemini part
  | "function" // a Gemini functionCall / functionResponse object
  | "other";

interface Candidate {
  readonly path: Step[];
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

interface Frame {
  readonly kind: Kind;
  readonly array: boolean;
  /** The member key whose value comes next, or the index of the next item. */
  key: string | undefined;
  index: number;
  /** Where the current member's key starts (objects). */
  keyStart: number;
  /** Elements and blocks: the last `role` / `type` string. */
  role?: string | undefined;
  type?: string | undefined;
  /** Candidates waiting for the element's discriminator, by what they are. */
  pending?: { readonly name: string; readonly candidate: Candidate }[];
  /** Gemini parts: which spellings were present (any value), and Responses items: the members' spans. */
  present?: Set<string>;
  members?: { readonly key: string; readonly keyStart: number; valueEnd: number }[];
  /** A Gemini function object: the part member it is (`functionCall`, `function_call`, ...). */
  spelling?: string;
}

const GEMINI_CALL = ["functionCall", "function_call"] as const;
const GEMINI_RESPONSE = ["functionResponse", "function_response"] as const;

/** A tokenizer whose numbers are not parsed (as parse.ts's `LayoutTokenizer`) and whose strings are exact. */
class SiteTokenizer extends Tokenizer {
  constructor() {
    super({ stringBufferSize: 0, emitPartialTokens: false });
    exactStrings(this);
  }

  protected override parseNumber(): number {
    return 0;
  }

  /** The end of the string token just emitted at `offset`: its raw bytes, the opening and the closing quote. */
  stringEnd(offset: number): number {
    const self = this as unknown as { escapedCharsByteLength: number; bufferedString: { byteLength: number } };
    return offset + self.escapedCharsByteLength + self.bufferedString.byteLength + 2;
  }
}

/**
 * Scans the value of a request's site member (`siteMember`), fed in chunks; offsets are `base` plus
 * the position in what was fed. Throws what the tokenizer throws for text that is not JSON (the
 * caller has parsed or located the member, so this is a bug).
 */
export class SiteScanner {
  private readonly protocol: Protocol;
  private readonly wanted: (value: string) => boolean;
  private readonly base: number;
  private readonly tokenizer = new SiteTokenizer();
  private readonly stack: Frame[] = [];
  private readonly path: Step[];
  private readonly found: ByteSite[] = [];
  private readonly items: ItemId[] = [];
  private prev: TokenType | null = null;

  constructor(protocol: Protocol, member: string, base: number, wanted: (value: string) => boolean) {
    this.protocol = protocol;
    this.wanted = wanted;
    this.base = base;
    this.path = [member];
    this.tokenizer.onToken = ({ token, value, offset }) => this.token(token, value, offset);
    this.tokenizer.onError = (error) => {
      throw error;
    };
  }

  write(chunk: Uint8Array): void {
    if (chunk.length > 0) this.tokenizer.write(chunk);
  }

  /** The sites found, in document order. */
  end(): ScannedSites {
    this.tokenizer.end();
    this.found.sort((a, b) => a.start - b.start);
    return { sites: this.found, items: this.items };
  }

  private top(): Frame | undefined {
    return this.stack[this.stack.length - 1];
  }

  /** The next string in the innermost object is a key. */
  private keyNext(): boolean {
    const top = this.top();
    return top !== undefined && !top.array && (this.prev === TokenType.LEFT_BRACE || this.prev === TokenType.COMMA);
  }

  /** The kind of a container opening at the current place. */
  private kindOf(array: boolean): Kind {
    const parent = this.top();
    if (parent === undefined) return array ? "list" : "other";
    const key = parent.key;
    switch (parent.kind) {
      case "list":
        return array ? "other" : "element";
      case "element":
        if (!array) return "other";
        if (this.protocol === "open_ai_chat" && key === "tool_calls") return "calls";
        if (this.protocol === "anthropic_messages" && key === "content") return "blocks";
        if (this.protocol === "gemini" && key === "parts") return "parts";
        return "other";
      case "calls":
        return array ? "other" : "call";
      case "blocks":
        return array ? "other" : "block";
      case "parts":
        return array ? "other" : "part";
      case "part":
        if (!array && key !== undefined && ((GEMINI_CALL as readonly string[]).includes(key) || (GEMINI_RESPONSE as readonly string[]).includes(key))) return "function";
        return "other";
      default:
        return "other";
    }
  }

  private open(array: boolean, offset: number): void {
    const kind = this.kindOf(array);
    const parent = this.top();
    if (parent !== undefined) this.path.push(parent.array ? parent.index : (parent.key as string));
    const frame: Frame = { kind, array, key: undefined, index: 0, keyStart: offset };
    if (kind === "element" || kind === "block" || kind === "part") frame.pending = [];
    if (kind === "part") frame.present = new Set();
    if (kind === "element" && this.protocol === "open_ai_responses") frame.members = [];
    if (kind === "function") frame.spelling = parent?.key;
    this.stack.push(frame);
  }

  /** A value of the innermost container ended at `end` (exclusive). */
  private valueEnded(end: number): void {
    const frame = this.top();
    if (frame === undefined) return;
    if (frame.array) frame.index += 1;
    else {
      const last = frame.members?.[frame.members.length - 1];
      if (last !== undefined && last.valueEnd < 0) last.valueEnd = end;
      frame.key = undefined;
    }
  }

  private close(offset: number): void {
    const frame = this.stack.pop();
    if (frame === undefined) return;
    this.settle(frame);
    if (this.stack.length > 0) this.path.pop();
    this.valueEnded(offset + 1);
  }

  /** An element, block or part closed: its candidates are sites now that its discriminators are known. */
  private settle(frame: Frame): void {
    const pending = frame.pending;
    if (pending === undefined) return;
    const emit = (c: Candidate, role: Role) => this.found.push({ path: c.path, role, value: c.value, start: c.start, end: c.end });
    switch (frame.kind) {
      case "element":
        if (this.protocol === "open_ai_chat") {
          if (frame.role === "tool") for (const p of pending) if (p.name === "tool_call_id") emit(p.candidate, "result");
        } else if (this.protocol === "open_ai_responses") {
          const role: Role = frame.type !== undefined && frame.type.endsWith("_output") ? "result" : "call";
          let last: Candidate | null = null;
          for (const p of pending) {
            if (p.name !== "call_id") continue;
            emit(p.candidate, role);
            if (last === null || p.candidate.start > last.start) last = p.candidate;
          }
          // A call item's ids go together for another issuer's route, as one set of spans that keeps
          // the item JSON whatever the number and places of its `id` members.
          if (role === "call" && last !== null) {
            const members = frame.members!;
            const removed = members.flatMap((m, i) => (m.key === "id" ? [i] : []));
            if (removed.length > 0) this.items.push({ callStart: last.start, spans: memberRemovals(members, removed) });
          }
        }
        break;
      case "block":
        for (const p of pending) {
          if (frame.type === "tool_use" && p.name === "id") emit(p.candidate, "call");
          if (frame.type === "tool_result" && p.name === "tool_use_id") emit(p.candidate, "result");
        }
        break;
      case "part": {
        const present = frame.present!;
        // `gemini_key`: both spellings of a field present leave it out.
        const usable = (names: readonly string[]) => !(present.has(names[0]!) && present.has(names[1]!));
        for (const p of pending) {
          if ((GEMINI_CALL as readonly string[]).includes(p.name) && usable(GEMINI_CALL)) emit(p.candidate, "call");
          if ((GEMINI_RESPONSE as readonly string[]).includes(p.name) && usable(GEMINI_RESPONSE)) emit(p.candidate, "result");
        }
        break;
      }
      default:
        break;
    }
  }

  private string(value: string, offset: number): void {
    const frame = this.top();
    const end = this.base + this.tokenizer.stringEnd(offset);
    if (frame === undefined) return;
    if (frame.array) {
      this.valueEnded(end);
      return;
    }
    const key = frame.key;
    const candidate = (): Candidate => ({ path: [...this.path, key as string], value, start: this.base + offset, end });
    const want = this.wanted(value);
    switch (frame.kind) {
      case "element":
        if (key === "role") frame.role = value;
        if (key === "type") frame.type = value;
        if (this.protocol === "open_ai_chat" && key === "tool_call_id" && want) frame.pending!.push({ name: key, candidate: candidate() });
        if (this.protocol === "open_ai_responses" && key === "call_id" && want) frame.pending!.push({ name: key, candidate: candidate() });
        break;
      case "call":
        if (key === "id" && want) this.found.push({ ...candidate(), role: "call" });
        break;
      case "block":
        if (key === "type") frame.type = value;
        if ((key === "id" || key === "tool_use_id") && want) frame.pending!.push({ name: key, candidate: candidate() });
        break;
      case "function": {
        const part = this.stack[this.stack.length - 2];
        if (key === "id" && want && part?.kind === "part") part.pending!.push({ name: frame.spelling as string, candidate: candidate() });
        break;
      }
      default:
        break;
    }
    this.valueEnded(end);
  }

  private key(key: string, offset: number): void {
    const frame = this.top()!;
    frame.key = key;
    // serde_json keeps the last of equal keys: a discriminator given again counts only as its last
    // value, which a string sets (`string`) and anything else leaves unset.
    if (key === "role") frame.role = undefined;
    if (key === "type") frame.type = undefined;
    frame.keyStart = this.base + offset;
    frame.present?.add(key);
    frame.members?.push({ key, keyStart: this.base + offset, valueEnd: -1 });
  }

  private token(type: TokenType, value: unknown, offset: number): void {
    switch (type) {
      case TokenType.LEFT_BRACE:
      case TokenType.LEFT_BRACKET:
        this.open(type === TokenType.LEFT_BRACKET, offset);
        break;
      case TokenType.RIGHT_BRACE:
      case TokenType.RIGHT_BRACKET:
        this.close(this.base + offset);
        break;
      case TokenType.STRING:
        if (this.keyNext()) this.key(value as string, offset);
        else this.string(value as string, offset);
        break;
      case TokenType.NUMBER:
        this.valueEnded(this.base + offset + this.numberText().length);
        break;
      case TokenType.TRUE:
      case TokenType.NULL:
        this.valueEnded(this.base + offset + 4);
        break;
      case TokenType.FALSE:
        this.valueEnded(this.base + offset + 5);
        break;
      default:
        break;
    }
    this.prev = type;
  }

  /** A number token's source text, still in the tokenizer's number builder while its token is handed over (`emitNumber`). */
  private numberText(): string {
    const self = this.tokenizer as unknown as { bufferedNumber: { toString(): string } };
    return self.bufferedNumber.toString();
  }
}

/** Scans a member value held as bytes (tiers A and B): the sites of `bytes` at `base`. */
export function scanSites(protocol: Protocol, member: string, bytes: Uint8Array, base: number, wanted: (value: string) => boolean): ScannedSites {
  const scanner = new SiteScanner(protocol, member, base, wanted);
  scanner.write(bytes);
  return scanner.end();
}
