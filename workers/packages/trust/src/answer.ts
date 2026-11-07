/**
 * What the tool gate holds back of a non-streaming answer while the gateway passes it on (enforce
 * mode only; docs/cloudflare-native/gateway.md section 8). The gateway reads the answer as it
 * arrives (@gray/protocol `StrictJsonScan` and `AnswerProjection`) and lets a byte go only once no
 * part of the answer that could refuse it is still open; the answer's closing `}` goes last, after
 * the whole-answer checks and the charge, so a client never has a document it can parse before the
 * answer was judged.
 *
 * The parts are the entries `responseCalls` (src/shapes.ts) reads calls from, with the same tables:
 * Chat's `choices[*].message.tool_calls[*]`, its `function_call` and the parts of an array
 * `content`; Responses' `output[*]` and the content parts of a message item; Anthropic's
 * `content[*]`; Gemini's `candidates[*].content.parts[*]`.
 *
 * - An entry is held from its first byte until its type (Gemini: its first variant key) says what it
 *   is. Text-like (TEXT_PARTS, a Responses message, reasoning or compaction item, an Anthropic
 *   `fallback` block, a Gemini text, data or function response part) goes out at once; an
 *   executable key or a second variant that follows in it is held from that key on.
 * - A call (a `tool_calls` item, a Responses `function_call`, a `tool_use` block, a `functionCall`
 *   part) is held until it closes, then checked with its own branch of `responseCalls` and
 *   `inspectCall` (the request's tools were checked once, as `streamToolInspector` does). Passed, it
 *   goes out; refused, the answer is refused and nothing after it goes out.
 * - Anything else at those places (an opaque or unknown entry, a value of the wrong kind) is held
 *   until the end, where `inspectResponse` refuses it. A string there is held from its opening quote
 *   while it is still being read (`stringRuns`): the gateway would otherwise pass a string value's
 *   bytes on as they come.
 *
 * Holding is about when bytes may go, never about the verdict: the gateway still runs
 * `inspectResponse` on the projection at the end, and only that verdict lets the held bytes and the
 * closing `}` go. A refusal here is one `inspectResponse` gives too: the entry is one it checks, with
 * the same code path (test/answer-check.test.ts compares them on every answer of the trust fixtures).
 * A non-streaming client can act only on a whole document, so passing a checked call on before
 * later entries are known is safe; a stream holds from its first call to its end instead, because an
 * SSE client acts on each event.
 */
import { type Json, asStr } from "@gray/json";
import type { PathKey, ProjectionObserver, Protocol } from "@gray/protocol";
import { withCompileAllowance } from "./engine.ts";
import { MAX_TOOLS } from "./limits.ts";
import { type GateRequest, ToolSchemas, type TrustPolicy } from "./policy.ts";
import { type Call, EXECUTABLE_KEYS, GEMINI_ACCOMPANYING, GEMINI_REFUSED, GEMINI_VARIANTS, TEXT_PARTS, chatToolCall, contentCalls, responseItemCalls } from "./shapes.ts";
import { type TrustViolation, attempt, refuse } from "./violations.ts";

/** What an entry is known to be so far. */
type Kind = "pending" | "text" | "call" | "late" | "opaque" | "done";

interface Entry {
  readonly start: number;
  kind: Kind;
  /** An executable key came before the type. */
  exec: boolean;
  /** Gemini: the part's variant key. */
  variant?: string;
  /** Responses: the item's content began before its type. */
  content?: boolean;
}

const isIndex = (step: PathKey | undefined): boolean => typeof step === "number";

/** `path` is `pattern`, where `#` is any index. */
function at(path: readonly PathKey[], ...pattern: readonly (string | "#")[]): boolean {
  if (path.length !== pattern.length) return false;
  for (let i = 0; i < pattern.length; i++) {
    const want = pattern[i];
    if (want === "#" ? !isIndex(path[i]) : path[i] !== want) return false;
  }
  return true;
}

const keyOf = (path: readonly PathKey[], length = path.length): string => path.slice(0, length).join("/");

export class AnswerCallCheck implements ProjectionObserver {
  private readonly policy: TrustPolicy;
  private readonly gate: GateRequest;
  private readonly protocol: Protocol;
  private readonly argumentLimit: number;
  private readonly schemas = new ToolSchemas();
  private readonly entries = new Map<string, Entry>();
  /** Holds an entry's classification or check will release, by their start. */
  private readonly pending = new Set<number>();
  /** The earliest byte held to the end. */
  private sticky = Number.POSITIVE_INFINITY;
  private calls = 0;
  /** The refusal of an entry's check, or of the request's tools; nothing goes out once set. */
  refused: TrustViolation | undefined;

  constructor(policy: TrustPolicy, gate: GateRequest, protocol: Protocol, argumentLimit: number) {
    this.policy = policy;
    this.gate = gate;
    this.protocol = protocol;
    this.argumentLimit = argumentLimit;
    this.refused = withCompileAllowance(this.schemas.allowance, () =>
      attempt(() => {
        if (gate.request.protocol !== protocol) refuse("trust_protocol_mismatch");
        policy.checkTools(gate, { admitted: true });
      }),
    );
  }

  /** The first byte that may not go out yet (+Infinity when none is held). After a refusal nothing more goes. */
  heldFrom(): number {
    let first = this.sticky;
    for (const start of this.pending) if (start < first) first = start;
    return first;
  }

  // ------------------------------------------------------------------ holds

  private hold(start: number): void {
    this.pending.add(start);
  }

  private holdToEnd(start: number): void {
    if (start < this.sticky) this.sticky = start;
  }

  private entry(path: readonly PathKey[], start: number): Entry {
    const entry: Entry = { start, kind: "pending", exec: false };
    this.entries.set(keyOf(path), entry);
    this.hold(start);
    return entry;
  }

  private release(entry: Entry, kind: Kind): void {
    entry.kind = kind;
    this.pending.delete(entry.start);
  }

  /** The entry stays held to the end. */
  private opaque(entry: Entry): void {
    entry.kind = "opaque";
    this.pending.delete(entry.start);
    this.holdToEnd(entry.start);
  }

  /** A text-like type: out at once, unless an executable key came first. */
  private classifyText(entry: Entry): void {
    if (entry.kind !== "pending") return;
    if (entry.exec) this.opaque(entry);
    else this.release(entry, "text");
  }

  /** An executable key in a text-like entry: held from the key on (the end refuses it). */
  private executableKey(entry: Entry | undefined, key: string, offset: number): void {
    if (entry === undefined || !EXECUTABLE_KEYS.includes(key)) return;
    if (entry.kind === "pending") entry.exec = true;
    else if (entry.kind === "text") this.holdToEnd(offset);
  }

  /** A call entry closed: its own branch of `responseCalls`, then `inspectCall` for each call it states. */
  private check(entry: Entry, read: (calls: Call[]) => void): void {
    if (this.refused !== undefined) return;
    const violation = withCompileAllowance(this.schemas.allowance, () =>
      attempt(() => {
        const calls: Call[] = [];
        read(calls);
        this.calls += calls.length;
        if (this.calls > MAX_TOOLS) refuse("trust_payload_limit");
        for (const [name, args] of calls) this.policy.inspectCall(this.gate, this.schemas, name, args, [], this.argumentLimit);
      }),
    );
    if (violation !== undefined) {
      this.refused = violation;
      return;
    }
    this.release(entry, "done");
  }

  private find(path: readonly PathKey[], length: number): Entry | undefined {
    return this.entries.get(keyOf(path, length));
  }

  // ------------------------------------------------------------------ the projection's tokens

  open(path: readonly PathKey[], array: boolean, offset: number): void {
    switch (this.protocol) {
      case "open_ai_chat":
        if (at(path, "choices")) {
          if (!array) this.holdToEnd(offset);
        } else if (at(path, "choices", "#")) {
          // A choice is no entry: what precedes its message (its index, its log probabilities, which
          // a relay that sorts keys writes first) carries no call. A choice that is no object is.
          if (array) this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message")) {
          if (array) this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message", "function_call")) {
          const call = this.find(path, 4);
          if (call !== undefined) this.opaque(call);
        } else if (at(path, "choices", "#", "message", "content") || at(path, "choices", "#", "message", "tool_calls")) {
          if (!array) this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message", "content", "#")) {
          if (array) this.holdToEnd(offset);
          else this.entry(path, offset);
        } else if (at(path, "choices", "#", "message", "tool_calls", "#")) {
          this.entry(path, offset).kind = "call";
        } else if (at(path, "choices", "#", "message", "content", "#", "type")) {
          const part = this.find(path, 5);
          if (part !== undefined && part.kind === "pending") this.opaque(part);
        }
        break;
      case "open_ai_responses":
        if (at(path, "output")) {
          if (!array) this.holdToEnd(offset);
        } else if (at(path, "output", "#")) {
          if (array) this.holdToEnd(offset);
          else this.entry(path, offset);
        } else if (at(path, "output", "#", "type")) {
          const item = this.find(path, 2);
          if (item !== undefined && item.kind === "pending") this.opaque(item);
        } else if (at(path, "output", "#", "content")) {
          const item = this.find(path, 2);
          if (item?.kind === "pending") item.content = true;
          else if (item?.kind === "text" && !array) this.holdToEnd(offset);
        } else if (at(path, "output", "#", "content", "#")) {
          if (this.find(path, 2)?.kind !== "text") break;
          if (array) this.holdToEnd(offset);
          else this.entry(path, offset);
        } else if (at(path, "output", "#", "content", "#", "type")) {
          const part = this.find(path, 4);
          if (part !== undefined && part.kind === "pending") this.opaque(part);
        }
        break;
      case "anthropic_messages":
        if (at(path, "content")) {
          if (!array) this.holdToEnd(offset);
        } else if (at(path, "content", "#")) {
          if (array) this.holdToEnd(offset);
          else this.entry(path, offset);
        } else if (at(path, "content", "#", "type")) {
          const part = this.find(path, 2);
          if (part !== undefined && part.kind === "pending") this.opaque(part);
        }
        break;
      case "gemini":
        if (at(path, "candidates") || at(path, "candidates", "#", "content", "parts")) {
          if (!array) this.holdToEnd(offset);
        } else if (at(path, "candidates", "#", "content", "parts", "#")) {
          if (array) this.holdToEnd(offset);
          else this.entry(path, offset);
        }
        break;
      default:
        break;
    }
  }

  key(path: readonly PathKey[], key: string, offset: number): void {
    switch (this.protocol) {
      case "open_ai_chat":
        if (at(path, "choices", "#", "message")) {
          // Held from the key until its value says whether a function call is present.
          if (key === "function_call") this.entry([...path, key], offset);
        } else if (at(path, "choices", "#", "message", "content", "#")) {
          this.executableKey(this.find(path, 5), key, offset);
        }
        break;
      case "open_ai_responses":
        if (at(path, "output", "#", "content", "#")) this.executableKey(this.find(path, 4), key, offset);
        break;
      case "anthropic_messages":
        if (at(path, "content", "#")) this.executableKey(this.find(path, 2), key, offset);
        break;
      case "gemini":
        if (at(path, "candidates", "#", "content", "parts", "#")) this.geminiKey(this.find(path, 5), key, offset);
        break;
      default:
        break;
    }
  }

  /** `content_calls` for one Gemini part, as its keys arrive. */
  private geminiKey(part: Entry | undefined, key: string, offset: number): void {
    if (part === undefined || part.kind === "opaque" || part.kind === "call") return;
    if (GEMINI_ACCOMPANYING.includes(key)) return;
    if (GEMINI_VARIANTS.includes(key) && part.variant === undefined) {
      part.variant = key;
      if (key === "functionCall") part.kind = "call";
      else if (GEMINI_REFUSED.includes(key)) this.opaque(part);
      else this.release(part, "text");
      return;
    }
    // A second variant, or a key no variant has: refused at the end.
    if (part.kind === "pending") this.opaque(part);
    else this.holdToEnd(offset);
  }

  /**
   * A string value at `path` is held to the end (`value` holds it once it completes): a value of the
   * wrong kind where an entry or a list of entries goes. Strings at an entry's own keys are behind
   * the entry's hold already.
   */
  private heldString(path: readonly PathKey[]): boolean {
    switch (this.protocol) {
      case "open_ai_chat":
        return (
          at(path, "choices") ||
          at(path, "choices", "#") ||
          at(path, "choices", "#", "message") ||
          at(path, "choices", "#", "message", "content", "#") ||
          at(path, "choices", "#", "message", "tool_calls") ||
          at(path, "choices", "#", "message", "tool_calls", "#")
        );
      case "open_ai_responses":
        if (at(path, "output") || at(path, "output", "#")) return true;
        return (at(path, "output", "#", "content") || at(path, "output", "#", "content", "#")) && this.find(path, 2)?.kind === "text";
      case "anthropic_messages":
        return at(path, "content") || at(path, "content", "#");
      case "gemini":
        return at(path, "candidates") || at(path, "candidates", "#", "content", "parts") || at(path, "candidates", "#", "content", "parts", "#");
      default:
        return false;
    }
  }

  stringRuns(path: readonly PathKey[], offset: number): void {
    if (this.heldString(path)) this.holdToEnd(offset);
  }

  value(path: readonly PathKey[], value: Json, offset: number): void {
    if (typeof value === "string" && this.heldString(path)) {
      this.holdToEnd(offset);
      return;
    }
    switch (this.protocol) {
      case "open_ai_chat":
        if (at(path, "choices") || at(path, "choices", "#") || at(path, "choices", "#", "message") || at(path, "choices", "#", "message", "content", "#")) {
          this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message", "function_call")) {
          const call = this.find(path, 4);
          if (call === undefined) break;
          if (value === null) this.release(call, "done");
          else this.opaque(call);
        } else if (at(path, "choices", "#", "message", "content")) {
          if (value !== null && typeof value !== "string") this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message", "tool_calls")) {
          if (value !== null) this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message", "tool_calls", "#")) {
          this.holdToEnd(offset);
        } else if (at(path, "choices", "#", "message", "content", "#", "type")) {
          const part = this.find(path, 5);
          if (part === undefined || part.kind !== "pending") break;
          if (typeof value === "string" && TEXT_PARTS.includes(value)) this.classifyText(part);
          else this.opaque(part);
        }
        break;
      case "open_ai_responses":
        if (at(path, "output") || at(path, "output", "#")) {
          this.holdToEnd(offset);
        } else if (at(path, "output", "#", "type")) {
          const item = this.find(path, 2);
          if (item === undefined || item.kind !== "pending") break;
          if (value === "function_call") item.kind = "call";
          // A message whose content came first is checked whole when it closes.
          else if (value === "message") {
            if (item.content === true) item.kind = "late";
            else this.release(item, "text");
          }
          else if (value === "reasoning" || value === "compaction") this.release(item, "done");
          else this.opaque(item);
        } else if (at(path, "output", "#", "content")) {
          const item = this.find(path, 2);
          if (item?.kind === "pending") item.content = true;
          else if (item?.kind === "text" && value !== null) this.holdToEnd(offset);
        } else if (at(path, "output", "#", "content", "#")) {
          if (this.find(path, 2)?.kind === "text") this.holdToEnd(offset);
        } else if (at(path, "output", "#", "content", "#", "type")) {
          const part = this.find(path, 4);
          if (part === undefined || part.kind !== "pending") break;
          if (typeof value === "string" && TEXT_PARTS.includes(value)) this.classifyText(part);
          else this.opaque(part);
        }
        break;
      case "anthropic_messages":
        if (at(path, "content")) {
          if (value !== null) this.holdToEnd(offset);
        } else if (at(path, "content", "#")) {
          this.holdToEnd(offset);
        } else if (at(path, "content", "#", "type")) {
          const part = this.find(path, 2);
          if (part === undefined || part.kind !== "pending") break;
          const type = asStr(value);
          if (type === "tool_use") part.kind = "call";
          else if (type !== undefined && (type === "fallback" || TEXT_PARTS.includes(type))) this.classifyText(part);
          // Hosted-tool blocks (ANTHROPIC_HOSTED) and every unknown type.
          else this.opaque(part);
        }
        break;
      case "gemini":
        if (at(path, "candidates") || at(path, "candidates", "#", "content", "parts", "#")) {
          this.holdToEnd(offset);
        } else if (at(path, "candidates", "#", "content", "parts")) {
          if (value !== null) this.holdToEnd(offset);
        }
        break;
      default:
        break;
    }
  }

  close(path: readonly PathKey[], node: Json): void {
    this.closed(path, node);
    // A closed entry's state is not needed again (a hold it leaves stays in `pending` or `sticky`).
    this.entries.delete(keyOf(path));
  }

  private closed(path: readonly PathKey[], node: Json): void {
    switch (this.protocol) {
      case "open_ai_chat":
        if (at(path, "choices", "#", "message", "tool_calls", "#")) {
          const call = this.find(path, 5);
          if (call !== undefined) this.check(call, (calls) => chatToolCall(node, calls));
        }
        break;
      case "open_ai_responses":
        if (at(path, "output", "#")) {
          const item = this.find(path, 2);
          if (item !== undefined && (item.kind === "call" || item.kind === "late")) this.check(item, (calls) => responseItemCalls(node, calls));
        }
        break;
      case "anthropic_messages":
        if (at(path, "content", "#")) {
          const part = this.find(path, 2);
          if (part?.kind === "call") this.check(part, (calls) => contentCalls(this.protocol, [node], calls));
        }
        break;
      case "gemini":
        if (at(path, "candidates", "#", "content", "parts", "#")) {
          // A call, or a part of accompanying keys only (which no rule refuses).
          const part = this.find(path, 5);
          if (part !== undefined && (part.kind === "call" || part.kind === "pending")) this.check(part, (calls) => contentCalls(this.protocol, [node], calls));
        }
        break;
      default:
        break;
    }
  }
}
