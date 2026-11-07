/**
 * The operator's translation policy (crates/gray-gateway/src/translation/mod.rs,
 * `TranslationPolicy`): which upstream protocols may serve a (model, client protocol) pair that
 * has no native route, in order of preference. Empty by default, so translation is off.
 *
 * `parse` accepts exactly the documents Rust's serde reads: `{"rules": [{model, client,
 * upstream}]}` with unknown fields refused, a struct also given as an array of its fields in
 * order and a protocol also given as `{"<name>": null}` (serde's sequence and map forms), and
 * then the policy's own rules. A document the JSON reader or the shape refuses fails with a
 * message of this module's wording (`rule: false`; Rust's carries serde_json's wording there); a
 * rule fails with Rust's exact message (`rule: true`).
 */
import { type Json, type JsonObject, compareUtf8, isArray, isObject, parseStrict, parseStrictBytes } from "@gray/json";
import { PROTOCOLS, type Protocol, utf8Length } from "@gray/protocol";

/** Why a policy document was refused. */
export class PolicyError extends Error {
  override readonly name = "PolicyError";
  /** One of the policy's own rules (Rust's exact text) rather than the JSON reader or the shape. */
  readonly rule: boolean;

  constructor(message: string, rule: boolean) {
    super(`translation policy: ${message}`);
    this.rule = rule;
  }
}

function shapeError(message: string): PolicyError {
  return new PolicyError(message, false);
}

/** A serde struct: an object with exactly these fields, or an array of them in order. */
function struct(value: Json, name: string, fields: readonly string[]): Json[] {
  if (isArray(value)) {
    if (value.length !== fields.length) throw shapeError(`invalid length ${value.length}, expected struct ${name} with ${fields.length} elements`);
    return value;
  }
  if (!isObject(value)) throw shapeError(`invalid type, expected struct ${name}`);
  for (const key of Object.keys(value)) {
    if (!fields.includes(key)) throw shapeError(`unknown field \`${key}\`, expected one of ${fields.map((f) => `\`${f}\``).join(", ")}`);
  }
  return fields.map((field) => {
    if (!Object.hasOwn(value, field)) throw shapeError(`missing field \`${field}\``);
    return value[field] as Json;
  });
}

function isProtocolName(value: unknown): value is Protocol {
  return typeof value === "string" && (PROTOCOLS as readonly string[]).includes(value);
}

/** A serde unit-variant enum: its name, or `{"<name>": null}`. */
function protocol(value: Json): Protocol {
  if (isProtocolName(value)) return value;
  if (isObject(value)) {
    const keys = Object.keys(value);
    if (keys.length === 1 && isProtocolName(keys[0]) && value[keys[0] as string] === null) return keys[0] as Protocol;
  }
  throw shapeError(`invalid protocol ${typeof value === "string" ? `\`${value}\`` : "value"}`);
}

function generation(p: Protocol): boolean {
  return p === "open_ai_chat" || p === "open_ai_responses" || p === "anthropic_messages" || p === "gemini";
}

/** Unicode general category Cc (`char::is_control`). */
function isControl(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
}

/**
 * A string as Rust's `{:?}` writes it, for the control characters a refused model can hold: the
 * named escapes, `\u{..}` for other control characters, everything else as it is. (Rust also
 * escapes the few non-control characters it deems unprintable; a model holding one of those is
 * valid unless it breaks another rule, and only then is its message written differently.)
 */
export function rustDebug(text: string): string {
  let out = '"';
  for (const c of text) {
    const code = c.codePointAt(0) as number;
    if (c === "\t") out += "\\t";
    else if (c === "\r") out += "\\r";
    else if (c === "\n") out += "\\n";
    else if (c === "\\") out += "\\\\";
    else if (c === '"') out += '\\"';
    else if (c === "\0") out += "\\0";
    else if (isControl(code)) out += `\\u{${code.toString(16)}}`;
    else out += c;
  }
  return `${out}"`;
}

interface Rule {
  readonly model: string;
  readonly client: Protocol;
  readonly upstream: readonly Protocol[];
}

function order(a: Rule, b: Rule): number {
  return compareUtf8(a.model, b.model) || PROTOCOLS.indexOf(a.client) - PROTOCOLS.indexOf(b.client);
}

export class TranslationPolicy {
  private readonly rules: ReadonlyMap<string, Rule>;

  private constructor(rules: ReadonlyMap<string, Rule>) {
    this.rules = rules;
  }

  /** No rules: translation is off. */
  static empty(): TranslationPolicy {
    return new TranslationPolicy(new Map());
  }

  /**
   * Parses a policy document (bytes, or its text). Every rule names one exact model, one client
   * protocol and a non-empty ordered list of other upstream protocols. Throws a PolicyError.
   */
  static parse(document: Uint8Array | string): TranslationPolicy {
    let value: Json;
    try {
      value = typeof document === "string" ? parseStrict(document) : parseStrictBytes(document);
    } catch (error) {
      throw shapeError(error instanceof Error ? error.message : "invalid JSON");
    }
    const [rulesValue] = struct(value, "PolicyFile", ["rules"]) as [Json];
    if (!isArray(rulesValue)) throw shapeError("invalid type, expected a sequence of rules");
    const parsed: Rule[] = rulesValue.map((item) => {
      const [model, client, upstream] = struct(item, "RuleFile", ["model", "client", "upstream"]) as [Json, Json, Json];
      if (typeof model !== "string") throw shapeError("invalid type, expected a string model");
      if (!isArray(upstream)) throw shapeError("invalid type, expected a sequence of upstream protocols");
      return { model, client: protocol(client), upstream: upstream.map(protocol) };
    });
    const rules = new Map<string, Rule>();
    for (const rule of parsed) {
      const { model, client, upstream } = rule;
      if (model === "" || utf8Length(model) > 256 || model.includes("*") || [...model].some((c) => isControl(c.codePointAt(0) as number))) {
        throw new PolicyError(`invalid model ${rustDebug(model)}`, true);
      }
      if (!generation(client) || upstream.length === 0 || !upstream.every(generation)) {
        throw new PolicyError(`${model}: client and upstream must be text generation protocols`, true);
      }
      if (new Set(upstream).size !== upstream.length || upstream.includes(client)) {
        throw new PolicyError(`${model}: upstream protocols must be distinct and differ from the client`, true);
      }
      const key = `${client}\u0000${model}`;
      if (rules.has(key)) throw new PolicyError(`duplicate rule for ${model}`, true);
      rules.set(key, rule);
    }
    return new TranslationPolicy(rules);
  }

  /** The policy as the document `parse` reads, rules ordered by model and client protocol. */
  document(): JsonObject {
    const rules = [...this.rules.values()].sort(order);
    return { rules: rules.map((r) => ({ model: r.model, client: r.client, upstream: [...r.upstream] })) };
  }

  /** The upstream protocols allowed for `model` requested in `client`, in order; undefined without a rule. */
  upstreams(model: string, client: Protocol): readonly Protocol[] | undefined {
    return this.rules.get(`${client}\u0000${model}`)?.upstream;
  }

  isEmpty(): boolean {
    return this.rules.size === 0;
  }

  /** The number of (model, client protocol) rules. */
  get size(): number {
    return this.rules.size;
  }
}
