/**
 * The input bound a request is held for before it is sent (`PromptUnits`,
 * crates/gray-protocol/src/reservation.rs): the prompt's units (src/prompt.ts), a token per byte,
 * images by their documented formulas (src/images.ts), each `tool_reference` as the tool it loads;
 * the hash of every prefix of units, so a later turn of a conversation finds the prefix an earlier
 * one was billed for; and the request's shape.
 *
 * Why a token per byte: byte-level tokenizers emit at least one byte per token, so a text's bytes
 * bound its tokens. A unit is counted with its JSON (its place, its type and field names), more
 * than the text the upstream renders, which leaves room for template tokens. Counts are u64 and
 * saturate, as in Rust.
 */
import { sha256 } from "@noble/hashes/sha2";
import { type Json, asStr, get, isArray, isObject, sortedKeys } from "@gray/json";
import { type Protocol, isGeneration } from "./types.ts";
import { type Counting, NO_COUNTING, geminiImages, geminiImagesName, imageFamily, satAdd, scan } from "./images.ts";
import { anthropicCache, hashSetting, promptBlocks, settingLen, u64le, unitFields } from "./prompt.ts";

/**
 * Provider-side prompt text billed as input but absent from the body (rendered tool definitions,
 * chat-template tokens): every endpoint gets this allowance unless its provider declares more.
 */
export const RESERVED_PROMPT_OVERHEAD_TOKENS = 4096n;
/** The largest prompt allowance a provider may declare for an endpoint. */
export const MAX_PROMPT_OVERHEAD_TOKENS = 65536n;
/**
 * The largest output allowance a provider may declare for an endpoint (`output_overhead_tokens`):
 * output an upstream bills beyond a request's own limit, such as reasoning a relay does not bound
 * by it (grok-4.7 behind yylx billed 527 output tokens for a limit of 64, 2026-10-14).
 */
export const MAX_OUTPUT_OVERHEAD_TOKENS = 65536n;

const satSub = (a: bigint, b: bigint): bigint => (a > b ? a - b : 0n);

/** A request whose input its body does not carry (a continuation, a stored prompt, a cache). */
export class Unbounded extends Error {
  override readonly name = "Unbounded";
  constructor() {
    super("the request refers to input its body does not carry");
  }
}

/** `output_limit_field`: the request's output limit, which bills no input. */
function outputLimitField(protocol: Protocol, key: string): boolean {
  switch (protocol) {
    case "anthropic_messages":
      return key === "max_tokens";
    case "open_ai_chat":
      return key === "max_tokens" || key === "max_completion_tokens";
    case "open_ai_responses":
      return key === "max_output_tokens";
    default:
      return false;
  }
}

/** `refers_elsewhere`: whether `body` continues input it does not carry. */
function refersElsewhere(protocol: Protocol, body: Json): boolean {
  const stated = (key: string) => {
    const value = get(body, key);
    return value !== undefined && value !== null;
  };
  return (
    stated("previous_response_id") ||
    stated("conversation") ||
    (protocol === "open_ai_responses" && stated("prompt")) ||
    (protocol === "gemini" && (stated("cachedContent") || stated("cached_content")))
  );
}

/** A request body's prompt, unit by unit in prompt order: what each unit can cost at most. */
export class PromptUnits {
  /** Entry `k` hashes the first `k + 1` units. */
  private readonly prefixHashes: Uint8Array[];
  /** Entry `k`: the most tokens the units from `k` on can cost; the last entry is 0. */
  private readonly suffix: bigint[];
  /** The units from this one on all have a bound. */
  private readonly boundedFrom: number;
  private readonly expectedSuffix: bigint[];
  private readonly expectedBoundedFrom: number;
  private readonly geminiImageTokens: readonly ["gemini_3" | "gemini_2", bigint] | undefined;
  /** Anthropic: which prefixes a cache lookup reads (entry `k`: the first `k + 1` units). */
  private readonly cacheReads: boolean[] | undefined;
  /** Bytes of the top-level fields that are not units. */
  private readonly rest: bigint;
  private readonly shapeHash: Uint8Array;
  private readonly images: boolean;
  private readonly compaction: boolean;

  private constructor(fields: {
    prefixHashes: Uint8Array[];
    suffix: bigint[];
    boundedFrom: number;
    expectedSuffix: bigint[];
    expectedBoundedFrom: number;
    geminiImageTokens: readonly ["gemini_3" | "gemini_2", bigint] | undefined;
    cacheReads: boolean[] | undefined;
    rest: bigint;
    shapeHash: Uint8Array;
    images: boolean;
    compaction: boolean;
  }) {
    this.prefixHashes = fields.prefixHashes;
    this.suffix = fields.suffix;
    this.boundedFrom = fields.boundedFrom;
    this.expectedSuffix = fields.expectedSuffix;
    this.expectedBoundedFrom = fields.expectedBoundedFrom;
    this.geminiImageTokens = fields.geminiImageTokens;
    this.cacheReads = fields.cacheReads;
    this.rest = fields.rest;
    this.shapeHash = fields.shapeHash;
    this.images = fields.images;
    this.compaction = fields.compaction;
  }

  /** `PromptUnits::of`: the units of `body`, a request of `protocol` as it is sent upstream. */
  static of(protocol: Protocol, body: Json): PromptUnits {
    return PromptUnits.ofModel(protocol, body, undefined);
  }

  /**
   * `PromptUnits::of_model`: as `of`, for a request of `model` when its body does not name it (a
   * Gemini request names it in its path). Throws `Unbounded` for a request whose input its body
   * does not carry.
   */
  static ofModel(protocol: Protocol, body: Json, model: string | undefined): PromptUnits {
    if (!isObject(body) || !isGeneration(protocol)) throw new Unbounded();
    if (refersElsewhere(protocol, body)) throw new Unbounded();
    const named = asStr(get(body, "model"));
    const counting: Counting = {
      family: imageFamily(protocol, named),
      gemini: geminiImages(protocol, named ?? model, body),
    };
    const hasher = sha256.create();
    const prefixHashes: Uint8Array[] = [];
    const bounds: bigint[] = [];
    const expected: bigint[] = [];
    let boundedFrom = 0;
    let expectedBoundedFrom = 0;
    let geminiTokens: bigint | undefined = 0n;
    let images = false;
    // Anthropic tools by name, with what each costs: a `tool_reference` block expands into its
    // tool's whole definition (platform.claude.com, tool-search-tool, read 2026-10-15), billed
    // nowhere else; a name no tool has costs every tool's bound.
    const tools: Array<[string | undefined, bigint]> = [];
    const blocks = promptBlocks(protocol, body);
    const cacheReads =
      protocol === "anthropic_messages" ? (anthropicCache(blocks, body)?.reads ?? []) : undefined;
    blocks.forEach((block, index) => {
      const unit = block.digest();
      hasher.update(u64le(unit.len));
      hasher.update(unit.sha256);
      prefixHashes.push(hasher.clone().digest());
      // A tool definition holds no media; a `file_id` in its examples is data.
      const found = block.place === "tools" ? scan(null, NO_COUNTING) : block.media(counting);
      if (found.unbounded) boundedFrom = index + 1;
      if (found.expectedUnbounded) expectedBoundedFrom = index + 1;
      if (found.geminiUncounted) geminiTokens = undefined;
      if (geminiTokens !== undefined) geminiTokens = satAdd(geminiTokens, found.expectedTokens);
      images ||= found.image;
      let bound = satAdd(satSub(BigInt(unit.len), found.replaced), found.tokens);
      let expect = satAdd(satSub(bound, found.expectedReplaced), found.expectedTokens);
      if (protocol === "anthropic_messages") {
        if (block.place === "tools") {
          tools.push([asStr(get(block.value(), "name")), bound]);
        } else {
          for (const reference of found.references) {
            let named: bigint | undefined;
            for (const [name, toolBound] of tools) {
              if (reference !== undefined && name === reference && (named === undefined || toolBound > named)) named = toolBound;
            }
            const expansion = named ?? tools.reduce((sum, [, toolBound]) => satAdd(sum, toolBound), 0n);
            bound = satAdd(bound, expansion);
            expect = satAdd(expect, expansion);
          }
        }
      }
      bounds.push(bound);
      expected.push(expect);
    });
    const suffix = new Array<bigint>(bounds.length + 1).fill(0n);
    for (let i = bounds.length - 1; i >= 0; i -= 1) suffix[i] = satAdd(suffix[i + 1] as bigint, bounds[i] as bigint);
    const expectedSuffix = new Array<bigint>(expected.length + 1).fill(0n);
    for (let i = expected.length - 1; i >= 0; i -= 1) {
      expectedSuffix[i] = satAdd(expectedSuffix[i + 1] as bigint, expected[i] as bigint);
    }
    // The other top-level fields each count towards the body's bound, and all but the output limit
    // and the stream settings, which bill nothing, make the request's shape.
    const units = unitFields(protocol);
    const shape = sha256.create();
    let rest = 0n;
    for (const key of sortedKeys(body)) {
      if (units.includes(key)) continue;
      const value = body[key] as Json;
      // A setting that refers to a file carries input no earlier turn's bill stands for.
      if (scan(value, NO_COUNTING).unbounded) throw new Unbounded();
      rest = satAdd(rest, BigInt(settingLen(key, value)));
      if (outputLimitField(protocol, key) || key === "stream" || key === "stream_options") continue;
      // Gemini's output limit sits in its generation settings.
      const limit =
        protocol === "gemini" && (key === "generationConfig" || key === "generation_config")
          ? ["maxOutputTokens", "max_output_tokens"]
          : [];
      hashSetting(shape, key, value, limit);
    }
    shape.update(new Uint8Array([images ? 1 : 0]));
    const contextManagement = get(body, "context_management");
    const compaction =
      protocol === "open_ai_responses" &&
      isArray(contextManagement) &&
      contextManagement.some((entry) => asStr(get(entry, "type")) === "compaction");
    return new PromptUnits({
      prefixHashes,
      suffix,
      boundedFrom,
      expectedSuffix,
      expectedBoundedFrom,
      geminiImageTokens:
        counting.gemini !== undefined && geminiTokens !== undefined ? [geminiImagesName(counting.gemini), geminiTokens] : undefined,
      cacheReads,
      rest,
      shapeHash: shape.digest(),
      images,
      compaction,
    });
  }

  /** How many units the prompt has. */
  get length(): number {
    return this.prefixHashes.length;
  }

  /** The hash of each prefix of the prompt: entry `k` covers the first `k + 1` units. */
  prefixes(): readonly Uint8Array[] {
    return this.prefixHashes;
  }

  /**
   * The most input tokens the body can cost: every unit and every other top-level field, a token
   * per byte, images by their formulas, each `tool_reference` as its tool. Undefined when a unit
   * holds input its bytes do not bound. The provider's hidden prompt is not in it.
   */
  bodyBound(): bigint | undefined {
    return this.boundedFrom === 0 ? satAdd(this.suffix[0] as bigint, this.rest) : undefined;
  }

  /** The most input tokens the units after the first `units` can add to a prompt of those units. */
  boundAfter(units: number): bigint | undefined {
    return units >= this.boundedFrom ? (this.suffix[units] ?? 0n) : undefined;
  }

  /**
   * What the body is expected to cost (docs/holds-debt-mode.md 7.2): `bodyBound` with each Gemini
   * image counted at the tier the request asks for instead of the largest. Never a bound.
   */
  expectedBodyBound(): bigint | undefined {
    return this.expectedBoundedFrom === 0 ? satAdd(this.expectedSuffix[0] as bigint, this.rest) : undefined;
  }

  expectedBoundAfter(units: number): bigint | undefined {
    return units >= this.expectedBoundedFrom ? (this.expectedSuffix[units] ?? 0n) : undefined;
  }

  /**
   * Whether a cache lookup can read an entry written for the prefix of the first `units` units:
   * on Anthropic only within the lookback of a breakpoint; on the other APIs always.
   */
  readsPrefix(units: number): boolean {
    if (this.cacheReads === undefined) return units > 0;
    return units > 0 && (this.cacheReads[units - 1] ?? false);
  }

  /** The tokens Google documents for the prompt's Gemini images, with the generation counted for. */
  geminiImages(): readonly ["gemini_3" | "gemini_2", bigint] | undefined {
    return this.geminiImageTokens;
  }

  /** The body's size as its bound counts it, a unit without a bound by its bytes. */
  byteCount(): bigint {
    return satAdd(this.suffix[0] as bigint, this.rest);
  }

  /** The request asks for OpenAI's server-side compaction (`context_management` with `compaction`). */
  compacts(): boolean {
    return this.compaction;
  }

  /** The hash of everything in the request but its units, its output limit and stream settings. */
  shape(): Uint8Array {
    return this.shapeHash;
  }

  hasImages(): boolean {
    return this.images;
  }
}
