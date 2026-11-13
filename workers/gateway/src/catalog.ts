import { thinkingSent } from "@gray/control/opencode-thinking";
import { rustTrim } from "@gray/errors";
import { compareUtf8 } from "@gray/json";
import type { CustomerRate } from "@gray/holds";
import { billingUnit, endpointPath, geminiModelValue as geminiModel, isGeneration, modality, PROTOCOLS, type Protocol } from "@gray/protocol";
import type { TranslationPolicy } from "@gray/translation";
import { servesGeminiImages, speaks } from "./gemini-images.ts";
import { pricedQuoteOf } from "./money.ts";
import { jaroWinkler } from "./similarity.ts";
import { type GatewaySnapshot, routeServes } from "./snapshot.ts";

/**
 * The model catalog the model API publishes (crates/gray-gateway/src/model_catalog.rs): which models a
 * key may call through which APIs, at what price, with what the routes proved and what the metadata
 * says, worked out from the key and route snapshot the gateway already holds (its routes, their
 * quotes and proofs, the translation policy and the model facts ConfigDO puts in it). A listing calls
 * nothing: no route, account or database is asked.
 *
 * A listed model has a live route with a customer price. A listing is not a promise that a later
 * request passes capacity, budget or capability checks.
 */

/** What Gray knows of a model besides its routes (@gray/snapshot `ModelFacts`); every field optional here. */
export interface Facts {
  readonly name?: string | null;
  readonly created?: number | null;
  readonly context_length?: number | null;
  readonly max_output_tokens?: number | null;
  readonly input_modalities?: readonly string[];
  readonly output_modalities?: readonly string[];
}

/** What the live routes of one listed model offer (model_catalog.rs `Listed`). */
export interface Listed {
  /** A route of the listing's protocol serves it natively (only meaningful for a protocol's listing). */
  native: boolean;
  /** The protocols its live, priced routes speak. */
  readonly protocols: Set<Protocol>;
  /** Each route's customer rate. */
  readonly rates: CustomerRate[];
  /** The largest output allowance one of its routes declared (`inference::output_overhead`). */
  outputOverhead: number;
  /** What the routes' probe reports proved (`catalog::capability_words`). */
  readonly capabilities: Set<string>;
  /** A route proved streaming. */
  streams: boolean;
  /** The best `agentTier` a single one of its routes reaches. */
  agentTier: number;
  /**
   * What a route's current report withdrew after confirming a failed check, which its next check, minutes later,
   * may give back (catalog.rs `recovering_capabilities`), as the snapshot's rebuild found it in force. Pooled like
   * `capabilities`; only configs a client keeps read it (the console's setup): listing, the model list and admission
   * read only what was proved.
   */
  readonly recovering: Set<string>;
  /**
   * A route of the listing's protocol (of any, for a listing of every protocol) that proved streaming and tools
   * served a request shaped like OpenCode's own agent turn, by its latest result of the coding-agent check or of
   * customers' requests of that shape, for the thinking OpenCode sends the model now (`servesOpencode`).
   */
  codingAgent: boolean;
}

/**
 * model_catalog.rs `serves_opencode`: whether a model's routes serve OpenCode's agent turn as OpenCode sends it
 * now: one of `passes`, the protocol of a route whose coding-agent result passed and the thinking that result's
 * request carried, has the thinking OpenCode asks the model `id` for on that protocol, `reasoning` being whether
 * the routes OpenCode is configured from proved reasoning (@gray/control `thinkingSent`). A pass with thinking
 * turned off, found while the routes had not proved reasoning, would otherwise make the model OpenCode's default
 * once they proved it, when OpenCode asks a Claude 5.5 model for adaptive thinking with its binding beta.
 */
export function servesOpencode(passes: readonly (readonly [Protocol, string])[], id: string, reasoning: boolean): boolean {
  return passes.some(([protocol, thinking]) => thinking === thinkingSent(protocol, id, reasoning));
}

/** `agent_tier`: 3 streaming, tools and reasoning; 2 streaming and tools; 1 streaming; else 0. */
export function agentTier(streaming: boolean, tools: boolean, reasoning: boolean): number {
  if (!streaming) return 0;
  if (!tools) return 1;
  return reasoning ? 3 : 2;
}

/** A `BTreeSet<Protocol>`'s order: the enum's (@gray/protocol `PROTOCOLS`). */
export function sortProtocols(protocols: Iterable<Protocol>): Protocol[] {
  return [...new Set(protocols)].sort((a, b) => PROTOCOLS.indexOf(a) - PROTOCOLS.indexOf(b));
}

/**
 * `listed_in`: the models a key of `scope` may call through `protocol` (through any API for null), by id
 * in byte order; every model when `scope` is null or empty. A model is listed under a protocol when one
 * of its live, priced routes speaks it, or, when no live route of that protocol exists for it at all, when
 * the translation policy serves it to that protocol's clients from a route's protocol, or (Gemini) its
 * image routes speak Gemini's API (`gemini_images::speaks`). A native route always wins on generation, its
 * failures included, so such a model is never listed as served otherwise.
 */
export function listedIn(snapshot: GatewaySnapshot, policy: TranslationPolicy, scope: readonly string[] | null, protocol: Protocol | null, nowMs: number, feeBps: number): Map<string, Listed> {
  const live = snapshot.routes.filter((r) => routeServes(r.expiresAt, nowMs));
  const routed = new Set(protocol === null ? [] : live.filter((r) => r.protocol === protocol).map((r) => r.model));
  const models = new Map<string, Listed>();
  // Each model's coding-agent passes (`servesOpencode`), read once the routes' proofs are pooled.
  const passes = new Map<string, [Protocol, string][]>();
  for (const r of live) {
    const model = r.model;
    // `customer_rate`: the route's approved quote with the platform fee, its unit price the `*` one.
    const priced = pricedQuoteOf(r.quote, feeBps, []);
    if (priced === undefined) continue;
    if (scope !== null && scope.length > 0 && !scope.includes(model)) continue;
    const native = protocol === null || r.protocol === protocol;
    const translated =
      protocol !== null &&
      !routed.has(model) &&
      ((policy.upstreams(model, protocol)?.includes(r.protocol) ?? false) || (protocol === "gemini" && r.protocol === "open_ai_image_generations" && speaks(r)));
    if (!native && !translated) continue;
    let entry = models.get(model);
    if (entry === undefined) {
      entry = { native: false, protocols: new Set(), rates: [], outputOverhead: 0, capabilities: new Set(), streams: false, agentTier: 0, recovering: new Set(), codingAgent: false };
      models.set(model, entry);
    }
    entry.native ||= native;
    entry.streams ||= r.capabilities.streaming;
    entry.agentTier = Math.max(entry.agentTier, agentTier(r.capabilities.streaming, r.capabilities.tools, r.capabilities.reasoning));
    entry.protocols.add(r.protocol);
    entry.rates.push(priced.rate);
    entry.outputOverhead = Math.max(entry.outputOverhead, r.outputOverheadTokens ?? 0);
    for (const word of r.proved ?? []) entry.capabilities.add(word);
    // As the rebuild found them (@gray/snapshot `routeRecovering`), until the next one: the server's catalog judges
    // them at each refresh, not at each read (catalog.rs `projection`, run by inference.rs `refresh_catalog`).
    for (const word of r.recovering ?? []) entry.recovering.add(word);
    // Each thinking's pass of a route that proved streaming and tools: OpenCode's default takes the one of the
    // thinking OpenCode sends the model now. The snapshot carries passes of the route's binding now only
    // (model_catalog.rs `proves_opencode`).
    if (native && r.capabilities.streaming && r.capabilities.tools) {
      for (const thinking of r.codingAgent ?? []) {
        const list = passes.get(model);
        if (list === undefined) passes.set(model, [[r.protocol, thinking]]);
        else list.push([r.protocol, thinking]);
      }
    }
  }
  for (const [model, entry] of models) entry.codingAgent = servesOpencode(passes.get(model) ?? [], model, entry.capabilities.has("reasoning"));
  return new Map([...models].sort(([a], [b]) => compareUtf8(a, b)));
}

const GENERATION: readonly Protocol[] = ["open_ai_chat", "open_ai_responses", "anthropic_messages", "gemini"];

/**
 * `reachable`: the APIs a client can call `model` through, given the protocols its routes speak: the
 * generation APIs among them, those the translation policy serves from one of them, and Gemini's for an
 * image model its image routes serve (`gemini_images::serves`); then its other APIs, in enum order.
 */
export function reachable(snapshot: GatewaySnapshot, policy: TranslationPolicy, model: string, served: ReadonlySet<Protocol>, nowMs: number): Protocol[] {
  const apis = GENERATION.filter(
    (p) =>
      served.has(p) ||
      (policy.upstreams(model, p)?.some((u) => served.has(u)) ?? false) ||
      (p === "gemini" && served.has("open_ai_image_generations") && servesGeminiImages(snapshot, model, nowMs)),
  );
  return [...apis, ...sortProtocols(served).filter((p) => !isGeneration(p))];
}

const TRILLION = 1_000_000_000_000n;

/** `per_token`: micro-USD per million as USD per token (OpenRouter's convention), an exact decimal string. */
export function perToken(microusdPerMillion: bigint): string {
  const whole = microusdPerMillion / TRILLION;
  const fraction = microusdPerMillion % TRILLION;
  if (fraction === 0n) return whole.toString();
  return `${whole}.${fraction.toString().padStart(12, "0").replace(/0+$/, "")}`;
}

/** The cheapest rate of each priced component across a model's routes (`Prices`). */
export interface Prices {
  readonly input?: bigint;
  readonly output?: bigint;
  readonly cacheRead?: bigint;
  readonly cacheWrite?: bigint;
  readonly imageInput?: bigint;
  readonly imageOutput?: bigint;
  readonly audioInput?: bigint;
  readonly audioOutput?: bigint;
  /** Price per billing unit, micro-USD per million units. */
  readonly unit?: bigint;
}

function least(values: readonly (bigint | undefined)[]): bigint | undefined {
  let out: bigint | undefined;
  for (const v of values) if (v !== undefined && (out === undefined || v < out)) out = v;
  return out;
}

/**
 * `Prices::of`: each component's cheapest rate among the routes billed by tokens (unset cache prices at
 * the input rate, `CustomerRate::rates`); the unit price's cheapest among every route.
 */
export function pricesOf(rates: readonly CustomerRate[]): Prices {
  const token = rates.filter((r) => r.media.unit === undefined);
  return {
    input: least(token.map((r) => r.input)),
    output: least(token.map((r) => r.output)),
    cacheRead: least(token.map((r) => r.cacheRead ?? r.input)),
    cacheWrite: least(token.map((r) => r.cacheWrite ?? r.input)),
    imageInput: least(token.map((r) => r.media.imageInput)),
    imageOutput: least(token.map((r) => r.media.imageOutput)),
    audioInput: least(token.map((r) => r.media.audioInput)),
    audioOutput: least(token.map((r) => r.media.audioOutput)),
    unit: least(rates.map((r) => r.media.unit)),
  };
}

/** `input_modalities`: the metadata's, else text, with images where a route proved vision. */
export function inputModalities(facts: Facts, listed: Pick<Listed, "capabilities">): string[] {
  if ((facts.input_modalities ?? []).length > 0) return [...facts.input_modalities!];
  return listed.capabilities.has("vision") ? ["text", "image"] : ["text"];
}

/**
 * `output_modalities`: the metadata's, else what its APIs produce, with images where a route proved image
 * output on a text generation API (a Gemini image model on `generateContent`); sorted, each once.
 */
export function outputModalities(facts: Facts, listed: Pick<Listed, "capabilities" | "protocols">): string[] {
  if ((facts.output_modalities ?? []).length > 0) return [...facts.output_modalities!];
  const words: string[] = sortProtocols(listed.protocols).map(modality);
  if (listed.capabilities.has("image_output")) words.push("image");
  return [...new Set(words)].sort(compareUtf8);
}

/**
 * `supported_parameters`: the OpenRouter parameter names its routes proved: the sampling and length
 * controls every generation route takes, and tools, structured output and reasoning where a probe report
 * verified them; none for a model with no generation API.
 */
export function supportedParameters(listed: Pick<Listed, "capabilities" | "protocols">): string[] {
  if (![...listed.protocols].some(isGeneration)) return [];
  const out = ["max_tokens", "temperature", "top_p", "stop"];
  const named: readonly (readonly [string, readonly string[]])[] = [
    ["tools", ["tools", "tool_choice"]],
    ["structured_output", ["response_format", "structured_outputs"]],
    ["reasoning", ["reasoning", "include_reasoning"]],
  ];
  for (const [capability, names] of named) if (listed.capabilities.has(capability)) out.push(...names);
  return out.sort(compareUtf8);
}

/** A JSON value of the listings: objects are written with their keys in byte order, as serde_json's `Map` (a BTreeMap) writes them. */
export type CatalogJson = string | number | boolean | null | readonly CatalogJson[] | { readonly [key: string]: CatalogJson };

/** `openai_model`'s object from its parts: the model, its listing, its facts and the APIs it is reachable through. */
export function openaiModelValue(id: string, listed: Listed, facts: Facts, apis: readonly Protocol[]): { readonly [key: string]: CatalogJson } {
  const prices = pricesOf(listed.rates);
  const pricing: Record<string, CatalogJson> = {};
  const components: readonly (readonly [string, bigint | undefined])[] = [
    ["prompt", prices.input],
    ["completion", prices.output],
    ["input_cache_read", prices.cacheRead],
    ["input_cache_write", prices.cacheWrite],
    ["image", prices.imageInput],
    ["image_output", prices.imageOutput],
    ["audio", prices.audioInput],
    ["audio_output", prices.audioOutput],
  ];
  for (const [key, rate] of components) if (rate !== undefined) pricing[key] = perToken(rate);
  const unit = sortProtocols(listed.protocols)
    .map(billingUnit)
    .find((u) => u !== undefined);
  if (prices.unit !== undefined && unit !== undefined) {
    // A unit-billed route charges per image, second, character or request; named so a client never
    // reads it as a token price.
    pricing.per_unit = perToken(prices.unit);
    pricing.unit = unit.replace(/s+$/, "");
  }
  const name = facts.name ?? id;
  const slash = id.indexOf("/");
  const contextLength = facts.context_length ?? null;
  return sorted({
    id,
    object: "model",
    created: facts.created ?? 0,
    owned_by: slash >= 0 ? id.slice(0, slash) : "gray",
    name,
    // Claude Code's gateway model discovery reads `display_name`.
    display_name: name,
    context_length: contextLength,
    architecture: sorted({ input_modalities: inputModalities(facts, listed), output_modalities: outputModalities(facts, listed) }),
    pricing: sorted(pricing),
    top_provider: sorted({ context_length: contextLength, max_completion_tokens: facts.max_output_tokens ?? null }),
    supported_parameters: supportedParameters(listed),
    endpoints: apis.map((p) => sorted({ protocol: p, path: endpointPath(p, id, false) })),
  });
}

/**
 * `gemini_model_value`: @gray/protocol's `geminiModelValue`, the one the `gemini-gateway` replay checks, its keys in
 * serde_json's order. No `countTokens` while this gateway does not count tokens (declared, conformance/README.md).
 */
export function geminiModelValue(id: string, native: boolean): { readonly [key: string]: CatalogJson } {
  const model = geminiModel(id, native);
  return { displayName: model.displayName, name: model.name, supportedGenerationMethods: [...model.supportedGenerationMethods] };
}

function sorted(o: Record<string, CatalogJson>): { readonly [key: string]: CatalogJson } {
  const out: Record<string, CatalogJson> = {};
  for (const key of Object.keys(o).sort(compareUtf8)) out[key] = o[key]!;
  return out;
}

/** How similar a suggestion must be (model_resolution.rs `SUGGESTION_SIMILARITY`). */
const SUGGESTION_SIMILARITY = 0.8;

function tail(id: string): string {
  const at = id.lastIndexOf("/");
  return at >= 0 ? id.slice(at + 1) : id;
}

/**
 * `model_resolution::suggest`: up to three of `known` most like `model`, best first (ties by id): compared
 * as a whole and without the vendor prefix, in lower case, by Jaro-Winkler similarity of at least 0.8.
 */
export function suggest(model: string, known: Iterable<string>): string[] {
  const wanted = rustTrim(model).toLowerCase();
  const wantedTail = tail(wanted);
  const scored: [number, string][] = [];
  for (const id of known) {
    const lower = id.toLowerCase();
    const score = Math.max(jaroWinkler(wanted, lower), jaroWinkler(wantedTail, tail(lower)));
    if (score >= SUGGESTION_SIMILARITY) scored.push([score, id]);
  }
  scored.sort((a, b) => b[0] - a[0] || compareUtf8(a[1], b[1]));
  return scored.slice(0, 3).map(([, id]) => id);
}
