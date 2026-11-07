/**
 * The input bound of a prompt at the routes of a request, from what their endpoints billed for its
 * earlier prefixes (crates/gray-gateway/src/inference.rs `input_bound`, `expected_input`;
 * crates/gray-gateway/src/prompt_usage.rs `Recorded::warm`; docs/holds-debt-mode.md 3.1, 3.2).
 *
 * The prompt's units (gray-protocol `PromptUnits`: the body's own bound and what the units after an
 * earlier prefix can cost) come in as `PromptFacts`, and the records as `longest`, the longest
 * earlier prefix an endpoint was recorded billing; the records themselves live where the
 * workspace's state does.
 */
import { addU64, max, min } from "./rates.ts";

/** What the bound reads of a prompt's units (`PromptUnits`). */
export interface PromptFacts {
  /** The most tokens the whole prompt can cost; unset when a unit has no bound (`body_bound`). */
  readonly bodyBound: bigint | undefined;
  /** What the whole prompt is expected to cost, a Gemini image at the tier asked for (`expected_body_bound`). */
  readonly expectedBodyBound: bigint | undefined;
  /** The most the units after the first `units` can cost (`bound_after`). */
  boundAfter(units: number): bigint | undefined;
  /** What the units after the first `units` are expected to cost (`expected_bound_after`). */
  expectedBoundAfter(units: number): bigint | undefined;
  /** Whether an Anthropic cache lookup reads the prefix of the first `units` units; always for the other protocols (`reads_prefix`). */
  readsPrefix(units: number): boolean;
}

/** What an endpoint was recorded billing for an earlier prefix of the prompt (`prompt_usage::Recorded`). */
export interface Recorded {
  readonly units: number;
  readonly billedInput: bigint;
  /** The cache-read and cache-write tokens of `billedInput`. */
  readonly cached: bigint;
  /** When the cache those tokens are in ends (Unix ms); 0 when Gray cannot tell. */
  readonly expiresMs: bigint;
}

/**
 * The tokens of the prefix the endpoint still has cached for a request sent `latencyMs` after
 * `nowMs` at the latest: its cached tokens (at most what it billed) while `now + L` is before the
 * cache's end, else 0; 0 while L is unmeasured (`Recorded::warm`).
 */
export function warm(recorded: Recorded, nowMs: bigint, latencyMs: bigint | undefined): bigint {
  if (latencyMs !== undefined && addU64(nowMs, latencyMs) < recorded.expiresMs) return min(recorded.cached, recorded.billedInput);
  return 0n;
}

/** The longest earlier prefix of the prompt `endpoint` was recorded billing. */
export type Longest = (endpoint: string) => Recorded | undefined;

/** The most input tokens a request's own prompt can cost at any of its routes, and where it came from (`InputBound`). */
export interface InputBound {
  /** Unset when the body cannot bound its input. */
  readonly tokens: bigint | undefined;
  /** The routes bounded by an earlier prefix their endpoint billed, below the body's bound. */
  readonly chains: readonly (readonly [string, Recorded])[];
  /** Every route was, so `tokens` is such a bound. */
  readonly chained: boolean;
  /** The record `tokens` came from, when every route was chained. */
  readonly binding: Recorded | undefined;
}

/**
 * The input bound of `prompt` at the routes of `endpoints`, the largest of theirs (`input_bound`):
 * each route's is what its endpoint billed for the longest earlier prefix it was recorded serving
 * (when `chain` is on), plus what the units appended since can cost, when that is below the body's
 * bound or the body has none; otherwise the body's bound. Unset when one route has no bound.
 */
export function inputBound(longest: Longest, chain: boolean, prompt: PromptFacts | undefined, endpoints: Iterable<string>): InputBound {
  if (prompt === undefined) return { tokens: undefined, chains: [], chained: false, binding: undefined };
  const body = prompt.bodyBound;
  let tokens: bigint | undefined = 0n;
  const chains: (readonly [string, Recorded])[] = [];
  let binding: Recorded | undefined;
  const seen = new Set<string>();
  for (const endpoint of endpoints) {
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    let recorded: { record: Recorded; chained: bigint } | undefined;
    const record = chain ? longest(endpoint) : undefined;
    if (record !== undefined) {
      const added = prompt.boundAfter(record.units);
      if (added !== undefined) {
        const chained = addU64(record.billedInput, added);
        if (body === undefined || chained < body) recorded = { record, chained };
      }
    }
    let bound: bigint | undefined;
    let from: Recorded | undefined;
    if (recorded !== undefined) {
      chains.push([endpoint, recorded.record]);
      bound = recorded.chained;
      from = recorded.record;
    } else {
      bound = body;
    }
    if (bound !== undefined && tokens !== undefined && bound >= tokens) {
      tokens = bound;
      binding = from;
    } else if (bound === undefined) {
      tokens = undefined;
    }
  }
  // No route to look a record up for: the body bounds it.
  if (seen.size === 0) tokens = body;
  const chained = chains.length > 0 && chains.length === seen.size;
  return { tokens, chains, chained, binding: chained ? binding : undefined };
}

/**
 * What debt mode expects the input of `prompt` to be at the routes of `endpoints`
 * (`expected_input`): T as `inputBound` takes it but with the expected bounds, the largest of the
 * routes'; and P, the smallest of what each route's endpoint still has cached of the prompt for a
 * request sent at most `latencyMs` after `nowMs`, on Anthropic only where a lookup reads it. A
 * route without a warm record is cold.
 */
export function expectedInput(longest: Longest, chain: boolean, prompt: PromptFacts | undefined, endpoints: Iterable<string>, nowMs: bigint, latencyMs: bigint | undefined): { readonly tokens: bigint | undefined; readonly warm: bigint } {
  if (prompt === undefined) return { tokens: undefined, warm: 0n };
  const body = prompt.expectedBodyBound;
  let tokens: bigint | undefined = 0n;
  let least: bigint | undefined;
  const seen = new Set<string>();
  for (const endpoint of endpoints) {
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    const record = chain ? longest(endpoint) : undefined;
    let own: bigint | undefined;
    if (record !== undefined) {
      const added = prompt.expectedBoundAfter(record.units);
      if (added !== undefined) {
        const chained = addU64(record.billedInput, added);
        if (body === undefined || chained < body) own = chained;
      }
    }
    own ??= body;
    tokens = tokens !== undefined && own !== undefined ? max(tokens, own) : undefined;
    const cached = record !== undefined && prompt.readsPrefix(record.units) ? warm(record, nowMs, latencyMs) : 0n;
    least = least === undefined ? cached : min(least, cached);
  }
  // No route to look a record up for: the body, cold.
  return least === undefined ? { tokens: body, warm: 0n } : { tokens, warm: least };
}
