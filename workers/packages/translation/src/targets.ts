/**
 * Which upstream protocols a request with no native route may be translated into, and which rule listed them
 * (crates/gray-gateway/src/translation/mod.rs `targets`, `Rule`, `RESPONSES_FALLBACK`, `Fallback`): an operator's rule
 * for the (model, client protocol) pair, or the implied Responses fallback (decision (b) of 2026-10-23).
 */
import type { Protocol } from "@gray/protocol";
import type { TranslationPolicy } from "./policy.ts";

/**
 * `Fallback`: whether a Responses request with no native route that can serve it may be translated without an
 * operator rule (the implied rule, `targets`). `off` is the lever that turns it off without a deploy (the gateway's
 * TRANSLATION_FALLBACK, the server's GRAY_TRANSLATION_FALLBACK); an operator rule always applies.
 */
export type Fallback = "open_ai_responses" | "off";

/** `Rule`: which rule chose a translation's upstream protocols (`targets`). */
export type Rule =
  /** An operator listed them for the (model, client protocol) pair. A request the translation refuses is answered with the refusal. */
  | "operator"
  /**
   * The implied Responses fallback. A request the translation refuses is not served by it, and is answered as if it
   * had no translation: the refusal it would get without the rule (`selectTranslation`).
   */
  | "implied";

/**
 * `RESPONSES_FALLBACK`: the upstream protocols the implied rule tries, in order: Chat keeps the prompt cache key and
 * maps the reasoning effort, Messages drops the cache key, Gemini comes last.
 */
export const RESPONSES_FALLBACK: readonly Protocol[] = ["open_ai_chat", "anthropic_messages", "gemini"];

/**
 * `targets`: the upstream protocols a request of `model` through `client` with no native route that can serve it may
 * be translated into, and the rule that listed them; null when it may not be. An operator rule for the pair wins.
 * Otherwise, while the lever is on, a Responses request of a model some endpoint maps on Responses (`responsesMapped`,
 * live or not: decision (b) is the strict fallback, so a model served on other APIs only is not reachable through
 * Responses by it) takes `RESPONSES_FALLBACK`, narrowed to the protocols with a live route of the model (`live`); with
 * none left, null, and the request is refused as without a translation.
 */
export function translationTargets(
  policy: TranslationPolicy,
  fallback: Fallback,
  model: string,
  client: Protocol,
  responsesMapped: boolean,
  live: (upstream: Protocol) => boolean,
): { readonly upstreams: readonly Protocol[]; readonly rule: Rule } | null {
  const ruled = policy.upstreams(model, client);
  if (ruled !== undefined) return { upstreams: ruled, rule: "operator" };
  if (client !== "open_ai_responses" || fallback === "off" || !responsesMapped) return null;
  const upstreams = RESPONSES_FALLBACK.filter((upstream) => live(upstream));
  return upstreams.length === 0 ? null : { upstreams, rule: "implied" };
}
