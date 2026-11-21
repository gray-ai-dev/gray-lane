import { entryTranslations, type EntryOffer } from "@gray/snapshot";
import type { Protocol } from "@gray/protocol";
import { PolicyError, TranslationPolicy } from "@gray/translation";
import type { GatewaySnapshot } from "./snapshot.ts";

/**
 * The cross-protocol hook (the server's `select_translation` and `StreamStage`,
 * crates/gray-gateway/src/inference.rs and translation/; @gray/translation, docs/cloudflare-
 * native/translation.md section 3). Native routes always win, including their failures; a
 * translation is considered only when a request has no native route and an operator listed that
 * exact model and client protocol. Translated bodies are made from the parse, so only tier A bodies
 * can be translated (docs/cloudflare-native.md section 3 and section 12 item 11).
 *
 * The operator's policy travels with the snapshot (`GatewaySnapshot.translation`, the document of
 * the server's `translation_policy`), as the server reads it with its snapshot; a snapshot without
 * one translates nothing.
 *
 * The confidential entry reads no operator policy: it translates by its own rule (`entryRules`,
 * docs/design/lane-provider-routes.md section 10).
 */

/** What the request path and the listings read of a translation rule: the APIs a (model, client API) pair is translated onto, in order. */
export interface TranslationRules {
  upstreams(model: string, client: Protocol): readonly Protocol[] | undefined;
}

let parsed: { readonly version: number; readonly text: string | undefined; readonly policy: TranslationPolicy } | null = null;

/** The snapshot's translation policy, parsed once per version. A document that does not parse translates nothing, with an alert. */
export function translationPolicy(snapshot: GatewaySnapshot): TranslationPolicy {
  if (parsed !== null && parsed.version === snapshot.version && parsed.text === snapshot.translation) return parsed.policy;
  let policy = TranslationPolicy.empty();
  if (snapshot.translation !== undefined) {
    try {
      policy = TranslationPolicy.parse(snapshot.translation);
    } catch (error) {
      if (!(error instanceof PolicyError)) throw error;
      console.error(JSON.stringify({ level: "alert", event: "translation_policy_invalid", version: snapshot.version, message: error.message }));
    }
  }
  parsed = { version: snapshot.version, text: snapshot.translation, policy };
  return policy;
}

/** No translation at all. */
export const NO_TRANSLATION: TranslationRules = { upstreams: () => undefined };

/**
 * The confidential entry's rule over the routes it serves (@gray/snapshot `entryTranslations`, the one rule the entry's
 * routing, its listings and the catalog read; the owner's decision of 2026-11-21): a request on a text API for a model
 * the entry has no route of on that API, lane relay or endpoint route, live or not, is translated onto the other text
 * APIs on which the model has endpoint routes there. A lane relay's route is never a target. None when `off`.
 */
export function entryRulesOver(offers: Iterable<EntryOffer>, off: boolean): TranslationRules {
  const table = entryTranslations(offers, off);
  return table.size === 0 ? NO_TRANSLATION : { upstreams: (model, client) => table.get(model)?.get(client) };
}

let entry: { readonly snapshot: GatewaySnapshot; readonly rules: TranslationRules } | null = null;

/**
 * `entryRulesOver` the entry's lane snapshot (every route of which is a lane relay's or an endpoint route the entry
 * serves), off while the snapshot says ConfigDO's ENTRY_TRANSLATION is (`entryTranslation`). Built once per snapshot.
 */
export function entryRules(snapshot: GatewaySnapshot): TranslationRules {
  if (entry !== null && entry.snapshot === snapshot) return entry.rules;
  const rules = entryRulesOver(
    snapshot.routes.map((r) => ({ model: r.model, protocol: r.protocol, endpoint: r.auth !== "lane_relay" })),
    snapshot.entryTranslation === "off",
  );
  entry = { snapshot, rules };
  return rules;
}

/**
 * The rules a gateway reads for a request or a listing: the entry's own in lane mode; none for a request the
 * confidential entry forwarded here (docs/design/one-address.md: the entry translates for itself, so translated content
 * never comes through Cloudflare to be translated here, and the entry's copy of this gateway's model list names only
 * the APIs it serves natively); else the operator's policy.
 */
export function translationRules(snapshot: GatewaySnapshot, lane: boolean, viaEntry: boolean): TranslationRules {
  if (lane) return entryRules(snapshot);
  return viaEntry ? NO_TRANSLATION : translationPolicy(snapshot);
}
