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
 */

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
