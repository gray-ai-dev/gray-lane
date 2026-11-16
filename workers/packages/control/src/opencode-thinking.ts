import type { Protocol } from "@gray/protocol";
import type { OpencodeThinking } from "./coding-agent.ts";

/**
 * What OpenCode 2.0.27 asks a model to think in its agent turn (crates/gray-verifier/src/coding_agent.rs
 * `thinking_sent`, `opencode_thinking`, `binds_thinking`): pure, so that the gateway's catalog reads it for
 * OpenCode's default (model_catalog.rs `serves_opencode`) without the check's fixtures, which @gray/verifier
 * re-exports these from for the check itself.
 */

/**
 * `thinking_sent`: what OpenCode 2.0.27 asks the Gray model `id` on `protocol` to think, `reasoning` being whether
 * its routes of that API proved reasoning: on the Messages API by `opencodeThinking`; on every other API nothing,
 * as the check's fixtures carry nothing there. What the check sends, and what a result must have been found with
 * for OpenCode's default.
 */
export function thinkingSent(protocol: Protocol, id: string, reasoning: boolean): OpencodeThinking {
  if (protocol !== "anthropic_messages") return "none";
  return opencodeThinking({ id, reasoning });
}

/**
 * `opencode_thinking`: what OpenCode 2.0.27 asks `model` to think on the Messages API. Gray's configuration sets
 * `thinking` only to turn it off, for a model whose routes proved no reasoning and that can turn it off
 * (`keepsThinkingOn`); OpenCode sends that as it is, and otherwise adds `block_binding`, adaptive when none, for a
 * model it binds thinking blocks for. The fixture anthropic_thinking.json records OpenCode's own turns per model ID.
 */
export function opencodeThinking(model: { readonly id: string; readonly reasoning: boolean }): OpencodeThinking {
  if (!model.reasoning && !keepsThinkingOn(model.id)) return "disabled";
  return bindsThinking(model.id) ? "adaptive" : "none";
}

/**
 * `binds_thinking`: whether OpenCode 2.0.27 binds thinking blocks for the model `id`: an ID that reads as
 * `claude-<family>-<major>[.-<minor>]` of version 5.1 or later, by its own pattern on the lowercased ID, the
 * version read as numbers and a missing minor as 0 (its `kE` and `nj`).
 */
export function bindsThinking(id: string): boolean {
  const version = claudeVersion(id);
  return version !== null && (version.major > 5 || (version.major === 5 && version.minor >= 1));
}

/**
 * `keeps_thinking_on`: whether the Claude model `id` refuses a request that turns thinking off, so that Gray's
 * configuration leaves OpenCode's thinking as it is even where the model's routes proved no reasoning: Anthropic
 * answers `thinking: {"type":"disabled"}` 400 on Claude Opus 5.5 and Sonnet 5.5 at every effort and on every Fable
 * and Mythos model, while Opus 5, Sonnet 5, Haiku 5.5 and older models accept it at OpenCode's effort, the default
 * (Anthropic's model migration guide, 2026-11). Family `opus` or `sonnet` of version 5.5 or later, assumed to keep
 * the rule, or `fable` or `mythos` of any version.
 */
export function keepsThinkingOn(id: string): boolean {
  const version = claudeVersion(id);
  if (version === null) return false;
  if (version.family === "fable" || version.family === "mythos") return true;
  if (version.family === "opus" || version.family === "sonnet") return version.major > 5 || (version.major === 5 && version.minor >= 5);
  return false;
}

/**
 * `claude_version`: the family and version of a Claude model `id` by OpenCode 2.0.27's own pattern on the lowercased
 * ID, the version read as numbers and a missing minor as 0; null for an ID that does not read as one.
 */
function claudeVersion(id: string): { family: string; major: number; minor: number } | null {
  const found = /(?:^|[./])claude-(?<family>[a-z]+)-(?<major>[0-9]+)(?:[.-](?<minor>[0-9]{1,2}))?(?:$|[-:@])/.exec(id.toLowerCase());
  if (found === null) return null;
  // As JavaScript's Number reads a run of digits: never an error.
  const number = (name: "major" | "minor") => {
    const text = found.groups?.[name];
    return text === undefined ? 0 : Number(text);
  };
  return { family: found.groups?.family ?? "", major: number("major"), minor: number("minor") };
}
