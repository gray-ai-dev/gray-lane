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
 * `thinking` only to turn it off, for a model whose routes proved no reasoning; OpenCode sends that as it is, and
 * otherwise adds `block_binding`, adaptive when none, for a model it binds thinking blocks for. The fixture
 * anthropic_thinking.json records OpenCode's own turns per model ID.
 */
export function opencodeThinking(model: { readonly id: string; readonly reasoning: boolean }): OpencodeThinking {
  if (!model.reasoning) return "disabled";
  return bindsThinking(model.id) ? "adaptive" : "none";
}

/**
 * `binds_thinking`: whether OpenCode 2.0.27 binds thinking blocks for the model `id`: an ID that reads as
 * `claude-<family>-<major>[.-<minor>]` of version 5.1 or later, by its own pattern on the lowercased ID, the
 * version read as numbers and a missing minor as 0 (its `kE` and `nj`).
 */
export function bindsThinking(id: string): boolean {
  const found = /(?:^|[./])claude-(?<family>[a-z]+)-(?<major>[0-9]+)(?:[.-](?<minor>[0-9]{1,2}))?(?:$|[-:@])/.exec(id.toLowerCase());
  if (found === null) return false;
  // As JavaScript's Number reads a run of digits: never an error.
  const number = (name: "major" | "minor") => {
    const text = found.groups?.[name];
    return text === undefined ? 0 : Number(text);
  };
  const major = number("major");
  const minor = number("minor");
  return major > 5 || (major === 5 && minor >= 1);
}
