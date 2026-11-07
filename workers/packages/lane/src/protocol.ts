/**
 * The three protocols of the lane's early scope (owner decision: the official Anthropic and OpenAI
 * APIs only) and the four append positions.
 *
 * The protocol names are @gray/protocol's own strings, so a lane request is the same `Protocol` the
 * rest of the gateway routes on; this package narrows that type to the three the lane accepts rather
 * than spelling the names again.
 *
 * Positions are per protocol, from the shared wire shapes:
 * - Anthropic Messages: `system_start`, `system_end` (inside the `system` field);
 * - OpenAI Chat Completions: `instructions_before`, `instructions_after` (in `messages`);
 * - OpenAI Responses: `instructions_before`, `instructions_after` (inside `instructions`).
 */
import type { Protocol } from "@gray/protocol";

/** The protocols the lane's append rules are defined for. */
export type LaneProtocol = Extract<Protocol, "anthropic_messages" | "open_ai_chat" | "open_ai_responses">;

/** The lane's protocols, in the order the wire shapes and the vectors list them. */
export const LANE_PROTOCOLS: readonly LaneProtocol[] = ["anthropic_messages", "open_ai_chat", "open_ai_responses"];

/** Every append position of the shared wire shapes. */
export const POSITIONS = ["system_start", "system_end", "instructions_before", "instructions_after"] as const;

/** One of the four positions a relay template may be placed at. */
export type Position = (typeof POSITIONS)[number];

/** The positions a request of each protocol has, and the only ones its appends may name. */
export const POSITIONS_BY_PROTOCOL: Readonly<Record<LaneProtocol, readonly Position[]>> = {
  anthropic_messages: ["system_start", "system_end"],
  open_ai_chat: ["instructions_before", "instructions_after"],
  open_ai_responses: ["instructions_before", "instructions_after"],
};

/** Whether `value` is one of the lane's three protocols. */
export function isLaneProtocol(value: unknown): value is LaneProtocol {
  return value === "anthropic_messages" || value === "open_ai_chat" || value === "open_ai_responses";
}

/** Whether `value` is one of the four positions. */
export function isPosition(value: unknown): value is Position {
  return value === "system_start" || value === "system_end" || value === "instructions_before" || value === "instructions_after";
}

/** Every position a request of `protocol` has. */
export function positionsFor(protocol: LaneProtocol): readonly Position[] {
  return POSITIONS_BY_PROTOCOL[protocol];
}

/** Whether `position` exists for `protocol`. */
export function isPositionForProtocol(protocol: LaneProtocol, position: Position): boolean {
  return POSITIONS_BY_PROTOCOL[protocol].includes(position);
}
