import type { ToolCallIdLocator, ToolCallIdRpc } from "@gray/tool-ids";
import type { GatewayEnv } from "./env.ts";

/**
 * The gateway's way to its tool-call id shards: a fresh stub per call (a stub breaks when its object
 * restarts), created with the shard's region as its location hint so it stays there (C51). For the
 * request path: one call to a request's entry shard (@gray/tool-ids `lookupRows`, `writeRows`, through
 * the request's Outbound), which asks the home shards itself.
 */
export function toolCallIdShards(env: Pick<GatewayEnv, "TOOL_CALL_IDS">): ToolCallIdLocator {
  return (name, hint) => env.TOOL_CALL_IDS.get(env.TOOL_CALL_IDS.idFromName(name), { locationHint: hint }) as unknown as ToolCallIdRpc;
}
