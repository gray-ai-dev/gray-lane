import { continuationStoreName, type ContinuationLocator, type ContinuationRpc } from "@gray/continuation";
import type { GatewayEnv } from "./env.ts";

/**
 * The gateway's way to its continuation stores: a fresh stub per call (a stub breaks when its object
 * restarts), created with the store's region as its location hint so it stays there (C51). For
 * @gray/continuation's `pinContinuation`, `bindContinuation` and `StreamBinding`.
 */
export function continuationStores(env: Pick<GatewayEnv, "CONTINUATION">): ContinuationLocator {
  return (a) => env.CONTINUATION.get(env.CONTINUATION.idFromName(continuationStoreName(a)), { locationHint: a.region }) as unknown as ContinuationRpc;
}
