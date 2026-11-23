import type { GatewayRouting } from "@gray/routing";
import { routingPolicyOfSnapshot, type SnapshotRouting } from "@gray/snapshot";

/**
 * The routing policy and the reference prices a gateway routes by (r17, docs/utility-routing.md "Configuration"): the
 * snapshot's `routing` (gray-jobs' `snapshotRouting`) read into `GatewaySnapshot.routing` once per snapshot version, as
 * `gatewaySnapshotOf` runs once per version (the snapshot cache's source and the lane entry's source map each version
 * once), on the main gateway and the lane entry alike. A document that does not read runs the code's defaults at the
 * row's version (as the roots do: gray-jobs sends them the defaults at that version) and says `routing_policy_invalid`, as
 * translate.ts says `translation_policy_invalid`: a bad policy never stops routing. The reference prices are gray-jobs'
 * (the publisher's facts), used as they are: its overrides go unused only when gray-jobs cannot read the document either.
 */
export function gatewayRoutingOf(routing: SnapshotRouting, snapshotVersion: number): GatewayRouting {
  const { policy, invalid } = routingPolicyOfSnapshot(routing);
  if (invalid !== null) {
    console.error(JSON.stringify({ level: "alert", event: "routing_policy_invalid", version: snapshotVersion, policy_version: routing.version, message: invalid }));
  }
  return { policy, referencePrices: new Map(routing.referencePrices.map((p) => [p.model, p])) };
}
