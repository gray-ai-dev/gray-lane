/** What an attempt is keyed by and marked with, read without the request's state (`InferenceRun`, inference.ts). */
import type { PermitToken } from "@gray/endpoint";
import type { Route } from "../routes.ts";
import type { RouteRecord } from "../snapshot.ts";
import type { LaneDeps } from "../lane/types.ts";
import type { Attempt } from "./types.ts";
import type { LaneStackVendor, OfficialVendor } from "@gray/lane";

/**
 * The relay the route belongs to, from its lane record (`route.record.lane.relayId`, the snapshot's
 * copy of the endpoint's `config.lane`), or null when this is not a lane relay or its record is
 * absent. The credential is deliberately never read: the jobs snapshot carries it sealed under the
 * master key, which the lane does not hold (D107), so only the route's control record names a relay.
 */
export function relayOf(route: Route): string | null {
  if (route.record.auth !== "lane_relay") return null;
  return route.record.lane?.relayId ?? null;
}

/**
 * `attempt`'s failure implicated its provider (`due`, traffic-evidence.ts `ProviderFailures`): the lane's record of it
 * says so (`providerFailure`) when `endAttempt` writes it, which comes after every caller. A held refusal's record is
 * written before it is settled, and `settleHeld` marks it there.
 */
export function laneProviderFailure(attempt: Attempt, due: boolean): void {
  if (due) attempt.providerFailure = true;
}

/** The permit key of a deferred release. */
export function permitKey(permit: PermitToken): string {
  return `${permit.shard}/${permit.incarnation ?? ""}/${permit.epoch}/${permit.id}`;
}

/**
 * Gray's own request deadline cut the attempt's answer while it arrived: Gray's limit, not the provider's, for the
 * evidence of its route's mapping (traffic_evidence.rs `cut_by_deadline`) and for its answer checks, which then count
 * nothing (docs/error-rates.md, sinks.ts `countedChecks`; kept in the lane too, which has no evidence).
 */
export function cutByDeadline(attempt: Attempt): void {
  attempt.deadlineCut = true;
  if (attempt.evidence !== undefined) attempt.evidence.deadlineCut = true;
}

/** The vendor a lane relay's scheduler is asked for: chatgpt.com's Codex backend is its own pool (`laneAttempt`). */
export function laneVendor(vendor: OfficialVendor): LaneStackVendor {
  return vendor === "chatgpt" ? "chatgpt_codex" : vendor;
}

const encoder = new TextEncoder();

/** SHA-256 of `bytes`, hex. */
export function hexDigest(bytes: Uint8Array): Promise<string> {
  return crypto.subtle.digest("SHA-256", bytes).then((d) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""));
}

/** The public pseudonym of the serving route (`routing::provider_ref`): SHA-256 of `workspace:endpoint`, hex. */
export function providerRef(route: Route): Promise<string> {
  return hexDigest(encoder.encode(`${route.record.operator}:${route.record.endpointId}`));
}

/**
 * Whether a failure at `route` of a lane request files no rest (`restRoute`): a lane relay's route is a pool of the
 * relay's accounts, and every failure there, a rate limit's too (the account's own allowance), is one account's, which
 * the relay and egress cool themselves. The lead's proposal of 2026-11-15, confirmed by the user on 2026-11-16
 * (conformance/README.md "声明过的差别"; review r16 blocker 1).
 */
export function laneRouteFilesNoRest(lane: LaneDeps | null, route: RouteRecord): boolean {
  return lane !== null && route.auth === "lane_relay";
}

/**
 * Whether a route proved image output on a text generation API, as a Gemini image model's route does
 * (`RouteCapabilities.chat.image_output`, read by `Scope::with_routes`, `asks_for_image` and the image price's
 * gate): the claim word `image_output` in what its report proved (the snapshot's `proved`, which carries it for
 * a Gemini mapping alone, @gray/snapshot `mappingCapabilities`).
 */
export function provesImageOutput(route: Route): boolean {
  return route.record.protocol === "gemini" && (route.record.proved ?? []).includes("image_output");
}

/** The host of an upstream URL (record.rs Attempt `upstream_host`), or null when it does not parse. */
export function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}
