import { accountSettings } from "@gray/account";
import type { GatewayConfig } from "@gray/config";
import type { MediaRoute, MediaSettings } from "@gray/media";
import type { RouteRecord } from "./snapshot.ts";

/**
 * The model APIs' glue at the confidential entry: their settings from @gray/config, a snapshot route as the model APIs
 * read it, and the hold a video create asks for. The confidential entry records and follows a
 * video job behind the lane bridge (lane/video-jobs.ts, docs/design/standard-media-at-entry.md section 2.7).
 */

/** The model APIs' settings (@gray/media `MediaSettings`) from the gateway's configuration. */
export function mediaSettings(cfg: GatewayConfig): MediaSettings {
  return { responseBytes: cfg.mediaResponseBytes };
}

/** A media route with the confidential lane's auth: no lane relay serves a model API. */
function failLaneMedia(): never {
  throw new Error("a media route cannot be a confidential-lane relay");
}

/**
 * A snapshot route as the model APIs read it (@gray/media `MediaRoute`): the capabilities its endpoint states and has
 * proved, and whether its price for the request bills units (`billsUnits`; undefined: unpriced). It carries no key: an
 * attempt takes its provider's key from the entry's own table (apis.ts `entryKey`).
 */
export function mediaRouteOf(record: RouteRecord, billsUnits: boolean | undefined): MediaRoute {
  return {
    endpointId: record.endpointId,
    providerWorkspace: record.operator,
    baseUrl: record.baseUrl,
    url: record.url,
    auth: record.auth === "lane_relay" ? failLaneMedia() : record.auth,
    credential: "",
    capabilities: record.claims,
    proved: record.proved ?? [],
    upstreamModel: record.upstreamModel,
    billsUnits,
  };
}

/**
 * The token lifetime the request path asks for when it admits `POST /v1/videos`
 * (`AdmitInput.lifetimeMs`): the job may run VIDEO_JOB_TTL_SECONDS, and after its deadline its last
 * poll and its settlement get an ordinary request's lifetime (STREAM_TOTAL_SECONDS plus
 * ACCOUNT_HOLD_MARGIN_MS). The server keeps the hold until the job settles
 * (crates/gray-gateway/src/credit.rs `keep_for_job`); a token must end, so it ends there. The account
 * shards accept up to exactly this (@gray/account `holdTtlMaxMs`).
 */
export function videoHoldLifetimeMs(cfg: GatewayConfig): number {
  return accountSettings(cfg).holdTtlMaxMs;
}
