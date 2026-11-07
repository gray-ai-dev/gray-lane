import { LOCATION_HINTS, type LocationHint } from "./index.ts";

/**
 * The region of a request: the Durable Object location hint its account and endpoint shards live in,
 * so a request never leaves the region it came from (docs/cloudflare-native.md 2.4, step 1; a
 * same-colo call takes 2-5 ms, a cross-region one 156-229 ms, scaling.md section 1).
 *
 * Moved here from `workers/gateway/src/region.ts`, which now re-exports it: the confidential lane's
 * bridge (`workers/lane-bridge`) had a byte-for-byte copy of it, and two copies of the rule that
 * places a request's Durable Objects can drift into placing the same client's objects in two
 * regions. The gateway and the bridge both import this one function.
 *
 * The design reads the region from a table by colo. Until that table exists this maps the continent
 * Cloudflare states for the request (request.cf.continent) to the hint of that area, as the
 * location-hint documentation lists them (C51 in docs/cloudflare-native.md section 14): North
 * America splits at the 100th meridian west (the Mountain / Central time-zone boundary), the Middle
 * East goes to `me`. A request without a continent (local development, workerd, the dstack CVM)
 * takes the caller's fallback region. TODO: the colo table of section 2.5.
 */

/** Countries of the `me` hint's area (ISO 3166-1 alpha-2). */
const MIDDLE_EAST = new Set(["AE", "BH", "IL", "IQ", "IR", "JO", "KW", "LB", "OM", "PS", "QA", "SA", "SY", "YE"]);

/** The three fields of `request.cf` the region rule reads. */
export interface RequestPlace {
  readonly continent?: string | undefined;
  readonly country?: string | undefined;
  readonly longitude?: string | undefined;
}

/** The location hint a request's `cf` blob names, or `fallback` when it names none. */
export function requestRegion(place: RequestPlace | undefined, fallback: LocationHint): LocationHint {
  switch (place?.continent) {
    case "NA": {
      const longitude = Number(place.longitude);
      return Number.isFinite(longitude) && longitude < -100 ? "wnam" : "enam";
    }
    case "SA":
      return "sam";
    case "EU":
      return "weur";
    case "AS":
      return place.country !== undefined && MIDDLE_EAST.has(place.country) ? "me" : "apac";
    case "OC":
      return "oc";
    case "AF":
      return "afr";
    default:
      return fallback;
  }
}

/**
 * The home region of a workspace made where no request exists: the seeds of staging and of the tests,
 * and the rows that existed before `control_workspaces.home_region` (staging's; production had none). A
 * workspace made by a request takes that request's region (`requestRegion`; the console's sign-in and
 * workspace creation, crates/gray-control `create_workspace`). wnam: the database's region, where the
 * jobs and the endpoint roots are (JOBS_LOCATION_HINT, ENDPOINT_ROOT_LOCATION_HINT). The column's
 * default in both migration chains is this value (workers/db/migrations/0023_workspace_home_region.sql,
 * crates/gray-db/migrations/gateway/0002_workspace_home_region.sql), and so is the server's
 * `gray_protocol::region::DEFAULT_HOME_REGION`.
 */
export const DEFAULT_HOME_REGION: LocationHint = "wnam";

/** Whether `value` is a location hint (a workspace's stored home region is read through this). */
export function isLocationHint(value: unknown): value is LocationHint {
  return typeof value === "string" && (LOCATION_HINTS as readonly string[]).includes(value);
}
