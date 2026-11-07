import type { LocationHint } from "@gray/config";
import { REGION_CODES } from "@gray/tool-ids";

/**
 * The gateway's region helpers.
 *
 * `requestRegion` (and its `RequestPlace`) is `@gray/config`'s: it lived here, and the confidential
 * lane's bridge (`workers/lane-bridge`) carried a copy of it, so a change to the rule could have
 * placed one client's Durable Objects in two regions. It is re-exported under the same names because
 * `index.ts`, `tool-ids.ts`, `lane/deps.ts` and the request-path tests import it from this file.
 *
 * What stays here is the gateway's own use of a region: the tool-call id handles' region code.
 */
export { requestRegion, type RequestPlace } from "@gray/config";

/**
 * The region code a request's tool-call id handles name, and where their rows are stored: its
 * region's (@gray/tool-ids REGION_CODES; docs/cloudflare-native/tool-call-ids.md section 1). The
 * server names one deployment's region with GRAY_REGION_CODE (`u`, Silicon Valley); one Cloudflare
 * deployment serves every region at once, so the code follows the request's location hint instead of a
 * var, `wnam` keeping the server's `u`. A code is in every handle it issued, so the table never changes.
 */
export function handleRegion(region: LocationHint): string {
  return REGION_CODES[region];
}
