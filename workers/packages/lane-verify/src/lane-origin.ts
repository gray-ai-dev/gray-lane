/**
 * The origin of the entry replica that served a response (docs/design/entry-replicas.md ER6, EI8). With several
 * replicas behind one shared name, the next connection may land on another replica, which holds none of this
 * response's receipts (`receipt_not_found`). So an entry with a replica index names its own origin in every response,
 * `x-gray-lane-origin: https://lane-<n>.<zone>`, and a verifier attests that origin and asks it for the receipts.
 *
 * The header is not signed: it chooses where to ask, never what to trust. A receipt still verifies only against the
 * keyset attested at that origin (`receipt.ts`, `keyset_digest`), and that keyset must hold a TLS record for the
 * origin's host (`attestation.ts`, `tls_spki`). It is accepted only as a sibling of the origin the customer named:
 * `https://<one label>.<parent zone of --origin>`, on the default port 443, with no credentials, path, query or
 * fragment. `--origin https://lane.usefallback.com` accepts `https://lane-2.usefallback.com` and refuses
 * `https://evil.example`. A refusal names why; it never falls back to another origin.
 *
 * No imports: `scripts/ops/lane-request.mjs` applies the same rule before it sends a key to that origin.
 */

/** The response header an entry replica names its own origin in (`workers/gateway/src/lane/receipts.ts`). */
export const LANE_ORIGIN_HEADER = "x-gray-lane-origin";

export type LaneOriginRead =
  | { readonly ok: true; readonly origin: URL }
  | { readonly ok: false; readonly reason: string };

/** Whether `host` (a URL's hostname) is an IP literal: an address names no zone. */
function isAddress(host: string): boolean {
  return host.startsWith("[") || /^[0-9.]+$/.test(host);
}

/**
 * `value` (the header's value) read as the origin of a replica of `origin` (the shared lane origin the customer
 * named), or the reason it is refused.
 */
export function readLaneOrigin(value: string, origin: string | URL): LaneOriginRead {
  const refuse = (reason: string): LaneOriginRead => ({ ok: false, reason });
  let base: URL;
  try {
    base = new URL(origin);
  } catch {
    return refuse("the lane origin it is checked against is not a URL");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return refuse("not a URL");
  }
  if (url.protocol !== "https:") return refuse(`${url.protocol.replace(/:$/u, "")} is not https`);
  if (url.username !== "" || url.password !== "") return refuse("it carries credentials");
  // The URL parser drops the scheme's default port, so any port left is not 443.
  if (url.port !== "") return refuse(`port ${url.port} is not 443`);
  if (url.pathname !== "/" && url.pathname !== "") return refuse("it carries a path");
  if (url.search !== "" || url.hash !== "") return refuse("it carries a query or fragment");
  const baseHost = base.hostname;
  if (isAddress(baseHost)) return refuse(`the lane origin ${baseHost} is an address, which names no zone a replica could be in`);
  const baseLabels = baseHost.split(".");
  // A parent zone of one label would be a top-level domain: every name under it would pass.
  if (baseLabels.length < 3) return refuse(`the lane origin ${baseHost} has no parent zone of two labels or more for a replica to be in`);
  const zone = baseLabels.slice(1).join(".");
  const labels = url.hostname.split(".");
  if (labels.length !== baseLabels.length || labels.slice(1).join(".") !== zone || labels[0] === "") {
    return refuse(`${url.hostname} is not a name directly under ${zone}, the zone of the lane origin ${baseHost}`);
  }
  return { ok: true, origin: new URL(`https://${url.hostname}`) };
}
