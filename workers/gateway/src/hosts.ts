import type { GatewayConfig } from "@gray/config";
import { publicOrigins, type Origins } from "@gray/errors";

/**
 * The gateway Worker's side of the two hosts (crates/gray-gateway/src/hosts.rs, docs/configuration.md "Origins"). The
 * Worker is the model API: in production its only way in is the Workers route on the model API's host
 * (deploy/terraform-edge `workers_serve`), in staging its workers.dev name. It answers the public API alone
 * (@gray/errors `isPublicPath`, request_log.rs `is_public`) and never the console, whose Worker is on the console's
 * host. Its one operator path, `/livez`, is answered only to a name inside the machine or its network (`internal`), as
 * hosts.rs answers it: any other name, the model API's own and one routed to the Worker later included, gets the
 * public API's 404. The edge blocks the same paths on the model API's host first (`api_host_model_api_only`); this is
 * the second barrier.
 */

/**
 * hosts.rs `internal`: whether `hostname` (a URL's `hostname`: lower case, an IPv6 literal in brackets) names the
 * Worker from inside its machine or network, never through the edge: a loopback, private or link-local address,
 * `localhost` or a name under it (RFC 6761 6.3), or a name of one label. Every name Cloudflare routes is a domain of
 * the zone, so it has a dot.
 */
export function internal(hostname: string): boolean {
  const host = hostname.replace(/\.$/, "");
  if (host.startsWith("[") && host.endsWith("]")) return internalV6(host.slice(1, -1));
  const v4 = ipv4(host);
  if (v4 !== null) return internalV4(v4);
  return host === "localhost" || host.endsWith(".localhost") || !host.includes(".");
}

/** The four octets of a dotted-quad address (the WHATWG parser has already written any IPv4 form as one), or null. */
function ipv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255)) return null;
  return parts.map(Number);
}

/** `Ipv4Addr::is_loopback`, `is_private`, `is_link_local`. */
function internalV4([a, b]: number[]): boolean {
  return a === 127 || a === 10 || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

/**
 * `Ipv6Addr::is_loopback`, `is_unique_local`, `is_unicast_link_local`, and an IPv4-mapped address by its IPv4 rules
 * (`to_canonical`). `address` is as the WHATWG serializer writes it: lower case, compressed.
 */
function internalV6(address: string): boolean {
  if (address === "::1") return true;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (mapped !== null) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    return internalV4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff]);
  }
  const first = address.startsWith("::") ? 0 : parseInt(address.split(":")[0]!, 16);
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}

/**
 * The origins the Worker's errors name (`public_errors::Origins`): the model API's is the one the request was sent
 * to, the Worker's own; the console's is CONSOLE_ORIGIN, or the request's when it is empty, the one-origin setup that
 * row describes.
 */
export function originsOf(cfg: GatewayConfig, url: URL): Origins {
  return publicOrigins(cfg.consoleOrigin === "" ? url.origin : cfg.consoleOrigin, url.origin);
}
