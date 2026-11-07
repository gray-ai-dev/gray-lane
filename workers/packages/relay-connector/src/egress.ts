import { toJsonString, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { utf8Bytes } from "./bytes.ts";
import { RelayConnectorError } from "./errors.ts";

/**
 * The egress proxy an account's traffic leaves through (design v3 addendum §E2, owner D15).
 *
 * The sealed member is structured, never a URL string: an HTTP(S) or SOCKS5 proxy is
 * `{type, host, port, username?, password?}`. Parsing the fields separately is what keeps a value
 * like `proxy.example@evil.example:8080` from being read two ways by two URL parsers, and it lets
 * every field be validated on its own. The same rules are in `deploy/tee/egress/spec.go` (the
 * sidecar that receives the value in `x-gray-egress`), so a member this package accepts is a header
 * the sidecar accepts and the other way round.
 *
 * Two sizes are load-bearing:
 * - the whole member is at most 1024 bytes, the same cap the sidecar puts on the header;
 * - each of `username` and `password` is at most 255 bytes, SOCKS5 RFC 1929's one-byte length
 *   field (D15). The bound is bytes, not code units.
 * - every credential character is printable ASCII 0x21-0x7e (D24), the one alphabet that this
 *   package, the relay-kit source checks and the sidecar share; a space or a non-ASCII byte has
 *   one reading only by accident, so it is refused.
 *
 * The `port` is an integer token on the wire (D42): `@gray/json` reads an integer as a `bigint`, and
 * `wireEgressSchema` accepts only that, so a JSON `8080.0` is refused exactly as the Go sidecar's
 * `*int` decoder refuses it. `egressSchema` is the same member for in-memory values and also takes an
 * integral `number` (relay-kit's `SourceEgress`); nothing on the wire is read through it.
 *
 * Errors name the member path (`accounts.N.egress.port`) and never echo the value, the host, the
 * username or the password: an egress member is a relay secret, and a validation error may reach a
 * log or an error page.
 */

/** The proxy protocols the lane accepts (the sidecar's set). */
export const EGRESS_TYPES = ["http", "https", "socks5", "socks5h"] as const;
export type EgressType = (typeof EGRESS_TYPES)[number];

/** The whole member's cap, in its compact JSON form (the sidecar header's cap). */
export const MAX_EGRESS_BYTES = 1024;

/** One proxy credential's cap: SOCKS5 RFC 1929's one-byte length field (D15); ASCII only, so characters are bytes. */
export const MAX_EGRESS_CREDENTIAL_BYTES = 255;

/** A validated egress proxy. `port` is a number here; the wire writes it as an integer. */
export interface EgressSpec {
  readonly type: EgressType;
  readonly host: string;
  readonly port: number;
  readonly username?: string;
  readonly password?: string;
}

/**
 * Whether `text` is a printable-ASCII proxy credential: every character in 0x21-0x7e, at
 * most `MAX_EGRESS_CREDENTIAL_BYTES` characters (and so bytes). Empty is allowed: the wire
 * represents no credential by the absent member, while an explicitly empty username or
 * password is still a value both sides read the same way.
 */
export function isValidEgressCredential(text: string): boolean {
  if (text.length > MAX_EGRESS_CREDENTIAL_BYTES) return false;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

/**
 * Whether `host` follows the E2 host rules: printable ASCII, no userinfo, no trailing dot, no
 * backslash, no percent escape, no path/query/fragment delimiters and no brackets. A colon is allowed
 * only inside a valid IPv6 literal; the wire form is structured fields, so brackets are never part of
 * the value (the sidecar adds them when it builds the proxy URL).
 */
export function isValidEgressHost(host: string): boolean {
  if (host.length === 0) return false;
  for (let index = 0; index < host.length; index += 1) {
    const code = host.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) return false;
  }
  if (/[@\\%]/.test(host)) return false;
  if (host.endsWith(".")) return false;
  if (/[/?#]/.test(host)) return false;
  if (/[\[\]]/.test(host)) return false;
  if (host.includes(":")) return isIpv6Literal(host);
  return true;
}

/** A colon-bearing host is an IPv6 literal only when the platform URL parser accepts it as one. */
function isIpv6Literal(host: string): boolean {
  try {
    const parsed = new URL(`http://[${host}]/`);
    return parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
  } catch {
    return false;
  }
}

/**
 * The port as the sealed wire carries it (D42): an integer token, which `@gray/json` reads as a
 * `bigint`. A JSON `8080.0` is a float and is refused exactly as the Go sidecar's `*int` decoder
 * refuses it; the wire never writes one (`egressValue` writes `BigInt(port)`).
 */
const wirePortSchema = z.bigint().min(1n).max(65_535n);

/**
 * The in-memory form also accepts an integral number: relay-kit's `SourceEgress` carries the port as
 * a number between reading a source and sealing it, and its own source validator
 * (`sourceEgressSchema`) already bounds it. Only `wireEgressSchema` is the sidecar's rule.
 */
const anyPortSchema = z.union([wirePortSchema, z.number().int().min(1).max(65_535)]);

/** The member before normalization, as either port rule reads it. */
interface RawEgress {
  readonly type: EgressType;
  readonly host: string;
  readonly port: bigint | number;
  readonly username?: string;
  readonly password?: string;
}

function normalize(raw: RawEgress): EgressSpec {
  return Object.freeze({
    type: raw.type,
    host: raw.host,
    port: typeof raw.port === "bigint" ? Number(raw.port) : raw.port,
    ...(raw.username === undefined ? {} : { username: raw.username }),
    ...(raw.password === undefined ? {} : { password: raw.password }),
  });
}

/** One member schema over a port rule: the shared fields, the whole-member cap, the frozen value. */
function egressMemberSchema(port: typeof wirePortSchema | typeof anyPortSchema) {
  return z
    .object({
      type: z.enum(EGRESS_TYPES),
      host: z.string().min(1).refine(isValidEgressHost, "host"),
      port,
      username: z.string().refine(isValidEgressCredential, "username").optional(),
      password: z.string().refine(isValidEgressCredential, "password").optional(),
    })
    .strict()
    .superRefine((raw, context) => {
      const hasUsername = raw.username !== undefined;
      const hasPassword = raw.password !== undefined;
      if (hasUsername !== hasPassword) {
        context.addIssue({ code: "custom", path: ["username"], message: "username and password are both required or both absent" });
        return;
      }
      const normalized = normalize(raw);
      if (utf8Bytes(toJsonString(egressValue(normalized))).length > MAX_EGRESS_BYTES) {
        context.addIssue({ code: "custom", path: [], message: "the egress member is over 1024 bytes" });
      }
    })
    .transform((raw): EgressSpec => normalize(raw));
}

/**
 * The validated member schema for a value already read from JSON: an integer-token port only (D42),
 * the rule the Go sidecar decodes with. `parseEgress` and the sealed bundle/update parsers use this
 * one, so a wire document this package accepts is one the sidecar accepts.
 */
export const wireEgressSchema = egressMemberSchema(wirePortSchema);

/**
 * The same member for in-memory values, which may carry the port as an integral number (relay-kit's
 * `SourceEgress`). Nested in an account it reports the full zod path, so a bundle's refusal is
 * `accounts.N.egress.port` and an update's is `egress.port`.
 */
export const egressSchema = egressMemberSchema(anyPortSchema);

/** The value the sealed member and the sidecar header carry: the port is written as an integer. */
export function egressValue(egress: EgressSpec): JsonObject {
  return {
    type: egress.type,
    host: egress.host,
    port: BigInt(egress.port),
    ...(egress.username === undefined ? {} : { username: egress.username }),
    ...(egress.password === undefined ? {} : { password: egress.password }),
  };
}

/** The compact JSON value the sidecar receives in `x-gray-egress`. */
export function egressHeader(egress: EgressSpec): string {
  return toJsonString(egressValue(egress));
}

/** Parse one egress value from JSON, throwing `invalid_bundle` with a member path and never a value. */
export function parseEgress(value: Json, path = "egress"): EgressSpec {
  const parsed = wireEgressSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const suffix = issue === undefined || issue.path.length === 0 ? "" : `.${issue.path.map(String).join(".")}`;
    throw new RelayConnectorError("invalid_bundle", `${path}${suffix}`);
  }
  return parsed.data;
}
