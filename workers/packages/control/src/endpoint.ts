import { checkOfficialUpstream } from "@gray/lane";
import { PROTOCOLS, type Protocol, geminiMethodPath } from "@gray/protocol";
import { z } from "zod";
import { capabilitiesFromClaims, UnsupportedClaim } from "./capabilities.ts";
import { adapterServes } from "./media.ts";
import { rustTrim, utf8Length } from "./text.ts";

/**
 * A provider endpoint's configuration and the rules registration applies to it, ported from
 * crates/gray-control/src/lib.rs (`ModelMapping`, `EndpointConfig`, `validate_endpoint`,
 * `validate_endpoint_shape`, `config_fingerprint`). The serde forms are kept exactly: the stored JSON,
 * the fingerprint and a signed snapshot are all computed from `endpointConfigJson`.
 *
 * The confidential lane's endpoint (design v2 section B, module L0): a **lane relay** is a normal
 * endpoint whose `auth` is `lane_relay`, whose `base_url` is an official vendor origin, and which
 * carries a `lane` record instead of a Gray-sealed credential. Its stored credential is the sentinel
 * `lane:<relay_id>`, never a key. The main lane filters these routes out when it builds its
 * snapshot; the lane gateway serves only them.
 */

export type UpstreamAuth = "protocol_native" | "bearer" | "lane_relay";

/** The two non-lane ways an upstream takes its credential (a lane relay's comes from the relay). */
export type DirectAuth = Exclude<UpstreamAuth, "lane_relay">;

/** Whether `auth` is the confidential lane's endpoint kind. */
export function isLaneRelayAuth(auth: UpstreamAuth): auth is "lane_relay" {
  return auth === "lane_relay";
}

/**
 * `auth` as one of the two direct kinds, or a throw. A caller that sends an upstream request with a
 * credential of its own (a probe, a benchmark) cannot do that for a lane relay: its accounts are
 * sealed to the TEE and its credential is a sentinel. Used where a `DirectAuth` is wanted, so the
 * refusal is one line and not a silent cast.
 */
export function directAuth(auth: UpstreamAuth): DirectAuth {
  if (auth === "lane_relay") throw new InvalidConfig("a confidential-lane endpoint has no credential of its own to probe or benchmark with");
  return auth;
}

/**
 * The confidential-lane record of an endpoint (design v2 section B): the relay it belongs to, the
 * relay's Ed25519 key (it signs policy bundles and the scheduler's answers), and the relay's
 * scheduler with the key that signs the scheduler's answers.
 *
 * The names are snake_case and part of the stored configuration's serde form, so the fingerprint
 * covers them, as it covers every other field of the configuration.
 *
 * `mode` says how the lane serves the relay (S22, docs/confidential-lane-supply-implementation.md section 7): absent
 * for the sealed-credential lane (the relay's scheduler picks an account, its credentials are sealed to the TEE);
 * `stack` when the relay's own software runs in the VM between the lane's entry and its egress. A relay stack has no
 * scheduler, so its record may leave out both scheduler fields (`StackLaneEndpoint`); a sealed-credential record names
 * both (`SealedLaneEndpoint`). An absent field is not written, and `mode` comes after the others, so the record and
 * fingerprint of every other lane endpoint stay as they were. Rust reads and writes the same record and never serves
 * a lane relay (D125).
 */
interface LaneRecord {
  readonly relay_id: string;
  /** The relay's Ed25519 public key, lowercase hex, 32 bytes. */
  readonly signing_public_key: string;
}
export interface SealedLaneEndpoint extends LaneRecord {
  /** `https://relay.example`: an https origin only; no path (other than `/`), query or fragment. */
  readonly scheduler_url: string;
  /** The scheduler's Ed25519 public key, lowercase hex, 32 bytes. */
  readonly scheduler_public_key: string;
  readonly mode?: undefined;
}
export interface StackLaneEndpoint extends LaneRecord {
  /** Both or neither (validateLaneEndpoint). */
  readonly scheduler_url?: string;
  readonly scheduler_public_key?: string;
  readonly mode: LaneMode;
}
export type LaneEndpoint = SealedLaneEndpoint | StackLaneEndpoint;

/** The lane modes a record may name (S22); absent is the sealed-credential lane. */
export const LANE_MODES = ["stack"] as const;
export type LaneMode = (typeof LANE_MODES)[number];

/** A relay id: `@gray/relay-connector`'s `RESOURCE_ID`, the pattern the relay signs its bundles under. */
export const LANE_RELAY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/** A 32-byte Ed25519 public key as lowercase hex (ACI Appendix A: no `0x`, no uppercase). */
export const LANE_PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;

/** The longest scheduler URL; 2048 matches the `base_url` bound. */
export const LANE_SCHEDULER_URL_MAX_BYTES = 2048;

/** The credential sentinel of a lane relay (design v2 section B): `lane:<relay_id>`, never a key. */
export function laneCredential(relayId: string): string {
  return `lane:${relayId}`;
}

/** The relay a lane credential names, or null when it is not the sentinel of a well-formed relay id. */
export function laneRelayOfCredential(credential: string): string | null {
  if (!credential.startsWith("lane:")) return null;
  const relayId = credential.slice("lane:".length);
  return LANE_RELAY_ID_PATTERN.test(relayId) ? relayId : null;
}

/** The console's wording of each lane refusal. */
export const LANE_BASE_URL_RULE =
  "A confidential-lane endpoint's base URL is an official vendor origin: https://api.anthropic.com/v1/, https://api.openai.com/v1/, https://chatgpt.com/backend-api/codex/ or an OpenAI-compatible vendor's base URL (such as https://generativelanguage.googleapis.com/v1beta/openai/), with no query, no fragment and no user information.";
export const LANE_AUTH_RULE =
  'A confidential-lane endpoint has "auth": "lane_relay" and a "lane" record; every other endpoint has "protocol_native" or "bearer" and no "lane" record.';
export const LANE_RELAY_RULE =
  "A lane record names its relay (1-128 characters of A-Z a-z 0-9 . _ : -), the relay's Ed25519 public key and its scheduler's (64 lowercase hex digits each), and the scheduler's https origin without a path, a query or a fragment.";
export const LANE_CREDENTIAL_RULE =
  "A confidential-lane endpoint's credential is the sentinel lane:<relay_id>, the same relay its lane record names; the relay's own accounts are sealed to the TEE, never stored as the endpoint's credential.";

export interface ModelMapping {
  readonly requested_model: string;
  readonly upstream_model: string;
  readonly protocol: Protocol;
  readonly native_path: string;
  /** The vendor-native media API (`gray-media-adapters`), or null for the OpenAI-compatible API at `native_path`. */
  readonly adapter: string | null;
}

export interface EndpointConfig {
  readonly name: string;
  readonly base_url: string;
  readonly mappings: readonly ModelMapping[];
  readonly capabilities: readonly string[];
  readonly auth: UpstreamAuth;
  readonly prompt_overhead_tokens: number | null;
  readonly output_overhead_tokens: number | null;
  readonly cache_ttl_as_requested: boolean;
  /** The confidential lane's record; present exactly when `auth` is `lane_relay` (design v2 section B). */
  readonly lane: LaneEndpoint | null;
}

/** `gray_protocol::RESERVED_PROMPT_OVERHEAD_TOKENS`, `MAX_PROMPT_OVERHEAD_TOKENS`, `MAX_OUTPUT_OVERHEAD_TOKENS` (reservation.rs:27-41). */
export const RESERVED_PROMPT_OVERHEAD_TOKENS = 4096;
export const MAX_PROMPT_OVERHEAD_TOKENS = 65_536;
export const MAX_OUTPUT_OVERHEAD_TOKENS = 65_536;
// The console's wording of each refusal (lib.rs constants).
export const MODEL_ID_RULE = "A model ID starts with a letter or digit and uses only letters, digits and . _ : @ + / -, at most 256 characters.";
export const PROMPT_OVERHEAD_RULE = "The hidden prompt allowance is a whole number of tokens from 4096 to 65536.";
export const OUTPUT_OVERHEAD_RULE = "The output allowance is a whole number of tokens from 1 to 65536.";
export const NATIVE_PATH_TEMPLATE =
  'A native request path cannot contain "{" or "}": Gray sends the path exactly as written and fills in no placeholder. Write the upstream model ID into the path, for example /v1beta/models/gemini-2.5-flash:generateContent for a Gemini mapping.';
/** Why registration refuses a Gemini mapping's native path that names no model and generation method (lib.rs `GEMINI_PATH_RULE`). */
export const GEMINI_PATH_RULE =
  "A Gemini mapping's native request path ends with the upstream model ID and its method, for example /v1beta/models/gemini-2.5-flash:generateContent: Gray calls :generateContent, :streamGenerateContent or :countTokens on it.";

/** A configuration registration refuses, with the console's message (`Error::Invalid`). */
export class InvalidConfig extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidConfig";
  }
}

// u64 as JSON numbers JavaScript can hold exactly.
const u64 = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/**
 * serde's reading of a `ModelMapping`: unknown fields ignored, `adapter` null or absent is None. A stored
 * mapping that still names `response_model_aliases` (any value) reads without them, and is written and
 * fingerprinted without them, as gray-control does since Gray stopped reading the model an answer names.
 */
export const modelMappingSchema = z.object({
  requested_model: z.string(),
  upstream_model: z.string(),
  protocol: z.enum(PROTOCOLS as [Protocol, ...Protocol[]]),
  native_path: z.string(),
  adapter: z
    .string()
    .nullish()
    .transform((v) => v ?? null),
});

/**
 * serde's reading of a `LaneEndpoint` (gray-control's `RawLaneEndpoint`): `mode` and the two scheduler fields are
 * `Option`s (null or absent is None, a mode the lane does not know is refused), the scheduler fields required unless
 * the mode is `stack`; unknown fields ignored (serde's default), so a record or snapshot written while relay stacks
 * still carried `origins` and `direct` reads without them.
 */
export const laneEndpointSchema = z
  .object({
    relay_id: z.string().regex(LANE_RELAY_ID_PATTERN),
    signing_public_key: z.string().regex(LANE_PUBLIC_KEY_PATTERN),
    scheduler_url: z.string().nullish(),
    scheduler_public_key: z.string().regex(LANE_PUBLIC_KEY_PATTERN).nullish(),
    mode: z.enum(LANE_MODES).nullish(),
  })
  .superRefine((lane, ctx) => {
    if ((lane.mode === null || lane.mode === undefined) && (lane.scheduler_url == null || lane.scheduler_public_key == null)) {
      ctx.addIssue({ code: "custom", path: ["scheduler_url"], message: "a confidential-lane record names its scheduler unless its mode is stack" });
    }
  })
  .transform(({ relay_id, signing_public_key, scheduler_url, scheduler_public_key, mode }): LaneEndpoint => {
    if (mode === null || mode === undefined) return { relay_id, signing_public_key, scheduler_url: scheduler_url!, scheduler_public_key: scheduler_public_key! };
    return {
      relay_id,
      signing_public_key,
      ...(scheduler_url == null ? {} : { scheduler_url }),
      ...(scheduler_public_key == null ? {} : { scheduler_public_key }),
      mode,
    };
  });

/** serde's reading of an `EndpointConfig`. `lane` is absent for a direct endpoint. */
export const endpointConfigSchema = z.object({
  name: z.string(),
  base_url: z.string(),
  mappings: z.array(modelMappingSchema),
  capabilities: z.array(z.string()).default([]),
  auth: z.enum(["protocol_native", "bearer", "lane_relay"]).default("protocol_native"),
  prompt_overhead_tokens: u64.nullish().transform((v) => v ?? null),
  output_overhead_tokens: u64.nullish().transform((v) => v ?? null),
  cache_ttl_as_requested: z.boolean().default(false),
  lane: laneEndpointSchema
    .nullish()
    .transform((v) => v ?? null),
});

/** Reads a configuration as `serde_json::from_value::<EndpointConfig>` does; throws on a shape serde refuses. */
export function decodeEndpointConfig(value: unknown): EndpointConfig {
  return endpointConfigSchema.parse(value);
}

/** The serde form of a mapping, field by field in declaration order, skipped fields left out. */
export function modelMappingValue(m: ModelMapping): Record<string, unknown> {
  const out: Record<string, unknown> = { requested_model: m.requested_model, upstream_model: m.upstream_model, protocol: m.protocol, native_path: m.native_path };
  if (m.adapter !== null) out.adapter = m.adapter;
  return out;
}

/** The serde form of a lane record, field by field in declaration order; an absent field is not written. */
export function laneEndpointValue(lane: LaneEndpoint): Record<string, unknown> {
  const out: Record<string, unknown> = { relay_id: lane.relay_id, signing_public_key: lane.signing_public_key };
  if (lane.scheduler_url !== undefined) out.scheduler_url = lane.scheduler_url;
  if (lane.scheduler_public_key !== undefined) out.scheduler_public_key = lane.scheduler_public_key;
  if (lane.mode !== undefined) out.mode = lane.mode;
  return out;
}

/** Whether `lane` is a relay stack's record (S22): the relay's own software runs in the VM. */
export function isStackLane(lane: LaneEndpoint | null | undefined): boolean {
  return lane?.mode === "stack";
}

/**
 * The serde form of a configuration (`skip_serializing_if` honoured), as stored and fingerprinted.
 * `lane` is written for a lane relay only, in its declaration position (after `cache_ttl_as_requested`),
 * so the fingerprint covers it exactly as the Rust side would.
 */
export function endpointConfigValue(c: EndpointConfig): Record<string, unknown> {
  const out: Record<string, unknown> = { name: c.name, base_url: c.base_url, mappings: c.mappings.map(modelMappingValue), capabilities: [...c.capabilities] };
  if (c.auth !== "protocol_native") out.auth = c.auth;
  if (c.prompt_overhead_tokens !== null) out.prompt_overhead_tokens = c.prompt_overhead_tokens;
  if (c.output_overhead_tokens !== null) out.output_overhead_tokens = c.output_overhead_tokens;
  if (c.cache_ttl_as_requested) out.cache_ttl_as_requested = true;
  if (c.lane !== null) out.lane = laneEndpointValue(c.lane);
  return out;
}

/** `serde_json::to_string(&config)`. JSON.stringify escapes strings exactly as serde_json does. */
export function endpointConfigJson(c: EndpointConfig): string {
  return JSON.stringify(endpointConfigValue(c));
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** `config_fingerprint`: SHA-256 of `serde_json::to_vec(&(config, generation))`, in hex. */
export function configFingerprint(c: EndpointConfig, generation: number): Promise<string> {
  return sha256Hex(`[${endpointConfigJson(c)},${generation}]`);
}

/** `valid_model_id`: an ASCII letter or digit, then at most 255 of letters, digits and `. _ : @ + / -`. */
export function validModelId(id: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,255}$/.test(id);
}

/**
 * `validate_endpoint_shape`: the rules a stored endpoint must keep. Capability claims are left out, so a
 * signed snapshot holding an older endpoint stays recoverable.
 */
export function validateEndpointShape(c: EndpointConfig): void {
  if (
    rustTrim(c.name) === "" ||
    utf8Length(c.base_url) > 2048 ||
    !(c.base_url.startsWith("https://") || c.base_url.startsWith("http://")) ||
    /[@?#]/.test(c.base_url) ||
    c.mappings.length === 0
  ) {
    throw new InvalidConfig("endpoint configuration");
  }
  const seen = new Set<string>();
  for (const m of c.mappings) {
    const key = JSON.stringify([m.requested_model, m.protocol]);
    if (
      rustTrim(m.requested_model) === "" ||
      m.requested_model === "*" ||
      rustTrim(m.upstream_model) === "" ||
      !m.native_path.startsWith("/") ||
      m.native_path.startsWith("//") ||
      /[?#]/.test(m.native_path) ||
      (m.adapter !== null && !adapterServes(m.adapter, m.protocol)) ||
      seen.has(key)
    ) {
      throw new InvalidConfig("exact model mapping");
    }
    seen.add(key);
  }
}

/**
 * `validate_lane_endpoint`: a lane relay's own rules (design v2 section B, module L0).
 *
 * - `base_url` must name an official vendor origin, by `@gray/lane`'s `checkOfficialUpstream`: the
 *   relay's routes go to the vendor, never to the relay's own host, and the lane's origin rules are
 *   the one place that is decided.
 * - `lane` is required, and names a well-formed relay, two Ed25519 keys and an `https` scheduler URL
 *   without a query or a fragment (the scheduler client refuses either).
 * - the stored credential must be the sentinel `lane:<relay_id>` of the same relay: a lane endpoint
 *   never holds a key, and the relay's accounts are sealed to the TEE.
 *
 * Every other rule of `validate_endpoint` still applies: mappings, capabilities, the overheads.
 */
export function validateLaneEndpoint(c: EndpointConfig, credential: string | null): void {
  if (c.auth !== "lane_relay") throw new InvalidConfig(LANE_AUTH_RULE);
  if (c.lane === null) throw new InvalidConfig(LANE_AUTH_RULE);
  const lane = c.lane;
  if (!LANE_RELAY_ID_PATTERN.test(lane.relay_id) || !LANE_PUBLIC_KEY_PATTERN.test(lane.signing_public_key)) throw new InvalidConfig(LANE_RELAY_RULE);
  // Both scheduler fields, valid; a relay stack's record may leave out both (S22), never one.
  const url = lane.scheduler_url;
  const key = lane.scheduler_public_key;
  const scheduler = url !== undefined && key !== undefined ? validSchedulerUrl(url) && LANE_PUBLIC_KEY_PATTERN.test(key) : url === undefined && key === undefined && lane.mode !== undefined;
  if (!scheduler) throw new InvalidConfig(LANE_RELAY_RULE);
  // The origin check is @gray/lane's, so a URL the lane gateway would refuse can never be stored.
  const origin = checkOfficialUpstream(c.base_url);
  if (!origin.ok) throw new InvalidConfig(LANE_BASE_URL_RULE);
  if (credential !== null && laneRelayOfCredential(credential) !== lane.relay_id) throw new InvalidConfig(LANE_CREDENTIAL_RULE);
}

/**
 * Whether `url` is a scheduler URL the relay connector and the bridge accept (D23, D42): an https
 * origin only. A path (other than `/`), a query, a fragment, user information and a non-https
 * scheme are all refused; the reference scheduler serves its routes at the origin root and the
 * bridge appends the route path itself, so a base path would make two readers disagree.
 *
 * The text must carry an authority of its own and nothing after it but at most one slash (D42), and
 * it must be the origin spelling itself: exactly `origin` or `origin + "/"` (D83). `new URL(
 * "https:///path")` is `https://path/` — the parser takes the first path segment as the host — so
 * without the authority check the stored text would name no host while every reader connects to
 * `path`, and a dot-segment path would be silently folded away. The text check refuses every other
 * spelling the parser folds to the same origin: an explicit default port (`:443`), an upper-case
 * host, a percent-encoded host, and a backslash the parser reads as a slash. Each of those would be
 * shown on the console as text that is not the origin the connector and the bridge would call.
 *
 * Known narrowing (D120 m1, D122 e): a host with a label that begins with `xn--` (an ACE label) is
 * refused, valid Punycode or not. `new URL` here accepts one that is not valid Punycode
 * (`https://xn--abc`) where the Rust control plane's WHATWG parser (the `idna` crate) refuses it, so
 * neither parser decides it; refusing every ACE label is the rule both languages implement
 * identically. The cost is that a relay whose scheduler host is internationalized cannot register it.
 * The `scheduler-url-*` conformance cases (conformance/fixtures/endpoint-config), generated by Rust and
 * replayed in workerd (test/workerd/conformance.test.ts), are the evidence that the two read every other
 * spelling they cover alike.
 */
export function validSchedulerUrl(url: string): boolean {
  if (utf8Length(url) > LANE_SCHEDULER_URL_MAX_BYTES) return false;
  if (!url.startsWith("https://")) return false;
  if (/\s/.test(url)) return false;
  const rest = url.slice("https://".length);
  const authority = rest.split(/[/?#]/, 1)[0] ?? "";
  if (authority === "") return false;
  const tail = rest.slice(authority.length);
  if (tail !== "" && tail !== "/") return false;
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" &&
      parsed.hostname !== "" &&
      !parsed.hostname.split(".").some((label) => label.startsWith("xn--")) &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.search === "" &&
      parsed.hash === "" &&
      parsed.pathname === "/" &&
      parsed.href === `${parsed.origin}/` &&
      // D83: the stored text is the origin itself, not a spelling the parser folds to it.
      (url === parsed.origin || url === `${parsed.origin}/`)
    );
  } catch {
    return false;
  }
}

/**
 * The credential a lane endpoint's stored value must be (design v2 section B): the sentinel of its
 * lane record's relay. Null for any other endpoint, which stores a key as before.
 */
export function requiredCredentialOf(c: EndpointConfig): string | null {
  return c.auth === "lane_relay" && c.lane !== null ? laneCredential(c.lane.relay_id) : null;
}

/**
 * `validate_endpoint`: what registration accepts, every capability claim provable.
 *
 * A lane relay passes its own rules; every other endpoint must name `protocol_native` or `bearer`
 * and carry no lane record, so a lane endpoint cannot be registered by accident with a key.
 */
export function validateEndpoint(c: EndpointConfig, credential?: string | null): void {
  validateEndpointShape(c);
  if (c.auth === "lane_relay") {
    validateLaneEndpoint(c, credential ?? null);
  } else if (c.lane !== null) {
    throw new InvalidConfig(LANE_AUTH_RULE);
  }
  if (c.mappings.some((m) => /[{}]/.test(m.native_path))) throw new InvalidConfig(NATIVE_PATH_TEMPLATE);
  // Gray could not tell the upstream which method a call is on a Gemini path that names none, so a
  // route on it could never be called (@gray/protocol `geminiMethodPath`).
  if (c.mappings.some((m) => m.protocol === "gemini" && geminiMethodPath(m.native_path, "generateContent") === undefined)) throw new InvalidConfig(GEMINI_PATH_RULE);
  if (c.mappings.some((m) => !validModelId(m.requested_model))) throw new InvalidConfig(MODEL_ID_RULE);
  if (c.prompt_overhead_tokens !== null && !(c.prompt_overhead_tokens >= RESERVED_PROMPT_OVERHEAD_TOKENS && c.prompt_overhead_tokens <= MAX_PROMPT_OVERHEAD_TOKENS)) {
    throw new InvalidConfig(PROMPT_OVERHEAD_RULE);
  }
  if (c.output_overhead_tokens !== null && !(c.output_overhead_tokens >= 1 && c.output_overhead_tokens <= MAX_OUTPUT_OVERHEAD_TOKENS)) {
    throw new InvalidConfig(OUTPUT_OVERHEAD_RULE);
  }
  try {
    capabilitiesFromClaims(c.capabilities);
  } catch (error) {
    if (error instanceof UnsupportedClaim) throw new InvalidConfig("capability claim");
    throw error;
  }
}

/** The error code of an endpoint edit `endpointGenerationCheck` refuses, answered with a 409 (lib.rs `ENDPOINT_GENERATION_CONFLICT_CODE`). */
export const ENDPOINT_GENERATION_CONFLICT_CODE = "endpoint_generation_conflict";
/** The text that refusal carries, the console's and the gateway's alike (lib.rs `ENDPOINT_GENERATION_CONFLICT_TEXT`). */
export const ENDPOINT_GENERATION_CONFLICT_TEXT = "The endpoint changed since it was loaded. Reload it before saving.";

/** The refusal of an edit whose generation is not the endpoint's current one (`Error::EndpointGenerationConflict`). */
export interface EndpointGenerationConflict {
  readonly code: typeof ENDPOINT_GENERATION_CONFLICT_CODE;
  readonly message: string;
}

/**
 * `endpoint_generation_check` (D114(d), D119): whether an edit of `PUT /api/v1/endpoints/{id}` that names
 * `expected` may write an endpoint whose credential generation is `current`. An edit that names no
 * generation is not checked and one that names the current generation is allowed (null); any other, lower
 * or higher, is refused before anything is written.
 */
export function endpointGenerationCheck(expected: number | null | undefined, current: number): EndpointGenerationConflict | null {
  if (expected === null || expected === undefined || expected === current) return null;
  return { code: ENDPOINT_GENERATION_CONFLICT_CODE, message: ENDPOINT_GENERATION_CONFLICT_TEXT };
}

/** `EndpointConfig::prompt_overhead`: the declared allowance, or the default. */
export function promptOverhead(c: EndpointConfig): number {
  return c.prompt_overhead_tokens ?? RESERVED_PROMPT_OVERHEAD_TOKENS;
}

/** `EndpointConfig::output_overhead`. */
export function outputOverhead(c: EndpointConfig): number {
  return c.output_overhead_tokens ?? 0;
}
