import type { UpstreamAuth as ControlUpstreamAuth, LaneEndpoint } from "@gray/control";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { isProtocol, type Protocol } from "@gray/protocol";
import { parsePlain } from "@gray/json";

/**
 * Control-plane records as crates/gray-control stores them (JSON text in `control_endpoints.config`,
 * `control_verifications.record`), read with serde's rules, and the two fingerprints that are
 * hashes of serde_json's own serialization: `config_fingerprint` (ControlStore::config_fingerprint,
 * crates/gray-control/src/lib.rs) and `mapping_fingerprint` (crates/gray-gateway/src/
 * provider_offers.rs). Both are held to the Rust code by the conformance area `snapshot`.
 *
 * serde_json writes a struct's fields in declaration order, compact, leaving out a field whose
 * `skip_serializing_if` holds, and escapes strings as JSON.stringify does for well-formed strings
 * (@gray/json). Records come from PostgreSQL text, which is always well-formed UTF-8.
 */

/**
 * How the credential is presented (gray_protocol::UpstreamAuth); `protocol_native` is the default and
 * is never written. `lane_relay` is the confidential lane's kind (design v2 section B): its stored
 * credential is the sentinel `lane:<relay_id>` sealed under the master key, and the lane reads the
 * relay from `config.lane`, never from the credential (D107). `@gray/control` owns the vocabulary and
 * this is its type.
 */
export type UpstreamAuth = ControlUpstreamAuth;

export interface ModelMapping {
  readonly requested_model: string;
  readonly upstream_model: string;
  readonly protocol: Protocol;
  readonly native_path: string;
  /** A vendor-native adapter (`gemini`, `volcengine`, `minimax`, `kling`, `fal`), or null. */
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
  /** The confidential lane's record; present exactly when `auth` is `lane_relay` (`@gray/control` `LaneEndpoint`). */
  readonly lane: LaneEndpoint | null;
}

/** gray_control::ProviderEndpoint: a row of control_endpoints with its fingerprint. */
export interface ProviderEndpoint {
  readonly id: string;
  readonly workspace_id: string;
  readonly owner_user_id: string;
  readonly config: EndpointConfig;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
  readonly enabled: boolean;
}

export type VerificationOutcome = "pass" | "fail" | "inconclusive";

/** gray_control::VerificationRecord. */
export interface VerificationRecord {
  readonly id: string;
  readonly endpoint_id: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
  readonly outcome: VerificationOutcome;
  /** Unix seconds. */
  readonly checked_at: number;
  readonly expires_at: number;
  readonly evaluator_version: string;
}

/** A record that does not parse as serde would read it. */
export class RecordError extends Error {
  constructor(what: string) {
    super(what);
    this.name = "RecordError";
  }
}

type Obj = Record<string, unknown>;

function obj(v: unknown, what: string): Obj {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new RecordError(`${what} must be an object`);
  return v as Obj;
}

function str(o: Obj, key: string, what: string): string {
  const v = o[key];
  if (typeof v !== "string") throw new RecordError(`${what}.${key} must be a string`);
  return v;
}

/** A u64 field. JSON numbers past 2^53 are not exact here and are refused (docs/cloudflare-native.md 6.2). */
function u64(v: unknown, what: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new RecordError(`${what} must be a non-negative integer`);
  return v;
}

function i64(v: unknown, what: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v)) throw new RecordError(`${what} must be an integer`);
  return v;
}

function optU64(v: unknown, what: string): number | null {
  return v === undefined || v === null ? null : u64(v, what);
}

function strings(v: unknown, what: string): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((s) => typeof s !== "string")) throw new RecordError(`${what} must be an array of strings`);
  return v as string[];
}

function protocol(v: unknown, what: string): Protocol {
  if (!isProtocol(v)) throw new RecordError(`${what} is not a protocol`);
  return v;
}

/**
 * `serde_json::from_value::<ModelMapping>`: unknown fields are ignored. A stored mapping that still names
 * `response_model_aliases` (any value, null too) reads, is written and is fingerprinted without them, as
 * gray-control does since Gray stopped reading the model an answer names.
 */
export function parseMapping(v: unknown, what = "mapping"): ModelMapping {
  const o = obj(v, what);
  const adapter = o.adapter;
  if (adapter !== undefined && adapter !== null && typeof adapter !== "string") throw new RecordError(`${what}.adapter must be a string`);
  return {
    requested_model: str(o, "requested_model", what),
    upstream_model: str(o, "upstream_model", what),
    protocol: protocol(o.protocol, `${what}.protocol`),
    native_path: str(o, "native_path", what),
    adapter: typeof adapter === "string" ? adapter : null,
  };
}

/**
 * `serde_json::from_value::<LaneEndpoint>`: every field required but `mode` (S22: `stack`, or null or absent for the
 * sealed-credential lane; any other value refused), a shape a lane endpoint cannot be used without. Unknown fields are
 * ignored, as serde does, so a record written while relay stacks still carried `origins` and `direct` reads without them.
 */
export function parseLaneEndpoint(v: unknown): LaneEndpoint {
  const o = obj(v, "config.lane");
  const relay_id = str(o, "relay_id", "config.lane");
  const signing_public_key = str(o, "signing_public_key", "config.lane");
  if (relay_id === "" || signing_public_key === "") throw new RecordError("config.lane names its relay and key as non-empty strings");
  const optional = (key: string): string | undefined => (o[key] === undefined || o[key] === null ? undefined : str(o, key, "config.lane"));
  const scheduler_url = optional("scheduler_url");
  const scheduler_public_key = optional("scheduler_public_key");
  if (scheduler_url === "" || scheduler_public_key === "") throw new RecordError("config.lane's scheduler fields are non-empty strings");
  if (o.mode === undefined || o.mode === null) {
    // A sealed-credential relay names its scheduler; a relay stack may not (S22).
    if (scheduler_url === undefined || scheduler_public_key === undefined) throw new RecordError("config.lane holds four non-empty strings");
    return { relay_id, signing_public_key, scheduler_url, scheduler_public_key };
  }
  if (o.mode !== "stack") throw new RecordError("config.lane.mode must be stack, null or absent");
  return {
    relay_id,
    signing_public_key,
    ...(scheduler_url === undefined ? {} : { scheduler_url }),
    ...(scheduler_public_key === undefined ? {} : { scheduler_public_key }),
    mode: o.mode,
  };
}

/** The serde form of a lane record: `serde_json::to_string` field by field, in declaration order; an absent field left out. */
export function serializeLaneEndpoint(lane: LaneEndpoint): string {
  const url = lane.scheduler_url === undefined ? "" : `,"scheduler_url":${s(lane.scheduler_url)}`;
  const key = lane.scheduler_public_key === undefined ? "" : `,"scheduler_public_key":${s(lane.scheduler_public_key)}`;
  const mode = lane.mode === undefined ? "" : `,"mode":${s(lane.mode)}`;
  return `{"relay_id":${s(lane.relay_id)},"signing_public_key":${s(lane.signing_public_key)}${url}${key}${mode}}`;
}

/** `serde_json::from_str::<EndpointConfig>`: unknown fields are ignored, missing defaults applied. */
export function parseEndpointConfig(v: unknown): EndpointConfig {
  const o = obj(v, "config");
  if (!Array.isArray(o.mappings)) throw new RecordError("config.mappings must be an array");
  // `#[serde(default)]` fills a missing field only; an explicit null is a type error there.
  const auth = o.auth === undefined ? "protocol_native" : o.auth;
  if (auth !== "protocol_native" && auth !== "bearer" && auth !== "lane_relay") throw new RecordError("config.auth must be protocol_native, bearer or lane_relay");
  const cache = o.cache_ttl_as_requested === undefined ? false : o.cache_ttl_as_requested;
  if (typeof cache !== "boolean") throw new RecordError("config.cache_ttl_as_requested must be a boolean");
  return {
    name: str(o, "name", "config"),
    base_url: str(o, "base_url", "config"),
    mappings: o.mappings.map((m, i) => parseMapping(m, `config.mappings[${i}]`)),
    capabilities: strings(o.capabilities, "config.capabilities"),
    auth,
    lane: auth === "lane_relay" ? parseLaneEndpoint(o.lane) : null,
    prompt_overhead_tokens: optU64(o.prompt_overhead_tokens, "config.prompt_overhead_tokens"),
    output_overhead_tokens: optU64(o.output_overhead_tokens, "config.output_overhead_tokens"),
    cache_ttl_as_requested: cache,
  };
}

/**
 * `serde_json::from_value::<VerificationRecord>`: unknown fields are ignored, the retired `model_label` (any
 * value) among them: a record written before Gray stopped reading the model an answer names reads as any other.
 */
export function parseVerification(v: unknown): VerificationRecord {
  const o = obj(v, "verification");
  const outcome = o.outcome;
  if (outcome !== "pass" && outcome !== "fail" && outcome !== "inconclusive") throw new RecordError("verification.outcome is not an outcome");
  return {
    id: str(o, "id", "verification"),
    endpoint_id: str(o, "endpoint_id", "verification"),
    model: str(o, "model", "verification"),
    protocol: protocol(o.protocol, "verification.protocol"),
    credential_generation: u64(o.credential_generation, "verification.credential_generation"),
    config_fingerprint: str(o, "config_fingerprint", "verification"),
    outcome,
    checked_at: i64(o.checked_at, "verification.checked_at"),
    expires_at: i64(o.expires_at, "verification.expires_at"),
    evaluator_version: str(o, "evaluator_version", "verification"),
  };
}

// ---------------------------------------------------------------- serde_json's serialization

const s = (v: string) => JSON.stringify(v);

export function serializeMapping(m: ModelMapping): string {
  let out = `{"requested_model":${s(m.requested_model)},"upstream_model":${s(m.upstream_model)},"protocol":${s(m.protocol)},"native_path":${s(m.native_path)}`;
  if (m.adapter !== null) out += `,"adapter":${s(m.adapter)}`;
  return `${out}}`;
}

/** `serde_json::to_string(&config)`. */
export function serializeEndpointConfig(c: EndpointConfig): string {
  let out = `{"name":${s(c.name)},"base_url":${s(c.base_url)},"mappings":[${c.mappings.map(serializeMapping).join(",")}],"capabilities":[${c.capabilities.map(s).join(",")}]`;
  if (c.auth !== "protocol_native") out += `,"auth":${s(c.auth)}`;
  if (c.prompt_overhead_tokens !== null) out += `,"prompt_overhead_tokens":${c.prompt_overhead_tokens}`;
  if (c.output_overhead_tokens !== null) out += `,"output_overhead_tokens":${c.output_overhead_tokens}`;
  if (c.cache_ttl_as_requested) out += `,"cache_ttl_as_requested":true`;
  // A lane endpoint's record is written for the lane kind only, in its declaration position after
  // `cache_ttl_as_requested` (@gray/control `endpointConfigValue`), so the fingerprint covers it as
  // the control side writes it.
  if (c.lane != null) out += `,"lane":${serializeLaneEndpoint(c.lane)}`;
  return `${out}}`;
}

const ENCODER = new TextEncoder();
const sha256Hex = (text: string) => bytesToHex(sha256(ENCODER.encode(text)));

/** ControlStore::config_fingerprint: hex SHA-256 of `serde_json::to_vec(&(config, generation))`. */
export function configFingerprint(c: EndpointConfig, generation: number): string {
  return sha256Hex(`[${serializeEndpointConfig(c)},${generation}]`);
}

/**
 * provider_offers::mapping_fingerprint: hex SHA-256 of the JSON array ("gray.offer-mapping.v1",
 * endpoint id, requested model, protocol, upstream model, native path, adapter or null).
 */
export function mappingFingerprint(endpointId: string, m: ModelMapping): string {
  return sha256Hex(JSON.stringify(["gray.offer-mapping.v1", endpointId, m.requested_model, m.protocol, m.upstream_model, m.native_path, m.adapter]));
}

/** ControlStore::endpoint_row: a control_endpoints row (config as stored JSON text) as a ProviderEndpoint. */
export function endpointRow(row: { id: string; workspace_id: string; owner_user_id: string; config: string; generation: number; enabled: number }): ProviderEndpoint {
  const config = parseEndpointConfig(parsePlain(row.config));
  return {
    id: row.id,
    workspace_id: row.workspace_id,
    owner_user_id: row.owner_user_id,
    config,
    credential_generation: row.generation,
    config_fingerprint: configFingerprint(config, row.generation),
    enabled: row.enabled !== 0,
  };
}

/** routing::provider_ref: the public pseudonym of a route, hex SHA-256 of `workspace:endpoint`. */
export function providerRef(workspaceId: string, endpointId: string): string {
  return sha256Hex(`${workspaceId}:${endpointId}`);
}

/** routing::supplier_ref: the public pseudonym of a supplier, hex SHA-256 of `supplier:workspace`. */
export function supplierRef(workspaceId: string): string {
  return sha256Hex(`supplier:${workspaceId}`);
}

/** routing::registered_refs: every reference naming a registered endpoint, published or not. */
export function registeredRefs(endpoints: Iterable<readonly [workspaceId: string, endpointId: string]>): Set<string> {
  const out = new Set<string>();
  for (const [w, e] of endpoints) {
    out.add(providerRef(w, e));
    out.add(supplierRef(w));
  }
  return out;
}

/** gray_media_adapters ADAPTERS and Vendor::for_adapter / supports, for `adapter_serves` (crates/gray-control/src/lib.rs). */
export function adapterServes(adapter: string, p: Protocol): boolean {
  const op = p === "open_ai_image_generations" ? "image_generation" : p === "open_ai_image_edits" ? "image_edit" : p === "open_ai_speech" ? "speech" : p === "open_ai_videos" ? "video_create" : null;
  if (op === null) return false;
  switch (adapter) {
    case "gemini":
      // Gemini's video operations are Veo's; image generation and edits are Imagen's; no speech.
      return op !== "speech";
    case "volcengine":
      return op !== "speech";
    case "minimax":
      return true;
    case "kling":
    case "fal":
      return op !== "speech";
    default:
      return false;
  }
}

/** Whether an image API is served through an adapter other than Gemini's, which reports image counts and no tokens (provider_offers::adapter_reports_image_counts). */
export function adapterReportsImageCounts(p: Protocol, adapter: string | null): boolean {
  if (p !== "open_ai_image_generations" && p !== "open_ai_image_edits") return false;
  return adapter !== null && adapter !== "gemini" && adapterServes(adapter, p);
}

/** ControlStore::validate_endpoint_shape: what a stored configuration must keep passing to be published. */
export function validEndpointShape(c: EndpointConfig): boolean {
  if (c.name.trim().length === 0 || utf8Bytes(c.base_url) > 2048 || !(c.base_url.startsWith("https://") || c.base_url.startsWith("http://"))) return false;
  if (/[@?#]/.test(c.base_url) || c.mappings.length === 0) return false;
  const seen = new Set<string>();
  for (const m of c.mappings) {
    if (m.requested_model.trim().length === 0 || m.requested_model === "*" || m.upstream_model.trim().length === 0) return false;
    if (!m.native_path.startsWith("/") || m.native_path.startsWith("//") || /[?#]/.test(m.native_path)) return false;
    if (m.adapter !== null && !adapterServes(m.adapter, m.protocol)) return false;
    const key = `${m.requested_model}\u0000${m.protocol}`;
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

function utf8Bytes(text: string): number {
  return ENCODER.encode(text).byteLength;
}
