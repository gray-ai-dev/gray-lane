import { createScanner } from "jsonc-parser";
import { parsePlain } from "@gray/json";
import { configFingerprint, parseEndpointConfig, parseVerification, validEndpointShape, type ProviderEndpoint, type VerificationRecord } from "./control.ts";

/**
 * A provider workspace's signed snapshot (control_snapshots, gray_control::SignedSnapshot): the
 * endpoints and verifications an administrator published, signed with Ed25519. The server's
 * refresh serves only endpoints present in a valid one (`recover_snapshots`), so a row written to
 * the database alone publishes nothing.
 *
 * The server verifies the signature over `serde_json::to_vec(&payload)`, the payload re-serialized.
 * The stored text is `serde_json::to_string(&signed)`, so the payload's bytes in it are those same
 * bytes; this module verifies over them as stored, read with jsonc-parser's scanner (the tokenizer
 * @gray/json uses), and never re-serializes. A payload stored in any other form does not verify.
 *
 * Ed25519 is WebCrypto's (workerd and Node both have it). Trusted keys come from the secret
 * SNAPSHOT_VERIFYING_KEYS, `kid:base64(32-byte public key)[,kid:...]`: the server's key is
 * `local-v1`, derived from the master key (crates/gray-gateway/src/config/mod.rs
 * `snapshot_signing_key`); the jobs Worker gets only the public half.
 */

export interface SnapshotPayload {
  readonly workspace_id: string;
  readonly sequence: number;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly endpoints: readonly ProviderEndpoint[];
  readonly verifications: readonly VerificationRecord[];
}

export type VerifyingKeys = ReadonlyMap<string, CryptoKey>;

const ENCODER = new TextEncoder();
const I64_MAX = 9_223_372_036_854_775_807n;

/** Parses SNAPSHOT_VERIFYING_KEYS. Throws on a malformed entry or a key that is not 32 bytes. */
export async function parseVerifyingKeys(spec: string): Promise<VerifyingKeys> {
  const keys = new Map<string, CryptoKey>();
  for (const entry of spec.split(",").map((e) => e.trim()).filter((e) => e.length > 0)) {
    const at = entry.indexOf(":");
    if (at <= 0) throw new RangeError("SNAPSHOT_VERIFYING_KEYS: each entry is kid:base64");
    const kid = entry.slice(0, at);
    const raw = Uint8Array.from(atob(entry.slice(at + 1)), (c) => c.charCodeAt(0));
    if (raw.byteLength !== 32) throw new RangeError(`SNAPSHOT_VERIFYING_KEYS: key ${kid} is not 32 bytes`);
    if (keys.has(kid)) throw new RangeError(`SNAPSHOT_VERIFYING_KEYS: key ${kid} appears twice`);
    keys.set(kid, await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]));
  }
  return keys;
}

// jsonc-parser's SyntaxKind values (an ambient const enum, which isolatedModules cannot read).
const OPEN_BRACE = 1;
const CLOSE_BRACE = 2;
const OPEN_BRACKET = 3;
const CLOSE_BRACKET = 4;
const COMMA = 5;
const COLON = 6;
const STRING = 10;
const EOF = 17;

/** The `payload` member of the stored signed snapshot, as its exact text; null when the top-level object has none (or it is not an object). */
export function payloadText(signed: string): string | null {
  const scanner = createScanner(signed, true);
  let depth = 0;
  /** The previous token inside the top-level object, at its own level. */
  let prev = 0;
  let key: string | null = null;
  let afterColon = false;
  let start = -1;
  for (;;) {
    const t: number = scanner.scan();
    if (t === EOF) return null;
    const level = depth;
    if (level === 1 && afterColon) {
      afterColon = false;
      if (key === "payload" && start < 0) {
        if (t !== OPEN_BRACE) return null;
        start = scanner.getTokenOffset();
      }
    }
    if (t === OPEN_BRACE || t === OPEN_BRACKET) {
      if (level <= 1) prev = t;
      depth++;
      continue;
    }
    if (t === CLOSE_BRACE || t === CLOSE_BRACKET) {
      depth--;
      if (depth === 1) {
        prev = t;
        if (start >= 0) return signed.slice(start, scanner.getTokenOffset() + scanner.getTokenLength());
      }
      continue;
    }
    if (level === 1) {
      if (t === STRING && (prev === OPEN_BRACE || prev === COMMA)) key = scanner.getTokenValue();
      if (t === COLON) afterColon = true;
      prev = t;
    }
  }
}

function endpointOf(v: unknown): ProviderEndpoint {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new RangeError("endpoint must be an object");
  const o = v as Record<string, unknown>;
  const gen = o.credential_generation;
  if (typeof o.id !== "string" || typeof o.workspace_id !== "string" || typeof o.owner_user_id !== "string" || typeof o.config_fingerprint !== "string" || typeof o.enabled !== "boolean") {
    throw new RangeError("endpoint fields");
  }
  if (typeof gen !== "number" || !Number.isSafeInteger(gen) || gen < 0) throw new RangeError("endpoint generation");
  return { id: o.id, workspace_id: o.workspace_id, owner_user_id: o.owner_user_id, config: parseEndpointConfig(o.config), credential_generation: gen, config_fingerprint: o.config_fingerprint, enabled: o.enabled };
}

function integer(v: unknown): bigint | null {
  return typeof v === "number" && Number.isSafeInteger(v) ? BigInt(v) : null;
}

/** `ControlStore::validate_snapshot`. */
export function validSnapshot(p: SnapshotPayload): boolean {
  if (p.workspace_id.length === 0) return false;
  const ids = new Set<string>();
  for (const e of p.endpoints) {
    if (e.workspace_id !== p.workspace_id || ids.has(e.id) || e.credential_generation === 0) return false;
    ids.add(e.id);
    if (e.config_fingerprint !== configFingerprint(e.config, e.credential_generation) || !validEndpointShape(e.config)) return false;
  }
  for (const v of p.verifications) {
    const e = p.endpoints.find((x) => x.id === v.endpoint_id);
    if (!e) return false;
    if (v.credential_generation !== e.credential_generation || v.config_fingerprint !== e.config_fingerprint || v.expires_at <= v.checked_at) return false;
    if (!e.config.mappings.some((m) => m.requested_model === v.model && m.protocol === v.protocol)) return false;
  }
  return true;
}

/**
 * `ControlStore::recovered`: the stored snapshot of `workspace` if it verifies (a trusted key, a
 * valid signature, a sequence above 0, issued at most 60 s ahead of `nowSeconds`, not expired),
 * passes `validate_snapshot` and is for the workspace and sequence it is stored under; else null.
 */
export async function recoverSnapshot(workspace: string, signed: string, sequence: number, keys: VerifyingKeys, nowSeconds: number): Promise<SnapshotPayload | null> {
  let outer: unknown;
  try {
    outer = parsePlain(signed);
  } catch {
    return null;
  }
  if (outer === null || typeof outer !== "object") return null;
  const o = outer as Record<string, unknown>;
  const key = typeof o.key_id === "string" ? keys.get(o.key_id) : undefined;
  const signature = o.signature;
  if (!key || !Array.isArray(signature) || signature.length !== 64 || signature.some((b) => typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255)) return null;
  const text = payloadText(signed);
  if (text === null) return null;
  const valid = await crypto.subtle.verify("Ed25519", key, Uint8Array.from(signature as number[]), ENCODER.encode(text));
  if (!valid) return null;
  let payload: SnapshotPayload;
  try {
    const p = parsePlain(text) as Record<string, unknown>;
    const seq = integer(p.sequence);
    const issued = integer(p.issued_at);
    const expires = integer(p.expires_at);
    if (typeof p.workspace_id !== "string" || seq === null || issued === null || expires === null || !Array.isArray(p.endpoints) || !Array.isArray(p.verifications)) return null;
    if (seq === 0n || seq > I64_MAX || issued > BigInt(nowSeconds) + 60n || expires <= BigInt(nowSeconds) || expires <= issued) return null;
    payload = {
      workspace_id: p.workspace_id,
      sequence: Number(seq),
      issued_at: Number(issued),
      expires_at: Number(expires),
      endpoints: p.endpoints.map(endpointOf),
      verifications: p.verifications.map(parseVerification),
    };
  } catch {
    return null;
  }
  if (!validSnapshot(payload)) return null;
  if (payload.workspace_id !== workspace || payload.sequence !== sequence) return null;
  return payload;
}
