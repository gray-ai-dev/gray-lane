import { parseSerde, toJsonString, type Json } from "@gray/json";
import { createTemplateRegistry, isLaneProtocol, isPosition, type LaneProtocol, type Position, type RelayTemplate } from "@gray/lane";
import { canonicalTemplates, policyClaim, type RelayPolicyBundle } from "@gray/relay-policy";
import { readRefreshedRequest, RELAY_INTAKE_MAX_BODY_BYTES, sealRefreshedAnswer, type RefreshedRequest, type RefreshedToken } from "@gray/relay-connector";
import { z } from "zod";
import type { LaneProcessState } from "./state.ts";

/**
 * The two intake routes of the lane (design v2 section C.1), whose paths are `@gray/relay-kit`'s
 * `LANE_ENDPOINTS` (the relay-side tooling and the TEE must agree on one spelling):
 *
 * - `POST /v1/aci/relay-credentials`: one sealed credential message
 *   (`@gray/relay-connector`'s `sealedCredentialValue`), opened by the boot's
 *   `RelayCredentialStore`. The message is the relay's secret-bearing document and is never logged;
 *   the answer names the outcome, never the input.
 * - `POST /v1/aci/relay-policy/bundle`: one signed policy bundle (the `@gray/relay-kit`
 *   `policyBundleValue` document: base64 module, canonical templates, hex signature), verified
 *   against the relay's registered key and prepared by `@gray/relay-policy`'s store.
 *
 * Both are **refusals, not errors**: a malformed or unauthenticated message is a 400/403 naming a
 * closed code, because a relay's tooling can act on a code and a 500 cannot. Neither route needs a
 * Gray customer key: they are the relay's, authenticated by the relay's own Ed25519 signature inside
 * the document (the credential message under HPKE, the bundle over its claim). That is also why they
 * carry no receipt (M21).
 */

export const RELAY_CREDENTIALS_PATH = "/v1/aci/relay-credentials";
/**
 * The write-back of in-VM refresh (docs/relay-changes-v2.md §6): gray-relay asks for the tokens egress refreshed with
 * a request signed by the relay's key, and gets them sealed to the reply key it named (`@gray/relay-connector`
 * refreshed.ts), to write to the relay's account source (`PUT …/credential`).
 */
export const RELAY_REFRESHED_PATH = "/v1/aci/relay-credentials/refreshed";
export const RELAY_POLICY_BUNDLE_PATH = "/v1/aci/relay-policy/bundle";
/** The registry GET, by relay id (`/v1/aci/relay-policy/{relay_id}`, M22). */
export const RELAY_POLICY_PREFIX = "/v1/aci/relay-policy/";

/** The closed intake refusals, with the status they answer. */
export type IntakeRefusal = { readonly status: number; readonly code: string; readonly detail: string };

/** The relay-kit bundle document's version tag (`@gray/relay-kit` `POLICY_BUNDLE_API_VERSION`). */
export const POLICY_BUNDLE_API_VERSION = "gray.relay-kit/relay-policy-bundle/1";

/**
 * The largest intake body either POST route reads: a policy bundle of a 4 MiB module in base64. It is
 * `@gray/relay-connector`'s `RELAY_INTAKE_MAX_BODY_BYTES`, the same 6 MiB the sealed-credential
 * envelope bounds are derived from (FV D34, D84), so the two caps cannot drift apart.
 */
export const INTAKE_MAX_BYTES = RELAY_INTAKE_MAX_BODY_BYTES;

const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const LOWER_HEX_32 = /^[0-9a-f]{64}$/;
const LOWER_HEX_64 = /^[0-9a-f]{128}$/;

/** The bundle document a relay posts, as `@gray/relay-kit` `policyBundleValue` writes it. */
const bundleSchema = z
  .object({
    api_version: z.literal(POLICY_BUNDLE_API_VERSION),
    relay_id: z.string().regex(RELAY_ID),
    // relay-kit writes the version as a `bigint`; `parseSerde` reads an integer back as one.
    version: z.bigint().min(0n),
    module: z.string().min(1),
    module_sha256: z.string().regex(LOWER_HEX_32),
    templates_sha256: z.string().regex(LOWER_HEX_32),
    templates: z.array(z.unknown()),
    signature: z.string().regex(LOWER_HEX_64),
  })
  .strict();

/** One template entry of a bundle, as relay-kit writes it (`canonicalTemplates`). */
const templateSchema = z
  .object({
    id: z.string().min(1).max(128),
    text: z.string(),
    positions: z.array(z.string()).min(1),
    protocols: z.array(z.string()).min(1),
    maxTextBytes: z.union([z.number().int().positive(), z.bigint().positive()]),
  })
  .strict();

/** The result of reading a bundle document: the typed bundle or a refusal. */
export type BundleRead = { readonly ok: true; readonly bundle: RelayPolicyBundle } | { readonly ok: false; readonly refusal: IntakeRefusal };

/**
 * Read a `@gray/relay-kit` policy bundle document into the `@gray/relay-policy` bundle the TEE
 * verifies. The two digests are recomputed and checked against the document, so a relay cannot post
 * a signature over another module than the one in the body; the templates go through the lane's own
 * registry rules, so the TEE cannot hold a registry the module could not select from.
 */
export function readPolicyBundle(value: Json): BundleRead {
  const parsed = bundleSchema.safeParse(value);
  if (!parsed.success) return refuse(400, "invalid_policy_bundle", "the document is not a signed policy bundle");
  const moduleBytes = base64Bytes(parsed.data.module);
  if (moduleBytes === null || moduleBytes.length === 0) return refuse(400, "invalid_policy_bundle", "module");
  const templates = readTemplates(parsed.data.templates);
  if (!templates.ok) return templates;
  const claim = policyClaim({ relayId: parsed.data.relay_id, version: parsed.data.version, moduleBytes, templates: templates.templates });
  if (!claim.ok) return refuse(400, "invalid_policy_bundle", claim.code);
  if (claim.claim.module_sha256 !== parsed.data.module_sha256 || claim.claim.templates_sha256 !== parsed.data.templates_sha256) {
    return refuse(400, "invalid_policy_bundle", "the digests do not describe the module and templates");
  }
  const signature = hexBytes(parsed.data.signature, 64);
  if (signature === null) return refuse(400, "invalid_policy_bundle", "signature");
  return { ok: true, bundle: { relayId: parsed.data.relay_id, version: parsed.data.version, moduleBytes, templates: templates.templates, signature } };
}

function readTemplates(entries: readonly unknown[]): { readonly ok: true; readonly templates: readonly RelayTemplate[] } | { readonly ok: false; readonly refusal: IntakeRefusal } {
  const templates: RelayTemplate[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const parsed = templateSchema.safeParse(entries[index]);
    if (!parsed.success) return refuse(400, "invalid_policy_bundle", `templates.${index}`);
    const positions: Position[] = [];
    for (const position of parsed.data.positions) {
      if (!isPosition(position)) return refuse(400, "invalid_policy_bundle", `templates.${index}.positions`);
      positions.push(position);
    }
    const protocols: LaneProtocol[] = [];
    for (const protocol of parsed.data.protocols) {
      if (!isLaneProtocol(protocol)) return refuse(400, "invalid_policy_bundle", `templates.${index}.protocols`);
      protocols.push(protocol);
    }
    const maxTextBytes = typeof parsed.data.maxTextBytes === "bigint" ? parsed.data.maxTextBytes : BigInt(parsed.data.maxTextBytes);
    if (maxTextBytes > BigInt(Number.MAX_SAFE_INTEGER)) return refuse(400, "invalid_policy_bundle", `templates.${index}.maxTextBytes`);
    templates.push({ id: parsed.data.id, text: parsed.data.text, positions, protocols, maxTextBytes: Number(maxTextBytes) });
  }
  // The semantic rules live in @gray/lane, so this parser cannot disagree with the module's registry.
  const registry = createTemplateRegistry(templates);
  if (!registry.ok) return refuse(400, "invalid_policy_bundle", registry.code);
  return { ok: true, templates: registry.templates };
}

/** What the JSON body of a POST route is, or a refusal (empty, not JSON, over the cap). */
export function readJsonBody(text: string, maxBytes: number): { readonly ok: true; readonly value: Json } | { readonly ok: false; readonly refusal: IntakeRefusal } {
  // The cap is bytes (the constant's name and its callers say so), so measure the UTF-8 form, never
  // the JavaScript string's length: a body of multibyte characters is up to 4x its code-unit count
  // (entry-3/F-07).
  if (new TextEncoder().encode(text).byteLength > maxBytes) return refuse(413, "body_too_large", "the intake body is over the cap");
  try {
    return { ok: true, value: parseSerde(text) };
  } catch {
    return refuse(400, "invalid_body", "the body is not JSON");
  }
}

/** The `POST /v1/aci/relay-credentials` result: what the store said, never the input. */
export type CredentialIntake =
  | { readonly ok: true; readonly relayId: string; readonly version: bigint; readonly kind: string; readonly accounts: number }
  | { readonly ok: false; readonly refusal: IntakeRefusal };

/**
 * Apply one sealed credential message (`RelayCredentialStore.applySealed`). The store returns a
 * closed code and never a credential; the answer is the code and, on success, what became of the
 * relay's pool (its version and size, which its operator already knows).
 */
export async function applyCredentialMessage(state: LaneProcessState, value: Json, nowMs: number): Promise<CredentialIntake> {
  const applied = await state.credentials.applySealed(value, nowMs);
  if (!applied.ok) return { ok: false, refusal: { status: 400, code: applied.code, detail: applied.path ?? "the message was refused" } };
  return { ok: true, relayId: applied.relay_id, version: applied.version, kind: applied.kind, accounts: applied.accounts };
}

/**
 * Accept one signed policy bundle: verify the relay's signature and prepare the module (§C.5, M22).
 * A relay whose key the registry does not hold is refused without touching the store.
 */
export async function acceptPolicyBundle(
  state: LaneProcessState,
  bundle: RelayPolicyBundle,
): Promise<{ readonly ok: true; readonly version: bigint; readonly moduleSha256: string } | { readonly ok: false; readonly refusal: IntakeRefusal }> {
  const relay = state.registry.get(bundle.relayId);
  if (relay === undefined) return { ok: false, refusal: { status: 403, code: "unknown_relay", detail: "the relay is not in this boot's registry" } };
  const key = hexBytes(relay.signingPublicKey, 32);
  if (key === null) return { ok: false, refusal: { status: 503, code: "relay_key_invalid", detail: "the registry's relay key is not 32 bytes of hex" } };
  const accepted = await state.policies.accept(bundle, key);
  // A relay that leaves the registry while its bundle is in flight is the same refusal the pre-check
  // answers (403 unknown_relay), not a malformed document (F2 entry-6/G2 open question).
  if (!accepted.ok) return { ok: false, refusal: { status: accepted.code === "unknown_relay" ? 403 : 400, code: accepted.code, detail: accepted.detail } };
  return { ok: true, version: accepted.record.policy.version, moduleSha256: accepted.record.policy.moduleSha256 };
}

/**
 * The `GET /v1/aci/relay-policy/{relay_id}` document (M22): the signed bundle metadata and the
 * template texts this CVM accepted, so a customer can run the strongest receipt check (receipt-5
 * needs the texts whose SHA-256 the receipt names).
 *
 * What is served is the **accepted** bundle's own content: the module digest and version the relay
 * signed, and the canonical templates. The canonical form is what the signature covers, so a
 * customer can recompute `templates_sha256` and re-verify the relay's signature with the relay's
 * registered key, and the receipt's `module_sha256`/`policy_version` then name exactly this
 * document. Nothing secret is here: a template is text the relay chose to append.
 */
export function policyRegistryDocument(state: LaneProcessState, relayId: string): Record<string, unknown> | null {
  const record = state.policies.get(relayId);
  if (record === undefined) return null;
  const claim = policyClaim({ relayId, version: record.policy.version, moduleBytes: record.policy.moduleBytes, templates: record.policy.registry.templates });
  if (!claim.ok) return null;
  return {
    relay_id: relayId,
    version: record.policy.version,
    module_sha256: record.policy.moduleSha256,
    templates_sha256: claim.claim.templates_sha256,
    templates: canonicalTemplates(record.policy.registry.templates),
  };
}

/**
 * `POST /v1/aci/relay-credentials/refreshed`: the signed request checked against the registry's relay key, then the
 * tokens not yet written back, sealed to the request's reply key. The answer is ciphertext only; nothing of a token
 * is logged or answered in the clear.
 */
export async function answerRefreshed(
  state: LaneProcessState,
  value: Json,
  nowMs: number,
  tokensFor: (request: RefreshedRequest) => readonly RefreshedToken[],
): Promise<{ readonly ok: true; readonly answer: Record<string, unknown>; readonly tokens: number } | { readonly ok: false; readonly refusal: IntakeRefusal }> {
  const read = await readRefreshedRequest(
    value,
    (relayId) => {
      const relay = state.registry.get(relayId);
      return relay === undefined ? null : hexBytes(relay.signingPublicKey, 32);
    },
    Math.floor(nowMs / 1000),
  );
  if (!read.ok) {
    const status = read.code === "unknown_relay" || read.code === "bad_signature" ? 403 : 400;
    return { ok: false, refusal: { status, code: read.code, detail: "the request was refused" } };
  }
  const tokens = tokensFor(read.request);
  return { ok: true, answer: await sealRefreshedAnswer(read.request, tokens), tokens: tokens.length };
}

/** The response body of a refusal: the closed code and a fixed detail, never the input. */
export function refusalBody(refusal: IntakeRefusal): string {
  return toJsonString({ error: { code: refusal.code, message: refusal.detail } });
}

function refuse(status: number, code: string, detail: string): { readonly ok: false; readonly refusal: IntakeRefusal } {
  return { ok: false, refusal: { status, code, detail } };
}

/** Strict base64 (the standard alphabet, padding optional): the relay-kit module encoding. */
export function base64Bytes(text: string): Uint8Array | null {
  const trimmed = text.replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(trimmed) || trimmed.length % 4 === 1) return null;
  const padded = trimmed + "=".repeat((4 - (trimmed.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return null;
  }
}

/** Lowercase hex to bytes, or null when it is not exactly `length` bytes of hex. */
export function hexBytes(text: string, length: number): Uint8Array | null {
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`).test(text)) return null;
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}
