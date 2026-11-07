/**
 * What a relay submits, and what its signature covers.
 *
 * A bundle is `{relay_id, version, module, templates, signature}`. The signature is Ed25519 by the
 * relay's registered key over the ACI canonical JSON (JCS) of
 *
 *     {"relay_id":…,"version":7,"module_sha256":"…","templates_sha256":"…"}
 *
 * where `module_sha256` is SHA-256 of the uploaded bytes and `templates_sha256` is SHA-256 of the
 * canonical JSON of the registry entries. Why a signature at all: sealing the upload to an attested
 * key gives confidentiality, not origin authentication (review.md §2.7, item 2 — dstack's envelope
 * is explicitly confidentiality-only, and anyone with VMM access can substitute the ciphertext). The
 * signature is what says "this is the relay's module", and it is checked here, inside the TEE,
 * against a key that the relay registered and Gray pinned.
 *
 * The template digest is taken over a canonical form, not over the submitted JSON: the entries are
 * sorted by id, `positions` and `protocols` are sorted, and every value is what @gray/lane's
 * registry would hold. A registry is a set, so two submissions that differ only in the order the
 * relay wrote its arrays are the same policy and sign the same bytes — and there is one canonical
 * form for the relay to sign and for the host to verify, published here as {@link templateDigest}.
 *
 * Transport is not this package's job: how the bundle reaches the TEE (encrypted to an attested key)
 * belongs to the intake package. This one takes bytes and a signature.
 */
import { ed25519Verify, jcsBytes } from "@gray/attest";
import { compareUtf8, type Json } from "@gray/json";
import { createTemplateRegistry, refusal, sha256Hex, type Refusal, type RelayTemplate } from "@gray/lane";

/** A relay's submission: the module, the templates it may append, and the relay's signature. */
export interface RelayPolicyBundle {
  readonly relayId: string;
  readonly version: bigint;
  readonly moduleBytes: Uint8Array;
  readonly templates: readonly RelayTemplate[];
  /** 64 bytes: RFC 8032 Ed25519 over {@link policyClaimBytes}. */
  readonly signature: Uint8Array;
}

/** The signed statement: everything a receipt's policy fields rest on. */
export interface PolicyClaim {
  readonly relay_id: string;
  readonly version: bigint;
  readonly module_sha256: string;
  readonly templates_sha256: string;
}

/** The largest version a bundle may carry: the u64 `preparePolicy` enforces. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Why a bundle is refused before anything loads it. */
export type BundleRefusalCode = "invalid_bundle" | "invalid_signature" | "invalid_templates" | "invalid_module";

/** The canonical JSON of a template registry: the array a digest is taken over. */
export function canonicalTemplates(templates: readonly RelayTemplate[]): Json {
  return [...templates]
    .sort((left, right) => compareUtf8(left.id, right.id))
    .map(
      (template): Json => ({
        id: template.id,
        text: template.text,
        positions: [...template.positions].sort(compareUtf8),
        protocols: [...template.protocols].sort(compareUtf8),
        maxTextBytes: BigInt(template.maxTextBytes),
      }),
    );
}

/**
 * SHA-256 of the canonical JSON of `templates`: the `templates_sha256` a relay signs and the host
 * recomputes. A template whose text holds a lone surrogate is not canonicalizable (it has no UTF-8
 * bytes) and is refused.
 */
export function templateDigest(
  templates: readonly RelayTemplate[],
): { readonly ok: true; readonly sha256: string } | Refusal<BundleRefusalCode> {
  for (const template of templates) {
    if (typeof template?.text !== "string" || !template.text.isWellFormed()) {
      return refusal("invalid_templates", "a template's text is not well-formed UTF-16");
    }
    if (typeof template.id !== "string" || template.id.length === 0) {
      return refusal("invalid_templates", "a template has no id");
    }
  }
  try {
    return { ok: true, sha256: sha256Hex(jcsBytes(canonicalTemplates(templates))) };
  } catch {
    return refusal("invalid_templates", "the templates are not ACI-canonicalizable");
  }
}

/** The claim a bundle's signature covers, computed from the bundle's own bytes. */
export function policyClaim(bundle: {
  readonly relayId: string;
  readonly version: bigint;
  readonly moduleBytes: Uint8Array;
  readonly templates: readonly RelayTemplate[];
}): { readonly ok: true; readonly claim: PolicyClaim } | Refusal<BundleRefusalCode> {
  if (typeof bundle.relayId !== "string" || bundle.relayId.length === 0) {
    return refusal("invalid_bundle", "the bundle has no relay id");
  }
  // The u64 bound is enforced here, where the version is signed, not only at `preparePolicy`: a
  // version outside u64 canonicalises to bytes a receipt cannot carry and a store cannot accept.
  if (typeof bundle.version !== "bigint" || bundle.version < 0n || bundle.version > U64_MAX) {
    return refusal("invalid_bundle", "the bundle's version is not a u64");
  }
  if (!(bundle.moduleBytes instanceof Uint8Array) || bundle.moduleBytes.length === 0) {
    return refusal("invalid_module", "the bundle holds no module bytes");
  }
  if (!Array.isArray(bundle.templates)) return refusal("invalid_templates", "the bundle's templates are not an array");
  const digest = templateDigest(bundle.templates);
  if (!digest.ok) return digest;
  return {
    ok: true,
    claim: {
      relay_id: bundle.relayId,
      version: bundle.version,
      module_sha256: sha256Hex(bundle.moduleBytes),
      templates_sha256: digest.sha256,
    },
  };
}

/** The signature preimage: the claim as ACI canonical JSON, which is what a relay signs. */
export function policyClaimBytes(claim: PolicyClaim): Uint8Array {
  return jcsBytes({
    relay_id: claim.relay_id,
    version: claim.version,
    module_sha256: claim.module_sha256,
    templates_sha256: claim.templates_sha256,
  });
}

/**
 * The claim bytes, as a refusal rather than a throw: `jcsBytes` throws on a value outside its
 * integer range, and a `PolicyClaim` built by hand (rather than by {@link policyClaim}, which
 * bounds the version to u64) can hold one. Verification wraps the canonicalisation in this so a
 * malformed claim can never escape the bundle API as an exception (VERIFY RP-8).
 */
function claimBytes(claim: PolicyClaim): { readonly ok: true; readonly bytes: Uint8Array } | Refusal<BundleRefusalCode> {
  try {
    return { ok: true, bytes: policyClaimBytes(claim) };
  } catch {
    return refusal("invalid_bundle", "the claim is not ACI-canonicalizable");
  }
}

/**
 * Check a bundle's signature against the relay's registered public key. The claim is recomputed from
 * the bytes being submitted, so a signature cannot describe a different module or a different set of
 * templates than the ones that will be stored.
 */
export async function verifyPolicyBundle(
  bundle: RelayPolicyBundle,
  relayPublicKey: Uint8Array,
): Promise<{ readonly ok: true; readonly claim: PolicyClaim } | Refusal<BundleRefusalCode>> {
  const claimed = policyClaim(bundle);
  if (!claimed.ok) return claimed;
  // The signature must be spent on a registry the lane could actually build: a bundle whose
  // templates `createTemplateRegistry` refuses can never become a policy, so it is refused here
  // rather than being verified authentic and failing later (VERIFY RP-9).
  const registry = createTemplateRegistry(bundle.templates);
  if (!registry.ok) return refusal("invalid_templates", registry.detail);
  if (!(bundle.signature instanceof Uint8Array) || bundle.signature.length !== 64) {
    return refusal("invalid_signature", "the bundle's signature is not 64 bytes");
  }
  if (!(relayPublicKey instanceof Uint8Array) || relayPublicKey.length !== 32) {
    return refusal("invalid_signature", "the relay's public key is not 32 bytes");
  }
  const preimage = claimBytes(claimed.claim);
  if (!preimage.ok) return preimage;
  let verified = false;
  try {
    verified = await ed25519Verify(relayPublicKey, preimage.bytes, bundle.signature);
  } catch {
    verified = false;
  }
  if (!verified) return refusal("invalid_signature", "the bundle's signature does not verify against the relay's key");
  return { ok: true, claim: claimed.claim };
}
