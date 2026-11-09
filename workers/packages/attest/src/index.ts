/**
 * @gray/attest — the trust primitives of Gray's confidential lane, wire-compatible with the Attested
 * Confidential Inference (ACI) specification of Phala's Private AI Gateway (commit 578778a).
 *
 * - Canonical JSON (`canonical.ts`): the JCS form of an ACI document, enforced on the ACI subset
 *   (ASCII member names, numbers serde_json read as i64/u64) and byte-identical to PAG's
 *   `jcs_bytes`.
 * - Integer kinds (`integers.ts`): the one i64/u64 rule, shared with `@gray/lane`'s policy version.
 * - Digests (`digest.ts`): SHA-256 in the three encodings Appendix A names.
 * - Workload identity (`identity.ts`): the keyset, its digest, the §3.2 attestation statement and the
 *   64-byte `report_data` slot.
 * - The attestation report (`report.ts`): the bare object `GET /v1/aci/attestation` serves, its
 *   builder, its parser, and the §9.1 binding recomputation.
 * - Receipts (`receipt.ts`, `events.ts`): the §7 document, its event vocabulary, the builder that
 *   signs it, the verifier, Gray's `relay_policy.*` and `request.modified` extension events, and the
 *   relay-stack attempt events (plan S26) with their grammar.
 * - Debug sharing (`debug.ts`): the stack VM's signed share and the entry's signed grant of a request a customer
 *   authorized for debugging at its relay (docs/design/relay-debug-sharing.md).
 * - Relay-stack digests (`stack-hash.ts`): the `events_sha256` hash chain over S19 event digests and
 *   the `headers_sha256` line form.
 * - Reading served documents (`wire.ts` behind `parseReceiptText`, `parseKeysetText`,
 *   `parseAttestationReportText` and their `verify*Text` wrappers): a document read from HTTP text
 *   must go through these, never through `@gray/json`'s `parsePlain`, whose `number` integers the
 *   ACI schemas refuse.
 * - Streaming hashing (`stream-hash.ts`): a pass-through hashing stream for SSE responses whose
 *   `done` settles (resolves or rejects) on every stream path.
 * - The seams (`keys.ts`, `quote.ts`, `ed25519.ts`): the per-boot receipt key, the dstack guest agent
 *   quoter, and the workspace's Ed25519 helpers (moved here from `@gray/verifier`).
 *
 * Pure code: no `cloudflare:*` import, no I/O of its own, runs in Node and in workerd. Not in scope:
 * the HTTP server, DCAP quote verification, TLS, and the gateway integration.
 */
export * from "./canonical.ts";
export * from "./debug.ts";
export * from "./digest.ts";
export * from "./ed25519.ts";
export * from "./events.ts";
export * from "./identity.ts";
export * from "./integers.ts";
export * from "./keys.ts";
export * from "./quote.ts";
export * from "./receipt.ts";
export * from "./report.ts";
export * from "./stack-hash.ts";
export * from "./stream-hash.ts";
