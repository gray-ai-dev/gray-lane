/**
 * @gray/lane-wire: the wire contract of Gray's lane bridge (design v2 section D), shared by the two
 * sides of every bridge call — the gateway in the dstack CVM (`workers/gateway/src/lane/remote/`)
 * and the Cloudflare bridge Worker (`workers/lane-bridge`) — so neither can drift from the other.
 *
 * What is here:
 * - **Ops** (`ops.ts`): `account.admit|count|settle|release`, `endpoint.acquire|release|note|reserveRetry`,
 *   `snapshot.current`, `scheduler.forward`, `records.index|events|points|service_events`, `stack.config`,
 *   `stack.proxy_checks`, `stack.rules`, `stack.report`, `stack.tests`, `stack.debug_shares`, `stack.vault.get|put` (Gray's
 *   ciphertext copy of a VM's sealed records, stack-vault.ts), `release.lists`, `attest.collateral`, with
 *   `lane.acme_failed` and `ticket.use` (a model-check ticket's one-time id, ticket.ts), with their paths, methods and target addresses; a relay stack's account-health words are the closed lists of
 *   `stack-health.ts` (S34); the two background reads a lane VM verifies a peer with are `background.ts`'s.
 * - **The peer hop** (`peer.ts`): the entry's signed envelope to a relay's stack VM, the stack VM's `head`/`data`/`end`
 *   frames and refusals, and the late-facts answer (docs/confidential-lane-stack-routing.md section 4.5); `peer-debug.ts`
 *   is its debug hop (docs/design/relay-debug-sharing.md). Not a bridge
 *   op: both ends are lanes, and egress carries the bytes.
 * - **Documents** (`account.ts`, `endpoint.ts`, `snapshot.ts`, `records.ts`): zod schemas over
 *   `@gray/json`, every integer a `bigint` (ints.ts), written by `toJsonString` and read by
 *   `parseSerde`, and the converters to and from the Durable Object / gateway types (the only place
 *   a `bigint` and a JS `number` meet).
 * - **Signing** (`signing.ts`): the canonical string `gray-lane-bridge-v1` (domain, op, target,
 *   method, path, timestamp, nonce, body SHA-256), Ed25519 through `@gray/attest`, the header family,
 *   the timestamp window and nonce rule as documented constants, and the in-memory replay window
 *   the bridge's durable nonce table must match.
 * - **The read rule** (`wire.ts`): a body that is too large, not UTF-8, not JSON or not the op's
 *   document **throws** (`BridgeWireError`); only a well-formed answer becomes a result (B6).
 * - **The lane's closed records** (`allow.ts`): `ReleaseInput.detail` and `SettleInput.meta` as
 *   allow-lists, with projections that drop everything else before a document leaves the CVM (M13).
 *
 * Pure code: no `cloudflare:*` import, no I/O, no clock, no randomness beyond `bridgeNonce`'s own
 * argument. It runs in Node and in workerd. `IMPLEMENTATION_NOTES.md` records the decisions, the
 * deviations from design v1 and what is not done.
 */

export * from "./error.ts";
export * from "./ints.ts";
export * from "./ops.ts";
export * from "./signing.ts";
export * from "./nonce-objects.ts";
export * from "./allow.ts";
export * from "./account.ts";
export * from "./endpoint.ts";
export * from "./snapshot.ts";
export * from "./scheduler.ts";
export * from "./records.ts";
export * from "./stack.ts";
export * from "./stack-health.ts";
export * from "./stack-rules.ts";
export * from "./stack-report.ts";
export * from "./stack-tests.ts";
export * from "./stack-debug.ts";
export * from "./stack-vault.ts";
export * from "./stack-trace.ts";
export * from "./background.ts";
export * from "./lane-acme.ts";
export * from "./ticket.ts";
export * from "./peer.ts";
export * from "./peer-debug.ts";
export * from "./wire.ts";
