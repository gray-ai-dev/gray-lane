import { parseSerde, toJsonString, type Json } from "@gray/json";
import { z } from "zod";
import { admitInputSchema, admitResultSchema, countInputSchema, countResultSchema, releaseInputSchema, releaseResultSchema, settleInputSchema, settleResultSchema } from "./account.ts";
import { attestCollateralAnswerSchema, attestCollateralRequestSchema, releaseListsAnswerSchema, releaseListsRequestSchema } from "./background.ts";
import { acquireInputSchema, acquireResultSchema, emptyAnswerSchema, endpointReleaseInputSchema, endpointReleaseResultSchema, noteInputSchema, probeAnsweredInputSchema, retryReleaseInputSchema, retryReserveInputSchema, retryReserveResultSchema, warmInputSchema, warmResultSchema } from "./endpoint.ts";
import { BridgeWireError } from "./error.ts";
import { laneAcmeFailedAnswerSchema, laneAcmeFailedSchema } from "./lane-acme.ts";
import { BRIDGE_METHODS, type BridgeOp } from "./ops.ts";
import { laneEventsSchema, laneIndexMessageSchema, lanePointsSchema, laneServiceEventsSchema, recordsAcceptedSchema } from "./records.ts";
import { SCHEDULER_FORWARD_REQUEST_MAX_BYTES, schedulerForwardAnswerSchema, schedulerForwardRequestSchema, schedulerForwardRequestV1Schema } from "./scheduler.ts";
import type { LaneBridgeApiVersion } from "./signing.ts";
import { SNAPSHOT_RESPONSE_MAX_BYTES, snapshotAnswerSchema, snapshotCurrentRequestSchema } from "./snapshot.ts";
import { stackConfigAnswerSchema, stackConfigRequestSchema, stackProxyChecksAnswerSchema, stackProxyChecksRequestSchema } from "./stack.ts";
import { stackDebugSharesAnswerSchema, stackDebugSharesRequestSchema } from "./stack-debug.ts";
import { stackInstanceAnswerSchema, stackInstanceRequestSchema } from "./stack-instance.ts";
import {
  STACK_VAULT_PUT_MAX_BYTES,
  STACK_VAULT_SHARE_MAX_BYTES,
  stackVaultGetAnswerSchema,
  stackVaultGetRequestSchema,
  stackVaultPutAnswerSchema,
  stackVaultPutRequestSchema,
  stackVaultShareAnswerSchema,
  stackVaultShareNonceAnswerSchema,
  stackVaultShareNonceRequestSchema,
  stackVaultShareRequestSchema,
} from "./stack-vault.ts";
import { STACK_REPORT_MAX_BYTES, stackReportAnswerSchema, stackReportSchema } from "./stack-report.ts";
import { stackRulesAnswerSchema, stackRulesRequestSchema } from "./stack-rules.ts";
import { stackTestsAnswerSchema, stackTestsRequestSchema } from "./stack-tests.ts";
import { ticketUseAnswerSchema, ticketUseInputSchema } from "./ticket.ts";

/**
 * The op → document registry, and the one way a document crosses the wire: written by
 * `@gray/json`'s `toJsonString`, read by its serde reader, then checked by the op's zod schema.
 *
 * The read rule is design v2 section D's error table (B6): a transport failure, a timeout, a
 * non-2xx, a body that is not JSON or a body that is not the op's document is a **throw**. Only a
 * well-formed answer becomes a result, so the account and endpoint callers keep the branches they
 * take for a failed Durable Object call (retry, in-doubt, release). The throw is a
 * `BridgeWireError`; a caller maps its `code` to its own log line, never to a refund decision.
 *
 * The GET op (`snapshot.current`) signs an empty body and carries its request in the query; its
 * request document is the parsed query (`snapshotCurrentRequestOf`), and `encodeBridgeRequest`
 * returns no bytes for it.
 */

/** The largest request body a records op carries. The snapshot read has none; the records are the large ones. */
export const BRIDGE_REQUEST_MAX_BYTES = 8 * 1024 * 1024;
/**
 * The largest request body an account or endpoint op carries (bridge-13): their documents are a few
 * KB (a hold token, a permit, a retry ticket), so the bridge reads no more than this before the
 * signature is checked. The records ops keep `BRIDGE_REQUEST_MAX_BYTES`.
 */
export const BRIDGE_SMALL_REQUEST_MAX_BYTES = 64 * 1024;

/**
 * The request body bound of `op`: the records ops are the large ones; `scheduler.forward` has its
 * own bound (a report batch, base64-expanded, which is below the records' 8 MiB and above the small
 * ops' 64 KiB); `stack.report` has S42's 1 MiB (a relay's 1000 accounts); `stack.vault.put` carries a sealed
 * record of up to 1 MiB (`STACK_VAULT_PUT_MAX_BYTES`); `stack.vault.share` a TDX quote and its event log
 * (`STACK_VAULT_SHARE_MAX_BYTES`); every other op's document is a few KB.
 */
export function bridgeRequestMaxBytes(op: BridgeOp): number {
  if (op === "scheduler.forward") return SCHEDULER_FORWARD_REQUEST_MAX_BYTES;
  if (op === "stack.report") return STACK_REPORT_MAX_BYTES;
  if (op === "stack.vault.put") return STACK_VAULT_PUT_MAX_BYTES;
  if (op === "stack.vault.share") return STACK_VAULT_SHARE_MAX_BYTES;
  return op.startsWith("records.") ? BRIDGE_REQUEST_MAX_BYTES : BRIDGE_SMALL_REQUEST_MAX_BYTES;
}

/** The largest answer body a bridge op carries, the snapshot included (`SNAPSHOT_RESPONSE_MAX_BYTES`). */
export const BRIDGE_RESPONSE_MAX_BYTES = SNAPSHOT_RESPONSE_MAX_BYTES;

/**
 * The default deadline of one bridge call (the gateway's `internalCallTimeoutMs` range), shared so
 * the bridge's configuration can prove one whole snapshot check fits inside it (bridge-3): two
 * replicas plus ConfigDO, each `CONFIG_CALL_TIMEOUT_MS`.
 */
export const LANE_BRIDGE_CALL_MS = 20_000;

/** P7 (stack-instance.ts): how long a role answer stands on the VM without a newer one: a few of the lane's polls, and of the 15 s lease pushes. */
export const LANE_ROLE_TTL_MS = 20_000;
/** egress's cap on one vendor call (deploy/tee/egress stack_ops.go `stackOpsCallCap`, stack_login.go `loginCallCap`). */
export const EGRESS_CALL_CAP_MS = 60_000;
/** The lane vault's first wait after a failed upload, doubling after each (workers/gateway/src/lane/vault.ts). */
export const VAULT_RETRY_FIRST_MS = 5_000;
/**
 * P7 (docs/design/relay-no-always-on-host.md 13.4, the final mark): the most the retiring instance needs for its final
 * mark when every call is answered at once (100 s). It learns it is draining within a role answer's life, a call at a
 * vendor when that happened returns within egress's cap, and its final put is one bridge call.
 */
export const LANE_FINAL_MARK_FLOOR_MS = LANE_ROLE_TTL_MS + EGRESS_CALL_CAP_MS + LANE_BRIDGE_CALL_MS;
/** P7: what rounds the final mark's wait up to three minutes; it also covers the lane's polls (5 s each) between the ack and the put. */
export const LANE_FINAL_MARK_MARGIN_MS = 25_000;
/**
 * P7 (13.4, the final mark): how long the serving instance waits for the retiring one's final mark, and the least the
 * provisioner's `remove_old` waits (PROVISION_FINAL_MARK_WAIT_MS is refused below it), 180 s: the floor (100 s), then two
 * final puts that time out, each one bridge call, with the vault's backoff after each (5 s, then 10 s), so the third put
 * starts by 135 s and lands by 155 s; and the margin.
 */
export const LANE_FINAL_MARK_WAIT_MS = LANE_FINAL_MARK_FLOOR_MS + 2 * LANE_BRIDGE_CALL_MS + VAULT_RETRY_FIRST_MS * (1 + 2) + LANE_FINAL_MARK_MARGIN_MS;

export const BRIDGE_REQUEST_SCHEMAS = {
  "account.admit": admitInputSchema,
  "account.count": countInputSchema,
  "account.settle": settleInputSchema,
  "account.release": releaseInputSchema,
  "endpoint.acquire": acquireInputSchema,
  "endpoint.release": endpointReleaseInputSchema,
  "endpoint.release_retry": retryReleaseInputSchema,
  "endpoint.note": noteInputSchema,
  "endpoint.probe_answered": probeAnsweredInputSchema,
  "endpoint.reserve_retry": retryReserveInputSchema,
  "endpoint.warm": warmInputSchema,
  "snapshot.current": snapshotCurrentRequestSchema,
  "scheduler.forward": schedulerForwardRequestSchema,
  "records.index": laneIndexMessageSchema,
  "records.events": laneEventsSchema,
  "records.points": lanePointsSchema,
  "records.service_events": laneServiceEventsSchema,
  "stack.config": stackConfigRequestSchema,
  "stack.proxy_checks": stackProxyChecksRequestSchema,
  "stack.rules": stackRulesRequestSchema,
  "stack.report": stackReportSchema,
  "stack.tests": stackTestsRequestSchema,
  "stack.debug_shares": stackDebugSharesRequestSchema,
  "stack.vault.get": stackVaultGetRequestSchema,
  "stack.vault.put": stackVaultPutRequestSchema,
  "stack.vault.share_nonce": stackVaultShareNonceRequestSchema,
  "stack.vault.share": stackVaultShareRequestSchema,
  "stack.instance": stackInstanceRequestSchema,
  "release.lists": releaseListsRequestSchema,
  "attest.collateral": attestCollateralRequestSchema,
  "lane.acme_failed": laneAcmeFailedSchema,
  "ticket.use": ticketUseInputSchema,
} as const satisfies Record<BridgeOp, z.ZodType>;

export const BRIDGE_RESPONSE_SCHEMAS = {
  "account.admit": admitResultSchema,
  "account.count": countResultSchema,
  "account.settle": settleResultSchema,
  "account.release": releaseResultSchema,
  "endpoint.acquire": acquireResultSchema,
  "endpoint.release": endpointReleaseResultSchema,
  "endpoint.release_retry": emptyAnswerSchema,
  "endpoint.note": emptyAnswerSchema,
  "endpoint.probe_answered": emptyAnswerSchema,
  "endpoint.reserve_retry": retryReserveResultSchema,
  "endpoint.warm": warmResultSchema,
  "snapshot.current": snapshotAnswerSchema,
  "scheduler.forward": schedulerForwardAnswerSchema,
  "records.index": recordsAcceptedSchema,
  "records.events": recordsAcceptedSchema,
  "records.points": recordsAcceptedSchema,
  "records.service_events": recordsAcceptedSchema,
  "stack.config": stackConfigAnswerSchema,
  "stack.proxy_checks": stackProxyChecksAnswerSchema,
  "stack.rules": stackRulesAnswerSchema,
  "stack.report": stackReportAnswerSchema,
  "stack.tests": stackTestsAnswerSchema,
  "stack.debug_shares": stackDebugSharesAnswerSchema,
  "stack.vault.get": stackVaultGetAnswerSchema,
  "stack.vault.put": stackVaultPutAnswerSchema,
  "stack.vault.share_nonce": stackVaultShareNonceAnswerSchema,
  "stack.vault.share": stackVaultShareAnswerSchema,
  "stack.instance": stackInstanceAnswerSchema,
  "release.lists": releaseListsAnswerSchema,
  "attest.collateral": attestCollateralAnswerSchema,
  "lane.acme_failed": laneAcmeFailedAnswerSchema,
  "ticket.use": ticketUseAnswerSchema,
} as const satisfies Record<BridgeOp, z.ZodType>;

/**
 * The request schema of `op` at bridge API `version` (D122'): version 2 is "`scheduler.forward`
 * carries `budget_ms`", so that op alone differs, and version 1 reads its forward without the member.
 * Every other op is the same document at both versions. The CVM signs version 2 and writes with
 * `BRIDGE_REQUEST_SCHEMAS`; the bridge reads with this, by the version its header check answered.
 */
export function bridgeRequestSchemaAt(op: BridgeOp, version: LaneBridgeApiVersion): z.ZodType {
  return op === "scheduler.forward" && version === 1 ? schedulerForwardRequestV1Schema : BRIDGE_REQUEST_SCHEMAS[op];
}

export type BridgeRequestOf<O extends BridgeOp> = z.infer<(typeof BRIDGE_REQUEST_SCHEMAS)[O]>;
export type BridgeResponseOf<O extends BridgeOp> = z.infer<(typeof BRIDGE_RESPONSE_SCHEMAS)[O]>;

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const EMPTY = new Uint8Array(0);

function parseJson(text: string, code: BridgeWireError["code"]): Json {
  try {
    return parseSerde(text);
  } catch {
    throw new BridgeWireError(code, null, "the body is not JSON");
  }
}

function decode(bytes: Uint8Array, maxBytes: number): string {
  if (bytes.byteLength > maxBytes) throw new BridgeWireError("body_too_large", null, `the body is over ${maxBytes} bytes`);
  try {
    return DECODER.decode(bytes);
  } catch {
    throw new BridgeWireError("invalid_document", null, "the body is not UTF-8");
  }
}

function checked(value: unknown, schema: z.ZodType, what: string): unknown {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue === undefined ? null : issue.path.map(String).join(".") || null;
    throw new BridgeWireError("invalid_document", field, `the ${what} is not its wire shape: ${field ?? "(root)"}: ${issue?.message ?? "invalid"}`);
  }
  return parsed.data;
}

/** One request's body bytes: the JSON text of its document, or nothing for the GET op. */
export function encodeBridgeRequest<O extends BridgeOp>(op: O, value: BridgeRequestOf<O>): Uint8Array {
  if (BRIDGE_METHODS[op] === "GET") return EMPTY;
  const bytes = ENCODER.encode(toJsonString(value as unknown as Json));
  if (bytes.byteLength > BRIDGE_REQUEST_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the ${op} request is over ${BRIDGE_REQUEST_MAX_BYTES} bytes`);
  return bytes;
}

/** Check one request document (the snapshot read's query included) before it is signed and sent. */
export function parseBridgeRequest<O extends BridgeOp>(op: O, value: unknown): BridgeRequestOf<O> {
  return checked(value, BRIDGE_REQUEST_SCHEMAS[op], "request") as BridgeRequestOf<O>;
}


/** One answer's body bytes. */
export function encodeBridgeResponse<O extends BridgeOp>(op: O, value: BridgeResponseOf<O>): Uint8Array {
  const bytes = ENCODER.encode(toJsonString(value as unknown as Json));
  if (bytes.byteLength > BRIDGE_RESPONSE_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the ${op} answer is over ${BRIDGE_RESPONSE_MAX_BYTES} bytes`);
  return bytes;
}

/** Read one answer: size, strict UTF-8, serde JSON, then the op's response schema. Throws `BridgeWireError`. */
export function parseBridgeResponse<O extends BridgeOp>(op: O, body: Uint8Array): BridgeResponseOf<O> {
  const value = parseJson(decode(body, BRIDGE_RESPONSE_MAX_BYTES), "invalid_document");
  return checked(value, BRIDGE_RESPONSE_SCHEMAS[op], `answer to ${op}`) as BridgeResponseOf<O>;
}
