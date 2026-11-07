import { sha256 } from "@noble/hashes/sha2";
import { get, isObject, parsePlain, readSerdeBytes, toJsonString, type Json, type JsonObject } from "@gray/json";
import { ApiError } from "@gray/errors";
import {
  applyDeclaredChanges,
  checkOfficialUpstream,
  isRelayPolicyReasonCode,
  sha256Hex,
  textSha256Hex,
  type AppendedText,
  type AppliedRecord,
  type GrayRewriteOp,
  type LaneProtocol,
} from "@gray/lane";
import {
  EVENT_REQUEST_MODIFIED,
  bytesToLowerHex,
  requestModifiedEvent,
  type ReceiptBuilder,
} from "@gray/attest";
import type { Protocol } from "@gray/protocol";
import type { LaneEgress, LanePolicyOutcome, LaneReceiptDraft, LaneTiming, RewritePlan } from "./types.ts";
import { planOps } from "./plan.ts";

/**
 * The lane's request-path rules that are not one line at a hook site: the body cap's refusal, the
 * four fixed 400s, the relay policy step with its padding, the append reserve, the header merge and
 * the response hash (design v2 §C.4–§C.11). Everything here is pure or an injected dependency, so
 * `inference.ts` keeps only `if (this.lane !== null)` branches at the sites the design names.
 */

/**
 * The one header the lane's egress sidecar reads (design v3 addendum E1/E2). Its value is a compact
 * JSON egress spec; `laneFetch` sends it to the `EGRESS` binding, and the sidecar removes it before
 * the vendor. It must never be built from a client header: `laneHeaders` copies no arbitrary client
 * header, and `send` deletes it before setting the attempt's own value.
 */
export const EGRESS_HEADER = "x-gray-egress";

/** The fixed error codes the egress sidecar answers a failed 502 with (deploy/tee/egress/README.md). */
const EGRESS_FAILURES = ["egress_connect_failed", "egress_proxy_failed", "egress_tls_failed", "egress_upstream_failed"] as const;

/**
 * The egress failures that happen before the vendor connection is made, so no byte of the request
 * reached the vendor (D72): the direct dial, any stage of a proxy (the proxy stands before the
 * vendor), and the vendor TLS handshake. `egress_upstream_failed` is deliberately not here: the
 * sidecar answers it only after the vendor connection exists.
 */
const EGRESS_BEFORE_VENDOR = ["egress_connect_failed", "egress_proxy_failed", "egress_tls_failed"] as const;

/** The compact JSON the sidecar receives: the port is written as an integer, not a float. */
export function egressHeader(egress: LaneEgress): string {
  return toJsonString({
    type: egress.type,
    host: egress.host,
    port: BigInt(egress.port),
    ...(egress.username === undefined ? {} : { username: egress.username }),
    ...(egress.password === undefined ? {} : { password: egress.password }),
  });
}

/**
 * Whether a 502 body is one of gray-egress's fixed failures. Such an answer maps to the attempt's
 * `transport` or `connect` outcome: a dead proxy or a TLS failure is not the account's
 * `auth_failed`. The body is parsed as data only; nothing in it is ever logged or recorded.
 */
export function egressSidecarFailure(status: number, body: Uint8Array): boolean {
  return egressFailure(status, body) !== null;
}

/**
 * Whether the sidecar failed before it connected the vendor (D72): then the request never reached the
 * vendor and must not be reported or receipted as forwarded. The code is the sidecar's closed one;
 * the body is data only, and nothing in it is ever logged or recorded.
 */
export function egressBeforeVendor(status: number, body: Uint8Array): boolean {
  const code = egressFailure(status, body);
  return code !== null && (EGRESS_BEFORE_VENDOR as readonly string[]).includes(code);
}

/** The sidecar's fixed error code in a 502 body, or null when the answer is not one of its failures. */
function egressFailure(status: number, body: Uint8Array): string | null {
  if (status !== 502) return null;
  try {
    const value = parsePlain(new TextDecoder().decode(body)) as Json;
    if (!isObject(value)) return null;
    const code = get(value, "error");
    return typeof code === "string" && (EGRESS_FAILURES as readonly string[]).includes(code) ? code : null;
  } catch {
    return null;
  }
}

/** The lane's fixed error codes (design v2 §C.1, §C.5, §C.10). Each is one Gray code with one text. */
export const LANE_CODES = {
  bodyTooLarge: "request_body_limit",
  continuation: "lane_continuation_unsupported",
  toolHandles: "lane_tool_handles_unsupported",
  duplicateKey: "lane_duplicate_key",
  policyRefused: "relay_policy_refused",
} as const;

/** 400 for a Responses continuation in lane mode (design v2 §A, M11/M18): the conversation is at the vendor, under an account the scheduler picked. */
export function laneContinuationUnsupported(): ApiError {
  return new ApiError(400, LANE_CODES.continuation).withMessage(
    "The confidential lane does not continue an earlier response: `previous_response_id` and `conversation` are refused, and a lane conversation must start fresh.",
  );
}

/**
 * 400 for a routing preference in the body in lane mode: the lane sends the body as received with its
 * declared rewrites only (`gray-lane-rewrites-v1`, @gray/lane), and none takes a `provider` member out, which
 * the upstream would refuse. The `x-gray-routing` header carries the same preference and is never forwarded.
 */
export function laneRoutingInBody(): ApiError {
  return new ApiError(400, "routing_invalid").withMessage(
    "The confidential lane sends the request body as received and cannot take `provider` out of it: send the routing preference in the `x-gray-routing` header instead.",
  );
}

/** 400 for a body carrying a Gray tool-call id handle (design v2 §A, M25): the lane resolves none, so the vendor would see an opaque id. */
export function laneToolHandlesUnsupported(): ApiError {
  return new ApiError(400, LANE_CODES.toolHandles).withMessage(
    "The confidential lane does not restore Gray tool-call id handles: start the conversation on the lane, or send the original ids instead of their handles.",
  );
}

/** 400 for a body with a member name twice anywhere the lane reads it (design v2 §A, M3; a documented difference from the main lane). */
export function laneDuplicateKey(): ApiError {
  return new ApiError(400, LANE_CODES.duplicateKey).withMessage(
    "The confidential lane refuses a request body that names a member twice, because the vendor's parser and Gray's could read it differently. Send each member once.",
  );
}

/** 403 for a relay policy that blocked the request or could not run (design v2 §C.5, B7): one fixed code, no module text. */
export function lanePolicyRefused(): ApiError {
  return new ApiError(403, LANE_CODES.policyRefused).withMessage(
    "The relay's policy refused this request. The relay's module can only allow or block a request; Gray cannot tell you why, and nothing was forwarded.",
  );
}

/**
 * Whether a Responses request continues an earlier one (`previous_response_id` or `conversation`
 * present, either with a value): the lane refuses both (design v2 §A, M11). Read from the parsed
 * body, because `@gray/protocol`'s canonical projection has no member for either: only the Responses
 * API defines them, and the lane must refuse the pair exactly when the vendor would honour it.
 */
export function continuesEarlierResponse(protocol: Protocol, body: Json): boolean {
  if (protocol !== "open_ai_responses" || !isObject(body)) return false;
  // A member the client wrote as `null` is how several clients spell "absent": the vendor reads it as
  // no continuation either, so the lane does not refuse it (F2 hooks-9).
  const present = (name: string): boolean => {
    const value = get(body, name);
    return value !== undefined && value !== null;
  };
  return present("previous_response_id") || present("conversation");
}

/**
 * The most append-reserve tokens one relay's accepted bundle can imply (F2 D2). The largest selection
 * the bundle's own templates allow is bounded by the store's `maxItems` (3 by default) and
 * `maxTotalBytes` (8 KiB by default); this caps a misconfigured registry, and is the old
 * `LANE_APPEND_RESERVE_TOKENS` range's maximum, so no configuration can reserve more than it could.
 */
export const LANE_APPEND_RESERVE_MAX_TOKENS = 1_000_000;

/**
 * The append reserve in prompt tokens for one relay (design v2 §C.4, M5; F2 D2): the relay's largest
 * total append bytes, from its accepted bundle, converted with the gateway's byte-to-token upper
 * bound. The bound is the same one the hold's own input bound uses (`@gray/protocol` `bodyBound`: "a
 * token per byte"), so the reserve is the byte count itself, capped at
 * {@link LANE_APPEND_RESERVE_MAX_TOKENS}.
 *
 * The reserve is added to the hold's prompt units for every request the relay may serve, whether or
 * not its policy appends anything: a decision that depends on the module's runtime would be a side
 * channel, and an appended text can be as large as the relay's whole allowance. A relay with no
 * accepted bundle reserves nothing; it is passed over rather than served (F2 D7).
 */
export function appendReserveTokens(maxAppendBytes: number): number {
  if (!Number.isFinite(maxAppendBytes) || maxAppendBytes <= 0) return 0;
  return Math.min(Math.ceil(maxAppendBytes), LANE_APPEND_RESERVE_MAX_TOKENS);
}

/**
 * The relay policy step (design v2 §C.5, B7, M14; F2 D1 as amended by D32 and D128): run the module
 * for one request, map every outcome to the lane's one fixed answer, and pad the step to a duration
 * that depends only on the size of the module's input, so the module's own runtime never shows in a
 * duration Gray records.
 *
 * `run` is the policy's `run` (the wasmi host's), `fuel` the budget that run gives the module
 * (`LanePolicyRecord.fuel`), `sleep` the wall clock's wait. D128: the step's budget is
 * {@link policyStepBudgetMs} of that fuel — the time the sandbox needs to spend the whole budget plus
 * the fixed cost around a run, capped at `LANE_POLICY_STEP_MS` (or at what the boot raised that cap
 * to, F2 D130) — rather than the cap itself on every request. The fuel is a function of the input's
 * length alone (the ABI header and the body): D128 rules that size something an observer already
 * sees, so the step's duration carries nothing about what the module did. The padding is the
 * difference between the budget and what the module took, floored at zero: a fast or a failing module
 * is padded to the same duration as an allowing one.
 *
 * D32: the isolate cannot interrupt a synchronous wasm run, so there is no mid-run deadline and an
 * overrun cannot be padded back to the step. (D32 assumed workerd's clock stood still during such a
 * run; in the workerd the image ships, 1.20261006.1, it advances, in whole milliseconds — measured
 * 2026-10-22 — so the overrun below is observable after the run returns.) **Fuel is THE bound on the
 * run**, and since D128' the budget is the time the whole fuel takes at the slower of the configured
 * and the boot-calibrated rate (`calibration.ts`). The step observes the run's duration after it returns: a run at
 * or inside the budget (the module plus the preparation of its input, which happens inside `run`) is
 * padded to exactly the budget; an observed overrun is the fixed failure, `policy_unavailable`,
 * whatever the module answered, and its duration is the module's own, bounded by fuel. The cache is
 * the caller's: the design caches per `(relayId, protocol, model)` within a request (M12), and the
 * plan is per attempt, so the decision is taken once per relay and model.
 */
export interface PolicyStepInput {
  readonly timing: LaneTiming;
  /** The fuel `run` gives the module (`LanePolicyRecord.fuel`); null when it answers before the module runs. */
  readonly fuel: bigint | null;
  readonly run: () => PolicyRun;
  /** The wall clock's wait, in ms; the caller injects it so a test needs no real time. */
  readonly sleep: (ms: number) => Promise<void>;
  readonly clock: () => number;
}

/**
 * The policy step's budget in ms for a run given `fuel` (F2 D128):
 *
 *     min(ceil(fuel / LANE_POLICY_FUEL_PER_MS) + LANE_POLICY_OVERHEAD_MS, LANE_POLICY_STEP_MS)
 *
 * `LANE_POLICY_FUEL_PER_MS` is the sandbox's fuel throughput on the slowest module shape measured
 * (`burn-branch`) and `LANE_POLICY_OVERHEAD_MS` the fixed cost of building the input, instantiating
 * the module and reading its answer (`workers/packages/relay-policy/bench/policy-step.ts`; D128'
 * measurement, 2026-10-22), each replaced at boot by this machine's own calibration when that is
 * slower (`calibration.ts`), so a module that spends its whole budget finishes inside the uncapped
 * term ({@link policyStepUncappedMs}). The cap is `LANE_POLICY_STEP_MS` unless it would cut that term
 * at the largest input (`LANE_POLICY_MAX_FUEL`, 82,960,000 fuel: the 4 MiB body and the header's
 * bound): when the boot's rate and overhead make the term longer there — a rate below about 55,400
 * fuel per ms at a 3 ms overhead, 82,960,000 / (1,500 - 3) — the boot raises the cap to it (F2 D130,
 * `calibration.ts`), so a module that spends its whole budget finishes inside T at every size. At the
 * configured settings the term is 444 ms there, the cap does not bind, and no request waits longer
 * than before D128. A run with no fuel budget (`run` answers before the module runs: an input the ABI
 * refuses) gets the cap, as every run did before D128. The arithmetic is exact (bigint): a fuel count
 * is a u64.
 */
export function policyStepBudgetMs(timing: LaneTiming, fuel: bigint | null): number {
  if (fuel === null || fuel <= 0n) return timing.policyStepMs;
  const budget = policyStepUncappedMs(timing, fuel);
  const cap = BigInt(timing.policyStepMs);
  return Number(budget < cap ? budget : cap);
}

/**
 * The step's budget before the cap, in ms: `ceil(fuel / policyFuelPerMs) + policyOverheadMs`, the time
 * the sandbox needs to spend all of `fuel` plus the fixed cost around a run (F2 D128). The boot's cap
 * rule (D130, `calibration.ts`) takes it at the largest input. Exact bigint arithmetic.
 */
export function policyStepUncappedMs(speed: Pick<LaneTiming, "policyFuelPerMs" | "policyOverheadMs">, fuel: bigint): bigint {
  const perMs = BigInt(speed.policyFuelPerMs);
  return (fuel + perMs - 1n) / perMs + BigInt(speed.policyOverheadMs);
}

export type PolicyRun =
  | { readonly kind: "allow"; readonly appends: readonly AppendedText[] }
  | { readonly kind: "block"; readonly reasonCode: string }
  | { readonly kind: "unavailable" };

/**
 * What a padded policy step answers: the module's decision, the receipt's `relay_policy.*` outcome,
 * and the bytes it appended (empty for a refusal). A non-allow outcome always carries the lane's one
 * refusal code, so nothing the module did reaches the client or a record but the shared event shape.
 */
export interface PolicyStepResult {
  readonly allow: boolean;
  readonly appends: readonly AppendedText[];
  readonly outcome: LanePolicyOutcome;
}

export async function policyStep(input: PolicyStepInput, moduleSha256: string, policyVersion: bigint): Promise<PolicyStepResult> {
  const budgetMs = policyStepBudgetMs(input.timing, input.fuel);
  const started = input.clock();
  let run: PolicyRun;
  try {
    run = input.run();
  } catch {
    // The wasmi host answers a value, never a throw; a host bug is still one fixed refusal.
    run = { kind: "unavailable" };
  }
  const elapsed = Math.max(0, input.clock() - started);
  // D32: a run that finished inside the budget is padded to it; an observed overrun cannot be padded
  // (and the isolate's clock cannot interrupt a synchronous wasm run), so its duration stays the
  // module's own — fuel is the bound — while the answer becomes the fixed failure below.
  const pad = Math.max(0, budgetMs - elapsed);
  if (pad > 0) await input.sleep(pad);
  // F2 D1/D32/D128: over the budget is the fixed failure, even when the module answered allow or
  // block: an answer above the budget must not buy a decision the same request under it cannot get.
  if (elapsed > budgetMs) run = { kind: "unavailable" };
  if (run.kind === "allow") {
    return {
      allow: true,
      appends: run.appends,
      outcome: {
        type: "relay_policy.applied",
        moduleSha256,
        policyVersion,
        appended: run.appends.map((append) => ({ templateId: append.templateId, position: append.position, textSha256: textSha256Hex(append.text) })),
      },
    };
  }
  const reasonCode = run.kind === "block" ? run.reasonCode : "policy_unavailable";
  return { allow: false, appends: [], outcome: { type: "relay_policy.refused", moduleSha256, policyVersion, reasonCode } };
}

/**
 * The lane's forwarded bytes: the declared ops and the relay's appends over the received body
 * (design v2 §C.7, M2, M4). One result per `(relayId, appends)` is the caller's cache; this is the
 * computation it caches.
 *
 * A refusal is Gray's fixed 400 or 403, never the module's text: `duplicate_key` when the body has a
 * member twice (or the plan carries a collapsed one), `invalid_stream_options` when a Chat body's
 * `stream_options` is not an object (the main lane's own refusal), and `policy`/`path`/`not_found`/
 * `already_exists` from `@gray/lane`'s op checks, which a plan built from a body cannot hit and a
 * host bug is the only way to reach.
 */
export type Forwarded =
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly events: readonly Readonly<Record<string, unknown>>[];
      readonly applied: readonly AppliedRecord[];
    }
  | { readonly ok: false; readonly error: ApiError };

export function forwardedBody(received: Uint8Array, protocol: Protocol, plan: RewritePlan, appends: readonly AppendedText[]): Forwarded {
  if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") {
    return { ok: false, error: new ApiError(400, "invalid_protocol_request").withMessage("The confidential lane serves the Anthropic Chat Completions and Responses APIs.") };
  }
  // The ops are decided against the body as received, never the gateway's parse of it: the parse has
  // already deleted the customer's `models` list, so a removal judged by it would never be emitted
  // (design v2 §C.7, M2: "and the received body").
  let body: Json;
  try {
    body = readSerdeBytes(received).value;
  } catch {
    return { ok: false, error: new ApiError(400, "invalid_json") };
  }
  const ops = planOps(plan, protocol, body);
  if (!ops.ok) {
    return { ok: false, error: ops.reason === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_stream_options") };
  }
  const applied = applyDeclaredChanges(received, protocol as LaneProtocol, { grayOps: ops.ops, appends });
  if (!applied.ok) {
    if (applied.code === "duplicate_key") return { ok: false, error: laneDuplicateKey() };
    if (applied.code === "position_protocol" || applied.code === "invalid_text" || applied.code === "append_shape") {
      // The relay's own bundle was accepted with these appends, so this is Gray's bug: a fixed 403.
      return { ok: false, error: lanePolicyRefused() };
    }
    return { ok: false, error: new ApiError(400, "invalid_json").withMessage("The confidential lane could not apply its declared rewrites to this body.") };
  }
  return { ok: true, bytes: applied.forwarded, events: applied.events.map((event) => event as unknown as Readonly<Record<string, unknown>>), applied: applied.applied };
}

/** The `request.modified` events of an op list, as the receipt builder takes them (one per op, in order). */
export function modifiedEvents(ops: readonly GrayRewriteOp[], declaredIn: string): readonly Readonly<Record<string, unknown>>[] {
  return ops.map((op) =>
    requestModifiedEvent({
      op: op.op,
      path: op.path,
      ...(op.op === "remove_member" ? {} : { value: op.value }),
      declaredIn,
    }) as unknown as Readonly<Record<string, unknown>>,
  );
}

/**
 * The events a lane receipt holds, in the order `@gray/attest`'s `checkEventLog` requires (design v2
 * §C.8): `request.received` first; the attempt's `request.modified` events; its `relay_policy.*`
 * outcome; `request.forwarded`; the honest `upstream.verified` failure; and `response.returned` last.
 *
 * The `upstream.verified` event is the ACI §7.5 aggregator rule: Gray's vendor call is not a TEE, so
 * the verification failed and it was never required — `{result: "failed", required: false}`. It
 * replaces nothing (the §7.5 exemption needs `required: true`), so a receipt that forwarded nothing
 * still needs either `request.forwarded` or a policy refusal, which is why one is only built for
 * those two cases.
 *
 * A policy-refused draft forwarded nothing: it carries `request.received`, the refusal, the failed
 * verification and the error body the client got, and no `request.modified` (`checkEventLog` refuses
 * one without `request.forwarded`).
 */
export function addReceiptEvents(builder: ReceiptBuilder, input: { readonly receivedHash: string; readonly draft: LaneReceiptDraft; readonly responseHash: string }): void {
  builder.addRequestReceivedHash(input.receivedHash);
  const forwarded = input.draft.forwardedHash;
  const policy = input.draft.policy;
  if (forwarded !== null) {
    // One `request.modified` per op the attempt applied, in application order: after
    // `request.received`, before `relay_policy.applied` and `request.forwarded` (§7.4, M2).
    for (const event of input.draft.modifiedEvents) {
      builder.addExtensionEvent(EVENT_REQUEST_MODIFIED, modifiedFields(event));
    }
    if (policy !== null) addPolicyEvent(builder, policy);
    builder.addRequestForwardedHash(forwarded);
    builder.addUpstreamVerificationFailed({ modelId: input.draft.upstreamModel, required: false, reason: UPSTREAM_NOT_TEE });
  } else if (policy !== null && policy.type === "relay_policy.refused") {
    addPolicyEvent(builder, policy);
    builder.addUpstreamVerificationFailed({ modelId: input.draft.upstreamModel, required: false, reason: UPSTREAM_NOT_TEE });
  }
  builder.addResponseReturnedHash(input.responseHash);
}

/** A `request.modified` event's fields, without its `type` (the builder writes that from the type it is given). */
function modifiedFields(event: Readonly<Record<string, unknown>>): Readonly<Record<string, Json>> {
  const fields: Record<string, Json> = {};
  for (const [key, value] of Object.entries(event)) {
    if (key !== "type" && value !== undefined) fields[key] = value as Json;
  }
  return fields;
}

/** Why every lane receipt says its upstream verification failed (§C.8): the vendor's API is not a TEE. */
export const UPSTREAM_NOT_TEE = "vendor_api_not_tee";

/** One `relay_policy.*` event, in the shared wire shape (`@gray/attest`'s builders, which validate it). */
function addPolicyEvent(builder: ReceiptBuilder, outcome: LanePolicyOutcome): void {
  if (outcome.type === "relay_policy.applied") {
    builder.addRelayPolicyApplied({
      moduleSha256: outcome.moduleSha256,
      policyVersion: outcome.policyVersion,
      appended: outcome.appended.map((append) => ({ template_id: append.templateId, position: append.position, text_sha256: append.textSha256 })),
    });
    return;
  }
  // `policyStep` only ever records the closed vocabulary (`blocked`, `append_limit`, and the host's
  // `policy_unavailable`); anything else would be a host bug, and the refusal is recorded as the
  // fixed failure rather than thrown away.
  const reasonCode = isRelayPolicyReasonCode(outcome.reasonCode) ? outcome.reasonCode : "policy_unavailable";
  builder.addRelayPolicyRefused({ moduleSha256: outcome.moduleSha256, policyVersion: outcome.policyVersion, reasonCode });
}

/**
 * The one coarse outcome word a relay's scheduler is told (design v2 §C.10, §D): a closed set of
 * metadata, never a status code or Gray's code, and never anything of the request's content. A
 * success is `ok`; everything else maps by what the relay can act on — its own account's health.
 */
export function laneOutcomeWord(o: { readonly ok: boolean; readonly status: number | null; readonly clientLeft: boolean; readonly timedOut: boolean; readonly rateLimited: boolean; readonly authFailed: boolean; readonly quotaExhausted: boolean; readonly overloaded: boolean }): string {
  if (o.ok) return "ok";
  if (o.clientLeft) return "client_left";
  if (o.rateLimited) return "rate_limited";
  if (o.authFailed) return "auth_failed";
  if (o.quotaExhausted) return "quota_exhausted";
  if (o.overloaded) return "overloaded";
  if (o.timedOut) return "timeout";
  return "upstream_error";
}

/**
 * The connector's closed error codes (`@gray/relay-connector` `RELAY_CONNECTOR_ERROR_CODES`), copied
 * here so the gateway does not import the connector's value code; `test/lane-hooks/lane-units.test.ts`
 * holds the copy to the connector's list. A lane pick or credential failure's cause is one of these
 * or `unknown` (D116(e)), never a string a thrower chose.
 */
export const LANE_CONNECTOR_CODES = [
  "quote_not_verified",
  "report_binding_invalid",
  "keyset_expired",
  "no_intake_key",
  "invalid_bundle",
  "invalid_envelope",
  "unknown_intake_key",
  "attestation_mismatch",
  "decryption_failed",
  "invalid_plaintext",
  "unknown_relay",
  "bad_relay_signature",
  "bundle_rollback",
  "bundle_replay",
  "bundle_expired",
  "bundle_not_yet_valid",
  "invalid_credential",
  "duplicate_account",
  "unknown_account",
  "credential_expired",
  "invalid_scheduler_request",
  "scheduler_timeout",
  "scheduler_transport",
  "scheduler_unauthorized",
  "scheduler_bad_response",
  "scheduler_bad_signature",
  "scheduler_stale_timestamp",
  "scheduler_unknown_account",
  "invalid_table",
  "table_rollback",
  "table_expired",
  "report_schema",
  "closed",
] as const;

/**
 * The latency band a report carries (design v2 §C.10, M14): a coarse band, never a duration, because
 * a precise one is the side channel the policy padding exists to close. The bands are
 * `@gray/relay-connector`'s own (`LATENCY_BUCKETS`), copied here so the gateway does not import the
 * connector's value code; `test/lane-hooks/lane-units.test.ts` pins the vocabulary and its bands, and
 * the connector validates every report against its own list before it is queued.
 */
export const LATENCY_BANDS = ["lt_250ms", "lt_500ms", "lt_1s", "lt_2s", "lt_5s", "lt_15s", "lt_60s", "gte_60s"] as const;

/** The band of `milliseconds`: negative and non-finite inputs are the caller's bug (`gte_60s`, the widest band). */
export function latencyBand(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "gte_60s";
  if (milliseconds < 250) return "lt_250ms";
  if (milliseconds < 500) return "lt_500ms";
  if (milliseconds < 1000) return "lt_1s";
  if (milliseconds < 2000) return "lt_2s";
  if (milliseconds < 5000) return "lt_5s";
  if (milliseconds < 15_000) return "lt_15s";
  if (milliseconds < 60_000) return "lt_60s";
  return "gte_60s";
}

/** The usage counters a report carries, from the request's own (which the ledger already normalized). */
export function laneUsage(usage: Readonly<Record<string, number>> | null): { readonly input_tokens: bigint; readonly output_tokens: bigint; readonly cache_read_input_tokens: bigint; readonly cache_creation_input_tokens: bigint } {
  const of = (key: string): bigint => {
    const value = usage?.[key];
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : 0n;
  };
  return {
    input_tokens: of("input_tokens"),
    output_tokens: of("output_tokens"),
    cache_read_input_tokens: of("cache_read_input_tokens"),
    // The scheduler's cache-write counter is the gateway's `cache_write_input_tokens` (F2 hooks-7);
    // the 1 h counter is already part of that total, so it is not added again.
    cache_creation_input_tokens: of("cache_write_input_tokens"),
  };
}

/**
 * The fields a lane record must not carry (design v2 §D, M13, M20): who the client is and what its
 * tools are called. The lane's record goes to the bridge and on to Gray's own tables, and none of
 * these may leave the CVM — not because they are the prompt, but because they are the client's
 * fingerprint, and the lane's promise is that Gray learns nothing of the conversation beyond the
 * counts it bills. The list is the review's (§6), applied by name so a later field cannot slip in
 * silently: a new client-derived member of the record must be added here.
 */
export const LANE_RECORD_NULLED = Object.freeze(["clientIp", "userAgent", "client", "clientVersion", "sessionId", "parentSessionId", "turnStart"] as const);

/** `value` with every lane-forbidden member nulled, and the answer's tool names kept as a count only. */
export function laneSafeRecord<T extends object>(value: T): T {
  const out: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  for (const name of LANE_RECORD_NULLED) if (name in out) out[name] = null;
  if (Array.isArray(out.toolNames)) out.toolNames = [];
  return out as T;
}

/**
 * A log line's fields as a lane may emit them (design v2 §D, M13): free text is dropped, because the
 * only free text the request path logs is an upstream's (or a parser's) message, which may quote the
 * customer's content. The event name, the ids and the codes stay.
 */
export const LANE_LOG_DROPPED = Object.freeze(["why", "message", "detail", "reason_text"] as const);

/** `event` with every free-text member removed: the same line, without anything that may be content. */
export function laneSafeLog<T extends object>(event: T): T {
  const out: Record<string, unknown> = { ...(event as Record<string, unknown>) };
  for (const name of LANE_LOG_DROPPED) delete out[name];
  return out as T;
} 

/**
 * One attempt's receipt draft (design v2 §C.8, M6): the events the attempt would record, the policy
 * outcome its relay gave, the hash of the bytes it forwarded and the account it ran on. A failed
 * attempt's draft is dropped with it; the committed attempt's is adopted, and the receipt is signed
 * only once the response body closes.
 *
 * `request.modified` events come from the ops the attempt applied and sit after `request.received`,
 * before `relay_policy.applied` and `request.forwarded` (`@gray/attest` `checkEventLog`). A forwarded
 * body is the only thing a `request.modified` event may describe, so a draft without one (a policy
 * refusal, an attempt that failed before it sent) carries no events.
 */
export function receiptDraft(input: {
  readonly modifiedEvents: readonly Readonly<Record<string, unknown>>[];
  readonly policy: LanePolicyOutcome | null;
  readonly forwardedHash: string | null;
  readonly accountId: string | null;
  readonly upstreamModel: string;
}): LaneReceiptDraft {
  return {
    modifiedEvents: input.forwardedHash === null ? [] : input.modifiedEvents,
    policy: input.policy,
    forwardedHash: input.forwardedHash,
    accountId: input.accountId,
    upstreamModel: input.upstreamModel,
  };
}

/**
 * The lane's auth headers for one attempt (design v2 §C.6, M1): the account's headers from the
 * credential store, merged with the protocol's own client headers (never `route.auth`).
 *
 * - Anthropic: one `anthropic-version` (the client's, else `2023-06-01`), and `anthropic-beta` as
 *   the comma-joined union of the client's and the account's, so an OAuth account's
 *   `oauth-2025-04-20` betas reach the vendor without dropping the client's;
 * - the OpenAI family: `openai-beta` as the union;
 * - `content-type: application/json`, the one header every upstream body needs.
 *
 * The account's own `anthropic-version`/`anthropic-beta`/`openai-beta` are unioned, every other
 * account header set as it is. A header the account sets twice in the record is impossible (a
 * record is a map), and the merge is a set, so no account header can produce a duplicate.
 */
export function laneHeaders(protocol: Protocol, client: Headers, account: Readonly<Record<string, string>>): Headers {
  const headers = new Headers({ "content-type": "application/json" });
  for (const [name, value] of Object.entries(account)) headers.set(name.toLowerCase(), value);
  const beta = protocol === "anthropic_messages" ? "anthropic-beta" : protocol === "open_ai_chat" || protocol === "open_ai_responses" ? "openai-beta" : null;
  if (beta !== null) {
    const union = unionHeader(client.get(beta), headers.get(beta));
    if (union === null) headers.delete(beta);
    else headers.set(beta, union);
  }
  if (protocol === "anthropic_messages") headers.set("anthropic-version", client.get("anthropic-version") ?? "2023-06-01");
  return headers;
}

/** Two comma-separated header values as one union, each side's values in its own order, both empty: null. */
function unionHeader(left: string | null, right: string | null): string | null {
  const values: string[] = [];
  for (const side of [left, right]) {
    if (side === null) continue;
    for (const part of side.split(",")) {
      const value = part.trim();
      if (value.length > 0 && !values.includes(value)) values.push(value);
    }
  }
  return values.length === 0 ? null : values.join(",");
}

/**
 * Whether `url` may be sent to (design v2 §B, m8): `checkOfficialUpstream`'s answer, as a boolean. The
 * route's `url` is used as the control plane built it, never rebuilt, so this runs before every send.
 */
export function officialUpstream(url: string): boolean {
  return checkOfficialUpstream(url).ok;
}

/**
 * An incremental SHA-256 the response hash uses (design v2 §C.9, M7): finalisable on abort, so a body
 * the client left is still hashed up to the bytes it got. `@noble/hashes`'s `sha256.create()` is
 * synchronous and already a dependency of the workspace; `@gray/attest`'s hashing stream refuses a
 * partial digest, which is exactly the case a cut body is.
 */
export interface ResponseHash {
  update(bytes: Uint8Array): void;
  /** `sha256:` plus lowercase hex of every byte handed to `update` so far; callable at any time. */
  bodyHash(): string;
  readonly byteLength: number;
}

/** A body hash over the bytes handed to it, finalisable at any point. */
export function responseHash(): ResponseHash {
  return createResponseHash();
}

/** The incremental digest behind {@link responseHash}: `@noble/hashes`'s synchronous SHA-256. */
function createResponseHash(): ResponseHash {
  const hasher = sha256.create();
  let byteLength = 0;
  return {
    update(bytes: Uint8Array): void {
      hasher.update(bytes);
      byteLength += bytes.length;
    },
    // A digest of what was written so far, at any point: a stream cut by its client is still a body
    // the receipt can name (design v2 §C.9, M7: the bytes handed to the response stream up to the
    // failure), and `sha256.digest()` on a clone keeps the running state usable.
    bodyHash(): string {
      return `sha256:${bytesToLowerHex(hasher.clone().digest())}`;
    },
    get byteLength(): number {
      return byteLength;
    },
  };
}

/** `sha256:` plus lowercase hex of `bytes` (the receipt's `body_hash` field). */
export function bodyHashOf(bytes: Uint8Array): string {
  return `sha256:${sha256Hex(bytes)}`;
}

/**
 * A body the lane forwards, as `UpstreamBody` takes it (upstream.ts): its exact length and a fresh
 * stream handing views of at most `UPSTREAM_BODY_CHUNK_BYTES` each, the chunk every held and stored
 * body is sent in. The bytes are one object held by the request's per-`(relayId, appends)` cache, so
 * the second attempt at the same relay re-sends exactly the bytes the first one did.
 */
export function forwardedStream(bytes: Uint8Array, chunkBytes: number): { readonly length: number; readonly stream: () => ReadableStream<Uint8Array> } {
  return {
    length: bytes.length,
    stream: () => {
      let at = 0;
      return new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            if (at >= bytes.length) {
              controller.close();
              return;
            }
            controller.enqueue(bytes.subarray(at, Math.min(bytes.length, at + chunkBytes)));
            at += chunkBytes;
          },
        },
        { highWaterMark: 0 },
      );
    },
  };
}


