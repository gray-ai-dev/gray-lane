/**
 * Zero-retention continuations on the confidential lane (`InferenceRun`, inference.ts): the sealed state a Responses
 * request continues from, its expansion into the body a relay is sent, the fallbacks of an encrypted-content refusal, and
 * the continuation a lane answer pins and binds.
 */
import { CONTINUATION_ERRORS, CONTINUATION_STATE_TTL_MS, MAX_REPLY_ITEM_REFERENCES, StreamBinding, continuationReferences, hashedReference, storesContinuation, type BindReference, type PinResult } from "@gray/continuation";
import { ApiError } from "@gray/errors";
import { type Json, get, isObject, toJsonString } from "@gray/json";
import type { Protocol } from "@gray/protocol";
import { continuationBody, type ParsedRequest } from "../parse.ts";
import type { ChunkTap } from "../relay.ts";
import type { KeyRecord, RouteRecord } from "../snapshot.ts";
import { continuesEarlierResponse, laneContinuationConversation, laneContinuationSealed, laneContinuationUnrecorded } from "../lane/hooks.ts";
import { ExpandedBodyTooLargeError, ResponsesStateTap, expandZeroRetentionContinuation, isInvalidEncryptedContentError, isUnsupportedIncludeEncryptedReasoningError, newContinuationAffinityId, normalizeResponsesInput, openContinuationState, routeEnforcesStoreFalse, sealContinuationState, shouldAddEncryptedReasoningInclude, type CapturedResponsesReply, type ExpandZeroRetentionResult, type SealedResponseState } from "../lane/responses-continuation.ts";
import { laneBodyCap, STACK_BODY_MAX_BYTES } from "../lane/body-limits.ts";
import type { Attempt, Answering } from "./types.ts";
import { type StackRoutesRun, laneEndpointRoute, stackRoute } from "./stack-routes.ts";
import { type HoldRun, continuationStoreTiming } from "./hold.ts";

const encoder = new TextEncoder();

/** What zdr.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface ZdrRun extends HoldRun, StackRoutesRun {}

/**
 * Whether `route` is a confidential entry zero-retention OpenAI Responses route that enforces
 * `store: false` upstream (P2 zero upstream retention).
 */
export function laneZeroRetentionRoute(run: ZdrRun, route: RouteRecord): boolean {
  if (run.lane === null || route.protocol !== "open_ai_responses") return false;
  return routeEnforcesStoreFalse(route);
}

/**
 * Decrypts sealed continuation state returned by `lane.continuation.pin` inside the entry TEE.
 *
 * On zero-retention routes, `item_reference` entries require decrypted item state (an unresolved
 * `item_reference` cannot be forwarded to a `store: false` upstream and fails with 404
 * `continuation_not_found`). For `previous_response_id` on a Relay Stack route without sealed
 * state (for example past the 2-hour sealed-state TTL), preserves passthrough to the pinned VM.
 */
export async function laneDecryptSealedContinuation(
  run: ZdrRun,
  workspaceId: string,
  body: Json,
  sealedHits: readonly { readonly kind: "response" | "conversation" | "item"; readonly reference: string; readonly sealed: string }[] | undefined,
  records: readonly RouteRecord[],
): Promise<{ readonly ok: true } | { readonly ok: false; readonly error: ApiError }> {
  const lane = run.lane;
  if (lane === null) return { ok: true };
  run.zdr.laneSealedResponses.clear();
  run.zdr.laneSealedItems.clear();
  const refs = continuationReferences(body);
  if (refs === undefined || refs.length === 0) return { ok: true };
  const hits = new Map<string, string>();
  for (const hit of sealedHits ?? []) hits.set(`${hit.kind}\u0000${hit.reference}`, hit.sealed);

  let hasResponseRef = false;
  let hasItemRef = false;
  let missingResponseSealed = false;
  let missingItemSealed = false;
  const maxExpandedBytes =
    records.length > 0 ? Math.max(...records.map((r) => laneZdrBodyLimit(run, r))) : STACK_BODY_MAX_BYTES;
  let decryptedBytes = 0;

  for (const ref of refs) {
    if (ref.kind === "conversation") continue;
    if (ref.kind === "response") hasResponseRef = true;
    if (ref.kind === "item") hasItemRef = true;
    const hashed = await hashedReference(workspaceId, ref);
    const token = hits.get(`${ref.kind}\u0000${hashed.reference}`);
    if (token === undefined) {
      if (ref.kind === "response") missingResponseSealed = true;
      if (ref.kind === "item") missingItemSealed = true;
      continue;
    }
    const opened = await openContinuationState(
      lane.state.continuationKey,
      { workspaceId, kind: ref.kind, referenceHash: hashed.reference },
      token,
    );
    if (opened === null) {
      if (ref.kind === "response") missingResponseSealed = true;
      if (ref.kind === "item") missingItemSealed = true;
      continue;
    }
    if (opened.kind === "response") {
      decryptedBytes +=
        encoder.encode(toJsonString(opened.items)).byteLength +
        (opened.instructions === undefined ? 0 : encoder.encode(opened.instructions).byteLength);
      if (decryptedBytes > maxExpandedBytes) {
        run.zdr.laneSealedResponses.clear();
        run.zdr.laneSealedItems.clear();
        return { ok: false, error: CONTINUATION_ERRORS.stateTooLarge() };
      }
      run.zdr.laneSealedResponses.set(ref.reference, opened);
      run.zdr.laneZdrAffinityId ??= opened.affinityId;
    } else if (opened.kind === "item") {
      decryptedBytes += encoder.encode(toJsonString(opened.item)).byteLength;
      if (decryptedBytes > maxExpandedBytes) {
        run.zdr.laneSealedResponses.clear();
        run.zdr.laneSealedItems.clear();
        return { ok: false, error: CONTINUATION_ERRORS.stateTooLarge() };
      }
      run.zdr.laneSealedItems.set(ref.reference, opened);
      run.zdr.laneZdrAffinityId ??= opened.affinityId;
    }
  }

  if (hasItemRef && missingItemSealed) {
    return {
      ok: false,
      error: CONTINUATION_ERRORS.notFound().withMessage(
        "The referenced continuation item state is unavailable or expired on this zero-retention route. Send the full conversation or set `store: false`.",
      ),
    };
  }
  if (hasResponseRef && missingResponseSealed && !records.some((r) => stackRoute(run, r))) {
    return {
      ok: false,
      error: CONTINUATION_ERRORS.notFound().withMessage(
        "The referenced continuation response state is unavailable or expired on this zero-retention route. Send the full conversation or set `store: false`.",
      ),
    };
  }
  return { ok: true };
}

export function laneZdrBodyLimit(run: ZdrRun, route: RouteRecord): number {
  if (stackRoute(run, route)) return STACK_BODY_MAX_BYTES;
  return laneVmBodyLimit(run, run.protocol);
}

/** The most a lane route other than a stack route is sent of one request in `protocol`: the API's limit within the lane's cap. */
export function laneVmBodyLimit(run: ZdrRun, protocol: Protocol): number {
  return laneBodyCap(protocol, run.lane!.timing.bodyMaxBytes, run.deps.cfg.bodyParseMaxBytes);
}

/**
 * Computes zero-retention continuation expansion for `route`, or `null` when the request is not a
 * zero-retention Responses request (including when the client explicitly opted out with `store: false`).
 * Throws `ExpandedBodyTooLargeError` if the expanded payload exceeds `maxExpandedBytes`.
 */
export function laneZdrExpansionFor(run: ZdrRun, route: RouteRecord, parsedBody: Json, maxExpandedBytes?: number): ExpandZeroRetentionResult | null {
  if (
    run.lane === null ||
    run.protocol !== "open_ai_responses" ||
    run.facts.translation !== null ||
    run.laneRelays.laneReceived === null ||
    !laneZeroRetentionRoute(run, route) ||
    !storesContinuation(run.protocol, parsedBody)
  ) {
    return null;
  }
  const addInclude = !run.zdr.zdrSuppressInclude && shouldAddEncryptedReasoningInclude(parsedBody, route);
  let expanded: ExpandZeroRetentionResult;
  try {
    expanded = expandZeroRetentionContinuation({
      receivedBytes: run.laneRelays.laneReceived,
      parsedBody,
      sealedResponses: run.zdr.laneSealedResponses,
      sealedItems: run.zdr.laneSealedItems,
      addEncryptedReasoningInclude: addInclude,
      stripReplayedEncryptedReasoning: run.zdr.zdrStripEncryptedReasoning,
      maxExpandedBytes: maxExpandedBytes ?? laneZdrBodyLimit(run, route),
    });
  } catch (error) {
    if (error instanceof ExpandedBodyTooLargeError) throw error;
    return null;
  }
  if (run.lane.continuation !== undefined) {
    run.zdr.laneZdrAffinityId ??= expanded.inheritedAffinityId ?? newContinuationAffinityId();
  }
  return expanded;
}

/** Activates at most one zero-retention fallback mode when upstream rejects an entry-added transform with 400. */
export function activateZdrFallback(run: ZdrRun, attempt: Attempt, status: number, body: Uint8Array): boolean {
  const expansion = attempt.zdrExpansion;
  if (expansion === undefined || run.zdr.zdrFallbackUsed || run.answer.headersSent) return false;
  if (expansion.includeEncryptedReasoningAdded && isUnsupportedIncludeEncryptedReasoningError(status, body)) {
    run.zdr.zdrFallbackUsed = true;
    run.zdr.zdrSuppressInclude = true;
    return true;
  }
  if (expansion.replayedEncryptedReasoning && isInvalidEncryptedContentError(status, body)) {
    run.zdr.zdrFallbackUsed = true;
    run.zdr.zdrStripEncryptedReasoning = true;
    return true;
  }
  return false;
}

/**
 * An entry's endpoint route or a relay stack's route: the software that answers is the provider's API or the relay's
 * own, which may hold a conversation. A sealed-credential lane relay route is not one: Gray's lane calls the vendor
 * itself with `store: false`, so nothing holds the earlier turns.
 */
export function laneHoldsConversation(run: ZdrRun, route: RouteRecord): boolean {
  return stackRoute(run, route) || laneEndpointRoute(run, route);
}

/**
 * The endpoint a lane request's `previous_response_id`, `conversation`, or `item_reference` is bound to.
 * The answers match the API Worker's (`pinContinuation`): 404 `continuation_not_found`, 409
 * `continuation_endpoint_conflict`, 503 `continuation_lookup_unavailable`, 400 `invalid_continuation_reference`.
 */
export async function lanePin(run: ZdrRun, key: KeyRecord, parsed: ParsedRequest, records: readonly RouteRecord[]): Promise<PinResult> {
  const pinBody = continuationBody(run.protocol, parsed);
  if (!continuesEarlierResponse(run.protocol, pinBody)) return { ok: true, pinned: null };
  const record = run.lane?.continuation;
  if (record === undefined) return { ok: false, error: laneContinuationUnrecorded(), unanswered: [] };
  const { cfg } = run.deps;
  const pin = await record.pin({ workspace: key.workspaceId, protocol: run.protocol, body: pinBody, timeoutMs: run.budget.preWait(cfg.continuationCallTimeoutMs + cfg.laneBridgeAnswerMarginMs) });
  if (pin.ok) {
    const conversation = get(pinBody, "conversation");
    const named = conversation !== undefined && conversation !== null;
    return named && records.some((r) => r.endpointId === pin.pinned && (stackRoute(run, r) || laneZeroRetentionRoute(run, r))) ? { ok: false, error: laneContinuationConversation(), unanswered: [] } : pin;
  }
  if (pin.error.code !== "continuation_not_found") return pin;
  // No native route: the translation branch answers (no route at all, or a translation, which is refused there).
  if (records.length === 0) return { ok: true, pinned: null };
  return records.some((r) => laneHoldsConversation(run, r)) ? pin : { ok: false, error: laneContinuationSealed(), unanswered: [] };
}

/** Whether a lane reply's references are recorded: an untranslated Responses reply to a request that stores, on a route that supports continuation pinning or zero-retention continuation. */
export function laneBinds(run: ZdrRun, a: Answering, attempt: Attempt): boolean {
  return (
    run.lane?.continuation !== undefined &&
    a.protocol === "open_ai_responses" &&
    a.stores &&
    run.facts.translation === null &&
    (laneHoldsConversation(run, attempt.route.record) || laneZeroRetentionRoute(run, attempt.route.record))
  );
}

/**
 * Records continuation references for a lane Responses reply (`LaneContinuation.bind`), within what
 * the post phase has left. Best effort.
 *
 * - Plain Endpoint routes: hash-only endpoint pinning for `response`, `conversation`, and `item`
 *   (`output[].id`), with no sealed state.
 * - Zero-retention routes: seals `SealedResponseState` (`response`) and `SealedItemState` (`item`,
 *   up to 64) under the per-app TEE key with `CONTINUATION_STATE_TTL_MS` (2h), never binding
 *   `conversation`, and falls back to hash-only references if a payload exceeds 512 KiB.
 */
export async function laneBindState(run: ZdrRun, a: Answering, attempt: Attempt, captured: CapturedResponsesReply): Promise<void> {
  const lane = run.lane;
  const continuation = lane?.continuation;
  if (lane === null || continuation === undefined) return;
  const { cfg } = run.deps;
  const workspace = run.caller.key!.workspaceId;
  const route = attempt.route.record;
  const zeroRetention = laneZeroRetentionRoute(run, route);
  const references: BindReference[] = [];

  if (!zeroRetention) {
    if (captured.id !== null) references.push({ kind: "response", reference: captured.id });
    if (!stackRoute(run, route) && captured.conversation !== null) references.push({ kind: "conversation", reference: captured.conversation });
    for (const itemId of captured.outputIds.slice(0, MAX_REPLY_ITEM_REFERENCES)) {
      references.push({ kind: "item", reference: itemId });
    }
    if (references.length === 0) return;
    const result = await continuation.bind({
      workspace,
      endpoint: route.endpointId,
      model: a.model,
      reply: { id: captured.id },
      references,
      timeoutMs: run.budget.postWait(cfg.continuationCallTimeoutMs + cfg.laneBridgeAnswerMarginMs),
    });
    if (result.failed > 0) console.warn(JSON.stringify({ level: "warn", event: "lane_continuation_unbound", request_id: run.requestId, endpoint: route.endpointId, failed: result.failed }));
    return;
  }

  const affinityId = run.zdr.laneZdrAffinityId ?? run.client.sessionId ?? newContinuationAffinityId();
  const requestBody = run.zdr.laneZdrRequestBody;
  const effectiveInputs = attempt.zdrExpansion?.effectiveInputItems ?? (requestBody === null ? [] : normalizeResponsesInput(requestBody));
  const effectiveInstructions =
    attempt.zdrExpansion?.effectiveInstructions ??
    (requestBody !== null && isObject(requestBody) && typeof get(requestBody, "instructions") === "string"
      ? (get(requestBody, "instructions") as string)
      : undefined);
  const key = lane.state.continuationKey;

  if (captured.id !== null) {
    let sealed: string | null = null;
    if (!captured.overflow) {
      const refHash = (await hashedReference(workspace, { kind: "response", reference: captured.id })).reference;
      const payload: SealedResponseState = {
        v: 1,
        kind: "response",
        items: [...effectiveInputs, ...captured.output],
        ...(effectiveInstructions === undefined ? {} : { instructions: effectiveInstructions }),
        affinityId,
      };
      sealed = await sealContinuationState(key, { workspaceId: workspace, kind: "response", referenceHash: refHash }, payload);
    }
    references.push(sealed === null ? { kind: "response", reference: captured.id } : { kind: "response", reference: captured.id, sealed });
  }

  if (!captured.overflow && captured.output.length > 0) {
    const seen = new Set<string>();
    for (const item of captured.output) {
      if (seen.size >= MAX_REPLY_ITEM_REFERENCES) break;
      const itemId = get(item, "id");
      if (typeof itemId !== "string" || itemId.length === 0 || seen.has(itemId)) continue;
      seen.add(itemId);
      const refHash = (await hashedReference(workspace, { kind: "item", reference: itemId })).reference;
      const sealed = await sealContinuationState(key, { workspaceId: workspace, kind: "item", referenceHash: refHash }, { v: 1, kind: "item", item, affinityId });
      references.push(sealed === null ? { kind: "item", reference: itemId } : { kind: "item", reference: itemId, sealed });
    }
  } else {
    for (const itemId of captured.outputIds.slice(0, MAX_REPLY_ITEM_REFERENCES)) {
      references.push({ kind: "item", reference: itemId });
    }
  }

  if (references.length === 0) return;
  const result = await continuation.bind({
    workspace,
    endpoint: route.endpointId,
    model: a.model,
    reply: { id: captured.id },
    references,
    stateTtlMs: CONTINUATION_STATE_TTL_MS,
    timeoutMs: run.budget.postWait(cfg.continuationCallTimeoutMs + cfg.laneBridgeAnswerMarginMs),
  });
  if (result.failed > 0) console.warn(JSON.stringify({ level: "warn", event: "lane_continuation_unbound", request_id: run.requestId, endpoint: route.endpointId, failed: result.failed }));
}

/** The continuation binding of the reply (an untranslated Responses reply to a request that stores), or null. */
export function binding(run: ZdrRun, a: Answering, attempt: Attempt): { readonly tap: ChunkTap | null; readonly stateTap: ResponsesStateTap | null } {
  if (run.lane !== null) {
    if (!laneBinds(run, a, attempt)) return { tap: null, stateTap: null };
    const stateTap = new ResponsesStateTap();
    return {
      stateTap,
      tap: {
        observe: async (chunk: Uint8Array) => {
          stateTap.pushSseChunk(chunk);
        },
      },
    };
  }
  const streamBinding = StreamBinding.forReply({
    locate: run.io.continuation,
    workspace: run.caller.key!.workspaceId,
    region: run.deps.region,
    timing: continuationStoreTiming(run, "post"),
    endpoint: attempt.route.record.endpointId,
    model: a.model,
    protocol: a.protocol,
    stores: a.stores,
    translated: run.facts.translation !== null,
  });
  if (streamBinding === null) return { tap: null, stateTap: null };
  const stateTap = new ResponsesStateTap();
  return {
    stateTap,
    tap: {
      observe: async (chunk: Uint8Array) => {
        stateTap.pushSseChunk(chunk);
        await streamBinding.observe(chunk);
      },
    },
  };
}
