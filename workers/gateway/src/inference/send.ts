/**
 * Opening and sending an attempt (`InferenceRun`, inference.ts): its permit, plan and body checks, the lane relay's or
 * the stack's part, the upstream body it is sent and the request to the upstream, egress or the peer.
 */
import type { BlockLease } from "@gray/endpoint";
import { ApiError, ERROR_BODY_WAIT_MS, type Next, bareOutcome, classify, headerReader, stopOfSkip, upstreamUnavailable } from "@gray/errors";
import { Overlay, geminiOperationUrl } from "@gray/protocol";
import { openCredential } from "../crypto.ts";
import { Dispatcher } from "../dispatcher.ts";
import { probeSent, releasePermit } from "../endpoints.ts";
import { STACK_BODY_MAX_BYTES } from "../lane/body-limits.ts";
import { EGRESS_HEADER, type EgressOwnAnswer, LANE_CODES, bodyHashOf, egressCapacity, egressHeader, egressOwnAnswer, egressRefused, egressSentNothing, forwardedStream, laneDuplicateKey, laneUpstreamOf, officialUpstream, receiptDraft } from "../lane/hooks.ts";
import { type ExpandZeroRetentionResult, ExpandedBodyTooLargeError } from "../lane/responses-continuation.ts";
import type { LaneReceiptDraft } from "../lane/types.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import type { Route } from "../routes.ts";
import type { Selection } from "../sinks.ts";
import { type BodyEdits, UPSTREAM_BODY_CHUNK_BYTES, type UpstreamBody, heldBody, releasedAtEnd, sendable, storedBody, upstreamHeaders } from "../upstream.ts";
import { abandonLease, attemptBound, classifyContext, endAttempt, failAttempt, gates, inSessionNow, issuerOf, laneCompositionRefused, noteAgentRefusal, noteFollowed, overlayFor, passRoute, startEvidence } from "./attempt.ts";
import { type BodyLimitsRun, bodyEdits, laneForwardedFor, overVmLimit } from "./body-limits.ts";
import { laneAttempt, laneOutcomeFor } from "./lane-attempt.ts";
import { errorBody, unsentOutcome } from "./settle-pure.ts";
import { peerCall, peerFailed, sendPeer, stackAttemptPlan, stackPlan, stackTap } from "./stack-peer.ts";
import { laneEndpointKey, laneEndpointRoute, stackRoute } from "./stack-routes.ts";
import type { Acquired, Answered, Attempt, Dispatch, Prepared, SendResult, Stopped } from "./types.ts";
import { activateZdrFallback, laneZdrExpansionFor } from "./zdr.ts";
import { openLaneSent, resetLaneSent } from "./lane-receipt.ts";
import { spoolOpener } from "./request-body.ts";

/** What send.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface SendRun extends BodyLimitsRun {}

/**
 * Opens the attempt on what it acquired, sends it, and closes it if it failed: `continue` for the next
 * attempt, or the answer, or why the request stops.
 */
export async function openAttempt(run: SendRun, d: Dispatcher, o: Dispatch, prepared: Prepared, route: Route, acquired: Acquired, next: Next, selection: Selection, backoffMs: number | null, answerDeadline: number, retest: BlockLease | null): Promise<Answered | Stopped | { readonly kind: "continue" }> {
  const { clock } = run.deps;
  const { permit, group, ranked } = acquired;
  // Compute zero-retention continuation expansion up front so stable affinity IDs are ready
  // before scheduler picks (`laneAttempt`) and peer/stack dispatch.
  let directZdrExpansion: ExpandZeroRetentionResult | null = null;
  if (!stackRoute(run, route.record)) {
    try {
      directZdrExpansion = laneZdrExpansionFor(run, route.record, o.parsed.value);
    } catch (error) {
      if (error instanceof ExpandedBodyTooLargeError) {
        if (retest !== null) gates(run).drop(retest);
        run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, permit, unsentOutcome(permit), false));
        const label = overVmLimit(run, prepared.protocol, error.limitBytes);
        passRoute(run, d, route, label);
        if (selection === "same_route") d.stallRepeat(route, stopOfSkip(label));
        return { kind: "continue" };
      }
      throw error;
    }
  }
  // S23: a stack relay's route has no scheduler pick and no sealed credential: the relay's container
  // picks its own account, and an entry's attempt is one call to it over the peer hop. A route it cannot
  // be made for (no usable peer, a body the hop cannot carry) is passed over unsent.
  const stackPlan = stackRoute(run, route.record) ? stackAttemptPlan(run, route, o) : null;
  if (stackPlan !== null && !stackPlan.ok) {
    if (retest !== null) gates(run).drop(retest);
    run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, permit, unsentOutcome(permit), false));
    // A body too large for the stack is the request's to change, as at admission (`overRequestLimit`), not a route
    // that cannot be made now: its pass weighs as any other route's too small for the body (`Tried.skipped`).
    const label = stackPlan.code === "body_over_stack_limit" ? overVmLimit(run, prepared.protocol, STACK_BODY_MAX_BYTES) : `lane_stack_unavailable:${stackPlan.code}`;
    passRoute(run, d, route, label);
    // The repeat of a route that failed, which cannot be made now (an entry's peer left usable only by a re-pin in
    // the background, L5), keeps only itself from the attempt, as a repeat the dispatcher could not acquire does: a
    // stack route has no account pool, so its pass alone would leave it the repeat chosen again, after a backoff and a
    // permit each time, until the request's deadline (F14).
    if (selection === "same_route") d.stallRepeat(route, stopOfSkip(label));
    return { kind: "continue" };
  }
  // A lane relay has no Gray-sealed credential to open: its account and its auth headers come from
  // the relay itself (design v2 §C.6, B2). The main lane's `master`/`openCredential` is skipped for
  // it, because `master: () => null` in the lane would otherwise pass every lane route over as
  // `route_inactive` before anything was sent.
  const lanePick = run.lane === null || route.record.auth !== "lane_relay" || stackPlan !== null ? null : await laneAttempt(run, route, o, prepared, d.tried.attempts);
  if (lanePick !== null && !lanePick.ok) {
    // No account: the relay's scheduler said so, its pool answered with a wait, or its credential
    // store refused the account. The route is passed over like one that cannot serve; when every
    // route is, the request ends 503 (the body is unchanged). D111(d): the cause stays on the
    // skipped-route record, which the request's wide event carries (`routing_skipped`).
    // A re-test lease it took goes back: nothing reached the vendor.
    if (retest !== null) gates(run).drop(retest);
    run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, permit, unsentOutcome(permit), false));
    passRoute(run, d, route, `lane_account_unavailable:${lanePick.code}`);
    return { kind: "continue" };
  }
  const lanePicked = lanePick?.attempt ?? null;
  // An entry's endpoint route (docs/design/lane-provider-routes.md section 5): the provider's key from the entry's
  // memory, or one `endpoint.credential` call within the attempt's budget; none in time passes the route over below.
  // A lane without the entry's table (a relay stack VM) opens no key: its `master` is null, so the route is passed over.
  const laneEndpoint = laneEndpointRoute(run, route.record) ? run.lane!.endpointFetch : undefined;
  // The lane's attempt carries no supplier credential at all (`upstreamHeaders` refuses a lane route
  // rather than send one); the empty string keeps the attempt's shape and is never read for it.
  let credential: string | null;
  if (lanePicked !== null || stackPlan !== null) {
    credential = "";
  } else if (laneEndpoint !== undefined) {
    credential = await laneEndpointKey(run, route.record, answerDeadline);
  } else {
    const master = await run.deps.master();
    credential = master === null ? null : await openCredential(master, route.record.endpointId, route.record.credential);
  }
  if (credential === null) {
    // A credential the gateway cannot open is the gateway's fault: no upstream is asked, and the route
    // is passed over like one that cannot serve. A re-test lease it took goes back.
    if (retest !== null) gates(run).drop(retest);
    run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, permit, unsentOutcome(permit), false));
    passRoute(run, d, route, "route_inactive");
    return { kind: "continue" };
  }
  // The attempt is about to go: whether it follows a refusal is what its bound reads (`going`, then `attempt_bound`).
  d.going(next);
  const bound = attemptBound(run, d, route, answerDeadline, retest);
  const index = d.tried.attempts;
  if (index === 0 && run.admitting.planProbe === null) {
    // Without a probe the plan leased for its head (docs/utility-routing.md "Evidence"): a probe permit the shard grants
    // the first attempt names the probe endpoint, and when every candidate was open and the plan put no probe first, the
    // shard's permit says why the head went first. Never a failover's attempt.
    const probePermit = permit.probeId !== null && permit.trial !== true;
    if (probePermit) run.admitting.recoveryProbeEndpoint = route.record.endpointId;
    if (run.admitting.planAllOpen && permit.probeId !== null) run.admitting.headReason = probePermit ? "recovery_probe" : "recovery_trial";
  }
  d.sent(route, next);
  if (next !== "none") noteFollowed(run, next, backoffMs);
  const attemptZdrExpansion = stackPlan !== null && stackPlan.ok ? (stackPlan.expansion ?? undefined) : (directZdrExpansion ?? undefined);
  const attempt: Attempt = {
    route,
    index,
    permit,
    startedAt: clock(),
    controller: new AbortController(),
    credential,
    issuer: null,
    status: null,
    ended: false,
    next,
    selection,
    inSession: inSessionNow(run, route),
    committed: false,
    backoffMs,
    retest,
    ...(lanePicked === null ? {} : { lane: lanePicked }),
    group,
    ranked,
    ...(laneEndpoint === undefined ? {} : { endpoint: { fetch: laneEndpoint(route.record) } }),
    ...(attemptZdrExpansion === undefined ? {} : { zdrExpansion: attemptZdrExpansion }),
  };
  // F2 D72: the receipt id, forwarded draft, receipt kind and `laneSent` state this attempt may replace, kept
  // so a pre-connect egress failure (or an unsent peer attempt with no envelope) can restore them cleanly.
  const laneBefore = { receiptId: run.receipt.laneReceiptId, forwardedDraft: run.receipt.laneForwardedDraft, forwardedReceipt: run.receipt.lastForwardedReceipt, laneSentOpen: run.receipt.laneSentOpen };
  if (stackPlan !== null && stackPlan.ok) attempt.peer = peerCall(run, stackPlan, attempt, o);
  attempt.evidence = startEvidence(run, route, o.canonical);
  run.admitting.current = attempt;
  run.facts.toolIds?.startAttempt();
  attempt.issuer = await issuerOf(run, route.record, credential);
  const attemptUntil = bound ?? answerDeadline;
  let result = await send(run, o, prepared, attempt, attemptUntil);
  let prefetchedStatusBody: Uint8Array | null = null;
  if (!run.zdr.zdrFallbackUsed && !run.answer.headersSent && !run.presence.gone && attempt.zdrExpansion !== undefined) {
    let fallbackStatus: number | null = null;
    let fallbackBody: Uint8Array | null = null;
    if (result.kind === "peer" && result.outcome.kind === "vendor_error") {
      fallbackStatus = result.outcome.status;
      fallbackBody = result.outcome.body;
    } else if (
      result.kind === "status" &&
      attempt.lane !== undefined &&
      result.response.status === 400 &&
      (attempt.zdrExpansion.includeEncryptedReasoningAdded || attempt.zdrExpansion.replayedEncryptedReasoning)
    ) {
      fallbackStatus = result.response.status;
      prefetchedStatusBody = await errorBody(result.response, Math.min(answerDeadline, clock() + ERROR_BODY_WAIT_MS), clock);
      fallbackBody = prefetchedStatusBody;
    }
    if (
      fallbackStatus !== null &&
      fallbackBody !== null &&
      clock() < attemptUntil &&
      activateZdrFallback(run, attempt, fallbackStatus, fallbackBody)
    ) {
      const retried = await retryZdrFallback(run, attempt, route, o, prepared, attemptUntil, laneBefore);
      if (retried !== null) {
        result = retried;
        prefetchedStatusBody = null;
      }
    }
  }
  if (attempt.peer !== undefined && attempt.peer.envelopeSha256 === null && !run.answer.headersSent) {
    run.receipt.laneReceiptId = laneBefore.receiptId;
    run.receipt.lastForwardedReceipt = laneBefore.forwardedReceipt;
    if (!laneBefore.laneSentOpen) resetLaneSent(run);
  }
  switch (result.kind) {
    case "answered":
      return { kind: "answered", attempt, response: result.response, firstBytesBy: bound };
    case "status": {
      const status = result.response.status;
      // Bounded by the deadline and a small byte budget; its end also ends the attempt's transport.
      const body = prefetchedStatusBody ?? (await errorBody(result.response, Math.min(answerDeadline, clock() + ERROR_BODY_WAIT_MS), clock));
      // A lane attempt and an entry's endpoint attempt (egress's `/route/` kind) go through egress, which marks every
      // answer it gives itself: read before any classification, such an answer is never the provider's.
      const own = lanePicked !== null || attempt.endpoint !== undefined ? egressOwnAnswer(result.response.headers, body) : null;
      if (own !== null) {
        return egressAnswered(run, d, attempt, own, status, () => {
          run.receipt.laneReceiptId = laneBefore.receiptId;
          run.receipt.laneForwardedDraft = laneBefore.forwardedDraft;
          run.receipt.lastForwardedReceipt = laneBefore.forwardedReceipt;
          run.receipt.attemptLaneDrafts.delete(attempt.index);
          if (!laneBefore.laneSentOpen) resetLaneSent(run);
        });
      }
      attempt.status = status;
      if (attempt.evidence !== undefined) attempt.evidence.upstreamStatus = status;
      const classified = classify(status, headerReader(result.response.headers), body, classifyContext(run, o.canonical.model, route), clock() - attempt.startedAt, clock());
      noteAgentRefusal(run, attempt, classified.outcome, { status, body });
      failAttempt(run, d, attempt, classified.outcome, classified.error, "upstream_attempt_failed", false, false, body);
      return { kind: "continue" };
    }
    case "connect":
      // Nothing of the body was taken: no request reached the upstream, which did no work for it.
      failAttempt(run, d, attempt, bareOutcome("connect", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
      return { kind: "continue" };
    case "transport":
      // The connection broke after the request was sent: whether the upstream did work is unknown, so its
      // permit stays taken as for a timeout.
      failAttempt(run, d, attempt, bareOutcome("transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
      return { kind: "continue" };
    case "timeout":
      // The attempt bound or the time for an answer ran out while the upstream may still be working.
      failAttempt(run, d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
      return { kind: "continue" };
    case "unsent":
      // The bound ran out while the request still waited in the gateway (its connection, its body's): the
      // route never got it, so it is not the route's timeout, and its permit goes back as unused.
      failAttempt(run, d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false, false, undefined, true);
      return { kind: "continue" };
    case "left":
      endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left");
      return { kind: "stopped", stop: "client_left" };
    case "mapping":
      // A route whose mapping has no Gemini method cannot be asked: the route's fault, not the supplier's.
      endAttempt(run, attempt, unsentOutcome(attempt.permit), false, "invalid_native_mapping", { rejected: true });
      return { kind: "stopped", stop: null, error: new ApiError(502, "invalid_native_mapping") };
    case "not_official":
      // A lane route whose URL is not an official vendor origin is never sent: the route is passed
      // over without an attempt, and the request ends with Gray's own refusal when none is left.
      endAttempt(run, attempt, unsentOutcome(attempt.permit), false, "lane_upstream_not_official", { rejected: true });
      passRoute(run, d, route, "lane_upstream_not_official");
      return { kind: "continue" };
    case "lane_refused": {
      // The lane's body could not be composed: `send` carries the composed refusal itself (F2
      // hooks-10). A failed append composition is the lane's fixed 403 `relay_policy_refused`, the
      // same answer a policy refusal gets (F2 D3), never a bare 400 `invalid_json`; a body Gray
      // cannot rewrite is its own fixed 400. No upstream was asked.
      const refused = result.error;
      if (refused.code === LANE_CODES.policyRefused) laneCompositionRefused(run, attempt.route);
      endAttempt(run, attempt, unsentOutcome(attempt.permit), false, refused.code, { rejected: true });
      return { kind: "stopped", stop: null, error: refused };
    }
    case "peer":
      return peerFailed(run, d, attempt, o.canonical.model, result.outcome);
  }
}

/** Re-dispatches the same attempt once after a zero-retention fallback stripped an unsupported transform. */
export async function retryZdrFallback(
  run: SendRun,
  attempt: Attempt,
  route: Route,
  o: Dispatch,
  prepared: Prepared,
  until: number,
  laneBefore: { readonly receiptId: string | null; readonly forwardedDraft: LaneReceiptDraft | null },
): Promise<SendResult | null> {
  // The retry is planned before the first call is let go: a plan that fails leaves that call, its answer, inner
  // receipt and trace as they were, and the attempt is settled on its own answer.
  if (attempt.peer !== undefined) {
    const retryPlan = stackAttemptPlan(run, route, o);
    if (!retryPlan.ok) return null;
    const previous = attempt.peer;
    previous.close();
    const idx = run.stackPeer.peerCalls.indexOf(previous);
    if (idx >= 0) run.stackPeer.peerCalls.splice(idx, 1);
    run.stackPeer.lanePeerExpansions.delete(previous);
    run.stackPeer.peerHopEvents.delete(previous);
    run.stackPeer.peerRid = null;
    run.stackPeer.peerHops.clear();
    attempt.zdrExpansion = retryPlan.expansion ?? undefined;
    attempt.peer = peerCall(run, retryPlan, attempt, o);
    return await send(run, o, prepared, attempt, until);
  }
  if (attempt.lane !== undefined) {
    run.laneRelays.laneForwarded.clear();
    attempt.laneDraft = undefined;
    run.receipt.laneReceiptId = laneBefore.receiptId;
    run.receipt.laneForwardedDraft = laneBefore.forwardedDraft;
    try {
      attempt.zdrExpansion = laneZdrExpansionFor(run, route.record, o.parsed.value) ?? undefined;
    } catch (error) {
      if (error instanceof ExpandedBodyTooLargeError) return null;
      throw error;
    }
    return await send(run, o, prepared, attempt, until);
  }
  return null;
}

/**
 * An answer egress gave itself on an attempt's call (`egressOwnAnswer`, by its mark), which says nothing of the provider.
 *
 * D72: when no byte of the request reached the vendor or provider, `sendable`'s marks are rolled back (`rollBack`)
 * before any response headers can promise a receipt: the account is reported as not reaching the vendor, and the
 * response names no id. If early stream headers already went (the narrow race), the id they named stays and the
 * receipt is finalised from this attempt's draft (`request.forwarded` then means handed to the attested egress).
 *
 * - A connection that failed (D18/E1) is a failure of the egress path, not of the account, so a dead proxy cannot
 *   look like a banned credential to the relay: a `connect` failure before the vendor, else `transport`, and the next
 *   route may go. Its status stays the attempt's, as before.
 * - Egress's body budget full (`capacity`) is Gray's capacity: 429 `gateway_capacity` with no `retry-after`, the
 *   attempt Gray's own (not counted, no `providerFailure`, no rest). No other route is tried: every route of this
 *   entry leaves through the same egress and its one budget, so the next would wait on the same bytes, and the
 *   entry answers its own capacity (the forms it holds, the answers it keeps) the same way.
 * - Egress refusing the request as handed to it, or failing itself (`refused`), is Gray's error: 500
 *   `internal_error`, the attempt Gray's own. No other route is tried either: the next attempt is built by the same
 *   code and handed to the same egress.
 */
export function egressAnswered(run: SendRun, d: Dispatcher, attempt: Attempt, own: EgressOwnAnswer, status: number, rollBack: () => void): { readonly kind: "continue" } | Stopped {
  const { clock } = run.deps;
  const unsent = egressSentNothing(own) && !run.answer.headersSent;
  if (unsent) {
    rollBack();
    attempt.sentToVendor = false;
    if (attempt.lane !== undefined) attempt.laneNotSentReport = true;
  }
  switch (own.kind) {
    case "before_vendor":
    case "after_vendor":
      attempt.status = status;
      if (attempt.evidence !== undefined) attempt.evidence.upstreamStatus = status;
      failAttempt(run, d, attempt, bareOutcome(unsent ? "connect" : "transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
      return { kind: "continue" };
    case "capacity": {
      const error = egressCapacity();
      endAttempt(run, attempt, unsentOutcome(attempt.permit), false, error.code, { rejected: true });
      return { kind: "stopped", stop: null, error };
    }
    case "refused": {
      const error = egressRefused();
      endAttempt(run, attempt, unsentOutcome(attempt.permit), own.sent, error.code, { rejected: true });
      return { kind: "stopped", stop: null, error };
    }
  }
}

/**
 * The body of one attempt at `route`, streamed as the upstream reads it (upstream.ts). A tier C
 * body is read from R2 under one connection the attempt took before sending (`Outbound.hold`),
 * released when the stream ends: its reads never wait behind the upstream request they feed.
 */
export async function attemptBody(run: SendRun, o: Dispatch, prepared: Prepared, overlay: Overlay, signal: AbortSignal, change?: BodyEdits, forwardedBytes?: Uint8Array): Promise<{ readonly body: UpstreamBody; readonly done: () => void }> {
  // A lane attempt sends the bytes `applyDeclaredChanges` composed (design v2 §C.7, M2, M4): the
  // client's body with Gray's declared ops and the relay's appends, cached per `(relayId, appends)`
  // so every retry at the relay sends the same object. The overlay is never spliced: it is the main
  // lane's way of writing a body the lane may not write.
  if (forwardedBytes !== undefined) return { body: forwardedStream(forwardedBytes, UPSTREAM_BODY_CHUNK_BYTES), done: () => {} };
  if (run.facts.translation === null && o.body.tier === "C") {
    // Waiting for the connection ends when the attempt does (the client left, its deadline passed).
    const taken = await run.outbound.hold(signal);
    run.facts.bodyHeld++;
    run.deps.meter?.bodyHeld?.();
    let given = false;
    const release = (): void => {
      if (given) return;
      given = true;
      run.facts.bodyHeld--;
      taken();
    };
    run.facts.holds.push(release);
    // Read under the connection just taken, not through `run` (outbound.ts `hold`).
    const stored = storedBody(spoolOpener(run, o.body, run.deps.env.CONTENT), o.body.length, o.parsed.layout!, overlay, change);
    return { body: releasedAtEnd(stored, release), done: release };
  }
  return { body: heldBody(prepared.body!, prepared.layout, overlay, run.deps.meter?.heldBody, change), done: () => {} };
}

/** The response hash's tap, or none on the main lane: every byte the client's stream queues is hashed. */
export function laneTap(run: SendRun): ((bytes: Uint8Array) => void) | undefined {
  if (run.lane === null) return undefined;
  return (bytes: Uint8Array): void => {
    run.receipt.laneResponse?.update(bytes);
    stackTap(run, bytes);
  };
}

/**
 * One upstream call, until its response headers (the attempt's bound or the time for an answer, the
 * client's leaving). A fetch that fails before the upstream took any of the body is a refused connection:
 * a request whose body was never read reached no upstream whole (`connect`); one that fails after is a
 * broken connection, whose work is unknown (`transport`).
 */
export async function send(run: SendRun, o: Dispatch, prepared: Prepared, attempt: Attempt, until: number): Promise<SendResult> {
  const { clock } = run.deps;
  const route = attempt.route.record;
  const protocol = prepared.protocol;
  const overlay = overlayFor(run, o, prepared, route);
  // The client's tool-call handles as this route is sent them: the originals only where it issued them.
  const change = bodyEdits(prepared.removals, run.facts.toolIds?.forAttempt(attempt.issuer, protocol));
  // A Gemini route names the model and the method in its URL (`gemini_operation_url`).
  const url = protocol === "gemini" ? geminiOperationUrl(route.url, o.canonical.stream) : route.url;
  if (url === undefined) return { kind: "mapping" };
  // A confidential-lane request may only reach an official vendor origin, and the check runs before
  // every send (design v2 §B, m8): the route's URL is used exactly as the control plane built it,
  // never rebuilt, and a URL that names any other origin is refused rather than sent.
  const lane = attempt.lane;
  if (lane !== undefined && !officialUpstream(url)) return { kind: "not_official" };
  // An entry's endpoint attempt (docs/design/lane-provider-routes.md section 5): its own fetch checks the URL against the
  // endpoint's row in egress's table, and egress checks it again.
  const endpoint = attempt.endpoint;
  // A recovery probe goes out from here: its spell's clock runs whatever becomes of its lease (the server's
  // `probe_sent`, called as it dispatches). The dispatch's point records when it went (`mark_dispatched`).
  if (attempt.permit.probeId !== null && attempt.permit.trial !== true) run.ctx.waitUntil(probeSent(run.io.endpoints, run.deps.region, attempt.permit));
  attempt.dispatchedAtMs = run.deps.clock();
  // From here the attempt owns the recovery lease the plan's head took for its route (the server's `ProbeLease::sent`);
  // one held for another route, which this attempt does not probe, goes back.
  await run.routing.heldProbe.sent(attempt.route.record.endpointId);
  // S23: a stack relay's attempt is one call over the peer hop to its stack VM, whose egress checks it; nothing below
  // (the overlay, the composed body, the account's headers) applies to it.
  if (attempt.peer !== undefined) return sendPeer(run, attempt, attempt.peer, until);
  // A translated request forwards none of the client's protocol headers. A lane route's headers are
  // the account's merged with the client's, built once in `openAttempt` (§C.6, M1), and never
  // `upstreamHeaders`' (a lane relay has no credential of that kind).
  const headers = lane !== undefined ? new Headers(lane.headers) : upstreamHeaders(protocol, route, attempt.credential, run.facts.translation === null ? run.request.headers : new Headers());
  // E1/E2: the attempt's egress proxy travels in the one sidecar header, never in the vendor's
  // header set. Delete first, so no account or client header can ever supply this control value;
  // a direct account sends nothing and the sidecar dials directly. An endpoint route has no proxy.
  if (lane !== undefined || endpoint !== undefined) {
    headers.delete(EGRESS_HEADER);
    if (lane?.egress !== undefined) headers.set(EGRESS_HEADER, egressHeader(lane.egress));
  }
  // The attempt's bound and the client's leaving abort it from here on, also while its calls wait for a
  // connection (outbound.ts): a tier C body's R2 connection, then the upstream's.
  let timedOut = false;
  const deadlined = () => {
    timedOut = true;
    attempt.controller.abort("attempt_deadline");
  };
  // The attempt's deadline is the request path's timer; `deps.timers` (client.ts `StreamTimers`) lets
  // a test drive it exactly instead of racing a loaded machine (F2 D43, as stream-timeouts.test.ts
  // does for the stream bounds). Production has no timers and keeps the platform's `setTimeout`.
  const timers = run.deps.timers;
  const timer = timers === undefined ? setTimeout(deadlined, Math.max(0, until - clock())) : timers.setTimeout(deadlined, Math.max(0, until - clock()));
  // A client that leaves does not end an attempt already sent: it is cut only when the Worker could no
  // longer read its answer (client.ts `readOnUntil`), and then counts as left unread. One that has no
  // connection yet never left the gateway (`started`): no upstream works for it, and it ends at once.
  /** The outbound gate made the call (a connection): before that the request never left the gateway. */
  let started = false;
  let readOn: unknown | null = null;
  const unsubscribe = run.presence.onLeave(() => {
    if (!started) {
      attempt.controller.abort("client_left");
      return;
    }
    const ms = Math.max(0, (run.presence.readOnUntil ?? clock()) - clock());
    const cut = () => {
      run.answer.leftUnread = true;
      attempt.controller.abort("client_left_unread");
    };
    readOn = timers === undefined ? setTimeout(cut, ms) : timers.setTimeout(cut, ms);
  });
  let made: { readonly body: UpstreamBody; readonly done: () => void } | null = null;
  let body: ReadableStream<Uint8Array> | null = null;
  let taken = false;
  try {
    // The lane's bytes are composed before the body is built: the same object goes to `sendable`
    // (one Content-Length, design v2 §C.7 M4) and its hash and events are the attempt's receipt
    // draft (§C.8 M6). A failed attempt's draft is dropped with it; the committed one is adopted.
    let forwarded: Uint8Array | undefined;
    if (lane !== undefined || endpoint !== undefined) {
      const composed = await laneForwardedFor(run, attempt.route, prepared, o);
      // F2 hooks-10: the composition's own refusal is the answer (a 403 for the relay's appends, a
      // fixed 400 for a body Gray cannot rewrite), never a bare `invalid_json`. Nothing left the
      // gateway: the recovery lease the attempt took over goes back, as below.
      if (composed === null || !composed.ok) {
        abandonLease(run, attempt.route);
        return { kind: "lane_refused", error: composed === null ? laneDuplicateKey() : composed.error };
      }
      forwarded = composed.bytes;
      attempt.laneDraft = receiptDraft({
        continuationExpanded: composed.continuationExpanded,
        modifiedEvents: composed.events,
        policy: lane === undefined ? null : (laneOutcomeFor(run, lane.relayId, protocol, o) ?? null),
        forwardedHash: bodyHashOf(composed.bytes),
        accountId: lane?.accountId ?? null,
        upstreamModel: route.upstreamModel,
        // The host the bytes went to (`upstream_name`): the vendor's for a relay, the provider's for an endpoint route.
        upstream: laneUpstreamOf(route),
      });
    }
    made = await attemptBody(run, o, prepared, overlay, attempt.controller.signal, change, forwarded);
    // F2 D29: the fetch taking the body's first chunk is what "handed to a vendor fetch" means (a
    // connect that never takes it sent nothing). Only then is the attempt marked sent, the receipt id
    // allocated, the forwarded draft kept and the early-header gate opened; `started` below is the
    // outbound gate's connection callback, which can run before the fetch is invoked. D72: for the
    // lane this is not yet "reached the vendor": gray-egress reads the body before it dials, and an
    // egress 502 with a pre-connect code rolls these marks back in `openAttempt` when no response
    // headers have gone out (a stream whose early headers already named the id keeps the receipt).
    body = sendable(made.body, () => {
      taken = true;
      attempt.sentToVendor = true;
      if (lane !== undefined || endpoint !== undefined) {
        // F2 hooks-4/D3: the body is handed to the vendor's fetch now, so a stream may follow with its
        // headers at once: the response must name the id its receipt will use, and the last body that
        // really went is the receipt of a request nothing commits or refuses.
        run.receipt.laneReceiptId ??= newLaneReceiptId();
        run.receipt.laneForwardedDraft = attempt.laneDraft ?? null;
        if (attempt.laneDraft !== undefined) run.receipt.attemptLaneDrafts.set(attempt.index, attempt.laneDraft);
        run.receipt.lastForwardedReceipt = "lane";
        openLaneSent(run);
      }
    });
    // An endpoint attempt's own fetch, through the request's outbound gate as every upstream fetch.
    const upstream = endpoint === undefined ? run.io.fetch : run.outbound.fetch(endpoint.fetch);
    const response = await upstream(url, { method: "POST", headers, body, signal: attempt.controller.signal, redirect: "manual" }, () => {
      started = true;
    });
    if (response.status >= 200 && response.status <= 299) return { kind: "answered", response };
    // Not answered: a tier C body's R2 connection goes back now, before the next attempt asks for one.
    made.done();
    return { kind: "status", response };
  } catch {
    body?.cancel().catch(() => {});
    made?.done();
    // An attempt that ended before the outbound gate made its call never left the gateway (its body unbuilt, its bound
    // or its client gone while it waited): the recovery lease it took over from the plan's head goes back, as the
    // server's `close_attempt` gives back that of an attempt neither observed nor sent. One that reached a connection
    // keeps it: its probe went, whatever came of it.
    if (!started) abandonLease(run, attempt.route);
    if (run.presence.gone && (run.answer.leftUnread || !started)) return { kind: "left" };
    if (timedOut) return { kind: started ? "timeout" : "unsent" };
    return { kind: taken ? "transport" : "connect" };
  } finally {
    if (timers === undefined) {
      clearTimeout(timer as ReturnType<typeof setTimeout>);
      if (readOn !== null) clearTimeout(readOn as ReturnType<typeof setTimeout>);
    } else {
      timers.clearTimeout(timer);
      if (readOn !== null) timers.clearTimeout(readOn);
    }
    // From the answer on, its reader bounds the read after the client left (relay.ts `UpstreamReader`).
    unsubscribe();
  }
}
