/**
 * The stack relay's peer hop (`InferenceRun`, inference.ts, S22-S27): an attempt's plan and call, its sending and
 * follow-up, a failed or uncommitted hop, a vendor's answer passed over or served, a relay change's refusal, and what
 * the client and the receipt are told of the stack's stream.
 */
import { StackEventsChain } from "@gray/attest";
import { ApiError, type Outcome as RetryOutcome, type Stop, bareOutcome, classify, classifyEvent, headerReader, shapeOf, upstreamUnavailable } from "@gray/errors";
import type { Json } from "@gray/json";
import { type LaneProtocol, type LaneStackVendor, StackEventDigester, checkOfficialUpstream } from "@gray/lane";
import { PEER_GATE_REFUSED } from "@gray/lane-wire";
import { platformTimers } from "../client.ts";
import { Dispatcher } from "../dispatcher.ts";
import { STACK_BODY_MAX_BYTES, overStackBody } from "../lane/body-limits.ts";
import { type PeerHopBody, peerHopBody as composePeerHop } from "../lane/claude-code-user-id.ts";
import { bodyHashOf, egressCapacity, egressRefused } from "../lane/hooks.ts";
import type { LanePeerCall } from "../lane/peer-model.ts";
import { type ExpandZeroRetentionResult, ExpandedBodyTooLargeError } from "../lane/responses-continuation.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import { stackStreamOptionsUnusable } from "../lane/stack-rewrite.ts";
import { LANE_RELAY_FAILED, RELAY_DECLINED, laneFaultError, newStackRid, peerEndVerdict, stackPeerHeaders, stackRawQuery } from "../lane/stack.ts";
import type { Route } from "../routes.ts";
import type { RequestOutcome } from "../sinks.ts";
import { laneVendor, permitKey } from "./attempt-pure.ts";
import { PEER_END_WAIT_MS, passesToNextRoute, peerEndedOutcome, peerFaultWhy, refusedTheRelaysAccount } from "./peer-end.ts";
import { unsentOutcome } from "./settle-pure.ts";
import { entryPeers } from "./stack-routes.ts";
import type { Attempt, Dispatch, PeerOutcome, SendResult, Sent, StackPassthrough, StackPlan, Stopped, Uncommitted } from "./types.ts";
import { type ZdrRun, laneZdrExpansionFor } from "./zdr.ts";
import { laneConversationFor } from "./lane-attempt.ts";
import { abandonLease, classifyContext, endAttempt, failAttempt, noteAgentRefusal } from "./attempt.ts";
import { releaseHold } from "./hold.ts";
import { openLaneSent, stackErrorWritten } from "./lane-receipt.ts";
import { type RecordRun, droppedHeader, record } from "./record.ts";
import { requestDeadline } from "./request-body.ts";

/** What stack-peer.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface StackPeerRun extends RecordRun, ZdrRun {}

/**
 * What an attempt at a stack route is made of (S23), or why none can be made. Only an entry sends one, over the peer
 * hop (`peerPlan`); a stack relay's own VM serves no customer key (`lane_entry_required`), so any other lane has none.
 */
export function stackPlan(run: StackPeerRun, route: Route, o?: Dispatch): StackPlan {
  if (entryPeers(run) !== null) return peerPlan(run, route, o);
  return { ok: false, code: "config_unready" };
}

/**
 * What an entry's attempt at a stack route is made of (docs/confidential-lane-stack-routing.md section 4.5): the
 * client's bytes held whole (or their zero-retention expanded bytes), a protocol the hop serves, an official
 * upstream, and a usable peer of the route's relay.
 */
export function peerPlan(run: StackPeerRun, route: Route, o?: Dispatch): StackPlan {
  const peers = entryPeers(run)!;
  const lane = route.record.lane;
  if (run.laneRelays.laneReceived === null) return { ok: false, code: "body_not_held" };
  const parsedBody = o?.parsed.value ?? run.zdr.laneZdrRequestBody;
  let expansion: ExpandZeroRetentionResult | null;
  try {
    expansion = parsedBody === null ? null : laneZdrExpansionFor(run, route.record, parsedBody, STACK_BODY_MAX_BYTES);
  } catch (error) {
    if (error instanceof ExpandedBodyTooLargeError) return { ok: false, code: "body_over_stack_limit" };
    throw error;
  }
  const baseBytes = expansion?.changed ? expansion.expandedBytes : run.laneRelays.laneReceived;
  if (overStackBody(baseBytes.length)) return { ok: false, code: "body_over_stack_limit" };
  const official = checkOfficialUpstream(route.record.url);
  if (!official.ok) return { ok: false, code: "upstream_not_official" };
  const protocol = route.record.protocol;
  if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") return { ok: false, code: "protocol" };
  const usable = lane === undefined || lane === null ? [] : peers.registry.usable(lane.relayId);
  if (usable.length === 0) return { ok: false, code: "peer_unpinned" };
  const vendor = laneVendor(official.vendor);
  const hop = peerHopBody(run, protocol, lane!.relayId, vendor, baseBytes, o?.parsed.value);
  if (hop === null) return { ok: false, code: "stack_rewrite_refused" };
  // The hop carries the entry's declared ops too (a Codex route's `wrap_input_text`), and Entry egress refuses a hop
  // body past the lane's 4 MiB: the bytes measured are the hop's, as admission measures them (`overStackLimit`).
  if (overStackBody(baseBytes.length, hop.bytes.length)) return { ok: false, code: "body_over_stack_limit" };
  return { ok: true, vendor, peers: usable, expansion };
}

/**
 * The bytes the peer hop to `relayId`'s VM carries (`lane/claude-code-user-id.ts` `peerHopBody`): `baseBytes` (the
 * client's bytes or the zero-retention expanded bytes) with the entry's declared ops, a Claude Code `metadata.user_id`
 * replaced by the stand-in for this workspace, key and relay (any other `user_id` removed), `/provider` removed when
 * the client stated its routing preference in the body, and on a Codex route (`vendor` `chatgpt_codex`) a string
 * `input` wrapped as a message (`wrap_input_text`). The ops are declared on each `peer.forwarded` of the outer
 * receipt, and the customer's verifier replays them before comparing with the stack VM's inner receipt. Null when they
 * do not apply (the route is passed over). Cached per relay and vendor: one relay may serve a Responses model on
 * api.openai.com and on chatgpt.com, and only the Codex route's hop body carries the wrap.
 */
export function peerHopBody(run: StackPeerRun, protocol: LaneProtocol, relayId: string, vendor: LaneStackVendor, baseBytes?: Uint8Array, value?: Json): PeerHopBody | null {
  const base = baseBytes ?? run.laneRelays.laneReceived;
  if (base === null || run.lane === null) return null;
  const cacheKey = `${relayId}\u0000${vendor}`;
  const cached = run.stackPeer.peerHops.get(cacheKey);
  if (cached !== undefined && cached.base === base) return cached;
  const key = run.caller.key;
  const hop = composePeerHop({
    protocol,
    base,
    ...(value === undefined || base !== run.laneRelays.laneReceived ? {} : { value }),
    stripProvider: run.routing.stripProvider,
    key: run.lane.state.affinityKey,
    owner: key === null ? null : { workspaceId: key.workspaceId, keyId: key.keyId },
    relayId,
    codex: vendor === "chatgpt_codex",
  });
  if (hop === null) return null;
  run.stackPeer.peerHops.set(cacheKey, { ...hop, base });
  return hop;
}

/**
 * The plan of one attempt at a stack route (relay standard v1.7, `stack-rewrite.ts`): a Chat stream whose
 * `stream_options` is not an object reaches no container over the hop, and the route is passed over.
 */
export function stackAttemptPlan(run: StackPeerRun, route: Route, o: Dispatch): StackPlan {
  const plan = stackPlan(run, route, o);
  if (!plan.ok) return plan;
  const protocol = route.record.protocol as LaneProtocol;
  if (stackStreamOptionsUnusable(protocol, o.canonical.stream, o.parsed.value)) return { ok: false, code: "stream_options_unusable" };
  return plan;
}

/**
 * An entry's attempt at a stack route (section 4.5): one envelope per peer it is sent to, under the request's hop
 * rid and this attempt's number, with the outer receipt's id it promises and what the request has left.
 */
export function peerCall(run: StackPeerRun, plan: Extract<StackPlan, { ok: true }>, attempt: Attempt, o: Dispatch): LanePeerCall {
  const peers = entryPeers(run)!;
  const lane = run.lane!;
  const protocol = attempt.route.record.protocol as LaneProtocol;
  run.stackPeer.peerRid ??= newStackRid();
  run.receipt.laneReceiptId ??= newLaneReceiptId();
  const baseBytes = plan.expansion?.changed ? plan.expansion.expandedBytes : run.laneRelays.laneReceived!;
  const conversation = attempt.route.record.lane === undefined || attempt.route.record.lane === null ? undefined : laneConversationFor(run, attempt.route.record.lane.relayId);
  // `peerPlan` made this relay's hop body (a usable peer of the route's relay), so it is there.
  const hop = peerHopBody(run, protocol, attempt.route.record.lane!.relayId, plan.vendor, baseBytes, o.parsed.value)!;
  const url = run.request.url;
  const query = stackRawQuery(url);
  const call = peers.call({
    peers: plan.peers,
    entry: lane.state.keysetDigest,
    rid: run.stackPeer.peerRid,
    n: attempt.index + 1,
    receiptId: run.receipt.laneReceiptId,
    route: { endpoint: attempt.route.record.endpointId, protocol, model: attempt.route.record.model },
    path: query === "" ? run.path : `${run.path}?${query}`,
    headers: stackPeerHeaders(run.request.headers, protocol),
    body: hop.bytes,
    budgetMs: requestDeadline(run, o.bodyRead) - run.deps.clock(),
    // Relay standard v1.7: the conversation id at the route's relay, derived with this entry's boot key, since the
    // envelope names no workspace.
    ...(conversation === undefined ? {} : { conversation }),
    // The customer's opt-out from relays' own changes, which the stack VM registers (docs/relay-request-changes.md).
    ...(run.routing.preference.relayChanges === "exclude" ? { relayChanges: "exclude" as const } : {}),
    // Named by a violation the stack VM reports (docs/design/relay-ejection.md section 3).
    requestId: run.requestId,
    egress: run.outbound.fetch(peers.egress),
    clock: run.deps.clock,
    timers: run.deps.timers ?? platformTimers,
    signal: attempt.controller.signal,
  });
  run.stackPeer.lanePeerExpansions.set(call, plan.expansion ?? null);
  run.stackPeer.peerHopEvents.set(call, hop.events);
  return call;
}

/**
 * One attempt over the peer hop (docs/confidential-lane-stack-routing.md section 4.7), until its answer commits on the
 * stack VM or the attempt ends:
 *
 * - a dial that sent nothing (egress's `sent: 0` codes, at each origin of the relay in turn) and a refusal before any
 *   frame dialed no vendor: the next route may go. `401 peer_unknown` (the stack VM lost its entries) is answered once
 *   with a hello and the same route again, within the attempt's bound (section 5, row 8); `403 peer_audience` (its
 *   workerd restarted, a new keyset) ends the pin, re-pinned behind the request, and the next origin or route may go;
 * - `head` and `end` with nothing released: `end` says not dialed, the vendor's error, or dialed and failed;
 * - a request that may have reached the stack VM with nothing saying what became of it (`peer_failed_after_send`, a
 *   silence past egress's bound, the attempt's own bound): the follow-up decides (`peerFollowUp`).
 *
 * The receipt id is promised from here, as the envelope names it; the client's answer is digested as a stack
 * request's (`stackClient`), so the outer `response.returned` is computed as the inner one is (L6).
 */
export async function sendPeer(run: StackPeerRun, attempt: Attempt, call: LanePeerCall, until: number): Promise<SendResult> {
  const { clock } = run.deps;
  const timers = run.deps.timers ?? platformTimers;
  const timer = timers.setTimeout(() => attempt.controller.abort("attempt_deadline"), Math.max(0, until - clock()));
  const unsubscribe = run.presence.onLeave(() => attempt.controller.abort("client_left"));
  run.stackPeer.peerCalls.push(call);
  if (run.stackPeer.stackClient === null) {
    run.stackPeer.stackClient = { digester: new StackEventDigester(), chain: new StackEventsChain(), body: [], bodyBytes: 0 };
    run.presence.onLeave(() => {
      const client = run.stackPeer.stackClient!;
      run.stackPeer.stackLeft ??= { answered: client.chain.count() > 0 || client.bodyBytes > 0, bodyHash: run.receipt.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)) };
    });
  }
  openLaneSent(run);
  try {
    const registry = entryPeers(run)!.registry;
    let sent = await call.send();
    if (sent.kind === "unsent" && sent.code === "peer_unknown") {
      if (await registry.rehello(call.peer, until)) sent = await call.send();
      else call.close();
    }
    if (call.envelopeSha256 !== null) run.receipt.lastForwardedReceipt = "peer";
    // A peer this attempt found down or rebooted is attested again behind the request, never inside its wait (L5).
    if (sent.kind !== "answered" && sent.kind !== "ended") run.ctx.waitUntil(registry.maintain());
    switch (sent.kind) {
      case "answered":
        return { kind: "answered", response: sent.response };
      case "ended":
        return { kind: "peer", outcome: peerEndedOutcome(sent.end, sent.head, sent.body) };
      case "unsent":
        return { kind: "peer", outcome: { kind: "not_dialed", code: sent.code, ...(call.egressRefusal === null ? {} : { egress: call.egressRefusal }) } };
      case "aborted":
        // The client left: the attempt counts nothing. Its recovery lease goes back only when the request never reached the
        // stack VM, or the follow-up says no vendor was dialed (review r17-gateway-5 minor 39).
        if (run.presence.gone) {
          if (call.stored() === null) abandonLease(run, attempt.route);
          else run.ctx.waitUntil(peerFollowUp(run, call, "peer_aborted").then((outcome) => (outcome.kind === "not_dialed" ? abandonLease(run, attempt.route) : undefined)));
          return { kind: "left" };
        }
        return { kind: "peer", outcome: await peerFollowUp(run, call, "peer_aborted") };
      case "unknown":
        return { kind: "peer", outcome: await peerFollowUp(run, call, sent.code) };
    }
  } finally {
    timers.clearTimeout(timer);
    unsubscribe();
  }
}

/**
 * The late facts of an attempt the hop left unknown (section 4.7, row 5): `GET /v1/peer/attempts/<rid>` on a new
 * connection within what the pre phase has left. `unknown` or `registered` dialed no vendor (the next route may go);
 * `dialed`, `done` or no answer may have, and the request is answered 502 and not retried (I3).
 */
export async function peerFollowUp(run: StackPeerRun, call: LanePeerCall, code: string): Promise<PeerOutcome> {
  call.close();
  // PEER_FOLLOW_UP_MS (@gray/config): a new connection and an answer from the stack VM's memory, within the pre phase.
  const left = run.budget.preWait(run.deps.cfg.peerFollowUpMs);
  const answer = left <= 0 ? null : await call.followUp(run.deps.clock() + left);
  if (answer !== null && (answer.state === "unknown" || answer.state === "registered")) return { kind: "not_dialed", code };
  return { kind: "relay_failed", code };
}

/**
 * An entry's peer attempt that ended without an answer the request path relays (section 4.7): not dialed is closed
 * as a connection that never reached an upstream, and the next route may go (with none left, the client gets a
 * connection's `upstream_unavailable`; the attempt's record keeps the stack VM's code); the vendor's error that is the
 * supplier's (a rate limit, an overload, a server error, a timeout) lets the next route go as the main gateway's does
 * and is the client's answer if none serves (`stackVendorPassedOver`), one that refused the relay's own account does
 * too but is never the client's answer (`relayAccountRefused`: Gray's error), a 400 of a body the relay's software
 * changed lets one other operator's route go (`relayChangeRefused`), and any other (a refusal of the request) ends the
 * request with it (`passthrough`); an answer the stack VM's trust gate refused is `upstream_trust_policy_rejected`;
 * anything else is `lane_relay_failed`; either way no other route, nothing charged.
 */
export function peerFailed(run: StackPeerRun, d: Dispatcher, attempt: Attempt, model: string, outcome: PeerOutcome): { readonly kind: "continue" } | Stopped {
  const { clock } = run.deps;
  const elapsed = clock() - attempt.startedAt;
  attempt.peer?.close();
  if (outcome.kind === "not_dialed" && outcome.egress !== undefined) {
    // Egress refused the hop's request itself (its mark, nothing sent): never the relay's failure. Its body budget full
    // is Gray's capacity (429), anything else Gray's error (500); the attempt counts against nothing, and no other
    // route is tried, every route leaving through the same egress (`egressAnswered`).
    const error = outcome.egress === "capacity" ? egressCapacity() : egressRefused();
    endAttempt(run, attempt, unsentOutcome(attempt.permit), false, error.code, { rejected: true });
    return { kind: "stopped", stop: null, error };
  }
  if (outcome.kind === "not_dialed") {
    // The container's decline, which the stack VM names only with egress's record of no vendor call, counts against nothing:
    // with no outcome to observe and nothing sent, the recovery lease the attempt took over goes back, as the server's
    // `close_attempt` gives back that of an attempt neither observed nor sent. Any other not dialed counts as a
    // connection that failed, observed: the lease stays with it.
    const declined = outcome.code === RELAY_DECLINED;
    if (declined) abandonLease(run, attempt.route);
    failAttempt(run, d, attempt, bareOutcome("connect", elapsed), upstreamUnavailable(), outcome.code, false, false, undefined, false, declined);
    return { kind: "continue" };
  }
  if (outcome.kind === "vendor_error") {
    attempt.status = outcome.status;
    // The vendor's allowlisted error headers (`retry-after`, `retry-after-ms`, `x-should-retry`, `content-type`) cross
    // the hop on `head.headers` (`error_headers` capability) so classification and client passthrough both receive them.
    const classified = classify(outcome.status, headerReader(new Headers(outcome.headers)), outcome.body, classifyContext(run, model, attempt.route), elapsed, clock());
    noteAgentRefusal(run, attempt, classified.outcome, { status: outcome.status, body: outcome.body });
    failAttempt(run, d, attempt, classified.outcome, classified.error, "upstream_attempt_failed", false, false, outcome.body);
    if (refusedTheRelaysAccount(classified.outcome)) return relayAccountRefused(run, outcome.accountId);
    const passthrough: StackPassthrough = { status: outcome.status, body: outcome.body, headers: outcome.headers, accountId: outcome.accountId };
    // The vendor's error is the served attempt's answer (S32), as the stack VM's receipt says it, once the client gets it.
    const peer = attempt.peer;
    const served = (): void => {
      if (peer !== undefined) peer.served = true;
      run.receipt.winningReceipt = "peer";
    };
    if (passesToNextRoute(classified.outcome)) return stackVendorPassedOver(run, attempt, classified.error, outcome.accountId, passthrough, served);
    if (outcome.changedBody && relayChangeRefused(run, d, attempt, outcome.status, classified.outcome, classified.error, outcome.accountId, passthrough, served)) return { kind: "continue" };
    served();
    return { kind: "stopped", stop: null, error: classified.error, passthrough };
  }
  if (outcome.kind === "vendor_event") {
    // The vendor's own error event before the stack VM's commit: answered as the main gateway answers an upstream's
    // in-band error before its commit (`streamFailure`: the status it maps to, `classifyEvent`), and counted as the
    // vendor's, not the relay's.
    const classified = classifyEvent(attempt.route.record.protocol, outcome.event, classifyContext(run, model, attempt.route), elapsed, clock());
    noteAgentRefusal(run, attempt, classified.outcome, { inBand: outcome.event });
    failAttempt(run, d, attempt, classified.outcome, classified.error, "upstream_error", false);
    if (refusedTheRelaysAccount(classified.outcome)) return relayAccountRefused(run, outcome.accountId);
    // A rate limit, an overload or a server error of the vendor's goes to the next route as the main gateway's does
    // (`passesToNextRoute`); with none left the client gets its classification (`stopError`).
    if (passesToNextRoute(classified.outcome)) return stackVendorPassedOver(run, attempt, classified.error, outcome.accountId, null, () => {});
    return { kind: "stopped", stop: null, error: classified.error };
  }
  // The stack VM's verdict (its trace's fault, else `end.code`): an answer that failed Gray's check is the relay's
  // `upstream_answer_refused`, any other fault of its container `lane_relay_failed`; either counts against its route.
  const fault = attempt.peer?.trace?.calls.at(-1)?.fault ?? null;
  const verdict = peerEndVerdict(fault, { code: outcome.code });
  if (verdict.kind === "gate") {
    // The stack VM's trust gate refused the vendor's answer before its commit (GL-23): the request's own error, an
    // answer defect of the route and not the relay's transport. A vendor was dialed, so no other route (S25).
    run.answer.trustRejected = true;
    const error = new ApiError(502, PEER_GATE_REFUSED);
    failAttempt(run, d, attempt, { ...bareOutcome("answer_defect", elapsed), answered: true }, error, PEER_GATE_REFUSED, false);
    return { kind: "stopped", stop: null, error };
  }
  const code = verdict.kind === "lane" ? verdict.code : LANE_RELAY_FAILED;
  const error = laneFaultError(code, fault?.why ?? peerFaultWhy(outcome.code));
  failAttempt(run, d, attempt, bareOutcome("transport", elapsed), error, code, false);
  return { kind: "stopped", stop: null, error };
}

/**
 * An entry's committed peer answer that failed before the request path committed it (the hop broke after `head`, or
 * the answer was not one the request path takes): with `end` in, it is the end's to say whether a vendor was dialed;
 * without, the follow-up's (F7: a reset after `head` is dialed, 502, nothing charged).
 */
export async function peerUncommitted(run: StackPeerRun, d: Dispatcher, attempt: Attempt, model: string, failure: Uncommitted): Promise<{ readonly kind: "continue" } | Stopped> {
  const call = attempt.peer!;
  // Not dialed, and a whole answer the request path refused, follow the `end` that was in when the request path failed
  // the answer, as before.
  const end = call.end;
  // An answer that ended (Gray's error frame) has its `end` on the way, read for the attempt's answer checks alone,
  // within PEER_END_WAIT_MS (review r14 lane-wire finding 10); one still answering is not waited for. The hop, which
  // its priming kept open (`endKept`), is closed after.
  const late = end === null && !failure.upstreamMayStillWork ? await call.endWithin(run.deps.clock() + run.budget.preWait(PEER_END_WAIT_MS)) : null;
  // The stack VM's verdict on a dialed attempt reads the `end` that came in the wait too: a fault of the relay's or its
  // gate's `cut` (GL-23) is that verdict whenever it arrived. Not dialed, or no verdict, closes as before.
  const verdict = end ?? (late?.dialed === true ? late : null);
  call.close();
  call.served = false;
  run.answerShare.hold(0, run.deps.cfg.answerHeldMaxBytes);
  if (end !== null && !end.dialed) return peerFailed(run, d, attempt, model, { kind: "not_dialed", code: end.code ?? "peer_invalid" });
  // The stack VM ended an answer it had begun to release for a fault of the relay's (its error frame before the entry's
  // commit): its verdict decides the code, as `peerFailed`'s does, and it counts against the relay's route.
  const judged = verdict === null ? null : peerEndVerdict(call.trace?.calls.at(-1)?.fault ?? null, verdict);
  if (verdict !== null && judged?.kind === "lane") return peerFailed(run, d, attempt, model, { kind: "relay_failed", code: verdict.code ?? LANE_RELAY_FAILED });
  // Its trust gate refused a later part of an answer it had begun to release (a `cut` end, GL-23): as one it refused
  // before its commit, the request's `upstream_trust_policy_rejected` (`peerFailed`).
  if (judged?.kind === "gate") return peerFailed(run, d, attempt, model, { kind: "relay_failed", code: PEER_GATE_REFUSED });
  if (end !== null) {
    // A whole answer the request path refused (its trust gate, its protocol checks): the request's own error. The stack
    // VM's attempt is over (`end` is in).
    failAttempt(run, d, attempt, { ...failure.outcome, answered: true }, failure.error, failure.code, false, failure.answered === true);
    return { kind: "stopped", stop: null, error: failure.error };
  }
  return peerFailed(run, d, attempt, model, await peerFollowUp(run, call, "peer_failed_after_send"));
}

/**
 * A stack relay's vendor error that refused the relay's own upstream account (`refusedTheRelaysAccount`: a 401, 402
 * or 403, a quota, the provider's key, credit or standing, or the vendor's block of the account) is the provider's
 * failure, not the client's: passed on, its status and text would tell the client that its own key was refused. So
 * it is not the client's answer (`passthrough`): the attempt failed with its classification as any route's does
 * (`upstream_auth_failed`, `upstream_model_unavailable`, `upstream_account_refused`, nothing charged), and the
 * dispatcher's rules for its class decide the next route (the vendor did no work for it). With none left the client gets that error, Gray's own
 * (`replaced_error` true, no served attempt). The account stays named on the request's row (S27: errors per
 * account) unless a later attempt's answer ends the request.
 */
export function relayAccountRefused(run: StackPeerRun, accountId: string | null): { readonly kind: "continue" } {
  run.stackPeer.stackAnsweredAccount = accountId;
  return { kind: "continue" };
}

/**
 * A stack relay's vendor error that is the supplier's, not the request's (`passesToNextRoute`: a rate limit, an
 * overload, a server error, a timeout), as any route's: the attempt failed with its classification, and the
 * dispatcher's rules for its class decide the next route, another operator's first (tier A), as the main gateway
 * decides after an endpoint route's 429 or 5xx. Production, 2026-11-20: a relay's subscription account answered 429
 * and the request ended with it, though another relay's route could serve it. The vendor's own status and body stay
 * the client's answer should the request end on it (`stackVendorAnswered`), as before; nothing of it was released.
 * The account stays named on the request's row (S27) unless a later attempt's answer ends the request.
 */
export function stackVendorPassedOver(run: StackPeerRun, attempt: Attempt, error: ApiError, accountId: string | null, passthrough: StackPassthrough | null, served: () => void): { readonly kind: "continue" } {
  run.stackPeer.stackVendorAnswer = { attempt, error, passthrough, serve: served };
  run.stackPeer.stackAnsweredAccount = accountId;
  return { kind: "continue" };
}

/**
 * The stack relay's vendor error the dispatcher's stop ends the request on (`stackVendorPassedOver`): its error, its
 * status and body for the client (`passthrough`) and the mark of its attempt as served; none when the client left or
 * a refusal is held (that refusal is told). Taken once: a model the customer listed next starts without it.
 */
export function stackVendorAnswered(run: StackPeerRun, d: Dispatcher, stop: Stop | null): Pick<Stopped, "error" | "passthrough" | "served" | "vendorAnswer"> | null {
  const changed = relayChangeAnswer(run, d, stop);
  if (changed !== null) {
    run.stackPeer.stackVendorAnswer = null;
    return changed;
  }
  const answer = run.stackPeer.stackVendorAnswer;
  run.stackPeer.stackVendorAnswer = null;
  if (answer === null || stop === "client_left" || d.heldToTell() !== null) return null;
  return { error: answer.error, vendorAnswer: true, ...(answer.passthrough === null ? {} : { passthrough: answer.passthrough, served: answer.serve }) };
}

/**
 * A vendor's 400 at a stack route whose body the relay's software changed (`changedBody`, from the attempt's inner
 * receipt), refused as the main gateway refuses one (`Dispatcher.fail` holds it): one other operator's route is tried
 * when one could take the request (`sendableElsewhere`), once per request, and no repeat at the same relay
 * (`otherOperatorsOnly`). Production, 2026-11-19: a relay's software moved a client's system prompt and added a
 * 1-hour cache mark after the client's 5-minute one, and Anthropic answered 400 to a request the customer sent
 * correctly. Served there, the held refusal is the first route's failure (`settleHeld`: its breaker and its error
 * rate, the record's code `relay_change_refused`). Refused there too, the request was at fault: the client gets that
 * last 400, the vendor's answer to the latest attempt (the dispatcher holds the later refusal and drops the first, as
 * the main gateway does), and neither relay is held to it. Ended there any other way, or with no other route, the
 * client gets this 400 as before (`relayChangeAnswer`), held against no one. True when the request goes on. Never for
 * a request pinned to the endpoint that issued the response it continues (`lanePin`): that 400 is the client's.
 */
export function relayChangeRefused(run: StackPeerRun, d: Dispatcher, attempt: Attempt, status: number, outcome: RetryOutcome, error: ApiError, accountId: string | null, passthrough: StackPassthrough, serve: () => void): boolean {
  if (status !== 400 || outcome.class !== "refusal" || run.stackPeer.relayChangePermit !== null) return false;
  // A request pinned to the endpoint that issued the response it continues is tried at no other operator: no other
  // relay knows the id it names.
  if (run.admitting.pinned) return false;
  if (!d.refused || d.held?.attempt !== attempt.index || !d.sendableElsewhere()) return false;
  run.stackPeer.relayChangePermit = permitKey(attempt.permit);
  d.otherOperatorsOnly = true;
  run.stackPeer.relayChangeHeld = { attempt, error, passthrough, serve };
  run.stackPeer.stackAnsweredAccount = accountId;
  console.log(JSON.stringify({ level: "info", event: "relay_change_refused", request_id: run.requestId, endpoint: attempt.route.record.endpointId, attempt: attempt.index }));
  return true;
}

/**
 * The request ends on the vendor's 400 of a relay's change (`relayChangeRefused`): the attempt after it served
 * nothing and refused nothing, so its refusal is still the one held (`heldToTell`). Its status and body are the
 * client's, and its attempt the served one (S32), as before the rule; nothing when the client left. Taken once.
 */
export function relayChangeAnswer(run: StackPeerRun, d: Dispatcher, stop: Stop | null): Pick<Stopped, "error" | "passthrough" | "served" | "vendorAnswer"> | null {
  const held = run.stackPeer.relayChangeHeld;
  run.stackPeer.relayChangeHeld = null;
  d.otherOperatorsOnly = false;
  if (held === null || stop === "client_left" || d.heldToTell()?.attempt !== held.attempt.index) return null;
  run.stackPeer.stackAnsweredAccount = held.passthrough.accountId;
  return { error: held.error, vendorAnswer: true, passthrough: held.passthrough, served: held.serve };
}

/**
 * The vendor's own error, from a stack relay's feed (S24): its status and body, the allowlisted
 * headers egress recorded (never its content coding: egress asked for none, and a coded answer is
 * never released) beside Gray's own. The hold is released with the classification's reason.
 */
export function stackPassthrough(run: StackPeerRun, passthrough: StackPassthrough, error: ApiError, reason: string): Sent {
  releaseHold(run, { reason, detail: { code: error.code, status: passthrough.status } });
  const rendered = error.render({ shape: shapeOf(run.path), origins: run.origins, requestId: run.requestId });
  const headers = new Headers(rendered.headers);
  headers.delete("content-length");
  if (Object.keys(passthrough.headers).some((name) => name.toLowerCase() === "content-type")) {
    headers.delete("content-type");
  }
  for (const [name, value] of Object.entries(passthrough.headers)) if (name.toLowerCase() !== "content-encoding") headers.set(name, value);
  run.receipt.laneResponse?.update(passthrough.body);
  run.stackPeer.stackAnsweredAccount = passthrough.accountId;
  // The vendor's error is the served attempt's answer, tied by its body digest (S32), not a replacement.
  stackErrorWritten(run, passthrough.body, false);
  run.answer.responseBytes = passthrough.body.length;
  droppedHeader(run, headers);
  const outcome: RequestOutcome = passthrough.status >= 500 ? "failed" : "rejected";
  record(run, passthrough.status, outcome, error.code);
  return { kind: "failed", response: new Response(passthrough.body, { status: passthrough.status, headers }), code: error.code, outcome };
}

/**
 * Gray cut a committed answer (a charge it could not record, a body limit, a failure of its own): the
 * client got what was sent before the cut, and a stack receipt says Gray ended the answer
 * (`replaced_error`, S32), over the digest of what was sent. A client that left is not a cut of Gray's
 * (`client_left`).
 */
export function stackCut(run: StackPeerRun): void {
  if (run.stackPeer.stackClient !== null) run.stackPeer.stackReplacedError = true;
}

/**
 * The tap of a stack request's client stream (S26 `response.returned`): a stream's events are digested
 * as they are written (S19, WHATWG framing, Gray's own frames included); a non-stream answer's bytes
 * are kept for its body digest. They are never more than ANSWER_HELD_MAX_BYTES, because every body a
 * stack request's client is handed was held whole first, within that row: the container's (refused
 * past it, `answer_too_large`), a buffered Codex terminal response (`upstream_body_limit` past it), an
 * error body (at most the vendor's 64 KiB, or the container's verified bytes). So the receipt always has
 * the digest of what the client got.
 */
export function stackTap(run: StackPeerRun, bytes: Uint8Array): void {
  const client = run.stackPeer.stackClient;
  if (client === null) return;
  if (run.facts.stream) {
    for (const digest of client.digester.write(bytes)) client.chain.push(digest);
    return;
  }
  client.bodyBytes += bytes.length;
  client.body.push(bytes.slice());
}

