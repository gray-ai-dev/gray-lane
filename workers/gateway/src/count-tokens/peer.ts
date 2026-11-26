/**
 * The entry's peer hop to a relay's stack VM for a count (`CountTokensRun`, count-tokens.ts): the signed envelope, the
 * VM's answer or refusal, and the count reply's validation.
 */
import { classify, countStep, headerReader, noCountStatus } from "@gray/errors";
import { type JsonObject, toJsonString } from "@gray/json";
import { checkOfficialUpstream, stackBodyDigest } from "@gray/lane";
import { COUNT_REPLY_LIMIT } from "@gray/protocol";
import type { Preference } from "@gray/routing";
import { platformTimers } from "../client.ts";
import { overStackBody } from "../lane/body-limits.ts";
import { egressCapacity, egressRefused } from "../lane/hooks.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import { newStackRid, stackPeerHeaders, stackRawQuery } from "../lane/stack.ts";
import type { Route } from "../routes.ts";
import { entryPeers, peerHopBody, laneConversationFor } from "./lane.ts";
import { parseCountReply, readBoundedWithin, peerEndedOutcome, encoder } from "./pure.ts";
import { classifyContext, overStackLimit, skipRoute, pushAttempt } from "./record.ts";
import type { CountRunCore, AttemptResult } from "./state.ts";

export async function attemptPeer(run: CountRunCore, input: {
  readonly route: Route;
  readonly model: string;
  readonly received: Uint8Array;
  /** The body as the gateway read it. */
  readonly value?: JsonObject;
  readonly statedProvider: boolean;
  readonly preference: Preference;
  readonly deadline: number;
  readonly attemptIndex: number;
}): Promise<AttemptResult> {
  const lane = run.lane!;
  const peers = entryPeers(run)!;
  const { route, model, received, statedProvider, preference, deadline, attemptIndex } = input;
  const { clock } = run.deps;

  if (run.protocol !== "anthropic_messages") {
    skipRoute(run, route, "lane_stack_unavailable:protocol");
    return { kind: "pass" };
  }
  if (overStackBody(received.length)) return overStackLimit(run, route);
  const official = checkOfficialUpstream(route.record.url);
  if (!official.ok) {
    skipRoute(run, route, "lane_stack_unavailable:upstream_not_official");
    return { kind: "pass" };
  }
  const relayId = route.record.lane?.relayId ?? null;
  const usable = relayId === null ? [] : peers.registry.usable(relayId);
  if (usable.length === 0) {
    skipRoute(run, route, "lane_stack_unavailable:peer_unpinned");
    return { kind: "pass" };
  }
  const hop = peerHopBody(run, received, statedProvider, relayId!, input.value);
  if (hop === null) {
    skipRoute(run, route, "lane_stack_unavailable:stack_rewrite_refused");
    return { kind: "pass" };
  }
  // The hop carries the entry's declared ops too, and Entry egress refuses a hop body past the stack's 4 MiB: the bytes
  // measured are the hop's, as inference.ts `peerPlan` measures them.
  if (overStackBody(received.length, hop.bytes.length)) return overStackLimit(run, route);

  const startedAt = clock();
  const laneBefore = {
    receiptId: run.laneReceiptId,
    forwardedReceipt: run.lastForwardedReceipt,
  };
  run.peerRid ??= newStackRid();
  run.laneReceiptId ??= newLaneReceiptId();
  const conversation = relayId === null ? undefined : laneConversationFor(run, relayId);
  const query = stackRawQuery(run.request.url);
  const controller = new AbortController();
  const timers = run.deps.timers ?? platformTimers;
  const timer = timers.setTimeout(() => controller.abort("attempt_deadline"), Math.max(0, deadline - clock()));
  const unsubscribe = run.presence.onLeave(() => controller.abort("client_left"));

  const call = peers.call({
    peers: usable,
    entry: lane.state.keysetDigest,
    rid: run.peerRid,
    n: attemptIndex + 1,
    receiptId: run.laneReceiptId,
    route: { endpoint: route.record.endpointId, protocol: "anthropic_messages", model: route.record.model },
    path: query === "" ? run.path : `${run.path}?${query}`,
    headers: stackPeerHeaders(run.request.headers, "anthropic_messages"),
    body: hop.bytes,
    budgetMs: Math.max(1, deadline - clock()),
    countTokens: true,
    ...(conversation === undefined ? {} : { conversation }),
    ...(preference.relayChanges === "exclude" ? { relayChanges: "exclude" as const } : {}),
    requestId: run.requestId,
    egress: run.outbound.fetch(peers.egress),
    clock,
    timers,
    signal: controller.signal,
  });
  run.peerCalls.push(call);
  run.peerHopEvents.set(call, hop.events);

  try {
    let sent = await call.send();
    if (sent.kind === "unsent" && sent.code === "peer_unknown") {
      if (await peers.registry.rehello(call.peer, deadline)) {
        sent = await call.send();
      } else {
        call.close();
      }
    }
    if (call.envelopeSha256 === null) {
      run.laneReceiptId = laneBefore.receiptId;
      run.lastForwardedReceipt = laneBefore.forwardedReceipt;
    } else {
      run.lastForwardedReceipt = "peer";
    }
    if (sent.kind !== "answered" && sent.kind !== "ended") {
      run.ctx.waitUntil(peers.registry.maintain());
    }

    if (sent.kind === "unsent") {
      call.close();
      if (call.egressRefusal !== null) {
        return { kind: "stop", stage: "routes", error: call.egressRefusal === "capacity" ? egressCapacity() : egressRefused() };
      }
      if (call.predatesCountHop) {
        // Its stack VMs run a release before the count hop: the route has no counter until they take one, as a route
        // whose API answers the count path 404 (#972). Nothing was registered or dialed, and nothing counts against it;
        // the receipt keeps the stack VM's refusal (`peer.failed`, `peer_malformed`).
        pushAttempt(run, route, startedAt, null, "count_unsupported", "count_tokens_unsupported", true);
        return { kind: "uncounted" };
      }
      pushAttempt(run, route, startedAt, null, "upstream_error", sent.code);
      return { kind: "unavailable" };
    }
    if (sent.kind === "aborted" || sent.kind === "unknown") {
      call.close();
      pushAttempt(run, route, startedAt, null, "upstream_error", sent.kind === "aborted" ? "peer_aborted" : sent.code);
      return { kind: "unavailable" };
    }
    if (sent.kind === "ended") {
      const outcome = peerEndedOutcome(sent.end, sent.head, sent.body);
      call.close();
      if (outcome.kind === "not_dialed") {
        if (outcome.code === "relay_error_status" && noCountStatus(outcome.relayStatus)) {
          // The relay's container has no count path: it answered 404, 405 or 501 before any vendor call (relay standard
          // section 2), as a route whose API answers the count path so (#972). Its decline (503 `relay_declined`) stays one.
          pushAttempt(run, route, startedAt, outcome.relayStatus, "count_unsupported", "count_tokens_unsupported", true);
          return { kind: "uncounted" };
        }
        pushAttempt(run, route, startedAt, null, "upstream_error", outcome.code);
        return { kind: "unavailable" };
      }
      if (outcome.kind === "vendor_error") {
        const elapsed = clock() - startedAt;
        const classified = classify(
          outcome.status,
          headerReader(new Headers(outcome.headers)),
          outcome.body,
          classifyContext(run, model, route, []),
          elapsed,
          clock(),
        );
        // A stack route reaches only an official vendor, which counts tokens: its vendor's missing count path is a failure
        // (`uncounted` goes on as `next`). A container without a count path answers before any vendor call (`not_dialed`).
        const step = countStep(classified.outcome, false, false);
        pushAttempt(run, route, startedAt, outcome.status, "upstream_error", step === "rejected" ? "count_tokens_request_rejected" : "count_tokens_unavailable");
        if (step === "rejected") {
          run.peerReplacedError = true;
          run.peerGrayBody = true;
          return { kind: "rejected" };
        }
        return { kind: "unavailable" };
      }
      pushAttempt(run, route, startedAt, null, "upstream_error", outcome.code);
      return { kind: "unavailable" };
    }

    // 200 answered from Stack VM: read bounded reply, wait for end frame, validate counts & digest.
    const replyBytes = await readBoundedWithin(sent.response, COUNT_REPLY_LIMIT, deadline, clock, timers);
    if (replyBytes === null) {
      call.served = false;
      call.close();
      pushAttempt(run, route, startedAt, 200, "invalid_response", "count_tokens_unavailable");
      return { kind: "unavailable" };
    }
    await call.endWithin(Math.min(deadline, clock() + run.deps.cfg.peerFollowUpMs));
    const counts = parseCountReply(run.protocol, replyBytes);
    if (counts === null) {
      call.served = false;
      call.close();
      pushAttempt(run, route, startedAt, 200, "invalid_response", "count_tokens_unavailable");
      return { kind: "unavailable" };
    }
    const rebuilt = encoder.encode(toJsonString(counts));
    if (stackBodyDigest(replyBytes) !== stackBodyDigest(rebuilt)) {
      call.served = false;
      call.close();
      pushAttempt(run, route, startedAt, 200, "invalid_response", "body_mismatch");
      return { kind: "unavailable" };
    }
    call.served = true;
    run.winningReceipt = "peer";
    run.peerReturnedBytes = rebuilt;
    run.peerReplacedError = false;
    run.peerGrayBody = false;
    pushAttempt(run, route, startedAt, 200, "success", null);
    return { kind: "answered", counts };
  } finally {
    timers.clearTimeout(timer);
    unsubscribe();
  }
}
