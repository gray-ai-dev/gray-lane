/**
 * The lane's receipt (`InferenceRun`, inference.ts): the promise a lane stream's headers wait on, the receipt the request
 * finalises and the id its response names, the receipt of a lane relay's or an endpoint route's request, the outer
 * receipt of an entry's peer attempts and the trace they carried, what a stack request's client got, and the relay's
 * outcome report.
 */
import { ReceiptBuilder, StackEventsChain, checkEventLog } from "@gray/attest";
import { ERROR_BODY_WAIT_MS } from "@gray/errors";
import { StackEventDigester, stackBodyDigest } from "@gray/lane";
import { platformTimers } from "../client.ts";
import { addReceiptEvents, bodyHashOf, laneOutcomeWord, laneUsage, latencyBand, responseHash } from "../lane/hooks.ts";
import { bindLateInners } from "../lane/peer-inner.ts";
import type { LanePeerCall } from "../lane/peer-model.ts";
import { failureNames } from "../lane/run-common.ts";
import { addStackReceipt, peerTraceOf } from "../lane/stack.ts";
import type { LaneDeps, LaneReceiptDraft } from "../lane/types.ts";
import type { RequestRecord } from "../sinks.ts";
import { type LaneAttemptRun, reportLanePick } from "./lane-attempt.ts";
import { peerAttemptChecks } from "./peer-end.ts";

/** docs/design/one-address.md: a receipt of a request that reached the VM through Gray's API says so (`aci/1+gray-api`). */
function laneArrival(lane: LaneDeps): { readonly arrival?: "gray_api" } {
  return lane.arrival === "gray_api" ? { arrival: "gray_api" } : {};
}

/** What lane-receipt.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface LaneReceiptRun extends LaneAttemptRun {
  laneSent: Promise<void>;
  markLaneSent: () => void;
}

/** Each peer hop's answer (`ended`), ERROR_BODY_WAIT_MS at most. */
export async function peersEnded(run: LaneReceiptRun): Promise<void> {
  const timers = run.deps.timers ?? platformTimers;
  let timer: unknown = null;
  await Promise.race([Promise.all(run.stackPeer.peerCalls.map((call) => call.ended)), new Promise<void>((resolve) => (timer = timers.setTimeout(resolve, ERROR_BODY_WAIT_MS)))]);
  timers.clearTimeout(timer);
}

/**
 * An entry's `record` with the trace its peer attempts' `end` frames carried (docs/confidential-lane-stack-routing.md
 * section 4.10, `peerTraceOf`): the stack VM in backend mode makes no record, so the relay's attempts reach its panel
 * (`lane_stack_traces`, `lane_stack_attempts`) through this row alone. Each hop's answer is waited for as a stack
 * call's close is, ERROR_BODY_WAIT_MS at most; an `end` not in by then is left out.
 *
 * A hop the entry let go of before its `end` came (its own limit before the commit, the client gone, the bound after
 * a failed stream) still had its attempt ended by the stack VM, which keeps the trace and answers it on the follow-up
 * once the attempt is done (`traceLate`). That is asked within the same ERROR_BODY_WAIT_MS, so the record waits no
 * longer than before. The outer receipt (`finishPeer`) waits for the attempt's inner receipt alone, within
 * PEER_FOLLOW_UP_MS, and a follow-up of either one serves both.
 *
 * Each peer attempt's two answer checks are read again from its `end` then (`peerEnded`, `peerAttemptChecks`): a
 * stream that failed after its commit closed its attempt before the stack VM's `end` was in, which the hop still had
 * on its way (`endKept`), and the record takes its checks from it as the attempt's own end would have (review r14
 * whole-pr blocker 1). Only the two checks change: the attempt's end, class and charge are as they were.
 */
export async function withPeerTrace(run: LaneReceiptRun, record: RequestRecord): Promise<RequestRecord> {
  try {
    const until = run.deps.clock() + ERROR_BODY_WAIT_MS;
    await peersEnded(run);
    await Promise.all(run.stackPeer.peerCalls.map((call) => call.traceLate(until)));
    const attempts = record.attempts.map((attempt, at) => {
      const closed = run.log.peerEnded.get(at);
      if (closed === undefined) return attempt;
      const checks = peerAttemptChecks(closed.attempt, closed.ended, closed.code, closed.rejected);
      const { toolCallCheck: _tool, outputCheck: _output, ...rest } = attempt;
      return { ...rest, ...(checks.toolCallCheck === null ? {} : { toolCallCheck: checks.toolCallCheck }), ...(checks.outputCheck === null ? {} : { outputCheck: checks.outputCheck }) };
    });
    const stackTrace = peerTraceOf({ requestStart: run.started, calls: run.stackPeer.peerCalls.map((call) => ({ relayId: call.peer.target.relayId, startedAt: call.startedAt, trace: call.trace })) });
    return stackTrace === null ? { ...record, attempts } : { ...record, attempts, stackTrace };
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event: "lane_stack_trace_failed", request_id: run.requestId, ...failureNames(error) }));
    return record;
  }
}

/**
 * The lane's receipt (design v2 §C.9), signed and stored as soon as the answer has ended: from the request's
 * `waitUntil` (`record`), beside the record's own work and never after its sends. Metadata: a failure is logged as a
 * content-free event and never changes the response.
 *
 * A receipt exists exactly when the ACI event log can be honest (`@gray/attest` `checkEventLog`):
 * the committed attempt forwarded a body, a relay policy refused one, or a body stayed handed to a
 * vendor fetch whose answer never committed (D53) — including a pre-connect egress failure whose
 * early stream headers already named the id (D72: `request.forwarded` then means "handed to the
 * attested egress"). A request that forwarded nothing and was not refused (no route, an opening
 * failure, a pre-connect egress failure before any headers, a client that left first) has no
 * honest receipt shape, so none is signed and the id the headers named answers 404 — the documented
 * behaviour of a receipt that was promised and not produced. Until then the id reads as pending
 * (`LaneReceiptStore.announce`), and it is withdrawn here when no receipt was stored under it.
 */
export function resetLaneSent(run: LaneReceiptRun): void {
  run.receipt.laneSentOpen = false;
  run.laneSent = new Promise<void>((resolve) => (run.markLaneSent = resolve));
}

export function openLaneSent(run: LaneReceiptRun): void {
  if (run.receipt.laneSentOpen) return;
  run.receipt.laneSentOpen = true;
  run.markLaneSent();
}

export function hasPeerEnvelope(run: LaneReceiptRun): boolean {
  return run.stackPeer.peerCalls.some((call) => call.envelopeSha256 !== null);
}

/**
 * Which receipt kind this request will finalise (`X-Receipt-Id`, `laneReceipt`, `finishLane`), bound strictly
 * to the winning attempt (or, when all attempts failed, the last attempt that actually forwarded bytes or a
 * peer envelope) so mixed endpoint <-> stack peer failover never overwrites the winning attempt's receipt.
 */
export function receiptMode(run: LaneReceiptRun): "peer" | "lane" | null {
  if (run.lane === null || run.receipt.laneReceiptId === null) return null;
  if (run.receipt.winningReceipt === "peer") return hasPeerEnvelope(run) ? "peer" : null;
  if (run.receipt.winningReceipt === "lane") return laneReceiptToSign(run) !== null ? "lane" : null;
  if (run.receipt.lastForwardedReceipt === "peer" && hasPeerEnvelope(run)) return "peer";
  if (run.receipt.lastForwardedReceipt === "lane" && laneReceiptToSign(run) !== null) return "lane";
  if (laneReceiptToSign(run) !== null) return "lane";
  if (hasPeerEnvelope(run)) return "peer";
  return null;
}

export async function laneReceipt(run: LaneReceiptRun): Promise<void> {
  const lane = run.lane;
  if (lane === null) return;
  const receiptId = run.receipt.laneReceiptId;
  const mode = receiptMode(run);
  try {
    if (mode === "peer") await finishPeer(run, lane, receiptId);
    else if (mode === "lane") await signLaneReceipt(run, lane, receiptId);
  } finally {
    // A stored receipt is no longer pending (`put`); an id the response named with no receipt under it reads as unknown.
    if (run.receipt.laneAnnounced !== null) lane.state.receipts.withdraw(run.receipt.laneAnnounced);
  }
}

/**
 * The end of a lane request after its record (design v2 §C.10): the relay's scheduler hears how the attempt went, after
 * the receipt (F2 D31). An entry's request over the peer hop reports nothing here (S27).
 */
export function finishLane(run: LaneReceiptRun, record: RequestRecord, finishedAt: number): void {
  const lane = run.lane;
  const mode = receiptMode(run);
  if (lane === null || mode === "peer") return;
  reportLaneOutcome(run, lane, record, finishedAt);
}

/** The receipt of a lane relay's or an endpoint route's request, under the id the response named. */
export async function signLaneReceipt(run: LaneReceiptRun, lane: LaneDeps, receiptId: string | null): Promise<void> {
  try {
    // F2 D31: the receipt is signed before the report. A scheduler lookup or a report is metadata;
    // neither may cancel the receipt the response already named (GW-03).
    const draft = laneReceiptToSign(run);
    if (draft !== null && receiptId !== null) {
      const received = run.laneRelays.laneReceived;
      if (received !== null) {
        const builder = new ReceiptBuilder({
          receiptId,
          // F2 D4: `chat_id` stays null in v1. ACI §7.3 allows it, and the lane's answer id lives at the
          // vendor under an account Gray does not keep; the customer correlates by `X-Receipt-Id`.
          chatId: null,
          model: run.facts.model,
          workloadKeysetDigest: lane.state.keysetDigest,
          endpoint: run.path,
          method: run.request.method,
          servedAt: BigInt(Math.floor(run.deps.clock() / 1000)),
          ...laneArrival(lane),
        });
        addReceiptEvents(builder, { receivedHash: bodyHashOf(received), draft, responseHash: run.receipt.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)) });
        const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
        // The lane refuses a keyless request before its body is read, so a finalised receipt always has an owner.
        if (run.laneRelays.laneOwner === null) throw new Error("a lane receipt without a key hash");
        lane.state.receipts.put(signed, run.laneRelays.laneOwner);
      }
    }
  } catch (error) {
    // Content-free by construction: the event, the id, and whether it was a receipt or a report.
    console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: run.requestId, receipt_id: receiptId, ...failureNames(error) }));
  }
}

/**
 * The end of an entry's request whose last attempt went over the peer hop (docs/confidential-lane-stack-routing.md
 * section 4.8): the outer receipt, signed under the id the envelopes named, of the request's peer attempts in order
 * (`peer.forwarded`, then `peer.answered` or `peer.failed`) and what the client got (`response.returned`, digested as
 * the stack VM digests what it released, so a served attempt's two digests are equal: L6). Pending the owner's decision
 * (section 4.8), each peer is named by its commitment alone (`LanePeerCall.commitment`), never by its relay or its origin.
 * Each hop's answer is over first, so an `end` still on its way is in the receipt. An answered attempt whose hop ended
 * without `end` (the client left mid-stream, the entry's own bound) has its inner receipt asked of the stack VM within
 * PEER_FOLLOW_UP_MS (`bindLateInners`), so `peer.answered.inner` names it once it checks and the store holds it.
 */
export async function finishPeer(run: LaneReceiptRun, lane: LaneDeps, receiptId: string | null): Promise<void> {
  let builder: ReceiptBuilder | null = null;
  try {
    // The answer is over: each hop's `end` is waited for as the record's trace waits for it (`peersEnded`), so the
    // receipt holds every `end` the trace does; then a hop still open is closed.
    await peersEnded(run);
    for (const call of run.stackPeer.peerCalls) call.close();
    await Promise.all(run.stackPeer.peerCalls.map((call) => call.ended));
    const received = run.laneRelays.laneReceived;
    if (receiptId === null || received === null) return;
    await bindLateInners(run.stackPeer.peerCalls, { receiptId, entryKeysetDigest: lane.state.keysetDigest, requestId: run.requestId }, run.deps.clock() + run.deps.cfg.peerFollowUpMs);
    builder = new ReceiptBuilder({
      receiptId,
      chatId: null,
      model: run.facts.model,
      workloadKeysetDigest: lane.state.keysetDigest,
      endpoint: run.path,
      method: run.request.method,
      servedAt: BigInt(Math.floor(run.deps.clock() / 1000)),
      ...laneArrival(lane),
    });
    builder.addRequestReceivedHash(bodyHashOf(received));
    let servedPeerCall: LanePeerCall | null = null;
    for (const call of run.stackPeer.peerCalls) {
      if (call.envelopeSha256 !== null && call.head !== null && call.served) servedPeerCall = call;
    }
    const peerExpansionCall = servedPeerCall ?? run.stackPeer.peerCalls.at(-1) ?? null;
    const peerExpansion = peerExpansionCall === null ? null : (run.stackPeer.lanePeerExpansions.get(peerExpansionCall) ?? null);
    if (peerExpansion !== null && peerExpansion.changed) {
      builder.addRequestContinuationExpanded({
        mode: "zero_retention",
        previousResponseIdExpanded: peerExpansion.previousResponseIdExpanded,
        itemReferencesExpanded: BigInt(peerExpansion.itemReferencesExpanded),
        includeEncryptedReasoningAdded: peerExpansion.includeEncryptedReasoningAdded,
        expandedBodySha256: peerExpansion.expandedBodySha256,
      });
    }
    let servedAttempt: bigint | null = null;
    for (const call of run.stackPeer.peerCalls) {
      if (call.envelopeSha256 === null) continue;
      const n = BigInt(call.n);
      const modified = run.stackPeer.peerHopEvents.get(call) ?? [];
      builder.addPeerForwarded({ n, envelopeSha256: call.envelopeSha256, ...(modified.length === 0 ? {} : { modified }) });
      if (call.head === null) {
        const failure = call.failure ?? { code: "peer_invalid" as const, sent: true };
        builder.addPeerFailed({ n, code: failure.code, sent: failure.sent, peer: call.commitment() });
        continue;
      }
      builder.addPeerAnswered({ n, status: call.head.status, dialed: call.dialed, inner: call.inner(), peer: call.commitment() });
      if (call.served) servedAttempt = n;
    }
    // What `GET /v1/aci/receipts/{id}/peers/{n}` serves of each attempt in the receipt (section 4.8).
    const peers = run.stackPeer.peerCalls.flatMap((call) => {
      const stored = call.envelopeSha256 === null ? null : call.stored();
      return stored === null ? [] : [stored];
    });
    const returned = stackReturned(run);
    builder.addStackResponseReturned({
      bodyHash: returned.bodyHash,
      status: BigInt(returned.status),
      ...(returned.eventsSha256 !== null ? { eventsSha256: returned.eventsSha256 } : returned.bodySha256 !== null ? { bodySha256: returned.bodySha256 } : {}),
      dropped: [],
      replacedError: returned.replacedError,
      servedAttempt: returned.leftBeforeAnswer === true || returned.grayErrorOnly === true ? null : servedAttempt,
      ...(returned.servedAs === "client_left" ? { servedAs: returned.servedAs } : {}),
    });
    const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
    if (run.laneRelays.laneOwner === null) throw new Error("a lane receipt without a key hash");
    lane.state.receipts.put(signed, run.laneRelays.laneOwner, peers, { requestId: run.requestId, workspaceId: run.caller.key?.workspaceId ?? null });
  } catch (error) {
    const issues = builder === null ? [] : [...new Set(checkEventLog(builder.events()).map((issue) => issue.code))];
    console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: run.requestId, receipt_id: receiptId, ...failureNames(error), ...(issues.length > 0 ? { issues } : {}) }));
  }
}

/**
 * The scheduler's outcome report for the account that served (design v2 §C.10): metadata only, one
 * coarse word, the four usage counters and a latency band, then the client's own flush
 * (`reportLanePick`, which frees the lease by its ref alone when the store dropped the account).
 */
export function reportLaneOutcome(run: LaneReceiptRun, lane: LaneDeps, record: RequestRecord, finishedAt: number): void {
  const serving = run.laneRelays.laneServing;
  if (serving === null) return;
  const code = record.errorCode === null ? "" : record.errorCode;
  const word = laneOutcomeWord({
    ok: record.status !== null && record.status >= 200 && record.status <= 299 && code === "",
    status: record.status,
    clientLeft: code === "client_cancelled" || code === "client_left",
    timedOut: code.includes("timeout") || code === "upstream_unavailable",
    rateLimited: record.status === 429,
    authFailed: record.status === 401 || record.status === 403,
    quotaExhausted: record.status === 402,
    overloaded: record.status === 503 || record.status === 529,
  });
  reportLanePick(run, lane, serving.relayId, {
    account_id: serving.accountId,
    // D116(a): the pick's lease key, so the relay frees exactly this pick's slot.
    request_ref: serving.requestRef,
    outcome: word,
    usage: laneUsage(record.usage),
    latency_bucket: latencyBand(finishedAt - run.started),
  });
}

/**
 * A stack request's client got an error body: Gray's own (`replaced`), or the vendor's, which its
 * attempt served (S32). `response.returned` covers its bytes (S26).
 */
export function stackErrorWritten(run: LaneReceiptRun, body: Uint8Array, replaced: boolean): void {
  const client = run.stackPeer.stackClient;
  if (client === null) return;
  run.stackPeer.stackReplacedError = replaced;
  run.stackPeer.stackGrayBody = replaced;
  client.body.length = 0;
  client.body.push(body);
  client.bodyBytes = body.length;
}

/**
 * The answer the client gets starts again (a later model, or the key's minute answering instead of a
 * refusal that waited): the lane's `response.returned` covers only what follows, a stack receipt's too.
 */
export function restartLaneResponse(run: LaneReceiptRun): void {
  run.receipt.laneResponse = responseHash();
  if (run.stackPeer.stackClient !== null) run.stackPeer.stackClient = { digester: new StackEventDigester(), chain: new StackEventsChain(), body: [], bodyBytes: 0 };
  run.stackPeer.stackReplacedError = false;
  run.stackPeer.stackGrayBody = false;
}

/**
 * What the outer receipt's `response.returned` says the client got (S26, L6), once the response is written. An
 * answer the served attempt gave that is not its events or body as they were says how (S32 `served_as`): a stream
 * the client left before its end got a prefix of them (`client_left`). A buffered Codex answer's
 * `codex_terminal_response` is the stack VM's to say (`backend.ts`).
 */
export function stackReturned(run: LaneReceiptRun): Parameters<typeof addStackReceipt>[1]["returned"] {
  const client = run.stackPeer.stackClient!;
  const bodyHash = run.receipt.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0));
  const status = run.log.recordedStatus ?? 200;
  // S32: a client that left before any event or body reached it (keep-alive comments at most) got
  // nothing: no attempt served it, whatever was read on after it left.
  if (run.stackPeer.stackLeft !== null && !run.stackPeer.stackLeft.answered) {
    return {
      bodyHash: run.stackPeer.stackLeft.bodyHash,
      status,
      eventsSha256: run.facts.stream ? new StackEventsChain().hex() : null,
      bodySha256: run.facts.stream ? null : stackBodyDigest(new Uint8Array(0)),
      replacedError: false,
      servedAs: "client_left",
      leftBeforeAnswer: true,
    };
  }
  // An entry's peer attempt served the client when the answer it released (or the vendor's error) is what it got.
  const served = run.stackPeer.peerCalls.some((peer) => peer.served) && !run.stackPeer.stackReplacedError;
  if (run.facts.stream && run.answer.headersSent) {
    for (const digest of client.digester.close()) client.chain.push(digest);
    return {
      bodyHash,
      status,
      eventsSha256: client.chain.hex(),
      bodySha256: null,
      replacedError: run.stackPeer.stackReplacedError,
      ...(served && run.answer.leftBeforeFinal ? { servedAs: "client_left" as const } : {}),
    };
  }
  const body = new Uint8Array(client.bodyBytes);
  let at = 0;
  for (const chunk of client.body) {
    body.set(chunk, at);
    at += chunk.length;
  }
  return {
    bodyHash,
    status,
    eventsSha256: null,
    bodySha256: stackBodyDigest(body),
    replacedError: run.stackPeer.stackReplacedError,
    // Gray's error body in place of an answer (its limit on a buffered answer included): none served it,
    // whatever the container's events the request path read before it refused them.
    ...(run.stackPeer.stackGrayBody ? { grayErrorOnly: true } : {}),
    // A client that left mid-body got a prefix of what it was being sent (untied), a buffered Codex
    // answer's included.
    ...(served && (run.answer.leftBeforeFinal || run.stackPeer.stackUndelivered) ? { servedAs: "client_left" as const } : {}),
  };
}

/**
 * The `X-Receipt-Id` a lane response carries (design v2 §C.9, M9; F2 D3): the id the first body
 * taken by a vendor fetch was given, and only when {@link laneReceiptToSign} will finalise a receipt
 * for it. A response that names no id (a pre-body refusal, a failure before any byte went) has none.
 */
export function laneReceiptHeader(run: LaneReceiptRun, headers: Headers): void {
  if (run.lane === null || run.receipt.laneReceiptId === null) return;
  headers.set("x-receipt-id", run.receipt.laneReceiptId);
}

/**
 * The draft the receipt of this response is signed from (F2 D3, hooks-4, D53):
 *
 * - a committed attempt's or a policy refusal's draft (`laneDraft`), always signed;
 * - else the last body that stayed handed to a vendor fetch, buffered and streamed alike: the fetch
 *   took it (F2 D29), so the id is on the answer and the bytes that went to the vendor and the bytes
 *   the client got are both real. D53 removed the early-headers condition: a buffered vendor non-2xx
 *   is a forwarded request too and must carry its receipt. D72: a pre-connect egress failure rolls
 *   this back when no headers went; if early headers already named the id, it stays and the receipt
 *   means "handed to the attested egress";
 * - else null: no fetch took a body and nothing was refused (no eligible route, a connect failure, a
 *   pre-connect egress failure before any headers, a client gone first), so the response names no id.
 */
export function laneReceiptToSign(run: LaneReceiptRun): LaneReceiptDraft | null {
  if (run.receipt.laneDraft !== null) return run.receipt.laneDraft;
  return run.receipt.laneForwardedDraft;
}
