/**
 * The count's end (`CountTokensRun`, count-tokens.ts): which receipt the lane signs, the lane and peer receipts, and
 * the background work that signs them, reports the relay pick and emits the record once the client has its answer.
 */
import { ReceiptBuilder, checkEventLog } from "@gray/attest";
import { notWritten } from "@gray/content";
import { stackBodyDigest } from "@gray/lane";
import { platformTimers } from "../client.ts";
import { confidentialContent } from "../content.ts";
import { addReceiptEvents, bodyHashOf, laneSafeRecord } from "../lane/hooks.ts";
import { bindLateInners } from "../lane/peer-inner.ts";
import { failureNames } from "../lane/run-common.ts";
import type { LaneDeps } from "../lane/types.ts";
import { emitRecord, recordDelivery, type RequestRecord } from "../sinks.ts";
import { reportLaneOutcome } from "./lane.ts";
import type { CountRunCore } from "./state.ts";

export function receiptMode(run: CountRunCore): "lane" | "peer" | null {
  if (run.lane === null) return null;
  if (run.winningReceipt !== null) return run.winningReceipt;
  return run.lastForwardedReceipt;
}

export function scheduleFinish(run: CountRunCore, record: RequestRecord, finishedAt: number, mode: "lane" | "peer" | null, receiptId: string | null): void {
  const lane = run.lane;
  const emittedRecord = lane === null ? record : laneSafeRecord(record);
  const work = (async () => {
    try {
      await run.responded;
      if (lane !== null) {
        if (mode === "peer") {
          await finishPeer(run, lane, receiptId);
        } else if (mode === "lane") {
          await signLaneReceipt(run, lane, receiptId);
        }
        if (run.laneAnnounced !== null && run.laneOwner !== null && lane.state.receipts.get(run.laneAnnounced, run.laneOwner) === null) {
          lane.state.receipts.withdraw(run.laneAnnounced);
        }
        // F2 D31: report lane relay pick outcome AFTER receipt signing.
        if (mode !== "peer") reportLaneOutcome(run, lane, finishedAt);
      }
      const delivery = recordDelivery(run.deps.cfg, finishedAt + run.deps.cfg.contentTailReserveMs, run.deps.clock, run.deps.waitTimers ?? platformTimers);
      await emitRecord({
        record: emittedRecord,
        sinks: run.io.sinks,
        // Nothing of a count is kept; at the confidential entry the row says why (`confidential`).
        content: lane === null ? notWritten("withheld", null) : confidentialContent(),
        service: run.deps.service,
        delivery,
      });
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "count_tokens_finish_failed", request_id: run.requestId, ...failureNames(error) }));
    } finally {
      run.releaseLoad();
    }
  })();
  run.ctx.waitUntil(work);
}

export async function signLaneReceipt(run: CountRunCore, lane: LaneDeps, receiptId: string | null): Promise<void> {
  try {
    const draft = run.laneDraft ?? run.laneForwardedDraft;
    const received = run.laneReceived;
    if (draft === null || receiptId === null || received === null) return;
    const builder = new ReceiptBuilder({
      receiptId,
      chatId: null,
      model: run.model,
      workloadKeysetDigest: lane.state.keysetDigest,
      endpoint: run.path,
      method: run.request.method,
      servedAt: BigInt(Math.floor(run.deps.clock() / 1000)),
      ...(lane.arrival === "gray_api" ? { arrival: "gray_api" as const } : {}),
    });
    addReceiptEvents(builder, {
      receivedHash: bodyHashOf(received),
      draft,
      responseHash: run.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)),
    });
    const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
    if (run.laneOwner === null) throw new Error("a lane receipt without a key hash");
    lane.state.receipts.put(signed, run.laneOwner);
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: run.requestId, receipt_id: receiptId, ...failureNames(error) }));
  }
}

export async function finishPeer(run: CountRunCore, lane: LaneDeps, receiptId: string | null): Promise<void> {
  let builder: ReceiptBuilder | null = null;
  try {
    const until = run.deps.clock() + run.deps.cfg.peerFollowUpMs;
    await Promise.all(run.peerCalls.map((call) => call.endWithin(until)));
    for (const call of run.peerCalls) call.close();
    await Promise.all(run.peerCalls.map((call) => call.ended));
    const received = run.laneReceived;
    if (receiptId === null || received === null) return;
    // An answered count whose hop ended without `end` has its inner receipt from the stack VM, as a request's does.
    await bindLateInners(run.peerCalls, { receiptId, entryKeysetDigest: lane.state.keysetDigest, requestId: run.requestId }, run.deps.clock() + run.deps.cfg.peerFollowUpMs);
    builder = new ReceiptBuilder({
      receiptId,
      chatId: null,
      model: run.model,
      workloadKeysetDigest: lane.state.keysetDigest,
      endpoint: run.path,
      method: run.request.method,
      servedAt: BigInt(Math.floor(run.deps.clock() / 1000)),
      ...(lane.arrival === "gray_api" ? { arrival: "gray_api" as const } : {}),
    });
    builder.addRequestReceivedHash(bodyHashOf(received));
    let servedAttempt: bigint | null = null;
    for (const call of run.peerCalls) {
      if (call.envelopeSha256 === null) continue;
      const n = BigInt(call.n);
      builder.addPeerForwarded({
        n,
        envelopeSha256: call.envelopeSha256,
        ...((run.peerHopEvents.get(call) ?? []).length === 0 ? {} : { modified: run.peerHopEvents.get(call)! }),
      });
      if (call.head === null) {
        const failure = call.failure ?? { code: "peer_invalid" as const, sent: true };
        builder.addPeerFailed({ n, code: failure.code, sent: failure.sent, peer: call.commitment() });
        continue;
      }
      builder.addPeerAnswered({ n, status: call.head.status, dialed: call.dialed, inner: call.inner(), peer: call.commitment() });
      if (call.served) servedAttempt = n;
    }
    const peers = run.peerCalls.flatMap((call) => {
      const stored = call.envelopeSha256 === null ? null : call.stored();
      return stored === null ? [] : [stored];
    });
    const returnedBytes = run.peerReturnedBytes;
    builder.addStackResponseReturned({
      bodyHash: run.laneResponse?.bodyHash() ?? bodyHashOf(returnedBytes),
      status: BigInt(run.recordedStatus),
      bodySha256: stackBodyDigest(returnedBytes),
      dropped: [],
      replacedError: run.peerReplacedError,
      servedAttempt: run.peerGrayBody ? null : servedAttempt,
    });
    const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
    if (run.laneOwner === null) throw new Error("a lane receipt without a key hash");
    lane.state.receipts.put(signed, run.laneOwner, peers, { requestId: run.requestId, workspaceId: run.key?.workspaceId ?? null });
  } catch (error) {
    const issues = builder === null ? [] : [...new Set(checkEventLog(builder.events()).map((issue) => issue.code))];
    console.error(
      JSON.stringify({
        level: "error",
        event: "lane_finish_failed",
        request_id: run.requestId,
        receipt_id: receiptId,
        ...failureNames(error),
        ...(issues.length > 0 ? { issues } : {}),
      }),
    );
  }
}
