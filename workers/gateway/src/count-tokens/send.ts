/**
 * One HTTP count attempt (`CountTokensRun`, count-tokens.ts), shared by the main gateway, an entry's endpoint route
 * and an entry's lane relay route: the upstream call, its error classification and the relay scheduler's outcome.
 */
import { ERROR_BODY_WAIT_MS, bareOutcome, classify, countStep, headerReader } from "@gray/errors";
import { COUNT_REPLY_LIMIT } from "@gray/protocol";
import { platformTimers } from "../client.ts";
import { egressCapacity, egressOwnAnswer, egressRefused, egressSentNothing, forwardedStream, laneOutcomeWord, latencyBand } from "../lane/hooks.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import type { LaneReceiptDraft } from "../lane/types.ts";
import type { Route } from "../routes.ts";
import { UPSTREAM_BODY_CHUNK_BYTES, sendable } from "../upstream.ts";
import { recordLanePrevious, reportLaneNotSent, reportLanePick } from "./lane.ts";
import { parseCountReply, readBoundedWithin, errorBody } from "./pure.ts";
import { classifyContext, pushAttempt } from "./record.ts";
import { type CountRunCore, type AttemptResult, ZERO_LANE_USAGE } from "./state.ts";

export async function executeHttpAttempt(run: CountRunCore, input: {
  readonly route: Route;
  readonly model: string;
  readonly url: string;
  readonly headers: Headers;
  readonly bodyBytes: Uint8Array;
  readonly fetcher: (input: string, init: RequestInit, started?: () => void) => Promise<Response>;
  readonly deadline: number;
  readonly unvouched: boolean;
  readonly restoredPairs: readonly (readonly [string, string])[];
  readonly repeatedConnect: boolean;
  readonly laneContext:
    | null
    | { readonly kind: "endpoint"; readonly draft: LaneReceiptDraft }
    | { readonly kind: "relay"; readonly draft: LaneReceiptDraft; readonly relayId: string; readonly accountId: string; readonly requestRef: string };
}): Promise<AttemptResult> {
  const { route, model, url, headers, bodyBytes, fetcher, deadline, unvouched, restoredPairs, repeatedConnect, laneContext } = input;
  const { clock } = run.deps;
  const startedAt = clock();
  const controller = new AbortController();
  const timers = run.deps.timers ?? platformTimers;
  let timedOut = false;
  const timer = timers.setTimeout(() => {
    timedOut = true;
    controller.abort("attempt_deadline");
  }, Math.max(0, deadline - clock()));
  const unsubscribe = run.presence.onLeave(() => controller.abort("client_left"));

  const laneBefore = {
    receiptId: run.laneReceiptId,
    forwardedDraft: run.laneForwardedDraft,
    forwardedReceipt: run.lastForwardedReceipt,
  };

  let taken = false;
  let body: ReadableStream<Uint8Array> | null = null;
  try {
    body = sendable(forwardedStream(bodyBytes, UPSTREAM_BODY_CHUNK_BYTES), () => {
      taken = true;
      if (laneContext !== null) {
        run.laneReceiptId ??= newLaneReceiptId();
        run.laneForwardedDraft = laneContext.draft;
        run.lastForwardedReceipt = "lane";
      }
    });

    let response: Response;
    try {
      response = await fetcher(url, { method: "POST", headers, body, signal: controller.signal, redirect: "manual" });
    } catch {
      body.cancel().catch(() => {});
      const elapsed = clock() - startedAt;
      if (laneContext?.kind === "relay") {
        if (!taken) {
          reportLaneNotSent(run, laneContext.relayId, laneContext.accountId, laneContext.requestRef);
        } else {
          const word = timedOut ? "timeout" : "upstream_error";
          recordLanePrevious(run, laneContext.relayId, laneContext.accountId, word);
          reportLanePick(run, run.lane!, laneContext.relayId, {
            account_id: laneContext.accountId,
            request_ref: laneContext.requestRef,
            outcome: word,
            usage: ZERO_LANE_USAGE,
            latency_bucket: latencyBand(elapsed),
          });
        }
      }
      pushAttempt(run, route, startedAt, null, timedOut ? "timeout" : "upstream_error", "count_tokens_unavailable");
      return !taken && !timedOut && !run.presence.gone ? { kind: "connect" } : { kind: "unavailable" };
    }

    const status = response.status;
    if (status < 200 || status > 299) {
      const errBytes = await errorBody(response, Math.min(deadline, clock() + ERROR_BODY_WAIT_MS), clock);
      const elapsed = clock() - startedAt;

      const own = laneContext !== null ? egressOwnAnswer(response.headers, errBytes) : null;
      if (own !== null) {
        const unsent = egressSentNothing(own);
        if (unsent) {
          run.laneReceiptId = laneBefore.receiptId;
          run.laneForwardedDraft = laneBefore.forwardedDraft;
          run.lastForwardedReceipt = laneBefore.forwardedReceipt;
          if (laneContext!.kind === "relay") {
            reportLaneNotSent(run, laneContext!.relayId, laneContext!.accountId, laneContext!.requestRef);
          }
        }
        switch (own.kind) {
          case "before_vendor":
            pushAttempt(run, route, startedAt, status, "upstream_error", "count_tokens_unavailable");
            return countStep(bareOutcome("connect", elapsed), false, repeatedConnect) === "repeat" ? { kind: "connect" } : { kind: "unavailable" };
          case "after_vendor":
            if (laneContext!.kind === "relay") {
              recordLanePrevious(run, laneContext!.relayId, laneContext!.accountId, "upstream_error");
              reportLanePick(run, run.lane!, laneContext!.relayId, {
                account_id: laneContext!.accountId,
                request_ref: laneContext!.requestRef,
                outcome: "upstream_error",
                usage: ZERO_LANE_USAGE,
                latency_bucket: latencyBand(elapsed),
              });
            }
            pushAttempt(run, route, startedAt, status, "upstream_error", "count_tokens_unavailable");
            return { kind: "unavailable" };
          case "capacity":
            return { kind: "stop", stage: "routes", error: egressCapacity() };
          case "refused":
            if (own.sent && laneContext!.kind === "relay") {
              recordLanePrevious(run, laneContext!.relayId, laneContext!.accountId, "upstream_error");
              reportLanePick(run, run.lane!, laneContext!.relayId, {
                account_id: laneContext!.accountId,
                request_ref: laneContext!.requestRef,
                outcome: "upstream_error",
                usage: ZERO_LANE_USAGE,
                latency_bucket: latencyBand(elapsed),
              });
            }
            return { kind: "stop", stage: "routes", error: egressRefused() };
        }
      }

      const classified = classify(status, headerReader(response.headers), errBytes, classifyContext(run, model, route, restoredPairs), elapsed, clock());
      const counted = countStep(classified.outcome, unvouched, repeatedConnect);
      // A relay route reaches only an official vendor's API, which counts tokens: a count path missing there is its failure.
      const step = counted === "uncounted" && laneContext?.kind === "relay" ? "next" : counted;
      if (step === "uncounted") {
        // The route's API has no token count, which no standard asks of it: the attempt counts neither for nor against
        // the route (recorded `rejected`, as the server records it), and nothing here reaches its circuit, rests,
        // ranking, evidence or `providerFailure`.
        pushAttempt(run, route, startedAt, status, "count_unsupported", "count_tokens_unsupported", true);
        return { kind: "uncounted" };
      }
      pushAttempt(run, route, startedAt, status, "upstream_error", step === "rejected" ? "count_tokens_request_rejected" : "count_tokens_unavailable");

      if (laneContext?.kind === "relay") {
        const word = laneOutcomeWord({
          ok: false,
          status,
          clientLeft: false,
          timedOut: false,
          rateLimited: status === 429,
          authFailed: status === 401 || status === 403,
          quotaExhausted: status === 402,
          overloaded: status === 503 || status === 529,
          // Only a refusal every provider would give is the customer's (`countStep`): anything else that goes to the
          // next route is the account's or its route's, and still cools it (AF-19).
          supplierFailure: step !== "rejected",
        });
        recordLanePrevious(run, laneContext.relayId, laneContext.accountId, word);
        if (step === "rejected") {
          // Defer reporting until after the receipt is signed.
          run.laneServing = {
            relayId: laneContext.relayId,
            accountId: laneContext.accountId,
            requestRef: laneContext.requestRef,
            status,
            code: "count_tokens_request_rejected",
          };
        } else {
          reportLanePick(run, run.lane!, laneContext.relayId, {
            account_id: laneContext.accountId,
            request_ref: laneContext.requestRef,
            outcome: word,
            usage: ZERO_LANE_USAGE,
            latency_bucket: latencyBand(elapsed),
          });
        }
      }

      if (step === "rejected") return { kind: "rejected" };
      if (step === "repeat") return { kind: "connect" };
      return { kind: "unavailable" };
    }

    // 2xx reply: bounded read at COUNT_REPLY_LIMIT within deadline.
    const replyBytes = await readBoundedWithin(response, COUNT_REPLY_LIMIT, deadline, clock, timers);
    const elapsed = clock() - startedAt;
    const counts = replyBytes === null ? null : parseCountReply(run.protocol, replyBytes);
    if (counts === null) {
      if (laneContext?.kind === "relay") {
        recordLanePrevious(run, laneContext.relayId, laneContext.accountId, "upstream_error");
        reportLanePick(run, run.lane!, laneContext.relayId, {
          account_id: laneContext.accountId,
          request_ref: laneContext.requestRef,
          outcome: "upstream_error",
          usage: ZERO_LANE_USAGE,
          latency_bucket: latencyBand(elapsed),
        });
      }
      pushAttempt(run, route, startedAt, status, "invalid_response", "count_tokens_unavailable");
      return { kind: "unavailable" };
    }

    if (laneContext !== null) {
      run.laneDraft = laneContext.draft;
      run.winningReceipt = "lane";
      run.laneReceiptId ??= newLaneReceiptId();
      if (laneContext.kind === "relay") {
        run.laneServing = {
          relayId: laneContext.relayId,
          accountId: laneContext.accountId,
          requestRef: laneContext.requestRef,
          status,
          code: "",
        };
      }
    }
    pushAttempt(run, route, startedAt, status, "success", null);
    return { kind: "answered", counts };
  } finally {
    timers.clearTimeout(timer);
    unsubscribe();
  }
}
