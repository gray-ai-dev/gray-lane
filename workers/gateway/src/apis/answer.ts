/**
 * The answer of a model API other than video creation (`ModelApiRun`, apis.ts): read, checked and metered, charged or
 * released, and handed to the client.
 */
import { ApiError } from "@gray/errors";
import type { ApiRequest } from "@gray/media";
import { AFTER_CLIENT_LEFT_MS } from "../client.ts";
import { countedFailure } from "../dispatcher.ts";
import { responseHash } from "../lane/hooks.ts";
import { answerReader, type MediaAnswer } from "../media-answer.ts";
import { MODEL_REFUSED, type Attempt, type ApiRunCore } from "./state.ts";
import { errorResponse, leftDetail } from "./io.ts";
import { releaseHold, endAttempt, abandon } from "./hold.ts";
import { refuse, record } from "./record.ts";
import { settle } from "./settle.ts";
import { dropEntryBody } from "./send.ts";

/**
 * 8. The answer of a model API other than video creation: read, checked and metered (media-answer.ts),
 * then charged or released, and the response handed over: as it started (a streamed answer), or
 * whole at its end.
 */
export function answer(run: ApiRunCore, api: ApiRequest, attempt: Attempt, response: Response, deadline: number): Promise<Response> {
  const { cfg, clock } = run.deps;
  let handOver!: (response: Response) => void;
  const handed = new Promise<Response>((resolve) => (handOver = resolve));
  let reader: MediaAnswer | null = null;
  // An answer committed: no other attempt follows, so the client's bytes are let go; what the client is sent is hashed
  // from here.
  dropEntryBody(run);
  run.laneResponse = responseHash();
  const relay = (async () => {
    reader = answerReader({
      tap: (bytes: Uint8Array) => run.laneResponse?.update(bytes),
      protocol: run.protocol,
      api,
      route: attempt.candidate.media,
      response,
      presence: run.presence,
      clock,
      // F2 D54/D74: the media answer's `ClientStream` takes the request path's timers, so a stall
      // or keep-alive bound is the test's clock and not the machine's.
      timers: run.deps.timers,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      cfg,
      retained: run.retained,
      isolate: run.answerShare,
      drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
      endpoint: { name: attempt.candidate.record.name, baseUrl: attempt.candidate.record.baseUrl },
      start: (stream, headers) => {
        run.ttfbMs = clock() - run.started;
        headers.set("x-request-id", run.requestId);
        headers.set("x-gray-attempt", String(attempt.index + 1));
        handOver(new Response(stream, { status: 200, headers }));
      },
    });
    const current = reader;
    const read = await current.read();
    run.heldBytes = Math.max(run.heldBytes, current.heldMost);
    if (read.kind === "client_left") {
      attempt.controller.abort("client_left");
      run.leftBeforeFinal = true;
      endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, read.why);
      releaseHold(run, read.why, leftDetail(run, attempt, read.received));
      if (current.started) {
        current.abort(read.why);
        run.responseBytes = current.written;
        record(run, 200, "cancelled", read.why);
        return;
      }
      handOver(errorResponse(run, new ApiError(499, "client_cancelled")));
      record(run, 499, "cancelled", "client_left");
      return;
    }
    if (read.kind === "refused") {
      // The model's refusal of the request (apis/mod.rs `refused_upstream`): the request's own outcome, not
      // charged, and neither for nor against the route.
      endAttempt(run, attempt, { kind: "not_counted", reason: "request_refused" }, false, read.error.code);
      releaseHold(run, read.error.code, { code: read.error.code, reason: String(read.error.metadata.reason ?? ""), endpoint: attempt.candidate.record.endpointId, provider: attempt.candidate.record.operator, attempt: attempt.index });
      handOver(errorResponse(run, read.error));
      record(run, read.error.status, "rejected", read.error.code);
      return;
    }
    if (read.kind === "failed") {
      answerFailed(run, attempt, current, handOver, read.error, read.reason, read.why, read.supplierFailure, read.upstreamMayStillWork);
      return;
    }
    if (read.billed.kind === "refused") {
      // The model's refusal of the request in an answer of its own (inference.rs `refused_answer` on main):
      // delivered as it came, charged nothing, and neither for nor against the route.
      const routeRecord = attempt.candidate.record;
      endAttempt(run, attempt, { kind: "not_counted", reason: "request_refused" }, false, MODEL_REFUSED, { rejected: true });
      releaseHold(run, MODEL_REFUSED, { refusal: read.billed.reason, endpoint: routeRecord.endpointId, provider: routeRecord.operator, attempt: attempt.index });
    } else {
      const settled = await settle(run, api, attempt, read.billed);
      if (!settled.ok) {
        answerFailed(run, attempt, current, handOver, settled.error, settled.reason, settled.why, settled.error.code === "billing_finalize_failed" ? null : "invalid_response", false);
        return;
      }
      endAttempt(run, attempt, { kind: "success" }, false, null);
    }
    const out = await current.deliver();
    if (out.kind === "whole") {
      run.laneResponse?.update(out.bytes);
      run.responseBytes = out.bytes.length;
      run.responseComplete = true;
      const headers = new Headers(out.headers);
      headers.set("content-length", String(out.bytes.length));
      headers.set("x-request-id", run.requestId);
      headers.set("x-gray-attempt", String(attempt.index + 1));
      run.ttfbMs = clock() - run.started;
      handOver(new Response(out.bytes, { status: 200, headers }));
      try {
        record(run, 200, "completed", null);
      } catch (error) {
        abandon(run, error, "record_failed");
      }
      return;
    }
    run.responseBytes = current.written;
    run.responseComplete = out.delivered;
    try {
      record(run, 200, "completed", null);
    } catch (error) {
      abandon(run, error, "record_failed");
    }
  })();
  const relayed = relay.catch((error: unknown) => {
    const started = reader?.started === true;
    if (!started && run.billing === "charged") {
      // Charged at the shard before `handOver`: mark unsettled so gray-jobs refunds the undelivered answer.
      run.billing = "unsettled";
      run.charged = null;
      run.chargedSides = null;
      run.chargeSeq = null;
    }
    abandon(run, error, started ? "relay_failed" : "request_failed");
    if (started) {
      reader!.abort("internal_error");
      run.responseBytes = reader!.written;
      record(run, 200, "failed", "internal_error");
      return;
    }
    handOver(refuse(run, new ApiError(500, "internal_error"), run.admission));
  });
  run.ctx.waitUntil(relayed);
  return handed;
}

/** An answer's failure before or after its response started: the endpoint's outcome, the hold released, the client told. */
export function answerFailed(run: ApiRunCore, attempt: Attempt, reader: MediaAnswer, handOver: (response: Response) => void, error: ApiError, reason: string, why: string, supplier: "timeout" | "upstream_error" | "invalid_response" | null, upstreamMayStillWork: boolean): void {
  run.answerShare.hold(0, run.deps.cfg.answerHeldMaxBytes);
  if (upstreamMayStillWork) attempt.controller.abort(error.code);
  if (supplier !== null && run.traffic.committedFailed(attempt.evidence, error.code, run.deps.clock())) attempt.providerFailure = true;
  endAttempt(run, attempt, supplier === null ? { kind: "not_counted", reason: "gray_error" } : { kind: "supplier_failure", reason: supplier }, upstreamMayStillWork, error.code, { failure: countedFailure(null, error.code) });
  releaseHold(run, reason, { code: error.code, why: why.slice(0, 200), endpoint: attempt.candidate.record.endpointId, provider: attempt.candidate.record.operator, attempt: attempt.index });
  run.heldBytes = Math.max(run.heldBytes, reader.heldMost);
  if (reader.started) {
    reader.abort(error.code);
    run.responseBytes = reader.written;
    record(run, 200, "interrupted", error.code);
    return;
  }
  handOver(errorResponse(run, error));
  record(run, error.status, "failed", error.code);
}
