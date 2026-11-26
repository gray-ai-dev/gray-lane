/**
 * The client's stream and its headers (`InferenceRun`, inference.ts): the error event a stream ends with, the headers an
 * answer names its cap, model and dropped members in, the log lines of an answer Gray's own bound cut, the end of a
 * stream, and Gray's own failure, which abandons the attempt and releases the hold.
 */
import { ApiError, shapeOf } from "@gray/errors";
import { ClientStream, errorFrame } from "../client.ts";
import { lanePolicyRefused, laneSafeLog } from "../lane/hooks.ts";
import { failureNames } from "../lane/run-common.ts";
import type { Route } from "../routes.ts";
import { endAttempt } from "./attempt.ts";
import { type HoldRun, releaseHold } from "./hold.ts";
import { type RecordRun, errorResponse, record } from "./record.ts";

const encoder = new TextEncoder();

/** What stream.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface StreamRun extends HoldRun, RecordRun {}

/** The client protocol's error event (a translated stream's from its stage, which numbers it). */
export function errorFrameOf(run: StreamRun, stage: { errorFrame(code: string): Uint8Array } | null, code: string): Uint8Array {
  return stage !== null ? stage.errorFrame(code) : errorFrame(run.protocol, code, 0n);
}

/**
 * The error frame for a relay policy refusal that arrives after a lane stream's headers went (F2
 * hooks-4, the residual path): the protocol's error event whose data payload is **exactly** the
 * fixed 403 `relay_policy_refused` body a client gets without early headers, so a client parsing
 * either form reads the same refusal — never a generic `upstream_error`.
 */
export function laneRefusalFrame(run: StreamRun): Uint8Array {
  const rendered = lanePolicyRefused().render({ shape: shapeOf(run.path), origins: run.origins, requestId: run.requestId });
  const event = run.protocol === "anthropic_messages" || run.protocol === "open_ai_responses" ? "event: error\n" : "";
  return encoder.encode(`${event}data: ${rendered.body}\n\n`);
}

/** A request that listed fallback models is told which one served it (`x-gray-model`). */
export function modelHeader(run: StreamRun, headers: Headers): void {
  if (run.admitting.listedModels.length > 0 && run.facts.model !== null) headers.set("x-gray-model", run.facts.model);
}

/**
 * The relay of a stream whose headers wait for its first bytes failed before any (`openStream`): the
 * client gets the refusal held for the attempt, as JSON with its status, and the record says so. False
 * when the headers went, or no refusal is held to tell: the stream ends with its error event.
 */
export function failedBeforeBytes(run: StreamRun, client: ClientStream): boolean {
  const pre = run.answer.preHeaders;
  const held = run.admitting.dispatcher?.heldToTell() ?? null;
  if (pre === null || held === null || client.written > 0) return false;
  run.answer.preHeaders = null;
  if (run.lane !== null) {
    const heldDraft = run.receipt.attemptLaneDrafts.get(held.attempt);
    if (heldDraft !== undefined) {
      run.receipt.laneDraft = heldDraft;
      run.receipt.winningReceipt = "lane";
    }
  }
  const error = told(run, held.refusal);
  const response = errorResponse(run, error);
  record(run, error.status, error.status >= 500 ? "failed" : "rejected", error.code);
  pre.told(response);
  return true;
}

export function cleanupInflight(run: StreamRun, reason: string): void {
  const attempt = run.admitting.current;
  if (attempt !== null) {
    attempt.controller.abort(reason);
    endAttempt(run, attempt, { kind: "not_counted", reason: "gray_error" }, true, reason);
  }
  releaseHold(run, { reason, detail: { stage: run.admitting.admission, endpoint: attempt?.route.record.endpointId ?? null } });
}

/**
 * After a failure of Gray's own (a bug): the attempt in flight is cancelled and its permit handed
 * back as Gray's fault, and the hold released. Nothing is charged.
 */
export function abandon(run: StreamRun, error: unknown, event: string): void {
  console.error(
    JSON.stringify(
      run.lane === null
        ? { level: "error", event, request_id: run.requestId, stage: run.admitting.admission, message: error instanceof Error ? error.message : String(error) }
        : laneSafeLog({ level: "error", event, request_id: run.requestId, stage: run.admitting.admission, ...failureNames(error) }),
    ),
  );
  cleanupInflight(run, "internal_error");
}

/**
 * Gray's own bound (ANSWER_HELD_MAX_BYTES) ended an answer, a held stream's frames or what a
 * non-streaming answer kept: the request is released free, and the supplier, who made what was
 * cut, gets no accrual for it either (it may still owe its own upstream for it; whether Gray should
 * read on and charge by usage instead is for the owner, gateway.md section 13 item 18). No agent's
 * tool call comes near the bound, so this is a bug or a client asking for it (text passed on, then a
 * tool call grown past it): an alert, with the key and workspace, so a key that repeats it is seen.
 */
export function answerLimitCut(run: StreamRun, route: Route, code: string, limitBytes: number | null, received: number): void {
  // The bound from the request's output limit (@gray/limits `answerLimit`) ended an answer: Gray's limit, free, and not
  // the supplier's failure in its circuit (a buffered one is evidence that the route did not honour the cap,
  // `bodyPastOutputLimit`). A real answer of the cap that passes it means the bound is too small for that API's
  // answers (docs/limits.md section 6): a warning with what it read, so a bound to raise is seen.
  const line = { level: "warn", event: "answer_limit_cut", request_id: run.requestId, code, limit_bytes: limitBytes, bytes_received: received, endpoint: route.record.endpointId };
  console.warn(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
}

export function heldLimitAlert(run: StreamRun, route: Route): void {
  // The entry's line has no key and no workspace (laneSafeLog; deploy/tee/IMPLEMENTATION_NOTES.md §9, "public_logs"):
  // the request id finds them in the request's record.
  const line = { level: "alert", event: "answer_held_limit", request_id: run.requestId, workspace: run.caller.key?.workspaceId ?? null, key: run.caller.key?.keyId ?? null, held_bytes: run.answer.heldBytes, limit_bytes: run.deps.cfg.answerHeldMaxBytes, endpoint: route.record.endpointId };
  console.error(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
}

/**
 * Ends a stream with its last frames (an error event), which the content keeps too when the client's
 * stream took them: the server's tee keeps only what passed to its client, so what is stored is never
 * more than the record counts.
 */
export function endStream(run: StreamRun, client: ClientStream, last?: Uint8Array): void {
  if (client.end(last) && last !== undefined) run.facts.content?.push(last);
  // A stack relay's stream that ends with Gray's error event ended with an error its container did not write (S26).
  if (last !== undefined && run.stackPeer.stackClient !== null) run.stackPeer.stackReplacedError = true;
  run.answer.responseBytes = client.written;
}

export function capHeaders(run: StreamRun, headers: Headers): void {
  if (run.facts.outputCap !== null) headers.set("x-gray-max-output-tokens", String(run.facts.outputCap));
  if (run.facts.outputCapReason !== null) headers.set("x-gray-output-limit-reason", run.facts.outputCapReason);
}

/**
 * What every client error after admission carries (`told`): the upstream attempts this model sent, and
 * for a request under a client's Idempotency-Key that the key is spent, with `x-should-retry: false`.
 */
export function told(run: StreamRun, error: ApiError): ApiError {
  const told = error.withMeta("attempts", BigInt(run.admitting.dispatcher?.tried.attempts ?? 0));
  if (!run.caller.clientKey) return told;
  return told.withMeta("idempotency_key", "spent").note("This Idempotency-Key is spent; send the request again with a new one.").noRetry();
}
