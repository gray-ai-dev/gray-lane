/**
 * How an entry reads the end of a peer attempt (docs/confidential-lane-stack-routing.md section 4.7): the hop's answer kept
 * open for its `end`, the answer checks and outcome that `end` carries, and what a vendor's error over the hop means for
 * the next route.
 */
import type { PeerEndDto, PeerHeadDto } from "@gray/lane-wire";
import { classDisposition, type Outcome as RetryOutcome } from "@gray/errors";
import type { Json } from "@gray/json";
import { type AnswerChecks, type Protocol, type ResponseBillingMeta, UNCOUNTED_CHECKS } from "@gray/protocol";
import type { StreamTimers } from "../client.ts";
import { countedChecks } from "../sinks.ts";
import { codexBackend } from "../lane/plan.ts";
import { receiptChangedBody } from "../lane/stack.ts";
import type { Attempt, PeerOutcome } from "./types.ts";

/**
 * Whether a peer attempt's answer checks are its stack VM's as they came (review r14 lane-wire finding 10): the stack
 * VM ended the attempt itself (its `end.outcome` is not `served`: its gate refused the answer, egress cut it, the relay
 * failed, the vendor erred) and counted that ending before it sent `end.checks` (lane/backend.ts `#endChecks`), so what
 * the entry made of it after is not the entry's to discount again: Gray's error frame, which fails the answer at the
 * entry before its commit (`peerUncommitted`: `lane_relay_failed` after the follow-up, or `answered`, `gray_error`, when
 * the `end` was in), or the stream cut after its commit. Only the entry's own endings count
 * nothing: its client left, its own deadline cut the answer, or the attempt was refused before it went (`rejected`). A
 * served attempt, or one whose `end` never came, is counted by the entry's end as any other (`countedChecks`): a served
 * answer the entry failed is the entry's own Gray error. The retry class, the success rate and the charge are as before.
 */
export function stackVmEnded(attempt: Attempt, ended: string, rejected: boolean): boolean {
  const end = attempt.peer?.end ?? null;
  if (end === null || end.outcome === "served") return false;
  return ended !== "client_left" && attempt.deadlineCut !== true && !rejected;
}

/** A peer attempt's two answer checks from its `end` as it is now, as its record closed it (`stackVmEnded`, `countedChecks`). */
export function peerAttemptChecks(attempt: Attempt, ended: string, code: string | null, rejected: boolean): AnswerChecks {
  const classified = peerChecks(attempt.peer?.end ?? null);
  return stackVmEnded(attempt, ended, rejected) ? classified : countedChecks(classified, { outcome: ended, code, rejected, deadlineCut: attempt.deadlineCut === true });
}

/**
 * The longest an entry waits for the hop's `end` after the request path failed a peer answer before it (Gray's error
 * frame after a stream the stack VM's gate refused; review r14 lane-wire finding 10), for the attempt's answer checks
 * alone: 500 ms. The stack VM writes `end` right after that frame, once it closed the rid at egress (a call within its
 * own VM) and signed its receipt (lane/backend.ts `run`), on the hop already open, so a few milliseconds is the rule. The
 * bound is PEER_FOLLOW_UP_MS's floor (egress's -peer-connect-timeout default), within what the request's pre phase has
 * left; the follow-up that may come after keeps its own. An `end` not in by then counts nothing, and the attempt closes as
 * it did.
 */
export const PEER_END_WAIT_MS = 500;

/**
 * A peer answer as the request path reads it (`InferenceRun.prime`, then the relay), whose letting go of the answer does
 * not close the hop at once, for the `end` the stack VM writes after its last frame, once it closed its rid at egress
 * and signed its receipt (lane/backend.ts `run`): the attempt's answer checks come with it (review r14 lane-wire finding
 * 10, whole-pr blocker 1). Priming lets go of an answer that ended with an error event at once (relay.ts
 * `primeStream`, which frees a vendor's slot so), and the relay of a stream that failed after its commit lets go of it
 * too (relay.ts `fail`), both before that `end` is in.
 *
 * Before the commit, a let-go is kept back until `commit` (then passed on at once, as before) or until the attempt
 * closes the call (`peerUncommitted`: `endWithin`, then `close`). From the commit, a let-go stops the relay's reading
 * here, and so does `closeAfterEnd`, which takes the place of the attempt's abort of an upstream that may still work
 * (`InferenceRun.relay`): the hop is let go of, and the attempt's fetch aborted (`abort`), once `end` is in (the hop
 * then ended itself: nothing is left to close), PEER_END_WAIT_MS later at most, or when the call closes first
 * (`finishPeer`). Nothing the client was sent waits for it: the relay wrote its error frame and settled before
 * (`end.usage` included). The hop is read one frame ahead meanwhile: this stream's own pull, and below it the call's
 * body's (each pulls again while its queue is empty), so the `end` that follows the last frame read lands in `ended`.
 */
export function endKept(response: Response, timers: StreamTimers, abort: (reason: unknown) => void): { readonly response: Response; commit(): void; closeAfterEnd(reason: unknown): void } {
  const source = response.body;
  if (source === null) return { response, commit: () => {}, closeAfterEnd: abort };
  const reader = source.getReader();
  let committed = false;
  let kept: { readonly reason: unknown } | null = null;
  let closing: unknown = null;
  let closingReason: unknown = undefined;
  let over = false;
  /** The hop is let go of: cancelled, and with `abortToo`, the attempt's fetch aborted. */
  const letGo = (reason: unknown, abortToo: boolean): void => {
    if (over) return;
    over = true;
    if (closing !== null) timers.clearTimeout(closing);
    closing = null;
    reader.cancel(reason).catch(() => {});
    if (abortToo) abort(reason);
  };
  /** The hop has ended (its `end`, or without it): nothing is left to let go of. */
  const ended = (): void => {
    over = true;
    if (closing !== null) timers.clearTimeout(closing);
    closing = null;
  };
  const closeAfterEnd = (reason: unknown): void => {
    if (reason !== undefined) closingReason = reason;
    if (over || closing !== null) return;
    closing = timers.setTimeout(() => letGo(closingReason, true), PEER_END_WAIT_MS);
  };
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      let read: ReadableStreamReadResult<Uint8Array>;
      try {
        read = await reader.read();
      } catch (error) {
        const lettingGo = kept !== null || closing !== null;
        ended();
        // Let go of meanwhile, the read's failure is the call's alone; else it is the answer's.
        if (!lettingGo) controller.error(error);
        return;
      }
      if (read.done) ended();
      try {
        if (read.done) controller.close();
        else controller.enqueue(read.value);
      } catch {
        // Let go of meanwhile: what the hop still sends (its `end`) is the call's alone.
      }
    },
    cancel(reason) {
      if (!committed) kept = { reason };
      else closeAfterEnd(reason);
    },
  });
  return {
    response: new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers }),
    commit: () => {
      committed = true;
      if (kept !== null) letGo(kept.reason, false);
    },
    closeAfterEnd,
  };
}

/**
 * A peer attempt's answer checks: the ones its stack VM computed with the gate code the entry runs and sent in `end`
 * (docs/error-rates.md, The TEE lane), none when `end` did not come or carried none (a stack VM before them). Never the
 * entry's own gate's: the entry gets no byte of an answer the stack VM refused.
 */
export function peerChecks(end: PeerEndDto | null): AnswerChecks {
  const checks = end?.checks;
  return checks === undefined ? UNCOUNTED_CHECKS : { toolCallCheck: checks.tool_call_check, outputCheck: checks.output_check };
}

/**
 * A peer attempt's billing meta: `read`, what the entry read in the answer it got, with the hosted tool calls in place
 * of its own when the stack VM counted them (`end.hosted_tool_calls`, a buffered Codex answer read from its stream there,
 * whose terminal output may be empty). The stack VM's count heard that output too, so it is never added to the entry's.
 * Only a Responses answer of a Codex route takes it: that is the one answer the stack VM reads from a stream the hop
 * does not carry (D129). Any other answer's hosted tool calls are in the bytes the entry got, so a count in `end` there
 * is ignored, as is one from a stack VM before it: `read` as it is, as before.
 */
export function peerBillingMeta(attempt: Attempt, protocol: Protocol, read: ResponseBillingMeta): ResponseBillingMeta {
  const counted = attempt.peer?.end?.hosted_tool_calls;
  if (counted === undefined || protocol !== "open_ai_responses" || !codexBackend(attempt.route.record.url)) return read;
  return { ...read, toolCalls: counted };
}

/**
 * What an entry's hop answer that did not commit ends as (section 4.7): `end.outcome` `not_dialed` is the next route's,
 * `vendor_error` the vendor's own error body (`data`), `relay_failed` Gray's `lane_relay_failed`. A `served` or `cut`
 * end with a head that is not 200 is not one the backend writes (its head is 200 once bytes are released): Gray's 502.
 */
export function peerEndedOutcome(end: PeerEndDto, head: PeerHeadDto, body: Uint8Array): PeerOutcome {
  if (end.outcome === "not_dialed") return { kind: "not_dialed", code: end.code ?? "peer_invalid" };
  // The stack VM's attempt whose error it released is `served_attempt`; its group in the inner receipt lists what the
  // relay's software changed (S26). A stack VM that sends no receipt, or one before `relay_stack.changed`, changed nothing.
  if (end.outcome === "vendor_error") {
    const headers: Record<string, string> = {};
    if (head.headers !== undefined) {
      for (const [name, value] of Object.entries(head.headers)) {
        if (value !== undefined) headers[name] = value;
      }
    }
    return { kind: "vendor_error", status: Number(head.status), body, headers, accountId: end.relay_account_id, changedBody: receiptChangedBody(end.receipt, end.served_attempt) };
  }
  if (end.vendor_event !== undefined) return { kind: "vendor_event", event: end.vendor_event as Json, accountId: end.relay_account_id };
  return { kind: "relay_failed", code: end.code ?? "peer_invalid" };
}

/**
 * Whether a stack relay's vendor error is one the main gateway tries another route after, the supplier's and not the
 * request's: a rate limit (`throttled`, a 429 or an overload), a server error, a timeout. A refusal of the request (a
 * 400, a 404, a context overflow) stays the client's answer at once, the vendor's words, as before, but a 400 of a body
 * the relay's software changed (`relayChangeRefused`).
 */
export function passesToNextRoute(outcome: RetryOutcome): boolean {
  return outcome.class === "throttled" || outcome.class === "server_error" || outcome.class === "timeout";
}

/**
 * Whether a stack relay's vendor error refused the relay's own upstream account rather than the request: the
 * classes the request log records as `credential` (@gray/errors `classDisposition`: `credential` and
 * `account_request`).
 */
export function refusedTheRelaysAccount(outcome: RetryOutcome): boolean {
  return classDisposition(outcome.class, outcome.status, outcome.serverCode) === "credential";
}
