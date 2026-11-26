/** The settlement's pure steps (`InferenceRun.settle`, inference.ts): what an answer's end, usage and error body say, read without the request's state. */
import type { Outcome as EndpointOutcome, PermitToken } from "@gray/endpoint";
import { ERROR_BODY_LIMIT } from "@gray/errors";
import type { Sizing } from "@gray/holds";
import { type Json, isObject } from "@gray/json";
import { eqIgnoreAsciiCase } from "@gray/limits";
import { type FinishReason, type OutputLimit, type Protocol, type Settlement, type AnswerEndFailure, AnswerEnd, GeminiRefusal, missingUsageReason, unfinished } from "@gray/protocol";
import type { FinishError } from "../image-usage.ts";
import type { SettleOutcome } from "../relay.ts";
import { outputOverhead, type Route } from "../routes.ts";
import { ERROR_DETAIL_BYTES, bounded } from "../sinks.ts";
import type { GatewaySnapshot } from "../snapshot.ts";
import type { Attempt, Answering, SettleEnd } from "./types.ts";

/** The output a request may be billed for at its serving route (`OutputLimit`). */
export function outputLimit(a: Answering, route: Route): OutputLimit {
  return { maxOutputTokens: a.outputCap, allowance: BigInt(route.record.outputOverheadTokens ?? 0), candidateCount: a.candidates };
}

/**
 * Whether the model's facts list image output (inference.rs `model_outputs_images`): its answers may carry generated
 * images, which the answer limit counts at the largest documented image per token (@gray/limits `IMAGE_BYTES_PER_TOKEN`).
 * Counted as text before, a Gemini image answer passed its limit and was cut.
 */
export function outputsImages(snapshot: GatewaySnapshot, model: string): boolean {
  return snapshot.facts?.[model]?.output_modalities.some((m) => eqIgnoreAsciiCase(m, "image")) === true;
}

/** The output tokens an answer may take: what the hold covers (at most the largest window when nothing bounds it), plus the endpoints' allowance, per candidate. */
export function answerTokens(sizing: Sizing, routes: readonly Route[], snapshot: GatewaySnapshot, model: string, candidates: number): bigint {
  const allowance = outputOverhead(routes);
  let output = sizing.heldOutput;
  const window = snapshot.models[model]?.window;
  const largest = snapshot.largestWindow;
  if (sizing.defaultCap && !sizing.writeCap && window === undefined && largest !== undefined && BigInt(largest) < output) output = BigInt(largest);
  return (output + allowance) * BigInt(candidates);
}

/**
 * An answer whose end is its chain's failure (`AnswerEnd`, `UNFINISHED_EMPTY`): refused uncharged with its code, as
 * any other answer defect is, so that a buffered one not yet committed may go to another route and either counts as
 * its supplier's invalid answer. Its words are the attempt's `error_detail`; no `gray.usage_refusal/1` event is
 * sent, since its usage is not what was refused (the event's codes are the three usage codes, lane-wire records.ts).
 * An answer that is also a Gemini refusal is this failure, not the model's refusal (`refusedOf`, the stream's
 * `settleRefused`): a candidate stopped for the supplier's account is the supplier's whatever the others say.
 */
export function answerEndFailed(attempt: Attempt, failure: AnswerEndFailure): SettleOutcome {
  attempt.errorDetail = bounded(failure.why, ERROR_DETAIL_BYTES);
  // The supplier's account limited by its vendor is the provider's own fault, whatever its code says to the traffic
  // evidence (`AttemptEvidence.providerFault`): the route's next check comes forward.
  if (failure.reason === "upstream_account_limited" && attempt.evidence !== undefined) attempt.evidence.providerFault = true;
  return { ok: false, code: failure.code, reason: failure.code, why: failure.why };
}

/**
 * A settlement's failure that is Gray's after the answer passed its checks (the server settles after the
 * commit, `buffered_answer`): a charge the shard did not confirm, Gray's own evidence that its review
 * refused, or the answer's tool-call id rows that could not be stored (`blameless`). Any other failure is the usage's (missing, invalid, over the output limit or the bound), which
 * the server checks before the commit, so another attempt may serve the request.
 */
export function grayAfterCheck(settled: Extract<SettleOutcome, { ok: false }>): boolean {
  return settled.code === "billing_finalize_failed" || settled.reason === "usage_evidence_invalid" || settled.blameless === true;
}

/**
 * The estimation's point an attempt's release carries (r24, docs/utility-routing.md): its answer's uncached and
 * cache-read input (`estInput`), for a charged success or a model check's (`charged`: no free delivery, no answer Gray
 * failed), read from a buffered upstream (`bufferedRead`), with no time to first token and at least one output token. The
 * endpoint shard adds the measure's output tokens and latency beside it. Null for any other attempt.
 */
export function estimationPoint(attempt: Pick<Attempt, "bufferedRead" | "ttftMs" | "outputTokens" | "estInput">, charged: boolean): readonly [u: number, c: number] | null {
  if (!charged || attempt.bufferedRead !== true || attempt.ttftMs !== undefined || (attempt.outputTokens ?? 0) < 1) return null;
  return attempt.estInput ?? null;
}

/**
 * How a permit goes back whose attempt Gray stopped before anything was sent (a credential it cannot open,
 * a route whose mapping cannot be asked): Gray's own error, and for a recovery probe `not_dispatched`, so
 * the root gives the probe lease back as never sent and starts no clock for its waiters (the server's
 * `abandon_recovery` before `probe_sent`).
 */
export function unsentOutcome(permit: PermitToken): EndpointOutcome {
  return { kind: "not_counted", reason: permit.probeId !== null ? "not_dispatched" : "gray_error" };
}

/** An error body, read within ERROR_BODY_LIMIT bytes and until `until` (`upstream_errors::read`). */
export async function errorBody(response: Response, until: number, clock: () => number): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < ERROR_BODY_LIMIT) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const next = await Promise.race([reader.read(), new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), Math.max(0, until - clock()))))]);
      clearTimeout(timer);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      length += next.value.length;
    }
  } catch {
    // What arrived is what the rules read.
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(length, ERROR_BODY_LIMIT));
  let at = 0;
  for (const c of chunks) {
    const n = Math.min(c.length, out.length - at);
    out.set(c.subarray(0, n), at);
    at += n;
    if (at >= out.length) break;
  }
  return out;
}

/**
 * The reason a refused usage releases its hold with, by why it was refused: the request log's and the
 * release's words for each `FinishError` (an image not counted apart is never refused, `deliveredFree`).
 */
export const REFUSED_AS: Readonly<Record<FinishError["kind"], string>> = {
  usage_missing: "upstream_usage_missing",
  upstream_usage: "upstream_usage_invalid",
  output_over_limit: "upstream_usage_exceeds_limit",
  image_usage_unsplit: "image_usage_unsplit",
};

/** `SettleEnd` of a buffered answer: its body, as `upstream` answered it, and the stop `parseResponse` read of it. */
export function bufferedEnd(upstream: Protocol, payload: Json, finish: FinishReason | null): SettleEnd {
  return { failure: AnswerEnd.of(upstream, payload), unfinished: unfinished(upstream, payload, finish) };
}

/**
 * The model's refusal a buffered answer of `upstream` is (a Gemini one's, `GeminiRefusal`), unless its end is its
 * chain's failure (`AnswerEnd`): a candidate stopped for the supplier's account fails the answer as the supplier's,
 * whatever its other candidates say.
 */
export function refusedOf(upstream: Protocol, payload: Json): string | undefined {
  if (upstream !== "gemini" || AnswerEnd.of(upstream, payload) !== undefined) return undefined;
  return GeminiRefusal.of(payload);
}

/**
 * The settlement of a buffered answer whose usage did not parse into counters (inference.rs `buffered`):
 * missing, saying what was missing, the usage object itself or a counter it is billed on.
 */
export function unreported(protocol: Protocol, rawUsage: Json | null): Settlement {
  return { kind: "missing", reason: isObject(rawUsage) ? missingUsageReason(protocol, rawUsage) : "the answer reported no usage object" };
}
