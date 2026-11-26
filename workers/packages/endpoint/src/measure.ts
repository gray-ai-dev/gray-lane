import type { AttemptFailure } from "@gray/routing";

// A leaf module: the lane bundle checks measures through the package's top-level entry without
// loading circuit.ts.

/**
 * An attempt's measures as its shard carries them (the server's `Observation` beside its outcome): its latency (from
 * its start to its end), its time to first token (streams only; null when unmeasured), the committed answer's output
 * tokens (0 for a failure and a free answer), and a failure's kind (`AttemptFailure`; null for a success).
 */
export type OutcomeMeasure = readonly [latencyMs: number, ttftMs: number | null, outputTokens: number, failure: AttemptFailure | null, inSession?: 0 | 1];

/**
 * Whether `m` is an attempt's measures (`OutcomeMeasure`): what the root takes from a report or a probe's result, and a
 * shard from a release. The fifth member (r17, docs/utility-routing.md "The long record"): 1 when the attempt's route was
 * its session's established provider on the gateway instance that sent it; the shard consumes it for the long record and
 * never sends it on to the root, so a root of an earlier release only ever meets four members.
 */
export function validMeasure(m: unknown): m is OutcomeMeasure {
  if (!Array.isArray(m) || (m.length !== 4 && m.length !== 5)) return false;
  const [latency, ttft, tokens, failure, inSession] = m as unknown[];
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  return count(latency) && (ttft === null || count(ttft)) && count(tokens) && (failure === null || (typeof failure === "string" && ATTEMPT_FAILURES.includes(failure as AttemptFailure))) && (m.length === 4 || inSession === 0 || inSession === 1);
}

const ATTEMPT_FAILURES: readonly string[] = ["timeout", "rate_limited", "transport", "rejected", "protocol"];
