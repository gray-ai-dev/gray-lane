/**
 * The age a snapshot answer is judged by (design v2 section D, M19).
 *
 * Moved here from `workers/gateway/src/snapshot.ts` so the CVM's remote source and the bridge both
 * judge an answer with the same rule: the bridge's `snapshot.current` applies it while choosing among
 * the region's replicas, and the gateway's `ReplicaSource` applies it to the copies it reads.
 */

/**
 * The age a check's answer will be acted on past (`SnapshotCache`): CONFIG_ALERT_AGE_MS while the
 * copy has not been said stale, CONFIG_MAX_AGE_MS once it has. A copy older than `ageMs` at `now` is
 * the writer's age only when its source heard so from the writer (`currentFor`).
 */
export interface AgeJudgement {
  readonly now: number;
  readonly ageMs: number;
}

/** When an answer's version was last confirmed current (`SnapshotAnswer.confirmedAt`, or its `refreshedAt` when the source does not say). */
export function confirmedAtOf(answer: { readonly refreshedAt: number; readonly confirmedAt?: number }): number {
  return typeof answer.confirmedAt === "number" && Number.isFinite(answer.confirmedAt) ? answer.confirmedAt : answer.refreshedAt;
}

/**
 * Whether an answer's age can be acted on (`AgeJudgement`): its copy is within the age, or its source
 * confirmed it with the writer when it was already past the age, and within the age of now. Otherwise
 * the copy aged because its source did not hear from the writer since (a replica nobody asked for a
 * while, whose sync is now slower than half the call timeout, or that cannot reach ConfigDO), which
 * says nothing about whether the writer still rebuilds. ConfigDO's own answers confirm at its clock.
 */
export function currentFor(answer: { readonly refreshedAt: number; readonly confirmedAt?: number }, judge: AgeJudgement): boolean {
  if (judge.now - answer.refreshedAt <= judge.ageMs) return true;
  const confirmed = confirmedAtOf(answer);
  return confirmed - answer.refreshedAt > judge.ageMs && judge.now - confirmed <= judge.ageMs;
}
