import { feedAnswerBytes, feedColumnsCount, type FeedAnswer } from "@gray/routing";

/**
 * The ranking feed's Analytics Engine points that do not come with a request's record (review r31 findings 11-13;
 * docs/cloudflare-native/endpoint.md section 12, the staging soak's criteria): one per ranking check of an isolate, one
 * per circuit trip at an endpoint root. In the request points' dataset, as the retry points are (sinks.ts `retryPoint`):
 * index and blob 1 name the series. No workspace and no key; a route only where the criterion counts per route.
 */

/**
 * A ranking check's point (criteria (c), (d)): blob 2 `full`, `delta` or `none` (the check asked and got no ranking: a
 * replica with no copy yet, or a collector still sweeping), blob 3 the isolate (the wide event's `service_instance`), blob 4
 * the replica that answered (`region/index`; "" unknown): a check another replica answered is a fallback, and a replica
 * that restarted answers each of its readers one full answer of the epoch they hold (criterion (d2)).
 * Doubles: 1 the count (1), 2 the answer's keys, 3 its samples, 4 its data bytes (@gray/routing `feedAnswerBytes`), 5 the
 * base's keys and 6 its samples after the check, 7 the base's age after it (ms; -1: no usable base), 8 the answer's
 * failure-log entries, 9 the base's after the check (criterion (c): each takes memory beside the samples), 10 whether a
 * full answer was of the epoch the isolate already held (1: a replica's restart, a fallback, or a reader behind the
 * replica's removal log; 0: the first, a new collector epoch, or a delta), 11 the samples of the keys it carried whole (a
 * new run of a key's samples, sent again in full; all of a full answer's): the rest of a delta's samples are new to the
 * isolate (criterion (d1)).
 */
export function rankingCheckPoint(
  answer: FeedAnswer | undefined,
  base: { readonly keys: number; readonly samples: number; readonly failures: number; readonly ageMs: number | null },
  instance: string,
  from: { readonly source: string; readonly sameEpoch: boolean } = { source: "", sameEpoch: false },
): AnalyticsEngineDataPoint {
  let samples = 0;
  let failures = 0;
  let whole = 0;
  for (const k of answer?.keys ?? []) {
    const count = feedColumnsCount(k.samples);
    samples += count;
    if (k.whole) whole += count;
    failures += k.failures?.length ?? 0;
  }
  const kind = answer === undefined ? "none" : answer.full ? "full" : "delta";
  return {
    indexes: ["ranking_check"],
    blobs: ["ranking_check", kind, instance, from.source],
    doubles: [1, answer?.keys.length ?? 0, samples, answer === undefined ? 0 : feedAnswerBytes(answer), base.keys, base.samples, base.ageMs ?? -1, failures, base.failures, answer?.full === true && from.sameEpoch ? 1 : 0, whole],
  };
}

/** A circuit's trip at its root (criterion (e)): blob 2 the rank key, blob 3 the route (the root's endpoint); doubles 1 the count (1), 2 the cooldown (ms). */
export function circuitTripPoint(key: string, endpoint: string, cooldownMs: number): AnalyticsEngineDataPoint {
  return { indexes: ["circuit_trip"], blobs: ["circuit_trip", key, endpoint], doubles: [1, cooldownMs] };
}
