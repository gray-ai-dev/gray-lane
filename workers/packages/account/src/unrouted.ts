// A leaf module: the lane bundle reads the reason through the package's top-level entry without
// loading shard.ts.

/**
 * The release reason of a hold whose request the gateway refused before it asked any upstream, because every route
 * was in recovery (its breaker open or cooling down, or resting after a failure): the server refuses such a request
 * at admission, before it holds anything (inference.rs `admit`, `recovery_refusal`), and the gateway learns it only
 * from the endpoint shards, after this hold was asked for beside the head's permit. So the hold is not the request's
 * decision, and a later admission of the same request key (the client's repeat under its Idempotency-Key, or the next
 * model the customer listed) is admitted afresh, as after a superseded hold. The gateway releases a hold so only when
 * no attempt of the request was sent (apis/failure.ts and inference.ts `unrouted`).
 */
export const UNROUTED = "unrouted";
