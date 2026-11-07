import type { TimeoutTimers } from "@gray/account";
import type { StreamTimers } from "./client.ts";

/**
 * The gateway isolate's clock: the time the request path reads (`GatewayDeps.clock`), the timers of a request's
 * early headers and of a repeat's wait (`GatewayDeps.requestTimers`), and the time the endpoint objects run on
 * (objects/endpoint-root.ts, objects/endpoint-shard.ts: rests, circuits, leases). The machine's (`Date.now`, the
 * platform's timers) unless a test holds another in the isolate (`holdGatewayClock`), as the server's scenario tests
 * hold tokio's clock and make its ranker follow it (`Ranker::follow_tokio_clock_for_test`; the conformance area
 * `scenario-rests`, run through workers/e2e). A seam: no production code holds it.
 */
export interface HeldGatewayClock {
  now(): number;
  readonly timers: StreamTimers;
}

let held: HeldGatewayClock | null = null;

/** Unix milliseconds on the isolate's clock: the held one, else the machine's. */
export function gatewayNow(): number {
  return held === null ? Date.now() : held.now();
}

/** The held clock's timers; undefined while none is held (the request path then takes the platform's). */
export function heldTimers(): StreamTimers | undefined {
  return held?.timers;
}

/** From now on the isolate's clock is `clock`; null gives the machine's back. */
export function holdGatewayClock(clock: HeldGatewayClock | null): void {
  held = clock;
}

/**
 * The account shards' clock (objects/account-shard.ts): the machine's unless a test holds another (`holdAccountClock`).
 * A key's requests per minute count by the UTC minute of this clock (@gray/account `rpmWindowStart`), so a test that
 * counts a key's requests within one minute holds it still: the minute never turns between them, however long the
 * machine takes. Held near the machine's time (within the shard's 60 s clock skew of a request's `requestAt`). A seam:
 * no production code holds it.
 */
let heldAccountNow: (() => number) | null = null;

/** Unix milliseconds on the account shards' clock: the held one, else the machine's. */
export function accountNow(): number {
  return heldAccountNow === null ? Date.now() : heldAccountNow();
}

/** From now on the account shards' clock is `clock`; null gives the machine's back. */
export function holdAccountClock(clock: (() => number) | null): void {
  heldAccountNow = clock;
}

/**
 * The timers of the account shards' calls to their root and their peers (ACCOUNT_ROOT_CALL_TIMEOUT_MS, @gray/account
 * `withTimeout`), and of a shard's wait for the gateway's admit or count (its `waitMs`): the platform's unless a test
 * holds others (`holdAccountCallTimers`). In the workerd tests every Durable
 * Object of the run shares the test's thread, so a burst of work (a hundred streams sealed at once) can keep a root's
 * answer past its 1 s on a busy box, and the shard would refuse `unavailable`: a test that is not about that timeout
 * holds these timers (ones that never fire), so slowness is not a refusal. A seam: no production code holds it.
 */
let heldAccount: TimeoutTimers | null = null;

const platformTimeouts: TimeoutTimers = {
  setTimeout: (handler, ms) => setTimeout(handler, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** What the account shards' calls time out on: each timer is cleared by the timers that set it. */
export const accountCallTimers: TimeoutTimers = {
  setTimeout: (handler, ms) => {
    const timers = heldAccount ?? platformTimeouts;
    return { timers, handle: timers.setTimeout(handler, ms) };
  },
  clearTimeout: (set) => {
    const { timers, handle } = set as { readonly timers: TimeoutTimers; readonly handle: unknown };
    timers.clearTimeout(handle);
  },
};

/** From now on the account shards' call timeouts run on `timers`; null gives the platform's back. */
export function holdAccountCallTimers(timers: TimeoutTimers | null): void {
  heldAccount = timers;
}
