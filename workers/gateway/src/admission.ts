import { admitWithRetry, rpmWindowStart, shardName, type AdmitAttempt, type AdmitInput, type AdmitResult, type ClientKeyFallback, type HoldToken, type ShardCountTable, type ShardLocator } from "@gray/account";
import type { StreamTimers } from "./client.ts";
import type { LocationHint } from "@gray/config";
import { LRUCache } from "lru-cache";

/**
 * Admission on the account shards (docs/cloudflare-native.md 2.4 step 3, @gray/account
 * `admitWithRetry`), with every answer the gateway stopped waiting for watched.
 *
 * An admit that misses its attempt's wait is retried as the next attempt, on the shard of that
 * attempt number. The missed call can still hold: the shard counts the wait from the call's arrival,
 * so a call slow on its way, or an answer lost on its way back, leaves a hold the gateway never
 * uses. On one shard the next attempt deals with it (a later attempt supersedes an earlier hold; an
 * earlier attempt arriving late is a duplicate). On another shard nothing would: the hold would sit
 * there until its token expired (the stream total plus the margin, about an hour), holding the
 * workspace's money. The gateway hears a late answer, so it releases such a hold at once, as it
 * hands back an endpoint permit that came too late (endpoints.ts). The reason is the shard's own for
 * a hold a later attempt replaced, `superseded_by_attempt`, which is not the request's decision: the
 * attempt that serves it settles or releases it.
 *
 * The server answers a refusal after an attempt of unknown outcome with 503 so the client asks again
 * (credit_path.rs `a_refusal_after_an_attempt_of_unknown_outcome_asks_the_client_again`): there a
 * refusal is not stored, and the first attempt could still hold. Here such a hold is released when
 * its answer arrives, so the refusal stands as the account's answer.
 *
 * Releasing such a hold gives back its money. Its admission also took a unit of the key's minute
 * (`AdmitInput.countsRate`): the request's one count, as the server's preflight makes one, unless
 * another admitted hold of the request took one too. Exactly one unit of a request stays (`RateUnit`):
 * the one of the hold the gateway uses, or else of the first late one whose answer came in; the
 * release of any other hold tells its shard to give its unit back (`ReleaseInput.countedElsewhere`).
 * A later attempt on the same shard takes the earlier attempt's unit over by itself (@gray/account
 * shard.ts `Inherited`), so when the gateway can tell that it did (`linked`), the two hold one unit
 * between them and neither gives it back. So a late-admitted attempt superseded by another admitted
 * attempt counts once (r31, the product lead's item 2 of part A), also when both answered late from
 * one shard. And the request's end must not count it again
 * (inference.ts and apis.ts `closeRate`): `mayHaveCounted` says whether an attempt the gateway
 * stopped waiting for admitted after all, or has not answered yet (it still may; the shard counts
 * its wait from the call's arrival).
 */
/**
 * The admitted holds of one admission, by the place of their calls in it (`admitOnce`): whether the holds of the calls
 * `a` and `b` hold one unit of the key's minute between them (`linked` holds every call from one to the other).
 */
interface AdmissionChains {
  sameChain(a: number, b: number): boolean;
}

/**
 * Whether the admitted hold `after`, of the call right after the one of the admitted hold `before` in one admission,
 * took over `before`'s unit of the key's minute at their shard, so that the two hold one unit between them (on
 * `after`). It did when both are of one shard, one epoch of it (a restart forgets open holds) and one request key, and
 * were issued in one UTC minute of its clock: the attempts of an admission go one after another and none of its holds
 * is released before it ends (`admitOnce` releases the late ones after), so `before` was open there when `after`'s
 * admission looked, and `after` superseded it and took its unit over (@gray/account shard.ts `tryAdmit`, `Inherited`;
 * had `before` been issued after `after`, it would have been refused as a duplicate). With any other call between
 * them, or one not answered yet, the gateway cannot tell: one that superseded `before` and was then refused leaves
 * `before`'s unit counted at the shard with no hold to give it back, and `after` counted its own. Across admissions
 * of a request (a refit, the next model under the same key) holds are never linked: a late hold of the earlier one
 * may be released before the later one's attempt reaches its shard, which then counts again.
 */
function linked(before: HoldToken, after: HoldToken): boolean {
  return (
    shardName(before.shard) === shardName(after.shard) &&
    before.epoch === after.epoch &&
    before.requestKey === after.requestKey &&
    rpmWindowStart(before.issuedAt) === rpmWindowStart(after.issuedAt)
  );
}

/**
 * Which admitted holds of one request keep the request's unit of its key's minute (one per request, all its
 * admissions: a refit and the models the customer listed next share it). Admissions that count (`countsRate`) give
 * each admitted hold to `take`: the first one keeps the unit, with the holds of its admission linked to it
 * (`linked`), and every other hold is told to give its own back on release. A request whose unit a hold took is
 * counted: its later admissions do not count (`taken`).
 */
export class RateUnit {
  #holder: { readonly chains: AdmissionChains; readonly call: number } | null = null;

  /** Whether an admitted hold of the request keeps its unit: the request is counted, and a later admission counts nothing. */
  get taken(): boolean {
    return this.#holder !== null;
  }

  /**
   * The admitted hold of the call `call` of an admission (`chains`, one per admission) counted the request: whether
   * it keeps the unit (false: a hold not linked to it has the unit, so this hold's shard gives this hold's own back).
   */
  take(chains: AdmissionChains, call: number): boolean {
    this.#holder ??= { chains, call };
    return this.#holder.chains === chains && chains.sameChain(this.#holder.call, call);
  }
}

export interface WatchedAdmission extends AdmitAttempt {
  /**
   * Whether an attempt of this admission that counts against the key's minute may have counted the request: one
   * that admitted it (also one whose answer came after the gateway moved on, its hold released), or one that has not
   * answered yet. False when every such attempt was refused, or failed as a call. Asked at the request's end.
   */
  readonly mayHaveCounted: () => boolean;
}

export async function admitOnce(o: {
  readonly locate: ShardLocator;
  readonly counts: ShardCountTable;
  readonly workspace: string;
  readonly region: LocationHint;
  /** The workspace's home region (AdmitInput.home). */
  readonly home: LocationHint;
  /** ACCOUNT_CLIENT_KEY_FALLBACK. */
  readonly clientKeyFallback: ClientKeyFallback;
  /** The gateway's id for this request (AdmitInput.flow), the same across a refit's admissions. */
  readonly flow: string;
  readonly request: Omit<AdmitInput, "shard" | "attempt" | "waitMs" | "home" | "flow">;
  readonly timing: { readonly attemptMs: number; readonly budgetMs: number; readonly clock?: () => number; readonly timers?: StreamTimers };
  /** The first attempt number: past every attempt an earlier admission of the same request used. */
  readonly firstAttempt?: number;
  /** Keeps background work alive past the response (the request's `ctx.waitUntil`). */
  readonly background: (work: Promise<unknown>) => void;
  /**
   * Releases a hold the request does not use (`superseded_by_attempt`). `countedElsewhere`: another admitted hold of
   * the request keeps its unit of the key's minute, so this hold's shard gives this hold's back (ReleaseInput).
   */
  readonly release: (token: HoldToken, detail: { readonly attempt: number }, countedElsewhere: boolean) => Promise<unknown>;
  /** The request's unit of its key's minute, shared by all its admissions; a fresh one when the request is admitted once. */
  readonly unit?: RateUnit;
}): Promise<WatchedAdmission> {
  const calls: { readonly attempt: number; readonly answer: Promise<AdmitResult>; readonly counts: boolean; answered: "no" | "admitted" | "refused" | "failed"; token: HoldToken | null }[] = [];
  const watched: ShardLocator = (address) => {
    const shard = o.locate(address);
    return {
      admit: (input) => {
        const answer = shard.admit(input);
        const call = { attempt: input.attempt, answer, counts: input.countsRate !== false, answered: "no" as "no" | "admitted" | "refused" | "failed", token: null as HoldToken | null };
        answer.then(
          (result) => {
            call.answered = result.ok ? "admitted" : "refused";
            if (result.ok) call.token = result.token;
          },
          () => {
            call.answered = "failed";
          },
        );
        calls.push(call);
        return answer;
      },
      count: (input) => shard.count(input),
      settle: (input) => shard.settle(input),
      release: (input) => shard.release(input),
    };
  };
  const admitted = await admitWithRetry({ locate: watched, counts: o.counts, workspace: o.workspace, region: o.region, home: o.home, clientKeyFallback: o.clientKeyFallback, flow: o.flow, request: o.request, timing: o.timing, firstAttempt: o.firstAttempt });
  const kept = admitted.result.ok ? admitted.result.token.sig : null;
  const unit = o.unit ?? new RateUnit();
  // Linked as far as the answers in so far tell (an answer's own call has its token before the loop below looks).
  const chains: AdmissionChains = {
    sameChain: (a, b) => {
      for (let n = Math.min(a, b) + 1; n <= Math.max(a, b); n++) {
        const before = calls[n - 1]!.token;
        const after = calls[n]!.token;
        if (before === null || after === null || !linked(before, after)) return false;
      }
      return true;
    },
  };
  // The hold the request uses keeps its unit, before any late answer is looked at (they are, below, only after this).
  const keptCall = calls.findIndex((call) => call.token !== null && call.token.sig === kept);
  if (keptCall >= 0 && o.request.countsRate !== false) unit.take(chains, keptCall);
  calls.forEach((call, n) => {
    o.background(
      call.answer.then(
        (answer) => (answer.ok && answer.token.sig !== kept ? o.release(answer.token, { attempt: call.attempt }, call.counts && !unit.take(chains, n)) : undefined),
        () => undefined,
      ),
    );
  });
  return { ...admitted, mayHaveCounted: () => calls.some((call) => call.counts && (call.answered === "no" || call.answered === "admitted")) };
}

/** The `alert_key` of the degraded admissions of one home shard: one key while it is sick, in every isolate. */
export function degradedAlertKey(home: string): string {
  return `admission_degraded:${home}`;
}

/**
 * Which line a degraded admission says, per isolate (docs/cloudflare-native/jobs.md 1.4). A request
 * under a client's Idempotency-Key whose home shard failed is admitted in its own region
 * (ACCOUNT_CLIENT_KEY_FALLBACK local): recorded and alerted, the owner's rule of 2026-10-18. Alerting
 * each such request would page once a request while one shard is sick (2,000 a second for one
 * workspace), so the alert is grouped: every line carries `alert_key` = the home shard that failed, the
 * same in every isolate. No isolate can say for all of them that the shard is well again (each sees
 * only its own requests, and an isolate that alerted may be gone), so gray-alerts closes the key once
 * ALERT_GROUP_MS passes without an alert line of it (workers/alerts src/catalog.ts: the cause has no
 * `resolvedBy`). An isolate therefore says `level: alert` for its first degraded admission of a home
 * shard and again for the first one at least half of ALERT_GROUP_MS after its last alert of it, and
 * `warn` for the others (each request is still recorded, also in its wide event and Analytics Engine
 * point): while the shard stays sick and requests keep coming, the router hears the key at least twice
 * per ALERT_GROUP_MS, so it stays one open incident instead of closing and paging again. When that
 * shard admits a client's key again, the isolate says `admission_degraded_resolved` (info, for Workers
 * Logs; it closes nothing) and starts over, so a relapse is alerted at once.
 */
export class DegradedAdmissions {
  /**
   * Per home shard (its name): when this isolate last said its alert line. At most `max` home shards
   * (ISOLATE_TABLE_ENTRIES), the least recently used going first (tables.ts): one that falls out alerts
   * again at its next degraded admission, under the same alert key (the router's open incident, no new
   * page), and its resolved line is not said by this isolate.
   */
  private readonly alerted: LRUCache<string, number>;

  constructor(max: number) {
    this.alerted = new LRUCache<string, number>({ max });
  }

  /** Home shards kept now (tests). */
  get size(): number {
    return this.alerted.size;
  }

  /** The most home shards kept (tests, the leak harness). */
  get max(): number {
    return this.alerted.max;
  }

  /** A request admitted degraded away from `home` at `now`: the level of its line and the line's key. */
  degraded(home: string, now: number, groupMs: number): { readonly level: "alert" | "warn"; readonly alertKey: string } {
    const last = this.alerted.get(home);
    const alert = last === undefined || now - last >= groupMs / 2;
    if (alert) this.alerted.set(home, now);
    return { level: alert ? "alert" : "warn", alertKey: degradedAlertKey(home) };
  }

  /** `home` answered a client's key itself: the key to say resolved when this isolate had alerted it, once; otherwise null. */
  answered(home: string): string | null {
    if (!this.alerted.has(home)) return null;
    this.alerted.delete(home);
    return degradedAlertKey(home);
  }
}
