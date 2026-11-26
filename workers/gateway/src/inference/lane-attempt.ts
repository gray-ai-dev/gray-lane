/**
 * A confidential-lane relay's part of an attempt (`InferenceRun`, inference.ts): the route kinds it is sent to, its
 * account pool and pick, the reports to the relay's scheduler, the affinity, conversation and headers it is sent with,
 * and the relay policy's step, appends and outcome.
 */
import { ApiError } from "@gray/errors";
import { type AppendedText, type LaneProtocol, checkOfficialUpstream } from "@gray/lane";
import type { Protocol } from "@gray/protocol";
import { CONVERSATION_DOMAIN, deriveAffinity } from "../lane/affinity.ts";
import { laneDuplicateKey, laneHeaders, lanePolicyRefused, laneUpstreamOf, policyStep, receiptDraft } from "../lane/hooks.ts";
import { codexBackend, storeOffBackend } from "../lane/plan.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import type { LaneAttempt, LaneDeps, LanePolicyOutcome } from "../lane/types.ts";
import type { Route } from "../routes.ts";
import type { RouteRecord } from "../snapshot.ts";
import { laneVendor, relayOf } from "./attempt-pure.ts";
import { laneFailureCode } from "./errors.ts";
import { type StackRoutesRun, stackRoute } from "./stack-routes.ts";
import type { Attempt, Dispatch, LanePick, LanePolicyAnswer, LanePolicyStep, Prepared } from "./types.ts";
import { type RequestBodyRun, upstreamPromptUnits } from "./request-body.ts";

/** What lane-attempt.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface LaneAttemptRun extends RequestBodyRun, StackRoutesRun {}

/** A lane route whose upstream is ChatGPT's Codex backend (D129, `plan.ts` `codexBackend`). */
export function laneCodexRoute(run: LaneAttemptRun, route: RouteRecord): boolean {
  return run.lane !== null && route.auth === "lane_relay" && codexBackend(route.url);
}

/** Whether a sealed-credential lane relay route requires `store: false` on OpenAI/ChatGPT backends. */
export function laneStoreOffRoute(run: LaneAttemptRun, route: RouteRecord): boolean {
  return run.lane !== null && route.auth === "lane_relay" && !stackRoute(run, route) && storeOffBackend(route.url);
}

/**
 * D129: a lane attempt whose upstream streams while its customer asked for a buffered answer: a
 * Responses request on a Codex route, sent with `stream: true` (`planOps`), whose answer is read to
 * its terminal event and answered as the Responses object (`codexAnswer`).
 */
export function laneCodexBuffered(run: LaneAttemptRun, attempt: Attempt): boolean {
  return attempt.lane !== undefined && !run.facts.stream && run.facts.translation === null && run.protocol === "open_ai_responses" && laneCodexRoute(run, attempt.route.record);
}

/**
 * F2 D124': the account pool a lane route's attempt picks from, named by what `laneAttempt` asks its
 * relay's scheduler (the relay, the vendor its URL names, the route's upstream model): two routes of
 * one relay with these alike ask the same pool (D112's two routes on one (model, protocol) may not:
 * api.openai.com and chatgpt.com are different vendors). Null outside the lane and for a route
 * `laneAttempt` would never open an attempt on.
 */
export function laneAccountPool(run: LaneAttemptRun, route: Route): string | null {
  // A stack relay's container picks its accounts itself (S23): Gray asks no pool.
  if (run.lane === null || stackRoute(run, route.record)) return null;
  const relayId = relayOf(route);
  const official = checkOfficialUpstream(route.record.url);
  if (relayId === null || !official.ok) return null;
  return JSON.stringify([relayId, laneVendor(official.vendor), route.record.upstreamModel]);
}

/**
 * What a lane relay gives one attempt (design v2 §C.6, B2, M1): the account its scheduler picks,
 * the auth headers its credential store builds for that account, and the two merged with the
 * protocol's own client headers. `false` when there is no account to try (the scheduler answered a
 * wait or unavailable, or the store refused the account), which the caller passes the route over
 * for; `null` never returns here.
 *
 * The scheduler's vendor and model are the vendor the route's URL names and the route's upstream
 * model: the relay must know which of its accounts can serve the vendor's model, and it is the
 * relay's own pool. The policy module, which must not learn the mapping, is called with the
 * customer's model instead (`lanePolicyStep`). `previous` carries the accounts this request already
 * tried at this relay, by their relay-side outcome word, and never a credential nor another relay's
 * account (F2 D124'', D16).
 *
 * F2 D111(a),(d): every account a pick returns is reported even when no attempt can be opened. A
 * credential-store refusal reports that account as not sent (`reportLaneNotSent`, D120 F3) so the
 * relay frees its lease, and the failure's own code travels back to `openAttempt` for the request's
 * skipped-route cause. A pick error has no account; the scheduler client has already queued the
 * `request_ref` release the relay needs (D111(b)). D116(a): the attempt keeps the `request_ref` its
 * pick was signed with, and every report about it names that lease. D116(d): every way out after a
 * pick flushes, so a release queued by this or an earlier request is sent now, not left to a timer.
 */
export async function laneAttempt(run: LaneAttemptRun, route: Route, o: Dispatch, prepared: Prepared, index: number): Promise<LanePick> {
  const lane = run.lane;
  const relayId = relayOf(route);
  const official = checkOfficialUpstream(route.record.url);
  if (lane === null) return { ok: false, code: "lane_unavailable" };
  if (relayId === null) return { ok: false, code: "lane_relay_missing" };
  if (!official.ok) return { ok: false, code: "lane_upstream_not_official" };
  const vendor = laneVendor(official.vendor);
  const units = upstreamPromptUnits(run, o.parsed, o.canonical);
  const affinity = laneAffinityFor(run, relayId);
  let picked: Awaited<ReturnType<ReturnType<LaneDeps["schedulers"]>["pickFor"]>> | null = null;
  try {
    for (let tries = 0; tries < 2; tries++) {
      picked = await lane.schedulers(relayId).pickFor({
        vendor,
        model: route.record.upstreamModel,
        inputTokens: units?.bodyBound() ?? 0n,
        // The mode the vendor is asked in: a Codex route's Responses request always streams (D129).
        stream: run.facts.stream === true || (vendor === "chatgpt_codex" && prepared.protocol === "open_ai_responses"),
        attempt: BigInt(index),
        previous: run.laneRelays.lanePrevious.get(relayId) ?? [],
        ...(affinity === undefined ? {} : { affinity }),
      });
      if (picked.kind !== "retry_after" || tries === 1) break;
      // The scheduler offered no account yet but said when: wait that long (bounded, the request's
      // own time is the outer bound) and ask once more, which is how a pool that is refilling is
      // used instead of passed over (design v2 §C.6).
      const waitMs = Math.min(Number(picked.retry_after_ms), 250);
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    }
  } catch (error) {
    // F2 D27: lane v1 has no lease-table fallback. A scheduler timeout or any other scheduler error
    // passes the route over — never a retry at its own relay with no account — so every pick is the
    // relay's own decision (it alone sees its live concurrency), with one transport and one deadline.
    // F2 D131: a lost pick whose pass would end the request with nothing sent gets one more pick,
    // the relay's own again (`coldRepeat`).
    // D111(b): the client queued a `request_ref` release for a pick whose answer was lost; flush it
    // now so the relay frees the lease even when this was the request's last attempt.
    flushLaneReports(run, relayId);
    return { ok: false, code: laneFailureCode(error) };
  }
  if (picked === null || picked.kind !== "account") {
    // D116(d): no account (a wait that did not clear, or unavailable). A relay whose slots are held
    // by lost picks answers exactly this, so the releases queued for it must go out here too.
    flushLaneReports(run, relayId);
    return { ok: false, code: "lane_no_account" };
  }
  let auth: { readonly headers: Readonly<Record<string, string>>; readonly egress?: LaneAttempt["egress"] };
  try {
    auth = lane.credentials.upstreamAuth(picked.account_id, run.deps.clock(), relayId);
  } catch (error) {
    // The account expired, or the store no longer holds it: the relay's own pool moved, and the
    // next attempt picks again (a later route or the same one after the dispatcher's wait). The
    // pick was made, so report it as not sent before passing the route over (D111(a)).
    reportLaneNotSent(run, relayId, picked.account_id, picked.request_ref);
    return { ok: false, code: laneFailureCode(error) };
  }
  return {
    ok: true,
    attempt: {
      relayId,
      accountId: picked.account_id,
      requestRef: picked.request_ref,
      headers: laneHeadersFor(run, prepared.protocol, auth.headers),
      ...(auth.egress === undefined ? {} : { egress: auth.egress }),
    },
  };
}

/**
 * The release-only report for a pick no vendor saw (D111(a)): a credential-store refusal right
 * after the pick, or an attempt that ended before its body was taken (`laneAttemptEnded`). D120 F3:
 * the report is `{account_id, request_ref, outcome: "not_sent"}`, the release shape with the
 * account the pick named, so the relay frees exactly that pick's lease (D116(a)) and no scheduler
 * can read it as vendor work; it carries no usage or latency. Metadata only; never fails the
 * request (D31). An account the store dropped after the pick is released by its ref alone
 * (`reportLanePick`, D120 F2).
 */
export function reportLaneNotSent(run: LaneAttemptRun, relayId: string, accountId: string, requestRef: string): void {
  const lane = run.lane;
  if (lane === null) return;
  reportLanePick(run, lane, relayId, { account_id: accountId, request_ref: requestRef, outcome: "not_sent" });
}

/**
 * One report about a pick's account, then the client's own flush, in the background: every account
 * report the request makes goes through here (the sent attempt's outcome, the committed attempt's
 * at the request's end, and the not-sent release). Metadata only; never fails the request (D31),
 * and the lookup is inside the catch too: a relay that left the registry while the attempt was in
 * flight has no client and nothing to report (GW-03, GW-04).
 *
 * D120 F2, D122 f: the client refuses an account report for an account its store no longer holds
 * (`scheduler_unknown_account`). A sealed bundle applied, or an account removed, between the pick
 * and the report leaves exactly that, for an attempt a vendor saw as for one it did not, and the
 * refused report would leave the pick's lease to the relay's TTL. The ref alone frees the same
 * lease, so the report falls back to the accountless release `{request_ref, outcome: "not_sent"}`,
 * which the client queues without a membership check. The dropped account's outcome is lost: the
 * relay frees the slot and learns nothing about that account (accepted; the store no longer holds
 * it, so no later pick can name it either).
 */
export function reportLanePick(run: LaneAttemptRun, lane: LaneDeps, relayId: string, report: Readonly<Record<string, unknown>> & { readonly request_ref: string }): void {
  run.ctx.waitUntil(
    (async () => {
      try {
        const scheduler = lane.schedulers(relayId);
        try {
          scheduler.report([report]);
        } catch (error) {
          if (laneFailureCode(error) !== "scheduler_unknown_account") throw error;
          scheduler.report([{ request_ref: report.request_ref, outcome: "not_sent" }]);
        }
        await scheduler.flushReports();
      } catch {
        // A relay that did not take a report is not the customer's problem; the next flush retries.
      }
    })(),
  );
}

/** Flush a relay scheduler's queued metadata (a lost pick's release) in the background; never throws. */
export function flushLaneReports(run: LaneAttemptRun, relayId: string): void {
  const lane = run.lane;
  if (lane === null) return;
  try {
    const scheduler = lane.schedulers(relayId);
    run.ctx.waitUntil(Promise.resolve(scheduler.flushReports()).catch(() => undefined));
  } catch {
    // The client or the registry is gone: there is nothing to flush.
  }
}

/**
 * The request's conversation token at one relay (E3), or undefined when the client sent no session
 * id or the workspace is unknown. It is computed once per relay and then reused on every attempt,
 * so a retry carries exactly the same value. `K_boot` is the boot's affinity key (`LaneState`); the
 * token names no content, no key and no customer identity.
 */
export function laneAffinityFor(run: LaneAttemptRun, relayId: string): string | undefined {
  return laneTokenFor(run, run.laneRelays.laneAffinities, relayId, undefined);
}

/**
 * The request's conversation id at one relay (relay standard v1.7 `X-Gray-Conversation`, docs/relay-standard-v1.7.md
 * section 3): the affinity token's inputs under `CONVERSATION_DOMAIN`, so the container's value is never the lane's
 * affinity token. Undefined without a session id, computed once per relay.
 */
export function laneConversationFor(run: LaneAttemptRun, relayId: string): string | undefined {
  return laneTokenFor(run, run.laneRelays.laneConversations, relayId, CONVERSATION_DOMAIN);
}

export function laneTokenFor(run: LaneAttemptRun, cache: Map<string, string>, relayId: string, domain: string | undefined): string | undefined {
  const lane = run.lane;
  const sessionId = run.client.sessionId ?? run.zdr.laneZdrAffinityId;
  const workspaceId = run.caller.key?.workspaceId;
  if (lane === null || sessionId === null || workspaceId === undefined) return undefined;
  const cached = cache.get(relayId);
  if (cached !== undefined) return cached;
  const token = deriveAffinity(lane.state.affinityKey, relayId, workspaceId, sessionId, domain);
  cache.set(relayId, token);
  return token;
}

/** `laneHeaders` as the attempt records them: the account's headers merged with the client's, as a plain map. */
export function laneHeadersFor(run: LaneAttemptRun, protocol: Protocol, account: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  const merged = laneHeaders(protocol, run.request.headers, account);
  const out: Record<string, string> = {};
  merged.forEach((value, name) => (out[name] = value));
  return Object.freeze(out);
}

/**
 * The relay policy step of one attempt (design v2 §C.5, B7, M12, M14): run the relay's module for
 * `(protocol, requested model, received body)`, pad it to the step's budget for that input's size
 * (`policyStepBudgetMs`, F2 D128: at most `LANE_POLICY_STEP_MS`, or the cap the boot raised it to, D130), and answer a
 * `Stopped` when it did not allow the request, or null to go on.
 *
 * The decision is cached per `(relayId, protocol, model)` within the request: the customer's
 * `models` list tries each model and the dispatcher may retry at one relay, and the module may not
 * be asked twice about the same request. The model is `canonical.model` — the one the customer
 * asked for — never the route's `upstreamModel`, or the relay would learn Gray's mapping.
 *
 * A route that is not a lane relay runs no policy (the main lane, or a lane snapshot whose lanes
 * are all relays by construction). A relay with **no accepted policy at all** is passed over (F2
 * D7): not ready is availability, not a refusal — only a module that ran and blocked, or could not
 * run, stops the request with the lane's one 403.
 *
 * `target` is the route the dispatcher is about to try: `chosen.target` for a repeat, and the
 * plan's head for tier A. A different route the ranking picks after the policy allowed is still the
 * same relay, so its decision holds and the cache answers it without a second step.
 */
export async function lanePolicyStep(run: LaneAttemptRun, o: Dispatch, prepared: Prepared, target: Route, answerDeadline: number): Promise<LanePolicyStep> {
  const lane = run.lane;
  if (lane === null) return { kind: "go" };
  const relayId = relayOf(target);
  // S23: a stack relay runs no policy module; what its container may change is egress's to check.
  if (relayId === null || stackRoute(run, target.record)) return { kind: "go" };
  const protocol = prepared.protocol;
  if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") {
    return { kind: "stop", stop: null, error: new ApiError(400, "invalid_protocol_request") };
  }
  const received = run.laneRelays.laneReceived;
  if (received === null) return { kind: "stop", stop: null, error: laneDuplicateKey() };
  // F2 D7: a relay with no accepted policy is **passed over** like an unavailable relay, never
  // answered 403. "Not ready" is an availability state independent of the request's content, and a
  // 403 would tell the customer their request was refused when nothing about it was decided.
  if (lane.policies.get(relayId) === undefined) return { kind: "pass" };
  const key = `${relayId}\u0000${protocol}\u0000${o.canonical.model}`;
  let decision = run.laneRelays.lanePolicy.get(key);
  if (decision === undefined) {
    const running = runLanePolicy(run, lane, relayId, protocol as LaneProtocol, o.canonical.model, received);
    if (running === null) return { kind: "pass" };
    decision = running;
    run.laneRelays.lanePolicy.set(key, decision);
  }
  const answer = await decision;
  if (answer instanceof ApiError) return { kind: "stop", stop: null, error: answer };
  run.laneRelays.lanePolicyOutcomes.set(key, answer.outcome);
  if (!answer.allow) {
    // A refusal forwarded nothing, so no attempt commits and the receipt is this step's own
    // (design v2 §C.8, M6): `request.received`, the refusal and the error body the client gets.
    run.receipt.laneDraft = receiptDraft({ modifiedEvents: [], policy: answer.outcome, forwardedHash: null, accountId: null, upstreamModel: target.record.upstreamModel, upstream: laneUpstreamOf(target.record) });
    run.receipt.winningReceipt = "lane";
    run.receipt.laneReceiptId ??= newLaneReceiptId();
    return { kind: "stop", stop: null, error: lanePolicyRefused() };
  }
  // The step was padded, so the module's own runtime never shows; only the request's own deadline
  // can still be past, and then no attempt goes (the main lane's `deadline` stop, unchanged).
  if (run.deps.clock() >= answerDeadline) return { kind: "stop", stop: "deadline" };
  return { kind: "go" };
}

/**
 * One relay's policy decision, padded (`policyStep`). Null when the store holds no record for the
 * relay any more: the caller passes the route over (F2 D7). A record whose module cannot run is the
 * host's fixed `policy_unavailable`, and the receipt cites the module's own digest and version, with
 * the failure's reason code.
 */
export function runLanePolicy(run: LaneAttemptRun, lane: LaneDeps, relayId: string, protocol: LaneProtocol, model: string, body: Uint8Array): Promise<LanePolicyAnswer> | null {
  const sleep = run.deps.laneSleep ?? ((ms: number): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const record = lane.policies.get(relayId);
  // The caller checked (`lanePolicyStep`): a relay that lost its policy between the check and here
  // is passed over, never answered 403 (F2 D7).
  if (record === undefined) return null;
  return policyStep(
    {
      timing: lane.timing,
      // F2 D128: the step's budget follows the fuel this run gives the module, a function of the
      // input's length alone.
      fuel: record.fuel({ protocol, model, body }),
      run: () => {
        const answer = record.run({ protocol, model, body });
        if (!answer.ok) return { kind: "unavailable" };
        if (answer.decision === "block") return { kind: "block", reasonCode: answer.reasonCode };
        // The record resolved the template ids for `protocol` (F2 entry-4): the appends carry the
        // position that protocol has, and a template registered for two protocols lands at the right
        // one for the request. A resolution failure is already the fixed policy failure.
        return { kind: "allow", appends: answer.appends };
      },
      sleep,
      clock: run.deps.clock,
    },
    record.moduleSha256,
    record.policyVersion,
  ).then((step) => ({ allow: step.allow, appends: step.appends, outcome: step.outcome }));
}

/** The appends this request's relay policy chose for `relayId`, or none when its decision is not in yet. */
export async function laneAppendsFor(run: LaneAttemptRun, relayId: string, protocol: Protocol, o: Dispatch): Promise<readonly AppendedText[]> {
  const cached = run.laneRelays.lanePolicy.get(`${relayId}\u0000${protocol}\u0000${o.canonical.model}`);
  if (cached === undefined) return [];
  const answer = await cached;
  return answer instanceof ApiError ? [] : answer.appends;
}

/** The policy outcome the relay's decision recorded, for the receipt's `relay_policy.*` event; null when none ran. */
export function laneOutcomeFor(run: LaneAttemptRun, relayId: string, protocol: Protocol, o: Dispatch): LanePolicyOutcome | null {
  const cached = run.laneRelays.lanePolicyOutcomes.get(`${relayId}\u0000${protocol}\u0000${o.canonical.model}`);
  return cached ?? null;
}
