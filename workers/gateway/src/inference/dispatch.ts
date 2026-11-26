/**
 * Dispatch (`InferenceRun`, inference.ts): what every attempt of an admitted request shares, the loops that send
 * attempts until one answers or the request stops, a stream's headers, the cold repeat, and what the client is told when
 * the request stops.
 */
import { UNROUTED } from "@gray/account";
import { storesContinuation } from "@gray/continuation";
import { ApiError, attemptsAllowed, coldRepeatAllowed, retryAfterSeconds } from "@gray/errors";
import { type Json, type JsonObject, isObject, toJsonString } from "@gray/json";
import { generatedIdSeed } from "@gray/ledger-keys";
import { type BodyLayout, type ClientBody, Overlay, type ScrubSpan, attemptOverlay, locateMembers, scrubNative } from "@gray/protocol";
import type { StreamStage } from "@gray/translation";
import { ClientStream, keepAliveFrame } from "../client.ts";
import { Dispatcher, noAttemptError, noRouteRetryAfter } from "../dispatcher.ts";
import type { FragmentUse, StreamInspector } from "../gate.ts";
import { LANE_CODES } from "../lane/hooks.ts";
import { STACK_KEEP_ALIVE } from "../lane/stack.ts";
import type { ParsedRequest } from "../parse.ts";
import type { RequestOutcome } from "../sinks.ts";
import { type BufferedAnswerRun, buffered } from "./answer-buffered.ts";
import { answerLimit, fail, prime, relay } from "./answer.ts";
import { providerRef } from "./attempt-pure.ts";
import { commit, endAttempt, noteFollowed, reject } from "./attempt.ts";
import { type DispatchEnvRun, dispatchEnv, dispatchPlan, releaseUnusedHead, streamTimers } from "./dispatch-env.ts";
import { laneTap, openAttempt } from "./send.ts";
import { peerUncommitted, relayChangeAnswer, stackPassthrough, stackVendorAnswered } from "./stack-peer.ts";
import { entryPeers, stackRoute } from "./stack-routes.ts";
import { abandon, capHeaders, endStream, errorFrameOf, laneRefusalFrame, modelHeader, told } from "./stream.ts";
import type { Answered, Answering, Dispatch, HeadPermit, ModelResult, Prepared, Primed, Stopped } from "./types.ts";
import { releasingHold } from "./hold.ts";
import { laneReceiptHeader } from "./lane-receipt.ts";
import { droppedHeader, record, unserved } from "./record.ts";
import { requestDeadline } from "./request-body.ts";

const encoder = new TextEncoder();

/** What dispatch.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface DispatchRun extends BufferedAnswerRun, DispatchEnvRun {}

export async function dispatchAndRelay(run: DispatchRun, o: Dispatch): Promise<ModelResult> {
  const { cfg, clock } = run.deps;
  const deadline = requestDeadline(run, o.bodyRead);
  const answerDeadline = run.facts.stream ? Math.min(deadline, o.admittedAt + cfg.upstreamHeaderMs) : deadline;
  const prepared = prepare(run, o);
  // The upstream ids' handles in the body every attempt is made from: each attempt sets them for its route.
  run.facts.toolIds?.prepare({ protocol: prepared.protocol, body: prepared.body, layout: prepared.layout, translated: run.facts.translation !== null });
  const answering = answeringOf(run, o, prepared);
  const plan = dispatchPlan(run, o);
  const d = new Dispatcher(plan);
  run.admitting.dispatcher = d;
  run.admitting.modelPasses = 0;
  run.admitting.recoveryOnly = true;
  run.admitting.recoveryEnds.clear();
  run.admitting.rebuildingEnds = null;
  run.admitting.attemptsAllowedCount = attemptsAllowed({ operators: new Set(o.routes.map((r) => r.record.operator)).size, pinned: run.admitting.pinned, otherOperators: plan.otherOperators, clientRetrying: plan.clientRetrying }, plan.retry);
  const head = { permit: o.head };
  if (!run.facts.stream) return bufferedLoop(run, d, o, prepared, answering, deadline, answerDeadline, head);
  const translation = run.facts.translation;
  const stage = translation === null ? null : translation.stage(translation.context(generatedIdSeed(run.requestId), BigInt(Math.floor(clock() / 1000)), answering.model));
  // A forwarded Responses stream gives the client each call's complete arguments where its argument
  // deltas differ from them (the relay's repair); a translation of one gives the client each call
  // from its complete arguments alone, so its fragments are nothing a client reads (`relay_gated`).
  const fragments: FragmentUse = stage !== null ? (stage.streamsCallArguments() ? "forwarded" : "unused") : answering.protocol === "open_ai_responses" ? "repaired" : "forwarded";
  // A stream answers with its headers once an upstream's answer committed (its first frame outside the
  // preamble), or STREAM_HEADERS_MS after the request's first admission if none has; then keep-alives
  // while nothing else is written (`sse_reply`). Until the headers go, a model whose every attempt failed
  // leaves the request to the next model the customer listed.
  const dispatching = primedLoop(run, d, o, prepared, answering, deadline, answerDeadline, head, fragments);
  const headersAt = (run.admitting.firstAdmittedAt ?? o.admittedAt) + cfg.streamHeadersMs;
  const timers = streamTimers(run);
  let timer: unknown = null;
  const headers = new Promise<"headers">((resolve) => (timer = timers.setTimeout(() => resolve("headers"), Math.max(0, headersAt - clock()))));
  let early: Primed | Stopped | "headers";
  if (run.lane === null) {
    early = await Promise.race([dispatching, headers]);
  } else {
    // F2 hooks-4: a lane stream's headers never go before a vendor fetch takes the body (the receipt
    // id is allocated there), so a policy that blocks the first relay always answers the fixed 403
    // before the headers can. Re-check `laneSentOpen` after `headers` fires so a pre-connect egress
    // 502 rollback re-gates early headers until a subsequent attempt genuinely forwards a body.
    for (;;) {
      const decided = await Promise.race([dispatching, run.laneSent.then(() => "sent" as const)]);
      if (decided !== "sent") {
        early = decided;
        break;
      }
      const raced = await Promise.race([dispatching, headers]);
      if (raced !== "headers") {
        early = raced;
        break;
      }
      if (!run.receipt.laneSentOpen) continue;
      early = "headers";
      break;
    }
  }
  timers.clearTimeout(timer);
  if (early !== "headers" && early.kind === "stopped") return await stoppedResult(run, d, early);
  const hasStackPeerCandidate = entryPeers(run) !== null && o.routes.some((r) => stackRoute(run, r.record));
  return { kind: "response", response: await openStream(run, d, answering, early, dispatching, headersAt, deadline, stage, fragments, hasStackPeerCandidate) };
}

/**
 * The stream's response, and its relay in the background. The headers go now, unless the answer
 * committed after a refusal held for it: they wait for its first bytes (or STREAM_HEADERS_MS after the
 * first admission), so that an attempt that fails before then still answers with that refusal, as a
 * call straight to the refusing route would have (`fail_request`; main 14ab29bd).
 */
export async function openStream(run: DispatchRun, d: Dispatcher, answering: Answering, early: Primed | "headers", dispatching: Promise<Primed | Stopped>, headersAt: number, deadline: number, stage: StreamStage | null, fragments: FragmentUse, hasStackPeerCandidate: boolean): Promise<Response> {
  const { cfg, clock } = run.deps;
  const client = new ClientStream(run.presence, clock, cfg.streamClientStallMs, run.deps.meter?.clientQueued, laneTap(run), run.deps.timers);
  const translation = run.facts.translation;
  const answerLimit = answering.answerLimit;
  // The stream's inspector, from the request as the gate keeps it after admission; a translated
  // stream is always gated (`relay`: `translation.is_some() || requires_buffered_stream`). A gate
  // that fails here is Gray's own failure after the headers: the stream ends with its error event.
  let inspector: StreamInspector | null = null;
  let gateFailure: { readonly error: unknown } | null = null;
  try {
    inspector = run.deps.gate.stream(answering.contract, answerLimit, translation !== null, fragments);
  } catch (error) {
    gateFailure = { error };
  }
  run.answer.gated = (inspector?.holdsToolCalls ?? false) || translation !== null;
  const waitForBytes = early !== "headers" && d.held !== null;
  let told: (response: Response) => void = () => {};
  const refusedFirst = new Promise<Response>((resolve) => (told = resolve));
  if (waitForBytes) run.answer.preHeaders = { told };
  // The relay keeps `answering`, not the request's parse or body (`releaseRequestBody`).
  const relayed = (async () => {
    const sent = early === "headers" ? await dispatching : early;
    if (sent.kind === "stopped") {
      // No upstream's answer committed after the early headers: the protocol's error event ends the
      // stream. A relay policy refusal that arrives only now (a later relay, after the first one's
      // body went) still ends it with exactly the fixed 403 body, never a generic upstream error
      // (F2 hooks-4, the residual path); its receipt is finalised under the id the headers named.
      const failed = await stoppedResult(run, d, sent);
      const frame = run.lane !== null && failed.code === LANE_CODES.policyRefused ? laneRefusalFrame(run) : errorFrameOf(run, stage, failed.code);
      endStream(run, client, frame);
      // A client gone before its error event is a client that left (capture.rs: `Ending::ClientGone`), as below.
      record(run, 200, run.presence.gone ? "cancelled" : failed.outcome, failed.code);
      return;
    }
    if (gateFailure !== null) {
      sent.stream.upstream.cancel();
      throw gateFailure.error;
    }
    await relay(run, answering, sent.attempt, sent.response, sent.stream, client, deadline, inspector!, stage, answerLimit);
  })();
  // A failure of Gray's own while relaying (a bug) still ends the request: free, the upstream and
  // the permit let go, the client told, the record written.
  run.answer.relayed = relayed.catch((error: unknown) => {
    abandon(run, error, "relay_failed");
    endStream(run, client, errorFrameOf(run, stage, "internal_error"));
    record(run, 200, "failed", "internal_error");
  });
  run.ctx.waitUntil(run.answer.relayed);
  if (waitForBytes) {
    const timers = streamTimers(run);
    let wait: unknown = null;
    const first = await Promise.race([
      client.firstWrite.then(() => null),
      refusedFirst,
      new Promise<null>((resolve) => (wait = timers.setTimeout(() => resolve(null), Math.max(0, headersAt - clock())))),
      run.answer.relayed.then(() => null),
    ]);
    timers.clearTimeout(wait);
    run.answer.preHeaders = null;
    // The attempt failed before its first bytes: the client gets the refusal held for it.
    if (first !== null) return first;
  }
  // S32 / L6: stack VM and stack-peer streams use SSE comment keep-alives (`STACK_KEEP_ALIVE`) so the events chain
  // stays identical to the vendor's. Endpoint-only routes on an entry with `LANE_PEERS` (or streams already
  // committed to an endpoint route) keep the client protocol's own keep-alive (e.g. Anthropic `event: ping`).
  const stackKeepAlive =
    (run.lane?.stackConfig?.relayId ?? null) !== null ||
    (entryPeers(run) !== null && (early === "headers" ? hasStackPeerCandidate : early.attempt.peer !== undefined));
  client.startKeepAlive(cfg.streamKeepAliveMs, stackKeepAlive ? STACK_KEEP_ALIVE : keepAliveFrame(run.protocol));
  run.answer.headersSent = true;
  const headers = new Headers({ "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", "x-accel-buffering": "no", "x-request-id": run.requestId });
  if (run.protocol === "anthropic_messages") headers.set("request-id", run.requestId);
  if (early !== "headers") {
    headers.set("x-gray-provider", await providerRef(early.attempt.route));
    headers.set("x-gray-attempt", String(early.attempt.index + 1));
  }
  if (run.answer.gated) headers.set("x-gray-stream-gated", "tool-calls");
  if (translation !== null) for (const [name, value] of Object.entries(translation.headers())) headers.set(name, value);
  capHeaders(run, headers);
  modelHeader(run, headers);
  droppedHeader(run, headers);
  // F2 hooks-4: the id of the receipt these early headers promise goes out with them.
  laneReceiptHeader(run, headers);
  run.answer.ttfbMs = clock() - run.started;
  return new Response(client.readable, { status: 200, headers });
}

/**
 * What every attempt of the admitted request shares: the body the upstream is sent (the client's,
 * or the translated one, serialized once the cap is settled) and the request as the gate keeps it.
 */
export function prepare(run: DispatchRun, o: Dispatch): Prepared {
  const t = run.facts.translation;
  if (t === null) {
    const scrub = scrubbed(run, o.parsed);
    return {
      protocol: run.protocol,
      value: scrub?.value ?? o.parsed.value,
      body: scrub?.body ?? o.parsed.body,
      layout: scrub === null ? o.parsed.layout : scrub.layout,
      overlay: o.overlay,
      contract: run.deps.gate.contract({ request: o.canonical, body: o.parsed.value }),
      // Read from the client's body: a lane reply is bound only on a route whose own software may hold the
      // conversation (`laneBinds`), and a stack route's container is sent `store: false` whatever the client wrote.
      stores: storesContinuation(run.protocol, o.parsed.value),
      removals: scrub?.removals ?? [],
    };
  }
  const bytes = t.upstreamBytes();
  const body: ClientBody = { bytes, value: t.body, duplicateKeys: false };
  let layout: BodyLayout | null = null;
  try {
    layout = locateMembers(bytes);
  } catch {
    // serde_json's own output always locates; a body that does not is sent as written below.
  }
  return { protocol: t.upstream, value: t.body, body, layout, overlay: new Overlay(), contract: run.deps.gate.contract({ request: t.contract, body: t.body }), stores: false, removals: [] };
}

/**
 * A native request's body without what only a translation can read (@gray/protocol `scrubNative`, inference.rs
 * `serve_model`): the implied Responses fallback (decision (b) of 2026-10-23) moves a session between a native and a
 * translated route on its own, and the protocol's own upstream refuses carrier text where it expects its signature,
 * and a reasoning item Gray minted that it never stored. Null when nothing is dropped. A body read whole (tier A) is
 * then written from its parse, as serde_json writes it, as the server sends every body. A body not read whole (tier B
 * and C: the conversation is not parsed) keeps its bytes: the layout scan found the items to take out
 * (parse.ts `ScrubScan`, the server's `scrub_native` of a body of any size), and each attempt's body leaves those spans
 * out (`removals`, `bodyEdits`). A later turn of a conversation an earlier translated turn served may well be one
 * that large. Null in the confidential lane too: a vendor is sent the bytes its client sent, or their declared
 * translation (`laneForwardedFor`), which the receipt describes, so it drops nothing it does not name.
 */
export function scrubbed(run: DispatchRun, parsed: ParsedRequest): { readonly value: Json; readonly body: ClientBody | null; readonly layout: BodyLayout | null; readonly removals: readonly ScrubSpan[] } | null {
  if (run.lane !== null || run.protocol !== "open_ai_responses") return null;
  if (!parsed.whole) {
    if (parsed.scrubbed.length === 0) return null;
    run.facts.nativeDropped = ["reasoning_signature"];
    return { value: parsed.value, body: parsed.body, layout: parsed.layout, removals: parsed.scrubbed };
  }
  if (parsed.body === null || !isObject(parsed.value)) return null;
  // `scrubNative` takes items out of `input` and changes nothing else: a copy of the body's top level and of that
  // array holds the change, the parse every other step reads stays as it was.
  const input = parsed.value.input;
  const value: JsonObject = { ...parsed.value, ...(Array.isArray(input) ? { input: [...input] } : {}) };
  const dropped = scrubNative(run.protocol, value);
  if (dropped.length === 0) return null;
  run.facts.nativeDropped = dropped;
  const bytes = encoder.encode(toJsonString(value));
  let layout: BodyLayout | null = null;
  try {
    layout = locateMembers(bytes);
  } catch {
    // serde_json's own output always locates; a body that does not is sent as written.
  }
  return { value, body: { bytes, value, duplicateKeys: false }, layout, removals: [] };
}

/** What the answer needs of the admitted request: nothing of its body or of its parse, so neither outlives the attempts. */
export function answeringOf(run: DispatchRun, o: Dispatch, prepared: Prepared): Answering {
  return {
    model: o.canonical.model,
    protocol: prepared.protocol,
    contract: prepared.contract,
    stores: prepared.stores,
    outputCap: o.sizing.defaultCap ? (o.sizing.writeCap ? o.sizing.outputCap : undefined) : o.sizing.outputCap,
    candidates: o.candidates,
    answerLimit: answerLimit(run, o),
  };
}

/** A non-streaming request's attempts: each answer is read up to its commit; one that fails before closes alone, and the next goes. */
export async function bufferedLoop(run: DispatchRun, d: Dispatcher, o: Dispatch, prepared: Prepared, answering: Answering, deadline: number, answerDeadline: number, head: { permit: Promise<HeadPermit> | null }): Promise<ModelResult> {
  try {
    for (;;) {
      const sent = await nextAttempt(run, d, o, prepared, deadline, answerDeadline, head);
      if (sent.kind === "stopped") return await stoppedResult(run, d, sent);
      const read = await buffered(run, answering, sent.attempt, sent.response, deadline, d);
      if (read.kind === "uncommitted") {
        // S25: a stack attempt whose vendor was dialed ends the request; only a call no vendor saw may be followed.
        if (sent.attempt.peer !== undefined) {
          const decided = await peerUncommitted(run, d, sent.attempt, o.canonical.model, read.failure);
          if (decided.kind === "stopped") return await stoppedResult(run, d, decided);
          continue;
        }
        reject(run, d, sent.attempt, read.failure);
        continue;
      }
      return { kind: "response", response: read.response };
    }
  } finally {
    releaseUnusedHead(run, head);
  }
}

/** A stream's attempts: each answer is read up to its first frame outside the preamble (`prime`); one that fails before closes alone, and the next goes. */
export async function primedLoop(run: DispatchRun, d: Dispatcher, o: Dispatch, prepared: Prepared, answering: Answering, deadline: number, answerDeadline: number, head: { permit: Promise<HeadPermit> | null }, fragments: FragmentUse): Promise<Primed | Stopped> {
  try {
    for (;;) {
      const sent = await nextAttempt(run, d, o, prepared, deadline, answerDeadline, head);
      if (sent.kind === "stopped") return sent;
      // What priming held leaves the isolate's answer pool when the attempt ends; the frames a committed
      // stream hands back stay counted until the relay's first count replaces them (relay.ts `primeStream`).
      const primed = await prime(run, answering, sent.attempt, sent.response, deadline, sent.firstBytesBy, fragments);
      if (primed.kind === "left") {
        // The client left and the stream did not commit while the Worker could still read it.
        run.answer.leftUnread = true;
        sent.attempt.controller.abort("client_left_unread");
        endAttempt(run, sent.attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left_unread");
        return { kind: "stopped", stop: "client_left" };
      }
      if (primed.kind === "final") {
        // Gray's own limit, not the supplier's: the attempt counts against no route, and the request ends.
        sent.attempt.controller.abort(primed.code);
        endAttempt(run, sent.attempt, { kind: "not_counted", reason: "gray_error" }, true, primed.code);
        return { kind: "stopped", stop: null, error: primed.error, gray: true };
      }
      if (primed.kind === "uncommitted") {
        // S25: a stack attempt whose vendor was dialed ends the request; only a call no vendor saw may be followed.
        if (sent.attempt.peer !== undefined) {
          const decided = await peerUncommitted(run, d, sent.attempt, o.canonical.model, primed.failure);
          if (decided.kind === "stopped") return decided;
          continue;
        }
        reject(run, d, sent.attempt, primed.failure);
        continue;
      }
      commit(run, d, sent.attempt);
      return { kind: "committed", attempt: sent.attempt, response: sent.response, stream: primed.stream };
    }
  } finally {
    releaseUnusedHead(run, head);
  }
}

/**
 * Sends the next attempt, and the ones after it while they fail, until one answers 2xx (`next`). Returns
 * that answer, uncommitted, or why no further attempt goes (`Stopped`).
 */
export async function nextAttempt(run: DispatchRun, d: Dispatcher, o: Dispatch, prepared: Prepared, deadline: number, answerDeadline: number, head: { permit: Promise<HeadPermit> | null }): Promise<Answered | Stopped> {
  // `stream_options` that is not an object is the request's error, the same at every route; the
  // server finds it building the first attempt and rejects it locally (`reject_local`, 400), no
  // upstream asked and no route blamed.
  const local = attemptOverlay(prepared.protocol, o.canonical.stream, prepared.value, prepared.overlay, "");
  if (typeof local === "string") return { kind: "stopped", stop: null, error: new ApiError(400, local) };
  // The tiers, the routes passed over and the repeats that could not go are the dispatcher's
  // (`Dispatcher.nextAttempt`, inference.rs `next_attempt`); this run answers it and carries out what it decided.
  const env = dispatchEnv(run, d, o, prepared, head, answerDeadline, deadline);
  for (;;) {
    // What the dispatcher asks (permits, repeats' places) is Gray's; an attempt's own wait is its upstream's.
    run.budget.resume();
    const chosen = await d.nextAttempt(env);
    if (chosen.kind === "stop") {
      // A route a cold path passed over before anything was sent is asked once more (F2 D131, every route).
      if (chosen.error === undefined && coldRepeat(run, d, answerDeadline)) continue;
      const answered = stackVendorAnswered(run, d, chosen.stop);
      return { kind: "stopped", stop: chosen.stop, ...(chosen.error === undefined ? (answered ?? {}) : { error: chosen.error }) };
    }
    const failure = d.last?.outcome.class;
    if (failure !== undefined && chosen.next !== "none") run.admitting.retryEvents.push({ kind: "retry", next: chosen.next, cls: failure });
    run.budget.pause();
    const opened = await openAttempt(run, d, o, prepared, chosen.route, chosen.acquired, chosen.next, chosen.selection, chosen.backoffMs, answerDeadline, chosen.retest);
    // The attempt after a vendor's 400 of a relay's change ended the request without an answer of a vendor's (a fault
    // of its relay's, Gray's check of its answer): that 400 is the client's, as before (`relayChangeAnswer`).
    if (opened.kind === "stopped" && opened.gray !== true && opened.passthrough === undefined && run.stackPeer.relayChangeHeld !== null) {
      const changed = relayChangeAnswer(run, d, opened.stop);
      if (changed !== null) return { ...opened, ...changed };
    }
    if (opened.kind !== "continue") return opened;
  }
}

/**
 * The one repeat of a route whose cold pass would end the request with nothing sent
 * (`Dispatcher.coldPass`; docs/cloudflare-native/gateway.md section 14): its permit was still being
 * borrowed when the wait ended (production, 2026-10-22/23: a new endpoint shard borrowing from a cold
 * root took longer than ENDPOINT_ACQUIRE_WAIT_MS, and the requests seconds later were served), or its
 * lane pick was lost (F2 D131). The earliest such pass is undone (`Dispatcher.repeatPass`) and asked
 * again as the request's first attempt, at the shard the pass asked (`dispatchEnv`'s `acquire`, with `awaitLease`:
 * it waits on the borrow already on its way). In the lane, also the relay's cached policy decision and a
 * new pick (each pick names its own `request_ref`; the lost one's release was flushed with its pass).
 * `choose` stops only after tier A passed every route of every operator, so this comes after every
 * other operator. It is no vendor retry: no breaker counts the pass (a late permit goes back
 * `not_dispatched`, an unsent one `unsentOutcome`), the repeat takes no retry ticket, budget or backoff,
 * the request's one admission and hold stand, and the pass stays in `routing_skipped` beside the
 * repeat's attempt.
 *
 * @gray/errors `coldRepeatAllowed` (retry.rs `cold_repeat_allowed`) decides: at most once per request,
 * only while nothing was sent upstream by any model of it (no attempt recorded; `coldPass` checks this
 * model's dispatcher), the client still there, and the answer deadline (a stream's UPSTREAM_HEADER_MS
 * after admission, a buffered request's NON_STREAM_TOTAL_MS after its body) leaving more than the waits
 * the repeat adds before it can send: ENDPOINT_ACQUIRE_WAIT_MS for its permit, plus
 * LANE_SCHEDULER_PICK_MS for a route that picks an account (their own settings' bounds; a lane policy
 * step is the cached decision). With less room it would pay its waits for an attempt the deadline cuts,
 * and the request ends as it did before.
 */
export function coldRepeat(run: DispatchRun, d: Dispatcher, answerDeadline: number): boolean {
  const cold = d.coldPass();
  if (cold === null) return false;
  const { cfg, clock } = run.deps;
  const needMs = cfg.endpointAcquireWaitMs + (d.plan.accountPool(cold.route) !== null ? cfg.laneSchedulerPickMs : 0);
  if (!coldRepeatAllowed({ sent: run.log.attempts.length, repeated: run.admitting.coldRepeated, clientGone: run.presence.gone, roomMs: answerDeadline - clock(), needMs })) return false;
  // Its permit waits what the pre phase has left (`acquire`): none left, no repeat. In the lane the permit has its own
  // bound, and the room rule above is the repeat's bound (`acquire`).
  if (run.lane === null && run.budget.preLeft() === 0) return false;
  run.admitting.coldRepeated = true;
  run.admitting.coldRepeatAt = cold;
  d.repeatPass(cold);
  console.log(JSON.stringify({ level: "info", event: "cold_repeat", request_id: run.requestId, endpoint: cold.route.record.endpointId, shard: cold.shard?.name ?? null, why: cold.why }));
  return true;
}

/**
 * The client's error after the dispatcher stopped (`stop` and `fail_request`): with a refusal held for
 * the last attempt, that refusal, as a call straight to the refusing route would have answered; with no
 * attempt failed, why none could go (the time for an answer ran out, every route's breaker refused, or no
 * route could take the request); otherwise the last failure's, as `Dispatcher.lastError` words it. Every
 * error carries the attempts sent and says when its Idempotency-Key was spent (`told`).
 */
export function stopError(run: DispatchRun, d: Dispatcher, s: Stopped): { readonly error: ApiError; readonly left: boolean; readonly next: boolean; readonly unrouted?: true } {
  if (s.stop === null) return { error: told(run, s.error!), left: false, next: false };
  d.stop(s.stop);
  if (d.last !== null || s.stop === "invariant") {
    run.admitting.retryEvents.push({ kind: "retry_stop", stop: s.stop });
    run.admitting.retryStop = s.stop;
    noteFollowed(run, "none", null, s.stop);
  }
  if (s.stop === "client_left") return { error: new ApiError(499, "client_cancelled"), left: true, next: false };
  const held = d.heldToTell();
  let error: ApiError;
  if (held !== null) {
    error = held.refusal;
  } else if (d.last === null) {
    // The time for an answer ran out before an attempt went; every route left would be sent the originals of
    // the client's handles, past its API's limit; or routes of a supplier whose upstream account a block holds
    // off were all that was left, and the client is told that block (`no_attempt_error`).
    const none = noAttemptError(s.stop, d.heldOffBy, run.facts.model ?? "", run.upstreamProtocol);
    // A route too small for the body in Gray's confidential VM names that limit, not the tool-call handles' (GL-29).
    if (none.kind === "told") error = s.stop === "request_body_limit" && run.zdr.bodyLimitRefusal !== null ? run.zdr.bodyLimitRefusal : none.error;
    else if (run.admitting.recoveryOnly && run.admitting.modelPasses > 0) {
      // Every route was refused by its breaker (cooling down after recent failures, or holding requests
      // for a probe that is out until the request's time ran out): the soonest moment one may serve is
      // the Retry-After, when a shard said it; none is invented when none did (the server's
      // `recovery_retry_after`, set only with a cooldown's or a probe's end).
      error = new ApiError(503, "all_endpoints_in_recovery");
      if (run.admitting.recoveryEnds.size > 0) {
        const seconds = retryAfterSeconds(Math.max(0, Math.min(...run.admitting.recoveryEnds.values()) - run.deps.clock()));
        run.admitting.recoveryRetryAfterS = Number(seconds);
        error = error.withRetryAfter(seconds);
      }
      // This model sent no attempt and the client has no headers: the server's admission refused it (`unrouted`).
      // A lane request is the lane's own (Workers alone).
      if (d.tried.attempts === 0 && run.lane === null && !run.answer.headersSent) return { error, left: false, next: false, unrouted: true };
    } else {
      error = noRouteRetryAfter(new ApiError(none.status, none.code), d, run.deps.cfg, run.admitting.rebuildingEnds === null ? null : Math.max(0, run.admitting.rebuildingEnds - run.deps.clock()));
    }
  } else if (s.vendorAnswer === true && s.error !== undefined) {
    // A stack relay's vendor error the request ended on after the other routes (`stackVendorAnswered`): its own.
    error = s.error;
  } else if (run.lane !== null && s.stop === "no_route" && d.tried.lastSkip?.startsWith("lane_account_unavailable") === true && !(d.last.outcome.class === "credential" && d.passedAtFailedPool())) {
    // F2 D30: a lane relay whose scheduler answered "no account" is passed over terminally. When no
    // other route is left, the request is the lane's 503 (as `openAttempt` says), not the supplier
    // error of an earlier attempt: the last thing that happened was an availability pass. D111(d)
    // appends the closed cause to the label (`lane_account_unavailable:<code>`); the terminal rule
    // still matches the family. F2 D124': not when the last failure was a credential failure and the
    // pass that ended the request asked an account pool where this request had a credential failure
    // (D124'': the last failure's or an earlier one's; its repeat, or another route of the relay asking
    // the same pool) and found no other account (a one-account relay, or a pool every account of which
    // this request already tried): the counted failure stands, 502 `upstream_auth_failed` with its
    // receipt (D110), as it did before the repeat. When the request ends on a pass at a relay or pool
    // no credential failure touched, or on no account after a 5xx or 429 (GW-02, also when an earlier
    // credential failure was at another relay), the 503 stays.
    error = new ApiError(503, "provider_capacity_or_quote_unavailable");
  } else {
    error = d.lastError()!;
  }
  // The next model the customer listed may serve the request: the dispatcher gave up for this model alone,
  // and the client has no headers yet.
  return { error: told(run, error), left: false, next: d.leavesToNextModel() && !run.answer.headersSent };
}

/**
 * Every route of this model was refused by its breaker or its rest, and no attempt was sent. The server refuses such
 * a model at admission, before it holds anything (inference.rs `admit`: an empty ranking is `recovery_refusal`,
 * `Refused::Unrouted`, which leaves the request to the next model the customer listed, unreserved), and this gateway
 * does when its isolate's ranking knows the rests (`serveModel`). Here the endpoint shards said it after the hold was
 * asked for beside the head's permit (an isolate that had not heard of a rest, or a circuit, which lives in the
 * endpoint root alone), so the model ends as that refusal at ranking: the hold goes back as never the request's
 * (@gray/account `UNROUTED`: the client's Idempotency-Key stays unused, its repeat is admitted afresh, and the
 * projection keeps no row of it); the client is told it as admission tells it (no `attempts`, no spent key, so
 * `x-should-retry` stays true); the record holds nothing and lists no admission of the model; and the next model is
 * served as if this one had never been admitted (the request key and the stream's headers deadline of the
 * request's first admission, `Turn::reserved`, `Turn::headers_at`).
 *
 * The release is waited for (within its retries' budget) before the next model is admitted and before the client is
 * answered: the next model and a repeat of the client's key are admitted under the same request key, and a shard
 * that still held this hold open would answer that admission as a duplicate of it (409 `request_already_admitted`),
 * where the server, which never held anything for this model, serves it (r30 review, money lens). Should the release
 * not land, the next model's admission is numbered past this one's (`baseKeyAttempt`), so it supersedes the hold.
 */
export async function unroutedResult(run: DispatchRun, error: ApiError): Promise<ModelResult> {
  await releasingHold(run, { reason: UNROUTED, detail: { code: error.code } }, "none");
  run.settlement.heldMicrousd = null;
  run.admitting.admissions.pop();
  run.admitting.reserved = run.admitting.beforeAdmission.reserved;
  if (!run.admitting.reserved) run.admitting.baseKeyModel = null;
  run.admitting.firstAdmittedAt = run.admitting.beforeAdmission.firstAdmittedAt;
  return unserved(run, error, "ranking");
}

/**
 * The dispatcher stopped before the client had headers: the hold is released and the client gets the
 * error, or the next model the customer listed is tried (`Unserved::NextModel`). After the headers the
 * caller ends the stream with `code`'s error event and the record.
 */
export async function stoppedResult(run: DispatchRun, d: Dispatcher, s: Stopped): Promise<ModelResult & { readonly code: string; readonly outcome: RequestOutcome }> {
  const heldRefusal = d.heldToTell();
  const held = heldRefusal !== null;
  const { error, left, next, unrouted } = stopError(run, d, s);
  if (unrouted === true) return { ...(await unroutedResult(run, error)), code: error.code, outcome: "failed" };
  // The hold's release names why the last failure failed (a usage refusal's reason), else the client's code.
  const reason = left ? (run.answer.leftUnread ? "client_left_unread" : "client_left") : !held && d.last !== null && run.admitting.lastFailureReason !== null && error.code === d.last.error.code ? run.admitting.lastFailureReason : error.code;
  // A stack relay's vendor error is the client's answer while no headers went (S24); after them, the
  // stream ends with the error event of its classification, as any failure after the headers does.
  // A model the customer listed next goes first (`deferRecord`: this model is not the last); the vendor's error is the
  // answer of the last one.
  if (s.passthrough !== undefined && !run.answer.headersSent && !(next && run.log.deferRecord)) {
    s.served?.();
    const passed = stackPassthrough(run, s.passthrough, error, reason);
    return { kind: "response", response: passed.response!, code: passed.code, outcome: passed.outcome };
  }
  if (heldRefusal !== null && run.lane !== null && !(next && run.log.deferRecord)) {
    const heldDraft = run.receipt.attemptLaneDrafts.get(heldRefusal.attempt);
    if (heldDraft !== undefined) {
      run.receipt.laneDraft = heldDraft;
      run.receipt.winningReceipt = "lane";
    }
  }
  const sent = fail(run, error, reason, null, 0, s.gray === true, next);
  return { kind: next ? "next" : "response", response: sent.response ?? new Response(null, { status: 499 }), code: sent.code, outcome: sent.outcome };
}
