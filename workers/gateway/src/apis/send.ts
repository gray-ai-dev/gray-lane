/**
 * A model API attempt at the confidential entry (`ModelApiRun`, apis.ts): which routes are the entry's, the provider's
 * key, the forwarded body, and the upstream call.
 */
import { ApiError } from "@gray/errors";
import { LANE_BRIDGE_CALL_MS } from "@gray/lane-wire";
import { probeSent } from "../endpoints.ts";
import { laneUpstreamOf, receiptDraft } from "../lane/hooks.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import { type EntryBody, type EntryForward, ENTRY_FORM_CHUNK_BYTES, entryForwarded, entryUpstreamHeaders, formTooLarge } from "../lane/standard-api.ts";
import type { RouteRecord } from "../snapshot.ts";
import { sendable, UPSTREAM_BODY_CHUNK_BYTES } from "../upstream.ts";
import type { Attempt, SendResult, ApiRunCore } from "./state.ts";
import { endpoints } from "./io.ts";
import { abandonLease } from "./route-steps.ts";

/**
 * An endpoint route at the entry (docs/design/lane-provider-routes.md section 5): any route of the lane's view that is
 * no lane relay's, attempted through egress's `/route/` kind when the entry has its keys and table.
 */
export function entryRoute(run: ApiRunCore, record: RouteRecord): boolean {
  const lane = run.lane;
  return record.auth !== "lane_relay" && lane.endpointFetch !== undefined && lane.endpointCredentials !== undefined;
}

/**
 * The provider's key of an entry's endpoint route at its credential generation (inference.ts `laneEndpointKey`): the one
 * in the entry's memory, else one `endpoint.credential` call waited for within a bridge call's bound and the time to
 * the answer's deadline, its own bound and not what the pre phase left. Null when none came.
 */
export async function entryKey(run: ApiRunCore, record: RouteRecord, deadline: number): Promise<string | null> {
  const keys = run.lane.endpointCredentials;
  if (keys === undefined) return null;
  const budgetMs = Math.max(0, Math.min(LANE_BRIDGE_CALL_MS, deadline - run.deps.clock()));
  try {
    return await keys.credential(record.endpointId, record.credentialGeneration, budgetMs);
  } catch {
    return null;
  }
}

/**
 * The bytes an entry's attempt forwards to a provider that calls the model `upstreamModel`, and the events that
 * declare them (lane/standard-api.ts `entryForwarded`). One is kept, the last route's: a failover to a provider
 * with another name for the model makes its own once the earlier one is let go. A form's is views over the client's
 * bytes, so the request holds the form once; a JSON body's is one changed copy.
 */
export async function entryForwardedFor(run: ApiRunCore, body: EntryBody, upstreamModel: string): Promise<EntryForward> {
  const kept = run.entryForwards;
  if (kept !== null && kept.upstreamModel === upstreamModel) return kept.forwarded;
  run.entryForwards = null;
  const forwarded = await entryForwarded(run.protocol, body, upstreamModel);
  run.entryForwards = { upstreamModel, forwarded };
  run.retained.set("request_body", body.bytes.length + (forwarded.ok ? forwarded.ownBytes : 0));
  return forwarded;
}

/** The request's body is no longer needed (an answer committed): its bytes and their forwarded copy are let go. */
export function dropEntryBody(run: ApiRunCore): void {
  run.entryBody = null;
  run.entryForwards = null;
  run.retained.set("request_body", 0);
  run.answerShare.holdBody(0, run.deps.cfg.laneFormHeldMaxBytes);
}

/**
 * One upstream call of an entry's attempt, until its response headers (docs/design/standard-media-at-entry.md
 * sections 2.2 and 2.4): the client's bytes with the entry's declared changes, to the route's URL through the
 * attempt's own fetch (egress's `/route/` kind), with `content-type` as the client sent it, an `accept` of any type
 * and the provider's key. The bytes' hash and events are the attempt's receipt draft; the request has a receipt
 * from the moment a fetch took the body.
 */
export async function send(run: ApiRunCore, attempt: Attempt, deadline: number): Promise<SendResult> {
  const { clock } = run.deps;
  const entry = attempt.entry;
  const record = attempt.candidate.record;
  const body = run.entryBody;
  if (body === null) return { kind: "refused", error: new ApiError(500, "internal_error") };
  const forwarded = await entryForwardedFor(run, body, record.upstreamModel);
  if (!forwarded.ok) return { kind: "refused", error: forwarded.error };
  // A form at the bound that the provider's longer name for the model takes past it: the bound is also what egress
  // carries to a route (`-route-max-body-bytes`), so the entry refuses it with the limit rather than send it.
  if (body.kind === "form" && forwarded.length > run.deps.cfg.laneFormMaxBytes) return { kind: "refused", error: formTooLarge(run.deps.cfg.laneFormMaxBytes) };
  attempt.laneDraft = receiptDraft({
    modifiedEvents: forwarded.events,
    policy: null,
    forwardedHash: forwarded.hash,
    accountId: null,
    upstreamModel: record.upstreamModel,
    // The host the bytes go to (`upstream_name`): the provider's, whose API is not a TEE.
    upstream: laneUpstreamOf(record),
  });
  // A recovery probe goes out from here, as the server's attempt sends it (`probe_sent`, `ProbeLease::sent`): its spell's
  // clock runs, the dispatch's point records when it went, and the attempt owns the recovery lease the plan's head took
  // for its route.
  const permit = attempt.permit;
  if (permit.probeId !== null && permit.trial !== true) run.ctx.waitUntil(probeSent(endpoints(run), run.deps.region, permit));
  attempt.dispatchedAtMs = run.deps.clock();
  await run.heldProbe.sent(attempt.route.record.endpointId);
  let timedOut = false;
  const timer = setTimeout(
    () => {
      timedOut = true;
      attempt.controller.abort("attempt_deadline");
    },
    Math.max(0, deadline - clock()),
  );
  const unsubscribe = run.presence.onLeave(() => attempt.controller.abort("client_left"));
  let taken = false;
  let started = false;
  let stream: ReadableStream<Uint8Array> | null = null;
  try {
    const headers = entryUpstreamHeaders(run.protocol, body, run.request.headers, entry.credential);
    stream = sendable(forwarded.body(body.kind === "form" ? ENTRY_FORM_CHUNK_BYTES : UPSTREAM_BODY_CHUNK_BYTES), () => {
      taken = true;
      // The body is handed to the provider's fetch: the response names the id its receipt will use, and the last
      // body that really went is the receipt of a request no attempt commits.
      run.laneReceiptId ??= newLaneReceiptId();
      run.laneForwardedDraft = attempt.laneDraft ?? null;
    });
    const response = await run.outbound.fetch(entry.fetch)(record.url, { method: "POST", headers, body: stream, signal: attempt.controller.signal, redirect: "manual" }, () => (started = true));
    if (response.status >= 200 && response.status <= 299) return { kind: "answered", response };
    return { kind: "status", response };
  } catch {
    stream?.cancel().catch(() => {});
    // An attempt whose call was never made never left the entry: the recovery lease it took over from the plan's head
    // goes back (inference.ts `send`, the server's `close_attempt`).
    if (!started) abandonLease(run, attempt.route);
    if (run.presence.gone) return { kind: "left", started };
    if (timedOut) return { kind: started ? "timeout" : "unsent" };
    return { kind: taken ? "transport" : "connect" };
  } finally {
    clearTimeout(timer);
    unsubscribe();
  }
}
