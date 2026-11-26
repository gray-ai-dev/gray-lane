/**
 * A request's intake (`InferenceRun`, inference.ts): the key and the snapshot, the content's scope, the body by tier,
 * the lane's refusals of a body, the routing preference and parameters taken out of it, the key's model scope, a
 * request forwarded to the confidential entry, a model check's ticket, and the loop over the models the customer listed.
 */
import type { Placement } from "@gray/content";
import { ApiError } from "@gray/errors";
import { type Json, type JsonObject, isObject, readSerdeBytes } from "@gray/json";
import { API_FORWARD_HEADER, type TicketUseOutcome } from "@gray/lane-wire";
import { requestLimit } from "@gray/limits";
import { type CanonicalRequest, outputCandidateCount } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, Preference, ROUTING_PARAMS_HEADER, modeSourceOf, resolveRoutingParams, takeRouting } from "@gray/routing";
import { HandleWatch } from "@gray/tool-ids";
import { hasQueryCredentials, keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "../auth.ts";
import { type Body, readBody } from "../body.ts";
import { withinPhase } from "../budget.ts";
import { platformTimers } from "../client.ts";
import { RequestContent } from "../content.ts";
import { type EntryChatForward, endingWith, entryAnswerUsable, entryServesChain, entryUnreachable, forwardedAnswer, forwardedRequestHeaders } from "../entry-forward.ts";
import { admissionUnavailable } from "../key-rate.ts";
import { verifiableViaApi } from "../lane/api-arrival.ts";
import { VM_BODY_LIMIT_SOURCE, laneBodyCap } from "../lane/body-limits.ts";
import { laneDuplicateKey, laneRoutingInBody, laneRoutingParamsInBody, laneSafeLog, laneToolHandlesUnsupported } from "../lane/hooks.ts";
import { laneEntryRequired } from "../lane/run-common.ts";
import { type TicketRefusal, type TicketStoreUnavailable, checkTicket, ticketHeader, ticketUseVerdict } from "../model-check.ts";
import { type ParsedRequest, parseHeld, parseStored } from "../parse.ts";
import { laneServes, layeredOver, modelCheckPinned, modelCheckUnpinned, preferenceFacts, registeredOf, routingRefused, takeTags, unadmitted, unreadableDefault, unreadablePreference, verifiableUpFront } from "../preference.ts";
import { preferenceLevels, statedOf } from "../request-routing.ts";
import { turnStart } from "../sinks.ts";
import { type GatewaySnapshot, type KeyRecord, RANKING_WAIT_MS, snapshotTiming } from "../snapshot.ts";
import { spoolPlaintext } from "../spool.ts";
import { handlesInBody, handlesInSpan, siteMember } from "../tool-ids.ts";
import { closeRate, flushRecord, refuse } from "./record.ts";
import { requestDeadline, spoolOpener, spoolRead } from "./request-body.ts";
import { type ServeModelRun, beginModel, endModel, serveModel } from "./serve-model.ts";

/** A Gemini request streams by its path's method, whatever its body says (forward_traced). */
function geminiStream(path: string): boolean {
  return path.endsWith(":streamGenerateContent");
}

/**
 * The members of a client body that are Gray's, not its API's (inference.rs `GRAY_MEMBERS`): the routing preference
 * (`provider`) and the routing parameters (`routing`; the parser takes `models` out itself). Each is read where its part
 * of the request is decided, and none is forwarded: a first-party API refuses a member it does not define.
 */
const GRAY_MEMBERS = ["provider", "routing"] as const;

/** Takes Gray's own members (`GRAY_MEMBERS`) out of a parsed body (`without_gray_members`). */
function withoutGrayMembers(value: Json): void {
  if (!isObject(value)) return;
  for (const member of GRAY_MEMBERS) delete (value as JsonObject)[member];
}

/** What intake.ts needs of the run: its state alone. */
export interface IntakeRun extends ServeModelRun {}

/**
 * The request's content, once its scope is known and before its body is read (content.md 2.7): a
 * usable key's workspace; a revoked or expired key's workspace (stored under `anon/v3/w/`, so its
 * deletion takes these too, content.md 2.2); the anonymous scope without a key or for an unknown one.
 */
export async function openContent(run: IntakeRun, placement: Placement, snapshot: GatewaySnapshot | null): Promise<void> {
  // The confidential lane keeps no request content (design v2 §C.11, M13): its snapshot carries no
  // recipients, its bucket is a stub, and `details()` is never built. Every early return below is
  // still reached in lane mode, so the guard is here rather than at each of them. No recipient is
  // looked up, so none is missed or alerted on; the row says `withheld`, `confidential` (`record`).
  if (run.lane !== null) return;
  if (run.facts.content !== null) return;
  run.facts.content = await RequestContent.open(
    {
      cfg: run.deps.cfg,
      state: run.deps.content,
      bucket: run.io.content,
      clock: run.deps.clock,
      ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers }),
      background: (p) => run.ctx.waitUntil(p),
      retained: run.retained,
      log: (event) => (event.level === "alert" ? console.error : console.warn)(JSON.stringify(event)),
    },
    snapshot,
    placement,
    run.requestId,
    run.started,
  );
}

/** The isolate's copy of the snapshot as it is, without waiting (a request refused before its key is looked up). */
export function peekSnapshot(run: IntakeRun): GatewaySnapshot | null {
  return run.deps.snapshots.peek(snapshotTiming(run.deps.cfg), run.deps.clock());
}

export async function serveRequest(run: IntakeRun): Promise<Response> {
  const { cfg, clock } = run.deps;
  const url = new URL(run.request.url);
  // Query credentials leak through URL logs (`preflight`).
  if (hasQueryCredentials(url)) {
    await openContent(run, { kind: "anonymous" }, peekSnapshot(run));
    return refuse(run, new ApiError(400, "query_credentials_unsupported"), "query_credentials");
  }

  // 1. The key, from the snapshot.
  const presented = presentedKey(run.request.headers);
  if (presented instanceof ApiError) {
    run.caller.authResult = presented.code === "missing_api_key" ? "missing" : "malformed";
    await openContent(run, { kind: "anonymous" }, peekSnapshot(run));
    return refuse(run, presented, "auth");
  }
  run.caller.authScheme = presented.scheme;
  const timing = run.deps.waitTimers === undefined ? snapshotTiming(cfg) : { ...snapshotTiming(cfg), timers: run.deps.waitTimers };
  // The snapshot's waits (the read, an unknown key's confirmation) are the first of the request's budget before its
  // upstream; their own cap is one whole check (docs/request-path-availability.md 3.3, rule 1).
  const snapshotLeft = () => run.budget.preWait(timing.checkMaxMs ?? timing.waitMs);
  const read = await run.deps.snapshots.read(
    run.deps.source,
    timing,
    clock(),
    (p) => run.ctx.waitUntil(p),
    (call) => run.outbound.run(call),
    snapshotLeft(),
  );
  if (!read.ok) {
    run.caller.authResult = "unavailable";
    // No usable snapshot: no recipient either (content.md 3.7, `no_recipient`).
    await openContent(run, { kind: "anonymous" }, null);
    return refuse(run, new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
  }
  run.routing.isolateGapMs = read.gapMs;
  let snapshot = read.snapshot;
  const hash = await keyHash(presented.token);
  run.laneRelays.laneOwner = hash;
  let key: KeyRecord | undefined = snapshot.keys[hash];
  if (key === undefined) {
    // A copy served for hours may lack a key made since it was last confirmed (an isolate idle for
    // minutes, a replica that had not synced): the key is refused only from a copy confirmed
    // current within one interval of this request (snapshot.ts `confirm`).
    const confirmed = await run.deps.snapshots.confirm(run.deps.source, timing, run.started, (p) => run.ctx.waitUntil(p), (call) => run.outbound.run(call), snapshotLeft());
    if (confirmed.ok) {
      snapshot = confirmed.snapshot;
      key = snapshot.keys[hash];
    }
  }
  run.routing.snapshot = snapshot;
  if (key === undefined) {
    run.caller.authResult = "unknown";
    await openContent(run, { kind: "anonymous" }, snapshot);
    return refuse(run, new ApiError(401, "invalid_api_key"), "auth");
  }
  const keyRefused = keyRefusal(key, Math.floor(clock() / 1000));
  if (keyRefused !== null) {
    run.caller.authResult = keyRefused.code.replace("api_key_", "").replace("owner_", "");
    run.caller.refusedKey = key;
    // A revoked, expired or disabled key still names its workspace: sealed to it (content.md 2.2).
    await openContent(run, { kind: "revoked", workspace: key.workspaceId }, snapshot);
    return refuse(run, keyRefused, "auth");
  }
  // docs/design/relay-outbound-only.md section 6: a relay's VM never serves a customer key itself; its customers go
  // through an entry (what `direct: false` meant before the cleanup removed `direct`).
  const own = run.lane?.stackConfig?.relayId ?? null;
  if (own !== null) {
    run.caller.authResult = "lane_entry_required";
    await openContent(run, { kind: "workspace", workspace: key.workspaceId }, snapshot);
    return refuse(run, laneEntryRequired(), "auth");
  }
  run.caller.authResult = "ok";
  run.caller.key = key;
  // A usable key: the request counts against its minute, once (`closeRate`).
  run.caller.rateOpen = true;
  await openContent(run, { kind: "workspace", workspace: key.workspaceId }, snapshot);

  try {
    return await closeRate(run, await receive(run, snapshot, key));
  } finally {
    const spooled = run.facts.spooled;
    if (spooled !== null) {
      // The stored body is needed until the last attempt has sent it and the content writer has read
      // its first part; a lifecycle rule on the spool prefix removes what a lost delete leaves.
      const read = run.facts.content?.requestDone ?? Promise.resolve();
      run.ctx.waitUntil(Promise.all([run.answer.relayed, read]).then(() => run.log.emitted).then(() => run.io.content.delete(spooled)).catch(() => {}));
    }
  }
}

/**
 * 2. The body, by tier, then the rest of the request. It returns the rest's promise without
 * waiting for it, as the steps after it do, so no finished step keeps the body alive while the
 * answer runs: the request path lets go of it once an upstream answered (`releaseRequestBody`).
 */
export async function receive(run: IntakeRun, snapshot: GatewaySnapshot, key: KeyRecord): Promise<Response> {
  const { cfg, clock } = run.deps;
  run.admitting.admission = "body";
  const limit = Number(requestLimit(run.protocol));
  // Whether the body can hold a tool-call id handle, as it arrives (tool-ids.ts): one without is not walked.
  const handles = new HandleWatch();
  // The confidential lane reads no spooled body (design v2 §A, B3, B5): its cap is the smaller of
  // the API's own limit and the lane's (the tier A/B boundary until measured), and `readBody` answers
  // the existing 413 `request_body_limit` above it once `spool` is undefined. The bytes are kept
  // whole for the lane's own ops and hashes (`laneReceived`); tier A/B already hold them.
  const lane = run.lane;
  const laneCap = lane === null ? null : laneBodyCap(run.protocol, lane.timing.bodyMaxBytes, cfg.bodyParseMaxBytes);
  // The client's upload and its spool are REQUEST_BODY_MS's, not the pre phase's.
  run.facts.bodyDeadline = clock() + cfg.requestBodyMs;
  run.budget.pause();
  const read = await readBody(
    run.request,
    {
      protocol: run.protocol,
      limit: laneCap ?? limit,
      parseMax: cfg.bodyParseMaxBytes,
      rawMax: laneCap ?? cfg.bodyRawMaxBytes,
      waitMs: cfg.requestBodyMs,
      ...(lane === null ? {} : { limitSource: VM_BODY_LIMIT_SOURCE }),
      ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers }),
    },
    lane === null ? run.io.content : undefined,
    (bytes) => run.retained.set("request_body", bytes),
    (chunk) => handles.push(chunk),
  );
  run.budget.resume();
  if (!read.ok) {
    run.retained.set("request_body", 0);
    return refuse(run, read.error, "body");
  }
  const body = read.body;
  const bodyRead = clock();
  run.facts.requestComplete = true;
  run.facts.bodyReadMs = bodyRead - run.started;
  run.facts.bodyTier = body.tier;
  run.facts.requestBytes = body.length;
  run.retained.set("request_body", body.tier === "C" ? 0 : body.length);
  if (run.lane !== null) run.laneRelays.laneReceived = body.tier === "C" ? null : body.bytes;
  bodyContent(run, body);
  run.facts.mayHoldHandles = handles.found;
  return afterBody(run, snapshot, key, body, bodyRead);
}

/**
 * The body read: a tier C body's spool is noted for its deletion, and the content writer takes the request
 * part. A spooled body's first part it reads itself, in the background, decrypted from its start and
 * cancelled at the cap (content.md 3.4, 3.8); a held body it seals from the held bytes as views while the
 * request path holds them (content.md 3.1 step 2).
 */
export function bodyContent(run: IntakeRun, body: Body): void {
  if (body.tier === "C") {
    run.facts.spooled = body.key;
    const spool = { key: body.key, length: body.length, identity: body.identity };
    run.facts.content?.requestSpooled(() => run.outbound.run(() => spoolPlaintext(run.deps.env.CONTENT, spool), false), body.length);
  } else {
    run.facts.content?.requestHeld(body.bytes);
  }
}

/**
 * The confidential lane's fixed refusals of a body (design v2 §A), in the design's order:
 *
 * - a Gray tool-call id handle (`gtc1_`): the lane resolves none, so the vendor would see an opaque
 *   id; starting a conversation on the lane is the documented migration rule (M25);
 * - a member name twice anywhere `applyDeclaredChanges` reads the body: the lane refuses rather than
 *   re-serialise, a deliberate difference from the main lane (M3).
 *
 * The checks run over the bytes as received, before the parse re-serialised anything. `parsed` is
 * the parse `afterBody` just made; its `layout` already holds one member per key (the last of a
 * repeated top-level key), so the duplicate check reads the body again with `@gray/json`'s serde
 * reader, which is the reader whose "last wins" rule the main lane's re-serialisation follows.
 *
 * A Responses continuation (`previous_response_id`, `conversation`) is not refused here (the owner's decision of
 * 2026-11-21): it is routed to the endpoint that issued the response it names, once the routes are known (`lanePin`).
 */
export function laneBodyRefusal(run: IntakeRun, bytes: Uint8Array, parsed: ParsedRequest): ApiError | null {
  if (run.lane === null) return null;
  // A Gemini request is served too, on the entry's endpoint routes (docs/design/lane-provider-routes.md sections 2, 7),
  // under the same refusals: Gray forwards its bytes as they came (`laneForwardedFor`).
  // A duplicate anywhere is the lane's fixed 400. `readSerdeBytes` is the reader the main lane's
  // own parse uses, so the rule is the same one that decided the body's meaning upstream.
  const read = readSerdeBytes(bytes);
  if (read.duplicateKeys) return laneDuplicateKey();
  // `mayHoldHandles` is only a prefilter: it also fires on the escaped `<`/`>` that Go's and
  // Gson's JSON writers emit by default, and on any literal `gtc1_` in ordinary text. The lane
  // refuses only a body that really holds a handle **at a tool-call id site** (F2 hooks-3), which
  // is the search `RequestToolIds.resolve` makes with the same two helpers.
  if (run.facts.mayHoldHandles && laneBodyHoldsHandles(run, bytes, parsed, read.value)) return laneToolHandlesUnsupported();
  return null;
}

/**
 * Whether a body the prefilter flagged really holds a handle at a tool-call id site (F2 hooks-3):
 * the same sites and the same `parseHandle` test `RequestToolIds.resolve` uses, from the same two
 * helpers in `tool-ids.ts`. A tier B body is searched in its conversation member's span, as the
 * resolve does; a body whose member the layout cannot place holds none the lane could forward.
 */
export function laneBodyHoldsHandles(run: IntakeRun, bytes: Uint8Array, parsed: ParsedRequest, value: Json): boolean {
  if (parsed.whole) return handlesInBody(run.protocol, value).length > 0;
  const member = siteMember(run.protocol);
  const span = member === null ? undefined : parsed.layout?.members.find((found) => found.key === member);
  if (member === null || span === undefined) return false;
  return handlesInSpan(run.protocol, member, bytes, span.valueStart, span.valueEnd).sites.length > 0;
}

export async function afterBody(run: IntakeRun, snapshot: GatewaySnapshot, key: KeyRecord, body: Body, bodyRead: number): Promise<Response> {
  const { cfg } = run.deps;
  const protocol = run.protocol;
  run.admitting.admission = "parse";
  // The customer's routing preference is read and removed from the body before the body is parsed or
  // forwarded (`Preference::take`): first-party APIs reject unknown body fields, so a preference left in
  // place would become a provider-side 400. The body's `provider` member, or the `x-gray-routing` header. At the lane
  // the body's member goes out of the forwarded bytes as a declared rewrite (`remove_member /provider`,
  // gray-lane-rewrites-v1; docs/design/one-address.md), which the receipt names; a Gemini body has no declared op, so
  // there the preference is the header's alone. The routing parameters (r17) are the body's `routing` member or the
  // `x-gray-routing-params` header (`takeRouting`), read after the preference, and are left out of every upstream body
  // as `provider` is. The lane has no declared op for `routing`: a body's member there is its 400 on every protocol, and
  // the header carries the parameters (docs/utility-routing.md "Request parameters").
  let preferenceRefused = false;
  const take = (value: Json): ApiError | null => {
    const stated = isObject(value) && Object.hasOwn(value, "provider");
    const routing = isObject(value) && Object.hasOwn(value, "routing");
    if (run.lane !== null && ((stated && protocol === "gemini") || routing)) {
      preferenceRefused = true;
      return stated && protocol === "gemini" ? laneRoutingInBody() : laneRoutingParamsInBody();
    }
    const taken = Preference.take(value, run.request.headers);
    if (!taken.ok) {
      preferenceRefused = true;
      return unreadablePreference(taken.code);
    }
    // Out of the parsed value, which the translation decodes strictly, and marked for the overlay of a body read in
    // part (tier B, C), whose members the upstream body is spliced from.
    const routed = takeRouting(value, run.request.headers.get(ROUTING_PARAMS_HEADER));
    if (!routed.ok) {
      preferenceRefused = true;
      return routingRefused(routed.code, routed.message);
    }
    // The request's own parameters alone: an API key's stored default names no mode (r21), whatever r20 stored in it.
    run.routing.routingParams = resolveRoutingParams(routed.request, snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY);
    run.routing.routingStated = statedOf(routed.request);
    run.routing.routingModeSource = modeSourceOf(routed.request);
    // Explicit parameters opt every tiered route in (`tierAdmitted`), marked before the preference is layered.
    run.routing.preference = taken.preference.withRoutingExplicit(run.routing.routingParams.explicit);
    run.routing.stripProvider = stated;
    run.routing.stripRouting = routed.source === "body";
    return null;
  };
  // A tier C body's scan holds at most one value of BODY_RAW_MAX_BYTES, what a tier B body holds whole.
  const parsed =
    body.tier === "C"
      ? await spoolRead(run, () => parseStored(protocol, spoolOpener(run, body), cfg.bodyParseMaxBytes, run.facts.pathModel, cfg.bodyRawMaxBytes, take))
      : parseHeld(protocol, body.tier, body.bytes, run.facts.pathModel, cfg.bodyParseMaxBytes, take);
  if (parsed instanceof ApiError) return refuse(run, parsed, preferenceRefused ? "preference" : "parse");
  if (body.tier !== "C") {
    run.facts.requestBody = body.bytes;
    const laneRefusal = laneBodyRefusal(run, body.bytes, parsed);
    if (laneRefusal !== null) return refuse(run, laneRefusal, "parse");
  }
  // A Gemini request streams by its method, whatever its body says (forward_traced).
  let canonical: CanonicalRequest = protocol === "gemini" ? { ...parsed.canonical, stream: geminiStream(run.path) } : parsed.canonical;
  // Each model string gives up its tag (`model@pattern`, preference.ts `takeTags`): from here on the body, the
  // path's model and the chain name the models alone; the request record keeps the list as the client sent it.
  const tagged = takeTags(snapshot, canonical.model, parsed.models);
  if (!tagged.ok) return refuse(run, unreadablePreference(tagged.code), "preference");
  if (tagged.tags.length > 0) {
    canonical = { ...canonical, model: tagged.model };
    if (run.facts.pathModel !== null) run.facts.pathModel = tagged.model;
    else if (isObject(parsed.value)) (parsed.value as JsonObject).model = tagged.model;
  }
  const chain = tagged.models.length === 0 ? [canonical.model] : tagged.models;
  run.facts.model = canonical.model;
  run.facts.stream = canonical.stream;
  run.facts.toolCount = canonical.tools.length;
  run.facts.turnStart = parsed.whole ? turnStart(canonical) : null;
  run.admitting.listedModels = parsed.models;
  run.admitting.laneServed = run.lane === null && laneServes(snapshot, chain, protocol, run.deps.clock());

  // The key's model scope. A key restricted to some models must allow every model the request lists, not
  // only the one it is served by: which one serves is decided later, by supply the customer does not control.
  for (const model of chain) {
    const scope = modelScopeRefusal(key, model);
    if (scope !== null) return refuse(run, scope, "model_scope");
  }
  let candidates: number;
  try {
    candidates = outputCandidateCount(protocol, parsed.value);
  } catch {
    return refuse(run, new ApiError(400, "invalid_protocol_request"), "parse");
  }
  // The request's preference layered over the defaults its key and its workspace set (`layered_preference`):
  // a request narrows them and never widens them; a stored default this gateway cannot read refuses the
  // request (503), since an organization's constraint is never silently dropped.
  run.admitting.admission = "preference";
  const own = run.routing.preference;
  const layer = (index: number) => layeredOver(snapshot, key.routing ?? null, key.workspaceId, own, chain[index]!, tagged.tags[index] ?? null);
  const layered = layer(0);
  if (!layered.ok) return refuse(run, unreadableDefault(layered.code), "preference");
  run.routing.preference = layered.preference;
  run.routing.preferenceRecord = preferenceFacts(layered.preference, layered.sources);
  // The routing record's preference by level, of each model the request lists: its routes, its tag.
  const levelsOf = (index: number) => preferenceLevels(snapshot, key.routing ?? null, key.workspaceId, own, chain[index]!, protocol, tagged.tags[index] ?? null);
  // docs/design/one-address.md: a request that reached the VM through Gray's API had its TLS ended at Cloudflare, so
  // nothing here verifies it end to end; a verifiable preference is refused before anything is admitted or sent.
  if (run.lane?.arrival === "gray_api" && layered.preference.verifiable) return refuse(run, verifiableViaApi(new URL(run.request.url).origin), "preference");
  // Patterns are resolved against one model's routes: a request that states any is layered again for each
  // later model it lists.
  const preferences = [layered.preference];
  if (tagged.tags.length > 0 || layered.preference.resolvedForModel()) {
    for (let index = 1; index < chain.length; index++) {
      const later = layer(index);
      if (!later.ok) return refuse(run, unreadableDefault(later.code), "preference");
      preferences.push(later.preference);
    }
  }
  // No route of this gateway is verifiable but in lane mode: a `verifiable` request is answered here, before any
  // route is looked at, translated or admitted (`verifiableUpFront`), and tries no next model.
  const upFront = verifiableUpFront(run.lane !== null, snapshot, registeredOf(snapshot), layered.preference, chain, protocol, true, run.deps.clock());
  if (upFront !== null) return refuse(run, atEntry(run, unadmitted(upFront).error), "preference");
  // An older client's chat at this address, with no verifiable preference (refused just above, never forwarded), for a
  // model the confidential entry serves on this API (`entryServes`): the entry serves it, so it reaches every route
  // (docs/design/one-address.md). Not a model check, which the console sends for this gateway's own route, not a body
  // that states `provider` (the entry takes it out as a declared rewrite, but a relay stack's VM does so only from the
  // stack release that has the rule, so until every stack VM runs one such a request stays here), not a body that states
  // `routing` (the entry takes none out and refuses it, 400 naming the header: docs/utility-routing.md "Request
  // parameters"; the header goes on with the request), and not a model the entry has no route of here (the entry never
  // forwards a request back): those are answered here as before.
  const entry = run.deps.entryChat;
  if (run.lane === null && entry !== undefined && !run.routing.stripProvider && !run.routing.stripRouting && ticketHeader(run.request.headers) === null && entryServesChain(snapshot, chain, protocol)) return forwardToEntry(run, entry, body);
  // At the entry nothing is forwarded (docs/design/standard-media-at-entry.md section 2.9): a request for models the
  // entry has no route of, and translates onto none, gets the entry's own answer below (resolution.ts `unrouted`).
  // A ModelTrace probe is a model check only with the ticket the console signed for it (`takeModelCheck`). It checks one
  // route: its own preference names that endpoint alone, with fallbacks refused, for one model; the stored defaults
  // layered over it only narrow it. Anything else is refused before anything is held or sent.
  const checked = await takeModelCheck(run, snapshot, key, own, parsed.models, body);
  if (checked !== null) return checked;

  // The ranking base every model's ranking reads, refreshed first when the isolate has none it can use.
  await refreshedRanking(run);

  // Each model is tried only after the one before it had no eligible provider or failed every attempt it
  // was allowed, in the customer's order and never another (forward_traced). The last model's refusal is
  // the answer, and none is tried once the request's time has run out: a later model has what is left of it.
  const deadline = requestDeadline(run, bodyRead);
  let refused: Response | null = null;
  let turn: { readonly parsed: ParsedRequest; readonly canonical: CanonicalRequest } = { parsed, canonical };
  for (let index = 0; index < chain.length; index++) {
    if (index > 0 && run.deps.clock() >= deadline) break;
    const last = index === chain.length - 1;
    const model = chain[index]!;
    beginModel(run, index, model, last);
    run.routing.preference = preferences[index] ?? run.routing.preference;
    run.routing.preferenceLevels = levelsOf(index);
    if (index > 0) {
      const again = await forModel(run, body, model);
      if (again instanceof ApiError) {
        run.log.deferRecord = false;
        return refuse(run, again, "parse");
      }
      turn = again;
    }
    const served = await serveModel(run, snapshot, key, turn.parsed, body, turn.canonical, candidates, bodyRead);
    // A model pinned to the endpoint that holds a Responses continuation failed there: the continuation
    // stays with that endpoint, and the request ends. A model with no route there was never pinned.
    if (served.kind === "response" || run.admitting.pinned || last) {
      flushRecord(run);
      return served.response;
    }
    refused = served.response;
    endModel(run);
  }
  // The request's time ran out before the next model: the last refusal is the answer.
  flushRecord(run);
  return refused!;
}

/**
 * Before the request ranks (Option B of the ranking freshness change; production lane-bridge, Z16: requests served without
 * their floor read a base 98.8 s to 114.9 s old): when the isolate's ranking base cannot serve (none, one past
 * CONFIG_ALERT_AGE_MS, or one without the roots' records), the request waits for one (snapshot.ts `refreshRanking`)
 * before every read of it, the formula's routes, the constraints and its session's route (`utilityRoutesOf`) among them.
 * At most RANKING_WAIT_MS, and never into the share of the pre budget the account admission needs: one whole admit
 * attempt (ACCOUNT_ADMIT_ATTEMPT_MS, at most ACCOUNT_ADMIT_BUDGET_MS) stays for it, so a slow bridge never turns into a
 * 503 `billing_admission_unavailable`; with less left the request does not wait at all. It does not wait either while a
 * wait cannot bring a base (the source's syncs with the collector fail, its answers carry no roots' records, or a
 * request's wait ended without a base in the last RANKING_AHEAD_MS: `SnapshotCache.waitsForRanking`), so in an outage a
 * request asks nothing more and pays nothing for it. A base that does not come leaves the request ranked as before,
 * without the checks that read the feed (ranking.ts says so). The main gateway and the entry share this path and the
 * isolate's cache.
 */
async function refreshedRanking(run: IntakeRun): Promise<void> {
  const { cfg, clock } = run.deps;
  const now = clock();
  if (run.deps.snapshots.fed(now)) return;
  const reserveMs = Math.min(cfg.accountAdmitAttemptMs, cfg.accountAdmitBudgetMs);
  const waitMs = Math.min(RANKING_WAIT_MS, run.budget.preLeft() - reserveMs);
  const timing = run.deps.waitTimers === undefined ? snapshotTiming(cfg) : { ...snapshotTiming(cfg), timers: run.deps.waitTimers };
  const refreshed = await run.deps.snapshots.refreshRanking(run.deps.source, timing, now, (p) => run.ctx.waitUntil(p), waitMs, (call) => run.outbound.run(call));
  run.routing.rankingWaitMs = refreshed.waited ? Math.max(0, clock() - now) : 0;
}

/**
 * `verifiable_routes_at_lane` names the confidential entry's address when this gateway forwards chat there
 * (LANE_ENTRY_ORIGIN); every other refusal, and that one without the setting, is the catalog's.
 */
export function atEntry(run: IntakeRun, error: ApiError): ApiError {
  const entry = run.deps.entryChat;
  if (entry === undefined || error.code !== "verifiable_routes_at_lane") return error;
  return error.withMessage(
    `The routing preference \`verifiable: true\` asks for verifiable routes, which are served only at Gray's confidential VM address, ${entry.origin}, not at this one. Send the request there.`,
  );
}

/**
 * The request goes to the confidential entry as the client sent it (docs/design/one-address.md): the same method, path
 * and query (a client's base URL included), the body bytes read here (a spooled body read back as it streams), the
 * client's headers but the hop-by-hop, address, proxy and Gray's own, and this gateway's `x-gray-api-forward` mark.
 * The entry admits, bills, records and answers it; its answer streams back as it came. This gateway keeps no record
 * of it (the entry's is the request's one record: two would list one request twice) and counts nothing against the
 * key: it lets go of what the request holds here, its content unwritten. An entry that does not answer is the
 * client's 502 `upstream_unavailable`, recorded here as a failure: nothing was billed.
 *
 * Until the entry has the body, a spooled one is kept: its delete waits on `relayed` (`authorized`), which settles
 * once the entry read the stream to its end or its answer ended, whichever is first (an entry that refuses before it
 * reads needs no more of it). Until the answer has reached the client, or the client left, the request counts as in
 * flight here (`load`), as an answer this gateway serves itself does.
 */
export async function forwardToEntry(run: IntakeRun, entry: EntryChatForward, body: Body): Promise<Response> {
  const url = new URL(run.request.url);
  const target = new URL(`${url.pathname}${url.search}`, entry.origin);
  const headers = forwardedRequestHeaders(run.request.headers);
  let bodyDone!: () => void;
  run.answer.relayed = new Promise<void>((resolve) => (bodyDone = resolve));
  let payload: BodyInit | null;
  if (body.tier === "C") {
    const opened = await spoolOpener(run, body)();
    payload = opened === null ? null : endingWith(opened, bodyDone);
    if (opened === null) bodyDone();
    headers.set("content-length", String(body.length));
  } else {
    payload = body.bytes;
    bodyDone();
  }
  let answer: Response;
  try {
    headers.set(API_FORWARD_HEADER, await entry.mark({ method: run.request.method, host: target.host, pathAndQuery: `${target.pathname}${target.search}` }, run.deps.clock()));
    // Not followed (`redirect: "manual"`), and ended with the client's request (docs/cloudflare-native.md 5.6).
    answer = await entry.fetch(
      new Request(target, { method: run.request.method, headers, body: payload, redirect: "manual", signal: run.request.signal, ...(payload instanceof ReadableStream ? { duplex: "half" } : {}) } as RequestInit),
    );
  } catch (error) {
    bodyDone();
    console.error(JSON.stringify({ level: "error", event: "lane_entry_unreachable", request_id: run.requestId, error: error instanceof Error ? error.message : String(error) }));
    return refuse(run, entryUnreachable(), "preference");
  }
  if (!entryAnswerUsable(answer)) {
    bodyDone();
    await answer.body?.cancel().catch(() => undefined);
    console.error(JSON.stringify({ level: "error", event: "lane_entry_unreachable", request_id: run.requestId, status: answer.status }));
    return refuse(run, entryUnreachable(), "preference");
  }
  // Its place in the count is given back once, by whoever took the request's end (`forwarded`, or `record` before it).
  const counted = forwarded(run);
  console.log(JSON.stringify({ level: "info", event: "chat_forwarded_to_entry", request_id: run.requestId, status: answer.status }));
  return forwardedAnswer(answer, () => {
    bodyDone();
    if (counted) run.deps.load.leave();
  });
}

/**
 * A request the entry answered (`forwardToEntry`): what it holds here is let go, and nothing is recorded or counted
 * against its key. Its place in the isolate's count (`load`) is given back when the forwarded answer ends.
 */
export function forwarded(run: IntakeRun): boolean {
  if (run.log.recorded) return false;
  run.log.recorded = true;
  run.log.pendingRecord = null;
  run.answer.pendingErrorBody = null;
  run.log.deferRecord = false;
  run.caller.rateOpen = false;
  for (const release of run.facts.holds) release();
  run.answerShare.release();
  run.facts.content?.discard();
  run.facts.requestBody = null;
  run.retained.set("request_body", 0);
  return true;
}

/**
 * Whether the request is a model check (`modelCheck`; model-check.ts; docs/model-authenticity-workflow.md, "Probes are
 * not billed", decided with the user on 2026-11-04), once its body is read and its preference taken: a request without
 * a ticket header is served as before, and nothing is asked. A ticket that fails a check before its one-time id
 * (`checkTicket`) makes an ordinary request, said at warn level with its reason only (`model_check_ticket_refused`).
 * One that passes them must pin one route (else 400 `model_check_unpinned`, its id unused). On the main gateway it is
 * then a model check: the main gateway keeps no record of the ids used (decided with the user on 2026-11-05;
 * model-check.ts says why). On the lane entry its id is used in the bridge's record within what the pre phase leaves:
 * not fresh, an ordinary request (`reused`, or the record's own refusal); the record not answering (a throw, no answer
 * in that time, no record at all) or full, 503 `billing_admission_unavailable` with `retry-after: 1`, never free (the
 * console sends the probe again with a new ticket). Null: go on, a model check or not; else the request's answer.
 */
export async function takeModelCheck(run: IntakeRun, snapshot: GatewaySnapshot, key: KeyRecord, own: Preference, models: readonly string[], body: Body): Promise<Response | null> {
  const ticket = ticketHeader(run.request.headers);
  if (ticket === null) return null;
  const checked = await checkTicket({
    ticket,
    keys: snapshot.modelCheckKeys,
    workspace: key.workspaceId,
    own,
    body,
    now: run.deps.clock(),
    // On the main gateway a model check comes over the console's service binding, never from the internet: Cloudflare
    // sets cf-connecting-ip on every request from the internet and a client cannot take it off (decided with the user
    // on 2026-11-03). The lane entry is reached over the internet by design.
    serviceBinding: run.lane === null ? !run.request.headers.has("cf-connecting-ip") : null,
  });
  if (!checked.ok) {
    ticketRefused(run, checked.reason);
    return null;
  }
  if (!modelCheckPinned(own, models, snapshot)) return refuse(run, modelCheckUnpinned(), "preference");
  // The main gateway asks no record (decided with the user on 2026-11-05): a ticket reaches it only over the console's
  // service binding, the one binding of its default entrypoint, and the console signs a new ticket for every request.
  if (run.lane === null) {
    run.caller.modelCheck = true;
    return null;
  }
  const store = run.io.modelCheckTickets;
  if (store === null) return ticketStoreUnavailable(run, "no_store");
  let outcome: TicketUseOutcome;
  try {
    outcome = await withinPhase(store.use(checked.id, checked.expiresAtMs), run.budget.preWait(run.deps.cfg.accountAdmitAttemptMs), run.deps.waitTimers ?? run.deps.timers ?? platformTimers);
  } catch {
    return ticketStoreUnavailable(run, "unanswered");
  }
  // Only a fresh id makes a model check; a full record is one that cannot remember (review r8 minor 6).
  const verdict = ticketUseVerdict(outcome);
  if (verdict.kind === "unavailable") return ticketStoreUnavailable(run, verdict.reason);
  if (verdict.kind === "refused") {
    ticketRefused(run, verdict.reason);
    return null;
  }
  run.caller.modelCheck = true;
  return null;
}

/**
 * The lane entry's record of used tickets made no answer the request can use (none configured, none in time, full):
 * 503 `billing_admission_unavailable`, never free, said at warn level with why.
 */
export function ticketStoreUnavailable(run: IntakeRun, reason: TicketStoreUnavailable): Response {
  console.warn(JSON.stringify(laneSafeLog({ level: "warn", event: "model_check_ticket_store_unavailable", request_id: run.requestId, reason })));
  return refuse(run, admissionUnavailable(), "preference");
}

/** A ticket that made no model check, said with its reason and the request's id only: never the ticket or any of its claims. */
export function ticketRefused(run: IntakeRun, reason: TicketRefusal): void {
  const line = { level: "warn", event: "model_check_ticket_refused", request_id: run.requestId, reason };
  console.warn(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
}

/**
 * The request as its client would have sent it for `model`, a later model it listed (`Call::for_model`):
 * its body parsed again, without `models`, and naming `model`, so that every check reads the model it is
 * served as (the tool gate refuses a request whose body names another model than the one it is served as,
 * `trust_request_model_mismatch`). The upstream body gets the route's own model either way. A tier C body
 * is scanned again from R2, as its first parse was.
 */
export async function forModel(run: IntakeRun, body: Body, model: string): Promise<{ readonly parsed: ParsedRequest; readonly canonical: CanonicalRequest } | ApiError> {
  const { cfg } = run.deps;
  const protocol = run.protocol;
  // The first parse read Gray's own members; this one only leaves them out (`without_gray_members`), as the first
  // left them out of the body every later model is parsed from.
  const take = (value: Json): null => {
    withoutGrayMembers(value);
    return null;
  };
  const parsed = body.tier === "C" ? await spoolRead(run, () => parseStored(protocol, spoolOpener(run, body), cfg.bodyParseMaxBytes, run.facts.pathModel, cfg.bodyRawMaxBytes, take)) : parseHeld(protocol, body.tier, body.bytes, run.facts.pathModel, undefined, take);
  if (parsed instanceof ApiError) return parsed;
  if (isObject(parsed.value)) (parsed.value as JsonObject).model = model;
  const canonical: CanonicalRequest = protocol === "gemini" ? { ...parsed.canonical, stream: geminiStream(run.path) } : parsed.canonical;
  return { parsed, canonical: { ...canonical, model } };
}
