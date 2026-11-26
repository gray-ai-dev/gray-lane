/**
 * Whether a request's body fits where an attempt would send it (`InferenceRun`, inference.ts): the request's own limit,
 * a stack relay's and its VM's, the peer hop's bytes, and the body a confidential-lane relay is forwarded or translated.
 */
import { ApiError } from "@gray/errors";
import { type Json, isObject, readSerdeBytes } from "@gray/json";
import { requestLimit } from "@gray/limits";
import type { Protocol, ScrubSpan } from "@gray/protocol";
import { bodyTooLarge } from "../body.ts";
import type { Route } from "../routes.ts";
import type { RouteRecord } from "../snapshot.ts";
import { toolIdIsolate } from "../tool-ids.ts";
import { heldBody, storedBody, type BodyEdits } from "../upstream.ts";
import { forwardedBody, type Forwarded } from "../lane/hooks.ts";
import type { TranslatedApi } from "@gray/attest";
import { planRewrites } from "../lane/plan.ts";
import { ExpandedBodyTooLargeError, type ExpandZeroRetentionResult } from "../lane/responses-continuation.ts";
import { type GrayRewriteOp, type LaneProtocol, applyDeclaredChanges, checkOfficialUpstream, GRAY_LANE_TRANSLATION, GRAY_LANE_TRANSLATION_ID, translatedForwarded } from "@gray/lane";
import { overStackBody, STACK_BODY_MAX_BYTES, STACK_OVER_LIMIT_SKIP, VM_BODY_LIMIT_SOURCE } from "../lane/body-limits.ts";
import type { Dispatch, Prepared } from "./types.ts";
import { laneVendor, relayOf } from "./attempt-pure.ts";
import { laneVmBodyLimit, laneZdrExpansionFor } from "./zdr.ts";
import { entryPeers, laneEndpointRoute, stackRoute } from "./stack-routes.ts";
import { type StackPeerRun, peerHopBody } from "./stack-peer.ts";
import { laneAppendsFor, laneCodexRoute, laneStoreOffRoute } from "./lane-attempt.ts";
import { overlayFor } from "./attempt.ts";
import { spoolOpener } from "./request-body.ts";

/** What body-limits.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface BodyLimitsRun extends StackPeerRun {}

/**
 * Whether an attempt at `candidate` would be sent a body past its API's request limit, the originals
 * of the client's tool-call handles in it (`Attempts::admits`), measured on the bytes it is made of.
 */
export async function overRequestLimit(run: BodyLimitsRun, o: Dispatch, prepared: Prepared, candidate: Route): Promise<boolean> {
  // A lane route forwards the bytes its declared ops and the relay's appends make (design v2 §C.7,
  // M4): the client's body is never sent as it is, so the length checked is that body's. The bytes
  // are the same object `send` sends, out of the one cache, so the check and the Content-Length
  // cannot disagree.
  // A stack relay's container is sent the client's own bytes (S23), or their zero-retention expansion, which
  // admission did not measure (GL-29).
  if (stackRoute(run, candidate.record)) return overStackLimit(run, candidate.record, o, prepared.protocol);
  const laneForwards = run.lane === null || (candidate.record.auth !== "lane_relay" && !laneEndpointRoute(run, candidate.record)) ? null : await laneForwardedFor(run, candidate, prepared, o);
  if (laneForwards !== null) {
    if (!laneForwards.ok) {
      if (laneForwards.error.code !== "request_body_limit") return false;
      run.zdr.bodyLimitRefusal = laneForwards.error;
      return true;
    }
    // What the route is sent goes through Gray's confidential VM and its egress, which hold no more than the lane's
    // cap: a body the declared ops or the appends push past it is too large for the route, as at a stack route.
    const cap = laneVmBodyLimit(run, prepared.protocol);
    if (laneForwards.bytes.length <= cap) return false;
    overVmLimit(run, prepared.protocol, cap);
    return true;
  }
  const ids = run.facts.toolIds;
  if (ids === null || ids.keys === null || ids.resolution.resolved.size === 0) return false;
  const master = await run.deps.master();
  if (master === null) return false;
  const issuer = await (run.deps.toolIds ?? toolIdIsolate).issuer(ids.keys, candidate.record, master);
  if (!ids.restores(issuer, prepared.protocol)) return false;
  const overlay = overlayFor(run, o, prepared, candidate.record);
  const change = bodyEdits(prepared.removals, ids.forAttempt(issuer, prepared.protocol));
  const length = run.facts.translation === null && o.body.tier === "C" ? storedBody(spoolOpener(run, o.body), o.body.length, o.parsed.layout!, overlay, change).length : heldBody(prepared.body!, prepared.layout, overlay, undefined, change).length;
  return length > Number(requestLimit(prepared.protocol));
}

/**
 * Whether a stack route would be sent a body past the lane's 4 MiB (relay standard v1.7 section 4): the client's
 * bytes, or their zero-retention expansion for the route. `stackPlan` and `peerPlan` refuse the same body; this
 * passes the route over before it takes a permit, as too small for the body.
 */
export function overStackLimit(run: BodyLimitsRun, route: RouteRecord, o: Dispatch, protocol: Protocol): boolean {
  const received = run.laneRelays.laneReceived;
  if (received === null) return false;
  let expansion: ExpandZeroRetentionResult | null;
  try {
    expansion = laneZdrExpansionFor(run, route, o.parsed.value, STACK_BODY_MAX_BYTES);
  } catch (error) {
    if (!(error instanceof ExpandedBodyTooLargeError)) throw error;
    overVmLimit(run, protocol, error.limitBytes);
    return true;
  }
  const baseBytes = expansion?.changed ? expansion.expandedBytes : received;
  // The hop is composed (and cached for the attempt) only for a base that fits.
  const hopLen = overStackBody(baseBytes.length) ? null : (peerHopBytes(run, route, baseBytes, o.parsed.value)?.length ?? null);
  if (!overStackBody(baseBytes.length, hopLen)) return false;
  overVmLimit(run, protocol, STACK_BODY_MAX_BYTES);
  return true;
}

/**
 * On an entry, the bytes its hop to `route`'s stack VM would carry for `baseBytes` (`peerHopBody`, out of its cache, so
 * the attempt sends what admission measured); null on a stack VM, or for a route `peerPlan` passes over for another
 * reason (no official upstream, a protocol the hop does not serve, ops that do not apply).
 */
export function peerHopBytes(run: BodyLimitsRun, route: RouteRecord, baseBytes: Uint8Array, value: Json): Uint8Array | null {
  const lane = route.lane;
  if (entryPeers(run) === null || lane === undefined || lane === null) return null;
  const official = checkOfficialUpstream(route.url);
  const protocol = route.protocol;
  if (!official.ok || (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses")) return null;
  return peerHopBody(run, protocol, lane.relayId, laneVendor(official.vendor), baseBytes, value)?.bytes ?? null;
}

/**
 * Notes the 413 of a route the body is too large for in Gray's confidential VM (`limitBytes`), and gives the label
 * the route is passed over with: `request_body_limit`, which the request stops with when no other route is left.
 */
export function overVmLimit(run: BodyLimitsRun, protocol: Protocol, limitBytes: number): typeof STACK_OVER_LIMIT_SKIP {
  run.zdr.bodyLimitRefusal = bodyTooLarge(protocol, limitBytes, VM_BODY_LIMIT_SOURCE);
  return STACK_OVER_LIMIT_SKIP;
}

/**
 * The bytes a lane attempt at `route` forwards, cached per `(relayId, appends)` across the request's
 * retries (design v2 §C.7, B5, M4). The appends are the relay's policy decision for this request;
 * a relay whose policy has not been asked yet (a candidate `otherOperator` is weighing) is composed
 * with no appends, which is the only body that can be composed before its module ran, and the
 * check is repeated once it did (`send` uses the refined cache entry).
 *
 * A refusal is Gray's own (a duplicate-key body, a `stream_options` that is not an object): the
 * route is passed over and the request ends with that error when no route is left, never sent.
 */
export async function laneForwardedFor(run: BodyLimitsRun, route: Route, prepared: Prepared, o: Dispatch): Promise<Forwarded | null> {
  const relayId = relayOf(route);
  const received = run.laneRelays.laneReceived;
  const decisions = run.laneRelays.laneDecisions;
  // An entry's endpoint route forwards Gray's declared ops alone (docs/design/lane-provider-routes.md section 5): it has
  // no relay and so no appends, and its receipt describes the bytes as for a relay's.
  const endpoint = route.record.auth !== "lane_relay";
  if ((relayId === null && !endpoint) || received === null || decisions === null) return null;
  // A translated request (`entryRules`: endpoint routes alone) forwards the declared translation of the client's bytes.
  if (run.facts.translation !== null) return endpoint ? laneTranslatedFor(run, route, received, o) : null;
  // A Gemini body goes as it came: the rewrite policy declares no Gemini op, and the request is refused at admission
  // when Gray would have to write its cap (`geminiCapRequired`). Its model is in the URL, never in the body.
  if (endpoint && prepared.protocol === "gemini") return { ok: true, bytes: received, events: [], applied: [] };
  const appends = relayId === null ? [] : await laneAppendsFor(run, relayId, prepared.protocol, o);
  const plan = planRewrites(decisions, route.record.upstreamModel, laneCodexRoute(run, route.record), laneStoreOffRoute(run, route.record));
  let expansion: ExpandZeroRetentionResult | null;
  try {
    expansion = laneZdrExpansionFor(run, route.record, o.parsed.value);
  } catch (error) {
    if (error instanceof ExpandedBodyTooLargeError) {
      return { ok: false, error: bodyTooLarge(prepared.protocol, error.limitBytes, VM_BODY_LIMIT_SOURCE) };
    }
    throw error;
  }
  const baseBytes = expansion?.changed ? expansion.expandedBytes : received;
  // F2 hooks-2: the key carries the route's upstream model too. Two models (a customer's fallback
  // list) or two endpoints of one relay (D13) with the same client cap and the same appends would
  // otherwise reuse the first route's composed bytes, so the vendor would be sent one model while
  // the scheduler and the receipt name another. The appends' full text, not its length, names them.
  // D129: and whether the route is the Codex backend or enforces `store: false`, so routes with
  // distinct zero-retention rewrites never share composed bytes.
  const key = `${relayId ?? "\u0001endpoint"}\u0000${route.record.upstreamModel}\u0000${plan.codex ? "codex" : ""}\u0000${plan.storeOff ? "store_off" : ""}\u0000${plan.cap === null ? "" : `${plan.cap.field}=${plan.cap.value}`}\u0000${expansion?.changed ? expansion.expandedBodySha256 : ""}\u0000${appends.map((a) => `${a.templateId}:${a.position}:${a.text}`).join("\u0001")}`;
  let forwarded = run.laneRelays.laneForwarded.get(key);
  if (forwarded === undefined) {
    const composed = forwardedBody(baseBytes, prepared.protocol, plan, appends);
    forwarded =
      composed.ok && expansion?.changed
        ? {
            ...composed,
            continuationExpanded: {
              previousResponseIdExpanded: expansion.previousResponseIdExpanded,
              itemReferencesExpanded: BigInt(expansion.itemReferencesExpanded),
              includeEncryptedReasoningAdded: expansion.includeEncryptedReasoningAdded,
              expandedBodySha256: expansion.expandedBodySha256,
            },
          }
        : composed;
    run.laneRelays.laneForwarded.set(key, forwarded);
  }
  return forwarded;
}

/**
 * The bytes a translated request forwards to an endpoint route at the entry, and the events that declare them
 * (docs/design/lane-provider-routes.md section 10; @gray/lane `translatedForwarded`, the function a verifier replays):
 * the client's bytes without the members the gateway took out of them (`remove_member /models`, `/provider`,
 * gray-lane-rewrites-v1), translated from the client's API to the route's with the cap Gray wrote, then the route's
 * upstream model (`set_member /model`, in the translation's own policy, gray-lane-translation-v2; a Gemini route names
 * it in its URL). The receipt names that translation, the one this gateway's @gray/protocol code writes. The bytes must
 * be the translated body this request was inspected, priced and held for (`Translation.body`) with the same model:
 * otherwise the receipt could not prove what was sent, and the attempt is refused, never sent. Cached per upstream
 * model.
 */
export function laneTranslatedFor(run: BodyLimitsRun, route: Route, received: Uint8Array, o: Dispatch): Forwarded {
  const t = run.facts.translation!;
  const model = route.record.upstreamModel;
  const key = `\u0002translated\u0000${model}`;
  const cached = run.laneRelays.laneForwarded.get(key);
  if (cached !== undefined) return cached;
  let client: Json;
  try {
    client = readSerdeBytes(received).value;
  } catch {
    return { ok: false, error: new ApiError(400, "invalid_json") };
  }
  const before: GrayRewriteOp[] = [];
  if (o.parsed.strip && isObject(client) && Object.hasOwn(client, "models")) before.push({ op: "remove_member", path: "/models" });
  if (run.routing.stripProvider && isObject(client) && Object.hasOwn(client, "provider")) before.push({ op: "remove_member", path: "/provider" });
  const after: GrayRewriteOp[] = t.upstream === "gemini" ? [] : [{ op: Object.hasOwn(t.body, "model") ? "set_member" : "insert_member", path: "/model", value: model }];
  const spec = { endpoint: run.path, from: t.client as TranslatedApi, to: t.upstream as TranslatedApi, declaredIn: GRAY_LANE_TRANSLATION_ID, ...(run.facts.translationCap === null ? {} : { outputCap: run.facts.translationCap }) };
  const replayed = translatedForwarded(received, spec, before, after, t.dropped);
  const own = after.length === 0 ? { ok: true as const, forwarded: t.upstreamBytes() } : applyDeclaredChanges(t.upstreamBytes(), t.upstream as LaneProtocol, { grayOps: after, appends: [], policy: GRAY_LANE_TRANSLATION });
  let forwarded: Forwarded;
  if (replayed.ok && own.ok && bytesEqual(replayed.forwarded, own.forwarded)) {
    forwarded = { ok: true, bytes: replayed.forwarded, events: [...replayed.events.before, replayed.events.translated, ...replayed.events.after], applied: [] };
  } else {
    // Gray's own failure: what the receipt's replay gives is not the body admission inspected. Content-free.
    console.error(JSON.stringify({ level: "error", event: "lane_translation_unreplayable", request_id: run.requestId, from: t.client, to: t.upstream, replayed: replayed.ok, rewritten: own.ok }));
    forwarded = { ok: false, error: new ApiError(500, "internal_error") };
  }
  run.laneRelays.laneForwarded.set(key, forwarded);
  return forwarded;
}

/** Whether two byte strings are the same. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * What an attempt changes in the client's bytes (upstream.ts `BodyEdits`): the request's own spans taken out
 * (`Prepared.removals`) and the attempt's tool-call ids (`forAttempt`), apart and in order. An id inside a span taken
 * out goes with it (a reasoning item carries none: the ids' sites are calls and their outputs).
 */
export function bodyEdits(removals: readonly ScrubSpan[], ids: BodyEdits | undefined): BodyEdits | undefined {
  if (removals.length === 0) return ids;
  const kept = (ids?.edits ?? []).filter((e) => !removals.some((r) => e.start < r.end && r.start < e.end));
  const edits = [...removals.map((r) => ({ start: r.start, end: r.end, text: "" })), ...kept].sort((a, b) => a.start - b.start);
  return { edits, value: ids?.value ?? null };
}
