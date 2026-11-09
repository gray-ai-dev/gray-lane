import type { GatewayConfig } from "@gray/config";
import { parseStrict, type Json } from "@gray/json";
import { requestLimit } from "@gray/limits";
import { encodePeerAttemptsAnswer, encodePeerDebugAnswer, encodePeerDebugRefusal, PEER_DEBUG_PREFIX, PEER_DEBUG_REFUSAL_STATUS, PEER_HEADER, peerRequestIdOf, type PeerDebugRefusalCode } from "@gray/lane-wire";
import { readBody } from "../body.ts";
import { platformTimers, type StreamTimers } from "../client.ts";
import { servedProtocol } from "../paths.ts";
import { trustGate } from "../trust.ts";
import { peerRefusal, serveBackend } from "./backend.ts";
import { bridgeFetch, stackTransportOf, type LaneEnv, type LaneIsolate } from "./deps.ts";
import { BridgePeerVerifier, PEER_HELLO_REFUSAL_STATUS, PeerAttempts, PeerState, peerListKeys, verifyEntryReport } from "./peer.ts";
import { BackgroundClient } from "./remote/background.ts";
import type { LaneProcessState } from "./state.ts";
import { aciJson } from "./receipts.ts";
import { stackDebugOf } from "./stack-debug.ts";
import type { CapturedCall } from "./stack-debug-record.ts";

/**
 * The peer routes of a stack VM in backend mode (docs/confidential-lane-stack-routing.md sections 4.3, 4.5, 4.6), on
 * its one 443 socket beside the routes it serves everyone:
 *
 * - `GET /v1/peer/challenge` → `{nonce}`; `POST /v1/peer/hello {nonce, report}` → `{entry, not_after_ms}`;
 * - `GET /v1/peer/attempts/<rid>` (enveloped under the follow-up's domain line) → the attempts answer;
 * - `POST /v1/peer/debug/<rid>` (enveloped under the debug hop's domain line) → the attempt's debug share
 *   (docs/design/relay-debug-sharing.md §4, `stack-debug.ts`);
 * - an inference path with `x-gray-peer` → checks 1 to 6, then the attempt's frames (`backend.ts`).
 *
 * Backend mode is on in the relay-stack layout when the VM has the environment's list public keys
 * (`LANE_RELEASE_PUBLIC_KEY`, `LANE_RELEASE_FRESHNESS_PUBLIC_KEY`, measured literals of the stack compose); without them
 * these routes are the lane's 404, and in the default layout they always are: an entry is never a backend.
 */

export const PEER_PREFIX = "/v1/peer/";
export const PEER_CHALLENGE_PATH = "/v1/peer/challenge";
export const PEER_HELLO_PATH = "/v1/peer/hello";
export const PEER_ATTEMPTS_PREFIX = "/v1/peer/attempts/";

/** The largest hello body: one ACI report with its event log (about 30 KiB measured) and the nonce, with room. */
export const PEER_HELLO_MAX_BYTES = 1024 * 1024;

/** One backend per boot state: the peer state, the list refresh its hellos read, and the timers its answers run on. */
export interface Backend {
  readonly peer: PeerState;
  readonly verifier: Pick<BridgePeerVerifier, "refresh">;
  readonly timers: StreamTimers;
}

const backends = new WeakMap<LaneProcessState, Backend>();
let keysProblemLogged = false;

/**
 * The boot's backend, made at the first peer call, or null when this VM is no backend (the default layout, or no list
 * keys). Malformed keys leave it off and are logged once (the names, never a value).
 */
export function backendOf(state: LaneProcessState, env: LaneEnv & Readonly<Record<string, unknown>>, cfg: GatewayConfig): Backend | null {
  if (state.stack === null) return null;
  const known = backends.get(state);
  if (known !== undefined) return known;
  const keys = peerListKeys(env);
  if (typeof keys === "string") {
    if (!keysProblemLogged) console.error(`lane backend mode refused: ${keys}`);
    keysProblemLogged = true;
    return null;
  }
  if (keys === null) return null;
  const background = new BackgroundClient({ baseUrl: state.bridgeUrl, keyId: state.laneKeyId, signingKey: state.bridgeSigner, fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv), now: state.now });
  const verifier = new BridgePeerVerifier(background, keys, state.now);
  const peer = new PeerState({ keysetDigest: state.keysetDigest, verify: (report, nonce) => verifyEntryReport(report, nonce, verifier, state.now), now: state.now, attemptsMs: cfg.streamTotalSeconds * 1000 });
  const backend = { peer, verifier, timers: platformTimers };
  backends.set(state, backend);
  return backend;
}

/** Whether `request` is the peer hop's (a peer path, or an inference path with an envelope). */
export function isPeerRequest(request: Request, path: string): boolean {
  return path.startsWith(PEER_PREFIX) || request.headers.has(PEER_HEADER);
}

/** One peer request of a backend; `ctx` runs the attempt and the list's refresh after the answer opens. */
export async function peerRoute(request: Request, env: LaneEnv, cfg: GatewayConfig, state: LaneProcessState, backend: Backend, isolate: LaneIsolate, path: string, ctx: ExecutionContext): Promise<Response> {
  const { peer, verifier } = backend;
  // The default list is kept current in the background (section 4.2), so a hello rarely waits for a read.
  ctx.waitUntil(verifier.refresh());
  if (path === PEER_CHALLENGE_PATH) {
    if (request.method !== "GET") return methodNotAllowed(state, "GET");
    return aciJson(200, { nonce: peer.challenge() }, state.keysetDigest);
  }
  if (path === PEER_HELLO_PATH) {
    if (request.method !== "POST") return methodNotAllowed(state, "POST");
    return hello(request, cfg, state, peer);
  }
  if (path.startsWith(PEER_DEBUG_PREFIX)) {
    if (request.method !== "POST") return methodNotAllowed(state, "POST");
    const checked = await peer.checkDebug(request.headers.get(PEER_HEADER));
    if (!checked.ok) return debugRefusal(checked.code);
    if (checked.envelope.rid !== path.slice(PEER_DEBUG_PREFIX.length)) return debugRefusal("peer_malformed");
    const store = stackDebugOf(state, env as LaneEnv & Readonly<Record<string, unknown>>, cfg);
    if (store === null) return debugRefusal("debug_unsupported");
    const granted = await store.grant(checked.envelope);
    ctx.waitUntil(store.report());
    if (!granted.ok) return debugRefusal(granted.code);
    return new Response(encodePeerDebugAnswer(granted.share), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  if (path.startsWith(PEER_ATTEMPTS_PREFIX)) {
    if (request.method !== "GET") return methodNotAllowed(state, "GET");
    const checked = await peer.check(request.headers.get(PEER_HEADER), "attempts");
    if (!checked.ok) return peerRefusal(checked.code);
    if (checked.envelope.rid !== path.slice(PEER_ATTEMPTS_PREFIX.length)) return peerRefusal("peer_malformed");
    const answer = peer.attempts.answer(PeerAttempts.key(checked.envelope), state.now());
    return new Response(encodePeerAttemptsAnswer({ state: answer.state, receipt: answer.receipt as Record<string, unknown> | null }), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  const served = servedProtocol(request.method, path);
  if (served === null || served.protocol === "gemini" || path.startsWith(PEER_PREFIX)) return peerRefusal("peer_malformed");
  const checked = await peer.check(request.headers.get(PEER_HEADER), "request");
  if (!checked.ok) return peerRefusal(checked.code);
  const protocol = served.protocol;
  // The lane's body cap (as `InferenceRun.receive` reads a lane body): no spool, the bytes held whole.
  const cap = Math.min(Number(requestLimit(protocol)), state.timing.bodyMaxBytes, cfg.bodyParseMaxBytes);
  const read = await readBody(request, { protocol, limit: cap, parseMax: cfg.bodyParseMaxBytes, rawMax: cap, waitMs: cfg.requestBodyMs }, undefined);
  // A body that cannot be read whole is not the one the envelope names.
  if (!read.ok || read.body.tier === "C" || !peer.bodyMatches(checked.envelope, read.body.bytes)) return peerRefusal("peer_body_mismatch");
  return serveBackend({
    request,
    protocol,
    path,
    envelope: checked.envelope,
    body: read.body.bytes,
    cfg,
    state,
    relayImage: state.stackConfig.relayImage ?? null,
    config: state.stackConfig.current(ctx),
    transport: stackTransportOf(env.RELAY, env.EGRESS).stackTransport,
    peer,
    gate: trustGate(cfg),
    share: isolate.load.answers.share(),
    clock: state.now,
    timers: backend.timers,
    waitUntil: (promise) => ctx.waitUntil(promise),
    // Gray's request id, for the console's account of a violation only (docs/design/relay-ejection.md section 3).
    violation: (found) => state.stackConfig.violation?.(found, peerRequestIdOf(request.headers), ctx),
    ...debugCapture(state, env, cfg),
  });
}

/** `POST /v1/peer/hello`: `{nonce, report}`, read within PEER_HELLO_MAX_BYTES by the strict reader. */
async function hello(request: Request, cfg: GatewayConfig, state: LaneProcessState, peer: PeerState): Promise<Response> {
  const refused = (code: keyof typeof PEER_HELLO_REFUSAL_STATUS): Response => aciJson(PEER_HELLO_REFUSAL_STATUS[code], { code }, state.keysetDigest);
  const read = await readBody(request, { protocol: "anthropic_messages", limit: PEER_HELLO_MAX_BYTES, parseMax: PEER_HELLO_MAX_BYTES, rawMax: PEER_HELLO_MAX_BYTES, waitMs: cfg.requestBodyMs }, undefined);
  if (!read.ok || read.body.tier === "C") return refused("peer_malformed");
  let value: Json;
  try {
    value = parseStrict(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(read.body.bytes));
  } catch {
    return refused("peer_malformed");
  }
  const body = value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Readonly<Record<string, Json>>) : null;
  if (body === null || Object.keys(body).some((key) => key !== "nonce" && key !== "report") || body.report === undefined) return refused("peer_malformed");
  const accepted = await peer.hello(body.nonce, body.report);
  if (!accepted.ok) return refused(accepted.code);
  return aciJson(200, { entry: accepted.entry, not_after_ms: accepted.notAfterMs }, state.keysetDigest);
}

/** The debug store's capture of a backend call (docs/design/relay-debug-sharing.md §2), when this VM can share one. */
function debugCapture(state: LaneProcessState, env: LaneEnv, cfg: GatewayConfig): { readonly debug?: (call: CapturedCall) => void } {
  const store = stackDebugOf(state, env as LaneEnv & Readonly<Record<string, unknown>>, cfg);
  return store === null || store.relayKey === null ? {} : { debug: (call) => store.capture(call) };
}

function debugRefusal(code: PeerDebugRefusalCode): Response {
  return new Response(encodePeerDebugRefusal(code), { status: PEER_DEBUG_REFUSAL_STATUS[code], headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

function methodNotAllowed(state: LaneProcessState, allow: string): Response {
  return aciJson(405, { error: "METHOD_NOT_ALLOWED" }, state.keysetDigest, { allow });
}
