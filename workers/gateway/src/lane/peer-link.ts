import { parseStrict } from "@gray/json";
import { aciJson } from "./receipts.ts";
import type { PeerChannel } from "./peer-client.ts";
import {
  PEER_ATTACH_HEADERS,
  PEER_ATTACH_PATH,
  PEER_RELAYS_PREFIX,
  channelKeyset,
  PEER_TUNNEL_PREFIX,
  PeerSessions,
  isKeysetDigest,
  isRelayId,
  readAttach,
  type AttachRefusal,
  type KeysetPin,
  type LiveSession,
  type PeerSessionsDeps,
  type SessionChanges,
} from "./peer-attach.ts";

/**
 * The entry's three public routes of the outbound-only channel (docs/design/relay-outbound-only.md sections 3.5, 5):
 *
 * - `GET /v1/peer/attach` (WebSocket): a stack VM's peerlink attaches a session; `PeerSessions` decides, then the
 *   upgrade goes to the entry's peerlink (`/attach` on its unix socket) and its un-accepted WebSocket is returned as it
 *   is, so workerd pumps the two sockets natively and no JavaScript runs per message (X-O3);
 * - `GET /v1/peer/tunnel/<relay>[?keyset=<digest>]` (WebSocket, public, R3): gray-relay, a customer or Gray's tools run
 *   TLS through it to the VM's workerd; the entry picks a session and hands the upgrade to peerlink's `/tunnel`; it
 *   carries bytes only (O7). `?keyset=` names one boot: while an image rollout runs two instances of the relay's app,
 *   gray-relay reaches each of its replicas' VMs by it. Without it, the relay's newest boot (docs/design/relay-zero-
 *   downtime.md): its newest pinned one, else (a VM that just started) peerlink's newest unverified session;
 * - `GET /v1/peer/relays/<relay>/healthz` (public, R4): the VM's own `/healthz` through egress's pinned stream, with
 *   `x-gray-peer-keyset` and `x-gray-peer-sessions`;
 * - `GET /v1/peer/relays/<relay>/boots` (public): every boot of the relay with a session, newest first: its keyset, app
 *   and instance ids, relay image, sessions, open streams, and whether it is ready (pinned, usable, holding the relay's
 *   sealed credentials). The provisioner's image rollout reads it to know the new instance serves and the old one has
 *   drained; gray-relay reads it to find a new instance's boot to seal beside the one it serves.
 *
 * peerlink's unix socket (the workerd `external` service `PEERLINK`) also serves the lane's session control, as PR #377's
 * `deploy/tee/peerlink/README.md` ("Interface") defines it: `GET /v1/sessions` (its table),
 * `POST /v1/sessions/<id>/promote` and `DELETE /v1/sessions/<id>`.
 */

/** The entry's peerlink on its unix socket, as the lane's `PEERLINK` service binding names it. */
export const PEERLINK_ORIGIN = "http://peerlink";

/** The header the lane adds to an attach it forwards: the state peerlink records the session in. */
export const PEER_SESSION_STATE_HEADER = "x-gray-peer-state";

/** The client's WebSocket handshake headers, and nothing else of its request. */
function upgradeHeaders(request: Request): Headers {
  const headers = new Headers();
  for (const name of ["upgrade", "connection", "sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions"]) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  return headers;
}

export interface PeerLinkDeps extends Omit<PeerSessionsDeps, "pinOf"> {
  /** The PEERLINK binding's fetch. */
  readonly peerlink: (request: Request) => Promise<Response>;
  /** The EGRESS binding's fetch (the health route's pinned stream). */
  readonly egress: (input: string, init: RequestInit) => Promise<Response>;
  /** This boot's TLS SPKI SHA-256 (`TLS_SPKI_SHA256`): what a VM's attach must name. */
  readonly entrySpki: string;
  /** This boot's keyset digest, for the ACI headers of the answers. */
  readonly keysetDigest: string;
  /** The registry's pin of (relay, keyset), or null. */
  readonly pinOf: (relay: string, keyset: string) => KeysetPin | null;
  /** What the registry knows of one boot (`PeerRegistry.bootOf`), for the boots route. */
  readonly bootOf?: (relay: string, keyset: string) => { readonly appId: string | null; readonly instanceId: string | null; readonly relayImage: string | null; readonly usable: boolean; readonly sealed: boolean | null } | null;
}

/** The entry's channel: its sessions and its three routes; the registry's `PeerChannel`. */
export class PeerLink implements PeerChannel {
  readonly #deps: PeerLinkDeps;
  readonly sessions: PeerSessions;

  constructor(deps: PeerLinkDeps) {
    this.#deps = deps;
    this.sessions = new PeerSessions({ clock: deps.clock, isStackRelay: deps.isStackRelay, stackRelays: deps.stackRelays, pinOf: deps.pinOf, log: deps.log });
  }

  /** Whether `path` is one of the channel's routes. */
  static handles(path: string): boolean {
    return path === PEER_ATTACH_PATH || path.startsWith(PEER_TUNNEL_PREFIX) || path.startsWith(PEER_RELAYS_PREFIX);
  }

  /** One request on a channel route. */
  async route(request: Request, url: URL): Promise<Response> {
    const path = url.pathname;
    if (request.method !== "GET") return this.#error(405, "peer_method_not_allowed", "Only GET is served here.", { allow: "GET" });
    if (path === PEER_ATTACH_PATH) return this.attach(request, url);
    if (path.startsWith(PEER_TUNNEL_PREFIX)) {
      const relay = path.slice(PEER_TUNNEL_PREFIX.length);
      // `?keyset=` takes the digest as 64 hex or as `sha256:<hex>`. Without one, the relay's newest pinned boot: while an
      // image rollout runs two instances, the new one (docs/design/relay-zero-downtime.md); with none pinned, peerlink's
      // newest unverified session (a VM that just started, which gray-relay attests itself).
      const asked = url.searchParams.get("keyset");
      const keyset = asked === null ? null : channelKeyset(asked);
      if (!isRelayId(relay) || (keyset !== null && !isKeysetDigest(keyset))) return this.#error(404, "peer_relay_unknown", "No relay by that name is routed here.");
      return this.tunnel(request, relay, keyset ?? this.#newestPinned(relay) ?? undefined);
    }
    const rest = path.slice(PEER_RELAYS_PREFIX.length);
    const slash = rest.indexOf("/");
    const relay = slash < 0 ? rest : rest.slice(0, slash);
    if (slash < 0 || !isRelayId(relay)) return this.#error(404, "not_found", "No such route.");
    if (rest.slice(slash) === "/healthz") return this.health(relay);
    if (rest.slice(slash) === "/boots") return this.boots(relay);
    return this.#error(404, "not_found", "No such route.");
  }

  /** The relay's newest boot with a pinned session (64 hex), or null. */
  #newestPinned(relay: string): string | null {
    return this.sessions.keysetsOf(relay).find((row) => row.pinned > 0)?.keyset ?? null;
  }

  /** `GET /v1/peer/attach` (section 3.5). */
  async attach(request: Request, url: URL): Promise<Response> {
    if (!isUpgrade(request)) return this.#error(426, "peer_upgrade_required", "Attach with a WebSocket upgrade.", { upgrade: "websocket" });
    const read = readAttach(request.headers, url.hostname, this.#deps.entrySpki);
    if (read === null) return this.#error(400, "peer_attach_invalid", "The attach headers are missing or malformed.");
    if (!this.#deps.isStackRelay(read.claims.relay)) return this.#error(404, "peer_relay_unknown", "No relay by that name is routed here.");
    const synced = await this.sync();
    if (!synced) return this.#error(503, "peer_link_unavailable", "The entry cannot take sessions right now; try again shortly.");
    const verdict = await this.sessions.admit(read.claims, read.signature);
    if (!verdict.ok) return this.#error(verdict.status, verdict.code, ATTACH_MESSAGES[verdict.code]);
    const headers = upgradeHeaders(request);
    for (const name of [PEER_ATTACH_HEADERS.relay, PEER_ATTACH_HEADERS.keyset, PEER_ATTACH_HEADERS.session]) headers.set(name, request.headers.get(name)!);
    // The verdict is the lane's alone: whatever the VM sent under this name is not forwarded.
    headers.set(PEER_SESSION_STATE_HEADER, verdict.state);
    // The un-accepted WebSocket peerlink answers is returned as it is: workerd pumps it (X-O3).
    return this.#deps.peerlink(new Request(`${PEERLINK_ORIGIN}/v1/attach`, { method: "GET", headers }));
  }

  /**
   * `GET /v1/peer/tunnel/<relay>` (section 5). peerlink picks the session (a pinned one, of `keyset` when given, else
   * the newest unverified one) and holds the 16 tunnels per relay atomically with its table; its refusals
   * (`503 peer_session_missing`, `429 peer_tunnel_busy`, `503 peer_session_refused`, `{"error": "<code>"}`) reach the
   * caller as peerlink gave them.
   */
  async tunnel(request: Request, relay: string, keyset?: string): Promise<Response> {
    if (!isUpgrade(request)) return this.#error(426, "peer_upgrade_required", "Open the tunnel with a WebSocket upgrade.", { upgrade: "websocket" });
    if (!this.#deps.isStackRelay(relay)) return this.#error(404, "peer_relay_unknown", "No relay by that name is routed here.");
    const headers = upgradeHeaders(request);
    headers.set(PEER_ATTACH_HEADERS.relay, relay);
    if (keyset !== undefined) headers.set(PEER_ATTACH_HEADERS.keyset, keyset);
    try {
      return await this.#deps.peerlink(new Request(`${PEERLINK_ORIGIN}/v1/tunnel`, { method: "GET", headers }));
    } catch {
      return this.#error(503, "peer_link_unavailable", "The entry cannot open tunnels right now; try again shortly.");
    }
  }

  /** `GET /v1/peer/relays/<relay>/healthz` (section 5, fault test 13). */
  async health(relay: string): Promise<Response> {
    if (!this.#deps.isStackRelay(relay)) return this.#error(404, "peer_relay_unknown", "No relay by that name is routed here.");
    if (!(await this.sync())) return this.#error(503, "peer_link_unavailable", "The entry cannot reach its sessions right now; try again shortly.");
    const keyset = this.sessions.keysetsOf(relay).find((row) => row.pinned > 0 && this.#deps.pinOf(relay, row.keyset) !== null);
    if (keyset === undefined) return this.#error(503, "peer_session_missing", "The relay's stack VM is not connected to this entry right now.");
    let answer: Response;
    try {
      answer = await this.#deps.egress(`http://egress/peer/${keyset.keyset}/healthz`, { method: "GET" });
    } catch {
      return this.#error(502, "peer_health_failed", "The relay's stack VM did not answer its health check.");
    }
    const headers = new Headers({ "content-type": answer.headers.get("content-type") ?? "application/json", "cache-control": "no-store" });
    headers.set("x-gray-peer-keyset", keyset.keyset);
    headers.set("x-gray-peer-sessions", String(keyset.pinned));
    if (answer.status !== 200) return this.#error(502, "peer_health_failed", "The relay's stack VM did not answer its health check.", { "x-gray-peer-keyset": keyset.keyset, "x-gray-peer-sessions": String(keyset.pinned) });
    return new Response(answer.body, { status: 200, headers });
  }

  /**
   * `GET /v1/peer/relays/<relay>/boots` (docs/design/relay-zero-downtime.md): every boot of the relay with a session,
   * newest first. Counts and public values only (keyset digests and app ids are in every receipt and attestation).
   */
  async boots(relay: string): Promise<Response> {
    if (!this.#deps.isStackRelay(relay)) return this.#error(404, "peer_relay_unknown", "No relay by that name is routed here.");
    if (!(await this.sync())) return this.#error(503, "peer_link_unavailable", "The entry cannot reach its sessions right now; try again shortly.");
    const boots = this.sessions.keysetsOf(relay).map((row) => {
      const known = this.#deps.bootOf?.(relay, row.keyset) ?? null;
      const usable = known !== null && known.usable && row.pinned > 0;
      return {
        keyset: row.keyset,
        app_id: known?.appId ?? null,
        instance_id: known?.instanceId ?? null,
        relay_image: known?.relayImage ?? null,
        first_seen_ms: row.firstSeenMs,
        sessions: { pinned: row.pinned, unverified: row.unverified },
        streams: row.streams,
        sealed: known?.sealed ?? null,
        ready: usable && known.sealed === true,
      };
    });
    return aciJson(200, { relay_id: relay, boots }, this.#deps.keysetDigest, { "cache-control": "no-store" });
  }

  /** Reads peerlink's table into the sessions, and closes the unverified sessions held too long. False when peerlink did not answer. */
  async sync(): Promise<boolean> {
    let rows: LiveSession[];
    try {
      const answer = await this.#deps.peerlink(new Request(`${PEERLINK_ORIGIN}/v1/sessions`, { method: "GET" }));
      if (answer.status !== 200) return false;
      rows = readSessions(await answer.text());
    } catch {
      return false;
    }
    const strangers = this.sessions.sync(rows);
    const closed = [...strangers, ...this.sessions.expired()];
    if (strangers.length > 0) this.#deps.log({ level: "warn", event: "lane_peer_session_unknown", sessions: strangers.length });
    if (closed.length > 0) await this.apply({ promoted: [], closed });
    return true;
  }

  /** The registry pinned (relay, keyset): promote its signed sessions, close the rest. */
  async pinned(relay: string, keyset: string, pin: KeysetPin): Promise<SessionChanges> {
    const changes = await this.sessions.promote(relay, keyset, pin);
    await this.apply(changes);
    return changes;
  }

  /** The registry refused (relay, keyset): close its sessions, refuse it `forMs` (5 min by default). */
  async refused(relay: string, keyset: string, forMs?: number): Promise<SessionChanges> {
    const changes = this.sessions.refuse(relay, keyset, forMs);
    await this.apply(changes);
    return changes;
  }

  /** Egress reported `peer_pin_mismatch` on `session`: close that session only. */
  async mismatch(session: string): Promise<void> {
    await this.apply(this.sessions.condemn(session));
  }

  /** Every (relay, keyset) with a session (the registry's channel peers, `PeerChannel`). */
  keysets(): readonly { readonly relay: string; readonly keyset: string }[] {
    const seen = new Map<string, { relay: string; keyset: string }>();
    for (const session of this.sessions.sessions) seen.set(`${session.relay}\n${session.keyset}`, { relay: session.relay, keyset: session.keyset });
    return [...seen.values()];
  }

  hasPinnedSession(relay: string, keyset: string): boolean {
    return this.sessions.hasPinnedSession(relay, keyset);
  }

  pinWanted(relay: string, keyset: string): boolean {
    return this.sessions.pinWanted(relay, keyset);
  }

  bornOf(relay: string, keyset: string): number | null {
    return this.sessions.firstSeenOf(relay, keyset);
  }

  /** Tells peerlink the promotions and closes. A failure is logged; the next sync shows what peerlink holds. */
  async apply(changes: SessionChanges): Promise<void> {
    const calls: Promise<unknown>[] = [];
    for (const id of changes.promoted) calls.push(this.#control("POST", `${id}/promote`));
    for (const id of changes.closed) calls.push(this.#control("DELETE", id));
    await Promise.all(calls);
  }

  async #control(method: "POST" | "DELETE", path: string): Promise<void> {
    try {
      const answer = await this.#deps.peerlink(new Request(`${PEERLINK_ORIGIN}/v1/sessions/${path}`, { method }));
      if (answer.status >= 300 && answer.status !== 404) this.#deps.log({ level: "error", event: "lane_peerlink_control_failed", method, status: answer.status });
    } catch {
      this.#deps.log({ level: "error", event: "lane_peerlink_control_failed", method });
    }
  }

  /**
   * A refusal before any upgrade: `{"error": "<code>", "message": "..."}`. The code is what gray-relay's tunnel
   * transport and peerlink read (`error` as a string, as the lane's other control answers); the message is for a person.
   */
  #error(status: number, code: string, message: string, extra: Record<string, string> = {}): Response {
    return aciJson(status, { error: code, message }, this.#deps.keysetDigest, extra);
  }
}

const ATTACH_MESSAGES: Readonly<Record<AttachRefusal, string>> = {
  peer_relay_unknown: "No relay by that name is routed here.",
  peer_keyset_refused: "This boot's attestation was refused recently; it is not accepted for a few minutes.",
  peer_attach_forged: "The attach is not signed by this boot's receipt key, is too old, or names another entry.",
  peer_attach_busy: "Too many sessions are attached for this relay; try again later.",
};

function isUpgrade(request: Request): boolean {
  return request.headers.get("upgrade")?.toLowerCase() === "websocket";
}

/** peerlink's `GET /v1/sessions` body, read strictly: rows with a bad field are dropped. */
export function readSessions(text: string): LiveSession[] {
  const parsed = parseStrict(text) as unknown;
  const rows = Array.isArray(parsed) ? parsed : typeof parsed === "object" && parsed !== null && Array.isArray((parsed as { sessions?: unknown }).sessions) ? (parsed as { sessions: unknown[] }).sessions : null;
  if (rows === null) throw new Error("peerlink sessions: not a list");
  const out: LiveSession[] = [];
  for (const row of rows) {
    if (typeof row !== "object" || row === null) continue;
    // `{id, relay, keyset, state, opened_ms, streams}` (PR #377); `state` and `opened_ms` are the lane's own to know.
    const { id, relay, keyset, streams } = row as Record<string, unknown>;
    const count = typeof streams === "bigint" ? Number(streams) : (streams ?? 0);
    if (typeof id !== "string" || typeof relay !== "string" || typeof keyset !== "string" || typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) continue;
    out.push({ session: id, relay, keyset, tunnels: count });
  }
  return out;
}
