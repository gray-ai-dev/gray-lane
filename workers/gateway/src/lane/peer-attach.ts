import { bytesToLowerHex, ed25519Verify, jcsBytes, lowerHexBytes } from "@gray/attest";
import { LANE_RELAY_ID_PATTERN } from "@gray/control";
import { base64Url, base64UrlBytes } from "@gray/lane-wire";

/**
 * The entry's side of the outbound-only channel (docs/design/relay-outbound-only.md sections 3.5, 3.6 and 5): which
 * WebSocket session a stack VM's peerlink attached belongs to which relay and boot, and whether it may carry requests.
 *
 * A session is attached with `GET /v1/peer/attach` and four headers (`PEER_ATTACH_HEADERS`): the relay, the VM's keyset
 * digest (its boot), the session id the VM's lane chose, the time the VM signed, and the Ed25519 signature of that
 * keyset's receipt key over `"gray-lane-attach/v1\n" ‖ JCS{relay, keyset, entry, entry_spki, session, issued_ms}`.
 *
 * `PeerSessions` decides each attach before the upgrade reaches peerlink (section 3.5):
 *
 * - a relay the snapshot does not route to a stack VM: 404 `peer_relay_unknown`;
 * - a keyset refused within the last 5 min: 403 `peer_keyset_refused`;
 * - a pinned keyset: the signature must verify under the pin's receipt key, `issued_ms` be within 10 min and
 *   `entry_spki` be this boot's (else 403 `peer_attach_forged`); the session is then `pinned`;
 * - a keyset not pinned: the session is `unverified`, at most 2 per relay (else 429 `peer_attach_busy`), kept 60 s for
 *   the registry to attest over it; when the attestation succeeds its signature is checked and it is promoted, when it
 *   fails it is closed and the keyset refused for 5 min (30 s, `peer.ts` LIST_REREAD_MS, when it failed only because
 *   the list did not name its release: the registry reads the list again before refusing, at most that often);
 * - at most 4 sessions per (relay, keyset) and 4 × stack relays + 64 in all (else 429 `peer_attach_busy`).
 *
 * peerlink holds the sessions themselves (the WebSocket, yamux, the streams); the lane learns which are still open from
 * peerlink's table (`sync`) before each decision, so a closed session never counts against a cap.
 */

/** The domain line the attach signature starts with. */
export const PEER_ATTACH_DOMAIN = "gray-lane-attach/v1\n";

/** The attach route, the tunnel route's prefix and the health route's prefix on the entry (sections 3.5 and 5). */
export const PEER_ATTACH_PATH = "/v1/peer/attach";
export const PEER_TUNNEL_PREFIX = "/v1/peer/tunnel/";
export const PEER_RELAYS_PREFIX = "/v1/peer/relays/";

/**
 * The headers of an attach, as peerlink (PR #377, `deploy/tee/peerlink/README.md` "Interface") sends them: the keyset
 * as its digest's 64 lowercase hex (no `sha256:`), `issued_ms` in decimal, and the signature as unpadded base64url.
 */
export const PEER_ATTACH_HEADERS = Object.freeze({
  relay: "x-gray-peer-relay",
  keyset: "x-gray-peer-keyset",
  session: "x-gray-peer-session",
  issued: "x-gray-peer-issued",
  signature: "x-gray-peer-attach",
});

/** Section 3.5's bounds. */
export const PEER_ATTACH_LIMITS = Object.freeze({
  /** How old a signed attach may be. */
  issuedMaxAgeMs: 10 * 60_000,
  /** Unverified sessions one relay may hold. */
  unverifiedPerRelay: 2,
  /** How long an unverified session waits for the registry's attestation. */
  unverifiedMs: 60_000,
  /** How long a keyset whose attestation failed is refused. */
  refusedMs: 5 * 60_000,
  /** Sessions per (relay, keyset). */
  perKeyset: 4,
  /** Sessions in all: `perStackRelay` × stack relays + `totalSlack`. */
  perStackRelay: 4,
  totalSlack: 64,
  /** Open tunnels per relay (section 5). */
  tunnelsPerRelay: 16,
  /** A pin with no session for this long ends (section 3.5, O6). */
  pinIdleMs: 60_000,
});

/** The signed facts of one attach. */
export interface AttachClaims {
  readonly relay: string;
  /** The VM's current keyset digest as 64 lowercase hex (the channel's form; the registry's is `sha256:<hex>`). */
  readonly keyset: string;
  /** The entry name the VM dialed (`lane.usefallback.com`). */
  readonly entry: string;
  /** The entry's TLS SPKI SHA-256 the VM observed and pinned, 64 lowercase hex. */
  readonly entry_spki: string;
  /** 32 lowercase hex digits, chosen by the VM's lane per session slot. */
  readonly session: string;
  readonly issued_ms: number;
}

/** The snapshot's own relay id rule (`@gray/control`), so every routed relay can attach. */
const RELAY_ID = LANE_RELAY_ID_PATTERN;
const KEYSET = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SESSION = /^[0-9a-f]{32}$/;
/** 64 bytes as unpadded base64url. */
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const ISSUED = /^[0-9]{1,15}$/;

/** Whether `value` is a relay id as the snapshot names them. */
export function isRelayId(value: string): boolean {
  return RELAY_ID.test(value);
}

/** Whether `value` is a keyset digest in the channel's form (64 lowercase hex). */
export function isKeysetDigest(value: string): boolean {
  return KEYSET.test(value);
}

/** The channel's keyset form (64 hex) of a registry digest (`sha256:<hex>`), or the value as it is. */
export function channelKeyset(digest: string): string {
  return digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
}

/** The bytes the attach signature covers. */
export function attachMessage(claims: AttachClaims): Uint8Array {
  const body = jcsBytes({ relay: claims.relay, keyset: claims.keyset, entry: claims.entry, entry_spki: claims.entry_spki, session: claims.session, issued_ms: BigInt(claims.issued_ms) });
  const domain = new TextEncoder().encode(PEER_ATTACH_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain);
  out.set(body, domain.length);
  return out;
}

/** The VM's lane signs one attach with its keyset's receipt key (`LaneProcessState.signer`). */
export async function signAttach(signer: { sign(message: Uint8Array): Promise<Uint8Array> }, claims: AttachClaims): Promise<string> {
  return base64Url(await signer.sign(attachMessage(claims)));
}

/** Whether `signature` (unpadded base64url) verifies over `claims` under one of `publicKeys` (64 hex each). */
export async function verifyAttach(publicKeys: readonly string[], claims: AttachClaims, signature: string): Promise<boolean> {
  if (!SIGNATURE.test(signature)) return false;
  const message = attachMessage(claims);
  const sig = base64UrlBytes(signature);
  if (sig === null || sig.length !== 64) return false;
  for (const key of publicKeys) {
    const bytes = HEX64.test(key) ? lowerHexBytes(key) : null;
    if (bytes !== null && (await ed25519Verify(bytes, message, sig))) return true;
  }
  return false;
}

/** An attach's headers, read strictly: null when one is missing or malformed. `entry` is the host the VM dialed. */
export function readAttach(headers: Headers, entry: string, entrySpki: string): { readonly claims: AttachClaims; readonly signature: string } | null {
  const relay = headers.get(PEER_ATTACH_HEADERS.relay);
  const keyset = headers.get(PEER_ATTACH_HEADERS.keyset);
  const session = headers.get(PEER_ATTACH_HEADERS.session);
  const issued = headers.get(PEER_ATTACH_HEADERS.issued);
  const signature = headers.get(PEER_ATTACH_HEADERS.signature);
  if (relay === null || keyset === null || session === null || issued === null || signature === null) return null;
  if (!RELAY_ID.test(relay) || !KEYSET.test(keyset) || !SESSION.test(session) || !ISSUED.test(issued) || !SIGNATURE.test(signature)) return null;
  return { claims: { relay, keyset, entry, entry_spki: entrySpki, session, issued_ms: Number(issued) }, signature };
}

/** One row of peerlink's session table (`GET /v1/sessions`: `{id, relay, keyset, state, opened_ms, streams}`). */
export interface LiveSession {
  readonly session: string;
  readonly relay: string;
  readonly keyset: string;
  /** Open streams on this session (requests and tunnels). */
  readonly tunnels: number;
}

export type SessionState = "unverified" | "pinned";

export interface PeerSession {
  readonly session: string;
  readonly relay: string;
  readonly keyset: string;
  state: SessionState;
  readonly attachedMs: number;
  readonly claims: AttachClaims;
  readonly signature: string;
  tunnels: number;
  /** Whether peerlink's table has listed it (until then it is pending, PENDING_MS at most). */
  seen: boolean;
}

/** How long an admitted session may be missing from peerlink's table before it counts as gone: the upgrade's way. */
export const PENDING_MS = 10_000;

/** A keyset pinned by the registry: its receipt keys (64 hex each) and how long the pin holds. */
export interface KeysetPin {
  readonly receiptKeys: readonly string[];
  readonly notAfterMs: number;
}

export interface PeerSessionsDeps {
  readonly clock: () => number;
  /** Whether the snapshot routes to `relay` as a stack relay. */
  readonly isStackRelay: (relay: string) => boolean;
  /** How many stack relays the snapshot names (the total cap). */
  readonly stackRelays: () => number;
  /** The registry's pin of (relay, keyset), or null. */
  readonly pinOf: (relay: string, keyset: string) => KeysetPin | null;
  readonly log: (line: Record<string, unknown>) => void;
}

/** An attach's verdict: forward it to peerlink in `state`, or refuse it. */
export type AttachVerdict = { readonly ok: true; readonly state: SessionState } | { readonly ok: false; readonly status: 403 | 404 | 429; readonly code: AttachRefusal };

export type AttachRefusal = "peer_relay_unknown" | "peer_keyset_refused" | "peer_attach_forged" | "peer_attach_busy";

/** What `promote` and `refuse` ask peerlink to do. */
export interface SessionChanges {
  readonly promoted: readonly string[];
  readonly closed: readonly string[];
}

/** The sessions of one entry boot (section 3.5). */
export class PeerSessions {
  readonly #deps: PeerSessionsDeps;
  readonly #sessions = new Map<string, PeerSession>();
  readonly #refused = new Map<string, number>();
  /** When each (relay, keyset) last had a session: its pin ends `pinIdleMs` after (O6). */
  readonly #lastSeen = new Map<string, number>();
  /**
   * When each (relay, keyset) first attached since it last went `pinIdleMs` without a session: the boot's age as this
   * entry boot knows it (docs/design/relay-zero-downtime.md, the order of two boots of one relay).
   */
  readonly #firstSeen = new Map<string, number>();

  constructor(deps: PeerSessionsDeps) {
    this.#deps = deps;
  }

  /**
   * peerlink's table: a session peerlink no longer holds is forgotten (one admitted within PENDING_MS may not be in it
   * yet: the upgrade is still on its way), and the tunnel counts are peerlink's. Returns the sessions peerlink holds
   * that this boot never admitted (the lane restarted under them, or they differ from what was admitted): the caller
   * closes them, and the VM redials with freshly signed attaches.
   */
  sync(live: readonly LiveSession[]): readonly string[] {
    const now = this.#deps.clock();
    const open = new Map(live.map((row) => [row.session, row]));
    const strangers: string[] = [];
    for (const row of live) {
      const known = this.#sessions.get(row.session);
      if (known === undefined || known.relay !== row.relay || known.keyset !== row.keyset) strangers.push(row.session);
    }
    for (const [id, session] of this.#sessions) {
      const row = open.get(id);
      if (row === undefined) {
        if (session.seen || now - session.attachedMs >= PENDING_MS) this.#sessions.delete(id);
        continue;
      }
      if (row.relay !== session.relay || row.keyset !== session.keyset) {
        this.#sessions.delete(id);
        continue;
      }
      session.seen = true;
      session.tunnels = row.tunnels;
      this.#lastSeen.set(pairKey(session.relay, session.keyset), now);
    }
    return strangers;
  }

  /** Section 3.5's checks for one attach. Admitted sessions are recorded; peerlink is told their state. */
  async admit(claims: AttachClaims, signature: string): Promise<AttachVerdict> {
    const { clock, isStackRelay, stackRelays, pinOf } = this.#deps;
    const now = clock();
    if (!isStackRelay(claims.relay)) return { ok: false, status: 404, code: "peer_relay_unknown" };
    const refusedUntil = this.#refused.get(pairKey(claims.relay, claims.keyset));
    if (refusedUntil !== undefined) {
      if (now < refusedUntil) return { ok: false, status: 403, code: "peer_keyset_refused" };
      this.#refused.delete(pairKey(claims.relay, claims.keyset));
    }
    // A redial of a slot replaces its old session (the old one is closed by then or about to be).
    const previous = this.#sessions.get(claims.session);
    if (previous !== undefined && (previous.relay !== claims.relay || previous.keyset !== claims.keyset)) return { ok: false, status: 403, code: "peer_attach_forged" };
    const others = [...this.#sessions.values()].filter((s) => s.session !== claims.session);
    const total = others.length;
    if (total >= PEER_ATTACH_LIMITS.perStackRelay * stackRelays() + PEER_ATTACH_LIMITS.totalSlack) return this.#busy(claims, "total");
    if (others.filter((s) => s.relay === claims.relay && s.keyset === claims.keyset).length >= PEER_ATTACH_LIMITS.perKeyset) return this.#busy(claims, "keyset");
    const pin = pinOf(claims.relay, claims.keyset);
    let state: SessionState;
    if (pin !== null && now < pin.notAfterMs) {
      if (!(await this.#signed(claims, signature, pin, now))) {
        this.#deps.log({ level: "warn", event: "lane_peer_attach_refused", relay: claims.relay, keyset_digest: claims.keyset, code: "peer_attach_forged" });
        return { ok: false, status: 403, code: "peer_attach_forged" };
      }
      state = "pinned";
    } else {
      this.#expire(now);
      const unverified = others.filter((s) => s.relay === claims.relay && s.state === "unverified").length;
      if (unverified >= PEER_ATTACH_LIMITS.unverifiedPerRelay) return this.#busy(claims, "unverified");
      state = "unverified";
    }
    this.#sessions.set(claims.session, { session: claims.session, relay: claims.relay, keyset: claims.keyset, state, attachedMs: now, claims, signature, tunnels: 0, seen: false });
    if (this.firstSeenOf(claims.relay, claims.keyset) === null) this.#firstSeen.set(pairKey(claims.relay, claims.keyset), now);
    this.#lastSeen.set(pairKey(claims.relay, claims.keyset), now);
    this.#deps.log({ level: "info", event: "lane_peer_attached", relay: claims.relay, keyset_digest: claims.keyset, session: claims.session, state });
    return { ok: true, state };
  }

  /**
   * The registry pinned (relay, keyset) by an attestation over one of its sessions: each unverified session of it whose
   * signature verifies under the pin is promoted, any other is closed (a liar that guessed the digest).
   */
  async promote(relay: string, keyset: string, pin: KeysetPin): Promise<SessionChanges> {
    const now = this.#deps.clock();
    const promoted: string[] = [];
    const closed: string[] = [];
    for (const session of this.#sessions.values()) {
      if (session.relay !== relay || session.keyset !== keyset || session.state !== "unverified") continue;
      if (await this.#signed(session.claims, session.signature, pin, now)) {
        session.state = "pinned";
        promoted.push(session.session);
      } else closed.push(session.session);
    }
    for (const id of closed) this.#sessions.delete(id);
    if (closed.length > 0) this.#deps.log({ level: "warn", event: "lane_peer_attach_refused", relay, keyset_digest: keyset, code: "peer_attach_forged", sessions: closed.length });
    return { promoted, closed };
  }

  /**
   * The registry's attestation of (relay, keyset) failed: its sessions are closed and the keyset refused for `forMs`,
   * 5 min by default; the registry passes its LIST_REREAD_MS (`peer.ts`) for a boot refused only because the list does
   * not name its release yet, so its redial is attested again once the list may be read again.
   */
  refuse(relay: string, keyset: string, forMs: number = PEER_ATTACH_LIMITS.refusedMs): SessionChanges {
    const now = this.#deps.clock();
    this.#refused.set(pairKey(relay, keyset), now + forMs);
    const closed: string[] = [];
    for (const session of this.#sessions.values()) if (session.relay === relay && session.keyset === keyset) closed.push(session.session);
    for (const id of closed) this.#sessions.delete(id);
    this.#deps.log({ level: "error", event: "lane_peer_refused", relay, keyset_digest: keyset, code: "peer_keyset_refused", sessions: closed.length, refused_ms: forMs });
    return { promoted: [], closed };
  }

  /** A pin mismatch on a stream of `session` (section 3.5): that session is condemned, the pin stays. */
  condemn(session: string): SessionChanges {
    const known = this.#sessions.get(session);
    if (known === undefined) return { promoted: [], closed: [] };
    this.#sessions.delete(session);
    this.#deps.log({ level: "warn", event: "lane_peer_session_condemned", relay: known.relay, keyset_digest: known.keyset, session });
    return { promoted: [], closed: [session] };
  }

  /** Unverified sessions held past `unverifiedMs` without an attestation: to close. */
  expired(): readonly string[] {
    return this.#expire(this.#deps.clock());
  }

  /**
   * The keysets of `relay` that have sessions, the newest boot first (first seen, then latest attach), each with its
   * sessions by state, its open streams (peerlink's count at the last sync: requests and tunnels) and when it was first
   * seen.
   */
  keysetsOf(relay: string): readonly { readonly keyset: string; readonly pinned: number; readonly unverified: number; readonly streams: number; readonly firstSeenMs: number }[] {
    const by = new Map<string, { keyset: string; pinned: number; unverified: number; streams: number; firstSeenMs: number; newest: number }>();
    for (const s of this.#sessions.values()) {
      if (s.relay !== relay) continue;
      const row = by.get(s.keyset) ?? { keyset: s.keyset, pinned: 0, unverified: 0, streams: 0, firstSeenMs: this.firstSeenOf(relay, s.keyset) ?? s.attachedMs, newest: 0 };
      if (s.state === "pinned") row.pinned += 1;
      else row.unverified += 1;
      row.streams += s.tunnels;
      row.newest = Math.max(row.newest, s.attachedMs);
      by.set(s.keyset, row);
    }
    return [...by.values()]
      .sort((a, b) => b.firstSeenMs - a.firstSeenMs || b.newest - a.newest)
      .map(({ keyset, pinned, unverified, streams, firstSeenMs }) => ({ keyset, pinned, unverified, streams, firstSeenMs }));
  }

  /** When (relay, keyset) first attached, or null when it has had no session within `pinIdleMs` (it is forgotten). */
  firstSeenOf(relay: string, keyset: string): number | null {
    const key = pairKey(relay, keyset);
    if (!this.pinWanted(relay, keyset)) {
      this.#firstSeen.delete(key);
      return null;
    }
    return this.#firstSeen.get(key) ?? null;
  }

  /** Whether (relay, keyset) has a pinned session now (routing prefers such a peer; O5). */
  hasPinnedSession(relay: string, keyset: string): boolean {
    for (const s of this.#sessions.values()) if (s.relay === relay && s.keyset === keyset && s.state === "pinned") return true;
    return false;
  }

  /** Whether the pin of (relay, keyset) may stay: a session now, or one within `pinIdleMs` (O6). */
  pinWanted(relay: string, keyset: string): boolean {
    const seen = this.#lastSeen.get(pairKey(relay, keyset));
    return seen !== undefined && this.#deps.clock() - seen < PEER_ATTACH_LIMITS.pinIdleMs;
  }

  /** The sessions held (for `/healthz` and tests). */
  get sessions(): readonly PeerSession[] {
    return [...this.#sessions.values()];
  }

  async #signed(claims: AttachClaims, signature: string, pin: KeysetPin, now: number): Promise<boolean> {
    if (Math.abs(now - claims.issued_ms) > PEER_ATTACH_LIMITS.issuedMaxAgeMs) return false;
    return verifyAttach(pin.receiptKeys, claims, signature);
  }

  #expire(now: number): string[] {
    const out: string[] = [];
    for (const s of this.#sessions.values()) if (s.state === "unverified" && now - s.attachedMs >= PEER_ATTACH_LIMITS.unverifiedMs) out.push(s.session);
    for (const id of out) this.#sessions.delete(id);
    return out;
  }

  #busy(claims: AttachClaims, cap: string): AttachVerdict {
    this.#deps.log({ level: "warn", event: "lane_peer_attach_busy", relay: claims.relay, keyset_digest: claims.keyset, cap });
    return { ok: false, status: 429, code: "peer_attach_busy" };
  }
}

function pairKey(relay: string, keyset: string): string {
  return `${relay}\n${keyset}`;
}

/** A random session id (16 bytes, 32 lowercase hex). */
export function newSessionId(): string {
  return bytesToLowerHex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Whether `value` is a session id. */
export function isSessionId(value: string): boolean {
  return SESSION.test(value);
}

/** Whether `value` is 64 lowercase hex (an SPKI SHA-256). */
export function isSpkiHex(value: string): boolean {
  return HEX64.test(value);
}
