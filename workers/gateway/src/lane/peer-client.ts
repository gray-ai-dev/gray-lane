import { bytesToLowerHex, jcsBytes, peerCommitment, sha256BareHex, type PeerFailedCode } from "@gray/attest";
import type { GatewayConfig } from "@gray/config";
import { get, isObject, parseSerde, parseStrict, toJsonString, type Json } from "@gray/json";
import { verifyPeerAttestation, type PeerReleaseList, type QuoteVerifier } from "@gray/lane-verify";
import {
  parsePeerAttemptsAnswer,
  parsePeerDebugAnswer,
  parsePeerDebugRefusal,
  parsePeerFrame,
  parsePeerRefusal,
  peerEnvelopeBytes,
  PEER_BUDGET_MAX_MS,
  PEER_DEBUG_PREFIX,
  PEER_HEADER,
  PEER_REQUEST_ID_HEADER,
  signPeerDebugEnvelope,
  signPeerEnvelope,
  stackTraceOf,
  type BridgeSigner,
  type PeerAttemptState,
  type PeerEndDto,
  type PeerEnvelopeDto,
  type PeerFrame,
  type PeerHeadDto,
  type PeerProtocol,
} from "@gray/lane-wire";
import { SseDecoder, SseFrames } from "@gray/protocol";
import type { StackTrace } from "@gray/request-index";
import type { StreamTimers } from "../client.ts";
import type { GatewaySnapshot } from "../snapshot.ts";
import { peerUsageOf } from "./backend.ts";
import { LIST_REREAD_MS, onlyListMiss, verifyWithReread } from "./peer.ts";
import {
  Peer,
  channelOrigin,
  peerKey,
  type LanePeerCall,
  type LanePeerRegistry,
  type PeerAttemptsReply,
  type PeerCallInput,
  type PeerDebugInput,
  type PeerDebugReply,
  type PeerPin,
  type PeerSent,
  type PeerTarget,
  type RouteLane,
  type StoredPeerAttempt,
} from "./peer-model.ts";

export { Peer, type PeerAttemptsReply, type PeerCallInput, type PeerPin, type PeerSent, type PeerStatus, type PeerTarget, type RouteLane, type StoredPeerAttempt } from "./peer-model.ts";

/**
 * An entry's side of the peer hop (docs/confidential-lane-stack-routing.md sections 4.3, 4.4, 4.7): which relay stack
 * VMs it may send content to, and one attempt's request over the hop.
 *
 * **The registry** (`PeerRegistry`) keeps one peer per (relay, keyset) of the sessions the stack relays' VMs hold to this
 * entry (docs/design/relay-outbound-only.md section 3), in one of five states:
 *
 * - `unverified`: nothing is known of its current boot; nothing is sent to it but the attestation request;
 * - `attesting`: the attestation request is out (egress's attest mode, no pin, WebPKI and the host name only);
 * - `pinned`: its report verified against the environment's signed stack list with `@gray/lane-verify` (DCAP, OS image,
 *   compose hash, a sealed relay identity naming the route's relay and its signing key, the TLS SPKI egress saw, the
 *   keyset's `not_after`), the pin is pushed to egress (`PUT /v1/peer/pins`), and the stack VM accepted this entry's hello;
 * - `refused`: the report did not verify, or the stack VM refused the hello; checked again PEER_RECHECK_MS later;
 * - `down`: a dial failed before a byte was sent; tried again after a backoff of PEER_DOWN_MS doubling to PEER_DOWN_MAX_MS
 *   (`@gray/config`'s rows, `PeerTiming`).
 *
 * A peer serves requests only while it is pinned, its pin and its hello are current and it is not down (L1). The work
 * that moves a peer between states (attest, pin, hello, probe) runs in the background of the lane's fetches, as the
 * route warm does (`warm.ts`): never inside a request's wait (L5), except the one hello row 8 of section 5 allows
 * after `401 peer_unknown`. A pin ends at its `not_after` (at most an hour, and never past the list's acceptance), at
 * the first dial whose SPKI differs (a reboot: `peer_pin_mismatch`), or at the first request the stack VM refuses for
 * the pin's keyset (a workerd restart within the boot: `peer_audience`); the peer is then unverified and attested again.
 *
 * **The attempt** (`PeerCall`) forwards the client's exact bytes with a signed envelope (`@gray/lane-wire` peer.ts) to a
 * pinned peer through egress (`/peer/<digest>/<path>`), and reads the answer's frames: a refusal before any frame, egress's
 * own failure (`x-gray-peer-sent`), or `head`, `data` and `end`. A committed answer (`head` 200) is handed on as an
 * upstream `Response` whose body is the `data` bytes and which ends only once `end` is in, so the request path's relay,
 * which holds an answer's terminal frames until its charge is settled, settles only after `end`.
 */

/** The lane's egress unix socket, as the stack layout's control calls name it (`stack.ts` STACK_EGRESS_ORIGIN). */
export const PEER_EGRESS_ORIGIN = "http://egress";

/** The pin table route of egress's peer mode (PR 3). */
export const PEER_PINS_URL = `${PEER_EGRESS_ORIGIN}/v1/peer/pins`;

/** The longest a pin or a hello holds (section 4.3: `now + 1 h`); egress refuses a pin further away. */
export const PEER_PIN_MAX_MS = 3_600_000;

/**
 * How often a pinned boot not yet known to hold the relay's sealed credentials is probed (docs/design/relay-zero-
 * downtime.md): a new boot of an image rollout is sent requests once a probe finds it sealed, so it is looked at more
 * often than the timing's `probeMs` until then. A probe is one small GET over the boot's own session.
 */
export const PEER_UNSEALED_PROBE_MS = 5_000;

/** A dstack app or instance id as the boots route names it: 40 lower-case hex. */
export const PEER_APP_ID = /^[0-9a-f]{40}$/;

/** The app or instance id a verified report names, lower-cased, or null for none or another form. */
export function peerAppIdOf(value: string | null | undefined): string | null {
  const id = typeof value === "string" ? value.toLowerCase() : "";
  return PEER_APP_ID.test(id) ? id : null;
}

/**
 * The registry's timing, `@gray/config`'s PEER_* rows (each with its bounds and source there; routing PR 9):
 *
 * - `probeMs` (PEER_PROBE_MS): a pinned peer's `/healthz` is asked this often (section 4.4): it finds a reboot as an SPKI
 *   mismatch before a request does;
 * - `downMs`, `downMaxMs` (PEER_DOWN_MS, PEER_DOWN_MAX_MS): a dial that failed before a byte was sent rests the peer
 *   `downMs`, doubling to `downMaxMs` (section 4.7, row 1);
 * - `recheckMs` (PEER_RECHECK_MS): a refused peer (its report, or its refusal of the hello) is checked again this much
 *   later (section 5, rows 16 and 17);
 * - `renewMs` (PEER_RENEW_MS): a pin or a hello is renewed this long before it lapses, so a busy peer never lapses under
 *   its traffic;
 * - `callMs` (PEER_CALL_MS): the bound of one background call of the registry (the attestation route, the challenge, the
 *   hello, a probe, a pin push).
 */
export interface PeerTiming {
  readonly probeMs: number;
  readonly downMs: number;
  readonly downMaxMs: number;
  readonly recheckMs: number;
  readonly renewMs: number;
  readonly callMs: number;
}

/** The registry's timing from the lane's configuration. */
export function peerTimingOf(cfg: GatewayConfig): PeerTiming {
  return {
    probeMs: cfg.peerProbeMs,
    downMs: cfg.peerDownMs,
    downMaxMs: cfg.peerDownMaxMs,
    recheckMs: cfg.peerRecheckMs,
    renewMs: cfg.peerRenewMs,
    callMs: cfg.peerCallMs,
  };
}

/** The egress codes of a dial that sent nothing (README "Peer mode"): the next origin or route may go. */
const UNSENT_CODES = new Set(["peer_unpinned", "peer_connect_failed", "peer_tls_failed", "peer_pin_mismatch", "peer_timeout", "peer_session_missing", "peer_session_refused"]);

/**
 * The stack VM's refusal of an envelope for a keyset it does not hold (check 3): its workerd restarted within the boot
 * (D133: the same certificate, so the same SPKI, and a new keyset), and the pin names the keyset before. Nothing was
 * registered, so it is a dial that sent nothing too, and the pin ends as at `peer_pin_mismatch` (section 4.3).
 */
const STALE_PIN_CODE = "peer_audience";

/**
 * The most bounded calls one job of the registry makes one after another: an attestation's route, the list, the
 * collateral, the pin push, the challenge, this entry's own report, the hello and a push again. A job is let go this
 * many PEER_CALL_MS after it started (`maintain`).
 */
const PEER_JOB_CALLS = 8;

/** SHA-256 of the empty body: the follow-up's `received_sha256` (`@gray/lane-wire` peer.ts). */
const EMPTY_SHA256 = sha256BareHex(new Uint8Array(0));

/** The verifier of a stack peer's report: the stack list and a quote verifier over the bridge's collateral (`peer.ts` BridgePeerVerifier). */
export interface StackListVerifier {
  list(): Promise<PeerReleaseList>;
  /** Reads the list again when its copy is stale (resolves either way), so an attestation is checked against a current one. */
  refresh?(): Promise<void>;
  /** The list read again now, or null when the held copy was read within LIST_REREAD_MS; throws when it cannot be had. */
  reread?(verified?: PeerReleaseList): Promise<PeerReleaseList | null>;
  quoteVerifier(): { readonly verifier: QuoteVerifier; readonly unavailable: () => boolean };
}

export interface PeerRegistryDeps {
  /** The EGRESS binding: the pin table and every peer call (attest mode and `/peer/<digest>/`). */
  readonly egress: (input: string, init: RequestInit) => Promise<Response>;
  readonly verifier: StackListVerifier;
  /** The peer check (`@gray/lane-verify` `verifyPeerAttestation`; a test's own). */
  readonly verify?: typeof verifyPeerAttestation;
  /** This entry's own ACI report for a stack VM's challenge nonce, as text (`attestation.ts` `attestationFor`). */
  readonly selfReport: (nonce: string) => Promise<string>;
  readonly clock: () => number;
  readonly timers: StreamTimers;
  /** The probe, backoff, recheck, renewal and call bounds (`peerTimingOf`). */
  readonly timing: PeerTiming;
  /** The attestation nonce source (32 random bytes as hex by default). */
  readonly nonce?: () => string;
  readonly log: (line: Record<string, unknown>) => void;
}

/** The peer summary `/healthz` reports (no relay or origin: the route is public; the log lines name them). */
export interface PeerSummary {
  readonly peers: number;
  readonly pinned: number;
  readonly unverified: number;
  readonly refused: number;
  readonly down: number;
  /** The refused and down peers by their closed code, for lane-watch's `lane_peer_refused`. */
  readonly codes: Readonly<Record<string, number>>;
}

/**
 * The entry's outbound-only channel as the registry uses it (`peer-link.ts` PeerLink; docs/design/relay-outbound-only.md
 * sections 3.3, 3.5, 3.6): which (relay, keyset) pairs have sessions, and what the registry tells it back.
 */
export interface PeerChannel {
  /** Every (relay, keyset) with a session, keyset as 64 hex, as of the channel's last read of peerlink's table. */
  keysets(): readonly { readonly relay: string; readonly keyset: string }[];
  /** Whether (relay, keyset) has a promoted session now (O5). */
  hasPinnedSession(relay: string, keyset: string): boolean;
  /** Whether (relay, keyset) had a session within the last 60 s (O6). */
  pinWanted(relay: string, keyset: string): boolean;
  /** The registry pinned (relay, keyset): promote its signed sessions. */
  pinned(relay: string, keyset: string, pin: { readonly receiptKeys: readonly string[]; readonly notAfterMs: number }): Promise<unknown>;
  /** The registry refused (relay, keyset): close its sessions, refuse it `forMs` (5 min by default). */
  refused(relay: string, keyset: string, forMs?: number): Promise<unknown>;
  /** A pin mismatch on `session`: close that session only. */
  mismatch(session: string): Promise<void>;
  /**
   * When this entry boot first saw (relay, keyset) attach, or null when it has had no session within the last 60 s: the
   * boot's age as the entry knows it, for the order of two boots of one relay. Optional: a channel without it orders by
   * the pin alone.
   */
  bornOf?(relay: string, keyset: string): number | null;
}

/** The codes of a channel peer that rests until its next signed attach (section 3.6, 3.7). */
const SESSION_CODES = new Set(["peer_session_missing", "peer_session_refused"]);

/** The registry of one entry boot (section 4.3). */
export class PeerRegistry implements LanePeerRegistry {
  readonly #deps: PeerRegistryDeps;
  readonly #peers = new Map<string, Peer>();
  /** The snapshot's stack relays and their signing keys: what a peer is checked against. */
  #relayKeys = new Map<string, string>();
  #channel: PeerChannel | null = null;
  /** `X-Gray-Peer-Version`: fixed when the registry starts, so a restarted lane's table counts above the last. */
  readonly #epoch: number;
  #push = 0;
  /**
   * The background push now out (`pushPins`) and the clock by which its current call has ended or is let go. Its call
   * and that call's timer belong to the fetch that started it: once that fetch's context ends, neither settles
   * (D116 (c); tee peer e2e D3, 2026-11-06), so it is held only until `until`, by the clock of whoever looks.
   */
  #pushing: { done: Promise<void>; until: number } | null = null;
  #pushAgain = false;
  /** Changes asked to be pushed (`pushPins` calls), and how many of them the last table egress took (204) covered. */
  #changes = 0;
  #pushedChanges = 0;

  constructor(deps: PeerRegistryDeps) {
    this.#deps = deps;
    this.#epoch = deps.clock();
  }

  /** The peers held, in the snapshot's order. */
  get peers(): readonly Peer[] {
    return [...this.#peers.values()];
  }

  /** The entry's channel, once its PEERLINK binding is known (`entry.ts`). */
  setChannel(channel: PeerChannel): void {
    this.#channel = channel;
  }

  /**
   * The snapshot's stack relays with their signing keys (`stackRelayKeysOf`): a relay no longer named loses its peers,
   * a relay whose key changed has its peers attested anew.
   */
  syncRelays(keys: ReadonlyMap<string, string>): void {
    this.#relayKeys = new Map(keys);
    let dropped = false;
    for (const [key, peer] of this.#peers) {
      if (!peer.channel || keys.get(peer.target.relayId) === peer.target.relayKey) continue;
      this.#peers.delete(key);
      dropped ||= peer.pin !== null;
    }
    if (dropped) void this.pushPins();
  }

  /** The stack relays the snapshot names. */
  stackRelays(): ReadonlySet<string> {
    return new Set([...this.#relayKeys.keys(), ...[...this.#peers.values()].map((peer) => peer.target.relayId)]);
  }

  /**
   * The usable peers of `relayId` (L1): its peers with a promoted session. A peer resting on
   * `peer_session_missing`/`peer_session_refused` is usable again once a promoted session is back (section 3.6: no
   * re-attestation while the pin lasts). Nothing is attested here (L5).
   *
   * The order is the image rollout's handover (docs/design/relay-zero-downtime.md): boots a probe found holding the
   * relay's sealed credentials first, the newest of them first, so a new boot takes new requests once it can serve them;
   * then the others, the oldest first, so a boot still starting is tried last. A request goes to the first and moves on
   * only after a dial that sent nothing, which is how the older boot drains: what it holds finishes, nothing new starts.
   */
  usable(relayId: string): Peer[] {
    const now = this.#deps.clock();
    const out: Peer[] = [];
    const channel = this.#channel;
    if (channel !== null) {
      const sessions: Peer[] = [];
      for (const peer of this.#peers.values()) {
        if (!peer.channel || peer.target.relayId !== relayId) continue;
        if (!channel.hasPinnedSession(relayId, peer.target.keyset!)) continue;
        if (peer.status === "down" && peer.code !== null && SESSION_CODES.has(peer.code)) {
          peer.status = "pinned";
          peer.code = null;
        }
        // A boot in the empty slot is pinned for the relay's own tunnel only (PeerPin.emptySlot): never a request's.
        if (peer.usable(now) && peer.pin?.emptySlot !== true) sessions.push(peer);
      }
      const born = (peer: Peer): number => channel.bornOf?.(relayId, peer.target.keyset!) ?? 0;
      sessions.sort((a, b) => {
        const ready = Number(b.sealed === true) - Number(a.sealed === true);
        if (ready !== 0) return ready;
        const age = a.sealed === true ? born(b) - born(a) : born(a) - born(b);
        return age !== 0 ? age : (b.pin?.notAfterMs ?? 0) - (a.pin?.notAfterMs ?? 0);
      });
      out.push(...sessions);
    }
    return out;
  }

  /**
   * What the entry knows of one boot of `relay` (`keyset` as 64 hex), for the boots route (docs/design/relay-zero-
   * downtime.md): its app and instance ids, its relay image, whether it is usable, and whether it holds the relay's
   * sealed credentials. Null when no channel peer of that boot is held.
   */
  bootOf(relay: string, keyset: string): { readonly appId: string | null; readonly instanceId: string | null; readonly relayImage: string | null; readonly usable: boolean; readonly sealed: boolean | null } | null {
    const peer = this.#peers.get(peerKey(relay, channelOrigin(keyset)));
    if (peer === undefined || !peer.channel) return null;
    return { appId: peer.pin?.appId ?? null, instanceId: peer.pin?.instanceId ?? null, relayImage: peer.pin === null || peer.pin.relayImage === "" ? null : peer.pin.relayImage, usable: peer.usable(this.#deps.clock()), sealed: peer.sealed };
  }

  /** Whether `relayId` has a usable channel peer now (the warm's wait, section 8.1 row 1). */
  hasSession(relayId: string): boolean {
    const now = this.#deps.clock();
    const channel = this.#channel;
    if (channel === null) return false;
    for (const peer of this.#peers.values()) if (peer.channel && peer.target.relayId === relayId && peer.usable(now) && peer.pin?.emptySlot !== true && channel.hasPinnedSession(relayId, peer.target.keyset!)) return true;
    return false;
  }

  /**
   * The channel's (relay, keyset) pairs as peers: a pair of a stack relay with a session and no peer gets one,
   * unverified; a channel peer whose boot has had no session for 60 s is forgotten and its pin leaves egress (O6).
   */
  #syncChannel(): void {
    const channel = this.#channel;
    if (channel === null) return;
    for (const { relay, keyset } of channel.keysets()) {
      const relayKey = this.#relayKeys.get(relay);
      if (relayKey === undefined) continue;
      const key = peerKey(relay, channelOrigin(keyset));
      if (!this.#peers.has(key)) this.#peers.set(key, new Peer({ relayId: relay, origin: channelOrigin(keyset), relayKey, keyset }));
    }
    let dropped = false;
    for (const [key, peer] of this.#peers) {
      if (!peer.channel || channel.pinWanted(peer.target.relayId, peer.target.keyset!)) continue;
      // A peer whose work is still out keeps its place until the work ends.
      if (peer.work !== null) continue;
      this.#peers.delete(key);
      dropped ||= peer.pin !== null;
      this.#deps.log({ level: "info", event: "lane_peer_session_gone", relay: peer.target.relayId, keyset_digest: `sha256:${peer.target.keyset!}` });
    }
    if (dropped) void this.pushPins();
  }

  /**
   * The current pin of `relay` at boot `keyset`, as an attach is checked against it (docs/design/relay-outbound-only.md
   * section 3.5): the keyset's Ed25519 receipt keys and the pin's end. Null when no peer of the relay holds that pin.
   */
  keysetPin(relay: string, keyset: string): { readonly receiptKeys: readonly string[]; readonly notAfterMs: number } | null {
    const now = this.#deps.clock();
    for (const peer of this.#peers.values()) {
      const pin = peer.pin;
      if (peer.target.relayId !== relay || pin === null || pin.keysetDigest !== keyset || pin.notAfterMs <= now) continue;
      return { receiptKeys: pin.receiptKeys.filter((key) => key.algo === "ed25519").map((key) => key.public_key), notAfterMs: pin.notAfterMs };
    }
    return null;
  }

  /** What `/healthz` says of the peers. */
  summary(): PeerSummary {
    const now = this.#deps.clock();
    const codes: Record<string, number> = {};
    let pinned = 0;
    let refused = 0;
    let down = 0;
    for (const peer of this.#peers.values()) {
      if (peer.usable(now)) pinned += 1;
      else if (peer.status === "refused") refused += 1;
      else if (peer.status === "down") down += 1;
      if ((peer.status === "refused" || peer.status === "down") && peer.code !== null) codes[peer.code] = (codes[peer.code] ?? 0) + 1;
    }
    return { peers: this.#peers.size, pinned, unverified: this.#peers.size - pinned - refused - down, refused, down, codes };
  }

  /**
   * Everything due, all at once (the boot's warm, then each fetch's): an unverified peer, a refused one past its recheck,
   * a pin about to lapse, and a down one past its backoff are attested; a pinned one whose hello lapses soon is helloed;
   * a pinned one not probed for the timing's `probeMs` is probed. Resolves when the work it started or found running has ended.
   *
   * A job runs in the background of the fetch that started it, and the timers that bound its calls are that fetch's:
   * once the fetch's context ends, neither its calls nor those timers settle (D116 (c)). So a job is let go here, by the
   * clock of the fetch that finds it, PEER_JOB_CALLS call bounds after it started, and the peer is due again as it stands
   * (an `attesting` one is attested again). A job that ends without a state of its own (it threw) leaves its peer down.
   */
  maintain(): Promise<void> {
    this.#syncChannel();
    const now = this.#deps.clock();
    const runs: Promise<void>[] = [];
    // A change egress has not taken (its push failed, or was let go) is pushed again here, in this fetch, which holds
    // it to its end. A push still within its bound is left alone: it may yet be answered, and is not waited on here.
    if (this.#pushedChanges < this.#changes && (this.#pushing === null || now >= this.#pushing.until)) runs.push(this.#pushBackground());
    for (const peer of this.#peers.values()) {
      if (peer.work !== null && now < peer.workUntil) {
        runs.push(peer.work);
        continue;
      }
      if (peer.work !== null) {
        this.#deps.log({ level: "warn", event: "lane_peer_work_lapsed", relay: peer.target.relayId, origin: peer.target.origin, status: peer.status });
        peer.work = null;
      }
      const job = this.#due(peer, now);
      if (job === null) continue;
      const work: Promise<void> = job()
        .catch(() => undefined)
        .then(() => {
          if (peer.work === work && peer.status === "attesting") this.#down(peer, "peer_attest_failed", this.#deps.clock());
        })
        .finally(() => {
          // A job let go may still end later: the job after it is then the peer's.
          if (peer.work === work) peer.work = null;
        });
      peer.work = work;
      peer.workUntil = now + PEER_JOB_CALLS * this.#deps.timing.callMs;
      runs.push(work);
    }
    return Promise.all(runs).then(() => undefined);
  }

  #due(peer: Peer, now: number): (() => Promise<void>) | null {
    switch (peer.status) {
      case "unverified":
        return () => this.#attest(peer);
      case "attesting":
        // No job of its own (`maintain` let it go): attested again.
        return () => this.#attest(peer);
      case "refused":
        return now >= peer.retryAt ? () => this.#attest(peer) : null;
      case "down": {
        if (now < peer.retryAt) return null;
        // Back from its rest by the step it failed at: an attestation without a current pin, the hello without a
        // current one, else a probe of the pinned session.
        const pin = peer.pin;
        if (pin === null || pin.notAfterMs - this.#deps.timing.renewMs <= now) return () => this.#attest(peer);
        if (peer.helloUntil - this.#deps.timing.renewMs <= now) return () => this.#hello(peer).then(() => undefined);
        return () => this.#probe(peer);
      }
      case "pinned": {
        const pin = peer.pin!;
        if (pin.notAfterMs - this.#deps.timing.renewMs <= now) return () => this.#attest(peer);
        if (peer.helloUntil - this.#deps.timing.renewMs <= now) return () => this.#hello(peer).then(() => undefined);
        const probeMs = peer.sealed === true ? this.#deps.timing.probeMs : Math.min(this.#deps.timing.probeMs, PEER_UNSEALED_PROBE_MS);
        if (now - peer.probedAt >= probeMs) return () => this.#probe(peer);
        return null;
      }
    }
  }

  /**
   * What a request's dial found (section 4.7, row 1): a pin mismatch, and a stack VM that refuses the pin's keyset
   * (`peer_audience`), end the pin and start a re-pin at the next maintenance; egress without the pin gets the table
   * again; any other dial that sent nothing rests the peer.
   */
  failed(peer: Peer, code: string, session?: string | null): void {
    const now = this.#deps.clock();
    if (peer.channel && code === "peer_pin_mismatch") {
      // Section 3.5: a mismatch condemns the session it came from, not the pin; the other sessions still serve. Egress
      // closed that session at peerlink already; the channel forgets it.
      if (session !== undefined && session !== null && this.#channel !== null) void this.#channel.mismatch(session);
      this.#deps.log({ level: "warn", event: "lane_peer_session_condemned", relay: peer.target.relayId, keyset_digest: peer.pin?.keysetDigest ?? null });
      return;
    }
    if (code === "peer_pin_mismatch" || code === STALE_PIN_CODE) {
      this.#unpin(peer, code);
      return;
    }
    if (code === "peer_unpinned") void this.pushPins();
    this.#down(peer, code, now);
  }

  /** A request went through: the peer's backoff starts again from its first step. */
  answered(peer: Peer): void {
    peer.backoffMs = 0;
  }

  /**
   * After `401 peer_unknown` (the stack VM lost its table, a reboot that kept its key cannot happen, so its table was
   * cleared): the hello once more, now, within `untilMs` (section 5, row 8). True when the stack VM accepted it. A
   * workerd restart within the boot accepts it too but holds a new keyset, which only an attestation names: the resend
   * is then refused `peer_audience` and the pin ends (`failed`), never moved to a digest the hello's answer gave.
   */
  async rehello(peer: Peer, untilMs: number): Promise<boolean> {
    peer.helloUntil = 0;
    return this.#hello(peer, untilMs);
  }

  #down(peer: Peer, code: string, now: number): void {
    peer.backoffMs = peer.backoffMs === 0 ? this.#deps.timing.downMs : Math.min(this.#deps.timing.downMaxMs, peer.backoffMs * 2);
    peer.status = "down";
    peer.code = code;
    peer.retryAt = now + peer.backoffMs;
    this.#deps.log({ level: "warn", event: "lane_peer_down", relay: peer.target.relayId, origin: peer.target.origin, code, retry_ms: peer.backoffMs });
  }

  /** Refuses the peer for `restMs` (the timing's recheck by default; LIST_REREAD_MS for a list miss alone). */
  #refuse(peer: Peer, code: string, restMs?: number): void {
    const hadPin = peer.pin !== null;
    const rest = restMs ?? this.#deps.timing.recheckMs;
    peer.status = "refused";
    peer.code = code;
    peer.pin = null;
    peer.helloUntil = 0;
    peer.retryAt = this.#deps.clock() + rest;
    // lane-watch alerts on the summary's refused count (section 5, row 16); the line names the relay for the operator.
    this.#deps.log({ level: "error", event: "lane_peer_refused", relay: peer.target.relayId, origin: peer.target.origin, code, retry_ms: rest });
    // A channel boot that failed its attestation: its sessions are closed and the keyset refused for 5 min (section 3.5),
    // or for the peer's own rest when that is a list miss's LIST_REREAD_MS.
    if (peer.channel && this.#channel !== null) void this.#channel.refused(peer.target.relayId, peer.target.keyset!, restMs);
    if (hadPin) void this.pushPins();
  }

  #unpin(peer: Peer, code: string): void {
    peer.status = "unverified";
    peer.code = code;
    peer.pin = null;
    peer.helloUntil = 0;
    this.#deps.log({ level: "warn", event: "lane_peer_unpinned", relay: peer.target.relayId, origin: peer.target.origin, code });
    void this.pushPins();
  }

  /** One call through egress, bounded by `untilMs` (the timing's `callMs` from now by default). */
  async #call(url: string, init: RequestInit, untilMs?: number): Promise<Response> {
    const { timers, clock } = this.#deps;
    const controller = new AbortController();
    const timer = timers.setTimeout(() => controller.abort("peer_call_timeout"), Math.max(0, (untilMs ?? clock() + this.#deps.timing.callMs) - clock()));
    try {
      const response = await this.#deps.egress(url, { ...init, signal: controller.signal });
      // The body is read within the same bound: a stalled answer ends with the call.
      const bytes = new Uint8Array(await response.arrayBuffer());
      return new Response(response.status === 204 || response.status === 304 ? null : bytes, { status: response.status, headers: response.headers });
    } finally {
      timers.clearTimeout(timer);
    }
  }

  /**
   * Section 4.3 steps 1 to 3, then the hello: the report for a fresh nonce through attest mode, verified against the
   * stack list for the route's relay and its key, the pin pushed to egress, then this entry's own report for the stack
   * VM's challenge. A verification that fails on the evidence refuses the peer; one that could not get the list or the
   * collateral, or a call that failed, leaves it down with its backoff.
   */
  async #attest(peer: Peer): Promise<void> {
    const { clock, verifier } = this.#deps;
    // A pin still current keeps serving while its renewal runs: only a peer with none is attesting.
    if (peer.status !== "pinned") peer.status = "attesting";
    const nonce = (this.#deps.nonce ?? (() => bytesToLowerHex(crypto.getRandomValues(new Uint8Array(32)))))();
    let report: Json;
    let spki: string | null;
    // A peer is attested over one of its (relay, keyset) sessions, unverified ones included (egress's attest mode by
    // relay and keyset).
    const attestPath = `${peer.target.relayId}/${peer.target.keyset!}`;
    try {
      const answer = await this.#call(`${PEER_EGRESS_ORIGIN}/peer/attest/${attestPath}/v1/aci/attestation?nonce=${nonce}`, { method: "GET" });
      spki = answer.headers.get("x-gray-peer-spki");
      if (peer.channel && answer.headers.get("x-gray-peer-sent") !== null && SESSION_CODES.has(await refusalCode(answer))) {
        // The sessions went before the attestation could ride one: nothing to judge; the next attach brings it back.
        this.#down(peer, await refusalCode(answer), clock());
        return;
      }
      if (answer.status >= 400 && answer.status < 500 && answer.headers.get("x-gray-peer-sent") === null) {
        // The VM answered, and not as a lane does (section 5, row 22: a peer that is no Gray TEE): refused.
        this.#refuse(peer, `attestation_refused:status_${answer.status}`);
        return;
      }
      if (answer.status !== 200 || spki === null) {
        this.#down(peer, attestCode(answer), clock());
        return;
      }
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(await answer.arrayBuffer());
      try {
        report = parseSerde(text);
      } catch {
        this.#refuse(peer, "attestation_refused:not_a_report");
        return;
      }
    } catch {
      this.#down(peer, "peer_attest_failed", clock());
      return;
    }
    let list: PeerReleaseList;
    try {
      await verifier.refresh?.();
      list = await verifier.list();
    } catch {
      // C11/F17: no list can be had now; the peer is tried again after its backoff, never pinned without one.
      this.#down(peer, "peer_list_unavailable", clock());
      return;
    }
    const quote = verifier.quoteVerifier();
    // The identity rule of a peer (section 3.3): the relay the session claimed (`relay_pin`, with the relay's key). A
    // peer has no host: `""` skips the domain check, and the SPKI must be one of the keyset's TLS keys bound to no
    // domain, as release B's per-boot self-signed key is (section 3.9). A boot whose TLS key is bound to a name (a
    // release before B) is refused.
    // A release the held list does not name may have been published since it was read (D3): read again at once, at most
    // every LIST_REREAD_MS, as a stack VM does for an entry's hello (`peer.ts` verifyWithReread).
    const verified = await verifyWithReread(list, verifier.reread?.bind(verifier), (releaseList) =>
      (this.#deps.verify ?? verifyPeerAttestation)(report, {
        layout: "stack",
        releaseList,
        nonce,
        tlsSpkiSha256: spki,
        host: peer.channel ? "" : peer.host,
        nowSecs: BigInt(Math.floor(clock() / 1000)),
        expectedRelayId: peer.target.relayId,
        expectedRelayPublicKey: peer.target.relayKey,
        // P2d/P4b: a phase-2 boot in the empty slot waits for the relay's first delivery, which reaches it only through
        // this entry's tunnel; it is pinned for that alone (PeerPin.emptySlot) and checked against the relay key below.
        allowEmptySlot: true,
        quoteVerifier: quote.verifier,
      }),
    );
    if (verified === null) {
      this.#down(peer, "peer_list_unavailable", clock());
      return;
    }
    const v = verified.verification;
    const facts = v?.stackBoot?.ok === true ? v.stackBoot.facts : null;
    const phaseOk = facts !== null && (facts.phase === "sealed" || facts.phase === "empty_slot");
    if (!verified.ok || v === null || v.keysetDigest === null || v.keyset === null || v.composeHash === null || v.osImageHash === null || facts === null || !phaseOk || verified.listCurrentUntil === null) {
      if (quote.unavailable()) {
        this.#down(peer, "peer_collateral_unavailable", clock());
        return;
      }
      const failed = verified.checks.find((check) => check.status === "fail");
      // A boot refused only because the list it was checked against (read just now, or within LIST_REREAD_MS) does not
      // name its release rests LIST_REREAD_MS, not the recheck: the next attestation may read a list published since.
      // Of a channel peer, only when the report binds the keyset the sessions claimed; anything else is a real refusal.
      const listOnly = onlyListMiss(verified.checks) && (!peer.channel || v?.keysetDigest === `sha256:${peer.target.keyset!}`);
      this.#refuse(peer, `attestation_refused:${failed?.id ?? "unknown"}`, listOnly ? LIST_REREAD_MS : undefined);
      return;
    }
    // The empty slot's identity is held to the relay's key here: @gray/lane-verify checks only its relay id there (it has
    // no relay image whose signature would carry the key).
    if (facts.phase === "empty_slot" && facts.identity.publicKey !== peer.target.relayKey) {
      this.#refuse(peer, "attestation_refused:relay_key_pin");
      return;
    }
    if (peer.channel && v.keysetDigest !== `sha256:${peer.target.keyset!}`) {
      // The session claimed one boot and the report binds another: a liar, whatever the report is (section 3.5).
      this.#refuse(peer, "attestation_refused:keyset_mismatch");
      return;
    }
    const notAfterMs = Math.min(Number(v.keyset.not_after) * 1000, Number(verified.listCurrentUntil) * 1000, clock() + PEER_PIN_MAX_MS);
    // The same boot again (a renewal): the stack VM still holds this entry's hello. A new boot holds none.
    const sameBoot = peer.pin?.keysetDigest === v.keysetDigest && peer.pin.spkiSha256 === spki;
    peer.pin = {
      keysetDigest: v.keysetDigest,
      digest: v.keysetDigest.slice("sha256:".length),
      spkiSha256: spki,
      notAfterMs,
      composeHash: v.composeHash,
      osImageHash: v.osImageHash,
      relayImage: facts.phase === "sealed" ? facts.image.image : "",
      ...(facts.phase === "empty_slot" ? { emptySlot: true } : {}),
      appId: peerAppIdOf(v.appId),
      instanceId: peerAppIdOf(v.instanceId),
      report,
      nonce,
      receiptKeys: v.keyset.receipt_signing_keys,
    };
    if (!sameBoot) {
      peer.helloUntil = 0;
      peer.sealed = null;
    }
    peer.probedAt = clock();
    // A channel peer's sessions are promoted (their attach signatures checked under this keyset's receipt key) before
    // egress may dial them for content: the hello below rides a promoted session (O5).
    if (peer.channel && this.#channel !== null) {
      await this.#channel.pinned(peer.target.relayId, peer.target.keyset!, { receiptKeys: v.keyset.receipt_signing_keys.filter((key) => key.algo === "ed25519").map((key) => key.public_key), notAfterMs });
    }
    // The pin goes to egress in a push of this job's own, never by waiting on a background push: that one may belong to
    // a fetch whose context has ended and never settle, and the boot would stay unpinned behind it (tee peer e2e D3,
    // 2026-11-06). A push that fails leaves the change for the next maintenance; the hello below then fails and rests.
    this.#changes += 1;
    await this.#pushTable();
    if (peer.helloUntil - this.#deps.timing.renewMs <= clock() && !(await this.#hello(peer))) return;
    peer.status = "pinned";
    peer.code = null;
    peer.backoffMs = 0;
    this.#deps.log({ level: "info", event: "lane_peer_pinned", relay: peer.target.relayId, origin: peer.target.origin, keyset_digest: v.keysetDigest, not_after_ms: notAfterMs, ...(facts.phase === "empty_slot" ? { empty_slot: true } : {}) });
  }

  /**
   * The hello on the pinned session (section 4.3): `GET /v1/peer/challenge`, then `POST /v1/peer/hello {nonce, report}`
   * with this entry's report for that nonce. A refusal refuses the peer (rechecked later); `peer_hello_unavailable` and
   * a failed call leave it down with its backoff ("hello again later").
   */
  async #hello(peer: Peer, untilMs?: number): Promise<boolean> {
    const { clock } = this.#deps;
    const pin = peer.pin;
    if (pin === null) return false;
    const base = `${PEER_EGRESS_ORIGIN}/peer/${pin.digest}`;
    try {
      const challenge = await this.#call(`${base}/v1/peer/challenge`, { method: "GET" }, untilMs);
      if (challenge.status !== 200) return this.#helloFailed(peer, challenge);
      const nonce = (parseSerde(await challenge.text()) as { readonly nonce?: unknown }).nonce;
      if (typeof nonce !== "string") return this.#helloFailed(peer, null);
      const report = await this.#deps.selfReport(nonce);
      // The report is this boot's own document text (`attestationFor`'s `json`), set in the body as it is.
      const body = `{"nonce":${toJsonString(nonce)},"report":${report}}`;
      const answer = await this.#call(`${base}/v1/peer/hello`, { method: "POST", headers: { "content-type": "application/json" }, body }, untilMs);
      if (answer.status !== 200) return this.#helloFailed(peer, answer);
      const accepted = parseSerde(await answer.text()) as { readonly not_after_ms?: unknown };
      const until = typeof accepted.not_after_ms === "bigint" ? Number(accepted.not_after_ms) : typeof accepted.not_after_ms === "number" ? accepted.not_after_ms : null;
      if (until === null || !Number.isSafeInteger(until)) return this.#helloFailed(peer, null);
      peer.helloUntil = Math.min(until, pin.notAfterMs);
      if (peer.status === "pinned" || peer.status === "down") {
        peer.status = "pinned";
        peer.code = null;
      }
      return true;
    } catch {
      this.#down(peer, "peer_hello_failed", clock());
      return false;
    }
  }

  async #helloFailed(peer: Peer, answer: Response | null): Promise<false> {
    const code = answer === null ? "peer_hello_invalid" : await refusalCode(answer);
    if (code === "peer_hello_refused") this.#refuse(peer, code);
    else this.#down(peer, code, this.#deps.clock());
    return false;
  }

  /**
   * `GET /peer/<digest>/healthz?relay=<relay>` on the pinned session: a reboot is found as `peer_pin_mismatch` before a
   * request finds it, and the answer's `relay.sealed_version` says whether the boot holds the relay's credentials.
   */
  async #probe(peer: Peer): Promise<void> {
    const pin = peer.pin;
    if (pin === null) return;
    peer.probedAt = this.#deps.clock();
    let answer: Response;
    try {
      answer = await this.#call(`${PEER_EGRESS_ORIGIN}/peer/${pin.digest}/healthz?relay=${encodeURIComponent(peer.target.relayId)}`, { method: "GET" });
    } catch {
      this.#down(peer, "peer_probe_failed", this.#deps.clock());
      return;
    }
    if (answer.status === 200) {
      peer.sealed = await sealedOf(answer, peer.target.relayId);
      if (peer.status === "down") {
        peer.status = "pinned";
        peer.code = null;
      }
      return;
    }
    const sent = answer.headers.get("x-gray-peer-sent");
    this.failed(peer, sent === null ? "peer_probe_failed" : await refusalCode(answer));
  }

  /**
   * The table changed: push it in the background. One background push at a time; a change during one pushes again
   * after it. A push past its call's bound by the caller's clock is let go (`lane_peer_pins_lapsed`) and a new one
   * starts in the caller's fetch: the one let go belongs to a fetch whose context may have ended, and then never ends
   * (D116 (c)). Should it be answered after all, its number is below the new push's, and egress refuses a lower one
   * (`409 peer_pins_stale`, deploy/tee/egress/README.md "Peer mode"), so it can never replace a newer table.
   */
  pushPins(): Promise<void> {
    this.#changes += 1;
    return this.#pushBackground();
  }

  #pushBackground(): Promise<void> {
    const now = this.#deps.clock();
    const running = this.#pushing;
    if (running !== null && now < running.until) {
      this.#pushAgain = true;
      return running.done;
    }
    // `held_ms`: how long its current call has been out.
    if (running !== null) this.#deps.log({ level: "warn", event: "lane_peer_pins_lapsed", held_ms: now - (running.until - this.#deps.timing.callMs) });
    // Its first call's bound, from now; each call moves it on (below). `done` is set before the first call returns.
    const push: { done: Promise<void>; until: number } = { done: Promise.resolve(), until: now + this.#deps.timing.callMs };
    this.#pushing = push;
    push.done = (async () => {
      do {
        this.#pushAgain = false;
        push.until = this.#deps.clock() + this.#deps.timing.callMs;
        await this.#pushTable();
        // A push let go stops here: the change it owed is the new push's.
      } while (this.#pushAgain && this.#pushing === push);
    })().finally(() => {
      if (this.#pushing === push) this.#pushing = null;
    });
    return push.done;
  }

  /**
   * `PUT /v1/peer/pins`: the whole table, every peer with a pin (a lapsed one is kept and never dialed, as egress keeps
   * it), under the registry's epoch and the next push number, bounded by PEER_CALL_MS from now in the caller's fetch
   * (`#call`): the bound of every background call of the registry, 15 s by default, which a push over egress's unix
   * socket is far under. Never throws.
   */
  async #pushTable(): Promise<void> {
    this.#push += 1;
    const covers = this.#changes;
    // A pin row names its relay: egress dials peerlink's sessions of (relay, keyset) for it.
    const rows = [...this.#peers.values()].flatMap((peer) =>
      peer.pin === null ? [] : [{ peer: peer.pin.digest, relay: peer.target.relayId, spki_sha256: peer.pin.spkiSha256, not_after: Math.ceil(peer.pin.notAfterMs / 1000) }],
    );
    try {
      const answer = await this.#call(PEER_PINS_URL, {
        method: "PUT",
        headers: { "content-type": "application/json", "x-gray-peer-version": String(this.#epoch), "x-gray-peer-push": String(this.#push) },
        body: JSON.stringify(rows),
      });
      if (answer.status === 204) {
        this.#pushedChanges = Math.max(this.#pushedChanges, covers);
        return;
      }
      const code = await refusalCode(answer);
      // A later push of this registry reached egress first: its table, read after this one's, is the one that holds.
      if (answer.status === 409 && code === "peer_pins_stale") return;
      this.#deps.log({ level: "error", event: "lane_peer_pins_refused", status: answer.status, code });
    } catch {
      this.#deps.log({ level: "error", event: "lane_peer_pins_failed" });
    }
  }
}

/** The closed code of an egress or stack VM refusal body (`{error}` or `{code}`), or the status's when it has none. */
async function refusalCode(answer: Response): Promise<string> {
  try {
    const body = parseSerde(await answer.clone().text()) as { readonly error?: unknown; readonly code?: unknown };
    const code = typeof body.code === "string" ? body.code : typeof body.error === "string" ? body.error : null;
    if (code !== null && /^[a-z_]{1,64}$/.test(code)) return code;
  } catch {
    // Not a closed body.
  }
  return `status_${answer.status}`;
}

/**
 * Whether a VM's `/healthz?relay=` answer says it can serve the relay: it holds the relay's sealed credentials
 * (`relay.sealed_version` a string) and its relay container fetched a configuration (`relay.config_version` a string),
 * without which a request finds `config_unready`. A VM of a release before `config_version` says only the first. Null
 * for an answer that does not say (a body that is not that shape): unknown, not unsealed.
 */
async function sealedOf(answer: Response, relayId: string): Promise<boolean | null> {
  try {
    const relay = get(parseStrict(await answer.text()), "relay");
    if (!isObject(relay) || get(relay, "relay_id") !== relayId) return null;
    const version = get(relay, "sealed_version");
    if (version === null) return false;
    if (typeof version !== "string") return null;
    const config = get(relay, "config_version");
    return config === undefined || typeof config === "string";
  } catch {
    return null;
  }
}

function attestCode(answer: Response): string {
  return answer.headers.get("x-gray-peer-spki") === null && answer.status === 200 ? "peer_attest_invalid" : `peer_attest_status_${answer.status}`;
}

// ---------------------------------------------------------------------------------------------------------- the attempt

/** One attempt at a stack route over the hop (section 4.5). */
export class PeerCall implements LanePeerCall {
  readonly #input: PeerCallInput;
  /** The peer the request went to last (the next origin's after a dial that sent nothing). */
  peer: Peer;
  /** That peer's pin when the request went: the boot the envelope named, whatever the registry learns of it later. */
  pin: PeerPin | null = null;
  /** The envelope's digest (`peer.forwarded`), once one was signed. */
  envelopeSha256: string | null = null;
  head: PeerHeadDto | null = null;
  end: PeerEndDto | null = null;
  /** Why the hop gave no answer (`peer.failed`), when it gave none. */
  failure: { readonly code: PeerFailedCode; readonly sent: boolean } | null = null;
  /** The channel session egress named on its last own answer (`x-gray-peer-session`, a pin mismatch's). */
  #session: string | null = null;
  /** The follow-up's state, when one was asked. */
  followed: PeerAttemptState | null = null;
  /** A committed answer's bytes have been handed on: the stack VM's attempt served this request. */
  served = false;
  /** Resolves when the hop's answer is over: its `end`, or null when it ended without one. */
  readonly ended: Promise<PeerEndDto | null>;
  #resolveEnded!: (end: PeerEndDto | null) => void;
  #reader: HopReader | null = null;
  /** The peer of `peers` the next send starts at: a dial that sent nothing moves it on, an answer keeps it. */
  #at = 0;
  readonly startedAt: number;

  constructor(input: PeerCallInput) {
    this.#input = input;
    this.peer = input.peers[0]!;
    this.startedAt = input.clock();
    this.ended = new Promise((resolve) => (this.#resolveEnded = resolve));
  }

  get n(): number {
    return this.#input.n;
  }

  /** The relay account of `end` (S27), or null. */
  get accountId(): string | null {
    return this.end?.relay_account_id ?? null;
  }

  /** The relay's trace of the attempt (`end.trace`, S43) with JS numbers, or null. */
  get trace(): StackTrace | null {
    const trace = this.end?.trace;
    return trace === undefined ? null : stackTraceOf(trace);
  }

  /** Whether a vendor was dialed, as `end` or the follow-up said; null when neither did. */
  get dialed(): boolean | null {
    if (this.end !== null) return this.end.dialed;
    // A `head` of 200 is an answer the stack VM committed, which a vendor's answer did (PR 4: `head` goes at the commit).
    if (this.head?.status === 200n) return true;
    if (this.followed === null) return null;
    return this.followed === "dialed" || this.followed === "done";
  }

  /** The commitment of the receipt's peer events (`@gray/attest` `peerCommitment`), over `end`'s inner receipt when it came. */
  commitment(): string {
    const pin = this.pin;
    return peerCommitment({
      keysetDigest: pin?.keysetDigest ?? `sha256:${"0".repeat(64)}`,
      composeHash: pin?.composeHash ?? "0".repeat(64),
      osImageHash: pin?.osImageHash ?? "0".repeat(64),
      relayImage: pin?.relayImage ?? "",
      innerReceiptSha256: this.inner()?.receiptSha256 ?? null,
    });
  }

  /** The inner receipt's id and digest, when `end` carried one. */
  inner(): { readonly receiptId: string; readonly receiptSha256: string } | null {
    const receipt = this.end?.receipt;
    if (receipt === null || receipt === undefined) return null;
    const id = (receipt as { readonly receipt_id?: unknown }).receipt_id;
    if (typeof id !== "string" || !/^rcpt_[0-9a-f]{32}$/.test(id)) return null;
    return { receiptId: id, receiptSha256: sha256BareHex(jcsBytes(receipt as unknown as Json)) };
  }

  /**
   * What the outer receipt keeps of this attempt (section 4.8): the pinned peer's report and boot facts, the inner
   * receipt `end` carried (its JCS bytes, the ones `inner()` digests), and the late fetch, a closure over the envelope's
   * facts, the signer and egress alone (never the request's bytes or headers). Null when no envelope went to a pinned peer.
   */
  stored(): StoredPeerAttempt | null {
    const pin = this.pin;
    if (pin === null || this.envelopeSha256 === null) return null;
    const input = this.#input;
    const inner = this.inner();
    const target: FollowUpTarget = { pin, entry: input.entry, rid: input.rid, n: input.n, receiptId: input.receiptId, route: input.route };
    const deps: FollowUpDeps = { signer: input.signer, egress: input.egress, clock: input.clock, timers: input.timers };
    return {
      n: input.n,
      rid: input.rid,
      attestation: { report: pin.report, nonce: pin.nonce, tlsSpkiSha256: pin.spkiSha256, host: this.peer.host, relayId: this.peer.target.relayId },
      keysetDigest: pin.keysetDigest,
      receiptKeys: pin.receiptKeys,
      inner,
      receipt: inner === null ? null : jcsBytes(this.end!.receipt as unknown as Json),
      fetchLate: (untilMs) => peerFollowUp(target, deps, untilMs, Math.max(1, untilMs - deps.clock())),
      shareDebug: (debug) => peerDebug(target, deps, debug),
    };
  }

  /** Whether `rawUsage` (the request path's reading of the answer) is the usage `end` says, as `safe_usage_counters` keeps it. */
  usageAgrees(rawUsage: Json | null): boolean {
    if (this.end === null) return false;
    const read = rawUsage === null ? null : peerUsageOf(rawUsage);
    return toJsonString((read ?? null) as unknown as Json) === toJsonString((this.end.usage ?? null) as unknown as Json);
  }

  /** Ends the hop (the request path is done with the answer, or left it). */
  close(): void {
    this.#reader?.cancel();
    this.#resolveEnded(this.end);
  }

  /**
   * Sends the request to the first peer, and to the next after a dial that sent nothing, until one answers: then the
   * answer's first frames are read up to `head`, and for an answer that did not commit up to `end`.
   */
  async send(): Promise<PeerSent> {
    const input = this.#input;
    let last: PeerSent = { kind: "unsent", code: "peer_unpinned" };
    for (; this.#at < input.peers.length; this.#at += 1) {
      const peer = input.peers[this.#at]!;
      this.peer = peer;
      last = await this.#sendTo(peer);
      if (last.kind !== "unsent" || !(UNSENT_CODES.has(last.code) || last.code === STALE_PIN_CODE)) break;
      input.registry.failed(peer, last.code, this.#session);
    }
    if (last.kind !== "answered") this.#resolveEnded(this.end);
    return last;
  }

  async #sendTo(peer: Peer): Promise<PeerSent> {
    const input = this.#input;
    const pin = peer.pin;
    this.pin = pin;
    if (pin === null) return this.#failed("peer_unpinned", false);
    const envelope = {
      ...this.#envelope(pin.keysetDigest, input.body),
      ...(input.conversation === undefined ? {} : { conversation: input.conversation }),
      ...(input.relayChanges === undefined ? {} : { relay_changes: input.relayChanges }),
    };
    const header = await signPeerEnvelope("request", envelope, input.signer);
    this.envelopeSha256 = sha256BareHex(peerEnvelopeBytes(envelope));
    this.failure = null;
    let response: Response;
    try {
      response = await input.egress(`${PEER_EGRESS_ORIGIN}/peer/${pin.digest}${input.path}`, {
        method: "POST",
        headers: { ...input.headers, "content-type": "application/json", [PEER_HEADER]: header, ...(input.requestId === undefined ? {} : { [PEER_REQUEST_ID_HEADER]: input.requestId }) },
        body: input.body,
        signal: input.signal,
      });
    } catch {
      if (input.signal.aborted) return this.#aborted();
      // The entry's own egress did not answer: nothing left the VM.
      return this.#failed("peer_connect_failed", false);
    }
    const sent = response.headers.get("x-gray-peer-sent");
    this.#session = response.headers.get("x-gray-peer-session");
    if (sent !== null) {
      // Egress's own answer (README "Peer mode"): the hop codes, or a refusal of the entry's request.
      const code = await refusalCode(response);
      if (code === "peer_failed_after_send" || (code === "peer_timeout" && sent === "1")) return this.#unknown(code, true);
      return UNSENT_CODES.has(code) ? this.#failed(code as PeerFailedCode, false) : this.#failed("peer_invalid", false);
    }
    if (response.status !== 200 || !(response.headers.get("content-type") ?? "").startsWith("text/event-stream")) {
      // The stack VM's lane answered before any frame: a refusal of checks 1 to 6, or any other answer of a lane that
      // registered nothing (its 404 without backend mode, its boot's 503). No vendor was dialed (S25).
      let code: PeerFailedCode = "peer_invalid";
      try {
        code = parsePeerRefusal(new Uint8Array(await response.arrayBuffer())).code;
      } catch {
        // Not a refusal body: `peer_invalid`.
      }
      return this.#failed(code, true);
    }
    input.registry.answered(peer);
    this.#reader = new HopReader(response.body!);
    let frame: PeerFrame | "eof";
    try {
      frame = await this.#reader.next();
    } catch {
      return input.signal.aborted ? this.#aborted() : this.#unknown("peer_failed_after_send", true);
    }
    if (frame === "eof" || frame.event !== "head") return frame === "eof" ? this.#unknown("peer_failed_after_send", true) : this.#unknown("peer_invalid", true);
    this.head = frame.head;
    if (frame.head.status === 200n) return { kind: "answered", response: this.#answer(frame.head) };
    // Not committed: the vendor's error body in `data`, or nothing, then `end` (PR 4: `end` follows at once).
    const body: Uint8Array[] = [];
    for (;;) {
      let next: PeerFrame | "eof";
      try {
        next = await this.#reader.next();
      } catch {
        return input.signal.aborted ? this.#aborted() : this.#unknown("peer_failed_after_send", true);
      }
      if (next === "eof") return this.#unknown("peer_failed_after_send", true);
      if (next.event === "data") body.push(next.bytes);
      else if (next.event === "end") {
        this.end = next.end;
        return { kind: "ended", head: frame.head, end: next.end, body: joined(body) };
      } else return this.#unknown("peer_invalid", true);
    }
  }

  #failed(code: PeerFailedCode | string, answered: boolean): PeerSent {
    // A refusal the stack VM answered is the hop's answer, not its failure; egress's codes are failures.
    this.failure = answered ? { code: code as PeerFailedCode, sent: true } : { code: code as PeerFailedCode, sent: false };
    return { kind: "unsent", code };
  }

  #unknown(code: PeerFailedCode, sent: boolean): PeerSent {
    this.failure = { code, sent };
    return { kind: "unknown", code };
  }

  #aborted(): PeerSent {
    this.failure = { code: "peer_aborted", sent: true };
    return { kind: "aborted" };
  }

  #envelope(aud: string, body: Uint8Array): PeerEnvelopeDto {
    const input = this.#input;
    const budget = BigInt(Math.max(1, Math.min(Number(PEER_BUDGET_MAX_MS), Math.floor(input.budgetMs))));
    return {
      aud,
      entry: input.entry,
      rid: input.rid,
      n: BigInt(input.n),
      receipt_id: input.receiptId,
      route: input.route,
      received_sha256: sha256BareHex(body),
      issued_ms: BigInt(Math.floor(input.clock())),
      budget_ms: budget,
      nonce: bytesToLowerHex(crypto.getRandomValues(new Uint8Array(16))),
    };
  }

  /**
   * A committed answer as an upstream `Response`: the `data` bytes as the stack VM released them, read as the request
   * path reads (nothing ahead of its consumer). The body ends once `end` is in; a hop that ends without `end`, or with a
   * frame that is not the wire, is a broken body, as a vendor connection that broke.
   */
  #answer(head: PeerHeadDto): Response {
    const reader = this.#reader!;
    const body = new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        for (;;) {
          let frame: PeerFrame | "eof";
          try {
            frame = await reader.next();
          } catch (error) {
            this.#resolveEnded(null);
            controller.error(error);
            return;
          }
          if (frame === "eof" || frame.event === "head") {
            this.#resolveEnded(null);
            controller.error(new Error(frame === "eof" ? "the hop ended without its end frame" : "a second head frame"));
            return;
          }
          if (frame.event === "data") {
            this.served = true;
            controller.enqueue(frame.bytes);
            return;
          }
          this.end = frame.end;
          this.#resolveEnded(frame.end);
          controller.close();
          return;
        }
      },
      cancel: () => {
        reader.cancel();
        this.#resolveEnded(this.end);
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": head.stream ? "text/event-stream" : "application/json" } });
  }

  /**
   * `GET /v1/peer/attempts/<rid>` on a new request within `untilMs` (section 4.5's late facts): whether the stack VM
   * registered or dialed this attempt, and its inner receipt once it is done. Null when no answer came.
   */
  async followUp(untilMs: number): Promise<PeerAttemptsReply | null> {
    const input = this.#input;
    const pin = this.pin;
    if (pin === null) return null;
    const answer = await peerFollowUp(
      { pin, entry: input.entry, rid: input.rid, n: input.n, receiptId: input.receiptId, route: input.route },
      { signer: input.signer, egress: input.egress, clock: input.clock, timers: input.timers },
      untilMs,
      input.budgetMs,
    );
    if (answer !== null) this.followed = answer.state;
    return answer;
  }
}

/** The envelope facts of one attempt a follow-up asks about (it carries the attempt's envelope, section 4.5). */
interface FollowUpTarget {
  readonly pin: PeerPin;
  readonly entry: string;
  readonly rid: string;
  readonly n: number;
  readonly receiptId: string | null;
  readonly route: PeerCallInput["route"];
}

interface FollowUpDeps {
  readonly signer: PeerCallInput["signer"];
  readonly egress: PeerCallInput["egress"];
  readonly clock: () => number;
  readonly timers: StreamTimers;
}

/**
 * The follow-up of one attempt on the pinned session (`/peer/<digest>/v1/peer/attempts/<rid>`), signed under the
 * attempts domain line with the empty body's digest, within `untilMs`. Null when no answer came (egress's own failure:
 * the pin is gone after a reboot, say), or the answer is not the wire.
 */
async function peerFollowUp(target: FollowUpTarget, deps: FollowUpDeps, untilMs: number, budgetMs: number): Promise<PeerAttemptsReply | null> {
  if (untilMs <= deps.clock()) return null;
  const envelope: PeerEnvelopeDto = {
    aud: target.pin.keysetDigest,
    entry: target.entry,
    rid: target.rid,
    n: BigInt(target.n),
    receipt_id: target.receiptId,
    route: target.route,
    received_sha256: EMPTY_SHA256,
    issued_ms: BigInt(Math.floor(deps.clock())),
    budget_ms: BigInt(Math.max(1, Math.min(Number(PEER_BUDGET_MAX_MS), Math.floor(budgetMs)))),
    nonce: bytesToLowerHex(crypto.getRandomValues(new Uint8Array(16))),
  };
  const controller = new AbortController();
  const timer = deps.timers.setTimeout(() => controller.abort("peer_follow_up_timeout"), Math.max(0, untilMs - deps.clock()));
  try {
    const header = await signPeerEnvelope("attempts", envelope, deps.signer);
    const response = await deps.egress(`${PEER_EGRESS_ORIGIN}/peer/${target.pin.digest}/v1/peer/attempts/${target.rid}`, { method: "GET", headers: { [PEER_HEADER]: header }, signal: controller.signal });
    if (response.status !== 200 || response.headers.has("x-gray-peer-sent")) return null;
    const answer = parsePeerAttemptsAnswer(new Uint8Array(await response.arrayBuffer()));
    return { state: answer.state, receipt: (answer.receipt ?? null) as Json | null };
  } catch {
    return null;
  } finally {
    deps.timers.clearTimeout(timer);
  }
}

/**
 * The debug hop of one attempt on the pinned session (`/peer/<digest>/v1/peer/debug/<rid>`, docs/design/relay-debug-sharing.md
 * §4), signed under the debug domain line, within `untilMs`. The share comes back as sent; the caller verifies it under
 * the stack VM's receipt keys. Never throws.
 */
async function peerDebug(target: FollowUpTarget, deps: FollowUpDeps, input: PeerDebugInput): Promise<PeerDebugReply> {
  if (input.untilMs <= deps.clock()) return { outcome: "unavailable", code: "timeout" };
  const controller = new AbortController();
  const timer = deps.timers.setTimeout(() => controller.abort("peer_debug_timeout"), Math.max(0, input.untilMs - deps.clock()));
  try {
    const header = await signPeerDebugEnvelope(
      {
        aud: target.pin.keysetDigest,
        entry: target.entry,
        rid: target.rid,
        n: BigInt(target.n),
        receipt_id: input.receiptId,
        inner_receipt_id: input.innerReceiptId,
        request_id: input.requestId,
        issued_ms: BigInt(Math.floor(deps.clock())),
        nonce: bytesToLowerHex(crypto.getRandomValues(new Uint8Array(16))),
      },
      deps.signer,
    );
    const response = await deps.egress(`${PEER_EGRESS_ORIGIN}/peer/${target.pin.digest}${PEER_DEBUG_PREFIX}${target.rid}`, { method: "POST", headers: { [PEER_HEADER]: header }, signal: controller.signal });
    const body = new Uint8Array(await response.arrayBuffer());
    // Egress's own answer (the pin is gone, the dial failed) is not the stack VM's.
    if (response.headers.has("x-gray-peer-sent")) return { outcome: "unavailable", code: "egress" };
    if (response.status === 200) return { outcome: "shared", value: parsePeerDebugAnswer(body).value };
    const code = parsePeerDebugRefusal(body);
    if (code === "debug_rate_limited" || code === "debug_store_full") return { outcome: "refused", code };
    return { outcome: "unavailable", code: code ?? `status_${response.status}` };
  } catch {
    return { outcome: "unavailable", code: controller.signal.aborted ? "timeout" : "failed" };
  } finally {
    deps.timers.clearTimeout(timer);
  }
}

function joined(chunks: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, chunk) => n + chunk.length, 0));
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/** The hop's frames, read as they come (`@gray/protocol` SseFrames and SseDecoder); the hop's comments are skipped. */
class HopReader {
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly #frames = new SseFrames();
  readonly #decoder = new SseDecoder();
  readonly #queue: PeerFrame[] = [];
  #done = false;

  constructor(body: ReadableStream<Uint8Array>) {
    this.#reader = body.getReader();
  }

  /** The next frame, or `eof`; throws when the hop broke or sent what is not the wire (`parsePeerFrame`). */
  async next(): Promise<PeerFrame | "eof"> {
    for (;;) {
      const queued = this.#queue.shift();
      if (queued !== undefined) return queued;
      for (let frame = this.#frames.nextFrame(); frame !== undefined; frame = this.#frames.nextFrame()) {
        for (const event of this.#decoder.pushFrame(frame)) this.#queue.push(parsePeerFrame(event.event, event.data));
      }
      if (this.#queue.length > 0) continue;
      if (this.#done) return "eof";
      const read = await this.#reader.read();
      if (read.done) {
        this.#done = true;
        for (const event of [...this.#decoder.push(this.#frames.rest()), ...this.#decoder.finish()]) this.#queue.push(parsePeerFrame(event.event, event.data));
        continue;
      }
      this.#frames.push(read.value);
    }
  }

  cancel(): void {
    this.#done = true;
    this.#reader.cancel().catch(() => {});
  }
}

/**
 * The snapshot's stack relays and their signing keys:
 * what a channel peer's attach and attestation are checked against (`PeerRegistry.syncRelays`).
 */
export function stackRelayKeysOf(snapshot: Pick<GatewaySnapshot, "routes">): Map<string, string> {
  const keys = new Map<string, string>();
  for (const route of snapshot.routes) {
    const lane = route.lane;
    if (route.auth !== "lane_relay" || lane === undefined || lane === null || lane.mode !== "stack") continue;
    keys.set(lane.relayId, lane.signingPublicKey);
  }
  return keys;
}
