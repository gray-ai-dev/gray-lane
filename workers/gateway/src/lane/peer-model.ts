import type { KeyedPublicKey, PeerFailedCode } from "@gray/attest";
import type { Json } from "@gray/json";
import type { BridgeSigner, PeerAttemptState, PeerEndDto, PeerHeadDto, PeerProtocol } from "@gray/lane-wire";
import type { StackTrace } from "@gray/request-index";
import type { StreamTimers } from "../client.ts";
import type { GatewaySnapshot } from "../snapshot.ts";

/**
 * The peer client as the request path sees it (docs/confidential-lane-stack-routing.md sections 4.3–4.7): the peers the
 * registry holds, what an attempt over the hop is made of, and the parts of the registry and of an attempt that
 * `InferenceRun` calls. `peer-client.ts` implements them.
 *
 * This module imports types alone and nothing of the peer check: `peer-client.ts` reaches `@gray/lane-verify` (and,
 * through `peer.ts`, its DCAP adapter), whose dependencies' typings bring Node's into a program. The request path, and
 * so every program that type-checks against it (console, e2e), names only this module.
 */

/** A route's lane record, as the snapshot carries it. */
export type RouteLane = NonNullable<GatewaySnapshot["routes"][number]["lane"]>;

/** One stack VM origin of a relay, as the lane snapshot names it, with the relay's signing key (S57). */
export interface PeerTarget {
  readonly relayId: string;
  /** `https://<host>`: port 443, no path (section 4.2). */
  readonly origin: string;
  /** The relay's signing key from its lane record, 64 hex: the identity the stack VM's boot measured must name it. */
  readonly relayKey: string;
  /**
   * A boot reached over the outbound-only channel (docs/design/relay-outbound-only.md section 3.5): its keyset digest as
   * 64 hex. Such a peer has no origin to dial (`origin` is `channel:<keyset>`); egress reaches it through peerlink's
   * sessions of (relay, keyset).
   */
  readonly keyset?: string;
}

/** The pseudo-origin of a channel peer (`PeerTarget.keyset`). */
export function channelOrigin(keyset: string): string {
  return `channel:${keyset}`;
}

export type PeerStatus = "unverified" | "attesting" | "pinned" | "refused" | "down";

/** What a verified attestation proved of one boot of a stack VM: the pin, and the facts its receipts commit to. */
export interface PeerPin {
  /** The stack VM's keyset digest, `sha256:<64 hex>`: every envelope's `aud`. */
  readonly keysetDigest: string;
  /** The same digest's 64 hex: egress's pin name and the `/peer/<digest>/` path. */
  readonly digest: string;
  readonly spkiSha256: string;
  readonly notAfterMs: number;
  readonly composeHash: string;
  readonly osImageHash: string;
  readonly relayImage: string;
  /** The report the entry verified, served beside the outer receipt (`GET /v1/aci/receipts/{id}/peers/{n}`, section 4.8). */
  readonly report: Json;
  /** The nonce the report was verified for, so a customer can verify it again. */
  readonly nonce: string;
  /** The receipt keys of the keyset the report bound: a late inner receipt is checked under them. */
  readonly receiptKeys: readonly KeyedPublicKey[];
}

/** What the attempts route answered (`GET /v1/peer/attempts/<rid>`, section 4.5's late facts). */
export interface PeerAttemptsReply {
  readonly state: PeerAttemptState;
  readonly receipt: Json | null;
}

/**
 * One peer attempt of an outer receipt, kept with it for its lifetime (section 4.8): what
 * `GET /v1/aci/receipts/{id}/peers/{n}` serves, and how the inner receipt is asked for when the entry does not hold it.
 * It holds no request content: the report, the boot facts, the inner receipt's digest and bytes, and a closure over the
 * entry's signer and egress alone.
 */
export interface StoredPeerAttempt {
  /** The entry's attempt number (the outer events' `n`). */
  readonly n: number;
  /** The entry's request id: the stack VM's attempts key and the inner `peer.entry.rid`. */
  readonly rid: string;
  /** The stack VM's report as the entry verified it, with what it verified it under. */
  readonly attestation: { readonly report: Json; readonly nonce: string; readonly tlsSpkiSha256: string; readonly host: string; readonly relayId: string };
  /** The stack VM's keyset digest and its receipt keys (from the verified report). */
  readonly keysetDigest: string;
  readonly receiptKeys: readonly KeyedPublicKey[];
  /** The outer `peer.answered.inner`, or null: the hop ended without `end`, or the attempt failed. */
  readonly inner: { readonly receiptId: string; readonly receiptSha256: string } | null;
  /** The inner receipt's JCS bytes, when the entry holds them (in band, or fetched late and checked). */
  readonly receipt: Uint8Array | null;
  /** `GET /v1/peer/attempts/<rid>` on the pinned session within `untilMs`; null when no answer came. */
  readonly fetchLate: (untilMs: number) => Promise<PeerAttemptsReply | null>;
}

/** One peer the registry holds. */
export class Peer {
  readonly target: PeerTarget;
  status: PeerStatus = "unverified";
  pin: PeerPin | null = null;
  /** Until when the stack VM keeps this entry's hello (its answer's `not_after_ms`). */
  helloUntil = 0;
  /** Why it is refused or down: a closed code. */
  code: string | null = null;
  /** When a refused peer is checked again, or a down one dialed again. */
  retryAt = 0;
  backoffMs = 0;
  probedAt = 0;
  work: Promise<void> | null = null;
  /** When the job in `work` is let go (`PeerRegistry.maintain`): its start plus its calls' bounds. */
  workUntil = 0;

  constructor(target: PeerTarget) {
    this.target = target;
  }

  get key(): string {
    return peerKey(this.target.relayId, this.target.origin);
  }

  get host(): string {
    return this.target.keyset === undefined ? this.target.origin.slice("https://".length) : "";
  }

  /** Whether this boot is reached over the channel (no origin). */
  get channel(): boolean {
    return this.target.keyset !== undefined;
  }

  /** Whether a request may be sent to it now (L1): pinned, pin and hello current, not resting. */
  usable(now: number): boolean {
    return this.status === "pinned" && this.pin !== null && this.pin.notAfterMs > now && this.helloUntil > now;
  }
}

export function peerKey(relayId: string, origin: string): string {
  return `${relayId} ${origin}`;
}


/** The parts of the registry (`peer-client.ts` `PeerRegistry`) an attempt and the request path call. */
export interface LanePeerRegistry {
  /** The usable peers of `relayId`, newest pin first (L1). Nothing is attested here (L5). */
  usable(relayId: string): Peer[];
  /**
   * What a request's dial found that sent nothing (section 4.7, row 1). `session` is the channel session egress named
   * (`x-gray-peer-session`), for a pin mismatch on a channel peer.
   */
  failed(peer: Peer, code: string, session?: string | null): void;
  /** A request went through. */
  answered(peer: Peer): void;
  /** After `401 peer_unknown`: the hello once more, within `untilMs` (section 5, row 8). */
  rehello(peer: Peer, untilMs: number): Promise<boolean>;
  /** Everything due, in the background. */
  maintain(): Promise<void>;
}

export interface PeerCallInput {
  readonly registry: LanePeerRegistry;
  /** The relay's usable peers for the route, in its origins' order: a dial that sent nothing goes to the next (section 4.7). */
  readonly peers: readonly Peer[];
  /** This entry's keyset digest (the envelope's `entry`) and its receipt key's signer. */
  readonly entry: string;
  readonly signer: BridgeSigner;
  /** The entry's request id (32 hex) and this attempt's number within the request (from 1). */
  readonly rid: string;
  readonly n: number;
  readonly receiptId: string | null;
  readonly route: { readonly endpoint: string; readonly protocol: PeerProtocol; readonly model: string };
  /** The client's path and raw query (`/v1/messages?…`), as the stack VM serves it. */
  readonly path: string;
  /** The client headers the stack path reads (`stack.ts` STACK_CLIENT_HEADERS, STACK_BEHAVIOUR_HEADERS). */
  readonly headers: Readonly<Record<string, string>>;
  /** The client's exact bytes. */
  readonly body: Uint8Array;
  /** What the request has left (the envelope's `budget_ms`). */
  readonly budgetMs: number;
  /**
   * The request's conversation id at the route's relay (`affinity.ts` CONVERSATION_DOMAIN, 32 lower hex), absent when
   * the client named no session: the envelope's `conversation`.
   */
  readonly conversation?: string;
  /**
   * The customer chose relays that change nothing (routing preference `relay_changes: "exclude"`,
   * docs/relay-request-changes.md): the envelope's `relay_changes`, so the stack VM registers the request without
   * `relay_changes`. Absent otherwise.
   */
  readonly relayChanges?: "exclude";
  readonly egress: (input: string, init: RequestInit) => Promise<Response>;
  readonly clock: () => number;
  readonly timers: StreamTimers;
  readonly signal: AbortSignal;
}

/** How a peer attempt's request went, before anything of an answer reached the request path. */
export type PeerSent =
  /** `head` 200: the answer committed on the stack VM; `response` carries the `data` bytes. */
  | { readonly kind: "answered"; readonly response: Response }
  /** `head` and `end` with nothing released, or the vendor's error released: `end` says which. */
  | { readonly kind: "ended"; readonly head: PeerHeadDto; readonly end: PeerEndDto; readonly body: Uint8Array }
  /** Nothing reached a vendor: a dial that sent nothing at every origin, a refusal before any frame. */
  | { readonly kind: "unsent"; readonly code: PeerFailedCode | string }
  /** The request may have reached the stack VM and nothing says whether a vendor was dialed: the follow-up decides. */
  | { readonly kind: "unknown"; readonly code: PeerFailedCode }
  /** The attempt ended first: its signal (the client left, the attempt's bound). */
  | { readonly kind: "aborted" };


/** One attempt over the hop as the request path drives it (`peer-client.ts` `PeerCall`). */
export interface LanePeerCall {
  /** The peer the request went to last. */
  readonly peer: Peer;
  /** The attempt's number within the request (the envelope's `n`). */
  readonly n: number;
  /** When the attempt was made, by the entry's clock. */
  readonly startedAt: number;
  /** The relay's S43 trace of the attempt (`end.trace`, offsets from `startedAt`), or null when `end` carried none. */
  readonly trace: StackTrace | null;
  /** The envelope's digest, once one was signed (`peer.forwarded`). */
  readonly envelopeSha256: string | null;
  readonly head: PeerHeadDto | null;
  readonly end: PeerEndDto | null;
  /** Why the hop gave no answer (`peer.failed`). */
  readonly failure: { readonly code: PeerFailedCode; readonly sent: boolean } | null;
  /** Whether a vendor was dialed, as `end`, `head` or the follow-up said; null when none did. */
  readonly dialed: boolean | null;
  /** The relay account of `end` (S27), or null. */
  readonly accountId: string | null;
  /** The stack VM's attempt served this request (a released answer, or the vendor's error). */
  served: boolean;
  /** Resolves when the hop's answer is over: its `end`, or null. */
  readonly ended: Promise<PeerEndDto | null>;
  send(): Promise<PeerSent>;
  followUp(untilMs: number): Promise<{ readonly state: PeerAttemptState; readonly receipt: Json | null } | null>;
  close(): void;
  /** The commitment naming the peer in the outer receipt (`@gray/attest` `peerCommitment`). */
  commitment(): string;
  /** The inner receipt's id and digest, when `end` carried one. */
  inner(): { readonly receiptId: string; readonly receiptSha256: string } | null;
  /** What the outer receipt keeps of this attempt (section 4.8), or null when nothing was sent to a pinned peer. */
  stored(): StoredPeerAttempt | null;
  /** Whether the request path's reading of the answer's usage is `end.usage`. */
  usageAgrees(rawUsage: Json | null): boolean;
}
