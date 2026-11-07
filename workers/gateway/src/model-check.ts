import type { TicketUseOutcome } from "@gray/lane-wire";
import type { Preference } from "@gray/routing";
import { MODEL_CHECK_TICKET_AHEAD_MS, MODEL_CHECK_TICKET_HEADER, readModelCheckTicket, ticketBodyHash, verifyModelCheckTicket } from "@gray/verifier/model-check-ticket";
import type { Body } from "./body.ts";

/**
 * A ModelTrace probe's ticket at the gateway (docs/model-authenticity-workflow.md, "Probes are not billed", decided with
 * the user on 2026-11-04; Workers only): a request is a model check (free, pinned, unpaid, listed to the provider) only
 * when the ticket the console signed for it passes every check, in this order, once its body is read and its preference
 * taken: the ticket reads; its kid is one the routing snapshot publishes (`modelCheckKeys`); its signature verifies; its
 * workspace is the key's; the request's own preference (before the stored defaults are layered over it) has its route,
 * and only it, in `only`; the body is held (a tier C body, spooled, is never a model check) and its SHA-256 is the
 * ticket's; the ticket has not expired and expires at most MODEL_CHECK_TICKET_AHEAD_MS ahead; and on the main gateway it
 * came over a service binding (no `cf-connecting-ip`, which Cloudflare sets on every request from the internet). Then
 * inference.ts checks the pin (`modelCheckPinned`, 400 `model_check_unpinned`), and on the lane entry uses the ticket's
 * one-time id (`ModelCheckTicketStore`). Anything else is an ordinary request, refused for the model-check workspace's
 * want of credit, and said at warn level with its reason only. A key alone or a ticket alone gives nothing.
 *
 * Only the lane entry keeps a record of the ids used (decided with the user on 2026-11-05): it is public, so a ticket
 * that leaked with the model-check key could come back there, through any lane VM, and the bridge keeps the ids for
 * every lane VM. The main gateway keeps none and asks none: only the console's service binding reaches it with a ticket
 * (`TicketRequest.serviceBinding`), and the console signs a new ticket for every request it sends, retries too.
 *
 * The ticket and its claims stay in this module and the request's memory: never forwarded (every upstream, peer and
 * stack-container request carries allowlisted client headers only), never recorded (`withoutTicket`), never logged; the
 * lane entry's used-ticket record keeps the id and its expiry only. The body's SHA-256 the ticket names is no field the
 * lane adds: the lane's receipt (`request.received.body_hash`) and peer envelope (`received_sha256`) carry the received
 * body's for every request, as before, the receipt only to whoever presented the request's key and the envelope only to
 * Gray's stack VM, so a probe carries the same fields as a customer's request (review r8 finding 3).
 */

/**
 * Why a ticket made no model check: the codes of the warn line `model_check_ticket_refused`. The last four are the lane
 * entry's record's (review r8 minor 6): an id used before, and an id the record refused by its own clock or form.
 */
export type TicketRefusal =
  | "malformed"
  | "unknown_key"
  | "signature"
  | "workspace"
  | "pin"
  | "body"
  | "expired"
  | "ahead"
  | "not_service_binding"
  | "spooled"
  | "reused"
  | "expired_at_store"
  | "ahead_at_store"
  | "malformed_at_store";

/** Why the lane entry's record of used tickets made no answer the request can use: the `reason` of `model_check_ticket_store_unavailable`. */
export type TicketStoreUnavailable = "no_store" | "unanswered" | "full";

/**
 * The lane entry's record of the one-time ids used: the bridge op `ticket.use` (lane/remote/tickets.ts), whose ids the
 * bridge keeps in a `LaneNonceDO` of their own. `use` answers `fresh` once per id, recording it until `expiresAtMs`, or
 * why the id is not fresh (@gray/lane-wire `TicketUseOutcome`), and throws when the record does not answer. A record
 * that throws or is full is one that cannot remember, and such a request is never free (503
 * `billing_admission_unavailable`). The main gateway keeps none (the file comment).
 */
export interface ModelCheckTicketStore {
  use(id: string, expiresAtMs: number): Promise<TicketUseOutcome>;
}

/** What a request makes of the record's outcome: a model check, an ordinary request with its refusal, or the record unavailable. */
export function ticketUseVerdict(outcome: TicketUseOutcome): { readonly kind: "fresh" } | { readonly kind: "refused"; readonly reason: TicketRefusal } | { readonly kind: "unavailable"; readonly reason: TicketStoreUnavailable } {
  switch (outcome) {
    case "fresh":
      return { kind: "fresh" };
    case "full":
      return { kind: "unavailable", reason: "full" };
    case "reused":
      return { kind: "refused", reason: "reused" };
    case "expired":
      return { kind: "refused", reason: "expired_at_store" };
    case "ahead":
      return { kind: "refused", reason: "ahead_at_store" };
    case "malformed":
      return { kind: "refused", reason: "malformed_at_store" };
  }
}

/** What the checks before the one-time id read of the request. */
export interface TicketRequest {
  /** The header's value. */
  readonly ticket: string;
  /** The snapshot's published keys, kid to 64 lower hex digits; absent: none. */
  readonly keys: Readonly<Record<string, string>> | undefined;
  /** The key's workspace. */
  readonly workspace: string;
  /** The request's own preference, before the stored defaults (`Preference.take`). */
  readonly own: Preference;
  readonly body: Body;
  readonly now: number;
  /**
   * The main gateway: whether the request came over a service binding (no cf-connecting-ip); null on the lane, public by
   * design. The console's MODEL_CHECK_GATEWAY is the one binding of the gateway's default entrypoint
   * (workers/production/test/gateway-default-entrypoint.test.ts fails any other in the wrangler files), so a ticket that
   * comes over one was sent by the console, which signs a new one for every request: the main gateway keeps no record of
   * the ids used.
   */
  readonly serviceBinding: boolean | null;
}

/** The checks' answer: the one-time id to use and its expiry, or why the request is an ordinary one. */
export type TicketCheck = { readonly ok: true; readonly id: string; readonly expiresAtMs: number } | { readonly ok: false; readonly reason: TicketRefusal };

/** The checks before the one-time id, in the decided order (the file comment). Never throws. */
export async function checkTicket(r: TicketRequest): Promise<TicketCheck> {
  const refused = (reason: TicketRefusal): TicketCheck => ({ ok: false, reason });
  const ticket = readModelCheckTicket(r.ticket);
  if (ticket === null) return refused("malformed");
  const publicKey = r.keys !== undefined && Object.hasOwn(r.keys, ticket.kid) ? r.keys[ticket.kid] : undefined;
  if (publicKey === undefined) return refused("unknown_key");
  if (!(await verifyModelCheckTicket(ticket, publicKey))) return refused("signature");
  const { claims } = ticket;
  if (claims.ws !== r.workspace) return refused("workspace");
  if (r.own.only.length !== 1 || r.own.only[0] !== claims.pin) return refused("pin");
  if (r.body.tier === "C") return refused("spooled");
  if ((await ticketBodyHash(r.body.bytes)) !== claims.body) return refused("body");
  if (claims.exp <= r.now) return refused("expired");
  if (claims.exp > r.now + MODEL_CHECK_TICKET_AHEAD_MS) return refused("ahead");
  if (r.serviceBinding === false) return refused("not_service_binding");
  return { ok: true, id: claims.id, expiresAtMs: claims.exp };
}

/** The request's ticket header, or null without one: a request without it is served as before. */
export function ticketHeader(headers: Headers): string | null {
  return headers.get(MODEL_CHECK_TICKET_HEADER);
}

/** `headers` without the ticket's: what a request's record keeps of them, valid ticket or not (content details, public records). */
export function withoutTicket(headers: Headers): Headers {
  if (!headers.has(MODEL_CHECK_TICKET_HEADER)) return headers;
  const kept = new Headers(headers);
  kept.delete(MODEL_CHECK_TICKET_HEADER);
  return kept;
}
