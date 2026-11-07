import { z } from "zod";
import { asBigint, asNumber, uintSchema } from "./ints.ts";

/**
 * `ticket.use`: the lane's record of the model-check tickets' one-time ids (docs/model-authenticity-workflow.md, "Probes
 * are not billed", decided with the user on 2026-11-04; "One-time ids", 2026-11-05). The lane entry is public, so a
 * ticket that leaked with the model-check key could come back there through any lane VM: the lane VMs keep their used
 * ids in one record, which the bridge keeps in a `LaneNonceDO` of its own (the class of its call nonces, never a key's
 * nonce shard), through this op. The main gateway keeps none: only the console's service binding reaches it with a
 * ticket. A lane VM calls it last, once a ticket has passed every other check: `{id, expires_at_ms}`, answered
 * `{fresh: true}` exactly once per id, else `{fresh: false, reason}`. The record keeps the id until its expiry and
 * nothing else: never the ticket, its workspace, its route or the body's SHA-256 it names.
 *
 * Not fresh, and why (review r8 minor 6): an id used before (`reused`), an expiry already past or more than
 * MODEL_CHECK_TICKET_USE_AHEAD_MS ahead on the bridge's clock or the record's (`expired`, `ahead`), an id of another form
 * (`malformed`), a record with no room (`full`, which the lane serves as a record that did not answer). A call that does
 * not answer is the lane's 503, never a free request. The target is the op's one name, which every call signs; the
 * bridge names the record's object itself (by its nonce region).
 */

/** The target every `ticket.use` call signs: the op's one name, whatever object the bridge keeps the ids in. */
export const MODEL_CHECK_TICKETS_TARGET = "model-check-tickets";

/**
 * How far ahead of the bridge's clock an expiry may be (ms): @gray/verifier's MODEL_CHECK_TICKET_AHEAD_MS, which the
 * gateway checks first (the gateway's tests hold the two equal).
 */
export const MODEL_CHECK_TICKET_USE_AHEAD_MS = 600_000;

/** A one-time id: 16 bytes in lower hex (@gray/verifier `MODEL_CHECK_TICKET_ID_PATTERN`). */
export const TICKET_ID_PATTERN = /^[0-9a-f]{32}$/;

export const ticketUseInputSchema = z.object({ id: z.string().regex(TICKET_ID_PATTERN), expires_at_ms: uintSchema }).strict();
export type TicketUseInputDto = z.infer<typeof ticketUseInputSchema>;

/** What the record answers of one use: the id fresh now, or why it is not. */
export const TICKET_USE_OUTCOMES = ["fresh", "reused", "expired", "ahead", "malformed", "full"] as const;
export type TicketUseOutcome = (typeof TICKET_USE_OUTCOMES)[number];

/** Whether `value` is one of the record's outcomes (an object's answer is checked before it is the op's). */
export function isTicketUseOutcome(value: unknown): value is TicketUseOutcome {
  return typeof value === "string" && (TICKET_USE_OUTCOMES as readonly string[]).includes(value);
}

/** `{fresh: true}`, or `{fresh: false, reason}` with the record's reason. */
export const ticketUseAnswerSchema = z.union([
  z.object({ fresh: z.literal(true) }).strict(),
  z.object({ fresh: z.literal(false), reason: z.enum(["reused", "expired", "ahead", "malformed", "full"]) }).strict(),
]);
export type TicketUseAnswerDto = z.infer<typeof ticketUseAnswerSchema>;

export function ticketUseAnswerDtoOf(outcome: TicketUseOutcome): TicketUseAnswerDto {
  return outcome === "fresh" ? { fresh: true } : { fresh: false, reason: outcome };
}

export function ticketUseOutcomeOf(dto: TicketUseAnswerDto): TicketUseOutcome {
  return dto.fresh ? "fresh" : dto.reason;
}

/** One use, as the lane and the bridge's object hold it. */
export interface TicketUse {
  readonly id: string;
  readonly expiresAtMs: number;
}

export function ticketUseInputDtoOf(use: TicketUse): TicketUseInputDto {
  return { id: use.id, expires_at_ms: asBigint(use.expiresAtMs, "expires_at_ms") };
}

export function ticketUseInputOf(dto: TicketUseInputDto): TicketUse {
  return { id: dto.id, expiresAtMs: asNumber(dto.expires_at_ms, "expires_at_ms") };
}
