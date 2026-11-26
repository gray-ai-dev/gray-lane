import { ApiError } from "@gray/errors";

/**
 * Small pieces the inference run (inference.ts), the count-tokens run (count-tokens.ts) and the API routes (apis.ts)
 * share, so each is written once.
 */

/** 403 for a customer key sent to a relay's VM, which serves only Gray's entries (section 4.6). */
export function laneEntryRequired(): ApiError {
  return new ApiError(403, "lane_entry_required").withMessage(
    "This relay is served through Gray's confidential lane, not at its own address. Send your requests to the confidential lane address in your Gray console; it routes them to this relay.",
  );
}

/** A lane receipt id: `rcpt_` and 32 lowercase hex digits, the shape the entry's route and the tests pin. */
export function newLaneReceiptId(): string {
  return `rcpt_${crypto.randomUUID().replaceAll("-", "")}`;
}

/**
 * A failure's content-free names for a lane's log (its message may carry content): its class, and its
 * closed `code` word when it has one (`ReceiptError`'s, an API error's).
 */
export function failureNames(error: unknown): { readonly error: string; readonly code?: string } {
  const name = error instanceof Error ? error.name : typeof error;
  const code = typeof error === "object" && error !== null ? (error as { readonly code?: unknown }).code : undefined;
  return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? { error: name, code } : { error: name };
}
