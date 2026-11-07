import type { Outcome } from "./protocol.ts";

/**
 * The money rules of a request's end, in the order gray_record_completion_v2 applies them
 * (crates/gray-ledger/src/sql/settlement.sql:177-236). The shard decides first; the projection runs
 * the same function in PostgreSQL, and a different verdict there is a bug that raises an alert
 * (docs/cloudflare-native.md section 2.3, rule 5, and 5.3).
 *
 *   LG005  an accrual whose provider has no address. PostgreSQL then writes the completion as a
 *          transaction that derives the address. A shard does not know addresses: it refuses only
 *          an accrual without a provider (no provider can have an address), and the address of a
 *          named provider is derived when the batch is projected (5.2).
 *   LG001  the request was released or is under review; a charge above its bound
 *          (`amount > COALESCE(bound, held)`); and, the shard's own rule, a token past its expiry
 *          (5.5: a settlement after the hold's lifetime is refused and alerts).
 *   LG002  completed before with another amount or evidence hash. The same completion again is
 *          answered with the first result and writes nothing. (The SQL's other LG002, a second
 *          accrual for the request, cannot arise in a shard, which closes a hold once; PostgreSQL's
 *          unique accrual per request still backs it when the batch is projected.)
 *   LG003  no record of the request: a token whose hold this shard never issued.
 *   LG004  an accrual that owes its provider more than the request charges (`payable > amount`).
 */

export interface CompletionFields {
  readonly amount: number;
  readonly evidenceHash: string | null;
  readonly provider: string | null;
  readonly payable: number | null;
  readonly accrualId: string | null;
}

/** How a hold already ended, as far as the rules need it. */
export interface PriorClose {
  readonly outcome: Outcome;
  readonly amount: number;
  readonly evidenceHash: string | null;
}

export interface HoldTerms {
  readonly bound: number;
  readonly held: number;
  readonly expiresAt: number;
}

export type CompletionVerdict =
  | { readonly kind: "refuse"; readonly code: "LG001" | "LG002" | "LG004" | "LG005"; readonly message: string }
  | { readonly kind: "replay"; readonly prior: PriorClose }
  | { readonly kind: "complete" };

export function checkCompletion(f: CompletionFields, hold: HoldTerms, prior: PriorClose | null, now: number): CompletionVerdict {
  // settlement.sql:189-191, checked before the request's row is read.
  if (f.accrualId !== null && f.provider === null) {
    return { kind: "refuse", code: "LG005", message: "an accrual needs its provider, and a missing provider has no address" };
  }
  if (prior !== null) {
    // settlement.sql:195-197: released (or under review) cannot complete.
    if (prior.outcome === "released") return { kind: "refuse", code: "LG001", message: "the request was released" };
    // settlement.sql:198-206: `r.amount<>p_amount OR r.evidence_hash IS DISTINCT FROM p_evidence_hash`.
    if (prior.amount !== f.amount || prior.evidenceHash !== f.evidenceHash) {
      return { kind: "refuse", code: "LG002", message: "the request was completed with another amount or evidence" };
    }
    return { kind: "replay", prior };
  }
  if (now > hold.expiresAt) return { kind: "refuse", code: "LG001", message: "the hold expired before it was settled" };
  // settlement.sql:207-209: above COALESCE(bound, held); a token always carries its bound.
  if (f.amount > hold.bound) return { kind: "refuse", code: "LG001", message: `charge ${f.amount} is above its bound ${hold.bound}` };
  // settlement.sql:213-216, with SQL's null semantics: no payable, nothing to compare.
  if (f.accrualId !== null && f.payable !== null && f.payable > f.amount) {
    return { kind: "refuse", code: "LG004", message: "the request owes its provider more than it charges" };
  }
  return { kind: "complete" };
}

/** The outcome a completion records: `free` for nothing charged, as the SQL's `state` (settlement.sql:210). */
export function completionOutcome(amount: number): Outcome {
  return amount === 0 ? "free" : "charged";
}
