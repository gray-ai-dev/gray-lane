import type { ImageUsageUnsplit, UsageMissingRule } from "@gray/config";
import type { MediaRates } from "@gray/holds";
import { asArray, asU64, get, type Json } from "@gray/json";
import { isInlineImage } from "@gray/media";
import {
  billableUsage,
  billedTokens,
  charge,
  type CostRates,
  inLedgerRange,
  MeteringError,
  missingUsageReason,
  modalityUsage,
  type Protocol,
  textOutputTokens,
  type UsageCounters,
  usageCost,
} from "@gray/protocol";
import { FREE_NO_USAGE, IMAGE_USAGE_UNSPLIT, type FreeReason } from "./sinks.ts";

/**
 * A Gemini answer's generated image and a usage that does not count it apart (release 4: inference.rs
 * `bill_unsplit_image`, traffic_evidence.rs `gemini_images`; GRAY_IMAGE_USAGE_UNSPLIT, here
 * IMAGE_USAGE_UNSPLIT). A route that prices image output tokens serves only while its image check proved
 * that its usage counts them apart (routes.ts `imageUsageKnown`), but a relay's pool may still answer without
 * the split: yylx answered request de93ee8a (Nano Banana preview, one image and 93 characters) with 1,522
 * output tokens and no `candidatesTokensDetails`, which Gray billed as text at $0 while yylx's own usage
 * summary charged $0.03 for the same call made direct (2026-10-19).
 */

/**
 * Whether a Gemini answer or stream event carries a generated image in any of its candidates, each of which
 * the client gets (`candidateCount`): a part that is not an interim thought, with inline data whose head has
 * a PNG, JPEG or WebP signature by serving's image rule (@gray/media `isInlineImage`). Read from the same
 * payloads the usage is read from: a non-streaming answer's projection keeps a long string's first code
 * units, the head this rule reads.
 */
export function geminiImages(value: Json): boolean {
  const image = (part: Json): boolean => {
    if (get(part, "thought") === true) return false;
    // `inline_data` is read only when `inlineData` is absent, not when it is null (`or_else` on `get`).
    const inline = get(part, "inlineData");
    const data = get(inline === undefined ? get(part, "inline_data") : inline, "data");
    return typeof data === "string" && isInlineImage(data);
  };
  return (asArray(get(value, "candidates")) ?? []).some((candidate) => (asArray(get(get(candidate, "content"), "parts")) ?? []).some(image));
}

/** What `billUnsplitImage` made of the counters: billed at the image price, delivered free, or refused as invalid usage. */
export type UnsplitBilling =
  | { readonly kind: "image_price"; readonly counters: UsageCounters }
  | { readonly kind: "free"; readonly reason: string }
  | { readonly kind: "invalid"; readonly reason: string };

/**
 * `counters` of a Gemini answer that carried a generated image its usage `raw` did not count apart, on a route
 * that prices image output tokens, by `policy`: `image_price` bills the visible output (`candidatesTokenCount`)
 * as image output, thoughts staying text output as Google bills them; `free` delivers it at $0. A visible
 * output larger than the billable output is invalid usage, as a counter that is not a non-negative integer is.
 */
export function billUnsplitImage(counters: UsageCounters, raw: Json, policy: ImageUsageUnsplit): UnsplitBilling {
  const stated = get(raw, "candidatesTokenCount");
  let visible = 0n;
  if (stated !== undefined && stated !== null) {
    const count = asU64(stated);
    if (count === undefined) return { kind: "invalid", reason: "usage.candidatesTokenCount must be a non-negative integer" };
    visible = count;
  }
  if (policy === "free") {
    return { kind: "free", reason: `the answer carried a generated image and its usage counted no image tokens apart (no IMAGE entry in candidatesTokensDetails; candidatesTokenCount ${visible})` };
  }
  const billed: UsageCounters = { ...counters, image_output_tokens: visible };
  if (textOutputTokens(billed) === undefined) return { kind: "invalid", reason: "candidatesTokenCount exceeds the billable output" };
  return { kind: "image_price", counters: billed };
}

/**
 * Why an answer was not charged (inference.rs `FinishError`, less Gray's own failure to record the charge,
 * `LocalFinalization`): its usage is missing (`usage_missing`), malformed or unbillable (`upstream_usage`),
 * above the output the request allowed (`output_over_limit`), or, under IMAGE_USAGE_UNSPLIT free, it carried
 * a generated image its usage did not count apart (`image_usage_unsplit`, delivered at $0, never refused).
 * `reason` says which counter, in Gray's own words and counts.
 */
export interface FinishError {
  readonly kind: "usage_missing" | "upstream_usage" | "output_over_limit" | "image_usage_unsplit";
  readonly reason: string;
}

/** `FinishError::status`: each is the upstream's failure, a 502. */
export function finishStatus(_error: FinishError): 502 {
  return 502;
}

/** `FinishError::code`: the code of the request's failure and of its usage refusal event. */
export function finishCode(error: FinishError): string {
  switch (error.kind) {
    case "usage_missing":
      return "upstream_usage_missing";
    case "upstream_usage":
      return "billing_usage_invalid";
    case "output_over_limit":
      return "upstream_usage_exceeds_limit";
    case "image_usage_unsplit":
      return "image_usage_unsplit";
  }
}

/**
 * The refusal of usage that `billableUsage` or `modalityUsage` would not bill once no counter it bills on is
 * missing (`FinishError::of_counters`): counters malformed or contradicting each other.
 */
function ofCounters(error: unknown): FinishError {
  if (!(error instanceof MeteringError)) throw error;
  return { kind: "upstream_usage", reason: error.message };
}

/** Whether a price prices image or audio tokens apart from text (`prices_modalities`). */
function pricesModalities(media: MediaRates): boolean {
  return media.imageInput !== undefined || media.audioInput !== undefined || media.imageOutput !== undefined || media.audioOutput !== undefined;
}

/** What `usageCounters` read: the counters billed on and whether the answer's image was billed unsplit, or why it is not charged. */
export type CountersRead = { readonly ok: true; readonly counters: UsageCounters; readonly imageUnsplit: boolean } | { readonly ok: false; readonly error: FinishError };

/**
 * `usage_counters`: the counters an answer's usage `raw` is billed on at a route priced by `media` (the
 * supplier's media prices), and whether its image was billed unsplit: `billableUsage` (a counter it bills
 * on that is missing is `usage_missing`, `missingUsageReason`), the image and audio subsets where the route
 * prices any of them apart (`modalityUsage`), and a generated image the usage does not count apart by
 * `policy` (`billUnsplitImage`): a Gemini answer that carried one (`answeredImage`, `geminiImages`) on a
 * route that prices image output tokens, whose image output tokens are 0. Such a route serves only while
 * its check proved the split, but a relay's pool does not always send it (yylx, request de93ee8a,
 * 2026-10-18), and billed as text it cost $0 where the relay charged $0.03.
 */
export function usageCounters(protocol: Protocol, raw: Json, media: MediaRates, answeredImage: boolean, policy: ImageUsageUnsplit): CountersRead {
  const billed = billedTokens(protocol, raw);
  if (billed.kind === "missing") return { ok: false, error: { kind: "usage_missing", reason: missingUsageReason(protocol, raw) } };
  let counters: UsageCounters;
  try {
    counters = billableUsage(protocol, raw);
    if (pricesModalities(media)) counters = modalityUsage(protocol, raw, counters);
  } catch (error) {
    return { ok: false, error: ofCounters(error) };
  }
  const unsplit = protocol === "gemini" && answeredImage && media.imageOutput !== undefined && counters.image_output_tokens === 0n;
  if (!unsplit) return { ok: true, counters, imageUnsplit: false };
  const unsplitBilled = billUnsplitImage(counters, raw, policy);
  if (unsplitBilled.kind === "invalid") return { ok: false, error: { kind: "upstream_usage", reason: unsplitBilled.reason } };
  if (unsplitBilled.kind === "free") return { ok: false, error: { kind: "image_usage_unsplit", reason: unsplitBilled.reason } };
  return { ok: true, counters: unsplitBilled.counters, imageUnsplit: true };
}

/** What `priced` made of the counters: the charge, or why the usage cannot be billed and whether it was the request's bound that refused it. */
export type PricedCharge = { readonly ok: true; readonly amount: bigint } | { readonly ok: false; readonly error: FinishError; readonly overBound: boolean };

/**
 * `priced`: the charge of `counters` at the attempt's `rates`, up to `bound`, the most the request may be
 * charged (@gray/protocol `charge`); or why the usage cannot be billed (`Admission::checked`). A count
 * beyond the ledger's range is the upstream's usage, not a fault of Gray's: refused here it releases the
 * hold, where the ledger would refuse the completion. At a zero rate such a count would otherwise pass the
 * charge check.
 */
export function priced(counters: UsageCounters, rates: CostRates, bound: bigint): PricedCharge {
  if (!inLedgerRange(counters)) return { ok: false, error: { kind: "upstream_usage", reason: "a usage counter is above the ledger's range of 9223372036854775807" }, overBound: false };
  try {
    return { ok: true, amount: charge(counters, rates, bound) };
  } catch (error) {
    if (!(error instanceof MeteringError)) throw error;
    const cost = usageCost(counters, rates);
    return { ok: false, error: { kind: "upstream_usage", reason: error.message }, overBound: cost !== undefined && cost > bound };
  }
}

/**
 * `charged_usage_note`: the attempt's `usage_note` once its answer is charged: `image_usage_unsplit` when
 * the image of the answer was billed though its usage did not count it apart (`usageCounters`), which the
 * alert and the counter say too.
 */
export function chargedUsageNote(imageUnsplit: boolean): typeof IMAGE_USAGE_UNSPLIT | null {
  return imageUnsplit ? IMAGE_USAGE_UNSPLIT : null;
}

/** Why an answer is delivered free (`FreeDelivery`): its usage is missing, or its image was not counted apart. */
export type FreeDelivery = "usage_missing" | "image_usage_unsplit";

/** `FreeDelivery::free_reason`: the request log's `free_reason`. */
export function freeReasonOf(why: FreeDelivery): FreeReason {
  return why === "usage_missing" ? FREE_NO_USAGE : IMAGE_USAGE_UNSPLIT;
}

/** `FreeDelivery::code`: the code of its `gray.usage_refusal/1` event. */
export function freeDeliveryCode(why: FreeDelivery): "upstream_usage_missing" | "image_usage_unsplit" {
  return why === "usage_missing" ? "upstream_usage_missing" : "image_usage_unsplit";
}

/**
 * `delivered_free`: whether an answer whose usage failed with `error` is still delivered, at $0, and why:
 * one whose image its usage did not count apart always (only IMAGE_USAGE_UNSPLIT free fails it so), one
 * whose usage is missing under USAGE_MISSING free. Null: the usage is refused, before the answer commits
 * where it has not, so another attempt may serve the request. Buffered answers and the end of a stream
 * call the same.
 */
export function deliveredFree(error: FinishError, usageMissing: UsageMissingRule): FreeDelivery | null {
  if (error.kind === "usage_missing" && usageMissing === "free") return "usage_missing";
  if (error.kind === "image_usage_unsplit") return "image_usage_unsplit";
  return null;
}

/**
 * The alert that an answer's image was not counted apart by its usage `raw` (`image_unsplit_alert`, a live
 * warning on the server): naming the request, the endpoint, the model, the visible output count as reported
 * and `policy`, as a Workers Logs line the alerts router tells the team (workers/alerts `image_usage_unsplit`,
 * notify), grouped by endpoint.
 */
export function imageUnsplitAlert(requestId: string, endpoint: string | null, model: string, raw: Json, policy: ImageUsageUnsplit): { readonly [key: string]: Json } {
  return {
    level: "alert",
    event: "image_usage_unsplit",
    alert_key: endpoint === null ? "image_usage_unsplit" : `image_usage_unsplit:${endpoint}`,
    request_id: requestId,
    endpoint,
    model,
    candidates_token_count: get(raw, "candidatesTokenCount") ?? null,
    policy,
  };
}
