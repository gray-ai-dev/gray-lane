import type { Protocol } from "@gray/protocol";

/**
 * The vendor-native media APIs a mapping's `adapter` may name (crates/gray-media-adapters/src/lib.rs
 * `ADAPTERS`, `Vendor::for_adapter`, `Vendor::supports`).
 */
export const ADAPTERS = ["gemini", "volcengine", "minimax", "kling", "fal"] as const;

type Operation = "image_generation" | "image_edit" | "image_poll" | "image_result" | "speech" | "video_create" | "video_poll" | "video_content";
type Vendor = "gemini_imagen" | "gemini_veo" | "volcengine_ark" | "minimax" | "kling" | "fal";

function supports(vendor: Vendor, op: Operation): boolean {
  switch (vendor) {
    case "gemini_imagen":
      return op === "image_generation" || op === "image_edit";
    case "gemini_veo":
      return op === "video_create" || op === "video_poll" || op === "video_content";
    case "volcengine_ark":
      return op !== "image_poll" && op !== "image_result" && op !== "speech";
    case "minimax":
      return op !== "image_poll" && op !== "image_result";
    case "kling":
    case "fal":
      return op !== "speech";
  }
}

function forAdapter(label: string, op: Operation): Vendor | null {
  let vendor: Vendor;
  switch (label) {
    case "gemini":
      vendor = op === "video_create" || op === "video_poll" || op === "video_content" ? "gemini_veo" : "gemini_imagen";
      break;
    case "volcengine":
      vendor = "volcengine_ark";
      break;
    case "minimax":
      vendor = "minimax";
      break;
    case "kling":
      vendor = "kling";
      break;
    case "fal":
      vendor = "fal";
      break;
    default:
      return null;
  }
  return supports(vendor, op) ? vendor : null;
}

/** `gray_control::adapter_serves`: the adapter serves image generations and edits, speech or video of `protocol`. */
export function adapterServes(adapter: string, protocol: Protocol): boolean {
  const op: Operation | null =
    protocol === "open_ai_image_generations"
      ? "image_generation"
      : protocol === "open_ai_image_edits"
        ? "image_edit"
        : protocol === "open_ai_speech"
          ? "speech"
          : protocol === "open_ai_videos"
            ? "video_create"
            : null;
  return op !== null && forAdapter(adapter, op) !== null;
}

/**
 * What an image offer on a Gemini image model's per-image route says of a Gemini client's answer beyond
 * its images (crates/gray-gateway/src/provider_offers.rs `OfferMediaTerms` on main): an answer without
 * an image costs one image at the price the request's size selects (`text_answer: "one_image"`), Google
 * Search grounding is included in the image price (`grounding: "included"`), and the relay bills each
 * thought image an answer carries as an image (`thought_images: "billed"`). Unset, the provider has not
 * said: Gray delivers no answer without an image there, forwards no grounding, and bills no thought
 * image, as Google charges none.
 */
export const TEXT_ANSWERS = ["one_image"] as const;
export const GROUNDINGS = ["included"] as const;
export const THOUGHT_IMAGES = ["billed"] as const;
export type TextAnswer = (typeof TEXT_ANSWERS)[number];
export type Grounding = (typeof GROUNDINGS)[number];
export type ThoughtImages = (typeof THOUGHT_IMAGES)[number];

/** The terms of an offer's media that say what a per-image price covers of a Gemini answer. */
export interface GeminiAnswerTerms {
  readonly text_answer: TextAnswer | null;
  readonly grounding: Grounding | null;
  readonly thought_images: ThoughtImages | null;
  readonly unit_prices: Readonly<Record<string, number>>;
}

/** Why an offer that says what its image price covers of a Gemini answer is refused on a price that is not per image (`GEMINI_ANSWERS_NEED_IMAGE_PRICE`). */
export const GEMINI_ANSWERS_NEED_IMAGE_PRICE =
  "text_answer, grounding and thought_images say what a price per image covers: set them only on an image offer with a default (*) unit price.";

/** Why such an offer is refused on a mapping the Gemini adapter does not serve (`GEMINI_ANSWERS_NEED_GEMINI_ADAPTER`). */
export const GEMINI_ANSWERS_NEED_GEMINI_ADAPTER = "text_answer, grounding and thought_images apply to an image mapping through the gemini adapter only.";

/** `OfferMediaTerms::declares_gemini_answers`: whether the terms say anything of a Gemini image model's answers beyond their images. */
export function declaresGeminiAnswers(m: GeminiAnswerTerms): boolean {
  return m.text_answer !== null || m.grounding !== null || m.thought_images !== null;
}

/**
 * `OfferMediaTerms::misplaces_gemini_answers`: whether they say it of anything but a price per image:
 * a route priced by tokens bills an answer's words as tokens, and only an image API answers with images.
 */
export function misplacesGeminiAnswers(m: GeminiAnswerTerms, protocol: Protocol): boolean {
  return declaresGeminiAnswers(m) && (Object.keys(m.unit_prices).length === 0 || (protocol !== "open_ai_image_generations" && protocol !== "open_ai_image_edits"));
}

/**
 * `through_gemini_adapter`, of the offered mapping's adapter: an image route the Gemini adapter serves
 * (`Vendor::for_adapter(adapter, ImageGeneration) == GeminiImagen`), the one that forwards a Gemini
 * client's request, words and grounding included.
 */
export function throughGeminiAdapter(adapter: string | null): boolean {
  return adapter !== null && forAdapter(adapter, "image_generation") === "gemini_imagen";
}
