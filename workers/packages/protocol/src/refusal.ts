/**
 * A refusal by the model, as Gemini answers it: with HTTP 200 and no content, where other APIs refuse a
 * request with a 4xx (crates/gray-protocol/src/refusal.rs). Such an answer is the model's verdict on
 * the request's content, the same from every provider of the model, so serving delivers it as it came,
 * holds it neither for nor against the route, and charges nothing for it.
 */
import { type Json, asStr, get, isArray, pointer } from "@gray/json";

/**
 * The finish reasons with which Gemini ends a candidate it would not generate for the request: a
 * safety, recitation, blocklist, prohibited-content, personal-data or language stop, an image it would
 * not show for one of those, or no image drawn for the prompt (`NO_IMAGE`, which Google's image guide
 * answers by asking for the image explicitly) (https://ai.google.dev/api/generate-content#FinishReason).
 * A stop that says nothing of the request is not listed: an image stopped for "other miscellaneous
 * issue" (`IMAGE_OTHER`), like a malformed response, is a failed generation; an account limited for
 * prohibited use (`PUP_LIMITED_DISABLED`) is the provider's fault; and an escalation rule
 * (`ESCALATION`) says nothing of whose.
 */
const GEMINI_REFUSALS: readonly string[] = [
  "SAFETY",
  "RECITATION",
  "LANGUAGE",
  "BLOCKLIST",
  "PROHIBITED_CONTENT",
  "SPII",
  "IMAGE_SAFETY",
  "IMAGE_PROHIBITED_CONTENT",
  "IMAGE_RECITATION",
  "NO_IMAGE",
];

/** `is_gemini_refusal`: whether a Gemini candidate's `finishReason` is a refusal of the request's content. */
export function isGeminiRefusal(finishReason: string): boolean {
  return GEMINI_REFUSALS.includes(finishReason);
}

/**
 * The reasons for which Gemini blocks a prompt (`promptFeedback.blockReason`), other than its
 * unspecified default (https://ai.google.dev/api/generate-content#BlockReason).
 */
const GEMINI_BLOCK_REASONS: readonly string[] = ["SAFETY", "OTHER", "BLOCKLIST", "PROHIBITED_CONTENT", "IMAGE_SAFETY"];

/**
 * `gemini_block_reason`: the reason a prompt blocked with `blockReason` is named by: Gemini's own when
 * it is one of its documented reasons, else `OTHER`. Gray names the model's reason in errors of its
 * own, and a relay's own words in the field are not repeated there as the model's.
 */
export function geminiBlockReason(blockReason: string): string {
  return GEMINI_BLOCK_REASONS.includes(blockReason) ? blockReason : "OTHER";
}

/** The part fields that carry an answer's content, in both spellings Gemini's JSON accepts. A thought, a signature and an empty text carry none. */
const CONTENT_FIELDS: readonly string[] = [
  "inlineData",
  "inline_data",
  "fileData",
  "file_data",
  "functionCall",
  "function_call",
  "functionResponse",
  "function_response",
  "executableCode",
  "executable_code",
  "codeExecutionResult",
  "code_execution_result",
];

function carriesContent(part: Json): boolean {
  if (get(part, "thought") === true) return false;
  const text = asStr(get(part, "text"));
  return (text !== undefined && text.length > 0) || CONTENT_FIELDS.some((field) => get(part, field) !== undefined);
}

/**
 * `GeminiRefusal`: what a Gemini answer has shown of a refusal by the model, fed the body of a buffered
 * answer or each event of a streamed one: a blocked prompt (`promptFeedback.blockReason`) or a candidate
 * that ended for a refusal reason (`isGeminiRefusal`), and whether any candidate carried content (a part
 * that is no thought, with text or one of the content fields). The answer is the model's refusal when
 * it gave a reason and no content; an answer that delivered content before a safety stop is an answer.
 */
export class GeminiRefusal {
  private refusedFor: string | undefined;
  private content = false;

  /** The refusal a buffered answer is, if it is one. */
  static of(answer: Json): string | undefined {
    const refusal = new GeminiRefusal();
    refusal.observe(answer);
    return refusal.reason();
  }

  /** Notes one answer body or stream event. */
  observe(answer: Json): void {
    const blocked = asStr(pointer(answer, "/promptFeedback/blockReason"));
    if (blocked !== undefined && blocked !== "" && blocked !== "BLOCK_REASON_UNSPECIFIED") this.refusedFor ??= geminiBlockReason(blocked);
    const candidates = get(answer, "candidates");
    for (const candidate of isArray(candidates) ? candidates : []) {
      const parts = pointer(candidate, "/content/parts");
      if (isArray(parts) && parts.some(carriesContent)) this.content = true;
      const finish = asStr(get(candidate, "finishReason"));
      if (finish !== undefined && isGeminiRefusal(finish)) this.refusedFor ??= finish;
    }
  }

  /** The model's reason, when what was observed is its refusal and nothing else. */
  reason(): string | undefined {
    return this.content ? undefined : this.refusedFor;
  }
}
