/**
 * System One decisions (`POST /v1/systemone`, crates/gray-gateway/src/apis/systemone.rs): a `state`
 * object and named `questions` in, one answer per question out, billed by tokens. The model version
 * the answer names is not read (main 2c165fb7: an upstream can print any name, and an upgraded model
 * answers under a new one).
 */
import { type Json, get, isObject } from "@gray/json";
import { type Billed, apiError, billedBy, checkMetered, invalid, jsonModel, missing, strictJson, tokenUsage } from "./common.ts";
import type { Answered } from "./images.ts";
import { readUpstream } from "./read.ts";
import { type ApiRequest, type MediaRoute, type Received, UNBOUNDED } from "./types.ts";

const FIELDS = ["model", "state", "questions", "stream"];

/** `decode`: exactly these fields, a `state` object and a non-empty object of question objects, no streaming. */
export function decodeSystemOne(received: Received): ApiRequest {
  if (received.kind !== "json") throw invalid("invalid_protocol_request");
  const body = received.value;
  const model = jsonModel(body);
  const questions = get(body, "questions");
  const named = isObject(questions) && Object.keys(questions).length > 0 && Object.values(questions).every((q) => isObject(q));
  if (!named || !isObject(get(body, "state"))) throw invalid("invalid_protocol_request");
  const stream = get(body, "stream");
  if (stream !== undefined && stream !== false) throw invalid("streaming_unsupported");
  if (isObject(body) && Object.keys(body).some((k) => !FIELDS.includes(k))) throw invalid("unsupported_request_field");
  if (!isObject(body)) throw invalid("invalid_protocol_request");
  // The service tokenizes the state and questions with its own template and takes no output limit:
  // neither count is knowable up front, so the request reserves its ceiling and settles on usage.
  return { model, stream: false, selectors: [], bound: UNBOUNDED, body: { kind: "json", value: body } };
}

export interface SystemOneAttempt {
  readonly billsUnits: boolean;
  readonly deadlineMs: number;
  readonly responseBytes: number;
}

/**
 * The checks and metering of a System One answer (`respond`, on the parsed answer or on a streamed
 * answer's projection, which keeps the type of `answers` and the whole usage): an `answers` object and
 * token usage. Throws the answer's refusal as an ApiError.
 */
export function systemOneAnswer(value: Json, billsUnits: boolean): Billed {
  if (!isObject(get(value, "answers"))) throw apiError(502, "invalid_upstream_response");
  const usage = get(value, "usage");
  if (usage === undefined) return missing("usage missing");
  const billed = billedBy(() => ({ counters: tokenUsage(usage, "input_tokens", "output_tokens"), raw: usage, unit: undefined }), usage);
  if (billed.kind === "metered") checkMetered("system_one", UNBOUNDED, billed.metered, billsUnits);
  return billed;
}

/** `respond`: an `answers` object and token usage; the body goes back as received. */
export async function respondSystemOne(_api: ApiRequest, _route: MediaRoute, upstream: Response, attempt: SystemOneAttempt): Promise<Answered> {
  const bytes = await readUpstream(upstream, attempt.responseBytes, attempt.deadlineMs);
  return { body: bytes, contentType: "application/json", billed: systemOneAnswer(strictJson(bytes), attempt.billsUnits) };
}
