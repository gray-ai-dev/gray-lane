/**
 * Speech, transcription and translation (`POST /v1/audio/speech`, `/v1/audio/transcriptions`,
 * `/v1/audio/translations`), billed per input character, per audio second or by audio tokens
 * (crates/gray-gateway/src/apis/audio.rs; the module docs there give every rule's reason).
 *
 * Speech takes OpenAI's JSON, checked against OpenAI's limits before anything is sent, and is
 * billed in characters only: Gray counts `input` plus `instructions` on an OpenAI-compatible route;
 * a vendor route bills the vendor's confirmed count. The character bound counts one per ASCII
 * character and two per other character. The audio is buffered within the response limit;
 * uncompressed audio of a long input at a slow speaking rate is refused up front.
 *
 * Transcription and translation take OpenAI's multipart form and answer in each of its formats:
 * `json` (and `text`) is asked upstream for a transcription's `text`, `verbose_json` for `srt` and
 * `vtt` and for every translation, and the answer is converted back. Billing reads `usage`
 * (`duration` seconds or `tokens`), else a `verbose_json` duration on a unit-priced route.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, type UsageCounters, OPENAI_LINKING_FIELDS, ZERO_COUNTERS, nestedCounter, rustTrim, textInputTokens } from "@gray/protocol";
import { type Json, type JsonObject, get, isObject, toJsonString } from "@gray/json";
import { authHeaders, build } from "../adapters.ts";
import { AdapterError } from "../error.ts";
import type { HttpCall } from "../types.ts";
import { parseRustF64, parseSerdeSlice } from "../util.ts";
import {
  type Billed,
  UsageError,
  UsageUnreported,
  apiError,
  checkMetered,
  countedUnits,
  metered,
  missing,
  formText,
  invalid,
  jsonModel,
  optionalCounter,
  capabilityUnproved,
  preferProvingAll,
  retainServing,
  strictJson,
  tokenUsage,
  vendorAnswer,
  vendorFor,
  vendorRequest,
  type Outgoing,
} from "./common.ts";
import type { Answered } from "./images.ts";
import { readUpstream } from "./read.ts";
import { type ApiRequest, type Clock, type FormPart, type MediaRoute, type Metered, type Received, UNBOUNDED, nowUnix, partSize, partText } from "./types.ts";

const SPEECH_FIELDS = ["model", "input", "voice", "instructions", "response_format", "speed", "stream_format"];
const SPEECH_FORMATS = ["mp3", "opus", "aac", "flac", "wav", "pcm"];
/** Formats whose size follows the audio length (FLAC at its worst). */
const UNCOMPRESSED_FORMATS = ["wav", "pcm", "flac"];
/** OpenAI's limit on `input`, in characters; `instructions` share it. */
export const MAX_SPEECH_CHARACTERS = 4096;
/** OpenAI's `speed` range. */
const SPEED_MIN = 0.25;
const SPEED_MAX = 4.0;
/** Bytes a second of 24 kHz 16-bit mono PCM, OpenAI's uncompressed output. */
const PCM_BYTES_PER_SECOND = 48_000;
/** A slow speaking rate at speed 1, for the size of uncompressed audio. */
const SLOW_CHARACTERS_PER_SECOND = 10;
const TRANSCRIPTION_FIELDS = [
  "file",
  "model",
  "language",
  "prompt",
  "response_format",
  "temperature",
  "timestamp_granularities[]",
  "include[]",
  "stream",
  "chunking_strategy",
  // An object field as OpenAI's SDKs put it in a form.
  "chunking_strategy[type]",
  "chunking_strategy[prefix_padding_ms]",
  "chunking_strategy[silence_duration_ms]",
  "chunking_strategy[threshold]",
];
const TRANSLATION_FIELDS = ["file", "model", "prompt", "response_format", "temperature"];
/** Longest upstream audio content type passed through. */
const MAX_CONTENT_TYPE = 128;
/** Longest billed duration read from an answer (a day of audio). */
const MAX_SECONDS = 86_400;
const JSON_TYPE = "application/json";
const TEXT_TYPE = "text/plain; charset=utf-8";
const VTT_TYPE = "text/vtt; charset=utf-8";

/** `decode` for the audio APIs. `responseBytes` is the media answer limit the speech size check holds to. */
export function decodeAudio(protocol: Protocol, received: Received, responseBytes: number): ApiRequest {
  if (protocol === "open_ai_speech") {
    if (received.kind !== "json") throw invalid("invalid_protocol_request");
    return decodeSpeech(received.value, responseBytes);
  }
  if (protocol === "open_ai_transcriptions" || protocol === "open_ai_translations") {
    if (received.kind !== "form") throw invalid("invalid_protocol_request");
    return decodeTranscription(protocol, received.parts);
  }
  throw apiError(404, "unsupported_protocol");
}

function chars(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

function decodeSpeech(value: Json, responseBytes: number): ApiRequest {
  const bad = () => invalid("invalid_protocol_request");
  if (!isObject(value)) throw bad();
  const body: JsonObject = {};
  for (const key of Object.keys(value)) if (!OPENAI_LINKING_FIELDS.includes(key)) body[key] = value[key] as Json;
  if (Object.keys(body).some((k) => !SPEECH_FIELDS.includes(k))) throw invalid("unsupported_request_field");
  const model = jsonModel(body);
  const input = get(body, "input");
  if (typeof input !== "string" || rustTrim(input).length === 0 || chars(input) > MAX_SPEECH_CHARACTERS) throw bad();
  const voice = get(body, "voice");
  let voiceOk = false;
  if (typeof voice === "string") voiceOk = voice.length > 0;
  else if (isObject(voice)) {
    const id = get(voice, "id");
    voiceOk = Object.keys(voice).length === 1 && typeof id === "string" && id.length > 0;
  }
  if (!voiceOk) throw bad();
  const instructionsValue = get(body, "instructions");
  let instructions = "";
  if (instructionsValue !== undefined) {
    if (typeof instructionsValue !== "string" || chars(instructionsValue) > MAX_SPEECH_CHARACTERS) throw bad();
    instructions = instructionsValue;
  }
  const formatValue = get(body, "response_format");
  let format = "mp3";
  if (formatValue !== undefined) {
    if (typeof formatValue !== "string") throw bad();
    if (!SPEECH_FORMATS.includes(formatValue)) throw invalid("unsupported_response_format");
    format = formatValue;
  }
  const speedValue = get(body, "speed");
  let speed = 1.0;
  if (speedValue !== undefined) {
    const f = typeof speedValue === "number" ? speedValue : typeof speedValue === "bigint" ? Number(speedValue) : undefined;
    if (f === undefined || !(f >= SPEED_MIN && f <= SPEED_MAX)) throw bad();
    speed = f;
  }
  const streamFormat = get(body, "stream_format");
  if (streamFormat !== undefined) {
    if (streamFormat === "sse") throw invalid("streaming_unsupported");
    if (streamFormat !== "audio") throw bad();
  }
  if (UNCOMPRESSED_FORMATS.includes(format)) {
    const seconds = chars(input) / (SLOW_CHARACTERS_PER_SECOND * speed);
    if (seconds * PCM_BYTES_PER_SECOND > responseBytes) throw invalid("audio_output_limit");
  }
  const units = characterBound(input) + characterBound(instructions);
  // Speech bills characters, never tokens.
  return { model, stream: false, selectors: [], bound: { inputTokens: 0n, outputTokens: 0n, units }, body: { kind: "json", value: body } };
}

/** `character_bound`: most characters a vendor may bill: one per ASCII character, two per other character. */
export function characterBound(input: string): bigint {
  let n = 0n;
  for (const ch of input) n += (ch.codePointAt(0) as number) < 0x80 ? 1n : 2n;
  return n;
}

/** `speech_characters`: the characters Gray bills for a speech request (`input` plus `instructions`, Unicode scalar values). */
export function speechCharacters(api: ApiRequest): bigint | undefined {
  if (api.body.kind !== "json") return undefined;
  const input = get(api.body.value, "input");
  if (typeof input !== "string") return undefined;
  const instructions = get(api.body.value, "instructions");
  return BigInt(chars(input) + (typeof instructions === "string" ? chars(instructions) : 0));
}

function decodeTranscription(protocol: Protocol, all: readonly FormPart[]): ApiRequest {
  const bad = () => invalid("invalid_form_field");
  const allowed = protocol === "open_ai_translations" ? TRANSLATION_FIELDS : TRANSCRIPTION_FIELDS;
  const parts = all.filter((p) => !OPENAI_LINKING_FIELDS.includes(p.name));
  if (parts.some((p) => !allowed.includes(p.name))) throw invalid("unsupported_request_field");
  const model = formText(parts, "model");
  if (model === undefined || model.length === 0) throw invalid("invalid_protocol_request");
  const files = parts.filter((p) => p.name === "file");
  if (files.length === 0) throw invalid("invalid_protocol_request");
  if (files.length > 1) throw invalid("duplicate_form_field");
  const file = files[0] as FormPart;
  if (file.fileName === undefined || partSize(file) === 0) throw bad();
  const format = parseTranscript(formText(parts, "response_format"));
  if (format === undefined) throw invalid("unsupported_response_format");
  const stream = formText(parts, "stream");
  if (stream === "true") throw invalid("streaming_unsupported");
  if (stream !== undefined && stream !== "false") throw bad();
  const temperature = formText(parts, "temperature");
  if (temperature !== undefined) {
    const t = parseRustF64(temperature);
    if (t === undefined || !Number.isFinite(t) || t < 0 || t > 1) throw bad();
  }
  const language = formText(parts, "language");
  if (language !== undefined && (language.length < 2 || language.length > 16 || !/^[A-Za-z0-9-]+$/.test(language))) throw bad();
  formText(parts, "prompt");
  if (!chunkingStrategy(parts)) throw bad();
  for (const part of parts.filter((p) => p.name === "include[]")) if (partText(part) !== "logprobs") throw bad();
  for (const part of parts.filter((p) => p.name === "timestamp_granularities[]")) {
    const text = partText(part);
    if (!(text === "word" || text === "segment") || format !== "verbose_json") throw bad();
  }
  // The client's format stays in the form for the answer; the format asked upstream is set when sent.
  return { model, stream: false, selectors: [], bound: UNBOUNDED, body: { kind: "multipart", parts } };
}

/**
 * `chunking_strategy`: absent, `auto`, or OpenAI's `server_vad` settings, as one JSON object or as
 * the bracketed fields OpenAI's SDKs send an object as. Either form is forwarded as sent.
 */
function chunkingStrategy(parts: readonly FormPart[]): boolean {
  const whole = formText(parts, "chunking_strategy");
  const fields: JsonObject = {};
  let any = false;
  for (const part of parts.filter((p) => p.name.startsWith("chunking_strategy["))) {
    const text = formText(parts, part.name) ?? "";
    const key = part.name.slice("chunking_strategy[".length, part.name.length - 1);
    let value: Json;
    if (key === "type") {
      value = text;
    } else {
      const parsed = parseSerdeSlice(new TextEncoder().encode(text));
      if (typeof parsed !== "bigint" && typeof parsed !== "number") return false;
      value = parsed;
    }
    fields[key] = value;
    any = true;
  }
  let strategy: Json;
  if (whole === undefined && !any) return true;
  if (whole === "auto" && !any) return true;
  if (whole !== undefined && !any) {
    const parsed = parseSerdeSlice(new TextEncoder().encode(whole));
    if (parsed === undefined) return false;
    strategy = parsed;
  } else if (whole === undefined) {
    strategy = fields;
  } else {
    return false;
  }
  if (!isObject(strategy)) return false;
  if (get(strategy, "type") !== "server_vad") return false;
  return Object.entries(strategy).every(([key, value]) => {
    switch (key) {
      case "type":
        return true;
      case "prefix_padding_ms":
      case "silence_duration_ms":
        return typeof value === "bigint" && value >= 0n && value <= 0xffff_ffff_ffff_ffffn;
      case "threshold": {
        const f = typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : undefined;
        return f !== undefined && f >= 0 && f <= 1;
      }
      default:
        return false;
    }
  });
}

/** A transcription or translation answer format (`response_format`). */
export type Transcript = "json" | "verbose_json" | "text" | "srt" | "vtt";

/** The client's format; `json` when absent, undefined when unknown. */
function parseTranscript(format: string | undefined): Transcript | undefined {
  if (format === undefined) return "json";
  return (["json", "verbose_json", "text", "srt", "vtt"] as const).find((f) => f === format);
}

/** `Transcript::asked`: the format the client asked for (validated when decoded). */
export function askedTranscript(parts: readonly FormPart[]): Transcript {
  try {
    return parseTranscript(formText(parts, "response_format")) ?? "json";
  } catch {
    return "json";
  }
}

/** `Transcript::timed`: the client's answer is built from the upstream's timed `segments`. */
function timed(format: Transcript): boolean {
  return format === "verbose_json" || format === "srt" || format === "vtt";
}

/**
 * `Transcript::upstream`: the format asked upstream, an answer that carries usage and the segments
 * subtitles are built from. A translation always asks `verbose_json`.
 */
export function upstreamTranscript(format: Transcript, protocol: Protocol): "json" | "verbose_json" {
  return (format === "json" || format === "text") && protocol === "open_ai_transcriptions" ? "json" : "verbose_json";
}

/** `forwarded_parts`: the form sent upstream asks the format its answer is billed and built from. */
export function forwardedParts(protocol: Protocol, parts: readonly FormPart[]): readonly FormPart[] {
  if (protocol !== "open_ai_transcriptions" && protocol !== "open_ai_translations") return parts;
  const format = upstreamTranscript(askedTranscript(parts), protocol);
  return [
    ...parts.filter((p) => p.name !== "response_format"),
    { name: "response_format", fileName: undefined, contentType: undefined, data: new TextEncoder().encode(format) },
  ];
}

/** Speech and translations settle in units only (characters, seconds). */
function settlesInUnits(protocol: Protocol): boolean {
  return protocol === "open_ai_speech" || protocol === "open_ai_translations";
}

/** `retain_unit_priced`: drops the speech and translation routes without a unit price, before pricing, so the next route serves. */
export function retainUnitPriced(protocol: Protocol, routes: readonly MediaRoute[]): MediaRoute[] {
  return settlesInUnits(protocol) ? routes.filter((r) => r.billsUnits === true) : [...routes];
}

/**
 * `timed_transcripts`: keeps the routes that can answer timed `segments` when the client's answer is
 * built from them. `timed_transcripts` is a capability a provider claims and a check proves by reading
 * the segments out of a real `verbose_json` answer: the routes that proved it take the request when any
 * did; a route that claimed it and did not prove it never does, its check having withdrawn the claim
 * (`preferProvingAll`), and when that leaves no route the request is refused (400
 * `unsupported_capability`). Where no route proved it, the price decides among the others as it did
 * before any route could state this: a route without a unit price is taken to answer `json` only. When
 * none is left, 400 `unsupported_response_format`.
 */
export function timedTranscripts(api: ApiRequest, routes: readonly MediaRoute[]): MediaRoute[] {
  if (api.body.kind !== "multipart" || !timed(askedTranscript(api.body.parts))) return [...routes];
  const sorted = preferProvingAll(routes, ["timed_transcripts"]);
  if (sorted.proof === "proved") return sorted.routes;
  if (sorted.proof === "withdrawn") throw capabilityUnproved(api.model, ["timed segments (`verbose_json`, `srt` or `vtt`)"], "response_format");
  return retainServing(sorted.routes, (route) => (route.billsUnits === false ? [400, "unsupported_response_format"] : undefined));
}

/** `require_unit_price`: the attempt's frozen rate must still price units (502 `unit_price_missing`). */
export function requireUnitPrice(protocol: Protocol, billsUnits: boolean): void {
  if (settlesInUnits(protocol) && !billsUnits) throw apiError(502, "unit_price_missing");
}

/** The speech call on a vendor route, mapped from the client's request. */
function vendorCall(route: MediaRoute, api: ApiRequest): HttpCall {
  const vendor = vendorFor(route, "speech");
  if (vendor === undefined) throw new AdapterError({ kind: "unsupported_operation", message: "no speech vendor" });
  if (api.body.kind !== "json") throw new AdapterError({ kind: "invalid_request", message: "speech takes JSON" });
  return build(vendor, "speech", route.upstreamModel, api.body.value);
}

/** `refused`: how a vendor's refusal to map the request answers. */
function refused(error: unknown): readonly [number, string] {
  if (error instanceof AdapterError) {
    if (error.detail.kind === "unsupported") return [400, "unsupported_request_field"];
    if (error.detail.kind === "invalid_request") return [400, "invalid_protocol_request"];
  }
  return [502, "invalid_vendor_call"];
}

/**
 * `serviceable` for speech: drops the routes without a unit price, and the adapter routes whose
 * vendor cannot take the request or its credential. When none is left, a vendor's refusal of the
 * request itself answers (400), else the route's problem (503).
 */
export function serviceableSpeech(api: ApiRequest, routes: readonly MediaRoute[], clock: Clock): MediaRoute[] {
  return retainServing(retainUnitPriced("open_ai_speech", routes), (route) => {
    if (route.adapter === undefined) return undefined;
    const vendor = vendorFor(route, "speech");
    if (vendor === undefined) return [503, "unsupported_adapter"];
    try {
      authHeaders(vendor, route.auth, route.credential, nowUnix(clock));
    } catch {
      return [503, "invalid_provider_credential"];
    }
    try {
      vendorCall(route, api);
      return undefined;
    } catch (error) {
      const [status, code] = refused(error);
      return status === 400 ? [400, code] : [503, code];
    }
  });
}

/** `vendor_upstream` for speech on an adapter route. */
export function speechVendorUpstream(api: ApiRequest, route: MediaRoute, clock: Clock): Outgoing {
  const vendor = vendorFor(route, "speech");
  if (vendor === undefined) throw apiError(502, "unsupported_adapter");
  let call: HttpCall;
  try {
    call = vendorCall(route, api);
  } catch (error) {
    const [status, code] = refused(error);
    throw apiError(status, code);
  }
  return vendorRequest(route, vendor, call, nowUnix(clock));
}

export interface AudioAttempt {
  readonly protocol: Protocol;
  readonly billsUnits: boolean;
  readonly deadlineMs: number;
  /** The largest answer read (MEDIA_RESPONSE_BYTES). */
  readonly responseBytes: number;
  /** Reads a vendor's JSON answer within `limit` bytes (images.ts `ImagesAttempt.readJson`): whole by default. */
  readonly readJson?: (upstream: Response, limit: number) => Promise<Uint8Array>;
}

/** `respond` for the audio APIs: the answer metered (and checked as `settle` checks it) and ready to return. */
export async function respondAudio(api: ApiRequest, route: MediaRoute, upstream: Response, attempt: AudioAttempt): Promise<Answered> {
  let answered: Answered;
  if (attempt.protocol === "open_ai_speech") {
    answered = route.adapter !== undefined ? await vendorSpeech(api, route, upstream, attempt) : await speech(api, upstream, attempt);
  } else if (attempt.protocol === "open_ai_transcriptions" || attempt.protocol === "open_ai_translations") {
    answered = await transcription(api, upstream, attempt);
  } else {
    throw apiError(502, "unsupported_protocol");
  }
  if (answered.billed.kind === "metered") checkMetered(attempt.protocol, api.bound, answered.billed.metered, attempt.billsUnits);
  return answered;
}

/** An OpenAI-compatible speech answer: audio bytes billed at the characters Gray counted from the request. */
async function speech(api: ApiRequest, upstream: Response, attempt: AudioAttempt): Promise<Answered> {
  const contentType = audioContentType(upstream.headers.get("content-type"));
  if (contentType === undefined) {
    await upstream.body?.cancel();
    throw apiError(502, "invalid_upstream_response");
  }
  const audio = await readUpstream(upstream, attempt.responseBytes, attempt.deadlineMs);
  const characters = speechCharacters(api);
  if (characters === undefined || audio.length === 0) throw apiError(502, "invalid_upstream_response");
  return { body: audio, contentType, billed: metered(countedUnits("characters", characters)) };
}

/** A vendor speech answer: the decoded audio, billed at the characters the vendor confirmed. */
async function vendorSpeech(api: ApiRequest, route: MediaRoute, upstream: Response, attempt: AudioAttempt): Promise<Answered> {
  const vendor = vendorFor(route, "speech");
  if (vendor === undefined) throw apiError(502, "unsupported_adapter");
  let sent: HttpCall;
  try {
    // The mapping is deterministic: this is the call that was sent.
    sent = vendorCall(route, api);
  } catch {
    throw apiError(502, "invalid_vendor_call");
  }
  const limit = 64 * 1024 * 1024;
  const bytes = attempt.readJson !== undefined ? await attempt.readJson(upstream, limit) : await readUpstream(upstream, limit, attempt.deadlineMs);
  const parsed = vendorAnswer(vendor, "speech", sent, upstream.status, bytes);
  if (parsed.kind !== "speech") throw apiError(502, "invalid_upstream_response");
  if (parsed.usage.unit !== "characters" || parsed.audio.length === 0) throw apiError(502, "invalid_upstream_response");
  return {
    body: parsed.audio,
    contentType: parsed.contentType,
    billed: metered({ counters: { ...ZERO_COUNTERS, units: parsed.usage.units }, raw: parsed.usage.raw, unit: "characters" }),
  };
}

/** `audio_content_type`: `audio/*`, or the `application/octet-stream` some servers send raw PCM as. */
export function audioContentType(value: string | null): string | undefined {
  // `HeaderValue::to_str`: visible ASCII and tab only.
  if (value === null || value.length > MAX_CONTENT_TYPE || !/^[\t\x20-\x7e]*$/.test(value)) return undefined;
  const essence = rustTrim(value.split(";")[0] as string).replace(/[A-Z]/g, (c) => c.toLowerCase());
  const audio = essence.startsWith("audio/") && /^[A-Za-z0-9+.-]+$/.test(essence.slice("audio/".length));
  return audio || essence === "application/octet-stream" ? value : undefined;
}

/**
 * A transcription or translation answer, billed from its usage, in the client's format: the JSON as
 * received, `{"text"}` for a translation asked as `json`, the text alone for `text`, or subtitles
 * built from the `verbose_json` segments for `srt` and `vtt`.
 */
async function transcription(api: ApiRequest, upstream: Response, attempt: AudioAttempt): Promise<Answered> {
  const bytes = await readUpstream(upstream, attempt.responseBytes, attempt.deadlineMs);
  const value = strictJson(bytes);
  const text = get(value, "text");
  if (typeof text !== "string") throw apiError(502, "invalid_upstream_response");
  const asked = api.body.kind === "multipart" ? askedTranscript(api.body.parts) : "json";
  const utf8 = new TextEncoder();
  let answer: [Uint8Array, string] | undefined;
  switch (asked) {
    case "json":
      answer = attempt.protocol === "open_ai_translations" ? [utf8.encode(toJsonString({ text })), JSON_TYPE] : [bytes, JSON_TYPE];
      break;
    case "verbose_json":
      answer = [bytes, JSON_TYPE];
      break;
    case "text":
      answer = [utf8.encode(text), TEXT_TYPE];
      break;
    case "srt": {
      const srt = subtitles(value, false);
      answer = srt === undefined ? undefined : [utf8.encode(srt), TEXT_TYPE];
      break;
    }
    case "vtt": {
      const vtt = subtitles(value, true);
      answer = vtt === undefined ? undefined : [utf8.encode(vtt), VTT_TYPE];
      break;
    }
  }
  if (answer === undefined) throw apiError(502, "invalid_upstream_response");
  return { body: answer[0], contentType: answer[1], billed: transcriptionBilled(value, attempt.billsUnits) };
}

/**
 * What a transcription or translation answer is billed by (`transcription_usage`), on the parsed
 * answer or on a streamed answer's projection (which keeps its usage and duration): its usage, or the
 * missing usage when it reports none. A malformed usage is 502 `billing_usage_invalid`.
 */
export function transcriptionBilled(value: Json, billsUnits: boolean): Billed {
  let m: Metered | undefined;
  try {
    m = transcriptionUsage(value, billsUnits);
  } catch (error) {
    if (error instanceof UsageUnreported) return missing(error.message, get(value, "usage") ?? null);
    throw apiError(502, "billing_usage_invalid");
  }
  return m === undefined ? missing("usage missing", get(value, "usage") ?? null) : metered(m);
}

/** Whether the client's answer is the upstream's JSON as received (`json` for a transcription, `verbose_json`), so it can pass as it arrives; the other formats are made from the whole answer. */
export function transcriptPassesThrough(protocol: Protocol, api: ApiRequest): boolean {
  const asked = api.body.kind === "multipart" ? askedTranscript(api.body.parts) : "json";
  return asked === "verbose_json" || (asked === "json" && protocol === "open_ai_transcriptions");
}

/** The checks of an answer that passes as it arrives (`transcriptPassesThrough`): `text` is a string, and what it is billed by. */
export function transcriptAnswer(value: Json, billsUnits: boolean): Billed {
  if (typeof get(value, "text") !== "string") throw apiError(502, "invalid_upstream_response");
  return transcriptionBilled(value, billsUnits);
}

/**
 * `subtitles`: SubRip (numbered) or WebVTT cues, one per `verbose_json` segment with text, at its
 * `start` and `end` (seconds, rounded to milliseconds). Undefined when the segments are missing or a
 * segment is not timed.
 */
export function subtitles(answer: Json, vtt: boolean): string | undefined {
  let out = vtt ? "WEBVTT\n\n" : "";
  let cues = 0;
  const segments = get(answer, "segments");
  if (!Array.isArray(segments)) return undefined;
  for (const segment of segments) {
    const startValue = get(segment, "start");
    const endValue = get(segment, "end");
    if (startValue === undefined || endValue === undefined) return undefined;
    const start = cueTime(startValue);
    const end = cueTime(endValue);
    if (start === undefined || end === undefined || end < start) return undefined;
    const textValue = get(segment, "text");
    if (typeof textValue !== "string") return undefined;
    // `str::lines` then `trim`: a blank line would end the cue.
    const lines = textValue
      .split("\n")
      .map((line) => rustTrim(line.endsWith("\r") ? line.slice(0, -1) : line))
      .filter((line) => line.length > 0);
    if (lines.length === 0) continue;
    cues += 1;
    const text = lines.join("\n");
    if (vtt) {
      const escaped = text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      out += `${timestamp(start, ".")} --> ${timestamp(end, ".")}\n${escaped}\n\n`;
    } else {
      out += `${cues}\n${timestamp(start, ",")} --> ${timestamp(end, ",")}\n${text}\n\n`;
    }
  }
  return out;
}

/** `cue_time`: a segment time in seconds, within a day, as milliseconds (rounded half away from zero). */
function cueTime(seconds: Json): number | undefined {
  const s = typeof seconds === "number" ? seconds : typeof seconds === "bigint" ? Number(seconds) : undefined;
  if (s === undefined || !Number.isFinite(s) || s < 0 || s > MAX_SECONDS) return undefined;
  return Math.round(s * 1000);
}

/** `HH:MM:SS` and milliseconds after `separator` (`,` in SubRip, `.` in WebVTT). */
function timestamp(ms: number, separator: string): string {
  const pad = (n: number, width: number) => String(n).padStart(width, "0");
  return `${pad(Math.floor(ms / 3_600_000), 2)}:${pad(Math.floor(ms / 60_000) % 60, 2)}:${pad(Math.floor(ms / 1000) % 60, 2)}${separator}${pad(ms % 1000, 3)}`;
}

/**
 * `transcription_usage`: the billable usage of a transcription answer; undefined when it reports
 * none. `durationFallback` bills a `verbose_json` duration when there is no `usage`. Throws on a
 * malformed usage.
 */
export function transcriptionUsage(answer: Json, durationFallback: boolean): Metered | undefined {
  const usage = get(answer, "usage");
  if (usage === undefined || usage === null) {
    const duration = get(answer, "duration");
    if (duration !== undefined && durationFallback && duration !== null) return billedSeconds(duration);
    return undefined;
  }
  if (!isObject(usage)) throw new UsageError("usage must be an object");
  // A usage that reports nothing it is billed on is missing (`Unreported`), not malformed.
  const type = get(usage, "type");
  if (type === undefined || type === null) throw new UsageUnreported("usage.type missing");
  if (type === "duration") {
    const seconds = get(usage, "seconds");
    if (seconds === undefined || seconds === null) throw new UsageUnreported("usage.seconds missing");
    return billedSeconds(seconds);
  }
  if (type === "tokens") return audioTokenUsage(usage);
  throw new UsageError("usage.type must be duration or tokens");
}

/** `billed_seconds`: `ceil(seconds)` as billed seconds, within a day. */
function billedSeconds(seconds: Json): Metered {
  const s = typeof seconds === "number" ? seconds : typeof seconds === "bigint" ? Number(seconds) : undefined;
  if (s === undefined || !Number.isFinite(s) || s < 0 || s > MAX_SECONDS) throw new UsageError("usage seconds must be a duration within a day");
  const units = BigInt(Math.ceil(s));
  return { counters: { ...ZERO_COUNTERS, units }, raw: { seconds: units }, unit: "seconds" };
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `audio_token_usage`: token usage of a transcription; `input_token_details.audio_tokens` is the audio subset of the input. */
function audioTokenUsage(usage: Json): Metered {
  let counters: UsageCounters = tokenUsage(usage, "input_tokens", "output_tokens");
  const nested = (key: string) => {
    try {
      return nestedCounter(usage, "input_token_details", key);
    } catch (error) {
      throw new UsageError((error as Error).message);
    }
  };
  const audio = nested("audio_tokens");
  const text = nested("text_tokens");
  if (audio !== undefined) {
    if (counters.audio_input_tokens !== 0n && counters.audio_input_tokens !== audio) throw new UsageError("audio token counts disagree");
    counters = { ...counters, audio_input_tokens: audio };
  }
  const detailed = counters.audio_input_tokens + (text ?? 0n);
  if (detailed > U64_MAX) throw new UsageError("token counts overflow");
  if (detailed > counters.input_tokens || textInputTokens(counters) === undefined) throw new UsageError("input token details exceed input tokens");
  const total = optionalCounter(usage, "total_tokens");
  if (total !== undefined) {
    const sum = counters.input_tokens + counters.output_tokens;
    if (sum > U64_MAX || total !== sum) throw new UsageError("usage.total_tokens is not input plus output");
  }
  return { counters, raw: usage, unit: undefined };
}

export { ApiError };
