/**
 * Speech, transcription and translation (`POST /v1/audio/speech`, `/v1/audio/transcriptions`,
 * `/v1/audio/translations`), billed per input character, per audio second or by audio tokens
 * (crates/gray-gateway/src/apis/audio.rs; the module docs there give every rule's reason).
 *
 * Speech takes OpenAI's JSON, checked against OpenAI's limits before anything is sent, and is
 * billed in characters only: Gray counts `input` plus `instructions`. Uncompressed audio of a long
 * input at a slow speaking rate is refused up front.
 *
 * Transcription and translation take OpenAI's multipart form. Billing reads `usage` (`duration`
 * seconds or `tokens`), else a `verbose_json` duration on a unit-priced route.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, type UsageCounters, OPENAI_LINKING_FIELDS, ZERO_COUNTERS, nestedCounter, rustTrim, textInputTokens } from "@gray/protocol";
import { type Json, type JsonObject, JsonError, get, isObject, parseSerdeBytes } from "@gray/json";
import {
  type Billed,
  UsageError,
  UsageUnreported,
  apiError,
  metered,
  missing,
  formText,
  invalid,
  jsonModel,
  optionalCounter,
  capabilityUnproved,
  preferProvingAll,
  retainServing,
  tokenUsage,
} from "./common.ts";
import { type ApiRequest, type FormPart, type MediaRoute, type Metered, type Received, UNBOUNDED, partSize, partText } from "./types.ts";

const SPEECH_FIELDS = ["model", "input", "voice", "instructions", "response_format", "speed", "stream_format"];
/** The optional speech fields: each sent as null reads as left out. */
const SPEECH_OPTIONAL = ["instructions", "response_format", "speed", "stream_format"];
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

/**
 * `decode` for the audio APIs. `responseBytes` is the media answer limit the speech size check holds to.
 *
 * `entry`: the request as the confidential entry serves it on a provider's own API
 * (docs/design/standard-media-at-entry.md sections 2.3 and 2.6), where the provider's answer passes as it arrives and
 * Gray converts no format:
 *
 * - speech streamed as events (`stream_format: "sse"`) is taken, and the hold is the characters Gray counts, which is
 *   the charge (`characterBound` holds more);
 * - a transcription streamed as events (`stream` `true`) is taken, and so is `diarized_json`;
 * - `text`, `srt` and `vtt`, which have nowhere to report usage, are refused with 400 `unsupported_response_format`.
 */
export function decodeAudio(protocol: Protocol, received: Received, responseBytes: number, entry = false): ApiRequest {
  if (protocol === "open_ai_speech") {
    if (received.kind !== "json") throw invalid("invalid_protocol_request");
    return decodeSpeech(received.value, responseBytes, entry);
  }
  if (protocol === "open_ai_transcriptions" || protocol === "open_ai_translations") {
    if (received.kind !== "form") throw invalid("invalid_protocol_request");
    return decodeTranscription(protocol, received.parts, entry);
  }
  throw apiError(404, "unsupported_protocol");
}

function chars(s: string): number {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
}

function decodeSpeech(value: Json, responseBytes: number, entry: boolean): ApiRequest {
  const bad = () => invalid("invalid_protocol_request");
  if (!isObject(value)) throw bad();
  const body: JsonObject = {};
  for (const key of Object.keys(value)) if (!OPENAI_LINKING_FIELDS.includes(key)) body[key] = value[key] as Json;
  if (Object.keys(body).some((k) => !SPEECH_FIELDS.includes(k))) throw invalid("unsupported_request_field");
  // An optional field sent as null is left out, as an SDK that serializes unset options sends it (embeddings does the same).
  for (const key of SPEECH_OPTIONAL) if (Object.hasOwn(body, key) && body[key] === null) delete body[key];
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
    if (streamFormat === "sse" && !entry) throw invalid("streaming_unsupported");
    if (streamFormat !== "audio" && streamFormat !== "sse") throw bad();
  }
  if (UNCOMPRESSED_FORMATS.includes(format)) {
    const seconds = chars(input) / (SLOW_CHARACTERS_PER_SECOND * speed);
    if (seconds * PCM_BYTES_PER_SECOND > responseBytes) throw invalid("audio_output_limit");
  }
  const units = entry ? BigInt(chars(input) + chars(instructions)) : characterBound(input) + characterBound(instructions);
  // Speech bills characters, never tokens.
  return { model, stream: entry && streamFormat === "sse", selectors: [], bound: { inputTokens: 0n, outputTokens: 0n, units }, body: { kind: "json", value: body } };
}

/** `character_bound`: one per ASCII character, two per other character (the API Worker's speech hold). */
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

/** The formats the entry answers a transcript in: the ones that carry `usage` (the standard's clause 11.7). */
const ENTRY_TRANSCRIPTS: Readonly<Record<string, readonly string[]>> = {
  open_ai_transcriptions: ["json", "verbose_json", "diarized_json"],
  open_ai_translations: ["json", "verbose_json"],
};

/** 400 for a transcript format with nowhere to report usage. */
function usageFormatOnly(protocol: Protocol): ApiError {
  const formats = (ENTRY_TRANSCRIPTS[protocol] ?? []).map((format) => `\`${format}\``).join(", ");
  return invalid("unsupported_response_format")
    .withMessage(`This address answers this API in ${formats}: the formats that report the usage Gray bills on. Gray converts no format; build \`text\`, \`srt\` or \`vtt\` from the JSON answer.`)
    .withParam("response_format");
}

function decodeTranscription(protocol: Protocol, all: readonly FormPart[], entry: boolean): ApiRequest {
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
  const asked = formText(parts, "response_format");
  if (entry && asked !== undefined && !(ENTRY_TRANSCRIPTS[protocol] ?? []).includes(asked)) throw usageFormatOnly(protocol);
  const format = entry && asked === "diarized_json" ? "json" : parseTranscript(asked);
  if (format === undefined) throw invalid("unsupported_response_format");
  const stream = formText(parts, "stream");
  if (stream === "true" && !entry) throw invalid("streaming_unsupported");
  if (stream !== undefined && stream !== "false" && stream !== "true") throw bad();
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
  return { model, stream: entry && stream === "true", selectors: [], bound: UNBOUNDED, body: { kind: "multipart", parts } };
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

/** `serviceable` for speech: drops the routes without a unit price. */
export function serviceableSpeech(routes: readonly MediaRoute[]): MediaRoute[] {
  return retainUnitPriced("open_ai_speech", routes);
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
 * What a transcription or translation answer is billed by (`transcription_usage`), on the answer's
 * projection (which keeps its usage and duration): its usage, or the missing usage when it reports
 * none. A malformed usage is 502 `billing_usage_invalid`.
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

/** The checks of a transcript answer that passes as it arrives: `text` is a string, and what it is billed by. */
export function transcriptAnswer(value: Json, billsUnits: boolean): Billed {
  if (typeof get(value, "text") !== "string") throw apiError(502, "invalid_upstream_response");
  return transcriptionBilled(value, billsUnits);
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

/**
 * `audio_token_usage`: token usage of a transcription; `input_token_details.audio_tokens` is the audio subset of the input.
 * When `input_token_details` omits `audio_tokens`, every non-text input token (all `input_tokens` when `text_tokens` is
 * also absent) is billed as `audio_input_tokens` so unsplit audio usage never falls back to the cheaper text input rate.
 */
export function audioTokenUsage(usage: Json): Metered {
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
  let pluralAudio: bigint | undefined;
  try {
    pluralAudio = nestedCounter(usage, "input_tokens_details", "audio_tokens");
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
  if (audio !== undefined) {
    if (counters.audio_input_tokens !== 0n && counters.audio_input_tokens !== audio) throw new UsageError("audio token counts disagree");
    counters = { ...counters, audio_input_tokens: audio };
  } else if (pluralAudio === undefined) {
    if (text === undefined) {
      counters = { ...counters, audio_input_tokens: counters.input_tokens };
    } else if (text <= counters.input_tokens) {
      counters = { ...counters, audio_input_tokens: counters.input_tokens - text };
    }
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

/**
 * `serde_json::from_slice::<Value>`: what serde_json accepts (a duplicate key keeps its last value),
 * or `undefined`. Integers within u64/i64 are `bigint`, other numbers `number`.
 */
function parseSerdeSlice(body: Uint8Array): Json | undefined {
  try {
    return parseSerdeBytes(body);
  } catch (error) {
    if (error instanceof JsonError) return undefined;
    throw error;
  }
}

/**
 * `str::parse::<f64>`: the value of Rust's float grammar (core::num, `dec2flt`: a sign, then `inf`,
 * `infinity`, `nan` or a decimal number with an optional exponent, case-insensitive), or undefined.
 * Its value is the correctly rounded double, which `Number()` computes for the same text.
 */
function parseRustF64(s: string): number | undefined {
  if (!/^[+-]?(?:inf|infinity|nan|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?)$/i.test(s)) return undefined;
  const lower = s.toLowerCase().replace(/^\+/, "");
  if (lower === "inf" || lower === "infinity") return Infinity;
  if (lower === "-inf" || lower === "-infinity") return -Infinity;
  if (lower === "nan" || lower === "-nan") return NaN;
  return Number(s);
}

export { ApiError };
