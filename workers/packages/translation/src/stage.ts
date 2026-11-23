/**
 * The client side of a translated stream (crates/gray-gateway/src/translation/stream.rs). The
 * gateway's tool gate decodes and inspects every upstream frame first; only those inspected events
 * reach this stage, which translates them and immediately decodes the produced bytes again with
 * the client protocol's own validating decoder.
 *
 * And `translateBody` (crates/gray-gateway/src/inference.rs, `translate_body`): a buffered
 * answer, translated and checked the same way.
 */
import {
  type CanonicalEvent,
  type CanonicalResponse,
  PROJECTION_NODE_BYTES,
  type Protocol,
  ProtocolStreamDecoder,
  Refusal,
  type ResponseContext,
  StreamTranslator,
  TRANSLATION_CODES,
  parseResponse,
  stringHeapBytes,
  translateResponse,
  translationErrorFrame,
} from "@gray/protocol";
import { type Json, asStr, get, isObject, toJsonString } from "@gray/json";
import { CallSet, canonicalArguments } from "./calls.ts";

/** Failure codes of the translation stages (HTTP 502 before the first release). */
export const CLIENT_STREAM_INVALID = "translation_client_stream_invalid";
export const TOOL_CALL_MISMATCH = "translation_tool_call_mismatch";
/** The translated response body does not parse as the client protocol. */
export const CLIENT_RESPONSE_INVALID = "translation_client_response_invalid";

/**
 * A translated answer that cannot be released: `code` is a stage failure above, or the
 * translator's own (`translation_invalid_upstream`, `translation_invalid_upstream_arguments`).
 * Rust returns it as `Err(code)`.
 */
export class TranslationFailure extends Error {
  override readonly name = "TranslationFailure";
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/**
 * Whether the attempt of a request that failed with `code` still counts as its route's answer
 * (`fail_request` in inference.rs): tool arguments that are not one JSON object cannot reach an
 * Anthropic or Gemini client, but the upstream answered as its own API allows, and a native route
 * serves the same answer, so the route did not fail. Every other translation failure counts
 * against the route. Either way the request is not charged and the supplier is not paid.
 */
export function answeredByUpstream(code: string): boolean {
  return code === TRANSLATION_CODES.UPSTREAM_ARGUMENTS;
}

/**
 * Tracks completed tool calls per stream index and reconciles repeated Responses completions
 * (`response.function_call_arguments.done` followed by `response.output_item.done`).
 *
 * - A repeated `tool_call_complete` for the same index whose canonical `(name, arguments)` matches
 *   the first completion (for example `""` followed by `"{}"`) reconciles as one call rather than
 *   double-counting it.
 * - A repeated completion or `native` `response.output_item.done` for a `function_call` whose
 *   canonical name or raw arguments disagree with the earlier completion (or that appears without
 *   any completed call for that index) flags a conflict so `finish()` refuses with
 *   `TOOL_CALL_MISMATCH`, because `StreamTranslator` already emitted the first completion to the
 *   client and ignores subsequent completions for the same index.
 */
class CallLedger {
  private readonly calls = new CallSet();
  private readonly byIndex = new Map<bigint, readonly [string, string]>();
  private readonly rawByIndex = new Map<bigint, string>();
  private conflict = false;
  private extraHeap = 0;

  observe(events: readonly CanonicalEvent[], seen: { tool: boolean }): void {
    for (const event of events) {
      if (event.type === "tool_call_complete") {
        seen.tool = true;
        const name = event.name ?? "";
        const key = canonicalArguments(event.arguments);
        const existing = this.byIndex.get(event.index);
        if (existing === undefined) {
          this.byIndex.set(event.index, [name, key]);
          this.extraHeap += PROJECTION_NODE_BYTES.item + PROJECTION_NODE_BYTES.array + 2 * PROJECTION_NODE_BYTES.item;
          this.calls.push(name, event.arguments);
        } else if (existing[0] !== name || existing[1] !== key) {
          this.conflict = true;
        }
      } else if (event.type === "tool_call_delta") {
        seen.tool = true;
      }
    }
    for (const event of events) {
      if (event.type !== "native" || event.protocol !== "open_ai_responses" || !isObject(event.payload)) continue;
      const kind = asStr(get(event.payload, "type"));
      if (kind === "response.function_call_arguments.done") {
        const index = get(event.payload, "output_index");
        const raw = get(event.payload, "arguments");
        if (typeof index === "bigint" && typeof raw === "string") this.recordRaw(index, canonicalArguments(raw));
      } else if (kind === "response.output_item.done") {
        const item = get(event.payload, "item");
        if (!isObject(item) || asStr(get(item, "type")) !== "function_call") continue;
        seen.tool = true;
        const index = get(event.payload, "output_index");
        if (typeof index !== "bigint") continue;
        const recorded = this.byIndex.get(index);
        if (recorded === undefined) {
          this.conflict = true;
          continue;
        }
        const itemName = asStr(get(item, "name"));
        if (itemName !== undefined && recorded[0] !== itemName) this.conflict = true;
        const raw = get(item, "arguments");
        if (typeof raw === "string") this.recordRaw(index, canonicalArguments(raw));
      }
    }
  }

  private recordRaw(index: bigint, rawKey: string): void {
    const previous = this.rawByIndex.get(index);
    if (previous === undefined) {
      this.rawByIndex.set(index, rawKey);
      this.extraHeap += PROJECTION_NODE_BYTES.item + PROJECTION_NODE_BYTES.string + stringHeapBytes(rawKey);
    } else if (previous !== rawKey) {
      this.conflict = true;
    }
  }

  same(other: CallLedger): boolean {
    return !this.conflict && !other.conflict && this.calls.same(other.calls);
  }

  retainedBytes(): number {
    return this.calls.retainedBytes() + this.extraHeap;
  }
}

export class StreamStage {
  private readonly client: Protocol;
  private readonly translator: StreamTranslator;
  private readonly clientDecoder: ProtocolStreamDecoder;
  private readonly upstreamCalls = new CallLedger();
  private readonly clientCalls = new CallLedger();
  /** Sticky: a tool call was seen on either side, so nothing more may be released before the end-of-stream comparison. */
  private readonly seen = { tool: false };

  constructor(upstream: Protocol, client: Protocol, ctx: ResponseContext) {
    this.client = client;
    this.translator = new StreamTranslator(upstream, client, ctx);
    this.clientDecoder = new ProtocolStreamDecoder(client);
  }

  /** Translates the inspected events of one upstream frame. Returns the client bytes, which the caller holds or releases like native bytes. */
  push(events: readonly CanonicalEvent[]): Uint8Array {
    this.upstreamCalls.observe(events, this.seen);
    let bytes: Uint8Array;
    try {
      bytes = this.translator.push(events);
    } catch (error) {
      if (error instanceof Refusal) throw new TranslationFailure(error.code);
      throw error;
    }
    if (bytes.length > 0) {
      let decoded: CanonicalEvent[];
      try {
        decoded = this.clientDecoder.push(bytes);
      } catch {
        throw new TranslationFailure(CLIENT_STREAM_INVALID);
      }
      this.clientCalls.observe(decoded, this.seen);
    }
    return bytes;
  }

  /** True until the first tool call, on either side. */
  releasable(): boolean {
    return !this.seen.tool;
  }

  /**
   * Whether the client gets each call's arguments as the upstream streams them, else from the
   * complete call alone (`StreamTranslator.streamsCallArguments`: a Responses upstream's calls reach
   * the client whole). The gate's inspector of such a stream reads the fragments as unused.
   */
  streamsCallArguments(): boolean {
    return this.translator.streamsCallArguments();
  }

  /**
   * End of stream, after the upstream decoder finished and its last events were pushed: the client
   * stream must be complete and carry exactly the inspected upstream tool calls.
   */
  finish(): void {
    if (!this.translator.isDone()) throw new TranslationFailure(CLIENT_STREAM_INVALID);
    let decoded: CanonicalEvent[];
    try {
      decoded = this.clientDecoder.finish();
    } catch {
      throw new TranslationFailure(CLIENT_STREAM_INVALID);
    }
    this.clientCalls.observe(decoded, this.seen);
    if (!this.clientDecoder.isTerminal()) throw new TranslationFailure(CLIENT_STREAM_INVALID);
    if (!this.upstreamCalls.same(this.clientCalls)) throw new TranslationFailure(TOOL_CALL_MISMATCH);
  }

  /**
   * What the stage keeps of the stream so far, in heap bytes (the gateway weighs it with the frames a
   * translated stream holds): the translator's state (`StreamTranslator.retainedBytes`), the client
   * decoder's (`ProtocolStreamDecoder.retainedBytes`: its own parse of each call the client is given)
   * and both sides' calls as text for the end's comparison (`CallSet.retainedBytes`).
   */
  retainedBytes(): number {
    return this.translator.retainedBytes() + this.clientDecoder.retainedBytes() + this.upstreamCalls.retainedBytes() + this.clientCalls.retainedBytes();
  }

  /** The client protocol's error frame, for a failure after release. */
  errorFrame(code: string): Uint8Array {
    return translationErrorFrame(this.client, code, this.translator.sequenceNumber());
  }
}

const utf8 = new TextEncoder();

/**
 * `translate_body`: translates an inspected upstream response body (`payload`, natively parsed as
 * `parsed`) for the client, and checks that the client body carries exactly the inspected tool
 * calls. Returns the body's bytes as serde_json writes them; throws a TranslationFailure.
 */
export function translateBody(upstream: Protocol, client: Protocol, payload: Json, parsed: CanonicalResponse, ctx: ResponseContext): Uint8Array {
  let body;
  try {
    body = translateResponse(upstream, client, payload, ctx);
  } catch (error) {
    if (error instanceof Refusal) throw new TranslationFailure(error.code);
    throw error;
  }
  let reparsed: CanonicalResponse;
  try {
    reparsed = parseResponse(client, body);
  } catch {
    throw new TranslationFailure(CLIENT_RESPONSE_INVALID);
  }
  const inspected = new CallSet();
  for (const call of parsed.tool_calls) inspected.push(call.name, call.arguments);
  const delivered = new CallSet();
  for (const call of reparsed.tool_calls) delivered.push(call.name, call.arguments);
  if (!inspected.same(delivered)) throw new TranslationFailure(TOOL_CALL_MISMATCH);
  return utf8.encode(toJsonString(body));
}
