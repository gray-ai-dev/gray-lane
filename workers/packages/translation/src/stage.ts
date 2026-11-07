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
  type Protocol,
  ProtocolStreamDecoder,
  Refusal,
  type ResponseContext,
  StreamTranslator,
  TRANSLATION_CODES,
  parseResponse,
  translateResponse,
  translationErrorFrame,
} from "@gray/protocol";
import { type Json, toJsonString } from "@gray/json";
import { CallSet } from "./calls.ts";

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

function observe(events: readonly CanonicalEvent[], calls: CallSet, seen: { tool: boolean }): void {
  for (const event of events) {
    if (event.type === "tool_call_complete") {
      seen.tool = true;
      calls.push(event.name ?? "", event.arguments);
    } else if (event.type === "tool_call_delta") {
      seen.tool = true;
    }
  }
}

export class StreamStage {
  private readonly client: Protocol;
  private readonly translator: StreamTranslator;
  private readonly clientDecoder: ProtocolStreamDecoder;
  private readonly upstreamCalls = new CallSet();
  private readonly clientCalls = new CallSet();
  /** Sticky: a tool call was seen on either side, so nothing more may be released before the end-of-stream comparison. */
  private readonly seen = { tool: false };

  constructor(upstream: Protocol, client: Protocol, ctx: ResponseContext) {
    this.client = client;
    this.translator = new StreamTranslator(upstream, client, ctx);
    this.clientDecoder = new ProtocolStreamDecoder(client);
  }

  /** Translates the inspected events of one upstream frame. Returns the client bytes, which the caller holds or releases like native bytes. */
  push(events: readonly CanonicalEvent[]): Uint8Array {
    observe(events, this.upstreamCalls, this.seen);
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
      observe(decoded, this.clientCalls, this.seen);
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
    observe(decoded, this.clientCalls, this.seen);
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
