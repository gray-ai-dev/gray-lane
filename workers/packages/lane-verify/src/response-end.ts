/**
 * Whether the response bytes a customer holds end the answer by its protocol (1.7.1, the `PARTIAL` verdict).
 *
 * A receipt whose `response.returned` says `served_as: client_left` commits to every event (or every body byte) the
 * entry queued for the client, and the client left before it read them all. Bytes shorter than that cannot reproduce
 * the receipt's digest, and `PARTIAL` says so instead of `FAIL`. Bytes that end the answer cleanly cannot be that
 * shorter prefix, so a digest mismatch on them stays a failure. These are the clean ends:
 *
 * - OpenAI Chat: a `data: [DONE]` event;
 * - OpenAI Responses: a `response.completed`, `response.incomplete` or `response.failed` event (its `event` field or
 *   its data's `type`);
 * - Anthropic Messages: a `message_stop` event (its `event` field or its data's `type`);
 * - Gemini: none, since a Gemini stream has no terminal frame of its own;
 * - a buffered answer: the bytes are a whole JSON text (S19's reading, `stackJsonTree`).
 *
 * A stream is read with the framing the digest uses (`StackEventDigester`, the WHATWG event-stream rules): comments are
 * not events, and an event whose blank line has not arrived is not one either. A clean end anywhere in the bytes
 * counts, not only as the last event: an honest entry sends nothing after its terminal event but keep-alive comments,
 * which are not events. The check is local to this package and does not use `@gray/protocol`.
 */
import { get, isObject, parseStrict } from "@gray/json";
import { StackEventDigester, stackJsonTree } from "@gray/lane";

/** What the event stream a customer holds contains. */
export interface StreamEnd {
  /** The events dispatched from the bytes, comments not counted. */
  readonly events: number;
  /** The first terminal event the protocol defines (its name as printed), or null when the bytes carry none. */
  readonly terminal: string | null;
}

const RESPONSES_TERMINAL: ReadonlySet<string> = new Set(["response.completed", "response.incomplete", "response.failed"]);
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** The `type` member of an event's data when it is a JSON object, else null. */
function dataType(data: Uint8Array): string | null {
  try {
    const value = parseStrict(STRICT_UTF8.decode(data));
    const type = isObject(value) ? get(value, "type") : undefined;
    return typeof type === "string" ? type : null;
  } catch {
    return null;
  }
}

function text(bytes: Uint8Array): string | null {
  try {
    return STRICT_UTF8.decode(bytes);
  } catch {
    return null;
  }
}

/** The protocol's terminal event this event is, by name, or null. A protocol without one (Gemini, any other) has none. */
function terminalOf(protocol: string, type: Uint8Array, data: Uint8Array): string | null {
  if (protocol === "open_ai_chat") return text(data) === "[DONE]" ? "[DONE]" : null;
  if (protocol === "open_ai_responses") {
    const named = text(type);
    if (named !== null && RESPONSES_TERMINAL.has(named)) return named;
    const typed = dataType(data);
    return typed !== null && RESPONSES_TERMINAL.has(typed) ? typed : null;
  }
  if (protocol === "anthropic_messages") {
    if (text(type) === "message_stop" || dataType(data) === "message_stop") return "message_stop";
    return null;
  }
  return null;
}

/** Reads an event stream as the digest reads it: how many events it holds and the first terminal one. */
export function readStreamEnd(protocol: string, bytes: Uint8Array): StreamEnd {
  let events = 0;
  let terminal: string | null = null;
  const digester = new StackEventDigester((type, data) => {
    events += 1;
    terminal ??= terminalOf(protocol, type, data);
  });
  digester.write(bytes);
  digester.close();
  return { events, terminal };
}

/** A buffered answer's bytes are a whole JSON text (S19's reading), so they are not a prefix the client was cut off in. */
export function isWholeJsonBody(bytes: Uint8Array): boolean {
  return stackJsonTree(bytes) !== null;
}
