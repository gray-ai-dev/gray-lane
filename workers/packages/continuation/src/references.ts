/**
 * Which Responses continuation references a request names and a reply creates
 * (crates/gray-gateway/src/continuation.rs). A stored response or conversation exists only in
 * the provider account that created it, and every Gray workspace reaches a provider through the
 * same supplier credential. A request naming `previous_response_id` or `conversation` is
 * therefore served only by the endpoint that produced that reference, and only for the workspace
 * that received it.
 */
import { type Json, get, isObject, parseSerde } from "@gray/json";
import { type Protocol, SseDecoder, utf8Length } from "@gray/protocol";

/** The longest reference Gray binds or looks up, in UTF-8 bytes (continuation.rs `MAX_REFERENCE_BYTES`). */
export const MAX_REFERENCE_BYTES = 256;

export type ReferenceKind = "response" | "conversation";

export interface Reference {
  readonly kind: ReferenceKind;
  readonly reference: string;
}

function id(value: Json | undefined): string | undefined {
  return typeof value === "string" && value !== "" && utf8Length(value) <= MAX_REFERENCE_BYTES ? value : undefined;
}

/**
 * `references`: the continuation references a Responses request names, in Rust's order
 * (`previous_response_id`, then `conversation`). Absent or null fields name none; any other
 * non-string shape is invalid (undefined).
 */
export function continuationReferences(body: Json): Reference[] | undefined {
  const out: Reference[] = [];
  const previous = get(body, "previous_response_id");
  if (previous !== undefined && previous !== null) {
    const reference = id(previous);
    if (reference === undefined) return undefined;
    out.push({ kind: "response", reference });
  }
  const conversation = get(body, "conversation");
  if (conversation !== undefined && conversation !== null) {
    let reference: string | undefined;
    if (isObject(conversation)) {
      const inner = get(conversation, "id");
      if (inner === undefined) return undefined;
      reference = id(inner);
    } else {
      reference = id(conversation);
    }
    if (reference === undefined) return undefined;
    out.push({ kind: "conversation", reference });
  }
  return out;
}

/** `stores`: whether the reply to `request` leaves references to continue from: a Responses request that did not ask the provider not to store it. */
export function storesContinuation(protocol: Protocol, request: Json): boolean {
  return protocol === "open_ai_responses" && get(request, "store") !== false;
}

/**
 * The references a successful reply names, as `Binding::record` binds them: its id, and its
 * conversation's (an object's `id`, or the value itself), each a non-empty string of at most
 * `MAX_REFERENCE_BYTES`.
 */
export function replyReferences(reply: Json): Reference[] {
  const out: Reference[] = [];
  const response = id(get(reply, "id"));
  if (response !== undefined) out.push({ kind: "response", reference: response });
  const c = get(reply, "conversation");
  let conversation: Json | undefined;
  if (c !== undefined) {
    const inner = get(c, "id");
    conversation = inner !== undefined ? inner : c;
  }
  const reference = id(conversation);
  if (reference !== undefined) out.push({ kind: "conversation", reference });
  return out;
}

/**
 * The first `response` object a streamed Responses reply completes (`first_response` with
 * `StreamBinding`'s decoder): feed every chunk before it reaches the client; the first time a
 * chunk completes an event whose `response` has a string `id`, that object is returned, and the
 * tap reads nothing after it.
 */
export class ResponseTap {
  private decoder: SseDecoder | undefined = new SseDecoder();

  /** Whether the tap still reads (no `response` object found yet). */
  get reading(): boolean {
    return this.decoder !== undefined;
  }

  observe(chunk: Uint8Array): Json | undefined {
    const decoder = this.decoder;
    if (decoder === undefined) return undefined;
    let events;
    try {
      events = decoder.push(chunk);
    } catch {
      return undefined;
    }
    for (const event of events) {
      let value: Json;
      try {
        value = parseSerde(event.data);
      } catch {
        continue;
      }
      const reply = get(value, "response");
      if (reply === undefined || typeof get(reply, "id") !== "string") continue;
      this.decoder = undefined;
      return reply;
    }
    return undefined;
  }
}
