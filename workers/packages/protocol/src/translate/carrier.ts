/**
 * Opaque continuation data carried through a client of another protocol
 * (crates/gray-protocol/src/translate/carrier.rs).
 *
 * A carrier is `gr1.<origin>.<base64url(JSON object)>`. It becomes native reasoning again only
 * when the next request goes to the protocol named by its origin; anywhere else it is dropped and
 * reported.
 *
 * Tool call ids carry two kinds of data through clients that have no field for them:
 * `<id>__gts_<base64url(signature bytes)>` (or `__gtr_` for a signature that is not canonical
 * base64) for a Gemini call's thought signature, and `__grr_<base64url(carrier)>` for the
 * reasoning of a Chat client's turn.
 *
 * Base64 is @scure/base. Rust's decoder accepts exactly the canonical encoding of the decoded
 * bytes (it re-encodes and compares); so does this one, whatever leniency the library has.
 */
import { base64 as standard, base64urlnopad } from "@scure/base";
import { type Json, type JsonObject, isObject, parseStrictBytes, toJsonString } from "@gray/json";
import type { Protocol } from "../types.ts";

const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function canonical(coder: { encode(bytes: Uint8Array): string; decode(text: string): Uint8Array }, text: string): Uint8Array | undefined {
  let bytes: Uint8Array;
  try {
    bytes = coder.decode(text);
  } catch {
    return undefined;
  }
  return coder.encode(bytes) === text ? bytes : undefined;
}

/** Standard alphabet, padded. */
export function base64(bytes: Uint8Array): string {
  return standard.encode(bytes);
}

export function base64Decode(text: string): Uint8Array | undefined {
  return canonical(standard, text);
}

/** URL-safe alphabet, unpadded. */
export function base64url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

export function base64urlDecode(text: string): Uint8Array | undefined {
  return canonical(base64urlnopad, text);
}

/** `String::from_utf8`: undefined for invalid UTF-8. */
function utf8Text(bytes: Uint8Array): string | undefined {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return undefined;
  }
}

function tag(protocol: Protocol): string {
  switch (protocol) {
    case "open_ai_chat":
      return "chat";
    case "open_ai_responses":
      return "responses";
    case "anthropic_messages":
      return "anthropic";
    default:
      return "gemini";
  }
}

export class Carrier {
  readonly origin: Protocol;
  readonly payload: JsonObject;

  /** A payload that is not an object becomes an empty object, as in Rust. */
  constructor(origin: Protocol, payload: Json) {
    this.origin = origin;
    this.payload = isObject(payload) ? payload : {};
  }

  static empty(origin: Protocol): Carrier {
    return new Carrier(origin, {});
  }

  encode(): string {
    return `gr1.${tag(this.origin)}.${base64url(utf8.encode(toJsonString(this.payload)))}`;
  }

  static decode(text: string): Carrier | undefined {
    if (!text.startsWith("gr1.")) return undefined;
    const rest = text.slice(4);
    const dot = rest.indexOf(".");
    if (dot < 0) return undefined;
    let origin: Protocol;
    switch (rest.slice(0, dot)) {
      case "chat":
        origin = "open_ai_chat";
        break;
      case "responses":
        origin = "open_ai_responses";
        break;
      case "anthropic":
        origin = "anthropic_messages";
        break;
      case "gemini":
        origin = "gemini";
        break;
      default:
        return undefined;
    }
    const json = base64urlDecode(rest.slice(dot + 1));
    if (json === undefined) return undefined;
    let payload: Json;
    try {
      payload = parseStrictBytes(json);
    } catch {
      return undefined;
    }
    return isObject(payload) ? new Carrier(origin, payload) : undefined;
  }

  /** Standard base64 of the carrier text, for fields typed as bytes (Gemini `thoughtSignature`). */
  encodeBytes(): string {
    return base64(utf8.encode(this.encode()));
  }

  static decodeBytes(text: string): Carrier | undefined {
    const bytes = base64Decode(text);
    if (bytes === undefined) return undefined;
    const decoded = utf8Text(bytes);
    return decoded === undefined ? undefined : Carrier.decode(decoded);
  }

  getStr(key: string): string | undefined {
    const value = Object.hasOwn(this.payload, key) ? this.payload[key] : undefined;
    return typeof value === "string" ? value : undefined;
  }

  /** Whether the payload holds anything the origin needs back. */
  isEmpty(): boolean {
    return Object.keys(this.payload).length === 0;
  }
}

const SIGNATURE = "__gts_";
const SIGNATURE_RAW = "__gtr_";
const REASONING = "__grr_";

/** A client-visible tool call id carrying a Gemini thought signature. */
export function signedId(id: string, signature: string | undefined): string {
  if (signature === undefined || signature === "") return id;
  const bytes = base64Decode(signature);
  return bytes !== undefined ? `${id}${SIGNATURE}${base64url(bytes)}` : `${id}${SIGNATURE_RAW}${base64url(utf8.encode(signature))}`;
}

/** A client-visible tool call id carrying a reasoning carrier. */
export function carrierId(id: string, carrier: Carrier): string {
  return `${id}${REASONING}${base64url(utf8.encode(carrier.encode()))}`;
}

/** What a client-visible id carries. */
export interface SplitId {
  readonly id: string;
  readonly signature: string | undefined;
  readonly carrier: Carrier | undefined;
}

/**
 * Takes the suffixes this module adds off a tool call id. An id with a marker that does not
 * decode is kept whole, as the client's own id. The markers are ASCII, so the first occurrence
 * found in UTF-16 units is the one Rust finds in bytes.
 */
export function splitId(id: string): SplitId {
  let rest = id;
  let carrier: Carrier | undefined;
  const r = rest.indexOf(REASONING);
  if (r > 0) {
    const bytes = base64urlDecode(rest.slice(r + REASONING.length));
    const text = bytes === undefined ? undefined : utf8Text(bytes);
    const decoded = text === undefined ? undefined : Carrier.decode(text);
    if (decoded !== undefined) {
      carrier = decoded;
      rest = rest.slice(0, r);
    }
  }
  let signature: string | undefined;
  const s = rest.indexOf(SIGNATURE);
  if (s > 0) {
    const bytes = base64urlDecode(rest.slice(s + SIGNATURE.length));
    if (bytes !== undefined && bytes.length > 0) {
      signature = base64(bytes);
      rest = rest.slice(0, s);
    }
  } else {
    const raw = rest.indexOf(SIGNATURE_RAW);
    if (raw > 0) {
      const bytes = base64urlDecode(rest.slice(raw + SIGNATURE_RAW.length));
      const text = bytes === undefined ? undefined : utf8Text(bytes);
      if (text !== undefined && text !== "") {
        signature = text;
        rest = rest.slice(0, raw);
      }
    }
  }
  return { id: rest, signature, carrier };
}
