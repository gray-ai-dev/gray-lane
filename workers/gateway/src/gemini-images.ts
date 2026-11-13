import { ApiError } from "@gray/errors";
import { type Json, type JsonObject, isObject, readSerdeBytes } from "@gray/json";
import { requestLimit } from "@gray/limits";
import { type GeminiBodyView, type GeminiImageBody, GEMINI_CONVERSATION, geminiImageReads, speaksGemini, wholeGeminiView } from "@gray/media";
import { type BodyLayout, type MemberSpan, Overlay, TooManyMembers, exactStrings, geminiStreams, memberHeldBytes, refuseByteOrderMark } from "@gray/protocol";
import { Tokenizer, TokenType } from "@streamparser/json";
import type { Body } from "./body.ts";
import type { ContentBucket } from "./outbound.ts";
import { TokenTooLong, membersTooMany, valueTooLong } from "./parse.ts";
import { PlainCursor, SpoolBroken, type SpoolRef, spoolPlaintext } from "./spool.ts";
import type { GatewayDeps } from "./inference.ts";
import { type GatewaySnapshot, type RouteRecord, routeServes, snapshotTiming } from "./snapshot.ts";
import { type UpstreamBody, UPSTREAM_BODY_CHUNK_BYTES, heldBody, storedBody } from "./upstream.ts";

/**
 * A Gemini image model (Nano Banana) served to Gemini clients through its image routes, the routes
 * whose vendor adapter speaks Gemini's `generateContent` to the relay (the `gemini` adapter)
 * (crates/gray-gateway/src/apis/gemini_images.rs on main; @gray/media gemini-images.ts holds the
 * request's and the answer's own rules). This module is the gateway's part: which path serves a
 * Gemini request of the model (`geminiImageServing`), and the request body read as that path needs it,
 * never whole beyond what one isolate parses (`geminiBodyRead`).
 *
 * Which path serves the model: without a live route on the Gemini API, its image routes serve every
 * request. With one, the generation path serves them, except a request carrying an image or file when
 * no live Gemini route proved image input (`vision`) and the model has a live edits route through the
 * Gemini adapter: that edits route takes it, as it does for a model with neither a Gemini route nor an
 * image generation route through the adapter. Only live routes count either way.
 */

/** Which Gemini requests of a model its image routes serve: every one (`all`), or those carrying an image or file (`edits`, decided by the body). */
export type GeminiServing = "all" | "edits";

/** A Gemini request the image routes serve: its model, whether the client asked `streamGenerateContent`, and whether its body decides the path. */
export interface GeminiAsked {
  readonly model: string;
  readonly stream: boolean;
  /** The generation path serves the request unless it carries an image or file, which the edits route takes. */
  readonly byBody: boolean;
}

/** `speaks`: an image route that sends its requests to the Gemini image API (the `gemini` adapter), which takes a Gemini client's own request. */
export function speaks(route: RouteRecord): boolean {
  return (route.protocol === "open_ai_image_generations" || route.protocol === "open_ai_image_edits") && speaksGemini(route.adapter);
}

/** `serving`: which Gemini requests of `model` the image routes among `routes` serve; null: none, the generation path serves or refuses them. */
export function geminiImageServing(routes: readonly RouteRecord[], model: string, nowMs: number): GeminiServing | null {
  const live = routes.filter((r) => routeServes(r.expiresAt, nowMs) && r.model === model);
  const through = (protocol: RouteRecord["protocol"]) => live.some((r) => r.protocol === protocol && speaks(r));
  // A native route counts only while it answers buffered requests: one that serves streamed requests only (decision
  // (a) of 2026-10-23, its buffered image check failed) leaves the model's Gemini requests to the image routes, as a
  // route out of the snapshot did.
  const native = live.filter((r) => r.protocol === "gemini" && r.capabilities.streamedOnly !== true);
  if (native.length === 0 && through("open_ai_image_generations")) return "all";
  return !native.some((r) => r.capabilities.vision) && through("open_ai_image_edits") ? "edits" : null;
}

/** `serves`: whether the image routes serve every Gemini request of `model`, so the model's Gemini path is listed for it (without `countTokens`). */
export function servesGeminiImages(snapshot: GatewaySnapshot, model: string, nowMs: number): boolean {
  return geminiImageServing(snapshot.routes, model, nowMs) === "all";
}

/** `asked`: the Gemini request of `model` (from the path) when the image routes may serve it. */
export function geminiAsked(snapshot: GatewaySnapshot, model: string, stream: boolean, nowMs: number): GeminiAsked | null {
  const serving = geminiImageServing(snapshot.routes, model, nowMs);
  return serving === null ? null : { model, stream, byBody: serving === "edits" };
}

/**
 * The image routes' part of a Gemini request at `path` for `model` (count_tokens.rs `gemini_or_forward`
 * on main): the request they serve, or null for the generation path. It reads the isolate's cached
 * snapshot, which the request path reads next; when none can be read, the generation path refuses the
 * request as it refuses any.
 */
export async function geminiImagesEntry(deps: Pick<GatewayDeps, "cfg" | "snapshots" | "source" | "clock">, path: string, model: string, background: (work: Promise<unknown>) => void): Promise<GeminiAsked | null> {
  const read = await deps.snapshots.read(deps.source, snapshotTiming(deps.cfg), deps.clock(), background, (call) => call());
  return read.ok ? geminiAsked(read.snapshot, model, geminiStreams(path), deps.clock()) : null;
}

/**
 * How an attempt sends a Gemini image request's body: as the parsed body serialised (a body parsed
 * whole, `whole`), or as the client's own bytes with the generation config spelled in place (a body
 * too large to parse whole: held bytes, or the spooled object).
 */
export type GeminiSend =
  | { readonly tier: "A" }
  | { readonly tier: "B"; readonly bytes: Uint8Array; readonly layout: BodyLayout }
  /** Spooled, sealed to `identity` (spool.ts): read again from its start for each attempt. */
  | { readonly tier: "C"; readonly spool: SpoolRef; readonly layout: BodyLayout };

/** A Gemini image request's body as read: the view its decoding reads, and how an attempt sends it. */
export interface GeminiRead {
  readonly view: GeminiBodyView;
  readonly send: GeminiSend;
}

/** The part fields that put an image or file in a request, in both spellings (@gray/media `MEDIA_PARTS`). */
const MEDIA_PARTS: readonly string[] = ["inlineData", "inline_data", "fileData", "file_data"];

/**
 * The body of a Gemini image request, by tier (body.ts): parsed whole within BODY_PARSE_MAX_BYTES, as
 * serde_json reads it (the last of equal keys); above it its layout and, in the same pass, its
 * conversation's turns and the parts that carry an image or file (`scanGeminiBody`, which holds one
 * record per distinct key, at most `smallMax` bytes of them: past that 413, `membersTooMany`), the
 * members that `decodeGeminiImages` reads then parsed from their spans (at most `smallMax` bytes of
 * them). Any other member it refuses by its key unless it is null, so its value is neither read from R2
 * nor parsed: it is sent as the client wrote it. A body that is no JSON is 400 `invalid_json`, one that
 * is no object 400 `invalid_protocol_request`, as the server's `parse_body` answers.
 */
export async function geminiBodyRead(body: Body, bucket: ContentBucket, limits: { readonly smallMax: number; readonly tokenMax: number }): Promise<GeminiRead | ApiError> {
  if (body.tier === "A") {
    let value: Json;
    try {
      value = readSerdeBytes(body.bytes).value;
    } catch {
      return new ApiError(400, "invalid_json");
    }
    if (!isObject(value)) return new ApiError(400, "invalid_protocol_request");
    return { view: wholeGeminiView(value as JsonObject), send: { tier: "A" } };
  }
  // Tier B: the bytes held; tier C: the spooled body, decrypted from its start as it is read (spool.ts).
  const unavailable = () => new ApiError(503, "request_body_store_unavailable");
  const held = body.tier === "C" ? null : body.bytes;
  const spool: SpoolRef | null = body.tier === "C" ? { key: body.key, length: body.length, identity: body.identity } : null;
  let stream: ReadableStream<Uint8Array>;
  if (held !== null) {
    stream = bytesStream(held);
  } else {
    const plain = await spoolPlaintext(bucket, spool!);
    if (plain === null) return unavailable();
    stream = plain;
  }
  let scanned: Scanned;
  try {
    scanned = await scanGeminiBody(stream, limits.tokenMax, limits.smallMax);
  } catch (error) {
    if (error instanceof TokenTooLong) return valueTooLong(error.limit);
    if (error instanceof TooManyMembers) return membersTooMany(error.limit);
    if (error instanceof NotAnObject) return new ApiError(400, "invalid_protocol_request");
    if (error instanceof SpoolBroken) return unavailable();
    return new ApiError(400, "invalid_json");
  }
  // The last of equal keys, as serde_json keeps it; the splice then sends only that one.
  const kept = scanned.members;
  const values = new Map<string, Json>();
  const spans: MemberSpan[] = [];
  let total = 0;
  // A spooled body's members are read in its order, from one more decryption from its start.
  let cursor: PlainCursor | null = null;
  try {
    for (const m of kept) {
      // The customer's routing preference (`provider`) is read too: the request path takes it out of the body
      // before the decoding sees it (apis/mod.rs, `Preference::take`).
      if (GEMINI_CONVERSATION.includes(m.key) || (!geminiImageReads(m.key) && m.key !== "provider")) {
        // The conversation is copied as the client wrote it, never parsed or replaced; so is a field the
        // decoding refuses by its key (or lets through as null) without reading it.
        spans.push({ key: m.key, keyStart: m.keyStart, valueStart: m.from, valueEnd: m.to });
        continue;
      }
      total += m.to - m.from;
      if (total > limits.smallMax) {
        return new ApiError(413, "request_body_limit").withMessage(
          `The fields of this request other than its conversation are larger than ${limits.smallMax} bytes, which Gray reads of a request this large.`,
        );
      }
      let raw: Uint8Array;
      if (held !== null) {
        raw = held.subarray(m.from, m.to);
      } else {
        if (cursor === null) {
          const again = await spoolPlaintext(bucket, spool!);
          if (again === null) return unavailable();
          cursor = new PlainCursor(again);
        }
        // The members are in the body's order: the cursor only moves forward.
        await cursor.skipTo(m.from);
        raw = await cursor.take(m.to - m.from);
      }
      const [start, end] = trimmedSpan(raw);
      spans.push({ key: m.key, keyStart: m.keyStart, valueStart: m.from + start, valueEnd: m.from + end });
      try {
        values.set(m.key, readSerdeBytes(raw.subarray(start, end)).value);
      } catch {
        return new ApiError(400, "invalid_json");
      }
    }
  } catch (error) {
    if (error instanceof SpoolBroken) return unavailable();
    throw error;
  } finally {
    await cursor?.cancel();
  }
  const layout: BodyLayout = { open: scanned.open, close: scanned.close, members: spans };
  const view: GeminiBodyView = {
    members: kept.map((m) => ({ key: m.key, isNull: m.isNull })),
    value: (key) => values.get(key),
    parts: scanned.turns ? { kind: "ok", media: scanned.media } : { kind: "no_turns" },
  };
  const send: GeminiSend = held !== null ? { tier: "B", bytes: held, layout } : { tier: "C", spool: spool!, layout };
  return { view, send };
}

/**
 * The body an attempt sends for a body too large to parse whole: the client's bytes with the
 * generation config sent under `generationConfig` as `spelling` says (@gray/media `GeminiImageBody`),
 * without the members in `strip`.
 * Null for a body parsed whole, which goes as its parse serialised (the attempt's own request).
 */
export function geminiAttemptBody(send: GeminiSend, body: GeminiImageBody, bucket: ContentBucket, strip: readonly string[] = []): UpstreamBody | null {
  if (send.tier === "A") return null;
  const overlay = new Overlay();
  // Members the request path took out of the body (the routing preference's `provider`) are left out.
  for (const member of strip) overlay.remove(member);
  if (body.spelling !== null) {
    if (body.spelling.from !== "generationConfig") overlay.remove(body.spelling.from);
    overlay.set("generationConfig", body.spelling.value);
  }
  if (send.tier === "B") return heldBody({ bytes: send.bytes, value: {}, duplicateKeys: false }, send.layout, overlay);
  return storedBody(() => spoolPlaintext(bucket, send.spool), send.spool.length, send.layout, overlay);
}

/** Held bytes as a stream of views, at most UPSTREAM_BODY_CHUNK_BYTES each times 16. */
function bytesStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  const step = UPSTREAM_BODY_CHUNK_BYTES * 16;
  let at = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (at >= bytes.length) return controller.close();
        const end = Math.min(bytes.length, at + step);
        controller.enqueue(bytes.subarray(at, end));
        at = end;
      },
    },
    { highWaterMark: 0 },
  );
}

/** JSON whitespace (RFC 8259). */
function isWhitespace(b: number | undefined): boolean {
  return b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;
}

/** The span of a value's bytes without the whitespace around it. */
function trimmedSpan(bytes: Uint8Array): [number, number] {
  let start = 0;
  let end = bytes.length;
  while (start < end && isWhitespace(bytes[start])) start++;
  while (end > start && isWhitespace(bytes[end - 1])) end--;
  return [start, end];
}

/** A body whose top level is no object. */
class NotAnObject extends Error {}

/** A top-level member as the scan found it: its key, where it sits, and whether its value is `null`. */
interface ScannedMember {
  readonly key: string;
  readonly keyStart: number;
  /** After the colon. */
  readonly from: number;
  /** The separator after the value (a comma or the closing brace). */
  readonly to: number;
  readonly isNull: boolean;
}

interface Scanned {
  readonly open: number;
  readonly close: number;
  /** One per key, the last of equal keys, in the order of those last ones. */
  readonly members: readonly ScannedMember[];
  /** The last `contents` is a non-empty list. */
  readonly turns: boolean;
  /** A part of a turn of the last `contents`, or of the last system instruction, carries an image or file. */
  readonly media: boolean;
}

/**
 * The scan's tokenizer, as the layout scan's (parse.ts `LayoutTokenizer`): strings read exactly, numbers not parsed,
 * no byte order mark anywhere (a skipped one would put the members' offsets 3 bytes short).
 */
class ScanTokenizer extends Tokenizer {
  constructor() {
    super({ stringBufferSize: 0, emitPartialTokens: true });
    exactStrings(this);
    refuseByteOrderMark(this);
  }

  protected override parseNumber(): number {
    return 0;
  }
}

/** What a container is to the scan. */
type Role = "top" | "contents" | "turn" | "system" | "parts" | "part" | "other";

interface Frame {
  readonly role: Role;
  readonly array: boolean;
  /** An object's key awaiting its value; null when the next string is a key. */
  key: string | null;
  /** An array's elements so far. */
  count: number;
  /** A part object: each media field's last value, non-null or not. */
  readonly media: Map<string, boolean>;
  /** A parts list: a part carried media. A turn or the system instruction: what its last `parts` said. */
  carries: boolean;
}

/**
 * One pass over a Gemini body too large to parse whole (`locateMembersStream`'s, with the same
 * tokenizer and the same bound on one value): its top-level members, and what `request_parts` reads
 * of its conversation as serde_json would (the last of equal keys): whether the last `contents` lists
 * any turn, and whether a part of a turn or of the system instruction puts an image or file in the
 * request (a media field whose value is not `null`). No string is kept beyond the one the tokenizer
 * is assembling; a value longer than `tokenMax` bytes ends the scan (`TokenTooLong`). One record is
 * kept per distinct top-level key, the last of equal keys; once those take more than `heldMax` bytes
 * (@gray/protocol `memberHeldBytes`) no new key is kept, and the scan ends with `TooManyMembers` once
 * the chunk is read: a body is only bytes, and one naming a field every six of them would otherwise
 * hold many times the isolate.
 */
async function scanGeminiBody(stream: ReadableStream<Uint8Array>, tokenMax: number, heldMax: number): Promise<Scanned> {
  const stack: Frame[] = [];
  let open = -1;
  let close = -1;
  // By key, in the order of each key's last member (a later one is deleted and set again).
  const members = new Map<string, ScannedMember>();
  let held = 0;
  let pending: { key: string; keyStart: number; from: number; isNull: boolean } | null = null as { key: string; keyStart: number; from: number; isNull: boolean } | null;
  let contents: { turns: boolean; media: boolean } = { turns: false, media: false };
  let system = false;
  const frame = (role: Role, array: boolean): Frame => ({ role, array, key: null, count: 0, media: new Map(), carries: false });
  const top = () => stack[stack.length - 1];
  /** A value starts in the innermost container: counted, and its key's place noted. */
  const valueStarts = (token: TokenType): void => {
    const parent = top();
    if (parent === undefined) return;
    if (parent.array) {
      parent.count += 1;
      return;
    }
    if (parent.role === "top" && pending !== null) pending.isNull = token === TokenType.NULL;
    if (parent.role === "part" && parent.key !== null && MEDIA_PARTS.includes(parent.key)) parent.media.set(parent.key, token !== TokenType.NULL);
    // A top-level `contents` that is no list has no turns; a system instruction that is no object has no parts.
    if (parent.role === "top" && parent.key === "contents" && token !== TokenType.LEFT_BRACKET) contents = { turns: false, media: false };
    if (parent.role === "top" && (parent.key === "systemInstruction" || parent.key === "system_instruction") && token !== TokenType.LEFT_BRACE) system = false;
    if ((parent.role === "turn" || parent.role === "system") && parent.key === "parts" && token !== TokenType.LEFT_BRACKET) parent.carries = false;
  };
  /** The role of a container opening as the value of the innermost container's current key or element. */
  const roleOf = (array: boolean): Role => {
    const parent = top();
    if (parent === undefined) return "top";
    if (parent.role === "top" && parent.key === "contents" && array) return "contents";
    if (parent.role === "top" && (parent.key === "systemInstruction" || parent.key === "system_instruction") && !array) return "system";
    if (parent.role === "contents" && !array) return "turn";
    if ((parent.role === "turn" || parent.role === "system") && parent.key === "parts" && array) return "parts";
    if (parent.role === "parts" && !array) return "part";
    return "other";
  };
  /** A value of an object ended: its key awaits no value any more. */
  const valueEnds = (): void => {
    const parent = top();
    if (parent !== undefined && !parent.array) parent.key = null;
  };
  const finish = (separator: number) => {
    if (pending === null) throw new Error("body layout: member without key or colon");
    const member: ScannedMember = { key: pending.key, keyStart: pending.keyStart, from: pending.from, to: separator, isNull: pending.isNull };
    pending = null;
    if (members.delete(member.key)) {
      members.set(member.key, member);
      return;
    }
    held += memberHeldBytes(member.key);
    if (held <= heldMax) members.set(member.key, member);
  };
  const tokenizer = new ScanTokenizer();
  let written = 0;
  let tooLong = false;
  tokenizer.onToken = ({ token, value, offset, partial }) => {
    if (partial === true) {
      if ((token === TokenType.STRING || token === TokenType.NUMBER) && written - offset > tokenMax) tooLong = true;
      return;
    }
    const parent = top();
    switch (token) {
      case TokenType.LEFT_BRACE:
      case TokenType.LEFT_BRACKET: {
        const array = token === TokenType.LEFT_BRACKET;
        if (parent === undefined) {
          if (array) throw new NotAnObject();
          open = offset;
          stack.push(frame("top", false));
          return;
        }
        valueStarts(token);
        stack.push(frame(roleOf(array), array));
        return;
      }
      case TokenType.RIGHT_BRACE:
      case TokenType.RIGHT_BRACKET: {
        const done = stack.pop();
        if (done === undefined) throw new Error("body layout: unbalanced");
        const outer = top();
        switch (done.role) {
          case "top":
            if (pending !== null) finish(offset);
            close = offset;
            return;
          case "part":
            if (outer !== undefined && [...done.media.values()].some((v) => v)) outer.carries = true;
            break;
          case "parts":
            // The last `parts` of a turn is what serde_json keeps.
            if (outer !== undefined) outer.carries = done.carries;
            break;
          case "turn":
            if (outer !== undefined && done.carries) outer.carries = true;
            break;
          case "contents":
            contents = { turns: done.count > 0, media: done.carries };
            break;
          case "system":
            system = done.carries;
            break;
          default:
            break;
        }
        valueEnds();
        return;
      }
      case TokenType.COMMA:
        if (stack.length === 1) finish(offset);
        return;
      case TokenType.COLON:
        // The colon of a top-level member is where its value's span starts.
        if (stack.length === 1 && pending !== null) pending.from = offset + 1;
        return;
      case TokenType.STRING:
        if (parent !== undefined && !parent.array && parent.key === null) {
          parent.key = value as string;
          if (parent.role === "top") pending = { key: value as string, keyStart: offset, from: -1, isNull: false };
          return;
        }
        valueStarts(token);
        valueEnds();
        return;
      default:
        // A number, true, false or null.
        valueStarts(token);
        valueEnds();
        return;
    }
  };
  tokenizer.onError = (error) => {
    throw error;
  };
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      written += value.length;
      tokenizer.write(value);
      if (tooLong) throw new TokenTooLong(tokenMax);
      if (held > heldMax) throw new TooManyMembers(heldMax);
    }
  } catch (error) {
    reader.cancel().catch(() => {});
    throw error;
  }
  if (open < 0 || close < 0) throw new Error("body layout: not a complete object");
  return { open, close, members: [...members.values()], turns: contents.turns, media: contents.media || system };
}
