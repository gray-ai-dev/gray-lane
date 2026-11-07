import { type Json, toJsonString } from "@gray/json";
import { type BodyLayout, type ClientBody, type Overlay, type Protocol, upstreamAuthHeaders, withDefaultAccept } from "@gray/protocol";
import type { RouteRecord } from "./snapshot.ts";
import { PlainCursor, SpoolBroken } from "./spool.ts";

/**
 * The upstream request of one attempt (crates/gray-gateway/src/upstream.rs `request_overlaid`,
 * `authorize`, `native_headers`): Gray builds it itself and forwards none of the client's headers
 * but the protocol's own version and beta headers (docs/cloudflare-native.md section 7), and none
 * at all for a translated request; the client's key never leaves Gray; the body is the client's
 * bytes with the attempt's overlay spliced in (docs/cloudflare-native.md 2.3 rule 7).
 *
 * A body is never copied whole to send it. Each attempt's body is a stream produced on demand,
 * pulled by the runtime as the upstream reads it, through a FixedLengthStream that carries its exact
 * length (C13): the held bytes of tiers A and B as views of the client's buffer, a tier C body as views
 * of its decrypted spool. Only the members the overlay rewrites are new bytes, and the tool-call ids an
 * attempt puts back in place of their handles (tool-ids.ts `forAttempt`): an original at its route, or a
 * Responses item id left out at another issuer's.
 */

/**
 * The most bytes one pull of a held body hands on: what the runtime may have taken from it ahead of
 * the upstream, besides its own pipe (test/workerd/memory.test.ts states that bound,
 * UPSTREAM_BODY_AHEAD_BYTES). 4 KiB is the chunk workerd's own body streams deliver: an R2 object,
 * an R2 range, a fetch response between Workers and an incoming request body all arrive in chunks of
 * at most 4,096 bytes (measured in workerd, compatibility date 2026-10-01, 2026-10-18), so a held
 * body (tiers A and B) is sent in the same steps as a stored one (tier C).
 */
export const UPSTREAM_BODY_CHUNK_BYTES = 4096;

/**
 * The headers of one attempt at `route` under `protocol`; `client` the client's request headers, or
 * none for a translated request. With the Accept the server's HTTP client gives every request
 * (@gray/protocol `withDefaultAccept`), since none of the client's is forwarded.
 *
 * A lane relay's route has no credential of this kind, and its auth headers come from the relay's
 * credential store, merged with the protocol's client headers by the lane's own builder (design v2
 * section C.6, M1). So this function refuses a lane route rather than send an account id or the
 * stored credential (the sentinel sealed as ciphertext, D107) as one: the main lane never has such
 * a route (it filters them out of its snapshot), and the lane never calls it.
 */
export function upstreamHeaders(protocol: Protocol, route: RouteRecord, credential: string, client: Headers): Headers {
  if (route.auth === "lane_relay") throw new Error("a confidential-lane route's headers come from the relay's credential store");
  const headers = new Headers({ "content-type": "application/json" });
  for (const [name, value] of upstreamAuthHeaders(route.auth, protocol, credential, client)) headers.set(name, value);
  return withDefaultAccept(headers);
}

/**
 * `inner`, each request it sends given the Accept the server's HTTP client gives every request that names none
 * (@gray/protocol `withDefaultAccept`): the model APIs' downloads and polls (apis.rs, images.rs, video/), which reqwest
 * sends with it.
 */
export function acceptingFetch<Rest extends unknown[]>(inner: (input: string, init: RequestInit, ...rest: Rest) => Promise<Response>): (input: string, init: RequestInit, ...rest: Rest) => Promise<Response> {
  return (input, init, ...rest) => inner(input, { ...init, headers: withDefaultAccept(new Headers(init.headers)) }, ...rest);
}

/** Anthropic's current API version, sent when the client named none (the server's default). */
export const ANTHROPIC_VERSION = "2023-06-01";

const encoder = new TextEncoder();

type Piece = { readonly kind: "range"; readonly offset: number; readonly length: number } | { readonly kind: "bytes"; readonly bytes: Uint8Array };

/**
 * The pieces of a spliced body (`serializeOverlaid` for a body without collapsed keys): the client's
 * bytes up to and with the opening brace; each member the overlay does not name as the client wrote
 * it, a replaced member with its new value, a removed one left out, a new one added before the
 * closing brace, all joined by commas; then the closing brace and what follows it. Without edits,
 * the client's bytes as they are.
 */
function splicePieces(total: number, layout: BodyLayout, overlay: Overlay): { readonly pieces: readonly Piece[]; readonly length: number } {
  const edits = overlay.edits();
  if (edits.size === 0) return { pieces: [{ kind: "range", offset: 0, length: total }], length: total };
  const pieces: Piece[] = [{ kind: "range", offset: 0, length: layout.open + 1 }];
  const seen = new Set<string>();
  let first = true;
  const separator = () => {
    if (!first) pieces.push({ kind: "bytes", bytes: encoder.encode(",") });
    first = false;
  };
  for (const m of layout.members) {
    seen.add(m.key);
    if (!edits.has(m.key)) {
      separator();
      pieces.push({ kind: "range", offset: m.keyStart, length: m.valueEnd - m.keyStart });
      continue;
    }
    const value = edits.get(m.key);
    if (value === undefined) continue;
    separator();
    pieces.push({ kind: "range", offset: m.keyStart, length: m.valueStart - m.keyStart });
    pieces.push({ kind: "bytes", bytes: encoder.encode(toJsonString(value)) });
  }
  for (const [name, value] of edits) {
    if (value === undefined || seen.has(name)) continue;
    separator();
    pieces.push({ kind: "bytes", bytes: encoder.encode(`${JSON.stringify(name)}:${toJsonString(value)}`) });
  }
  pieces.push({ kind: "range", offset: layout.close, length: total - layout.close });
  let length = 0;
  for (const p of pieces) length += p.kind === "range" ? p.length : p.bytes.length;
  return { pieces, length };
}

/**
 * What an attempt changes in the body besides its overlay (tool-ids.ts `forAttempt`): bytes of the
 * client's body replaced (`[start, end)` by `text`, sorted, apart, inside members the overlay leaves
 * as they are), or, for a body written again from its parse, the change to that parse.
 */
export interface BodyEdits {
  readonly edits: readonly { readonly start: number; readonly end: number; readonly text: string }[];
  readonly value: ((body: Json) => void) | null;
}

/**
 * The pieces with `edits` applied: each edit inside a range piece splits it, its text a piece of its
 * own; an edit that is not inside one range piece lies in a member the overlay wrote anew, and goes.
 */
function withEdits(pieces: readonly Piece[], edits: BodyEdits["edits"]): { readonly pieces: readonly Piece[]; readonly length: number } {
  const out: Piece[] = [];
  let e = 0;
  for (const p of pieces) {
    if (p.kind === "bytes") {
      out.push(p);
      continue;
    }
    const end = p.offset + p.length;
    let at = p.offset;
    while (e < edits.length && edits[e]!.start < p.offset) e++;
    while (e < edits.length && edits[e]!.end <= end) {
      const edit = edits[e]!;
      if (edit.start > at) out.push({ kind: "range", offset: at, length: edit.start - at });
      if (edit.text.length > 0) out.push({ kind: "bytes", bytes: encoder.encode(edit.text) });
      at = edit.end;
      e++;
    }
    if (end > at) out.push({ kind: "range", offset: at, length: end - at });
  }
  let length = 0;
  for (const p of out) length += p.kind === "range" ? p.length : p.bytes.length;
  return { pieces: out, length };
}

/** A body to send: its exact length, and a fresh stream of it per attempt. */
export interface UpstreamBody {
  readonly length: number;
  readonly stream: () => ReadableStream<Uint8Array>;
}

/**
 * Hands `body` to fetch with its length (C13), the stream pulled only as the upstream reads. `taken` is
 * called once the runtime took the body's first chunk from the FixedLengthStream, which holds none of its
 * own: a write settles when the readable side read it. A fetch that fails before then sent none of the
 * body, so no request reached the upstream whole (the dispatcher's refused connection, @gray/errors
 * `connect`).
 */
export function sendable(body: UpstreamBody, taken?: () => void): ReadableStream<Uint8Array> {
  const fixed = new FixedLengthStream(body.length);
  if (taken === undefined) {
    // pipeTo writes a chunk only once the FixedLengthStream took the last one (it holds none of its own).
    body.stream().pipeTo(fixed.writable).catch(() => {});
    return fixed.readable;
  }
  void (async () => {
    const reader = body.stream().getReader();
    const writer = fixed.writable.getWriter();
    let first = true;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          await writer.close();
          return;
        }
        await writer.write(value);
        if (first) {
          first = false;
          taken();
        }
      }
    } catch (error) {
      await reader.cancel(error).catch(() => {});
      await writer.abort(error).catch(() => {});
    }
  })();
  return fixed.readable;
}

/**
 * `body` with `release` called once its stream ends, fails or is cancelled: a stored body read under the
 * R2 connection its attempt holds (outbound.ts `hold`) gives it back only when nothing more is read, which
 * may be after the upstream's response headers (an upstream may answer before it has read the whole body).
 */
export function releasedAtEnd(body: UpstreamBody, release: () => void): UpstreamBody {
  return {
    length: body.length,
    stream: () => {
      const reader = body.stream().getReader();
      return new ReadableStream<Uint8Array>(
        {
          async pull(controller) {
            try {
              const { done, value } = await reader.read();
              if (done) {
                release();
                controller.close();
                return;
              }
              controller.enqueue(value);
            } catch (error) {
              release();
              controller.error(error);
            }
          },
          async cancel(reason) {
            release();
            await reader.cancel(reason).catch(() => {});
          },
        },
        { highWaterMark: 0 },
      );
    },
  };
}

/**
 * A body held in memory (tiers A and B, or a translated body), with the overlay spliced in, as views
 * of `bytes` at most UPSTREAM_BODY_CHUNK_BYTES each. `pulled` counts what each pull hands on (the
 * memory guards' test seam). A body whose equal keys collapsed is written as serde_json writes its
 * value: the client's bytes, which an upstream could read differently, are never sent; that one
 * body is a copy (tier A only: tiers B and C rewrite the collapsed members through the overlay).
 */
export function heldBody(body: ClientBody, layout: BodyLayout | null, overlay: Overlay, pulled?: (bytes: number) => void, change?: BodyEdits): UpstreamBody {
  if (body.duplicateKeys || layout === null) {
    const value = overlay.apply(body.value);
    change?.value?.(value);
    const whole = encoder.encode(toJsonString(value));
    return { length: whole.length, stream: () => chunked([{ kind: "range", offset: 0, length: whole.length }], whole, pulled) };
  }
  const spliced = splicePieces(body.bytes.length, layout, overlay);
  const { pieces, length } = change === undefined || change.edits.length === 0 ? spliced : withEdits(spliced.pieces, change.edits);
  return { length, stream: () => chunked(pieces, body.bytes, pulled) };
}

function chunked(pieces: readonly Piece[], bytes: Uint8Array, pulled: ((bytes: number) => void) | undefined): ReadableStream<Uint8Array> {
  let index = 0;
  let at = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        for (;;) {
          const p = pieces[index];
          if (p === undefined) {
            controller.close();
            return;
          }
          if (p.kind === "bytes") {
            index++;
            if (p.bytes.length === 0) continue;
            pulled?.(p.bytes.length);
            controller.enqueue(p.bytes);
            return;
          }
          if (at >= p.length) {
            index++;
            at = 0;
            continue;
          }
          const n = Math.min(UPSTREAM_BODY_CHUNK_BYTES, p.length - at);
          const view = bytes.subarray(p.offset + at, p.offset + at + n);
          at += n;
          pulled?.(n);
          controller.enqueue(view);
          return;
        }
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * A stored body (tier C) with the overlay spliced in: its plaintext read from the start (`open`, spool.ts
 * `spoolPlaintext`, decrypted a chunk at a time), each range handed on as views of at most
 * UPSTREAM_BODY_CHUNK_BYTES, what lies between ranges dropped, literal pieces between them; at the end the
 * body is checked to be all there, `total` bytes as it was received (a spool cut short fails the attempt).
 * Produced on demand: a slow upstream holds back the reads, so a sealed chunk and its plaintext sit in
 * memory, never the whole body (a tier C body can be hundreds of MB against the Worker's 128 MB).
 */
export function storedBody(open: () => Promise<ReadableStream<Uint8Array> | null>, total: number, layout: BodyLayout, overlay: Overlay, change?: BodyEdits): UpstreamBody {
  const spliced = splicePieces(total, layout, overlay);
  const { pieces, length } = change === undefined || change.edits.length === 0 ? spliced : withEdits(spliced.pieces, change.edits);
  const stream = () => {
    let cursor: PlainCursor | null = null;
    let index = 0;
    let left = 0;
    return new ReadableStream<Uint8Array>(
      {
        async pull(controller) {
          try {
            if (cursor === null) {
              const plain = await open();
              if (plain === null) throw new SpoolBroken("is gone");
              cursor = new PlainCursor(plain);
            }
            for (;;) {
              if (left > 0) {
                const view = await cursor.next(Math.min(left, UPSTREAM_BODY_CHUNK_BYTES));
                if (view === null) throw new SpoolBroken(`ends at ${cursor.position}, inside a piece`);
                left -= view.length;
                controller.enqueue(view);
                return;
              }
              const p = pieces[index++];
              if (p === undefined) {
                await cursor.finish(total);
                controller.close();
                return;
              }
              if (p.kind === "bytes") {
                if (p.bytes.length === 0) continue;
                controller.enqueue(p.bytes);
                return;
              }
              if (p.length === 0) continue;
              // The pieces are in the body's order: the cursor only moves forward.
              await cursor.skipTo(p.offset);
              left = p.length;
            }
          } catch (error) {
            controller.error(error);
          }
        },
        async cancel(reason) {
          await cursor?.cancel(reason);
          cursor = null;
        },
      },
      { highWaterMark: 0 },
    );
  };
  return { length, stream };
}
