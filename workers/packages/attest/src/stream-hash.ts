import { sha256 } from "@noble/hashes/sha2";
import { bytesToLowerHex, sha256BareHex } from "./digest.ts";

/**
 * Streaming hashing: a pass-through that hashes every byte it forwards and settles a promise when
 * the stream ends.
 *
 * This is how the lane will hash "the bytes the client received" for a streamed SSE response (§7.4:
 * for SSE, the raw in-order stream including framing). The transform does not change, re-chunk or
 * hold back bytes: every chunk is hashed and enqueued in the same `transform` call, so the readable
 * side sees exactly the objects the writable side was given, in order, and never waits for a later
 * chunk. Backpressure is the same as a plain `TransformStream`'s: a write is only accepted when the
 * reader has taken the previous chunk, so a slow client does not accumulate the whole response.
 *
 * `done` settles on **every** path, so a gateway can await it in a `finally`:
 *
 * - it resolves with the digest when the writable closes and the transform flushes;
 * - it rejects with a [`HashingStreamError`] when the writable is aborted (a failed upstream, an
 *   aborted pipe), when the readable is cancelled (the client went away), or when a write or the
 *   final close fails. `digest()`, `digestHex()` and `bodyHash()` stay `null` in those cases: there
 *   is no complete byte stream to digest, and a partial digest is never offered.
 *
 * A stream that is neither closed nor aborted never settles `done` (nothing happened yet); that is
 * the one case in which awaiting it waits forever, and it is the caller's stream to finish.
 */

/** Why `done` rejected: the stream stopped before its digest was final. */
export type HashingStreamFailure = "aborted" | "cancelled" | "errored";

const FAILURE_MESSAGES: Readonly<Record<HashingStreamFailure, string>> = {
  aborted: "the hashing stream was aborted, so no digest exists",
  cancelled: "the hashing stream's readable side was cancelled, so no digest exists",
  errored: "the hashing stream failed, so no digest exists",
};

/** The rejection `done` carries when the stream did not end cleanly. */
export class HashingStreamError extends Error {
  override readonly name = "HashingStreamError";
  readonly code: HashingStreamFailure;
  /** What ended the stream: the abort or cancel reason, or the error a write or close threw. */
  readonly reason: unknown;

  constructor(code: HashingStreamFailure, reason: unknown) {
    super(`${FAILURE_MESSAGES[code]}${reason === undefined ? "" : `: ${describe(reason)}`}`);
    this.code = code;
    this.reason = reason;
  }
}

/** The digest of a finished stream, and how many bytes went through it. */
export interface StreamDigest {
  /** The raw 32-byte SHA-256. */
  readonly digest: Uint8Array;
  readonly byteLength: number;
}

/**
 * A hashing pass-through and the digest it will produce. `stream` is the `readable`/`writable` pair
 * `pipeThrough`, `getReader` and `getWriter` take; the writable is wrapped so that its abort settles
 * `done` (a bare `TransformStream` has no abort hook).
 */
export interface HashingStream {
  /** Write into `writable`; read the same bytes, unmodified, from `readable`. */
  readonly stream: ReadableWritablePair<Uint8Array, Uint8Array>;
  /**
   * Resolves with the digest when the stream ends cleanly (its flush ran), and rejects with a
   * [`HashingStreamError`] on abort, cancel or error. It settles on every path except a stream that
   * is never finished, so awaiting it in a `finally` is safe.
   */
  readonly done: Promise<StreamDigest>;
  /** The digest, or null until (and unless) the stream ended cleanly. */
  digest(): Uint8Array | null;
  /** The digest as bare lowercase hex (Appendix A), or null before a clean end. */
  digestHex(): string | null;
  /** The digest as a §7.4 `body_hash` field (`sha256:` plus hex), or null before a clean end. */
  bodyHash(): string | null;
  /** The bytes forwarded so far. */
  byteLength(): number;
}

/** A pass-through stream that hashes every byte it forwards. */
export function hashingStream(): HashingStream {
  const hasher = sha256.create();
  let byteLength = 0;
  let digest: Uint8Array | null = null;
  let settled = false;
  let resolveDone: (value: StreamDigest) => void = () => {};
  let rejectDone: (reason: unknown) => void = () => {};
  const done = new Promise<StreamDigest>((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });
  // The rejection is for callers that await `done`. A caller that does not (an abort triggered by a
  // failing pipe, say) must not turn every cancelled response into an unhandled rejection in the
  // isolate, so the promise is marked observed here; awaiting it still observes the rejection.
  void done.catch(() => {});

  const succeed = (final: StreamDigest): void => {
    if (settled) return;
    settled = true;
    digest = final.digest;
    resolveDone(final);
  };
  const fail = (code: HashingStreamFailure, reason: unknown): void => {
    // A cancel after a clean flush must not turn a resolved digest into a rejection.
    if (settled) return;
    settled = true;
    rejectDone(new HashingStreamError(code, reason));
  };

  const passThrough = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      try {
        hasher.update(chunk);
        byteLength += chunk.length;
        controller.enqueue(chunk);
      } catch (error) {
        // Settle here as well as in the writable wrapper: the write promise only rejects once the
        // transform runs, and `done` must not depend on a reader pulling before it can fail.
        fail("errored", error);
        throw error;
      }
    },
    flush() {
      succeed({ digest: hasher.digest(), byteLength });
    },
    cancel(reason) {
      fail("cancelled", reason);
    },
  });

  // One writer for the transform's writable, held here so the wrapper below can surface its abort.
  const inner = passThrough.writable.getWriter();
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) =>
      inner.write(chunk).catch((error: unknown) => {
        fail("errored", error);
        throw error;
      }),
    close: () =>
      inner.close().catch((error: unknown) => {
        fail("errored", error);
        throw error;
      }),
    abort: (reason: unknown) => {
      fail("aborted", reason);
      return inner.abort(reason);
    },
  });

  return {
    stream: { readable: passThrough.readable, writable },
    done,
    digest: () => digest,
    digestHex: () => (digest === null ? null : bytesToLowerHex(digest)),
    bodyHash: () => (digest === null ? null : `sha256:${bytesToLowerHex(digest)}`),
    byteLength: () => byteLength,
  };
}

/** The one-shot counterpart for a whole buffer: the same SHA-256 the streaming form produces. */
export function hashBytes(bytes: Uint8Array): Uint8Array {
  return sha256(bytes);
}

/** `hashBytes` as bare lowercase hex. */
export function hashBytesHex(bytes: Uint8Array): string {
  return sha256BareHex(bytes);
}

function describe(reason: unknown): string {
  if (reason instanceof Error) return reason.message;
  if (typeof reason === "string") return reason;
  try {
    return String(reason);
  } catch {
    return "an unprintable reason";
  }
}
