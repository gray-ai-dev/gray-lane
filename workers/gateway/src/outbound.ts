import type { ShardLocator } from "@gray/account";
import type { ContinuationLocator } from "@gray/continuation";
import type { ToolCallIdLocator } from "@gray/tool-ids";
import type { EndpointLocator } from "./endpoints.ts";
import type { ModelCheckTicketStore } from "./model-check.ts";
import type { EndpointRootLocator } from "./rests.ts";
import type { Sinks } from "./sinks.ts";
import type { SnapshotSource } from "./snapshot.ts";

/**
 * The outbound connections of one request (docs/cloudflare-native.md section 3; the owner's second
 * hard limit of a Worker): at most MAX_WAITING_CONNECTIONS may wait for their response headers at
 * once. Every call the request path makes to another service goes through one `Outbound`: the
 * account and endpoint shards, the continuation stores, the tool-call id shards, the snapshot source,
 * the upstream, R2 (the content, the spooled bodies and the records outbox), the request index Queue and the wide-event
 * pipeline.
 *
 * A call holds its connection until its promise settles: for `fetch` and an R2 `get` that is when the
 * response headers arrive (the body streams on afterwards, counted no more, as the platform counts
 * it); for a Durable Object call, a Queue send or an R2 write, when its answer arrives. A call that
 * finds every connection taken waits here, in order, the request path's calls before background
 * work (releases, the record), instead of being queued by the runtime, which may cancel the least
 * recently used open connection of an invocation it believes stuck (C1) — possibly the upstream's.
 *
 * Retries do not add parallel waits beyond the limit: an attempt given up by its caller (an admit or
 * a settle past its attempt time, a permit past its wait) still holds its connection until it
 * answers, so the next attempt waits for a free one. A caller's own deadline counts the time spent
 * waiting here, and a call made with an AbortSignal leaves the queue when it aborts (the client left,
 * or the attempt's deadline passed): it never waits for a connection it no longer wants.
 */

/**
 * Cloudflare: an invocation may have at most six connections waiting for response headers at once;
 * further ones are queued (C1, https://developers.cloudflare.com/workers/platform/limits/,
 * "Simultaneous open connections"). The owner states the limit for every request of the gateway.
 */
export const MAX_WAITING_CONNECTIONS = 6;

interface Waiter {
  readonly urgent: boolean;
  readonly start: () => void;
}

export class Outbound {
  private waiting = 0;
  private readonly queue: Waiter[] = [];
  private readonly clock: () => number;
  /** The most connections that waited at once (the record keeps it). */
  peak = 0;
  /** How long calls waited in the queue for a connection, in all (the record keeps it). */
  queuedMs = 0;
  readonly limit: number;

  constructor(limit: number = MAX_WAITING_CONNECTIONS, clock: () => number = Date.now) {
    if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError(`an outbound limit must be a positive integer, got ${limit}`);
    this.limit = limit;
    this.clock = clock;
  }

  /** Connections waiting now. */
  get inFlight(): number {
    return this.waiting;
  }

  /**
   * Runs `call` when a connection is free and holds it until `call` settles. `urgent`: the request
   * path waits for it (an admit, a permit, the upstream, a settlement); background work (releases,
   * the record) waits behind every urgent call. `signal`: a call still in the queue when it aborts
   * leaves the queue and fails with the signal's reason, and one aborted already never starts.
   */
  run<T>(call: () => Promise<T>, urgent = true, signal?: AbortSignal | null): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      if (signal?.aborted) {
        reject(abortReason(signal));
        return;
      }
      const start = (): void => {
        this.waiting++;
        if (this.waiting > this.peak) this.peak = this.waiting;
        let p: Promise<T>;
        try {
          p = call();
        } catch (error) {
          p = Promise.reject(error);
        }
        // The connection is free before the caller hears the answer, so its next call finds it free.
        const done = (): void => {
          this.waiting--;
          this.next();
        };
        p.then(
          (value) => {
            done();
            resolve(value);
          },
          (error: unknown) => {
            done();
            reject(error);
          },
        );
      };
      if (this.waiting < this.limit && this.queue.length === 0) {
        start();
        return;
      }
      const queuedAt = this.clock();
      let leave: (() => void) | null = null;
      const waiter: Waiter = {
        urgent,
        start: () => {
          this.queuedMs += this.clock() - queuedAt;
          leave?.();
          start();
        },
      };
      if (urgent) {
        const firstBackground = this.queue.findIndex((w) => !w.urgent);
        if (firstBackground < 0) this.queue.push(waiter);
        else this.queue.splice(firstBackground, 0, waiter);
      } else {
        this.queue.push(waiter);
      }
      if (signal) {
        const aborted = (): void => {
          const at = this.queue.indexOf(waiter);
          if (at < 0) return;
          this.queue.splice(at, 1);
          this.queuedMs += this.clock() - queuedAt;
          reject(abortReason(signal));
        };
        signal.addEventListener("abort", aborted, { once: true });
        leave = () => signal.removeEventListener("abort", aborted);
      }
    });
  }

  /**
   * Takes one connection until `release` is called, for calls that must not wait behind the ones
   * they feed: a tier C body is read from R2 while its upstream request waits for headers, so the
   * attempt takes the body's connection before it sends (see `send` in inference.ts); otherwise an
   * upstream waiting for a body whose read waits for a connection would hold the request until its
   * deadline. The calls made under it do not go through `run`. `signal`: as `run`'s, while it waits.
   */
  hold(signal?: AbortSignal | null): Promise<() => void> {
    return new Promise<() => void>((resolve, reject) => {
      this.run(
        () =>
          new Promise<void>((done) => {
            let released = false;
            resolve(() => {
              if (released) return;
              released = true;
              done();
            });
          }),
        true,
        signal,
      ).catch(reject);
    });
  }

  private next(): void {
    while (this.waiting < this.limit && this.queue.length > 0) this.queue.shift()!.start();
  }

  // ---------------------------------------------------------------- the bindings, through it

  accounts(inner: ShardLocator): ShardLocator {
    return (address) => {
      const shard = () => inner(address);
      return {
        admit: (input) => this.run(() => shard().admit(input)),
        count: (input) => this.run(() => shard().count(input)),
        settle: (input) => this.run(() => shard().settle(input)),
        // Releases are background work, except the one that decides an undecided settlement, which
        // the request waits for; either way it is one connection.
        release: (input) => this.run(() => shard().release(input), false),
      };
    };
  }

  endpoints(inner: EndpointLocator): EndpointLocator {
    return (name, region) => {
      const shard = () => inner(name, region);
      return {
        acquire: (input) => this.run(() => shard().acquire(input)),
        release: (input) => this.run(() => shard().release(input), false),
        // A repeat waits for its place in the route's retry concurrency, as it waits for a permit.
        reserveRetry: (input) => this.run(() => shard().reserveRetry(input)),
        releaseRetry: (input) => this.run(() => shard().releaseRetry(input), false),
        // Background work, as a release is.
        note: (input) => this.run(() => shard().note(input), false),
        probeAnswered: (permit) => this.run(() => shard().probeAnswered(permit), false),
        probeSent: (permit) => this.run(() => shard().probeSent(permit), false),
      };
    };
  }

  /** The endpoint roots a failure's rest is filed at: background work, as a release is. */
  endpointRoots(inner: EndpointRootLocator): EndpointRootLocator {
    return (capacityKey) => ({ rest: (input) => this.run(() => inner(capacityKey).rest(input), false) });
  }

  continuation(inner: ContinuationLocator): ContinuationLocator {
    return (address) => {
      const store = () => inner(address);
      return {
        lookup: (input) => this.run(() => store().lookup(input)),
        bind: (input) => this.run(() => store().bind(input)),
      };
    };
  }

  /**
   * The tool-call id shards: the request's entry shard, asked for its handles before routing and to
   * store its answer's before they go out, both waited for (the home shards it asks are its calls,
   * not the request's).
   */
  toolCallIds(inner: ToolCallIdLocator): ToolCallIdLocator {
    return (name, hint) => {
      const shard = () => inner(name, hint);
      return {
        find: (input) => this.run(() => shard().find(input)),
        issue: (input) => this.run(() => shard().issue(input)),
      };
    };
  }

  /** The lane entry's record of used model-check tickets (model-check.ts): one call a lane model check waits for before it is served. */
  modelCheckTickets(inner: ModelCheckTicketStore): ModelCheckTicketStore {
    return { use: (id, expiresAtMs) => this.run(() => inner.use(id, expiresAtMs)) };
  }

  source(inner: SnapshotSource): SnapshotSource {
    return { current: (have) => this.run(() => inner.current(have)) };
  }

  /**
   * A fetch leaves the queue when its own signal aborts (the attempt's: the client left, its deadline passed).
   * `started` hears when it got its connection and was made: one aborted before never left the gateway.
   */
  fetch(inner: (input: string, init: RequestInit) => Promise<Response>): (input: string, init: RequestInit, started?: () => void) => Promise<Response> {
    return (input, init, started) =>
      this.run(
        () => {
          started?.();
          return inner(input, init);
        },
        true,
        init.signal,
      );
  }

  sinks(inner: Sinks): Sinks {
    const outbox = inner.outbox;
    return {
      sendEvents: (records) => this.run(() => inner.sendEvents(records), false),
      writePoint: (point) => inner.writePoint(point),
      serviceEvent: (event) => inner.serviceEvent(event),
      sendIndex: (message) => this.run(() => inner.sendIndex(message), false),
      // One R2 put (and a head when the key is there), one after the other: one connection.
      ...(outbox === undefined ? {} : { outbox: (kind, startedMs, requestId, body) => this.run(() => outbox.call(inner, kind, startedMs, requestId, body), false) }),
    };
  }

  bucket(inner: ContentBucket): ContentBucket {
    return {
      get: (key, options) => this.run(() => inner.get(key, options)),
      head: (key) => this.run(() => inner.head(key), false),
      put: (key, value, options) => this.run(() => inner.put(key, value, options), false),
      delete: (keys) => this.run(() => inner.delete(keys), false),
      createMultipartUpload: async (key) => {
        const upload = await this.run(() => inner.createMultipartUpload(key));
        return {
          uploadPart: (part, value) => this.run(() => upload.uploadPart(part, value)),
          complete: (parts) => this.run(() => upload.complete(parts)),
          abort: () => this.run(() => upload.abort(), false),
        };
      },
    };
  }
}

/** Why an aborted call failed: the signal's reason, as `fetch` rejects with it. */
function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

/** The part of the content bucket (R2) the request path uses. */
export interface ContentBucket {
  get(key: string, options?: R2GetOptions): Promise<R2ObjectBody | null>;
  head(key: string): Promise<R2Object | null>;
  put(key: string, value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob, options?: R2PutOptions): Promise<R2Object | null>;
  delete(keys: string | string[]): Promise<void>;
  createMultipartUpload(key: string): Promise<ContentUpload>;
}

/** The part of an R2 multipart upload the request path uses. */
export interface ContentUpload {
  uploadPart(part: number, value: ReadableStream | ArrayBuffer | ArrayBufferView | string | Blob): Promise<R2UploadedPart>;
  complete(parts: R2UploadedPart[]): Promise<R2Object>;
  abort(): Promise<void>;
}
