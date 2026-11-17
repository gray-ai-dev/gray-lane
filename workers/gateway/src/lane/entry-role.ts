import { bridgeCall, entryRoleOf, entryRoleRequestDtoOf, entryRoleTarget, type EntryRole } from "@gray/lane-wire";
import { BridgeCallError, BridgeClient, type BridgeClientOptions } from "./remote/client.ts";

export type { EntryRole };

/**
 * An entry replica's drain (docs/design/entry-replicas.md ER9, as the entry replicas' operating spec of 2026-11-17
 * revised it). To update replica k the release tool sets k's role to `draining`, disables k's endpoint at the load
 * balancer, waits until k's `/healthz` reports `replica.in_flight == 0` for 10 s (at least 60 s, at most 15 min), updates
 * k's VM, and sets the role back to `serving` once k passed its gate.
 *
 * This file is the replica's side, for an entry with a replica index (LANE_REPLICA) only; an entry without one has
 * none of it:
 *
 * - **The role** (`LaneEntryRole`): read through the bridge (`entry.role`, the console's `lane_entry_roles`) at most every
 *   LANE_ENTRY_ROLE_POLL_MS, behind the requests the replica serves (workerd runs nothing between requests). It starts
 *   `serving`; an answer that cannot be read keeps the role last read (EI10: an unreadable role is never a drain).
 *   `stopping` is `draining` here, and more: the Worker drives the stop (ops spec "Review fixes, 2026-11-17 night").
 * - **The stop.** On a `stopping` written during this boot the Worker calls the entrypoint's stop socket (`ENTRY_STOP`,
 *   `POST /stop`, deploy/tee/bin/entrypoint.mjs `serveEntryStop`), every poll until it answers 200: the entrypoint
 *   sends workerd SIGTERM once, and workerd's own drain then takes no new request and ends each one in flight. Only
 *   after that 200, and with nothing in flight, does the Worker close the stack VMs' channel sessions through peerlink
 *   (`PeerLink.closeAll`), every poll until peerlink lists none: workerd's SIGTERM drain waits for open WebSockets
 *   (measured 2026-11-17, IMPLEMENTATION_NOTES.md) and these never end on their own. Closing them only after the stop
 *   means a replica never takes requests without its sessions (`peer_session_missing`). From the first such `stopping`
 *   the channel refuses new attaches and tunnels. The watch that does it runs in the background of a request
 *   (`ctx.waitUntil`) from the first read of a role other than `serving` written during this boot, and reads the role
 *   every poll on its own: after SIGTERM no new request is answered, and background work keeps running (measured).
 * - **A role written before this boot** (`updated_ms` older than the holder) is reported and its header sent, but it
 *   stops nothing and starts no watch: a replica updated or restarted while its row still says `stopping` must pass its
 *   gate. A workerd the supervisor restarted after `stopping` was written is such a boot: it does not stop, and the
 *   release tool's bound on the stop applies.
 * - **While draining** every response carries `Connection: close`, so a keep-alive client would reconnect through the
 *   load balancer to another replica. Best effort: workerd v1.20261006.1 does not honour it (measured 2026-11-17: the
 *   header is dropped from the wire answer and the connection stays open for the next request, over HTTP and HTTPS).
 *   The bound is the release tool's: no new connection reaches a disabled endpoint, and the drain waits at most 15 min.
 *   IMPLEMENTATION_NOTES.md, "The entry's role and in-flight count", says what workerd does instead.
 * - **The in-flight count**: a request is counted from the moment the entry takes it until its answer is done (its body
 *   ends, the client goes away, or the handler throws, exactly once whichever comes first) **and** the work it holds has
 *   settled: the handler's own run and everything it left behind in `ctx.waitUntil` (`RequestCount.hold`; the entry
 *   hands the handler a context whose `waitUntil` holds). That work is the request's end: its record, its receipt, the
 *   relay scheduler's outcome report that frees the pick's lease (`inference.ts` `finishLane`, `reportLanePick`) and the
 *   permit's release. workerd's SIGTERM drain does not wait for `ctx.waitUntil` (measured, IMPLEMENTATION_NOTES.md "The
 *   entry's role and in-flight count"): at staging's stop of 2026-11-17 the sessions were closed 0.1 s after the last
 *   answer's body ended, workerd exited, the record calls were cut and the outcome report never left, so the relay held
 *   the pick's lease to its in-flight TTL (600 s). Held work counts at most REQUEST_TAIL_MAX_MS after the answer is done,
 *   so a promise that never settles cannot hold a stop. `/healthz` and the outbound-only channel's routes (attach,
 *   tunnel: long-lived sessions the stack VMs redial) are not counted. An answer of fixed length stays one on the wire
 *   (`answer` below).
 * - **After the stop** (SIGTERM sent) a counted answer's body is closed only once its request's held work settled (at
 *   most REQUEST_TAIL_MAX_MS): its bytes go out as they come, only the end waits. The open answer is what holds workerd's
 *   drain for that work when no channel session does (a replica without stack VMs).
 */

/**
 * How long the work a request left behind (`RequestCount.hold`) keeps it counted after its answer is done: twice the
 * platform's 30 s after the client (AFTER_CLIENT_LEFT_MS, `client.ts`), the time the request path fits its record and
 * receipt into, which the scheduler's report (3 s, `@gray/relay-connector`) and the sinks' flush follow.
 */
export const REQUEST_TAIL_MAX_MS = 60_000;

/**
 * One counted request (`LaneEntryRole.begin`): calling it ends the answer (idempotent: the body's end, a cancelled body,
 * the handler's throw and the client's abort signal may all call it); `hold` keeps the request counted until `work`
 * settles; `settled` resolves once the answer is done and every held work settled.
 */
export interface RequestCount {
  (): void;
  hold(work: PromiseLike<unknown>): void;
  readonly settled: Promise<void>;
}

/** A counted request's state. */
interface Counted {
  /** The answer is not done yet. */
  open: boolean;
  /** Held work not settled yet. */
  pending: number;
  /** When the answer was done (the held work's bound runs from it). */
  doneMs: number | null;
  readonly settle: () => void;
}

/** `entry.role` over the bridge, signed with the lane's bridge key. */
export class EntryRoleClient extends BridgeClient {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  async role(index: number): Promise<{ readonly role: EntryRole; readonly updatedMs: number | null }> {
    return entryRoleOf(await this.call("entry.role", bridgeCall("entry.role", entryRoleTarget(index)), entryRoleRequestDtoOf(index)));
  }
}

export interface EntryRoleSource {
  role(index: number): Promise<{ readonly role: EntryRole; readonly updatedMs: number | null }>;
}

export interface LaneEntryRoleOptions {
  /** The replica's index, 1 to 16 (LANE_REPLICA). */
  readonly index: number;
  /** The replica's own origin, `https://<replica name>` (the boot state's `laneOrigin`). */
  readonly origin: string;
  readonly source: EntryRoleSource;
  readonly now: () => number;
  /** LANE_ENTRY_ROLE_POLL_MS. */
  readonly pollMs: number;
  readonly log?: (line: Record<string, unknown>) => void;
  /**
   * The stack VMs' channel sessions closed at a stop (`PeerLink.closeAll`): how many peerlink listed before the closes
   * (0: none left), or null when peerlink did not answer. `idle` is checked again right before the closes.
   */
  readonly closeSessions?: (idle: () => boolean) => Promise<number | null>;
  /** The entrypoint's stop (`ENTRY_STOP`'s `POST /stop`): true once it answered 200. Absent: no stop can be sent. */
  readonly requestStop?: () => Promise<boolean>;
  readonly sleep?: (ms: number) => Promise<void>;
}

/** What `/healthz` says of a replica. */
export interface EntryReplicaSummary {
  readonly index: number;
  readonly origin: string;
  readonly role: EntryRole;
  readonly in_flight: number;
}

function codeOf(error: unknown): string {
  if (error instanceof BridgeCallError) return error.status === null ? error.code : `${error.code}_${error.status}`;
  return error instanceof Error ? error.name : "error";
}

/**
 * `body` read through a JavaScript stream of its own, which calls `end` once its source is read to its end, errors, or
 * is cancelled (the client went away). It reads the source's own reader: never a `pipeTo` from one of workerd's
 * streams into another. workerd 1.20261006.1 does not implement that pipe between two of its transform streams
 * ("Inter-TransformStream ReadableStream.pipeTo() is not implemented"; `inference.ts` answers a `FixedLengthStream`'s
 * readable): it rejects at once, the second stream is never written, and the answer's head goes out with its length
 * and no body ever (the two-entry e2e of 2026-11-17, test/lane-hooks/workerd/lane-hooks-cvm.test.ts). `highWaterMark`
 * 0: nothing is read ahead of the consumer, so the source's end is read only once the consumer took the last chunk.
 * At its end `tail` says what to wait for before the close (the request's held work, after the stop), or null.
 */
function counted(body: ReadableStream<Uint8Array>, end: () => void, tail: () => Promise<void> | null): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        let read: ReadableStreamReadResult<Uint8Array>;
        try {
          read = await reader.read();
        } catch (error) {
          end();
          controller.error(error);
          return;
        }
        if (read.done) {
          end();
          const waiting = tail();
          if (waiting === null) {
            controller.close();
            return;
          }
          await waiting;
          // A client that cancelled meanwhile closed the stream already.
          try {
            controller.close();
          } catch {
            // Nothing is left to close.
          }
        } else {
          controller.enqueue(read.value);
        }
      },
      cancel(reason) {
        end();
        return reader.cancel(reason);
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * The counted body as it goes on the wire. With a declared length, the counted stream is piped into a
 * `FixedLengthStream` of it (a JavaScript stream into a workerd one, as `inference.ts` makes its own answer), so the
 * answer keeps its Content-Length; without one (a live stream, or Node in the tests) it is the counted stream itself.
 */
function wireBody(body: ReadableStream<Uint8Array>, length: number | null, end: () => void, tail: () => Promise<void> | null): ReadableStream<Uint8Array> {
  const source = counted(body, end, tail);
  if (length === null || typeof FixedLengthStream === "undefined") return source;
  const fixed = new FixedLengthStream(length);
  // A client that cancels the answer cancels the pipe's source, and so the handler's own stream, as before.
  source.pipeTo(fixed.writable).catch(() => {});
  return fixed.readable;
}

const CONTENT_LENGTH = /^(0|[1-9][0-9]{0,15})$/;

export class LaneEntryRole {
  readonly #options: LaneEntryRoleOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #role: EntryRole = "serving";
  #updatedMs: number | null = null;
  #askedAt: number | null = null;
  #asking: Promise<void> | null = null;
  /** The counted requests not yet done with (`begin`); `inFlight` reads them. */
  readonly #requests = new Set<Counted>();
  /** When this holder began: a role written before it is this boot's predecessor's. */
  readonly #bootMs: number;
  /** Reads in a row that answered `stopping` written during this boot. */
  #stops = 0;
  #watching = false;
  /** The entrypoint answered the stop with 200: workerd's drain has begun, nothing undoes it. */
  #stopSent = false;
  /** peerlink listed no session after the stop: the watch is done (until a read of `serving`). */
  #closed = false;
  #noStopLogged = false;

  constructor(options: LaneEntryRoleOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
    this.#bootMs = options.now();
  }

  get index(): number {
    return this.#options.index;
  }

  /** The role last read: `serving` before the first answer and while none can be read. */
  get role(): EntryRole {
    return this.#role;
  }

  /** `draining` or `stopping`: out of rotation (`Connection: close` on every answer). */
  get draining(): boolean {
    return this.#role !== "serving";
  }

  /** A `stopping` written during this boot has been read, or the stop was sent: the channel takes no new session or tunnel. */
  get stopping(): boolean {
    return this.#stops > 0 || this.#stopSent;
  }

  /**
   * The customer requests this replica holds now: those whose answer is not done, and those whose held work has not
   * settled within REQUEST_TAIL_MAX_MS of it.
   */
  get inFlight(): number {
    const now = this.#options.now();
    let held = 0;
    for (const request of this.#requests) {
      if (request.open || (request.pending > 0 && now - (request.doneMs ?? now) < REQUEST_TAIL_MAX_MS)) held += 1;
      else this.#requests.delete(request);
    }
    return held;
  }

  summary(): EntryReplicaSummary {
    return { index: this.#options.index, origin: this.#options.origin, role: this.#role, in_flight: this.inFlight };
  }

  /** Reads the role when a poll is due (one at a time). Never throws: a failed read keeps the role. */
  async tick(): Promise<void> {
    const now = this.#options.now();
    if (this.#asking === null && (this.#askedAt === null || now - this.#askedAt >= this.#options.pollMs)) {
      this.#askedAt = now;
      this.#asking = this.#ask().finally(() => {
        this.#asking = null;
      });
    }
    if (this.#asking !== null) await this.#asking;
  }

  /** Whether the role last read was written during this boot. */
  #fresh(): boolean {
    return this.#updatedMs !== null && this.#updatedMs >= this.#bootMs;
  }

  async #ask(): Promise<void> {
    const index = this.#options.index;
    try {
      const answer = await this.#options.source.role(index);
      const previous = this.#role;
      this.#role = answer.role;
      this.#updatedMs = answer.updatedMs;
      this.#stops = answer.role === "stopping" && this.#fresh() ? this.#stops + 1 : 0;
      // A drain called off: a later stop closes the sessions again.
      if (answer.role === "serving") this.#closed = false;
      if (answer.role !== previous) this.#log({ level: answer.role === "serving" ? "info" : "warn", event: "lane_entry_role", index, role: answer.role, previous, updated_ms: this.#updatedMs, this_boot: this.#fresh() });
    } catch (error) {
      this.#log({ level: "warn", event: "lane_entry_role_failed", index, code: codeOf(error), role: this.#role });
    }
  }

  /** One read now (or the one running). */
  async #askNow(): Promise<void> {
    if (this.#asking === null) {
      this.#askedAt = this.#options.now();
      this.#asking = this.#ask().finally(() => {
        this.#asking = null;
      });
    }
    await this.#asking;
  }

  /**
   * The stop's watch (see above), started behind a request once a role other than `serving`, written during this boot,
   * has been read; at most one runs. `keepAlive` is the request's `ctx.waitUntil`. Every poll: on a `stopping` of this
   * boot it asks for the stop until the entrypoint answers 200; once it has, and nothing is in flight, it closes the
   * sessions until peerlink lists none, then ends. Before the stop it ends when the role is `serving` again. It never
   * holds workerd's drain longer than the stop needs.
   */
  watch(keepAlive: (work: Promise<unknown>) => void): void {
    if (this.#watching || this.#closed || this.#role === "serving" || !this.#fresh()) return;
    this.#watching = true;
    const sleep = this.#options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    keepAlive(
      (async () => {
        try {
          for (;;) {
            if (!this.#stopSent && this.#stops > 0) this.#stopSent = await this.#requestStop();
            if (this.#stopSent) {
              // After the stop workerd takes no new request, so the count only falls; `closeSessions` checks it again
              // right before its closes. The count holds each request's own end (its record, receipt and outcome
              // report): the sessions are what holds workerd's drain while that work runs.
              if (this.inFlight === 0 && (await this.#closeSessions())) return;
            } else if (this.#role === "serving") {
              return;
            }
            await sleep(this.#options.pollMs);
            await this.#askNow();
          }
        } finally {
          this.#watching = false;
        }
      })(),
    );
  }

  /** The entrypoint's stop; false (asked again at the next poll) without a 200. */
  async #requestStop(): Promise<boolean> {
    const index = this.#options.index;
    const request = this.#options.requestStop;
    if (request === undefined) {
      if (!this.#noStopLogged) this.#log({ level: "error", event: "lane_entry_stop_unavailable", index, code: "no_entry_stop" });
      this.#noStopLogged = true;
      return false;
    }
    try {
      const sent = await request();
      this.#log({ level: sent ? "warn" : "error", event: sent ? "lane_entry_stop_sent" : "lane_entry_stop_refused", index, in_flight: this.inFlight });
      return sent;
    } catch (error) {
      this.#log({ level: "error", event: "lane_entry_stop_refused", index, code: codeOf(error) });
      return false;
    }
  }

  /** One round of closes; true once peerlink lists no session, false (again at the next poll) otherwise. */
  async #closeSessions(): Promise<boolean> {
    const index = this.#options.index;
    const close = this.#options.closeSessions;
    try {
      const listed = close === undefined ? 0 : await close(() => this.inFlight === 0);
      if (listed === null) {
        this.#log({ level: "warn", event: "lane_entry_sessions_close_failed", index, code: "peerlink_unavailable" });
        return false;
      }
      if (listed > 0) {
        this.#log({ level: "warn", event: "lane_entry_sessions_closing", index, sessions: listed });
        return false;
      }
      this.#closed = true;
      this.#log({ level: "warn", event: "lane_entry_sessions_closed", index });
      return true;
    } catch (error) {
      this.#log({ level: "error", event: "lane_entry_sessions_close_failed", index, code: codeOf(error) });
      return false;
    }
  }

  /**
   * Counts one request from now. Calling the returned count ends its answer; it is idempotent, so every path that may
   * end the answer (the body's end, a cancelled body, the handler's throw, the client's abort signal) may call it. Its
   * `hold` keeps the request counted until a work settles (the handler's run, each `ctx.waitUntil` of the request),
   * at most REQUEST_TAIL_MAX_MS after the answer; a work held after the request was done counts it again within that
   * bound.
   */
  begin(signal?: AbortSignal | null): RequestCount {
    let settle = (): void => undefined;
    const settled = new Promise<void>((resolve) => (settle = resolve));
    const request: Counted = { open: true, pending: 0, doneMs: null, settle };
    this.#requests.add(request);
    const done = (): void => {
      if (request.open || request.pending > 0) return;
      this.#requests.delete(request);
      request.settle();
    };
    const end = (): void => {
      if (!request.open) return;
      request.open = false;
      request.doneMs = this.#options.now();
      signal?.removeEventListener("abort", end);
      done();
    };
    const release = (): void => {
      request.pending -= 1;
      done();
    };
    const hold = (work: PromiseLike<unknown>): void => {
      request.pending += 1;
      this.#requests.add(request);
      Promise.resolve(work).then(release, release);
    };
    if (signal?.aborted === true) end();
    else signal?.addEventListener("abort", end);
    return Object.assign(end, { hold, settled });
  }

  /**
   * What a counted answer's close waits for: after the stop (SIGTERM sent), the request's held work, at most
   * REQUEST_TAIL_MAX_MS; nothing before it, when workerd does not exit.
   */
  #tailOf(count: RequestCount): () => Promise<void> | null {
    return () => {
      if (!this.#stopSent) return null;
      let timer: ReturnType<typeof setTimeout> | null = null;
      const bound = new Promise<void>((resolve) => (timer = setTimeout(resolve, REQUEST_TAIL_MAX_MS)));
      return Promise.race([count.settled, bound]).finally(() => clearTimeout(timer));
    };
  }

  /**
   * The answer as the replica sends it: with `Connection: close` while draining, and, for a counted request (`end`), the
   * end of its answer. Every answer of fixed length stays one on the wire:
   *
   * - a declared `content-length` (the generation path's whole answers): the body is read through `counted`, piped into a
   *   `FixedLengthStream` of that length (`wireBody`), and the answer is done when its last chunk was taken;
   * - `live` (a generation answer that may still be streaming: a 2xx without a declared length, SSE or a relayed body):
   *   read through `counted`, chunked as such a stream goes anyway, and the answer is done with it;
   * - anything else (the lane's own JSON and text answers, errors included, whose bodies are complete when the handler
   *   returns; workerd puts no content-length in their headers but sends one): the body is not touched, so workerd keeps
   *   sending its length, and the answer is done now.
   *
   * After the stop a piped body's close waits for the request's held work (`#tailOf`); its bytes do not.
   */
  answer(response: Response, end: RequestCount | null, live = false): Response {
    const draining = this.draining;
    const declared = response.headers.get("content-length");
    const length = declared !== null && CONTENT_LENGTH.test(declared) ? Number(declared) : null;
    const pipe = end !== null && response.body !== null && (length !== null || live);
    if (end !== null && !pipe) end();
    if (!draining && !pipe) return response;
    const headers = new Headers(response.headers);
    if (draining) headers.set("connection", "close");
    let body = response.body;
    if (pipe && body !== null && end !== null) body = wireBody(body, length, end, this.#tailOf(end));
    return new Response(body, { status: response.status, statusText: response.statusText, headers });
  }
}

/**
 * The replica index of a lane with `env`, or null for an entry without one. LANE_REPLICA is the entrypoint's
 * (deploy/tee/bin/entrypoint.mjs `replicaFragments`, rendered from the instance's index beside TLS_REPLICA_DOMAIN), a
 * whole number from 1 to 16; set without a replica name, or malformed, it is a configuration problem.
 */
export function laneReplicaIndex(env: Readonly<Record<string, unknown>>, replicaDomain: string | null): { readonly index: number | null; readonly problem: string | null } {
  const value = env.LANE_REPLICA;
  if (value === undefined || value === null || value === "") return { index: null, problem: null };
  if (typeof value !== "string" || !/^[1-9][0-9]?$/.test(value) || Number(value) > 16) return { index: null, problem: "LANE_REPLICA is a replica's index, a whole number from 1 to 16" };
  if (replicaDomain === null) return { index: null, problem: "LANE_REPLICA is set without TLS_REPLICA_DOMAIN: a replica's index comes with its name" };
  return { index: Number(value), problem: null };
}
