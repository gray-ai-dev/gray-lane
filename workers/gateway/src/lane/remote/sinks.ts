import { asNumber, bridgeCall, laneEventsDtoOf, laneIndexMessageDtoOf, lanePointsDtoOf, laneServiceEventsDtoOf, RECORDS_TARGET } from "@gray/lane-wire";
import type { RequestIndexMessage, Sinks } from "../../sinks.ts";
import { BridgeCallError, BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The lane's sinks (design v2 section D, M20/M13): the **real** `RequestIndexRow`, the **real**
 * `gray.request/1` wide event and the Analytics Engine point of one request, over the bridge, with
 * the lane-forbidden fields nulled before they leave the CVM.
 *
 * The row and the event are the gateway's own, not a reduced record: the bridge passes each to the
 * same Queue and Pipeline the main lane uses, so PostgreSQL, the stream schema and the console read
 * lane rows exactly as they read main-lane rows. What changes is only what is *not* in them, and
 * `@gray/lane-wire`'s `laneIndexMessageDtoOf` and `laneEventsDtoOf` do that nulling themselves, so a
 * caller cannot forget a field.
 *
 * Two members of `Sinks` are synchronously typed and cannot be awaited: `writePoint` returns
 * `void` and `serviceEvent` returns `void`. They buffer here, and `flushSinks` drains the buffers in
 * the gateway's `ctx.waitUntil` at request end (design v2 section C.10). A failed flush never fails
 * the request (the main lane's `emitRecord` rule: a lost row is found by the hourly reconciliation).
 *
 * `serviceEvent` is carried: today's one service event is `gray.usage_refusal/1`
 * (usage-refusal.ts), and `records.service_events` takes it to the bridge, which validates the
 * envelope against the closed allow-list and writes it exactly as the gateway's
 * `bindingSinks.serviceEvent` does (`console.log(JSON.stringify(event))`), so it lands in the same
 * Workers Logs. The CVM's own log is not that place: a lane log line carries no record (M13).
 */
export interface LaneSinksOptions extends BridgeClientOptions {}

/** What a flush sent, for the request's own accounting; never a body. */
export interface LaneSinkFlush {
  readonly points: number;
  /** Service events written by the bridge as log lines. */
  readonly serviceEvents: number;
  /** The first failure's name, when one failed; never its message (a message may quote provider text). */
  readonly failed: string | null;
}

export class RemoteSinks extends BridgeClient implements Sinks {
  readonly #points: AnalyticsEngineDataPoint[] = [];
  readonly #serviceEvents: Record<string, unknown>[] = [];
  #flushing: Promise<LaneSinkFlush> | null = null;

  constructor(options: LaneSinksOptions) {
    super(options);
  }

  /**
   * The index row as it is: `laneIndexMessageDtoOf` nulls the forbidden columns (M20). A bridge that predates an entry's
   * traces (docs/confidential-lane-stack-routing.md section 4.10) refuses a trace of another relay than the key's with
   * 404 `unknown_relay`: the rows go again without their traces, so neither deploy order loses a row, only its trace.
   */
  async sendIndex(message: RequestIndexMessage): Promise<void> {
    try {
      await this.#sendIndex(message);
    } catch (error) {
      if (!(error instanceof BridgeCallError && error.status === 404) || !message.rows.some((row) => row.stackTrace !== undefined)) throw error;
      await this.#sendIndex({ ...message, rows: message.rows.map(({ stackTrace: _stackTrace, ...row }) => row) });
    }
  }

  async #sendIndex(message: RequestIndexMessage): Promise<void> {
    const dto = laneIndexMessageDtoOf(message);
    const answer = await this.call("records.index", bridgeCall("records.index", RECORDS_TARGET), dto);
    const accepted = asNumber(answer.accepted, "accepted");
    if (accepted !== dto.rows.length) throw new Error(`the bridge accepted ${accepted} of ${dto.rows.length} index rows`);
  }

  /** The wide event with every lane-forbidden column removed (`laneEventsDtoOf`, M13). */
  async sendEvents(records: readonly Record<string, unknown>[]): Promise<void> {
    if (records.length === 0) return;
    const dto = laneEventsDtoOf(records);
    const answer = await this.call("records.events", bridgeCall("records.events", RECORDS_TARGET), dto);
    const accepted = asNumber(answer.accepted, "accepted");
    if (accepted !== dto.records.length) throw new Error(`the bridge accepted ${accepted} of ${dto.records.length} events`);
  }

  /** "void in `Sinks`: buffered, and sent by `flushSinks` in the request's `waitUntil`." */
  writePoint(point: AnalyticsEngineDataPoint): void {
    this.#points.push(point);
  }

  /** "void in `Sinks`: buffered, and sent by `flushSinks` in the request's `waitUntil`." */
  serviceEvent(event: Record<string, unknown>): void {
    this.#serviceEvents.push(event);
  }

  /** Service events buffered now (tests and the request's accounting). */
  get bufferedServiceEvents(): number {
    return this.#serviceEvents.length;
  }

  /**
   * Sends what is buffered and never throws (the main lane's `emitRecord` rule). Coalesces with a
   * flush in flight; a later flush sends what arrived meanwhile.
   */
  async flush(): Promise<LaneSinkFlush> {
    if (this.#flushing !== null) {
      await this.#flushing;
      return this.flush();
    }
    const running = this.#sendPoints();
    this.#flushing = running;
    try {
      return await running;
    } finally {
      if (this.#flushing === running) this.#flushing = null;
    }
  }

  /** Sends both buffers; a failure in one does not hide the other's count, and neither throws. */
  async #sendPoints(): Promise<LaneSinkFlush> {
    const points = this.#points.splice(0, this.#points.length);
    const events = this.#serviceEvents.splice(0, this.#serviceEvents.length);
    if (points.length === 0 && events.length === 0) return { points: 0, serviceEvents: 0, failed: null };
    const failures: string[] = [];
    let written = 0;
    if (points.length > 0) {
      try {
        const dto = lanePointsDtoOf(points);
        const answer = await this.call("records.points", bridgeCall("records.points", RECORDS_TARGET), dto);
        written = asNumber(answer.accepted, "accepted");
        if (written !== dto.points.length) failures.push("records_points");
      } catch (error) {
        failures.push(error instanceof Error ? error.name : "error");
      }
    }
    if (events.length > 0) {
      try {
        // The projection drops every lane-forbidden member before the event leaves the CVM (M13).
        const dto = laneServiceEventsDtoOf(events);
        const answer = await this.call("records.service_events", bridgeCall("records.service_events", RECORDS_TARGET), dto);
        const accepted = asNumber(answer.accepted, "accepted");
        if (accepted !== dto.events.length) failures.push("records_service_events");
      } catch (error) {
        failures.push(error instanceof Error ? error.name : "error");
      }
    }
    return { points: written, serviceEvents: events.length, failed: failures.length === 0 ? null : failures[0]! };
  }
}

/** The lane's sinks over the bridge. */
export function remoteSinks(options: LaneSinksOptions): RemoteSinks {
  return new RemoteSinks(options);
}

/**
 * Flush a request's sink buffer inside `waitUntil` (design v2 section C.10), never throwing: the
 * request has already answered, and a lost record must not turn into an unhandled rejection.
 */
export async function flushSinks(sinks: { readonly flush?: () => Promise<unknown> } | null): Promise<void> {
  if (sinks === null || sinks.flush === undefined) return;
  try {
    await sinks.flush();
  } catch {
    // `flush` already swallows its failures; this only guards a foreign sink implementation.
  }
}
