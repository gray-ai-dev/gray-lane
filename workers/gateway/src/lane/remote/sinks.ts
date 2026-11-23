import { asNumber, bridgeCall, laneEventsDtoOf, laneIndexMessageDtoOf, lanePointsDtoOf, laneServiceEventsDtoOf, RECORDS_TARGET } from "@gray/lane-wire";
import { ATTEMPT_MEASURES, type RouteAttempt } from "@gray/request-index";
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

/** Whether a route attempt carries any of its five measures (r15). */
const measured = (a: RouteAttempt): boolean => ATTEMPT_MEASURES.some((key) => a[key] !== undefined);

/** A route attempt without its five measures: r14's seven members, what a bridge before r15 knows. */
function unmeasured(a: RouteAttempt): RouteAttempt {
  const out: Record<string, unknown> = { ...a };
  for (const key of ATTEMPT_MEASURES) delete out[key];
  return out as unknown as RouteAttempt;
}

/** A row whose routing record states where its preset came from (r20). */
const statesModeSource = (row: RequestIndexMessage["rows"][number]): boolean => row.routing !== undefined && row.routing !== null && Object.hasOwn(row.routing, "mode_source");

/** A routing record without where its preset came from: what a bridge of r18 knows (the member left out, not null). */
function withoutModeSource<R extends object>(routing: R): R {
  const { mode_source: _source, ...rest } = routing as Record<string, unknown>;
  return rest as R;
}

/** A route attempt without its provider failure (2026-11-23): what a bridge before it knows. */
const withoutProviderFailure = ({ providerFailure: _failure, ...a }: RouteAttempt): RouteAttempt => a;

/**
 * `message` without what a bridge that answered `error` to it may have refused it for (`RemoteSinks.sendIndex`): its
 * rows' traces after a 404; after a 400 the newest member first, so a bridge that knows the older ones still gets them:
 * their routing records' preset source (r20), then their routing records (r18, docs/utility-routing-reads.md); then their
 * route attempts' provider failure (2026-11-23, docs/design/one-address.md "Provider defects at the entry"); then their
 * five measures (r15, docs/live-speed.md "Compatibility and rollout"), r14's seven members kept; then the route attempts
 * (r14); then their charge sides and route API (0076). Null when the failure is another, or the rows carry nothing of
 * that kind to take out: the failure stands.
 */
function withoutRefused(error: unknown, message: RequestIndexMessage): RequestIndexMessage | null {
  if (!(error instanceof BridgeCallError)) return null;
  if (error.status === 404 && message.rows.some((row) => row.stackTrace !== undefined)) {
    return { ...message, rows: message.rows.map(({ stackTrace: _stackTrace, ...row }) => row) };
  }
  // r20's member of the routing record, where its preset came from, the newest: a bridge of r18 knows the record without it.
  if (error.status === 400 && message.rows.some(statesModeSource)) {
    return { ...message, rows: message.rows.map((row) => (statesModeSource(row) ? { ...row, routing: withoutModeSource(row.routing!) } : row)) };
  }
  // r18's routing record (docs/utility-routing-reads.md "The confidential entry's record").
  if (error.status === 400 && message.rows.some((row) => row.routing !== undefined)) {
    return { ...message, rows: message.rows.map(({ routing: _routing, ...row }) => row) };
  }
  if (error.status === 400 && message.rows.some((row) => row.routeAttempts?.some((a) => a.providerFailure !== undefined) === true)) {
    return { ...message, rows: message.rows.map((row) => (row.routeAttempts === undefined ? row : { ...row, routeAttempts: row.routeAttempts.map(withoutProviderFailure) })) };
  }
  if (error.status === 400 && message.rows.some((row) => row.routeAttempts?.some(measured) === true)) {
    return { ...message, rows: message.rows.map((row) => (row.routeAttempts === undefined ? row : { ...row, routeAttempts: row.routeAttempts.map(unmeasured) })) };
  }
  if (error.status === 400 && message.rows.some((row) => row.routeAttempts !== undefined)) {
    return { ...message, rows: message.rows.map(({ routeAttempts: _attempts, ...row }) => row) };
  }
  if (error.status === 400 && message.rows.some((row) => (row.chargedInputMicrousd ?? row.chargedOutputMicrousd ?? row.upstreamProtocol ?? null) !== null)) {
    return { ...message, rows: message.rows.map(({ chargedInputMicrousd: _input, chargedOutputMicrousd: _output, upstreamProtocol: _api, ...row }) => row) };
  }
  return null;
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
   *
   * A bridge that predates the charge's two sides and the route's API (workers/db/migrations/0072,
   * docs/effective-prices.md) does not know them in a row, and refuses a document that carries one as it refuses any
   * document that is not the op's: 400 `bad_request` (lane-bridge errors.ts), the one status of that. The rows go again
   * without the three, so they are indexed, only without what that bridge could not have written. The bridge is still
   * to be deployed first (docs/cloudflare-native/gateway.md). A bridge that predates the route attempts (r14,
   * docs/error-rates.md "Rollout") refuses them the same way: the rows go again without them, and once more without
   * 0076's three for a bridge older still; those rows count in no error rate. A bridge that predates the attempts'
   * measures (r15, docs/live-speed.md "Compatibility and rollout") refuses those the same way, so they go first: the
   * rows go again with r14's seven members of each attempt, which count in the error rates and in none of the three
   * figures. A bridge that predates the attempts' provider failure (2026-11-23) refuses it the same way, so it goes
   * before the measures: the rows go again without it, and gray-jobs reads their defects as it reads those of an entry
   * before it (jobs traffic-evidence.ts `rowDefects`). Each is tried once, since rows sent again carry nothing left to
   * take out: a document refused for another reason throws as before.
   */
  async sendIndex(message: RequestIndexMessage): Promise<void> {
    try {
      await this.#sendIndex(message);
    } catch (error) {
      const without = withoutRefused(error, message);
      if (without === null) throw error;
      await this.sendIndex(without);
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
