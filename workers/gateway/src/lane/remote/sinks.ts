import { asNumber, bridgeCall, laneEventsDtoOf, laneIndexMessageDtoOf, lanePointsDtoOf, laneServiceEventsDtoOf, RECORDS_TARGET } from "@gray/lane-wire";
import { isEntryRegion, isTeeEntryNode, type RouteAttempt } from "@gray/request-index";
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
export interface LaneSinksOptions extends BridgeClientOptions {
  /**
   * Where a downgrade is said (`RemoteSinks.sendIndex`): one warn line, `lane_index_downgraded` with the member taken out
   * as `reason`, as remote/endpoint.ts and remote/snapshot.ts say theirs; the console by default.
   */
  readonly log?: (line: Record<string, unknown>) => void;
}

/** What a flush sent, for the request's own accounting; never a body. */
export interface LaneSinkFlush {
  readonly points: number;
  /** Service events written by the bridge as log lines. */
  readonly serviceEvents: number;
  /** The first failure's name, when one failed; never its message (a message may quote provider text). */
  readonly failed: string | null;
}

/** A row whose routing record states where its preset came from (r20). */
const statesModeSource = (row: RequestIndexMessage["rows"][number]): boolean => row.routing !== undefined && row.routing !== null && Object.hasOwn(row.routing, "mode_source");

/** The row's routing record says its checks were not made (`checks`, 2026-11-26): a bridge before it refuses that member. */
const statesChecks = (row: RequestIndexMessage["rows"][number]): boolean => row.routing !== undefined && row.routing !== null && Object.hasOwn(row.routing, "checks");

/** A routing record without `checks`: what a bridge before it knows (the member left out, not null). */
function withoutChecks<R extends object>(routing: R): R {
  const { checks: _checks, ...rest } = routing as Record<string, unknown>;
  return rest as R;
}

/** A routing record without where its preset came from: what a bridge of r18 knows (the member left out, not null). */
function withoutModeSource<R extends object>(routing: R): R {
  const { mode_source: _source, ...rest } = routing as Record<string, unknown>;
  return rest as R;
}

/** A route attempt without its provider failure (2026-11-23): what a bridge before it knows. */
const withoutProviderFailure = ({ providerFailure: _failure, ...a }: RouteAttempt): RouteAttempt => a;

/** A row that says the entry kept no content (`withheld`, `confidential`, content.ts `confidentialContent`). */
const confidential = (row: RequestIndexMessage["rows"][number]): boolean => row.contentReason === "confidential";

/**
 * The row as an entry before `confidential` sent it: content `failed`, `no_recipient`, which a bridge and a console of
 * that time read as the entry's (console request-log.ts `laneServed`).
 */
function asBeforeConfidential<R extends RequestIndexMessage["rows"][number]>(row: R): R {
  return { ...row, contentWithheld: false, contentStatus: "failed", contentReason: "no_recipient" };
}

/**
 * A row whose document names its serving entry (0110), what a bridge before it refuses: a TEE's pair, the only one
 * `laneIndexRowDtoOf` sends. Half a pair or a Workers gateway's was never in the document, so it is nothing to take out.
 */
const namesEntry = (row: RequestIndexMessage["rows"][number]): boolean => isTeeEntryNode(row.entryNode) && isEntryRegion(row.entryRegion);

/** What `withoutRefused` took out of a message: the member it names in its log line. */
type Downgrade = "checks" | "entry" | "confidential" | "mode_source" | "routing" | "provider_failure" | "trace";

/**
 * `message` without what a bridge that answered `error` to it may have refused it for (`RemoteSinks.sendIndex`), and
 * what was taken: its rows' traces after a 404; after a 400 the newest member first, so a bridge that knows the older
 * ones still gets them: their routing records' `checks` (2026-11-26, the checks that read the feed not made), then their
 * serving entry (0110, docs/design/request-logs.md "The serving entry"), then their content
 * reason `confidential` (the row as an entry before it sent it, `asBeforeConfidential`), then their routing records'
 * preset source (r20), then their routing records (r18, docs/utility-routing-reads.md); then their route attempts'
 * provider failure (2026-11-23, docs/design/one-address.md "Provider defects at the entry"). Null when the failure is
 * another, or the rows carry nothing of that kind to take out: the failure stands. Every bridge deployed since release
 * Z12 knows the older members (the route attempts of r14 and their measures of r15, the charge sides and route API of
 * 0072/0076), so a refusal of those is not taken for a missing member. Only a bridge's answer comes here: a document the
 * CVM's own check refused (`laneIndexRowDtoOf` projects nothing it would) was never sent.
 */
function withoutRefused(error: unknown, message: RequestIndexMessage): { readonly message: RequestIndexMessage; readonly downgrade: Downgrade } | null {
  if (!(error instanceof BridgeCallError)) return null;
  const rows = (map: (row: RequestIndexMessage["rows"][number]) => RequestIndexMessage["rows"][number]) => ({ ...message, rows: message.rows.map(map) });
  if (error.status === 404 && message.rows.some((row) => row.stackTrace !== undefined)) {
    return { message: rows(({ stackTrace: _stackTrace, ...row }) => row), downgrade: "trace" };
  }
  // The routing record's `checks`, the newest: an entry deployed before its bridge (the wrong order) loses only the word.
  if (error.status === 400 && message.rows.some(statesChecks)) {
    return { message: rows((row) => (statesChecks(row) ? { ...row, routing: withoutChecks(row.routing!) } : row)), downgrade: "checks" };
  }
  // 0110's serving entry: a bridge that knows `confidential` knows every other member of the row.
  if (error.status === 400 && message.rows.some(namesEntry)) {
    return { message: rows(({ entryNode: _node, entryRegion: _region, ...row }) => row), downgrade: "entry" };
  }
  // The content reason `confidential`: a bridge before it gets the row as an entry before it sent it.
  if (error.status === 400 && message.rows.some(confidential)) {
    return { message: rows((row) => (confidential(row) ? asBeforeConfidential(row) : row)), downgrade: "confidential" };
  }
  // r20's member of the routing record, where its preset came from: a bridge of r18 knows the record without it.
  if (error.status === 400 && message.rows.some(statesModeSource)) {
    return { message: rows((row) => (statesModeSource(row) ? { ...row, routing: withoutModeSource(row.routing!) } : row)), downgrade: "mode_source" };
  }
  // r18's routing record (docs/utility-routing-reads.md "The confidential entry's record").
  if (error.status === 400 && message.rows.some((row) => row.routing !== undefined)) {
    return { message: rows(({ routing: _routing, ...row }) => row), downgrade: "routing" };
  }
  if (error.status === 400 && message.rows.some((row) => row.routeAttempts?.some((a) => a.providerFailure !== undefined) === true)) {
    return { message: rows((row) => (row.routeAttempts === undefined ? row : { ...row, routeAttempts: row.routeAttempts.map(withoutProviderFailure) })), downgrade: "provider_failure" };
  }
  return null;
}

export class RemoteSinks extends BridgeClient implements Sinks {
  readonly #points: AnalyticsEngineDataPoint[] = [];
  readonly #serviceEvents: Record<string, unknown>[] = [];
  #flushing: Promise<LaneSinkFlush> | null = null;
  readonly #log: (line: Record<string, unknown>) => void;
  #downgrades = 0;

  constructor(options: LaneSinksOptions) {
    super(options);
    this.#log = options.log ?? ((line) => console.warn(JSON.stringify(line)));
  }

  /** How many times these sinks sent index rows again without a member a bridge refused (`withoutRefused`). */
  get downgrades(): number {
    return this.#downgrades;
  }

  /**
   * The index row as it is: `laneIndexMessageDtoOf` nulls the forbidden columns (M20). A bridge that predates an entry's
   * traces (docs/confidential-lane-stack-routing.md section 4.10) refuses a trace of another relay than the key's with
   * 404 `unknown_relay`: the rows go again without their traces, so neither deploy order loses a row, only its trace.
   *
   * A bridge that predates a member of the row does not know it, and refuses a document that carries one as it refuses
   * any document that is not the op's: 400 `bad_request` (lane-bridge errors.ts), the one status of that. The rows go
   * again without the member, so they are indexed, only without what that bridge could not have written. The bridge is
   * still to be deployed first (docs/cloudflare-native/gateway.md). A bridge that predates the routing record (r18,
   * docs/utility-routing-reads.md) refuses it so, and one that knows the record but not its preset's source (r20) that
   * member. A bridge that predates the attempts' provider failure (2026-11-23) refuses it the same way: the rows go
   * again without it, and gray-jobs reads their defects as it reads those of an entry before it (jobs
   * traffic-evidence.ts `rowDefects`). A bridge that predates the content reason `confidential` refuses
   * it the same way, so it goes before those: the rows go again as an entry before it sent them (`failed`,
   * `no_recipient`). The Workers that take it deploy before the entry release that sends it (@gray/request-index
   * CONTENT_REASONS), so this is the wrong order's fallback. A bridge that predates the serving entry (0110) refuses the
   * pair the same way, so it goes first of all: the rows go again without it, every other member kept, and are indexed
   * with both columns NULL, the identity unavailable (docs/design/request-logs.md "The serving entry"). A bridge that
 * predates the routing record's `checks` (2026-11-26) refuses it the same way, so it goes before even the serving
 * entry: the rows go again with the record as an entry before it wrote it, every other member kept. Each is tried
   * once, since rows sent again carry nothing left to take out: a document refused for another reason throws as before.
   * Each downgrade is counted (`downgrades`) and said in one line naming the member, never a value.
   */
  async sendIndex(message: RequestIndexMessage): Promise<void> {
    try {
      await this.#sendIndex(message);
    } catch (error) {
      const without = withoutRefused(error, message);
      if (without === null) throw error;
      this.#downgrades += 1;
      this.#log({ level: "warn", event: "lane_index_downgraded", reason: without.downgrade });
      await this.sendIndex(without.message);
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
