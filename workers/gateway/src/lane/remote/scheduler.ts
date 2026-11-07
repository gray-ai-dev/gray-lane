import {
  BridgeWireError,
  SCHEDULER_FORWARD_MAX_BODY_BYTES,
  SCHEDULER_FORWARD_MAX_BUDGET_MS,
  SCHEDULER_FORWARD_METHODS,
  SCHEDULER_REQUEST_HEADERS,
  bridgeCall,
  isSchedulerForwardPath,
  schedulerForwardAnswerOf,
  schedulerForwardRequestDtoOf,
  schedulerTarget,
  type SchedulerForwardPath,
  type SchedulerRequestHeader,
  type SchedulerResponseHeader,
} from "@gray/lane-wire";
import { RelayConnectorError, type SchedulerFetch, type SchedulerResponseLike } from "@gray/relay-connector";
import { BridgeCallError, BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * A relay's scheduler calls over the bridge (F2 G5 option A, D16): the `SchedulerFetch` every
 * `SchedulerClient` of one relay is built with, wrapping one signed scheduler call into
 * `@gray/lane-wire`'s `scheduler.forward` op.
 *
 * Why: the lane's `LANE_BRIDGE` is an external-service binding that delivers every URL to the
 * bridge Worker (`entry.ts` boot `fetch: bridgeFetch(...)`). A `SchedulerClient` that used it
 * directly sent `https://relay.example/v1/pick` to the bridge, which has no such route (F2
 * entry-2). This transport strips the relay's URL down to what the scheduler protocol signs - the
 * method, the route and the closed `x-gray-*` request-header list - and the bridge reconstructs the
 * destination from **its own snapshot's** lane record for `relayId`, never from this request. Both
 * consumers require the record's `scheduler_url` to be an https **root** origin (D23/D42 re-enforced
 * by D51): this transport refuses a userinfo field, a path prefix, a query or a fragment with
 * `scheduler_bad_response` before any bridge call. The scheduler's own `gray-relay-scheduler-v1`
 * signature travels unchanged through the bridge, and the `SchedulerClient` verifies the relay's
 * signed answer here in the CVM; so the bridge can drop a pick (lane v1 then passes the route over;
 * there is no lease-table fallback, D27) but cannot choose an account.
 *
 * D109', D122' c': the forward carries what is left of the client's deadline for the exchange when
 * this transport sends (`budget_ms`: `SchedulerFetch`'s `remainingMs()`, of the pick's
 * `LANE_SCHEDULER_PICK_MS` or the report timeout), and the bridge's whole-op deadline is that budget
 * from its own request start. The bridge starts one one-way network time after the send, so its
 * deadline is not this one: in the tail its answer can land up to one round trip after the client
 * gave up, and D111's release (the ref's `not_sent`, which the client queues for a pick it lost) frees
 * the lease the relay may have taken. Nothing left means the exchange has already timed out: it fails
 * as `scheduler_timeout` here, and a budget of 0 is never sent. The CVM's own bridge call is timed by
 * the same remainder rather than the bridge client's `LANE_BRIDGE_CALL_MS` default, so a pick budget
 * above that default is honoured end to end. The call is bridge API version 2 (`@gray/lane-wire`
 * `LANE_BRIDGE_API_VERSION`): the version whose forward carries `budget_ms`.
 *
 * The bridge call itself is signed with the provisioned lane bridge key (D17, `LANE_BRIDGE_KEY_SEED`
 * through `createLaneState`'s `bridgeSigner`), never the per-boot key the scheduler request is
 * signed with. The two keys have different verifiers: the bridge knows the first before boot, the
 * relay learns the second from the ACI keyset.
 *
 * Nothing here is logged: a scheduler body is metadata and the header values are signatures and
 * timestamps, and the lane's log rule (M13) allows neither.
 */

export interface RemoteSchedulerOptions extends BridgeClientOptions {
  /** The relay whose scheduler this transport reaches (`scheduler.forward`'s `relay_id`). */
  readonly relayId: string;
  /** The relay's scheduler base URL from the lane record (the client's `baseUrl`). */
  readonly schedulerUrl: string;
}

/**
 * The relay's scheduler origin, or the protocol-fault refusal (D51).
 *
 * D23/D42 require a scheduler URL to be an https **root** origin: a host, no user information, a
 * pathname of exactly `/`, and no query or fragment. The control plane (`@gray/control`'s
 * `validSchedulerUrl`) enforces it on save; this transport enforces it again because an old or
 * malformed snapshot record must not reach a pick. The two fixed routes are appended to the origin
 * only, never to a path prefix. Refusing here refuses with `scheduler_bad_response` (the class the
 * scheduler client passes over), never `invalid_scheduler_request` (a caller's request bug) and
 * never a forwarded call.
 */
function schedulerOriginOf(schedulerUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(schedulerUrl);
  } catch {
    throw new RelayConnectorError("scheduler_bad_response");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname === "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new RelayConnectorError("scheduler_bad_response");
  }
  return parsed.origin;
}

/** The closed request-header list, all present (the `SchedulerClient` always sets every one). */
function schedulerRequestHeadersOf(headers: Record<string, string>): Record<SchedulerRequestHeader, string> {
  const out: Partial<Record<SchedulerRequestHeader, string>> = {};
  for (const name of SCHEDULER_REQUEST_HEADERS) {
    const value = headers[name];
    if (typeof value !== "string") throw new RelayConnectorError("invalid_scheduler_request", name);
    out[name] = value;
  }
  return out as Record<SchedulerRequestHeader, string>;
}

/**
 * The connector error a failed bridge call becomes, so `SchedulerClient`'s own mapping sees the kind
 * it expects (lane v1 passes the route over on any of them, D27). A bridge deadline or a
 * forwarded-call timeout is a timeout; a connection failure (`status === null`) is a transport
 * failure; a 2xx whose body is not the op's document is a protocol fault, never a transport failure
 * (VBF-4): `BridgeClient.call` throws `BridgeWireError` from `parseBridgeResponse` there. Any other
 * non-2xx is a protocol fault too.
 */
function schedulerErrorOf(error: unknown): RelayConnectorError {
  if (error instanceof RelayConnectorError) return error;
  if (error instanceof BridgeCallError) {
    if (error.code === "bridge_timeout" || error.status === 504) return new RelayConnectorError("scheduler_timeout");
    if (error.status === null) return new RelayConnectorError("scheduler_transport");
    return new RelayConnectorError("scheduler_bad_response");
  }
  if (error instanceof BridgeWireError) return new RelayConnectorError("scheduler_bad_response");
  return new RelayConnectorError("scheduler_transport");
}

/** One relay's scheduler transport. Its `fetch` is the `SchedulerFetch` the client takes. */
export class RemoteSchedulerTransport extends BridgeClient {
  readonly #relayId: string;
  readonly #origin: string;

  constructor(options: RemoteSchedulerOptions) {
    super(options);
    this.#relayId = options.relayId;
    this.#origin = schedulerOriginOf(options.schedulerUrl);
  }

  /** `SchedulerFetch`: one signed scheduler call becomes one signed `scheduler.forward`.
   *
   * The URL must be this relay's own **root** origin plus one of the two lane v1 routes: a
   * `SchedulerClient` built by the gateway always is (its base is the same root origin, D51), and
   * anything else (`/v1/lease`, D27; a path prefix; another host; user information; a query) is
   * refused here rather than forwarded to a destination the relay record does not name.
   */
  readonly fetch: SchedulerFetch = async (url, init) => {
    const route = this.#routeOf(url);
    const method = init.method.toUpperCase();
    if (method !== SCHEDULER_FORWARD_METHODS[route]) throw new RelayConnectorError("invalid_scheduler_request", "method");
    const body = init.body ?? new Uint8Array(0);
    // The op's own cap, checked here as well as by the bridge's reader: a body that could not
    // cross the wire is refused before it is base64-expanded and signed, not after.
    if (body.byteLength > SCHEDULER_FORWARD_MAX_BODY_BYTES) throw new RelayConnectorError("invalid_scheduler_request", "body");
    // D109', D122' c': what is left of the client's deadline for this exchange, now, is the budget the
    // bridge counts from its own start (so its deadline is not this one; the comment at the top). A call
    // without a deadline, or with one the wire cannot carry, is a caller bug, refused before any bridge
    // call; one with nothing left has already timed out.
    const budgetMs = init.remainingMs?.();
    if (budgetMs === undefined || !Number.isSafeInteger(budgetMs) || budgetMs > SCHEDULER_FORWARD_MAX_BUDGET_MS) {
      throw new RelayConnectorError("invalid_scheduler_request", "budget_ms");
    }
    if (budgetMs < 1) throw new RelayConnectorError("scheduler_timeout");
    const request = schedulerForwardRequestDtoOf({
      relayId: this.#relayId,
      method: method === "GET" ? "GET" : "POST",
      path: route,
      headers: schedulerRequestHeadersOf(init.headers),
      body,
      budgetMs,
    });
    let answer;
    try {
      // The bridge call's own timer is the same remainder, not the client's `LANE_BRIDGE_CALL_MS`
      // default: the bridge keeps the forward open for `budget_ms`, up to the setting's maximum, and
      // the exchange's `signal` still ends it first (the client's deadline started before this one).
      answer = await this.call("scheduler.forward", bridgeCall("scheduler.forward", schedulerTarget(this.#relayId)), request, {
        timeoutMs: budgetMs,
        ...(init.signal === undefined ? {} : { signal: init.signal }),
      });
    } catch (error) {
      throw schedulerErrorOf(error);
    }
    let relayed;
    try {
      relayed = schedulerForwardAnswerOf(answer);
    } catch {
      // A 2xx answer the bridge wrote but this client cannot read as the op's document is a protocol
      // fault, never a connection failure (VBF-4).
      throw new RelayConnectorError("scheduler_bad_response");
    }
    const bytes = relayed.body;
    return {
      status: relayed.status,
      headers: { get: (name: string) => relayed.headers[name as SchedulerResponseHeader] ?? null },
      body: new Response(bytes).body,
      arrayBuffer: async () => bytes.slice().buffer,
    } satisfies SchedulerResponseLike;
  };

  /** The scheduler route `url` names, from this relay's root origin; anything else is refused. */
  #routeOf(url: string): SchedulerForwardPath {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new RelayConnectorError("invalid_scheduler_request", "schedulerUrl");
    }
    if (
      parsed.origin !== this.#origin ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== ""
    ) {
      throw new RelayConnectorError("invalid_scheduler_request", "schedulerUrl");
    }
    // The route is exactly one of the closed set at the root: a prefixed path is not a route.
    if (!isSchedulerForwardPath(parsed.pathname)) throw new RelayConnectorError("invalid_scheduler_request", "path");
    return parsed.pathname;
  }
}

/** The `SchedulerFetch` of one relay's scheduler client. */
export function remoteSchedulerFetch(options: RemoteSchedulerOptions): SchedulerFetch {
  return new RemoteSchedulerTransport(options).fetch;
}
