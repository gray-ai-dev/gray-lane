import {
  BRIDGE_REQUEST_MAX_BYTES,
  BRIDGE_RESPONSE_MAX_BYTES,
  BridgeWireError,
  LANE_BRIDGE_CALL_MS,
  encodeBridgeRequest,
  parseBridgeRequest,
  parseBridgeResponse,
  signBridgeRequest,
  type BridgeCall,
  type BridgeOp,
  type BridgeRequestOf,
  type BridgeResponseOf,
  type BridgeSigner,
} from "@gray/lane-wire";
import { laneNonceSpread } from "./nonces.ts";

/**
 * The lane's one transport to the bridge (design v2 section D): every remote client under
 * `lane/remote/` is a thin mapping of a gateway-local interface onto `bridgeCall` calls made
 * through this file, so the error table (B6) lives in exactly one place.
 *
 * The error table, as it decides money:
 *
 * - a `fetch` throw (the connection refused, reset or never made), a timeout (`bridge_timeout`),
 *   a non-2xx status, a body that is not the op's document (`parseBridgeResponse`'s
 *   `BridgeWireError`) — all **throw**, never become an `AdmitResult`/`SettleResult`/`AcquireResult`
 *   of another code. `admitWithRetry`, `settleWithRetry` and the in-doubt logic take exactly the
 *   branch they take for a failed Durable Object call; a lost settle or a lost release is read as
 *   "the shard may have committed", never as "refused".
 * - only a 2xx answer carrying the op's well-formed document becomes a result.
 *
 * One call is signed with the provisioned lane key (`gray-lane-bridge-v1`: the op, the target
 * address, the method, the path, the timestamp, the nonce and the body SHA-256), so a call cannot
 * be replayed as another op, at another target or inside another path (M26).
 */

/** Why a call could not be read as a result: transport or timeout, never a schema problem. */
export class BridgeCallError extends Error {
  override readonly name = "BridgeCallError";
  readonly code: "bridge_transport" | "bridge_timeout";
  /** The HTTP status a non-2xx answer carried; null when no answer arrived. */
  readonly status: number | null;

  constructor(code: "bridge_transport" | "bridge_timeout", message: string, status: number | null = null) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

/** The default deadline of one bridge call, from the wire package so the bridge can validate
 * its snapshot path against it (bridge-3). Re-exported here for the callers that read it. */
export { LANE_BRIDGE_CALL_MS };

/** What a remote client needs to place calls: a base URL, the lane key and a transport. */
export interface BridgeClientOptions {
  /**
   * The bridge's base URL, no trailing slash (`https://bridge.example`). The bridge routes exact
   * `@gray/lane-wire` paths, so a path prefix is not served (I-02): every call under one would 404.
   */
  readonly baseUrl: string;
  /** The provisioned lane key's id, as the bridge's configuration lists it. */
  readonly keyId: string;
  /** The lane key: a 32-byte seed, a function, or a `{sign}` object (the per-boot provider wrapper). */
  readonly signingKey: BridgeSigner;
  /** Injected for tests; production passes the binding's fetch. */
  readonly fetch?: (input: string, init: RequestInit) => Promise<Response>;
  /** The clock; `Date.now` by default. */
  readonly now?: () => number;
  /** Per-call deadline in milliseconds, default `LANE_BRIDGE_CALL_MS`. */
  readonly timeoutMs?: number;
}

interface BridgeBase {
  readonly base: string;
  readonly keyId: string;
  readonly signingKey: BridgeSigner;
  readonly fetch: (input: string, init: RequestInit) => Promise<Response>;
  readonly now: () => number;
  readonly timeoutMs: number;
}

function normalize(options: BridgeClientOptions): BridgeBase {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const parsed = new URL(`${baseUrl}/`);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopback(parsed.hostname))) {
    throw new BridgeCallError("bridge_transport", "the bridge URL is not https (a loopback http is for tests only)");
  }
  return {
    base: baseUrl,
    keyId: options.keyId,
    signingKey: options.signingKey,
    fetch: options.fetch ?? ((input, init) => fetch(input, init)),
    now: options.now ?? (() => Date.now()),
    timeoutMs: options.timeoutMs ?? LANE_BRIDGE_CALL_MS,
  };
}

function isLoopback(hostname: string): boolean {
  const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

/** A remote client over `options`; each subclass maps one gateway-local interface. */
export abstract class BridgeClient {
  private readonly inner: BridgeBase;

  protected constructor(options: BridgeClientOptions) {
    this.inner = normalize(options);
  }

  /**
   * The request document, encoded and checked, of `op`'s call to `call`.
   * The call's `path` must already be under the op's (`bridgeCall` enforces it).
   *
   * `options.signal` is an outer cancellation (the scheduler client's own per-call deadline, G5):
   * when it aborts, this call's controller aborts too, so a bridge call does not keep running after
   * its caller has already taken the fallback.
   *
   * `options.timeoutMs` replaces the client's per-call deadline for this one call. The scheduler
   * transport passes what is left of the exchange's budget when it sends, the forward's `budget_ms`
   * (D109', D122' c'): the bridge holds a forward open for that long from its own start, which may be
   * longer than `LANE_BRIDGE_CALL_MS`, so the client's default would cut a pick the setting allows.
   */
  protected async call<O extends BridgeOp>(op: O, call: BridgeCall, request: BridgeRequestOf<O>, options: { readonly signal?: AbortSignal; readonly timeoutMs?: number } = {}): Promise<BridgeResponseOf<O>> {
    const timeoutMs = options.timeoutMs ?? this.inner.timeoutMs;
    const parsed = parseBridgeRequest(op, request);
    const body = encodeBridgeRequest(op, parsed);
    if (body.byteLength > BRIDGE_REQUEST_MAX_BYTES) throw new BridgeCallError("bridge_transport", `the ${op} request is over ${BRIDGE_REQUEST_MAX_BYTES} bytes`);
    const headers = await signBridgeRequest({
      call,
      keyId: this.inner.keyId,
      timestampMs: this.inner.now(),
      // The nonce names the bridge object that remembers it; the lane's calls keep to as few as its rate allows (M14).
      nonce: laneNonceSpread(this.inner.keyId).next(this.inner.now()),
      body,
      signingKey: this.inner.signingKey,
    });
    const url = `${this.inner.base}${call.path}`;
    let response: Response;
    const controller = new AbortController();
    const outer = options.signal;
    const onAbort = (): void => controller.abort();
    if (outer !== undefined) {
      if (outer.aborted) onAbort();
      else outer.addEventListener("abort", onAbort, { once: true });
    }
    let timer: ReturnType<typeof setTimeout> | null = null;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        // Named before the abort: a fetch may reject on its signal synchronously, and the race must
        // read this call's own deadline as `bridge_timeout`, not as the transport failure of that abort.
        reject(new BridgeCallError("bridge_timeout", `${op} took longer than ${timeoutMs} ms`));
        controller.abort();
      }, timeoutMs);
    });
    try {
      response = await Promise.race([
        this.inner.fetch(url, {
          method: call.method,
          headers,
          ...(call.method === "GET" ? {} : { body }),
          signal: controller.signal,
          redirect: "manual",
        }),
        deadline,
      ]);
      // A non-2xx body is never read (bridge-5): cancel it and report the status, so a bridge that
      // answers an error with a stream does not make this client buffer it.
      if (response.status < 200 || response.status >= 300) {
        await response.body?.cancel().catch(() => undefined);
        throw new BridgeCallError("bridge_transport", `${op} answered ${response.status}`, response.status);
      }
      const stated = response.headers.get("content-length");
      if (stated !== null && /^[0-9]+$/.test(stated) && Number(stated) > BRIDGE_RESPONSE_MAX_BYTES) {
        await response.body?.cancel().catch(() => undefined);
        throw new BridgeCallError("bridge_transport", `${op} answered ${stated} bytes, over ${BRIDGE_RESPONSE_MAX_BYTES}`, response.status);
      }
      // The deadline covers the body too: a bridge that sends headers and then stalls must not hold
      // the request path (the relay scheduler's client has the same rule). The body is read with a
      // bound and cancelled past it, as the bridge reads a request (bridge-5).
      const reading = readBoundedBody(op, response, BRIDGE_RESPONSE_MAX_BYTES);
      // The deadline may win; a late rejection of the read is expected and already handled by the throw.
      reading.catch(() => undefined);
      const bytes = await Promise.race([reading, deadline]);
      // A well-formed answer or a throw: `parseBridgeResponse` covers the schema half of the table.
      return parseBridgeResponse(op, bytes);
    } catch (error) {
      if (error instanceof BridgeCallError) throw error;
      // A 2xx answer that is not the op's document is a wire fault, not a transport one: this class
      // is "transport or timeout, never a schema problem" (above). Keeping the `BridgeWireError`
      // lets a caller name it correctly (the scheduler transport's VBF-4 mapping is
      // `scheduler_bad_response`, not `scheduler_transport`).
      if (error instanceof BridgeWireError) throw error;
      throw new BridgeCallError("bridge_transport", `${op} failed in transport: ${error instanceof Error ? error.name : "error"}`);
    } finally {
      outer?.removeEventListener("abort", onAbort);
      if (timer !== null) clearTimeout(timer);
    }
  }
}

/**
 * Read a 2xx body with a running bound, cancelling the stream once it is past `max` (bridge-5). The
 * bridge's own `readBody` uses the same shape for a request; here it keeps a runaway snapshot
 * answer from being buffered before `parseBridgeResponse` refuses its size.
 */
async function readBoundedBody(op: BridgeOp, response: Response, max: number): Promise<Uint8Array> {
  const body = response.body;
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > max) {
        await reader.cancel().catch(() => undefined);
        throw new BridgeCallError("bridge_transport", `${op} answered over ${max} bytes`, response.status);
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
