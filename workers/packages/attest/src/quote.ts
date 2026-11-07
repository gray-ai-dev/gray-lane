import { get, isObject, parsePlain, toJsonString, type Json } from "@gray/json";
import { bytesToLowerHex, lowerHexBytes } from "./digest.ts";
import { reportDataSlot } from "./identity.ts";

/**
 * The quote seam (§3.2, §4.2).
 *
 * A `Quoter` turns the 64-byte report-data slot into the dstack guest agent's v1 `Attest` answer: a
 * `VersionedAttestation` in dstack's MessagePack V1 form. It is not a bare TDX quote: the quote and
 * the event log are inside the attestation. DCAP verification and extraction are out of scope; this
 * package produces and carries the bytes, a verifier appraises them (PAG's `Quoter`/`Quote`,
 * `src/aci/keys.rs:70-82`, `src/dstack.rs:264-312`).
 *
 * Wire facts, dstack v0.6.1:
 *
 * - `POST /v1/Attest` on the internal `DstackGuest` mount, with `Content-Type: application/json`.
 * - request `{"report_data":"<lowercase hex>"}`. `AttestRequest.report_data` is a proto `bytes`
 *   field, and prpc's JSON codec writes every `bytes` field as lowercase hex (and accepts an
 *   optional `0x` prefix on input). The body is parsed with `serde_json`; protobuf is used only
 *   when the content type is not JSON.
 * - response `{"attestation":"<lowercase hex>","boottime_gpu_evidence":[...]}`. `attestation` is
 *   the MessagePack V1 `VersionedAttestation`, not the legacy SCALE form and not a raw quote.
 *
 * What the seam does **not** check (VERIFY.md A-4, kept deliberately):
 *
 * - **No top-level `report_data` echo.** Unlike v0 `GetQuote` (`src/dstack.rs:276-282` in PAG,
 *   which compares the returned `report_data` field with the one it asked for), v1's HTTP envelope
 *   has no separate `report_data` member. The attestation blob itself does carry the 64-byte echo
 *   at `stack.data.report_data`; this client returns the blob untouched, so the host or verifier
 *   must parse the MessagePack and check that field. The blob must be appraised where it is parsed:
 *   the dstack attestation carries the TDX quote and the event log, and the verifier policy must
 *   check that the quote's `report_data` is the slot requested here and that the RTMR replay ends
 *   in the quote's measurements. This package does neither (DCAP and RTMR replay are out of scope,
 *   see `IMPLEMENTATION_NOTES.md` §4), so a caller must not treat the returned bytes as
 *   self-authenticating.
 * - **A TCP/HTTP address is a deployment requirement.** The internal listener is the Unix socket
 *   `/var/run/dstack.sock` (the systemd socket is `/run/dstack.sock`; the agent's own configured
 *   fallback is `/var/run/dstack/dstack.sock`), which `fetch` cannot reach. The external listener
 *   on `0.0.0.0:8090` is the `Worker` service (`/prpc/v1`: `Info`, `Version`, `Health`) and does
 *   not serve `DstackGuest.Attest`. This client has **no default** and refuses anything that is
 *   not an `http(s)` URL: a deployment inside the CVM supplies a `fetch` that speaks to the Unix
 *   socket, or runs a local TCP bridge. A missing or empty base URL is a configuration error,
 *   never a silent fallback to a socket that cannot work.
 */

export interface Quoter {
  /**
   * A fresh dstack v1 attestation binding the 32-byte `report_data` in the 64-byte slot (§3.2), as
   * the MessagePack V1 `VersionedAttestation` bytes `/v1/Attest` returns.
   */
  quote(reportData: Uint8Array): Promise<Uint8Array>;
}

/** A quoter that hands back fixed bytes and remembers what it was asked to bind. */
export interface RecordingQuoter extends Quoter {
  /** Every `reportData` passed to `quote`, in order (the slot is `reportDataSlot`). */
  readonly calls: readonly Uint8Array[];
}

export function fakeQuoter(quoteBytes: Uint8Array): RecordingQuoter {
  const calls: Uint8Array[] = [];
  return {
    calls,
    async quote(reportData: Uint8Array): Promise<Uint8Array> {
      calls.push(reportData.slice());
      return quoteBytes.slice();
    },
  };
}

/** Where the dstack guest agent is reached (its TCP address, or whatever `fetch` can reach). */
export interface DstackGuestAgentQuoterOptions {
  /**
   * Required base URL of the agent's HTTP mount, e.g. `http://127.0.0.1:8091` (a deployment-provided
   * bridge or injected Unix-socket `fetch`). dstack's external listener on 8090 serves `/prpc/v1`,
   * not `/v1/Attest`. There is no default: the agent's Unix socket is not reachable through the
   * global `fetch`, so the deployment must configure an address for it, and an absent or empty value
   * is an error rather than a silent fallback.
   */
  readonly baseUrl: string;
  /** The `fetch` to use; defaults to the global one. Injected in tests, which never reach the network. */
  readonly fetch?: typeof fetch;
  /** Fail the call after this many milliseconds. */
  readonly timeoutMs?: number;
}

/** The internal `DstackGuest` v1 attestation method (the guest RPC surface). */
export const DSTACK_ATTEST_PATH = "/v1/Attest";

/**
 * A `Quoter` that asks the dstack guest agent for an attestation.
 *
 * The agent serves `POST /v1/Attest` with `{"report_data": "<hex>"}` and answers
 * `{"attestation": "<hex>", "boottime_gpu_evidence": [...]}`. `AttestRequest.report_data` is a
 * proto `bytes` field, and prpc's JSON codec encodes `bytes` as lowercase hex
 * (`prpc/src/serde_helpers.rs`), so `bytesToLowerHex` is the exact wire encoding. The body is
 * parsed by `serde_json` (`prpc-build`'s generated `dispatch_json_request`); protobuf is used only
 * when the request's content type is not JSON.
 *
 * PAG reaches the same hardware through the v0 `GetQuote` method of `dstack-sdk` 0.1.2
 * (`src/dstack.rs:267-299`), called from `Quoter::get_quote` at `:302-312`, and checks the echoed
 * `report_data` field. The v1 HTTP envelope has no such field; the attestation blob carries
 * `stack.data.report_data`, and appraising that is the verifier's job.
 *
 * The agent accepts at most 64 bytes and zero-pads shorter input, so a 32-byte ACI `report_data` is
 * padded to the §3.2 slot here rather than relying on the agent's padding; 64 bytes are sent as
 * they are. `/v1/Attest` always returns the MessagePack V1 map; a first byte outside MessagePack's
 * map prefixes means the caller reached v0 `/Attest` (legacy SCALE) or a raw quote endpoint, and is
 * refused rather than returned as evidence.
 */
export function dstackGuestAgentQuoter(options: DstackGuestAgentQuoterOptions): Quoter {
  const base = options.baseUrl.replace(/\/+$/, "");
  if (!/^https?:\/\//.test(base)) {
    throw new Error(`dstack guest agent baseUrl must be an http(s) URL, got ${options.baseUrl}`);
  }
  const doFetch = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  const url = `${base}${DSTACK_ATTEST_PATH}`;
  return {
    async quote(reportData: Uint8Array): Promise<Uint8Array> {
      const slot = reportData.length === 32 ? reportDataSlot(reportData) : reportData;
      if (slot.length !== 64) throw new Error("report_data is 32 bytes, or the 64-byte slot (§3.2)");
      const body = toJsonString({ report_data: bytesToLowerHex(slot) });
      const signal = options.timeoutMs === undefined ? undefined : AbortSignal.timeout(options.timeoutMs);
      let response: Response;
      try {
        response = await doFetch(url, { method: "POST", headers: { "content-type": "application/json" }, body, signal });
      } catch (error) {
        throw new Error(`dstack guest agent did not answer at ${url}: ${messageOf(error)}`);
      }
      const text = await response.text();
      if (!response.ok) {
        throw new Error(`dstack guest agent answered ${response.status} at ${url}: ${text.slice(0, 200)}`);
      }
      const attestation = memberOf(parseAnswer(text), "attestation");
      if (typeof attestation !== "string") throw new Error(`dstack guest agent answered without a usable attestation: ${text.slice(0, 200)}`);
      const bytes = lowerHexBytes(attestation);
      if (bytes === null || bytes.length === 0) throw new Error(`dstack guest agent answered without a usable attestation: ${text.slice(0, 200)}`);
      const first = bytes[0];
      if (first === undefined || !isMessagePackMap(first)) {
        const got = first === undefined ? "none" : `0x${first.toString(16).padStart(2, "0")}`;
        throw new Error(
          `dstack guest agent answered with a non-MessagePack attestation (first byte ${got}); /v1/Attest returns the MessagePack V1 form, not the legacy SCALE form or a raw quote: ${text.slice(0, 200)}`,
        );
      }
      return bytes;
    },
  };
}

function memberOf(value: unknown, key: string): Json | undefined {
  const json = value as Json;
  return isObject(json) ? get(json, key) : undefined;
}

/** The agent's answer as a value; a text that is not JSON names the same failure as a missing field. */
function parseAnswer(text: string): unknown {
  try {
    return parsePlain(text);
  } catch {
    return null;
  }
}

/** MessagePack's three map prefixes: fixmap 0x80..0x8f, map16 0xde, map32 0xdf. */
function isMessagePackMap(first: number): boolean {
  return (first >= 0x80 && first <= 0x8f) || first === 0xde || first === 0xdf;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
