import { ApiError, shapeOf, type Origins } from "@gray/errors";
import { newRequestId } from "@gray/ledger-keys";
import { API_FORWARD_HEADER, checkForwardMark, forwardMarkKeys, type ForwardMarkProblem } from "@gray/lane-wire";

/**
 * A chat request the API Worker forwarded to the entry (docs/design/one-address.md, "API to entry"). The API Worker
 * marks it with `x-gray-api-forward`, signed with the key its master key derives (@gray/lane-wire forward-mark.ts); the
 * entry checks the mark with the public half its compose measures (`LANE_API_FORWARD_PUBLIC_KEY`, `api-1:<64 hex>`).
 *
 * - No mark: the request is the client's own connection to this VM, served as before.
 * - A valid mark: the header is taken off, and the request runs with `arrival: "gray_api"`. Its receipt says so
 *   (`aci/1+gray-api`, `arrival`), and a verifiable preference is refused (`verifiableViaApi`): the client's TLS ended at
 *   Cloudflare, so nothing here can be verified end to end.
 * - Any other mark (no key configured, malformed, stale, an unknown key, a bad signature): `400 api_forward_invalid`,
 *   before anything is read or sent. A receipt therefore never says "direct" for a request that came through the API,
 *   nor "through the API" for one that did not.
 *
 * Neither code is in `@gray/errors`' catalog, which is the server's (crates/gray-gateway/src/public_errors.rs): the
 * server has no entry. Each answer carries its own sentence and no help link.
 */

export type ApiArrival =
  | { readonly kind: "direct" }
  | { readonly kind: "gray_api"; readonly request: Request }
  | { readonly kind: "refused"; readonly problem: ForwardMarkProblem | "no_key"; readonly response: Response };

/** The keys of one LANE_API_FORWARD_PUBLIC_KEY value, read once per isolate; a value that does not read accepts nothing. */
let keysRead: { readonly text: string; readonly keys: ReadonlyMap<string, Uint8Array> } | null = null;

function acceptedKeys(value: unknown): ReadonlyMap<string, Uint8Array> {
  const text = typeof value === "string" ? value : "";
  if (keysRead !== null && keysRead.text === text) return keysRead.keys;
  const read = forwardMarkKeys(text);
  // The binding's name and the reason, never its value (the compose gate checks the form before a release).
  if (!read.ok) console.error(JSON.stringify({ level: "error", event: "lane_api_forward_key_invalid", binding: "LANE_API_FORWARD_PUBLIC_KEY", problem: read.problem }));
  keysRead = { text, keys: read.ok ? read.keys : new Map() };
  return keysRead.keys;
}

/** The arrival of a generation request at `url` (`path`, its base URL taken off), as `checkForwardMark` reads its mark. */
export async function apiArrival(request: Request, keyValue: unknown, url: URL, path: string, nowMs: number, origins: Origins): Promise<ApiArrival> {
  const mark = request.headers.get(API_FORWARD_HEADER);
  if (mark === null) return { kind: "direct" };
  const keys = acceptedKeys(keyValue);
  const checked = keys.size === 0 ? ({ ok: false, problem: "no_key" } as const) : await checkForwardMark("api", mark, { keys, nowMs, target: { method: request.method, host: url.host, pathAndQuery: `${url.pathname}${url.search}` } });
  if (!checked.ok) {
    const rendered = new ApiError(400, "api_forward_invalid")
      .withMessage("The request's x-gray-api-forward header is not a valid mark of Gray's API. Send the request without it.")
      .withHelp(null)
      .noRetry()
      .render({ shape: shapeOf(path), origins, requestId: newRequestId(nowMs) });
    return { kind: "refused", problem: checked.problem, response: new Response(rendered.body, { status: rendered.status, headers: rendered.headers }) };
  }
  const headers = new Headers(request.headers);
  headers.delete(API_FORWARD_HEADER);
  return { kind: "gray_api", request: new Request(request, { headers, signal: request.signal }) };
}

/**
 * The refusal of a verifiable request that arrived through Gray's API: `verifiable_routes_at_lane`, the code the API
 * itself answers such a request with, since from the client's side the request was sent to the API's address. The
 * sentence names this entry's own origin, where the client's connection ends in the VM.
 */
export function verifiableViaApi(entryOrigin: string): ApiError {
  return new ApiError(400, "verifiable_routes_at_lane").withMessage(
    `The routing preference \`verifiable: true\` needs a connection that ends in Gray's confidential VM, and this request reached the VM through Gray's API. Send it to ${entryOrigin} directly.`,
  );
}
