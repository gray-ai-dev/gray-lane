/**
 * The model API from the console's pages (docs/two-region-launch.md section 3): the console is on the apex, the model API
 * on its own host, and the console's Media Playground calls the model API as an application would, with an API key it
 * created for the run. A browser lets such a page make the call, and read its answer, only when the API says so (the
 * Fetch standard's CORS protocol): this module says so to the console's origin alone (CONSOLE_ORIGIN), and to no other
 * page. Nothing rides on the call but the key the page sends: no cookie is allowed (no Access-Control-Allow-Credentials),
 * so another site's page cannot spend a visitor's credit through it, and the key's own limits apply as to any client.
 */

/** The methods the Media Playground calls with: a request, then the polls of a video job. */
const METHODS = "GET, POST";
/** The headers it sets beyond the CORS-safelisted ones: the key, the body's type, and the request's idempotency key. */
const HEADERS = "authorization, content-type, idempotency-key";
/** The answer headers it reads: the request's id, and when a key's limit opens again (frontend error-categories.ts). */
export const EXPOSED = "x-request-id, x-gray-key-limit-reset";
/**
 * How long a browser may keep a preflight's answer: 2 hours, Chromium's cap (a longer value is cut to it; Firefox caps at
 * 24 hours), MDN Access-Control-Max-Age, read 2026-10-19.
 */
const MAX_AGE_SECONDS = "7200";

/** The request's Origin when it is the console's, else null (no console origin configured, another site, no Origin). */
export function allowedOrigin(request: Request, consoleOrigin: string): string | null {
  if (consoleOrigin === "") return null;
  const origin = request.headers.get("origin");
  return origin !== null && origin === consoleOrigin ? origin : null;
}

/** The answer to the console's preflight (an OPTIONS with Access-Control-Request-Method), or null for any other request. */
export function preflight(request: Request, origin: string | null): Response | null {
  if (origin === null || request.method !== "OPTIONS" || request.headers.get("access-control-request-method") === null) return null;
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": METHODS,
      "access-control-allow-headers": HEADERS,
      "access-control-max-age": MAX_AGE_SECONDS,
      vary: "Origin",
    },
  });
}

/**
 * The answer, readable by the console's page: the same status and body (the body is passed on as it streams, never read
 * here), with the CORS headers added. Unchanged for any other origin.
 *
 * `exposed` is the answer headers this answer type lets the page read. The main lane keeps `EXPOSED` (its own tests pin
 * that exact value); the confidential lane passes `EXPOSED` plus the ACI names and `X-Receipt-Id`, which its client needs
 * to read the attestation's identity and to find the receipt it fetched (M9, `lane/entry.ts` `LANE_EXPOSED`).
 */
export function withCors(response: Response, origin: string | null, exposed: string = EXPOSED): Response {
  if (origin === null) return response;
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-expose-headers", exposed);
  headers.append("vary", "Origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
