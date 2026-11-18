/**
 * A URL the lane may not send to (the origin check refused it, or an endpoint route's URL is not under its row in
 * egress's table): a programming error, never a retry. Its own module so `deps.ts` and `endpoint-routes.ts` both throw
 * it without importing each other.
 */
export class LaneFetchRefusal extends Error {
  override readonly name = "LaneFetchRefusal";
  readonly code: string;

  constructor(code: string) {
    // The code, not the URL: a refused URL may be a probe with a hostile host, and a lane log is content free.
    super(`the lane refuses this upstream URL (${code})`);
    this.code = code;
  }
}
