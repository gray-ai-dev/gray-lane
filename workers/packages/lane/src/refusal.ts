/**
 * The one refusal shape of @gray/lane.
 *
 * Every rule in this package is a total function of its bytes: it either answers with a value or
 * with a refusal, and it never throws for anything a caller's input can contain (a body, a URL, a
 * policy module's output, a registry). A refusal is a closed string code plus a fixed sentence that
 * explains the code and never echoes the input, so a code can be compared, logged and tested, and a
 * log line cannot carry a customer's text or a relay's text.
 *
 * A refusal is not an error: the host maps every non-allow outcome of the lane to one fixed
 * response (review.md section 4.1, item 4), and the verifier treats every refusal as "the receipt
 * does not describe these bytes".
 */
export interface Refusal<Code extends string = string> {
  readonly ok: false;
  readonly code: Code;
  readonly detail: string;
}

/** What an `Ok` value of these modules carries: no `ok: false`, so `result.ok` narrows either way. */
export function refusal<Code extends string>(code: Code, detail: string): Refusal<Code> {
  return { ok: false, code, detail };
}

/**
 * A broken invariant of this package or of its caller (a splice out of order, a hash that is not a
 * hash), never something a request can cause. Thrown, so it is visible in tests and in the host's
 * error handling instead of silently producing bytes nobody can verify.
 */
export class LaneError extends Error {
  override readonly name = "LaneError";
  readonly code: string;

  constructor(code: string, detail: string) {
    super(detail);
    this.code = code;
  }
}
