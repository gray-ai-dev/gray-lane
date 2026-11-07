/**
 * What a Durable Object call's error says about the object (docs/request-path-availability.md section 1.2, P3, P7, P8): the
 * request path's callers decide by it where their next try goes (M4).
 */

/**
 * The object was reset, in the platform's own words: a deploy reached it ("Durable Object reset because its code was
 * updated.", https://developers.cloudflare.com/durable-objects/observability/troubleshooting/) or its storage failed
 * ("Internal error in Durable Object storage caused object to be reset.", staging 2026-10-29 05:24:13Z). It restarts at
 * once with its storage, so the next try may go to the same object, once, on a new stub (P7). Any other failure (a lost
 * connection, an overloaded object, no answer) may leave it stalled or alive with the call taken.
 */
export function durableObjectReset(error: unknown): boolean {
  const message = error instanceof Error ? error.message : "";
  return message.startsWith("Durable Object reset because its code was updated") || message.startsWith("Internal error in Durable Object storage caused object to be reset");
}

/**
 * The object is overloaded: "Errors with the property .overloaded set to True should not be retried" there
 * (https://developers.cloudflare.com/durable-objects/best-practices/error-handling/). The next try goes to another object.
 */
export function durableObjectOverloaded(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { overloaded?: unknown }).overloaded === true;
}
