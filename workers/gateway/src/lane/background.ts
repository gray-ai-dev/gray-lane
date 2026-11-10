import { waitUntil } from "cloudflare:workers";

/**
 * Work a request starts and does not wait for (docs/design/relay-no-always-on-host.md 13.4: Gray's copy is uploaded
 * behind the write that made it), kept alive by that request.
 *
 * workerd ends a request's I/O once its response is done and nothing it passed to `waitUntil` is pending: a fetch still
 * in flight is dropped and its promise never settles. The lane's records are process state behind promise queues (the
 * vault's, the boot box intake's, the pair copy's), so one upload dropped that way left its queue waiting for ever: on
 * 2026-11-10 an account delivery in the empty slot answered while the vault's upload was at the disk's pair read, and
 * the next boot box delivery waited on the pair copy's queue until the VM was restarted (workerd 1.20261006.1: a step
 * forgotten on a module-level queue by a request that answered leaves every later step unanswered; the same step under
 * `waitUntil` does not, also when it is queued behind another request's).
 *
 * `waitUntil` here is the one of the request whose code is running (`cloudflare:workers`), so a step joins the request
 * that queued it wherever in the queue it runs. Outside a request (a module's own scope, a test in Node) there is none,
 * and the work is returned as it is.
 */
export function keepRequestAlive<T>(work: Promise<T>): Promise<T> {
  try {
    waitUntil(
      work.then(
        () => undefined,
        () => undefined,
      ),
    );
  } catch {
    // No request is running this code.
  }
  return work;
}

/** How a record's writer keeps work it does not wait for (`keepRequestAlive` in the lane; the identity in a test). */
export type Background = <T>(work: Promise<T>) => Promise<T>;
