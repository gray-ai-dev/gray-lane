/**
 * The two platform calls a timeout makes. Production passes no object: the default is the platform's
 * `setTimeout`/`clearTimeout`, so behavior is unchanged. A test can pass a timer that it controls
 * (e.g. one that never fires) when the timeout is the thing the test would otherwise race; the
 * account's slow-root test uses this to prove a slow root changes no minute's counts.
 */
export interface TimeoutTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** The platform's `setTimeout`/`clearTimeout`. */
export const PLATFORM_TIMERS: TimeoutTimers = {
  setTimeout: (handler, ms) => setTimeout(handler, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/**
 * A promise that rejects after `ms` milliseconds unless `p` settles first. The timer is cleared
 * either way, and a late rejection of `p` is not reported as unhandled.
 */
export function withTimeout<T>(p: Promise<T>, ms: number, timers: TimeoutTimers = PLATFORM_TIMERS): Promise<T> {
  let timer: unknown = null;
  p.catch(() => {});
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = timers.setTimeout(() => reject(new Error(`no answer within ${ms} ms`)), ms);
    }),
  ]).finally(() => {
    if (timer !== null) timers.clearTimeout(timer);
  });
}
