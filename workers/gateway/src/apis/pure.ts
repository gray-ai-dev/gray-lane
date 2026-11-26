/**
 * The model API run's pure helpers (`ModelApiRun`, apis.ts): the retry settings, a repeat's scope, the routing contract,
 * a digest, a permit's key and a bounded read of an error body.
 */
import type { PermitToken } from "@gray/endpoint";
import { ERROR_BODY_LIMIT, scopeOf, type RetryConfig, type Scope } from "@gray/errors";
import type { CanonicalRequest, Protocol } from "@gray/protocol";
import type { GatewayDeps } from "../inference/types.ts";
import type { RouteRecord } from "../snapshot.ts";

/** The retry settings (@gray/config RETRY_*), as @gray/errors reads them (inference.ts `retryConfig`). */
export function retryConfig(cfg: GatewayDeps["cfg"]): RetryConfig {
  return {
    maxAttempts: cfg.retryMaxAttempts,
    sameOperator: cfg.retrySameOperator,
    secondOpinion: cfg.retrySecondOpinion,
    backoffMs: cfg.retryBackoffMs,
    backoffMaxMs: cfg.retryBackoffMaxMs,
    retryAfterMaxMs: cfg.retryAfterMaxSeconds * 1000,
    budgetTokens: cfg.retryBudgetTokens,
    transientCost: cfg.retryTransientCost,
    throttledCost: cfg.retryThrottledCost,
    concurrencyPercent: cfg.retryConcurrencyPercent,
    concurrencyMin: cfg.retryConcurrencyMin,
  };
}

/**
 * What a repeat of a model API request could do to the supplier (apis/mod.rs `scope`): an image, audio or
 * video generation may already have been paid for (`no_work_proven`); embeddings, rerank and System One
 * follow the text rules (`generation`).
 */
export function apiScope(protocol: Protocol): Scope {
  return scopeOf(protocol, null);
}

export const encoder = new TextEncoder();

export function hexDigest(bytes: Uint8Array): Promise<string> {
  return crypto.subtle.digest("SHA-256", bytes).then((d) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""));
}

/** The routing contract a model API request is resolved with (apis/mod.rs `contract`): no messages, tools or limits. */
export function contract(model: string, protocol: Protocol): CanonicalRequest {
  return {
    model,
    model_alias: null,
    messages: [],
    tools: [],
    hasHostedTools: false,
    tool_choice: null,
    response_format: null,
    reasoning: null,
    stream: false,
    max_output_tokens: null,
    cache_hints: null,
    protocol,
    raw_body: null,
  } as unknown as CanonicalRequest;
}

/** The endpoint states streaming support (apis/mod.rs `streams`). */
export function streams(record: RouteRecord): boolean {
  return record.claims.includes("streaming") || record.claims.includes("stream");
}

/** An error body, read within ERROR_BODY_LIMIT bytes and until `until` (`upstream_errors::read`). */
export async function errorBody(response: Response, until: number, clock: () => number): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < ERROR_BODY_LIMIT) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const next = await Promise.race([reader.read(), new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), Math.max(0, until - clock()))))]);
      clearTimeout(timer);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      length += next.value.length;
    }
  } catch {
    // What arrived is what the rules read.
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(length, ERROR_BODY_LIMIT));
  let at = 0;
  for (const c of chunks) {
    const n = Math.min(c.length, out.length - at);
    out.set(c.subarray(0, n), at);
    at += n;
    if (at >= out.length) break;
  }
  return out;
}

/** The permit key of a deferred release. */
export function permitKey(permit: PermitToken): string {
  // With the storage that issued it: a shard whose storage started over numbers its permits from 1 again (PermitToken).
  return `${permit.shard}/${permit.incarnation ?? ""}/${permit.epoch}/${permit.id}`;
}
