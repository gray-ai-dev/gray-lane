/**
 * The request's body once it is read (`InferenceRun`, inference.ts): its release once an upstream answered, a spooled
 * body read back, the prompt units of the body the upstream executes, and the deadline the body's end sets.
 */
import { ApiError } from "@gray/errors";
import type { Json } from "@gray/json";
import { type CanonicalRequest, type Protocol, PromptUnits } from "@gray/protocol";
import { type Body, spoolReadBack } from "../body.ts";
import type { ContentBucket } from "../outbound.ts";
import type { ParsedRequest } from "../parse.ts";
import { spoolPlaintext } from "../spool.ts";
import type { RunCore } from "./state.ts";

/** What request-body.ts needs of the run: its state alone. */
export interface RequestBodyRun extends RunCore {}

/**
 * The held request body is no longer needed once an upstream answered (no attempt follows): the
 * gateway lets go of it rather than keep it for the length of the answer (docs/cloudflare-native.md
 * section 3). The content writer copies out what it has not sealed yet, if its budget has room, or
 * ends the request part there (content.md 3.1 step 3); either way it keeps no reference to the body.
 */
export function releaseRequestBody(run: RequestBodyRun): void {
  run.facts.content?.releaseRequest();
  run.facts.requestBody = null;
  run.retained.set("request_body", 0);
}

/**
 * A tier C body's plaintext from its start, decrypted as it is read (spool.ts), through `bucket`: the
 * request's (its reads wait for a connection in `Outbound.run`), or the unwrapped binding for a read made
 * under a connection the attempt already holds (`attemptBody`: `Outbound.hold`), which must not wait in
 * the queue a second time behind the calls the hold was taken to get past.
 */
export function spoolOpener(run: RequestBodyRun, body: Body & { readonly tier: "C" }, bucket: Pick<ContentBucket, "get"> = run.io.content): () => Promise<ReadableStream<Uint8Array> | null> {
  const spool = { key: body.key, length: body.length, identity: body.identity };
  return () => spoolPlaintext(bucket, spool);
}

/** The prompt's units of the body the upstream executes (`PromptUnits::of_model`); null when that body does not bound its input. */
export function upstreamPromptUnits(run: RequestBodyRun, parsed: ParsedRequest, canonical: CanonicalRequest): PromptUnits | null {
  const t = run.facts.translation;
  if (t !== null) return promptUnits(t.upstream, t.body, canonical.model);
  return parsed.whole ? promptUnits(run.protocol, parsed.value, canonical.model) : null;
}

/** The request's deadline: the end of its body plus the stream or the buffered total (`Plan::deadline`). */
export function requestDeadline(run: RequestBodyRun, bodyRead: number): number {
  const { cfg } = run.deps;
  return bodyRead + (run.facts.stream ? cfg.streamTotalSeconds * 1000 : cfg.nonStreamTotalMs);
}

/** A tier C body read back from its spool before the first upstream byte (body.ts `spoolReadBack`). */
export function spoolRead<T>(run: RequestBodyRun, read: () => Promise<T>): Promise<T | ApiError> {
  return spoolReadBack(read, { budget: run.budget, deadline: run.facts.bodyDeadline, clock: run.deps.clock, ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers }) });
}

/** The prompt's units of a whole body (`PromptUnits::of_model`); null when its body does not bound its input. */
export function promptUnits(protocol: Protocol, value: Json, model: string): PromptUnits | null {
  try {
    return PromptUnits.ofModel(protocol, value, model);
  } catch {
    return null;
  }
}
