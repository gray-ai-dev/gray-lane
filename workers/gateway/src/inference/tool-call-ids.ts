/**
 * The request's tool-call id handles (`InferenceRun`, inference.ts; tool-ids.ts): their resolution before any route is
 * chosen, what they hold in memory, the routes of their issuer, an attempt's record of them, and the answer's rows.
 */
import { ApiError } from "@gray/errors";
import type { Body } from "../body.ts";
import type { ParsedRequest } from "../parse.ts";
import type { SettleOutcome } from "../relay.ts";
import type { Route } from "../routes.ts";
import type { ToolCallIds } from "../sinks.ts";
import type { GatewaySnapshot, KeyRecord } from "../snapshot.ts";
import { RequestToolIds, TOOL_ID_CODES, toolIdIsolate } from "../tool-ids.ts";
import { capacityError } from "./errors.ts";
import { type RequestBodyRun, spoolRead } from "./request-body.ts";
import type { Attempt } from "./types.ts";

/** What tool-call-ids.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface ToolCallIdsRun extends RequestBodyRun {}

/**
 * The request's tool-call id handles (tool-ids.ts `RequestToolIds.resolve`), before any route is
 * chosen: a body that cannot spell a handle is not walked and asks nothing; a lookup with no answer
 * is 503 tool_call_id_lookup_unavailable, before anything is sent. What the handles open is held, in
 * the request's count and the isolate's pool, until the request ends.
 */
export async function resolveToolIds(run: ToolCallIdsRun, snapshot: GatewaySnapshot, key: KeyRecord, parsed: ParsedRequest, body: Body, mayHold: boolean): Promise<ApiError | null> {
  const locate = run.io.toolCallIds;
  if (locate === null) return null;
  const isolate = run.deps.toolIds ?? toolIdIsolate;
  const keys = await isolate.keys(snapshot, await run.deps.master());
  const workspace = key.workspaceId;
  const requestId = run.requestId;
  run.facts.toolIds = new RequestToolIds({
    isolate,
    locate,
    cfg: run.deps.cfg,
    keys,
    workspace,
    requestId,
    arrivalMs: run.started,
    region: run.deps.region,
    client: run.protocol,
    clock: run.deps.clock,
    ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers }),
    budget: run.budget,
    // `tool_call_id_integrity`: why a stored handle was not used; never a value.
    alert: (reason) => console.error(JSON.stringify({ level: "error", event: "tool_call_id_integrity", reason, workspace_id: workspace, request_id: requestId })),
    hold: (bytes) => holdIdBytes(run, bytes) === null,
    room: () => run.answerShare.idsRoom(run.deps.cfg.answerHeldMaxBytes),
  });
  const refused = await run.facts.toolIds.resolve({ protocol: run.protocol, parsed, body, mayHold, content: run.io.content, readStored: (read) => spoolRead(run, read) });
  if (refused !== null) return refused;
  return holdToolIds(run);
}

/**
 * Holds what the request's tool-call ids hold now (`Resolution::held_bytes`, and an answer's handles
 * until their rows are stored), in the request's count and the isolate's AnswerPool: a 429
 * gateway_capacity (Gray's limit) when the pool cannot take it. Released with the record.
 */
export function holdToolIds(run: ToolCallIdsRun): ApiError | null {
  return holdIdBytes(run, run.facts.toolIds?.heldBytes ?? 0);
}

/** `holdToolIds` of `bytes`: what the ids hold, or will once the rows being resolved are opened. */
export function holdIdBytes(run: ToolCallIdsRun, bytes: number): ApiError | null {
  run.retained.set("tool_ids", bytes);
  if (run.answerShare.holdIds(bytes, run.deps.cfg.answerHeldMaxBytes)) return null;
  return capacityError();
}

/**
 * The routes of the issuer of the conversation's latest tool call with a handle (`preferred_issuer`); null when
 * the request holds no such handle. Retries go to the issuer's routes first whatever their reliability
 * (inference.rs `let issued`); only one that holds the reliability a pin needs takes the head (plan-order.ts
 * `steering`, `issuer_target`).
 */
export async function issuerRoutes(run: ToolCallIdsRun, routes: readonly Route[]): Promise<ReadonlySet<string> | null> {
  const ids = run.facts.toolIds;
  const preferred = ids?.preferredIssuer ?? null;
  const keys = ids?.keys ?? null;
  if (preferred === null || keys === null) return null;
  const issued = new Set<string>();
  const master = await run.deps.master();
  if (master === null) return issued;
  const isolate = run.deps.toolIds ?? toolIdIsolate;
  for (const route of routes) if ((await isolate.issuer(keys, route.record, master)) === preferred) issued.add(route.record.endpointId);
  return issued;
}

/** What `attempt` did with tool-call ids (record.rs `ToolCallIds`): the request's record of its current attempt. */
export function attemptIds(run: ToolCallIdsRun, attempt: Attempt): ToolCallIds | null {
  return attempt.toolCallIds ?? run.facts.toolIds?.record() ?? null;
}

/** Stores the answer's tool-call id rows (tool-ids.ts `store`); null when stored or none, else the failure (Gray's, not the route's). */
export async function storeToolIds(run: ToolCallIdsRun): Promise<SettleOutcome | null> {
  const ids = run.facts.toolIds;
  if (ids === null) return null;
  const written = await ids.store();
  holdToolIds(run);
  if (written.ok) return null;
  console.error(JSON.stringify({ level: "error", event: "tool_call_id_store_unavailable", request_id: run.requestId, why: written.why }));
  return { ok: false, code: TOOL_ID_CODES.storeUnavailable, reason: TOOL_ID_CODES.storeUnavailable, why: written.why, blameless: true };
}
