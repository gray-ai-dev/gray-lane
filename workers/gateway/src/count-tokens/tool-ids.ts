/** The main gateway's tool-call ids for a count (`CountTokensRun`, count-tokens.ts): restoring them and the issuer's routes. */
import { ApiError } from "@gray/errors";
import type { Json } from "@gray/json";
import type { CanonicalRequest } from "@gray/protocol";
import type { Body } from "../body.ts";
import type { ParsedRequest } from "../parse.ts";
import type { Route } from "../routes.ts";
import type { GatewaySnapshot, KeyRecord, RouteRecord } from "../snapshot.ts";
import { RequestToolIds, toolIdIsolate } from "../tool-ids.ts";
import type { CountRunCore } from "./state.ts";

export async function resolveToolIds(
  run: CountRunCore,
  snapshot: GatewaySnapshot,
  key: KeyRecord,
  counted: Json,
  canonical: CanonicalRequest,
  body: Body,
  received: Uint8Array,
): Promise<ApiError | null> {
  const locate = run.io.toolCallIds;
  if (locate === null) return null;
  const isolate = run.deps.toolIds ?? toolIdIsolate;
  const keys = await isolate.keys(snapshot, await run.deps.master());
  const workspace = key.workspaceId;
  const requestId = run.requestId;
  run.toolIds = new RequestToolIds({
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
    alert: (reason) => console.error(JSON.stringify({ level: "error", event: "tool_call_id_integrity", reason, workspace_id: workspace, request_id: requestId })),
    hold: (bytes) => run.answerShare.holdIds(bytes, run.deps.cfg.answerHeldMaxBytes),
    room: () => run.answerShare.idsRoom(run.deps.cfg.answerHeldMaxBytes),
  });
  const parsed: ParsedRequest = {
    tier: body.tier,
    value: counted,
    canonical,
    layout: null,
    body: { bytes: received, value: counted, duplicateKeys: true },
    collapsed: new Map(),
    whole: true,
    breakpoints: {},
    models: [],
    strip: false,
    scrubbed: [],
    itemReferences: [],
    opaqueProviderState: false,
  };
  const refused = await run.toolIds.resolve({
    protocol: run.protocol,
    parsed,
    body,
    mayHold: true,
    content: run.deps.env.CONTENT,
    readStored: async (read) => read(),
  });
  if (refused !== null) return refused;
  if (!run.answerShare.holdIds(run.toolIds.heldBytes, run.deps.cfg.answerHeldMaxBytes)) {
    return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
  }
  run.toolIds.prepare({
    protocol: run.protocol,
    body: { bytes: received, value: counted, duplicateKeys: true },
    layout: null,
    translated: false,
  });
  return null;
}

export async function issuerRoutes(run: CountRunCore, routes: readonly Route[]): Promise<ReadonlySet<string> | null> {
  const ids = run.toolIds;
  const preferred = ids?.preferredIssuer ?? null;
  const keys = ids?.keys ?? null;
  if (preferred === null || keys === null) return null;
  const master = await run.deps.master();
  if (master === null) return new Set();
  const isolate = run.deps.toolIds ?? toolIdIsolate;
  const issued = new Set<string>();
  for (const route of routes) {
    if ((await isolate.issuer(keys, route.record, master)) === preferred) issued.add(route.record.endpointId);
  }
  return issued;
}

export async function issuerOf(run: CountRunCore, route: RouteRecord, credential: string): Promise<string | null> {
  const ids = run.toolIds;
  if (ids === null || ids.keys === null || !ids.needsIssuer) return null;
  return (run.deps.toolIds ?? toolIdIsolate).issuerWith(ids.keys, route, credential);
}
