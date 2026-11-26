/**
 * Request-side and response-side extraction for multi-tier pricing (`service_tier` / `speed`) and
 * per-call billable hosted tools (`web_search`, `google_search`, `code_execution`, `file_search`).
 *
 * Pure code: reads `@gray/json` values, never re-serializes client bodies,
 * and keeps counters exact as `bigint`.
 */
import { type Json, type JsonObject, asArray, asStr, asU64, get, isObject } from "@gray/json";
import type { CanonicalEvent, Protocol } from "./types.ts";

/** Accelerated service tiers that carry an explicit price table on an offer. */
export const SERVICE_TIER_NAMES = ["fast", "priority"] as const;
export type ServiceTierName = (typeof SERVICE_TIER_NAMES)[number];

/** Vendor-hosted tools billed per invocation/session beside token usage. */
export const HOSTED_TOOL_NAMES = ["web_search", "google_search", "code_execution", "file_search"] as const;
export type HostedToolName = (typeof HOSTED_TOOL_NAMES)[number];

export function isServiceTierName(v: unknown): v is ServiceTierName {
  return typeof v === "string" && (SERVICE_TIER_NAMES as readonly string[]).includes(v);
}

export function isHostedToolName(v: unknown): v is HostedToolName {
  return typeof v === "string" && (HOSTED_TOOL_NAMES as readonly string[]).includes(v);
}

export interface RequestedHostedTool {
  readonly tool: HostedToolName;
  /** Explicit per-request invocation cap (e.g. Anthropic `max_uses`); null when unbounded in request. */
  readonly maxUses: number | null;
}

export interface RequestedPricingFeatures {
  /** Requested accelerated tier (`"fast"` on Anthropic, `"priority"` on OpenAI), or null for standard. */
  readonly serviceTier: ServiceTierName | null;
  /** Distinct billable hosted tools declared by the request, in canonical `HOSTED_TOOL_NAMES` order. */
  readonly hostedTools: readonly RequestedHostedTool[];
}

export const NO_PRICING_FEATURES: RequestedPricingFeatures = {
  serviceTier: null,
  hostedTools: [],
};

/** Actual per-call billable hosted tool counts observed in an upstream answer. */
export type HostedToolCalls = Readonly<Partial<Record<HostedToolName, bigint>>>;

/** Billing metadata observed on an upstream answer (tier confirmation/downgrade + hosted tool counts). */
export interface ResponseBillingMeta {
  /**
   * Explicit service tier reported by upstream (`"fast"`, `"priority"`, `"standard"`, `"default"`, `"flex"`, etc.),
   * or null if the upstream did not report a tier field.
   */
  readonly reportedTier: string | null;
  /** Actual hosted tool call counts observed in the answer (positive counts only). */
  readonly toolCalls: HostedToolCalls;
}

/** Default conservative invocation bound reserved in holds when a requested hosted tool specifies no `max_uses`. */
export const DEFAULT_UNBOUNDED_TOOL_USES = 20n;

function positiveCap(value: Json | undefined): number | null {
  const n = asU64(value);
  if (n === undefined || n === 0n) return null;
  return n > 10_000n ? 10_000 : Number(n);
}

function recordRequestedTool(map: Map<HostedToolName, number | null>, tool: HostedToolName, cap: number | null): void {
  if (!map.has(tool)) {
    map.set(tool, cap);
    return;
  }
  const prev = map.get(tool) ?? null;
  if (prev === null || cap === null) {
    map.set(tool, null);
    return;
  }
  map.set(tool, Math.min(10_000, prev + cap));
}

/**
 * Extracts requested accelerated service tiers and per-call billable hosted tools from the client
 * request body.
 */
export function extractPricingFeatures(protocol: Protocol, body: Json): RequestedPricingFeatures {
  let serviceTier: ServiceTierName | null = null;
  const tools = new Map<HostedToolName, number | null>();

  if (protocol === "anthropic_messages") {
    if (isObject(body)) {
      const speed = asStr(get(body, "speed"))?.toLowerCase();
      if (speed === "fast") serviceTier = "fast";
      const list = asArray(get(body, "tools"));
      if (list) {
        for (const entry of list) {
          if (!isObject(entry)) continue;
          const typ = asStr(get(entry, "type"))?.toLowerCase();
          if (!typ) continue;
          if (typ === "web_search" || typ.startsWith("web_search_")) {
            recordRequestedTool(tools, "web_search", positiveCap(get(entry, "max_uses")));
          } else if (typ === "code_execution" || typ.startsWith("code_execution_")) {
            recordRequestedTool(tools, "code_execution", positiveCap(get(entry, "max_uses")));
          }
        }
      }
    }
  } else if (protocol === "open_ai_responses" || protocol === "open_ai_chat") {
    if (isObject(body)) {
      const tier = asStr(get(body, "service_tier"))?.toLowerCase();
      if (tier === "priority") serviceTier = "priority";
      if (protocol === "open_ai_chat") {
        const wsOpt = get(body, "web_search_options");
        if (wsOpt !== undefined && wsOpt !== null) {
          recordRequestedTool(tools, "web_search", 1);
        }
      }
      const list = asArray(get(body, "tools"));
      if (list) {
        for (const entry of list) {
          if (!isObject(entry)) continue;
          const typ = asStr(get(entry, "type"))?.toLowerCase();
          if (!typ) continue;
          if (typ === "web_search" || typ.startsWith("web_search_")) {
            recordRequestedTool(tools, "web_search", null);
          } else if (typ === "code_interpreter") {
            recordRequestedTool(tools, "code_execution", null);
          } else if (typ === "file_search") {
            recordRequestedTool(tools, "file_search", null);
          }
        }
      }
    }
  } else if (protocol === "gemini") {
    if (isObject(body)) {
      const list = asArray(get(body, "tools"));
      if (list) {
        for (const entry of list) {
          if (!isObject(entry)) continue;
          const has = (k: string) => {
            const v = get(entry, k);
            return v !== undefined && v !== null;
          };
          if (has("googleSearch") || has("google_search") || has("googleSearchRetrieval") || has("google_search_retrieval")) {
            recordRequestedTool(tools, "google_search", null);
          }
          if (has("codeExecution") || has("code_execution")) {
            recordRequestedTool(tools, "code_execution", null);
          }
        }
      }
    }
  }

  const hostedTools: RequestedHostedTool[] = [];
  for (const name of HOSTED_TOOL_NAMES) {
    if (tools.has(name)) hostedTools.push({ tool: name, maxUses: tools.get(name) ?? null });
  }
  return { serviceTier, hostedTools };
}

/**
 * Resolves the billed service tier given what the client requested and what the upstream response reported.
 * If the upstream explicitly downgraded (e.g. `"standard"`, `"default"`, `"flex"`), bills standard (`null`)
 * so customers are never overcharged when priority/fast capacity falls back.
 */
export function resolveAppliedServiceTier(requested: ServiceTierName | null, reportedTier: string | null): ServiceTierName | null {
  if (requested === null) return null;
  if (reportedTier === null) return requested;
  const norm = reportedTier.trim().toLowerCase();
  if (norm === "standard" || norm === "default" || norm === "flex") return null;
  if (norm === "fast" || norm === "priority") return norm === requested ? requested : null;
  return requested;
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

function addCount(counts: Map<HostedToolName, bigint>, tool: HostedToolName, delta: bigint): void {
  if (delta <= 0n) return;
  const prev = counts.get(tool) ?? 0n;
  const next = prev + delta;
  counts.set(tool, next > U64_MAX ? U64_MAX : next);
}

function mapToHostedToolCalls(counts: Map<HostedToolName, bigint>): HostedToolCalls {
  const out: Partial<Record<HostedToolName, bigint>> = {};
  for (const name of HOSTED_TOOL_NAMES) {
    const n = counts.get(name);
    if (n !== undefined && n > 0n) out[name] = n;
  }
  return out;
}

function anthropicServerToolCounts(rawUsage: Json | null, counts: Map<HostedToolName, bigint>): void {
  if (!isObject(rawUsage)) return;
  const stu = get(rawUsage, "server_tool_use");
  if (!isObject(stu)) return;
  const ws = asU64(get(stu, "web_search_requests"));
  if (ws !== undefined && ws > 0n) addCount(counts, "web_search", ws);
  const ce = asU64(get(stu, "code_execution_requests"));
  if (ce !== undefined && ce > 0n) addCount(counts, "code_execution", ce);
}

/** The hosted tool an OpenAI Responses output item type bills, if any. */
function responsesItemTool(itemType: string | undefined): HostedToolName | null {
  if (itemType === "web_search_call") return "web_search";
  if (itemType === "code_interpreter_call") return "code_execution";
  if (itemType === "file_search_call") return "file_search";
  return null;
}

/**
 * Records one OpenAI Responses output item under its id (or, without one, its type and position) with
 * the hosted tool it bills, or null when it bills none (not a hosted tool call, or `status: "failed"`).
 * A later record of the same item replaces the earlier one, so each item counts at most once and its
 * latest status decides.
 */
function recordResponsesItem(items: Map<string, HostedToolName | null>, item: Json | undefined, position: string): void {
  if (!isObject(item)) return;
  const itemType = asStr(get(item, "type"))?.toLowerCase();
  const failed = asStr(get(item, "status"))?.toLowerCase() === "failed";
  const key = asStr(get(item, "id")) ?? `${itemType ?? ""}:${position}`;
  items.set(key, failed ? null : responsesItemTool(itemType));
}

function countResponsesItems(items: Map<string, HostedToolName | null>, counts: Map<HostedToolName, bigint>): void {
  for (const tool of items.values()) if (tool !== null) addCount(counts, tool, 1n);
}

function responsesOutputToolCounts(output: Json | undefined, counts: Map<HostedToolName, bigint>): void {
  const list = asArray(output);
  if (!list) return;
  const items = new Map<string, HostedToolName | null>();
  list.forEach((item, i) => recordResponsesItem(items, item, String(i)));
  countResponsesItems(items, counts);
}

function geminiCandidateToolCounts(candidates: Json | undefined, counts: Map<HostedToolName, bigint>): void {
  const list = asArray(candidates);
  if (!list) return;
  for (const cand of list) {
    if (!isObject(cand)) continue;
    const gm = get(cand, "groundingMetadata");
    if (isObject(gm)) {
      const queries = asArray(get(gm, "webSearchQueries"));
      if (queries && queries.length > 0) addCount(counts, "google_search", 1n);
    }
    const parts = asArray(get(get(cand, "content"), "parts"));
    if (parts) {
      for (const part of parts) {
        if (!isObject(part)) continue;
        if (get(part, "executableCode") !== undefined && get(part, "executableCode") !== null) {
          addCount(counts, "code_execution", 1n);
        }
      }
    }
  }
}

/**
 * Extracts reported service tier and actual hosted tool invocations from a buffered upstream answer.
 */
export function extractBufferedBillingMeta(protocol: Protocol, body: Json, rawUsage: Json | null, requested?: RequestedPricingFeatures): ResponseBillingMeta {
  let reportedTier: string | null = null;
  const counts = new Map<HostedToolName, bigint>();

  if (protocol === "anthropic_messages") {
    const speed = asStr(get(rawUsage, "speed")) ?? asStr(get(body, "speed"));
    if (speed) reportedTier = speed;
    anthropicServerToolCounts(rawUsage, counts);
  } else if (protocol === "open_ai_responses") {
    const tier = asStr(get(body, "service_tier"));
    if (tier) reportedTier = tier;
    responsesOutputToolCounts(get(body, "output"), counts);
  } else if (protocol === "open_ai_chat") {
    const tier = asStr(get(body, "service_tier"));
    if (tier) reportedTier = tier;
    if (requested?.hostedTools.some((t) => t.tool === "web_search")) {
      const choices = asArray(get(body, "choices"));
      const hasAnnotation = choices?.some((c) => {
        const anns = asArray(get(get(c, "message"), "annotations"));
        return anns !== undefined && anns.length > 0;
      });
      if (hasAnnotation) addCount(counts, "web_search", 1n);
    }
  } else if (protocol === "gemini") {
    geminiCandidateToolCounts(get(body, "candidates"), counts);
  }

  return { reportedTier, toolCalls: mapToHostedToolCalls(counts) };
}

/**
 * Observes decoded streaming events to capture the reported service tier and actual hosted tool
 * invocations across Anthropic, OpenAI Responses, OpenAI Chat, and Gemini streams.
 */
export class StreamBillingObserver {
  private readonly protocol: Protocol;
  private readonly requested: RequestedPricingFeatures;
  private reportedTier: string | null = null;
  /**
   * Responses output items seen so far, from `response.output_item.done` and the terminal
   * `response.completed` / `response.incomplete` output, merged by item (recordResponsesItem). The
   * terminal output may be empty or partial, so it updates the items already seen and never replaces them.
   */
  private readonly responsesItems = new Map<string, HostedToolName | null>();
  private responsesUnindexedDone = 0;
  private chatSawCitation = false;
  private readonly geminiSearchCandidates = new Set<bigint>();
  private geminiCodeExecCount = 0n;

  constructor(protocol: Protocol, requested: RequestedPricingFeatures = NO_PRICING_FEATURES) {
    this.protocol = protocol;
    this.requested = requested;
  }

  observe(events: readonly CanonicalEvent[]): void {
    for (const ev of events) {
      if (ev.type !== "native") continue;
      this.observePayload(ev.payload);
    }
  }

  observePayload(payload: Json): void {
    if (!isObject(payload)) return;
    if (this.protocol === "anthropic_messages") {
      const typ = asStr(get(payload, "type"));
      if (typ === "message_start") {
        const msg = get(payload, "message");
        const speed = asStr(get(get(msg, "usage"), "speed")) ?? asStr(get(msg, "speed"));
        if (speed) this.reportedTier = speed;
      } else if (typ === "message_delta") {
        const speed = asStr(get(get(payload, "usage"), "speed")) ?? asStr(get(payload, "speed"));
        if (speed) this.reportedTier = speed;
      }
    } else if (this.protocol === "open_ai_responses") {
      const typ = asStr(get(payload, "type"));
      if (typ === "response.completed" || typ === "response.incomplete" || typ === "response.created") {
        const resp = get(payload, "response");
        const tier = asStr(get(resp, "service_tier"));
        if (tier) this.reportedTier = tier;
        if (typ === "response.completed" || typ === "response.incomplete") {
          const out = asArray(get(resp, "output"));
          out?.forEach((item, i) => recordResponsesItem(this.responsesItems, item, String(i)));
        }
      } else if (typ === "response.output_item.done") {
        const index = asU64(get(payload, "output_index"));
        recordResponsesItem(this.responsesItems, get(payload, "item"), index !== undefined ? String(index) : `done-${this.responsesUnindexedDone++}`);
      }
    } else if (this.protocol === "open_ai_chat") {
      const tier = asStr(get(payload, "service_tier"));
      if (tier) this.reportedTier = tier;
      if (!this.chatSawCitation && this.requested.hostedTools.some((t) => t.tool === "web_search")) {
        const choices = asArray(get(payload, "choices"));
        if (choices) {
          for (const c of choices) {
            const anns = asArray(get(get(c, "delta"), "annotations")) ?? asArray(get(get(c, "message"), "annotations"));
            if (anns && anns.length > 0) {
              this.chatSawCitation = true;
              break;
            }
          }
        }
      }
    } else if (this.protocol === "gemini") {
      const candidates = asArray(get(payload, "candidates"));
      if (candidates) {
        for (let i = 0; i < candidates.length; i++) {
          const cand = candidates[i];
          if (!isObject(cand)) continue;
          const candIdx = asU64(get(cand, "index")) ?? BigInt(i);
          const gm = get(cand, "groundingMetadata");
          if (isObject(gm)) {
            const queries = asArray(get(gm, "webSearchQueries"));
            if (queries && queries.length > 0) this.geminiSearchCandidates.add(candIdx);
          }
          const parts = asArray(get(get(cand, "content"), "parts"));
          if (parts) {
            for (const part of parts) {
              if (isObject(part) && get(part, "executableCode") !== undefined && get(part, "executableCode") !== null) {
                if (this.geminiCodeExecCount < U64_MAX) this.geminiCodeExecCount += 1n;
              }
            }
          }
        }
      }
    }
  }

  finish(rawUsage: Json | null = null): ResponseBillingMeta {
    const counts = new Map<HostedToolName, bigint>();
    if (this.protocol === "anthropic_messages") {
      const speed = asStr(get(rawUsage, "speed"));
      if (speed) this.reportedTier = speed;
      anthropicServerToolCounts(rawUsage, counts);
    } else if (this.protocol === "open_ai_responses") {
      countResponsesItems(this.responsesItems, counts);
    } else if (this.protocol === "open_ai_chat") {
      if (this.chatSawCitation) addCount(counts, "web_search", 1n);
    } else if (this.protocol === "gemini") {
      if (this.geminiSearchCandidates.size > 0) addCount(counts, "google_search", BigInt(this.geminiSearchCandidates.size));
      if (this.geminiCodeExecCount > 0n) addCount(counts, "code_execution", this.geminiCodeExecCount);
    }
    return { reportedTier: this.reportedTier, toolCalls: mapToHostedToolCalls(counts) };
  }
}

/**
 * Attaches sanitized `hosted_tool_calls` onto a shallow copy of `rawUsage` when non-Anthropic
 * protocols (OpenAI Responses/Chat, Gemini) incurred per-call hosted tool charges that are not
 * natively present inside the vendor's `usage` / `usageMetadata` object, so `@gray/ledger-keys`
 * can independently verify `usage.tool_calls` from `raw_usage`.
 */
export function attachHostedToolCallsToRawUsage(protocol: Protocol, rawUsage: Json, toolCalls: HostedToolCalls): Json {
  const entries = HOSTED_TOOL_NAMES.filter((k) => (toolCalls[k] ?? 0n) > 0n);
  if (entries.length === 0 || protocol === "anthropic_messages" || !isObject(rawUsage)) return rawUsage;
  const hosted: JsonObject = {};
  for (const k of entries) hosted[k] = toolCalls[k]!;
  return { ...rawUsage, hosted_tool_calls: hosted };
}
