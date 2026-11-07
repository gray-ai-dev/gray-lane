import { PROTOCOLS, type Protocol } from "@gray/protocol";
import { z } from "zod";
import { CODING_AGENT_SHAPE, OPENCODE_THINKINGS, type CodingAgentRecord, type OpencodeThinking } from "./coding-agent.ts";

/**
 * What customer traffic shows about the mapping that served it (crates/gray-gateway/src/traffic_evidence.rs
 * `TrafficEvidence`, crates/gray-control/src/traffic_evidence.rs): the newest time of each signal per mapping
 * binding, and the coding-agent check's results from customers' requests of its shape. The gateway notes a
 * request's evidence in one of these and sends it beside the request's index row; gray-jobs merges a consumer
 * batch's into another and writes it where the console's evidence schedule reads it (`control_traffic_evidence`,
 * `control_coding_agent_checks`). The server keeps one per gateway process and writes it on every maintenance
 * tick; here nothing on the request path waits for storage either.
 */

/** `TrafficSignal`, by its stored label; ordered as the Rust enum. */
export const TRAFFIC_SIGNALS = ["answer", "streaming", "tools", "structured_output", "reasoning", "image_output", "provider_failure"] as const;
export type TrafficSignal = (typeof TRAFFIC_SIGNALS)[number];

/**
 * The mapping binding evidence is about (`Binding`): an endpoint under one credential generation and
 * configuration, and one of its mappings (the Gray model ID and the API). A rotation or an edit starts another.
 */
export interface TrafficBinding {
  readonly endpointId: string;
  readonly generation: number;
  readonly fingerprint: string;
  readonly model: string;
  readonly protocol: Protocol;
}

/** `TrafficObservation`: the latest time customer traffic showed `signal` for one binding. */
export interface TrafficObservation extends TrafficBinding {
  readonly signal: TrafficSignal;
  readonly observedMs: number;
}

/**
 * What customers' requests of the coding-agent check's shape showed of one binding with one thinking (`AgentSeen`):
 * the newest pass, and the newest refusal with what the API said.
 */
export interface AgentSeen extends TrafficBinding {
  readonly thinking: OpencodeThinking;
  readonly passedMs: number | null;
  readonly refused: { readonly atMs: number; readonly message: string | null } | null;
}

/**
 * A request's or a batch's evidence as it travels to gray-jobs: what `TrafficEvidence` holds, drained. What the
 * provider earned is not in it: it is counted when the settlement is written (docs/model-authenticity-workflow.md,
 * "Traffic-paced rounds", decided 2026-11-04; workers/db/migrations/0051).
 */
export interface TrafficEvidenceWire {
  readonly observations: readonly TrafficObservation[];
  readonly agent: readonly AgentSeen[];
}

/**
 * Distinct (binding, signal) pairs, and (binding, thinking) pairs, held between two writes (`BUFFER_LIMIT`). Past
 * this, new pairs are dropped, which only costs an active check.
 */
export const TRAFFIC_BUFFER_LIMIT = 4096;

function bindingKey(b: TrafficBinding): string {
  return JSON.stringify([b.endpointId, b.generation, b.fingerprint, b.model, b.protocol]);
}

function bindingOf(b: TrafficBinding): TrafficBinding {
  return { endpointId: b.endpointId, generation: b.generation, fingerprint: b.fingerprint, model: b.model, protocol: b.protocol };
}

/** The newest time of each signal per binding, and the coding-agent results, between two writes (`TrafficEvidence`'s buffers). */
export class TrafficEvidence {
  private readonly pending = new Map<string, { binding: TrafficBinding; signal: TrafficSignal; at: number }>();
  private readonly agentSeen = new Map<string, { binding: TrafficBinding; thinking: OpencodeThinking; passedMs: number | null; refused: { atMs: number; message: string | null } | null }>();

  /** Keeps `at` as the time of each of `signals` for `binding`, unless a newer one is kept (`note`). */
  note(binding: TrafficBinding, signals: readonly TrafficSignal[], at: number): void {
    for (const signal of signals) {
      const key = `${bindingKey(binding)}|${signal}`;
      const kept = this.pending.get(key);
      if (kept !== undefined) kept.at = Math.max(kept.at, at);
      else if (this.pending.size < TRAFFIC_BUFFER_LIMIT) this.pending.set(key, { binding: bindingOf(binding), signal, at });
    }
  }

  private seen(binding: TrafficBinding, thinking: OpencodeThinking) {
    const key = `${bindingKey(binding)}|${thinking}`;
    let seen = this.agentSeen.get(key);
    if (seen === undefined && this.agentSeen.size < TRAFFIC_BUFFER_LIMIT) {
      seen = { binding: bindingOf(binding), thinking, passedMs: null, refused: null };
      this.agentSeen.set(key, seen);
    }
    return seen;
  }

  /** A relay served OpenCode's own agent turn at `at` (`answered`'s pass of the coding-agent check). */
  agentPassed(binding: TrafficBinding, thinking: OpencodeThinking, at: number): void {
    const seen = this.seen(binding, thinking);
    if (seen !== undefined) seen.passedMs = Math.max(seen.passedMs ?? 0, at);
  }

  /** A relay refused OpenCode's own agent turn at `at`, saying `message` (`coding_agent_refused`): the newest refusal is kept. */
  agentRefused(binding: TrafficBinding, thinking: OpencodeThinking, message: string | null, at: number): void {
    const seen = this.seen(binding, thinking);
    if (seen !== undefined && (seen.refused === null || seen.refused.atMs < at)) seen.refused = { atMs: at, message };
  }

  /** Takes in what another buffer drained: a request's evidence into a batch's. */
  merge(wire: TrafficEvidenceWire): void {
    for (const o of wire.observations) this.note(o, [o.signal], o.observedMs);
    for (const a of wire.agent) {
      if (a.passedMs !== null) this.agentPassed(a, a.thinking, a.passedMs);
      if (a.refused !== null) this.agentRefused(a, a.thinking, a.refused.message, a.refused.atMs);
    }
  }

  get empty(): boolean {
    return this.pending.size === 0 && this.agentSeen.size === 0;
  }

  /** The observations held, emptying the buffer of them (`drain`). */
  drain(): TrafficObservation[] {
    const out = [...this.pending.values()].map((p) => ({ ...p.binding, signal: p.signal, observedMs: p.at }));
    this.pending.clear();
    return out;
  }

  /** The coding-agent results held, emptying the buffer of them. */
  drainAgent(): AgentSeen[] {
    const out = [...this.agentSeen.values()].map((s) => ({ ...s.binding, thinking: s.thinking, passedMs: s.passedMs, refused: s.refused }));
    this.agentSeen.clear();
    return out;
  }

  /** Everything held, as it travels; the buffer is empty after. */
  wire(): TrafficEvidenceWire {
    return { observations: this.drain(), agent: this.drainAgent() };
  }
}

/**
 * The coding-agent results `seen` stand for (`drain_agent`): a pass and a refusal of one binding and thinking each
 * as its own result, from customer traffic, oldest first so the newest of a binding is written last.
 */
export function agentRecords(seen: readonly AgentSeen[]): CodingAgentRecord[] {
  const record = (s: AgentSeen, outcome: "passed" | "refused", code: string, message: string | null, at: number): CodingAgentRecord => ({
    endpoint_id: s.endpointId,
    credential_generation: s.generation,
    config_fingerprint: s.fingerprint,
    model: s.model,
    protocol: s.protocol,
    shape: CODING_AGENT_SHAPE,
    thinking: s.thinking,
    outcome,
    code,
    upstream_status: null,
    upstream_message: message,
    source: "traffic",
    verification_id: null,
    cost_microusd: null,
    checked_ms: at,
    // Not a try of Gray's own check: its schedule is the check's.
    attempted_ms: 0,
    attempt_cost_microusd: 0,
  });
  const records: CodingAgentRecord[] = [];
  for (const s of seen) {
    if (s.passedMs !== null) records.push(record(s, "passed", "served", null, s.passedMs));
    if (s.refused !== null) records.push(record(s, "refused", "agent_request_refused", s.refused.message, s.refused.atMs));
  }
  // A stable sort: of equal times the order they were found in, as Rust's `sort_by_key`.
  return records.sort((a, b) => a.checked_ms - b.checked_ms);
}

const millis = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const binding = {
  endpointId: z.string(),
  generation: millis,
  fingerprint: z.string(),
  model: z.string(),
  protocol: z.enum(PROTOCOLS),
};
const WIRE = z.object({
  observations: z.array(z.object({ ...binding, signal: z.enum(TRAFFIC_SIGNALS), observedMs: millis }).strict()).max(TRAFFIC_BUFFER_LIMIT),
  agent: z
    .array(
      z
        .object({
          ...binding,
          thinking: z.enum(OPENCODE_THINKINGS),
          passedMs: millis.nullable(),
          refused: z.object({ atMs: millis, message: z.string().nullable() }).strict().nullable(),
        })
        .strict(),
    )
    .max(TRAFFIC_BUFFER_LIMIT),
});

/**
 * `value` as evidence that travelled; null when it is none (a message from before it, or one this build cannot read).
 * A key it does not name is left out: a message of a gateway that still sent what the provider earned (`served`, #342's
 * count, never deployed) reads as the rest.
 */
export function parseTrafficEvidence(value: unknown): TrafficEvidenceWire | null {
  const parsed = WIRE.safeParse(value);
  return parsed.success ? parsed.data : null;
}
