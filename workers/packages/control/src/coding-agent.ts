import type { Protocol } from "@gray/protocol";
import { PROTOCOLS } from "@gray/protocol";

/**
 * What the coding-agent check (@gray/verifier coding-agent.ts) found for each mapping binding: whether it
 * serves a request shaped like a coding agent's own, from Gray's check or from customers' requests of exactly
 * that shape. The port of crates/gray-control/src/coding_agent.rs (the record, its table's rules) and of the
 * pure rules of crates/gray-gateway/src/coding_agent.rs that read records (`kept`, `current`, `findings`,
 * `due` ...).
 *
 * One row per binding (endpoint, credential generation, configuration fingerprint, model, protocol), shape and
 * the thinking the result's request carried, each another request (workers/db/migrations/0023). It is never a
 * route verdict: routing, admission and the evidence schedule's route plan never read it. The snapshot reads it
 * for OpenCode's default model, the schedule for when to send the check again, the provider setup status to say
 * what the API said. The upstream's words in it were cleaned before they got here.
 */

/** The shape this release checks: OpenCode's version (`gray_verifier::coding_agent::SHAPE`). A result is kept per shape. */
export const CODING_AGENT_SHAPE = "opencode-2.0.27";

/** What came of one coding-agent check or customer request (`CodingAgentOutcome`). */
export const CODING_AGENT_OUTCOMES = ["passed", "refused", "failed", "inconclusive"] as const;
export type CodingAgentOutcome = (typeof CODING_AGENT_OUTCOMES)[number];

/** Where a result came from (`CodingAgentSource`): Gray's own check, or a customer's request of exactly its shape. */
export const CODING_AGENT_SOURCES = ["check", "traffic"] as const;
export type CodingAgentSource = (typeof CODING_AGENT_SOURCES)[number];

/**
 * What OpenCode 2.0.27 asks a model to think in its agent turn, as a kept result names it
 * (`OpencodeThinking::label`): `disabled` (`thinking: {"type":"disabled"}`, Gray's configuration for a model
 * whose routes proved no reasoning), `adaptive` (with `block_binding` and the binding beta), `none` (no
 * `thinking`; every API but Anthropic Messages).
 */
export const OPENCODE_THINKINGS = ["disabled", "adaptive", "none"] as const;
export type OpencodeThinking = (typeof OPENCODE_THINKINGS)[number];

/** One result of a binding, shape and thinking (`CodingAgentRecord`). Times are Unix milliseconds; costs micro-USD. */
export interface CodingAgentRecord {
  readonly endpoint_id: string;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
  /** The Gray model ID of the mapping. */
  readonly model: string;
  readonly protocol: Protocol;
  readonly shape: string;
  /** Part of the result's key: each thinking is another request, with a result of its own. */
  readonly thinking: OpencodeThinking;
  readonly outcome: CodingAgentOutcome;
  /** The check's outcome code (@gray/verifier `OutcomeCode`), or the gateway's word for a result no code names. */
  readonly code: string;
  readonly upstream_status: number | null;
  /** What the API said, cleaned. */
  readonly upstream_message: string | null;
  readonly source: CodingAgentSource;
  /** The evidence id of the signed report that carried the check. */
  readonly verification_id: string | null;
  /**
   * What the check of the kept result was counted at against the daily check budget: the kept result's cost,
   * not the latest try's. A result that replaced it without a cost of its own keeps the one before. What the
   * provider setup status estimates the next check at, unless the latest try is newer and cost something.
   */
  readonly cost_microusd: number | null;
  /** When this result was found. */
  readonly checked_ms: number;
  /** When the check was last tried, whatever came of it. */
  readonly attempted_ms: number;
  /**
   * What that latest try was counted at: 0 when it was not sent or cost nothing, null when it was sent and what
   * it cost was not read (it may have cost a request). 0 for a result from customer traffic.
   */
  readonly attempt_cost_microusd: number | null;
}

/** The binding a record is of: an endpoint's id, credential generation and configuration fingerprint. */
export interface Binding {
  readonly id: string;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
}

/** A mapping's model and protocol, as `ModelMapping` carries them. */
export interface MappingOf {
  readonly requested_model: string;
  readonly protocol: Protocol;
}

/** `CodingAgentRecord::binds`: whether the record is of `endpoint`'s current binding of `model` over `protocol`. */
export function binds(record: CodingAgentRecord, endpoint: Binding, model: string, protocol: Protocol): boolean {
  return (
    record.endpoint_id === endpoint.id &&
    record.credential_generation === endpoint.credential_generation &&
    record.config_fingerprint === endpoint.config_fingerprint &&
    record.model === model &&
    record.protocol === protocol
  );
}

/**
 * `kept`: the results of `mapping`'s current binding on `endpoint` for this release's shape among `records`,
 * one per thinking.
 */
export function kept(records: readonly CodingAgentRecord[], endpoint: Binding, mapping: MappingOf): CodingAgentRecord[] {
  return records.filter((r) => r.shape === CODING_AGENT_SHAPE && binds(r, endpoint, mapping.requested_model, mapping.protocol));
}

/** `latest`: the one found or tried last; of equals the last, as Rust's `max_by_key` keeps it. */
export function latest(results: readonly CodingAgentRecord[]): CodingAgentRecord | null {
  let best: CodingAgentRecord | null = null;
  for (const r of results) {
    // max_by_key returns the last element among equal maxima.
    if (best === null || Math.max(r.checked_ms, r.attempted_ms) >= Math.max(best.checked_ms, best.attempted_ms)) best = r;
  }
  return best;
}

/** `current`: the result of `mapping`'s current binding, of whichever thinking was found or tried last. */
export function current(records: readonly CodingAgentRecord[], endpoint: Binding, mapping: MappingOf): CodingAgentRecord | null {
  return latest(kept(records, endpoint, mapping));
}

/** `current_of`: that thinking's result alone (none when it has none); the latest of any when `thinking` is not known. */
export function currentOf(records: readonly CodingAgentRecord[], endpoint: Binding, mapping: MappingOf, thinking: OpencodeThinking | null): CodingAgentRecord | null {
  const found = kept(records, endpoint, mapping);
  if (thinking === null) return latest(found);
  return found.find((r) => r.thinking === thinking) ?? null;
}

/** The key the snapshot and the catalog keep a route's findings under: endpoint, Gray model and protocol (`OfferKey`). */
export function routeKey(endpointId: string, model: string, protocol: Protocol): string {
  return `${endpointId}\u0000${model}\u0000${protocol}`;
}

/** A route as `findings` reads it: its endpoint's binding and its mapping. */
export interface BoundRoute {
  readonly endpoint: Binding;
  readonly mapping: MappingOf;
}

/**
 * `findings`: what the coding-agent checks found for each of `routes`' current bindings among `results`, each
 * thinking's result, keyed by `routeKey`; a route without a result of its binding has no entry.
 */
export function findings(results: readonly CodingAgentRecord[], routes: readonly BoundRoute[]): Map<string, CodingAgentRecord[]> {
  const out = new Map<string, CodingAgentRecord[]>();
  for (const { endpoint, mapping } of routes) {
    const found = kept(results, endpoint, mapping);
    if (found.length > 0) out.set(routeKey(endpoint.id, mapping.requested_model, mapping.protocol), found);
  }
  return out;
}

/**
 * `still_bound`: the `previous` findings still of `routes`' current bindings, what a reader keeps when it cannot
 * read the results. Kept by endpoint, model and protocol alone, the pass of a credential or configuration the
 * route no longer has would prove its new one, whose own check may have been refused.
 */
export function stillBound(previous: ReadonlyMap<string, readonly CodingAgentRecord[]>, routes: readonly BoundRoute[]): Map<string, CodingAgentRecord[]> {
  return findings([...previous.values()].flat(), routes);
}

/** The schedule `due` reads: the floor and the re-check interval, milliseconds (console verification/schedule.ts). */
export interface DueSchedule {
  readonly floor: number;
  readonly refresh: number;
}

/**
 * `paid_without_verdict`: whether the latest try of the check may have cost a request and gave no verdict that
 * was kept. A try that cost nothing (refused, a temporary account block, no answer, a 429 or 5xx, or never
 * sent) is not; a try whose cost was not read may have bought a request.
 */
export function paidWithoutVerdict(record: CodingAgentRecord): boolean {
  const unclear = record.outcome === "inconclusive" || record.attempted_ms > record.checked_ms;
  return unclear && record.attempt_cost_microusd !== 0;
}

/**
 * `due`: whether a run of a qualifying mapping sends the check now, given the results of its current binding
 * (`kept`): when it has none; otherwise once both the result of the request the check would send now and the
 * latest try allow it.
 *
 * - The result: a verdict once it is the floor less one re-check interval old, so a run within the day of the
 *   last one carries it; a refusal seen in customer traffic once it is the floor old, the hold within which a
 *   check's pass would not replace it; an inconclusive result at once.
 * - The latest try of the binding's check, with whichever thinking: one that cost a request and gave no verdict
 *   a floor less one re-check interval after it, any other a re-check interval after it.
 *
 * `thinking`: what the check would ask the model to think now; null: the latest result stands for it.
 */
export function due(results: readonly CodingAgentRecord[], schedule: DueSchedule, nowMs: number, thinking: OpencodeThinking | null): boolean {
  let tried: CodingAgentRecord | null = null;
  for (const r of results) if (tried === null || r.attempted_ms >= tried.attempted_ms) tried = r;
  if (tried === null) return true;
  const day = Math.max(0, schedule.floor - schedule.refresh);
  const result = thinking === null ? latest(results) : (results.find((r) => r.thinking === thinking) ?? null);
  const since = (at: number) => Math.max(0, nowMs - at);
  const resultAllows =
    result === null ||
    since(result.checked_ms) >= (result.outcome === "inconclusive" ? 0 : result.outcome === "refused" && result.source === "traffic" ? schedule.floor : day);
  const tryWaits = paidWithoutVerdict(tried) ? day : schedule.refresh;
  return resultAllows && since(tried.attempted_ms) >= tryWaits;
}

// The table's statements (crates/gray-control/src/coding_agent.rs `write_coding_agent`, `coding_agent_results`,
// `carry_coding_agent_results`), in PostgreSQL's numbered parameters.

/**
 * Whether the stored row is replaced by the excluded one: a newer result, conclusive or replacing an inconclusive
 * one, and not a pass within the hold ($16) of a refusal when either was seen in traffic.
 */
const REPLACES =
  "(control_coding_agent_checks.checked_ms < excluded.checked_ms " +
  "AND (excluded.outcome <> 'inconclusive' OR control_coding_agent_checks.outcome = 'inconclusive') " +
  "AND NOT (excluded.outcome = 'passed' " +
  "AND control_coding_agent_checks.outcome = 'refused' " +
  "AND (excluded.source = 'traffic' OR control_coding_agent_checks.source = 'traffic') " +
  "AND control_coding_agent_checks.checked_ms > excluded.checked_ms - $16))";

function keptColumn(column: string): string {
  // What a check was counted at stays when a result that counted nothing replaces it.
  const replaced = column === "cost_microusd" ? `COALESCE(excluded.${column}, control_coding_agent_checks.${column})` : `excluded.${column}`;
  return `${column}=CASE WHEN ${REPLACES} THEN ${replaced} ELSE control_coding_agent_checks.${column} END`;
}

/**
 * The upsert of one record (`write_coding_agent`), by these rules:
 * - a conclusive result (passed, refused, failed) replaces an older one;
 * - an inconclusive one replaces only an inconclusive one, so a timeout or a temporary account block never
 *   changes what a route was found to do; it still notes when the check was last tried;
 * - a pass does not replace a refusal found less than the hold before it when either was seen in customer
 *   traffic; a check's pass replaces a check's refusal;
 * - a result that replaces another without a cost of its own keeps what the one before was counted at;
 * - what the latest try was counted at follows `attempted_ms`.
 * Parameters: `recordParams`.
 */
export const RECORD_CODING_AGENT_SQL =
  "INSERT INTO control_coding_agent_checks(endpoint_id,generation,fingerprint,model,protocol,shape,outcome,code,upstream_status,upstream_message,source,verification_id,cost_microusd,checked_ms,attempted_ms,attempt_cost_microusd,thinking) " +
  "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$17,$18) " +
  "ON CONFLICT(endpoint_id,generation,fingerprint,model,protocol,shape,thinking) DO UPDATE SET " +
  ["outcome", "code", "upstream_status", "upstream_message", "source", "verification_id", "cost_microusd", "checked_ms"].map(keptColumn).join(", ") +
  ", attempt_cost_microusd=CASE WHEN excluded.attempted_ms >= control_coding_agent_checks.attempted_ms " +
  "THEN excluded.attempt_cost_microusd ELSE control_coding_agent_checks.attempt_cost_microusd END, " +
  "attempted_ms=GREATEST(control_coding_agent_checks.attempted_ms, excluded.attempted_ms)";

/** Results of older credential generations of the same endpoint, model, protocol and shape, of every thinking: their binding is gone. */
export const DELETE_OLDER_CODING_AGENT_SQL =
  "DELETE FROM control_coding_agent_checks WHERE endpoint_id=$1 AND model=$2 AND protocol=$3 AND shape=$4 AND generation<$5";

/** Every kept result of the endpoints `$1` (text[]), current bindings or not (`coding_agent_results`). */
export const SELECT_CODING_AGENT_SQL =
  "SELECT endpoint_id,generation,fingerprint,model,protocol,shape,thinking,outcome,code,upstream_status,upstream_message,source,verification_id,cost_microusd,checked_ms,attempted_ms,attempt_cost_microusd " +
  "FROM control_coding_agent_checks WHERE endpoint_id=ANY($1)";

/**
 * Copies the results of a model over a protocol, each thinking's, from one binding to the next of the same
 * endpoint (`carry_coding_agent_results`): $1 endpoint, $2/$3 the generation and fingerprint before, $4/$5 after,
 * $6 model, $7 protocol. Then `CARRY_DROP_CODING_AGENT_SQL` drops the older generations' rows.
 */
export const CARRY_CODING_AGENT_SQL =
  "INSERT INTO control_coding_agent_checks(endpoint_id,generation,fingerprint,model,protocol,shape,outcome,code,upstream_status,upstream_message,source,verification_id,cost_microusd,checked_ms,attempted_ms,attempt_cost_microusd,thinking) " +
  "SELECT endpoint_id,$4,$5,model,protocol,shape,outcome,code,upstream_status,upstream_message,source,verification_id,cost_microusd,checked_ms,attempted_ms,attempt_cost_microusd,thinking " +
  "FROM control_coding_agent_checks WHERE endpoint_id=$1 AND generation=$2 AND fingerprint=$3 AND model=$6 AND protocol=$7 " +
  "ON CONFLICT DO NOTHING";

/** After `CARRY_CODING_AGENT_SQL`: $1 endpoint, $2 the generation after, $3 model, $4 protocol. */
export const CARRY_DROP_CODING_AGENT_SQL = "DELETE FROM control_coding_agent_checks WHERE endpoint_id=$1 AND generation<$2 AND model=$3 AND protocol=$4";

/** The parameters of `RECORD_CODING_AGENT_SQL` for `record`, a pass held off a refusal for `refusalHoldsMs`. */
export function recordParams(record: CodingAgentRecord, refusalHoldsMs: number): unknown[] {
  return [
    record.endpoint_id,
    record.credential_generation,
    record.config_fingerprint,
    record.model,
    record.protocol,
    record.shape,
    record.outcome,
    record.code,
    record.upstream_status,
    record.upstream_message,
    record.source,
    record.verification_id,
    record.cost_microusd,
    record.checked_ms,
    record.attempted_ms,
    refusalHoldsMs,
    record.attempt_cost_microusd,
    record.thinking,
  ];
}

/** The parameters of `DELETE_OLDER_CODING_AGENT_SQL` for `record`. */
export function deleteOlderParams(record: CodingAgentRecord): unknown[] {
  return [record.endpoint_id, record.model, record.protocol, record.shape, record.credential_generation];
}

/** A query a caller's database connection runs: SQL with numbered parameters. */
export type Query = (sql: string, params: readonly unknown[]) => Promise<unknown>;

/**
 * `write_coding_agent`: keeps `records`, each for its binding, shape and thinking, by the rules of
 * `RECORD_CODING_AGENT_SQL`, inside the caller's transaction (a report's recording keeps the results its client
 * checks found in the report's own transaction). `refusalHoldsMs`: how long a refusal outranks a later pass when
 * either was seen in customer traffic (the evidence floor). Trusted server-only.
 */
export async function writeCodingAgent(query: Query, records: readonly CodingAgentRecord[], refusalHoldsMs: number): Promise<void> {
  for (const record of records) {
    await query(RECORD_CODING_AGENT_SQL, recordParams(record, refusalHoldsMs));
    await query(DELETE_OLDER_CODING_AGENT_SQL, deleteOlderParams(record));
  }
}

/** A row of `SELECT_CODING_AGENT_SQL` as a driver returns it: BIGINT columns as strings or numbers. */
export type CodingAgentRow = Readonly<Record<string, unknown>>;

function count(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = typeof v === "bigint" ? Number(v) : typeof v === "string" ? Number(v) : typeof v === "number" ? v : Number.NaN;
  return Number.isSafeInteger(n) ? n : null;
}

function oneOf<T extends string>(values: readonly T[], v: unknown): T | null {
  return typeof v === "string" && (values as readonly string[]).includes(v) ? (v as T) : null;
}

/** `OpencodeThinking::parse`: the thinking a kept result's `label` names (`OpencodeThinking::label`); null for any other text. */
export function parseOpencodeThinking(label: unknown): OpencodeThinking | null {
  return oneOf(OPENCODE_THINKINGS, label);
}

/** A stored row as a record; null for a row that no longer parses, which a reader leaves out (`coding_agent_results`). */
export function recordFromRow(r: CodingAgentRow): CodingAgentRecord | null {
  const generation = count(r["generation"]);
  const protocol = oneOf(PROTOCOLS, r["protocol"]);
  const thinking = parseOpencodeThinking(r["thinking"]);
  const outcome = oneOf(CODING_AGENT_OUTCOMES, r["outcome"]);
  const source = oneOf(CODING_AGENT_SOURCES, r["source"]);
  const checked = count(r["checked_ms"]);
  const attempted = count(r["attempted_ms"]);
  if (generation === null || generation < 0 || protocol === null || thinking === null || outcome === null || source === null || checked === null || attempted === null) return null;
  const status = count(r["upstream_status"]);
  const cost = count(r["cost_microusd"]);
  const attemptCost = count(r["attempt_cost_microusd"]);
  const text = (v: unknown) => (typeof v === "string" ? v : null);
  return {
    endpoint_id: String(r["endpoint_id"]),
    credential_generation: generation,
    config_fingerprint: String(r["fingerprint"]),
    model: String(r["model"]),
    protocol,
    shape: String(r["shape"]),
    thinking,
    outcome,
    code: String(r["code"]),
    upstream_status: status !== null && status >= 0 && status <= 0xffff ? status : null,
    upstream_message: text(r["upstream_message"]),
    source,
    verification_id: text(r["verification_id"]),
    cost_microusd: cost !== null && cost >= 0 ? cost : null,
    checked_ms: Math.max(0, checked),
    attempted_ms: Math.max(0, attempted),
    attempt_cost_microusd: attemptCost === null ? null : Math.max(0, attemptCost),
  };
}

/** `coding_agent_results`: every kept result of `endpointIds`, current bindings or not; rows that no longer parse are left out. */
export async function readCodingAgent(select: (sql: string, params: readonly unknown[]) => Promise<readonly CodingAgentRow[]>, endpointIds: readonly string[]): Promise<CodingAgentRecord[]> {
  if (endpointIds.length === 0) return [];
  const rows = await select(SELECT_CODING_AGENT_SQL, [endpointIds]);
  return rows.map(recordFromRow).filter((r): r is CodingAgentRecord => r !== null);
}
