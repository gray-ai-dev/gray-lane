import { parsePlain } from "@gray/json";

/**
 * What Gray knows about a model besides its routes (crates/gray-gateway/src/model_metadata.rs
 * `ModelFacts`, the fields the model listings publish: `GET /v1/models`, the agent setup texts). Two
 * sources, in this order: the model's metadata record (`model_records`, crates/gray-gateway/src/
 * model_records.rs), which the first provider of a model the reference catalog does not know proposes
 * and operators correct; then the reference catalog (frontend/src/catalog/openrouter-models.json), which
 * the server embeds in its binary and gray-jobs bundles (workers/jobs/src/model-reference.ts).
 *
 * The server works the facts out from both at each request; here the snapshot's writer works them out at
 * each rebuild for the models its routes serve (`SnapshotContent.modelFacts`), so the gateway answers its
 * listings from the snapshot it already holds, without the 1.3 MB catalog in its own bundle.
 */
export interface ModelFacts {
  readonly name: string | null;
  /** Unix seconds. */
  readonly created: number | null;
  readonly context_length: number | null;
  readonly max_output_tokens: number | null;
  readonly input_modalities: readonly string[];
  readonly output_modalities: readonly string[];
}

/** `ModelFacts` of one model, as the snapshot carries them (by model, in byte order). */
export interface SnapshotModelFacts extends ModelFacts {
  readonly model: string;
}

/** A stored metadata record (model_records.rs `ModelMetadata`). */
export interface ModelMetadata {
  readonly name: string;
  readonly context_length: number | null;
  readonly max_output_tokens: number | null;
  readonly input_modalities: readonly string[];
  readonly output_modalities: readonly string[];
}

const METADATA_FIELDS = new Set(["name", "context_length", "max_output_tokens", "input_modalities", "output_modalities"]);

/** A u64 as serde reads one: a non-negative integer (exact as a JSON number up to 2^53). */
function u64(v: unknown): number | null | undefined {
  if (v === null || v === undefined) return null;
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : undefined;
}

function strings(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((s) => typeof s === "string") ? (v as string[]) : undefined;
}

/**
 * `ModelRecord::from_row`'s `serde_json::from_str(record)` into `ModelMetadata` (`deny_unknown_fields`,
 * `name` and both modality lists required, the token counts optional): null when the record does not
 * read that way, and the server skips such a row.
 */
export function parseModelRecord(text: string): ModelMetadata | null {
  let v: unknown;
  try {
    v = parsePlain(text);
  } catch {
    return null;
  }
  if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).some((k) => !METADATA_FIELDS.has(k))) return null;
  const contextLength = u64(o.context_length);
  const maxOutput = u64(o.max_output_tokens);
  const input = strings(o.input_modalities);
  const output = strings(o.output_modalities);
  if (typeof o.name !== "string" || contextLength === undefined || maxOutput === undefined || input === undefined || output === undefined) return null;
  return { name: o.name, context_length: contextLength, max_output_tokens: maxOutput, input_modalities: input, output_modalities: output };
}

/**
 * `model_metadata::facts`: the record's statements, completed by the reference catalog's (its window and
 * maximum output where the record states none, its release time); null when neither source knows the
 * model.
 */
export function modelFacts(reference: ModelFacts | null, record: ModelMetadata | null): ModelFacts | null {
  if (reference === null && record === null) return null;
  const base: ModelFacts = reference ?? { name: null, created: null, context_length: null, max_output_tokens: null, input_modalities: [], output_modalities: [] };
  if (record === null) return base;
  return {
    name: record.name,
    created: base.created,
    context_length: record.context_length ?? base.context_length,
    max_output_tokens: record.max_output_tokens ?? base.max_output_tokens,
    input_modalities: record.input_modalities,
    output_modalities: record.output_modalities,
  };
}

/**
 * A stored metadata record with who wrote it last (`model_records.source`: `provider` until an operator
 * corrects it, then `operator`; model_records.rs `ModelRecord`).
 */
export interface StoredModelRecord {
  readonly metadata: ModelMetadata;
  readonly source: string;
}

/**
 * What bounds one request to a model (model_metadata.rs `ModelLimits`), each null where no source states
 * it: its context window, the maximum output a request that states no limit is sent with (and held for),
 * and the longest output such a request may be sent with at most.
 */
export interface ModelLimits {
  readonly window: number | null;
  readonly maxOutput: number | null;
  readonly longestOutput: number | null;
}

/** `ModelLimits` of one model, as the snapshot carries them (by model, in byte order). */
export interface SnapshotModelLimits extends ModelLimits {
  readonly model: string;
}

/**
 * `model_metadata::limits`: the limits the reference catalog (`reference`, what it states about the model)
 * and the model's stored record state. A hold below what a request may be billed lets it through unpaid on
 * every route of the model, so only a source Gray answers for bounds a hold: the window and the longest
 * output are the largest the catalog or an operator's record states, raised by a record a provider proposed
 * but never set by one alone. The maximum output is any record's, else the catalog's: it is written into
 * the request.
 */
export function modelLimits(reference: ModelFacts | null, record: StoredModelRecord | null): ModelLimits {
  const proposed = record?.metadata ?? null;
  const corrected = record !== null && record.source === "operator" ? record.metadata : null;
  const reviewed = (catalog: number | null, recorded: (m: ModelMetadata) => number | null): number | null => {
    const stated = [catalog, corrected === null ? null : recorded(corrected)].filter((n): n is number => n !== null);
    if (stated.length === 0) return null;
    const most = Math.max(...stated);
    const raised = proposed === null ? null : recorded(proposed);
    return raised === null ? most : Math.max(raised, most);
  };
  return {
    window: reviewed(reference?.context_length ?? null, (m) => m.context_length),
    maxOutput: proposed?.max_output_tokens ?? reference?.max_output_tokens ?? null,
    longestOutput: reviewed(reference?.max_output_tokens ?? null, (m) => m.max_output_tokens),
  };
}

/** Whether no source states any of `limits`: the model is one no source states limits for. */
export function noLimits(limits: ModelLimits): boolean {
  return limits.window === null && limits.maxOutput === null && limits.longestOutput === null;
}
