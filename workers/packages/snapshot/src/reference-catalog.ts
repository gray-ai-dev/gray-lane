import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { compareUtf8, parsePlain } from "@gray/json";
import { within } from "./cache.ts";

/**
 * The live reference catalog: OpenRouter's public model list, which gray-jobs fetches every
 * REFERENCE_CATALOG_SYNC_INTERVAL_MS and keeps in SNAPSHOT_KV, and which gray-jobs and gray-console read from there in
 * place of the copy they bundle (frontend/src/catalog/openrouter-models.json). The bundled copy stays the answer until
 * KV holds a valid one, and again whenever KV cannot be read: nothing here throws at a caller.
 *
 * - `normalizeReferenceSource` is scripts/update-model-catalog.py's `normalize`, `rate` and `validate`, line for line,
 *   down to the price units and the decimal text of `usdPerMillionTokens` (Python's `Decimal`, 28 digits, half even),
 *   on the fields the Workers and the frontend read (`REFERENCE_MODEL_FIELDS`).
 * - `syncReferenceCatalog` is the script's refresh: the same refusals (an incomplete page, fewer than MIN_MODELS, more
 *   than MAX_LOSS of the previous IDs gone), and nothing written when the models are as before.
 * - `createReferenceCatalogStore` is a caller's copy per isolate: the bundled catalog at once, then KV's, checked at most
 *   every REFERENCE_CATALOG_CACHE_TTL_MS by its small meta key, and the large value read only when that names another
 *   content. For a model the bundled file lists, the copy it serves keeps the bundled routing fields
 *   (`PINNED_REFERENCE_FIELDS`: window, maximum output, prices, long-context tier); KV keeps the source's values, and
 *   the sync, given the bundled models, reports each held difference (`reference_catalog_change_held`) once per live
 *   value when its caller keeps what was told (`ReferenceHeldToldStore`).
 *
 * The bundled JSON is never imported here: each caller passes its own, so gray-gateway's bundle stays without it.
 */

export const REFERENCE_CATALOG_KEY = "reference-catalog:v1";
export const REFERENCE_CATALOG_META_KEY = "reference-catalog:v1:meta";
/** How long an isolate serves its copy before it checks KV's meta key again. */
export const REFERENCE_CATALOG_CACHE_TTL_MS = 300_000;
/** After a failed KV read, the next try. */
export const REFERENCE_CATALOG_RETRY_MS = 60_000;
/** One KV read's bound. */
export const REFERENCE_CATALOG_KV_TIMEOUT_MS = 2_000;
/** The fetch's bound (the script's is 60 s; a Durable Object call should end well before the console's 45 s). */
export const REFERENCE_CATALOG_FETCH_TIMEOUT_MS = 30_000;
/** After a failed fetch, the next try of the cron. */
export const REFERENCE_CATALOG_ERROR_BACKOFF_MS = 900_000;
/** update-model-catalog.py MIN_MODELS and MAX_LOSS. */
export const REFERENCE_MIN_MODELS = 300;
export const REFERENCE_MAX_LOSS = 0.2;
export const REFERENCE_USER_AGENT = "Gray-catalog-refresh/1.0";

/** update-model-catalog.py UNITS. */
export const REFERENCE_UNITS: Readonly<Record<string, string>> = {
  prompt: "USD/input_token",
  completion: "USD/output_token",
  internal_reasoning: "USD/reasoning_token",
  input_cache_read: "USD/cached_input_token",
  input_cache_write: "USD/cache_write_token",
  input_cache_write_1h: "USD/cache_write_token_1h",
  audio: "USD/audio_input_token",
  audio_output: "USD/audio_output_token",
  input_audio_cache: "USD/cached_audio_input_token",
  image_token: "USD/image_token",
  image: "USD/input_image",
  image_output: "USD/output_image",
  request: "USD/request",
  web_search: "USD/web_search",
};
const TOKEN_FIELDS = new Set(Object.entries(REFERENCE_UNITS).filter(([, unit]) => unit.includes("token")).map(([key]) => key));

/** update-model-catalog.py `rate`'s answer. */
export interface ReferenceRate {
  readonly raw: unknown;
  readonly unit: string;
  readonly status: "priced" | "zero" | "dynamic" | "unknown";
  readonly usdPerMillionTokens: string | null;
}

/** One model as the store keeps it: the fields of the script's entry that some reader reads, in the script's order. */
export interface ReferenceModel {
  readonly id: string;
  readonly name: string;
  readonly description: string | null;
  readonly created: number | null;
  readonly context_length: number | null;
  readonly supported_parameters: readonly string[] | null;
  readonly top_provider: { readonly context_length: number | null; readonly max_completion_tokens: number | null } | null;
  readonly input_modalities: readonly string[] | null;
  readonly output_modalities: readonly string[] | null;
  readonly pricing_raw: unknown;
  readonly pricing: Readonly<Record<string, ReferenceRate>>;
  readonly has_pricing_overrides: boolean;
}

export const REFERENCE_MODEL_FIELDS = [
  "id",
  "name",
  "description",
  "created",
  "context_length",
  "supported_parameters",
  "top_provider",
  "input_modalities",
  "output_modalities",
  "pricing_raw",
  "pricing",
  "has_pricing_overrides",
] as const;

/** What `reference-catalog:v1` holds, and GET /api/v1/reference-catalog answers. */
export interface ReferenceCatalogDocument {
  readonly schemaVersion: 1;
  readonly sourceUrl: string;
  readonly fetchedAt: string;
  readonly modelCount: number;
  readonly models: readonly ReferenceModel[];
}

/** `reference-catalog:v1`'s KV metadata. */
export interface ReferenceCatalogKvMeta {
  readonly schemaVersion: 1;
  readonly fetchedAt: string;
  readonly contentSha256: string;
  readonly sourceSha256: string;
  readonly modelCount: number;
}

export type ReferenceSyncStatus = "updated" | "unchanged" | "rejected" | "error";

/** `reference-catalog:v1:meta`: the last sync's check, and what `reference-catalog:v1` holds (null before the first). */
export interface ReferenceCatalogSyncMeta {
  readonly schemaVersion: 1;
  readonly checkedAtMs: number;
  readonly fetchedAt: string | null;
  readonly contentSha256: string | null;
  readonly sourceSha256: string | null;
  readonly modelCount: number | null;
  readonly lastStatus: ReferenceSyncStatus;
  readonly lastError: string | null;
}

/** What a sync answers (ConfigDO `syncReferenceCatalog`). `disabled`: REFERENCE_CATALOG_URL is empty; `skipped`: not due. */
export interface ReferenceCatalogSyncResult {
  readonly status: ReferenceSyncStatus | "disabled" | "skipped";
  readonly fetchedAt: string | null;
  readonly modelCount: number | null;
  readonly contentSha256: string | null;
  readonly added?: number;
  readonly removed?: number;
  readonly error?: string;
}

/** ConfigDO's sync as its callers type the stub (the console's operator refresh, the jobs cron). */
export interface ReferenceCatalogSyncRpc {
  syncReferenceCatalog(input?: { readonly ifDue?: boolean }): Promise<ReferenceCatalogSyncResult>;
}

export class ReferenceCatalogRefusal extends Error {
  override readonly name = "ReferenceCatalogRefusal";
}

// ---------------------------------------------------------------- Python's Decimal, as `rate` uses it

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, key: string): unknown => (Object.hasOwn(o, key) ? o[key] : undefined);

/** Python's truth of a JSON value: `None`, `False`, `0`, `""`, `[]` and `{}` are false. */
function truthy(v: unknown): boolean {
  if (Array.isArray(v)) return v.length > 0;
  if (isObject(v)) return Object.keys(v).length > 0;
  return Boolean(v);
}

interface Dec {
  readonly negative: boolean;
  /** The coefficient's digits, no leading zero ("0" for zero). */
  readonly digits: string;
  readonly exponent: number;
}

const DECIMAL_TEXT = /^[+-]?(?:\d+(?:_\d+)*(?:\.(?:\d+(?:_\d+)*)?)?|\.\d+(?:_\d+)*)(?:[eE][+-]?\d+(?:_\d+)*)?$/;
const SPECIAL_TEXT = /^[+-]?(?:inf|infinity|s?nan\d*)$/i;
/** Exponents past this are refused here; Python's Decimal would overflow multiplying them and stop the script. */
const EXPONENT_BOUND = 100_000;

/** `Decimal(text)`: a finite value; `"special"` for an infinity or NaN; null when Decimal refuses the text. */
function decimalOf(text: string): Dec | "special" | null {
  const t = text.trim();
  if (SPECIAL_TEXT.test(t)) return "special";
  if (!DECIMAL_TEXT.test(t)) return null;
  const s = t.replaceAll("_", "");
  const negative = s.startsWith("-");
  const body = s.replace(/^[+-]/, "");
  const [mantissa, exp = "0"] = body.split(/[eE]/) as [string, string?];
  const dot = mantissa.indexOf(".");
  const whole = dot < 0 ? mantissa : mantissa.slice(0, dot);
  const fraction = dot < 0 ? "" : mantissa.slice(dot + 1);
  const exponent = Number(exp) - fraction.length;
  if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > EXPONENT_BOUND) return null;
  const digits = (whole + fraction).replace(/^0+/, "") || "0";
  return { negative, digits, exponent };
}

/** Python's `str(raw)` for a JSON value, as the text `Decimal` reads; null where Decimal refuses `str()` of it. */
function pythonText(raw: unknown): string | null {
  if (typeof raw === "string") return raw;
  if (typeof raw === "bigint") return raw.toString();
  if (typeof raw !== "number" || !Number.isFinite(raw)) return null;
  // A JSON integer is a Python int; a float's repr has the shortest digits JavaScript has too, written as Python writes
  // them: fixed point with ".0" for an integral value between 1e-4 and 1e16. (A number written `5.0` reads as `5` here:
  // OpenRouter writes its prices as strings.)
  if (Number.isSafeInteger(raw)) return String(raw);
  const [mantissa, exp] = raw.toExponential().split("e") as [string, string];
  const e = Number(exp);
  const digits = mantissa.replace("-", "").replace(".", "");
  const sign = raw < 0 ? "-" : "";
  if (e >= -4 && e < 16) {
    const point = e + 1;
    if (point <= 0) return `${sign}0.${"0".repeat(-point)}${digits}`;
    if (point >= digits.length) return `${sign}${digits}${"0".repeat(point - digits.length)}.0`;
    return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
  }
  return `${sign}${digits[0]}${digits.length > 1 ? `.${digits.slice(1)}` : ""}e${e < 0 ? "-" : "+"}${String(Math.abs(e)).padStart(2, "0")}`;
}

/** The default context's 28 digits, half even, as `value * 1_000_000` rounds a longer product. */
function rounded(d: Dec): Dec {
  if (d.digits.length <= 28) return d;
  const drop = d.digits.length - 28;
  let keep = BigInt(d.digits.slice(0, 28));
  const rest = d.digits.slice(28);
  const half = "5" + "0".repeat(drop - 1);
  const up = rest > half || (rest === half && keep % 2n === 1n);
  if (up) keep += 1n;
  let digits = keep.toString();
  let exponent = d.exponent + drop;
  if (digits.length > 28) {
    digits = digits.slice(0, 28);
    exponent += 1;
  }
  return { negative: d.negative, digits, exponent };
}

/** `format(d, "f")`. */
function formatFixed(d: Dec): string {
  let { digits, exponent } = d;
  if (digits === "0" && exponent > 0) exponent = 0;
  const dot = exponent + digits.length;
  let whole: string;
  let fraction: string;
  if (dot < 0) {
    whole = "0";
    fraction = "0".repeat(-dot) + digits;
  } else if (dot > digits.length) {
    whole = digits + "0".repeat(dot - digits.length);
    fraction = "";
  } else {
    whole = digits.slice(0, dot) || "0";
    fraction = digits.slice(dot);
  }
  return `${d.negative ? "-" : ""}${whole}${fraction === "" ? "" : `.${fraction}`}`;
}

/** update-model-catalog.py `rate(key, raw, token_context)`. */
export function referenceRate(key: string, raw: unknown, tokenContext: boolean): ReferenceRate {
  // A key is the source's text: `toString` or `__proto__` must not reach Object.prototype.
  let unit = Object.hasOwn(REFERENCE_UNITS, key) ? REFERENCE_UNITS[key]! : "unknown";
  if ((key === "prompt" || key === "completion") && !tokenContext) unit = "unknown";
  let status: ReferenceRate["status"] = "unknown";
  let converted: string | null = null;
  const text = pythonText(raw);
  const value = text === null ? null : decimalOf(text);
  if (value !== null && value !== "special") {
    const zero = value.digits === "0";
    status = zero ? "zero" : value.negative ? "dynamic" : "priced";
    if ((zero || !value.negative) && TOKEN_FIELDS.has(key) && unit !== "unknown") {
      converted = formatFixed(rounded({ negative: value.negative, digits: zero ? "0" : value.digits + "000000", exponent: value.exponent }));
    }
  }
  return { raw: raw === undefined ? null : raw, unit, status, usdPerMillionTokens: converted };
}

// ---------------------------------------------------------------- normalize and validate

const nullableInt = (v: unknown): number | null => (v === undefined || v === null ? null : (v as number));
const isCount = (v: unknown) => v === null || (typeof v === "number" && Number.isSafeInteger(v) && v >= 0);
const isWords = (v: unknown) => v === null || (Array.isArray(v) && v.every((w) => typeof w === "string"));

function topProvider(v: unknown): ReferenceModel["top_provider"] {
  if (!isObject(v)) return null;
  const n = (x: unknown) => (typeof x === "number" ? x : null);
  return { context_length: n(own(v, "context_length")), max_completion_tokens: n(own(v, "max_completion_tokens")) };
}

/** update-model-catalog.py `normalize` of one source entry, on REFERENCE_MODEL_FIELDS; refuses what the script fails on. */
export function normalizeReferenceModel(source: unknown): ReferenceModel {
  if (!isObject(source)) throw new ReferenceCatalogRefusal("a model is not an object");
  const architectureValue = own(source, "architecture");
  const architecture = truthy(architectureValue) ? architectureValue : {};
  if (!isObject(architecture)) throw new ReferenceCatalogRefusal("architecture must be an object or null");
  const outputs = own(architecture, "output_modalities") ?? null;
  const tokenContext = Array.isArray(outputs) && outputs.some((o) => o === "text" || o === "embeddings");
  const raw = own(source, "pricing") ?? null;
  if (raw !== null && !isObject(raw)) throw new ReferenceCatalogRefusal("pricing must be an object or null");
  // Own data properties only (`defineProperty`): a source key `__proto__` is a price like any other, never the prototype.
  const rates: Record<string, ReferenceRate> = {};
  const put = (key: string, rate: ReferenceRate) => Object.defineProperty(rates, key, { value: rate, enumerable: true, writable: true, configurable: true });
  for (const [key, value] of Object.entries(raw ?? {})) if (key !== "overrides") put(key, referenceRate(key, value, tokenContext));
  for (const key of ["prompt", "completion"]) if (!Object.hasOwn(rates, key)) put(key, referenceRate(key, null, tokenContext));
  return {
    id: own(source, "id") as string,
    name: own(source, "name") as string,
    description: (own(source, "description") ?? null) as string | null,
    created: nullableInt(own(source, "created")),
    context_length: nullableInt(own(source, "context_length")),
    supported_parameters: (own(source, "supported_parameters") ?? null) as string[] | null,
    top_provider: topProvider(own(source, "top_provider")),
    input_modalities: (own(architecture, "input_modalities") ?? null) as string[] | null,
    output_modalities: outputs as string[] | null,
    pricing_raw: raw,
    pricing: rates,
    has_pricing_overrides: truthy(raw === null ? undefined : own(raw, "overrides")),
  };
}

/** update-model-catalog.py `validate` of the models (ids unique, the types it asserts). */
export function validateReferenceModels(models: readonly ReferenceModel[]): void {
  const ids = new Set<string>();
  for (const m of models) {
    if (typeof m.id !== "string" || m.id === "") throw new ReferenceCatalogRefusal("a model has no id");
    if (ids.has(m.id)) throw new ReferenceCatalogRefusal(`duplicate model id ${m.id}`);
    ids.add(m.id);
    if (typeof m.name !== "string" || m.name === "") throw new ReferenceCatalogRefusal(`model ${m.id} has no name`);
    if (!isCount(m.created) || !isCount(m.context_length)) throw new ReferenceCatalogRefusal(`model ${m.id}: created and context_length must be whole numbers`);
    for (const words of [m.input_modalities, m.output_modalities, m.supported_parameters]) if (!isWords(words)) throw new ReferenceCatalogRefusal(`model ${m.id}: a list is not a list of strings`);
    if (m.description !== null && typeof m.description !== "string") throw new ReferenceCatalogRefusal(`model ${m.id}: description is not a string`);
  }
}

/**
 * The source's answer (`GET <REFERENCE_CATALOG_URL>`, parsed) to the models the store keeps, sorted by id: refused as the
 * script refuses it (a next page, a count that is not the list's, an entry it cannot read), fewer than MIN_MODELS included.
 */
export function normalizeReferenceSource(payload: unknown): ReferenceModel[] {
  if (!isObject(payload)) throw new ReferenceCatalogRefusal("the answer is not an object");
  const links = own(payload, "links");
  if (truthy(links) && isObject(links) && truthy(own(links, "next"))) throw new ReferenceCatalogRefusal("incomplete paginated response");
  const data = own(payload, "data");
  if (!Array.isArray(data)) throw new ReferenceCatalogRefusal("the answer has no data list");
  if (Object.hasOwn(payload, "total_count") && own(payload, "total_count") !== data.length) throw new ReferenceCatalogRefusal("incomplete model count");
  const models = data.map(normalizeReferenceModel);
  validateReferenceModels(models);
  if (models.length < REFERENCE_MIN_MODELS) throw new ReferenceCatalogRefusal(`${models.length} models, fewer than ${REFERENCE_MIN_MODELS}`);
  return models.sort((a, b) => compareUtf8(a.id, b.id));
}

/** A stored catalog entry (the bundled file's, or KV's) as the store keeps it: REFERENCE_MODEL_FIELDS only. */
export function compactReferenceModel(m: Record<string, unknown>): ReferenceModel {
  return {
    id: m.id as string,
    name: m.name as string,
    description: (m.description ?? null) as string | null,
    created: nullableInt(m.created),
    context_length: nullableInt(m.context_length),
    supported_parameters: (m.supported_parameters ?? null) as string[] | null,
    top_provider: topProvider(m.top_provider),
    input_modalities: (m.input_modalities ?? null) as string[] | null,
    output_modalities: (m.output_modalities ?? null) as string[] | null,
    pricing_raw: m.pricing_raw ?? null,
    pricing: (m.pricing ?? {}) as Record<string, ReferenceRate>,
    has_pricing_overrides: m.has_pricing_overrides === true,
  };
}

/** The content's hash: the models in id order, nothing of when they were fetched. */
export function referenceContentSha256(models: readonly ReferenceModel[]): string {
  const sorted = [...models].sort((a, b) => compareUtf8(a.id, b.id));
  return bytesToHex(sha256(utf8ToBytes(JSON.stringify(sorted))));
}

// ---------------------------------------------------------------- what the live copy may not change on its own

/**
 * The fields of an entry that routing, holds and the offer rules read: the context windows and the maximum output
 * (`context_length`, `top_provider`), the reference prices and the long-context tier (`pricing_raw`, its
 * `overrides[].min_prompt_tokens`, and `pricing`, `has_pricing_overrides` derived from it). For a model the bundled file
 * lists, the live copy's values of these are held back: the bundled file's stay, so a third party's change to a routed
 * model (a lower threshold, a smaller window) never drops routes, moves the offer rules or alerts a relay on its own. It
 * takes effect when the bundled file adopts it (scripts/update-model-catalog.py through the catalog-refresh workflow's
 * reviewed pull request); meanwhile the sync tells Gray's operators (`reference_catalog_change_held`). A model the bundled
 * file lacks, and every other field (name, description, modalities, parameters), follows the live copy.
 */
export const PINNED_REFERENCE_FIELDS = ["context_length", "top_provider", "pricing_raw", "pricing", "has_pricing_overrides"] as const;

/** One field of a bundled model whose live value differs and is held back. */
export interface HeldReferenceChange {
  readonly model: string;
  readonly field: (typeof PINNED_REFERENCE_FIELDS)[number];
  readonly bundled: unknown;
  readonly live: unknown;
}

/** A JSON value's text with object members in code-unit order, so two equal values compare equal whatever their order. */
function orderedJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => compareUtf8(a, b))) : v,
  );
}

/**
 * The live models with `PINNED_REFERENCE_FIELDS` of every model the bundled file lists taken from the bundled file, and
 * the differences held back. Models in the live order; the bundled file's entries are not added.
 */
export function pinReferenceModels(live: readonly ReferenceModel[], bundled: readonly ReferenceModel[]): { readonly models: ReferenceModel[]; readonly held: HeldReferenceChange[] } {
  const byId = new Map(bundled.map((m) => [m.id, m]));
  const held: HeldReferenceChange[] = [];
  const models = live.map((m) => {
    const b = byId.get(m.id);
    if (b === undefined) return m;
    let out: Record<string, unknown> | null = null;
    for (const field of PINNED_REFERENCE_FIELDS) {
      if (orderedJson(m[field] ?? null) === orderedJson(b[field] ?? null)) continue;
      held.push({ model: m.id, field, bundled: b[field] ?? null, live: m[field] ?? null });
      (out ??= { ...m })[field] = b[field] ?? null;
    }
    return out === null ? m : (out as unknown as ReferenceModel);
  });
  return { models, held };
}

/** The most `reference_catalog_change_held` lines one sync writes; a further count rides the last, told at the next. */
export const REFERENCE_HELD_LOG_MAX = 20;

/** A told record's key: the model and the field of a held difference. */
export function heldKey(h: { readonly model: string; readonly field: string }): string {
  return `${h.model}\u0000${h.field}`;
}

/**
 * What a sync has told Gray's operators of the held differences, kept by its caller (gray-jobs' ConfigDO, in its own
 * storage): `heldKey` to the live value told (`orderedJson`).
 */
export interface ReferenceHeldToldStore {
  read(): ReadonlyMap<string, string> | Promise<ReadonlyMap<string, string>>;
  write(told: ReadonlyMap<string, string>): void | Promise<void>;
}

/**
 * The held differences to tell now, once each: one whose live value no record holds (new, or the source changed it again
 * since it was told), at most `max`; the rest wait for the next check (`more`). The records to keep are the differences
 * still held, so one the bundled file adopted or the source returned to is dropped, and told again if it comes back.
 */
export function heldToTell(held: readonly HeldReferenceChange[], told: ReadonlyMap<string, string>, max: number): { readonly tell: HeldReferenceChange[]; readonly more: number; readonly told: Map<string, string> } {
  const next = new Map<string, string>();
  const fresh: HeldReferenceChange[] = [];
  for (const h of held) {
    const live = orderedJson(h.live ?? null);
    if (told.get(heldKey(h)) === live) next.set(heldKey(h), live);
    else fresh.push(h);
  }
  const tell = fresh.slice(0, max);
  for (const h of tell) next.set(heldKey(h), orderedJson(h.live ?? null));
  return { tell, more: fresh.length - tell.length, told: next };
}

// ---------------------------------------------------------------- the store

/** The parts of a KVNamespace the store reads. */
export interface ReferenceCatalogKvReader {
  get(key: string, type: "text"): Promise<string | null>;
  getWithMetadata<M = unknown>(key: string, type: "text"): Promise<{ readonly value: string | null; readonly metadata: M | null }>;
}

/** And the sync writes. */
export interface ReferenceCatalogKv extends ReferenceCatalogKvReader {
  put(key: string, value: string, options?: { readonly metadata?: unknown }): Promise<void>;
}

/** One copy a store serves: the bundled one or KV's. Replaced whole, never changed. */
export interface ReferenceCatalogState {
  readonly source: "kv" | "bundled";
  readonly sourceUrl: string;
  readonly fetchedAt: string;
  readonly models: readonly ReferenceModel[];
  /** Counts the copies this store has served, the bundled one 0. */
  readonly generation: number;
  /** `referenceContentSha256(models)` (worked out on first use for the bundled copy). */
  contentSha256(): string;
  /** The document as GET /api/v1/reference-catalog answers it (KV's text as written; the bundled one's, on first use). */
  jsonText(): string;
}

export interface ReferenceCatalogStoreOptions {
  readonly ttlMs?: number;
  readonly retryMs?: number;
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly log?: (event: Record<string, unknown>) => void;
}

export interface ReferenceCatalogStore {
  /** The copy served now. */
  current(): ReferenceCatalogState;
  /** The bundled copy, whose `PINNED_REFERENCE_FIELDS` the served one keeps for the models it lists. */
  bundled(): ReferenceCatalogState;
  /** `current()`'s key for what is derived from it: `bundled`, or the KV content's hash. */
  version(): string;
  /** Checks KV when due (or now, `force`); never throws, and keeps the copy it has on any failure. */
  ensure(kv: ReferenceCatalogKvReader | null | undefined, options?: { readonly force?: boolean }): Promise<ReferenceCatalogState>;
  /** Back to the bundled copy (tests). */
  reset(): void;
}

const lazy = <T>(make: () => T): (() => T) => {
  let held: { value: T } | null = null;
  return () => (held ??= { value: make() }).value;
};

const HEX64 = /^[0-9a-f]{64}$/;

function bundledState(bundled: unknown): ReferenceCatalogState {
  const doc = (isObject(bundled) ? bundled : {}) as { sourceUrl?: string; fetchedAt?: string; models?: Record<string, unknown>[] };
  // The bundled order is the file's (the order readers saw before the live copy); its hash is the sorted one's.
  const models = (doc.models ?? []).map(compactReferenceModel);
  const sourceUrl = doc.sourceUrl ?? "";
  const fetchedAt = doc.fetchedAt ?? "";
  const sha = lazy(() => referenceContentSha256(models));
  const text = lazy(() => JSON.stringify({ schemaVersion: 1, sourceUrl, fetchedAt, modelCount: models.length, models: [...models].sort((a, b) => compareUtf8(a.id, b.id)) }));
  return { source: "bundled", sourceUrl, fetchedAt, models, generation: 0, contentSha256: sha, jsonText: text };
}

/** KV's `reference-catalog:v1` text, read: the document, or why it is not one. */
export function parseReferenceDocument(text: string): ReferenceCatalogDocument {
  const doc = parsePlain(text);
  if (!isObject(doc) || doc.schemaVersion !== 1) throw new ReferenceCatalogRefusal("not a schemaVersion 1 document");
  const models = doc.models;
  if (!Array.isArray(models) || models.length < REFERENCE_MIN_MODELS) throw new ReferenceCatalogRefusal(`fewer than ${REFERENCE_MIN_MODELS} models`);
  for (const m of models) if (!isObject(m) || typeof m.id !== "string" || typeof m.name !== "string") throw new ReferenceCatalogRefusal("a model without an id or name");
  if (typeof doc.sourceUrl !== "string" || typeof doc.fetchedAt !== "string") throw new ReferenceCatalogRefusal("no sourceUrl or fetchedAt");
  return doc as unknown as ReferenceCatalogDocument;
}

/** `reference-catalog:v1:meta`'s text, read; null for none or one that is not a meta record. */
export function parseReferenceSyncMeta(text: string | null): ReferenceCatalogSyncMeta | null {
  if (text === null) return null;
  const meta = parsePlain(text);
  if (!isObject(meta) || meta.schemaVersion !== 1 || typeof meta.checkedAtMs !== "number") return null;
  return meta as unknown as ReferenceCatalogSyncMeta;
}

export function createReferenceCatalogStore(bundled: unknown, options: ReferenceCatalogStoreOptions = {}): ReferenceCatalogStore {
  const ttl = options.ttlMs ?? REFERENCE_CATALOG_CACHE_TTL_MS;
  const retry = options.retryMs ?? REFERENCE_CATALOG_RETRY_MS;
  const timeout = options.timeoutMs ?? REFERENCE_CATALOG_KV_TIMEOUT_MS;
  const now = options.now ?? Date.now;
  const log = options.log ?? ((event) => console.warn(JSON.stringify(event)));
  const initial = lazy(() => bundledState(bundled));
  let active: ReferenceCatalogState | null = null;
  // The KV content the served copy was made from (its hash as written); the served copy's own hash differs when fields
  // were held back.
  let heldKvSha: string | null = null;
  let nextCheckAt = Number.NEGATIVE_INFINITY;
  let inFlight: Promise<ReferenceCatalogState> | null = null;
  const current = () => (active ??= initial());

  async function load(kv: ReferenceCatalogKvReader): Promise<void> {
    const held = current();
    try {
      const meta = parseReferenceSyncMeta(await within(kv.get(REFERENCE_CATALOG_META_KEY, "text"), timeout, "SNAPSHOT_KV.get"));
      if (held.source === "kv" && meta?.contentSha256 != null && meta.contentSha256 === heldKvSha) {
        nextCheckAt = now() + ttl;
        return;
      }
      const read = await within(kv.getWithMetadata<Partial<ReferenceCatalogKvMeta>>(REFERENCE_CATALOG_KEY, "text"), timeout, "SNAPSHOT_KV.getWithMetadata");
      // None written yet (no sync has run here): the copy held stays, quietly.
      if (read.value === null) {
        nextCheckAt = now() + ttl;
        return;
      }
      const text = read.value;
      const doc = parseReferenceDocument(text);
      const stated = read.metadata?.contentSha256;
      const sha = typeof stated === "string" && HEX64.test(stated) ? stated : referenceContentSha256(doc.models);
      if (held.source !== "kv" || heldKvSha !== sha) {
        // The bundled file's routing fields stay for the models it lists (`pinReferenceModels`); the document served
        // (GET /api/v1/reference-catalog) is the copy served, so the frontend reads what the console and jobs read.
        const pinned = pinReferenceModels(doc.models, initial().models);
        const servedSha = pinned.held.length === 0 ? sha : referenceContentSha256(pinned.models);
        const servedText = pinned.held.length === 0
          ? text
          : JSON.stringify({ schemaVersion: 1, sourceUrl: doc.sourceUrl, fetchedAt: doc.fetchedAt, modelCount: pinned.models.length, models: pinned.models });
        active = { source: "kv", sourceUrl: doc.sourceUrl, fetchedAt: doc.fetchedAt, models: pinned.models, generation: held.generation + 1, contentSha256: () => servedSha, jsonText: () => servedText };
        heldKvSha = sha;
      }
      nextCheckAt = now() + ttl;
    } catch (error) {
      log({ level: "warn", event: "reference_catalog_read_failed", source: held.source, message: error instanceof Error ? error.message : String(error) });
      nextCheckAt = now() + retry;
    }
  }

  return {
    current,
    bundled: initial,
    version: () => {
      const s = current();
      return s.source === "bundled" ? "bundled" : s.contentSha256();
    },
    ensure(kv, opts = {}) {
      if (kv === null || kv === undefined) return Promise.resolve(current());
      if (!opts.force && now() < nextCheckAt) return Promise.resolve(current());
      const start = (): Promise<ReferenceCatalogState> => {
        const run: Promise<ReferenceCatalogState> = load(kv)
          .then(current)
          .finally(() => {
            if (inFlight === run) inFlight = null;
          });
        inFlight = run;
        return run;
      };
      if (inFlight === null) return start();
      // A forced read (after a sync wrote KV) must not take a read that started before the write: it waits for that one
      // and reads again; callers arriving meanwhile share the new read.
      if (!opts.force) return inFlight;
      const earlier = inFlight;
      const next = earlier.then(() => (inFlight !== null && inFlight !== earlier ? inFlight : start()));
      return next;
    },
    reset() {
      active = null;
      heldKvSha = null;
      nextCheckAt = Number.NEGATIVE_INFINITY;
    },
  };
}

// ---------------------------------------------------------------- the sync (gray-jobs' ConfigDO)

export interface ReferenceSyncInput {
  readonly url: string;
  readonly kv: ReferenceCatalogKv;
  /** The copy to measure a loss against when KV holds none (the caller's bundled catalog). */
  readonly fallback: ReferenceCatalogState;
  /**
   * The caller's bundled models (its store's `bundled()`): each check tells Gray's operators which of their
   * `PINNED_REFERENCE_FIELDS` the live list changes and the readers hold back (`reference_catalog_change_held`).
   */
  readonly bundled?: readonly ReferenceModel[];
  /** What was told before (with `bundled`): a held difference is told once per live value. None: at every check. */
  readonly told?: ReferenceHeldToldStore;
  readonly fetcher?: typeof fetch;
  readonly now?: () => number;
  readonly log?: (event: Record<string, unknown>) => void;
  readonly timeoutMs?: number;
  readonly kvTimeoutMs?: number;
}

/** Whether the cron's sync is due by the last check: its interval after a check that read, the error backoff after one that failed. */
export function referenceSyncDue(meta: ReferenceCatalogSyncMeta | null, nowMs: number, intervalMs: number): boolean {
  if (meta === null) return true;
  return nowMs - meta.checkedAtMs >= (meta.lastStatus === "error" ? Math.min(REFERENCE_CATALOG_ERROR_BACKOFF_MS, intervalMs) : intervalMs);
}

const message = (error: unknown) => (error instanceof Error ? error.message : String(error)).slice(0, 500);

/**
 * update-model-catalog.py's refresh into KV: fetch, refuse as the script refuses, and write `reference-catalog:v1` only
 * when the models changed; the meta key records every check. A refusal or a failure never touches the catalog key (its
 * last valid copy stays served) and is a warning.
 */
export async function syncReferenceCatalog(input: ReferenceSyncInput): Promise<ReferenceCatalogSyncResult> {
  const now = input.now ?? Date.now;
  const log = input.log ?? ((event) => console.warn(JSON.stringify(event)));
  const kvTimeout = input.kvTimeoutMs ?? REFERENCE_CATALOG_KV_TIMEOUT_MS;
  if (input.url === "") return { status: "disabled", fetchedAt: null, modelCount: null, contentSha256: null };
  const checkedAtMs = now();
  let prior: ReferenceCatalogSyncMeta | null = null;
  try {
    prior = parseReferenceSyncMeta(await within(input.kv.get(REFERENCE_CATALOG_META_KEY, "text"), kvTimeout, "SNAPSHOT_KV.get"));
  } catch {
    prior = null;
  }
  const writeMeta = async (meta: Omit<ReferenceCatalogSyncMeta, "schemaVersion" | "checkedAtMs">): Promise<void> => {
    try {
      await within(input.kv.put(REFERENCE_CATALOG_META_KEY, JSON.stringify({ schemaVersion: 1, checkedAtMs, ...meta })), kvTimeout, "SNAPSHOT_KV.put");
    } catch (error) {
      log({ level: "warn", event: "reference_catalog_meta_write_failed", message: message(error) });
    }
  };
  const kept = { fetchedAt: prior?.fetchedAt ?? null, contentSha256: prior?.contentSha256 ?? null, sourceSha256: prior?.sourceSha256 ?? null, modelCount: prior?.modelCount ?? null };
  const fail = async (status: "rejected" | "error", error: unknown): Promise<ReferenceCatalogSyncResult> => {
    const text = message(error);
    log({ level: "warn", event: status === "rejected" ? "reference_catalog_sync_rejected" : "reference_catalog_sync_failed", message: text });
    await writeMeta({ ...kept, lastStatus: status, lastError: text });
    return { status, fetchedAt: kept.fetchedAt, modelCount: kept.modelCount, contentSha256: kept.contentSha256, error: text };
  };

  let bytes: Uint8Array;
  let payload: unknown;
  try {
    const res = await (input.fetcher ?? fetch)(input.url, {
      headers: { "user-agent": REFERENCE_USER_AGENT, accept: "application/json" },
      signal: AbortSignal.timeout(input.timeoutMs ?? REFERENCE_CATALOG_FETCH_TIMEOUT_MS),
    });
    if (res.status !== 200) {
      await res.body?.cancel();
      throw new Error(`the source answered ${res.status}`);
    }
    bytes = new Uint8Array(await res.arrayBuffer());
    payload = parsePlain(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch (error) {
    return fail("error", error);
  }

  let models: ReferenceModel[];
  try {
    models = normalizeReferenceSource(payload);
  } catch (error) {
    return fail(error instanceof ReferenceCatalogRefusal ? "rejected" : "error", error);
  }
  const contentSha256 = referenceContentSha256(models);
  const sourceSha256 = bytesToHex(sha256(bytes));
  // What the readers hold back (they keep the bundled values): each difference told once per live value with a store of
  // what was told (`heldToTell`); a store that cannot be read tells them all again rather than none.
  if (input.bundled !== undefined) {
    const { held } = pinReferenceModels(models, input.bundled);
    let told: ReadonlyMap<string, string> = new Map();
    if (input.told !== undefined) {
      try {
        told = await input.told.read();
      } catch (error) {
        log({ level: "warn", event: "reference_catalog_held_read_failed", message: message(error) });
      }
    }
    const telling = heldToTell(held, told, REFERENCE_HELD_LOG_MAX);
    const shown = (v: unknown) => orderedJson(v).slice(0, 400);
    telling.tell.forEach((h, i) =>
      log({
        level: "alert",
        event: "reference_catalog_change_held",
        model: h.model,
        field: h.field,
        bundled: shown(h.bundled),
        live: shown(h.live),
        ...(i === telling.tell.length - 1 && telling.more > 0 ? { more: telling.more } : {}),
      }),
    );
    if (input.told !== undefined) {
      try {
        await input.told.write(telling.told);
      } catch (error) {
        log({ level: "warn", event: "reference_catalog_held_write_failed", message: message(error) });
      }
    }
  }

  // What KV holds now: the content to compare with, and the IDs a loss is measured against (else the bundled copy's).
  let stored: { readonly sha: string; readonly ids: ReadonlySet<string>; readonly fetchedAt: string } | null = null;
  try {
    const read = await within(input.kv.getWithMetadata<Partial<ReferenceCatalogKvMeta>>(REFERENCE_CATALOG_KEY, "text"), kvTimeout, "SNAPSHOT_KV.getWithMetadata");
    if (read.value !== null) {
      const doc = parseReferenceDocument(read.value);
      const stated = read.metadata?.contentSha256;
      stored = { sha: typeof stated === "string" && HEX64.test(stated) ? stated : referenceContentSha256(doc.models), ids: new Set(doc.models.map((m) => m.id)), fetchedAt: doc.fetchedAt };
    }
  } catch (error) {
    log({ level: "warn", event: "reference_catalog_read_failed", source: "sync", message: message(error) });
  }

  if (stored !== null && stored.sha === contentSha256) {
    // Only the fetch time would differ: the catalog key stays as it is.
    await writeMeta({ fetchedAt: stored.fetchedAt, contentSha256, sourceSha256, modelCount: models.length, lastStatus: "unchanged", lastError: null });
    return { status: "unchanged", fetchedAt: stored.fetchedAt, modelCount: models.length, contentSha256, added: 0, removed: 0 };
  }

  const previous = stored?.ids ?? new Set(input.fallback.models.map((m) => m.id));
  const current = new Set(models.map((m) => m.id));
  const removed = [...previous].filter((id) => !current.has(id)).length;
  const added = [...current].filter((id) => !previous.has(id)).length;
  if (removed > REFERENCE_MAX_LOSS * previous.size) {
    return fail("rejected", new ReferenceCatalogRefusal(`${removed} of ${previous.size} model IDs are gone, more than ${Math.round(REFERENCE_MAX_LOSS * 100)}%`));
  }

  const fetchedAt = new Date(checkedAtMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  const doc: ReferenceCatalogDocument = { schemaVersion: 1, sourceUrl: input.url, fetchedAt, modelCount: models.length, models };
  const metadata: ReferenceCatalogKvMeta = { schemaVersion: 1, fetchedAt, contentSha256, sourceSha256, modelCount: models.length };
  try {
    await within(input.kv.put(REFERENCE_CATALOG_KEY, JSON.stringify(doc), { metadata }), kvTimeout * 5, "SNAPSHOT_KV.put");
  } catch (error) {
    return fail("error", error);
  }
  await writeMeta({ fetchedAt, contentSha256, sourceSha256, modelCount: models.length, lastStatus: "updated", lastError: null });
  log({ level: "info", event: "reference_catalog_updated", models: models.length, added, removed, content_sha256: contentSha256 });
  return { status: "updated", fetchedAt, modelCount: models.length, contentSha256, added, removed };
}
