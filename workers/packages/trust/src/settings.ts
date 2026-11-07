/**
 * The tool gate's tunables, set once per isolate from the gateway's configuration (@gray/config rows
 * TRUST_*, where each default's source is written). Every value is optional; one left out keeps its
 * current value (the defaults, until set).
 */
import { configureRegexEngine } from "./engine.ts";
import { configurePatternCaches } from "./pattern.ts";
import { configureSchemas } from "./schema.ts";

export interface TrustSettings {
  /** TRUST_REGEX_COMPILE_MAX_BYTES: the budget of one regex compile (src/engine.ts). */
  readonly regexCompileMaxBytes?: number;
  /**
   * TRUST_SCHEMA_COMPILE_BUDGET_MS: the estimated compile time of one request's declared schemas;
   * past it the request is refused `trust_tool_schemas_too_complex` (src/schema.ts).
   */
  readonly schemaCompileBudgetMs?: number;
  /** TRUST_SCHEMA_CACHE_SUBSCHEMAS: the compiled validators kept, counted by their schemas' values. */
  readonly schemaCacheSubschemas?: number;
  /** TRUST_VERDICT_CACHE_KEY_UNITS: each map of verdicts and translations, in UTF-16 units of keys. */
  readonly verdictCacheKeyUnits?: number;
}

function positive(name: string, value: number | undefined): void {
  if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) throw new RangeError(`${name} must be a positive integer, not ${value}`);
}

export function configureTrust(settings: TrustSettings): void {
  positive("schemaCompileBudgetMs", settings.schemaCompileBudgetMs);
  positive("schemaCacheSubschemas", settings.schemaCacheSubschemas);
  positive("verdictCacheKeyUnits", settings.verdictCacheKeyUnits);
  if (settings.regexCompileMaxBytes !== undefined) configureRegexEngine({ compileMaxBytes: settings.regexCompileMaxBytes });
  configureSchemas({
    compileBudgetMs: settings.schemaCompileBudgetMs,
    cacheSubschemas: settings.schemaCacheSubschemas,
    verdictKeyUnits: settings.verdictCacheKeyUnits,
  });
  if (settings.verdictCacheKeyUnits !== undefined) configurePatternCaches(settings.verdictCacheKeyUnits);
}
