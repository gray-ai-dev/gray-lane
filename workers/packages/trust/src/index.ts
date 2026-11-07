/**
 * @gray/trust: the tool gate (crates/gray-gateway/src/trust.rs and the `ToolGate` of
 * crates/gray-gateway/src/inference.rs), ported to TypeScript and held to Rust-generated fixtures
 * (conformance areas `trust` and `trust-schema`). Pure code: no `cloudflare:*` imports. The regex
 * engine is a wasm module that must be initialised once per isolate (src/engine.ts); Worker code
 * imports `@gray/trust/workerd`, which does it. docs/cloudflare-native/trust.md describes the port.
 */
export {
  type CommandPolicy,
  DEFAULT_TRUST_POLICY,
  PACKAGE_MANAGERS,
  type PackageManager,
  TrustConfigError,
  type ToolPolicy,
  type TrustMode,
  type TrustPolicyConfig,
  parseTrustPolicyConfig,
} from "./config.ts";
export {
  REGEX_CACHE_MAX_BYTES,
  REGEX_COMPILE_MAX_BYTES_DEFAULT,
  REGEX_COMPILE_MIN_BYTES,
  REGEX_INSTANCE_BYTES,
  REGEX_REQUEST_COMPILE_BYTES,
  RegexEngineBusy,
  RegexEngineTrapped,
  RegexEngineUnavailable,
  RegexTextTooLong,
  type CompileAllowance,
  compileAllowance,
  configureRegexEngine,
  initRegexEngine,
  regexCacheUse,
  regexEngineCounters,
  regexEngineMemory,
  regexEngineReady,
  regexInstanceMaxBytes,
  regexPendingMaxBytes,
  withCompileAllowance,
} from "./engine.ts";
export {
  type Finding,
  type GateEnd,
  type GateFailure,
  type GateOptions,
  type GateStep,
  OpenGate,
  type StreamStage,
  ToolGate,
} from "./gate.ts";
export { AnswerCallCheck } from "./answer.ts";
export { StreamToolInspector } from "./inspector.ts";
export { MARKER_MAX_BYTES, MARKER_MIN_BYTES, MAX_TOOLS, TOOL_NAME_MAX_BYTES } from "./limits.ts";
export { type CompiledPattern, compilePattern, isRegexFormat, translate, type Translation } from "./pattern.ts";
export { type GateAnswer, type GateRequest, ToolSchemas, TrustPolicy } from "./policy.ts";
export { RECENT_KEY_UNITS as VERDICT_CACHE_KEY_UNITS_DEFAULT } from "./recent.ts";
export {
  MAX_SCHEMA_BYTES,
  SCHEMA_CACHE_SUBSCHEMAS_DEFAULT,
  SCHEMA_COMPILE_BUDGET_MS_DEFAULT,
  type IsValidOptions,
  type SchemaValidator,
  hasExternalSchemaReference,
  schemaCompileMicros,
  schemaValidator,
} from "./schema.ts";
export { type TrustSettings, configureTrust } from "./settings.ts";
export { ANTHROPIC_HOSTED, EXECUTABLE_KEYS, GEMINI_ACCOMPANYING, GEMINI_REFUSED, GEMINI_VARIANTS, TEXT_PARTS, carriesToolCall } from "./shapes.ts";
export { type StreamCheck, type StreamCheckOptions, answerContract } from "./stream.ts";
export {
  type InspectionResult,
  NOTHING_FOUND,
  TRUST_VIOLATIONS,
  type TrustInspection,
  type TrustViolation,
} from "./violations.ts";
