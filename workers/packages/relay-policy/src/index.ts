/**
 * @gray/relay-policy — the zero-capability sandbox for a relay's private policy module.
 *
 * A relay supplies a closed-source WebAssembly module. For each request the module reads the request
 * body and decides allow (optionally naming pre-registered template ids to append) or block (with a
 * reason code from a closed set). The module cannot keep or carry away anything and cannot run
 * unbounded: it has no imports (no WASI, no clock, no randomness, no logging), a fresh instance per
 * request, a declared memory maximum, wasmi fuel sized to the input, a mapped stack budget, and an
 * output capped at 4 KiB and validated against the ABI. Every failure — a trap, an out-of-fuel stop,
 * a stack overflow, a failed allocation, an invalid output, an unknown template — becomes one fixed
 * outcome with an internal typed cause (`outcome.ts`).
 *
 * The module is **interpreted** by wasmi 2.0.0 inside a wasm module the host imports at build time
 * (`workers/vendor/relay-policy-wasmi`). The host generates no code and never compiles the relay's
 * bytes, so the same path runs in Node, in workerd and in the dstack CVM whose measurement a customer
 * checks.
 *
 * The package is the host half only, and the pieces are separable:
 *
 * - `validate.ts` — the module contract, decided before anything runs it.
 * - `wasmi.ts` + `workers/vendor/relay-policy-wasmi` — the interpreter: no code generation, native
 *   fuel and limits, and the only way a relay's bytes run in workerd.
 * - `sandbox.ts` — `preparePolicy` (upload) and `runPolicy` (one request, one fresh instance).
 * - `limits.ts` — the budgets, including the fuel formula `base + per_kib * ceil(input_bytes / 1024)`
 *   and one hard input cap per lane protocol, from `@gray/limits`'s `requestLimit`.
 * - `bundle.ts` + `store.ts` — the relay signature over the claim, and the strictly increasing
 *   version per relay.
 * - `abi.ts` — the input header and output shapes (`abi.md` is the relay-facing document).
 * - `receipt.ts` — the pair a receipt cites and the two events, built by `@gray/attest`.
 * - `step-speed.ts` — the policy step's two timing settings (fuel per ms, overhead), how they are
 *   derived from timed runs, and the modules (shipped as bytes) the lane's boot calibration times.
 *
 * Pure code: no `cloudflare:*` import, no I/O, no clock, no randomness, so the same source runs in
 * Node and in workerd. Import `@gray/relay-policy/workerd` in a Worker: it hands the interpreter wasm
 * module over to this package's own code at start-up.
 */
export {
  MAX_MODEL_BYTES,
  MAX_POLICY_HEADER_BYTES,
  POLICY_INPUT_SEPARATOR,
  POLICY_INPUT_VERSION,
  buildPolicyInput,
  parsePolicyOutput,
  policyAllowSchema,
  policyBlockSchema,
  policyInputLength,
  policyOutputSchema,
  type PolicyInputRefusalCode,
  type PolicyInputRequest,
  type PolicyOutputRefusalCode,
} from "./abi.ts";
export {
  canonicalTemplates,
  policyClaim,
  policyClaimBytes,
  templateDigest,
  verifyPolicyBundle,
  type BundleRefusalCode,
  type PolicyClaim,
  type RelayPolicyBundle,
} from "./bundle.ts";
export {
  DEFAULT_POLICY_LIMITS,
  LANE_BODY_MAX_BYTES,
  LANE_MAX_INPUT_BYTES,
  MAX_FUEL,
  MODULE_WORKING_BYTES,
  WASM_PAGE_BYTES,
  policyFuel,
  resolvePolicyLimits,
  type LaneInputBytes,
  type LimitsRefusalCode,
  type PolicyLimitOverrides,
  type PolicyLimits,
} from "./limits.ts";
export {
  POLICY_UNAVAILABLE,
  isPolicyFailure,
  policyAllowed,
  policyBlocked,
  policyFailed,
  type PolicyAllow,
  type PolicyBlock,
  type PolicyCause,
  type PolicyResult,
} from "./outcome.ts";
export {
  appliedPolicyEvent,
  policyOutcomeEvent,
  policyReceiptRecord,
  refusedPolicyEvent,
  type PolicyReceiptRecord,
} from "./receipt.ts";
export {
  initInterpreter,
  interpreterReady,
  policyRunFuel,
  preparePolicy,
  runPolicy,
  type PolicyCandidate,
  type PolicyRequest,
  type PrepareOptions,
  type PrepareRefusalCode,
  type PreparedPolicy,
  type WasmiPolicy,
} from "./sandbox.ts";
export {
  STEP_BURN_MODULES,
  STEP_SPEED_MODEL,
  STEP_SPEED_PROTOCOL,
  STEP_TRIVIAL_MODULE,
  StepSpeedError,
  deriveStepSpeed,
  measureStepSpeed,
  percentile,
  sandboxStepSpeedRunner,
  stepSpeedBody,
  stepSpeedModule,
  type StepBurnModule,
  type StepBurnReading,
  type StepSpeed,
  type StepSpeedMeasurement,
  type StepSpeedModule,
  type StepSpeedRunner,
  type StepSpeedSizes,
  type StepSpeedTiming,
} from "./step-speed.ts";
export { createPolicyStore, type PolicyRecord, type PolicyStore, type PolicyStoreOptions, type StoreRefusalCode } from "./store.ts";
export { validatePolicyShape, type ModuleRefusalCode, type ValidatedShape } from "./validate.ts";
export {
  MAX_WASMI_MODULE_BYTES,
  loadPolicyModule,
  memoryBytesOf,
  type WasmiCallFailureCode,
  type WasmiCallLimits,
  type WasmiCallResult,
  type WasmiLoadFailureCode,
  type WasmiLoadLimits,
  type WasmiSession,
} from "./wasmi.ts";
export { scanMemoryDeclarations, type MemoryDeclaration, type WasmScanRefusalCode } from "./wasm-scan.ts";
