/**
 * The sandbox itself: what the gateway holds after a relay's bundle is accepted, and the one call it
 * makes per request.
 *
 * Preparing a policy is upload work, done once per version: validate the bytes (validate.ts), load
 * them into the interpreter (`wasmi.ts`), and cite the hash. Running a policy is request work: one
 * **fresh wasmi instance** of the relay's module per request, the input written through the
 * wrapper's own `alloc`, `evaluate` called with the fuel the formula in limits.ts gives that input,
 * the output read back, validated and turned into registered template ids, then the instance
 * dropped. Nothing is reused: a global a module sets in one request is zero in the next, which is
 * what makes "the module kept nothing" true by construction rather than by inspection (the review's
 * §5.2, item 2, and the fresh-instance test).
 *
 * The module is loaded once per policy version, not once per request: `load` parses and translates
 * it with wasmi, and `evaluate` builds a new wasmi `Store` and `Instance` over that translated module
 * for every request. That is the cheap half of instantiation; the part that needs a budget is the
 * guest's own code, which is what fuel bounds.
 *
 * **One engine.** The relay's bytes are only ever data: the interpreter is a wasm module the
 * gateway imports at build time (`workers/vendor/relay-policy-wasmi`), so the host never generates
 * code and a relay's module can run in workerd. Everything after the module's answer — the output
 * parser, the template selection, the fixed failure outcome, the receipt — is one shared tail
 * ({@link decide}).
 */
import {
  createTemplateRegistry,
  refusal,
  selectAppends,
  type LaneProtocol,
  type Refusal,
  type RelayTemplate,
  type TemplateRefusalCode,
  type TemplateRegistry,
} from "@gray/lane";
import { buildPolicyInput, parsePolicyOutput, policyInputLength } from "./abi.ts";
import { MAX_FUEL, policyFuel, resolvePolicyLimits, type LaneInputBytes, type LimitsRefusalCode, type PolicyLimitOverrides } from "./limits.ts";
import { policyAllowed, policyBlocked, policyFailed, type PolicyCause, type PolicyResult } from "./outcome.ts";
import { validatePolicyShape, type ModuleRefusalCode } from "./validate.ts";
import { loadPolicyModule, memoryBytesOf, type WasmiCallFailureCode, type WasmiLoadFailureCode, type WasmiSession } from "./wasmi.ts";

/**
 * A policy the gateway can run: one relay, one version, one loaded module, one set of budgets.
 *
 * A fresh instance of the relay's module is created for every request, so nothing the module writes
 * into a global or its memory survives to the next request.
 */
export interface PreparedPolicy {
  readonly relayId: string;
  /** The relay-declared, strictly increasing version a receipt cites. */
  readonly version: bigint;
  /** SHA-256 of the bytes exactly as uploaded: the `module_sha256` a receipt cites. */
  readonly moduleSha256: string;
  /** The fixed part of the fuel formula (`policyFuel`, limits.ts). */
  readonly fuelBase: bigint;
  /** The per-KiB part of the fuel formula. */
  readonly fuelPerKib: bigint;
  /** The lane's request-body caps, in bytes, per protocol (`maxInputBytes` in limits.ts). */
  readonly maxInputBytes: LaneInputBytes;
  readonly maxOutputBytes: number;
  readonly maxStackSlots: number;
  readonly registry: TemplateRegistry;
  /** The loaded module and the interpreter's budgets. */
  readonly session: WasmiSession;
  /**
   * The bytes exactly as uploaded, kept so a wrapper that trapped can be replaced by a new one
   * without the relay having to send them again. They never leave the isolate.
   */
  readonly moduleBytes: Uint8Array;
}

/** The same policy; the name the package used when the wasmi engine was one of two. */
export type WasmiPolicy = PreparedPolicy;

/** What a relay submits, before or after the signature is checked (bundle.ts does that). */
export interface PolicyCandidate {
  readonly relayId: string;
  readonly version: bigint;
  readonly moduleBytes: Uint8Array;
  readonly templates: readonly RelayTemplate[];
}

/** Why a candidate cannot become a policy. */
export type PrepareRefusalCode =
  | ModuleRefusalCode
  | TemplateRefusalCode
  | LimitsRefusalCode
  | "invalid_relay_id"
  | "invalid_version"
  | "too_many_templates"
  | "interpreter_unavailable";

/** The longest relay id this package accepts, and the characters it may hold. */
const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** That the longest 64-bit version is the largest one. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** What preparing a candidate needs besides the candidate. */
export interface PrepareOptions {
  /** Overrides of {@link DEFAULT_POLICY_LIMITS}; all of them are checked. */
  readonly limits?: PolicyLimitOverrides;
  /** The caps of @gray/lane's template registry (its defaults are the review's: 3 items, 8 KiB). */
  readonly maxAppendBytes?: number;
  readonly maxAppendItems?: number;
}

/**
 * Validate, load and cite a candidate: the upload path, once per policy version. Returns the loaded
 * policy, or a closed refusal. A host that has not initialised the interpreter (`initInterpreter`, or
 * importing `@gray/relay-policy/workerd`) is refused here rather than at the first request.
 */
export function preparePolicy(
  candidate: PolicyCandidate,
  options: PrepareOptions = {},
): { readonly ok: true; readonly policy: PreparedPolicy } | Refusal<PrepareRefusalCode> {
  const limits = resolvePolicyLimits(options.limits);
  if (!("maxModuleBytes" in limits)) return limits;
  if (typeof candidate.relayId !== "string" || !RELAY_ID.test(candidate.relayId)) {
    return refusal("invalid_relay_id", "the relay id is empty or holds characters other than [A-Za-z0-9_.:-]");
  }
  if (typeof candidate.version !== "bigint" || candidate.version < 0n || candidate.version > U64_MAX) {
    return refusal("invalid_version", "the policy version is not a u64");
  }
  if (!Array.isArray(candidate.templates)) return refusal("too_many_templates", "the templates are not an array");
  if (candidate.templates.length > limits.maxTemplates) {
    return refusal("too_many_templates", "the bundle registers more templates than the host allows");
  }
  const registry = createTemplateRegistry(candidate.templates, {
    ...(options.maxAppendBytes === undefined ? {} : { maxTotalBytes: options.maxAppendBytes }),
    ...(options.maxAppendItems === undefined ? {} : { maxItems: options.maxAppendItems }),
  });
  if (!registry.ok) return refusal(registry.code, registry.detail);

  const shape = validatePolicyShape(candidate.moduleBytes, limits);
  if (!shape.ok) return refusal(shape.code, shape.detail);
  const loaded = loadPolicyModule(shape.module.bytes, {
    maxMemoryPages: shape.module.memoryPages,
    maxTables: limits.maxTables,
    maxTableElements: limits.maxTableElements,
    maxStackSlots: limits.maxStackSlots,
  });
  if (!loaded.ok) return refusal(wasmiRefusalCode(loaded.code), loaded.detail);
  return {
    ok: true,
    // The policy a host runs is frozen: its limits were resolved once, and a later edit of a field
    // (a `fuelPerKib` the wrapper's i64 cannot carry, say) would become a refusal the relay's module
    // did not cause. Freezing keeps "what was prepared is what runs" true by construction.
    policy: Object.freeze({
      relayId: candidate.relayId,
      version: candidate.version,
      moduleSha256: shape.module.sha256,
      fuelBase: limits.fuelBase,
      fuelPerKib: limits.fuelPerKib,
      maxInputBytes: Object.freeze({ ...limits.maxInputBytes }),
      maxOutputBytes: limits.maxOutputBytes,
      maxStackSlots: limits.maxStackSlots,
      registry,
      session: loaded.session,
      moduleBytes: shape.module.bytes,
    }),
  };
}

/** One request, as the gateway has it at the policy step. */
export interface PolicyRequest {
  readonly protocol: LaneProtocol;
  readonly model: string;
  readonly body: Uint8Array;
}

/**
 * Run one request through one policy: the input, the fuel the formula gives that input, one fresh
 * instance of the module, and strict validation of whatever comes back. Every failure becomes the one
 * fixed outcome of outcome.ts.
 */
export function runPolicy(policy: PreparedPolicy, request: PolicyRequest): PolicyResult {
  // The request's own protocol selects its cap. An unknown protocol is refused by
  // `buildPolicyInput`; the lookup is only there to keep the argument a number.
  const input = buildPolicyInput(request, policy.maxInputBytes[request.protocol] ?? 0);
  if (!input.ok) return policyFailed(input.code);
  // The fuel formula is checked at construction for the largest allowed input, but a hand-built
  // `PreparedPolicy` can still name a budget the wrapper's i64 argument cannot carry. Refuse it
  // here as the host's own fault (`invalid_limit`), not as a module failure — the request must
  // never be `policy_unavailable` because the host's arithmetic overflowed (VERIFY RP-3).
  const fuel = runFuel(input.bytes.length, policy);
  if (fuel === null) return policyFailed("invalid_limit");
  const answer = policy.session.evaluate(input.bytes, {
    fuel,
    maxMemoryBytes: memoryBytesOf(policy.session),
    maxOutputBytes: policy.maxOutputBytes,
    stackSlots: policy.maxStackSlots,
  });
  if (!answer.ok) return policyFailed(wasmiCause(answer.code));
  return decide(policy, request.protocol, answer.output);
}

/**
 * The fuel {@link runPolicy} gives the module for this request, without running it: the formula on
 * the length of the input it would write (`policyInputLength`, the same header function). Null when
 * `runPolicy` would answer before the module runs: an input the ABI refuses, or a budget the
 * wrapper's i64 cannot carry. A host sizes what depends on the budget from it (the lane's policy step
 * deadline and padding, F2 D128); the module never sees it.
 */
export function policyRunFuel(policy: PreparedPolicy, request: PolicyRequest): bigint | null {
  const input = policyInputLength(request, policy.maxInputBytes[request.protocol] ?? 0);
  if (!input.ok) return null;
  return runFuel(input.length, policy);
}

/** `policyFuel` for an input of `inputBytes`, or null when the wrapper's i64 cannot carry it. */
function runFuel(inputBytes: number, policy: PreparedPolicy): bigint | null {
  const fuel = policyFuel(inputBytes, policy);
  return fuel <= 0n || fuel > MAX_FUEL ? null : fuel;
}

/**
 * The tail every policy shares: the output must be the ABI's strict JSON within the cap, and the
 * template ids it names must be the registry's. The emptiness and size checks are the parser's own,
 * so all that can still be wrong here is the document itself: not UTF-8, not strict JSON, or not the
 * ABI's shape.
 */
function decide(policy: PreparedPolicy, protocol: LaneProtocol, output: Uint8Array): PolicyResult {
  const parsed = parsePolicyOutput(output, policy.maxOutputBytes);
  if (!parsed.ok) return policyFailed("invalid_output");
  const selection = selectAppends(policy.registry, protocol, parsed.output);
  if (!selection.ok) return policyFailed(selectionCause(selection.code));
  if (selection.kind === "block") return policyBlocked(selection.reason_code);
  return policyAllowed(selection.appends);
}

/** The interpreter's closed failure codes, as this package's closed causes. */
function wasmiCause(code: WasmiCallFailureCode): PolicyCause {
  switch (code) {
    case "out_of_fuel":
      return "out_of_fuel";
    case "stack":
      return "stack_overflow";
    case "memory":
      return "memory_limit";
    case "output_empty":
      return "output_empty";
    case "output_too_large":
      return "output_too_large";
    case "output_bounds":
      return "output_out_of_bounds";
    case "allocation":
      return "allocation_failed";
    case "trap":
      return "trap";
    case "no_module":
    case "limits":
    case "instance_failed":
      return "instance_failed";
  }
}

/** The wrapper's load refusals, as the module contract's codes. */
function wasmiRefusalCode(code: WasmiLoadFailureCode): PrepareRefusalCode {
  switch (code) {
    case "unparseable":
      return "module_unparseable";
    case "imports":
      return "module_imports";
    case "memory":
      return "module_memory";
    case "tables":
      return "module_tables";
    case "exports":
      return "module_exports";
    case "abi":
      return "module_abi";
    case "start":
      return "module_start";
    case "size":
      return "module_too_large";
    case "limits":
      return "invalid_limit";
    case "allocation":
      return "module_invalid";
    case "instance_failed":
      return "module_instantiate";
    case "interpreter_unavailable":
      return "interpreter_unavailable";
  }
}

/** @gray/lane's refusal codes, as this package's closed causes. */
function selectionCause(code: string): PolicyCause {
  switch (code) {
    case "unknown_template":
      return "unknown_template";
    case "too_many_items":
      return "too_many_items";
    case "append_limit":
      return "append_limit";
    case "template_protocol":
    case "template_position":
      return "template_unavailable";
    default:
      return "invalid_output";
  }
}

/** The interpreter, re-exported so a host hands it over in the same import it uses for the sandbox. */
export { initInterpreter, interpreterReady } from "./wasmi.ts";
