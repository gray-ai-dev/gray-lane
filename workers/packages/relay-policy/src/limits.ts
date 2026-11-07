/**
 * The budgets every relay policy module is held to, and the defaults of §3.4 of IMPLEMENTATION_NOTES.
 *
 * They are parameters, not constants read from @gray/config: this package is pure code and keeps no
 * tunables of its own (workers/README.md, "可调的值都进 @gray/config"). The gateway passes what
 * @gray/config gave it; a test passes what it wants to hold a rule to. {@link DEFAULT_POLICY_LIMITS}
 * is what happens when the host passes nothing. The package therefore chose constructor options with
 * documented defaults instead of @gray/config rows: a pure package cannot read env, and a Worker that
 * wires @gray/config's values in passes them to `preparePolicy`.
 *
 * Two of these bound the module rather than the host, and both are checked before a byte of the
 * module runs: `maxMemoryPages` (the memory's declared maximum, 1024 pages = 64 MiB by default) and
 * `maxStackSlots`. The others bound the host: the upload's size, the body the module sees, the
 * output it may return, the templates a relay may register, and the fuel budget.
 */
import { requestLimit } from "@gray/limits";
import { LANE_PROTOCOLS, isLaneProtocol, refusal, type LaneProtocol, type Refusal } from "@gray/lane";
import { MAX_POLICY_HEADER_BYTES } from "./abi.ts";

/** The lane's hard request-body cap for each protocol it serves. */
export type LaneInputBytes = Readonly<Record<LaneProtocol, number>>;

/**
 * The confidential lane's own request-body cap for v1: 4 MiB, `@gray/config`'s
 * `BODY_PARSE_MAX_BYTES` default (`bodyParseMaxBytes`). The lane holds a body in memory while it
 * decides it — and a policy input is exactly that — so this is the most the policy step is asked
 * to take. It is what bounds `maxInputBytes` below together with each protocol's own
 * `requestLimit`: the lane's cap is the smaller of the two for every protocol it serves, so a
 * request that reaches a policy module always fits inside the guest memory the defaults allow.
 */
export const LANE_BODY_MAX_BYTES = 4 * 1024 * 1024;

/** One module's budgets, in the units each one is measured in. */
export interface PolicyLimits {
  /** The largest uploaded module: `WebAssembly.Module` bytes, 4 MiB by default. */
  readonly maxModuleBytes: number;
  /** The largest memory a module may declare, in 64 KiB pages: 1024 = 64 MiB by default. */
  readonly maxMemoryPages: number;
  /** The most tables a module may declare: 2 by default (one for indirect calls, one reserved). */
  readonly maxTables: number;
  /** The most elements all of a module's tables may declare (a table's maximum, or its minimum). */
  readonly maxTableElements: number;
  /**
   * The largest request body the host writes into one policy input, per lane protocol. Each cap is
   * at most {@link LANE_MAX_INPUT_BYTES} for its protocol — the smaller of the vendor's request
   * limit and the lane's own 4 MiB body cap — so a body the lane accepts is never refused by the
   * policy layer alone.
   */
  readonly maxInputBytes: LaneInputBytes;
  /** The largest output JSON a module may return: 4 KiB by default (the ABI's own cap). */
  readonly maxOutputBytes: number;
  /** The fixed part of one evaluation's fuel budget, in wasmi fuel: 1,000,000 by default. */
  readonly fuelBase: bigint;
  /** The part that grows with the input, in wasmi fuel per 1 KiB (rounded up): 20,000 by default. */
  readonly fuelPerKib: bigint;
  /** The stack budget in value slots the interpreter's engine maps to stack and frames: 65,536. */
  readonly maxStackSlots: number;
  /** The most templates one policy bundle may register: 256 by default. */
  readonly maxTemplates: number;
}

/**
 * What a host may override. `maxInputBytes` is a partial map so a caller can lower one protocol's cap
 * without restating the others; every cap it does not name keeps its default.
 */
export type PolicyLimitOverrides = Partial<Omit<PolicyLimits, "maxInputBytes">> & {
  readonly maxInputBytes?: Partial<LaneInputBytes>;
};

/** 64 KiB: one WebAssembly memory page. */
export const WASM_PAGE_BYTES = 65_536;

/** The largest fuel count the wrapper's i64 argument can carry. */
export const MAX_FUEL = 0x7fff_ffff_ffff_ffffn;

/**
 * The working room a module is assumed to need on top of the input it is handed: its static data,
 * its allocator's bookkeeping and its output buffer. 1 MiB is generous for a decision policy (the
 * fixtures use under 64 KiB); the point of the constant is that `resolvePolicyLimits` must never
 * allow a `maxInputBytes + MAX_POLICY_HEADER_BYTES` that could only just fill the memory cap and
 * leave the module nothing.
 */
export const MODULE_WORKING_BYTES = 1024 * 1024;

/**
 * The policy layer's hard request-body caps, one per protocol:
 *
 *     min(protocol's @gray/limits requestLimit, LANE_BODY_MAX_BYTES)
 *
 * The vendor caps are `anthropic_messages` 32 MiB and `open_ai_chat`/`open_ai_responses` 512 MiB;
 * the lane's own v1 body cap of 4 MiB ({@link LANE_BODY_MAX_BYTES}) is below both, so every
 * protocol's policy cap is 4 MiB. A request the lane accepts is therefore never refused only
 * because the policy layer used another protocol's smaller cap — and, just as important, the ABI
 * input (cap + header) always fits inside the guest memory the memory cap allows, which the
 * `requestLimit`-alone version of this table could not promise (VERIFY-relay-policy RP-1). A body
 * over its protocol's cap is the fixed `policy_unavailable`, never a truncated input (see
 * abi.md §3). The fuel formula is evaluated on the actual input, so the budget follows the same cap.
 */
export const LANE_MAX_INPUT_BYTES: LaneInputBytes = Object.freeze(
  Object.fromEntries(
    LANE_PROTOCOLS.map((protocol) => [protocol, Math.min(Number(requestLimit(protocol)), LANE_BODY_MAX_BYTES)]),
  ) as Record<LaneProtocol, number>,
);

/**
 * The defaults.
 *
 * The memory cap is the review's recommendation (review.md §1.3: 64 MiB); the body caps are the
 * lane's (see {@link LANE_MAX_INPUT_BYTES}); the fuel budget is the measurement of a module that
 * reads every byte (`test/timing.test.ts`, IMPLEMENTATION_NOTES §7.3): 17,425 fuel per KiB in wasmi.
 * `fuelPerKib` of 20,000 is 1.148x that, so the formula covers one pass over the whole body with
 * room for a decision. `fuelBase` of 1,000,000 (F2 D128', 2026-10-22; 10,000,000 before) covers the
 * header, the allocator and the trampoline: the golden vectors (`test/fixtures/vectors.json`,
 * `fuel_base` 1000000) run the reference modules — allow, block and template selection — under
 * exactly that base, and it is about 57 KiB of scanning on its own. The base is what a small prompt's
 * policy step waits for (the lane pads the step to the time the whole budget takes), so it is kept
 * at what the reference modules need rather than ten times that.
 */
export const DEFAULT_POLICY_LIMITS: PolicyLimits = Object.freeze({
  maxModuleBytes: 4 * 1024 * 1024,
  maxMemoryPages: 1024,
  maxTables: 2,
  maxTableElements: 1024,
  maxInputBytes: LANE_MAX_INPUT_BYTES,
  maxOutputBytes: 4096,
  fuelBase: 1_000_000n,
  fuelPerKib: 20_000n,
  maxStackSlots: 65_536,
  maxTemplates: 256,
});

/** Why a set of limits is not usable. */
export type LimitsRefusalCode = "invalid_limit";

/** The largest page count a 32-bit memory can declare (4 GiB). */
const MAX_PAGES = 65_536;

/**
 * The fuel one evaluation of an `inputBytes`-byte ABI input may spend:
 *
 *     fuel = fuelBase + fuelPerKib * ceil(inputBytes / 1024)
 *
 * `inputBytes` is the whole input the host writes (header, newline and body), so the budget grows
 * with exactly the bytes a scanning policy reads. The multiplication is exact bigint arithmetic: the
 * count never rounds to a float and never wraps.
 */
export function policyFuel(inputBytes: number, limits: Pick<PolicyLimits, "fuelBase" | "fuelPerKib">): bigint {
  const kib = (BigInt(inputBytes) + 1023n) / 1024n;
  return limits.fuelBase + limits.fuelPerKib * kib;
}

/**
 * Fill in the defaults and hold every number to its range. A host that asks for a budget this
 * package cannot enforce (0, a fraction, a negative fuel count, a memory over 4 GiB, a body over its
 * protocol's lane cap) is refused instead of being clamped, as @gray/config refuses a var out of
 * range. The fuel formula must also fit the wrapper's i64 at the largest input the limits allow, so
 * no request can overflow it.
 */
export function resolvePolicyLimits(overrides: PolicyLimitOverrides = {}): PolicyLimits | Refusal<LimitsRefusalCode> {
  const base = withoutUndefined(overrides);
  const inputs: Record<LaneProtocol, number> = { ...LANE_MAX_INPUT_BYTES };
  for (const [protocol, value] of Object.entries(overrides.maxInputBytes ?? {})) {
    if (!isLaneProtocol(protocol)) return refusal("invalid_limit", `${protocol} is not one of the lane's protocols`);
    if (value !== undefined) inputs[protocol] = value as number;
  }

  const limits: PolicyLimits = {
    maxModuleBytes: base.maxModuleBytes ?? DEFAULT_POLICY_LIMITS.maxModuleBytes,
    maxMemoryPages: base.maxMemoryPages ?? DEFAULT_POLICY_LIMITS.maxMemoryPages,
    maxTables: base.maxTables ?? DEFAULT_POLICY_LIMITS.maxTables,
    maxTableElements: base.maxTableElements ?? DEFAULT_POLICY_LIMITS.maxTableElements,
    maxInputBytes: inputs,
    maxOutputBytes: base.maxOutputBytes ?? DEFAULT_POLICY_LIMITS.maxOutputBytes,
    fuelBase: base.fuelBase ?? DEFAULT_POLICY_LIMITS.fuelBase,
    fuelPerKib: base.fuelPerKib ?? DEFAULT_POLICY_LIMITS.fuelPerKib,
    maxStackSlots: base.maxStackSlots ?? DEFAULT_POLICY_LIMITS.maxStackSlots,
    maxTemplates: base.maxTemplates ?? DEFAULT_POLICY_LIMITS.maxTemplates,
  };

  const counts: readonly (keyof PolicyLimits)[] = [
    "maxModuleBytes",
    "maxMemoryPages",
    "maxTables",
    "maxTableElements",
    "maxOutputBytes",
    "maxStackSlots",
    "maxTemplates",
  ];
  for (const name of counts) {
    const value = limits[name];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
      return refusal("invalid_limit", `${name} is not a positive integer`);
    }
  }
  if (limits.maxMemoryPages > MAX_PAGES) return refusal("invalid_limit", `maxMemoryPages is over ${MAX_PAGES}`);
  if (limits.maxStackSlots > 0x7fff_ffff) return refusal("invalid_limit", "maxStackSlots does not fit an i32");
  if (limits.maxOutputBytes > 1024 * 1024) return refusal("invalid_limit", "maxOutputBytes is over 1 MiB");
  for (const protocol of LANE_PROTOCOLS) {
    const value = inputs[protocol];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
      return refusal("invalid_limit", `maxInputBytes.${protocol} is not a positive integer`);
    }
    if (value > LANE_MAX_INPUT_BYTES[protocol]) {
      return refusal("invalid_limit", `maxInputBytes.${protocol} is over the lane's ${LANE_MAX_INPUT_BYTES[protocol]}-byte cap`);
    }
  }
  for (const name of ["fuelBase", "fuelPerKib"] as const) {
    const value = limits[name];
    if (typeof value !== "bigint" || value <= 0n || value > MAX_FUEL) {
      return refusal("invalid_limit", `${name} is not a positive i64`);
    }
  }
  // The largest input the limits allow must fit inside the memory the module may declare, or every
  // request over that size would be refused inside the sandbox (the whole ABI input lives in the
  // guest's memory). The bound is `cap + header + margin` against the host's page cap; the module's
  // own allocator and data come out of the margin, so a module that declares less than the host's
  // cap can still refuse a large request its memory cannot hold — that refusal is the module's own,
  // not the policy layer's.
  const memoryBudget = limits.maxMemoryPages * WASM_PAGE_BYTES;
  for (const protocol of LANE_PROTOCOLS) {
    const largest = inputs[protocol] + MAX_POLICY_HEADER_BYTES + MODULE_WORKING_BYTES;
    if (largest > memoryBudget) {
      return refusal(
        "invalid_limit",
        `maxMemoryPages (${limits.maxMemoryPages}) cannot hold the largest ${protocol} input plus the module's ${MODULE_WORKING_BYTES}-byte margin`,
      );
    }
  }
  // The worst case the limits allow: each protocol's largest body plus the ABI's header bound.
  for (const protocol of LANE_PROTOCOLS) {
    if (policyFuel(inputs[protocol] + MAX_POLICY_HEADER_BYTES, limits) > MAX_FUEL) {
      return refusal("invalid_limit", "the fuel formula is over an i64 at the largest input the limits allow");
    }
  }
  return Object.freeze({ ...limits, maxInputBytes: Object.freeze({ ...inputs }) });
}

function withoutUndefined(overrides: PolicyLimitOverrides): Omit<PolicyLimitOverrides, "maxInputBytes"> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(overrides)) {
    if (key !== "maxInputBytes" && value !== undefined) out[key] = value;
  }
  return out as Omit<PolicyLimitOverrides, "maxInputBytes">;
}
