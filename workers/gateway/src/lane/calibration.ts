import {
  DEFAULT_POLICY_LIMITS,
  LANE_BODY_MAX_BYTES,
  MAX_POLICY_HEADER_BYTES,
  StepSpeedError,
  measureStepSpeed,
  policyFuel,
  sandboxStepSpeedRunner,
  type StepSpeed,
  type StepSpeedMeasurement,
  type StepSpeedRunner,
} from "@gray/relay-policy";
import { policyStepUncappedMs } from "./hooks.ts";

/**
 * The policy step's boot calibration (F2 D128'(c)).
 *
 * The configured `LANE_POLICY_FUEL_PER_MS` and `LANE_POLICY_OVERHEAD_MS` are the build box's
 * measurement (`@gray/relay-policy` bench/policy-step.ts; D128' measurement, 2026-10-22: AMD Ryzen 9
 * 9950X3D, workerd 1.20261006.1). The CVM the lane serves from is another machine, and the step's
 * privacy property (D1/D32/D128: every outcome at one input size takes the same T) needs T to be at
 * least the real time a module that spends its whole budget takes there. So the lane measures again
 * at boot, on its own CPU, with every burn shape the benchmark times (`burn-branch`, `burn-memory`,
 * `burn-call`: which one is slowest depends on the CPU) and the trivial `allow`, all shipped in
 * `@gray/relay-policy` and prepared under the lane's own limits, and builds T from the **slower** rate
 * and the **larger** overhead of the two. A faster calibration never shortens T below the configured
 * one; a slower one lengthens it.
 *
 * A slower one can also make the configured cap (`LANE_POLICY_STEP_MS`) bind: T at the largest input
 * would then be the cap, shorter than a full-budget run there. F2 D130: the boot raises the cap to that
 * input's uncapped T instead (D1 wins over the configured latency bound; failing the boot would take
 * the lane down on a slow CVM for a property it can keep), and logs that it did.
 *
 * The calibration's derivation (`measureStepSpeed`) is conservative where the benchmark's is exact
 * only at the benchmark's large cells: a 1 KiB burn is about 6 ms at the configured rate, so on
 * workerd's 1 ms clock a single reading could be a sixth short, and subtracting a rounded-up overhead
 * from it could make the rate read faster than the machine runs. So each reading spans a group of
 * burns, one clock tick is added to it, nothing is subtracted from it, and the overhead is the trivial
 * module's on the largest body a module is given (it includes that input's copy), plus one tick.
 *
 * A calibration that cannot give both numbers (a module answered something else, the interpreter is
 * missing, the clock did not advance across a group of burns) is a boot failure: the lane serves
 * nothing rather than serve with a rate it did not measure where it runs.
 */

/**
 * Timed groups of burn runs per shape, and runs per group: 10 * 5 = 50 timed runs of each shape and
 * of `allow`, the benchmark's runs per cell (D128' measurement, 2026-10-22: 50 runs per cell). Five
 * runs per group make one reading about 5 * 1,040,000 / 188,401 = 27.6 ms of burning at the
 * configured rate, so one 1 ms tick is under 4% of it, where it was a sixth of a single 1 KiB run.
 *
 * What it costs the first request's boot: 55 `allow` runs on the 4 MiB body (each at most the
 * configured 3 ms overhead on the build box) and 55 runs of each of the three burn shapes on the 1 KiB
 * body (each about 6 ms at the configured rate, the slowest shape's on the build box), so at most
 * about 0.17 s + 3 * 0.33 s, near 1.2 s, on a machine as fast as the build box, longer on a slower one.
 */
export const LANE_CALIBRATION_GROUPS = 10;
export const LANE_CALIBRATION_GROUP_RUNS = 5;

/** Untimed runs of each module before its timed ones: the benchmark's default `--warmup` (bench/policy-step.mjs). */
export const LANE_CALIBRATION_WARMUP = 5;

/** The burn runs' body: 1 KiB, the benchmark's smallest cell (D128'(c)): 1,040,000 fuel under the default limits. */
export const LANE_CALIBRATION_BURN_BODY_BYTES = 1024;

/**
 * The trivial runs' body: the largest a module is given (`LANE_BODY_MAX_BYTES`, 4 MiB, the benchmark's
 * largest cell), so the calibrated overhead covers the input copy at the cap as the configured one does.
 */
export const LANE_CALIBRATION_TRIVIAL_BODY_BYTES = LANE_BODY_MAX_BYTES;

/**
 * The clock's resolution: workerd 1.20261006.1, the image's, advances `performance.now()` in 1 ms
 * steps during a synchronous run (probed 2026-10-22 under the lane's compatibility date and flags; the
 * lane notes' D128' section). A reading can be up to one tick short of what it spans, so one tick is
 * added to every reading. Node's finer clock only makes the addition more conservative.
 */
export const LANE_CALIBRATION_TICK_MS = 1;

/**
 * The most fuel a relay's module is given (F2 D130): the fuel formula under `DEFAULT_POLICY_LIMITS`
 * on the largest ABI input, the 4 MiB body (`LANE_BODY_MAX_BYTES`, which bounds every protocol's
 * `maxInputBytes`) plus the header's bound (`MAX_POLICY_HEADER_BYTES`, 2,048 bytes):
 * 1,000,000 + 20,000 * 4,098 KiB = 82,960,000.
 */
export const LANE_POLICY_MAX_FUEL = policyFuel(LANE_BODY_MAX_BYTES + MAX_POLICY_HEADER_BYTES, DEFAULT_POLICY_LIMITS);

/** The step's settings: its speed and the cap of T (`LANE_POLICY_STEP_MS`, F2 D128). */
export interface LaneStepSettings extends StepSpeed {
  readonly stepMs: number;
}

/** What the boot calibrated and what the step uses: the content-free numbers the boot logs. */
export interface LaneStepCalibration {
  readonly configured: LaneStepSettings;
  readonly calibrated: StepSpeedMeasurement;
  /**
   * What T is computed from: the slower rate and the larger overhead of the two, and the configured
   * cap, or `maxStepMs` when that is larger (F2 D130).
   */
  readonly effective: LaneStepSettings;
  /** The uncapped T of the largest input ({@link LANE_POLICY_MAX_FUEL}) at the effective rate and overhead. */
  readonly maxStepMs: number;
  /** Whether `maxStepMs` is over the configured cap, so the boot raised the cap to it (F2 D130). */
  readonly capBinds: boolean;
}

/** A calibration that failed: the lane does not boot (F2 D128'(c)). */
export class LaneCalibrationError extends Error {
  override readonly name = "LaneCalibrationError";
}

/** The slower fuel rate and the larger overhead of two measurements: never a faster rate than either measured. */
export function slowerStepSpeed(left: StepSpeed, right: StepSpeed): StepSpeed {
  return { fuelPerMs: Math.min(left.fuelPerMs, right.fuelPerMs), overheadMs: Math.max(left.overheadMs, right.overheadMs) };
}

/** What a calibration runs on; production takes the real sandbox and `performance.now`, a test its own. */
export interface LaneCalibrationOptions {
  /** The modules' runs; `@gray/relay-policy`'s sandbox runner on the two calibration bodies under the lane's limits by default. */
  readonly runner?: () => StepSpeedRunner;
  /** The clock, in ms; `performance.now()` by default (the benchmark's clock). */
  readonly clock?: () => number;
}

/**
 * Calibrate the step on this machine and combine the result with the configured settings. Throws a
 * {@link LaneCalibrationError} naming what failed (never a value from a binding); the caller fails
 * the boot with it.
 *
 * The limits are `DEFAULT_POLICY_LIMITS`, the ones `createLanePolicyStore` prepares every relay's
 * module under, so the burn spends exactly the budget a relay's module gets for the same input.
 *
 * The cap (F2 D130): the uncapped T of the largest input at the effective rate and overhead is
 * `maxStepMs`; when it is over the configured cap, the effective cap is `maxStepMs`, so the cap never
 * cuts T below a full-budget run at any size. At the configured settings it is ceil(82,960,000 /
 * 188,401) + 3 = 444 ms, under the 1,500 ms cap.
 */
export function calibrateLaneStep(configured: LaneStepSettings, options: LaneCalibrationOptions = {}): LaneStepCalibration {
  const clock = options.clock ?? (() => performance.now());
  let calibrated: StepSpeedMeasurement;
  try {
    const runner =
      options.runner === undefined
        ? sandboxStepSpeedRunner({ burnBytes: LANE_CALIBRATION_BURN_BODY_BYTES, trivialBytes: LANE_CALIBRATION_TRIVIAL_BODY_BYTES }, DEFAULT_POLICY_LIMITS)
        : options.runner();
    calibrated = measureStepSpeed(runner, {
      groups: LANE_CALIBRATION_GROUPS,
      groupRuns: LANE_CALIBRATION_GROUP_RUNS,
      warmup: LANE_CALIBRATION_WARMUP,
      tickMs: LANE_CALIBRATION_TICK_MS,
      clock,
    });
  } catch (thrown) {
    const reason = thrown instanceof StepSpeedError ? thrown.message : thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : "a non-error value was thrown";
    throw new LaneCalibrationError(`the policy step calibration failed: ${reason}`);
  }
  const speed = slowerStepSpeed(configured, calibrated);
  const maxStepMs = Number(policyStepUncappedMs({ policyFuelPerMs: speed.fuelPerMs, policyOverheadMs: speed.overheadMs }, LANE_POLICY_MAX_FUEL));
  const capBinds = maxStepMs > configured.stepMs;
  return { configured, calibrated, effective: { ...speed, stepMs: capBinds ? maxStepMs : configured.stepMs }, maxStepMs, capBinds };
}

/** The boot's one log line about the calibration: numbers only, nothing of a request or a binding. */
export function calibrationLogLine(calibration: LaneStepCalibration): string {
  return JSON.stringify({
    level: "info",
    event: "lane_policy_step_calibrated",
    configured_fuel_per_ms: calibration.configured.fuelPerMs,
    configured_overhead_ms: calibration.configured.overheadMs,
    calibrated_fuel_per_ms: calibration.calibrated.fuelPerMs,
    calibrated_overhead_ms: calibration.calibrated.overheadMs,
    calibrated_trivial_max_ms: calibration.calibrated.trivialMaxMs,
    calibrated_burn_fuel: calibration.calibrated.burnFuel.toString(),
    calibrated_burns: calibration.calibrated.burns.map((burn) => ({ module: burn.module, slowest_group_ms: burn.slowestGroupMs, fuel_per_ms: burn.fuelPerMs })),
    groups: calibration.calibrated.groups,
    group_runs: calibration.calibrated.groupRuns,
    tick_ms: calibration.calibrated.tickMs,
    fuel_per_ms: calibration.effective.fuelPerMs,
    overhead_ms: calibration.effective.overheadMs,
    // F2 D130: the uncapped T of the largest input, and whether it raised the configured cap.
    max_step_ms: calibration.maxStepMs,
    cap_binds: calibration.capBinds,
  });
}
