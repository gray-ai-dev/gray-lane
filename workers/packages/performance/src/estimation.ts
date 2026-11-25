/**
 * The buffered estimation (perf-metrics design §4): a route's time to first token and decode rate inferred from the
 * total times of its buffered text answers. Each point is weighed against a reference fit, added into eleven sums, and
 * the sums are merged into a decayed history; a bounded least-squares solve of the history gives the fit, and
 * `estimate` publishes it only when the data can separate the two phases (§4.7).
 *
 * Model: `y' ≈ a + b·E + d·D` with `E = u + κ·c` (effective input), `D = o − 1` (the first token belongs to TTFT),
 * `y' = max(y, o × 1000 / R)` and the bounds `a ≥ 0`, `b ≥ 0`, `d ≥ 1000 / R`. Pure: no I/O, no clock.
 */
import { isTime } from "./period.ts";
import { decayFactor } from "./statistics.ts";

/** One buffered success: uncached input, cache-read input and output tokens, and its latency in ms. Whole numbers. */
export interface EstimationPoint {
  readonly u: number;
  readonly c: number;
  readonly o: number;
  readonly y: number;
}

/** A fit: the fixed wait in ms, ms per effective input token, ms per output token. */
export interface EstimationFit {
  readonly a: number;
  readonly b: number;
  readonly d: number;
}

/**
 * The eleven sums and their clock. `g` is the upper triangle of `Σw·x·xᵀ` with `x = (1, E, D)`, in the order G00, G01,
 * G02, G11, G12, G22; `h` is `Σw·x·y'`; `w2` is `Σw²`; `n` the points ever added (never decayed); `at` the time of the
 * last merge (0 before the first).
 */
export interface EstimationSums {
  readonly g: readonly number[];
  readonly h: readonly number[];
  readonly w2: number;
  readonly n: number;
  readonly at: number;
}

/** Published; too few points (`n` or the effective count under its gate); or the data cannot separate the phases. */
export type EstimationState = "published" | "too_few" | "cannot_separate";

/** What `estimate` gives: the points, the state, the typical TTFT and the decode rate (both null unless published), the fit. */
export interface EstimationResult {
  readonly n: number;
  readonly state: EstimationState;
  readonly ttftMs: number | null;
  readonly tps: number | null;
  readonly fit: EstimationFit | null;
}

/**
 * The estimation's constants (design §4, decisions 5, 6 and 8): the cache-read weight κ, the points for a reference fit
 * and for publication, the effective points, the output spread in tokens, the largest correlation of input and output,
 * the Huber threshold in ms, the largest share of the rate cap a published decode rate may be, the decay of the history (half-life and floor on G00), and the largest token count and
 * latency a point may carry.
 */
export const ESTIMATION = Object.freeze({
  cacheWeight: 0.25,
  referenceMin: 30,
  publishMin: 200,
  effectiveMin: 50,
  outputSdMin: 32,
  corrMax: 0.95,
  huberMs: 1000,
  rateShareMax: 0.99,
  halfLifeMs: 3_600_000,
  floor: 50,
  maxTokens: 10_000_000,
  maxLatencyMs: 86_400_000,
} as const);

/**
 * Whether `value` is a point the estimation takes: four safe whole numbers, `u`, `c` and `o` at most `maxTokens`, `o ≥ 1`,
 * `1 ≤ y ≤ maxLatencyMs`. The check a receiver runs before `weighPoints`, which throws on anything else.
 */
export function isEstimationPoint(value: unknown): value is EstimationPoint {
  if (typeof value !== "object" || value === null) return false;
  const { u, c, o, y } = value as Readonly<Record<string, unknown>>;
  return count(u, ESTIMATION.maxTokens) && count(c, ESTIMATION.maxTokens) && count(o, ESTIMATION.maxTokens) && o >= 1 && count(y, ESTIMATION.maxLatencyMs) && y >= 1;
}

/** Whether `x` is a safe whole number from 0 to `max`. */
function count(x: unknown, max: number): x is number {
  return typeof x === "number" && Number.isSafeInteger(x) && x >= 0 && x <= max;
}

/**
 * Whether `value` has the shape of sums: six and three finite numbers of at least 0, `w2` likewise, `n` a safe whole
 * number from 0 and `at` a time. The check a reader of stored sums runs before handing them to this module.
 */
export function isEstimationSums(value: unknown): value is EstimationSums {
  if (typeof value !== "object" || value === null) return false;
  const { g, h, w2, n, at } = value as Readonly<Record<string, unknown>>;
  const nonNegative = (x: unknown): boolean => typeof x === "number" && Number.isFinite(x) && x >= 0;
  return (
    Array.isArray(g) && g.length === 6 && g.every(nonNegative) && Array.isArray(h) && h.length === 3 && h.every(nonNegative) && nonNegative(w2) && count(n, Number.MAX_SAFE_INTEGER) && typeof at === "number" && isTime(at)
  );
}

/** Sums with nothing in them, at 0. A new object. */
export function emptyEstimationSums(): EstimationSums {
  return { g: [0, 0, 0, 0, 0, 0], h: [0, 0, 0], w2: 0, n: 0, at: 0 };
}

/** The least ms per output token under the cap `maxRateTps`; a RangeError for a cap that is not finite and positive. */
function leastSlope(maxRateTps: number): number {
  if (!(Number.isFinite(maxRateTps) && maxRateTps > 0)) throw new RangeError(`a rate cap is finite and positive: ${maxRateTps}`);
  return 1000 / maxRateTps;
}

/**
 * The plain (undecayed) sums of `points`, each weighed against `reference` (none: weight 1) under the rate cap
 * `maxRateTps`, at `nowMs`. A point's weight is 1 within `huberMs` of the reference's prediction and `huberMs / r` at a
 * residual `r` beyond it (design §4.3). Points add in their order. A RangeError for a point `isEstimationPoint` refuses,
 * a reference that is not three finite numbers, a cap that is not finite and positive, or a time that is not one.
 */
export function weighPoints(points: readonly EstimationPoint[], reference: EstimationFit | null, maxRateTps: number, nowMs: number): EstimationSums {
  leastSlope(maxRateTps);
  if (!isTime(nowMs)) throw new RangeError(`a time is a whole number of milliseconds from 0 to 2^53 - 1: ${nowMs}`);
  if (reference !== null && !(Number.isFinite(reference.a) && Number.isFinite(reference.b) && Number.isFinite(reference.d))) {
    throw new RangeError(`a reference fit is three finite numbers: ${reference.a}, ${reference.b}, ${reference.d}`);
  }
  let g00 = 0, g01 = 0, g02 = 0, g11 = 0, g12 = 0, g22 = 0, h0 = 0, h1 = 0, h2 = 0, w2 = 0;
  for (const point of points) {
    if (!isEstimationPoint(point)) throw new RangeError(`an estimation point is four whole numbers, o and y at least 1: ${JSON.stringify(point)}`);
    const e = point.u + ESTIMATION.cacheWeight * point.c;
    const d = point.o - 1;
    const y = Math.max(point.y, (point.o * 1000) / maxRateTps);
    let w = 1;
    if (reference !== null) {
      const r = Math.abs(y - (reference.a + reference.b * e + reference.d * d));
      if (r > ESTIMATION.huberMs) w = ESTIMATION.huberMs / r;
    }
    g00 += w;
    g01 += w * e;
    g02 += w * d;
    g11 += w * e * e;
    g12 += w * e * d;
    g22 += w * d * d;
    h0 += w * y;
    h1 += w * e * y;
    h2 += w * d * y;
    w2 += w * w;
  }
  return { g: [g00, g01, g02, g11, g12, g22], h: [h0, h1, h2], w2, n: points.length, at: nowMs };
}

/**
 * `add` merged into `held` at `nowMs`: `held` decayed as the long record decays (`decayFactor` on G00 over the time
 * since `held.at`, half-life and floor of `ESTIMATION`; `g` and `h` times the factor, `w2` times its square, `n`
 * untouched), then `add` added; the clock the later of `held.at` and `nowMs`. Without a point in `add`, `held` itself. A
 * new object otherwise; neither input is changed. A RangeError for a time that is not one.
 */
export function mergeEstimationSums(held: EstimationSums, add: EstimationSums, nowMs: number): EstimationSums {
  if (!isTime(nowMs)) throw new RangeError(`a time is a whole number of milliseconds from 0 to 2^53 - 1: ${nowMs}`);
  if (!(add.n > 0)) return held;
  const k = decayFactor(held.g[0]!, held.at, nowMs, ESTIMATION.halfLifeMs, ESTIMATION.floor);
  return {
    g: held.g.map((x, i) => x * k + add.g[i]!),
    h: held.h.map((x, i) => x * k + add.h[i]!),
    w2: held.w2 * (k * k) + add.w2,
    n: held.n + add.n,
    at: Math.max(held.at, nowMs),
  };
}

/** The fit that weighs new points: the bounded solve of `sums` once `n ≥ referenceMin`, else null (or no fit). */
export function referenceFit(sums: EstimationSums, maxRateTps: number): EstimationFit | null {
  const dMin = leastSlope(maxRateTps);
  return sums.n >= ESTIMATION.referenceMin ? solve(sums, dMin) : null;
}

/** The unit roundoff of binary64, 2^−53. */
const UNIT = Number.EPSILON / 2;

/**
 * A bound on the relative error of each stored sum after `n` points (every sum adds terms of one sign): γ_m = m·u / (1 −
 * m·u) for m = 2n + 8 roundings of a term at most. A term takes two in its product, one per later point of its weighing
 * and two per later merge, and a merge adds at least one point.
 */
function sumError(n: number): number {
  const mu = (2 * n + 8) * UNIT;
  return mu < 0.5 ? mu / (1 - mu) : Number.POSITIVE_INFINITY;
}

/**
 * The error bound of a centered second moment read from raw sums whose relative error is at most `err`: the raw
 * moment's size times `6·err + 5u`. For a variance the size is its mean square, for a covariance √ of the two mean
 * squares; it does not shrink with the centered moment, so a small spread on a large mean is not readable.
 */
function momentError(err: number, size: number): number {
  return (6 * err + 5 * UNIT) * size;
}

/** The two variables' centered moments from `sums` and whether each is outside its error bound. */
interface Moments {
  readonly eMean: number;
  readonly dMean: number;
  readonly varE: number;
  readonly varD: number;
  /** The covariance, 0 when it is within its error bound or the input's variance is. */
  readonly cov: number;
  /** Whether the covariance is outside its error bound, whatever the variances. */
  readonly covResolved: boolean;
  readonly eResolved: boolean;
  readonly dResolved: boolean;
}

/**
 * `sums`' centered moments (G00 > 0). A variance within its error bound is unresolved: the variable is read as constant,
 * so an input that varies by less than rounding can show has no correlation and no slope (`solve` holds `b = 0`).
 */
function moments(sums: EstimationSums): Moments {
  const [g00, g01, g02, g11, g12, g22] = sums.g as readonly [number, number, number, number, number, number];
  const err = sumError(sums.n);
  const eMean = g01 / g00;
  const dMean = g02 / g00;
  const e2 = g11 / g00;
  const d2 = g22 / g00;
  const varE = Math.max(0, e2 - eMean * eMean);
  const varD = Math.max(0, d2 - dMean * dMean);
  const eResolved = varE > momentError(err, e2);
  const dResolved = varD > momentError(err, d2);
  const raw = g12 / g00 - eMean * dMean;
  const covResolved = Math.abs(raw) > momentError(err, Math.sqrt(e2 * d2));
  const cov = eResolved && dResolved && covResolved ? raw : 0;
  return { eMean, dMean, varE, varD, cov, covResolved, eResolved, dResolved };
}

/**
 * The estimate of `sums` under the rate cap `maxRateTps` (design §4.7). Published when `n ≥ publishMin`, the effective
 * points `G00² / w2 ≥ effectiveMin`, `sd(D) ≥ outputSdMin` with the output's variance outside its error bound, no
 * readable covariance on an input read as constant, `|ρ(E, D)| ≤ corrMax` (0 for an input read as constant or a
 * covariance within its bound: `moments`), and the fit exists with a decode rate of at most `rateShareMax` of the cap
 * (`d ≥ dMin / rateShareMax`; `solve` puts a slope within its error bound of `dMin` on it) and `a + b·Ē ≥ 1`: then `ttftMs = a +
 * b·Ē` (the TTFT at the typical effective input) and `tps = 1000 / d`. The first two gates give `too_few`, the others
 * `cannot_separate`. `fit` is the bounded solve whatever the state (null: none). A RangeError for a cap that is not
 * finite and positive.
 */
export function estimate(sums: EstimationSums, maxRateTps: number): EstimationResult {
  const dMin = leastSlope(maxRateTps);
  const fit = solve(sums, dMin);
  const n = sums.n;
  const withheld = (state: EstimationState): EstimationResult => ({ n, state, ttftMs: null, tps: null, fit });
  const g00 = sums.g[0]!;
  if (n < ESTIMATION.publishMin || !(g00 > 0) || !(sums.w2 > 0)) return withheld("too_few");
  if ((g00 * g00) / sums.w2 < ESTIMATION.effectiveMin) return withheld("too_few");
  const m = moments(sums);
  if (Math.sqrt(m.varD) < ESTIMATION.outputSdMin || !m.dResolved) return withheld("cannot_separate");
  // An input spread too small to read that still moves with the output: the phases cannot be told apart.
  if (!m.eResolved && m.covResolved) return withheld("cannot_separate");
  const rho = m.cov === 0 ? 0 : m.cov / Math.sqrt(m.varE * m.varD);
  if (Math.abs(rho) > ESTIMATION.corrMax) return withheld("cannot_separate");
  if (fit === null || !(fit.d >= dMin / ESTIMATION.rateShareMax)) return withheld("cannot_separate");
  const ttftMs = fit.a + fit.b * m.eMean;
  if (!(ttftMs >= 1)) return withheld("cannot_separate");
  return { n, state: "published", ttftMs, tps: 1000 / fit.d, fit };
}

/**
 * The candidate sets of bounds held with equality (0: a, 1: b, 2: d), tried in this order; a later feasible candidate
 * replaces the best only when its objective is lower (design §4.5). An input read as constant tries only the sets that
 * hold `b = 0`.
 */
const ACTIVE: readonly (readonly number[])[] = [[], [1], [0], [2], [0, 1], [1, 2], [0, 2], [0, 1, 2]];

/**
 * The minimum of `θᵀGθ − 2hᵀθ` over `a ≥ 0`, `b ≥ 0`, `d ≥ dMin` (design §4.5): for each set of bounds held with
 * equality, the reduced system solved (scaled to a unit diagonal, Cholesky); a singular one skipped, an infeasible or
 * non-finite one dropped; the feasible candidate of least objective kept. Null without one. An input read as constant
 * (`moments`) keeps `b` on its bound. A free slope within its error bound of `dMin` (`solveScaled`, from the sums' error
 * and the system's conditioning) is set to `dMin`, so that `estimate` reads it as on its bound.
 */
function solve(sums: EstimationSums, dMin: number): EstimationFit | null {
  const [g00, g01, g02, g11, g12, g22] = sums.g as readonly [number, number, number, number, number, number];
  if (!(g00 > 0)) return null;
  const G: readonly (readonly number[])[] = [
    [g00, g01, g02],
    [g01, g11, g12],
    [g02, g12, g22],
  ];
  const h = sums.h;
  const err = sumError(sums.n);
  const bFree = moments(sums).eResolved;
  const lower = [0, 0, dMin] as const;
  let best: readonly number[] | null = null;
  let bestObjective = 0;
  for (const active of ACTIVE) {
    if (!bFree && !active.includes(1)) continue;
    const theta = [lower[0], lower[1], lower[2]];
    const free = [0, 1, 2].filter((i) => !active.includes(i));
    if (free.length > 0) {
      const A = free.map((i) => free.map((j) => G[i]![j]!));
      const r = free.map((i) => active.reduce((rest, j) => rest - G[i]![j]! * lower[j]!, h[i]!));
      const size = free.map((i) => active.reduce((rest, j) => rest + G[i]![j]! * lower[j]!, h[i]!));
      const solved = solveScaled(A, r, size, err);
      if (solved === null) continue;
      const { x, dx } = solved;
      const k = free.indexOf(2);
      if (k >= 0 && Math.abs(x[k]! - dMin) <= dx[k]!) x[k] = dMin;
      if (free.some((i, k) => !Number.isFinite(x[k]!) || x[k]! < lower[i]!)) continue;
      free.forEach((i, k) => (theta[i] = x[k]!));
    }
    let quadratic = 0;
    let linear = 0;
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) quadratic += theta[i]! * G[i]![j]! * theta[j]!;
      linear += h[i]! * theta[i]!;
    }
    const objective = quadratic - 2 * linear;
    if (!Number.isFinite(objective)) continue;
    if (best === null || objective < bestObjective) {
      best = theta;
      bestObjective = objective;
    }
  }
  return best === null ? null : { a: best[0]!, b: best[1]!, d: best[2]! };
}

/**
 * `A x = r` for a symmetric `A` of one to three rows with entries of relative error at most `err` and `r` of error at
 * most `err × size`: scaled to a unit diagonal `M`, factored by Cholesky, solved and scaled back; with `dx`, a first-order
 * bound on the error of each `x` that these errors and the conditioning give: `|M⁻¹| (|δq| + |δM| |z|)` for the scaled
 * solution `z`, `|δM| ≤ err'` on every entry, `err' = err + 16u` for the scaling and the factorisation. Null when a
 * diagonal is not positive or a pivot is within that error of 0 (singular).
 */
function solveScaled(A: readonly (readonly number[])[], r: readonly number[], size: readonly number[], err: number): { x: number[]; dx: number[] } | null {
  const m = A.length;
  const e = err + 16 * UNIT;
  const s = A.map((row, i) => Math.sqrt(row[i]!));
  if (s.some((v) => !(v > 0) || !Number.isFinite(v))) return null;
  const L: number[][] = Array.from({ length: m }, () => new Array<number>(m).fill(0));
  for (let j = 0; j < m; j++) {
    let pivot = A[j]![j]! / (s[j]! * s[j]!);
    for (let k = 0; k < j; k++) pivot -= L[j]![k]! * L[j]![k]!;
    if (!(pivot > momentError(err, 1))) return null;
    L[j]![j] = Math.sqrt(pivot);
    for (let i = j + 1; i < m; i++) {
      let v = A[i]![j]! / (s[i]! * s[j]!);
      for (let k = 0; k < j; k++) v -= L[i]![k]! * L[j]![k]!;
      L[i]![j] = v / L[j]![j]!;
    }
  }
  /** `M⁻¹ q` through the factor. */
  const unscale = (q: readonly number[]): number[] => {
    const y = new Array<number>(m).fill(0);
    for (let i = 0; i < m; i++) {
      let v = q[i]!;
      for (let k = 0; k < i; k++) v -= L[i]![k]! * y[k]!;
      y[i] = v / L[i]![i]!;
    }
    const z = new Array<number>(m).fill(0);
    for (let i = m - 1; i >= 0; i--) {
      let v = y[i]!;
      for (let k = i + 1; k < m; k++) v -= L[k]![i]! * z[k]!;
      z[i] = v / L[i]![i]!;
    }
    return z;
  };
  const z = unscale(r.map((v, i) => v / s[i]!));
  const inverse = Array.from({ length: m }, (_, k) => unscale(Array.from({ length: m }, (_, i) => (i === k ? 1 : 0))));
  let zSize = 0;
  for (const v of z) zSize += Math.abs(v);
  const perturbation = size.map((v, j) => e * (v / s[j]!) + e * zSize);
  const dz = Array.from({ length: m }, (_, i) => inverse.reduce((acc, column, j) => acc + Math.abs(column[i]!) * perturbation[j]!, 0));
  return { x: z.map((v, i) => v / s[i]!), dx: dz.map((v, i) => v / s[i]!) };
}
