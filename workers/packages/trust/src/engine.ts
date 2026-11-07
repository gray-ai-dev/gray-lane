/**
 * The regular-expression engine: Rust's `regex` crate itself, built to WebAssembly from rregex
 * 1.13.1's source (regex 1.13.1, regex-syntax 0.8.11: the versions Cargo.lock pins for the server's
 * jsonschema). Using the reference engine makes the tool gate accept, refuse and match patterns
 * exactly as the Rust gateway does: no look-around, no backreferences, Unicode classes and word
 * boundaries as Rust reads them, and matching in linear time, so no pattern can spend the isolate's
 * CPU backtracking (docs/cloudflare-native.md 6.3; docs/cloudflare-native/trust.md section 3 has the
 * measurements behind choosing it over re2js).
 *
 * The build is workers/vendor/rregex-nowee (its README and build.sh): the npm package's source and
 * toolchain without the `wee_alloc` allocator, which never reused freed memory (RUSTSEC-2022-0054),
 * and with the module importing its memory, so each instance here gets a memory with a maximum.
 * Freed memory is now reused: 20,000 compile-and-free cycles of a small pattern grew the npm build by
 * 345 MiB and grow this one by 64 KiB (trust.md section 3.2).
 *
 * Four kinds of instance, all of the same module, none given more than `regexInstanceMaxBytes()`:
 *
 * - The builder and build instances (`buildRust`), where a pattern's compile is decided. The builder,
 *   one per isolate and used again, has 1 MiB of room, which ordinary patterns fit; a pattern that
 *   does not fit it gets a new build instance, whose memory may grow by at most the compile budget
 *   (`configureRegexEngine`, the gateway's TRUST_REGEX_COMPILE_MAX_BYTES). A compile that would grow it
 *   further fails its allocation and traps, and the pattern is refused, as Rust refuses a pattern past
 *   its size limit (at admission `trust_invalid_tool_schema`). A fresh instance makes the outcome the
 *   same in every isolate, and what it grew by is the compile's peak, which is what the pattern is
 *   charged in the cache.
 * - The prober (`parseRust`), one per isolate and used again: it only parses. The probed pattern
 *   follows a group regex-syntax translates to an error (`PROBE_PREFIX`), so the engine stops right
 *   after parsing and never compiles; parsing needs no fresh instance to decide the same everywhere.
 * - The isolate's instance (`matchRust`), which holds compiled patterns in a cache of the most
 *   recently used, bounded by their charged bytes (`REGEX_CACHE_MAX_BYTES`). A pattern that falls out
 *   is freed, and its memory serves the next compile. Before every match it is checked: grown past
 *   its start and the cache (fragmentation, the search caches each compiled pattern keeps), it is
 *   dropped and a new one started, and patterns compile again as they are used. A text that would
 *   grow it past that is matched in an instance of its own.
 * - Any instance that traps (`unreachable` from a panic or a failed allocation, an out-of-bounds
 *   access, a stack overflow) is dropped: its stack pointer and heap are no longer sound. A trap of
 *   the isolate's instance throws `RegexEngineTrapped`; at admission the gateway answers it 429
 *   `gateway_capacity`, which the client may retry. The next call starts a fresh instance.
 *
 * A dropped instance's memory is only given back when V8 collects it, and V8 does not count wasm
 * memory towards its own collection triggers (trust.md section 3.3: workerd left ten dropped build
 * instances uncollected for more than a minute). So the engine counts the dropped instances' memory until their collection is
 * reported (`FinalizationRegistry`) and starts no new one for a request while they hold
 * `regexPendingMaxBytes()`. What a request (or an answer) makes the engine do is charged to it
 * (`withCompileAllowance`), so one request cannot keep the isolate compiling.
 *
 * The wasm module must be given once per isolate before the first pattern is compiled: a Worker
 * imports `@gray/trust/workerd`, which hands over the module wrangler compiled at upload (Workers do
 * not compile wasm from bytes at run time); Node passes the file's bytes to `initRegexEngine`.
 */
import { type RRegexGlue, createRRegex } from "../../../vendor/rregex-nowee/factory.js";
import { Recent, RECENT_KEY_UNITS } from "./recent.ts";

type RRegex = InstanceType<RRegexGlue["RRegex"]>;

const PAGE = 65_536;
const MiB = 1024 * 1024;

/**
 * The pages the module declares as its memory's minimum (wasm-bindgen's glue creates its default
 * memory with `initial: 23`): 1.44 MiB, the 1 MiB stack plus static data. Each instance starts here.
 */
export const REGEX_INSTANCE_BYTES = 23 * PAGE;

/**
 * The default budget of one compile: 10 MiB. Measured in a fresh instance of this build
 * (docs/cloudflare-native/trust.md section 3.2): the patterns of real tool schemas peak at 64 KiB
 * (one page: `^[a-z]{1,40}$`, a UUID, a date) and a Unicode `.` at 320 KiB; `x{65535}`, the largest
 * counted repetition regex-syntax accepts, at 9.3 MiB, so every pattern of the trust-schema fixtures
 * decides as Rust does. `^\p{L}{150}$` (which Rust accepts) peaks at 20.5 MiB, and patterns Rust
 * refuses for size at up to 50 MiB before refusing; those are what the budget stops.
 */
export const REGEX_COMPILE_MAX_BYTES_DEFAULT = 10 * MiB;

/**
 * The least compile budget, the default: below it `x{65535}` (9.3 MiB), which the trust-schema
 * fixtures expect accepted as Rust accepts it, would be refused. The budget only decides builds;
 * whether a pattern parses is decided apart from it (`parseRust`).
 */
export const REGEX_COMPILE_MIN_BYTES = REGEX_COMPILE_MAX_BYTES_DEFAULT;

/**
 * The compiled patterns the isolate's instance keeps, by the peak each compile measured: 16 MiB.
 * Every pattern a compile budget allows fits (the budget's maximum is this, @gray/config), and at the
 * 64 KiB an ordinary pattern is charged it holds 256 of them, more than the patterns of all the tool
 * schemas of a busy isolate's agents (the trust-schema fixtures' 305 patterns are written to cover
 * every construct, not to be typical). A charge is the compile's peak, and what a compiled pattern
 * holds is a third to a half of it (^\p{L}{150}$: 7.4 of 20.5 MiB), so the cache holds less than it
 * is charged.
 */
export const REGEX_CACHE_MAX_BYTES = 16 * MiB;

/**
 * Room for one search's own caches, past the text it copies in: 4.25 MiB, regex 1.13.1's defaults:
 * a lazy DFA's cache is at most 2 MiB (`RegexBuilder::dfa_size_limit`, regex-automata 0.4.16
 * `meta::Config::get_hybrid_cache_capacity`), a regex keeps a forward and a reverse one, and the
 * bounded backtracker's visited set is at most 256 KiB (`backtrack::Config::get_visited_capacity`).
 * Measured: at most 1.56 MiB past the text over the 318 patterns of the trust-schema fixtures and
 * section 3.2, each searched in six 4 KB to 1 MiB texts (trust.md section 3.3).
 */
export const REGEX_SEARCH_BYTES = 2 * 2 * MiB + 256 * 1024;

let module: WebAssembly.Module | undefined;
let compileMax = REGEX_COMPILE_MAX_BYTES_DEFAULT;

/**
 * The most memory any instance of the engine is given: its start, the cache, one compile and one
 * search's caches, 1.44 + 16 + 10 + 4.25 = 31.7 MiB at the default budget. The isolate's instance has
 * this maximum, and so has an instance a pattern or a text gets on its own.
 */
export function regexInstanceMaxBytes(): number {
  return REGEX_INSTANCE_BYTES + REGEX_CACHE_MAX_BYTES + compileMax + REGEX_SEARCH_BYTES;
}

/**
 * What dropped instances may hold, awaiting V8's collection, before the engine starts no new
 * instance for a request: 16 MiB, as much as the cache. The last one started may pass it, so they hold
 * less than that plus one instance (`regexInstanceMaxBytes`): 47.7 MiB. Ordinary patterns never get
 * here (the builder and the prober are used again); what does is a pattern whose compile needs more
 * than 1 MiB, a text or a probe that needs an instance of its own, a prober a long probe trapped
 * (`mayTrapProber`), a builder such a pattern trapped (`mayStartBuilder`), and a replaced instance.
 */
export function regexPendingMaxBytes(): number {
  return REGEX_CACHE_MAX_BYTES;
}

/** Instantiates nothing yet: keeps rregex's compiled module (or compiles its bytes, outside Workers). Idempotent. */
export function initRegexEngine(wasm: WebAssembly.Module | BufferSource): void {
  if (module !== undefined) return;
  // Workers' types declare the constructor abstract: workerd refuses to compile wasm at run time.
  const compile = WebAssembly.Module as unknown as new (bytes: BufferSource) => WebAssembly.Module;
  module = wasm instanceof WebAssembly.Module ? wasm : new compile(wasm);
}

export function regexEngineReady(): boolean {
  return module !== undefined;
}

/**
 * Sets the budget of one compile, in bytes (the gateway's TRUST_REGEX_COMPILE_MAX_BYTES). What was
 * decided under the old budget is forgotten and the instances started again.
 */
export function configureRegexEngine(options: { readonly compileMaxBytes: number }): void {
  const bytes = options.compileMaxBytes;
  if (!Number.isSafeInteger(bytes) || bytes < REGEX_COMPILE_MIN_BYTES || bytes > REGEX_CACHE_MAX_BYTES) {
    throw new RangeError(`the regex compile budget must be ${REGEX_COMPILE_MIN_BYTES} to ${REGEX_CACHE_MAX_BYTES} bytes, not ${bytes}`);
  }
  if (bytes === compileMax) return;
  compileMax = bytes;
  built.resize(0);
  built.resize(builtKeyUnits);
  dropMain();
  dropProber();
  dropBuilder();
}

/**
 * The regex engine cannot decide now. Not a finding about the request: at admission the gateway
 * answers 429 `gateway_capacity` (retryable); after admission the check that met it fails.
 */
export class RegexEngineUnavailable extends Error {}

/** The engine trapped (a panic, a failed allocation, a stack overflow); the isolate's next call uses a new instance. */
export class RegexEngineTrapped extends RegexEngineUnavailable {
  override readonly name = "RegexEngineTrapped";

  constructor(cause: unknown) {
    super(`the regex engine trapped and was restarted: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
  }
}

/**
 * The request (or answer) spent its compile allowance (`withCompileAllowance`), or the instances the
 * engine dropped are not collected yet (`regexPendingMaxBytes`).
 */
export class RegexEngineBusy extends RegexEngineUnavailable {
  override readonly name = "RegexEngineBusy";

  constructor(reason: string) {
    super(`the regex engine is busy: ${reason}`);
  }
}

/**
 * A text the engine cannot match within `regexInstanceMaxBytes()`, even in an instance of its own
 * (the text, copied in, plus its pattern's compile and one search's caches). Deterministic: the same
 * pattern and text are refused in every isolate.
 */
export class RegexTextTooLong extends RegexEngineUnavailable {
  override readonly name = "RegexTextTooLong";
}

/**
 * What one request's admission, or one answer's checks, may make the engine do, in bytes: 128 MiB.
 * Charged: a compile in the builder what it grew the builder by (at least a page), each build
 * instance's whole memory at the end (its start and its growth; a compile stopped by the budget, its
 * start and the budget), each compile in the isolate's instance its pattern's charge, each probe
 * `probeCharge`, each instance a pattern or a text gets on its own its whole memory. Work takes time in proportion to what it allocates: at most 3.2 ms per MiB charged,
 * measured on this build in Node at load 21 (docs/cloudflare-native/trust.md section 3.3), so the
 * allowance holds a request's regex work in the isolate to about 0.4 s plus one compile, the order of
 * the schema compile budget (TRUST_SCHEMA_COMPILE_BUDGET_MS). Without it, a request could make the
 * isolate compile thousands of large patterns, each refused only after its compile, or recompile two
 * large patterns that evict each other for every row of a long argument.
 */
export const REGEX_REQUEST_COMPILE_BYTES = 128 * MiB;

/** What is left of a request's (or answer's) compile allowance. */
export interface CompileAllowance {
  left: number;
}

export function compileAllowance(): CompileAllowance {
  return { left: REGEX_REQUEST_COMPILE_BYTES };
}

let allowance: CompileAllowance | undefined;

/**
 * Runs `run` with the engine's work charged to `spend`; once nothing is left, the next piece of work
 * throws `RegexEngineBusy` instead of starting. Patterns this isolate already decided and keeps
 * compiled cost nothing. Within a call that already has an allowance, that one is kept.
 */
export function withCompileAllowance<T>(spend: CompileAllowance, run: () => T): T {
  if (allowance !== undefined) return run();
  allowance = spend;
  try {
    return run();
  } finally {
    allowance = undefined;
  }
}

/**
 * The allowance work is charged to now (`withCompileAllowance`), undefined outside one: one request's
 * admission, or one answer's checks (src/policy.ts `ToolSchemas`). src/pattern.ts keeps an answer's
 * own translations by it, so they last as long as the answer's checks.
 */
export function currentCompileAllowance(): CompileAllowance | undefined {
  return allowance;
}

/** Throws `RegexEngineBusy` when the current allowance is spent. */
function mayWork(): void {
  if (allowance !== undefined && allowance.left <= 0) throw new RegexEngineBusy(`the request spent its ${REGEX_REQUEST_COMPILE_BYTES} bytes of regex work`);
}

function charge(bytes: number): void {
  if (allowance !== undefined) allowance.left -= bytes;
}

/** A trap of the instance, as opposed to the error `regex` returns for a pattern. */
function isTrap(error: unknown): boolean {
  return error instanceof WebAssembly.RuntimeError || error instanceof RangeError;
}

interface Instance {
  readonly glue: RRegexGlue;
  readonly memory: WebAssembly.Memory;
}

/** Dropped instances' memory not yet reported collected, in bytes. */
let pending = 0;
const collected = new FinalizationRegistry<number>((bytes) => {
  pending -= bytes;
});

/** The instance is never called again; its memory counts as pending until V8 reports it collected. */
function retire(instance: Instance): void {
  const bytes = instance.memory.buffer.byteLength;
  pending += bytes;
  collected.register(instance.memory, bytes);
}

const counters = { mainStarts: 0, evictions: 0, instances: 0, busy: 0, probes: 0 };

/** A new instance whose memory may grow to `maxBytes`. Throws `RegexEngineTrapped` when the isolate cannot give it one. */
function instantiate(maxBytes: number): Instance {
  if (module === undefined) throw new Error("@gray/trust: the regex engine is not initialised (initRegexEngine)");
  const wasm = module;
  try {
    const memory = new WebAssembly.Memory({ initial: REGEX_INSTANCE_BYTES / PAGE, maximum: Math.floor(maxBytes / PAGE) });
    const glue = createRRegex();
    glue.initSync({ module: wasm, memory });
    counters.instances += 1;
    return { glue, memory };
  } catch (error) {
    if (isTrap(error)) throw new RegexEngineTrapped(error);
    throw error;
  }
}

/**
 * A new instance for the current request, which will be dropped after one use: refused with
 * `RegexEngineBusy` while dropped instances hold `regexPendingMaxBytes()` or more. Outside a request
 * (the operator's policy, compiled at configuration) nothing is refused.
 */
function instantiateForRequest(maxBytes: number): Instance {
  mayWork();
  if (allowance !== undefined && pending >= regexPendingMaxBytes()) {
    counters.busy += 1;
    throw new RegexEngineBusy(`dropped regex instances hold ${pending} bytes awaiting collection`);
  }
  return instantiate(maxBytes);
}

/**
 * The bytes wasm-bindgen's glue allocates to pass `text` in (factory.js `passStringToWasm0`): one per
 * UTF-16 unit, and from the first non-ASCII unit on a reallocation to three per unit, the old block
 * still held while it moves.
 */
function textBytes(text: string): number {
  const ascii = text.search(/[^\0-\x7f]/);
  return ascii < 0 ? text.length : text.length + ascii + 3 * (text.length - ascii);
}

/** A pattern's compile, as a fresh instance under the budget found it. */
export type Built =
  | { readonly ok: true; readonly peak: number }
  /** `regex`'s error text, or the budget's (`overBudget`). */
  | { readonly ok: false; readonly message: string; readonly overBudget: boolean };

/**
 * The builder's room: 1 MiB. A compile that fits it is decided there, in an instance used again, so
 * ordinary patterns leave nothing behind for V8 to collect. Deciding there is the same as deciding in
 * a fresh instance: memory cannot change `regex`'s errors, and a pattern the builder accepted never
 * peaked above 1.44 MiB in a fresh instance (474 patterns, each in ten orders after the others; the
 * fresh peak differs from the reused one by up to 40 pages, trust.md section 3.3), far within any
 * compile budget (at least 10 MiB). Ordinary tool-schema patterns fit: one page; a Unicode `.`,
 * 0.31 MiB; `\b\w+\s+\w+\b`, 0.98 MiB.
 */
const BUILDER_ROOM = 16 * PAGE;

let builder: Instance | undefined;

/**
 * Before a request starts the builder (the first, or the next after one a pattern trapped): a pattern past its room traps
 * it, and the builder cannot see which will (`regex`'s size limits leave out the translation of Unicode classes, which
 * alone takes more than the room for a few hundred `\w` or `\pL`), and a trapped builder is dropped with what it held,
 * up to its start and room (2.44 MiB). Refused with `RegexEngineBusy` while that drop could take the dropped instances
 * past what the bound lets them hold (`regexPendingMaxBytes` and one instance, 47.7 MiB): otherwise request after request
 * of such patterns drops a builder each while V8 collects none (30 held 96.5 MiB in workerd, 2026-10-31). Other drops
 * may come while a builder lives, so its own may take them past that by its 2.44 MiB, once: 50.1 MiB at most. A builder
 * that is there is used without a check, so a new ordinary pattern waits only while one a pattern trapped is not started
 * again; a pattern decided before is remembered (`buildRust`) and never comes here. Outside a request nothing is refused.
 */
function mayStartBuilder(): void {
  if (allowance !== undefined && pending + REGEX_INSTANCE_BYTES + BUILDER_ROOM > regexPendingMaxBytes() + regexInstanceMaxBytes()) {
    counters.busy += 1;
    throw new RegexEngineBusy(`dropped regex instances hold ${pending} bytes awaiting collection`);
  }
}

function dropBuilder(): void {
  if (builder !== undefined) retire(builder);
  builder = undefined;
}

/**
 * `regex::Regex::new(pattern)` decided: in the builder when it fits there, else in a build instance
 * of its own. A pattern accepted in the builder is charged what it grew the builder by, at least a
 * page (it may fit memory earlier patterns freed, so this can be less than its peak).
 */
function buildAlone(pattern: string): Built {
  mayWork();
  if (builder === undefined) {
    mayStartBuilder();
    builder = instantiate(REGEX_INSTANCE_BYTES + BUILDER_ROOM);
  }
  const instance = builder;
  const before = instance.memory.buffer.byteLength;
  try {
    new instance.glue.RRegex(pattern).free();
    const peak = Math.max(instance.memory.buffer.byteLength - before, PAGE);
    charge(peak);
    return { ok: true, peak };
  } catch (error) {
    if (!isTrap(error)) {
      charge(PAGE);
      return { ok: false, message: error instanceof Error ? error.message : String(error), overBudget: false };
    }
    dropBuilder();
    charge(REGEX_INSTANCE_BYTES + BUILDER_ROOM);
  }
  return buildFresh(pattern);
}

/**
 * Compiles `pattern` in a new build instance whose memory may grow by the compile budget, and drops
 * it: whether `regex::Regex::new` accepts it there, and the peak it took (whole pages: memory grows
 * by pages). A fresh instance makes the outcome the same in every isolate. A trap there is the
 * budget: a failed allocation aborts (`unreachable`), and a vector that doubles fails while pages are
 * still free. A panic of `regex` itself would trap the same way; none is known for any pattern, and
 * the pattern is refused either way.
 */
function buildFresh(pattern: string): Built {
  const scratch = instantiateForRequest(REGEX_INSTANCE_BYTES + compileMax);
  let outcome: Built;
  try {
    new scratch.glue.RRegex(pattern).free();
    outcome = { ok: true, peak: scratch.memory.buffer.byteLength - REGEX_INSTANCE_BYTES };
  } catch (error) {
    outcome = isTrap(error)
      ? { ok: false, message: `compiling the pattern takes more than ${compileMax} bytes`, overBudget: true }
      : { ok: false, message: error instanceof Error ? error.message : String(error), overBudget: false };
  }
  retire(scratch);
  charge(outcome.ok || !outcome.overBudget ? scratch.memory.buffer.byteLength : REGEX_INSTANCE_BYTES + compileMax);
  return outcome;
}

let builtKeyUnits = RECENT_KEY_UNITS;
/** Compile outcomes by pattern text, so a pattern is measured once while it is remembered. */
const built = new Recent<Built>(builtKeyUnits);

/** The bound of the outcome map, in UTF-16 units of keys (src/settings.ts). */
export function configureBuiltCache(keyUnits: number): void {
  builtKeyUnits = keyUnits;
  built.resize(keyUnits);
}

/**
 * `regex::Regex::new(pattern)` under the compile budget: accepted with its peak, or refused with
 * `regex`'s error (or the budget's). Remembered per pattern.
 */
export function buildRust(pattern: string): Built {
  let outcome = built.get(pattern);
  if (outcome === undefined) {
    outcome = buildAlone(pattern);
    built.set(pattern, outcome);
  }
  return outcome;
}

/**
 * What a pattern parses to, for translation (src/pattern.ts), which only needs regex-syntax's first
 * parse error: the error's message, parsed, or undecided when even an instance of the engine's
 * largest size could not hold the parse.
 */
export type Parsed =
  | { readonly kind: "parsed" }
  | { readonly kind: "error"; readonly message: string }
  | { readonly kind: "undecided" };

/**
 * Put in front of a probed pattern. regex-syntax parses the whole pattern first (every parse error
 * comes from there, the nest limit right after), then translates it left to right, and translating a
 * byte above 0x7F with Unicode off fails at once for a `Regex` (`InvalidUtf8`,
 * regex-syntax-0.8.11/src/hir/translate.rs `ast_literal_to_scalar`). So a pattern that parses gets
 * `PROBE_PARSED` before anything of it is translated or compiled, and the probe takes only what the
 * parse takes. The flag directive after the group keeps a leading repetition operator an error, as at
 * the start of a pattern (`RepetitionMissing` for a repetition of a flag directive).
 */
const PROBE_PREFIX = "(?-u:\\xFF)(?-u)";
const PROBE_PARSED = "pattern can match invalid UTF-8";
/** `ast::ErrorKind::NestLimitExceeded`'s display, up to its number. */
const NEST_LIMIT = "exceed the maximum number of nested parentheses/brackets";

/**
 * What parsing takes at most per byte of pattern outside bracketed classes: 88 bytes (measured in a
 * fresh instance over sizes from 200 bytes to 400 KB, trust.md section 3.3; inside a class up to 361,
 * nested brackets up to 616). A pattern that needs more than the prober's room even at this rate is
 * probed in an instance of its own at once, without trapping the prober first.
 */
const PARSE_BYTES_PER_BYTE = 88;

/** What parsing takes at most per byte of any pattern: 616 bytes, nested brackets (trust.md section 3.3). */
const PARSE_MAX_BYTES_PER_BYTE = 616;

/**
 * Before a request's probe that may trap the prober (one that may not fit its room at
 * `PARSE_MAX_BYTES_PER_BYTE`, or a compile in it): the prober is used again, but a trapped one is
 * dropped, with up to its whole room (11.44 MiB at the default budget). Refused with
 * `RegexEngineBusy` when that drop could take the dropped instances past what the bound lets them
 * hold (`regexPendingMaxBytes` and one instance, 47.7 MiB), so that a request after request whose
 * strings trap the prober cannot drop one each while V8 collects none. A shorter probe cannot trap it
 * and is never refused here, so ordinary patterns go on while new instances are refused. Outside a
 * request nothing is refused.
 */
function mayTrapProber(): void {
  if (allowance !== undefined && pending + REGEX_INSTANCE_BYTES + compileMax > regexPendingMaxBytes() + regexInstanceMaxBytes()) {
    counters.busy += 1;
    throw new RegexEngineBusy(`dropped regex instances hold ${pending} bytes awaiting collection`);
  }
}

/**
 * A probe's charge, standing for its time: 4 KiB and 32 bytes per UTF-16 unit of the pattern. Measured
 * in a reused instance (trust.md section 3.3): at most 82 ns per unit of a 3 KB or 64 KB pattern and
 * 7.2 us a probe, which at the allowance's 3.2 ms per MiB are 27 bytes and 2.4 KB.
 */
function probeCharge(pattern: string): number {
  return 4096 + 32 * pattern.length;
}

let prober: Instance | undefined;

function dropProber(): void {
  if (prober !== undefined) retire(prober);
  prober = undefined;
}

function errorKind(message: string): string {
  const at = message.lastIndexOf("\nerror: ");
  return at < 0 ? message : message.slice(at + "\nerror: ".length);
}

/** One probe in `instance`; "trap" when it ran out of memory there (the instance is then unsound). */
function probeIn(instance: Instance, pattern: string): Parsed | "trap" {
  try {
    new instance.glue.RRegex(PROBE_PREFIX + pattern).free();
    return { kind: "parsed" };
  } catch (error) {
    if (isTrap(error)) return "trap";
    const message = error instanceof Error ? error.message : String(error);
    return errorKind(message) === PROBE_PARSED ? { kind: "parsed" } : { kind: "error", message };
  }
}

/**
 * regex-syntax's first parse error for `pattern` (`regex::Regex::new`'s message), or parsed, or
 * undecided. Parsing takes memory in proportion to the pattern's text, up to 616 bytes per byte for
 * nested brackets (trust.md section 3.3), so a probe first runs in the prober, with the compile
 * budget's room, and when that is too small, once more in an instance of the engine's largest size,
 * dropped after; when that is too small as well, the pattern is undecided (src/pattern.ts: not a
 * regex for `format: "regex"`, refused as a schema pattern, as its build would be).
 */
export function parseRust(pattern: string): Parsed {
  mayWork();
  counters.probes += 1;
  let outcome: Parsed | "trap" = "trap";
  const bytes = textBytes(PROBE_PREFIX + pattern);
  if (PARSE_BYTES_PER_BYTE * bytes < compileMax) {
    if (PARSE_MAX_BYTES_PER_BYTE * bytes >= compileMax) mayTrapProber();
    prober ??= instantiate(REGEX_INSTANCE_BYTES + compileMax);
    outcome = probeIn(prober, pattern);
    charge(probeCharge(pattern));
    if (outcome === "trap") dropProber();
  }
  if (outcome === "trap") {
    const max = regexInstanceMaxBytes();
    if (bytes >= max - REGEX_INSTANCE_BYTES) return { kind: "undecided" };
    const alone = instantiateForRequest(max);
    outcome = probeIn(alone, pattern);
    retire(alone);
    charge(alone.memory.buffer.byteLength + probeCharge(pattern));
    if (outcome === "trap") return { kind: "undecided" };
  }
  return outcome.kind === "error" && errorKind(outcome.message).startsWith(NEST_LIMIT) ? nestedAlone(pattern, outcome) : outcome;
}

/**
 * The prefix adds a level of nesting when the pattern is not a concatenation at its top (a single
 * group, an alternation), so a pattern at regex-syntax's nest limit (250) is over it when probed. The
 * pattern parsed, so the limit is asked of the pattern alone, compiled as it is in the prober: its
 * nest-limit error is the pattern's own; anything else (accepted, a later error, running out while
 * compiling) means it parsed.
 */
function nestedAlone(pattern: string, probed: Parsed): Parsed {
  if (prober === undefined || textBytes(pattern) >= compileMax) return probed;
  // A compile may take all of the prober's room whatever the pattern's length.
  mayTrapProber();
  const instance = prober;
  try {
    new instance.glue.RRegex(pattern).free();
    return { kind: "parsed" };
  } catch (error) {
    if (isTrap(error)) {
      dropProber();
      return { kind: "parsed" };
    }
    const message = error instanceof Error ? error.message : String(error);
    return errorKind(message).startsWith(NEST_LIMIT) ? { kind: "error", message } : { kind: "parsed" };
  } finally {
    charge(compileMax);
  }
}

/** The isolate's instance and its cache, oldest first. */
let main: Instance | undefined;
const cache = new Map<string, { readonly regex: RRegex; readonly bytes: number }>();
let cached = 0;

function dropMain(): void {
  // Dropped whole: its memory goes with it. The compiled patterns are not freed into it (after a trap
  // that could fault again); each is only taken off its glue's finalizer, so that no finalizer calls
  // into the dropped instance later. `__destroy_into_raw` is wasm-bindgen 0.2.100's own step of
  // `free()` before the call into wasm (workers/vendor/rregex-nowee/factory.js).
  for (const entry of cache.values()) (entry.regex as unknown as { __destroy_into_raw(): number }).__destroy_into_raw();
  if (main !== undefined) retire(main);
  main = undefined;
  cache.clear();
  cached = 0;
}

function evict(): void {
  const oldest = cache.keys().next();
  if (oldest.done === true) return;
  const entry = cache.get(oldest.value);
  cache.delete(oldest.value);
  if (entry === undefined) return;
  cached -= entry.bytes;
  counters.evictions += 1;
  entry.regex.free();
}

/** Calls into the isolate's instance; a trap drops it and throws `RegexEngineTrapped`. */
function guarded<T>(call: () => T): T {
  try {
    return call();
  } catch (error) {
    if (!isTrap(error)) throw error;
    dropMain();
    throw new RegexEngineTrapped(error);
  }
}

/** `pattern`, compiled in the isolate's instance, kept in its cache. */
function compiledInMain(pattern: string): RRegex {
  const hit = cache.get(pattern);
  if (hit !== undefined) {
    cache.delete(pattern);
    cache.set(pattern, hit);
    return hit.regex;
  }
  const outcome = buildRust(pattern);
  if (!outcome.ok) throw new Error(`@gray/trust: matching a pattern the engine refused (${outcome.message})`);
  mayWork();
  if (main === undefined) {
    main = instantiate(regexInstanceMaxBytes());
    counters.mainStarts += 1;
  }
  // Room for what it will hold; its compile's transient peak is within the same charge.
  const bytes = Math.max(outcome.peak, PAGE);
  while (cached + bytes > REGEX_CACHE_MAX_BYTES && cache.size > 0) guarded(evict);
  const instance = main;
  const regex = guarded(() => {
    try {
      return new instance.glue.RRegex(pattern);
    } catch (error) {
      if (isTrap(error)) throw error;
      throw new Error(`@gray/trust: a pattern the build accepted was refused (${error instanceof Error ? error.message : String(error)})`);
    }
  });
  charge(bytes);
  cache.set(pattern, { regex, bytes });
  cached += bytes;
  return regex;
}

/**
 * A text too long for the isolate's instance (it would grow it past its start and the cache): matched
 * in an instance of its own, of the engine's largest size, dropped after, so that long texts cannot
 * keep replacing the isolate's instance outside the dropped-instance bound. `RegexTextTooLong` when
 * even that cannot hold the compile, the text and the search, which is decided before anything runs.
 */
function matchAlone(pattern: string, text: string, need: number): boolean {
  const outcome = buildRust(pattern);
  if (!outcome.ok) throw new Error(`@gray/trust: matching a pattern the engine refused (${outcome.message})`);
  const max = regexInstanceMaxBytes();
  if (REGEX_INSTANCE_BYTES + Math.max(outcome.peak, PAGE) + need + REGEX_SEARCH_BYTES > max) {
    throw new RegexTextTooLong(`a text of ${text.length} UTF-16 units does not fit a regex instance of ${max} bytes with its pattern`);
  }
  const alone = instantiateForRequest(max);
  try {
    const regex = new alone.glue.RRegex(pattern);
    try {
      return regex.isMatch(text);
    } finally {
      regex.free();
    }
  } catch (error) {
    if (isTrap(error)) throw new RegexEngineTrapped(error);
    throw error;
  } finally {
    retire(alone);
    charge(alone.memory.buffer.byteLength);
  }
}

/**
 * Whether `pattern`, which `buildRust` accepted, matches `text` (`Regex::is_match`), in the isolate's
 * instance, compiling it there when the cache does not have it. Throws `RegexEngineTrapped`, and
 * `RegexTextTooLong` for a text no instance of the engine can hold.
 */
export function matchRust(pattern: string, text: string): boolean {
  // Its search caches grow with every match of every pattern it keeps, and no charge counts them.
  if (main !== undefined && main.memory.buffer.byteLength > REGEX_INSTANCE_BYTES + REGEX_CACHE_MAX_BYTES) dropMain();
  const need = textBytes(text);
  const lean = REGEX_INSTANCE_BYTES + REGEX_CACHE_MAX_BYTES;
  if ((main?.memory.buffer.byteLength ?? REGEX_INSTANCE_BYTES) + need > lean) return matchAlone(pattern, text, need);
  const regex = compiledInMain(pattern);
  // Its own compile may have grown it; the search's caches still have their room within its maximum.
  if (main === undefined || main.memory.buffer.byteLength + need > lean) return matchAlone(pattern, text, need);
  return guarded(() => regex.isMatch(text));
}

/** The isolate's instance's memory now (it only grows; 0 before the first match). */
export function regexEngineMemory(): number {
  return main?.memory.buffer.byteLength ?? 0;
}

/** The compiled patterns the isolate's instance keeps now, and their charged bytes. */
export function regexCacheUse(): { readonly patterns: number; readonly bytes: number } {
  return { patterns: cache.size, bytes: cached };
}

/**
 * For monitoring: isolate's instances started, patterns evicted from its cache, instances made in
 * all, requests refused because dropped instances were not collected yet, parses asked of the engine
 * (`parseRust`), and the bytes the dropped instances hold.
 */
export function regexEngineCounters(): {
  readonly mainStarts: number;
  readonly evictions: number;
  readonly instances: number;
  readonly busy: number;
  readonly probes: number;
  readonly pendingBytes: number;
} {
  return { ...counters, pendingBytes: pending };
}

/** For tests only: grows the isolate's instance by `bytes`, as fragmentation or search caches would. */
export function growRegexEngineForTest(bytes: number): void {
  main?.memory.grow(Math.ceil(bytes / PAGE));
}

/**
 * For tests only: points every compiled pattern the isolate's instance keeps at a wild address, so
 * the next match of any of them traps (an out-of-bounds read), as a bug in `regex` would.
 */
export function poisonRegexCacheForTest(): number {
  for (const entry of cache.values()) (entry.regex as unknown as { __wbg_ptr: number }).__wbg_ptr = 0xffff_fff0;
  return cache.size;
}
