/**
 * The interpreter: the relay's module is *interpreted* by `wasmi` 2.0.0, which itself is a wasm
 * module the gateway imports at build time (`workers/vendor/relay-policy-wasmi`).
 *
 * This is the package's only engine. The relay's bytes are only ever data: the host never generates
 * code, so a module that arrives at run time works in workerd. Fuel and the resource limits are
 * wasmi's own, so there is no rewrite step and no `parity-wasm` in the path at all.
 *
 * The wrapper's ABI (its own source is the reference, `src/lib.rs`):
 *
 * ```text
 * alloc(len) -> ptr
 * dealloc(ptr, len)
 * load(ptr, len, max_pages, max_tables, max_table_elements, stack_slots) -> declared_pages | error
 * evaluate(input_ptr, input_len, fuel, max_memory_bytes, max_output_bytes, stack_slots) -> packed | error
 * last_fuel_consumed() -> fuel
 * ```
 *
 * `load` answers the module's declared memory maximum in the low word on success, so the session
 * reports — and each call enforces — what the module declared, not just the cap the host allowed.
 *
 * `load` is upload work and happens once per policy version: it holds the relay's bytes to the
 * module contract and keeps them as the session's module. `evaluate` is request work: a **fresh
 * wasmi instance** of that module every call, so nothing a module keeps in a global or its memory
 * survives to the next request.
 *
 * One session is one wrapper instance with one loaded module. A wrapper that traps is not reused:
 * {@link WasmiSession.evaluate} reports it, and the caller must build a new session from the bytes
 * (sandbox.ts keeps them for exactly that reason).
 */
import { refusal, type Refusal } from "@gray/lane";

/** The most a relay may upload, from abi.md §1. The host's own cap may be lower. */
export const MAX_WASMI_MODULE_BYTES = 4 * 1024 * 1024;

/** 64 KiB: one WebAssembly memory page. */
const WASM_PAGE_BYTES = 65_536;

/** The wrapper's own exports, and nothing else. */
interface WasmiExports {
  readonly memory?: WebAssembly.Memory;
  readonly alloc?: (len: number) => number;
  readonly dealloc?: (ptr: number, len: number) => void;
  readonly load?: (ptr: number, len: number, maxPages: number, maxTables: number, maxTableElements: number, stackSlots: number) => bigint;
  readonly evaluate?: (inputPtr: number, inputLen: number, fuel: bigint, maxMemoryBytes: bigint, maxOutputBytes: number, stackSlots: number) => bigint;
  readonly last_fuel_consumed?: () => bigint;
}

/** Why the wrapper refused a module at load (`src/lib.rs`, the `ERR_*` constants). */
export type WasmiLoadFailureCode =
  | "interpreter_unavailable"
  | "unparseable"
  | "imports"
  | "memory"
  | "tables"
  | "exports"
  | "abi"
  | "start"
  | "size"
  | "limits"
  | "allocation"
  | "instance_failed";

/** Why one evaluation produced no decision (`src/lib.rs` again). */
export type WasmiCallFailureCode =
  | "no_module"
  | "limits"
  | "allocation"
  | "out_of_fuel"
  | "stack"
  | "memory"
  | "trap"
  | "output_empty"
  | "output_too_large"
  | "output_bounds"
  | "instance_failed";

/** The wrapper's closed error codes, as this file's names. Never shown to a relay. */
const LOAD_ERRORS: Readonly<Record<number, WasmiLoadFailureCode>> = {
  1: "unparseable",
  2: "imports",
  3: "memory",
  4: "tables",
  5: "exports",
  6: "abi",
  8: "limits",
  9: "allocation",
  16: "start",
  17: "size",
};

/** What `load` is told about the host's budgets. */
export interface WasmiLoadLimits {
  readonly maxMemoryPages: number;
  readonly maxTables: number;
  readonly maxTableElements: number;
  readonly maxStackSlots: number;
}

/** What one evaluation may spend. */
export interface WasmiCallLimits {
  readonly fuel: bigint;
  readonly maxMemoryBytes: number;
  readonly maxOutputBytes: number;
  readonly stackSlots: number;
}

/** One request's answer from the interpreter. */
export type WasmiCallResult =
  | { readonly ok: true; readonly output: Uint8Array; readonly fuelConsumed: bigint }
  | { readonly ok: false; readonly code: WasmiCallFailureCode; readonly fuelConsumed: bigint };

/** A loaded policy: the wrapper instance holding it, and the budgets it was loaded with. */
export interface WasmiSession {
  /** The memory the module declared, in 64 KiB pages: the per-call memory cap. */
  readonly memoryPages: number;
  /** The stack budget the interpreter's engine was built with, in the ABI's slots. */
  readonly stackSlots: number;
  /** One request, through a fresh instance of the module. */
  evaluate(input: Uint8Array, limits: WasmiCallLimits): WasmiCallResult;
}

let interpreter: WebAssembly.Module | undefined;

/**
 * Hands the interpreter over. Call once per isolate before anything else: with a compiled
 * `WebAssembly.Module` where the embedder compiles wasm at upload (workerd, `@gray/relay-policy/workerd`)
 * and with bytes where it can compile at run time (Node).
 */
export function initInterpreter(source: WebAssembly.Module | BufferSource): void {
  // Workers' types declare the constructor abstract: workerd refuses to compile wasm at run time.
  const compile = WebAssembly.Module as unknown as new (bytes: BufferSource) => WebAssembly.Module;
  interpreter = source instanceof WebAssembly.Module ? source : new compile(source);
}

/** Whether {@link initInterpreter} has been called in this isolate. */
export function interpreterReady(): boolean {
  return interpreter !== undefined;
}

/** The wrapper's error code, split into its high and low halves. */
function decode(packed: bigint): { readonly error: number | null; readonly pointer: number; readonly length: number } {
  const value = BigInt.asUintN(64, packed);
  const high = Number(value >> 32n);
  const low = Number(value & 0xffff_ffffn);
  return { error: high === 0xffff_ffff ? low : null, pointer: high, length: low };
}

/**
 * Load a module: the wrapper validates it (structure, limits, proposals), parses it with wasmi and
 * keeps it. Returns a session, or a closed refusal.
 */
export function loadPolicyModule(
  bytes: Uint8Array,
  limits: WasmiLoadLimits,
): { readonly ok: true; readonly session: WasmiSession } | Refusal<WasmiLoadFailureCode> {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    return refusal("unparseable", "the module is empty");
  }
  if (bytes.length > MAX_WASMI_MODULE_BYTES) return refusal("size", "the module is over the wrapper's size cap");
  const source = interpreter;
  if (source === undefined) return refusal("interpreter_unavailable", "the policy interpreter was not initialised in this isolate");

  let instance: WebAssembly.Instance;
  try {
    instance = new WebAssembly.Instance(source, {});
  } catch {
    return refusal("interpreter_unavailable", "the policy interpreter could not be instantiated");
  }
  const exports = instance.exports as unknown as WasmiExports;
  if (!(exports.memory instanceof WebAssembly.Memory)) {
    return refusal("interpreter_unavailable", "the policy interpreter exports no memory");
  }
  if (exports.alloc === undefined || exports.load === undefined || exports.evaluate === undefined || exports.dealloc === undefined) {
    return refusal("interpreter_unavailable", "the policy interpreter does not export its ABI");
  }

  // The wrapper's i32 arguments: a page count over u32::MAX would truncate on the wasm32 `usize`,
  // so the host refuses one before it reaches the ABI (the wrapper checks its own too).
  const loadArgs = [limits.maxMemoryPages, limits.maxTables, limits.maxTableElements, limits.maxStackSlots];
  if (loadArgs.some((value) => !Number.isSafeInteger(value) || value > 0xffff_ffff)) {
    return refusal("limits", "a load limit does not fit the wrapper's i32 arguments");
  }

  const pointer = exports.alloc(bytes.length);
  if (typeof pointer !== "number" || !Number.isInteger(pointer) || pointer <= 0) {
    return refusal("allocation", "the interpreter could not allocate its input");
  }
  if (pointer + bytes.length > exports.memory.buffer.byteLength) {
    return refusal("allocation", "the interpreter's input region is outside its memory");
  }
  new Uint8Array(exports.memory.buffer, pointer, bytes.length).set(bytes);

  let packed: bigint;
  try {
    packed = exports.load(
      pointer,
      bytes.length,
      limits.maxMemoryPages,
      limits.maxTables,
      limits.maxTableElements,
      limits.maxStackSlots,
    );
  } catch {
    return refusal("instance_failed", "the policy interpreter trapped while loading the module");
  } finally {
    exports.dealloc(pointer, bytes.length);
  }
  const loaded = decode(packed);
  if (loaded.error !== null) {
    const code = LOAD_ERRORS[loaded.error];
    return refusal(code ?? "instance_failed", `the wrapper refused the module (code ${loaded.error})`);
  }

  // The declared memory maximum the wrapper answered, not the cap the host passed: the per-call
  // memory budget is what the module declared, so a caller that allowed more still enforces less.
  const memoryPages = loaded.length;
  const stackSlots = limits.maxStackSlots;
  const session: WasmiSession = {
    memoryPages,
    stackSlots,
    evaluate(input: Uint8Array, budgets: WasmiCallLimits): WasmiCallResult {
      return evaluateOn(exports, input, budgets);
    },
  };
  return { ok: true, session };
}

/** One request through the loaded module, with the wrapper's ABI. */
function evaluateOn(exports: WasmiExports, input: Uint8Array, limits: WasmiCallLimits): WasmiCallResult {
  const alloc = exports.alloc;
  const dealloc = exports.dealloc;
  const evaluate = exports.evaluate;
  const fuelOf = exports.last_fuel_consumed;
  const memory = exports.memory;
  if (alloc === undefined || dealloc === undefined || evaluate === undefined || fuelOf === undefined || memory === undefined) {
    return { ok: false, code: "instance_failed", fuelConsumed: 0n };
  }
  // The wrapper's `max_memory_bytes` is an i64 it casts to a wasm32 `usize`: a value over u32::MAX
  // would truncate (2^32 becomes 0, an instantiation failure in disguise). The host refuses it as
  // `limits` instead of letting it wrap — the wrapper refuses it too (VERIFY RP-15).
  if (!Number.isSafeInteger(limits.maxMemoryBytes) || limits.maxMemoryBytes > 0xffff_ffff) {
    return { ok: false, code: "limits", fuelConsumed: 0n };
  }
  let pointer: number;
  try {
    pointer = alloc(input.length);
  } catch {
    return { ok: false, code: "trap", fuelConsumed: fuelOf() };
  }
  if (typeof pointer !== "number" || !Number.isInteger(pointer) || pointer <= 0) {
    return { ok: false, code: "allocation", fuelConsumed: fuelOf() };
  }
  // The wrapper may have grown its memory to make room: read the buffer after `alloc`, never before.
  if (pointer + input.length > memory.buffer.byteLength) {
    return { ok: false, code: "allocation", fuelConsumed: fuelOf() };
  }
  new Uint8Array(memory.buffer, pointer, input.length).set(input);

  let packed: bigint;
  try {
    packed = evaluate(pointer, input.length, limits.fuel, BigInt(limits.maxMemoryBytes), limits.maxOutputBytes, limits.stackSlots);
  } catch {
    // The wrapper itself trapped: the wrapper instance is not trusted again (callers rebuild it).
    return { ok: false, code: "trap", fuelConsumed: fuelOf() };
  } finally {
    dealloc(pointer, input.length);
  }
  const fuelConsumed = fuelOf();
  const answer = decode(packed);
  if (answer.error !== null) {
    const code = CALL_ERRORS[answer.error] ?? "trap";
    return { ok: false, code, fuelConsumed };
  }
  if (answer.length === 0) {
    return { ok: false, code: "output_empty", fuelConsumed };
  }
  if (answer.length > limits.maxOutputBytes) {
    return { ok: false, code: "output_too_large", fuelConsumed };
  }
  // The wrapper's memory may have been replaced by this call (the guest's memory grew), so this is
  // the third place the buffer is read after the call that could have detached it.
  const buffer = memory.buffer;
  if (answer.pointer + answer.length > buffer.byteLength) {
    return { ok: false, code: "output_bounds", fuelConsumed };
  }
  const output = new Uint8Array(buffer, answer.pointer, answer.length).slice();
  dealloc(answer.pointer, answer.length);
  return { ok: true, output, fuelConsumed };
}

/** The evaluate half of the wrapper's closed codes. */
const CALL_ERRORS: Readonly<Record<number, WasmiCallFailureCode>> = {
  7: "no_module",
  8: "limits",
  9: "allocation",
  10: "instance_failed",
  11: "out_of_fuel",
  12: "stack",
  13: "memory",
  14: "trap",
  15: "output_empty",
  18: "output_too_large",
  19: "output_bounds",
};

/**
 * The per-call memory cap of a session: what the module declared, in bytes. The declared maximum
 * can name the whole 4 GiB a 32-bit memory may have (65,536 pages), whose byte count is `2^32` —
 * one over the `u32::MAX` the wrapper's `usize` can carry — so the answer is clamped at the
 * wrapper's own bound rather than handed over to be refused or wrapped.
 */
export function memoryBytesOf(session: WasmiSession): number {
  return Math.min(session.memoryPages * WASM_PAGE_BYTES, 0xffff_ffff);
}
