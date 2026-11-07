/**
 * What a relay may upload, decided before anything runs it. Every rule here is from the review's
 * §1.1/§1.3/§4 and the owner's decisions: a policy module is a closed function of its input, so it
 * needs no imports, no filesystem, no clock, no randomness, no threads, no shared memory, no start
 * hook and no way to hold memory beyond a declared cap.
 *
 * Two independent readers help decide, because no single one reports all of it:
 *
 * 1. `WebAssembly.validate` — V8's own validator. It is synchronous and compiles nothing, so it
 *    works in workerd too, where wasm code generation from bytes is disabled by the embedder. A
 *    module V8 refuses never reaches the interpreter.
 * 2. The vendored wrapper's own pass (`wasmi.ts` → `loadPolicyModule`), which parses the bytes with
 *    `wasmparser` and holds them to the structural rules: imports, tables, `start`, the exports and
 *    their signatures, and the proposals the ABI allows. `preparePolicy` calls this second reader
 *    after {@link validatePolicyShape}; a test drives it directly so the wrapper is not a
 *    pass-through.
 *
 * `scanMemoryDeclarations` reads the memory limits flags from the bytes themselves, because the
 * wrapper's higher-level parsers may stop at the first structural error: a shared memory, a 64-bit
 * memory or an unknown flag gets its own refusal code here, before the wrapper is asked about it.
 */
import { refusal, sha256Hex, type Refusal } from "@gray/lane";
import type { PolicyLimits } from "./limits.ts";
import { scanMemoryDeclarations, type MemoryDeclaration } from "./wasm-scan.ts";

/** Why a module may not become a policy. */
export type ModuleRefusalCode =
  | "module_too_large"
  | "module_invalid"
  | "module_unparseable"
  | "module_imports"
  | "module_memory_count"
  | "module_memory_flags"
  | "module_memory_shared"
  | "module_memory64"
  | "module_memory_unbounded"
  | "module_memory_too_large"
  | "module_tables"
  | "module_start"
  | "module_exports"
  | "module_abi"
  // The wrapper reports one code for the memory rule and one for "could not instantiate"; the
  // shape pass above has already named the precise memory rule by then.
  | "module_memory"
  | "module_instantiate";

/** A module that passed every rule this file can decide without running the interpreter's parser. */
export interface ValidatedShape {
  readonly bytes: Uint8Array;
  /** SHA-256 of the bytes exactly as uploaded: the `module_sha256` a receipt cites. */
  readonly sha256: string;
  /** The declared maximum of the module's one memory, in 64 KiB pages. */
  readonly memoryPages: number;
  /** The memory declarations the scanner read. */
  readonly memories: readonly MemoryDeclaration[];
}

/**
 * The rules that do not depend on the interpreter's parser: the size cap, the platform's own
 * validator and the memory declarations read from the bytes. `preparePolicy` starts here, then hands
 * the same bytes to the wrapper, which adds the structural pass as a second, independent reader.
 */
export function validatePolicyShape(
  bytes: Uint8Array,
  limits: PolicyLimits,
): { readonly ok: true; readonly module: ValidatedShape } | Refusal<ModuleRefusalCode> {
  if (!(bytes instanceof Uint8Array)) return refusal("module_invalid", "the module is not a byte array");
  if (bytes.length === 0) return refusal("module_invalid", "the module is empty");
  if (bytes.length > limits.maxModuleBytes) return refusal("module_too_large", "the module is over the host's size cap");
  let valid: boolean;
  try {
    valid = WebAssembly.validate(bytes);
  } catch {
    valid = false;
  }
  if (!valid) return refusal("module_invalid", "the platform's validator refuses the module");

  // The memory flags first: the scan names the actual rule (shared, 64-bit, unknown flags) instead of
  // letting the wrapper report every one of them as one structural code.
  const scanned = scanMemoryDeclarations(bytes);
  if (!scanned.ok) {
    return refusal(scanned.code === "unsupported_memory_flags" ? "module_memory_flags" : "module_invalid", scanned.detail);
  }

  for (const memory of scanned.memories) {
    if (memory.shared) return refusal("module_memory_shared", "a shared memory means threads, which the lane refuses");
    if (memory.memory64) return refusal("module_memory64", "a 64-bit memory is outside the ABI");
  }

  // Exactly one memory, with a declared maximum under the host's cap, not shared, 32-bit.
  if (scanned.memories.length !== 1) {
    return refusal("module_memory_count", "the module must declare exactly one memory");
  }
  const memory = scanned.memories[0];
  if (memory === undefined) return refusal("module_memory_count", "the module must declare exactly one memory");
  if (memory.max === null) return refusal("module_memory_unbounded", "the module's memory declares no maximum");
  if (memory.min > memory.max) return refusal("module_invalid", "the memory's minimum is above its maximum");
  if (memory.max > limits.maxMemoryPages) return refusal("module_memory_too_large", "the memory's maximum is over the host's cap");

  return { ok: true, module: { bytes, sha256: sha256Hex(bytes), memoryPages: memory.max, memories: scanned.memories } };
}
