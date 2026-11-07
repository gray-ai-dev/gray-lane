/**
 * The memory declarations of a wasm module, read straight from its bytes.
 *
 * This is the one fact the platform cannot give us in every runtime. `WebAssembly.validate` says
 * whether a module is valid, but neither workerd nor Node 26's `WebAssembly.Module` exposes a
 * module's declared memory limits (workerd has no static `imports`/`exports`/`customSections` at
 * all; Node 26 has only the static calls, not a `memory` accessor), and a shared memory or a 64-bit
 * memory has to be refused with its own code before the interpreter's parser reports every
 * structural problem as one code.
 *
 * So this scanner walks the binary's sections and reads the two places memory types appear — the
 * memory section and the import section — and reports the limits flags. It is not a validator and
 * does not try to be one: {@link WebAssembly.validate} and the wrapper's `wasmparser` pass decide
 * validity. It is total over arbitrary bytes: every read is bounds-checked, and anything it cannot
 * read is a refusal, never an exception or a guess.
 *
 * The format: `\0asm` then version 1, then sections of `id: varuint7, size: varuint32, payload`.
 * A memory type is `flags: varuint32, min: varuint32, max?: varuint32`; the flags are `0x01` for "a
 * maximum follows", `0x02` for shared, `0x04` for 64-bit. An import entry is `module name, field
 * name, kind: u8`, then per kind: function 0 → type index, table 1 → element type + limits, memory
 * 2 → memory type, global 3 → value type + mutability.
 */
import { refusal, type Refusal } from "@gray/lane";

/** A memory's limits, as the binary declares them. */
export interface MemoryDeclaration {
  /** Initial pages. */
  readonly min: number;
  /** Declared maximum pages, or null when the module declares none. */
  readonly max: number | null;
  /** The raw limits flags (a varuint32). */
  readonly flags: number;
  /** Whether the shared bit is set: threads, refused. */
  readonly shared: boolean;
  /** Whether the 64-bit bit is set: memory64, refused. */
  readonly memory64: boolean;
  /** Whether the memory came from an import rather than the memory section. */
  readonly imported: boolean;
}

/** Why bytes are not a module this scanner can read. */
export type WasmScanRefusalCode = "invalid_wasm" | "unsupported_memory_flags";

/** The memory declarations of `bytes`, in the order the module writes them. */
export function scanMemoryDeclarations(
  bytes: Uint8Array,
): { readonly ok: true; readonly memories: readonly MemoryDeclaration[] } | Refusal<WasmScanRefusalCode> {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) return refusal("invalid_wasm", "the module is shorter than its header");
  if (bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    return refusal("invalid_wasm", "the module does not start with the wasm magic");
  }
  if (bytes[4] !== 0x01 || bytes[5] !== 0x00 || bytes[6] !== 0x00 || bytes[7] !== 0x00) {
    return refusal("invalid_wasm", "the module does not declare version 1");
  }
  const memories: MemoryDeclaration[] = [];
  const sections = new Cursor(bytes, 8);
  while (!sections.done()) {
    const id = sections.byte();
    if (id === undefined) return refusal("invalid_wasm", "a section id is missing");
    const size = sections.varU32();
    if (size === undefined) return refusal("invalid_wasm", "a section size is not a varuint32");
    const payload = sections.take(size);
    if (payload === undefined) return refusal("invalid_wasm", "a section runs past the end of the module");
    const problem = id === 5 ? readMemorySection(payload, memories) : id === 2 ? readImportSection(payload, memories) : undefined;
    if (problem !== undefined) return problem;
  }
  return { ok: true, memories };
}

/** The memory section: a vector of memory types. */
function readMemorySection(payload: Cursor, memories: MemoryDeclaration[]): Refusal<WasmScanRefusalCode> | undefined {
  const count = payload.varU32();
  if (count === undefined) return refusal("invalid_wasm", "the memory section does not start with a count");
  for (let index = 0; index < count; index += 1) {
    const memory = readMemoryType(payload, false);
    if (!("min" in memory)) return memory;
    memories.push(memory);
  }
  return undefined;
}

/** The import section: names, a kind byte, then the kind's type. */
function readImportSection(payload: Cursor, memories: MemoryDeclaration[]): Refusal<WasmScanRefusalCode> | undefined {
  const count = payload.varU32();
  if (count === undefined) return refusal("invalid_wasm", "the import section does not start with a count");
  for (let index = 0; index < count; index += 1) {
    if (!payload.skipName()) return refusal("invalid_wasm", "an import's module name is not a string");
    if (!payload.skipName()) return refusal("invalid_wasm", "an import's field name is not a string");
    const kind = payload.byte();
    if (kind === undefined) return refusal("invalid_wasm", "an import has no kind");
    if (kind === 0x00) {
      if (payload.varU32() === undefined) return refusal("invalid_wasm", "an imported function has no type index");
    } else if (kind === 0x01) {
      if (payload.byte() === undefined) return refusal("invalid_wasm", "an imported table has no element type");
      if (!payload.skipLimits()) return refusal("invalid_wasm", "an imported table has no limits");
    } else if (kind === 0x02) {
      const memory = readMemoryType(payload, true);
      if (!("min" in memory)) return memory;
      memories.push(memory);
    } else if (kind === 0x03) {
      if (payload.byte() === undefined || payload.byte() === undefined) {
        return refusal("invalid_wasm", "an imported global has no type");
      }
    } else if (kind === 0x04) {
      // tag (exception handling): attribute byte + type index.
      if (payload.byte() === undefined || payload.varU32() === undefined) {
        return refusal("invalid_wasm", "an imported tag has no type");
      }
    } else {
      return refusal("invalid_wasm", "an import names a kind this scanner does not know");
    }
  }
  return undefined;
}

/** One memory type: flags, minimum, optional maximum. */
function readMemoryType(cursor: Cursor, imported: boolean): MemoryDeclaration | Refusal<WasmScanRefusalCode> {
  const flags = cursor.varU32();
  if (flags === undefined) return refusal("invalid_wasm", "a memory has no limits flags");
  if ((flags & ~0x07) !== 0) return refusal("unsupported_memory_flags", "a memory's limits flags hold bits outside 0x00..0x07");
  const min = cursor.varU32();
  if (min === undefined) return refusal("invalid_wasm", "a memory has no minimum");
  const max = (flags & 0x01) !== 0 ? cursor.varU32() : null;
  if (max === undefined) return refusal("invalid_wasm", "a memory's maximum is not a varuint32");
  return { min, max, flags, shared: (flags & 0x02) !== 0, memory64: (flags & 0x04) !== 0, imported };
}

/**
 * A bounds-checked cursor over a slice. Every reader returns undefined instead of throwing when the
 * bytes run out or a number is malformed (a varuint32 longer than five bytes, whose bits would not
 * fit, or one that carries bits above 2^32-1).
 */
class Cursor {
  readonly bytes: Uint8Array;
  offset: number;

  constructor(bytes: Uint8Array, offset: number) {
    this.bytes = bytes;
    this.offset = offset;
  }

  done(): boolean {
    return this.offset >= this.bytes.length;
  }

  byte(): number | undefined {
    if (this.offset >= this.bytes.length) return undefined;
    const value = this.bytes[this.offset] as number;
    this.offset += 1;
    return value;
  }

  take(length: number): Cursor | undefined {
    const end = this.offset + length;
    if (!Number.isSafeInteger(end) || end > this.bytes.length || end < this.offset) return undefined;
    const slice = this.bytes.subarray(this.offset, end);
    this.offset = end;
    return new Cursor(slice, 0);
  }

  /** An unsigned LEB128 that must fit 32 bits. */
  varU32(): number | undefined {
    let result = 0;
    let shift = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.byte();
      if (byte === undefined) return undefined;
      const chunk = byte & 0x7f;
      if (index === 4 && chunk > 0x0f) return undefined;
      result += chunk * 2 ** shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7;
    }
    return undefined;
  }

  /** A name: a varuint32 length then that many bytes. */
  skipName(): boolean {
    const length = this.varU32();
    if (length === undefined) return false;
    if (this.offset + length > this.bytes.length) return false;
    this.offset += length;
    return true;
  }

  /** A table's limits: flags, minimum, optional maximum. */
  skipLimits(): boolean {
    const flags = this.varU32();
    if (flags === undefined) return false;
    if (this.varU32() === undefined) return false;
    if ((flags & 0x01) !== 0 && this.varU32() === undefined) return false;
    return true;
  }
}
