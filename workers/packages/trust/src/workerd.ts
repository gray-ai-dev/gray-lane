/**
 * `@gray/trust` for a Worker: the same exports, with the regex engine initialised from the wasm
 * module wrangler compiled at upload (Workers cannot compile wasm from bytes at run time). Import
 * this entry, not `@gray/trust`, from Worker code; Node callers initialise the engine themselves
 * (`initRegexEngine` with the file's bytes).
 */
// Imported as a module, the file is the compiled WebAssembly.Module wrangler and the workerd pool
// hand over (the `*.wasm` declaration in src/wasm.d.ts, referenced here for checkouts whose
// tsconfig does not have it, such as workers/e2e).
/// <reference path="./wasm.d.ts" />
import wasm from "../../../vendor/rregex-nowee/rregex.wasm";
import { initRegexEngine } from "./engine.ts";

initRegexEngine(wasm);

export * from "./index.ts";
