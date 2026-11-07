/**
 * `@gray/relay-policy` for a Worker: the same exports, with the interpreter initialised from the
 * module wrangler compiled at upload. Workers cannot compile wasm from bytes at run time ("Wasm code
 * generation disallowed by embedder"), so the interpreter this package needs is imported here, as
 * `@gray/trust/workerd` does for its regex engine. Import this subpath instead of the package root
 * in any Worker.
 *
 * The interpreter (`relay_policy_wasmi.wasm`) is the package's whole runtime: it takes the relay's
 * bytes as they arrive and interprets them, so nothing has to be compiled at run time.
 */
// wrangler's CompiledWasm rule, which the workerd tests also apply (vitest.workerd.config.ts).
import interpreter from "../../../vendor/relay-policy-wasmi/relay_policy_wasmi.wasm";
import { initInterpreter } from "./wasmi.ts";

initInterpreter(interpreter);

export * from "./index.ts";
