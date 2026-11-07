import "@gray/relay-policy/workerd";

/**
 * Installs the relay policy interpreter (design v2 section C.5, B1).
 *
 * Workerd refuses wasm code generation from bytes at run time, so the policy interpreter is the
 * vendored `relay_policy_wasmi.wasm` module, imported at build time under wrangler's CompiledWasm
 * rule and handed to `@gray/relay-policy`'s `initInterpreter` by its `workerd` entry. Importing that
 * entry here — and nowhere else in the lane — means:
 *
 * - the lane bundle carries the interpreter exactly once, whether or not a relay ever uploads a
 *   policy (a module import is not a lazy import);
 * - a build whose bundler dropped the `.wasm` module fails at import time, not at the first upload.
 *
 * `wrangler.lane.jsonc` and the workerd test config both carry the rule; `@gray/relay-policy`'s
 * `workerd.ts` is the package's own documented entry for this.
 */
export {};
