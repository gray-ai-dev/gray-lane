/**
 * The gate's fixed bounds, each the Rust gate's own (crates/gray-gateway/src/trust.rs). They are rules
 * of the gate, not tunables: the conformance fixtures hold the TypeScript gate to the same numbers.
 */

/** `MAX_TOOLS` (trust.rs line 31): calls one answer may carry, and tools an operator may allow. */
export const MAX_TOOLS = 128;

/** Secret deny markers are 8 to 4,096 bytes (`TrustPolicy::compile`). */
export const MARKER_MIN_BYTES = 8;
export const MARKER_MAX_BYTES = 4096;

/** An allowed tool's name is 1 to 256 bytes (`TrustPolicy::compile`). */
export const TOOL_NAME_MAX_BYTES = 256;
