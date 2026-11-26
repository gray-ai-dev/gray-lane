/**
 * @gray/control: the control plane's pure rules (crates/gray-control, crates/gray-router's capability
 * claims), shared by the console and the gateway's snapshot.
 */
export * from "./capabilities.ts";
export * from "./endpoint.ts";
export * from "./streaming.ts";
export * from "./lane.ts";
export * from "./text.ts";
export * from "./coding-agent.ts";
export * from "./opencode-thinking.ts";
export * from "./traffic.ts";
export * from "./stack.ts";

// The public catalog, the offers' standing and the model-name keys are read by the main gateway's jobs
// and the console, never by the lane: their values come from `@gray/control/catalog`,
// `@gray/control/standing` and `@gray/control/model-names`. Their types stay here.
export type * from "./catalog.ts";
export type * from "./model-names.ts";
export type * from "./standing.ts";
