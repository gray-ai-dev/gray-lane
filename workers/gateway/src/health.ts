import type { GatewayConfig } from "@gray/config";

/** `GET /livez`: the isolate runs and its configuration parsed (the server's /livez, crates/gray-gateway/src/app.rs). */
export function livez(cfg: GatewayConfig): Response {
  return Response.json({ status: "alive", worker: "gray-gateway", deployEnv: cfg.deployEnv });
}
