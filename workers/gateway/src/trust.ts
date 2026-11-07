import type { GatewayConfig } from "@gray/config";
import { parseStrict } from "@gray/json";
import { type InspectionResult, RegexEngineUnavailable, type StreamCheck, TrustPolicy, answerContract, configureTrust } from "@gray/trust/workerd";
import type { Protocol } from "@gray/protocol";
import { type AnswerInspector, type FragmentUse, GateCapacity, type GateRequest, type GateVerdict, type StreamInspector, type ToolGate } from "./gate.ts";

/**
 * The production tool gate: @gray/trust's policy behind the gateway's `ToolGate` (gate.ts;
 * docs/cloudflare-native/trust.md section 2). The policy is the TRUST_POLICY var, the same JSON
 * document as the server's GRAY_TRUST_POLICY_FILE (crates/gray-gateway/src/config/mod.rs:460);
 * unset it is `{}`: enforce mode, tools authorised by the request's own declarations, no secret
 * markers. It is compiled once per isolate (and again only when the var changes), and the gate's
 * tunables (TRUST_*) are set before.
 *
 * This module imports `@gray/trust/workerd`, which hands the regex engine its wasm module at import
 * time: Worker code only (index.ts). Tests that are not about the gate use `PASS_THROUGH`.
 */

function verdict(result: InspectionResult): GateVerdict {
  if (!result.ok) return { ok: false, violation: result.violation };
  return { ok: true, violations: result.inspection.violations, passed: result.inspection.passed };
}

/** Both inspections of one request, their findings together; the first refusal wins. */
export function combined(a: GateVerdict, b: GateVerdict): GateVerdict {
  if (!a.ok) return a;
  if (!b.ok) return b;
  return { ok: true, violations: [...a.violations, ...b.violations], passed: [...a.passed, ...b.passed] };
}

class TrustInspector implements StreamInspector {
  private readonly check: StreamCheck;

  constructor(check: StreamCheck) {
    this.check = check;
  }

  get holdsToolCalls(): boolean {
    return this.check.holdsToolCalls;
  }

  observe(events: Parameters<StreamCheck["observe"]>[0]): GateVerdict {
    return verdict(this.check.observe(events));
  }

  releasable(): boolean {
    return this.check.releasable();
  }

  finish(): GateVerdict {
    return verdict(this.check.finish());
  }

  fragmentRepairs(): ReadonlySet<bigint> {
    return this.check.fragmentRepairs();
  }

  retainedBytes(): number {
    return this.check.retainedBytes();
  }
}

/** The gate of one compiled policy. */
export class TrustGate implements ToolGate {
  private readonly policy: TrustPolicy;

  constructor(policy: TrustPolicy) {
    this.policy = policy;
  }

  get mode(): string {
    return this.policy.mode;
  }

  inspectRequest(request: GateRequest, opaque: boolean): GateVerdict {
    // A body whose conversation Gray did not read cannot pass a search for secret markers in it.
    // Rust reads every body whole, so the case is the CF gateway's own (tiers B and C); the gate's
    // own rule for a request without its native body gives the code (`trust_opaque_tool_payload`).
    if (opaque && this.policy.config.secretDenyMarkers.length > 0) {
      const opaqueVerdict = verdict(this.policy.decision("trust_opaque_tool_payload", []));
      if (!opaqueVerdict.ok) return opaqueVerdict;
      const rest = this.inspect(request);
      return combined(opaqueVerdict, rest);
    }
    return this.inspect(request);
  }

  private inspect(request: GateRequest): GateVerdict {
    try {
      return verdict(this.policy.inspectRequest(request));
    } catch (error) {
      if (error instanceof RegexEngineUnavailable) throw new GateCapacity(error.message);
      throw error;
    }
  }

  contract(request: GateRequest): GateRequest {
    return answerContract(request);
  }

  holdsToolCalls(request: GateRequest): boolean {
    return this.policy.requiresBufferedStream(request.request);
  }

  stream(contract: GateRequest, answerLimit: number, gated: boolean, fragments: FragmentUse = "forwarded"): StreamInspector {
    return new TrustInspector(this.policy.streamCheck(contract, answerLimit, gated ? { gated: true, fragments } : { fragments }));
  }

  answer(contract: GateRequest, protocol: Protocol, answerLimit: number): AnswerInspector | null {
    return this.policy.answerCheck(contract, protocol, answerLimit);
  }

  inspectResponse(contract: GateRequest, answer: { readonly protocol: GateRequest["request"]["protocol"]; readonly body: Parameters<TrustPolicy["inspectResponse"]>[1]["body"] }, answerLimit: number): GateVerdict {
    return verdict(this.policy.inspectResponse(contract, answer, answerLimit));
  }
}

let compiled: { readonly key: string; readonly gate: TrustGate } | null = null;

/**
 * The isolate's gate for `cfg`. Throws the policy's TrustConfigError when TRUST_POLICY is not a
 * policy the server would read, so a bad var fails every request rather than serving without it.
 */
export function trustGate(cfg: GatewayConfig): TrustGate {
  const key = JSON.stringify([cfg.trustPolicy, cfg.trustRegexCompileMaxBytes, cfg.trustSchemaCompileBudgetMs, cfg.trustSchemaCacheSubschemas, cfg.trustVerdictCacheKeyUnits]);
  if (compiled !== null && compiled.key === key) return compiled.gate;
  configureTrust({
    regexCompileMaxBytes: cfg.trustRegexCompileMaxBytes,
    schemaCompileBudgetMs: cfg.trustSchemaCompileBudgetMs,
    schemaCacheSubschemas: cfg.trustSchemaCacheSubschemas,
    verdictCacheKeyUnits: cfg.trustVerdictCacheKeyUnits,
  });
  const gate = new TrustGate(TrustPolicy.fromJson(parseStrict(cfg.trustPolicy)));
  compiled = { key, gate };
  return gate;
}
