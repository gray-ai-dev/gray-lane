/**
 * `TrustPolicy` (crates/gray-gateway/src/trust.rs): the local policy checks at the request and
 * answer trust boundary. It never executes commands, fetches URLs, rewrites payloads or proves model
 * identity, and it does not read the model an answer names (owner, 2026-10-16). A valid schema is not
 * evidence that a tool call preserves the upstream model's intent; the optional command, package and
 * URL rules address a finite set of the router attacks in https://arxiv.org/html/2604.08407v1.
 *
 * Two findings about an answer's calls are recorded and passed through rather than refused: a call to
 * a tool the request did not declare, and arguments the declared schema refuses or that are not an
 * object. A client runs only the tools it declared and checks their arguments against its own
 * declaration, as it does when it talks to the upstream directly. Every rule that reads a declared
 * call's arguments for Gray itself (an operator schema, URL or command rule) still refuses, and so do
 * the tool-selection, secret, payload, protocol and shape rules.
 *
 * Requests travel as the canonical projection plus the parsed native body (`body`), which is what
 * Rust keeps as `raw_body`; `undefined` is Rust's `None`.
 */
import { type Json, get, isObject, pointer, serializedLength, utf8Length } from "@gray/json";
import type { CanonicalEvent, CanonicalRequest, Protocol } from "@gray/protocol";
import { AnswerCallCheck } from "./answer.ts";
import { type TrustMode, type TrustPolicyConfig, TrustConfigError, parseTrustPolicyConfig } from "./config.ts";
import { inspectToolDeclarations, inspectToolSelection } from "./declarations.ts";
import { MARKER_MAX_BYTES, MARKER_MIN_BYTES, MAX_TOOLS, TOOL_NAME_MAX_BYTES } from "./limits.ts";
import { domainProblem, inspectCommand, inspectUrl, safePackageSpec } from "./rules.ts";
import { type CompileAllowance, RegexEngineUnavailable, compileAllowance, withCompileAllowance } from "./engine.ts";
import { type SchemaValidator, schemaCompiles, schemaValidator, withinCompileBudget } from "./schema.ts";
import { inspectNativeStream, responseCalls } from "./shapes.ts";
import { StreamToolInspector } from "./inspector.ts";
import { type StreamCheck, type StreamCheckOptions, streamCheck } from "./stream.ts";
import { type InspectionResult, NOTHING_FOUND, type TrustViolation, attempt, pass, refuse } from "./violations.ts";

/** A canonical request with the native body it was parsed from (Rust's `raw_body`). */
export interface GateRequest {
  readonly request: CanonicalRequest;
  readonly body: Json | undefined;
}

/** An answer as the gate reads it: its protocol and its native body. */
export interface GateAnswer {
  readonly protocol: Protocol;
  readonly body: Json;
}

function problem(message: string): never {
  throw new TrustConfigError("config", message);
}

/** `validate_pointer`: a JSON pointer starting with `/` whose `~` escapes are `~0` or `~1`. */
function pointerProblem(path: string): string | undefined {
  if (!path.startsWith("/") || path.split("~").slice(1).some((s) => !s.startsWith("0") && !s.startsWith("1"))) {
    return "invalid argument JSON pointer";
  }
  return undefined;
}

/** `contains_secret`: a marker inside any string or key of the decoded request. */
function containsSecret(value: Json, markers: readonly string[]): boolean {
  if (typeof value === "string") return markers.some((marker) => value.includes(marker));
  if (Array.isArray(value)) return value.some((v) => containsSecret(v, markers));
  if (isObject(value)) {
    return Object.keys(value).some((key) => markers.some((marker) => key.includes(marker)) || containsSecret(value[key] as Json, markers));
  }
  return false;
}

/**
 * A schema compile after admission (an answer calling a tool). Compiling a schema decides its patterns
 * in scratch instances, which cannot trap the engine; checking the schema against its meta-schema
 * matches the meta-schema's own patterns in the isolate's instance, which can (src/engine.ts). A trap
 * there, or the answer's compile allowance running out, after the upstream has answered, counts as the
 * schema not compiling, `trust_invalid_tool_schema`, instead of throwing.
 */
function afterAdmission<T>(check: () => T | undefined): T | undefined {
  try {
    return check();
  } catch (error) {
    if (error instanceof RegexEngineUnavailable) return undefined;
    throw error;
  }
}

/**
 * The validators of a request's declared tools, each compiled when an answer first calls its tool and
 * kept for the rest of that answer (`ToolSchemas`). The declarations were checked whole beforehand,
 * each schema compiled and let go, so what an answer holds grows with the tools it calls (at most
 * `MAX_TOOLS`), not with the tools its request declared.
 */
export class ToolSchemas {
  private readonly compiled = new Map<string, SchemaValidator>();
  /** The answer's allowance for compiling patterns new to the isolate (src/engine.ts). */
  readonly allowance: CompileAllowance = compileAllowance();

  /** The validator of the declared tool `name`, or undefined when the request declared no such tool. */
  declared(request: CanonicalRequest, name: string): SchemaValidator | undefined {
    let validator = this.compiled.get(name);
    if (validator === undefined) {
      const tool = request.tools.find((t) => t.name === name);
      if (tool === undefined) return undefined;
      validator = afterAdmission(() => schemaValidator(tool.parameters));
      if (validator === undefined) refuse("trust_invalid_tool_schema");
      this.compiled.set(name, validator);
    }
    return validator;
  }
}

export class TrustPolicy {
  readonly config: TrustPolicyConfig;
  private readonly operatorSchemas: ReadonlyMap<string, SchemaValidator>;

  private constructor(config: TrustPolicyConfig, operatorSchemas: ReadonlyMap<string, SchemaValidator>) {
    this.config = config;
    this.operatorSchemas = operatorSchemas;
  }

  /**
   * `TrustPolicy::compile`: throws `TrustConfigError` (kind `config`) with the Rust message, or
   * `RegexEngineTrapped` when the regex engine trapped meanwhile (src/engine.ts).
   */
  static compile(config: TrustPolicyConfig): TrustPolicy {
    if (config.secretDenyMarkers.some((m) => utf8Length(m) < MARKER_MIN_BYTES || utf8Length(m) > MARKER_MAX_BYTES)) {
      problem("secret markers must contain 8 to 4096 bytes");
    }
    const operatorSchemas = new Map<string, SchemaValidator>();
    const tools = config.allowedTools;
    if (tools !== undefined) {
      if (tools.size > MAX_TOOLS) problem("too many allowed tools");
      // Map order is the UTF-8 order the config reader sorted by (Rust's BTreeMap).
      for (const [name, policy] of tools) {
        if (name === "" || utf8Length(name) > TOOL_NAME_MAX_BYTES) problem("invalid tool name");
        if (policy.schema !== undefined) {
          const validator = schemaValidator(policy.schema);
          if (validator === undefined) problem("invalid or unsupported operator schema");
          operatorSchemas.set(name, validator);
        }
        for (const [path, domains] of policy.urlArguments) {
          const found = pointerProblem(path) ?? domainProblem(domains);
          if (found !== undefined) problem(found);
        }
        if (policy.command !== undefined) {
          const found = pointerProblem(policy.command.argumentPointer) ?? domainProblem(policy.command.downloadDomains);
          if (found !== undefined) problem(found);
          for (const specs of policy.command.allowedPackages.values()) {
            for (const spec of [...specs]) if (!safePackageSpec(spec)) problem("unsupported package specification");
          }
        }
      }
    }
    return new TrustPolicy(config, operatorSchemas);
  }

  /** `serde_json::from_*` and then `compile`, from the configuration's JSON. */
  static fromJson(value: Json): TrustPolicy {
    return TrustPolicy.compile(parseTrustPolicyConfig(value));
  }

  get mode(): TrustMode {
    return this.config.mode;
  }

  /**
   * Gate these streams with a `StreamToolInspector` (or `ToolGate`): frames before the first sign of
   * a tool call are released once inspected; from that frame, or from the first terminal event,
   * every byte is held until the end-of-stream checks pass.
   */
  requiresBufferedStream(request: CanonicalRequest): boolean {
    return this.config.mode === "enforce" && request.stream && request.tools.length > 0;
  }

  /** `decision`: what a check's outcome means in this policy's mode. */
  decision(violation: TrustViolation | undefined, passed: readonly TrustViolation[]): InspectionResult {
    if (this.config.mode === "off") return { ok: true, inspection: NOTHING_FOUND };
    if (violation !== undefined) {
      if (this.config.mode === "enforce") return { ok: false, violation };
      return { ok: true, inspection: { violations: [violation], passed: [...passed] } };
    }
    return { ok: true, inspection: { violations: [], passed: [...passed] } };
  }

  /**
   * `inspect_request`. Throws `RegexEngineUnavailable` when the regex engine trapped while checking it
   * (`RegexEngineTrapped`), or the request spent its allowance for compiling patterns new to this
   * isolate (`RegexEngineBusy`): the gateway answers either as a retryable 429 `gateway_capacity`
   * (src/engine.ts), not as a verdict on the request; the isolate's next request has a new instance,
   * and the patterns decided so far stay decided. Only admission throws it: in the checks after it
   * (`inspectResponse`, `streamToolInspector`, `streamCheck`) either counts as the check failing (a
   * schema that does not compile, `trust_invalid_tool_schema`; arguments that do not validate,
   * `trust_invalid_tool_arguments`), within an allowance of their own per answer.
   */
  inspectRequest(gate: GateRequest): InspectionResult {
    if (this.config.mode === "off") return { ok: true, inspection: NOTHING_FOUND };
    const { request, body } = gate;
    const violation = withCompileAllowance(compileAllowance(), () => attempt(() => {
      if (body !== undefined) {
        const model = get(body, "model");
        if (model !== undefined && model !== request.model) refuse("trust_request_model_mismatch");
        if (containsSecret(body, this.config.secretDenyMarkers)) refuse("trust_secret_denied");
        inspectToolDeclarations(request, body);
      } else if (this.config.secretDenyMarkers.length > 0) {
        // The caller cannot omit native fields and still claim the request passed secret inspection.
        refuse("trust_opaque_tool_payload");
      }
      this.checkTools(gate);
    }));
    return this.decision(violation, []);
  }

  /**
   * `inspect_response_within`: a buffered answer to a request whose answer limit is `argumentLimit`
   * (no call's arguments may be longer, as no part of an answer can).
   */
  inspectResponse(gate: GateRequest, answer: GateAnswer, argumentLimit = Number.MAX_SAFE_INTEGER): InspectionResult {
    if (this.config.mode === "off") return { ok: true, inspection: NOTHING_FOUND };
    const passed: TrustViolation[] = [];
    const schemas = new ToolSchemas();
    const violation = withCompileAllowance(schemas.allowance, () => attempt(() => {
      if (gate.request.protocol !== answer.protocol) refuse("trust_protocol_mismatch");
      this.checkTools(gate, { admitted: true });
      for (const [name, args] of responseCalls(answer.protocol, answer.body)) {
        this.inspectCall(gate, schemas, name, args, passed, argumentLimit);
      }
    }));
    return this.decision(violation, passed);
  }

  /**
   * `inspect_stream_events`, for an open (ungated) stream: one decoded frame's events, before its
   * bytes are released. A request that declared tools streams its calls through a
   * `StreamToolInspector` instead; one that declared none has nothing to hold, so each call (to a tool
   * the client did not declare) is passed and recorded as it arrives.
   */
  inspectStreamEvents(gate: GateRequest, events: readonly CanonicalEvent[]): InspectionResult {
    if (this.config.mode === "off") return { ok: true, inspection: NOTHING_FOUND };
    const { request } = gate;
    const undeclared = request.tools.length === 0;
    const passed: TrustViolation[] = [];
    const violation = attempt(() => {
      for (const event of events) {
        if (event.type === "tool_call_delta" || event.type === "tool_call_complete") {
          if (!undeclared) refuse("trust_streaming_tools_unsupported");
          pass(passed, "trust_tool_not_allowed");
        } else if (event.type === "native") {
          if (event.protocol !== request.protocol) refuse("trust_protocol_mismatch");
          if (inspectNativeStream(event.protocol, event.payload, undeclared).length > 0) pass(passed, "trust_tool_not_allowed");
        }
      }
    });
    return this.decision(violation, passed);
  }

  /**
   * `inspect_buffered_stream`: every event of a held stream at once (the decoder finished at EOF).
   * Every complete call and terminal snapshot is checked; a later snapshot cannot repair a rejected
   * earlier call.
   */
  inspectBufferedStream(gate: GateRequest, events: readonly CanonicalEvent[]): InspectionResult {
    const inspector = this.streamToolInspector(gate);
    const observed = inspector.observe(events);
    if (!observed.ok || observed.inspection.violations.length > 0) return observed;
    const finished = inspector.finish();
    if (!finished.ok) return finished;
    return { ok: true, inspection: { violations: finished.inspection.violations, passed: observed.inspection.passed } };
  }

  /**
   * What the gate holds back of a non-streaming answer to `gate` while it passes (src/answer.ts):
   * in enforce mode its call entries, until each is checked; null in the modes that hold nothing
   * (audit, off), whose findings `inspectResponse` records at the end.
   */
  answerCheck(gate: GateRequest, protocol: Protocol, argumentLimit = Number.MAX_SAFE_INTEGER): AnswerCallCheck | null {
    return this.holdsAnswerCalls() ? new AnswerCallCheck(this, gate, protocol, argumentLimit) : null;
  }

  /** Whether a non-streaming answer's calls are held until checked: enforce mode, whatever the request declared (an opaque shape is refused without any tool). */
  holdsAnswerCalls(): boolean {
    return this.config.mode === "enforce";
  }

  /** The incremental form of `inspectBufferedStream`, for a gated stream. */
  streamToolInspector(gate: GateRequest, argumentLimit = Number.MAX_SAFE_INTEGER): StreamToolInspector {
    const schemas = new ToolSchemas();
    const refused = this.config.mode === "off" ? undefined : withCompileAllowance(schemas.allowance, () => attempt(() => this.checkTools(gate, { admitted: true })));
    return new StreamToolInspector(this, gate, refused ?? schemas, argumentLimit);
  }

  /**
   * The gate of one stream as the relay calls it per frame (src/stream.ts): a `StreamToolInspector`
   * when the stream is gated, `inspectStreamEvents` on each frame when it is open. `answerLimit` is
   * the request's answer limit in bytes (`Admission::answer_limit`), which also bounds every call's
   * arguments.
   */
  streamCheck(gate: GateRequest, answerLimit: number, options?: StreamCheckOptions): StreamCheck {
    return streamCheck(this, gate, answerLimit, options);
  }

  /**
   * `check_tools`: allowed names, no duplicate, and a schema that compiles. Each schema is compiled
   * and let go at once; how many tools a request may declare is the serving API's rule. Before
   * anything is compiled, the schemas' estimated compile time must fit the request's budget, or the
   * request is refused `trust_tool_schemas_too_complex` once every name passed (src/schema.ts; Rust
   * has no such step).
   * `admitted`: the request passed admission in this isolate, so this is a check of its answer
   * (`afterAdmission`).
   */
  checkTools(gate: GateRequest, options?: { readonly admitted?: boolean }): void {
    const { request, body } = gate;
    if (body !== undefined) {
      inspectToolDeclarations(request, body);
      inspectToolSelection(request, body, undefined);
    }
    const compiles = options?.admitted === true ? (schema: Json) => afterAdmission(() => schemaCompiles(schema)) === true : schemaCompiles;
    if (!withinCompileBudget(request.tools.map((tool) => tool.parameters))) {
      // Rust checks each tool's name and then compiles its schema, tool by tool. Over the budget
      // nothing is compiled, so a name refusal anywhere comes first, as Rust gives it unless an
      // earlier tool's schema fails to compile (docs/cloudflare-native/trust.md section 5).
      const names = new Set<string>();
      for (const tool of request.tools) this.checkToolName(tool.name, names);
      refuse("trust_tool_schemas_too_complex");
    }
    const names = new Set<string>();
    for (const tool of request.tools) {
      this.checkToolName(tool.name, names);
      if (!compiles(tool.parameters)) refuse("trust_invalid_tool_schema");
    }
  }

  /** `check_tools`'s name rules for one tool: allowed, and not declared twice (`names` so far). */
  private checkToolName(name: string, names: Set<string>): void {
    if (name === "" || (this.config.allowedTools !== undefined && !this.config.allowedTools.has(name))) refuse("trust_tool_not_allowed");
    if (names.has(name)) refuse("trust_duplicate_tool");
    names.add(name);
  }

  /**
   * `inspect_call`: one call of an answer. A call to an undeclared tool, and arguments the declared
   * schema refuses, are noted in `passed` and let through; the rules below them still apply to the
   * declared call, so a call is never refused less than its operator rules require.
   */
  inspectCall(gate: GateRequest, schemas: ToolSchemas, name: string, args: Json, passed: TrustViolation[], argumentLimit: number): void {
    withCompileAllowance(schemas.allowance, () => this.inspectCallWithin(gate, schemas, name, args, passed, argumentLimit));
  }

  private inspectCallWithin(gate: GateRequest, schemas: ToolSchemas, name: string, args: Json, passed: TrustViolation[], argumentLimit: number): void {
    const { request, body } = gate;
    const schema = schemas.declared(request, name);
    if (schema === undefined) {
      pass(passed, "trust_tool_not_allowed");
      return;
    }
    // A declared tool the request's own selection excludes is one the client would run.
    if (body !== undefined) inspectToolSelection(request, body, name);
    if (request.tool_choice?.type === "none") refuse("trust_tool_not_allowed");
    if (request.tool_choice?.type === "named" && request.tool_choice.name !== name) refuse("trust_tool_not_allowed");
    // Arguments are part of the answer that carries them: bounded by its limit, as serde_json writes them.
    if (serializedLength(args) > BigInt(argumentLimit)) refuse("trust_payload_limit");
    // The arguments are the upstream's: every format is decided as Rust does, `regex` included. Their
    // strings' translations are kept for this answer only, so a string it repeats, or that the operator
    // schema below checks too, is parsed once (`IsValidOptions`, src/pattern.ts `answerTranslations`).
    if (!isObject(args) || !schema.isValid(args, { upstream: true })) pass(passed, "trust_invalid_tool_arguments");
    // An operator schema is Gray's own rule: arguments it cannot read as an object, or refuses, are refused.
    const operator = this.operatorSchemas.get(name);
    if (operator !== undefined && (!isObject(args) || !operator.isValid(args, { upstream: true }))) refuse("trust_invalid_tool_arguments");
    const policy = this.config.allowedTools?.get(name);
    if (policy !== undefined) {
      for (const [path, domains] of policy.urlArguments) {
        const url = pointer(args, path);
        if (typeof url !== "string") refuse("trust_url_not_allowed");
        inspectUrl(url, domains);
      }
      if (policy.command !== undefined) {
        const text = pointer(args, policy.command.argumentPointer);
        if (typeof text !== "string") refuse("trust_command_not_allowed");
        inspectCommand(text, policy.command);
      }
    }
  }
}
