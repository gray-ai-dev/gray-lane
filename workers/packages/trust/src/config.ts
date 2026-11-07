/**
 * The trust policy's configuration (`TrustPolicyConfig`, `ToolPolicy`, `CommandPolicy` in
 * crates/gray-gateway/src/trust.rs) read from JSON as serde reads it: every field optional with its
 * default, an unknown field refused (`deny_unknown_fields`), a value of the wrong type refused.
 *
 * `require_response_model` is not a field here: it made the gate refuse an answer for the model name
 * it reports, which the owner ruled out on 2026-10-16 (release 2 removes the field on the server).
 * A configuration that sets it is refused as naming an unknown field, as release 2 refuses it.
 */
import { type Json, compareUtf8, isArray, isObject } from "@gray/json";

export type TrustMode = "off" | "audit" | "enforce";

/** `PackageManager`, in its derived order (pip, npm, cargo), which decides which check fails first. */
export type PackageManager = "pip" | "npm" | "cargo";
export const PACKAGE_MANAGERS: readonly PackageManager[] = ["pip", "npm", "cargo"];

export interface CommandPolicy {
  /** JSON pointer to the command string in the call's arguments. Default `/command`. */
  readonly argumentPointer: string;
  /** Exact full-command approvals: an explicit operator escape hatch. */
  readonly allowedCommands: ReadonlySet<string>;
  /** Exact package specifications, including any version, per manager. */
  readonly allowedPackages: ReadonlyMap<PackageManager, ReadonlySet<string>>;
  /** Hosts `curl -q URL` and `curl -q -fsS URL` may fetch from. */
  readonly downloadDomains: ReadonlySet<string>;
}

export interface ToolPolicy {
  /** An additional schema; the request's schema is always enforced too. */
  readonly schema: Json | undefined;
  /** JSON pointers whose values must be HTTPS URLs on exact allowed hosts. */
  readonly urlArguments: ReadonlyMap<string, ReadonlySet<string>>;
  readonly command: CommandPolicy | undefined;
}

export interface TrustPolicyConfig {
  readonly mode: TrustMode;
  /** Absent: tools are authorised by the request's declarations alone; present: intersected with these. */
  readonly allowedTools: ReadonlyMap<string, ToolPolicy> | undefined;
  /** Exact, case-sensitive deny markers looked for in the decoded request. */
  readonly secretDenyMarkers: readonly string[];
}

export const DEFAULT_TRUST_POLICY: TrustPolicyConfig = Object.freeze({
  mode: "enforce",
  allowedTools: undefined,
  secretDenyMarkers: Object.freeze([]) as readonly string[],
});

/**
 * Why a configuration was refused. `deserialize`: its JSON is not the configuration's shape (serde's
 * error, whose wording is not kept). `config`: `TrustPolicy::compile` refused a value; `message` is
 * the Rust `TrustConfigError` text.
 */
export class TrustConfigError extends Error {
  override readonly name = "TrustConfigError";
  readonly kind: "deserialize" | "config";

  constructor(kind: "deserialize" | "config", message: string) {
    super(kind === "config" ? `invalid trust policy configuration: ${message}` : message);
    this.kind = kind;
  }

  /** The `TrustConfigError` text without its prefix (the fixtures' `message`). */
  get reason(): string {
    return this.message.replace(/^invalid trust policy configuration: /, "");
  }
}

function shape(message: string): never {
  throw new TrustConfigError("deserialize", message);
}

function fields(value: Json | undefined, where: string, known: readonly string[]): Record<string, Json> {
  if (!isObject(value)) shape(`${where} must be an object`);
  for (const key of Object.keys(value)) if (!known.includes(key)) shape(`unknown field \`${key}\` in ${where}`);
  return value;
}

function string(value: Json | undefined, where: string): string {
  if (typeof value !== "string") shape(`${where} must be a string`);
  return value;
}

/** A serde `BTreeSet<String>` from a JSON array (duplicates collapse). */
function stringSet(value: Json | undefined, where: string): Set<string> {
  if (value === undefined) return new Set();
  if (!isArray(value)) shape(`${where} must be an array`);
  return new Set(value.map((item, i) => string(item, `${where}[${i}]`)));
}

/** A serde `BTreeMap<String, _>` from a JSON object, iterated in Rust's order (UTF-8 bytes). */
function sortedEntries(value: Record<string, Json>): [string, Json][] {
  return Object.keys(value)
    .sort(compareUtf8)
    .map((key) => [key, value[key] as Json]);
}

function commandPolicy(value: Json | undefined, where: string): CommandPolicy {
  const o = fields(value, where, ["argument_pointer", "allowed_commands", "allowed_packages", "download_domains"]);
  const packages = new Map<PackageManager, Set<string>>();
  if (o.allowed_packages !== undefined) {
    const map = o.allowed_packages;
    if (!isObject(map)) shape(`${where}.allowed_packages must be an object`);
    for (const [manager, specs] of sortedEntries(map)) {
      if (!(PACKAGE_MANAGERS as readonly string[]).includes(manager)) shape(`unknown variant \`${manager}\``);
      packages.set(manager as PackageManager, stringSet(specs, `${where}.allowed_packages.${manager}`));
    }
  }
  return {
    argumentPointer: o.argument_pointer === undefined ? "/command" : string(o.argument_pointer, `${where}.argument_pointer`),
    allowedCommands: stringSet(o.allowed_commands, `${where}.allowed_commands`),
    allowedPackages: new Map(PACKAGE_MANAGERS.filter((m) => packages.has(m)).map((m) => [m, packages.get(m) as Set<string>])),
    downloadDomains: stringSet(o.download_domains, `${where}.download_domains`),
  };
}

function toolPolicy(value: Json | undefined, where: string): ToolPolicy {
  const o = fields(value, where, ["schema", "url_arguments", "command"]);
  const urls = new Map<string, Set<string>>();
  if (o.url_arguments !== undefined) {
    if (!isObject(o.url_arguments)) shape(`${where}.url_arguments must be an object`);
    for (const [pointer, domains] of sortedEntries(o.url_arguments)) urls.set(pointer, stringSet(domains, `${where}.url_arguments`));
  }
  return {
    // `Option<Value>`: a JSON null is `None`.
    schema: o.schema === undefined || o.schema === null ? undefined : o.schema,
    urlArguments: urls,
    command: o.command === undefined || o.command === null ? undefined : commandPolicy(o.command, `${where}.command`),
  };
}

/** The configuration's serde form, read; throws `TrustConfigError` of kind `deserialize`. */
export function parseTrustPolicyConfig(value: Json): TrustPolicyConfig {
  const o = fields(value, "the trust policy", ["mode", "allowed_tools", "secret_deny_markers"]);
  let mode: TrustMode = "enforce";
  if (o.mode !== undefined) {
    const m = string(o.mode, "mode");
    if (m !== "off" && m !== "audit" && m !== "enforce") shape(`unknown variant \`${m}\``);
    mode = m;
  }
  let allowedTools: Map<string, ToolPolicy> | undefined;
  if (o.allowed_tools !== undefined && o.allowed_tools !== null) {
    if (!isObject(o.allowed_tools)) shape("allowed_tools must be an object");
    allowedTools = new Map(sortedEntries(o.allowed_tools).map(([name, policy]) => [name, toolPolicy(policy, `allowed_tools.${name}`)]));
  }
  let markers: string[] = [];
  if (o.secret_deny_markers !== undefined) {
    if (!isArray(o.secret_deny_markers)) shape("secret_deny_markers must be an array");
    markers = o.secret_deny_markers.map((m, i) => string(m, `secret_deny_markers[${i}]`));
  }
  return { mode, allowedTools, secretDenyMarkers: markers };
}
