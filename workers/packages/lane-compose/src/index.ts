/**
 * @gray/lane-compose: the supply app-compose policy (docs/confidential-lane-supply-implementation.md §3,
 * S7, S50, S54). Gray's release gate and gray-assistant's pull-token service run the same rules on the same bytes:
 * the app-compose JSON a relay-stack lane measures must contain nothing that could read the relay's
 * image. The rules are a closed allowlist: every member, key and value not named here is refused.
 *
 * The compose names no relay (S54): one compose serves every relay of a Gray release. The relay runs the local
 * slot pre-launch fills with the image the relay's token service chose and signed (S50, S51), and the relay's
 * identity reaches the services only through the two interpolations `STACK_LAYOUT.interpolations` names, whose
 * values pre-launch measured. Who the boot serves is therefore not this policy's question: the token service
 * reads the boot's `gray-stack-identity` event (@gray/lane-verify `stackBootFacts`).
 *
 * Problems carry a stable `code`, a `path` (`services.relay.user`, `pre_launch_script`,
 * `expectation.relayImage`) and a fixed message per code; never a value from the input.
 *
 * Pure code: no I/O, loaded in Node and in workerd.
 */
import { get, isArray, isObject, parseStrict, type Json, type JsonObject } from "@gray/json";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { STACK_LAYOUT } from "./layout.ts";
import { isYamlMap, parseComposeText, type YamlMap, type YamlValue } from "./yaml.ts";

export { STACK_LAYOUT, type StackLayout } from "./layout.ts";
// The strict compose reader, for relay-kit's `upgrade`, which reads the kit's own compose.yaml.
export { isYamlMap, parseComposeText, type YamlMap } from "./yaml.ts";

export interface SupplyExpectation {
  /** Digests the relay accepts for Gray's services (from the signed release list's `stack.gray_image`). */
  readonly grayImages: readonly string[];
  /** The one pre-launch script both sides accept: SHA-256 of its UTF-8 text, lower hex. */
  readonly preLaunchSha256: string;
  /**
   * Routing PR 9: the environment's release public key (64 lower-case hex), the one the relay verifies Gray's lists with.
   * When given, a compose whose lane names LANE_RELEASE_PUBLIC_KEY names exactly this one: a backend that verified
   * hellos against lists another key signs would serve entries Gray never released.
   */
  readonly releasePublicKey?: string;
  /** Routing PR 9: the environment's freshness public key, held to lane's LANE_RELEASE_FRESHNESS_PUBLIC_KEY the same way. */
  readonly releaseFreshnessPublicKey?: string;
}

const PROBLEM_TEXT = {
  expectation_invalid: "the expectation itself is malformed",
  app_compose_not_json: "the app-compose is not one strict JSON object (duplicate keys are refused)",
  app_compose_member_unknown: "an app-compose member outside the allowlist of its form (dstack or Phala-normalized)",
  app_compose_member_mismatch: "an app-compose member is missing or not the value the release tooling renders",
  runner_not_compose: "runner must be docker-compose",
  bash_script_present: "bash_script must be absent",
  init_script_not_empty: "init_script must be absent or empty",
  pre_launch_script_mismatch: "pre_launch_script is not the accepted script",
  allowed_envs_mismatch: "allowed_envs must be exactly the stack set (S8)",
  public_output_enabled: "public_logs and public_sysinfo must be false",
  swap_size_present: "swap_size must be absent",
  kms_not_enabled: "kms_enabled must be true",
  key_provider_not_kms: "the key provider must be the KMS (no local key provider)",
  docker_compose_file_invalid: "docker_compose_file is not a YAML mapping this policy can read",
  yaml_syntax_forbidden: "YAML anchors, aliases, merge keys, custom tags and directives are refused",
  yaml_warning: "the YAML parser warned; warnings are refused",
  compose_key_unknown: "a top-level compose key outside the allowlist",
  compose_name_mismatch: "the compose project name is not the layout's",
  service_missing: "a stack service is missing",
  service_unknown: "a service outside the stack layout",
  service_invalid: "a service is not a mapping",
  service_key_forbidden: "a forbidden service setting (build, namespaces, devices, privileges, DNS, host entries)",
  service_key_not_allowed: "a service setting this service may not carry",
  image_mismatch: "the service image is not the expected pinned digest (the relay: its local slot, S50)",
  pull_policy_mismatch: "the relay's slot must be pull_policy: never, and no other service sets a pull policy (S50)",
  bind_mount_forbidden: "a host bind mount other than lane's guest-agent socket and S2a's ACME account directory (read-write on lane)",
  docker_socket_mount: "the Docker socket may never be mounted",
  image_mount_forbidden: "an image mount (type: image) is refused",
  volume_undeclared: "a named volume not declared at the top level",
  volume_entry_invalid: "a volume entry this policy cannot read",
  volume_definition_forbidden: "the top-level volumes are not the layout's (the egress socket's plain volume only)",
  volumes_mismatch: "the service's mounts are not the layout's",
  interpolation_forbidden: "a `$` interpolation other than lane's LANE_BRIDGE_KEY_SEED and EAB expressions and the identity's two (S54, D133)",
  identity_interpolation_mismatch: "lane's LANE_STACK_RELAY_ID is not the layout's interpolation (S54)",
  env_passthrough: "an environment name without a value (taken from the host)",
  environment_invalid: "an environment block this policy cannot read (a mapping of names to values)",
  environment_mismatch: "the relay environment must be exactly S4's literals",
  environment_name_forbidden: "an environment name no service may set (rendered-config location, receipt key id, keyset subject, bridge key id, the certificate's test seams)",
  registry_credential_referenced: "a service names Gray's registry credential, which only the measured pre-launch reads (S8a)",
  user_mismatch: "the service user is not the layout's uid:gid",
  group_add_mismatch: "the supplementary groups are not the layout's",
  networks_mismatch: "the service networks or addresses are not the layout's",
  network_definition_mismatch: "the top-level networks are not S3's",
  ports_mismatch: "the published ports are not the layout's",
  tmpfs_mismatch: "the tmpfs mounts are not the layout's",
  logging_mismatch: "the logging driver is not the layout's",
  limit_mismatch: "a resource limit or OOM priority is not the layout's",
  restart_mismatch: "the restart policy is not the layout's",
  depends_on_mismatch: "the dependencies are not the layout's",
  healthcheck_mismatch: "the health check is not the layout's (egress: the relay's trust bundle is written, D1)",
  command_mismatch: "the entrypoint or command is not the layout's",
  listen_address_mismatch: "lane's client listener is not its front address (S3)",
  lane_environment_mismatch: "a fixed lane literal (relay config listener, relay address) is not the layout's",
  acme_key_dir_mismatch: "lane's gray-acme does not keep this boot's certificate key on its /run/lane tmpfs and its accounts on the S2a directory (D133)",
  release_key_invalid: "lane's release-list keys are not both set as two different 64 lower-case hex keys (routing PR 9)",
  release_key_mismatch: "lane's release-list key is not the environment's the relay verifies Gray's lists with (routing PR 9)",
  entry_environment_forbidden: "an entry's setting (LANE_PEERS, PEER_*) in the relay-stack layout: a stack VM is never an entry (routing PR 9)",
  isolation_missing: "a container hardening setting (read_only, cap_drop, security_opt, ulimits) is missing or different",
} as const;

export type ProblemCode = keyof typeof PROBLEM_TEXT;
export const PROBLEM_CODES = Object.freeze(Object.keys(PROBLEM_TEXT) as ProblemCode[]);

export interface Problem {
  readonly code: ProblemCode;
  readonly path: string;
  readonly message: string;
}

export interface SupplyServiceFacts {
  readonly name: string;
  readonly image: string | null;
  readonly user: string | null;
}

/** A parsed view for logs and the panel. Never throws; what cannot be read is null. */
export interface SupplyFacts {
  /** SHA-256 of the exact JSON text: what the `compose-hash` event measures. */
  readonly appComposeSha256: string;
  readonly parsed: boolean;
  readonly runner: string | null;
  readonly preLaunchSha256: string | null;
  readonly allowedEnvs: readonly string[] | null;
  readonly kmsEnabled: boolean | null;
  readonly services: readonly SupplyServiceFacts[];
  /**
   * lane's `LANE_KMS_URL` literal (P2c-2): the on-chain KMS an app of phase 2 keeps its lease with; null when lane names
   * none (phase 1) or the compose cannot be read. A fact, not a check: `checkSupplyAppCompose` checks it.
   */
  readonly laneKmsUrl: string | null;
  /**
   * P6: whether lane's volumes bind the relay's vault directory read-write at its own path (P2e, the layout's
   * `laneVaultVolumes` line). A fact, as `laneKmsUrl`; the policy requires it exactly when lane names its KMS.
   */
  readonly laneVaultBind: boolean;
}

const COMPOSE_TOP_KEYS = Object.freeze(["name", "services", "networks", "volumes"]);

/** Refused on every service, whatever the value (§3; plus the other namespace, device and link settings). */
const FORBIDDEN_SERVICE_KEYS = Object.freeze([
  "build", "volumes_from", "network_mode", "pid", "ipc", "runtime", "devices", "sysctls", "extra_hosts", "dns",
  "dns_search", "dns_opt", "privileged", "cap_add", "userns_mode", "uts", "cgroup", "cgroup_parent",
  "device_cgroup_rules", "links", "external_links", "gpus", "extends",
]);

/** The problem a fixed setting that differs from `STACK_LAYOUT.fixed` reports. */
const FIXED_CODES: Readonly<Record<string, ProblemCode>> = Object.freeze({
  user: "user_mismatch",
  group_add: "group_add_mismatch",
  networks: "networks_mismatch",
  restart: "restart_mismatch",
  depends_on: "depends_on_mismatch",
  healthcheck: "healthcheck_mismatch",
  entrypoint: "command_mismatch",
  command: "command_mismatch",
  volumes: "volumes_mismatch",
  tmpfs: "tmpfs_mismatch",
  environment: "environment_mismatch",
  mem_limit: "limit_mismatch",
  memswap_limit: "limit_mismatch",
  pids_limit: "limit_mismatch",
  cpus: "limit_mismatch",
  oom_score_adj: "limit_mismatch",
  logging: "logging_mismatch",
  image: "image_mismatch",
  pull_policy: "pull_policy_mismatch",
});

/** D101: the node KMS's P-256 `ca_pubkey` as Phala's `key_provider_id` (app-compose.mjs `validateKmsCaPubkey`). */
const KEY_PROVIDER_ID = /^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$/;

/** `name@sha256:<64 hex>`: a digest, never a tag (app-compose.mjs). */
const PINNED_IMAGE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:([0-9a-f]{64})$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

class Problems {
  readonly list: Problem[] = [];
  add(code: ProblemCode, path: string): void {
    if (this.list.some((problem) => problem.code === code && problem.path === path)) return;
    this.list.push({ code, path, message: PROBLEM_TEXT[code] });
  }
}

function sha256Hex(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text)));
}

/** A scalar as compose-go reads it into a string field; collections and null are undefined. */
function scalarText(value: YamlValue | undefined): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  return undefined;
}

function keyText(key: unknown): string {
  return typeof key === "string" ? key : String(key);
}

function sameStrings(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((item, index) => item === expected[index]);
}

/** A list of scalars as strings, or undefined when it is not one. */
function scalarList(value: YamlValue | undefined): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const item of value) {
    const text = scalarText(item);
    if (text === undefined) return undefined;
    out.push(text);
  }
  return out;
}

/**
 * A parsed YAML (or JSON) value equals an expected plain value exactly: mappings with the same string
 * keys in any order, sequences in order, scalars of the same type and value (`cpus: 1.5` is not "1.5"),
 * as app-compose.mjs compares its canonical JSON. A JSON integer (a bigint) equals the same integer.
 */
function sameValue(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && actual.length === expected.length && expected.every((member, index) => sameValue(actual[index], member));
  }
  if (expected !== null && typeof expected === "object") {
    const entries = Object.entries(expected);
    if (isYamlMap(actual)) {
      return actual.size === entries.length && entries.every(([key, member]) => actual.has(key) && sameValue(actual.get(key), member));
    }
    if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
    const record = actual as Record<string, unknown>;
    return Object.keys(record).length === entries.length && entries.every(([key, member]) => Object.hasOwn(record, key) && sameValue(record[key], member));
  }
  // @gray/json reads an integer as a bigint (serde_json's u64/i64); the yaml package as a number.
  if (typeof expected === "number" && typeof actual === "bigint") return Number.isInteger(expected) && actual === BigInt(expected);
  return actual === expected;
}

/** Every key and string scalar of a value with its path, for the document-wide rules. */
function walkStrings(value: YamlValue, path: string, visit: (text: string, path: string) => void): void {
  if (isYamlMap(value)) {
    for (const [key, member] of value) {
      const memberPath = path === "" ? keyText(key) : `${path}.${keyText(key)}`;
      if (typeof key === "string") visit(key, memberPath);
      walkStrings(member, memberPath, visit);
    }
  } else if (Array.isArray(value)) {
    value.forEach((member, index) => walkStrings(member, `${path}[${index}]`, visit));
  } else if (typeof value === "string") {
    visit(value, path);
  }
}

// ---------------------------------------------------------------------------------------------------
// The expectation and the app-compose members.

function checkExpectation(expect: SupplyExpectation, problems: Problems): void {
  if (!Array.isArray(expect.grayImages) || expect.grayImages.length === 0) {
    problems.add("expectation_invalid", "expectation.grayImages");
  } else {
    expect.grayImages.forEach((image, index) => {
      if (typeof image !== "string" || !PINNED_IMAGE.test(image)) problems.add("expectation_invalid", `expectation.grayImages[${index}]`);
    });
  }
  if (typeof expect.preLaunchSha256 !== "string" || !SHA256_HEX.test(expect.preLaunchSha256)) {
    problems.add("expectation_invalid", "expectation.preLaunchSha256");
  }
  for (const member of ["releasePublicKey", "releaseFreshnessPublicKey"] as const) {
    const key = expect[member];
    if (key !== undefined && (typeof key !== "string" || !SHA256_HEX.test(key))) problems.add("expectation_invalid", `expectation.${member}`);
  }
}

/** The specific problem a common member reports when it differs; the rest report app_compose_member_mismatch. */
const MEMBER_CODES: Readonly<Record<string, ProblemCode>> = Object.freeze({
  runner: "runner_not_compose",
  public_logs: "public_output_enabled",
  public_sysinfo: "public_output_enabled",
  kms_enabled: "kms_not_enabled",
  key_provider: "key_provider_not_kms",
  local_key_provider_enabled: "key_provider_not_kms",
});

/**
 * The app-compose members (§3): exactly one of app-compose.mjs's two forms. A `features` member makes it
 * the Phala-normalized form (D101), otherwise the dstack form; each has a closed member set and every
 * member its rendered value, so an unknown member, a member of the other form, a missing member and a
 * different value are each refused.
 */
function checkAppComposeMembers(doc: JsonObject, expect: SupplyExpectation, problems: Problems): void {
  const forms = STACK_LAYOUT.appCompose;
  const phala = Object.hasOwn(doc, "features");
  const expected: Readonly<Record<string, unknown>> = { ...forms.common, ...(phala ? forms.phala : forms.dstack) };
  const checkedHere = ["docker_compose_file", "pre_launch_script", "allowed_envs", ...(phala ? ["key_provider_id"] : [])];
  for (const key of Object.keys(doc)) {
    if (key === "bash_script") problems.add("bash_script_present", key);
    else if (key === "swap_size") problems.add("swap_size_present", key);
    else if (key === "init_script" && !emptyInitScript(get(doc, key))) problems.add("init_script_not_empty", key);
    else if (!Object.hasOwn(expected, key) && !checkedHere.includes(key)) problems.add("app_compose_member_unknown", key);
  }
  for (const [key, value] of Object.entries(expected)) {
    if (key === "init_script" && Object.hasOwn(doc, key) && !emptyInitScript(get(doc, key))) continue;
    if (!Object.hasOwn(doc, key) || !sameValue(get(doc, key), value)) problems.add(MEMBER_CODES[key] ?? "app_compose_member_mismatch", key);
  }
  if (phala) {
    const id = get(doc, "key_provider_id");
    if (typeof id !== "string" || !KEY_PROVIDER_ID.test(id)) problems.add("app_compose_member_mismatch", "key_provider_id");
  }

  const preLaunch = get(doc, "pre_launch_script");
  if (typeof preLaunch !== "string" || sha256Hex(preLaunch) !== expect.preLaunchSha256) {
    problems.add("pre_launch_script_mismatch", "pre_launch_script");
  }
  // S8/S8a: exactly the stack's names, in the rendered order (app-compose.mjs --check compares bytes).
  if (!sameValue(get(doc, "allowed_envs"), STACK_LAYOUT.allowedEnvs)) problems.add("allowed_envs_mismatch", "allowed_envs");
}

function emptyInitScript(value: Json | undefined): boolean {
  return value === undefined || value === "" || (isArray(value) && value.length === 0);
}

// ---------------------------------------------------------------------------------------------------
// The compose document.

type EnvValue = string | null;

/**
 * `environment:` as names → values; `null` is a name without a value (compose takes it from the host).
 * Only the mapping form is read: it is the form the layout writes, and its path is what the seed rule names.
 */
function environmentOf(service: YamlMap, path: string, problems: Problems): Map<string, EnvValue> | undefined {
  const raw = service.get("environment");
  const values = new Map<string, EnvValue>();
  if (raw === undefined) return values;
  if (!isYamlMap(raw)) {
    problems.add("environment_invalid", `${path}.environment`);
    return undefined;
  }
  for (const [key, value] of raw) {
    const text = value === null ? null : scalarText(value);
    if (typeof key !== "string" || text === undefined) {
      problems.add("environment_invalid", `${path}.environment.${keyText(key)}`);
      return undefined;
    }
    values.set(key, text);
  }
  return values;
}

/** A lower-case DNS name of at least two labels, not `*.invalid` (an entry the VM dials, LANE_PEER_ENTRIES). */
const PEER_ENTRY_NAME = /^(?=.{1,253}$)(?!.*\.invalid$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Every service: no value-less name (it reads the host's env without a `$`) and no forbidden name. */
function checkEnvironment(name: string, environment: Map<string, EnvValue>, path: string, expect: SupplyExpectation, problems: Problems): void {
  for (const [key, value] of environment) {
    if (value === null) problems.add("env_passthrough", `${path}.environment.${key}`);
    if ((STACK_LAYOUT.forbiddenEnvironment as readonly string[]).includes(key)) problems.add("environment_name_forbidden", `${path}.environment.${key}`);
    if ((STACK_LAYOUT.entryEnvironment as readonly string[]).includes(key)) problems.add("entry_environment_forbidden", `${path}.environment.${key}`);
    if (name !== "lane" && (STACK_LAYOUT.releaseKeyEnvs as readonly string[]).includes(key)) problems.add("release_key_invalid", `${path}.environment.${key}`);
  }
  if (name !== "lane") return;
  checkReleaseKeys(environment, path, expect, problems);
  // S3: lane's client listener is its front address.
  if (environment.get("LISTEN_ADDRESS") !== STACK_LAYOUT.laneListenAddress) {
    problems.add("listen_address_mismatch", `${path}.environment.LISTEN_ADDRESS`);
  }
  // S23/S28: the relay config listener and the relay's address, exactly.
  for (const [key, value] of Object.entries(STACK_LAYOUT.laneStackEnvironment)) {
    if (environment.get(key) !== value) problems.add("lane_environment_mismatch", `${path}.environment.${key}`);
  }
  // D133, relay-outbound-only §3.9: this boot's self-signed key and certificate on lane's tmpfs, exactly.
  for (const [key, value] of Object.entries(STACK_LAYOUT.laneAcmeEnvironment)) {
    if (environment.get(key) !== value) problems.add("acme_key_dir_mismatch", `${path}.environment.${key}`);
  }
  // relay-outbound-only §3.2: the entries the VM dials first, one or more DNS names (the environment's, not fixed).
  const entries = environment.get(STACK_LAYOUT.lanePeerEntriesName);
  if (typeof entries !== "string" || !entries.split(",").every((name) => PEER_ENTRY_NAME.test(name))) {
    problems.add("lane_environment_mismatch", `${path}.environment.${STACK_LAYOUT.lanePeerEntriesName}`);
  }
}

/**
 * Routing PR 9: lane's release-list keys, both or neither (neither: a release before PR 9, no backend mode), each 64
 * lower-case hex, two different keys (D134), and the expectation's when it names them.
 */
function checkReleaseKeys(environment: Map<string, EnvValue>, path: string, expect: SupplyExpectation, problems: Problems): void {
  const [releaseName, freshnessName] = STACK_LAYOUT.releaseKeyEnvs;
  const release = environment.get(releaseName);
  const freshness = environment.get(freshnessName);
  if (release === undefined && freshness === undefined) return;
  const valid = (value: EnvValue | undefined): value is string => typeof value === "string" && SHA256_HEX.test(value);
  if (!valid(release)) problems.add("release_key_invalid", `${path}.environment.${releaseName}`);
  if (!valid(freshness)) problems.add("release_key_invalid", `${path}.environment.${freshnessName}`);
  if (valid(release) && release === freshness) problems.add("release_key_invalid", `${path}.environment.${freshnessName}`);
  if (valid(release) && expect.releasePublicKey !== undefined && release !== expect.releasePublicKey) problems.add("release_key_mismatch", `${path}.environment.${releaseName}`);
  if (valid(freshness) && expect.releaseFreshnessPublicKey !== undefined && freshness !== expect.releaseFreshnessPublicKey) {
    problems.add("release_key_mismatch", `${path}.environment.${freshnessName}`);
  }
}

/**
 * S54: the identity reaches the services only as the layout's expressions: TLS_DOMAIN and LANE_STACK_RELAY_ID on
 * lane. A literal there would serve one relay's name from a compose meant for every relay. D133: the EAB names on
 * lane likewise (a literal would publish the credential in the measured compose).
 */
function checkIdentityInterpolations(services: YamlMap, problems: Problems): void {
  for (const [path, expression] of Object.entries(STACK_LAYOUT.interpolations)) {
    if (path === SEED_PATH) continue;
    const [, serviceName = "", , name = ""] = path.split(".");
    const service = services.get(serviceName);
    if (!isYamlMap(service)) continue;
    const environment = service.get("environment");
    const value = isYamlMap(environment) ? environment.get(name) : undefined;
    if (value !== expression) problems.add("identity_interpolation_mismatch", path);
  }
}

/** D58: exactly the layout's hardening; `ulimits` is `core: 0` (or soft and hard 0) and nothing else. */
function checkHardening(service: YamlMap, path: string, problems: Problems): void {
  const hardening = STACK_LAYOUT.hardening;
  if (service.get("read_only") !== true) problems.add("isolation_missing", `${path}.read_only`);
  if (!sameValue(service.get("cap_drop"), hardening.capDrop)) problems.add("isolation_missing", `${path}.cap_drop`);
  if (!sameValue(service.get("security_opt"), hardening.securityOpt)) problems.add("isolation_missing", `${path}.security_opt`);
  const core = hardening.ulimitsCore;
  const ulimits = service.get("ulimits");
  if (!sameValue(ulimits, { core }) && !sameValue(ulimits, { core: { soft: core, hard: core } })) {
    problems.add("isolation_missing", `${path}.ulimits`);
  }
}

function checkKeys(service: YamlMap, path: string, allowed: readonly string[], problems: Problems): void {
  for (const key of service.keys()) {
    const name = keyText(key);
    if (typeof key === "string" && FORBIDDEN_SERVICE_KEYS.includes(key)) problems.add("service_key_forbidden", `${path}.${name}`);
    else if (typeof key !== "string" || !allowed.includes(key)) problems.add("service_key_not_allowed", `${path}.${name}`);
  }
}

function checkImage(service: YamlMap, path: string, accepted: (image: string) => boolean, problems: Problems): void {
  const image = service.get("image");
  if (typeof image !== "string" || !PINNED_IMAGE.test(image) || !accepted(image)) problems.add("image_mismatch", `${path}.image`);
}

/** Published ports, normalized: `443:443` short form, or the long form with the same meaning (app-compose.mjs). */
function checkPorts(service: YamlMap, path: string, expected: readonly string[], problems: Problems): void {
  const raw = service.get("ports");
  if (raw === undefined) {
    if (expected.length > 0) problems.add("ports_mismatch", `${path}.ports`);
    return;
  }
  if (!Array.isArray(raw)) {
    problems.add("ports_mismatch", `${path}.ports`);
    return;
  }
  const ports: string[] = [];
  for (const item of raw) {
    if (typeof item === "string") ports.push(item.trim());
    else if (isYamlMap(item)) {
      const keys = [...item.keys()];
      const target = scalarText(item.get("target"));
      const published = scalarText(item.get("published"));
      const protocol = item.get("protocol") ?? "tcp";
      const plain = keys.every((key) => key === "target" || key === "published" || key === "protocol");
      ports.push(plain && protocol === "tcp" && target !== undefined && published !== undefined ? `${published}:${target}` : "long-form");
    } else ports.push("unreadable");
  }
  if (!sameStrings(ports, expected)) problems.add("ports_mismatch", `${path}.ports`);
}

/**
 * S2–S5: every fixed setting of the service equals the layout's (`STACK_LAYOUT.fixed`). P2e: lane's mounts are
 * `laneVaultVolumes` instead when lane names the KMS it keeps a lease with (`leased`), so the vault's bind comes with the
 * lease and never without it.
 */
function checkFixed(name: string, service: YamlMap, path: string, leased: boolean, problems: Problems): void {
  const fixed = STACK_LAYOUT.fixed[name as keyof typeof STACK_LAYOUT.fixed] as Readonly<Record<string, unknown>>;
  for (const [key, fixedValue] of Object.entries(fixed)) {
    const expected = name === "lane" && leased && key === "volumes" ? STACK_LAYOUT.laneVaultVolumes : fixedValue;
    if (!sameValue(service.get(key), expected)) problems.add(FIXED_CODES[key] ?? "service_key_not_allowed", `${path}.${key}`);
  }
}

/** The named volumes the top level declares; exactly the layout's. */
function checkTopVolumes(raw: YamlValue | undefined, problems: Problems): Set<string> {
  const declared = new Set<string>();
  const expected = STACK_LAYOUT.volumes as Readonly<Record<string, unknown>>;
  if (!isYamlMap(raw)) {
    problems.add("volume_definition_forbidden", "volumes");
    return declared;
  }
  for (const [key, definition] of raw) {
    if (typeof key === "string") declared.add(key);
    if (typeof key !== "string" || !Object.hasOwn(expected, key) || !sameValue(definition, expected[key])) {
      problems.add("volume_definition_forbidden", `volumes.${keyText(key)}`);
    }
  }
  for (const name of Object.keys(expected)) if (!raw.has(name)) problems.add("volume_definition_forbidden", `volumes.${name}`);
  return declared;
}

const LONG_VOLUME_KEYS = Object.freeze(["type", "source", "target", "read_only", "tmpfs"]);

function hostPath(source: string): boolean {
  return source.startsWith("/") || source.startsWith(".") || source.startsWith("~");
}

/** How a bind is mounted: read-write, read-only, or with options this policy does not accept. */
type BindAccess = "rw" | "ro" | "other";

/**
 * One bind mount. Allowed: the guest-agent socket on lane (read-write: connecting writes to it), and (P2e) the relay's
 * vault directory on lane, read-write at its own path, for an app with a KMS lease. Nothing else, no
 * subpath and no other target (relay-outbound-only §3.9 removed S2a's ACME account directory: gray-acme is
 * self-signed in this layout); the Docker socket gets its own code. (The exact mount lists of `STACK_LAYOUT.fixed`
 * are checked as well; these codes say what a mount would expose.)
 */
function checkBind(serviceName: string, source: string, target: string, access: BindAccess, path: string, problems: Problems): void {
  if (source.includes("docker.sock") || target.includes("docker.sock")) {
    problems.add("docker_socket_mount", path);
    return;
  }
  const guestAgent = serviceName === "lane" && access === "rw" && source === STACK_LAYOUT.dstackSocket && target === STACK_LAYOUT.dstackSocket;
  // P2e: the relay's vault directory, read-write on lane at its own path (checkFixed ties it to LANE_KMS_URL).
  const vault = serviceName === "lane" && access === "rw" && source === STACK_LAYOUT.vaultPath && target === STACK_LAYOUT.vaultPath;
  if (!guestAgent && !vault) problems.add("bind_mount_forbidden", path);
}

/** A short-form bind's access: `source:target` and `:rw` are read-write, `:ro` read-only, any other option is refused. */
function shortBindAccess(parts: readonly string[]): BindAccess {
  if (parts.length === 2 || parts[2] === "rw") return "rw";
  return parts[2] === "ro" ? "ro" : "other";
}

/** A long-form bind's access: only type, source, target and a boolean read_only. */
function longBindAccess(item: YamlMap): BindAccess {
  const readOnly = item.get("read_only");
  const plain = [...item.keys()].every((key) => key === "type" || key === "source" || key === "target" || key === "read_only");
  if (!plain) return "other";
  if (readOnly === undefined || readOnly === false) return "rw";
  return readOnly === true ? "ro" : "other";
}

function checkServiceVolumes(serviceName: string, service: YamlMap, path: string, declared: ReadonlySet<string>, problems: Problems): void {
  const raw = service.get("volumes");
  if (raw === undefined) return;
  if (!Array.isArray(raw)) {
    problems.add("volume_entry_invalid", `${path}.volumes`);
    return;
  }
  raw.forEach((item, index) => {
    const where = `${path}.volumes[${index}]`;
    if (typeof item === "string") {
      const parts = item.split(":");
      if (parts.length === 1) {
        if (item.includes("docker.sock")) problems.add("docker_socket_mount", where);
        return; // An anonymous volume at a container path (the exact list refuses it).
      }
      const [source = "", target = ""] = parts;
      if (parts.length > 3) problems.add("volume_entry_invalid", where);
      else if (hostPath(source) || source.includes("docker.sock")) checkBind(serviceName, source, target, shortBindAccess(parts), where, problems);
      else if (target.includes("docker.sock")) problems.add("docker_socket_mount", where);
      else if (!declared.has(source)) problems.add("volume_undeclared", where);
      return;
    }
    if (!isYamlMap(item) || ![...item.keys()].every((key) => typeof key === "string" && LONG_VOLUME_KEYS.includes(key))) {
      problems.add("volume_entry_invalid", where);
      return;
    }
    const type = item.get("type");
    const source = item.get("source");
    const target = item.get("target");
    if (typeof target !== "string" || (source !== undefined && typeof source !== "string")) {
      problems.add("volume_entry_invalid", where);
      return;
    }
    if (type === "image") problems.add("image_mount_forbidden", where);
    else if (type === "bind") checkBind(serviceName, source ?? "", target, longBindAccess(item), where, problems);
    else if (type === "volume") {
      if (source !== undefined && (hostPath(source) || !declared.has(source))) problems.add("volume_undeclared", where);
      else if (target.includes("docker.sock")) problems.add("docker_socket_mount", where);
    } else if (type !== "tmpfs") problems.add("volume_entry_invalid", where);
  });
}

/** S3: exactly the layout's three networks, each with exactly its definition. */
function checkTopNetworks(raw: YamlValue | undefined, problems: Problems): void {
  const expected = STACK_LAYOUT.networks as Readonly<Record<string, unknown>>;
  if (!isYamlMap(raw)) {
    problems.add("network_definition_mismatch", "networks");
    return;
  }
  for (const [key, definition] of raw) {
    if (typeof key !== "string" || !Object.hasOwn(expected, key) || !sameValue(definition, expected[key])) {
      problems.add("network_definition_mismatch", `networks.${keyText(key)}`);
    }
  }
  for (const name of Object.keys(expected)) if (!raw.has(name)) problems.add("network_definition_mismatch", `networks.${name}`);
}

function checkService(name: string, service: YamlMap, expect: SupplyExpectation, declared: ReadonlySet<string>, problems: Problems): void {
  const path = `services.${name}`;
  const keys = STACK_LAYOUT.serviceKeys[name as keyof typeof STACK_LAYOUT.serviceKeys] as readonly string[];
  checkKeys(service, path, keys, problems);
  // S50: the relay's image and pull policy are fixed values (`STACK_LAYOUT.fixed.relay`); Gray's are the release's digest.
  if (name !== "relay") checkImage(service, path, (image) => Array.isArray(expect.grayImages) && expect.grayImages.includes(image), problems);
  checkHardening(service, path, problems);
  checkPorts(service, path, STACK_LAYOUT.ports[name as keyof typeof STACK_LAYOUT.ports], problems);
  // P2e: whether lane names the KMS it keeps a lease with, read without a problem of its own (environmentOf reports those).
  const rawEnvironment = service.get("environment");
  checkFixed(name, service, path, isYamlMap(rawEnvironment) && rawEnvironment.has(STACK_LAYOUT.kmsUrlName), problems);
  checkServiceVolumes(name, service, path, declared, problems);
  const environment = environmentOf(service, path, problems);
  if (environment !== undefined) checkEnvironment(name, environment, path, expect, problems);
}

const SEED_PATH = `services.lane.environment.${STACK_LAYOUT.seed.name}`;

function checkComposeDocument(data: YamlMap, expect: SupplyExpectation, problems: Problems): void {
  for (const key of data.keys()) {
    if (typeof key !== "string" || !COMPOSE_TOP_KEYS.includes(key)) problems.add("compose_key_unknown", keyText(key));
  }
  if (data.get("name") !== STACK_LAYOUT.composeName) problems.add("compose_name_mismatch", "name");
  const services = data.get("services");
  if (!isYamlMap(services)) {
    problems.add("docker_compose_file_invalid", "services");
    return;
  }
  const required: readonly string[] = STACK_LAYOUT.services;
  for (const name of required) if (!services.has(name)) problems.add("service_missing", `services.${name}`);
  const declared = checkTopVolumes(data.get("volumes"), problems);
  for (const [key, service] of services) {
    const name = keyText(key);
    const path = `services.${name}`;
    if (typeof key !== "string" || !required.includes(key)) {
      problems.add("service_unknown", path);
      continue;
    }
    if (!isYamlMap(service)) {
      problems.add("service_invalid", path);
      continue;
    }
    checkService(key, service, expect, declared, problems);
  }
  checkTopNetworks(data.get("networks"), problems);
  checkIdentityInterpolations(services, problems);

  // Document-wide: the only interpolations are the layout's (the seed, the EAB and the identity's two, each exactly
  // its expression at its place); no service names Gray's registry credential.
  const interpolations = STACK_LAYOUT.interpolations as Readonly<Record<string, string>>;
  const registryNames = STACK_LAYOUT.registryEnvs.map((envName) => new RegExp(`\\b${envName}\\b`));
  walkStrings(data, "", (text, path) => {
    if (text.includes("$") && interpolations[path] !== text) problems.add("interpolation_forbidden", path);
    if (path.startsWith("services.") && registryNames.some((pattern) => pattern.test(text))) problems.add("registry_credential_referenced", path);
  });
}

/**
 * The supply policy (§3): `[]` when the app-compose passes for this relay's expectation, otherwise
 * every problem found. A malformed expectation is a problem too, never an exception.
 */
export function checkSupplyAppCompose(appComposeJson: string, expect: SupplyExpectation): Problem[] {
  const problems = new Problems();
  checkExpectation(expect, problems);
  let doc: Json;
  try {
    doc = parseStrict(appComposeJson);
  } catch {
    problems.add("app_compose_not_json", "");
    return problems.list;
  }
  if (!isObject(doc)) {
    problems.add("app_compose_not_json", "");
    return problems.list;
  }
  checkAppComposeMembers(doc, expect, problems);
  const composeText = get(doc, "docker_compose_file");
  if (typeof composeText !== "string") {
    problems.add("docker_compose_file_invalid", "docker_compose_file");
    return problems.list;
  }
  const parsed = parseComposeText(composeText);
  if (!parsed.ok) {
    problems.add(parsed.code, "docker_compose_file");
    return problems.list;
  }
  checkComposeDocument(parsed.value, expect, problems);
  return problems.list;
}

/** A parsed view of the app-compose for logs and the panel; never throws, never carries env values (lane's KMS URL is a public literal). */
export function supplyComposeFacts(appComposeJson: string): SupplyFacts {
  const facts: SupplyFacts = {
    appComposeSha256: sha256Hex(appComposeJson),
    parsed: false,
    runner: null,
    preLaunchSha256: null,
    allowedEnvs: null,
    kmsEnabled: null,
    services: [],
    laneKmsUrl: null,
    laneVaultBind: false,
  };
  let doc: Json;
  try {
    doc = parseStrict(appComposeJson);
  } catch {
    return facts;
  }
  if (!isObject(doc)) return facts;
  const runner = get(doc, "runner");
  const preLaunch = get(doc, "pre_launch_script");
  const envs = get(doc, "allowed_envs");
  const kms = get(doc, "kms_enabled");
  const composeText = get(doc, "docker_compose_file");
  const parsed = typeof composeText === "string" ? parseComposeText(composeText) : undefined;
  const services: SupplyServiceFacts[] = [];
  let laneKmsUrl: string | null = null;
  let laneVaultBind = false;
  const vaultLine = `${STACK_LAYOUT.vaultPath}:${STACK_LAYOUT.vaultPath}`;
  if (parsed?.ok === true) {
    const map = parsed.value.get("services");
    if (isYamlMap(map)) {
      for (const [key, service] of map) {
        const image = isYamlMap(service) && typeof service.get("image") === "string" ? (service.get("image") as string) : null;
        const user = isYamlMap(service) ? (scalarText(service.get("user")) ?? null) : null;
        services.push({ name: keyText(key), image, user });
        const environment = isYamlMap(service) ? service.get("environment") : undefined;
        if (keyText(key) === "lane" && isYamlMap(environment)) {
          const url = environment.get(STACK_LAYOUT.kmsUrlName);
          laneKmsUrl = typeof url === "string" ? url : null;
        }
        const volumes = isYamlMap(service) ? service.get("volumes") : undefined;
        if (keyText(key) === "lane" && Array.isArray(volumes)) laneVaultBind = volumes.some((volume) => volume === vaultLine);
      }
    }
  }
  return {
    ...facts,
    parsed: parsed?.ok === true,
    runner: typeof runner === "string" ? runner : null,
    preLaunchSha256: typeof preLaunch === "string" ? sha256Hex(preLaunch) : null,
    allowedEnvs: isArray(envs) && envs.every((name) => typeof name === "string") ? (envs as string[]) : null,
    kmsEnabled: typeof kms === "boolean" ? kms : null,
    services,
    laneKmsUrl,
    laneVaultBind,
  };
}
