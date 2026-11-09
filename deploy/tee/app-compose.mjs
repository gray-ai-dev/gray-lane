#!/usr/bin/env node
// Generates dstack's app-compose.json for gray-lane from deploy/tee/compose.yaml, and prints the
// `compose_hash` — the digest customers allowlist on chain.
//
//   node deploy/tee/app-compose.mjs                 # writes deploy/tee/app-compose.json, prints the hash
//   node deploy/tee/app-compose.mjs --check         # verifies the committed file is the generated one
//   node deploy/tee/app-compose.mjs --out /tmp/a.json
//   node deploy/tee/app-compose.mjs --allow-placeholders  # development only: keep set-at-deploy / .invalid
//   node deploy/tee/app-compose.mjs --target phala --kms-ca-pubkey <hex>  # Phala's measured form (D101)
//
// A deployment also sets the measured identity and the image (D47):
//
//   node deploy/tee/app-compose.mjs \
//     --deploy-env testnet \
//     --tls-domain lane-staging.usefallback.com \
//     --bridge-url https://gray-lane-staging.example.workers.dev \
//     --keyset-not-after 1798761600 \
//     --image ghcr.io/gray-ai-dev/gray-lane@sha256:<64 hex>
//
// and, when the deployment measures its own pick budget (D109'), `--scheduler-pick-ms <ms>`.
//
// Routing PR 9 (docs/confidential-lane-stack-routing.md section 9.1): `--release-public-key <64 hex>` and
// `--release-freshness-public-key <64 hex>` (the environment's, environments.json) set lane's list keys in either
// layout, and `--lane-peers true|false` (default layout only) sets LANE_PEERS and adds or removes egress's `-peer` and
// `-peer-link /run/peerlink/peerlink.sock` (docs/design/relay-outbound-only.md §3.2) to match. The gate refuses a compose whose keys are missing, malformed or one key twice, whose LANE_PEERS and `-peer`
// disagree, whose stack lane carries an entry's setting, or whose egress -max-body-bytes is below the lane's
// BODY_PARSE_MAX_BYTES.
//
// relay-outbound-only §3.2, §3.8 (PR 1.4): the default layout's third service is `peerlink`, gray-peerlink in the entry
// role on its unix socket (PEERLINK_SOCKET), with no network (`network_mode: "none"`, the only service that may set
// it), its entrypoint and command fixed, and only the `peerlink-socket` volume, which the lane and egress mount too.
//
// `--gateway-enabled true|false` (default layout only; `true` when absent, the committed bytes) sets the app-compose's
// `gateway_enabled`, and in the Phala form `tproxy_enabled` and `features`' `tproxy-net` with it: `false` takes the
// entry off dstack's shared gateway once Cloudflare Spectrum reaches it through Phala's direct port instead
// (deploy/terraform-edge/README.md "The direct origin"). It is measured, so it changes the compose hash.
//
// `--target dstack|phala` defaults to `dstack`, whose bytes are unchanged. `phala` emits exactly the
// form Phala Cloud stores and measures (D101): it omits `requirements.platforms` (and `requirements`
// itself when `platforms` is its only member) and `storage_discard` (D100), and adds
// `features: ["kms","tproxy-net"]`, `init_script: []`, `key_provider_id` (the node KMS's `ca_pubkey`
// from the required `--kms-ca-pubkey`), `port_policy.ports[].pp: false`, `storage_fs: "zfs"` and
// `tproxy_enabled: true`. Phala keeps `docker_compose_file` and `pre_launch_script` byte for byte, so
// regenerating with the same flags reproduces the measured bytes and `compose_hash`.
//
// `--deploy-env`, `--tls-domain`, `--bridge-url`, `--keyset-not-after` and `--scheduler-pick-ms`
// rewrite the matching compose literal; `--tls-domain` sets it in `lane`, and `--image` rewrites both
// `image:` lines (one digest runs both services, D44/D45; D133 moved gray-acme into the lane container,
// so there is no separate acme service). `KEYSET_SUBJECT` is not a generator
// input: the entrypoint derives it from the app id at boot (D47), and a compose that sets it is
// refused rather than measured.
//
// checkCompose parses the compose with the `yaml` package (D58), so flow-style lists, long-form
// port maps and comments cannot hide a setting from the release gate.
//
// `--layout default|stack` (docs/confidential-lane-supply-implementation.md S1-S8, §9 B, S50, S54) picks the
// compose and its gate. `default` is compose.yaml, and its output is byte for byte what this
// generator always wrote. `stack` is compose.stack.yaml: a third-party relay's own image runs as a
// fourth service between the entry and egress, so its gate adds the stack's networks, users, limits,
// logging and start order (each allowed only where the layout has it, checked value by value), the relay's
// local image slot (`gray-relay-slot:boot`, `pull_policy: never`, S50), `allowed_envs` of the bridge seed,
// Gray's registry credential (S8/S8a), the two EAB names (D133) and the relay identity's four `GRAY_STACK_*` names
// (S54), the identity's interpolation (LANE_STACK_RELAY_ID on lane) and
// deploy/tee/pre-launch.stack.sh as the measured pre-launch script. `--pre-launch <path>` overrides the script for either layout.
// relay-outbound-only (docs/design/relay-outbound-only.md §3.8, §3.9, O1): the stack layout adds gray-peerlink, publishes
// no port, renders `gateway_enabled: false` and `port_policy.ports: []`, runs gray-acme self-signed (no EAB, no TLS
// name in the identity, no ACME account directory), and `--peer-entries <name>[,...]` (required for a release: the
// committed `.invalid` placeholder is refused) sets the entries the VM dials first, the environment's entry name.
// One stack compose serves every relay of a release (S54): it names no relay, so the relay flags of earlier
// versions are gone, and so are `--tls-domain` and `--lane-key-id` there (the identity is the app's encrypted
// env; the entrypoint derives the bridge key id from the app id).
// A stack render then runs `@gray/lane-compose`'s `checkSupplyAppCompose` (S7), the policy the relay's
// pull-token service runs, on its own output for either target, and prints the release list's `stack`
// member (S55); `--image` is required for that check.
//
//   node deploy/tee/app-compose.mjs --layout stack --image <gray digest ref> --deploy-env <env> \
//     --bridge-url <https origin> --keyset-not-after <unix seconds> [--target phala --kms-ca-pubkey <hex>]
//
// What dstack does with it (dstack v0.6.1, `dstack/dstack-types/src/lib.rs` `AppCompose`, and
// `docs/security/cvm-boundaries.md`): the guest receives these JSON bytes, hashes exactly them
// (`vmm/src/app/workdir.rs::app_compose_hash`) into RTMR3 as `compose-hash`, and runs
// `docker compose up` on the embedded text. So the bytes are the measured unit: every field below is
// either a security setting a reviewer must see or something the guest needs to start the app.
//
// Field-by-field (IMPLEMENTATION_NOTES.md §9 has the reasoning, and what Phala adds that this does not):
//
// - `manifest_version: "3"` (string): 0.6 guests read `requirements` only at "3", and an older guest
//   refuses the compose instead of silently ignoring the requirement. `docs/upgrading-to-0.6.md`.
// - `runner: "docker-compose"`: the embedded file is a compose file.
// - `public_logs: false`, `public_sysinfo: false`: the lane's logs and system info are not published. Both
//   are set explicitly, because dstack's own default is `false` but a reviewer should not have to know
//   that to read this file.
// - `public_tcbinfo: true`: TCB/measurement info stays public — it is what a verifier needs, and it
//   contains no request data.
// - `kms_enabled: true` and `key_provider: "kms"`: keys are derived through dstack's KMS, so the host
//   cannot unseal what the CVM seals.
// - `allowed_envs` (D19, amended by D44): dstack's allowlist for **host-injected encrypted env** — the
//   `.encrypted-env` JSON the host drops into the shared directory and the CVM decrypts
//   (`docs/security/cvm-boundaries.md:127-129`). It holds the bridge seed (D17) plus the three
//   `DSTACK_DOCKER_*` names the measured `pre_launch_script` uses for `docker login`. No compose
//   service may reference those three (asserted below), so the host cannot use them to overwrite a
//   value the measured compose fixed. The image is public (ghcr.io/gray-ai-dev/gray-lane), so a lane's
//   env seals the three empty and the script skips the login; the names and the script stay measured as
//   they were, so the stack set every relay's gray-relay checks (@gray/lane-compose) does not change.
//   D133 adds `ACME_EAB_KID`/`ACME_EAB_HMAC_KEY`, the lane's External Account Binding for Google Trust
//   Services: they only choose which account registers at a CA that requires EAB, never the key.
// - `pre_launch_script` (D44): the text of `deploy/tee/pre-launch.sh`, embedded verbatim. dstack
//   sources it after dockerd and before `docker compose up` (`os/common/rootfs/app-compose.service:12-14`,
//   `os/common/rootfs/app-compose.sh:157-163`); it only runs `docker login` when all three registry
//   names are set. It is measured into the compose hash, and it is not a security gate
//   (`docs/security/security-best-practices.md:65-85`).
// - `secure_time: true`: receipts carry `served_at` (§7.3), so the clock must not be the host's.
// - `storage_discard: false`: the data disk does not return freed blocks to the host, so the host does
//   not learn allocation and deletion patterns. dstack's default is `true`; this trades disk reuse for
//   that leak, which is the right trade for a confidential lane. D100/D101: `--target phala` omits it
//   (Phala's schema refuses the member); the omission only reveals the encrypted disk's free-block
//   layout, and the measured compose/TDX quote still bind everything that matters.
// - `port_policy: { restrict_mode: true, ports: [{ port: 443 }] }`: the gateway forwards only 443 and
//   rejects every other port at TCP accept.
// - `gateway_enabled: true`: the dstack gateway routes to the app. **Only the TLS-passthrough forms
//   are usable for this lane**: the `s` suffix (`<app-id>-443s.<base-domain>`) or a custom domain with
//   a `_dstack-app-address` TXT record. The default `<app-id>-443.<base-domain>` host *terminates*
//   TLS at the gateway (`gateway/src/proxy.rs:155-168` sets `is_tls` only for the `s` suffix,
//   `:208-219` terminates otherwise), so the gateway would see plaintext and the client would see
//   its certificate, not the CVM's — a client pinning the keyset's TLS SPKI fails closed there.
//   `README.md` names the only address a customer should be handed. `--gateway-enabled false` (default layout
//   only) turns it off, for an entry that Spectrum reaches through Phala's direct port: the shared gateway then
//   routes nothing to the app, by the custom domain or by the `s` host.
// - `requirements.platforms: ["dstack-tdx"]`: the lane is a TDX lane (M0's target), so a guest on another
//   platform refuses the compose instead of running it unmeasured. D100/D101: `--target phala` omits
//   it (Phala's schema refuses `requirements.platforms`); the platform stays bound by the quote's TEE
//   type and the release list's OS measurements, which `gray-lane-verify` checks.
// - No `init_script` for dstack: nothing of ours runs before dockerd. The pre-launch script above only
//   authenticates dockerd for the pull; it does not gate the app. D101: Phala's normalized form adds
//   an empty `init_script: []`, so `--target phala` emits exactly that (and only that target).
// - D101's other Phala-normalized members: `features: ["kms","tproxy-net"]`, `storage_fs: "zfs"` and
//   `tproxy_enabled: true` describe the KMS and tproxy features Phala enables; `key_provider_id` is
//   the node KMS's `ca_pubkey`; `port_policy.ports[].pp` is Phala's per-port proxy flag (false).
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Alias, LineCounter, isScalar, isSeq, parseDocument } from "yaml";
import { SETTINGS } from "../../workers/packages/config/src/index.ts";
import { PEER_TUNABLE_NAMES } from "./bin/entrypoint.mjs";

// S7: the stack layout's final gate is `@gray/lane-compose`, the policy the relay's pull-token service
// runs (checkSupplyGate below). It lives in the workers/ workspace, so its `yaml`, `@noble/hashes` and
// `@gray/json` resolve from workers/node_modules; this file's own `yaml` resolves from deploy/tee's (both
// pinned at 2.9.0). The default layout never needs it, and a checkout that installed only deploy/tee
// (CI's Phala deploy-tool job) still renders compose.yaml, so a failed load is kept, not thrown: the stack
// path refuses to render without the policy.
const SUPPLY_POLICY = await import("../../workers/packages/lane-compose/src/index.ts").then(
  (module) => ({ module }),
  (error) => ({ error }),
);

export const APP_NAME = "gray-lane";
export const MANIFEST_VERSION = "3";
export const RUNNER = "docker-compose";

/**
 * D100: the deployment targets. `dstack` is the full dstack v0.6.1 app-compose (the default, byte
 * for byte what this generator always wrote). `phala` omits the two members Phala Cloud's
 * `/cvms/provision` schema rejects as `extra_forbidden`; every other member and check is identical.
 */
export const TARGETS = Object.freeze(["dstack", "phala"]);

/** D100: the members `--target phala` omits (`requirements` itself when `platforms` is its only key). */
export const PHALA_OMITTED_MEMBERS = Object.freeze(["requirements.platforms", "storage_discard"]);

const here = dirname(fileURLToPath(import.meta.url));
export const COMPOSE_PATH = join(here, "compose.yaml");
export const APP_COMPOSE_PATH = join(here, "app-compose.json");
export const PRE_LAUNCH_PATH = join(here, "pre-launch.sh");

/**
 * D133: the External Account Binding names. gray-acme sends them only when it registers an account at
 * a CA whose directory requires EAB (Google Trust Services); the account then signs orders for a key
 * gray-acme generated in memory. A host-chosen EAB can therefore only change which account the
 * certificate is ordered under (a different account URI in the log), never the certificate key or
 * where it is written. The lane passes them through as `${NAME:-}`, never literals (the measured
 * compose is public).
 */
export const EAB_ENVS = Object.freeze(["ACME_EAB_KID", "ACME_EAB_HMAC_KEY"]);

/**
 * The env names host-injected encrypted env may set (dstack's `allowed_envs` is the allowlist for the
 * host-side `.encrypted-env` JSON, not for what the compose sets).
 *
 * D19, amended by D44: the bridge seed is the one value the lane itself must receive from the host
 * (D17). The three `DSTACK_DOCKER_*` names are read only by the measured `pre_launch_script`, whose
 * sole action is `docker login` before the pull. `TLS_SPKI_SHA256` is computed inside the CVM by
 * `bin/entrypoint.mjs` from this boot's certificate (D133) and is never read from the host.
 * `KEYSET_NOT_AFTER`, `LANE_BRIDGE_URL`, `LANE_KEY_ID`, `TEE_TYPE`, `DEPLOY_ENV`, `TLS_DOMAIN`,
 * `GUEST_AGENT_URL` and the gateway vars are literals in the measured `docker_compose_file`; a host
 * name for any of them is not in this allowlist, so dstack refuses to inject it. `LANE_RECEIPT_KEY_ID`
 * is neither a compose literal nor an entrypoint default: the gateway generates it per boot (D11/D56).
 * D133: the two EAB names (`EAB_ENVS`).
 */
export const ALLOWED_ENVS = Object.freeze([
  "LANE_BRIDGE_KEY_SEED",
  "DSTACK_DOCKER_REGISTRY",
  "DSTACK_DOCKER_USERNAME",
  "DSTACK_DOCKER_PASSWORD",
  ...EAB_ENVS,
]);

/** The registry credential names, which the measured compose must never reference (D44). */
export const REGISTRY_ENVS = Object.freeze(["DSTACK_DOCKER_REGISTRY", "DSTACK_DOCKER_USERNAME", "DSTACK_DOCKER_PASSWORD"]);

/** `image: registry/name@sha256:<64 hex>` — a digest, never a tag. */
const PINNED_IMAGE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$/;
const PLACEHOLDER_DIGEST = /@sha256:0{64}$/;
// D133: spaces and tabs only around the value, never a newline: `\s*` let the trailing group run on into a
// comment line under `image:` and substituteImage dropped that line from the measured compose.
const IMAGE_LINE = /^([ \t]*image:[ \t]*)([^#\n]*?)([ \t]*(?:#.*)?)$/gm;

/**
 * The services of the measured compose (D63; D133 moved gray-acme into the lane container; relay-outbound-only §3.2
 * added the entry's peerlink).
 */
export const SERVICE_NAMES = Object.freeze(["egress", "lane", "peerlink"]);

/**
 * D94: the gate is a closed allowlist, not a denylist. These are exactly the top-level keys and the
 * per-service keys the committed compose uses. Anything else (include, extends, volumes_from,
 * env_file, secrets, configs, devices, network_mode, pid, ipc, privileged, cap_add, expose, ...) is
 * refused before the bytes are measured, whether this parser knows the key or not.
 */
export const TOP_LEVEL_KEYS = Object.freeze(["name", "services", "volumes"]);
export const SERVICE_KEYS = Object.freeze([
  "image", "restart", "depends_on", "ports", "entrypoint", "command", "environment", "volumes",
  "read_only", "tmpfs", "cap_drop", "security_opt", "ulimits",
]);

/**
 * D94: these names may never be set by a measured service (the rendered config is fixed). D133: nor
 * the entrypoint's host-test seams for the certificate (LANE_ACME, LANE_TLS_CERT, LANE_TLS_KEY), so the
 * measured lane always runs the image's gray-acme and serves the pair it wrote to ACME_KEY_DIR; nor
 * gray-acme's pre-D133 ACME_CERT_DIR, nor ACME_TLS_ALPN_ADDRESS, which the entrypoint sets to the lane's
 * own LISTEN_ADDRESS.
 */
export const FORBIDDEN_ENV_NAMES = Object.freeze([
  "LANE_RENDERED", "LANE_TEMPLATE", "LANE_RECEIPT_KEY_ID",
  "LANE_ACME", "LANE_TLS_CERT", "LANE_TLS_KEY", "ACME_CERT_DIR", "ACME_TLS_ALPN_ADDRESS",
]);

/** What the committed compose allows each service to publish (D58). */
const SERVICE_PORTS = Object.freeze({
  egress: Object.freeze([]),
  lane: Object.freeze(["443:443"]),
  peerlink: Object.freeze([]),
});

/** D63: the only volume lane and egress may share, and where it is mounted. */
export const EGRESS_VOLUME = "egress-socket";
export const EGRESS_MOUNT = "/run/gray";
/**
 * relay-outbound-only §3.2, §3.8: peerlink's socket volume and its mount, in both layouts. The lane and peerlink mount
 * it (and on an entry egress, which dials channel peers through peerlink's CONNECT); nothing else may, and peerlink
 * mounts nothing else.
 */
export const PEERLINK_SERVICE = "peerlink";
export const PEERLINK_VOLUME = "peerlink-socket";
export const PEERLINK_MOUNT = "/run/peerlink";
export const PEERLINK_SOCKET = `${PEERLINK_MOUNT}/peerlink.sock`;
/** The lane's setting that names peerlink's socket (bin/entrypoint.mjs `peerlinkLayout`). */
export const PEERLINK_SOCKET_ENV = "PEERLINK_SOCKET";
/** egress's flag that dials channel peers through peerlink (deploy/tee/egress config.go `-peer-link`). */
export const PEER_LINK_FLAG = "-peer-link";
/**
 * relay-outbound-only §3.2, §3.8: the entry's peerlink in the default layout, a closed allowlist of its keys and the
 * exact value of each fixed one. It has no network (`network_mode: "none"`, allowed on no other service), no
 * environment (its settings are peerlink's defaults), no port and no tmpfs; its one mount is checkPeerlinkSocket's.
 */
export const ENTRY_PEERLINK_KEYS = Object.freeze([
  "image", "restart", "entrypoint", "command", "network_mode", "volumes", "read_only", "cap_drop", "security_opt", "ulimits",
]);
export const ENTRY_PEERLINK_FIXED = Object.freeze({
  restart: "unless-stopped",
  entrypoint: ["/usr/local/bin/gray-peerlink"],
  command: ["-role", "entry", "-socket", PEERLINK_SOCKET],
  network_mode: "none",
  volumes: [`${PEERLINK_VOLUME}:${PEERLINK_MOUNT}`],
});
/** D63: the lane-only tmpfs the rendered config (with the bridge seed) lives on. */
export const LANE_RUN = "/run/lane";
/** D133: where gray-acme writes this boot's key and certificate: on the lane-only tmpfs. */
export const ACME_KEY_DIR = `${LANE_RUN}/tls`;
/** D133: the persistent volume (default layout) and the mount that hold only the ACME accounts. */
export const ACME_STATE_VOLUME = "lane-certs";
export const ACME_STATE_DIR = "/certs";
/**
 * Routing PR 9 (docs/confidential-lane-stack-routing.md sections 4.2-4.6): the environment's release-list public keys,
 * lane literals in both layouts (`--release-public-key`, `--release-freshness-public-key`). An entry verifies the stack
 * list with them before a stack VM gets any content (L1), and a stack VM in backend mode verifies an entry's hello
 * against the default list with them; neither may come from the host, so they are measured, 64 lower-case hex, and two
 * different keys (D134). `LANE_PEERS` (`--lane-peers`) is the default layout's entry switch, and egress's `-peer` runs
 * exactly when it is "true"; the relay-stack layout sets neither (a stack VM is never an entry, and egress refuses
 * -peer beside -relay-listen). The PEER_* tunables (bin/entrypoint.mjs `PEER_TUNABLE_NAMES`, @gray/config's rows) are
 * optional overrides on the default layout's lane, each inside its row's bounds.
 */
export const RELEASE_KEY_ENVS = Object.freeze(["LANE_RELEASE_PUBLIC_KEY", "LANE_RELEASE_FRESHNESS_PUBLIC_KEY"]);
const RELEASE_KEY = /^[0-9a-f]{64}$/;
export const PEERS_ENV = "LANE_PEERS";
export const PEER_FLAG = "-peer";
export const PEER_TUNABLES = PEER_TUNABLE_NAMES;
/** Every lane setting only an entry may carry. */
const ENTRY_ENVS = Object.freeze([PEERS_ENV, ...PEER_TUNABLES]);
/** Go's flag package reads `-name`, `--name`, `-name=v` and `--name=v` alike; the gate reads every spelling. */
function goFlag(name) {
  return new RegExp(`^--?${name}(?:=.*)?$`);
}
/** D58: KEYSET_NOT_AFTER is in (now, now + 400 days], and never the year-2100 default (D5). */
export const KEYSET_WINDOW_SECONDS = 400 * 24 * 60 * 60;
export const FORBIDDEN_KEYSET_NOT_AFTER = 4102444800;

/**
 * The two compose layouts (implementation plan S1). `default` is compose.yaml (gray-selfhost and the
 * sealed-credential relays); `stack` is compose.stack.yaml, where a relay's own image runs in the VM.
 */
export const LAYOUTS = Object.freeze(["default", "stack"]);

export const STACK_COMPOSE_PATH = join(here, "compose.stack.yaml");
export const STACK_APP_COMPOSE_PATH = join(here, "app-compose.stack.json");
/** The stack layout's measured pre-launch script (S9); another package writes it. */
export const STACK_PRE_LAUNCH_PATH = join(here, "pre-launch.stack.sh");

/**
 * S8/S8a/S54: the stack's host-injected env is the bridge seed, Gray's registry credential (which only the measured
 * pre-launch reads; empty for the public image, which it then pulls without a login, and set only for a release on the
 * earlier private image, deploy/tee/release/stack-env.mjs; no service may reference it, REGISTRY_ENVS) and the relay's
 * identity, which pre-launch validates and measures into RTMR3 before lane reads its relay id
 * (STACK_INTERPOLATIONS). The relay's registry login uses the pull token (§4), never env. relay-outbound-only §3.9:
 * no EAB (gray-acme is self-signed in this layout) and no GRAY_STACK_TLS_DOMAIN (the VM has no public name).
 */
export const STACK_ALLOWED_ENVS = Object.freeze(["LANE_BRIDGE_KEY_SEED", ...REGISTRY_ENVS, "GRAY_STACK_RELAY_ID", "GRAY_STACK_TOKEN_URL", "GRAY_STACK_RELAY_KEY"]);

/** S2: the stack's services (D133 merged acme into lane). `relay` is the only one that runs the relay's image. */
export const STACK_SERVICE_NAMES = Object.freeze(["egress", "isolation-check", "lane", "peerlink", "relay"]);
export const RELAY_SERVICE = "relay";
export const STACK_TOP_LEVEL_KEYS = Object.freeze(["name", "services", "networks", "volumes"]);
/** S50: the relay's local image slot: pre-launch tags the relay's signed choice into it; compose never pulls it. */
export const RELAY_SLOT_IMAGE = "gray-relay-slot:boot";

/**
 * S2-S5, §9 B: the stack's closed allowlist, per service. A key is allowed only on the service that
 * has it in compose.stack.yaml. D133: lane no longer waits for a one-shot acme service, so it has no
 * `depends_on`.
 */
export const STACK_SERVICE_KEYS = Object.freeze({
  // relay-outbound-only O1: no `ports` on any stack service.
  lane: Object.freeze([
    "image", "restart", "user", "group_add", "networks", "environment", "volumes",
    "read_only", "tmpfs", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
  ]),
  peerlink: Object.freeze([
    "image", "restart", "entrypoint", "command", "user", "group_add", "networks", "volumes",
    "read_only", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
  ]),
  egress: Object.freeze([
    "image", "restart", "entrypoint", "command", "user", "group_add", "networks", "volumes",
    "read_only", "tmpfs", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
  ]),
  "isolation-check": Object.freeze([
    "image", "restart", "depends_on", "entrypoint", "command", "user", "networks",
    "read_only", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
  ]),
  relay: Object.freeze([
    "image", "pull_policy", "restart", "depends_on", "user", "environment", "networks", "read_only", "tmpfs", "cap_drop",
    "security_opt", "ulimits", "mem_limit", "memswap_limit", "pids_limit", "cpus", "oom_score_adj", "logging",
  ]),
});

/**
 * relay-outbound-only §3.9: the stack's lane runs gray-acme in its self-signed mode (ACME_SELF_SIGNED "1"): no CA,
 * no ACME account and no persistent directory, so S2a's lane-certs bind is gone and no ACME setting but the key's
 * directory may be set.
 */
export const STACK_ACME_SELF_SIGNED = "1";
/** The ACME-mode settings the stack's lane must not set (gray-acme refuses each in its self-signed mode). */
const STACK_ACME_FORBIDDEN = Object.freeze(["TLS_DOMAIN", "ACME_DIRECTORY_URLS", "ACME_DIRECTORY_URL", "ACME_STATE_DIR", "ACME_EMAIL", ...EAB_ENVS]);
export const CERTS_MOUNT = ACME_STATE_DIR;

/** S2b: lane's uid and gid. */
const STACK_LANE_USER = "10001:10001";

/**
 * S3: lane's listener is its own `front` address, never `*:443`: a wildcard listener is also reachable at
 * 10.231.10.2:443 from the relay's network, which the isolation check refuses. relay-outbound-only §3.8: peerlink
 * (10.231.12.4) pipes the entry's streams to it; nothing is published.
 */
export const STACK_LANE_LISTEN_ADDRESS = "10.231.12.2:443";


/** S5: Gray's services log locally, capped, because the docker root is a tmpfs (S9). */
const GRAY_LOGGING = Object.freeze({ driver: "local", options: { "max-size": "10m", "max-file": "2" } });

/**
 * S2-S6, §9 B: the exact value of every stack-only setting, per service. The gate compares each
 * one (parsed, with keys in any order) and refuses a missing or different value; the rules shared
 * with compose.yaml (isolation, mounts, ports, identity) run as well.
 */
export const STACK_FIXED = Object.freeze({
  lane: Object.freeze({
    restart: "unless-stopped",
    user: STACK_LANE_USER,
    // 10100 opens egress.sock, 10101 peerlink.sock (relay-outbound-only §3.8).
    group_add: ["10100", "10101"],
    networks: { front: { ipv4_address: "10.231.12.2" }, relay_in: { ipv4_address: "10.231.10.2" } },
    volumes: ["/var/run/dstack.sock:/var/run/dstack.sock", `${EGRESS_VOLUME}:${EGRESS_MOUNT}`, `${PEERLINK_VOLUME}:${PEERLINK_MOUNT}`],
    tmpfs: ["/tmp", "/run/lane:mode=0700,uid=10001,gid=10001"],
    oom_score_adj: -500,
    logging: GRAY_LOGGING,
  }),
  egress: Object.freeze({
    restart: "unless-stopped",
    entrypoint: ["/usr/local/bin/gray-egress"],
    // S17: the budget and Go's soft limit, fixed (compose.stack.yaml names the measurement).
    command: ["-socket", "/run/gray/egress.sock", "-max-body-bytes", "4194304", "-relay-listen", "10.231.11.2:8080", "-stack-max-bytes", "201326592", "-memory-limit", "301989888"],
    user: "10002:10002",
    group_add: ["10100"],
    // S3: a fixed front address too, so docker's dynamic allocation (which starts at .2) can never
    // take lane's 10.231.12.2 when egress starts first.
    networks: { front: { ipv4_address: "10.231.12.3" }, relay_out: { ipv4_address: "10.231.11.2" } },
    volumes: [`${EGRESS_VOLUME}:${EGRESS_MOUNT}`],
    tmpfs: ["/tmp"],
    oom_score_adj: -500,
    logging: GRAY_LOGGING,
  }),
  // relay-outbound-only §3.2, §3.8: peerlink's VM role on front only, its socket shared with lane only.
  peerlink: Object.freeze({
    restart: "unless-stopped",
    entrypoint: ["/usr/local/bin/gray-peerlink"],
    command: ["-role", "vm", "-socket", PEERLINK_SOCKET, "-lane", "10.231.12.2:443"],
    user: "10005:10005",
    group_add: ["10101"],
    networks: { front: { ipv4_address: "10.231.12.4" } },
    volumes: [`${PEERLINK_VOLUME}:${PEERLINK_MOUNT}`],
    oom_score_adj: -500,
    logging: GRAY_LOGGING,
  }),
  "isolation-check": Object.freeze({
    restart: "no",
    depends_on: { lane: { condition: "service_started" }, egress: { condition: "service_started" }, peerlink: { condition: "service_started" } },
    entrypoint: ["/usr/local/bin/gray-isolation-check"],
    // §9 B: the only endpoints the relay's position may reach (and must), and the bound on waiting
    // for them; the check's item list is fixed in the binary. D133: the wait includes lane's
    // certificate order (gray-acme runs in lane before workerd listens), so it is the check's maximum,
    // 10 minutes: a failed first order's 5-minute hold and a second order fit.
    // relay-outbound-only §3.8: no port of front's bridge, lane, egress or peerlink answers the relay's position.
    command: ["-allow", "10.231.10.2:8081,10.231.11.2:8080", "-deny", "10.231.12.1,10.231.12.2,10.231.12.3,10.231.12.4", "-wait", "10m"],
    user: "10004:10004",
    networks: { relay_in: { ipv4_address: "10.231.10.4" }, relay_out: { ipv4_address: "10.231.11.4" } },
    oom_score_adj: -500,
    logging: GRAY_LOGGING,
  }),
  relay: Object.freeze({
    // S50: the slot, never pulled.
    image: RELAY_SLOT_IMAGE,
    pull_policy: "never",
    restart: "unless-stopped",
    depends_on: { "isolation-check": { condition: "service_completed_successfully" } },
    user: "10003:10003",
    environment: {
      GRAY_RELAY_LISTEN: "0.0.0.0:3000",
      GRAY_RELAY_CONFIG_URL: "http://10.231.10.2:8081/v1/relay/config",
      GRAY_EGRESS_URL: "http://10.231.11.2:8080",
      TMPDIR: "/tmp",
      GRAY_DATA_DIR: "/data",
    },
    networks: { relay_in: { ipv4_address: "10.231.10.3" }, relay_out: { ipv4_address: "10.231.11.3" } },
    // S5/S21a: sized, and owned by the relay's uid whatever the image holds at those paths.
    tmpfs: ["/tmp:size=256m,uid=10003,gid=10003,mode=1777", "/data:size=512m,uid=10003,gid=10003,mode=0700"],
    mem_limit: "1536m",
    memswap_limit: "1536m",
    pids_limit: 512,
    cpus: 1.5,
    oom_score_adj: 500,
    logging: { driver: "none" },
  }),
});

/**
 * S3: the stack's networks, exactly. Only `front` routes out (and carries the published 443); its subnet
 * is fixed so lane's client listener can name its address. The relay bridges' names are fixed for
 * pre-launch.
 */
export const STACK_NETWORKS = Object.freeze({
  front: { driver: "bridge", ipam: { config: [{ subnet: "10.231.12.0/24" }] } },
  relay_in: {
    driver: "bridge",
    internal: true,
    driver_opts: { "com.docker.network.bridge.name": "gr-relay-in" },
    ipam: { config: [{ subnet: "10.231.10.0/24" }] },
  },
  relay_out: {
    driver: "bridge",
    internal: true,
    driver_opts: { "com.docker.network.bridge.name": "gr-relay-out" },
    ipam: { config: [{ subnet: "10.231.11.0/24" }] },
  },
});

/**
 * D63/S2a/S2b: the stack's only named volume is the egress socket's, a plain local volume: docker fills
 * it from the image's /run/gray (10002:10100, 2750) on first use, and the docker root it lives on is a
 * tmpfs (S9). A tmpfs-driver volume is mounted empty and root-owned (measured), losing that ownership.
 */
export const STACK_VOLUMES = Object.freeze({
  [EGRESS_VOLUME]: {},
  // relay-outbound-only §3.8: peerlink's socket, the same kind (filled from the image's /run/peerlink, 10005:10101 2750).
  [PEERLINK_VOLUME]: {},
});

/** S8/S4: the seed's interpolation. */
const STACK_SEED_EXPRESSION = "${LANE_BRIDGE_KEY_SEED:-}";
/** S54: the identity's one interpolation (relay-outbound-only §3.9 removed the TLS name's), exactly this expression. */
export const STACK_RELAY_ID_EXPRESSION = "${GRAY_STACK_RELAY_ID:?the relay identity is missing}";
/**
 * S4/S8/S54: every interpolation the stack compose may hold, by path: lane's seed and the identity's relay id
 * (@gray/lane-compose `STACK_LAYOUT.interpolations`).
 */
export const STACK_INTERPOLATIONS = Object.freeze({
  "services.lane.environment.LANE_BRIDGE_KEY_SEED": STACK_SEED_EXPRESSION,
  "services.lane.environment.LANE_STACK_RELAY_ID": STACK_RELAY_ID_EXPRESSION,
});
/** relay-outbound-only §3.2: the stack lane's default entry list (--peer-entries), lower-case DNS names, comma-separated. */
export const PEER_ENTRIES_ENV = "LANE_PEER_ENTRIES";
/**
 * P2c-2 (docs/design/relay-no-always-on-host.md H9): the KMS a stack lane re-checks its app key with every 10 minutes
 * (--kms-url), rendered only for an app on an on-chain KMS, where the relay's contract decides whether the KMS gives
 * the app its keys. Absent, the VM keeps no lease (a phase-1 app on Phala's own KMS), and its compose is byte for byte
 * the one before. A lane literal, so it is measured: Gray's unmeasured environment cannot turn the lease off or point it
 * elsewhere (the entrypoint pins the KMS's certificate to the measured key provider whatever the URL names).
 */
export const KMS_URL_ENV = "LANE_KMS_URL";
/**
 * P2e (docs/design/relay-no-always-on-host.md §3.1, 13.11): the relay's vault on the data disk, bound read-write into
 * lane at the same path for an app with a KMS lease (--kms-url) and for no other. Pre-launch binds the data disk's
 * gray-persist at /var/lib/gray-persist (S9.1) and creates this directory owned by lane's uid, mode 0700; the lane's
 * supervisor serves it to the Worker (deploy/tee/bin/vault-disk.mjs). @gray/lane-compose `STACK_LAYOUT.vaultBind`.
 */
export const VAULT_BIND_PATH = "/var/lib/gray-persist/relay";
export const VAULT_BIND = `${VAULT_BIND_PATH}:${VAULT_BIND_PATH}`;
const DSTACK_SOCKET_BIND = "/var/run/dstack.sock:/var/run/dstack.sock";

/** What each layout's gate and output use; `default` is exactly the generator before layouts. */
const LAYOUT_SPECS = Object.freeze({
  default: Object.freeze({
    name: "default",
    label: "compose.yaml",
    composePath: COMPOSE_PATH,
    appComposePath: APP_COMPOSE_PATH,
    preLaunchPath: PRE_LAUNCH_PATH,
    services: SERVICE_NAMES,
    topLevelKeys: TOP_LEVEL_KEYS,
    serviceKeys: (name) => (name === PEERLINK_SERVICE ? ENTRY_PEERLINK_KEYS : SERVICE_KEYS),
    ports: SERVICE_PORTS,
    allowedEnvs: ALLOWED_ENVS,
    identityNames: "TLS_DOMAIN, LANE_BRIDGE_URL, KEYSET_NOT_AFTER, LANE_RELEASE_PUBLIC_KEY, LANE_RELEASE_FRESHNESS_PUBLIC_KEY",
    certsBind: undefined,
    vaultBind: undefined,
    bindRule: "only lane's guest-agent socket /var/run/dstack.sock may be bind-mounted (D94)",
  }),
  stack: Object.freeze({
    name: "stack",
    label: "compose.stack.yaml",
    composePath: STACK_COMPOSE_PATH,
    appComposePath: STACK_APP_COMPOSE_PATH,
    preLaunchPath: STACK_PRE_LAUNCH_PATH,
    services: STACK_SERVICE_NAMES,
    topLevelKeys: STACK_TOP_LEVEL_KEYS,
    serviceKeys: (name) => (Object.hasOwn(STACK_SERVICE_KEYS, name) ? STACK_SERVICE_KEYS[name] : []),
    // relay-outbound-only O1: no stack service publishes a port.
    ports: Object.freeze(Object.fromEntries(STACK_SERVICE_NAMES.map((name) => [name, Object.freeze([])]))),
    allowedEnvs: STACK_ALLOWED_ENVS,
    identityNames: "LANE_BRIDGE_URL, KEYSET_NOT_AFTER, LANE_RELEASE_PUBLIC_KEY, LANE_RELEASE_FRESHNESS_PUBLIC_KEY, LANE_PEER_ENTRIES (--peer-entries)",
    certsBind: undefined,
    vaultBind: VAULT_BIND_PATH,
    bindRule:
      "only lane's guest-agent socket /var/run/dstack.sock may be bind-mounted (D94; relay-outbound-only §3.9 removed S2a's ACME account directory), and for an app with LANE_KMS_URL lane's vault directory /var/lib/gray-persist/relay at its own path, read-write (P2e)",
  }),
});

/** `--layout` is `default` (the default) or `stack`; anything else is refused, never guessed. */
function layoutSpec(options) {
  const layout = options.layout ?? "default";
  if (!LAYOUTS.includes(layout)) throw new Error(`--layout '${layout}' is not default or stack`);
  return LAYOUT_SPECS[layout];
}

/** "a, b and c": the gate's messages name a closed list in prose. */
function listText(items) {
  return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** The two DEPLOY_ENV values a deployed lane takes (D47; `local` is for host e2e, never a release). */
const DEPLOY_ENVS = Object.freeze(["testnet", "production"]);

/** A lowercase DNS hostname: at least two labels, each 1-63 chars, no leading/trailing hyphen. */
const TLS_HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A parsed compose mapping; `yaml` is the measured file's only parser (D58). */
function isMap(value) {
  return value instanceof Map;
}

function isList(value) {
  return Array.isArray(value);
}

function scalarText(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isInteger(value)) return String(value);
  return undefined;
}

/**
 * D93: anchors, aliases, merge keys and custom tags are refused before `toJS`. A merge key is an
 * ordinary `<<` key in YAML 1.2, and an unknown tag such as `!reset` is only a warning, so both have
 * to be found in the syntax tree: the resolved object would hide exactly the override compose-go
 * would apply. Standard tags (`tag:yaml.org,2002:*`, `!!str`, ...) are not custom and are allowed.
 */
function forbiddenYamlSyntax(document) {
  let found;
  const walk = (node) => {
    if (found !== undefined || node === null || typeof node !== "object") return;
    if (node instanceof Alias) {
      found = "an alias (*name)";
      return;
    }
    if (typeof node.anchor === "string") {
      found = `an anchor (&${node.anchor})`;
      return;
    }
    if (node.key !== undefined && node.key !== null && typeof node.key === "object" && node.key.value === "<<") {
      found = "a merge key (<<)";
      return;
    }
    if (typeof node.tag === "string" && !node.tag.startsWith("tag:yaml.org,2002:")) {
      found = `a custom tag (${node.tag})`;
      return;
    }
    if (node.key !== undefined) walk(node.key);
    if (node.value !== undefined) walk(node.value);
    if (Array.isArray(node.items)) for (const item of node.items) walk(item);
  };
  walk(document.contents);
  return found;
}

/** Parse the measured compose as YAML. A compose this checker cannot place is refused. */
function parseCompose(composeText) {
  const lineCounter = new LineCounter();
  const document = parseDocument(composeText, { lineCounter, uniqueKeys: true, prettyErrors: false });
  if (document.errors.length > 0) {
    return { error: `does not parse as YAML: ${document.errors[0].message.split("\n")[0]}` };
  }
  // A `%YAML 1.1` directive changes how this parser resolves scalars (`yes`, `0700`); compose-go does not
  // follow it, so the gate would read different values than compose runs.
  if (document.directives?.yaml?.explicit === true) {
    return { error: "has a %YAML directive; the gate reads YAML 1.2 as compose-go does, so directives are refused (D93)" };
  }
  const syntax = forbiddenYamlSyntax(document);
  if (syntax !== undefined) {
    return { error: `contains ${syntax}; YAML anchors, aliases, merge keys and custom tags are refused (D93)` };
  }
  if (document.warnings.length > 0) {
    return { error: `has a YAML warning the gate does not accept: ${document.warnings[0].message.split("\n")[0]}` };
  }
  let data;
  try {
    data = document.toJS({ mapAsMap: true, maxAliasCount: 100 });
  } catch (thrown) {
    return { error: `does not parse as YAML: ${thrown instanceof Error ? thrown.message : String(thrown)}` };
  }
  if (!isMap(data)) return { error: "does not parse as a YAML mapping" };
  const services = data.get("services");
  if (!isMap(services)) return { error: "does not parse as a services map this checker can inspect" };
  return { data, services };
}

/** Every key and string scalar, for the rules that apply to the whole document (D44, D47). */
function forEachScalar(value, visit) {
  if (isMap(value)) {
    for (const [key, member] of value) {
      if (typeof key === "string") visit(key);
      forEachScalar(member, visit);
    }
  } else if (isList(value)) {
    for (const member of value) forEachScalar(member, visit);
  } else if (typeof value === "string") {
    visit(value);
  }
}

/** Compose `environment:` as a Map; the long form is a mapping, the short form KEY=value items. */
/**
 * The environment names a service lists without a value (`NAME:` with nothing after it, or `- NAME`):
 * compose fills each from the host's environment, an interpolation without a `$`.
 */
function hostEnvironmentNames(service) {
  const environment = service.get("environment");
  if (isMap(environment)) return [...environment].filter(([, value]) => value === null).map(([key]) => String(key));
  if (isList(environment)) return environment.filter((item) => typeof item === "string" && !item.includes("="));
  return [];
}

function environmentOf(service) {
  const environment = service.get("environment");
  const values = new Map();
  if (environment === undefined) return values;
  if (isMap(environment)) {
    for (const [key, value] of environment) {
      const text = scalarText(value);
      if (typeof key === "string") values.set(key, text ?? "");
    }
    return values;
  }
  if (isList(environment)) {
    for (const item of environment) {
      if (typeof item !== "string") continue;
      const at = item.indexOf("=");
      if (at < 0) values.set(item, "");
      else values.set(item.slice(0, at), item.slice(at + 1));
    }
  }
  return values;
}

/** D58: a published port is exactly `443:443`; anything else is a different publication. */
function normalizePorts(value, serviceName, label, problems) {
  if (value === undefined) return [];
  if (!isList(value)) {
    problems.push(`${label}: ${serviceName}.ports is not a list`);
    return null;
  }
  const ports = [];
  for (const item of value) {
    if (typeof item === "string") {
      ports.push(item.trim());
      continue;
    }
    if (isMap(item)) {
      const target = scalarText(item.get("target"));
      const published = scalarText(item.get("published"));
      const protocol = item.get("protocol") ?? "tcp";
      const hostIp = item.get("host_ip");
      if (target === "443" && published === "443" && protocol === "tcp" && (hostIp === undefined || hostIp === "")) {
        ports.push("443:443");
      } else {
        ports.push(`long-form ${JSON.stringify({ target, published, protocol, host_ip: hostIp ?? null })}`);
      }
      continue;
    }
    ports.push(String(item));
  }
  return ports;
}

/** Compose `volumes:` and `tmpfs:` as sources and targets, for D63's sharing rule. */
function mountsOf(service, serviceName, label, problems) {
  const mounts = [];
  const tmpfs = [];
  const volumes = service.get("volumes");
  if (volumes !== undefined) {
    if (!isList(volumes)) {
      problems.push(`${label}: ${serviceName}.volumes is not a list`);
    } else {
      for (const item of volumes) {
        if (typeof item === "string") {
          const parts = item.split(":");
          if (parts.length < 2) problems.push(`${label}: ${serviceName} volume '${item}' names no target`);
          else mounts.push({ source: parts[0], target: parts[1], readOnly: parts.slice(2).join(":").split(",").includes("ro") });
          continue;
        }
        if (isMap(item)) {
          const type = item.get("type");
          const target = scalarText(item.get("target")) ?? "";
          if (type === "tmpfs") tmpfs.push(target);
          else mounts.push({ source: scalarText(item.get("source")) ?? "", target, readOnly: item.get("read_only") === true });
          continue;
        }
        problems.push(`${label}: ${serviceName} has a volume entry this checker cannot inspect`);
      }
    }
  }
  const tmpfsList = service.get("tmpfs");
  if (tmpfsList !== undefined) {
    if (!isList(tmpfsList)) {
      problems.push(`${label}: ${serviceName}.tmpfs is not a list`);
    } else {
      for (const item of tmpfsList) {
        if (typeof item === "string") tmpfs.push(item.split(":")[0]);
        else if (isMap(item)) tmpfs.push(scalarText(item.get("target")) ?? "");
        else problems.push(`${label}: ${serviceName} has a tmpfs entry this checker cannot inspect`);
      }
    }
  }
  return { mounts, tmpfs };
}

/**
 * D58: the fields that keep a service inside its container, checked on every service. `noNetwork` names the one service
 * that may set `network_mode: "none"` (the entry's peerlink, relay-outbound-only §3.8): no namespace is shared by it.
 */
function checkIsolation(name, service, label, problems, noNetwork = undefined) {
  if (service.get("read_only") !== true) problems.push(`${label}: ${name} must set read_only: true`);
  const capDrop = service.get("cap_drop");
  if (!isList(capDrop) || capDrop.length !== 1 || capDrop[0] !== "ALL") {
    problems.push(`${label}: ${name} must set cap_drop: [ALL]`);
  }
  if (service.has("cap_add") && (!isList(service.get("cap_add")) || service.get("cap_add").length > 0)) {
    problems.push(`${label}: ${name} adds a capability; no measured service may`);
  }
  // Exact lists: an extra entry (seccomp=unconfined, apparmor=unconfined, a raised nofile) is refused.
  const security = service.get("security_opt");
  if (!isList(security) || security.length !== 1 || security[0] !== "no-new-privileges:true") {
    problems.push(`${label}: ${name} must set security_opt: [no-new-privileges:true] and nothing else`);
  }
  const ulimits = service.get("ulimits");
  const core = isMap(ulimits) && ulimits.size === 1 ? ulimits.get("core") : undefined;
  const coreZero = core === 0 || (isMap(core) && core.size === 2 && core.get("soft") === 0 && core.get("hard") === 0);
  if (!coreZero) problems.push(`${label}: ${name} must set ulimits.core: 0 and no other ulimit`);
  if (service.has("privileged") && service.get("privileged") !== false) {
    problems.push(`${label}: ${name} must not be privileged`);
  }
  for (const field of ["network_mode", "pid", "ipc"]) {
    if (field === "network_mode" && name === noNetwork && service.get(field) === "none") continue;
    if (service.has(field)) problems.push(`${label}: ${name} must not set ${field}${field === "network_mode" && name === noNetwork ? ` other than "none"` : ""}: it leaves the measured namespace`);
  }
  if (service.has("expose") && (!isList(service.get("expose")) || service.get("expose").length > 0)) {
    problems.push(`${label}: ${name} must not expose a port`);
  }
}

/**
 * D94: the closed allowlist. It is enforced on the resolved maps, so a key this parser does not know
 * is refused just like `include`, `extends`, `env_file`, `secrets` or `volumes_from`; a service may
 * not smuggle in an unknown setting for compose-go to interpret. The rendered-config names are
 * refused in every environment so a measured compose cannot move the config (with the seed) onto a
 * shared path.
 */
function checkClosedKeys(data, services, spec, problems) {
  const label = spec.label;
  // The project name scopes the named volumes (compose.yaml's lane-certs) and networks; it is the app's.
  if (data.get("name") !== APP_NAME) {
    problems.push(`${label}: the compose name is ${data.has("name") ? `'${String(data.get("name"))}'` : "missing"}; it must be '${APP_NAME}'`);
  }
  for (const key of data.keys()) {
    if (!spec.topLevelKeys.includes(key)) {
      problems.push(`${label}: top-level '${key}' is not allowed; the measured compose has only ${listText(spec.topLevelKeys)} (D94)`);
    }
  }
  if (data.has("volumes") && !isMap(data.get("volumes"))) {
    problems.push(`${label}: top-level volumes is not a mapping`);
  }
  for (const [name, service] of services) {
    if (!isMap(service)) {
      problems.push(`${label}: service '${name}' is not a mapping`);
      continue;
    }
    const allowed = spec.serviceKeys(name);
    for (const key of service.keys()) {
      if (!allowed.includes(key)) {
        problems.push(`${label}: ${name}.${key} is not an allowed service setting; the measured compose allows only ${allowed.join(", ")} (D94)`);
      }
    }
    for (const passthrough of hostEnvironmentNames(service)) {
      problems.push(`${label}: ${name} sets ${passthrough} without a value; compose would take it from the host's environment without a '$' (D94)`);
    }
    const environment = environmentOf(service);
    for (const forbidden of FORBIDDEN_ENV_NAMES) {
      if (environment.has(forbidden)) {
        problems.push(`${label}: ${name} sets ${forbidden}, which the measured compose must not set: the lane's rendered-config location and receipt key id are fixed (D94)`);
      }
    }
  }
}

/**
 * D58: only `lane` publishes, and only 443; D63: the only volume `lane` and `egress` may share is the
 * egress socket's, and the lane's rendered config lives on a lane-only tmpfs the egress service cannot
 * mount. D94: the only bind mount is lane's guest-agent socket (and, in the stack layout, its ACME
 * account directory), and every named volume must be declared at the top level.
 */
function checkVolumesAndPorts(services, data, spec, problems) {
  const label = spec.label;
  const volumes = data.get("volumes");
  const declared = isMap(volumes) ? new Set([...volumes.keys()].map(String)) : new Set();
  const mounts = new Map();
  for (const name of spec.services) {
    const service = services.get(name);
    if (!isMap(service)) continue;
    const found = mountsOf(service, name, label, problems);
    mounts.set(name, found);
    for (const mount of found.mounts) {
      const source = mount.source;
      if (source.startsWith("/") || source.startsWith(".") || source.startsWith("~")) {
        const guestAgent = name === "lane" && source === "/var/run/dstack.sock" && mount.target === "/var/run/dstack.sock";
        // S2a, D133: the stack's ACME account directory, read-write on lane only, at /certs only.
        const certs = spec.certsBind !== undefined && source === spec.certsBind && mount.target === CERTS_MOUNT
          && name === "lane" && !mount.readOnly;
        // P2e: the relay's vault directory, read-write on lane only, at its own path (checkStackFixed ties it to LANE_KMS_URL).
        const vault = spec.vaultBind !== undefined && source === spec.vaultBind && mount.target === spec.vaultBind && name === "lane" && !mount.readOnly;
        if (!guestAgent && !certs && !vault) {
          problems.push(`${label}: ${name} bind-mounts '${source}' at '${mount.target}'${mount.readOnly ? " read-only" : ""}; ${spec.bindRule}`);
        }
      } else if (source !== "" && !declared.has(source)) {
        problems.push(`${label}: ${name} mounts the undeclared volume '${source}'; declare it under the top-level volumes (D94)`);
      }
    }
    const ports = normalizePorts(service.get("ports"), name, label, problems);
    if (ports !== null) {
      const expected = spec.ports[name];
      if (ports.join(",") !== expected.join(",")) {
        problems.push(`${label}: ${name} publishes ${ports.length === 0 ? "no port" : ports.join(", ")}; the measured compose allows ${expected.length === 0 ? "none" : expected.join(", ")}`);
      }
    }
  }
  const lane = mounts.get("lane");
  const egress = mounts.get("egress");
  if (lane === undefined || egress === undefined) return;
  checkPeerlinkSocket(mounts, spec, problems);
  const socketInLane = lane.mounts.filter((mount) => mount.source === EGRESS_VOLUME && mount.target === EGRESS_MOUNT);
  if (socketInLane.length !== 1) problems.push(`${label}: lane must mount ${EGRESS_VOLUME} at ${EGRESS_MOUNT} (the egress socket)`);
  // relay-outbound-only §3.8: an entry's egress also mounts peerlink's socket volume (checkPeerlinkSocket holds where).
  const egressOwn = egress.mounts.filter((mount) => mount.source !== PEERLINK_VOLUME);
  if (egressOwn.length !== 1 || egressOwn[0].source !== EGRESS_VOLUME || egressOwn[0].target !== EGRESS_MOUNT) {
    problems.push(`${label}: egress must mount only ${EGRESS_VOLUME} at ${EGRESS_MOUNT}${spec.name === "default" ? ` (and ${PEERLINK_VOLUME} at ${PEERLINK_MOUNT})` : ""}: no other path may be shared with the lane`);
  }
  const shared = lane.mounts.filter((mount) => egress.mounts.some((other) => other.source === mount.source));
  for (const mount of shared) {
    if (mount.source !== EGRESS_VOLUME && mount.source !== PEERLINK_VOLUME) {
      problems.push(`${label}: lane and egress share the volume '${mount.source}'; only ${EGRESS_VOLUME} (the egress socket) and ${PEERLINK_VOLUME} (peerlink's) may be shared`);
    }
  }
  if (egress.tmpfs.includes(LANE_RUN) || egress.mounts.some((mount) => mount.target === LANE_RUN)) {
    problems.push(`${label}: egress can reach ${LANE_RUN}; the rendered config must live on a lane-only tmpfs`);
  }
  if (!lane.tmpfs.includes(LANE_RUN)) {
    problems.push(`${label}: lane must mount a tmpfs at ${LANE_RUN} for its rendered config`);
  }
}

/**
 * relay-outbound-only §3.2, §3.8: peerlink's socket volume. peerlink mounts it, and nothing else, at PEERLINK_MOUNT;
 * the lane mounts it there; on an entry (the default layout) egress may mount it there too, and in the stack layout
 * egress, which never dials a peer, may not. No other service mounts it, so the relay (stack) reaches no socket of
 * peerlink's.
 */
function checkPeerlinkSocket(mounts, spec, problems) {
  const label = spec.label;
  const may = new Set(["lane", PEERLINK_SERVICE, ...(spec.name === "default" ? ["egress"] : [])]);
  for (const [name, found] of mounts) {
    const own = found.mounts.filter((mount) => mount.source === PEERLINK_VOLUME);
    if (own.length > 0 && !may.has(name)) problems.push(`${label}: ${name} mounts ${PEERLINK_VOLUME}; only ${[...may].join(", ")} may reach peerlink's socket (relay-outbound-only §3.8)`);
    for (const mount of own) {
      if (mount.target !== PEERLINK_MOUNT || mount.readOnly) problems.push(`${label}: ${name} mounts ${PEERLINK_VOLUME} at '${mount.target}'${mount.readOnly ? " read-only" : ""}; it is mounted read-write at ${PEERLINK_MOUNT} only`);
    }
  }
  const peerlink = mounts.get(PEERLINK_SERVICE);
  if (peerlink === undefined) return;
  if (peerlink.mounts.length !== 1 || peerlink.mounts[0].source !== PEERLINK_VOLUME) {
    problems.push(`${label}: peerlink must mount only ${PEERLINK_VOLUME} at ${PEERLINK_MOUNT}: it holds no key and reaches no other file (relay-outbound-only O4)`);
  }
  if (!(mounts.get("lane")?.mounts ?? []).some((mount) => mount.source === PEERLINK_VOLUME)) {
    problems.push(`${label}: lane must mount ${PEERLINK_VOLUME} at ${PEERLINK_MOUNT}: the lane reaches peerlink only through its socket`);
  }
}

/**
 * D133: this boot's certificate key exists only on the lane's /run/lane tmpfs. The lane names
 * ACME_KEY_DIR there and mounts nothing (no named volume, no bind) over or under /run/lane, so the key
 * cannot land on a volume another compose of the app could mount; the ACME accounts go to /certs (the
 * persistent lane-certs volume, or in the stack layout its data-disk bind), which only the lane mounts.
 * The EAB is a host-injected passthrough, never a literal (the measured compose is public), and only the
 * lane may name it.
 */
function checkCertificateKey(services, spec, problems) {
  const label = spec.label;
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const environment = environmentOf(lane);
  if (environment.get("ACME_KEY_DIR") !== ACME_KEY_DIR) {
    problems.push(`${label}: lane must set ACME_KEY_DIR: "${ACME_KEY_DIR}", on the lane-only ${LANE_RUN} tmpfs (D133)`);
  }
  if (spec.name === "stack") {
    checkStackSelfSigned(services, lane, environment, label, problems);
    return;
  }
  if (environment.has("ACME_SELF_SIGNED")) {
    problems.push(`${label}: lane sets ACME_SELF_SIGNED; the default layout's lane has a WebPKI certificate for its name (only the relay-stack layout is self-signed)`);
  }
  if (environment.get("ACME_STATE_DIR") !== ACME_STATE_DIR) {
    problems.push(`${label}: lane must set ACME_STATE_DIR: "${ACME_STATE_DIR}", the directory that holds only the ACME accounts (D133)`);
  }
  const stateSource = spec.certsBind ?? ACME_STATE_VOLUME;
  const { mounts } = mountsOf(lane, "lane", label, []);
  if (!mounts.some((mount) => mount.source === stateSource && mount.target === ACME_STATE_DIR && !mount.readOnly)) {
    problems.push(`${label}: lane must mount ${stateSource} read-write at ${ACME_STATE_DIR} for the ACME accounts (D133)`);
  }
  for (const mount of mounts) {
    if (mount.target === LANE_RUN || mount.target.startsWith(`${LANE_RUN}/`)) {
      problems.push(`${label}: lane mounts '${mount.source}' at '${mount.target}'; nothing may be mounted over the ${LANE_RUN} tmpfs that holds this boot's key (D133)`);
    }
  }
  for (const name of EAB_ENVS) {
    const value = environment.get(name);
    if (value !== `\${${name}:-}`) {
      problems.push(`${label}: lane must set ${name}: "\${${name}:-}"; the EAB comes from the encrypted env and is never a measured literal (D133)`);
    }
  }
  for (const [name, service] of services) {
    if (name === "lane" || !isMap(service)) continue;
    for (const key of [...EAB_ENVS, "ACME_KEY_DIR", "ACME_STATE_DIR"]) {
      let referenced = false;
      forEachScalar(service, (text) => {
        if (new RegExp(`\\b${key}\\b`).test(text)) referenced = true;
      });
      if (referenced) problems.push(`${label}: ${name} references ${key}; only the lane's gray-acme takes this boot's ACME settings (D133)`);
    }
    const other = mountsOf(service, String(name), label, []);
    if (other.mounts.some((mount) => mount.source === stateSource)) {
      problems.push(`${label}: ${name} mounts ${stateSource}; only the lane may reach the ACME accounts (D133)`);
    }
  }
}

/**
 * relay-outbound-only §3.9: the stack's lane runs gray-acme self-signed (ACME_SELF_SIGNED "1") and sets none of ACME
 * mode's settings, no TLS_DOMAIN and no EAB; no service mounts the old ACME account directory, and nothing is
 * mounted over /run/lane, where this boot's key lives.
 */
function checkStackSelfSigned(services, lane, environment, label, problems) {
  if (environment.get("ACME_SELF_SIGNED") !== STACK_ACME_SELF_SIGNED) {
    problems.push(`${label}: lane must set ACME_SELF_SIGNED: "${STACK_ACME_SELF_SIGNED}": a stack VM has no public name, so gray-acme makes this boot's certificate itself (relay-outbound-only §3.9)`);
  }
  for (const name of STACK_ACME_FORBIDDEN) {
    if (environment.has(name)) problems.push(`${label}: lane sets ${name}; a stack VM has no public name and no ACME account (relay-outbound-only §3.9)`);
  }
  for (const mount of mountsOf(lane, "lane", label, []).mounts) {
    if (mount.target === LANE_RUN || mount.target.startsWith(`${LANE_RUN}/`)) {
      problems.push(`${label}: lane mounts '${mount.source}' at '${mount.target}'; nothing may be mounted over the ${LANE_RUN} tmpfs that holds this boot's key (D133)`);
    }
  }
  for (const [name, service] of services) {
    if (name === "lane" || !isMap(service)) continue;
    for (const key of [...EAB_ENVS, "ACME_KEY_DIR", "ACME_STATE_DIR", "ACME_SELF_SIGNED"]) {
      let referenced = false;
      forEachScalar(service, (text) => {
        if (new RegExp(`\\b${key}\\b`).test(text)) referenced = true;
      });
      if (referenced) problems.push(`${label}: ${name} references ${key}; only the lane's gray-acme takes this boot's certificate settings (D133)`);
    }
  }
}

/**
 * relay-outbound-only §3.2, §3.8: the stack lane's peerlink socket (PEERLINK_SOCKET, exactly) and its default entry
 * list (LANE_PEER_ENTRIES, the environment's entry names: --peer-entries).
 */
function checkStackPeerlink(services, label, problems) {
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const environment = environmentOf(lane);
  if (environment.get("PEERLINK_SOCKET") !== PEERLINK_SOCKET) {
    problems.push(`${label}: lane must set PEERLINK_SOCKET: "${PEERLINK_SOCKET}", the socket on ${PEERLINK_VOLUME} (relay-outbound-only §3.8)`);
  }
  const entries = environment.get(PEER_ENTRIES_ENV);
  if (typeof entries !== "string" || !entries.split(",").every((name) => TLS_HOST.test(name))) {
    problems.push(`${label}: lane must set ${PEER_ENTRIES_ENV} to one or more lower-case DNS names, comma-separated: the entries the VM dials first (relay-outbound-only §3.2, --peer-entries)`);
  }
}

/** --peer-entries: one or more lower-case DNS names, comma-separated, none of them `.invalid`. */
function validatePeerEntries(text) {
  const names = typeof text === "string" ? text.split(",") : [];
  if (names.length === 0 || names.some((name) => !TLS_HOST.test(name) || name.endsWith(".invalid"))) {
    throw new Error(`--peer-entries '${text}' is not one or more lower-case DNS names, comma-separated (the environment's entry, e.g. lane.usefallback.com)`);
  }
  return text;
}

/** D58: every service pins the same digest; a real digest next to a placeholder is refused. */
function checkImages(services, images, options, problems) {
  for (const name of SERVICE_NAMES) {
    const service = services.get(name);
    if (!isMap(service)) continue;
    const image = service.get("image");
    if (typeof image !== "string") {
      problems.push(`compose.yaml: ${name} names no image`);
      continue;
    }
    images.push(image);
    if (!PINNED_IMAGE.test(image)) {
      problems.push(`compose.yaml: ${name} image '${image}' is not pinned by @sha256:<64 hex>`);
    } else if (PLACEHOLDER_DIGEST.test(image) && !options.allowPlaceholderDigest) {
      problems.push(`compose.yaml: ${name} image '${image}' still has the placeholder digest: set the digest deploy/tee/build.sh printed`);
    }
    if (service.has("build")) {
      problems.push(`compose.yaml: ${name} has a build: section, so the image would be built inside the CVM`);
    }
  }
  if (images.length > 0 && new Set(images).size !== 1) {
    problems.push(`compose.yaml: the services run different images (${[...new Set(images)].join(", ")}); all must name the one audited digest`);
  }
  const placeholders = images.filter((image) => PLACEHOLDER_DIGEST.test(image));
  const real = images.filter((image) => !PLACEHOLDER_DIGEST.test(image));
  if (placeholders.length > 0 && real.length > 0) {
    problems.push("compose.yaml: a real digest sits next to a placeholder; all image lines must be the same placeholder before --image substitutes one digest");
  }
}

/** D58: the deployment identity is a measured literal in the lane, never a placeholder. */
function checkIdentity(services, data, options, spec, problems) {
  const label = spec.label;
  if (!options.allowPlaceholders) {
    const found = new Set();
    const scanned = spec.services.map((name) => services.get(name));
    for (const member of scanned) {
      if (!isMap(member)) continue;
      forEachScalar(member, (text) => {
        if (/set-at-deploy\b/i.test(text)) found.add("set-at-deploy");
        if (/\b[a-z0-9.-]*\.invalid\b/i.test(text)) found.add("*.invalid");
      });
    }
    if (found.size > 0) {
      problems.push(`${label} still holds the deployment placeholder ${[...found].join(", ")}: set the real identity (${spec.identityNames}) before a release, or pass --allow-placeholders for development`);
    }
  }
  for (const name of spec.services) {
    const service = services.get(name);
    if (isMap(service) && environmentOf(service).has("KEYSET_SUBJECT")) {
      problems.push(`${label}: ${name} sets KEYSET_SUBJECT; the entrypoint derives it from the guest agent (D47)`);
    }
  }
  const lane = services.get("lane");
  const laneDomain = isMap(lane) ? environmentOf(lane).get("TLS_DOMAIN") : undefined;
  if (spec.name === "stack") {
    // relay-outbound-only §3.9: the VM has no public name, so the stack lane sets no TLS_DOMAIN (checkStackSelfSigned
    // reports it); the keyset's TLS key is then bound to no domain.
  } else if (laneDomain === undefined) {
    problems.push(`${label}: lane has no TLS_DOMAIN literal`);
  }
  if (spec.name !== "stack" && laneDomain !== undefined) {
    if (!TLS_HOST.test(laneDomain)) problems.push(`${label}: TLS_DOMAIN '${laneDomain}' is not a lowercase DNS hostname`);
    if (!options.allowPlaceholders && (laneDomain.endsWith(".invalid") || laneDomain === "invalid")) {
      problems.push(`${label}: TLS_DOMAIN '${laneDomain}' is reserved for documentation (RFC 2606) and cannot be certified`);
    }
  }
  const raw = isMap(lane) ? environmentOf(lane).get("KEYSET_NOT_AFTER") : undefined;
  if (raw === undefined) {
    problems.push(`${label}: lane has no KEYSET_NOT_AFTER literal`);
    return;
  }
  if (raw === String(FORBIDDEN_KEYSET_NOT_AFTER)) {
    problems.push(`${label}: KEYSET_NOT_AFTER is the year-2100 default ${FORBIDDEN_KEYSET_NOT_AFTER}; the operator must choose the expiry (D5/D58)`);
    return;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) {
    if (!(options.allowPlaceholders && /set-at-deploy/i.test(raw))) {
      problems.push(`${label}: KEYSET_NOT_AFTER '${raw}' is not a u64 of Unix seconds`);
    }
    return;
  }
  const value = BigInt(raw);
  const now = BigInt(options.nowSeconds ?? Math.floor(Date.now() / 1000));
  const limit = now + BigInt(KEYSET_WINDOW_SECONDS);
  if (value <= now || value > limit) {
    problems.push(`${label}: KEYSET_NOT_AFTER ${raw} is not within (now, now + 400 days]; pass --keyset-not-after with the operator's expiry (D58)`);
  }
}

/**
 * D101: the DER SubjectPublicKeyInfo prefix of the KMS's P-256 `ca_pubkey` (the value Phala puts in
 * `key_provider_id`): SEQUENCE(89) { SEQUENCE(19) { id-ecPublicKey, prime256v1 }, BIT STRING(66)
 * { 0, uncompressed point } }. The full value is 91 bytes (182 lower-case hex).
 */
const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";
const KMS_CA_PUBKEY_HEX = /^[0-9a-fA-F]{182}$/;

/** D100: the target is `dstack` (default) or `phala`; anything else is refused, never guessed. */
function targetOf(options) {
  const target = options.target ?? "dstack";
  if (!TARGETS.includes(target)) {
    throw new Error(`--target '${target}' is not dstack or phala`);
  }
  return target;
}

/**
 * D101: validate the KMS's `ca_pubkey` and return it lower-case. Phala's normalized form puts this
 * exact hex in `key_provider_id`; a wrong length, a non-hex value or a different key algorithm would
 * make the measured bytes differ from what Phala stores.
 */
export function validateKmsCaPubkey(text) {
  if (typeof text !== "string" || !KMS_CA_PUBKEY_HEX.test(text) || !text.toLowerCase().startsWith(P256_SPKI_PREFIX)) {
    throw new Error("--kms-ca-pubkey must be the node KMS's 182-hex-character P-256 SPKI ca_pubkey (30593013...03420004 + 128 hex, 91 bytes)");
  }
  return text.toLowerCase();
}

/**
 * D101: the app-compose Phala Cloud normalizes and measures, as a copy of the dstack one. Phala
 * keeps `docker_compose_file` and `pre_launch_script` byte for byte, drops
 * `requirements.platforms`/`storage_discard` (D100) and adds `features`, `init_script: []`,
 * `key_provider_id` (the KMS `ca_pubkey`), `port_policy.ports[].pp: false`, `storage_fs: "zfs"` and
 * `tproxy_enabled: true` (D101). `init_script` is emitted only here, and only as the empty list.
 * `requirements` goes away entirely when `platforms` is its only member, otherwise only that member
 * is removed, so a future requirement (a GPU list, say) is not silently dropped.
 */
export function phalaAppCompose(appCompose, kmsCaPubkey) {
  if (kmsCaPubkey === undefined) {
    throw new Error("--target phala requires --kms-ca-pubkey <the node KMS's ca_pubkey hex>");
  }
  const keyProviderId = validateKmsCaPubkey(kmsCaPubkey);
  const phala = { ...appCompose };
  delete phala.storage_discard;
  const requirements = phala.requirements;
  if (requirements !== null && typeof requirements === "object" && !Array.isArray(requirements)) {
    const remaining = Object.keys(requirements).filter((key) => key !== "platforms");
    if (remaining.length !== Object.keys(requirements).length) {
      if (remaining.length === 0) {
        delete phala.requirements;
      } else {
        const trimmed = { ...requirements };
        delete trimmed.platforms;
        phala.requirements = trimmed;
      }
    }
  }
  // D101 saw these members for a gateway-enabled app. `tproxy_enabled` and the `tproxy-net` feature are dstack's older
  // names for the gateway, so an app with `gateway_enabled: false` (--gateway-enabled false) carries neither. Phala's
  // normalized form of such an app has not been observed yet: phala-deploy.mjs update refuses to commit when
  // Phala's compose_hash differs from this file's, so a different normalization fails before the CVM changes.
  const gateway = appCompose.gateway_enabled !== false;
  phala.features = gateway ? ["kms", "tproxy-net"] : ["kms"];
  phala.init_script = [];
  phala.key_provider_id = keyProviderId;
  // D101: Phala adds its per-port proxy flag (false) to each port the app forwards (none in the stack layout).
  phala.port_policy = { restrict_mode: true, ports: appCompose.port_policy.ports.map((entry) => ({ ...entry, pp: false })) };
  phala.storage_fs = "zfs";
  phala.tproxy_enabled = gateway;
  return phala;
}

/** A parsed compose value as plain JSON (mappings as objects), to compare with the stack's tables. */
function plainValue(value) {
  if (isMap(value)) {
    const object = Object.create(null);
    for (const [key, member] of value) object[String(key)] = plainValue(member);
    return object;
  }
  if (isList(value)) return value.map(plainValue);
  return value;
}

function sameValue(actual, expected) {
  return actual !== undefined && canonicalJson(plainValue(actual)) === canonicalJson(expected);
}

/**
 * P2e: lane's mounts in the stack layout: STACK_FIXED's, and for an app with a KMS lease the vault's bind after the guest
 * agent's socket (where --kms-url adds its line).
 */
export function stackLaneVolumes(leased) {
  const volumes = [...STACK_FIXED.lane.volumes];
  if (leased) volumes.splice(volumes.indexOf(DSTACK_SOCKET_BIND) + 1, 0, VAULT_BIND);
  return volumes;
}

/** S2-S5, §9 B: every stack-only setting is exactly the layout's value (STACK_FIXED). */
function checkStackFixed(services, label, problems) {
  for (const [name, fixed] of Object.entries(STACK_FIXED)) {
    const service = services.get(name);
    if (!isMap(service)) continue;
    // P2e: lane's mounts gain the vault's bind exactly when lane names the KMS it keeps a lease with (LANE_KMS_URL).
    const leased = name === "lane" && environmentOf(service).has(KMS_URL_ENV);
    for (const [key, fixedValue] of Object.entries(fixed)) {
      const expected = leased && key === "volumes" ? stackLaneVolumes(true) : fixedValue;
      const actual = service.get(key);
      if (actual === undefined) {
        problems.push(`${label}: ${name} must set ${key}: ${canonicalJson(expected)} (S2-S5)`);
      } else if (!sameValue(actual, expected)) {
        problems.push(`${label}: ${name}.${key} is ${canonicalJson(plainValue(actual))}; the stack layout fixes it to ${canonicalJson(expected)} (S2-S5)`);
      }
    }
  }
}

/**
 * The stack's environments are mappings, the form compose.stack.yaml writes: the seed rule names lane's
 * LANE_BRIDGE_KEY_SEED by its mapping path, and @gray/lane-compose reads only that form.
 */
function checkStackEnvironmentForm(services, label, problems) {
  for (const name of STACK_SERVICE_NAMES) {
    const service = services.get(name);
    if (isMap(service) && service.has("environment") && !isMap(service.get("environment"))) {
      problems.push(`${label}: ${name}.environment is not a mapping of names to values`);
    }
  }
}

/**
 * E1b/S54: no stack service sets LANE_KEY_ID: the entrypoint derives `app-<app id>` from the guest agent, one
 * per app, as it derives KEYSET_SUBJECT (D47), so one compose serves every relay.
 */
function checkStackLaneKeyId(services, label, problems) {
  for (const name of STACK_SERVICE_NAMES) {
    const service = services.get(name);
    if (isMap(service) && environmentOf(service).has("LANE_KEY_ID")) {
      problems.push(`${label}: ${name} sets LANE_KEY_ID; in the stack layout the entrypoint derives it from the app id (S54)`);
    }
  }
}

/** S3: lane listens for clients on its front address only (STACK_LANE_LISTEN_ADDRESS). */
function checkStackLaneListen(services, label, problems) {
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const address = environmentOf(lane).get("LISTEN_ADDRESS");
  if (address !== STACK_LANE_LISTEN_ADDRESS) {
    problems.push(`${label}: lane's LISTEN_ADDRESS is ${address === undefined ? "missing" : `'${address}'`}; the stack layout fixes it to '${STACK_LANE_LISTEN_ADDRESS}', lane's front address (S3: a wildcard listener is reachable from relay_in)`);
  }
}

/**
 * §9 B: every stack service runs as its own numeric, non-root uid and gid. A user name would resolve
 * through the image's /etc/passwd, which the compose does not measure. No two services share one.
 */
function checkStackUsers(services, label, problems) {
  const owners = new Map();
  for (const name of STACK_SERVICE_NAMES) {
    const service = services.get(name);
    if (!isMap(service)) continue;
    const user = scalarText(service.get("user"));
    const match = user === undefined ? null : /^([0-9]+):([0-9]+)$/.exec(user);
    if (match === null) {
      problems.push(`${label}: ${name} must set user: "<uid>:<gid>" with numeric ids; a name resolves through the image's /etc/passwd (§9 B)`);
      continue;
    }
    const uid = Number(match[1]);
    if (uid === 0 || Number(match[2]) === 0) {
      problems.push(`${label}: ${name} runs as uid or gid 0; every stack service runs as non-root (§9 B)`);
    }
    const other = owners.get(uid);
    if (other !== undefined) problems.push(`${label}: ${other} and ${name} share uid ${uid}; every stack service has its own (§9 B)`);
    else owners.set(uid, name);
  }
}

/** S3: exactly the stack's three networks, with their internal flags, subnets and bridge names. */
function checkStackNetworks(data, label, problems) {
  const networks = data.get("networks");
  const names = Object.keys(STACK_NETWORKS);
  if (!isMap(networks)) {
    problems.push(`${label}: the stack layout must declare the top-level networks ${listText(names)} (S3)`);
    return;
  }
  for (const key of networks.keys()) {
    if (!names.includes(String(key))) problems.push(`${label}: network '${key}' is not one of the stack's ${listText(names)} (S3)`);
  }
  for (const [name, expected] of Object.entries(STACK_NETWORKS)) {
    const actual = networks.get(name);
    if (!sameValue(actual, expected)) {
      problems.push(`${label}: network ${name} is ${actual === undefined ? "missing" : canonicalJson(plainValue(actual))}; the stack layout fixes it to ${canonicalJson(expected)} (S3)`);
    }
  }
}

/** D63/S2a: the stack's top-level volumes are exactly the egress socket's tmpfs. */
function checkStackVolumes(data, label, problems) {
  const volumes = data.get("volumes");
  if (!sameValue(volumes, STACK_VOLUMES)) {
    problems.push(`${label}: top-level volumes is ${volumes === undefined ? "missing" : canonicalJson(plainValue(volumes))}; the stack layout fixes it to ${canonicalJson(STACK_VOLUMES)} (D63, S2a)`);
  }
}

/**
 * S4/S8/S54: lane's bridge seed and the identity's two values are the only interpolations in the stack's file,
 * each exactly its expression at its place (STACK_INTERPOLATIONS). Any other `$` would let the host's encrypted
 * env change what the measured bytes run, so it is refused in every key and value.
 */
function checkStackInterpolation(data, label, problems) {
  const walk = (value, path) => {
    if (isMap(value)) {
      for (const [key, member] of value) {
        const keyText = String(key);
        if (keyText.includes("$")) problems.push(`${label}: ${[...path, keyText].join(".")} has a '$' in its key; the stack allows no interpolation there (S8)`);
        walk(member, [...path, keyText]);
      }
    } else if (isList(value)) {
      value.forEach((member, index) => walk(member, [...path, String(index)]));
    } else if (typeof value === "string" && value.includes("$")) {
      if (STACK_INTERPOLATIONS[path.join(".")] !== value) {
        problems.push(`${label}: ${path.join(".")} interpolates '${value}'; the stack allows only ${Object.entries(STACK_INTERPOLATIONS).map(([at, expression]) => `${at}: "${expression}"`).join(", ")} (S4/S8/S54)`);
      }
    }
  };
  walk(data, []);
}

function isPlaceholderText(text) {
  return /set-at-deploy\b/i.test(text) || /\b[a-z0-9.-]*\.invalid\b/i.test(text);
}

/**
 * S23/S28/S54: the lane settings that make the entrypoint render the relay-stack layout, with their fixed
 * values: the relay the identity names (its interpolation, which the entrypoint checks against the measured
 * event), the relay config listener on lane's relay_in address (S2: 8081 only) and the relay container's
 * address (S2: 10.231.10.3:3000).
 */
export const STACK_LANE_ENVIRONMENT = Object.freeze({
  LANE_STACK_RELAY_ID: STACK_RELAY_ID_EXPRESSION,
  LANE_STACK_CONFIG_LISTEN: "10.231.10.2:8081",
  LANE_STACK_RELAY_ADDRESS: "10.231.10.3:3000",
});
/** S28: the stack's tunable, a literal inside @gray/config's LANE_STACK_POLL_MS bounds (not a fixed value). */
const STACK_LANE_POLL = "LANE_STACK_POLL_MS";

function checkStackLaneEnvironment(services, label, problems) {
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const environment = environmentOf(lane);
  for (const [key, fixed] of Object.entries(STACK_LANE_ENVIRONMENT)) {
    const value = environment.get(key);
    if (typeof value !== "string") {
      problems.push(`${label}: lane must set ${key} to "${fixed}" (S28)`);
    } else if (value !== fixed) {
      problems.push(`${label}: lane.${key} is "${value}"; the relay-stack layout fixes it to "${fixed}" (S2, S28, S54)`);
    }
  }
  const poll = environment.get(STACK_LANE_POLL);
  if (typeof poll !== "string") {
    problems.push(`${label}: lane must set ${STACK_LANE_POLL} (@gray/config, S28)`);
  } else {
    const problem = boundedMsProblem(STACK_LANE_POLL, poll);
    if (problem !== null) problems.push(`${label}: lane.${STACK_LANE_POLL} ${problem}`);
  }
}

/**
 * S2/S7/S50: Gray's three services run one Gray digest, all placeholders or all real; `relay` runs its local
 * slot (STACK_FIXED holds it to exactly that, with `pull_policy: never`).
 */
function checkStackImages(services, images, options, label, problems) {
  for (const name of STACK_SERVICE_NAMES) {
    if (name === RELAY_SERVICE) continue;
    const service = services.get(name);
    if (!isMap(service)) continue;
    const image = service.get("image");
    if (typeof image !== "string") {
      problems.push(`${label}: ${name} names no image`);
      continue;
    }
    images.push(image);
    if (!PINNED_IMAGE.test(image)) {
      problems.push(`${label}: ${name} image '${image}' is not pinned by @sha256:<64 hex>`);
    } else if (PLACEHOLDER_DIGEST.test(image) && !options.allowPlaceholderDigest) {
      problems.push(`${label}: ${name} image '${image}' still has the placeholder digest: set the digest deploy/tee/build.sh printed (--image)`);
    }
  }
  if (new Set(images).size > 1) {
    problems.push(`${label}: Gray's services run different images (${[...new Set(images)].join(", ")}); egress, isolation-check and lane must name the one audited Gray digest`);
  }
  const relay = services.get(RELAY_SERVICE);
  if (isMap(relay) && typeof relay.get("image") === "string") images.push(relay.get("image"));
}

/**
 * The measured compose's gate (D58). It parses the file with the `yaml` package, not line patterns:
 * a flow-style port list, a long-form port map, a `privileged: true`, a dropped isolation field or a
 * volume shared with egress is refused before the bytes are measured. `allowPlaceholders` is the
 * documented development escape only (it skips the deployment identity, never the isolation rules);
 * `nowSeconds` is the injectable clock of the KEYSET_NOT_AFTER window. `target` (D100) selects the
 * output members only (D100/D101): every check below runs unchanged for both targets. `layout` picks
 * the layout's services and allowlist; `stack` adds S2-S8's rules on top of the shared ones.
 */
export function checkCompose(composeText, options = {}) {
  targetOf(options);
  const spec = layoutSpec(options);
  const label = spec.label;
  const problems = [];
  const images = [];
  const parsed = parseCompose(composeText);
  if (parsed.error !== undefined) {
    problems.push(`${label} ${parsed.error}`);
    return { problems, images };
  }
  const names = [...parsed.services.keys()].map(String).sort();
  if (names.join(",") !== [...spec.services].sort().join(",")) {
    problems.push(`${label} must define exactly the ${listText(spec.services)} services (found ${names.join(", ") || "none"})`);
  }
  for (const name of spec.services) {
    const service = parsed.services.get(name);
    if (!isMap(service)) continue;
    checkIsolation(name, service, label, problems, spec.name === "default" ? PEERLINK_SERVICE : undefined);
    for (const credential of REGISTRY_ENVS) {
      let referenced = false;
      forEachScalar(service, (text) => {
        if (new RegExp(`\\b${credential}\\b`).test(text)) referenced = true;
      });
      if (referenced) {
        problems.push(`${label}: ${name} references ${credential}: the registry credentials belong to pre_launch_script's docker login, never to a service`);
      }
    }
  }
  checkClosedKeys(parsed.data, parsed.services, spec, problems);
  checkVolumesAndPorts(parsed.services, parsed.data, spec, problems);
  checkCertificateKey(parsed.services, spec, problems);
  if (spec.name === "stack") {
    checkStackLaneEnvironment(parsed.services, label, problems);
    checkStackPeerlink(parsed.services, label, problems);
    checkStackKmsUrl(parsed.services, label, problems);
    checkStackImages(parsed.services, images, options, label, problems);
    checkStackEnvironmentForm(parsed.services, label, problems);
    checkStackFixed(parsed.services, label, problems);
    checkStackLaneListen(parsed.services, label, problems);
    checkStackLaneKeyId(parsed.services, label, problems);
    checkStackUsers(parsed.services, label, problems);
    checkStackNetworks(parsed.data, label, problems);
    checkStackVolumes(parsed.data, label, problems);
    checkStackInterpolation(parsed.data, label, problems);
    checkStackNotEntry(parsed.services, label, problems);
  } else {
    checkImages(parsed.services, images, options, problems);
    checkEntryPeers(parsed.services, label, problems);
    checkEntryPeerlink(parsed.services, label, problems);
    // The stack settings are what makes the entrypoint render the relay listener (S28); the default
    // layout has no relay network, so none of them belongs there.
    for (const [name, service] of parsed.services) {
      if (!isMap(service)) continue;
      for (const key of [...Object.keys(STACK_LANE_ENVIRONMENT), STACK_LANE_POLL, PEER_ENTRIES_ENV, KMS_URL_ENV]) {
        if (environmentOf(service).has(key)) problems.push(`${label}: ${name} sets ${key}, which only the relay-stack layout's lane sets (S28)`);
      }
    }
  }
  checkIdentity(parsed.services, parsed.data, options, spec, problems);
  checkSchedulerPick(parsed.services, label, problems);
  checkReleaseKeys(parsed.services, options, label, problems);
  checkBodyCap(parsed.services, label, problems);
  return { problems, images };
}

/** The measured pre-launch script's text: embedded verbatim, so its bytes are part of the hash. */
export function readPreLaunchScript(path = PRE_LAUNCH_PATH) {
  return readFileSync(path, "utf8");
}

/**
 * Rewrite the one `KEY: "value"` line of compose.yaml, preserving its indentation and any trailing
 * comment. Exactly one line must match: a flag that silently did nothing would leave a measurement
 * the operator did not intend.
 */
function setEnvLines(composeText, key, value, flag, expected) {
  const pattern = new RegExp(
    `^([ \\t]+${key}[ \\t]*:[ \\t]*)(?:"[^"\\n]*"|'[^'\\n]*'|[^\\n#]*?)([ \\t]*(?:#.*)?)$`,
    "gm",
  );
  const matches = composeText.match(pattern) ?? [];
  if (matches.length !== expected) {
    throw new Error(`compose.yaml has ${matches.length} ${key} lines; expected exactly ${expected} to set from ${flag}`);
  }
  return composeText.replace(pattern, (_match, prefix, suffix) => `${prefix}${JSON.stringify(value)}${suffix}`);
}

/**
 * A `key: "value"` line after the one line that sets `anchor`, with the same indentation; refused when `key` is set
 * already or `anchor` is not exactly one line.
 */
function addEnvLineAfter(composeText, anchor, key, value, flag) {
  if (new RegExp(`^[ \\t]+${key}[ \\t]*:`, "m").test(composeText)) throw new Error(`compose.yaml sets ${key} already; ${flag} adds it`);
  const pattern = new RegExp(`^([ \\t]+)${anchor}[ \\t]*:[^\\n]*$`, "gm");
  const matches = composeText.match(pattern) ?? [];
  if (matches.length !== 1) throw new Error(`compose.yaml has ${matches.length} ${anchor} lines; ${flag} adds its line under exactly one`);
  return composeText.replace(pattern, (line, indent) => `${line}\n${indent}${key}: ${JSON.stringify(value)}`);
}

/**
 * A `- item` list line after the one line that is `- anchor`, with the same indentation; refused when `item` is listed
 * already or `anchor` is not exactly one line.
 */
function addListLineAfter(composeText, anchor, item, flag) {
  const quote = (text) => text.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  if (new RegExp(`^[ \\t]+- ${quote(item)}[ \\t]*$`, "m").test(composeText)) throw new Error(`compose.yaml lists ${item} already; ${flag} adds it`);
  const pattern = new RegExp(`^([ \\t]+)- ${quote(anchor)}[ \\t]*$`, "gm");
  const matches = composeText.match(pattern) ?? [];
  if (matches.length !== 1) throw new Error(`compose.yaml has ${matches.length} '- ${anchor}' lines; ${flag} adds its line under exactly one`);
  return composeText.replace(pattern, (line, indent) => `${line}\n${indent}- ${item}`);
}

/**
 * `--kms-url` and the gate's LANE_KMS_URL: https://<host>[:port][/path] without credentials, query or fragment (the form
 * kms-lease.mjs dials), never a reserved .invalid host. Returns the problem, or null.
 */
function kmsUrlProblem(text) {
  let url;
  try {
    url = new URL(text);
  } catch {
    return "is not a URL";
  }
  if (url.protocol !== "https:" || url.hostname === "" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    return "is not https://<host>[:port][/path] without credentials, query or fragment";
  }
  if (url.hostname.endsWith(".invalid")) return "names a reserved .invalid host";
  return null;
}

function validateKmsUrl(text, flag) {
  const problem = kmsUrlProblem(text);
  if (problem !== null) throw new Error(`${flag} '${text}' ${problem} (the KMS of the app's measured key provider)`);
  return text;
}

/**
 * P2c-2: LANE_KMS_URL only on the stack lane, and only in its form (kmsUrlProblem). Absent is a VM without a lease.
 */
function checkStackKmsUrl(services, label, problems) {
  for (const [name, service] of services) {
    if (!isMap(service)) continue;
    const value = environmentOf(service).get(KMS_URL_ENV);
    if (value === undefined) continue;
    if (name !== "lane") {
      problems.push(`${label}: ${name} sets ${KMS_URL_ENV}; only the lane keeps the KMS lease (P2c-2)`);
      continue;
    }
    const problem = typeof value === "string" ? kmsUrlProblem(value) : "is not a string";
    if (problem !== null) problems.push(`${label}: lane.${KMS_URL_ENV} ${problem}; it is the KMS of the app's measured key provider (--kms-url, P2c-2)`);
  }
}

/** `--tls-domain`: a real lowercase DNS hostname; `.invalid` can never be issued a certificate. */
function validateTlsDomain(domain) {
  if (!TLS_HOST.test(domain)) throw new Error(`--tls-domain '${domain}' is not a lowercase DNS hostname`);
  if (domain.endsWith(".invalid") || domain === "invalid") {
    throw new Error(`--tls-domain '${domain}' is reserved for documentation (RFC 2606) and cannot be certified`);
  }
  return domain;
}

/** `--bridge-url`: the same https-origin rule the entrypoint enforces at boot. */
function validateBridgeUrl(text) {
  return validateHttpsOrigin(text, "--bridge-url");
}

/** An https origin with no user, path, query or fragment, parsed by WHATWG URL. */
function validateHttpsOrigin(text, flag) {
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error(`${flag} '${text}' is not a URL`);
  }
  if (url.protocol !== "https:") throw new Error(`${flag} '${text}' must be https`);
  if (url.username !== "" || url.password !== "" || (url.pathname !== "" && url.pathname !== "/") || url.search !== "" || url.hash !== "") {
    throw new Error(`${flag} '${text}' must be an https origin with no user, path, query or fragment`);
  }
  if (url.hostname === "") throw new Error(`${flag} '${text}' names no host`);
  if (url.hostname.endsWith(".invalid")) {
    throw new Error(`${flag} '${text}' names a reserved .invalid host`);
  }
  return text;
}



/** `--keyset-not-after`: a u64 of Unix seconds, never the 2100 default and inside D58's window. */
function validateKeysetNotAfter(text, nowSeconds) {
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`--keyset-not-after '${text}' is not a u64 of Unix seconds`);
  const value = BigInt(text);
  if (value === 0n || value > 18446744073709551615n) {
    throw new Error(`--keyset-not-after '${text}' must be a nonzero u64 of Unix seconds`);
  }
  if (value === BigInt(FORBIDDEN_KEYSET_NOT_AFTER)) {
    throw new Error(`--keyset-not-after '${text}' is the year-2100 default; the operator must choose the expiry`);
  }
  const now = BigInt(nowSeconds ?? Math.floor(Date.now() / 1000));
  if (value <= now || value > now + BigInt(KEYSET_WINDOW_SECONDS)) {
    throw new Error(`--keyset-not-after '${text}' is not within (now, now + 400 days]`);
  }
  return text;
}

/**
 * D109': `LANE_SCHEDULER_PICK_MS`'s row in `@gray/config`, the one source of its bounds: the gateway
 * refuses a value outside them at boot, so the generator refuses to measure one.
 */
function boundedRow(name) {
  const row = SETTINGS.find((setting) => setting.name === name);
  if (row === undefined || row.min === undefined || row.max === undefined) throw new Error(`@gray/config has no bounded ${name} row`);
  return row;
}

/** The problem with a millisecond setting's literal, or null: a decimal integer of ms inside its @gray/config row's bounds. */
function boundedMsProblem(name, text) {
  return boundedIntProblem(name, text, "milliseconds", "ms");
}

/** The problem with an integer setting's literal, or null: a decimal integer inside its @gray/config row's bounds. */
function boundedIntProblem(name, text, unit, short) {
  const row = boundedRow(name);
  if (!/^[1-9][0-9]*$/.test(text)) return `'${text}' is not a whole number of ${unit}`;
  const value = Number(text);
  if (value < row.min || value > row.max) return `${text} is not within ${name}'s ${row.min}..${row.max} ${short} (@gray/config)`;
  return null;
}

/** The problem with a LANE_SCHEDULER_PICK_MS value, or null: a decimal integer of ms inside the row's bounds. */
function schedulerPickProblem(text) {
  return boundedMsProblem("LANE_SCHEDULER_PICK_MS", text);
}

/** `--scheduler-pick-ms` (D109'): the lane's pick budget; each forward carries what is left of it as `budget_ms` (D122'). */
function validateSchedulerPickMs(text) {
  const problem = schedulerPickProblem(text);
  if (problem !== null) throw new Error(`--scheduler-pick-ms ${problem}`);
  return text;
}

/** D109': the lane carries its pick budget as a measured literal inside the setting's bounds. */
function checkSchedulerPick(services, label, problems) {
  const lane = services.get("lane");
  const raw = isMap(lane) ? environmentOf(lane).get("LANE_SCHEDULER_PICK_MS") : undefined;
  if (raw === undefined) {
    problems.push(`${label}: lane has no LANE_SCHEDULER_PICK_MS literal (D109')`);
    return;
  }
  const problem = schedulerPickProblem(raw);
  if (problem !== null) problems.push(`${label}: LANE_SCHEDULER_PICK_MS ${problem}; pass --scheduler-pick-ms`);
}

/**
 * Routing PR 9: the release-list keys are lane literals in both layouts, 64 lower-case hex, two different keys (D134),
 * and, when the caller names the environment's (`options.releaseKeys`, release.mjs's profile), exactly those. Only lane
 * sets them, or an entry's settings.
 */
function checkReleaseKeys(services, options, label, problems) {
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const environment = environmentOf(lane);
  const values = RELEASE_KEY_ENVS.map((name) => environment.get(name));
  RELEASE_KEY_ENVS.forEach((name, index) => {
    const value = values[index];
    if (value === undefined) {
      problems.push(`${label}: lane has no ${name} literal: the environment's release-list keys are measured in both layouts (routing PR 9); pass --release-public-key and --release-freshness-public-key`);
    } else if (!RELEASE_KEY.test(value) && !(options.allowPlaceholders && isPlaceholderText(value))) {
      problems.push(`${label}: lane.${name} '${value}' is not 64 lower-case hex (the environment's ${index === 0 ? "release" : "freshness"} public key, routing PR 9)`);
    }
  });
  if (values[0] !== undefined && RELEASE_KEY.test(values[0]) && values[0] === values[1]) {
    problems.push(`${label}: lane's LANE_RELEASE_FRESHNESS_PUBLIC_KEY is its LANE_RELEASE_PUBLIC_KEY; the freshness key is a key of its own (D134)`);
  }
  if (options.releaseKeys !== undefined) {
    const expected = [options.releaseKeys.release, options.releaseKeys.freshness];
    RELEASE_KEY_ENVS.forEach((name, index) => {
      if (values[index] !== undefined && values[index] !== expected[index]) {
        problems.push(`${label}: lane.${name} is ${values[index]}, not the environment's ${expected[index]}: a lane that verifies Gray's lists with another key accepts what that key signs (routing PR 9)`);
      }
    });
  }
  for (const [name, service] of services) {
    if (name === "lane" || !isMap(service)) continue;
    const other = environmentOf(service);
    for (const key of [...RELEASE_KEY_ENVS, ...ENTRY_ENVS]) {
      if (other.has(key)) problems.push(`${label}: ${name} sets ${key}, which only lane sets (routing PR 9)`);
    }
  }
}

/**
 * Routing PR 9, default layout: LANE_PEERS is "true" or "false", egress runs `-peer` (spelled so, once) exactly when it
 * is "true", never `-relay-listen` (the stack layout's, which egress refuses beside -peer), and every PEER_* override on
 * lane is inside its @gray/config row's bounds. An entry needs the keys too (checkReleaseKeys holds both layouts to them).
 */
function checkEntryPeers(services, label, problems) {
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const environment = environmentOf(lane);
  const peers = environment.get(PEERS_ENV);
  if (peers !== "true" && peers !== "false") {
    problems.push(`${label}: lane must set ${PEERS_ENV} to "true" or "false" (the generator's --lane-peers): whether this lane is an entry for the relay stacks is a measured decision (routing PR 9)`);
  }
  for (const name of PEER_TUNABLES) {
    const value = environment.get(name);
    if (value === undefined) continue;
    const problem = boundedMsProblem(name, value);
    if (problem !== null) problems.push(`${label}: lane.${name} ${problem}`);
  }
  const egress = services.get("egress");
  if (!isMap(egress)) return;
  const command = egress.get("command");
  if (!isList(command) || !command.every((arg) => typeof arg === "string")) {
    problems.push(`${label}: egress.command is not a list of strings the gate can read`);
    return;
  }
  const spelled = command.filter((arg) => goFlag("peer").test(arg));
  if (spelled.some((arg) => arg !== PEER_FLAG)) {
    problems.push(`${label}: egress.command spells the peer mode ${spelled.filter((arg) => arg !== PEER_FLAG).join(", ")}; the measured compose writes it as ${PEER_FLAG} only`);
  }
  const on = spelled.filter((arg) => arg === PEER_FLAG).length;
  if (on > 1) problems.push(`${label}: egress.command has ${PEER_FLAG} ${on} times`);
  if (peers === "true" && on === 0) {
    problems.push(`${label}: lane's ${PEERS_ENV} is "true" but egress.command has no ${PEER_FLAG}: the entry's pins and peer calls would find no peer mode (routing PR 9)`);
  }
  if (peers !== "true" && on > 0) {
    problems.push(`${label}: egress.command has ${PEER_FLAG} but lane's ${PEERS_ENV} is not "true": only an entry runs egress's peer mode (routing PR 9)`);
  }
  if (command.some((arg) => goFlag("relay-listen").test(arg))) {
    problems.push(`${label}: egress.command has -relay-listen, which only the relay-stack layout's egress runs (and egress refuses it beside ${PEER_FLAG})`);
  }
  // relay-outbound-only §3.2: an entry's egress dials channel peers through peerlink: `-peer-link <PEERLINK_SOCKET>`,
  // spelled so, once, exactly when `-peer` is there (egress refuses -peer-link without -peer).
  const links = command.flatMap((arg, index) => (goFlag("peer-link").test(arg) ? [index] : []));
  if (links.some((index) => command[index] !== PEER_LINK_FLAG)) {
    problems.push(`${label}: egress.command spells the peer link ${links.map((index) => command[index]).filter((arg) => arg !== PEER_LINK_FLAG).join(", ")}; the measured compose writes it as ${PEER_LINK_FLAG} ${PEERLINK_SOCKET} only`);
  }
  if (links.length > 1) problems.push(`${label}: egress.command has ${PEER_LINK_FLAG} ${links.length} times`);
  if (links.length === 1 && command[links[0]] === PEER_LINK_FLAG && command[links[0] + 1] !== PEERLINK_SOCKET) {
    problems.push(`${label}: egress's ${PEER_LINK_FLAG} is ${command[links[0] + 1] ?? "missing its value"}; it is peerlink's socket ${PEERLINK_SOCKET} (relay-outbound-only §3.8)`);
  }
  if (on > 0 && links.length === 0) {
    problems.push(`${label}: egress.command has ${PEER_FLAG} without ${PEER_LINK_FLAG} ${PEERLINK_SOCKET}: an entry reaches the stack VMs that dial it only through peerlink (relay-outbound-only §3.2)`);
  }
  if (on === 0 && links.length > 0) {
    problems.push(`${label}: egress.command has ${PEER_LINK_FLAG} without ${PEER_FLAG}: egress refuses it, and only an entry dials channel peers`);
  }
}

/**
 * relay-outbound-only §3.2, §3.8, default layout: the entry's peerlink runs exactly ENTRY_PEERLINK_FIXED, the lane names
 * its socket exactly (PEERLINK_SOCKET), and no other service names it or the stack VM's entry list.
 */
function checkEntryPeerlink(services, label, problems) {
  const peerlink = services.get(PEERLINK_SERVICE);
  if (isMap(peerlink)) {
    for (const [key, expected] of Object.entries(ENTRY_PEERLINK_FIXED)) {
      if (!sameValue(peerlink.get(key), expected)) {
        problems.push(`${label}: peerlink.${key} is ${JSON.stringify(plainValue(peerlink.get(key)))}; the measured compose fixes it at ${JSON.stringify(expected)} (relay-outbound-only §3.8)`);
      }
    }
  }
  for (const [name, service] of services) {
    if (!isMap(service)) continue;
    const environment = environmentOf(service);
    if (environment.has("LANE_PEER_ENTRIES")) problems.push(`${label}: ${name} sets LANE_PEER_ENTRIES, which only a relay stack VM's lane sets: an entry dials no entry`);
    if (name !== "lane" && environment.has(PEERLINK_SOCKET_ENV)) problems.push(`${label}: ${name} sets ${PEERLINK_SOCKET_ENV}, which only lane sets`);
  }
  const lane = services.get("lane");
  if (isMap(lane) && environmentOf(lane).get(PEERLINK_SOCKET_ENV) !== PEERLINK_SOCKET) {
    problems.push(`${label}: lane must set ${PEERLINK_SOCKET_ENV}: "${PEERLINK_SOCKET}", peerlink's socket on ${PEERLINK_VOLUME} (relay-outbound-only §3.2)`);
  }
}

/** Routing PR 9, relay-stack layout: lane sets no entry setting: a relay stack VM is never an entry (section 4.6). */
function checkStackNotEntry(services, label, problems) {
  const lane = services.get("lane");
  if (!isMap(lane)) return;
  const environment = environmentOf(lane);
  for (const name of ENTRY_ENVS) {
    if (environment.has(name)) problems.push(`${label}: lane sets ${name}, an entry's setting: a relay stack VM is never an entry (routing PR 9)`);
  }
}

/**
 * Routing PR 9: egress's -max-body-bytes is at least the lane's body cap. The lane accepts a body of at most
 * BODY_PARSE_MAX_BYTES (`inference.ts` laneCap, `peer-routes.ts`; also `requestLimit`'s, which is never larger here),
 * and every byte of it crosses egress: to the vendor, to a stack VM over the peer hop (an entry forwards the client's
 * exact bytes), and in the stack layout to egress's registration. A lower egress bound would refuse a body the lane
 * accepted after its admission. Both are literals here (the egress flag spelled once), each inside its own bounds.
 */
function checkBodyCap(services, label, problems) {
  const lane = services.get("lane");
  const egress = services.get("egress");
  if (!isMap(lane) || !isMap(egress)) return;
  const raw = environmentOf(lane).get("BODY_PARSE_MAX_BYTES");
  if (raw === undefined) {
    problems.push(`${label}: lane has no BODY_PARSE_MAX_BYTES literal: the lane's body cap, which egress's -max-body-bytes must cover (routing PR 9)`);
    return;
  }
  const problem = boundedIntProblem("BODY_PARSE_MAX_BYTES", raw, "bytes", "bytes");
  if (problem !== null) {
    problems.push(`${label}: lane.BODY_PARSE_MAX_BYTES ${problem}`);
    return;
  }
  const command = egress.get("command");
  if (!isList(command) || !command.every((arg) => typeof arg === "string")) return;
  const at = command.flatMap((arg, index) => (goFlag("max-body-bytes").test(arg) ? [index] : []));
  if (at.length !== 1) {
    problems.push(`${label}: egress.command ${at.length === 0 ? "has no" : "repeats"} -max-body-bytes; the gate holds one literal to the lane's body cap (BODY_PARSE_MAX_BYTES ${raw})`);
    return;
  }
  const flag = command[at[0]];
  const value = flag.includes("=") ? flag.slice(flag.indexOf("=") + 1) : command[at[0] + 1];
  if (value === undefined || !/^[1-9][0-9]*$/.test(value)) {
    problems.push(`${label}: egress's -max-body-bytes is not a whole number of bytes`);
  } else if (Number(value) < Number(raw)) {
    problems.push(`${label}: egress's -max-body-bytes ${value} is below the lane's body cap BODY_PARSE_MAX_BYTES ${raw}: egress would refuse a body the lane accepted (routing PR 9)`);
  }
}

/**
 * Apply the D47 deployment flags to the measured compose. Only the matching literal lines change;
 * `KEYSET_SUBJECT` is deliberately not one of them (the entrypoint derives it). A flag that is not
 * given leaves the committed line alone, so `--allow-placeholders` still works for development.
 */
function applyComposeFlags(composeText, options) {
  let measured = composeText;
  if (options.deployEnv !== undefined) {
    if (!DEPLOY_ENVS.includes(options.deployEnv)) {
      throw new Error(`--deploy-env '${options.deployEnv}' is not testnet or production`);
    }
    measured = setEnvLines(measured, "DEPLOY_ENV", options.deployEnv, "--deploy-env", 1);
  }
  // S54: the stack lane's name is the relay identity's (encrypted env, measured by pre-launch).
  for (const [option, flag] of [["tlsDomain", "--tls-domain"], ["laneKeyId", "--lane-key-id"], ["relayId", "--relay-id"], ["relayTokenUrl", "--relay-token-url"], ["relayRegistry", "--relay-registry"], ["relayImage", "--relay-image"]]) {
    if (options[option] !== undefined && layoutSpec(options).name === "stack") {
      throw new Error(`${flag} is not a stack compose value: one stack compose serves every relay, and the relay's identity is the app's encrypted env (S54)`);
    }
  }
  if (options.tlsDomain !== undefined) {
    measured = setEnvLines(measured, "TLS_DOMAIN", validateTlsDomain(options.tlsDomain), "--tls-domain", 1);
  }
  if (options.bridgeUrl !== undefined) {
    measured = setEnvLines(measured, "LANE_BRIDGE_URL", validateBridgeUrl(options.bridgeUrl), "--bridge-url", 1);
  }
  if (options.keysetNotAfter !== undefined) {
    measured = setEnvLines(measured, "KEYSET_NOT_AFTER", validateKeysetNotAfter(options.keysetNotAfter, options.nowSeconds), "--keyset-not-after", 1);
  }
  if (options.schedulerPickMs !== undefined) {
    measured = setEnvLines(measured, "LANE_SCHEDULER_PICK_MS", validateSchedulerPickMs(options.schedulerPickMs), "--scheduler-pick-ms", 1);
  }
  // Routing PR 9: the environment's list keys in both layouts; the entry switch in the default layout only.
  for (const [option, flag, name] of [["releasePublicKey", "--release-public-key", RELEASE_KEY_ENVS[0]], ["releaseFreshnessPublicKey", "--release-freshness-public-key", RELEASE_KEY_ENVS[1]]]) {
    if (options[option] === undefined) continue;
    if (typeof options[option] !== "string" || !RELEASE_KEY.test(options[option])) throw new Error(`${flag} is 64 lower-case hex (the environment's public key, environments.json)`);
    measured = setEnvLines(measured, name, options[option], flag, 1);
  }
  if (options.peerEntries !== undefined) {
    if (layoutSpec(options).name !== "stack") throw new Error("--peer-entries is a stack compose value: only a relay stack VM dials entries (relay-outbound-only §3.2)");
    measured = setEnvLines(measured, PEER_ENTRIES_ENV, validatePeerEntries(options.peerEntries), "--peer-entries", 1);
  }
  if (options.kmsUrl !== undefined) {
    if (layoutSpec(options).name !== "stack") throw new Error("--kms-url is a stack compose value: only a relay stack VM keeps a KMS lease (P2c-2)");
    // A new line under lane's LANE_PEER_ENTRIES, with its indentation: the committed compose has none, so an app
    // without a lease measures exactly what it did before.
    measured = addEnvLineAfter(measured, PEER_ENTRIES_ENV, KMS_URL_ENV, validateKmsUrl(options.kmsUrl, "--kms-url"), "--kms-url");
    // P2e: and the vault's bind, a new line under lane's guest-agent socket (the one service that mounts it).
    measured = addListLineAfter(measured, DSTACK_SOCKET_BIND, VAULT_BIND, "--kms-url");
  }
  if (options.lanePeers !== undefined) {
    if (layoutSpec(options).name === "stack") throw new Error("--lane-peers is not a stack compose value: a relay stack VM is never an entry (routing PR 9)");
    if (options.lanePeers !== "true" && options.lanePeers !== "false") throw new Error(`--lane-peers '${options.lanePeers}' is not true or false`);
    measured = setEgressPeer(setEnvLines(measured, PEERS_ENV, options.lanePeers, "--lane-peers", 1), options.lanePeers === "true");
  }
  for (const [option, flag] of [["laneKeyId", "--lane-key-id"], ["relayId", "--relay-id"], ["relayTokenUrl", "--relay-token-url"], ["relayRegistry", "--relay-registry"]]) {
    if (options[option] !== undefined) throw new Error(`${flag} is gone: the stack layout's relay identity is the app's encrypted env (S54), and the default layout has none`);
  }
  return measured;
}

/**
 * `--lane-peers` (routing PR 9): egress's command with `-peer -peer-link <PEERLINK_SOCKET>` appended (on) or every
 * `-peer` and `-peer-link` removed (off), found under
 * services.egress in the `yaml` syntax tree and rewritten as a flow list in its own place; nothing else of the text
 * changes, and a command that already says so is left byte for byte.
 */
function setEgressPeer(composeText, on) {
  const document = parseDocument(composeText, { uniqueKeys: true, prettyErrors: false });
  if (document.errors.length > 0) throw new Error(`compose.yaml does not parse as YAML: ${document.errors[0].message.split("\n")[0]}`);
  const node = document.getIn(["services", "egress", "command"], true);
  if (!isSeq(node) || !Array.isArray(node.range) || !node.items.every((item) => isScalar(item) && typeof item.value === "string")) {
    throw new Error("compose.yaml: egress.command is not a list of strings --lane-peers can set -peer in");
  }
  const args = node.items.map((item) => item.value);
  // relay-outbound-only §3.2: `-peer-link <socket>` rides with `-peer`.
  const off = args.filter((arg, index) => arg !== PEER_FLAG && arg !== PEER_LINK_FLAG && args[index - 1] !== PEER_LINK_FLAG);
  const next = on ? [...off, PEER_FLAG, PEER_LINK_FLAG, PEERLINK_SOCKET] : off;
  if (next.length === args.length && next.every((arg, index) => arg === args[index])) return composeText;
  return `${composeText.slice(0, node.range[0])}[${next.map((arg) => JSON.stringify(arg)).join(", ")}]${composeText.slice(node.range[1])}`;
}

/**
 * `--gateway-enabled true|false`, default layout only: whether dstack's gateway routes to the entry. `true` when absent
 * (the committed bytes). A relay stack VM is never on the gateway (relay-outbound-only O1: `false`, and
 * `port_policy.ports: []`), so the stack layout refuses the flag.
 */
function gatewayEnabledOf(options) {
  const value = options.gatewayEnabled;
  const stack = layoutSpec(options).name === "stack";
  if (stack && value !== undefined) throw new Error("--gateway-enabled is not a stack compose value: a relay stack VM is never on dstack's gateway (relay-outbound-only O1)");
  // relay-outbound-only O1: a stack VM accepts no inbound connection, so it is off the gateway and forwards no port.
  if (stack) return false;
  if (value === undefined) return true;
  if (value !== "true" && value !== "false") throw new Error(`--gateway-enabled '${value}' is not true or false`);
  return value === "true";
}

/** The AppCompose object, with its members in dstack's own order (the bytes are sorted for hashing). */
export function appComposeFor(composeText, options = {}) {
  const spec = layoutSpec(options);
  const gatewayEnabled = gatewayEnabledOf(options);
  const checked = checkCompose(composeText, options);
  const problems = [...checked.problems];
  if (problems.length > 0) {
    throw new Error(`${spec.label} is not deployable:\n  ${problems.join("\n  ")}`);
  }
  const preLaunchScript = options.preLaunchScript ?? readPreLaunchScript(spec.preLaunchPath);
  if (typeof preLaunchScript !== "string" || preLaunchScript.trim() === "") {
    throw new Error(spec.name === "stack"
      ? "the measured pre-launch script is empty: deploy/tee/pre-launch.stack.sh (or --pre-launch) must exist and do the plan-B steps (S9)"
      : "the measured pre-launch script is empty: deploy/tee/pre-launch.sh must exist and do the docker login");
  }
  const appCompose = {
    manifest_version: MANIFEST_VERSION,
    name: APP_NAME,
    runner: RUNNER,
    docker_compose_file: composeText,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: true,
    kms_enabled: true,
    key_provider: "kms",
    gateway_enabled: gatewayEnabled,
    local_key_provider_enabled: false,
    allowed_envs: [...spec.allowedEnvs],
    no_instance_id: false,
    secure_time: true,
    storage_discard: false,
    // relay-outbound-only O1: the stack forwards no port; the entry (default layout) its one 443.
    port_policy: { restrict_mode: true, ports: spec.name === "stack" ? [] : [{ port: 443 }] },
    requirements: { platforms: ["dstack-tdx"] },
    pre_launch_script: preLaunchScript,
  };
  if (targetOf(options) === "phala") return phalaAppCompose(appCompose, options.kmsCaPubkey);
  // A key is only measured for Phala, but an invalid one is still refused rather than ignored.
  if (options.kmsCaPubkey !== undefined) validateKmsCaPubkey(options.kmsCaPubkey);
  return appCompose;
}

/** JSON with object keys sorted at every level, compact — the form the file is written in. */
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const members = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${members.join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * dstack's SDK algorithm (`sdk/js/src/get-compose-hash.ts`, and its Go and Python twins): drop a
 * `docker_compose_file` from a bash runner and a `bash_script` from a compose runner, drop an empty
 * `pre_launch_script`, sort every object's keys, `JSON.stringify` compact, SHA-256 over UTF-8.
 * Our pre-launch script is non-empty, so it stays in the hash.
 */
export function sdkComposeHash(appCompose) {
  const copy = { ...appCompose };
  if (copy.runner === "bash") delete copy.docker_compose_file;
  else if (copy.runner === "docker-compose" || copy.runner === "nerdctl-compose") delete copy.bash_script;
  if ("pre_launch_script" in copy && !copy.pre_launch_script) delete copy.pre_launch_script;
  return createHash("sha256").update(canonicalJson(copy), "utf8").digest("hex");
}

/** SHA-256 of the exact bytes written to disk: what the guest measures and a customer allowlists. */
export function bytesHash(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * The compose text a release measures: the committed file with the D47 identity flags applied and the
 * lane's placeholder digest replaced by the digest `deploy/tee/build.sh` printed. Only those lines
 * change, and the image must change: the file in the repository cannot name an image that does not
 * exist yet.
 */
export function substituteImage(composeText, image) {
  if (!PINNED_IMAGE.test(image) || PLACEHOLDER_DIGEST.test(image)) {
    throw new Error(`--image '${image}' is not a pinned digest reference (name@sha256:<64 hex>)`);
  }
  const lines = [...composeText.matchAll(IMAGE_LINE)];
  if (lines.length !== SERVICE_NAMES.length) {
    throw new Error(`compose.yaml has ${lines.length} image: lines; expected exactly ${SERVICE_NAMES.length} (${SERVICE_NAMES.join(", ")})`);
  }
  // Both services run the same measured image. A real digest next to a placeholder would let
  // --image substitute only the placeholder and measure two images (D58), so refuse the mix.
  for (const line of lines) {
    const value = line[2].trim().replace(/^["']|["']$/g, "");
    if (!PLACEHOLDER_DIGEST.test(value)) {
      throw new Error(`compose.yaml already pins '${value}'; every image line must be the same placeholder before --image substitutes one digest`);
    }
  }
  IMAGE_LINE.lastIndex = 0;
  return composeText.replace(IMAGE_LINE, `$1${image}`);
}

/**
 * S2/S7/S50: the stack's one digest: `image` replaces the placeholder on egress, isolation-check and lane,
 * each found under its service in the `yaml` syntax tree (not by line order), each still a placeholder. The relay
 * keeps its slot.
 */
export function substituteStackImages(composeText, image) {
  if (typeof image !== "string" || !PINNED_IMAGE.test(image) || PLACEHOLDER_DIGEST.test(image)) {
    throw new Error(`--image '${image}' is not a pinned digest reference (name@sha256:<64 hex>)`);
  }
  const document = parseDocument(composeText, { uniqueKeys: true, prettyErrors: false });
  if (document.errors.length > 0) {
    throw new Error(`compose.stack.yaml does not parse as YAML: ${document.errors[0].message.split("\n")[0]}`);
  }
  const edits = [];
  for (const name of STACK_SERVICE_NAMES) {
    if (name === RELAY_SERVICE) continue;
    const node = document.getIn(["services", name, "image"], true);
    if (!isScalar(node) || typeof node.value !== "string" || !Array.isArray(node.range)) {
      throw new Error(`compose.stack.yaml: ${name} has no image line to substitute`);
    }
    if (!PLACEHOLDER_DIGEST.test(node.value)) {
      throw new Error(`compose.stack.yaml already pins '${node.value}' on ${name}; every Gray image line must be a placeholder before --image substitutes the digest`);
    }
    edits.push({ start: node.range[0], end: node.range[1], text: image });
  }
  let measured = composeText;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    measured = `${measured.slice(0, edit.start)}${edit.text}${measured.slice(edit.end)}`;
  }
  return measured;
}

/**
 * S7/S55: the final gate of a stack render. The relay's pull-token service checks the measured
 * app-compose with `@gray/lane-compose`'s `checkSupplyAppCompose` against an expectation built from the
 * release list's `stack` member; Gray runs the same function on the exact bytes it renders, for either
 * target, with that expectation built the same way: the one Gray digest and the SHA-256 of the measured
 * pre-launch script. A compose the relay's service would refuse is therefore never released. Returns the
 * `stack` member the release list publishes for this compose, one per release (S55).
 */
function checkSupplyGate(json, appCompose, options) {
  if (SUPPLY_POLICY.module === undefined) {
    const reason = SUPPLY_POLICY.error instanceof Error ? SUPPLY_POLICY.error.message : String(SUPPLY_POLICY.error);
    throw new Error(`--layout stack runs @gray/lane-compose as its final gate (S7), which did not load; run npm ci in workers/ (${reason})`);
  }
  if (options.image === undefined) {
    throw new Error("--layout stack checks the rendered app-compose against the relays' expectation (S7): pass --image");
  }
  const stack = { gray_image: options.image, pre_launch_sha256: bytesHash(appCompose.pre_launch_script) };
  // Routing PR 9: the relays' policy holds the backend's list keys to the ones this render was given, as a relay that
  // knows its environment's keys does (`SupplyExpectation.releasePublicKey`, `.releaseFreshnessPublicKey`).
  const problems = SUPPLY_POLICY.module.checkSupplyAppCompose(json, {
    grayImages: [stack.gray_image],
    preLaunchSha256: stack.pre_launch_sha256,
    ...(options.releasePublicKey === undefined ? {} : { releasePublicKey: options.releasePublicKey }),
    ...(options.releaseFreshnessPublicKey === undefined ? {} : { releaseFreshnessPublicKey: options.releaseFreshnessPublicKey }),
  });
  if (problems.length > 0) {
    const lines = problems.map((problem) => `${problem.code} at ${problem.path || "(root)"}: ${problem.message}`);
    throw new Error(`@gray/lane-compose refuses this stack app-compose, so the relay's token service would refuse its pull token (S7):\n  ${lines.join("\n  ")}`);
  }
  return stack;
}

/**
 * The app-compose file's text. Sorted keys and no trailing newline, so the bytes are canonical: the
 * customer may hash either the file or dstack's normalized form and get one value. A stack render also
 * passes checkSupplyGate and returns the release list's `stack` member (S11a) as `stack`.
 */
export function renderAppCompose(composeText, options = {}) {
  const target = targetOf(options);
  const spec = layoutSpec(options);
  const deployed = applyComposeFlags(composeText, options);
  let measured;
  if (spec.name === "stack") {
    measured = options.image === undefined ? deployed : substituteStackImages(deployed, options.image);
  } else {
    if (options.relayImage !== undefined) throw new Error("--relay-image is only for --layout stack");
    measured = options.image === undefined ? deployed : substituteImage(deployed, options.image);
  }
  const appCompose = appComposeFor(measured, options);
  const json = canonicalJson(appCompose);
  const hash = bytesHash(json);
  const normalized = sdkComposeHash(appCompose);
  if (hash !== normalized) {
    throw new Error(`the rendered bytes are not canonical: bytes ${hash}, dstack's normalized form ${normalized}`);
  }
  if (spec.name === "stack") {
    const stack = checkSupplyGate(json, appCompose, options);
    return { target, appCompose, json, hash, normalized, composeText: measured, stack };
  }
  return { target, appCompose, json, hash, normalized, composeText: measured };
}

const USAGE = `usage: app-compose.mjs [--check] [--out <file>] [--compose <file>] [--layout default|stack]
  [--target dstack|phala] [--kms-ca-pubkey <182 hex>] [--deploy-env testnet|production]
  [--tls-domain <host> (default layout only)] [--bridge-url <https origin>] [--keyset-not-after <unix seconds>]
  [--scheduler-pick-ms <ms>] [--release-public-key <64 hex>] [--release-freshness-public-key <64 hex>]
  [--lane-peers true|false (default layout only)] [--gateway-enabled true|false (default layout only; default true)]
  [--peer-entries <name>[,<name>...] (stack layout only: the entries the VM dials first)]
  [--kms-url <https url> (stack layout only: an app on an on-chain KMS, whose lane keeps the KMS lease)]
  [--image <name@sha256:<64 hex>>] [--pre-launch <file>] [--allow-placeholders]
  (the stack layout names no relay: the relay's identity is the app's encrypted env, S54)`;

const VALUE_OPTIONS = new Set([
  "--out", "--compose", "--image", "--target", "--kms-ca-pubkey", "--deploy-env", "--tls-domain", "--bridge-url",
  "--keyset-not-after", "--scheduler-pick-ms", "--layout", "--pre-launch", "--release-public-key",
  "--release-freshness-public-key", "--lane-peers", "--gateway-enabled", "--peer-entries", "--kms-url",
]);
const BOOLEAN_OPTIONS = new Set(["--check", "--allow-placeholders", "--help"]);

/** Parse the small option set by hand: no dependency, and an unknown option is refused, not ignored. */
function parseArgs(argv) {
  const values = {};
  const flags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (BOOLEAN_OPTIONS.has(arg)) {
      flags.add(arg);
      continue;
    }
    if (!VALUE_OPTIONS.has(arg)) throw new Error(`unknown option '${arg}'\n${USAGE}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value\n${USAGE}`);
    values[arg] = value;
    index += 1;
  }
  return { values, flags };
}

/** The CLI's body, with the log sink injected so a test can run it in-process. */
export function main(argv = process.argv.slice(2), log = console.log) {
  const { values, flags } = parseArgs(argv);
  if (flags.has("--help")) {
    log(USAGE);
    return;
  }
  const check = flags.has("--check");
  const layout = values["--layout"];
  const spec = layoutSpec({ layout });
  const out = values["--out"] ?? spec.appComposePath;
  const composePath = values["--compose"] ?? spec.composePath;
  const composeText = readFileSync(composePath, "utf8");
  const preLaunchPath = values["--pre-launch"] ?? spec.preLaunchPath;
  let preLaunchScript;
  try {
    preLaunchScript = readPreLaunchScript(preLaunchPath);
  } catch (thrown) {
    const code = thrown !== null && typeof thrown === "object" && "code" in thrown ? thrown.code : String(thrown);
    throw new Error(`the measured pre-launch script ${preLaunchPath} cannot be read (${code}); pass --pre-launch <file>`);
  }
  const rendered = renderAppCompose(composeText, {
    layout,
    target: values["--target"],
    kmsCaPubkey: values["--kms-ca-pubkey"],
    image: values["--image"],
    allowPlaceholders: flags.has("--allow-placeholders"),
    deployEnv: values["--deploy-env"],
    tlsDomain: values["--tls-domain"],
    bridgeUrl: values["--bridge-url"],
    keysetNotAfter: values["--keyset-not-after"],
    schedulerPickMs: values["--scheduler-pick-ms"],
    releasePublicKey: values["--release-public-key"],
    releaseFreshnessPublicKey: values["--release-freshness-public-key"],
    lanePeers: values["--lane-peers"],
    gatewayEnabled: values["--gateway-enabled"],
    peerEntries: values["--peer-entries"],
    kmsUrl: values["--kms-url"],
    preLaunchScript,
  });

  if (check) {
    const existing = readFileSync(out, "utf8");
    if (existing !== rendered.json) {
      console.error(`${out} is not what ${spec.label} generates; run node deploy/tee/app-compose.mjs${spec.name === "stack" ? " --layout stack" : ""}`);
      process.exit(1);
    }
  } else {
    writeFileSync(out, rendered.json);
  }

  const images = checkCompose(rendered.composeText, { target: rendered.target, layout }).images;
  log(`${check ? "checked" : "wrote"} ${out} (${rendered.json.length} bytes)`);
  log(`  layout       ${spec.name} (${composePath})`);
  log(`  target       ${rendered.target}${rendered.target === "phala" ? " (Phala-normalized; key_provider_id set; D101)" : ""}`);
  log(`  images       ${images.join(", ")}`);
  log(`  fields       ${Object.keys(rendered.appCompose).length} (public_logs=false, public_sysinfo=false, kms, port_policy ${rendered.appCompose.port_policy.ports.map((entry) => entry.port).join(",") || "none"})`);
  log(`  allowed_envs ${rendered.appCompose.allowed_envs.join(", ")}`);
  const laneEnvironment = (() => {
    const parsed = parseCompose(rendered.composeText);
    const lane = parsed.services?.get("lane");
    return isMap(lane) ? environmentOf(lane) : new Map();
  })();
  log(`  list keys    release ${laneEnvironment.get(RELEASE_KEY_ENVS[0]) ?? "(none)"}, freshness ${laneEnvironment.get(RELEASE_KEY_ENVS[1]) ?? "(none)"}`);
  log(`  peers        ${spec.name === "stack" ? "backend mode (a relay stack VM is never an entry)" : `LANE_PEERS=${laneEnvironment.get(PEERS_ENV) ?? "(none)"}${laneEnvironment.get(PEERS_ENV) === "true" ? " (egress -peer: an entry)" : ""}`}`);
  log(`  pre_launch   ${preLaunchPath} (${Buffer.byteLength(rendered.appCompose.pre_launch_script, "utf8")} bytes)`);
  log(`  compose_hash sha256:${rendered.hash}`);
  log(`  sdk form     sha256:${rendered.normalized} (equal: the file is canonical)`);
  if (rendered.stack !== undefined) {
    log("  supply gate  @gray/lane-compose passes (the relay token service's policy, S7)");
    log(`  stack entry  ${JSON.stringify(rendered.stack)} (the release list's releases[].stack, S11a)`);
  }
  if (spec.name === "stack") {
    log(`  access       none inbound: gateway off, no port; peerlink dials ${laneEnvironment.get(PEER_ENTRIES_ENV) ?? "(no entry)"} (relay-outbound-only §3)`);
    return;
  }
  if (rendered.appCompose.gateway_enabled === false) {
    log("  access       gateway off: dstack's gateway routes nothing to this app; Spectrum reaches it through Phala's direct port");
    log("               (deploy/terraform-edge/README.md \"The direct origin\")");
    return;
  }
  // The only address a customer may be handed is TLS passthrough; the default gateway host
  // terminates TLS, and this lane has no such path (README, IMPLEMENTATION_NOTES §6.2, VG-01).
  log("  access       publish only a TLS-passthrough origin: <app-id>-443s.<base-domain> or a _dstack-app-address custom domain");
  log("               (the default <app-id>-443.<base-domain> terminates TLS at the gateway — unusable for this lane)");
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (thrown) {
    console.error(thrown instanceof Error ? thrown.message : String(thrown));
    process.exit(1);
  }
}
