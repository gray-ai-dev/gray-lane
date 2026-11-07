/**
 * The relay-stack layout's fixed values (docs/confidential-lane-supply-implementation.md §2, S2–S5, S8, S50, S54),
 * in one object: `checkSupplyAppCompose` checks a compose against exactly these. Every value here is the
 * one deploy/tee/app-compose.mjs renders and its stack gate pins (`STACK_FIXED`, `STACK_NETWORKS`,
 * `STACK_VOLUMES`, `STACK_SERVICE_KEYS`, `appComposeFor`, `phalaAppCompose`); the cross-check in
 * workers/packages/lane-verify/test/deploy-tee-stack-gates.test.ts keeps the two in step.
 */

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

const RELAY_IN_SUBNET = "10.231.10.0/24";
const RELAY_OUT_SUBNET = "10.231.11.0/24";
const FRONT_SUBNET = "10.231.12.0/24";
const LANE_FRONT_ADDRESS = "10.231.12.2";
const EGRESS_FRONT_ADDRESS = "10.231.12.3";
const LANE_ADDRESS = "10.231.10.2";
const EGRESS_ADDRESS = "10.231.11.2";
const RELAY_IN_ADDRESS = "10.231.10.3";
const RELAY_OUT_ADDRESS = "10.231.11.3";
const CHECK_IN_ADDRESS = "10.231.10.4";
const CHECK_OUT_ADDRESS = "10.231.11.4";
/** relay-outbound-only §3.8: peerlink's front address, which the relay's position must not reach. */
const PEERLINK_FRONT_ADDRESS = "10.231.12.4";
/** front's bridge address, the host's side of the network. */
const FRONT_GATEWAY_ADDRESS = "10.231.12.1";
const LANE_CONFIG_PORT = 8081;
const EGRESS_RELAY_PORT = 8080;
const RELAY_PORT = 3000;
const SOCKET_GROUP = "10100";
/** relay-outbound-only §3.8: the group of peerlink.sock (the image's /run/peerlink), held by lane and peerlink only. */
const PEERLINK_GROUP = "10101";
const PEERLINK_VOLUME = "peerlink-socket";
const PEERLINK_MOUNT = "/run/peerlink";
const PEERLINK_SOCKET = `${PEERLINK_MOUNT}/peerlink.sock`;
/** S2b: lane's uid:gid. */
const LANE_USER = "10001:10001";
const DSTACK_SOCKET = "/var/run/dstack.sock";
const EGRESS_VOLUME = "egress-socket";
const EGRESS_MOUNT = "/run/gray";
/** S5: every Gray service. */
const GRAY_OOM_SCORE_ADJ = -500;
const GRAY_LOGGING = { driver: "local", options: { "max-size": "10m", "max-file": "2" } };
/** D58: the hardening every service carries; app-compose.mjs's `checkIsolation`. */
const HARDENING_KEYS = ["read_only", "cap_drop", "security_opt", "ulimits"];

/** S50: the local slot pre-launch tags the relay's chosen image into; compose never pulls it. */
const RELAY_SLOT = "gray-relay-slot:boot";
/**
 * S54: the three encrypted-env names that carry the relay's identity, which pre-launch measures. relay-outbound-only
 * §3.9: no TLS name (GRAY_STACK_TLS_DOMAIN is gone): the VM has no public name.
 */
const IDENTITY_ENVS = ["GRAY_STACK_RELAY_ID", "GRAY_STACK_TOKEN_URL", "GRAY_STACK_RELAY_KEY"];
/** S54: the one of them the compose reads, as exactly this expression. */
const RELAY_ID_EXPRESSION = "${GRAY_STACK_RELAY_ID:?the relay identity is missing}";

/** S4: the relay's environment, literals only. */
const RELAY_ENVIRONMENT = {
  GRAY_RELAY_LISTEN: `0.0.0.0:${RELAY_PORT}`,
  GRAY_RELAY_CONFIG_URL: `http://${LANE_ADDRESS}:${LANE_CONFIG_PORT}/v1/relay/config`,
  GRAY_EGRESS_URL: `http://${EGRESS_ADDRESS}:${EGRESS_RELAY_PORT}`,
  TMPDIR: "/tmp",
  GRAY_DATA_DIR: "/data",
};

export const STACK_LAYOUT = deepFreeze({
  /** The app-compose runner (dstack `runner`). */
  runner: "docker-compose",
  /**
   * S8/S8a/S54: the host-injected encrypted env names, in the order app-compose.mjs renders them: the bridge seed,
   * Gray's registry credential, which only the measured pre-launch reads, and the relay's identity, which pre-launch
   * measures before it is used. The relay's registry login uses the pull token, never env. relay-outbound-only §3.9:
   * no EAB (gray-acme is self-signed here) and no TLS name.
   */
  allowedEnvs: ["LANE_BRIDGE_KEY_SEED", "DSTACK_DOCKER_REGISTRY", "DSTACK_DOCKER_USERNAME", "DSTACK_DOCKER_PASSWORD", ...IDENTITY_ENVS],
  /** S8a: the registry credential's names, which no service may mention. */
  registryEnvs: ["DSTACK_DOCKER_REGISTRY", "DSTACK_DOCKER_USERNAME", "DSTACK_DOCKER_PASSWORD"],
  /** S4/S8: lane's own LANE_BRIDGE_KEY_SEED, exactly this expression. */
  seed: { name: "LANE_BRIDGE_KEY_SEED", expression: "${LANE_BRIDGE_KEY_SEED:-}" },
  /** S54: the identity names of the encrypted env. */
  identityEnvs: IDENTITY_ENVS,
  /**
   * S4/S8/S54: every interpolation the compose may hold, as `services.<name>.environment.<NAME>` → its one
   * expression: the seed and the relay id lane reads.
   */
  interpolations: {
    "services.lane.environment.LANE_BRIDGE_KEY_SEED": "${LANE_BRIDGE_KEY_SEED:-}",
    "services.lane.environment.LANE_STACK_RELAY_ID": RELAY_ID_EXPRESSION,
  },
  /**
   * D47/D94/S54: names no service may set (the rendered config's location, the receipt key id, the keyset subject,
   * and the bridge key id, which the entrypoint derives from the app id as it derives the subject). D133: nor the
   * entrypoint's certificate seams (LANE_ACME, LANE_TLS_CERT, LANE_TLS_KEY: the lane always serves the pair the
   * image's gray-acme wrote for this boot), gray-acme's pre-D133 ACME_CERT_DIR, or its challenge address, which
   * the entrypoint sets to lane's LISTEN_ADDRESS.
   */
  forbiddenEnvironment: [
    "LANE_RENDERED", "LANE_TEMPLATE", "LANE_RECEIPT_KEY_ID", "KEYSET_SUBJECT", "LANE_KEY_ID",
    "LANE_ACME", "LANE_TLS_CERT", "LANE_TLS_KEY", "ACME_CERT_DIR", "ACME_TLS_ALPN_ADDRESS",
    // relay-outbound-only §3.9: a stack VM has no public name and no ACME (gray-acme refuses each of these in its
    // self-signed mode; the entrypoint refuses TLS_DOMAIN).
    "TLS_DOMAIN", "ACME_DIRECTORY_URLS", "ACME_DIRECTORY_URL", "ACME_STATE_DIR", "ACME_EMAIL", "ACME_EAB_KID", "ACME_EAB_HMAC_KEY",
  ],
  /** The compose project name app-compose.mjs's layouts use. */
  composeName: "gray-lane",
  /** S2: the stack's services (D133 merged the one-shot acme into lane; relay-outbound-only §3.8 adds peerlink). */
  services: ["lane", "egress", "peerlink", "isolation-check", "relay"],
  /** S50: the relay's image slot. */
  relaySlot: RELAY_SLOT,
  /** The guest agent's socket: bind-mounted only on `lane`. */
  dstackSocket: DSTACK_SOCKET,

  /** S3: the top-level networks, exactly. Only `front` routes out; the relay bridges' names are fixed. */
  networks: {
    front: { driver: "bridge", ipam: { config: [{ subnet: FRONT_SUBNET }] } },
    relay_in: {
      driver: "bridge",
      internal: true,
      driver_opts: { "com.docker.network.bridge.name": "gr-relay-in" },
      ipam: { config: [{ subnet: RELAY_IN_SUBNET }] },
    },
    relay_out: {
      driver: "bridge",
      internal: true,
      driver_opts: { "com.docker.network.bridge.name": "gr-relay-out" },
      ipam: { config: [{ subnet: RELAY_OUT_SUBNET }] },
    },
  },
  /** D63/S2b: the top-level volumes, exactly: the egress socket's plain volume. */
  volumes: { [EGRESS_VOLUME]: {}, [PEERLINK_VOLUME]: {} },

  /**
   * S2–S5: the keys each service may carry (app-compose.mjs `STACK_SERVICE_KEYS`). The relay has no
   * entrypoint/command override, no volume and no port.
   */
  serviceKeys: {
    lane: [
      "image", "restart", "user", "group_add", "networks", "environment", "volumes",
      "read_only", "tmpfs", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
    ],
    peerlink: [
      "image", "restart", "entrypoint", "command", "user", "group_add", "networks", "volumes",
      "read_only", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
    ],
    egress: [
      "image", "restart", "entrypoint", "command", "user", "group_add", "networks", "volumes",
      "read_only", "tmpfs", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
    ],
    "isolation-check": [
      "image", "restart", "depends_on", "entrypoint", "command", "user", "networks",
      "read_only", "cap_drop", "security_opt", "ulimits", "oom_score_adj", "logging",
    ],
    relay: [
      "image", "pull_policy", "restart", "depends_on", "user", "environment", "networks", "read_only", "tmpfs", "cap_drop",
      "security_opt", "ulimits", "mem_limit", "memswap_limit", "pids_limit", "cpus", "oom_score_adj", "logging",
    ],
  },
  /** The published ports, per service: none (relay-outbound-only O1, §3.8). */
  ports: { lane: [], egress: [], peerlink: [], "isolation-check": [], relay: [] },
  /**
   * S2–S5, S2a, S2b, S3, §9 B: the exact value of every fixed setting, as compose reads it (app-compose.mjs
   * `STACK_FIXED`): users, groups, networks and addresses, mounts, tmpfs, start order, entrypoints and
   * commands, limits, OOM priorities and logging.
   */
  fixed: {
    lane: {
      restart: "unless-stopped",
      user: LANE_USER,
      group_add: [SOCKET_GROUP, PEERLINK_GROUP],
      networks: { front: { ipv4_address: LANE_FRONT_ADDRESS }, relay_in: { ipv4_address: LANE_ADDRESS } },
      volumes: [`${DSTACK_SOCKET}:${DSTACK_SOCKET}`, `${EGRESS_VOLUME}:${EGRESS_MOUNT}`, `${PEERLINK_VOLUME}:${PEERLINK_MOUNT}`],
      tmpfs: ["/tmp", "/run/lane:mode=0700,uid=10001,gid=10001"],
      oom_score_adj: GRAY_OOM_SCORE_ADJ,
      logging: GRAY_LOGGING,
    },
    egress: {
      restart: "unless-stopped",
      entrypoint: ["/usr/local/bin/gray-egress"],
      // S17: the budget (192 MiB) and Go's soft limit (288 MiB), fixed; deploy/tee/compose.stack.yaml names
      // the measurement they come from.
      command: ["-socket", `${EGRESS_MOUNT}/egress.sock`, "-max-body-bytes", "4194304", "-relay-listen", `${EGRESS_ADDRESS}:${EGRESS_RELAY_PORT}`, "-stack-max-bytes", "201326592", "-memory-limit", "301989888"],
      user: "10002:10002",
      group_add: [SOCKET_GROUP],
      networks: { front: { ipv4_address: EGRESS_FRONT_ADDRESS }, relay_out: { ipv4_address: EGRESS_ADDRESS } },
      volumes: [`${EGRESS_VOLUME}:${EGRESS_MOUNT}`],
      tmpfs: ["/tmp"],
      oom_score_adj: GRAY_OOM_SCORE_ADJ,
      logging: GRAY_LOGGING,
    },
    peerlink: {
      restart: "unless-stopped",
      entrypoint: ["/usr/local/bin/gray-peerlink"],
      // relay-outbound-only §3.8: the VM role, its socket on the volume lane shares, every stream piped to lane's 443.
      command: ["-role", "vm", "-socket", PEERLINK_SOCKET, "-lane", `${LANE_FRONT_ADDRESS}:443`],
      user: "10005:10005",
      group_add: [PEERLINK_GROUP],
      networks: { front: { ipv4_address: PEERLINK_FRONT_ADDRESS } },
      volumes: [`${PEERLINK_VOLUME}:${PEERLINK_MOUNT}`],
      oom_score_adj: GRAY_OOM_SCORE_ADJ,
      logging: GRAY_LOGGING,
    },
    "isolation-check": {
      restart: "no",
      depends_on: { lane: { condition: "service_started" }, egress: { condition: "service_started" }, peerlink: { condition: "service_started" } },
      entrypoint: ["/usr/local/bin/gray-isolation-check"],
      // D133: the wait includes lane's certificate order; 10 minutes is the check's maximum. relay-outbound-only
      // §3.8: no port of front's hosts (its bridge, lane, egress, peerlink) answers the relay's position.
      command: [
        "-allow", `${LANE_ADDRESS}:${LANE_CONFIG_PORT},${EGRESS_ADDRESS}:${EGRESS_RELAY_PORT}`,
        "-deny", `${FRONT_GATEWAY_ADDRESS},${LANE_FRONT_ADDRESS},${EGRESS_FRONT_ADDRESS},${PEERLINK_FRONT_ADDRESS}`,
        "-wait", "10m",
      ],
      user: "10004:10004",
      networks: { relay_in: { ipv4_address: CHECK_IN_ADDRESS }, relay_out: { ipv4_address: CHECK_OUT_ADDRESS } },
      oom_score_adj: GRAY_OOM_SCORE_ADJ,
      logging: GRAY_LOGGING,
    },
    relay: {
      // S50: the slot pre-launch fills, never pulled.
      image: RELAY_SLOT,
      pull_policy: "never",
      restart: "unless-stopped",
      depends_on: { "isolation-check": { condition: "service_completed_successfully" } },
      user: "10003:10003",
      environment: RELAY_ENVIRONMENT,
      networks: { relay_in: { ipv4_address: RELAY_IN_ADDRESS }, relay_out: { ipv4_address: RELAY_OUT_ADDRESS } },
      // S5/S21a: sized, and owned by the relay's uid whatever the image holds at those paths.
      tmpfs: ["/tmp:size=256m,uid=10003,gid=10003,mode=1777", "/data:size=512m,uid=10003,gid=10003,mode=0700"],
      mem_limit: "1536m",
      memswap_limit: "1536m",
      pids_limit: 512,
      cpus: 1.5,
      oom_score_adj: 500,
      logging: { driver: "none" },
    },
  },
  /** S3: lane's listener is its front address (peerlink's streams' target), never `*:443`. */
  laneListenAddress: `${LANE_FRONT_ADDRESS}:443`,
  /**
   * S23/S28: lane's relay-stack literals (app-compose.mjs `STACK_LANE_ENVIRONMENT`): the relay config
   * listener on lane's relay_in address only, and the relay container the entry calls.
   */
  laneStackEnvironment: {
    LANE_STACK_CONFIG_LISTEN: `${LANE_ADDRESS}:${LANE_CONFIG_PORT}`,
    LANE_STACK_RELAY_ADDRESS: `${RELAY_IN_ADDRESS}:${RELAY_PORT}`,
    // relay-outbound-only §3.2: the lane's PEERLINK binding.
    PEERLINK_SOCKET,
  },
  /**
   * relay-outbound-only §3.2: the entries the VM dials until the bridge's `stack.entries` names them, the environment's
   * entry name (app-compose.mjs --peer-entries): one or more lower-case DNS names, comma-separated.
   */
  lanePeerEntriesName: "LANE_PEER_ENTRIES",
  /**
   * D133, relay-outbound-only §3.9: lane's gray-acme in its self-signed mode, writing this boot's key and certificate to
   * ACME_KEY_DIR on lane's /run/lane tmpfs (which nothing is mounted over), exactly. A key on a persistent directory
   * could be copied out by another compose of the same app and used outside the VM with the attested SPKI.
   */
  laneAcmeEnvironment: { ACME_KEY_DIR: "/run/lane/tls", ACME_SELF_SIGNED: "1" },
  /** S28/S54: lane's relay id, the identity's (`interpolations`): the entry serves only that relay. */
  laneRelayIdName: "LANE_STACK_RELAY_ID",
  /**
   * Routing PR 9 (docs/confidential-lane-stack-routing.md sections 4.3, 4.6): the environment's release-list public keys,
   * lane literals (app-compose.mjs `RELEASE_KEY_ENVS`). With both, the stack VM is in backend mode: it serves an entry
   * whose hello verified against the default list these keys sign. A compose without them (a release before PR 9) runs
   * no backend mode; one that names them names both, 64 lower-case hex, two different keys.
   */
  releaseKeyEnvs: ["LANE_RELEASE_PUBLIC_KEY", "LANE_RELEASE_FRESHNESS_PUBLIC_KEY"],
  /**
   * Routing PR 9: an entry's settings (app-compose.mjs `PEERS_ENV` and `PEER_TUNABLES`), which no stack service sets: a
   * relay stack VM is never an entry (section 4.6), so its lane never routes to other relays' VMs.
   */
  entryEnvironment: ["LANE_PEERS", "PEER_PROBE_MS", "PEER_DOWN_MS", "PEER_DOWN_MAX_MS", "PEER_RECHECK_MS", "PEER_RENEW_MS", "PEER_CALL_MS", "PEER_FOLLOW_UP_MS"],
  /** S4: the relay's environment (also in `fixed.relay`). */
  relay: { environment: RELAY_ENVIRONMENT },

  /** D58: every service's hardening, exactly. */
  hardening: {
    keys: HARDENING_KEYS,
    capDrop: ["ALL"],
    securityOpt: ["no-new-privileges:true"],
    ulimitsCore: 0,
  },

  /**
   * The app-compose members besides `docker_compose_file`, `pre_launch_script`, `allowed_envs` and the
   * Phala form's `key_provider_id`, exactly as app-compose.mjs renders them: `common` in both forms, then
   * the dstack form's (`--target dstack`) or the Phala-normalized form's (`--target phala`, D100/D101).
   */
  appCompose: {
    common: {
      manifest_version: "3",
      name: "gray-lane",
      runner: "docker-compose",
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: true,
      kms_enabled: true,
      key_provider: "kms",
      // relay-outbound-only O1: off dstack's gateway; the VM accepts no inbound connection.
      gateway_enabled: false,
      local_key_provider_enabled: false,
      no_instance_id: false,
      secure_time: true,
    },
    dstack: {
      storage_discard: false,
      port_policy: { restrict_mode: true, ports: [] },
      requirements: { platforms: ["dstack-tdx"] },
    },
    phala: {
      // D101: tproxy is dstack's older name for the gateway, so a gateway-off app carries neither (app-compose.mjs).
      features: ["kms"],
      init_script: [],
      port_policy: { restrict_mode: true, ports: [] },
      storage_fs: "zfs",
      tproxy_enabled: false,
    },
  },
} as const);

export type StackLayout = typeof STACK_LAYOUT;
