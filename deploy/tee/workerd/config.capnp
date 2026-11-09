# The workerd configuration of gray-lane inside the dstack CVM.
#
# A template: the image's entrypoint (bin/entrypoint.mjs) fills every double-underscore placeholder in
# /run/lane/config.capnp and refuses to start while one is left. Values come from the image build
# (SOURCE_REPO_URL, SOURCE_REPO_COMMIT, written to /etc/lane/build.env), from the container's
# environment (the deployment identity and the gateway vars the compose sets), from the dstack
# encrypted env (LANE_BRIDGE_KEY_SEED), and from the TLS certificate the CVM generated
# (TLS_SPKI_SHA256, computed from the leaf certificate's SubjectPublicKeyInfo). D47: KEYSET_SUBJECT is
# computed by the entrypoint from the guest agent's v1 Info app id, not read from the compose.
#
# Why these choices (deploy/tee/IMPLEMENTATION_NOTES.md §3):
#
# - One listener, on 443, and it terminates TLS inside the CVM. The certificate's private key is made in
#   the CVM, so the keyset's TLS entry binds the key a client actually talks to.
# - `globalOutbound` is a network service that allows nothing. The only paths out of the Worker are the
#   three service bindings below: the dstack guest agent (a Unix socket), the bridge (HTTPS with a
#   certificate host and the browser roots), and EGRESS (the gray-egress sidecar on a Unix socket,
#   plain HTTP). D18: EGRESS replaces the three per-vendor external services; the gateway consumes it
#   for every vendor request (laneFetch maps the official URL to /anthropic, /openai or /chatgpt).
# - LANE_BRIDGE_KEY_SEED is a secret from the dstack encrypted env: the entrypoint renders it into the
#   workerd config on the tmpfs, never into a log line, an error or the image.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    # The dstack guest agent, which the dstack guest mounts at /var/run/dstack.sock. `http = ()` selects
    # plain HTTP over the socket (the agent speaks HTTP over it; there is no TLS on the host socket).
    ( name = "guest-agent",
      external = (
        address = "unix:__GUEST_AGENT_SOCKET__",
        http = ()
      )
    ),

    # The lane bridge on Cloudflare (design v2 §D). TLS is verified against the browser roots and the
    # certificate must authenticate the host in LANE_BRIDGE_URL; the service binding delivers every
    # signed call to that one server (the request URL's host is what the host header carries).
    ( name = "bridge",
      external = (
        address = "__LANE_BRIDGE_ADDRESS__",
        https = (
          options = (),
          tlsOptions = (
            trustBrowserCas = true__LANE_BRIDGE_EXTRA_TRUST__
          ),
          certificateHost = "__LANE_BRIDGE_HOST__"
        )
      )
    ),

    # gray-egress (design v3 addendum E1, D63): one Unix socket, mode 0600, shared with the egress
    # service through the `egress-socket` tmpfs volume mounted at /run/gray. That volume holds only
    # this socket; the rendered config with the bridge seed is on /run/lane, mounted only by the lane.
    # The sidecar owns the TLS session to the vendor.
    ( name = "egress",
      external = (
        address = "unix:__EGRESS_SOCKET__",
        http = ()
      )
    ),__STACK_SERVICES__
__PEERLINK_SERVICES__
__VAULT_DISK_SERVICES__
    # Nothing is reachable through this service: `allow` defaults to ["public"], and the empty list
    # permits no address family at all (workerd.capnp, `Network.allow`).
    ( name = "no-network",
      network = ( allow = [] )
    ),

    ( name = "lane",
      worker = (
        # The bundle wrangler produced from workers/gateway/src/lane/entry.ts (build.sh), embedded under
        # a stable module name so the config does not depend on the bundle's file name.
        modules = [
           ( name = "worker.mjs", esModule = embed "__WORKER_MODULE_PATH__" ),
           ( name = "entry.js", esModule = embed "__ENTRY_MODULE_PATH__" )
          __WASM_MODULES__
        ],
        # The workspace's compatibility date (workers/README.md, tooling/vitest.ts).
        compatibilityDate = "2026-10-01",
        compatibilityFlags = [ "enable_request_signal", "global_fetch_strictly_public" ],
        globalOutbound = "no-network",
        bindings = [
          ( name = "GUEST_AGENT", service = "guest-agent" ),
          ( name = "LANE_BRIDGE", service = "bridge" ),
          ( name = "EGRESS", service = "egress" ),__STACK_BINDINGS__

          # The deployment identity the report publishes. None of these is a credential; the bridge
          # seed below is, and it is rendered from the dstack encrypted env only.
          ( name = "DEPLOY_ENV", text = "__DEPLOY_ENV__" ),
          ( name = "TEE_TYPE", text = "__TEE_TYPE__" ),
          ( name = "KEYSET_SUBJECT", text = "__KEYSET_SUBJECT__" ),
          ( name = "KEYSET_NOT_AFTER", text = "__KEYSET_NOT_AFTER__" ),
          ( name = "TLS_SPKI_SHA256", text = "__TLS_SPKI_SHA256__" ),
          ( name = "TLS_DOMAIN", text = "__TLS_DOMAIN__" ),
          ( name = "GUEST_AGENT_URL", text = "__GUEST_AGENT_URL__" ),
          ( name = "GUEST_AGENT_TIMEOUT_MS", text = "__GUEST_AGENT_TIMEOUT_MS__" ),

          # The lane's bridge identity (design v2 §D): where the signed calls go, which key id they
          # use, and the provisioned 32-byte seed (D17). The seed is required outside `local`.
          ( name = "LANE_BRIDGE_URL", text = "__LANE_BRIDGE_URL__" ),
          ( name = "LANE_KEY_ID", text = "__LANE_KEY_ID__" ),
          ( name = "LANE_RECEIPT_KEY_ID", text = "__LANE_RECEIPT_KEY_ID__" ),
          ( name = "LANE_BRIDGE_KEY_SEED", text = "__LANE_BRIDGE_KEY_SEED__" ),

          # The gateway's own vars (workers/packages/config): the lane reads them through gatewayConfig.
          ( name = "GATEWAY_FALLBACK_REGION", text = "__GATEWAY_FALLBACK_REGION__" ),
          ( name = "BODY_PARSE_MAX_BYTES", text = "__BODY_PARSE_MAX_BYTES__" ),
          ( name = "LANE_POLICY_STEP_MS", text = "__LANE_POLICY_STEP_MS__" ),
          ( name = "LANE_POLICY_FUEL_PER_MS", text = "__LANE_POLICY_FUEL_PER_MS__" ),
          ( name = "LANE_POLICY_OVERHEAD_MS", text = "__LANE_POLICY_OVERHEAD_MS__" ),
          ( name = "LANE_SCHEDULER_PICK_MS", text = "__LANE_SCHEDULER_PICK_MS__" ),__PEER_BINDINGS__
__PEERLINK_BINDINGS__
__KMS_LEASE_BINDINGS__
__VAULT_DISK_BINDINGS__          # Provenance from the build (§4.1 of the ACI spec; a deployment fills the image digest).
          ( name = "SOURCE_REPO_URL", text = "__SOURCE_REPO_URL__" ),
          ( name = "SOURCE_REPO_COMMIT", text = "__SOURCE_REPO_COMMIT__" ),
          ( name = "SOURCE_IMAGE_DIGEST", text = "__SOURCE_IMAGE_DIGEST__" )
          # E2E-ONLY-BINDINGS: no legacy per-vendor services are added. D18 landed; the host e2e uses
          # the same EGRESS binding the measured config uses, so this comment stays a comment.
        ]
      )
    )
  ],

  sockets = [
    ( name = "https",
      # `*:443` in the CVM. The local e2e renders 127.0.0.1:<port> instead, because a non-root process
      # cannot bind 443 on the test machine.
      address = "__LISTEN_ADDRESS__",
      https = (
        options = (),
        # `embed` reads the files when this config is parsed, i.e. at workerd's start, after the
        # entrypoint checked that the CVM wrote them. The private key never leaves the CVM's disk.
        tlsOptions = (
          keypair = (
            privateKey = embed "__TLS_KEY_PATH__",
            certificateChain = embed "__TLS_CERT_PATH__"
          )
        )
      ),
      service = "lane"
    )__STACK_SOCKETS__
__KMS_LEASE_SOCKETS__  ]
);
