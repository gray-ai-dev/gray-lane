#!/usr/bin/env node
// The entrypoint of the gray-lane image: read the app id, wait for the egress sidecar's socket, have
// gray-acme issue this boot's TLS certificate (D133), render workerd's config, then run workerd.
//
// What it renders, and why each value lives where it does (deploy/tee/IMPLEMENTATION_NOTES.md §3):
//
// - /etc/lane/build.env is written at image build time (deploy/tee/build.sh): the source commit the
//   image was built from. It cannot be known before the build, so it cannot be in a committed config.
// - The container's environment carries the deployment identity that is not the subject
//   (not_after, TEE type, timeouts, the bridge URL and the guest agent socket). D47: the keyset
//   subject is NOT a compose literal; this file reads the app id from the guest agent's v1 Info RPC
//   at boot and sets KEYSET_SUBJECT to `dstack:app-id:<app_id>`. A host-set KEYSET_SUBJECT changes
//   nothing, and a boot that cannot read the app id fails loudly. None of this is a request secret;
//   the compose file that sets the rest is part of the measured app-compose (deploy/tee/app-compose.mjs).
// - LANE_BRIDGE_KEY_SEED comes from the dstack encrypted env (D17). It is rendered into the workerd
//   config on the tmpfs and never printed: the log lines below name values, never this one.
// - D133: the TLS key and certificate are new on every boot. This file runs gray-acme (the image's
//   /usr/local/bin/gray-acme) inside this container before workerd binds 443; it generates the key in
//   memory and writes the pair only to ACME_KEY_DIR, the lane-only /run/lane tmpfs, so no other
//   container or compose can read it and it is gone when the container stops. A gray-acme failure
//   stops the boot: the lane never serves without a certificate issued for this boot. gray-acme runs
//   only after the cheap refusals, the guest agent's app id and the egress socket, so a boot that
//   would fail anyway does not spend a certificate order. It gets only its own settings (TLS_DOMAIN,
//   ACME_*, LEGO_*), never the bridge seed, and answers the challenge on the lane's own LISTEN_ADDRESS
//   (ACME_TLS_ALPN_ADDRESS), so in the relay-stack layout it never listens on relay_in.
// - D133, the order budget: every start of this container orders a certificate, so this file, not
//   Docker's restart policy, restarts workerd when it exits (`superviseWorkerd`): with Docker's own
//   backoff, in this container, from the same rendered config and this boot's key, with no new order.
//   It gives up (the container exits, and its next start orders again) only after GIVE_UP_EXITS exits
//   within GIVE_UP_WINDOW_MS, and never sooner than GIVE_UP_WINDOW_MS after this boot's order; a failed
//   gray-acme run holds ISSUE_FAILURE_HOLD_MS after its start before the container exits. Why these
//   numbers: deploy/tee/IMPLEMENTATION_NOTES.md D133.
// - A failed gray-acme run is reported to the bridge before the hold (`lane.acme_failed`, @gray/lane-wire
//   lane-acme.ts), because this container's log is not public (Phala `public_logs` off): gray-acme's lines, which
//   carry no key material, token or EAB value, read from its stderr and passed through to this process's, are
//   grouped by CA, cut to the wire's bounds, cleaned of the EAB values and the bridge seed once more, and sent as
//   one call signed with the bridge key the way the lane's Worker signs every bridge call (`gray-lane-bridge-v1`).
//   A report that cannot be sent is one log line; it never changes what the boot does.
// - The TLS SPKI is computed here, from the leaf certificate gray-acme just wrote, because the key
//   and the certificate exist only inside the CVM and only for this boot. `crypto.X509Certificate`
//   and `publicKey.export({ format: "der", type: "spki" })` are Node's own X.509 and key encoders;
//   nothing here parses DER by hand.
// - In the relay-stack layout (docs/confidential-lane-supply-implementation.md S52, S54, S55) the guest
//   agent's v0 Info answer also carries the boot's event log. Pre-launch measured who the boot serves
//   (`gray-stack-identity`) and the image the relay chose for it (`gray-relay-image`, signed by the relay's
//   key) before its seal; this file reads both, checks the relay's signature, refuses a LANE_STACK_RELAY_ID that
//   differs from the identity and any TLS_DOMAIN (docs/design/relay-outbound-only.md §3.9: the stack VM has no
//   public name, so its identity names none and its keyset's TLS key is bound to no domain), and passes the image to the entry as
//   LANE_STACK_RELAY_IMAGE. A stack compose without a LANE_KEY_ID literal (S54) gets `app-<app id>-<key>`, the
//   bridge key id this VM's own: the app's id, as KEYSET_SUBJECT is derived (D47), and the first 16 hex digits of the
//   bridge key's Ed25519 public key, so two instances of one app (an image rollout's, docs/design/relay-zero-downtime.md)
//   never share a key id and neither replaces the other's key on the console's list.
// - P2c-2 (docs/design/relay-no-always-on-host.md H9): a relay stack app on an on-chain KMS names that KMS in its
//   measured compose (LANE_KMS_URL). This process then keeps the KMS lease (kms-lease.mjs): it asks the KMS for the app
//   key again every 10 minutes and pushes each change of the lease to the lane Worker on a unix socket of its own
//   tmpfs, which workerd serves on the Worker's `kmsLease` entrypoint; the Worker serves the relay's accounts only
//   while the lease serves. Without LANE_KMS_URL (a phase-1 app) nothing of it is rendered or run.
// - P2e (docs/design/relay-no-always-on-host.md §3.1, 13.11): the same app keeps the relay's vault on the data disk
//   (/var/lib/gray-persist/relay, bound into lane by the stack layout for an app with LANE_KMS_URL). workerd has no disk,
//   so this process serves it (vault-disk.mjs) on a second unix socket of its own tmpfs, which workerd binds as the
//   external service LANE_VAULT_DISK: the Worker reads the record and writes each new version through it (atomic, fsynced,
//   never a version the disk has seen). A phase-1 app renders and runs none of it.
// - P2d (the same docs, §3.5): a phase-2 app's pre-launch takes the image from the sealed boot box and measures
//   `gray-relay-image` v2 (the relay-signed designation, no nonce), or the empty slot (`image: null`) when no boot box
//   opened; `stackBoot` reads v2 in a phase-2 app only, and an empty slot renders LANE_STACK_EMPTY_SLOT for the Worker.
//
// The entrypoint refuses to start when a value is missing or malformed, and when a placeholder
// survives rendering. It also fails closed if gray-egress never creates its socket: a lane that starts
// workerd with no egress path would answer every request with a transport failure, which is worse than
// not starting (E1 §2).
//
// Paths are overridable so the host e2e (deploy/tee/e2e/lane-e2e.mjs) can run this same file outside
// an image.
import { spawn } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign as signMessage, verify as verifySignature, X509Certificate } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIPv4 } from "node:net";
import { createInterface } from "node:readline";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { uptime as osUptime } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { kmsLeaseInputsFromInfo, kmsLeaseSettings, startKmsLease } from "./kms-lease.mjs";
import { startVaultDisk, VAULT_DIR } from "./vault-disk.mjs";

/** What a rendered value may contain: no quote, no backslash, no newline, no `__` sequence. */
const SAFE = /^[A-Za-z0-9._:/@+=,*\[\]-]*$/;
const SEED = /^[0-9a-f]{64}$/;
/** The lane relay id form (`@gray/control` LANE_RELAY_ID_PATTERN; app-compose.mjs `RELAY_ID`). */
const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
/** A lower-case DNS name of at least two labels (an entry name in LANE_PEER_ENTRIES). */
const DNS_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** The relay-stack layout's settings (S23, S28): the compose sets all three or none. */
const STACK_NAMES = Object.freeze(["LANE_STACK_RELAY_ID", "LANE_STACK_CONFIG_LISTEN", "LANE_STACK_RELAY_ADDRESS"]);
/**
 * Routing PR 9 (docs/confidential-lane-stack-routing.md sections 4.3, 4.6): the environment's release-list public keys,
 * both or neither. With them a stack lane is in backend mode, and a default lane may be an entry (LANE_PEERS).
 */
const RELEASE_KEY_NAMES = Object.freeze(["LANE_RELEASE_PUBLIC_KEY", "LANE_RELEASE_FRESHNESS_PUBLIC_KEY"]);
const RELEASE_KEY = /^[0-9a-f]{64}$/;
/**
 * An entry's peer tunables (@gray/config's PEER_* rows, which hold their defaults and bounds); a compose may set them in
 * the default layout only, and the gateway's config refuses a value outside a row's bounds at boot.
 */
export const PEER_TUNABLE_NAMES = Object.freeze(["PEER_PROBE_MS", "PEER_DOWN_MS", "PEER_DOWN_MAX_MS", "PEER_RECHECK_MS", "PEER_RENEW_MS", "PEER_CALL_MS", "PEER_FOLLOW_UP_MS"]);

/** dstack's runtime event type (cc-eventlog `DSTACK_RUNTIME_EVENT_TYPE`); RTMR3 is index 3. */
const RUNTIME_EVENT_TYPE = 0x08000001;
/** S52: the runtime events a sealed stack boot has after `system-ready`, in this order. */
const STACK_BOOT_EVENTS = Object.freeze(["gray-stack-identity", "gray-relay-image", "gray-prelaunch-sealed"]);
const SEALED_PAYLOAD = "gray-prelaunch-sealed-v1";
/** P2d: what the relay signs for a phase-2 designation (`@gray/relay-connector/vault` DESIGNATION_DOMAIN). */
const DESIGNATION_DOMAIN = "gray-relay-designation/v1";
/** S51: `<registry host[:port]>/<repository>@sha256:<64 hex>` (@gray/lane-verify `STACK_RELAY_IMAGE_PATTERN`). */
const RELAY_IMAGE = /^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)\/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$/;

/**
 * D133: Docker's restart backoff (moby v26.1.5 restartmanager/restartmanager.go:13-15,66-79), which
 * `superviseWorkerd` applies to workerd inside this container instead of letting Docker restart the
 * container: 100 ms before the first restart, doubled after each exit up to 60 s, and back to 100 ms
 * after a run of 10 s or more.
 */
export const RESTART_BACKOFF_FIRST_MS = 100;
export const RESTART_BACKOFF_MAX_MS = 60_000;
export const RESTART_BACKOFF_RESET_MS = 10_000;
/**
 * D133: the supervisor gives up after this many workerd exits within GIVE_UP_WINDOW_MS: the tenth exit
 * is where Docker's backoff above stops doubling (100 ms x 2^9 = 51.2 s; the next is capped at 60 s), so
 * restarting in place is no longer recovering anything.
 */
export const GIVE_UP_EXITS = 10;
/**
 * D133: and never sooner than this after this boot's certificate order. A container start orders one
 * certificate per CA tried, so a lane whose workerd keeps failing orders at most twice an hour: Google
 * Trust Services allows 100 new orders per hour per Google Cloud project, shared by every lane in the
 * project (docs.cloud.google.com/certificate-manager/docs/quotas), so 50 lanes can loop at once.
 */
export const GIVE_UP_WINDOW_MS = 30 * 60_000;
/**
 * D133: how long after its start a failed gray-acme run (exit 1, or a signal) holds the container before
 * it exits; a refused configuration (exit 2) contacted no CA and does not wait. One retry per 5 minutes
 * is at most 12 orders an hour per CA; the relay-stack isolation check's 10-minute wait covers this hold
 * and a second run (compose.stack.yaml).
 */
export const ISSUE_FAILURE_HOLD_MS = 5 * 60_000;

/** A boot failure: the CLI wrapper prints `lane: <message>` and exits 1 (tests run this in-process). */
class LaneError extends Error {}

function fail(message) {
  throw new LaneError(message);
}

function buildEnv(path) {
  const values = {};
  if (!existsSync(path)) return values;
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line === "" || line.startsWith("#")) continue;
    const at = line.indexOf("=");
    if (at <= 0) continue;
    values[line.slice(0, at)] = line.slice(at + 1);
  }
  return values;
}

function fromEnvironment(env, name, fallback) {
  const value = env[name];
  if (value === undefined || value === "") {
    if (fallback === undefined) fail(`${name} is not set`);
    return fallback;
  }
  return value;
}

/** The SPKI digest of the leaf certificate: SHA-256 over the DER of its SubjectPublicKeyInfo (§3.1). */
function spkiSha256(certificatePemPath) {
  const pem = readFileSync(certificatePemPath, "utf8");
  const certificate = new X509Certificate(pem);
  const spki = certificate.publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex");
}

/**
 * The guest agent's v1 Info answer and its app id (D47). The guest agent serves the internal surface
 * on its Unix socket with `/v1` mounted (dstack v0.6.1 guest-agent/src/server.rs, mount_internal),
 * and `InfoResponse.app_id` is a 20-byte value encoded as lower-case hex (prpc's serde helper;
 * dstack v0.6.1 vmm/src/app/mr_config.rs:146-155 requires 20 bytes). This is the same socket the
 * lane's Worker uses for `POST /v1/Attest`.
 *
 * `path` is `/v1/Info` for the app id. A relay-stack boot also reads the v0 `/Info` (S52): dstack v0.6.1's v1
 * `InfoResponse` carries no `tcb_info` and no event log by design (guest-agent/rpc/proto/agent_rpc_v1.proto,
 * "Identity"), while the frozen v0 `AppInfo.tcb_info` on the internal socket still holds the event log
 * (guest-agent/src/rpc_service.rs `get_info`: hidden only on the external listener).
 */
function guestInfo(socketPath, timeoutMs, path = "/v1/Info") {
  return new Promise((resolve, reject) => {
    const body = "{}";
    const request = httpRequest({
      socketPath,
      path,
      method: "POST",
      headers: { host: "localhost", "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      timeout: timeoutMs,
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if (response.statusCode !== 200) {
          reject(new Error(`POST ${path} answered ${response.statusCode}: ${text.slice(0, 200)}`));
          return;
        }
        let value;
        try {
          value = JSON.parse(text);
        } catch {
          reject(new Error(`POST ${path} did not answer JSON: ${text.slice(0, 200)}`));
          return;
        }
        const appId = value !== null && typeof value === "object" ? value.app_id : undefined;
        if (typeof appId !== "string" || !/^[0-9a-f]{40}$/.test(appId)) {
          reject(new Error(`POST ${path} returned no 20-byte lower-case hex app_id`));
          return;
        }
        resolve({ appId, info: value });
      });
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error(`POST ${path} on unix:${socketPath} timed out after ${timeoutMs} ms`)));
    request.on("error", reject);
    request.end(body);
  });
}

/**
 * One S52 payload: the hex of a UTF-8 JSON object with exactly `members`, every one a string. Pre-launch
 * writes it with `jq -cS` (compact, keys sorted), and only that form is read: the text must be what
 * JSON.stringify writes for its parsed object with sorted keys, so a duplicate key, extra whitespace or
 * another order is refused rather than read the way JSON.parse happens to read it. Null otherwise.
 */
function stackPayload(hex, members) {
  if (typeof hex !== "string" || !/^([0-9a-f]{2})*$/.test(hex)) return null;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.from(hex, "hex"));
  } catch {
    return null;
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== [...members].sort().join(",")) return null;
  if (keys.some((key) => typeof value[key] !== "string")) return null;
  if (JSON.stringify(Object.fromEntries(keys.map((key) => [key, value[key]]))) !== text) return null;
  return value;
}

/**
 * P2d: a phase-2 `gray-relay-image` payload (docs/design/relay-no-always-on-host.md §3.5), or null. Pre-launch writes it with
 * `jq -cSj` from the boot box's designation: `{image, image_sig, issued_ms, previous, relay_id, seq}` (strings, two safe
 * integers, `previous` a string or null), or for the empty slot `{image: null, relay_id, seq: 0}`. As `stackPayload`, only
 * the form JSON.stringify writes for the parsed object with sorted keys is read.
 */
function stackImagePayloadV2(hex) {
  if (typeof hex !== "string" || !/^([0-9a-f]{2})*$/.test(hex)) return null;
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.from(hex, "hex"));
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const keys = Object.keys(value).sort();
  if (JSON.stringify(Object.fromEntries(keys.map((key) => [key, value[key]]))) !== text) return null;
  const relayId = value.relay_id;
  if (typeof relayId !== "string" || !RELAY_ID.test(relayId)) return null;
  if (keys.join(",") === "image,relay_id,seq") {
    return value.image === null && value.seq === 0 ? { relayId, image: null, seq: 0 } : null;
  }
  if (keys.join(",") !== "image,image_sig,issued_ms,previous,relay_id,seq") return null;
  const { image, image_sig: imageSig, issued_ms: issuedMs, previous, seq } = value;
  const isImage = (text) => typeof text === "string" && text.length <= 512 && RELAY_IMAGE.test(text);
  if (!isImage(image) || !(previous === null || isImage(previous)) || typeof imageSig !== "string" || !/^[0-9a-f]{128}$/.test(imageSig)) return null;
  if (!Number.isSafeInteger(seq) || seq < 1 || !Number.isSafeInteger(issuedMs) || issuedMs < 0) return null;
  return { relayId, image, imageSig, issuedMs, previous, seq };
}

/** P2d: the designation's signed bytes, `gray-relay-designation/v1\n` ‖ JCS (sorted keys; checked strings, safe integers, null). */
function designationMessage(claim) {
  const jcs = JSON.stringify({ image: claim.image, issued_ms: claim.issuedMs, previous: claim.previous, relay_id: claim.relayId, seq: claim.seq });
  return Buffer.from(`${DESIGNATION_DOMAIN}\n${jcs}`, "utf8");
}

/** An https origin written as its own origin (@gray/lane-verify `isStackTokenUrl`). */
function isTokenUrl(text) {
  if (!URL.canParse(text)) return false;
  const url = new URL(text);
  return url.protocol === "https:" && url.origin === text;
}

/**
 * S52: the identity and the relay image this boot measured, from the guest agent's v0 Info answer (its
 * `tcb_info` is JSON text whose `event_log` holds the RTMR3 events). After the one runtime `system-ready`
 * there must be exactly `gray-stack-identity`, `gray-relay-image`, `gray-prelaunch-sealed`, each payload in
 * its S52 form, the two relay ids equal, and `image_sig` the identity key's Ed25519 signature over
 * `gray-relay-image/v1\n<nonce>\n<image>`. The guest agent is this CVM's own, so its log is read as it
 * is; a party that relies on the image checks the quote (gray-lane-verify, gray-relay's intake). Every
 * refusal names the rule, never a value from the log.
 *
 * P2d: a phase-2 app (`phase2`, its measured compose names LANE_KMS_URL) has the v2 image event instead, and only it:
 * the designation and its signature (`image_sig` over `gray-relay-designation/v1\n` ‖ the designation's JCS, with the
 * identity's key), or the empty slot (`image: null`, `seq: 0`), which answers `image: null`. A v1 event in a phase-2 app,
 * or a v2 event in a phase-1 app, is refused: pre-launch picks the path by the same compose literal.
 */
function stackBoot(info, phase2 = false) {
  const tcbText = info !== null && typeof info === "object" ? info.tcb_info : undefined;
  if (typeof tcbText !== "string" || tcbText === "") fail("the guest agent's Info answer carries no tcb_info: a relay-stack boot reads its relay image from the event log (S52)");
  let tcb;
  try {
    tcb = JSON.parse(tcbText);
  } catch {
    fail("the guest agent's tcb_info is not JSON");
  }
  let events = tcb !== null && typeof tcb === "object" ? tcb.event_log : undefined;
  if (typeof events === "string") {
    try {
      events = JSON.parse(events);
    } catch {
      fail("the guest agent's event log is not JSON");
    }
  }
  if (!Array.isArray(events) || !events.every((event) => event !== null && typeof event === "object" && !Array.isArray(event))) fail("the guest agent's event log is not an array of events");
  const runtime = (event) => event.imr === 3 && event.event_type === RUNTIME_EVENT_TYPE;
  const ready = events.filter((event) => runtime(event) && event.event === "system-ready");
  if (ready.length !== 1) fail("the event log has no single system-ready event");
  const after = events.slice(events.indexOf(ready[0]) + 1);
  if (after.length !== STACK_BOOT_EVENTS.length || !after.every((event, index) => runtime(event) && event.event === STACK_BOOT_EVENTS[index])) {
    fail(`the runtime events after system-ready are not ${STACK_BOOT_EVENTS.join(", ")}: pre-launch did not measure this boot's relay identity and image (S52)`);
  }
  // docs/design/relay-outbound-only.md §3.9: this image's pre-launch measures no TLS name (stack release B). An identity
  // with `tls_domain` comes from an earlier release's pre-launch, which never runs beside this image: refused.
  const identity = stackPayload(after[0].event_payload, ["public_key", "relay_id", "token_url"]);
  if (identity === null || !RELAY_ID.test(identity.relay_id) || !/^[0-9a-f]{64}$/.test(identity.public_key) || !isTokenUrl(identity.token_url)) {
    fail("the gray-stack-identity payload is not {public_key, relay_id, token_url} in their forms (S52, relay-outbound-only §3.9)");
  }
  const sealed = after[2].event_payload;
  if (typeof sealed !== "string" || sealed !== Buffer.from(SEALED_PAYLOAD, "utf8").toString("hex")) fail(`the gray-prelaunch-sealed payload is not ${SEALED_PAYLOAD}`);
  // Node's own Ed25519 (the raw key as a JWK): nothing here builds a DER key by hand.
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(identity.public_key, "hex").toString("base64url") }, format: "jwk" });
  if (phase2) {
    const claim = stackImagePayloadV2(after[1].event_payload);
    if (claim === null) {
      fail("the gray-relay-image payload is not v2's {image, image_sig, issued_ms, previous, relay_id, seq} or the empty slot's {image: null, relay_id, seq: 0} in their forms (P2d)");
    }
    if (claim.relayId !== identity.relay_id) fail("the gray-relay-image event names another relay than gray-stack-identity (S52)");
    if (claim.image !== null && !verifySignature(null, designationMessage(claim), key, Buffer.from(claim.imageSig, "hex"))) {
      fail("the gray-relay-image designation's signature does not verify with the gray-stack-identity key (P2d)");
    }
    return { relayId: identity.relay_id, image: claim.image, publicKey: identity.public_key, seq: claim.seq };
  }
  const image = stackPayload(after[1].event_payload, ["image", "image_sig", "nonce", "relay_id"]);
  if (image === null || image.image.length > 512 || !RELAY_IMAGE.test(image.image) || !/^[0-9a-f]{128}$/.test(image.image_sig)
    || !/^([0-9a-f]{2}){16,64}$/.test(image.nonce) || !RELAY_ID.test(image.relay_id)) {
    fail("the gray-relay-image payload is not {image, image_sig, nonce, relay_id} in their forms (S52)");
  }
  if (image.relay_id !== identity.relay_id) fail("the gray-relay-image event names another relay than gray-stack-identity (S52)");
  const message = Buffer.from(`gray-relay-image/v1\n${image.nonce}\n${image.image}`, "utf8");
  if (!verifySignature(null, message, key, Buffer.from(image.image_sig, "hex"))) {
    fail("the gray-relay-image signature does not verify with the gray-stack-identity key (S52)");
  }
  return { relayId: identity.relay_id, image: image.image, publicKey: identity.public_key };
}

/** The external service's address and certificate host from the bridge URL (https, no path). */
function bridgeOf(urlText) {
  let url;
  try {
    url = new URL(urlText);
  } catch {
    fail("LANE_BRIDGE_URL is not a URL");
  }
  if (url.protocol !== "https:") fail("LANE_BRIDGE_URL must be https");
  if (url.username !== "" || url.password !== "" || url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    fail("LANE_BRIDGE_URL must be an https origin with no user, path, query or fragment");
  }
  if (url.hostname === "") fail("LANE_BRIDGE_URL names no host");
  const certificateHost = url.hostname.replace(/^\[|\]$/g, "");
  const port = url.port === "" ? "443" : url.port;
  const address = url.hostname.startsWith("[") ? `${url.hostname}:${port}` : `${url.hostname}:${port}`;
  return { address, certificateHost };
}

/**
 * S2/S3: one IPv4 address (Node's `isIPv4`) and a port, never a wildcard: `*` or 0.0.0.0 would also
 * listen on lane's other networks.
 */
function ipv4Port(name, value) {
  const at = value.lastIndexOf(":");
  const host = value.slice(0, at);
  const port = value.slice(at + 1);
  if (at < 0 || !isIPv4(host) || host === "0.0.0.0" || !/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) {
    fail(`${name} is an IPv4 address and port, not a wildcard`);
  }
  return value;
}

/**
 * The relay-stack layout (docs/confidential-lane-supply-implementation.md S2, S23, S28), or null for the
 * default layout. compose.stack.yaml sets three literals on lane: the relay id (x-gray-relay's), the
 * address the relay config is served on (lane's relay_in address, 8081) and the relay container's
 * address (relay_in, 3000). All three or none: one without the others would leave the relay without
 * its config or the entry without its relay. It also sets the stack's tunable LANE_STACK_POLL_MS
 * (@gray/config), passed to workerd as it is, like the gateway vars below: an empty binding is unset,
 * and the gateway's config refuses a value outside the row's bounds at boot.
 */
function stackLayout(env) {
  const set = STACK_NAMES.filter((name) => env[name] !== undefined && env[name] !== "");
  const pollMs = env.LANE_STACK_POLL_MS ?? "";
  if (set.length === 0) {
    if (pollMs !== "") fail("LANE_STACK_POLL_MS is set without the relay-stack layout's LANE_STACK_RELAY_ID, LANE_STACK_CONFIG_LISTEN and LANE_STACK_RELAY_ADDRESS");
    return null;
  }
  if (set.length !== STACK_NAMES.length) fail(`the relay-stack layout sets ${STACK_NAMES.join(", ")} together; this boot has only ${set.join(", ")}`);
  if (!RELAY_ID.test(env.LANE_STACK_RELAY_ID)) fail("LANE_STACK_RELAY_ID is 1-128 characters of A-Z a-z 0-9 _ . : -");
  if (!/^([1-9][0-9]*)?$/.test(pollMs)) fail("LANE_STACK_POLL_MS is a whole number of milliseconds");
  return {
    relayId: env.LANE_STACK_RELAY_ID,
    pollMs,
    configListen: ipv4Port("LANE_STACK_CONFIG_LISTEN", env.LANE_STACK_CONFIG_LISTEN),
    relayAddress: ipv4Port("LANE_STACK_RELAY_ADDRESS", env.LANE_STACK_RELAY_ADDRESS),
  };
}

/**
 * The three template fragments of the stack layout; all empty in the default layout, so its rendered
 * config is byte for byte the template's own text with the other values in place. Exported for the
 * host e2e's own renderers (deploy/tee/e2e/lane-e2e.mjs, and the relay-stack harness
 * deploy/tee/e2e/stack-e2e.mjs, which renders the stack layout with a plain-HTTP fake bridge), so no
 * renderer can drift from these fragments.
 */
export function stackFragments(stack) {
  if (stack === null) return { STACK_SERVICES: "", STACK_BINDINGS: "", STACK_SOCKETS: "" };
  // The fragments carry their own comments, so the template's text (and the default layout's rendered
  // config) has nothing of the stack layout but the three placeholders.
  const services = [
    "",
    "",
    "    # S23 (relay-stack layout): the relay's container on relay_in, plain HTTP (the network is internal",
    "    # and the container has no TLS). Bound as RELAY; the entry's stack request path calls it.",
    '    ( name = "relay",',
    "      external = (",
    `        address = "${stack.relayAddress}",`,
    "        http = ()",
    "      )",
    "    ),",
  ];
  const bindings = [
    "",
    "          # S23/S28: the relay's container, the relay this VM serves (its measured identity's relay_id, S54), and",
    "          # the stack's bridge poll interval (@gray/config LANE_STACK_POLL_MS; empty is its default).",
    '          ( name = "RELAY", service = "relay" ),',
    `          ( name = "LANE_STACK_RELAY_ID", text = "${stack.relayId}" ),`,
    `          ( name = "LANE_STACK_POLL_MS", text = "${stack.pollMs ?? ""}" ),`,
    "          # S52/S55: the image the relay chose for this boot, as pre-launch measured it (gray-relay-image).",
    `          ( name = "LANE_STACK_RELAY_IMAGE", text = "${stack.relayImage ?? ""}" ),`,
    // P2d: a phase-2 boot with no boot box to open runs the empty slot (gray-relay-image v2 with `image: null`); the
    // Worker then starts without a relay image. Rendered only then, so every other boot's config is as before.
    ...(stack.emptySlot === true
      ? ["          # P2d: no relay image this boot (gray-relay-image v2 `image: null`): the relay's slot runs gray-idle.", '          ( name = "LANE_STACK_EMPTY_SLOT", text = "1" ),']
      : []),
    "          # docs/design/relay-debug-sharing.md: the relay key the boot measured (gray-stack-identity), which gray-relay's",
    "          # debug fetch is checked against: never a key Gray's snapshot serves.",
    `          ( name = "LANE_STACK_RELAY_KEY", text = "${stack.relayKey ?? ""}" ),`,
  ];
  const sockets = [
    ",",
    "    # S28: the relay config listener, plain HTTP on lane's relay_in address only, bound to the",
    "    # `relayConfig` entrypoint (GET /v1/relay/config and .../version, 404 for every other path); the",
    "    # 443 socket's default entrypoint is not reachable from it.",
    '    ( name = "relay-config",',
    `      address = "${stack.configListen}",`,
    "      http = (),",
    '      service = ( name = "lane", entrypoint = "relayConfig" )',
    "    )",
  ];
  return { STACK_SERVICES: services.join("\n"), STACK_BINDINGS: bindings.join("\n"), STACK_SOCKETS: sockets.join("\n") };
}

/**
 * Routing PR 9's settings (docs/confidential-lane-stack-routing.md sections 4.3–4.6), or null when the compose sets
 * none: the release-list public keys (both or neither, 64 lower-case hex, two different keys: D134), LANE_PEERS
 * (`true`, `false` or unset; `true` needs both keys) and the entry's PEER_* tunables (whole milliseconds). The
 * relay-stack layout may carry the keys (its backend mode) but neither LANE_PEERS nor a PEER_* setting: a stack VM is
 * never an entry. app-compose.mjs's gate holds the measured compose to the same rules; this is the boot's own check.
 */
export function peerLayout(env, stack) {
  const flag = env.LANE_PEERS ?? "";
  if (!["", "true", "false"].includes(flag)) fail("LANE_PEERS is true or false");
  const [release, freshness] = RELEASE_KEY_NAMES.map((name) => env[name] ?? "");
  const tunables = PEER_TUNABLE_NAMES.filter((name) => (env[name] ?? "") !== "");
  if (stack !== null && flag !== "") fail("LANE_PEERS is set in the relay-stack layout: a relay stack VM is never an entry");
  if (stack !== null && tunables.length > 0) fail(`${tunables.join(", ")} ${tunables.length === 1 ? "is an entry's setting" : "are an entry's settings"}, never set in the relay-stack layout`);
  if (release !== "" || freshness !== "") {
    if (!RELEASE_KEY.test(release) || !RELEASE_KEY.test(freshness)) fail(`${RELEASE_KEY_NAMES.join(" and ")} are both set, each 64 lower-case hex (the environment's release and freshness public keys)`);
    if (release === freshness) fail("LANE_RELEASE_FRESHNESS_PUBLIC_KEY is LANE_RELEASE_PUBLIC_KEY; the freshness key is a key of its own (D134)");
  }
  if (flag === "true" && release === "") fail(`LANE_PEERS is true without ${RELEASE_KEY_NAMES.join(" and ")}: an entry verifies the stack list with them`);
  for (const name of tunables) if (!/^[1-9][0-9]*$/.test(env[name])) fail(`${name} is a whole number of milliseconds`);
  if (flag === "" && release === "" && tunables.length === 0) return null;
  return { peers: flag, releasePublicKey: release, releaseFreshnessPublicKey: freshness, tunables: Object.fromEntries(tunables.map((name) => [name, env[name]])) };
}

/**
 * The template fragment of routing PR 9's bindings: empty when the compose sets none of them (null), so a boot without
 * them renders the template's own text. Exported for the host e2e's renderers, as `stackFragments` is.
 */
export function peerFragments(peers) {
  if (peers === null) return { PEER_BINDINGS: "" };
  const lines = [
    "",
    "",
    "          # Routing PR 9: the environment's release-list public keys (an entry verifies the stack list, a stack VM",
    "          # the default list), whether this default-layout lane is an entry, and the entry's PEER_* tunables",
    "          # (@gray/config; an unset one is the row's default).",
  ];
  const text = (name, value) => `          ( name = "${name}", text = "${value}" ),`;
  if (peers.peers !== "") lines.push(text("LANE_PEERS", peers.peers));
  if (peers.releasePublicKey !== "") lines.push(text("LANE_RELEASE_PUBLIC_KEY", peers.releasePublicKey), text("LANE_RELEASE_FRESHNESS_PUBLIC_KEY", peers.releaseFreshnessPublicKey));
  for (const [name, value] of Object.entries(peers.tunables)) lines.push(text(name, value));
  return { PEER_BINDINGS: lines.join("\n") };
}

/**
 * docs/design/relay-outbound-only.md §3.2, §3.8: the lane's peerlink, or null when the compose names none. Both layouts
 * run gray-peerlink in its own container and share its unix socket with the lane (`PEERLINK_SOCKET`, an absolute path
 * on the socket's volume); the lane reaches it as the workerd `external` service `peerlink`, bound as `PEERLINK`. The
 * entry's lane serves the attach and tunnel routes through it (when LANE_PEERS is "true"); a stack VM's lane attests
 * its entries and hands peerlink their pins. `LANE_PEER_ENTRIES` (the stack layout only, and required there) is the
 * image's default entry list, comma-separated names, for a boot before the bridge's `stack.entries` (§3.2).
 */
export function peerlinkLayout(env, stack) {
  const socket = env.PEERLINK_SOCKET ?? "";
  const entries = env.LANE_PEER_ENTRIES ?? "";
  if (socket === "") {
    if (entries !== "") fail("LANE_PEER_ENTRIES is set without PEERLINK_SOCKET: a stack VM dials its entries through peerlink");
    return null;
  }
  if (!socket.startsWith("/") || !SAFE.test(socket)) fail("PEERLINK_SOCKET is an absolute path a workerd config string can carry");
  if (stack === null && entries !== "") fail("LANE_PEER_ENTRIES is set in the default layout: only a stack VM dials entries");
  if (stack !== null) {
    const names = entries.split(",");
    if (entries === "" || names.some((name) => !DNS_NAME.test(name))) fail("LANE_PEER_ENTRIES is one or more lower-case DNS names, comma-separated (the environment's entry)");
  }
  return { socket, entries };
}

/**
 * The template fragments of the lane's peerlink: empty when the compose names none (null), so such a boot renders the
 * template's own text. Exported for the host e2e's renderers, as `stackFragments` is.
 */
export function peerlinkFragments(link) {
  if (link === null) return { PEERLINK_SERVICES: "", PEERLINK_BINDINGS: "" };
  const services = [
    "",
    "",
    "    # relay-outbound-only §3.2/§3.8: gray-peerlink on its unix socket (its own container; the socket's volume is",
    "    # shared with the lane only, and on an entry with egress). Plain HTTP: every stream it carries is TLS that ends",
    "    # elsewhere.",
    '    ( name = "peerlink",',
    "      external = (",
    `        address = "unix:${link.socket}",`,
    "        http = ()",
    "      )",
    "    ),",
  ];
  const bindings = ["", "", "          # relay-outbound-only §3: the lane's peerlink.", '          ( name = "PEERLINK", service = "peerlink" ),'];
  if (link.entries !== "") {
    bindings.push("          # §3.2: the entries this stack VM dials until the bridge's stack.entries names them.", `          ( name = "LANE_PEER_ENTRIES", text = "${link.entries}" ),`);
  }
  return { PEERLINK_SERVICES: services.join("\n"), PEERLINK_BINDINGS: bindings.join("\n") };
}

/**
 * P2c-2 (docs/design/relay-no-always-on-host.md H9, 13.11): the KMS lease, or null when the measured compose names no
 * KMS to re-check. `LANE_KMS_URL` is a lane literal of the measured compose (app-compose.mjs `--kms-url`), which the
 * provisioner renders only for an app on an on-chain KMS: the relay's contract decides there whether the KMS gives
 * this app its keys, so the VM asks again every 10 minutes (kms-lease.mjs). Unset, the boot is a phase-1 one (Phala's
 * own KMS, the relay's host) and renders and runs exactly as before. Only a relay stack VM holds a relay's
 * accounts, so the default layout refuses it. The URL is checked here only for its form; `kmsAppKeyCheck` pins the
 * KMS's certificate to the measured key provider whatever the URL names.
 */
export function kmsLeaseLayout(env, stack) {
  const url = env.LANE_KMS_URL ?? "";
  if (url === "") return null;
  if (stack === null) fail("LANE_KMS_URL is set in the default layout: only a relay stack VM keeps a KMS lease");
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail("LANE_KMS_URL is not a URL");
  }
  if (parsed.protocol !== "https:" || parsed.hostname === "" || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    fail("LANE_KMS_URL is https://<host>[:port][/path] without credentials, query or fragment (the KMS of the measured key provider)");
  }
  return { kmsUrl: url };
}

/**
 * P2c-2: the template fragments of the KMS lease: a socket on the lane-only tmpfs bound to the Worker's `kmsLease`
 * entrypoint, which the supervisor pushes the lease's state to (kms-lease.mjs `startKmsLease`), and the binding that
 * tells the Worker a lease gates the relay's accounts. Each placeholder starts a line of its own in the template, so
 * both are empty for null and a phase-1 boot renders exactly the text it rendered before. Exported for the host e2e's
 * renderers, as `stackFragments` is.
 */
export function kmsLeaseFragments(lease, socketPath) {
  if (lease === null) return { KMS_LEASE_BINDINGS: "", KMS_LEASE_SOCKETS: "" };
  if (!socketPath.startsWith("/") || !SAFE.test(socketPath)) fail("the KMS lease socket is an absolute path a workerd config string can carry");
  const bindings = [
    "          # P2c-2 (docs/design/relay-no-always-on-host.md H9): the relay's accounts are served only while the KMS lease the",
    "          # supervisor keeps serves; its state arrives on the kms-lease socket below.",
    '          ( name = "LANE_KMS_LEASE", text = "required" ),',
    "",
  ];
  const sockets = [
    "    # P2c-2: the supervisor's pushes of the KMS lease's state, on the lane container's own tmpfs (nothing else mounts",
    "    # it), bound to the `kmsLease` entrypoint (PUT /v1/lane/kms-lease, 404 for every other path).",
    '  , ( name = "kms-lease",',
    `      address = "unix:${socketPath}",`,
    "      http = (),",
    '      service = ( name = "lane", entrypoint = "kmsLease" )',
    "    )",
    "",
  ];
  return { KMS_LEASE_BINDINGS: bindings.join("\n"), KMS_LEASE_SOCKETS: sockets.join("\n") };
}

/**
 * P2e: the template fragments of the relay's vault for a lease app (the vault exists exactly when the lease does): the
 * external service on the supervisor's vault-disk socket (vault-disk.mjs `startVaultDisk`) and the Worker's binding to
 * it. Both are empty for null, and each placeholder sits where the template had an empty line or a line's start, so a
 * phase-1 boot renders exactly the text it rendered before. Exported for the host e2e's renderers.
 */
export function vaultDiskFragments(lease, socketPath) {
  if (lease === null) return { VAULT_DISK_SERVICES: "", VAULT_DISK_BINDINGS: "" };
  if (!socketPath.startsWith("/") || !SAFE.test(socketPath)) fail("the vault disk socket is an absolute path a workerd config string can carry");
  const services = [
    "    # P2e (docs/design/relay-no-always-on-host.md §3.1): the relay's vault on the data disk, served by the supervisor",
    "    # (vault-disk.mjs) on the lane container's own tmpfs: GET and PUT /v1/lane/vault, plain HTTP.",
    '    ( name = "vault-disk",',
    "      external = (",
    `        address = "unix:${socketPath}",`,
    "        http = ()",
    "      )",
    "    ),",
    "",
  ];
  const bindings = [
    "          # P2e: the relay's vault disk (the supervisor's socket above); the Worker writes every version of the vault there.",
    '          ( name = "LANE_VAULT_DISK", service = "vault-disk" ),',
    "",
    "",
  ];
  return { VAULT_DISK_SERVICES: services.join("\n"), VAULT_DISK_BINDINGS: bindings.join("\n") };
}

/** Wait until the egress service has created its socket; fail closed after the deadline. */
async function waitForEgress(path, deadlineMs, now, sleep) {
  const started = now();
  for (;;) {
    try {
      if (statSync(path).isSocket()) return;
    } catch {
      // not created yet
    }
    if (now() - started >= deadlineMs) fail(`the egress socket ${path} did not appear within ${deadlineMs} ms: refusing to start with no egress path`);
    await sleep(100);
  }
}

function defaultSleep(ms) {
  return new Promise((resolveWait) => setTimeout(resolveWait, ms));
}

/**
 * D133: run gray-acme and wait for its exit status and its stderr lines. Each line goes on to this process's stderr as
 * it arrives (the container log is unchanged); the lines are what a failed run reports (`acmeReport`). A child without
 * a stderr stream (a test's fake) has no lines.
 */
function runAcme(spawnProcess, command, env, error) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawnProcess(command, [], { stdio: ["ignore", "inherit", "pipe"], env });
    const lines = [];
    let exited = null;
    let closed = child.stderr === undefined || child.stderr === null;
    const settle = () => {
      if (exited !== null && closed) resolveRun({ ...exited, lines });
    };
    if (!closed) {
      const reader = createInterface({ input: child.stderr, crlfDelay: Infinity });
      reader.on("line", (line) => {
        error(line);
        lines.push(line);
        // gray-acme prints a few dozen lines; the report keeps far fewer, so a runaway child cannot grow this.
        if (lines.length > ACME_LINES_KEPT) lines.splice(0, lines.length - ACME_LINES_KEPT);
      });
      reader.on("close", () => {
        closed = true;
        settle();
      });
    }
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      exited = { code, signal };
      settle();
    });
  });
}

/** How many of gray-acme's last stderr lines the entrypoint keeps for a report. */
const ACME_LINES_KEPT = 400;

/**
 * The bounds of `@gray/lane-wire`'s `lane.acme_failed` document (lane-acme.ts `ACME_REPORT_MAX_*`): CAs, a reason's
 * characters, detail lines per CA (the first ones: the CA's own state comes before lego's lines), other lines (the
 * last ones: the run's summary is last), one line's characters.
 */
const REPORT_MAX_CAS = 4;
const REPORT_MAX_REASON = 2048;
const REPORT_MAX_LINES = 16;
const REPORT_MAX_LINE = 512;
const REPORT_CA_HOST = /^[A-Za-z0-9.:[\]-]{1,261}$/;
const REPORT_DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const BRIDGE_KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;

/** One line as the wire takes it: no control character, at most `max` UTF-16 units, no half of a surrogate pair. */
function reportLine(text, max) {
  let line = text.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  if (line.length > max) {
    line = line.slice(0, max);
    if (/[\ud800-\udbff]$/.test(line)) line = line.slice(0, -1);
  }
  return line;
}

/**
 * The `lane.acme_failed` document of one failed gray-acme run: who and when, how it ended, and its stderr lines, each
 * `secrets` value replaced first (the EAB values and the bridge seed; gray-acme never prints them, and this makes sure).
 * `gray-acme: ca=<host> failed: <reason>` starts a CA, `gray-acme: ca=<host> detail: <line>` adds to it, and every
 * other line is `other`. Exported for the tests.
 */
export function acmeReport({ appId, domain, composeHash, attemptMs, exitCode, signal, lines, secrets }) {
  const hidden = secrets.filter((secret) => typeof secret === "string" && secret.length >= 4);
  const cas = [];
  const other = [];
  for (const raw of lines) {
    let text = raw;
    for (const secret of hidden) text = text.split(secret).join("[redacted]");
    const match = /^gray-acme: ca=(\S+) (failed|detail): (.*)$/.exec(text);
    const ca = match === null || !REPORT_CA_HOST.test(match[1]) ? null : match[1];
    if (ca !== null && match[2] === "failed") {
      if (cas.length < REPORT_MAX_CAS) cas.push({ ca, reason: reportLine(match[3], REPORT_MAX_REASON) || "(no reason)", details: [] });
      continue;
    }
    const entry = ca === null ? undefined : cas.findLast((each) => each.ca === ca);
    if (entry !== undefined) {
      const line = reportLine(match[3], REPORT_MAX_LINE);
      if (line !== "" && entry.details.length < REPORT_MAX_LINES) entry.details.push(line);
      continue;
    }
    const line = reportLine(text, REPORT_MAX_LINE);
    if (line !== "") other.push(line);
  }
  return {
    app_id: appId,
    domain: REPORT_DOMAIN.test(domain) && domain.length <= 253 ? domain : "",
    compose_hash: typeof composeHash === "string" && /^[0-9a-f]{64}$/.test(composeHash) ? composeHash : null,
    attempt_ms: attemptMs,
    exit_code: exitCode,
    signal: typeof signal === "string" && /^SIG[A-Z0-9]{1,12}$/.test(signal) ? signal : null,
    cas,
    other: other.slice(-REPORT_MAX_LINES),
  };
}

/** RFC 8410's PKCS#8 wrapping of a 32-byte Ed25519 seed (`@gray/attest` `ed25519Pkcs8`), the form Node imports it in. */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * A relay-stack VM's bridge key id: `app-<app id>-<the first 16 hex digits of the bridge key's Ed25519 public key>`
 * (`@gray/control/stack-provision` `stackBridgeKeyId`, which the provisioner installs the key under before the VM
 * exists). Without a seed (a `local` host test), `app-<app id>`.
 */
export function stackBridgeKeyId(appId, seed) {
  if (seed === "") return `app-${appId}`;
  const privateKey = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  return `app-${appId}-${publicKey.toString("hex").slice(0, 16)}`;
}

/**
 * The headers of one signed bridge call (`@gray/lane-wire` signing.ts): the canonical string `gray-lane-bridge-v1`, op,
 * target, method, path, timestamp, nonce and the body's SHA-256, one per line, signed with the bridge key's seed.
 */
function bridgeHeaders({ op, target, path, body, keyId, seed, timestampMs, nonce }) {
  const bodySha256 = createHash("sha256").update(body).digest("hex");
  const message = ["gray-lane-bridge-v1", op, target, "POST", path, String(timestampMs), nonce, bodySha256].join("\n");
  const key = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
  return {
    "content-type": "application/json",
    "x-gray-api-version": "2",
    "x-gray-key-id": keyId,
    "x-gray-timestamp": String(timestampMs),
    "x-gray-nonce": nonce,
    "x-gray-signature": signMessage(null, Buffer.from(message, "utf8"), key).toString("hex"),
  };
}

/** How long a report may take: it delays the hold's start, never the hold's end (the hold is dated from the order). */
const REPORT_TIMEOUT_MS = 15_000;

/** The default `postBridge`: one https POST, its status and the first KiB of its answer. */
function postBridgeHttps(url, headers, body) {
  return new Promise((resolvePost, rejectPost) => {
    const request = httpsRequest(url, { method: "POST", headers: { ...headers, "content-length": String(body.byteLength) }, timeout: REPORT_TIMEOUT_MS }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        if (size < 1024) chunks.push(chunk);
        size += chunk.length;
      });
      response.on("end", () => resolvePost({ status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8").slice(0, 1024) }));
      response.on("error", rejectPost);
    });
    request.on("timeout", () => request.destroy(new Error(`no answer within ${REPORT_TIMEOUT_MS} ms`)));
    request.on("error", rejectPost);
    request.end(body);
  });
}

/**
 * Send one failed run's report and say what came of it in one line. A lane without a bridge seed (`local`) or with a
 * key id the wire cannot carry sends none. Never throws: the boot fails the same way whatever the bridge answers.
 */
async function reportAcmeFailure({ bridgeUrl, keyId, seed, document, postBridge, wallNow, log, error }) {
  if (seed === "") {
    log("lane: no bridge seed: the failed certificate order is not reported to the bridge");
    return;
  }
  if (!BRIDGE_KEY_ID.test(keyId)) {
    error("lane: LANE_KEY_ID is not a bridge key id: the failed certificate order is not reported to the bridge");
    return;
  }
  const op = "lane.acme_failed";
  const path = "/v1/lane-bridge/lane/acme-failed";
  const body = Buffer.from(JSON.stringify(document), "utf8");
  try {
    const headers = bridgeHeaders({ op, target: `lane/${document.app_id}`, path, body, keyId, seed, timestampMs: wallNow(), nonce: randomBytes(16).toString("hex") });
    const answer = await postBridge(new URL(path, bridgeUrl).toString(), headers, body);
    if (answer.status === 200) log(`lane: reported the failed certificate order to the bridge (${document.cas.length} CA reason(s))`);
    else error(`lane: the bridge refused the failed certificate order's report: ${answer.status} ${reportLine(answer.text, 300)}`);
  } catch (thrown) {
    error(`lane: could not report the failed certificate order to the bridge: ${thrown instanceof Error ? thrown.message : String(thrown)}`);
  }
}

/**
 * D133: gray-acme's environment: its own settings and lego's (`TLS_DOMAIN`, `ACME_*`, `LEGO_*`, and Go's
 * root-store overrides), never the rest of the lane's (the bridge seed is not its business). The
 * challenge listener is the lane's own LISTEN_ADDRESS, whatever the environment says.
 */
function acmeEnvironment(env, listenAddress) {
  const out = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    if (name === "TLS_DOMAIN" || name === "SSL_CERT_FILE" || name === "SSL_CERT_DIR" || name.startsWith("ACME_") || name.startsWith("LEGO_")) {
      out[name] = value;
    }
  }
  out.ACME_TLS_ALPN_ADDRESS = listenAddress;
  return out;
}

/** The first exit or spawn error of a child, as `{ code, signal }` (an error is `{ code: null, signal: null, error }`). */
function exitOf(child) {
  return new Promise((resolveExit) => {
    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      resolveExit(result);
    };
    child.on("exit", (code, signal) => settle({ code, signal }));
    child.on("error", (thrown) => settle({ code: null, signal: null, error: thrown }));
  });
}

/**
 * D133: run workerd until a requested stop, restarting it in this container when it exits on its own.
 * The key and certificate stay on this container's /run/lane tmpfs and the rendered config names them,
 * so a restart serves the same attested keyset's certificate and orders nothing; only a container start
 * orders a certificate. The delay before each restart is Docker's restart backoff
 * (RESTART_BACKOFF_*). It gives up, and resolves 1 so the container exits, when workerd has exited
 * GIVE_UP_EXITS times within the last GIVE_UP_WINDOW_MS and that window has passed since this boot's
 * order (`orderedAt`); a broken workerd is therefore never kept "up" by this loop, and the next start's
 * order comes at most every GIVE_UP_WINDOW_MS. A requested stop (`stopped()` true when the child exits)
 * resolves 0. `restart()` spawns workerd again and returns the child; `first` is the one `main` started.
 */
export async function superviseWorkerd({ first, restart, orderedAt, stopped, now = Date.now, sleep = defaultSleep, error = console.error }) {
  const exits = [];
  let child = first;
  let started = now();
  let backoff = 0;
  for (;;) {
    const { code, signal, error: thrown } = await exitOf(child);
    if (stopped()) return 0;
    const at = now();
    const ran = at - started;
    exits.push(at);
    while (exits.length > 0 && exits[0] <= at - GIVE_UP_WINDOW_MS) exits.shift();
    const how = thrown !== undefined ? `could not run (${thrown instanceof Error ? thrown.message : String(thrown)})` : `exited ${signal ?? code}`;
    if (exits.length >= GIVE_UP_EXITS && at - orderedAt >= GIVE_UP_WINDOW_MS) {
      error(`lane: workerd ${how} after ${ran} ms, ${exits.length} exits within ${GIVE_UP_WINDOW_MS / 60_000} minutes: giving up; the container's next start orders a new certificate (D133)`);
      return 1;
    }
    // moby's restartmanager: a run of 10 s or more resets the backoff; otherwise it doubles, capped.
    if (ran >= RESTART_BACKOFF_RESET_MS) backoff = 0;
    backoff = backoff === 0 ? RESTART_BACKOFF_FIRST_MS : Math.min(backoff * 2, RESTART_BACKOFF_MAX_MS);
    error(`lane: workerd ${how} after ${ran} ms (${exits.length} exits within ${GIVE_UP_WINDOW_MS / 60_000} minutes); restarting it in ${backoff} ms with this boot's certificate (D133)`);
    await sleep(backoff);
    if (stopped()) return 0;
    child = restart();
    started = now();
  }
}

/**
 * Render workerd's boot config and start workerd. Exported so the deploy-tee tests run the real
 * entrypoint in-process (D95): the CLI wrapper below supplies the process defaults and owns the
 * process lifetime, while `now`, `sleep`, `spawnAcme` and `spawnWorker` are injection seams for
 * deterministic tests. Resolves with the started workerd child, the function that starts it again,
 * and when this boot's certificate order began (D133: what `superviseWorkerd` needs).
 */
export async function main({
  env = process.env,
  log = console.log,
  error = console.error,
  now = Date.now,
  sleep = defaultSleep,
  spawnAcme = spawn,
  spawnWorker = spawn,
  postBridge = postBridgeHttps,
  wallNow = Date.now,
  uptime = osUptime,
  startLease = startKmsLease,
  startDisk = startVaultDisk,
  vaultDir = VAULT_DIR,
} = {}) {
  const templatePath = env.LANE_TEMPLATE ?? "/srv/lane/config.capnp";
  // D63: the rendered config carries the bridge seed, so it lives on the lane-only /run/lane tmpfs,
  // never on the /run/gray volume the egress sidecar also mounts.
  const renderedPath = env.LANE_RENDERED ?? "/run/lane/config.capnp";
  const buildEnvPath = env.LANE_BUILD_ENV ?? "/etc/lane/build.env";
  const workerd = env.LANE_WORKERD ?? "workerd";

  const build = buildEnv(buildEnvPath);
  const deployEnv = fromEnvironment(env, "DEPLOY_ENV");
  if (!["local", "testnet", "production"].includes(deployEnv)) fail("DEPLOY_ENV is local, testnet or production");
  // D133: gray-acme writes this boot's pair to ACME_KEY_DIR (the measured compose fixes it at
  // /run/lane/tls). LANE_TLS_CERT, LANE_TLS_KEY and LANE_ACME are host-test seams only: the compose
  // gate refuses all three in the measured compose (app-compose.mjs FORBIDDEN_ENV_NAMES).
  const keyDir = fromEnvironment(env, "ACME_KEY_DIR", "/run/lane/tls");
  const certificate = fromEnvironment(env, "LANE_TLS_CERT", join(keyDir, "fullchain.pem"));
  const privateKey = fromEnvironment(env, "LANE_TLS_KEY", join(keyDir, "privkey.pem"));
  const acme = fromEnvironment(env, "LANE_ACME", "/usr/local/bin/gray-acme");

  const bridgeUrl = fromEnvironment(env, "LANE_BRIDGE_URL");
  const bridge = bridgeOf(bridgeUrl);
  const seed = fromEnvironment(env, "LANE_BRIDGE_KEY_SEED", "");
  if (seed === "") {
    // D5/D17: a deployed lane has no anonymous bridge mode; `local` may omit the seed for a host test
    // that builds its own config, but this image always gets one from the encrypted env.
    if (deployEnv !== "local") fail("LANE_BRIDGE_KEY_SEED is not set: a deployed lane needs the provisioned bridge key");
  } else if (!SEED.test(seed)) {
    fail("LANE_BRIDGE_KEY_SEED is 32 bytes as 64 lower-case hex");
  }

  const keysetNotAfter = fromEnvironment(env, "KEYSET_NOT_AFTER");
  if (!/^(0|[1-9][0-9]*)$/.test(keysetNotAfter)) fail("KEYSET_NOT_AFTER is a u64 of Unix seconds");

  const egressSocket = fromEnvironment(env, "EGRESS_SOCKET", "/run/gray/egress.sock");
  if (!egressSocket.startsWith("/")) fail("EGRESS_SOCKET is an absolute path");
  const stack = stackLayout(env);
  const peers = peerLayout(env, stack);
  const peerlink = peerlinkLayout(env, stack);
  const kmsLease = kmsLeaseLayout(env, stack);
  // P2c-2: the lease's tunables are read before anything runs, so a bad value stops the boot here (kmsLeaseSettings).
  let kmsLeaseTuning = null;
  if (kmsLease !== null) {
    try {
      kmsLeaseTuning = kmsLeaseSettings(env);
    } catch (thrown) {
      fail(thrown instanceof Error ? thrown.message : String(thrown));
    }
  }

  // D47: the app id is read from the guest agent at boot, before anything is rendered. There is no
  // default and no environment override: a boot that cannot read it must not serve a keyset whose
  // subject Gray's release tooling cannot tie to the quote.
  const guestSocket = fromEnvironment(env, "GUEST_AGENT_SOCKET", "/var/run/dstack.sock");
  if (!guestSocket.startsWith("/")) fail("GUEST_AGENT_SOCKET is an absolute path");
  const guestTimeout = Number(fromEnvironment(env, "GUEST_AGENT_TIMEOUT_MS", "5000"));
  if (!Number.isInteger(guestTimeout) || guestTimeout <= 0) fail("GUEST_AGENT_TIMEOUT_MS is a positive integer");
  let appId;
  let info;
  try {
    ({ appId, info } = await guestInfo(guestSocket, guestTimeout));
  } catch (thrown) {
    fail(`cannot read the app id from the guest agent at unix:${guestSocket} (POST /v1/Info): ${thrown instanceof Error ? thrown.message : String(thrown)}`);
  }
  // S52/S54: a stack boot serves the relay its identity event names and tells the entry the image the relay chose.
  // The compose's relay id is the measured one (S54 interpolates it from the encrypted env pre-launch measured); one
  // that differs from the event stops the boot. relay-outbound-only §3.9: the VM has no public name, so the stack
  // compose sets no TLS_DOMAIN and the keyset's TLS key is bound to no domain (the entry's channel and gray-relay's
  // tunnel accept only such a key); a TLS_DOMAIN here stops the boot.
  if (stack !== null) {
    let v0Info;
    try {
      ({ info: v0Info } = await guestInfo(guestSocket, guestTimeout, "/Info"));
    } catch (thrown) {
      fail(`cannot read this boot's event log from the guest agent at unix:${guestSocket} (POST /Info): ${thrown instanceof Error ? thrown.message : String(thrown)}`);
    }
    const boot = stackBoot(v0Info, kmsLease !== null);
    if ((env.TLS_DOMAIN ?? "") !== "") fail("TLS_DOMAIN is set in the relay-stack layout: a stack VM has no public name, and its TLS key is bound to no domain (relay-outbound-only §3.9)");
    if (stack.relayId !== boot.relayId) fail("LANE_STACK_RELAY_ID is not the gray-stack-identity event's relay_id (S54)");
    stack.relayImage = boot.image;
    stack.relayKey = boot.publicKey;
    stack.emptySlot = boot.image === null;
  }
  // P2c-2: the re-check's inputs are the guest agent's own (vm_config and the measured key provider's CA, from the same
  // v1 Info answer as the app id): a lease app that cannot read them does not serve.
  let kmsLeaseInputs = null;
  if (kmsLease !== null) {
    try {
      kmsLeaseInputs = kmsLeaseInputsFromInfo(info);
    } catch (thrown) {
      fail(`cannot read the KMS lease's inputs from the guest agent's Info: ${thrown instanceof Error ? thrown.message : String(thrown)}`);
    }
  }

  // D133: everything rendered but the certificate's SPKI is read and checked before gray-acme runs, so
  // a boot that would refuse its configuration does not spend a certificate order on it.
  // D19: TLS_SPKI_SHA256 is computed from this boot's certificate below and is never read from the
  // environment. A host that sets it (or a test) changes nothing; the compose allowlist does not even
  // include the name.
  const listenAddress = fromEnvironment(env, "LISTEN_ADDRESS", "*:443");
  const values = {
    DEPLOY_ENV: deployEnv,
    TEE_TYPE: fromEnvironment(env, "TEE_TYPE", "tdx"),
    KEYSET_SUBJECT: `dstack:app-id:${appId}`,
    KEYSET_NOT_AFTER: keysetNotAfter,
    TLS_DOMAIN: fromEnvironment(env, "TLS_DOMAIN", ""),
    GUEST_AGENT_URL: fromEnvironment(env, "GUEST_AGENT_URL", "http://guest-agent"),
    GUEST_AGENT_TIMEOUT_MS: fromEnvironment(env, "GUEST_AGENT_TIMEOUT_MS", "5000"),
    LANE_BRIDGE_URL: bridgeUrl,
    LANE_BRIDGE_ADDRESS: bridge.address,
    LANE_BRIDGE_HOST: bridge.certificateHost,
    LANE_BRIDGE_EXTRA_TRUST: "",
    // S54: a stack compose without the literal gets this VM's own bridge key id: the app's, as KEYSET_SUBJECT above, and
    // its bridge key's (docs/design/relay-zero-downtime.md: one key id per instance of the app).
    LANE_KEY_ID: stack !== null && (env.LANE_KEY_ID ?? "") === "" ? stackBridgeKeyId(appId, seed) : fromEnvironment(env, "LANE_KEY_ID"),
    // D56/D11: no default and no compose literal; an empty text binding is absent to the gateway,
    // which then generates a random receipt key id per boot.
    LANE_RECEIPT_KEY_ID: env.LANE_RECEIPT_KEY_ID ?? "",
    LANE_BRIDGE_KEY_SEED: seed,
    GATEWAY_FALLBACK_REGION: fromEnvironment(env, "GATEWAY_FALLBACK_REGION", "wnam"),
    BODY_PARSE_MAX_BYTES: fromEnvironment(env, "BODY_PARSE_MAX_BYTES", "4194304"),
    LANE_POLICY_STEP_MS: fromEnvironment(env, "LANE_POLICY_STEP_MS", "1500"),
    // D128: the compose literals (D128': the build box's measurement). No default here: an empty
    // binding is unset to `@gray/config`, which then takes each row's own default and refuses a value
    // outside its bounds at boot.
    LANE_POLICY_FUEL_PER_MS: env.LANE_POLICY_FUEL_PER_MS ?? "",
    LANE_POLICY_OVERHEAD_MS: env.LANE_POLICY_OVERHEAD_MS ?? "",
    // D109': the compose literal (app-compose.mjs --scheduler-pick-ms). No default here: an empty
    // binding is unset to `@gray/config`, which then takes LANE_SCHEDULER_PICK_MS's own default and
    // refuses a value outside its bounds at boot.
    LANE_SCHEDULER_PICK_MS: env.LANE_SCHEDULER_PICK_MS ?? "",
    // `embed` resolves relative to the config file being parsed, which is the rendered one. The paths
    // are therefore computed from here to the bundle and the certificate, wherever they are.
    WORKER_MODULE_PATH: relative(dirname(renderedPath), resolve(dirname(templatePath), "worker", "worker.mjs")),
    ENTRY_MODULE_PATH: relative(dirname(renderedPath), resolve(dirname(templatePath), "worker", "entry.js")),
    TLS_CERT_PATH: relative(dirname(renderedPath), resolve(certificate)),
    TLS_KEY_PATH: relative(dirname(renderedPath), resolve(privateKey)),
    GUEST_AGENT_SOCKET: guestSocket,
    EGRESS_SOCKET: egressSocket,
    LISTEN_ADDRESS: listenAddress,
    SOURCE_REPO_URL: build.SOURCE_REPO_URL ?? "",
    SOURCE_REPO_COMMIT: build.SOURCE_REPO_COMMIT ?? "",
    SOURCE_IMAGE_DIGEST: build.SOURCE_IMAGE_DIGEST ?? "",
  };
  for (const [name, value] of Object.entries(values)) {
    if (!SAFE.test(value)) fail(`${name} holds characters a workerd config string cannot carry`);
  }

  // wrangler emits each CompiledWasm import as its own file; workerd needs one module entry per file,
  // with the module name the bundle imports. Their names are content hashes, so scan the directory
  // instead of listing them in the template.
  const workerDir = resolve(dirname(templatePath), "worker");
  const wasmNames = readdirSync(workerDir).filter((name) => name.endsWith(".wasm")).sort();
  if (wasmNames.length === 0) fail("the Worker bundle carries no compiled wasm modules: the relay-policy interpreter is required");
  const wasmModules = wasmNames
    .map((name) => `,\n          ( name = "${name}", wasm = embed "${relative(dirname(renderedPath), resolve(workerDir, name))}" )`)
    .join("");

  // P2c-2: the socket the supervisor pushes the lease's state to, beside the rendered config on the lane-only tmpfs.
  const kmsLeaseSocket = join(dirname(renderedPath), "kms-lease.sock");
  // P2e: the vault disk's socket, beside it.
  const vaultDiskSocket = join(dirname(renderedPath), "vault-disk.sock");
  const template = readFileSync(templatePath, "utf8");
  const renderable = {
    ...values,
    TLS_SPKI_SHA256: "",
    WASM_MODULES: wasmModules,
    ...stackFragments(stack),
    ...peerFragments(peers),
    ...peerlinkFragments(peerlink),
    ...kmsLeaseFragments(kmsLease, kmsLeaseSocket),
    ...vaultDiskFragments(kmsLease, vaultDiskSocket),
  };
  // D57: one pass over the template. A value that itself contains `__NAME__` is data and is never
  // substituted again; the placeholders are checked against the template, before rendering.
  for (const match of template.matchAll(/__([A-Z0-9_]+)__/g)) {
    if (!(match[1] in renderable)) fail(`the config template still holds ${match[0]}: the entrypoint and the template disagree`);
  }

  await waitForEgress(egressSocket, Number(fromEnvironment(env, "EGRESS_WAIT_MS", "30000")), now, sleep);

  // D133: a new key and certificate for this boot, issued in this container. gray-acme prints its own
  // lines (the issuing CA, the account URI, the certificate SHA-256) and never key material.
  const orderedAt = now();
  const attemptMs = wallNow();
  let issued;
  try {
    issued = await runAcme(spawnAcme, acme, acmeEnvironment(env, listenAddress), error);
  } catch (thrown) {
    fail(`cannot run ${acme}: ${thrown instanceof Error ? thrown.message : String(thrown)}`);
  }
  if (issued.code !== 0) {
    // The reason exists only in this container's log, which nobody outside the CVM can read: report it first.
    const document = acmeReport({
      appId,
      domain: values.TLS_DOMAIN,
      composeHash: info !== null && typeof info === "object" ? info.compose_hash : null,
      attemptMs,
      exitCode: issued.code,
      signal: issued.signal,
      lines: issued.lines,
      secrets: [seed, env.ACME_EAB_KID ?? "", env.ACME_EAB_HMAC_KEY ?? ""],
    });
    await reportAcmeFailure({ bridgeUrl, keyId: values.LANE_KEY_ID, seed, document, postBridge, wallNow, log, error });
    // Exit 2 is a refused configuration: no CA was contacted. Anything else may have spent an order, so
    // the next container start (and its order) waits for the hold (ISSUE_FAILURE_HOLD_MS).
    if (issued.code !== 2) {
      const left = orderedAt + ISSUE_FAILURE_HOLD_MS - now();
      if (left > 0) {
        error(`lane: ${acme} exited ${issued.signal ?? issued.code}; holding ${Math.ceil(left / 1000)} s before the container exits, so its next start's certificate order stays within the CAs' limits (D133)`);
        await sleep(left);
      }
    }
    fail(`${acme} exited ${issued.signal ?? issued.code}: the lane does not start without a certificate issued for this boot (D133)`);
  }
  if (!existsSync(certificate)) {
    fail(`LANE_TLS_CERT names ${certificate}, which does not exist: gray-acme must write this boot's certificate before the lane starts (D133)`);
  }
  if (!existsSync(privateKey)) {
    fail(`LANE_TLS_KEY names ${privateKey}, which does not exist: gray-acme must generate this boot's key inside the CVM (D133)`);
  }
  const leaf = new X509Certificate(readFileSync(certificate, "utf8"));
  if (Date.parse(leaf.validTo) < now()) error(`lane: warning: the certificate expired at ${leaf.validTo}`);

  values.TLS_SPKI_SHA256 = spkiSha256(certificate);
  renderable.TLS_SPKI_SHA256 = values.TLS_SPKI_SHA256;
  const config = template.replace(/__([A-Z0-9_]+)__/g, (_match, name) => renderable[name]);

  mkdirSync(dirname(renderedPath), { recursive: true, mode: 0o700 });
  // D57: create a fresh file 0600 whatever existed at the path before (the bridge seed is in it).
  rmSync(renderedPath, { force: true });
  writeFileSync(renderedPath, config, { mode: 0o600, flag: "wx" });
  chmodSync(renderedPath, 0o600);

  // What a reviewer needs to line the report up with the image and the certificate. No key material:
  // the seed never appears, and neither does any request data (there is none at boot).
  log(`lane: listening on ${values.LISTEN_ADDRESS} / guest agent unix:${values.GUEST_AGENT_SOCKET} / egress unix:${egressSocket}`);
  log(`lane: deploy_env=${deployEnv} tee_type=${values.TEE_TYPE} subject=${values.KEYSET_SUBJECT} not_after=${values.KEYSET_NOT_AFTER}`);
  log(`lane: tls_domain=${values.TLS_DOMAIN || "(unscoped)"} tls_spki_sha256=${values.TLS_SPKI_SHA256}`);
  log(`lane: bridge=${bridgeUrl} key_id=${values.LANE_KEY_ID} receipt_key_id=${values.LANE_RECEIPT_KEY_ID || "(per boot)"} seed=${seed === "" ? "(none)" : "set"}`);
  log(`lane: source=${values.SOURCE_REPO_URL || "(unknown)"}@${values.SOURCE_REPO_COMMIT || "(unknown)"} image=${values.SOURCE_IMAGE_DIGEST || "(unknown)"}`);
  if (stack !== null) {
    log(`lane: relay stack ${stack.relayId}: config on ${stack.configListen} / relay ${stack.relayAddress} / poll_ms=${stack.pollMs || "(default)"}`);
    log(`lane: relay image ${stack.relayImage} (signed by the relay key, measured before the seal)`);
  }
  if (peers !== null) {
    const role = stack !== null ? `backend mode ${peers.releasePublicKey === "" ? "off" : "on"}` : `entry peers=${peers.peers || "false"}`;
    log(`lane: ${role} / release lists ${peers.releasePublicKey === "" ? "(no keys)" : `release key ${peers.releasePublicKey} freshness key ${peers.releaseFreshnessPublicKey}`}${Object.keys(peers.tunables).length === 0 ? "" : ` / ${Object.entries(peers.tunables).map(([name, value]) => `${name}=${value}`).join(" ")}`}`);
  }

  // P2c-2: the lease starts from the boot's own key fetch, which came after the VM started: the VM's start (the kernel's
  // uptime, which a container shares) is never later, so the first lease ends no later than the KMS's answer allows. A
  // container started again late in the VM's life therefore begins past its lease, not serving, and checks at once.
  let lease = null;
  if (kmsLease !== null) {
    const bootAllowedAtMs = wallNow() - Math.ceil(uptime() * 1000);
    log(`lane: KMS lease on ${kmsLease.kmsUrl}: re-check every ${kmsLeaseTuning.recheckMs} ms, lease ${kmsLeaseTuning.leaseMs} ms from the VM's start at ${new Date(bootAllowedAtMs).toISOString()}; state to the Worker on unix:${kmsLeaseSocket}`);
    lease = startLease({
      kmsUrl: kmsLease.kmsUrl,
      guestSocket,
      vmConfig: kmsLeaseInputs.vmConfig,
      caPublicKeyHex: kmsLeaseInputs.caPublicKeyHex,
      settings: kmsLeaseTuning,
      bootAllowedAtMs,
      workerSocket: kmsLeaseSocket,
      now: wallNow,
      log,
      error,
    });
  }

  // P2e: the vault's disk is served before workerd starts, so the Worker's first read finds it.
  let vaultDisk = null;
  if (kmsLease !== null) {
    try {
      vaultDisk = await startDisk({ dir: vaultDir, socketPath: vaultDiskSocket, log, error });
    } catch (thrown) {
      await lease?.stop();
      fail(`cannot serve the vault disk on unix:${vaultDiskSocket}: ${thrown instanceof Error ? thrown.message : String(thrown)}`);
    }
  }

  // D133: the CLI wrapper supervises this child (superviseWorkerd) and restarts it with `restart`. P2c-2: workerd binds
  // the lease socket itself, so a socket file a previous workerd left is removed first, and the lease's state is pushed
  // to each new workerd as soon as it listens.
  const restart = () => {
    if (lease !== null) rmSync(kmsLeaseSocket, { force: true });
    const child = spawnWorker(workerd, ["serve", renderedPath], { stdio: "inherit" });
    lease?.wake();
    return child;
  };
  return { child: restart(), restart, orderedAt, kmsLease: lease, vaultDisk };
}

// The CLI wrapper: production gets the process defaults; the deploy-tee tests import main() and
// superviseWorkerd() and inject a fake guest agent, clock, sleep and children (D95). Real paths on both
// sides, so the wrapper still runs when the image or a host e2e reaches the file through a symlink (D81's
// rule).
function isMainModule() {
  if (process.argv[1] === undefined) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  // A stop (docker stop, compose down) is handled from the first line: this process is the container's
  // PID 1, which the kernel delivers no unhandled SIGTERM to, and a boot may be inside gray-acme or a D133
  // hold. While workerd runs the signal goes to it and its exit ends the supervision with 0; otherwise
  // this process exits at once (gray-acme, if running, goes with the container).
  const state = { stopping: false, child: null, running: false };
  const stop = (signal) => {
    state.stopping = true;
    if (state.running && state.child !== null) state.child.kill(signal);
    else process.exit(0);
  };
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
  const track = (child) => {
    state.child = child;
    state.running = true;
    child.on("exit", () => {
      if (state.child === child) state.running = false;
    });
    child.on("error", () => {
      if (state.child === child) state.running = false;
    });
    return child;
  };
  main().then(async ({ child, restart, orderedAt, kmsLease, vaultDisk }) => {
    const code = await superviseWorkerd({ first: track(child), restart: () => track(restart()), orderedAt, stopped: () => state.stopping });
    await kmsLease?.stop();
    await vaultDisk?.close();
    process.exit(code);
  }).catch((thrown) => {
    console.error(`lane: ${thrown instanceof Error ? thrown.message : String(thrown)}`);
    process.exit(1);
  });
}
