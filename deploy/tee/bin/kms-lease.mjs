// The KMS lease (docs/design/relay-no-always-on-host.md section 3.6, H9): the VM asks the KMS for its app key again
// every 10 minutes, and serves the relay's accounts only while the last answer allows it.
//
// The relay's contract on Base decides, through Phala's KMS, whether this app gets its keys. The KMS reads the
// contract only when asked and never revokes a running VM, so the VM asks again by itself: an RA-TLS client
// certificate from the guest agent's GetTlsKey, then KMS.GetAppKey with that certificate, exactly as the A1b probe
// did (deploy/tee/probe/kms-probe-base/compose.yaml). This file is the re-check client (`kmsAppKeyCheck`), the
// lease state machine (`KmsLease`) and, since P2c-2, the supervisor's runner that tells the lane Worker each change
// (`startKmsLease`, at the end); nothing here starts by itself: entrypoint.mjs starts the runner for an app whose
// measured compose names the KMS (LANE_KMS_URL). Node built-ins only, like entrypoint.mjs.
//
// Three outcomes, and why each failure lands where it does:
//
// - "allowed": GetTlsKey answered a key and a chain, the KMS's TLS certificate is pinned to the measured key
//   provider (below), and the KMS answered 200 with a k256 key. Nothing else extends the lease, so a network that
//   lies, drops or replays cannot produce it: it cannot complete a TLS handshake as the KMS.
// - "refused": the KMS's own authorization said no, and only that. The KMS writes `Boot denied: <reason>` when the
//   auth API answers `isAllowed: false` (dstack v0.6.1 kms/src/main_service.rs `ensure_app_attestation_allowed`);
//   GetAppKey wraps it as `App not allowed: Boot denied: ...` and the guest agent's GetTlsKey as `Failed to sign the
//   CSR: Request failed with status=400 Bad Request, error={"error": "Boot denied: paused"}` (A1b, 2026-11-09).
//   The reason is the contract's (`paused`, `compose hash not effective`, ...) or DstackKms's (`App not registered`,
//   `OS image is not allowed`, ...). One reason is not a decision: dstack's auth-eth answers `isAllowed: false` with
//   `authorization backend unavailable` when it cannot read the chain (kms/auth-eth/src/server.ts), so that text is
//   "unreachable": a Base RPC outage at the KMS must not drop every relay's accounts at once. A refusal counts only
//   from a 4xx answer: the guest agent's (a local socket inside the measured VM) or a KMS pinned as below.
// - "unreachable": everything else. Socket and TLS errors, a KMS certificate not issued by the measured CA, time
//   outs, 5xx, any 4xx without a decision (`App not allowed: auth api ... returned 500`, `Quote verification
//   failed`, `KMS self authorization failed: KMS is not allowed: ...`, which is Phala's KMS and not the relay's
//   choice), and malformed answers. The lease keeps its end; the accounts stop when it passes (at most 1 h).
//
// The KMS's TLS certificate. The CA is the app's measured `key_provider_id`: the P-256 SubjectPublicKeyInfo DER of
// the KMS root CA, as hex, which the guest agent's Info returns inside `key_provider_info` ({"name":"kms","id":...}).
// The KMS's RPC certificate is signed directly by that root and is not a CA certificate (kms/src/onboard_service.rs
// `Keys::from_keys`: `special_usage("kms:rpc")`, `signed_by(&ca_cert, &ca_key)`). The same root also signs one
// "Dstack App CA" per app (main_service.rs `derive_app_ca`), and every app on that KMS can have its app CA sign a
// server certificate for any name through GetTlsKey. So "chains to the root" would let any other app on the same
// KMS answer "allowed"; the rule here is narrower: the leaf must verify directly with the measured CA's public key
// (`X509Certificate.verify`) and must not be a CA, and it must be inside its validity window. The host name is not
// checked: a certificate that passes is a genuine RPC certificate of a KMS holding this app's root key, and a name
// check would only add a way to fail. Node's TLS chain check is off for this one connection because the trust anchor
// is a bare public key, which OpenSSL's store cannot hold; the check above runs on `secureConnect`, before a byte of
// the request is written, and a failed check destroys the socket.
//
// No key material leaves this file: results and log lines carry a 16-hex SHA-256 prefix of the k256 key (computed
// over its hex text, as kms-probe-base computes `k256_key_fp`), the KMS's reason (cut to 120 printable characters)
// or an error text, never a key, a certificate's private part or a 200 body.
import { createHash, createPublicKey, X509Certificate } from "node:crypto";
import { request as httpRequest } from "node:http";
import { isIP } from "node:net";
import { setTimeout as sleepFor } from "node:timers/promises";
import { connect as tlsConnect } from "node:tls";

/** H9: one re-check every 10 minutes, so a pause takes effect within one interval (section 3.6, "≤ 10 min"). */
export const KMS_RECHECK_MS = 10 * 60_000;
/**
 * The re-check comes up to this much early, at random, so the VMs of one release do not ask the KMS in step. It is
 * only ever subtracted: the interval stays at most KMS_RECHECK_MS, which is the pause promise.
 */
export const KMS_RECHECK_JITTER_MS = 30_000;
/** H9: an allowed answer serves for one hour; a VM that cannot reach the KMS stops when it ends (section 3.6, "≤ 1 h"). */
export const KMS_LEASE_MS = 60 * 60_000;
/** One check (GetTlsKey and GetAppKey together) gives up after this; the A1b probe used 30 s per call. */
export const KMS_CHECK_TIMEOUT_MS = 30_000;
/** The environment names that override the four values above (`kmsLeaseSettings`). */
export const KMS_LEASE_TUNABLE_NAMES = Object.freeze(["KMS_RECHECK_MS", "KMS_RECHECK_JITTER_MS", "KMS_LEASE_MS", "KMS_CHECK_TIMEOUT_MS"]);

/** The auth API's answer when it cannot read the chain (dstack v0.6.1 kms/auth-eth/src/server.ts `backendUnavailable`). */
export const KMS_BACKEND_UNAVAILABLE = "authorization backend unavailable";

/** The subject of the RA-TLS client certificate the re-check asks the guest agent for (it names nothing else). */
const CLIENT_SUBJECT = "gray-kms-lease";
/** The guest agent's frozen v0 surface on its internal socket (guest-agent/src/server.rs `mount_internal`: "/" and "/v0"). */
const GET_TLS_KEY_PATH = "/GetTlsKey";
const GET_APP_KEY_PATH = "/prpc/KMS.GetAppKey?json";
/** A GetTlsKey answer carries a key and a chain with a quote (a few KB); a GetAppKey answer is smaller. */
const GUEST_ANSWER_MAX_BYTES = 256 * 1024;
const KMS_ANSWER_MAX_BYTES = 64 * 1024;
const REASON_MAX = 120;
const ERROR_MAX = 200;
/** `Boot denied: <reason>`, ending at a quote or backslash (the reason sits in a JSON string, escaped once or twice). */
const BOOT_DENIED = /Boot denied: ([^"\\\r\n]*)/;
/** The DER prefix of a P-256 SubjectPublicKeyInfo (app-compose.mjs `P256_SPKI_PREFIX`); 91 bytes in all. */
const P256_SPKI = /^3059301306072a8648ce3d020106082a8648ce3d030107034200[0-9a-f]{130}$/;
const HEX_32 = /^(0x)?[0-9a-fA-F]{64}$/;
const UINT = /^(0|[1-9][0-9]*)$/;

/** Printable ASCII only, one line, at most `max` characters. */
function printable(text, max) {
  const flat = String(text).replace(/[^\x20-\x7e]+/g, " ").replace(/ {2,}/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function messageOf(thrown) {
  return thrown instanceof Error ? thrown.message : String(thrown);
}

function unreachable(step, error) {
  return { outcome: "unreachable", step, error: printable(error, ERROR_MAX) };
}

/** The `error` member of a prpc error answer, else the text itself. */
function errorTextOf(text) {
  try {
    const value = JSON.parse(text);
    if (value !== null && typeof value === "object" && typeof value.error === "string") return value.error;
  } catch {
    // not JSON: the text is the message
  }
  return text;
}

/**
 * The KMS's refusal in a 4xx answer's text, as `Boot denied: <reason>`; null when the text holds no decision of the
 * app's authorization (including the auth API's own outage, KMS_BACKEND_UNAVAILABLE).
 */
export function kmsRefusal(text) {
  const match = BOOT_DENIED.exec(errorTextOf(String(text)));
  if (match === null) return null;
  const reason = printable(match[1], REASON_MAX);
  if (reason === "" || reason.startsWith(KMS_BACKEND_UNAVAILABLE)) return null;
  return `Boot denied: ${reason}`;
}

/** The KMS CA's public key from its SubjectPublicKeyInfo hex (the measured `key_provider_id`); throws when it is not P-256. */
function kmsCaPublicKey(hex) {
  const text = typeof hex === "string" ? hex.toLowerCase().replace(/^0x/, "") : "";
  if (!P256_SPKI.test(text)) throw new Error("the KMS CA public key is a P-256 SubjectPublicKeyInfo as 182 hex digits (key_provider_id)");
  const key = createPublicKey({ key: Buffer.from(text, "hex"), format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("the KMS CA public key is not a P-256 key");
  }
  return key;
}

function kmsEndpoint(urlText) {
  let url;
  try {
    url = new URL(urlText);
  } catch {
    throw new Error("the KMS URL is not a URL");
  }
  if (url.protocol !== "https:" || url.hostname === "" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new Error("the KMS URL is https://<host>[:port][/path] without credentials, query or fragment");
  }
  const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
  const port = url.port === "" ? 443 : Number(url.port);
  const prefix = url.pathname.replace(/\/+$/, "");
  return { host, port, hostHeader: url.host, path: `${prefix}${GET_APP_KEY_PATH}` };
}

/**
 * Why the KMS's leaf certificate is not acceptable, or null: it must verify directly with the measured CA key, must
 * not be a CA, and must be inside its validity window at `nowMs` (the header says why the chain may not be longer).
 */
export function kmsCertificateProblem(leaf, caPublicKey, nowMs) {
  if (!(leaf instanceof X509Certificate)) return "the KMS presented no certificate";
  if (leaf.ca) return "the KMS presented a CA certificate";
  if (!leaf.verify(caPublicKey)) return "the KMS certificate is not signed by the measured KMS CA (key_provider_id)";
  const from = leaf.validFromDate ?? new Date(leaf.validFrom);
  const to = leaf.validToDate ?? new Date(leaf.validTo);
  if (!(nowMs >= from.getTime() && nowMs <= to.getTime())) return "the KMS certificate is outside its validity window";
  return null;
}

/** POST JSON on the guest agent's unix socket; resolves with the status and text (bounded). */
function guestPost(socketPath, path, body, signal) {
  return new Promise((resolve, reject) => {
    const text = JSON.stringify(body);
    let settled = false;
    const done = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const request = httpRequest({
      socketPath,
      path,
      method: "POST",
      signal,
      headers: { host: "localhost", "content-type": "application/json", "content-length": Buffer.byteLength(text) },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > GUEST_ANSWER_MAX_BYTES) {
          done(new Error(`the answer is larger than ${GUEST_ANSWER_MAX_BYTES} bytes`));
          request.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => done(null, { status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", (error) => done(error));
      response.on("close", () => {
        if (!response.complete) done(new Error("the guest agent closed the connection mid-answer"));
      });
    });
    request.on("error", (error) => done(error));
    request.end(text);
  });
}

/** A TLS connection to the KMS with the guest agent's client certificate, resolved only once its certificate passed. */
function pinnedKmsSocket({ host, port, key, cert, caPublicKey, signal, wallNow }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tlsConnect({
      host,
      port,
      servername: isIP(host) === 0 ? host : undefined,
      key,
      cert,
      // The trust anchor is a bare public key; kmsCertificateProblem checks the leaf on secureConnect, before the
      // request is written (header).
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
    });
    const finish = (error) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      socket.removeListener("error", finish);
      if (error) {
        socket.destroy();
        reject(error);
      } else {
        // node:http attaches its own listener once it takes the socket; until then an error only closes it, and
        // postOverSocket reports a close before the answer.
        socket.on("error", () => {});
        resolve(socket);
      }
    };
    const onAbort = () => finish(signal.reason instanceof Error ? signal.reason : new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    socket.once("error", finish);
    socket.once("secureConnect", () => {
      let problem;
      try {
        problem = kmsCertificateProblem(socket.getPeerX509Certificate(), caPublicKey, wallNow());
      } catch (thrown) {
        problem = `the KMS certificate could not be checked: ${messageOf(thrown)}`;
      }
      finish(problem === null ? null : new Error(problem));
    });
  });
}

/** POST JSON over an already verified socket with node:http; resolves with the status and text (bounded). */
function postOverSocket(socket, { hostHeader, path, body, signal }) {
  return new Promise((resolve, reject) => {
    const text = JSON.stringify(body);
    let settled = false;
    let answered = false;
    const done = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const request = httpRequest({
      createConnection: () => socket,
      path,
      method: "POST",
      signal,
      headers: { host: hostHeader, "content-type": "application/json", "content-length": Buffer.byteLength(text), connection: "close" },
    }, (response) => {
      answered = true;
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > KMS_ANSWER_MAX_BYTES) {
          done(new Error(`the answer is larger than ${KMS_ANSWER_MAX_BYTES} bytes`));
          request.destroy();
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => done(null, { status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", (error) => done(error));
      response.on("close", () => {
        if (!response.complete) done(new Error("the KMS closed the connection mid-answer"));
      });
    });
    request.on("error", (error) => done(error));
    socket.once("close", () => {
      if (!answered) done(new Error("the KMS closed the connection before it answered"));
    });
    request.end(text);
  });
}

/** Why a call failed, naming the deadline or the stop rather than Node's generic AbortError. */
function failureText(thrown, deadline, stop, timeoutMs) {
  if (deadline.aborted) return `timed out after ${timeoutMs} ms`;
  if (stop?.aborted) return "stopped";
  return messageOf(thrown);
}

/**
 * One re-check: GetTlsKey on the guest agent, then KMS.GetAppKey with that certificate. Never throws; resolves with
 * `{outcome: "allowed", k256Fingerprint}`, `{outcome: "refused", step, reason}` or `{outcome: "unreachable", step,
 * error}` (header). `vmConfig` and `caPublicKeyHex` are the guest agent's Info values (`kmsLeaseInputsFromInfo`);
 * `kmsUrl` is the KMS of the measured key provider. `expectedK256Fingerprint`, when given, must equal the answer's,
 * else the answer extends nothing ("unreachable"): H9's "the answer's k256 key against the boot's".
 */
export async function kmsAppKeyCheck({
  guestSocket = "/var/run/dstack.sock",
  kmsUrl,
  caPublicKeyHex,
  vmConfig,
  timeoutMs = KMS_CHECK_TIMEOUT_MS,
  expectedK256Fingerprint,
  signal,
  wallNow = Date.now,
} = {}) {
  let endpoint;
  let caPublicKey;
  try {
    if (typeof guestSocket !== "string" || !guestSocket.startsWith("/")) throw new Error("the guest agent socket is an absolute path");
    if (typeof vmConfig !== "string" || vmConfig === "") throw new Error("vm_config is a non-empty string (the guest agent's Info)");
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new Error("timeoutMs is a positive integer");
    if (expectedK256Fingerprint !== undefined && !/^[0-9a-f]{16}$/.test(expectedK256Fingerprint)) {
      throw new Error("expectedK256Fingerprint is 16 lower-case hex digits");
    }
    endpoint = kmsEndpoint(kmsUrl);
    caPublicKey = kmsCaPublicKey(caPublicKeyHex);
  } catch (thrown) {
    return unreachable("input", messageOf(thrown));
  }
  const deadline = AbortSignal.timeout(timeoutMs);
  const combined = signal === undefined ? deadline : AbortSignal.any([deadline, signal]);

  // 1. The RA-TLS client certificate. The guest agent asks the KMS to sign it, so a paused contract is refused here
  //    already (A1b).
  let tls;
  try {
    const answer = await guestPost(guestSocket, GET_TLS_KEY_PATH, { subject: CLIENT_SUBJECT, usage_ra_tls: true, usage_client_auth: true }, combined);
    if (answer.status !== 200) {
      const reason = answer.status >= 400 && answer.status < 500 ? kmsRefusal(answer.text) : null;
      if (reason !== null) return { outcome: "refused", step: "GetTlsKey", reason };
      return unreachable("GetTlsKey", `the guest agent answered ${answer.status}: ${errorTextOf(answer.text)}`);
    }
    let value;
    try {
      value = JSON.parse(answer.text);
    } catch {
      return unreachable("GetTlsKey", "the guest agent's 200 answer is not JSON");
    }
    const chain = value !== null && typeof value === "object" ? value.certificate_chain : undefined;
    if (
      typeof value?.key !== "string" || !value.key.includes("PRIVATE KEY-----")
      || !Array.isArray(chain) || chain.length === 0 || !chain.every((pem) => typeof pem === "string" && pem.includes("-----BEGIN CERTIFICATE-----"))
    ) {
      return unreachable("GetTlsKey", "the guest agent's 200 answer has no key and certificate chain");
    }
    tls = { key: value.key, cert: chain.join("\n") };
  } catch (thrown) {
    return unreachable("GetTlsKey", failureText(thrown, deadline, signal, timeoutMs));
  }

  // 2. GetAppKey on the KMS, its certificate pinned to the measured CA before anything is sent.
  let answer;
  let socket;
  try {
    socket = await pinnedKmsSocket({ host: endpoint.host, port: endpoint.port, key: tls.key, cert: tls.cert, caPublicKey, signal: combined, wallNow });
    answer = await postOverSocket(socket, { hostHeader: endpoint.hostHeader, path: endpoint.path, body: { api_version: 1, vm_config: vmConfig }, signal: combined });
  } catch (thrown) {
    return unreachable("GetAppKey", failureText(thrown, deadline, signal, timeoutMs));
  } finally {
    socket?.destroy();
  }
  if (answer.status !== 200) {
    const reason = answer.status >= 400 && answer.status < 500 ? kmsRefusal(answer.text) : null;
    if (reason !== null) return { outcome: "refused", step: "GetAppKey", reason };
    return unreachable("GetAppKey", `the KMS answered ${answer.status}: ${errorTextOf(answer.text)}`);
  }
  let value;
  try {
    value = JSON.parse(answer.text);
  } catch {
    return unreachable("GetAppKey", "the KMS's 200 answer is not JSON");
  }
  const k256 = value !== null && typeof value === "object" ? value.k256_key : undefined;
  if (typeof k256 !== "string" || !HEX_32.test(k256)) return unreachable("GetAppKey", "the KMS's 200 answer has no 32-byte k256_key");
  const k256Fingerprint = createHash("sha256").update(k256).digest("hex").slice(0, 16);
  if (expectedK256Fingerprint !== undefined && k256Fingerprint !== expectedK256Fingerprint) {
    return unreachable("GetAppKey", `the KMS answered k256 key ${k256Fingerprint}, not this boot's ${expectedK256Fingerprint}`);
  }
  return { outcome: "allowed", k256Fingerprint };
}

/**
 * The re-check's two inputs from the guest agent's Info answer: `vm_config` and the KMS CA (`key_provider_info`, the
 * JSON text {"name":"kms","id":"<SPKI hex>"} of the boot's key-provider event). Both the v0 `/Info` and the v1
 * `/v1/Info` carry them on the internal socket (dstack v0.6.1 guest-agent rpc_service.rs `get_info`,
 * rpc_service_v1.rs `info_response`: hidden only on the external listener). Throws when either is missing or the key
 * provider is not a KMS with a P-256 CA.
 */
export function kmsLeaseInputsFromInfo(info) {
  if (info === null || typeof info !== "object") throw new Error("the guest agent's Info answer is not an object");
  if (typeof info.vm_config !== "string" || info.vm_config === "") throw new Error("the guest agent's Info answer carries no vm_config");
  let provider;
  try {
    provider = JSON.parse(info.key_provider_info);
  } catch {
    throw new Error("the guest agent's Info answer carries no key_provider_info JSON");
  }
  if (provider === null || typeof provider !== "object" || provider.name !== "kms") {
    throw new Error("the boot's key provider is not a KMS: a VM without a KMS has no lease to keep");
  }
  const caPublicKeyHex = typeof provider.id === "string" ? provider.id.toLowerCase().replace(/^0x/, "") : "";
  kmsCaPublicKey(caPublicKeyHex);
  return { vmConfig: info.vm_config, caPublicKeyHex };
}

/** POST /v1/Info on the guest agent's socket and read the re-check's inputs from it (`kmsLeaseInputsFromInfo`). */
export async function readKmsLeaseInputs({ guestSocket = "/var/run/dstack.sock", timeoutMs = KMS_CHECK_TIMEOUT_MS } = {}) {
  const deadline = AbortSignal.timeout(timeoutMs);
  let answer;
  try {
    answer = await guestPost(guestSocket, "/v1/Info", {}, deadline);
  } catch (thrown) {
    throw new Error(`POST /v1/Info on unix:${guestSocket}: ${failureText(thrown, deadline, undefined, timeoutMs)}`);
  }
  if (answer.status !== 200) throw new Error(`POST /v1/Info answered ${answer.status}: ${printable(errorTextOf(answer.text), ERROR_MAX)}`);
  let info;
  try {
    info = JSON.parse(answer.text);
  } catch {
    throw new Error("POST /v1/Info did not answer JSON");
  }
  return kmsLeaseInputsFromInfo(info);
}

function tunable(env, name, fallback, min, max) {
  const text = env[name];
  if (text === undefined || text === "") return fallback;
  if (!UINT.test(text)) throw new Error(`${name} is an integer number of milliseconds`);
  const value = Number(text);
  if (value < min || value > max) throw new Error(`${name} is from ${min} to ${max} ms (got ${value})`);
  return value;
}

/**
 * The lease's settings from the environment, as entrypoint.mjs reads its tunables: unset or empty means the default,
 * anything else must be an integer in bounds. The bounds keep the design's promises: a re-check at most every
 * 10 minutes (a pause acts within one interval), a lease of at most 1 hour and at least two intervals (one missed
 * check never ends it), a jitter of at most a tenth of the interval, a check timeout below the interval.
 */
export function kmsLeaseSettings(env = process.env) {
  const recheckMs = tunable(env, "KMS_RECHECK_MS", KMS_RECHECK_MS, 1_000, KMS_RECHECK_MS);
  const jitterMs = tunable(env, "KMS_RECHECK_JITTER_MS", Math.min(KMS_RECHECK_JITTER_MS, Math.floor(recheckMs / 10)), 0, Math.floor(recheckMs / 10));
  const leaseMs = tunable(env, "KMS_LEASE_MS", KMS_LEASE_MS, 2 * recheckMs, KMS_LEASE_MS);
  const timeoutMs = tunable(env, "KMS_CHECK_TIMEOUT_MS", Math.min(KMS_CHECK_TIMEOUT_MS, recheckMs - 1), 100, recheckMs - 1);
  return { recheckMs, jitterMs, leaseMs, timeoutMs };
}

function abortableSleep(ms, signal) {
  return sleepFor(ms, undefined, { signal });
}

function sameState(a, b) {
  return a.serving === b.serving && a.leaseUntilMs === b.leaseUntilMs && a.lastOutcome === b.lastOutcome && a.refusedReason === b.refusedReason;
}

function iso(ms) {
  return new Date(ms).toISOString();
}

/**
 * The lease (H9). It starts from the boot's own successful key fetch (`bootAllowedAtMs`), since the KMS gave this
 * VM its keys then. An allowed answer sets the end to the check's start + `leaseMs` and serves; a refused answer
 * stops serving at once, until a later allowed answer; an unreachable answer keeps the end, so serving stops when
 * the clock passes it. Every time is a number of milliseconds from the injected clock.
 */
export class KmsLease {
  #bootAllowedAtMs;
  #leaseMs;
  #recheckMs;
  #jitterMs;
  #random;
  #leaseUntilMs;
  #refused = false;
  #refusedReason = null;
  #lastCheckMs = null;
  #lastOutcome = null;
  #controller = null;

  constructor({ bootAllowedAtMs, leaseMs = KMS_LEASE_MS, recheckMs = KMS_RECHECK_MS, jitterMs = Math.min(KMS_RECHECK_JITTER_MS, Math.floor(recheckMs / 10)), random = Math.random } = {}) {
    if (!Number.isFinite(bootAllowedAtMs)) throw new Error("bootAllowedAtMs is the time of the boot's own key fetch");
    if (!Number.isInteger(recheckMs) || recheckMs <= 0) throw new Error("recheckMs is a positive integer");
    if (!Number.isInteger(jitterMs) || jitterMs < 0 || jitterMs >= recheckMs) throw new Error("jitterMs is a non-negative integer below recheckMs");
    if (!Number.isInteger(leaseMs) || leaseMs <= recheckMs) throw new Error("leaseMs is an integer above recheckMs");
    this.#bootAllowedAtMs = bootAllowedAtMs;
    this.#leaseMs = leaseMs;
    this.#recheckMs = recheckMs;
    this.#jitterMs = jitterMs;
    this.#random = random;
    this.#leaseUntilMs = bootAllowedAtMs + leaseMs;
  }

  /** `{serving, leaseUntilMs, lastCheckMs, lastOutcome, refusedReason}` at `nowMs`. */
  state(nowMs) {
    return {
      serving: !this.#refused && nowMs < this.#leaseUntilMs,
      leaseUntilMs: this.#leaseUntilMs,
      lastCheckMs: this.#lastCheckMs,
      lastOutcome: this.#lastOutcome,
      refusedReason: this.#refusedReason,
    };
  }

  /** Apply one check's result, the check having started at `startedAtMs`; anything but allowed or refused is unreachable. */
  record(result, startedAtMs) {
    const outcome = result?.outcome === "allowed" || result?.outcome === "refused" ? result.outcome : "unreachable";
    if (outcome === "allowed") {
      this.#leaseUntilMs = startedAtMs + this.#leaseMs;
      this.#refused = false;
      this.#refusedReason = null;
    } else if (outcome === "refused") {
      this.#refused = true;
      this.#refusedReason = typeof result.reason === "string" ? printable(result.reason, REASON_MAX + 20) : "refused";
    }
    this.#lastCheckMs = startedAtMs;
    this.#lastOutcome = outcome;
    return this.state(startedAtMs);
  }

  /** The wait before the next check: the interval less a random jitter in [0, jitterMs]. */
  nextDelayMs() {
    return this.#recheckMs - Math.floor(this.#random() * (this.#jitterMs + 1));
  }

  /**
   * Check every interval until `stop()`: the first check one interval after the boot's key fetch, each next one an
   * interval after the previous one started. `check({signal})` is a `kmsAppKeyCheck` bound to its inputs; a throw
   * counts as unreachable. `onChange(state)` is called with the state at the start and whenever serving, the lease
   * end, the last outcome or the refusal reason changes, including when the lease runs out between checks (the loop
   * wakes at the lease end for that). `log` gets one line per check, without key material. Resolves once stopped.
   */
  async run({ check, now = Date.now, sleep = abortableSleep, onChange = () => {}, log = () => {} } = {}) {
    if (typeof check !== "function") throw new Error("run needs a check function");
    if (this.#controller !== null) throw new Error("the lease is already running");
    const controller = new AbortController();
    this.#controller = controller;
    const { signal } = controller;
    let reported = null;
    const report = () => {
      const t = now();
      const state = this.state(t);
      if (reported !== null && sameState(reported, state)) return;
      if (reported !== null && reported.serving && !state.serving && state.lastOutcome !== "refused") {
        log(`kms-lease: the lease ended at ${iso(state.leaseUntilMs)} without an allowed answer; the accounts stop`);
      }
      reported = state;
      onChange({ ...state });
    };
    let nextCheckAt = this.#bootAllowedAtMs + this.nextDelayMs();
    try {
      report();
      while (!signal.aborted) {
        const t = now();
        const current = this.state(t);
        const wakeAt = current.serving ? Math.min(nextCheckAt, current.leaseUntilMs) : nextCheckAt;
        if (wakeAt > t) await sleep(wakeAt - t, signal);
        if (signal.aborted) break;
        const startedAt = now();
        if (startedAt >= nextCheckAt) {
          let result;
          try {
            result = await check({ signal });
          } catch (thrown) {
            result = unreachable("check", messageOf(thrown));
          }
          if (signal.aborted) break;
          const state = this.record(result, startedAt);
          if (state.lastOutcome === "allowed") {
            log(`kms-lease: allowed (k256 ${printable(result.k256Fingerprint ?? "?", 16)}); lease until ${iso(state.leaseUntilMs)}`);
          } else if (state.lastOutcome === "refused") {
            log(`kms-lease: refused at ${printable(result.step ?? "?", 20)}: ${state.refusedReason}; the accounts stop`);
          } else {
            log(`kms-lease: unreachable at ${printable(result?.step ?? "?", 20)}: ${printable(result?.error ?? "no result", ERROR_MAX)}; lease until ${iso(state.leaseUntilMs)}`);
          }
          nextCheckAt = startedAt + this.nextDelayMs();
        }
        report();
      }
    } catch (thrown) {
      if (!signal.aborted) throw thrown;
    } finally {
      this.#controller = null;
    }
  }

  /** Stop `run`: an in-flight check is aborted and its result not recorded. */
  stop() {
    this.#controller?.abort(new Error("the KMS lease was stopped"));
  }
}

// P2c-2: the supervisor's side. entrypoint.mjs starts `startKmsLease` for an app whose measured compose names the KMS
// to re-check (LANE_KMS_URL), and tells the lane Worker every change of the lease by a PUT on a unix socket that
// workerd serves on the Worker's `kmsLease` entrypoint (deploy/tee/workerd/config.capnp's KMS_LEASE_SOCKETS fragment,
// workers/gateway/src/lane/kms-lease.ts). Why a push and not a read by the Worker: workerd runs nothing between
// requests, so a Worker that only read the state would learn of a refusal, and act on the lease's end, only when some
// request arrived; the push is itself the request that makes the Worker empty egress's account sets at once. The
// socket is on the lane container's own /run/lane tmpfs: only this container reaches it.

/** How often the state is pushed when nothing changed: a restarted workerd has it within this, a failed push sooner. */
export const KMS_LEASE_PUSH_MS = 15_000;
/** The Worker's route on that socket (workers/gateway/src/lane/kms-lease.ts `KMS_LEASE_PATH`). */
export const KMS_LEASE_WORKER_PATH = "/v1/lane/kms-lease";
/** One push gives up after this; a failed push is tried again after PUSH_RETRY_MS, doubled up to KMS_LEASE_PUSH_MS. */
const PUSH_TIMEOUT_MS = 2_000;
const PUSH_RETRY_MS = 250;

/** The state as the Worker reads it (`kmsLeasePushSchema`): times in milliseconds of the wall clock. */
export function kmsLeaseWire(state) {
  return {
    serving: state.serving,
    lease_until_ms: state.leaseUntilMs,
    last_check_ms: state.lastCheckMs,
    last_outcome: state.lastOutcome,
    // `printable` marks a cut reason with an ellipsis; the Worker and the report take printable ASCII only.
    refused_reason: state.refusedReason === null ? null : state.refusedReason.replace(/\u2026/g, "...").replace(/[^\x20-\x7e]/g, "?"),
  };
}

/** PUT `body` on the Worker's unix socket; resolves with the status. */
function putWorker(socketPath, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      socketPath,
      path: KMS_LEASE_WORKER_PATH,
      method: "PUT",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { host: "lane", "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode ?? 0));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end(body);
  });
}

/**
 * Run this boot's lease and tell the lane Worker (above). The lease starts from the boot's own key fetch
 * (`bootAllowedAtMs`, which the caller takes no later than the VM's start); the first allowed answer pins its k256
 * fingerprint, and every later answer must carry the same key (`expectedK256Fingerprint`), else it extends nothing.
 * `settings` is `kmsLeaseSettings`'s; `check` defaults to `kmsAppKeyCheck`. A loop that stops on an error (it should
 * not: `run` throws only when an injected function does) pushes "not serving" from then on. Returns
 * `{state(), pinned(), wake(), stop()}`: `wake` pushes now (the supervisor calls it when it starts workerd again),
 * `stop` ends the loop and the pushes.
 */
export function startKmsLease({
  kmsUrl,
  guestSocket,
  vmConfig,
  caPublicKeyHex,
  settings,
  bootAllowedAtMs,
  workerSocket,
  pushEveryMs = KMS_LEASE_PUSH_MS,
  now = Date.now,
  random = Math.random,
  check = kmsAppKeyCheck,
  log = console.log,
  error = console.error,
}) {
  if (typeof workerSocket !== "string" || !workerSocket.startsWith("/")) throw new Error("the Worker's lease socket is an absolute path");
  const lease = new KmsLease({ bootAllowedAtMs, leaseMs: settings.leaseMs, recheckMs: settings.recheckMs, jitterMs: settings.jitterMs, random });
  let pinned;
  let failed = false;
  let stopped = false;
  let dirty = false;
  let waiter = null;
  const wake = () => {
    dirty = true;
    const resolve = waiter;
    waiter = null;
    resolve?.();
  };
  const stateNow = () => {
    const state = lease.state(now());
    return failed ? { ...state, serving: false } : state;
  };
  const pusher = (async () => {
    let retryMs = PUSH_RETRY_MS;
    let failing = false;
    while (!stopped) {
      dirty = false;
      let problem = null;
      try {
        const body = JSON.stringify(kmsLeaseWire(stateNow()));
        const status = await putWorker(workerSocket, body, PUSH_TIMEOUT_MS);
        if (status !== 204) problem = `the Worker answered ${status}`;
      } catch (thrown) {
        problem = printable(messageOf(thrown), ERROR_MAX);
      }
      if (problem === null) {
        if (failing) log("kms-lease: the lane Worker has the lease state again");
        failing = false;
        retryMs = PUSH_RETRY_MS;
      } else if (!failing) {
        failing = true;
        error(`kms-lease: could not tell the lane Worker the lease state (${problem}); trying again`);
      }
      if (stopped || dirty) continue;
      const waitMs = problem === null ? pushEveryMs : retryMs;
      if (problem !== null) retryMs = Math.min(retryMs * 2, pushEveryMs);
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          waiter = null;
          resolve();
        }, waitMs);
        waiter = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  })();
  const pinnedCheck = async ({ signal }) => {
    const result = await check({
      guestSocket,
      kmsUrl,
      caPublicKeyHex,
      vmConfig,
      timeoutMs: settings.timeoutMs,
      signal,
      ...(pinned === undefined ? {} : { expectedK256Fingerprint: pinned }),
    });
    if (result?.outcome === "allowed" && pinned === undefined) {
      pinned = result.k256Fingerprint;
      log(`kms-lease: this boot's k256 key is ${printable(pinned, 16)}; every later answer must carry it`);
    }
    return result;
  };
  const running = lease.run({ check: pinnedCheck, now, onChange: () => wake(), log }).catch((thrown) => {
    failed = true;
    error(`kms-lease: the re-check loop stopped (${printable(messageOf(thrown), ERROR_MAX)}); the accounts stop`);
    wake();
  });
  return {
    state: stateNow,
    pinned: () => pinned,
    wake,
    async stop() {
      stopped = true;
      lease.stop();
      wake();
      await Promise.all([running, pusher]);
    },
  };
}
