// The relay vault's disk, served by the lane supervisor to the lane Worker (P2e, docs/design/relay-no-always-on-host.md
// §3.1 and 13.11). workerd has no disk of its own, so the supervisor (entrypoint.mjs) holds the one directory the vault
// lives in, /var/lib/gray-persist/relay on the data disk (the stack layout's bind for an app on an on-chain KMS; pre-launch
// creates it owned by lane's uid, mode 0700), and answers the Worker on a unix socket of the lane container's own tmpfs,
// which workerd binds as the external service `LANE_VAULT_DISK`.
//
// The protocol (one route, `/v1/lane/vault`; anything else is 404):
//
// - `GET`: 200 `{"record": <the record text> | null, "highest_seen": <n>}`. `record` is the vault record as the Worker
//   wrote it (`@gray/relay-connector/vault` serializeRecord: JCS text, printable ASCII); `highest_seen` is the highest
//   version the disk has taken, which is that record's header version (0 with no record).
// - `PUT` with the record text as the body: the record's header version must be above `highest_seen`, else 409
//   `{"error": "vault_version_not_above", "highest_seen": <n>}`. The write is atomic: a temp file in the same
//   directory (O_EXCL, mode 0600), written and fsynced, renamed over `vault.v1`, then the directory fsynced; 204 once all
//   of that returned. A failure before the rename is 500 `vault_write_failed` and leaves the previous record in place (the
//   temp file is removed); a failure after it (opening or fsyncing the directory) is 500 `vault_write_uncertain`: the new
//   record is in place, but may not survive a crash, and the Worker reads the disk back. Writes run one at a time.
// - A body that is not one record (over the size, not printable ASCII, not JSON, no positive safe-integer
//   `header.version`) is 400 `invalid_record`. The supervisor reads the header's version and nothing else: the rest is
//   sealed under a key it never holds.
// - The directory must be a directory (not a link) owned by this process's uid with no group or other permission; if it
//   is not, every request is 503 `vault_disk_unavailable` (logged once), so a VM whose pre-launch did not prepare it
//   serves no vault rather than one on the wrong disk.
//
// The boot box (P4b) on the same socket and directory, `/v1/lane/boot`: the files pre-launch's boot box helper
// (workers/gateway/src/lane/prelaunch-boot-box.ts, deploy/tee/boot-box/main.mjs) reads and writes, in its format:
//
// - `boot.v1`, the sealed record (`gray-relay-boot/v1`, serializeRecord's JCS text), and `boot.v1.seen`, the JCS
//   `{"seq":M,"version":N}` of the highest designation seq and record version this disk has seen (no newline).
// - `GET`: 200 `{"record": <boot.v1> | null, "highest_seen": <N>, "seq": <M>}`, where `highest_seen` is the higher of the
//   seen file's version and the record's own. A seen file off its form is 500 `boot_seen_invalid` (the helper stops the
//   boot on one too).
// - `PUT` with the record text as the body and the designation's seq in `x-gray-boot-seq` (the supervisor cannot read
//   the sealed box): the record must be a boot record whose version is above `highest_seen`, else 409
//   `{"error": "boot_version_not_above", "highest_seen", "seq"}`, and the seq at least the seen one, else 409
//   `boot_seq_below`. `boot.v1` is written first, then `boot.v1.seen` (each as `vault.v1`: temp file, fsync, rename,
//   fsync of the directory), so a crash between them leaves a seen version below the record's, which every reader
//   takes as the record's.
//
// No line it logs carries a record's bytes: versions, sizes and error codes.

import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { chmodSync, closeSync, constants, fsyncSync, lstatSync, openSync, readFileSync, renameSync, rmSync, writeSync } from "node:fs";
import { join } from "node:path";

/** The directory on the data disk the stack layout binds into lane (app-compose.mjs VAULT_BIND_SOURCE). */
export const VAULT_DIR = "/var/lib/gray-persist/relay";
/** The record's file name in it: one record, the vault's latest version. */
export const VAULT_FILE = "vault.v1";
/** The Worker's route on the socket (workers/gateway/src/lane/vault.ts VAULT_DISK_URL). */
export const VAULT_DISK_PATH = "/v1/lane/vault";
/** P4b: the boot box's record and seen file (prelaunch-boot-box.ts BOOT_BOX_FILE, BOOT_BOX_SEEN_FILE). */
export const BOOT_FILE = "boot.v1";
export const BOOT_SEEN_FILE = "boot.v1.seen";
/** P4b: the Worker's boot box route (workers/gateway/src/lane/boot-intake.ts BOOT_DISK_URL). */
export const BOOT_DISK_PATH = "/v1/lane/boot";
const BOOT_FORMAT = "gray-relay-boot/v1";
/** The seen file's one form (prelaunch-boot-box.ts parseSeen). */
const SEEN_FORM = /^\{"seq":(0|[1-9][0-9]{0,15}),"version":(0|[1-9][0-9]{0,15})\}$/;
/**
 * The largest record: `@gray/lane-wire` STACK_VAULT_RECORD_MAX_CHARS (1 MiB), the most Gray's copy keeps, so a record the
 * disk takes can always be uploaded.
 */
export const VAULT_RECORD_MAX_BYTES = 1024 * 1024;

/** A vault disk failure, with a closed code the answer and the log carry. */
export class VaultDiskError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "VaultDiskError";
    this.code = code;
  }
}

/** Why `dir` cannot hold the vault (missing, a link, not a directory, another owner, any group or other bit), or null. */
export function vaultDirProblem(dir, uid = process.getuid?.() ?? null) {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch {
    return "missing";
  }
  if (stat.isSymbolicLink()) return "a symbolic link";
  if (!stat.isDirectory()) return "not a directory";
  if (uid !== null && stat.uid !== uid) return `owned by uid ${stat.uid}, not ${uid}`;
  if ((stat.mode & 0o077) !== 0) return `mode ${(stat.mode & 0o777).toString(8)}, not 0700`;
  return null;
}

/** The header version of a record's text, or null when the text is not one record. */
export function recordVersion(text) {
  if (typeof text !== "string" || text.length === 0 || Buffer.byteLength(text, "utf8") > VAULT_RECORD_MAX_BYTES || !/^[\x20-\x7e]+$/.test(text)) return null;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  const header = value !== null && typeof value === "object" && !Array.isArray(value) ? value.header : undefined;
  const version = header !== null && typeof header === "object" && !Array.isArray(header) ? header.version : undefined;
  return Number.isSafeInteger(version) && version >= 1 ? version : null;
}

/** A record's header format, or null (the text was already judged one record by `recordVersion`). */
function recordFormat(text) {
  try {
    const format = JSON.parse(text)?.header?.format;
    return typeof format === "string" ? format : null;
  } catch {
    return null;
  }
}

/** The seen file's text for `{seq, version}`: JCS, as prelaunch-boot-box.ts `seenText` writes it. */
export function bootSeenText(seen) {
  return `{"seq":${seen.seq},"version":${seen.version}}`;
}

/**
 * The boot box on the disk: the record, its version, and the seen file (`{seq: 0, version: 0}` without one). Throws
 * VaultDiskError (`boot_record_unreadable`, `boot_seen_invalid`, `boot_read_failed`).
 */
export function readBootRecord(dir) {
  const read = (name) => {
    try {
      return readFileSync(join(dir, name), "utf8");
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      throw new VaultDiskError("boot_read_failed", `reading ${name}: ${error?.code ?? "error"}`);
    }
  };
  const seenText = read(BOOT_SEEN_FILE);
  let seen = { seq: 0, version: 0 };
  if (seenText !== null) {
    const match = SEEN_FORM.exec(seenText);
    const seq = match === null ? NaN : Number(match[1]);
    const version = match === null ? NaN : Number(match[2]);
    if (!Number.isSafeInteger(seq) || !Number.isSafeInteger(version)) throw new VaultDiskError("boot_seen_invalid", `${BOOT_SEEN_FILE} is not {"seq","version"}`);
    seen = { seq, version };
  }
  const text = read(BOOT_FILE);
  if (text === null) return { record: null, version: 0, seen };
  const version = recordVersion(text);
  if (version === null || recordFormat(text) !== BOOT_FORMAT) throw new VaultDiskError("boot_record_unreadable", `${BOOT_FILE} is not a boot record`);
  return { record: text, version, seen };
}

/** The record on the disk and its version: `{record: null, version: 0}` without one. Throws VaultDiskError. */
export function readVaultRecord(dir) {
  let text;
  try {
    text = readFileSync(join(dir, VAULT_FILE), "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { record: null, version: 0 };
    throw new VaultDiskError("vault_read_failed", `reading ${VAULT_FILE}: ${error?.code ?? "error"}`);
  }
  const version = recordVersion(text);
  // A record this code cannot read is never served: the Worker would refuse it anyway, and its version is unknown.
  if (version === null) throw new VaultDiskError("vault_record_unreadable", `${VAULT_FILE} is not a vault record`);
  return { record: text, version };
}

/**
 * Write `text` as the vault's record: temp file (O_CREAT|O_EXCL, 0600), write, fsync, close, rename over `vault.v1`, fsync
 * the directory. `seams` replaces the fs calls in tests (a failure at any step). Throws VaultDiskError: `vault_write_failed`
 * before the rename (the temp file is removed, the previous record stays), `vault_write_uncertain` after it (the new
 * record is in place; the directory's fsync did not return).
 */
export function writeVaultRecord(dir, text, seams = {}) {
  writeAtomic(dir, VAULT_FILE, text, seams);
}

/** `writeVaultRecord`'s steps for any file of the directory (`vault.v1`, `boot.v1`, `boot.v1.seen`). */
export function writeAtomic(dir, name, text, seams = {}) {
  const fs = { openSync, writeSync, fsyncSync, closeSync, renameSync, rmSync, ...seams };
  const temp = join(dir, `.${name}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  let fd = null;
  let renamed = false;
  try {
    fd = fs.openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    const bytes = Buffer.from(text, "utf8");
    let at = 0;
    while (at < bytes.length) at += fs.writeSync(fd, bytes, at, bytes.length - at);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(temp, join(dir, name));
    renamed = true;
    const dirFd = fs.openSync(dir, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  } catch (error) {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // already failing
      }
    }
    if (!renamed) {
      try {
        fs.rmSync(temp, { force: true });
      } catch {
        // already failing
      }
    }
    throw new VaultDiskError(renamed ? "vault_write_uncertain" : "vault_write_failed", `writing ${name}: ${error?.code ?? error?.message ?? "error"}`);
  }
}

function answer(response, status, body) {
  if (body === null) {
    response.writeHead(status, { "cache-control": "no-store" });
    response.end();
    return;
  }
  const text = JSON.stringify(body);
  response.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), "cache-control": "no-store" });
  response.end(text);
}

/** A request's body as text, at most `max` bytes; null when it is longer (the read stops there). */
function readBody(request, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let over = false;
    request.on("data", (chunk) => {
      if (over) return;
      size += chunk.length;
      if (size > max) {
        over = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(over ? null : Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

/**
 * The request handler over `dir` (exported for the tests, which drive it without a socket too). Writes are serialized:
 * a PUT waits for the one before it, then reads the version on the disk again.
 */
export function vaultDiskHandler({ dir = VAULT_DIR, log = console.log, error = console.error, uid = process.getuid?.() ?? null, seams = {} } = {}) {
  let queue = Promise.resolve();
  let problemLogged = null;
  /** P4b: GET and PUT /v1/lane/boot, on the same queue as the vault's writes. */
  const boot = async (request, response) => {
    if (request.method === "GET") {
      request.resume();
      if (unavailable(response)) return;
      try {
        const { record, version, seen } = readBootRecord(dir);
        answer(response, 200, { record, highest_seen: Math.max(version, seen.version), seq: seen.seq });
      } catch (thrown) {
        error(`lane: boot box disk read failed: ${thrown?.code ?? "error"}`);
        answer(response, 500, { error: thrown?.code ?? "boot_read_failed" });
      }
      return;
    }
    const text = await readBody(request, VAULT_RECORD_MAX_BYTES);
    const version = text === null ? null : recordVersion(text);
    const seqHeader = request.headers["x-gray-boot-seq"];
    const seq = typeof seqHeader === "string" && /^[1-9][0-9]{0,15}$/.test(seqHeader) ? Number(seqHeader) : null;
    if (version === null || recordFormat(text) !== BOOT_FORMAT || seq === null || !Number.isSafeInteger(seq)) {
      answer(response, 400, { error: "invalid_record" });
      return;
    }
    const run = queue.then(() => {
      if (unavailable(response)) return;
      let held;
      try {
        held = readBootRecord(dir);
      } catch (thrown) {
        error(`lane: boot box disk read failed before a write: ${thrown?.code ?? "error"}`);
        answer(response, 500, { error: thrown?.code ?? "boot_read_failed" });
        return;
      }
      const highest = Math.max(held.version, held.seen.version);
      if (version <= highest) {
        log(`lane: boot box disk refused version ${version}: the disk has seen ${highest}`);
        answer(response, 409, { error: "boot_version_not_above", highest_seen: highest, seq: held.seen.seq });
        return;
      }
      if (seq < held.seen.seq) {
        log(`lane: boot box disk refused seq ${seq}: the disk has seen ${held.seen.seq}`);
        answer(response, 409, { error: "boot_seq_below", highest_seen: highest, seq: held.seen.seq });
        return;
      }
      try {
        writeAtomic(dir, BOOT_FILE, text, seams);
        writeAtomic(dir, BOOT_SEEN_FILE, bootSeenText({ seq, version }), seams);
      } catch (thrown) {
        error(`lane: boot box disk write of version ${version} failed: ${thrown?.message ?? "error"}`);
        answer(response, 500, { error: "boot_write_failed" });
        return;
      }
      log(`lane: boot box disk wrote version ${version} seq ${seq} (${Buffer.byteLength(text, "utf8")} bytes)`);
      answer(response, 204, null);
    });
    queue = run.catch(() => undefined);
    await run;
  };
  const unavailable = (response) => {
    const problem = vaultDirProblem(dir, uid);
    if (problem === null) {
      problemLogged = null;
      return false;
    }
    if (problemLogged !== problem) error(`lane: vault disk ${dir} is unusable (${problem}); the vault is unavailable`);
    problemLogged = problem;
    answer(response, 503, { error: "vault_disk_unavailable" });
    return true;
  };
  return async (request, response) => {
    const path = (request.url ?? "").split("?")[0];
    if ((path !== VAULT_DISK_PATH && path !== BOOT_DISK_PATH) || (request.method !== "GET" && request.method !== "PUT")) {
      request.resume();
      answer(response, 404, { error: "not_found" });
      return;
    }
    if (path === BOOT_DISK_PATH) {
      await boot(request, response);
      return;
    }
    if (request.method === "GET") {
      request.resume();
      if (unavailable(response)) return;
      try {
        const { record, version } = readVaultRecord(dir);
        answer(response, 200, { record, highest_seen: version });
      } catch (thrown) {
        error(`lane: vault disk read failed: ${thrown?.code ?? "error"}`);
        answer(response, 500, { error: thrown?.code ?? "vault_read_failed" });
      }
      return;
    }
    const text = await readBody(request, VAULT_RECORD_MAX_BYTES);
    const version = text === null ? null : recordVersion(text);
    if (version === null) {
      answer(response, 400, { error: "invalid_record" });
      return;
    }
    const run = queue.then(() => {
      if (unavailable(response)) return;
      let highest;
      try {
        highest = readVaultRecord(dir).version;
      } catch (thrown) {
        error(`lane: vault disk read failed before a write: ${thrown?.code ?? "error"}`);
        answer(response, 500, { error: thrown?.code ?? "vault_read_failed" });
        return;
      }
      if (version <= highest) {
        log(`lane: vault disk refused version ${version}: the disk has seen ${highest}`);
        answer(response, 409, { error: "vault_version_not_above", highest_seen: highest });
        return;
      }
      try {
        writeVaultRecord(dir, text, seams);
      } catch (thrown) {
        const code = thrown?.code === "vault_write_uncertain" ? "vault_write_uncertain" : "vault_write_failed";
        error(`lane: vault disk write of version ${version} failed (${code}): ${thrown?.message ?? "error"}`);
        answer(response, 500, { error: code });
        return;
      }
      log(`lane: vault disk wrote version ${version} (${Buffer.byteLength(text, "utf8")} bytes)`);
      answer(response, 204, null);
    });
    queue = run.catch(() => undefined);
    await run;
  };
}

/**
 * Serve the vault's disk on `socketPath` (a unix socket, mode 0600, on the lane container's own tmpfs). A socket file a
 * previous supervisor left is removed first. Resolves once listening, with `close()`.
 */
export async function startVaultDisk({ dir = VAULT_DIR, socketPath, log = console.log, error = console.error, uid, seams } = {}) {
  if (typeof socketPath !== "string" || !socketPath.startsWith("/")) throw new Error("the vault disk socket is an absolute path");
  rmSync(socketPath, { force: true });
  const handler = vaultDiskHandler({ dir, log, error, ...(uid === undefined ? {} : { uid }), ...(seams === undefined ? {} : { seams }) });
  const server = createServer((request, response) => {
    handler(request, response).catch((thrown) => {
      error(`lane: vault disk request failed: ${thrown?.message ?? "error"}`);
      if (!response.headersSent) answer(response, 500, { error: "vault_disk_error" });
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  // Owner only: workerd runs as this process's uid (the socket's directory, lane's own tmpfs, is 0700 as well).
  chmodSync(socketPath, 0o600);
  const problem = vaultDirProblem(dir, uid ?? process.getuid?.() ?? null);
  log(`lane: vault disk ${dir} on unix:${socketPath}${problem === null ? "" : ` (unusable: ${problem})`}`);
  return {
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
