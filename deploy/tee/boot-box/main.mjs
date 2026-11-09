// The boot box helper's Node entry (docs/design/relay-no-always-on-host.md §3.5 step 3, 13.11 P2d). build.sh bundles it
// with esbuild (bundle.mjs beside this file) into the lane image as /srv/lane/boot-box.mjs; the measured pre-launch of a
// phase-2 app (deploy/tee/pre-launch.stack.sh) runs it once per attempt:
//
//   docker run --rm -i --pull never --network bridge --user 10001:10001 --read-only --cap-drop ALL \
//     --security-opt no-new-privileges --tmpfs /tmp --entrypoint node \
//     -v /var/run/dstack.sock:/var/run/dstack.sock -v /var/lib/gray-persist/relay:/persist -v <work>/box:/out \
//     <lane image by digest> /srv/lane/boot-box.mjs --socket /var/run/dstack.sock --persist /persist --out /out
//
// Its input is one JSON object on stdin, {bridge_url, key_seed, relay_id, relay_key} (the seed never in argv or env), its
// logic is workers/gateway/src/lane/prelaunch-boot-box.ts (`openBootBox`), and its answer is files in --out:
//
//   designated  login.json        {"password","registry","username"}        mode 0600
//               designation.json  the designation's JCS                       mode 0600
//               designation.sig   its signature, 128 lower hex                mode 0600
//   empty slot  empty             the reason code (EMPTY_SLOT_REASONS)        mode 0600
//
// Exit status: 0 with one of the two answers; 75 (EX_TEMPFAIL) when Gray's copy (with no disk record) or Gray's share is
// unavailable, so pre-launch waits and runs it again; 1 for anything else, which stops the boot. Standard output carries
// fixed lines only (`gray-boot-box: <words>`), never a value read at run time; pre-launch passes on only lines of that
// form. Why it needs the network: the copy and the share are bridge calls (Gray's measured code, nothing of the relay's in
// it but ciphertext until the share arrives sealed to this run's key), so it runs on Docker's default bridge, not on
// the compose's networks and never on the relay's.
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { join } from 'node:path';
import { argv, exit, stdin, stdout } from 'node:process';
import { StackConfigClient } from '../../../workers/gateway/src/lane/remote/stack.ts';
import {
  BOOT_BOX_FILE_MAX_BYTES,
  BootBoxFault,
  BootBoxUnavailable,
  openBootBox,
  stackBridgeKeyIdOf,
} from '../../../workers/gateway/src/lane/prelaunch-boot-box.ts';

const EX_TEMPFAIL = 75;
const GUEST_TIMEOUT_MS = 30_000;
const BRIDGE_TIMEOUT_MS = 30_000;
const NAMES = new Set(['boot.v1', 'boot.v1.seen']);

function say(line) {
  stdout.write(`gray-boot-box: ${line}\n`);
}

function args() {
  const out = {};
  const rest = argv.slice(2);
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!['--socket', '--persist', '--out'].includes(flag) || typeof value !== 'string' || !value.startsWith('/')) throw new Error('usage');
    out[flag.slice(2)] = value;
  }
  if (out.socket === undefined || out.persist === undefined || out.out === undefined) throw new Error('usage');
  return out;
}

async function readInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of stdin) {
    size += chunk.length;
    if (size > 4096) throw new Error('input too long');
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const keys = value !== null && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value).sort().join(',') : '';
  if (keys !== 'bridge_url,key_seed,relay_id,relay_key') throw new Error('input members');
  const { bridge_url: bridgeUrl, key_seed: keySeed, relay_id: relayId, relay_key: relayKey } = value;
  if (typeof bridgeUrl !== 'string' || !/^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/.test(bridgeUrl)) throw new Error('bridge_url');
  if (typeof keySeed !== 'string' || !/^[0-9a-f]{64}$/.test(keySeed)) throw new Error('key_seed');
  if (typeof relayId !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(relayId)) throw new Error('relay_id');
  if (typeof relayKey !== 'string' || !/^[0-9a-f]{64}$/.test(relayKey)) throw new Error('relay_key');
  return { bridgeUrl, keySeed: Uint8Array.from(Buffer.from(keySeed, 'hex')), relayId, relayKey };
}

/** One POST of the guest agent's prpc on its unix socket (dstack v0.6.1: v0 at /, v1 at /v1), its JSON answer. */
function guest(socketPath, path, body) {
  return new Promise((resolve, reject) => {
    const text = JSON.stringify(body);
    const request = httpRequest({
      socketPath,
      path,
      method: 'POST',
      headers: { host: 'localhost', 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) },
      timeout: GUEST_TIMEOUT_MS,
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) request.destroy(new Error(`${path} answered too much`));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        if (response.statusCode !== 200) return reject(new Error(`${path} answered ${response.statusCode}`));
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          reject(new Error(`${path} did not answer JSON`));
        }
      });
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error(`${path} timed out`)));
    request.on('error', reject);
    request.end(text);
  });
}

/** Write `text` to `dir/name` atomically and durably: a temporary file (0600), fsync, rename, fsync of the directory. */
function writeDurable(dir, name, text) {
  const temporary = join(dir, `.${name}.tmp`);
  const fd = openSync(temporary, 'w', 0o600);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, join(dir, name));
  const dirFd = openSync(dir, 'r');
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

function readSmall(dir, name) {
  if (!NAMES.has(name)) throw new Error('not a boot box file');
  const path = join(dir, name);
  let size;
  try {
    size = statSync(path).size;
  } catch (error) {
    if (error && error.code === 'ENOENT') return null;
    throw error;
  }
  if (size > BOOT_BOX_FILE_MAX_BYTES) return null;
  return readFileSync(path, 'utf8');
}

async function main() {
  const paths = args();
  const input = await readInput();
  const info = await guest(paths.socket, '/v1/Info', {});
  const appId = info?.app_id;
  if (typeof appId !== 'string' || !/^[0-9a-f]{40}$/.test(appId)) throw new BootBoxFault('guest_agent', 'no app id');
  const client = new StackConfigClient({
    baseUrl: input.bridgeUrl,
    keyId: await stackBridgeKeyIdOf(appId, input.keySeed),
    signingKey: input.keySeed,
    timeoutMs: BRIDGE_TIMEOUT_MS,
  });
  const outcome = await openBootBox({
    relayId: input.relayId,
    relayKey: input.relayKey,
    appId,
    bridge: client,
    async getKey(path) {
      const answer = await guest(paths.socket, '/GetKey', { path, purpose: '' });
      const key = typeof answer?.key === 'string' && /^[0-9a-f]{64}$/.test(answer.key) ? answer.key : null;
      if (key === null) throw new Error('GetKey answered no 32-byte key');
      return Uint8Array.from(Buffer.from(key, 'hex'));
    },
    async quote(reportData) {
      const answer = await guest(paths.socket, '/GetQuote', { report_data: Buffer.from(reportData).toString('hex') });
      if (typeof answer?.quote !== 'string' || !/^([0-9a-f]{2})+$/.test(answer.quote) || typeof answer?.event_log !== 'string') {
        throw new Error('GetQuote answered no quote and event log');
      }
      return { quote: answer.quote, eventLog: answer.event_log };
    },
    readFile: async name => readSmall(paths.persist, name),
    writeFile: async (name, text) => {
      if (!NAMES.has(name)) throw new Error('not a boot box file');
      writeDurable(paths.persist, name, text);
    },
  });
  if (outcome.kind === 'empty') {
    writeFileSync(join(paths.out, 'empty'), outcome.reason, { mode: 0o600, flag: 'wx' });
    say(`empty slot (${outcome.reason})`);
    return 0;
  }
  const { box } = outcome;
  const d = box.designation;
  // JCS of the designation (keys sorted; strings of checked forms, safe integers, null): what the relay signed after
  // the domain line, which pre-launch checks again with the guest's OpenSSL.
  const designation = `{"image":${JSON.stringify(d.image)},"issued_ms":${d.issuedMs},"previous":${JSON.stringify(d.previous)},"relay_id":${JSON.stringify(d.relayId)},"seq":${d.seq}}`;
  writeFileSync(join(paths.out, 'designation.json'), designation, { mode: 0o600, flag: 'wx' });
  writeFileSync(join(paths.out, 'designation.sig'), box.designationSig, { mode: 0o600, flag: 'wx' });
  writeFileSync(join(paths.out, 'login.json'), JSON.stringify({ password: box.registry.password, registry: box.registry.host, username: box.registry.username }), { mode: 0o600, flag: 'wx' });
  say(`boot box opened (version ${outcome.header.version}, designation ${d.seq})`);
  return 0;
}

main().then(code => exit(code), error => {
  if (error instanceof BootBoxUnavailable) {
    say(error.code === 'share_unavailable' ? 'share not available, retrying' : 'boot box copy not available, retrying');
    exit(EX_TEMPFAIL);
  }
  // The class of the failure and a closed code, never its message (a parse error's message may quote its input).
  if (error instanceof BootBoxFault) say(`failed (${error.code})`);
  else say(`failed (${error instanceof Error && /^[A-Za-z]{1,40}$/.test(error.name) ? error.name : 'error'}${typeof error?.code === 'string' && /^[a-z_]{1,40}$/i.test(error.code) ? ` ${error.code}` : ''})`);
  exit(1);
});
