import { parsePlain, toJsonString, type Json } from "@gray/json";
import {
  checkLoginView,
  RELAY_LOGIN_API_VERSION,
  RELAY_LOGIN_CODES,
  RELAY_LOGIN_FLOWS,
  RELAY_LOGIN_IDLE_MS,
  RELAY_LOGIN_MAX_SKEW_SECONDS,
  RELAY_LOGIN_SESSION_MS,
  type RelayLoginCallback,
  type RelayLoginCode,
  type RelayLoginFlow,
  type RelayLoginPrompt,
  type RelayLoginStart,
  type RelayLoginView,
} from "@gray/relay-connector";
import { z } from "zod";

/**
 * The login operation, the lane's half (docs/design/relay-sign-in-in-vm.md §1, §4.2, §5 S1/S4/S7): sign-in sessions
 * that `gray-assistant login <account>` opens through the attested tunnel, kept in memory for this boot only.
 *
 * - **Start** (`@gray/relay-connector` `readLoginStart` checked the relay's signature; the nonce is checked here): one
 *   session per relay at a time (design v3: another account's open session refuses it, 409 `login_session_busy`; a new
 *   start for the same account replaces its session), refused while this VM is not its relay's serving instance
 *   (`login_held`). The session's key is answered once; only its SHA-256 is kept.
 * - **Egress** holds the session too (it reads the vendor's answers through its sign-in proxy). The lane tells it of each
 *   session and asks it for the prompt and the outcome, over the control socket (the interface below).
 * - **Life**: 15 minutes at most (`RELAY_LOGIN_SESSION_MS`, or a device code's own expiry), and voided 30 s after the
 *   last call of gray-assistant (`RELAY_LOGIN_IDLE_MS`), so a person who left (Ctrl-C, a closed terminal, a lost
 *   network) leaves no session behind. `sweep` runs on every login call and on the lane's own traffic.
 * - **Pins (D7)**: an authorize URL's template (egress blanked its `state` and `code_challenge`) is pinned per (image
 *   digest, vendor, flow): the first one is written to the vault before the prompt is released; a later one that differs
 *   ends that prompt (egress's result `template`; the session stays open for another). Egress holds the image's pin
 *   table (`PUT /v1/stack/ops/login-pins`), pushed at every start and after every new pin.
 *
 * **Lane → egress** (unix socket, `http://egress`), egress's routes as `deploy/tee/egress/signin_session.go` defines them:
 *
 * - `PUT /v1/stack/ops/login-sessions/{account}` `{"session","expires_at_ms"}` → 204 (open or renew; egress caps a
 *   session at 30 min); 409 `login_account_unknown`-style refusals as `{"error":"<code>"}`.
 * - `GET /v1/stack/ops/login-sessions` → `{"as_of_ms","sessions":[{"account","session","expires_at_ms","flow","prompt",
 *   "pin_request","input_seq","result"}]}` (`EGRESS_SESSIONS_SCHEMA`); a session missing from it is gone.
 * - `PUT /v1/stack/ops/login-pins` `{"pins":[{"vendor","flow","template"}]}`: this image's whole pin table, from the vault.
 *   A `pin_request` is pinned in the vault first, then the table is pushed again.
 * - `POST …/{account}/input` `{"session","input"}` → 204; 422 `login_input_refused`.
 * - `POST …/{account}/callback` `{"session","method":"GET","path","query"}` → 202 `{"delivered":true}`.
 * - `DELETE …/{account}` → 204.
 *
 * Nothing logged names a token, a code, a URL or an input: events, account ids, closed codes.
 */

export const LOGIN_SESSIONS_URL = "http://egress/v1/stack/ops/login-sessions/";
export const LOGIN_SESSIONS_LIST_URL = "http://egress/v1/stack/ops/login-sessions";
export const LOGIN_PINS_URL = "http://egress/v1/stack/ops/login-pins";
/** An ended session stays readable this long, so gray-assistant's next poll learns why. */
export const ENDED_KEEP_MS = 60_000;
/** The longest a template is (the design's 2,048-byte URL with two values blanked). */
export const MAX_TEMPLATE_BYTES = 2048;
const EGRESS_TIMEOUT_MS = 5_000;

/** The vendors whose accounts sign in (design §3.5): one list, the proxy's. */
export { SIGN_IN_PROXY_VENDORS as SIGN_IN_VENDORS } from "./sign-in-proxy.ts";
import { SIGN_IN_PROXY_VENDORS as SIGN_IN_VENDORS } from "./sign-in-proxy.ts";

const safeInt = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/** What egress answers for its sessions (`GET /v1/stack/ops/login-sessions`, signin_session.go `loginSessionView`). */
export const EGRESS_SESSIONS_SCHEMA = z.object({
  as_of_ms: safeInt,
  sessions: z.array(
    z
      .object({
        account: z.string(),
        session: z.string(),
        expires_at_ms: safeInt,
        flow: z.string().nullable(),
        prompt: z
          .object({
            url: z.string().url().max(4096).regex(/^[\x21-\x7e]+$/).nullable().optional(),
            user_code: z.string().regex(/^[\x21-\x7e]{1,64}$/).nullable().optional(),
            verification_uri: z.string().url().max(2048).regex(/^[\x21-\x7e]+$/).nullable().optional(),
            expires_at_ms: safeInt.nullable().optional(),
            callback_port: z.number().int().min(1).max(65535).nullable().optional(),
          })
          .nullable(),
        pin_request: z.object({ vendor: z.string(), flow: z.enum(RELAY_LOGIN_FLOWS), template: z.string().min(1).max(MAX_TEMPLATE_BYTES) }).nullable(),
        input_seq: safeInt,
        result: z
          .object({ outcome: z.enum(["ok", "failed"]), code: z.string().regex(/^[a-z0-9_]{1,64}$/).nullable().optional(), at_ms: safeInt })
          .nullable(),
      })
      .passthrough(),
  ),
});
type EgressSession = z.infer<typeof EGRESS_SESSIONS_SCHEMA>["sessions"][number];

/** A loopback redirect's port and path, read from an authorize URL's `redirect_uri` (null for any other). */
export function loopbackRedirect(url: string): { readonly port: number; readonly path: string } | null {
  try {
    const redirect = new URL(new URL(url).searchParams.get("redirect_uri") ?? "");
    if (redirect.protocol !== "http:" || (redirect.hostname !== "localhost" && redirect.hostname !== "127.0.0.1")) return null;
    const port = Number(redirect.port || "80");
    return port >= 1 && port <= 65535 && /^\/[\x21-\x7e]{0,255}$/.test(redirect.pathname) ? { port, path: redirect.pathname } : null;
  } catch {
    return null;
  }
}


/** The pins of authorize-URL templates, per (image digest, vendor, flow): the vault's (`LaneVault`), or memory. */
export interface LoginPins {
  get(image: string, vendor: string, flow: RelayLoginFlow): string | null;
  /**
   * `persisted`: on the vault's disk before it answers; `boot_only`: kept for this boot only (a RAM-only relay's vault, or
   * no vault: accepted by the owner, design D7); `failed`: not kept (the prompt is not released yet).
   */
  put(image: string, vendor: string, flow: RelayLoginFlow, template: string): Promise<"persisted" | "boot_only" | "failed">;
  /** Every pin of one image, for egress's table. */
  forImage(image: string): readonly { readonly vendor: string; readonly flow: RelayLoginFlow; readonly template: string }[];
}

/** Pins in memory (a VM without a vault: they last for the boot). */
export class MemoryLoginPins implements LoginPins {
  readonly #pins = new Map<string, string>();
  get(image: string, vendor: string, flow: RelayLoginFlow): string | null {
    return this.#pins.get(`${image}|${vendor}|${flow}`) ?? null;
  }
  async put(image: string, vendor: string, flow: RelayLoginFlow, template: string): Promise<"boot_only"> {
    this.#pins.set(`${image}|${vendor}|${flow}`, template);
    return "boot_only";
  }
  forImage(image: string): readonly { readonly vendor: string; readonly flow: RelayLoginFlow; readonly template: string }[] {
    const out: { vendor: string; flow: RelayLoginFlow; template: string }[] = [];
    for (const [key, template] of this.#pins) {
      const [pinImage, vendor, flow] = key.split("|") as [string, string, RelayLoginFlow];
      if (pinImage === image) out.push({ vendor, flow, template });
    }
    return out;
  }
}

export interface LaneLoginOptions {
  readonly relayId: string;
  readonly egress: { fetch(input: string, init: RequestInit): Promise<Response> } | undefined;
  /** The relay's accounts the VM holds now (the credential store's), with their vendors. */
  readonly accounts: () => readonly { readonly account_id: string; readonly vendor: string; readonly credential: { readonly type: string } }[];
  /** The relay image's digest reference the pins are kept under; null outside a stack VM with an image. */
  readonly image: string | null;
  readonly pins: LoginPins;
  /** Whether this VM is not its relay's serving instance now (P7): no session opens or continues. */
  readonly held: () => boolean;
  readonly now: () => number;
  readonly random: (length: number) => Uint8Array;
  /** A login call came in: the lane reads egress's tokens now (a sign-in's family is persisted sooner). */
  readonly onActivity?: () => void;
  readonly log?: (line: Record<string, unknown>) => void;
}

/** A route's answer: the status and the JSON body. */
export interface LoginAnswer {
  readonly status: number;
  readonly body: Record<string, Json>;
}

interface Session {
  readonly id: string;
  /** Empty while the start that holds the session waits on egress. */
  keySha256: string;
  readonly accountId: string;
  readonly vendor: string;
  expiresMs: number;
  lastSeenMs: number;
  state: RelayLoginView["state"];
  prompt: RelayLoginPrompt | null;
  inputSeq: number;
  last: RelayLoginView["last"];
  code: RelayLoginCode | null;
  endedMs: number | null;
  /** Whether egress was told the session ended. */
  egressDropped: boolean;
  /** Browser returns forwarded (at most `MAX_CALLBACKS`). */
  callbacks: number;
}

/** A session takes at most this many forwarded browser returns; more is 429 `login_callback_limit`. */
export const MAX_CALLBACKS = 3;

function refusal(status: number, code: string, message: string): LoginAnswer {
  return { status, body: { error: { code, message } } };
}

export const UNKNOWN_SESSION = (): LoginAnswer => refusal(404, "login_session_unknown", "no open sign-in session with this id and key: run gray-assistant login again");

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

/** Equal-length hex compared without an early exit. */
function sameHex(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return diff === 0;
}

function loginCode(code: string | null | undefined, fallback: RelayLoginCode): RelayLoginCode {
  return code !== null && code !== undefined && (RELAY_LOGIN_CODES as readonly string[]).includes(code) ? (code as RelayLoginCode) : fallback;
}

export class LaneLoginSessions {
  readonly #options: LaneLoginOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  readonly #sessions = new Map<string, Session>();
  /** Start nonces seen, with when they may be forgotten (twice the skew: a start older than that is stale anyway). */
  readonly #nonces = new Map<string, number>();

  constructor(options: LaneLoginOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** Whether any session is open (the lane reads egress's tokens more often meanwhile). */
  get open(): boolean {
    for (const session of this.#sessions.values()) if (session.endedMs === null) return true;
    return false;
  }

  /** A checked start (the signature is `readLoginStart`'s). */
  async start(start: RelayLoginStart): Promise<LoginAnswer> {
    const now = this.#options.now();
    await this.sweep();
    if (start.relayId !== this.#options.relayId) return refusal(403, "unknown_relay", "this VM serves another relay");
    if (this.#nonces.has(start.nonce)) return refusal(409, "request_replayed", "this start was already taken: run gray-assistant login again");
    this.#nonces.set(start.nonce, now + 2 * RELAY_LOGIN_MAX_SKEW_SECONDS * 1000);
    const account = this.#options.accounts().find((a) => a.account_id === start.accountId);
    if (account === undefined) return refusal(404, "login_account_unknown", "this VM holds no such account: seal it first (gray-assistant accounts push)");
    if (!SIGN_IN_VENDORS.has(account.vendor) || account.credential.type === "api_key") {
      return refusal(409, "login_not_subscription", "this account is an API key, not a subscription: an API key needs no sign-in");
    }
    if (this.#options.held()) return refusal(503, "login_held", "this VM is being replaced by a new release: run the command again in a few minutes");
    if (this.#options.egress === undefined) return refusal(503, "egress_unavailable", "this VM's egress is not reachable");
    // Design v3: one session per relay at a time; a new start for the same account replaces its session.
    const other = [...this.#sessions.values()].find((s) => s.accountId !== account.account_id && s.endedMs === null);
    if (other !== undefined) {
      return { status: 409, body: { error: { code: "login_session_busy", message: "another sign-in of this relay is running", account_id: other.accountId, expires_at_ms: other.expiresMs } } };
    }
    const previous = [...this.#sessions.values()].find((s) => s.accountId === account.account_id && s.endedMs === null);
    const id = `ls_${base64url(this.#options.random(16))}`;
    const key = hex(this.#options.random(32));
    const expiresMs = now + RELAY_LOGIN_SESSION_MS;
    // Held in the map before the first await, so a second start racing this one sees it (one session per relay); taken
    // out again when egress refuses it.
    const session: Session = {
      id,
      keySha256: "",
      accountId: account.account_id,
      vendor: account.vendor,
      expiresMs,
      lastSeenMs: now,
      state: "waiting",
      prompt: null,
      inputSeq: 0,
      last: null,
      code: null,
      endedMs: null,
      egressDropped: false,
      callbacks: 0,
    };
    this.#sessions.set(id, session);
    const withdraw = (answer: LoginAnswer): LoginAnswer => {
      this.#sessions.delete(id);
      return answer;
    };
    if (previous !== undefined) await this.#end(previous, "replaced");
    const image = this.#options.image;
    // Egress keeps pins in memory: the image's table goes with every start (an egress restart lost it).
    if (image !== null) await this.#pushPins(image);
    const put = await this.#egress(`${LOGIN_SESSIONS_URL}${encodeURIComponent(account.account_id)}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: toJsonString({ session: id, expires_at_ms: BigInt(expiresMs) }),
    });
    if (put === null) return withdraw(refusal(503, "egress_unavailable", "this VM's egress did not answer: try again"));
    if (put.status !== 204) {
      const code = errorOf(put.text);
      if (code === "login_held") return withdraw(refusal(503, "login_held", "this VM is being replaced by a new release: run the command again in a few minutes"));
      if (code === "login_account_unknown") return withdraw(refusal(404, "login_account_unknown", "this VM's egress holds no such account yet: try again in a minute"));
      if (code === "route_refused" || put.status === 404 || put.status === 405) return withdraw(refusal(501, "login_unsupported", "this VM's Gray release has no sign-in inside the VM yet"));
      this.#log({ level: "warn", event: "lane_login_start_refused", relay_id: this.#options.relayId, account_id: account.account_id, status: put.status, code });
      return withdraw(refusal(502, "egress_refused", "this VM's egress refused the session"));
    }
    session.keySha256 = await sha256Hex(key);
    this.#log({ level: "info", event: "lane_login_started", relay_id: this.#options.relayId, account_id: account.account_id });
    this.#options.onActivity?.();
    return { status: 200, body: { ...this.#view(session), key } };
  }

  /** `GET …/{session}`: the view, after egress's state is read. */
  async view(id: string, key: string): Promise<LoginAnswer> {
    const session = await this.#open(id, key);
    if (session === null) return UNKNOWN_SESSION();
    await this.#refresh(session);
    return { status: 200, body: this.#view(session) };
  }

  /** `POST …/{session}/input`: a paste, for a prompt that takes one. */
  async input(id: string, key: string, text: string): Promise<LoginAnswer> {
    const session = await this.#open(id, key);
    if (session === null) return UNKNOWN_SESSION();
    await this.#refresh(session);
    if (session.endedMs !== null) return { status: 200, body: this.#view(session) };
    if (session.prompt === null || session.prompt.kind !== "url" || session.prompt.flow === "callback") {
      return refusal(409, "login_input_unexpected", "this sign-in does not take a pasted input now");
    }
    const sent = await this.#egress(`${LOGIN_SESSIONS_URL}${encodeURIComponent(session.accountId)}/input`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: toJsonString({ session: session.id, input: text }),
    });
    if (sent === null) return refusal(503, "egress_unavailable", "this VM's egress did not answer: paste it again");
    if (sent.status !== 204) return refusal(errorOf(sent.text) === "login_session_unknown" ? 409 : 422, "login_input_refused", "the VM did not take the input: paste it again");
    session.inputSeq += 1;
    this.#options.onActivity?.();
    return { status: 200, body: this.#view(session) };
  }

  /** `POST …/{session}/callback`: the browser's request line, for a `callback` prompt; egress delivers it to the container. */
  async callback(id: string, key: string, callback: RelayLoginCallback): Promise<LoginAnswer> {
    const session = await this.#open(id, key);
    if (session === null) return UNKNOWN_SESSION();
    await this.#refresh(session);
    if (session.endedMs !== null) return { status: 200, body: this.#view(session) };
    const prompt = session.prompt;
    if (prompt === null || prompt.kind !== "url" || prompt.flow !== "callback" || prompt.callback === null) {
      return refusal(409, "login_callback_unexpected", "this sign-in does not take a browser callback now");
    }
    if (callback.method !== "GET" || callback.path !== prompt.callback.path) return refusal(422, "login_callback_path", "the browser came back to another path than the sign-in named");
    if (session.callbacks >= MAX_CALLBACKS) return refusal(429, "login_callback_limit", "this sign-in took its browser returns already: run gray-assistant login again");
    session.callbacks += 1;
    const sent = await this.#egress(`${LOGIN_SESSIONS_URL}${encodeURIComponent(session.accountId)}/callback`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: toJsonString({ session: session.id, method: "GET", path: callback.path, query: callback.query }),
    });
    if (sent === null) return refusal(503, "egress_unavailable", "this VM's egress did not answer: try the address again");
    if (sent.status !== 202 && sent.status !== 204) return refusal(502, "login_callback_failed", "the VM could not hand the browser's return to your software");
    session.inputSeq += 1;
    this.#options.onActivity?.();
    return { status: 200, body: this.#view(session) };
  }

  /** `DELETE …/{session}`: the person left. */
  async cancel(id: string, key: string): Promise<LoginAnswer> {
    const session = await this.#open(id, key);
    if (session === null) return UNKNOWN_SESSION();
    if (session.endedMs === null) await this.#end(session, "cancelled");
    return { status: 204, body: {} };
  }

  /** Ends every expired or idle session and forgets old nonces and ended sessions; never throws. */
  async sweep(): Promise<void> {
    const now = this.#options.now();
    for (const [nonce, until] of this.#nonces) if (until <= now) this.#nonces.delete(nonce);
    for (const session of [...this.#sessions.values()]) {
      if (session.endedMs !== null) {
        if (!session.egressDropped) await this.#dropAtEgress(session);
        if (now - session.endedMs >= ENDED_KEEP_MS) this.#sessions.delete(session.id);
        continue;
      }
      if (now >= session.expiresMs) await this.#end(session, "expired");
      else if (now - session.lastSeenMs >= RELAY_LOGIN_IDLE_MS) await this.#end(session, "idle");
    }
  }

  /** The session of `id` whose key is `key`, renewed; null for an unknown one or a wrong key (one answer for both). */
  async #open(id: string, key: string): Promise<Session | null> {
    await this.sweep();
    const session = this.#sessions.get(id);
    const keyHash = await sha256Hex(key);
    if (session === undefined || !sameHex(session.keySha256, keyHash)) return null;
    if (session.endedMs === null) session.lastSeenMs = this.#options.now();
    this.#options.onActivity?.();
    return session;
  }

  /** Egress's state of an open session, with the pin of a new authorize URL written before egress releases it. */
  async #refresh(session: Session): Promise<void> {
    if (session.endedMs !== null) return;
    if (this.#options.held()) {
      await this.#end(session, "held");
      return;
    }
    const answer = await this.#egress(LOGIN_SESSIONS_LIST_URL, { method: "GET" });
    if (answer === null || answer.status !== 200) return;
    let held: EgressSession | undefined;
    try {
      const parsed = EGRESS_SESSIONS_SCHEMA.safeParse(parsePlain(answer.text));
      if (!parsed.success) throw new Error("invalid_document");
      held = parsed.data.sessions.find((s) => s.account === session.accountId && s.session === session.id);
    } catch {
      this.#log({ level: "warn", event: "lane_login_egress_invalid", relay_id: this.#options.relayId, account_id: session.accountId });
      return;
    }
    if (held === undefined) {
      // Egress restarted (its sessions are memory only), or its own clock ended the session.
      await this.#end(session, this.#options.now() >= session.expiresMs - 1_000 ? "expired" : "restarted");
      return;
    }
    session.inputSeq = Math.max(session.inputSeq, held.input_seq);
    if (held.result !== null) {
      const code = held.result.outcome === "ok" ? null : held.result.code === "template" ? "prompt_refused" : loginCode(held.result.code, "vendor_rejected");
      session.last = { outcome: held.result.outcome, code, at_ms: held.result.at_ms };
      if (held.result.outcome === "ok") {
        // Egress reports `ok` once the exchange's family is in the vault (persist first).
        session.state = "signed_in";
        session.prompt = null;
        session.endedMs = this.#options.now();
        this.#log({ level: "info", event: "lane_login_signed_in", relay_id: this.#options.relayId, account_id: session.accountId });
        await this.#dropAtEgress(session);
        return;
      }
      // A refused template drops the prompt at egress (the session stays open for another).
      if (code === "prompt_refused") {
        session.prompt = null;
        session.state = "waiting";
      }
    }
    if (held.pin_request !== null) {
      await this.#pin(session, held.pin_request);
      return;
    }
    // The prompt as egress shows it now: a new device code (the program asked again) or a new URL replaces the old one.
    const next = this.#promptOf(held, session);
    if (next === undefined) return;
    if (next === null) {
      if (session.prompt !== null && held.result?.code === "template") session.prompt = null;
      return;
    }
    if (session.prompt === null || JSON.stringify(session.prompt) !== JSON.stringify(next)) {
      if (next.kind === "device_code") session.expiresMs = Math.min(session.expiresMs, next.expires_at_ms);
      session.prompt = next.kind === "device_code" ? { ...next, expires_at_ms: session.expiresMs } : next;
      session.state = "prompt";
    }
  }

  /** egress's prompt as the view shows it; null for none, undefined for one the view cannot show. */
  #promptOf(held: EgressSession, session: Session): RelayLoginPrompt | null | undefined {
    const prompt = held.prompt;
    if (prompt === null) return null;
    if (typeof prompt.user_code === "string" && typeof prompt.verification_uri === "string") {
      const expires = typeof prompt.expires_at_ms === "number" ? Math.min(session.expiresMs, prompt.expires_at_ms) : session.expiresMs;
      return { kind: "device_code", url: prompt.verification_uri, code: prompt.user_code, expires_at_ms: expires };
    }
    if (typeof prompt.url !== "string") return undefined;
    const flow = held.flow;
    if (flow !== "code" && flow !== "callback" && flow !== "callback_input") return undefined;
    // The browser's return: egress names its port for `callback`; the path (and `callback_input`'s port) is the URL's own
    // `redirect_uri`, which egress checked to be a loopback address.
    const redirect = flow === "code" ? null : loopbackRedirect(prompt.url);
    const callback = redirect === null ? null : { port: typeof prompt.callback_port === "number" ? prompt.callback_port : redirect.port, path: redirect.path };
    return { kind: "url", flow, url: prompt.url, callback, expires_at_ms: session.expiresMs };
  }

  /** D7: a pin egress asks for, written to the vault first, then the image's whole table pushed back. */
  async #pin(session: Session, request: { readonly vendor: string; readonly flow: RelayLoginFlow; readonly template: string }): Promise<void> {
    const image = this.#options.image;
    if (image === null || request.vendor !== session.vendor) return;
    if (this.#options.pins.get(image, request.vendor, request.flow) === null) {
      const kept = await this.#options.pins.put(image, request.vendor, request.flow, request.template);
      if (kept === "boot_only") this.#log({ level: "info", event: "lane_login_pin_boot_only", relay_id: this.#options.relayId, vendor: request.vendor, flow: request.flow });
      if (kept === "failed") {
        this.#log({ level: "warn", event: "lane_login_pin_unpersisted", relay_id: this.#options.relayId, account_id: session.accountId, flow: request.flow });
        return; // the next poll tries again; the person sees nothing yet
      }
      this.#log({ level: "info", event: "lane_login_pinned", relay_id: this.#options.relayId, vendor: request.vendor, flow: request.flow });
    }
    // A different pin already held: egress ends that prompt (`template`) when it takes the table.
    await this.#pushPins(image);
  }

  async #pushPins(image: string): Promise<void> {
    const pins = this.#options.pins.forImage(image).map((pin) => ({ vendor: pin.vendor, flow: pin.flow, template: pin.template }));
    const answer = await this.#egress(LOGIN_PINS_URL, { method: "PUT", headers: { "content-type": "application/json" }, body: toJsonString({ pins }) });
    if (answer !== null && answer.status !== 204) this.#log({ level: "warn", event: "lane_login_pins_refused", relay_id: this.#options.relayId, status: answer.status });
  }

  async #end(session: Session, code: RelayLoginCode): Promise<void> {
    if (session.endedMs !== null) return;
    session.state = "ended";
    session.code = code;
    session.prompt = null;
    session.endedMs = this.#options.now();
    this.#log({ level: "info", event: "lane_login_ended", relay_id: this.#options.relayId, account_id: session.accountId, code });
    await this.#dropAtEgress(session);
  }

  async #dropAtEgress(session: Session): Promise<void> {
    // Egress's DELETE closes the account's session, whichever it is: only one that is still this one is closed.
    if (this.#sessions.get(session.id) !== session || [...this.#sessions.values()].some((s) => s !== session && s.accountId === session.accountId && s.endedMs === null)) {
      session.egressDropped = true;
      return;
    }
    const answer = await this.#egress(`${LOGIN_SESSIONS_URL}${encodeURIComponent(session.accountId)}`, { method: "DELETE" });
    // 404: egress holds no such session any more, which is what the DELETE asks for.
    if (answer !== null && (answer.status === 204 || answer.status === 404)) session.egressDropped = true;
  }

  #view(session: Session): Record<string, Json> {
    const view: RelayLoginView = checkLoginView({
      api_version: RELAY_LOGIN_API_VERSION,
      session: session.id,
      account_id: session.accountId,
      vendor: session.vendor,
      state: session.state,
      expires_at_ms: session.expiresMs,
      prompt: session.prompt,
      input_seq: session.inputSeq,
      last: session.last,
      code: session.code,
    });
    // The checked view is plain JSON data already (strings, numbers, null, nested objects).
    return view as unknown as Record<string, Json>;
  }

  async #egress(url: string, init: RequestInit): Promise<{ readonly status: number; readonly text: string } | null> {
    const egress = this.#options.egress;
    if (egress === undefined) return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), EGRESS_TIMEOUT_MS);
    try {
      const response = await egress.fetch(url, { ...init, signal: controller.signal });
      return { status: response.status, text: await response.text() };
    } catch (error) {
      this.#log({ level: "warn", event: "lane_login_egress_failed", relay_id: this.#options.relayId, code: error instanceof Error ? error.name : "error" });
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** egress's `{"error":"<code>"}` (or `{"error":{"code"}}`), or null. */
function errorOf(text: string): string | null {
  try {
    const value = parsePlain(text) as unknown;
    if (typeof value !== "object" || value === null) return null;
    const error = (value as Record<string, unknown>)["error"];
    if (typeof error === "string") return error;
    if (typeof error === "object" && error !== null && typeof (error as Record<string, unknown>)["code"] === "string") return (error as Record<string, string>)["code"] ?? null;
    return null;
  } catch {
    return null;
  }
}
