import { parsePlain, toJsonString, type Json } from "@gray/json";
import { STACK_LOGIN_CODES, stackOwnCallSettings, type StackConfigDocument, type StackOwnCallSettings } from "@gray/lane-wire";
import {
  authHeaders,
  chatgptAccountId,
  egressValue,
  type Credential,
  type RelayVaultLogin,
  type StackSealedAccount,
} from "@gray/relay-connector";
import { z } from "zod";
import { LEASE_UNTIL_HEADER } from "./kms-lease.ts";
import { BridgeCallError } from "./remote/client.ts";
import { signInHandle, signsIn } from "./sign-in-proxy.ts";
import type { StackExclusion } from "./stack-document.ts";

/**
 * Own calls, the lane's half (docs/relay-changes-v2.md §6). Egress runs account upkeep on its own schedule from its
 * vendor operations table (deploy/tee/egress/stack_ops.go); this service gives it what it keeps up and takes back
 * what it refreshed. Nothing here starts an operation: the container has no route to one, and neither does this.
 *
 * **One round** (at most one at a time, at most once per `LANE_STACK_POLL_MS`, on the same traffic as the config
 * service: the relay's version polls and the credential intake):
 *
 * 1. `PUT /v1/stack/ops/accounts`: the panel's served accounts with the credential fields egress's templates read
 *    (the access token or API key, ChatGPT's account id, a refresh token when one is sealed), the sealed version, the
 *    proxy, and the panel's own-call settings: the relay's cadence for `limits` and `models`.
 *    Sent when it differs from the last one egress took, and at least every `LANE_STACK_OPS_RESEND_MS` (egress keeps
 *    the set in memory only, so a restarted egress gets it back within that).
 * 2. `GET /v1/stack/ops/tokens`: each token egress refreshed and the sealed version it was refreshed from. A token
 *    newer than the one held goes into the credential store (`applyRefreshed`), where it stands in for that sealed
 *    version: the config document's `credentials_version` moves, the container fetches it through `/credentials`, and
 *    egress's request table follows its hash. `onRefreshed` then rebuilds the document at once.
 *
 * **Persist first (P2e-2, docs/design/relay-no-always-on-host.md H12, I9).** With a vault (`persist`), the push says
 * `"persist_first": true`, and egress holds every new token family pending (egress stack_persist.go): it keeps using the
 * token it had until the lane acknowledges the family (`POST /v1/stack/ops/tokens/ack` with its seq). The lane writes the
 * family to the vault first (`LaneVault.persistToken`) and acknowledges only once it is on the disk; a family it could
 * not write is not acknowledged, and egress offers it again at the next round. An ack that was lost is sent again when
 * egress offers a family already written, without a second write. An account's installed token and pending family are
 * read as one state: while a family is pending, the installed token beside it (the one it replaces) is never taken, so
 * a lost ack cannot put the older family back into the store and onto the disk over the one the vendor issued last
 * (review 11-09b vm #1). The sign-in pacing egress reports (`logins`) goes into
 * the vault too, and back into the push (`login.pacing`) for egress to take after a restart.
 *
 * **Hold (P7, docs/design/relay-no-always-on-host.md 13.4).** During a rollout two instances hold the relay's accounts;
 * only the serving one refreshes and signs in. While this VM is not serving (draining, or its role unknown: `hold`), the
 * push says `"hold": true` and egress runs no refresh and no in-VM sign-in (stack_ops.go, stack_login.go), keeping the
 * tokens it holds for the requests this VM still serves; the push carries the accounts as before. The change is pushed
 * at once (the role's listener forces a round), and `hold: false` (absent) lets egress's schedule run again.
 *
 * No line it logs names a credential, a token or a header value: closed codes, account ids, counts.
 */

/** Egress's own-call control routes (unix socket). */
export const STACK_OPS_ACCOUNTS_URL = "http://egress/v1/stack/ops/accounts";
export const STACK_OPS_TOKENS_URL = "http://egress/v1/stack/ops/tokens";
/** P2e-2: the lane wrote a pending family to the vault (egress stack_persist.go). */
export const STACK_OPS_TOKENS_ACK_URL = "http://egress/v1/stack/ops/tokens/ack";
/** docs/design/relay-sign-in-in-vm.md §3.1: the sign-in proxy's handle map (egress signin_session.go). */
export const STACK_OPS_SIGN_IN_PROXY_URL = "http://egress/v1/stack/ops/sign-in-proxy";
/** How often the account set is sent even when unchanged: egress holds it in memory only. */
export const LANE_STACK_OPS_RESEND_MS = 60_000;

/**
 * The panel's own-call settings, as the console serves them in `stack.config` (the relay's `own_calls`, set in the
 * panel or the relay-stack document): `@gray/lane-wire` stackOwnCallSettings, which the console's tests hold to what a
 * console write serves.
 */
export type { StackOwnCallSettings };
export const ownCallSettings = stackOwnCallSettings;

/** What the service reads of the config service (`StackConfigService.healthView`). */
export interface StackOpsView {
  readonly metadata: StackConfigDocument | null;
  readonly excluded: readonly StackExclusion[] | null;
}

export interface StackOpsOptions {
  readonly relayId: string;
  readonly egress: { fetch(input: string, init: RequestInit): Promise<Response> } | undefined;
  readonly credentials: {
    stackAccounts(relayId: string, nowMs: number): readonly StackSealedAccount[];
    applyRefreshed(relayId: string, accountId: string, basedOn: bigint, credential: Credential): boolean;
  };
  readonly now: () => number;
  readonly pollMs: number;
  /** The panel's own-call settings; `ownCallSettings` of the metadata until P3's parsed config replaces it. */
  readonly settings?: (metadata: StackConfigDocument | null) => StackOwnCallSettings;
  /** A token was taken: rebuild the document and push egress's table now. */
  readonly onRefreshed?: () => Promise<void>;
  /**
   * P2c-2, review 11-09: the KMS lease's end the set is pushed with (`LEASE_UNTIL_HEADER`), egress's own bound on its own
   * calls; a changed end is a new push. Absent without a lease: no header.
   */
  readonly leaseUntil?: () => number;
  /**
   * P2e-2: the VM's vault, for persist first. Absent (phase 1): no `persist_first` in the push, and egress installs every
   * family at once, as before.
   */
  readonly persist?: StackOpsPersist;
  /** P7: whether this VM is not its relay's serving instance now (with `persist` only): egress refreshes and signs in nothing. */
  readonly hold?: () => boolean;
  readonly log?: (line: Record<string, unknown>) => void;
}

/** What persist first needs of the vault (`LaneVault`). */
export interface StackOpsPersist {
  persistToken(apply: () => boolean): Promise<"persisted" | "refused" | "failed">;
  /** A token taken without persist first (an egress that installed it at once) is written after the fact. */
  changed(reason: "token"): Promise<boolean>;
  pacingFor(accountId: string, username: string): RelayVaultLogin | null;
  notePacing(logins: readonly RelayVaultLogin[]): Promise<boolean>;
}

const u64Text = z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
const msTime = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
/** egress stack_persist.go `opsLoginPacing`. */
const pacingSchema = z
  .object({
    account_id: z.string().regex(/^[\x21-\x7e]{1,128}$/),
    username: z.string().min(1).max(254),
    failures: z.number().int().min(0).max(1_000_000),
    last: z
      .object({ outcome: z.enum(["ok", "failed"]), code: z.enum(STACK_LOGIN_CODES).nullable(), at_ms: msTime })
      .strict()
      .refine((l) => (l.outcome === "ok") === (l.code === null))
      .nullable(),
    last_ok_ms: msTime.nullable(),
  })
  .strict();
const tokensSchema = z
  .object({
    tokens: z.array(
      z
        .object({
          account_id: z.string().regex(/^[\x21-\x7e]{1,128}$/),
          based_on_version: u64Text,
          seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
          credential: z
            .object({ type: z.literal("oauth_access_token"), value: z.string().min(1).max(16_384), expires_at: z.number().int().positive().optional() })
            .strict(),
          refresh_token: z.string().min(1).max(16_384).nullable(),
          // P2e-2: a family egress holds pending until the lane acknowledges it.
          pending: z.literal(true).optional(),
        })
        .strict(),
    ),
    // P2e-2: the sign-in pacing, with persist first only.
    logins: z.array(pacingSchema).optional(),
    // P7 (13.4, the final mark): the refreshes, own calls and sign-ins egress runs now, with persist first only.
    in_flight: z.number().int().min(0).max(1_000_000).optional(),
  })
  .strict();
/** One entry of egress's tokens answer: an account's installed token, or (`pending`) the family it holds for the lane. */
type OpsToken = z.infer<typeof tokensSchema>["tokens"][number];

/** The reasons an account is left out of egress's set: the VM does not hold the credential the panel names. */
const NOT_HELD = new Set(["not_sealed", "vendor_mismatch", "credential_waiting", "invalid_credential", "proxy_unknown", "proxy_mismatch", "proxy_waiting"]);

function errorCode(error: unknown): string {
  if (error instanceof BridgeCallError) return error.code;
  return error instanceof Error ? error.name : "error";
}

/**
 * The credential fields egress's templates read, from a sealed credential (stack_ops_table.go stackOpsAccountFields). A
 * `password` account before its first sign-in has none: its token comes from the sign-in.
 */
export function opsCredentialFields(vendor: string, credential: Credential): Record<string, string> {
  if (credential.type === "api_key") return { api_key: credential.value };
  // A password or sign_in account before its first sign-in has none: its token comes from the sign-in.
  if (credential.type === "password" || credential.type === "sign_in") return {};
  const fields: Record<string, string> = { access_token: credential.value };
  if (vendor === "chatgpt_codex") fields.chatgpt_account_id = chatgptAccountId(credential.value);
  if (credential.refresh_token !== undefined) fields.refresh_token = credential.refresh_token;
  return fields;
}

/** egress's pacing as the vault keeps it (bigints, `@gray/relay-connector` RelayVaultLogin). */
function pacingOf(p: z.infer<typeof pacingSchema>): RelayVaultLogin {
  return {
    account_id: p.account_id,
    username: p.username,
    failures: BigInt(p.failures),
    last: p.last === null ? null : { outcome: p.last.outcome, code: p.last.code, at_ms: BigInt(p.last.at_ms) },
    last_ok_ms: p.last_ok_ms === null ? null : BigInt(p.last_ok_ms),
  };
}

/** The push's `login.pacing` (egress stack_persist.go `wireLoginPacing`), or nothing. */
function pacingMember(pacing: RelayVaultLogin | null): Record<string, Json> {
  if (pacing === null) return {};
  return {
    pacing: {
      failures: pacing.failures,
      last: pacing.last === null ? null : { outcome: pacing.last.outcome, code: pacing.last.code, at_ms: pacing.last.at_ms },
      last_ok_ms: pacing.last_ok_ms,
    },
  };
}

export class StackOpsService {
  readonly #options: StackOpsOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #polledAt: number | null = null;
  #running = false;
  /** A forced round was asked for while one ran: that round runs once more when it ends. */
  #again = false;
  /** The account set egress last took (with its lease end, when there is one), and when. */
  #sent: { readonly text: string; readonly at: number } | null = null;
  /** The highest token `seq` taken from egress, per account (a restarted egress numbers from 1 again: see #take). */
  #taken = new Map<string, { readonly seq: number; readonly value: string }>();
  /**
   * P2e-2: the pending family written to the vault, per account, whose ack egress has not taken yet, and the access token
   * egress listed as installed beside it when it was written (the family it replaces), if any.
   */
  #written = new Map<string, { readonly seq: number; readonly value: string; readonly replaces: string | null }>();
  /** P7: whether the account set egress last took carried `hold`. */
  #sentHold = false;
  /** P7: egress held, ran nothing and held no family pending, as of the last read. */
  #idle = false;

  constructor(options: StackOpsOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /**
   * One round (see above). `force` (P2c-2: the KMS lease changed) runs it whatever the interval, and once more after a
   * round already running, so a lease that stopped serving empties egress's set at once rather than at the next poll.
   * `view` is read when the round starts, so pass a function for a round that may run later.
   */
  async round(view: StackOpsView | (() => StackOpsView), force = false): Promise<void> {
    const viewNow = (): StackOpsView => (typeof view === "function" ? view() : view);
    if (this.#running) {
      if (force) this.#again = true;
      return;
    }
    const now = this.#options.now();
    if ((!force && this.#polledAt !== null && now - this.#polledAt < this.#options.pollMs) || viewNow().metadata === null) return;
    this.#running = true;
    try {
      if (this.#tokensRun !== null) await this.#tokensRun.catch(() => undefined);
      let again = true;
      while (again) {
        this.#again = false;
        const at = this.#options.now();
        this.#polledAt = at;
        const current = viewNow();
        if (current.metadata === null) break;
        await this.#push(current, at, force);
        await this.#readTokens();
        again = this.#again;
      }
    } finally {
      this.#running = false;
    }
  }

  /**
   * Sign-in inside the VM (docs/design/relay-sign-in-in-vm.md §4.2, "a round on every login-operation call"): egress's
   * tokens read now, without a push, so a sign-in's family egress holds pending is written and acknowledged within its
   * persist wait. Nothing while a round runs (it reads them itself), and at most once a second.
   */
  async tokensNow(): Promise<void> {
    const now = this.#options.now();
    if (this.#running || this.#tokensRun !== null || this.#sent === null || (this.#tokensReadAt !== null && now - this.#tokensReadAt < 1_000)) return;
    this.#tokensReadAt = now;
    this.#tokensRun = this.#readTokens().finally(() => {
      this.#tokensRun = null;
    });
    await this.#tokensRun;
  }
  /** The `tokensNow` read in flight: a round waits for it, so two reads never take one family twice. */
  #tokensRun: Promise<void> | null = null;
  #tokensReadAt: number | null = null;

  /** The `PUT /v1/stack/ops/accounts` body of now: served accounts only, in id order. */
  accountsBody(view: StackOpsView, now: number): string {
    const options = this.#options;
    const settings = (options.settings ?? ownCallSettings)(view.metadata);
    const notHeld = new Set((view.excluded ?? []).filter((e) => e.kind === "account" && NOT_HELD.has(e.reason)).map((e) => e.id));
    const sealed = new Map(options.credentials.stackAccounts(options.relayId, now).map((account) => [account.account_id, account]));
    const accounts: Json[] = [];
    for (const account of [...(view.metadata?.accounts ?? [])].sort((l, r) => (l.id < r.id ? -1 : l.id > r.id ? 1 : 0))) {
      const held = sealed.get(account.id);
      if (held === undefined || notHeld.has(account.id) || held.vendor !== account.vendor) continue;
      let fields: Record<string, string>;
      try {
        if (held.credential.type !== "password" && held.credential.type !== "sign_in") authHeaders(account.vendor, held.credential);
        fields = opsCredentialFields(account.vendor, held.credential);
      } catch {
        continue;
      }
      // A password account (docs/design/relay-in-cvm-login.md): egress holds its sign-in for the relay's sign-in calls;
      // the account is an access-token account (ChatGPT or Claude) whose token exists only in the VM.
      const login = held.login;
      const every: Record<string, bigint> = {};
      if (settings.everySeconds.limits !== undefined) every.limits = BigInt(settings.everySeconds.limits);
      if (settings.everySeconds.models !== undefined) every.models = BigInt(settings.everySeconds.models);
      accounts.push({
        account_id: account.id,
        vendor: account.vendor,
        // A sign_in account is a subscription (access-token) account whose token its sign-in in the VM makes.
        credential_type: login === undefined && held.credential.type !== "sign_in" ? held.credential.type : "oauth_access_token",
        // The version the account is the same one from (D9): egress keeps the token and the pending family it made from
        // it across a re-seal that changed nothing (stack_ops.go carries them while this is not past their `basedOn`).
        credential_version: (held.since ?? held.version).toString(),
        credential: fields,
        ...(held.credential.expires_at === undefined ? {} : { expires_at_s: held.credential.expires_at }),
        ...(held.egress === undefined || account.proxy_id === null ? {} : { proxy: egressValue(held.egress), proxy_id: account.proxy_id }),
        every_seconds: every,
        models: [...account.models],
        ...(login === undefined
          ? {}
          : {
              login: {
                username: login.username,
                password: login.password,
                ...(login.totp_secret === undefined ? {} : { totp_secret: login.totp_secret }),
                ...pacingMember(options.persist?.pacingFor(account.id, login.username) ?? null),
              },
            }),
      });
    }
    if (options.persist === undefined) return toJsonString({ accounts });
    return toJsonString(options.hold?.() === true ? { accounts, persist_first: true, hold: true } : { accounts, persist_first: true });
  }

  /** `PUT /v1/stack/ops/sign-in-proxy`'s body: each pushed subscription account's handle, in id order (no password, D3). */
  signInProxyBody(view: StackOpsView, now: number): string {
    const pushed = (parsePlain(this.accountsBody(view, now)) as { accounts: { account_id: string; vendor: string; credential_type: string }[] }).accounts;
    const accounts = pushed.filter((a) => signsIn(a.vendor, a.credential_type)).map((a) => ({ account: a.account_id, handle: signInHandle(this.#options.relayId, a.account_id) }));
    return toJsonString({ accounts });
  }

  async #pushSignInProxy(view: StackOpsView, now: number, force: boolean): Promise<void> {
    const body = this.signInProxyBody(view, now);
    const sent = this.#signInProxySent;
    if (!force && sent !== null && sent.text === body && now - sent.at < LANE_STACK_OPS_RESEND_MS) return;
    const answer = await this.#egress(STACK_OPS_SIGN_IN_PROXY_URL, { method: "PUT", headers: { "content-type": "application/json" }, body });
    if (answer === null) return;
    if (answer.status === 204) this.#signInProxySent = { text: body, at: now };
    else this.#log({ level: "warn", event: "lane_stack_ops_sign_in_proxy_failed", relay_id: this.#options.relayId, status: answer.status });
  }
  #signInProxySent: { readonly text: string; readonly at: number } | null = null;

  async #push(view: StackOpsView, now: number, force = false): Promise<void> {
    await this.#pushSignInProxy(view, now, force);
    const body = this.accountsBody(view, now);
    const until = this.#options.leaseUntil?.();
    // The lease's end is part of what egress holds: a changed end (a renewal, a refusal) is pushed even with the same set.
    const text = until === undefined ? body : `${body}\n${until}`;
    const sent = this.#sent;
    if (!force && sent !== null && sent.text === text && now - sent.at < LANE_STACK_OPS_RESEND_MS) return;
    const headers: Record<string, string> = { "content-type": "application/json", ...(until === undefined ? {} : { [LEASE_UNTIL_HEADER]: String(until) }) };
    const status = await this.#egress(STACK_OPS_ACCOUNTS_URL, { method: "PUT", headers, body });
    if (status === null) return;
    if (status.status === 204) {
      this.#sent = { text, at: now };
      this.#sentHold = this.#options.persist !== undefined && this.#options.hold?.() === true;
    } else this.#log({ level: "warn", event: "lane_stack_ops_push_failed", relay_id: this.#options.relayId, code: "status", status: status.status });
  }

  async #readTokens(): Promise<void> {
    const answer = await this.#egress(STACK_OPS_TOKENS_URL, { method: "GET" });
    if (answer === null || answer.status !== 200) return;
    let parsed: z.infer<typeof tokensSchema>;
    try {
      const result = tokensSchema.safeParse(parsePlain(answer.text));
      if (!result.success) throw new Error("invalid_document");
      parsed = result.data;
    } catch {
      this.#log({ level: "warn", event: "lane_stack_ops_tokens_failed", relay_id: this.#options.relayId, code: "invalid_document" });
      return;
    }
    // P7: idle under the hold: egress took the hold, runs nothing, and lists no family pending (one it listed before is
    // written and acknowledged by now: egress lists a family until its ack).
    this.#idle = this.#sentHold && parsed.in_flight === 0 && !parsed.tokens.some((token) => token.pending === true);
    // One account's installed token and pending family are one state (review 11-09b vm #1). egress lists the token it
    // uses beside the family it holds pending; the family is the newer of the two (made from that token's refresh token,
    // or by a sign-in after it), and once the vault holds it, it is the account's until egress confirms or drops it.
    const accounts = new Map<string, { installed?: OpsToken; pending?: OpsToken }>();
    for (const token of parsed.tokens) {
      const entry = accounts.get(token.account_id) ?? {};
      if (token.pending === true) entry.pending = token;
      else entry.installed = token;
      accounts.set(token.account_id, entry);
    }
    let taken = 0;
    let installed = 0;
    for (const entry of accounts.values()) {
      if (entry.pending !== undefined) {
        // The installed token is not taken while a family waits: it is the one the family replaces, and taking it would
        // put it back over a family already written (an ack that was lost), and then on the disk.
        if (await this.#takePending(entry.pending, entry.installed ?? null)) taken += 1;
      } else if (entry.installed !== undefined && this.#take(entry.installed)) {
        taken += 1;
        installed += 1;
      }
    }
    const persist = this.#options.persist;
    // A family egress installed at once (no persist first yet: its first push did not reach it) is written now.
    if (persist !== undefined && installed > 0) await persist.changed("token");
    if (persist !== undefined && parsed.logins !== undefined) {
      const written = await persist.notePacing(parsed.logins.map(pacingOf));
      if (!written) this.#log({ level: "warn", event: "lane_stack_ops_pacing_unpersisted", relay_id: this.#options.relayId });
    }
    if (taken > 0) {
      this.#log({ level: "info", event: "lane_stack_ops_tokens_taken", relay_id: this.#options.relayId, accounts: taken });
      await this.#options.onRefreshed?.();
    }
  }

  /**
   * P7 (docs/design/relay-no-always-on-host.md 13.4, the final mark): whether egress is idle under the hold as of the last
   * round: it took the hold (no refresh or sign-in starts), runs none, and holds no family pending (each it held is
   * written and acknowledged). What a draining instance waits for before its final mark.
   */
  idle(): boolean {
    return this.#idle && this.#options.hold?.() === true;
  }

  /**
   * One token from egress: taken when it is not the one already held. A family the vault holds and egress has not
   * confirmed yet (`#written`) stays the account's: an installed token other than it is not taken over it; the family
   * itself listed as installed is egress's confirmation (an ack whose answer was lost).
   */
  #take(token: OpsToken): boolean {
    const written = this.#written.get(token.account_id);
    if (written !== undefined) {
      // The family it replaced never goes back over it; any other token means egress no longer holds it pending (it
      // installed it, or a push or a restart dropped it), and is judged as before.
      if (written.replaces !== null && written.replaces === token.credential.value) return false;
      this.#written.delete(token.account_id);
    }
    const held = this.#taken.get(token.account_id);
    // A restarted egress numbers from 1 again; its token is still new when its value differs.
    if (held !== undefined && held.seq >= token.seq && held.value === token.credential.value) return false;
    const credential = this.#credentialOf(token);
    if (!this.#options.credentials.applyRefreshed(this.#options.relayId, token.account_id, BigInt(token.based_on_version), credential)) {
      this.#log({ level: "warn", event: "lane_stack_ops_token_refused", relay_id: this.#options.relayId, account_id: token.account_id });
      return false;
    }
    this.#recordTaken(token);
    return true;
  }

  #credentialOf(token: z.infer<typeof tokensSchema>["tokens"][number]): Credential {
    return {
      type: "oauth_access_token",
      value: token.credential.value,
      ...(token.credential.expires_at === undefined ? {} : { expires_at: BigInt(token.credential.expires_at) }),
      ...(token.refresh_token === null ? {} : { refresh_token: token.refresh_token }),
    };
  }

  /** A taken token: its seq for the next round. */
  #recordTaken(token: z.infer<typeof tokensSchema>["tokens"][number]): void {
    const held = this.#taken.get(token.account_id);
    const seq = Math.max(token.seq, (held?.seq ?? 0) + 1);
    this.#taken.set(token.account_id, { seq, value: token.credential.value });
  }

  /**
   * P2e-2, persist first: a family egress holds pending (`installed`: the token egress lists beside it, which it
   * replaces). Written to the vault, then acknowledged; one written before whose ack was lost is acknowledged again
   * without a second write, and stays the store's meanwhile. A family the store refuses (a newer sealed version replaced
   * its account) is left to egress, whose next push from the lane drops it.
   */
  async #takePending(token: OpsToken, installed: OpsToken | null): Promise<boolean> {
    const persist = this.#options.persist;
    const relayId = this.#options.relayId;
    if (persist === undefined) return false;
    const done = this.#written.get(token.account_id);
    if (done !== undefined && done.seq === token.seq && done.value === token.credential.value) {
      await this.#ack(token.account_id, token.seq);
      return false;
    }
    const credential = this.#credentialOf(token);
    const outcome = await persist.persistToken(() => this.#options.credentials.applyRefreshed(relayId, token.account_id, BigInt(token.based_on_version), credential));
    if (outcome !== "persisted") {
      this.#log({ level: "warn", event: outcome === "refused" ? "lane_stack_ops_token_refused" : "lane_stack_ops_token_unpersisted", relay_id: relayId, account_id: token.account_id });
      return false;
    }
    this.#written.set(token.account_id, { seq: token.seq, value: token.credential.value, replaces: installed?.credential.value ?? null });
    this.#recordTaken(token);
    await this.#ack(token.account_id, token.seq);
    return true;
  }

  /** `POST /v1/stack/ops/tokens/ack`: egress installs the family. A lost one is sent again at the next round. */
  async #ack(accountId: string, seq: number): Promise<void> {
    const answer = await this.#egress(STACK_OPS_TOKENS_ACK_URL, { method: "POST", headers: { "content-type": "application/json" }, body: toJsonString({ account_id: accountId, seq: BigInt(seq) }) });
    if (answer === null) return;
    if (answer.status === 204) {
      this.#written.delete(accountId);
      return;
    }
    this.#log({ level: "warn", event: "lane_stack_ops_ack_failed", relay_id: this.#options.relayId, account_id: accountId, status: answer.status });
    // 409: egress holds another family now (a newer one, or a push dropped it); the next round offers what it holds.
    if (answer.status === 409) this.#written.delete(accountId);
  }

  async #egress(url: string, init: RequestInit): Promise<{ readonly status: number; readonly text: string } | null> {
    const egress = this.#options.egress;
    if (egress === undefined) return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#options.pollMs);
    try {
      const response = await egress.fetch(url, { ...init, signal: controller.signal });
      return { status: response.status, text: await response.text() };
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_ops_egress_failed", relay_id: this.#options.relayId, code: errorCode(error) });
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
