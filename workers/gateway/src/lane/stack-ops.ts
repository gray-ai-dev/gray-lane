import { parsePlain, toJsonString, type Json } from "@gray/json";
import { stackOwnCallSettings, type StackConfigDocument, type StackOwnCallSettings } from "@gray/lane-wire";
import {
  authHeaders,
  chatgptAccountId,
  egressValue,
  type Credential,
  type RefreshedRequest,
  type RefreshedToken,
  type StackSealedAccount,
} from "@gray/relay-connector";
import { z } from "zod";
import { BridgeCallError } from "./remote/client.ts";
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
 *    proxy, and the panel's own-call settings: each account's refresh mode (`source`, the default: the relay's
 *    software refreshes outside the VM; `gray`: egress does) and the relay's cadence for `limits` and `models`.
 *    Sent when it differs from the last one egress took, and at least every `LANE_STACK_OPS_RESEND_MS` (egress keeps
 *    the set in memory only, so a restarted egress gets it back within that).
 * 2. `GET /v1/stack/ops/tokens`: each token egress refreshed and the sealed version it was refreshed from. A token
 *    newer than the one held goes into the credential store (`applyRefreshed`), where it stands in for that sealed
 *    version: the config document's `credentials_version` moves, the container fetches it through `/credentials`, and
 *    egress's request table follows its hash. `onRefreshed` then rebuilds the document at once.
 * 3. The write-back: tokens taken are held for gray-relay, which asks for them with a signed request
 *    (`POST /v1/aci/relay-credentials/refreshed`, `@gray/relay-connector` refreshed.ts) and writes each to the relay's
 *    account source. A token stays held until gray-relay acknowledges its `seq` or a newer sealed version replaces it.
 *
 * No line it logs names a credential, a token or a header value: closed codes, account ids, counts.
 */

/** Egress's own-call control routes (unix socket). */
export const STACK_OPS_ACCOUNTS_URL = "http://egress/v1/stack/ops/accounts";
export const STACK_OPS_TOKENS_URL = "http://egress/v1/stack/ops/tokens";
/** How often the account set is sent even when unchanged: egress holds it in memory only. */
export const LANE_STACK_OPS_RESEND_MS = 60_000;

/**
 * The panel's own-call settings, as the console serves them in `stack.config` (the relay's `own_calls` and each
 * account's `refresh`, set in the panel or the relay-stack document): `@gray/lane-wire` stackOwnCallSettings, which the
 * console's tests hold to what a console write serves.
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
  readonly log?: (line: Record<string, unknown>) => void;
}

const u64Text = z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
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
        })
        .strict(),
    ),
  })
  .strict();

/** The reasons an account is left out of egress's set: the VM does not hold the credential the panel names. */
const NOT_HELD = new Set(["not_sealed", "vendor_mismatch", "credential_waiting", "invalid_credential", "proxy_unknown", "proxy_mismatch", "proxy_waiting"]);

function errorCode(error: unknown): string {
  if (error instanceof BridgeCallError) return error.code;
  return error instanceof Error ? error.name : "error";
}

/** The credential fields egress's templates read, from a sealed credential (stack_ops_table.go stackOpsAccountFields). */
export function opsCredentialFields(vendor: string, credential: Credential): Record<string, string> {
  if (credential.type === "api_key") return { api_key: credential.value };
  const fields: Record<string, string> = { access_token: credential.value };
  if (vendor === "chatgpt_codex") fields.chatgpt_account_id = chatgptAccountId(credential.value);
  if (credential.refresh_token !== undefined) fields.refresh_token = credential.refresh_token;
  return fields;
}

export class StackOpsService {
  readonly #options: StackOpsOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #polledAt: number | null = null;
  #running = false;
  /** The account set egress last took, and when. */
  #sent: { readonly text: string; readonly at: number } | null = null;
  /** The highest token `seq` taken from egress, per account (a restarted egress numbers from 1 again: see #take). */
  #taken = new Map<string, { readonly seq: number; readonly value: string }>();
  /** Tokens held for gray-relay's write-back, by account. */
  #writeBack = new Map<string, RefreshedToken>();

  constructor(options: StackOpsOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** One round (see above). */
  async round(view: StackOpsView): Promise<void> {
    const now = this.#options.now();
    if (this.#running || (this.#polledAt !== null && now - this.#polledAt < this.#options.pollMs) || view.metadata === null) return;
    this.#running = true;
    this.#polledAt = now;
    try {
      await this.#push(view, now);
      await this.#readTokens();
    } finally {
      this.#running = false;
    }
  }

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
        authHeaders(account.vendor, held.credential);
        fields = opsCredentialFields(account.vendor, held.credential);
      } catch {
        continue;
      }
      const every: Record<string, bigint> = {};
      if (settings.everySeconds.limits !== undefined) every.limits = BigInt(settings.everySeconds.limits);
      if (settings.everySeconds.models !== undefined) every.models = BigInt(settings.everySeconds.models);
      accounts.push({
        account_id: account.id,
        vendor: account.vendor,
        credential_type: held.credential.type,
        credential_version: held.version.toString(),
        credential: fields,
        ...(held.credential.expires_at === undefined ? {} : { expires_at_s: held.credential.expires_at }),
        ...(held.egress === undefined || account.proxy_id === null ? {} : { proxy: egressValue(held.egress), proxy_id: account.proxy_id }),
        refresh: settings.refresh.get(account.id) ?? "source",
        every_seconds: every,
        models: [...account.models],
      });
    }
    return toJsonString({ accounts });
  }

  async #push(view: StackOpsView, now: number): Promise<void> {
    const text = this.accountsBody(view, now);
    const sent = this.#sent;
    if (sent !== null && sent.text === text && now - sent.at < LANE_STACK_OPS_RESEND_MS) return;
    const status = await this.#egress(STACK_OPS_ACCOUNTS_URL, { method: "PUT", headers: { "content-type": "application/json" }, body: text });
    if (status === null) return;
    if (status.status === 204) this.#sent = { text, at: now };
    else this.#log({ level: "warn", event: "lane_stack_ops_push_failed", relay_id: this.#options.relayId, code: "status", status: status.status });
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
    let taken = 0;
    for (const token of parsed.tokens) if (this.#take(token)) taken += 1;
    if (taken > 0) {
      this.#log({ level: "info", event: "lane_stack_ops_tokens_taken", relay_id: this.#options.relayId, accounts: taken });
      await this.#options.onRefreshed?.();
    }
  }

  /** One token from egress: taken when it is not the one already held. */
  #take(token: z.infer<typeof tokensSchema>["tokens"][number]): boolean {
    const held = this.#taken.get(token.account_id);
    // A restarted egress numbers from 1 again; its token is still new when its value differs.
    if (held !== undefined && held.seq >= token.seq && held.value === token.credential.value) return false;
    const credential: Credential = {
      type: "oauth_access_token",
      value: token.credential.value,
      ...(token.credential.expires_at === undefined ? {} : { expires_at: BigInt(token.credential.expires_at) }),
      ...(token.refresh_token === null ? {} : { refresh_token: token.refresh_token }),
    };
    if (!this.#options.credentials.applyRefreshed(this.#options.relayId, token.account_id, BigInt(token.based_on_version), credential)) {
      this.#log({ level: "warn", event: "lane_stack_ops_token_refused", relay_id: this.#options.relayId, account_id: token.account_id });
      return false;
    }
    const seq = Math.max(token.seq, (held?.seq ?? 0) + 1);
    this.#taken.set(token.account_id, { seq, value: token.credential.value });
    this.#writeBack.set(token.account_id, { account_id: token.account_id, seq, credential });
    return true;
  }

  /**
   * The tokens gray-relay has not acknowledged (`POST /v1/aci/relay-credentials/refreshed`): an acknowledged one,
   * and one whose account a newer sealed version replaced, are dropped.
   */
  writeBackTokens(request: RefreshedRequest): readonly RefreshedToken[] {
    if (request.relayId !== this.#options.relayId) return [];
    const current = new Map(this.#options.credentials.stackAccounts(this.#options.relayId, this.#options.now()).map((a) => [a.account_id, a.credential.value]));
    const out: RefreshedToken[] = [];
    for (const [accountId, token] of this.#writeBack) {
      const acked = request.acked.get(accountId);
      if ((acked !== undefined && acked >= token.seq) || current.get(accountId) !== token.credential.value) {
        this.#writeBack.delete(accountId);
        continue;
      }
      out.push(token);
    }
    return out.sort((l, r) => (l.account_id < r.account_id ? -1 : l.account_id > r.account_id ? 1 : 0));
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
