import { STACK_WAITING_EXCLUSIONS, type StackAccountState, type StackAccountStateReason, type StackAttemptClass } from "./stack-health.ts";
import type { StackReport, StackReportAccount, StackReportCooling } from "./stack-report.ts";

/**
 * One state per account of a relay stack (docs/confidential-lane-supply-implementation.md S46, review C1/C4), from the
 * VM's latest report, the panel's account and the attempts by class the request index kept. Pure: its readers read,
 * this decides. The console's panel, alerts and lane uptime pass (workers/console/src/lane-stack/state.ts re-exports it)
 * and gray-jobs' snapshot rebuild (which routes of a relay stack an account can serve, `stackRouteCovered`) read the
 * same rule. The words are STACK_ACCOUNT_STATES and STACK_ACCOUNT_STATE_REASONS (stack-health.ts), the panel's contract.
 *
 * Precedence, first match wins (S46):
 * 1. `not_served`: an exclusion other than the waiting ones; also an active account the latest report does not list
 *    (`not_reported`), or every account when the VM's configuration was refused (`config_refused`).
 * 2. `waiting_credential`: `not_sealed`, `credential_waiting`, `proxy_waiting`, `login_waiting` (a password account the
 *    relay's software has not signed in inside the VM yet), or no sealed credential.
 * 3. `paused`: paused in the panel or in the report.
 * 4. `held`: an enforced hold (the reason is its class; the panel says "banned · replace" for forbidden, restricted,
 *    billing and auth). An account-wide hold before one model's.
 * 5. `at_limit`: an enforced cool of class `window_exhausted`, a window `rejected`, or `used_percent` ≥ 100, while its
 *    reset is ahead; `until_ms` the latest of their ends.
 * 6. `cooling`: an enforced cool; `until_ms` the latest end of the account-wide ones (or of one model's).
 * 7. `proxy_failing`: ≥ 5 `proxy` attempts and none `ok` in 15 min.
 * 8. `credential_expiring`: the sealed credential's renewal is overdue (`renewalOverdue`: under a quarter of its sealed
 *    length left, at most 24 h ahead, or ended) and no `ok` agent login covers it; for an account the relay renews in
 *    the VM (by the report's `login`, or on a later boot by the console's memory of it), only once its token ended
 *    (`credentialEndingMs`).
 * 9. `failing`: ≥ 20 attempts in 1 h, at least half of them failures (FAILURE_CLASSES).
 * 10. `serving`.
 *
 * Observe-mode entries (`observed`) refuse nothing, so they decide no state; the panel lists them beside it. An entry
 * or window whose end has passed is over even when the report that named it is older. Times are the report's minutes.
 */

/** S46 row 7: proxy attempts in the window, none ok [推算: replaced by measured values from observe mode]. */
export const PROXY_FAILING_MIN = 5;
export const PROXY_FAILING_WINDOW_MS = 15 * 60_000;
/** S46 row 9: attempts in the window, the failure share [推算]. */
export const FAILING_MIN_ATTEMPTS = 20;
export const FAILING_WINDOW_MS = 60 * 60_000;
/**
 * S45: a sealed credential or the VM's credential lease is shown as ending once its renewal is overdue: less than
 * `RENEWAL_OVERDUE_SHARE` of its own length left (or it ended), and never more than `EXPIRING_WITHIN_MS` ahead.
 *
 * gray-assistant renews a lease once `renew_fraction` of it passed (relay-kit daemon.ts `#renewalDue`; the kit's defaults
 * are `lease_lifetime` 3600 s and `renew_fraction` 0.5, relay-kit init.ts), so a healthy lease keeps at least half its
 * length; a quarter left is a renewal half its margin late (15 minutes for the default lease). A lease is at most
 * `MAX_CREDENTIAL_LEASE_SECONDS` (86 400 s, relay-connector lease.ts), so a fixed day held every lease, renewed or not:
 * the rehearsal of 2026-11-03 showed "ends …" on a relay whose lease gray-assistant renewed every half hour. A sealed
 * credential that gray-assistant re-seals whenever its source refreshes it is read the same way, its length from the seal
 * (a clock version) to its end; with no length known it keeps the day.
 */
export const EXPIRING_WITHIN_MS = 24 * 60 * 60_000;
export const RENEWAL_OVERDUE_SHARE = 0.25;
/** A credential version at or above this is the seal's time in milliseconds (the panel's `isClockVersion`), not a counter. */
const CLOCK_VERSION_MIN = 1_000_000_000_000;

/**
 * Whether what ends at `endsMs` is past its renewal at `nowMs`: under `RENEWAL_OVERDUE_SHARE` of its length left (or
 * ended), the length from `givenMs` when known (else `fallbackMs`, else only the day), at most `EXPIRING_WITHIN_MS` ahead.
 */
export function renewalOverdue(endsMs: number, givenMs: number | null, nowMs: number, fallbackMs: number | null = null): boolean {
  const length = givenMs !== null && givenMs < endsMs ? endsMs - givenMs : fallbackMs;
  const margin = length === null ? EXPIRING_WITHIN_MS : Math.min(EXPIRING_WITHIN_MS, length * RENEWAL_OVERDUE_SHARE);
  return endsMs - nowMs < margin;
}

/** When a sealed credential was sealed, from its version when that is a clock; null for a counter. */
const sealedAtMs = (version: number): number | null => (version >= CLOCK_VERSION_MIN ? version : null);

/**
 * How long past its end the token of an account the relay renews in the VM may be before the account is shown as
 * expired: the relay's software refreshes ahead of the end, and the report naming the new token comes a moment later.
 */
export const RENEWED_IN_VM_GRACE_MS = 15 * 60_000;
/**
 * An account the relay's software renews inside the VM (docs/design/relay-sign-in-in-vm.md): the report's `login`, whose
 * `by` is `relay`. Not `login.vm_sign_in`, which reads false once a refresh in the VM re-sealed the account as a token
 * (the gateway's stack-health.ts reads it off the sealed credential's type).
 */
export const renewedInVm = (report: Pick<StackReportAccount, "login">): boolean => report.login?.by === "relay";

/**
 * What the console remembers of a report in which the relay renews the account in the VM (`renewedInVm`): the sealed
 * version that report names, else null. Egress keeps `login` in memory only (deploy/tee/egress/signin_session.go), so a
 * new boot (a release move, a restart) reports none until the relay's software next exchanges a token through the
 * sign-in proxy; the console keeps this across reports (lane_stack_account_state.renewed_in_vm_version) and hands it
 * back as `StateInput.renewedInVmVersion`.
 */
export const renewedInVmVersion = (report: Pick<StackReportAccount, "sealed" | "login">): number | null =>
  renewedInVm(report) && report.sealed !== null ? report.sealed.version : null;

/**
 * Whether the relay renews the account in the VM by the report or by what the console remembers: an earlier report
 * showed it renewing the credential the VM still holds (`rememberedVersion`, `renewedInVmVersion` of that report, is the
 * report's sealed version). Egress keeps a refreshed token under the first seal's version, and the vault hands it to
 * the next boot under the same one; a credential sealed again from the source (a new version) is the source's to renew
 * until a report shows the relay renewing it again.
 */
export function renewedInVmNow(report: Pick<StackReportAccount, "sealed" | "login">, rememberedVersion: number | null): boolean {
  if (renewedInVm(report)) return true;
  return rememberedVersion !== null && report.sealed !== null && report.sealed.version === rememberedVersion;
}

/**
 * When an account's sealed credential ends, if the panel shows it as ending now (`credential_expiring`), else null.
 * `renewalOverdue` for a credential the source renews. For one the relay renews in the VM (`renewedInVmNow`), only once
 * it ended `RENEWED_IN_VM_GRACE_MS` ago: egress keeps each refreshed token with the first seal's version, so the length
 * `renewalOverdue` measures from the seal grows with every refresh, a quarter of it outlasts a whole token, and such an
 * account read "expiring" most of the time, with an "Accounts that need attention" alert every few hours (Roteo, kit
 * 1.9.0). A refresh moves the token's end later, so the account reads as ended only when its token ended and no report
 * since named a later one. `rememberedVersion` keeps the rule on a new boot whose report has no `login` yet (Roteo,
 * 2026-11-25: an account read "ends soon" from a release move until its next refresh, six hours ahead). Routing reads
 * none of this: the state is the panel's, the alerts' and the setup status's.
 */
export function credentialEndingMs(report: Pick<StackReportAccount, "sealed" | "login">, nowMs: number, rememberedVersion: number | null = null): number | null {
  const sealed = report.sealed;
  if (sealed === null || sealed.expires_at_s === null) return null;
  const endsMs = sealed.expires_at_s * 1000;
  if (renewedInVmNow(report, rememberedVersion)) return endsMs + RENEWED_IN_VM_GRACE_MS <= nowMs ? endsMs : null;
  return renewalOverdue(endsMs, sealedAtMs(sealed.version), nowMs) ? endsMs : null;
}

/**
 * The classes that count as an account's failures for `failing`: the vendor's or the network's answers. Left out with
 * `client_error` and `gray_ended` (S46): what no vendor answered for the account (`relay_refused`, `cooling`,
 * `egress_limit`, the container closing first, `relay_closed`) and the rows of no account.
 */
export const FAILURE_CLASSES: ReadonlySet<StackAttemptClass> = new Set<StackAttemptClass>([
  "stream_error",
  "vendor_reset",
  "auth",
  "forbidden",
  "billing",
  "restricted",
  "window_exhausted",
  "rate_limit",
  "overloaded",
  "unavailable",
  "vendor_5xx",
  "challenge",
  "connect",
  "proxy",
]);

/** An account's attempts by class over the two windows the states read. */
export interface AttemptCounts {
  /** The last 15 minutes (`proxy_failing`). */
  readonly quarter: ReadonlyMap<string, number>;
  /** The last hour (`failing`). */
  readonly hour: ReadonlyMap<string, number>;
}

export const NO_ATTEMPTS: AttemptCounts = { quarter: new Map(), hour: new Map() };

export interface StateInput {
  readonly status: "active" | "paused";
  /** The account's object in the latest report, or null when that report did not list it (or none came). */
  readonly report: StackReportAccount | null;
  /** When the console took the report the account's state is from. */
  readonly reportedMs: number | null;
  /** Why the VM had no configuration, from its latest report. */
  readonly absent: StackReport["config"]["absent"];
  readonly attempts: AttemptCounts;
  readonly nowMs: number;
  /**
   * The sealed version under which an earlier report showed the relay renewing the account in the VM
   * (`renewedInVmVersion`, kept by the console across boots); null or absent when none did (`credentialEndingMs`).
   */
  readonly renewedInVmVersion?: number | null;
}

export interface AccountState {
  readonly state: StackAccountState;
  readonly reason: StackAccountStateReason;
  /** When a cool or a window ends (`at_limit`, `cooling`), or the credential (`credential_expiring`); else null. */
  readonly until_ms: number | null;
  /** The model a hold or a cool covers when it is one model's; null when it is the account's. */
  readonly model: string | null;
  /** When the console took the report the state is from; the panel says "as of" when it is over 3 minutes old. */
  readonly as_of_ms: number | null;
}

const WAITING: ReadonlySet<string> = new Set(STACK_WAITING_EXCLUSIONS);

const active = (e: StackReportCooling, nowMs: number): boolean => !e.observed && (e.until_minute_ms === null || e.until_minute_ms > nowMs);
const byModel = (a: StackReportCooling, b: StackReportCooling): number => ((a.model ?? "") < (b.model ?? "") ? -1 : (a.model ?? "") > (b.model ?? "") ? 1 : 0);
const sum = (counts: ReadonlyMap<string, number>, classes: Iterable<string>): number => {
  let n = 0;
  for (const c of classes) n += counts.get(c) ?? 0;
  return n;
};

/** The entries of one scope to show: the account-wide ones, else those of the first model. */
function scoped(entries: readonly StackReportCooling[]): readonly StackReportCooling[] {
  const wide = entries.filter((e) => e.model === null);
  if (wide.length > 0) return wide;
  const first = [...entries].sort(byModel)[0];
  return first === undefined ? [] : entries.filter((e) => e.model === first.model);
}

const latest = (values: readonly (number | null)[]): number | null => values.reduce<number | null>((m, v) => (v === null ? m : m === null ? v : Math.max(m, v)), null);

/** S46's one state of an account. */
export function accountStateOf(input: StateInput): AccountState {
  const { report, nowMs } = input;
  const as_of_ms = input.reportedMs;
  const of = (state: StackAccountState, reason: StackAccountStateReason, until_ms: number | null = null, model: string | null = null): AccountState => ({ state, reason, until_ms, model, as_of_ms });

  if (input.absent === "stack_config_refused") return of("not_served", "config_refused");
  if (report === null) return input.status === "paused" ? of("paused", "paused") : of("not_served", "not_reported");
  if (report.served === "excluded" && report.reason !== null) return WAITING.has(report.reason) ? of("waiting_credential", report.reason) : of("not_served", report.reason);
  if (report.sealed === null) return of("waiting_credential", "not_sealed");
  if (report.served === "paused" || input.status === "paused") return of("paused", "paused");

  const entries = report.cooling.filter((e) => active(e, nowMs));
  const holds = scoped(entries.filter((e) => e.kind === "hold"));
  if (holds.length > 0) return of("held", holds[0]!.class, null, holds[0]!.model);

  const cools = entries.filter((e) => e.kind === "cool");
  const windowCools = cools.filter((e) => e.class === "window_exhausted");
  const limited = report.windows.filter((w) => (w.resets_at_minute_ms === null || w.resets_at_minute_ms > nowMs) && (w.status === "rejected" || (w.used_percent ?? 0) >= 100));
  if (windowCools.length > 0 || limited.length > 0) {
    const shown = scoped(windowCools);
    // A window of the account (or one of its cools across the account) limits the whole account.
    const model = limited.length > 0 || shown.length === 0 ? null : shown[0]!.model;
    const until = latest([...(limited.length > 0 ? windowCools : shown).map((e) => e.until_minute_ms), ...limited.map((w) => w.resets_at_minute_ms)]);
    const reason: StackAccountStateReason = windowCools.length > 0 ? "window_exhausted" : limited.some((w) => w.status === "rejected") ? "window_rejected" : "window_used_up";
    return of("at_limit", reason, until, model);
  }
  if (cools.length > 0) {
    const shown = scoped(cools);
    return of("cooling", shown[0]!.class, latest(shown.map((e) => e.until_minute_ms)), shown[0]!.model);
  }

  const quarter = input.attempts.quarter;
  if ((quarter.get("proxy") ?? 0) >= PROXY_FAILING_MIN && (quarter.get("ok") ?? 0) === 0) return of("proxy_failing", "proxy_failing");

  const expires = credentialEndingMs(report, nowMs, input.renewedInVmVersion ?? null);
  if (expires !== null) return of("credential_expiring", expires <= nowMs ? "credential_expired" : "credential_expiring", expires);

  const hour = input.attempts.hour;
  const failures = sum(hour, FAILURE_CLASSES);
  const counted = failures + (hour.get("ok") ?? 0);
  if (counted >= FAILING_MIN_ATTEMPTS && failures * 2 >= counted) return of("failing", "failing");
  return of("serving", "serving");
}

/**
 * The account's state for the calls of one upstream model (`model`: a stack mapping's `upstream_model`, the
 * `rewrite.model.to` egress keys an account × model entry by): `accountStateOf` with the account's own holds and cools
 * and that model's, another model's left out, as egress refuses the account for the other model only (S38 `scope`). The
 * panel shows `accountStateOf`, which names the first held model for the whole account; a relay stack's routes are
 * covered and answered by it (`stackRouteCovered`, `stackRouteAnswered`).
 */
export function accountStateFor(input: StateInput, model: string): AccountState {
  const report = input.report === null ? null : { ...input.report, cooling: input.report.cooling.filter((e) => e.model === null || e.model === model) };
  return accountStateOf({ ...input, report });
}

// ------------------------------------------------------------------------------------------------- a stack route's accounts

/**
 * The S46 states in which an account serves no call of a model until something changes that is not the clock: not
 * served by the VM (an exclusion, an account the VM's latest report does not list, a refused configuration), waiting
 * for its credential, paused, or held (an enforced hold has no end). Every other state serves, or will by itself:
 * `at_limit` and `cooling` end at their times, `proxy_failing` and `failing` pass with the failures, a credential
 * still answers while `credential_expiring`.
 */
export const STACK_UNSERVING_STATES: ReadonlySet<StackAccountState> = new Set<StackAccountState>(["not_served", "waiting_credential", "paused", "held"]);

/** The S46 states in which an account answers now. */
export const STACK_ANSWERING_STATES: ReadonlySet<StackAccountState> = new Set<StackAccountState>(["serving", "credential_expiring"]);

/** A panel account of a relay stack as its routes read it: its vendor and models, and its S46 state for one upstream model. */
export interface StackRouteAccount {
  readonly vendor: string;
  /** The panel's `models` (lane_stack_accounts.models): the vendor's model names the account may serve. */
  readonly models: readonly string[];
  /** Its state for the calls of an upstream model (`accountStateFor`). */
  stateFor(upstreamModel: string): StackAccountState;
}

/** A relay stack's panel accounts, and whether its VM has reported at all (a lane_stack_vm_state row). */
export interface StackRouteAccounts {
  readonly reported: boolean;
  readonly accounts: readonly StackRouteAccount[];
}

/** An account of the panel as `stackRouteCovered` reads it, its state from what `accountStateOf` reads. */
export function stackRouteAccount(vendor: string, models: readonly string[], input: StateInput): StackRouteAccount {
  return { vendor, models, stateFor: (upstreamModel) => accountStateFor(input, upstreamModel).state };
}

/**
 * The accounts the relay standard lets serve a route (docs/relay-integration-standard.en.md, "Choosing an account"):
 * of the route's vendor, with its upstream model in `models`. Status and credential are the states' to say.
 */
const routeAccounts = (relay: StackRouteAccounts, vendor: string, upstreamModel: string): readonly StackRouteAccount[] =>
  relay.accounts.filter((a) => a.vendor === vendor && a.models.includes(upstreamModel));

/**
 * Whether a relay stack's route of `vendor` (its endpoint's, @gray/control `stackVendorOf`) and `upstreamModel` (its
 * mapping's) has an account that can serve it: one `routeAccounts` names that is in no `STACK_UNSERVING_STATES` for
 * the model. gray-jobs publishes a stack route only while this holds (src/snapshot-reader.ts `stackCoverage`), so the
 * lane's entry, the main view's `laneServed` and `laneOffers` and the catalog never offer a model no account of the
 * relay serves.
 *
 * A relay whose VM has never reported is judged by its panel alone (an active account of the vendor with the model):
 * no report says nothing of its accounts (a VM still booting, an entry older than the report), and taking such a
 * relay's every route away would be the report pipeline's failure, not the relay's. Once it has reported, the latest
 * report decides however old it is: a hold or an exclusion does not end with time, and a VM that stopped reporting is
 * an outage the endpoint's breaker and the uptime pass see, which a route coming and going with the report's age
 * would only hide.
 */
export function stackRouteCovered(relay: StackRouteAccounts, vendor: string, upstreamModel: string): boolean {
  return routeAccounts(relay, vendor, upstreamModel).some((a) => {
    const state = a.stateFor(upstreamModel);
    // Without a report every account reads `not_served` (not reported), or `paused` when the panel paused it.
    return relay.reported ? !STACK_UNSERVING_STATES.has(state) : state !== "paused";
  });
}

/**
 * Whether an account of `routeAccounts` answers the route now (`STACK_ANSWERING_STATES`), for the lane routes' uptime
 * (workers/console/src/lane-stack/uptime.ts); null for a relay whose VM has never reported, of whose accounts nothing
 * is known. A route `stackRouteCovered` leaves out is never published, so this is asked of covered routes only.
 */
export function stackRouteAnswered(relay: StackRouteAccounts, vendor: string, upstreamModel: string): boolean | null {
  if (!relay.reported) return null;
  return routeAccounts(relay, vendor, upstreamModel).some((a) => STACK_ANSWERING_STATES.has(a.stateFor(upstreamModel)));
}
