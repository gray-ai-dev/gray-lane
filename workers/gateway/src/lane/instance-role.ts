import { LANE_FINAL_MARK_WAIT_MS, LANE_ROLE_TTL_MS, type StackInstanceRole } from "@gray/lane-wire";
import { BridgeCallError } from "./remote/client.ts";

/**
 * Whether this VM is its relay's serving instance (docs/design/relay-no-always-on-host.md 13.4, "Two instances, one
 * vault"; P7). During a rollout without downtime one Phala app runs two instances that both hold the relay's vault;
 * only the serving one refreshes tokens, runs in-VM sign-ins and writes vault versions. The console names the serving
 * instance by its bridge key (`stack.instance`, from the deployment the provisioner keeps: one serving key at a time);
 * this object reads it on the lane's polls and holds the answer.
 *
 * - **serving**: the vault writes and uploads, egress refreshes and signs in.
 * - **draining**: no new vault version, no refresh, no sign-in (egress holds: `StackOpsService`'s `hold`); the requests
 *   it gets are served with the tokens it holds.
 * - **unknown**: before the first answer, and once the last answer is older than `ttlMs` (the bridge or the console
 *   cannot be read). Writes as draining, serves as either: a VM that cannot tell whether another instance writes does
 *   not write. Writes resume with the next answer that says serving.
 *
 * - **waiting** (P7, the final mark): the console names this VM serving and, during a rollout's drain, the instance it
 *   replaces (`retiring`). It writes as draining, and egress holds, until Gray's pair carries that instance's final mark
 *   (`finalMark`, read on each poll) or LANE_FINAL_MARK_WAIT_MS passed since it was first told so; then it is serving.
 *
 * A VM without a vault (phase 1) has none of this: it writes nothing anywhere.
 */

export type LaneRole = StackInstanceRole | "unknown" | "waiting";

export interface InstanceRoleSource {
  instance(relayId: string): Promise<{ readonly role: StackInstanceRole; readonly retiring?: string | null }>;
}

export interface LaneInstanceRoleOptions {
  readonly relayId: string;
  readonly source: InstanceRoleSource;
  readonly now: () => number;
  /** How often the role is read (the config service's poll, LANE_STACK_POLL_MS). */
  readonly pollMs: number;
  /** How long an answer stands without a newer one. */
  readonly ttlMs: number;
  /** P7: this VM's bridge key, to tell whether it is the instance a rollout retires. */
  readonly keyId?: string;
  /** P7: whether Gray's pair carries the final mark of `retiring`; without it no serving answer waits. */
  readonly finalMark?: (retiring: string) => Promise<boolean>;
  /** P7: the longest a serving answer waits for that mark (LANE_FINAL_MARK_WAIT_MS). */
  readonly waitMs?: number;
  readonly log?: (line: Record<string, unknown>) => void;
}

export { LANE_ROLE_TTL_MS };

function codeOf(error: unknown): string {
  if (error instanceof BridgeCallError) return error.status === null ? error.code : `${error.code}_${error.status}`;
  return error instanceof Error ? error.name : "error";
}

export class LaneInstanceRole {
  readonly #options: LaneInstanceRoleOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #known: { readonly role: StackInstanceRole; readonly retiring: string | null; readonly at: number } | null = null;
  /** P7: the retiring key a serving answer waits for, since when, and whether its mark was seen. */
  #wait: { readonly retiring: string; readonly since: number; seen: boolean; missed: boolean } | null = null;
  #askedAt: number | null = null;
  #asking: Promise<void> | null = null;
  /** The role last told to the listeners. */
  #told: LaneRole = "unknown";
  readonly #listeners: ((role: LaneRole, previous: LaneRole) => void | Promise<void>)[] = [];

  constructor(options: LaneInstanceRoleOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** The role now: the last answer while it stands, else unknown. */
  get role(): LaneRole {
    const known = this.#known;
    const now = this.#options.now();
    if (known === null || now - known.at > this.#options.ttlMs) return "unknown";
    if (known.role === "serving" && known.retiring !== null && known.retiring !== this.#options.keyId && this.#options.finalMark !== undefined) {
      const wait = this.#wait;
      if (wait === null || wait.retiring !== known.retiring || (!wait.seen && now - wait.since < (this.#options.waitMs ?? LANE_FINAL_MARK_WAIT_MS))) return "waiting";
    }
    return known.role;
  }

  /** Whether this VM may write now. */
  get serving(): boolean {
    return this.role === "serving";
  }

  /** P7 (13.4, the final mark): whether this VM is the draining instance a rollout retires (it puts the final mark). */
  get retiring(): boolean {
    const retiring = this.#known?.retiring ?? null;
    return this.role === "draining" && retiring !== null && retiring === this.#options.keyId;
  }

  /** Called with each change of `role` (an answer, or an answer aging out), after the change. */
  onChange(listener: (role: LaneRole, previous: LaneRole) => void | Promise<void>): void {
    this.#listeners.push(listener);
  }

  /**
   * Read the role when due (`force`: now, unless a read is running), then tell the listeners of a change. Never throws:
   * a failed read keeps the last answer until it ages out.
   */
  async tick(force = false): Promise<LaneRole> {
    const now = this.#options.now();
    const due = this.#askedAt === null || now - this.#askedAt >= this.#options.pollMs || this.role === "unknown";
    if (force || due) {
      if (this.#asking === null) {
        this.#askedAt = now;
        this.#asking = this.#ask().finally(() => {
          this.#asking = null;
        });
      }
      await this.#asking;
    }
    await this.#lookForMark();
    await this.#tell();
    return this.role;
  }

  /** Whether this VM is serving, reading the role first when it is not known (a delivery's or a write's check). */
  async ensureServing(): Promise<boolean> {
    if (this.role === "unknown") await this.tick(true);
    else await this.#tell();
    return this.serving;
  }

  /** P7: while a serving answer waits, read Gray's pair for the retiring instance's final mark (on each tick). */
  async #lookForMark(): Promise<void> {
    const known = this.#known;
    const finalMark = this.#options.finalMark;
    if (known === null || known.role !== "serving" || known.retiring === null || known.retiring === this.#options.keyId || finalMark === undefined) return;
    const now = this.#options.now();
    if (this.#wait?.retiring !== known.retiring) this.#wait = { retiring: known.retiring, since: now, seen: false, missed: false };
    const wait = this.#wait;
    if (wait.seen || wait.missed) return;
    try {
      wait.seen = await finalMark(known.retiring);
    } catch (error) {
      this.#log({ level: "warn", event: "lane_instance_final_mark_unread", relay_id: this.#options.relayId, retiring: known.retiring, code: codeOf(error) });
    }
    if (wait.seen) this.#log({ level: "info", event: "lane_instance_final_mark", relay_id: this.#options.relayId, retiring: known.retiring, waited_ms: now - wait.since });
    else if (now - wait.since >= (this.#options.waitMs ?? LANE_FINAL_MARK_WAIT_MS)) {
      // 13.4: past the bound the retiring instance is taken as gone; a family it still held is lost only if it could not
      // reach Gray for the whole wait.
      wait.missed = true;
      this.#log({ level: "warn", event: "lane_instance_final_mark_missed", relay_id: this.#options.relayId, retiring: known.retiring, waited_ms: now - wait.since });
    }
  }

  async #ask(): Promise<void> {
    const relayId = this.#options.relayId;
    try {
      const answer = await this.#options.source.instance(relayId);
      this.#known = { role: answer.role, retiring: answer.retiring ?? null, at: this.#options.now() };
    } catch (error) {
      this.#log({ level: "warn", event: "lane_instance_role_failed", relay_id: relayId, code: codeOf(error), role: this.role });
    }
  }

  async #tell(): Promise<void> {
    const role = this.role;
    const previous = this.#told;
    if (role === previous) return;
    this.#told = role;
    this.#log({ level: role === "serving" ? "info" : "warn", event: "lane_instance_role", relay_id: this.#options.relayId, role, previous });
    for (const listener of this.#listeners) {
      try {
        await listener(role, previous);
      } catch (error) {
        this.#log({ level: "error", event: "lane_instance_role_listener_failed", relay_id: this.#options.relayId, code: codeOf(error) });
      }
    }
  }
}
