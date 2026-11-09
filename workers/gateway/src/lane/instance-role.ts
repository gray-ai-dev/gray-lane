import type { StackInstanceRole } from "@gray/lane-wire";
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
 * A VM without a vault (phase 1) has none of this: it writes nothing anywhere.
 */

export type LaneRole = StackInstanceRole | "unknown";

export interface InstanceRoleSource {
  instance(relayId: string): Promise<{ readonly role: StackInstanceRole }>;
}

export interface LaneInstanceRoleOptions {
  readonly relayId: string;
  readonly source: InstanceRoleSource;
  readonly now: () => number;
  /** How often the role is read (the config service's poll, LANE_STACK_POLL_MS). */
  readonly pollMs: number;
  /** How long an answer stands without a newer one. */
  readonly ttlMs: number;
  readonly log?: (line: Record<string, unknown>) => void;
}

/** How long an answer stands: a few of the lane's polls, and of the supervisor's 15 s lease pushes. */
export const LANE_ROLE_TTL_MS = 20_000;

function codeOf(error: unknown): string {
  if (error instanceof BridgeCallError) return error.status === null ? error.code : `${error.code}_${error.status}`;
  return error instanceof Error ? error.name : "error";
}

export class LaneInstanceRole {
  readonly #options: LaneInstanceRoleOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #known: { readonly role: StackInstanceRole; readonly at: number } | null = null;
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
    if (known === null || this.#options.now() - known.at > this.#options.ttlMs) return "unknown";
    return known.role;
  }

  /** Whether this VM may write now. */
  get serving(): boolean {
    return this.role === "serving";
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
    await this.#tell();
    return this.role;
  }

  /** Whether this VM is serving, reading the role first when it is not known (a delivery's or a write's check). */
  async ensureServing(): Promise<boolean> {
    if (this.role === "unknown") await this.tick(true);
    else await this.#tell();
    return this.serving;
  }

  async #ask(): Promise<void> {
    const relayId = this.#options.relayId;
    try {
      const answer = await this.#options.source.instance(relayId);
      this.#known = { role: answer.role, at: this.#options.now() };
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
