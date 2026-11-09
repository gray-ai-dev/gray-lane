import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { STACK_WIRE_ID_PATTERN } from "./stack-rules.ts";

/**
 * `stack.instance` (docs/design/relay-no-always-on-host.md 13.4, "Two instances, one vault"; P7): whether the calling
 * VM is its relay's **serving** instance or a **draining** one. During a rollout without downtime
 * (docs/design/relay-zero-downtime.md) one Phala app runs two instances, each with its own bridge key
 * (`app-<app id>-<16 hex of its key>`), and both hold the relay's vault. Only the serving one refreshes tokens, runs
 * in-VM sign-ins and writes vault versions; the other serves the requests it holds with the tokens it has.
 *
 * The console answers from the deployment the provisioner keeps (migration 0058): the calling key is the deployment's
 * own (`lane_key_id`), or the key of an instance being added (`next_lane_key_id`) or retired
 * (`retiring_lane_key_id`). The deployment's key is serving; the other two are draining; a key the deployment does not
 * name is serving while no rollout runs (one instance: a hand-installed key, a relay without a deployment) and
 * draining while one does. The provisioner's `shift` moves the deployment to the new instance in one write, right
 * after the entry shows that instance's boot ready (sealed first, newest first: the entry's own order), so there is
 * one serving key at a time. A VM reads its role on its config polls; a VM that cannot read it writes nothing until it
 * can (the lane's `LaneInstanceRole`).
 *
 * The bridge answers a key only for its own relay (LANE_BRIDGE_STACK_RELAYS), as the other `stack.*` ops, and passes
 * the console the verified key id, never one the document names.
 */

/** The two roles. */
export const STACK_INSTANCE_ROLES = ["serving", "draining"] as const;
export type StackInstanceRole = (typeof STACK_INSTANCE_ROLES)[number];

export const stackInstanceRequestSchema = z.object({ relay_id: z.string().regex(STACK_WIRE_ID_PATTERN) }).strict();
export type StackInstanceRequestDto = z.infer<typeof stackInstanceRequestSchema>;

export const stackInstanceAnswerSchema = z.object({ role: z.enum(STACK_INSTANCE_ROLES) }).strict();
export type StackInstanceAnswerDto = z.infer<typeof stackInstanceAnswerSchema>;

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

/** The wire request: the relay the calling key's VM is. */
export function stackInstanceRequestDtoOf(relayId: string): StackInstanceRequestDto {
  return checked(stackInstanceRequestSchema, { relay_id: relayId });
}

/** The console's role as the wire answer. */
export function stackInstanceAnswerDtoOf(role: StackInstanceRole): StackInstanceAnswerDto {
  if (!STACK_INSTANCE_ROLES.includes(role)) throw new BridgeWireError("invalid_document", "role", `role: ${String(role)} is not a role`);
  return checked(stackInstanceAnswerSchema, { role });
}
