import { z } from "zod";
import { BridgeWireError, fromZod } from "./error.ts";
import { uintSchema } from "./ints.ts";

/**
 * `entry.role` (docs/design/entry-replicas.md ER9, as the entry replicas' operating spec of 2026-11-17 revised it): an
 * entry replica asks the bridge for its role, `serving`, `draining` or `stopping` (ENTRY_ROLES). The release tool sets a replica `draining` before
 * it updates that replica's VM; the replica then answers every response with `Connection: close` (best effort: see the
 * gateway's lane IMPLEMENTATION_NOTES.md, "The entry's role and in-flight count"), and `/healthz` reports how many
 * customer requests it still serves. The console keeps the roles (migration 0088, `lane_entry_roles`); the bridge reads
 * them through its console binding.
 *
 * The request names the replica's index, 1 to ENTRY_REPLICA_MAX (the entrypoint's LANE_REPLICA). The answer is the role,
 * and when it was last written (`updated_ms`), null when nobody has written one: an index without a row is `serving`.
 * Only an entry's key may call it, as `acme.challenge`: a relay stack VM is never an entry replica. The target is
 * `entry/<index>`, so a signature over one replica's call never verifies as another's.
 */

/** The prefix of the target a call signs: `entry/<index>`. */
export const ENTRY_ROLE_TARGET_PREFIX = "entry/";
/** The highest replica index (deploy/tee/bin/entrypoint.mjs REPLICA_MAX, STACK_ENTRIES_MAX). */
export const ENTRY_REPLICA_MAX = 16;

/**
 * `serving`; `draining` (out of the load balancer: every answer says `Connection: close`, best effort); `stopping` (the
 * replica's entrypoint stops workerd with its own SIGTERM drain, then answers only its health route; the Worker treats
 * it as `draining` and closes its stack VM channel sessions once nothing is in flight). Ops spec "Drain, revised
 * 2026-11-17 evening".
 */
export const ENTRY_ROLES = ["serving", "draining", "stopping"] as const;
export type EntryRole = (typeof ENTRY_ROLES)[number];

export const entryRoleRequestSchema = z.object({ index: z.bigint().min(1n).max(BigInt(ENTRY_REPLICA_MAX)) }).strict();
export type EntryRoleRequestDto = z.infer<typeof entryRoleRequestSchema>;

export const entryRoleAnswerSchema = z.object({ role: z.enum(ENTRY_ROLES), updated_ms: uintSchema.nullable() }).strict();
export type EntryRoleAnswerDto = z.infer<typeof entryRoleAnswerSchema>;

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

/** Whether `index` is a replica index: a whole number from 1 to ENTRY_REPLICA_MAX. */
export function isEntryReplicaIndex(index: unknown): index is number {
  return typeof index === "number" && Number.isInteger(index) && index >= 1 && index <= ENTRY_REPLICA_MAX;
}

/** `entry/<index>`, the target a call for replica `index` signs. */
export function entryRoleTarget(index: number | bigint): string {
  const n = typeof index === "bigint" ? Number(index) : index;
  if (!isEntryReplicaIndex(n)) throw new BridgeWireError("invalid_target", null, `a replica index is a whole number from 1 to ${ENTRY_REPLICA_MAX}`);
  return `${ENTRY_ROLE_TARGET_PREFIX}${n}`;
}

/** The wire request of replica `index`. */
export function entryRoleRequestDtoOf(index: number): EntryRoleRequestDto {
  if (!isEntryReplicaIndex(index)) throw new BridgeWireError("invalid_document", "index", `index: a whole number from 1 to ${ENTRY_REPLICA_MAX}`);
  return checked(entryRoleRequestSchema, { index: BigInt(index) });
}

/** The console's answer as the wire's. */
export function entryRoleAnswerDtoOf(role: EntryRole, updatedMs: number | null): EntryRoleAnswerDto {
  if (!ENTRY_ROLES.includes(role)) throw new BridgeWireError("invalid_document", "role", `role: ${String(role)} is not a role`);
  return checked(entryRoleAnswerSchema, { role, updated_ms: updatedMs === null ? null : BigInt(updatedMs) });
}

/** The wire answer as the lane reads it. */
export function entryRoleOf(dto: EntryRoleAnswerDto): { readonly role: EntryRole; readonly updatedMs: number | null } {
  return { role: dto.role, updatedMs: dto.updated_ms === null ? null : Number(dto.updated_ms) };
}
