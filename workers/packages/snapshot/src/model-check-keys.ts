import type { SnapshotContent } from "./snapshot.ts";

/**
 * The public keys of the model-check tickets (docs/model-authenticity-workflow.md, "Probes are not billed", decided with
 * the user on 2026-11-04): the console signs a ticket for each probe request under a key derived from MASTER_KEY
 * (@gray/verifier `ticketPublicKey`), and a gateway serves a request as a model check only under a key the routing
 * snapshot publishes. The deploy tools derive them on every run and give gray-jobs the optional secret
 * MODELTRACE_TICKET_KEYS, `<kid>:<64 lower hex>` comma-separated; ConfigDO publishes them as `modelCheckKeys`. No database
 * row names a key, so a write to the database mints no free probe. A rotation is a release in three steps: the deploy
 * tools publish the old and the new kid together (their kid list, workers/staging/src/keys.ts MODEL_CHECK_TICKET_KIDS),
 * the console switches its kid, then the tools drop the old one (docs/cloudflare-native/production.md).
 */
export interface SnapshotModelCheckKey {
  /** `v` and the label's version (@gray/verifier `MODEL_CHECK_TICKET_KID_PATTERN`). */
  readonly kid: string;
  /** The Ed25519 public key, 64 lower hex digits. */
  readonly publicKey: string;
}

/** A kid as the ticket's codec reads one (@gray/verifier `MODEL_CHECK_TICKET_KID_PATTERN`). */
const KID = /^v[1-9][0-9]*$/;
const KEY = /^[0-9a-f]{64}$/;

/** Parses MODELTRACE_TICKET_KEYS, in its order; empty is none. Throws RangeError on a malformed entry or a kid named twice. */
export function parseModelCheckKeys(spec: string): SnapshotModelCheckKey[] {
  const keys: SnapshotModelCheckKey[] = [];
  for (const entry of spec.split(",").map((e) => e.trim()).filter((e) => e.length > 0)) {
    const at = entry.indexOf(":");
    const kid = at < 0 ? "" : entry.slice(0, at);
    const publicKey = at < 0 ? "" : entry.slice(at + 1);
    if (!KID.test(kid)) throw new RangeError("MODELTRACE_TICKET_KEYS: each entry is v<n>:<64 lower hex digits>");
    if (!KEY.test(publicKey)) throw new RangeError(`MODELTRACE_TICKET_KEYS: key ${kid} is not 64 lower hex digits`);
    if (keys.some((k) => k.kid === kid)) throw new RangeError(`MODELTRACE_TICKET_KEYS: key ${kid} appears twice`);
    keys.push({ kid, publicKey });
  }
  return keys;
}

/** `content` with `keys` as its `modelCheckKeys`; unchanged without a key, so the field is absent and the digest as before. */
export function withModelCheckKeys<C extends SnapshotContent>(content: C, keys: readonly SnapshotModelCheckKey[]): C {
  return keys.length === 0 ? content : { ...content, modelCheckKeys: keys };
}
