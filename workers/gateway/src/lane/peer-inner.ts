/**
 * The stack VM's inner receipt of an entry's peer attempt when the hop's `end` did not carry it
 * (docs/confidential-lane-stack-routing.md sections 4.5 and 4.8): the one check every late inner receipt passes, on the
 * receipt route (`receipt-route.ts` `late`) and before the outer receipt is signed (`bindLateInners`).
 */
import { EVENT_PEER_ENTRY, eventType, jcsBytes, sha256BareHex, verifyReceipt } from "@gray/attest";
import { get, type Json } from "@gray/json";
import type { LanePeerCall, StoredPeerAttempt } from "./peer-model.ts";

/** What a late inner receipt is held to: the attempt's stack VM and digest, and the outer receipt and entry it serves. */
export interface InnerExpected {
  readonly peer: Pick<StoredPeerAttempt, "n" | "rid" | "keysetDigest" | "receiptKeys" | "inner">;
  /** The outer receipt's id. */
  readonly receiptId: string;
  /** The entry's keyset digest, which the inner `peer.entry` names. */
  readonly entryKeysetDigest: string;
}

/**
 * The JCS bytes of `receipt` when it is this attempt's inner receipt: the one the outer receipt names when it names one
 * (its JCS SHA-256 and id), signed under the stack VM's attested receipt keys for its keyset, and whose `peer.entry`
 * (the event after `request.received`) names this entry, outer receipt, request and attempt. Null otherwise.
 */
export async function checkedInner(receipt: Json, expected: InnerExpected): Promise<Uint8Array | null> {
  const { peer } = expected;
  const bytes = jcsBytes(receipt);
  if (peer.inner !== null && (sha256BareHex(bytes) !== peer.inner.receiptSha256 || get(receipt, "receipt_id") !== peer.inner.receiptId)) return null;
  const verified = await verifyReceipt(receipt, peer.receiptKeys, { workloadKeysetDigest: peer.keysetDigest });
  if (!verified.ok || verified.document === null) return null;
  const named = verified.document.event_log[1];
  if (named === undefined || eventType(named) !== EVENT_PEER_ENTRY) return null;
  const names =
    get(named, "keyset_digest") === expected.entryKeysetDigest &&
    get(named, "receipt_id") === expected.receiptId &&
    get(named, "rid") === peer.rid &&
    get(named, "n") === BigInt(peer.n);
  return names ? bytes : null;
}

/**
 * Before the outer receipt is signed: each answered attempt whose hop ended without `end` (the client left mid-stream,
 * the entry's own bound, a hop that broke after `head`) had its attempt finished by the stack VM, which signs the inner
 * receipt and answers it on the follow-up once the attempt is done. It is asked for until `untilMs` (`receiptLate`),
 * and one that checks (`checkedInner`) is bound to the call (`bindInner`): `peer.answered.inner` and the commitment
 * name it, and the store holds its bytes with the outer receipt, so `/peers/{n}` never depends on the stack VM keeping
 * the attempt. One that does not check is logged and left out; one not in by `untilMs` leaves `inner` null, and
 * `/peers/{n}` asks for it late. Never throws.
 */
export async function bindLateInners(calls: readonly LanePeerCall[], outer: { readonly receiptId: string; readonly entryKeysetDigest: string; readonly requestId: string }, untilMs: number): Promise<void> {
  await Promise.all(
    calls.map(async (call) => {
      if (call.head === null || call.end !== null || call.inner() !== null) return;
      const peer = call.stored();
      if (peer === null) return;
      try {
        const receipt = await call.receiptLate(untilMs);
        if (receipt === null) return;
        if ((await checkedInner(receipt, { peer, receiptId: outer.receiptId, entryKeysetDigest: outer.entryKeysetDigest })) !== null) {
          call.bindInner(receipt);
          return;
        }
      } catch {
        // A receipt that does not parse or canonicalize is one that does not check.
      }
      console.warn(JSON.stringify({ level: "warn", event: "lane_peer_inner_refused", request_id: outer.requestId, relay_id: call.peer.target.relayId, n: call.n }));
    }),
  );
}
