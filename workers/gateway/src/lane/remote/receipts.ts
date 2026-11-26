import { bridgeCall, receiptObjectsOf, receiptsGetRequestDtoOf, receiptsPutRequestDtoOf, receiptsPutResultOf, RECEIPTS_TARGET, type ReceiptObject } from "@gray/lane-wire";
import type { ReceiptObjects } from "../receipt-persist.ts";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The entry's sealed receipt copies behind the bridge (`receipts.put`, `receipts.get`, @gray/lane-wire receipts.ts;
 * docs/design/persisted-receipts.md section 4). The bridge stores opaque objects by name and knows nothing of what they
 * hold. A call that fails (no answer, a timeout, a status that is not 2xx, a document off the schema) throws, as every
 * bridge call does (client.ts); the persister decides what that means.
 */

/** One call's bound: a write-behind flush and a receipt lookup both wait at most this long for the bridge. */
export const RECEIPTS_CALL_MS = 2_000;

export class RemoteReceiptObjects extends BridgeClient implements ReceiptObjects {
  constructor(options: BridgeClientOptions) {
    super({ timeoutMs: RECEIPTS_CALL_MS, ...options });
  }

  async put(objects: readonly ReceiptObject[]): Promise<{ readonly stored: readonly string[]; readonly failed: readonly string[] }> {
    return receiptsPutResultOf(await this.call("receipts.put", bridgeCall("receipts.put", RECEIPTS_TARGET), receiptsPutRequestDtoOf(objects)));
  }

  async get(keys: readonly string[]): Promise<readonly (ReceiptObject | null)[]> {
    return receiptObjectsOf(await this.call("receipts.get", bridgeCall("receipts.get", RECEIPTS_TARGET), receiptsGetRequestDtoOf(keys)));
  }
}
