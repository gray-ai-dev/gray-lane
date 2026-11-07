import { bridgeCall, MODEL_CHECK_TICKETS_TARGET, ticketUseInputDtoOf, ticketUseOutcomeOf, type TicketUseOutcome } from "@gray/lane-wire";
import type { ModelCheckTicketStore } from "../../model-check.ts";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The lane's record of the model-check tickets' one-time ids used (model-check.ts `ModelCheckTicketStore`;
 * docs/model-authenticity-workflow.md, "Probes are not billed", decided 2026-11-04): the bridge op `ticket.use`, which
 * ends at the bridge's `LaneNonceDO` of the tickets (its nonce region's, decided 2026-11-05), the one record of every
 * lane VM. Only the id and its expiry cross the bridge. Every failure is a throw, as for every bridge call (client.ts's
 * error table): the request path reads it as a record that did not answer, 503 and never free.
 */
export class RemoteModelCheckTickets extends BridgeClient implements ModelCheckTicketStore {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  async use(id: string, expiresAtMs: number): Promise<TicketUseOutcome> {
    return ticketUseOutcomeOf(await this.call("ticket.use", bridgeCall("ticket.use", MODEL_CHECK_TICKETS_TARGET), ticketUseInputDtoOf({ id, expiresAtMs })));
  }
}

/** The lane's record of used model-check tickets over the bridge. */
export function remoteModelCheckTickets(options: BridgeClientOptions): ModelCheckTicketStore {
  return new RemoteModelCheckTickets(options);
}
