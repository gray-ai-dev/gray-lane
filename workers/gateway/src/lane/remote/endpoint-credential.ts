import { bridgeCall, endpointCredentialOf, endpointCredentialRequestDtoOf, endpointCredentialTarget } from "@gray/lane-wire";
import { endpointCredentialRequest, openEndpointCredential } from "@gray/relay-connector/endpoint-credential";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * A provider endpoint's API key for the entry (the bridge op `endpoint.credential`, docs/design/lane-provider-routes.md
 * section 3.2): each call makes a fresh X25519 key pair, sends the public half as the request's `reply_key`, and opens
 * the console's sealed answer with the private half, which lives only in this call's frame and is dropped when it
 * returns. The master key never enters the CVM and no key crosses the bridge in clear.
 *
 * The answer must name the endpoint and generation asked for (the HPKE binding holds them too, so a sealed key for
 * another endpoint or generation would not open either); anything else is `EndpointCredentialError`. A refusal or a
 * failed call is the bridge client's `BridgeCallError` (client.ts's error table): `endpoint_credential_refused` is a
 * 403, `credential_generation_changed` a 409, a console that cannot answer a 5xx. The key is returned as the bytes the
 * console stored (UTF-8 text); nothing here logs it, keeps it, or writes it anywhere.
 *
 * The entry keeps the keys in memory per (endpoint, generation) and prefetches them (`endpoint-routes.ts`); the request
 * path reads them through its `endpointCredentials` dependency (lane/deps.ts).
 */

/** Why an answer that arrived was not a key for this request. */
export class EndpointCredentialError extends Error {
  override readonly name = "EndpointCredentialError";
  /** `endpoint_credential_mismatch`: the answer names another endpoint or generation; `endpoint_credential_unopenable`: it does not open. */
  readonly code: "endpoint_credential_mismatch" | "endpoint_credential_unopenable";

  constructor(code: "endpoint_credential_mismatch" | "endpoint_credential_unopenable") {
    super(code);
    this.code = code;
  }
}

/** `endpoint.credential` over the bridge, signed with the lane's bridge key. */
export class EndpointCredentialClient extends BridgeClient {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  /**
   * The key of `endpointId` at `generation`, as the console stores it; a throw for anything else. `timeoutMs` replaces
   * the client's per-call deadline for this call (an attempt's own budget, or the entry's background bound).
   */
  async credential(endpointId: string, generation: number, timeoutMs?: number): Promise<Uint8Array> {
    const request = await endpointCredentialRequest();
    const dto = endpointCredentialRequestDtoOf({ endpointId, generation, replyKey: request.publicKey });
    const sealed = endpointCredentialOf(await this.call("endpoint.credential", bridgeCall("endpoint.credential", endpointCredentialTarget(endpointId)), dto, timeoutMs === undefined ? {} : { timeoutMs }));
    if (sealed.endpointId !== endpointId || sealed.generation !== generation) throw new EndpointCredentialError("endpoint_credential_mismatch");
    const key = await openEndpointCredential(request.privateKey, sealed, endpointId, generation);
    if (key === null) throw new EndpointCredentialError("endpoint_credential_unopenable");
    return key;
  }
}

/** A provider endpoint's key over the bridge: `credential(endpointId, generation)`. */
export function remoteEndpointCredentials(options: BridgeClientOptions): EndpointCredentialClient {
  return new EndpointCredentialClient(options);
}
