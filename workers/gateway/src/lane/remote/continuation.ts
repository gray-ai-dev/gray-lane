import {
  CONTINUATION_ERRORS,
  continuationReferences,
  hashedReference,
  replyReferences,
  type BindReference,
  type PinResult,
  type Reference,
} from "@gray/continuation";
import type { Json } from "@gray/json";
import {
  bridgeCall,
  continuationBindRequestDtoOf,
  continuationBoundOf,
  continuationPinOf,
  continuationPinRequestDtoOf,
  continuationTarget,
  type ContinuationBindReference,
} from "@gray/lane-wire";
import type { Protocol } from "@gray/protocol";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * Where a lane VM that admits requests records which endpoint issued a Responses reply, and reads it back for the
 * request that continues it (the bridge ops `continuation.pin` and `continuation.bind`, @gray/lane-wire
 * continuation.ts).
 *
 * Each id is hashed here, inside the VM (`@gray/continuation` `hashedReference`), before the call: the bridge and its
 * store get `sha256:<hex>`, the workspace, the endpoint, the model, and optional opaque TEE-sealed continuation state
 * (ciphertext only, never plaintext ids, prompts, or answers).
 */
export interface LaneContinuation {
  /**
   * The endpoint the references `body` names are bound to, as @gray/continuation's `pinContinuation` answers the API
   * Worker: `pinned: null` for a request that continues nothing; `invalid_continuation_reference` (400) for a reference
   * of the wrong shape; `continuation_not_found` (404) for one never bound, expired or another workspace's;
   * `continuation_endpoint_conflict` (409) for two references of two endpoints; `continuation_lookup_unavailable` (503)
   * when the record gave no answer within `timeoutMs` (0 asks nothing). When sealed continuation blobs are present,
   * `sealed` carries the opaque ciphertext hits keyed by `(kind, referenceHash)`.
   */
  pin(input: { readonly workspace: string; readonly protocol: Protocol; readonly body: Json; readonly timeoutMs: number }): Promise<PinResult>;
  /**
   * Binds the references `reply` creates (or explicit `references`, with optional per-reference opaque `sealed`
   * ciphertext and `stateTtlMs`) to `endpoint`. Best effort, as the API Worker's bind.
   */
  bind(input: {
    readonly workspace: string;
    readonly endpoint: string;
    readonly model: string;
    readonly reply: Json;
    readonly timeoutMs: number;
    readonly references?: readonly BindReference[];
    readonly stateTtlMs?: number;
  }): Promise<{ readonly bound: number; readonly failed: number }>;
}

function hashed(workspace: string, refs: readonly Reference[]): Promise<Reference[]> {
  return Promise.all(refs.map((ref) => hashedReference(workspace, ref)));
}

async function hashedBindRefs(workspace: string, refs: readonly BindReference[]): Promise<ContinuationBindReference[]> {
  return Promise.all(
    refs.map(async (ref) => {
      const h = await hashedReference(workspace, { kind: ref.kind, reference: ref.reference });
      return typeof ref.sealed === "string" && ref.sealed.length > 0 ? { ...h, sealed: ref.sealed } : h;
    }),
  );
}

/** `LaneContinuation` over the bridge, signed with the lane's bridge key. */
export class RemoteContinuation extends BridgeClient implements LaneContinuation {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  async pin(input: { readonly workspace: string; readonly protocol: Protocol; readonly body: Json; readonly timeoutMs: number }): Promise<PinResult> {
    if (input.protocol !== "open_ai_responses") return { ok: true, pinned: null };
    const refs = continuationReferences(input.body);
    if (refs === undefined) return { ok: false, error: CONTINUATION_ERRORS.invalidReference(), unanswered: [] };
    if (refs.length === 0) return { ok: true, pinned: null };
    const unavailable: PinResult = { ok: false, error: CONTINUATION_ERRORS.lookupUnavailable(), unanswered: [] };
    if (input.timeoutMs <= 0) return unavailable;
    try {
      const request = continuationPinRequestDtoOf({ workspaceId: input.workspace, references: await hashed(input.workspace, refs) });
      const pin = continuationPinOf(await this.call("continuation.pin", bridgeCall("continuation.pin", continuationTarget(input.workspace)), request, { timeoutMs: input.timeoutMs }));
      switch (pin.outcome) {
        case "pinned":
          return pin.sealed !== undefined && pin.sealed.length > 0
            ? { ok: true, pinned: pin.endpointId, sealed: pin.sealed }
            : { ok: true, pinned: pin.endpointId };
        case "missing":
          return { ok: false, error: CONTINUATION_ERRORS.notFound(), unanswered: [] };
        case "conflict":
          return { ok: false, error: CONTINUATION_ERRORS.endpointConflict(), unanswered: [] };
        case "too_large":
          return { ok: false, error: CONTINUATION_ERRORS.stateTooLarge(), unanswered: [] };
        case "unavailable":
          return unavailable;
      }
    } catch {
      // A bridge that did not answer, or answered no document of the op: no answer, never a route chosen without one.
      return unavailable;
    }
  }

  async bind(input: {
    readonly workspace: string;
    readonly endpoint: string;
    readonly model: string;
    readonly reply: Json;
    readonly timeoutMs: number;
    readonly references?: readonly BindReference[];
    readonly stateTtlMs?: number;
  }): Promise<{ readonly bound: number; readonly failed: number }> {
    const refs: readonly BindReference[] = input.references ?? replyReferences(input.reply);
    if (refs.length === 0) return { bound: 0, failed: 0 };
    if (input.timeoutMs <= 0) return { bound: 0, failed: refs.length };
    try {
      const request = continuationBindRequestDtoOf({
        workspaceId: input.workspace,
        endpointId: input.endpoint,
        model: input.model,
        references: await hashedBindRefs(input.workspace, refs),
        ...(input.stateTtlMs === undefined ? {} : { stateTtlMs: input.stateTtlMs }),
      });
      return continuationBoundOf(await this.call("continuation.bind", bridgeCall("continuation.bind", continuationTarget(input.workspace)), request, { timeoutMs: input.timeoutMs }));
    } catch {
      return { bound: 0, failed: refs.length };
    }
  }
}

/** The lane's record of which endpoint issued a reply, over the bridge. */
export function remoteContinuation(options: BridgeClientOptions): LaneContinuation {
  return new RemoteContinuation(options);
}
