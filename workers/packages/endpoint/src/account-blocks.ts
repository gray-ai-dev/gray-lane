/**
 * The memory of vendors' blocks on suppliers' upstream accounts (crates/gray-gateway/src/ranking.rs
 * `AccountBlockGates`, release 4): one gate per (supplier workspace, model, `Pattern`), each a breaker on
 * Envoy's ejection schedule (gates.ts), bounded as the second-opinion gates are. Pure code: the gateway keeps
 * one per isolate, as the server keeps one per process (docs/cloudflare-native/gateway.md section 13).
 *
 * A refusal by the supplier pauses the gate. While it is paused, requests of the pattern are steered away
 * from the supplier: at admission and at every later choice its routes go after every other route, and none
 * is sent. When the pause ends the gate is unproven, and one attempt of the pattern at a time carries its
 * re-test lease, taken as the attempt is sent to the supplier (`pass`) and given back when it ends unsettled:
 * admission only orders (`holdsOff`), so a request admitted then leaves the supplier in its ranked place while
 * the lease is free, and holds nothing while it is served elsewhere. An attempt that finds the lease out on
 * another steers its request away from the supplier too. The gate stays unproven until a re-test is served
 * (it opens, and the supplier takes its ranked place again) or refused (it pauses again). Refusals during a
 * pause belong to the same ejection, as with Envoy's ejected host: they add nothing to the multiplier.
 */
import type { AccountBlock } from "@gray/errors";
import { type Breaker, Gates, type GateLease, type GateState } from "./gates.ts";
import type { AccountBlockView } from "./types.ts";

/**
 * The kind of request an account block refuses, as Gray tells requests apart for it (`Pattern`): the client
 * application (@gray/client-apps `identify`, "" when none is named) and whether the request declares tools.
 * A relay never sees the client: Gray forwards a request's body and, on the Messages API,
 * `anthropic-version` and `anthropic-beta`, never a User-Agent. yylx refused every OpenCode tool turn of its
 * Claude models while it served OpenCode's title requests (2026-10-18): it read the tool turn's body,
 * OpenCode's prompt and tools. The client stands for that body here, and keeps a client the supplier does
 * serve, such as Claude Code with tools, from being steered.
 */
export interface Pattern {
  readonly client: string;
  readonly tools: boolean;
}

/** What an account-block gate shows: whose it is and what its refusals were (`BlockKind`). */
interface BlockMeta {
  readonly supplier: string;
  readonly model: string;
  readonly pattern: Pattern;
  kind: AccountBlock;
}

/** A re-test's pass through an account-block gate (`BlockLease`); dropped with `AccountBlockGates.drop`. */
export type BlockLease = GateLease;

/** What `AccountBlockGates.pass` says of an attempt about to be sent to a supplier (`Pass`). */
export type BlockPass =
  /** The gate is open, or there is none: the attempt goes. */
  | { readonly kind: "open" }
  /**
   * The gate is unproven, and the attempt took its one re-test lease: it goes, and carries the lease until it
   * ends. The supplier's answer or refusal settles the gate (`served`, `refused`); the lease goes back if the
   * attempt ends with neither (`drop`).
   */
  | { readonly kind: "retest"; readonly lease: BlockLease }
  /** The gate holds the attempt off: it is paused, or unproven with its one re-test lease out on another attempt. */
  | { readonly kind: "held_off"; readonly block: AccountBlock };

/** One account-block gate as operations health shows it (`AccountBlockRow`). */
export interface AccountBlockRow {
  readonly kind: AccountBlock;
  /** The client application's id, such as `opencode`; "" when none. */
  readonly client: string;
  readonly tools: boolean;
  readonly state: GateState;
  readonly pausedUntilMs: number | undefined;
  readonly lastRefusedAtMs: number | undefined;
  readonly lastServedAtMs: number | undefined;
}

export class AccountBlockGates {
  private readonly gates: Gates<BlockMeta>;

  constructor(bound: number) {
    this.gates = new Gates(bound);
  }

  private static id(supplier: string, model: string, pattern: Pattern): string {
    return JSON.stringify([supplier, model, pattern.client, pattern.tools]);
  }

  /**
   * The block whose gate of (`supplier`, `model`, `pattern`) holds a request of the pattern off the supplier
   * at `at`: the gate is paused, or unproven with its re-test lease out. Undefined while it is open, or
   * unproven with its lease free, or when there is none. The lease `held`, the asking request's own, counts as
   * given back: the request asks what the gate will say once the attempt carrying it has closed (release 4
   * round 3, 985672c36). Takes nothing.
   */
  holdsOff(supplier: string, model: string, pattern: Pattern, at: number, held: BlockLease | null = null): AccountBlock | undefined {
    const id = AccountBlockGates.id(supplier, model, pattern);
    const own = AccountBlockGates.own(id, held);
    return this.gates.with(id, at, undefined, (meta, gate) => AccountBlockGates.holding(meta, gate, at, own));
  }

  /**
   * What `holdsOff` will say at `at`, a time to come, if nothing else changes the gate meanwhile
   * (`will_hold_off`, 0fcf777a0): a pause that has ended by then is over. Reads the gate without touching it
   * (`Gates.peek`), so its decay and its place among the gates stay as they are. Takes nothing.
   */
  willHoldOff(supplier: string, model: string, pattern: Pattern, at: number, held: BlockLease | null = null): AccountBlock | undefined {
    const id = AccountBlockGates.id(supplier, model, pattern);
    const own = AccountBlockGates.own(id, held);
    return this.gates.peek(id, (meta, gate) => AccountBlockGates.holding(meta, gate, at, own));
  }

  /** The number of the lease `held` carries on the gate `id`, if any. */
  private static own(id: string, held: BlockLease | null): number | null {
    return held !== null && held.id === id ? held.lease : null;
  }

  /** The block `gate` holds a request off with at `at`, the lease `own` counted as given back. */
  private static holding(meta: BlockMeta, gate: Breaker, at: number, own: number | null): AccountBlock | undefined {
    const state = gate.state(at);
    if (state === "open") return undefined;
    if (state === "paused") return meta.kind;
    return gate.lease !== null && gate.lease !== own ? meta.kind : undefined;
  }

  /**
   * What the gate of (`supplier`, `model`, `pattern`) says at `at` of an attempt of the pattern about to be sent
   * to the supplier: unproven with its re-test lease free, the attempt takes the lease.
   */
  pass(supplier: string, model: string, pattern: Pattern, at: number): BlockPass {
    const id = AccountBlockGates.id(supplier, model, pattern);
    const seen = this.gates.with(id, at, undefined, (meta, gate) => ({ kind: meta.kind, state: gate.state(at), leased: gate.lease !== null }));
    if (seen === undefined || seen.state === "open") return { kind: "open" };
    if (seen.state === "paused" || seen.leased) return { kind: "held_off", block: seen.kind };
    const lease = this.gates.pass(id, at, () => ({ supplier, model, pattern, kind: seen.kind }));
    return lease === undefined ? { kind: "held_off", block: seen.kind } : { kind: "retest", lease };
  }

  /** The supplier refused a request of the pattern with `kind` at `at`: the gate pauses, unless it already is. */
  refused(supplier: string, model: string, pattern: Pattern, kind: AccountBlock, at: number): void {
    this.gates.with(
      AccountBlockGates.id(supplier, model, pattern),
      at,
      () => ({ supplier, model, pattern, kind }),
      (meta, gate) => {
        meta.kind = kind;
        if (gate.state(at) === "paused") gate.lastRefusedAt = at;
        else gate.refused(at);
      },
    );
  }

  /** The supplier answered a request of the pattern at `at`: a gate it has opens. */
  served(supplier: string, model: string, pattern: Pattern, at: number): void {
    this.gates.with(AccountBlockGates.id(supplier, model, pattern), at, undefined, (_, gate) => gate.served(at));
  }

  /** A re-test lease its attempt did not settle goes back, if it is still the gate's. */
  drop(lease: BlockLease): void {
    this.gates.drop(lease);
  }

  /** How many gates are paused at `at`. */
  paused(at: number): number {
    return this.gates.paused(at);
  }

  /** The gates of `supplier` and `model`, as they stand at `at`, by client and tools. */
  routeRows(supplier: string, model: string | null, at: number): AccountBlockRow[] {
    const rows = this.gates.rows(
      at,
      (meta) => meta.supplier === supplier && (model === null || meta.model === model),
      (meta, gate): AccountBlockRow => ({
        kind: meta.kind,
        client: meta.pattern.client,
        tools: meta.pattern.tools,
        state: gate.state(at),
        pausedUntilMs: at < gate.pausedUntil ? gate.pausedUntil : undefined,
        lastRefusedAtMs: gate.lastRefusedAt,
        lastServedAtMs: gate.lastServedAt,
      }),
    );
    return rows.sort((a, b) => (a.client < b.client ? -1 : a.client > b.client ? 1 : Number(a.tools) - Number(b.tools)));
  }

    /** Moves every gate `byMs` into the past, as if that time had gone by: tests cannot wait out a pause. */
  rewind(byMs: number): void {
    this.gates.rewind(byMs);
  }
}

/**
 * The rows of `views` (each shard's view of one route's gates, or several routes' of one supplier and model)
 * merged into one per client and tool shape (operations health): the most restrictive state any of them is in
 * (paused, then unproven, then open), as the second-opinion gates are merged, the latest pause, refusal and
 * answer any of them saw, and the block of the latest refusal. By client and tools.
 */
export function mergeAccountBlockViews(views: readonly (readonly AccountBlockView[])[]): AccountBlockView[] {
  const rank = (v: AccountBlockView) => (v.state === "open" ? 0 : v.state === "unproven" ? 1 : 2);
  const later = (a: number | null, b: number | null) => (a === null ? b : b === null ? a : Math.max(a, b));
  const merged = new Map<string, AccountBlockView>();
  for (const rows of views) {
    for (const row of rows) {
      const id = JSON.stringify([row.client, row.tools]);
      const kept = merged.get(id);
      if (kept === undefined) {
        merged.set(id, row);
        continue;
      }
      merged.set(id, {
        kind: (row.lastRefusedAtMs ?? -1) > (kept.lastRefusedAtMs ?? -1) ? row.kind : kept.kind,
        client: row.client,
        tools: row.tools,
        state: rank(row) > rank(kept) ? row.state : kept.state,
        pausedUntilMs: later(row.pausedUntilMs, kept.pausedUntilMs),
        lastRefusedAtMs: later(row.lastRefusedAtMs, kept.lastRefusedAtMs),
        lastServedAtMs: later(row.lastServedAtMs, kept.lastServedAtMs),
      });
    }
  }
  return [...merged.values()].sort((a, b) => (a.client < b.client ? -1 : a.client > b.client ? 1 : Number(a.tools) - Number(b.tools)));
}
