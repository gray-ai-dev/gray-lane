/**
 * The handles of one request, resolved before any route is chosen (crates/gray-gateway/src/
 * tool_call_ids.rs `Resolution`; docs/design/tool-call-ids.md "Restoring"), and what each attempt
 * sends in their place.
 *
 * - A row must still make its handle: its digest is recomputed from the row, and a changed issuer,
 *   kind or value is treated as lost (`openRow`).
 * - Each attempt sets every site for its own route: the original where the route is the issuer and
 *   either speaks the protocol the original was issued in or documents it as valid (Anthropic's
 *   pattern, Responses' 64 characters), the handle otherwise. A Responses `function_call` item whose
 *   call another issuer made goes without its item id. Here the body every attempt is built from is
 *   the client's own bytes, which hold the handles: an attempt changes only the sites that get an
 *   original and the item ids it leaves out, by their byte offsets (`attempt`); a body written again
 *   (equal keys collapsed) is set by its parse (`applyValue`).
 * - The issuer of the latest call site with a handle leads the routing (`preferred`).
 *
 * Pure code apart from WebCrypto: the gateway does the lookups (client.ts) and holds the memory.
 */
import type { Json } from "@gray/json";
import type { Protocol } from "@gray/protocol";
import { parseHandle } from "./handle.ts";
import { fits, requestSites, type Role, setSite, siteValue } from "./ids.ts";
import { digest, fromHex, type Kind, open } from "./keys.ts";
import type { ByteSite, ItemId } from "./scan.ts";
import type { StoredRow } from "./store.ts";

/** A stored handle as a request resolved it. */
export interface ResolvedHandle {
  readonly kind: Kind;
  readonly issuer: string;
  /** The protocol of the answer that issued it. */
  readonly protocol: Protocol;
  /** The original value; null when its content was deleted. */
  readonly value: string | null;
  /** The stored label: an upstream id, or a composed id's own id. */
  readonly label: string | null;
}

/** What a request's handles turned out to be, beyond those it resolved. */
export interface ResolutionCounts {
  /** Handles of this workspace that no row stands for (any more), or whose row no longer makes them. */
  lost: number;
  /** Handle-shaped ids this deployment did not issue to this workspace. */
  foreign: number;
  /** Handles whose content was deleted with its Activity. */
  contentDeleted: number;
}

/** What one attempt sent upstream in place of the client's handles (`AttemptIds`; the request log's `tool_call_ids`). */
export interface AttemptIds {
  /** Originals sent to the route that issued them. */
  restored: number;
  /** Handles sent to a route of another issuer. */
  otherIssuer: number;
  /** Handles sent to the issuer, whose protocol here does not take the original. */
  unfit: number;
  lost: number;
  foreign: number;
  contentDeleted: number;
  /** Responses call items sent without the item id another issuer gave. */
  itemIdsDropped: number;
  /** (original, handle) of each restored id: an upstream's error that quotes an original is told with the handle the client knows. */
  readonly pairs: [string, string][];
}

export function emptyAttemptIds(): AttemptIds {
  return { restored: 0, otherIssuer: 0, unfit: 0, lost: 0, foreign: 0, contentDeleted: 0, itemIdsDropped: 0, pairs: [] };
}

/** Nothing to tell: the request held no handle, or none that resolved or was counted. */
export function attemptIdsEmpty(ids: AttemptIds): boolean {
  return ids.restored === 0 && ids.otherIssuer === 0 && ids.unfit === 0 && ids.lost === 0 && ids.foreign === 0 && ids.contentDeleted === 0 && ids.itemIdsDropped === 0 && ids.pairs.length === 0;
}

/**
 * Ids the route cannot be expected to know: lost, foreign, deleted, another issuer's, or not in the
 * form this protocol takes. A failure of an attempt that sent any may be about them: unless it blames
 * the route by itself, it is not held against the route, and a refusal then is not the request's own.
 */
export function unvouched(ids: AttemptIds): number {
  return ids.lost + ids.foreign + ids.contentDeleted + ids.otherIssuer + ids.unfit;
}

/** One change to the bytes of a body: `[start, end)` replaced by `text` (empty to remove). */
export interface ByteEdit {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

const encoder = new TextEncoder();

/** The heap one (original, handle) pair holds beside its strings (two string headers). */
const PAIR_OVERHEAD = 32;
/** What a resolved handle holds beside its strings: its map entry and record. */
const RESOLVED_OVERHEAD = 96;

function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

const PROTOCOLS: ReadonlySet<string> = new Set(["open_ai_chat", "open_ai_responses", "anthropic_messages", "gemini", "open_ai_embeddings", "open_ai_image_generations", "open_ai_image_edits", "open_ai_speech", "open_ai_transcriptions", "open_ai_translations", "open_ai_videos"]);

/** Why a row could not be resolved (an alert's reason; never a value). */
export type RowAlert = "unreadable_row" | "content_unopenable" | "row_does_not_match_handle";

/**
 * Opens a stored row for `handle` of `workspace` (`Resolution::load`): the original from its label or
 * its sealed content, checked against the handle's digest. `integrity` hears why a row is not used (the
 * gateway logs it as an error, `tool_call_id_integrity`).
 * `contentKey` gives the key a content was sealed under, by its month and generation (null: none).
 */
export async function openRow(
  workspace: string,
  handle: string,
  row: StoredRow,
  contentKey: (month: number, generation: number) => Promise<Uint8Array | null>,
  integrity: (reason: RowAlert) => void,
): Promise<ResolvedHandle | null> {
  const label = row.label;
  const kind: Kind | null = label.kind === 1 || label.kind === 2 ? label.kind : null;
  const parsed = parseHandle(handle);
  if (kind === null || fromHex(label.issuer)?.length !== 16 || !PROTOCOLS.has(label.issuedProtocol) || parsed === null) {
    integrity("unreadable_row");
    return null;
  }
  let value: string | null;
  if (row.content === null) value = kind === 1 ? label.label : null;
  else {
    const key = await contentKey(row.content.keyMonth, row.content.keyGeneration);
    if (key === null) value = null;
    else {
      value = await open(key, workspace, handle, row.content.sealed);
      if (value === null) {
        integrity("content_unopenable");
        return null;
      }
    }
  }
  // The row must still make its handle: a changed issuer, kind or value is never sent to anyone.
  // Without its content a composed id has nothing to check (its own id is a handle checked on its
  // own, or a plain id that goes anywhere anyway).
  const checked = value ?? (kind === 1 ? label.label : null);
  if (checked !== null) {
    const d = await digest(kind, workspace, label.issuer, checked);
    let same = d.length === parsed.digest.length;
    for (let i = 0; same && i < d.length; i++) same = d[i] === parsed.digest[i];
    if (!same) {
      integrity("row_does_not_match_handle");
      return null;
    }
  }
  return { kind, issuer: label.issuer, protocol: label.issuedProtocol as Protocol, value, label: label.label };
}

/** The handles of one request (`Resolution`). */
export class Resolution {
  readonly resolved = new Map<string, ResolvedHandle>();
  readonly counts: ResolutionCounts = { lost: 0, foreign: 0, contentDeleted: 0 };
  /** The issuer of the latest call site with a resolved handle. */
  preferred: string | null = null;
  /** Every issuer a resolved handle names, in body order. */
  issuers: string[] = [];
  /** How many bytes longer the request can become at any route: what each original adds over its handle, at every site. */
  extraBytes = 0;
  /** Bytes of the (original, handle) pairs one attempt keeps of the sites it restores, at most. */
  pairBytes = 0;

  /** A resolved handle, noted with what it opened. */
  add(handle: string, found: ResolvedHandle): void {
    this.resolved.set(handle, found);
    if (found.value === null) this.counts.contentDeleted += 1;
  }

  /** The request holds a composed id's handle (`substituteComposites` has something to put back). */
  get hasComposites(): boolean {
    for (const r of this.resolved.values()) if (r.kind === 2) return true;
    return false;
  }

  /** The request holds an upstream id's handle (an attempt may restore one). */
  get hasUpstream(): boolean {
    for (const r of this.resolved.values()) if (r.kind === 1) return true;
    return false;
  }

  /** A handle each attempt sets for its route: an upstream id's (`prepare`: a composed id's handle stays a handle on a native route). */
  bound(value: string): boolean {
    return this.resolved.get(value)?.kind === 1;
  }

  /** The inner ids of the composed ids that are handles themselves and were not among `seen`: looked up next. */
  innerHandles(seen: ReadonlySet<string>): string[] {
    const out = new Set<string>();
    for (const r of this.resolved.values()) {
      if (r.kind === 2 && r.label !== null && parseHandle(r.label) !== null && !seen.has(r.label)) out.add(r.label);
    }
    return [...out];
  }

  /**
   * What the resolved handles at `sites` say, in body order (`index`): every issuer they name, the
   * issuer of the latest call, and the bytes their originals add.
   */
  index(sites: readonly { readonly value: string; readonly role: Role }[]): void {
    const issuers: string[] = [];
    for (const site of sites) {
      const found = this.resolved.get(site.value);
      if (found === undefined) continue;
      if (!issuers.includes(found.issuer)) issuers.push(found.issuer);
      if (site.role === "call") this.preferred = found.issuer;
      let handle = site.value;
      let upstream: ResolvedHandle | undefined = found;
      if (found.kind === 2) {
        upstream = found.label === null ? undefined : this.resolved.get(found.label);
        handle = found.label ?? handle;
      }
      if (upstream !== undefined && upstream.value !== null) {
        const length = utf8Length(upstream.value);
        this.extraBytes += Math.max(0, length - handle.length);
        this.pairBytes += length + handle.length + PAIR_OVERHEAD;
      }
    }
    this.issuers = issuers;
  }

  /**
   * The heap the request's tool-call ids hold from their resolution to its end (`held_bytes`): each
   * resolved handle with what it opened, and the (original, handle) pairs of an attempt's restored
   * sites, which the attempt keeps for an error that quotes an original and the record keeps a copy of.
   */
  get heldBytes(): number {
    let resolved = 0;
    for (const [handle, r] of this.resolved) resolved += Resolution.bytesOf(handle, r.value === null ? 0 : utf8Length(r.value), r.label);
    return resolved + 2 * this.pairBytes;
  }

  /**
   * What a resolved handle holds whose original is `opens` bytes long (`Resolved::bytes_of`): before a
   * row is opened, its sealed content's length, which the original is never longer than.
   */
  static bytesOf(handle: string, opens: number, label: string | null): number {
    return handle.length + opens + (label === null ? 0 : utf8Length(label)) + RESOLVED_OVERHEAD;
  }

  /**
   * The original an attempt at a route of `issuer` speaking `protocol` is sent in place of `handle`:
   * where that route issued it and the protocol takes it, while its content is kept (`original`).
   */
  original(handle: string, issuer: string, protocol: Protocol): string | null {
    const found = this.resolved.get(handle);
    if (found === undefined || found.kind !== 1 || found.value === null || found.issuer !== issuer) return null;
    return found.protocol === protocol || fits(protocol, found.value) ? found.value : null;
  }

  /** Whether an attempt at a route of `issuer` speaking `protocol` is sent an original among `sites` (`restores`). */
  restores(issuer: string, protocol: Protocol, sites: readonly { readonly value: string }[]): boolean {
    return sites.some((site) => this.original(site.value, issuer, protocol) !== null);
  }

  private counted(): AttemptIds {
    return { ...emptyAttemptIds(), lost: this.counts.lost, foreign: this.counts.foreign, contentDeleted: this.counts.contentDeleted };
  }

  /** A site sent its handle: counted as another issuer's, or as the issuer's on a protocol that does not take it. */
  private sentHandle(ids: AttemptIds, handle: string, issuer: string): void {
    const found = this.resolved.get(handle)!;
    if (found.issuer !== issuer) ids.otherIssuer += 1;
    else if (found.value !== null) ids.unfit += 1;
  }

  /**
   * The changes one attempt at a route of `issuer` speaking `protocol` makes to the client's bytes
   * (`apply` on bytes): each site of a bound handle (`sites`, from the body's scan) that gets its
   * original, and each Responses call item id (`items`) its route did not give. The rest of the body
   * goes as the client sent it, the handles in it.
   */
  attempt(issuer: string, protocol: Protocol, sites: readonly ByteSite[], items: readonly ItemId[]): { readonly edits: ByteEdit[]; readonly ids: AttemptIds } {
    const ids = this.counted();
    const edits: ByteEdit[] = [];
    const callIssuer = new Map<number, string>();
    for (const site of sites) {
      const found = this.resolved.get(site.value);
      if (found === undefined || found.kind !== 1) continue;
      callIssuer.set(site.start, found.issuer);
      const original = this.original(site.value, issuer, protocol);
      if (original !== null) {
        edits.push({ start: site.start, end: site.end, text: JSON.stringify(original) });
        ids.restored += 1;
        ids.pairs.push([original, site.value]);
      } else {
        this.sentHandle(ids, site.value, issuer);
      }
    }
    for (const item of items) {
      const owner = callIssuer.get(item.callStart);
      if (owner === undefined || owner === issuer) continue;
      for (const span of item.spans) edits.push({ start: span.start, end: span.end, text: "" });
      ids.itemIdsDropped += 1;
    }
    edits.sort((a, b) => a.start - b.start);
    return { edits, ids };
  }

  /**
   * `apply` on a body written again from its parse (equal keys collapsed): sets every bound site of
   * `body` (a copy, the request's parse) for an attempt at a route of `issuer` speaking `protocol`.
   */
  applyValue(issuer: string, protocol: Protocol, body: Json): AttemptIds {
    const ids = this.counted();
    for (const site of requestSites(protocol, body)) {
      const handle = siteValue(site, body);
      if (handle === undefined || !this.bound(handle)) continue;
      const original = this.original(handle, issuer, protocol);
      if (original !== null) {
        setSite(site, body, original);
        ids.restored += 1;
        ids.pairs.push([original, handle]);
      } else {
        this.sentHandle(ids, handle, issuer);
      }
      if (protocol === "open_ai_responses" && site.role === "call") {
        const item = walkTo(body, site.path.slice(0, -1));
        if (item !== null && this.resolved.get(handle)!.issuer !== issuer && Object.hasOwn(item, "id")) {
          delete item.id;
          ids.itemIdsDropped += 1;
        }
      }
    }
    return ids;
  }

  /**
   * Puts the composed ids back into a request about to be translated (`substitute_composites`), so the
   * translation layer finds what they carry: the whole composed id, or only its own id once its
   * content was deleted. `body` is a copy: the request's parse is the client's.
   */
  substituteComposites(protocol: Protocol, body: Json): void {
    if (!this.hasComposites) return;
    for (const site of requestSites(protocol, body)) {
      const handle = siteValue(site, body);
      const found = handle === undefined ? undefined : this.resolved.get(handle);
      if (found === undefined || found.kind !== 2) continue;
      const id = found.value ?? found.label;
      if (id !== null) setSite(site, body, id);
    }
  }
}

/** The object at `path` of `body`, or null. */
function walkTo(body: Json, path: readonly (string | number)[]): Record<string, Json> | null {
  let at: Json | undefined = body;
  for (const step of path) {
    if (at === null || typeof at !== "object") return null;
    at = Array.isArray(at) ? (typeof step === "number" ? at[step] : undefined) : typeof step === "string" && Object.hasOwn(at, step) ? (at as Record<string, Json>)[step] : undefined;
  }
  return at !== null && typeof at === "object" && !Array.isArray(at) ? (at as Record<string, Json>) : null;
}
