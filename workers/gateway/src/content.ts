/// <reference path="../../packages/content/src/node.d.ts" />
import { createHash } from "node:crypto";
import type { GatewayConfig } from "@gray/config";
import {
  CHUNK_SEALED_BYTES,
  ContentBudget,
  type ContentReason,
  type ContentStore,
  ContentWriter,
  type DetailsRecord,
  type Placement,
  type RecipientVerifyingKeys,
  type WriterResult,
  notWritten,
  objectKey,
  parseRecipientVerifyingKeys,
  placementScope,
  scopeLabel,
  utcDay,
  verifyRecipient,
  type AttemptRecord,
  type WriterTimers,
} from "@gray/content";
import type { ContentBucket } from "./outbound.ts";
import type { Retained } from "./retained.ts";
import type { AnswerSink } from "./sinks.ts";
import type { GatewaySnapshot, GatewayRecipient } from "./snapshot.ts";

/**
 * A request's content on the gateway (docs/cloudflare-native/content.md 2.7 and 3): the identity it is
 * sealed to, chosen and checked when the request's scope is known (before its body is read), and the
 * writer that seals it into R2 as it streams. The gateway holds no secret for content: it seals to the
 * recipient a snapshot record names, after it verified the record's signature with
 * CONTENT_RECIPIENT_KEYS, and never to anything else (no record of the day: `no_recipient`; a record
 * that does not verify: `recipient_invalid` and a security alert). The request is served either way.
 */

/** The public pseudonym of a route (`routing::provider_ref`, inference.ts `providerRef`): SHA-256 of `operator:endpoint`, hex; synchronous for the attempt records. */
export function providerRefOf(operator: string, endpointId: string): string {
  return createHash("sha256").update(`${operator}:${endpointId}`, "utf8").digest("hex");
}

/** The most of each part a request with a usable key stores, and one without (crates/gray-gateway/src/request_log/capture.rs AUTHENTICATED_CAP, ANONYMOUS_CAP). */
export const CONTENT_CAP = 32 * 1024 * 1024;
export const KEYLESS_CONTENT_CAP = 64 * 1024;

export type RecipientLookup =
  | { readonly kind: "ok"; readonly record: GatewayRecipient }
  | { readonly kind: "no_recipient" }
  | { readonly kind: "recipient_invalid"; readonly record: GatewayRecipient };

/**
 * The isolate's recipient records, each verified once (content.md 2.7): verifying an Ed25519
 * signature takes about 0.04 ms in workerd, and a record is the same for every request of its scope
 * and day. Records the snapshot no longer lists are forgotten when a new version arrives.
 */
export class RecipientBook {
  private keys: { readonly spec: string; readonly keys: Promise<RecipientVerifyingKeys> } | null = null;
  private readonly verified = new Map<string, boolean>();
  /** The (scope, day)s a keyed request found no record for, alerted once each in an isolate's life (a day is a new key). */
  private readonly missing = new Set<string>();
  private version = -1;
  private readonly log: (event: Record<string, unknown>) => void;

  constructor(log: (event: Record<string, unknown>) => void = (e) => console.error(JSON.stringify(e))) {
    this.log = log;
  }

  private keysFor(spec: string): Promise<RecipientVerifyingKeys> {
    if (this.keys === null || this.keys.spec !== spec) {
      const keys = parseRecipientVerifyingKeys(spec);
      keys.catch(() => {});
      this.keys = { spec, keys };
    }
    return this.keys.keys;
  }

  /**
   * The identity of `scope` for `day`: the newest generation the snapshot carries, verified. `keyed`: the
   * request has a usable key, so a missing record is alerted on (content.md 2.7), once per scope, day and
   * isolate; every request without one is counted by its point (`no_recipient`).
   */
  async lookup(snapshot: GatewaySnapshot | null, spec: string, scope: string, day: number, keyed = false): Promise<RecipientLookup> {
    if (snapshot !== null && snapshot.version !== this.version) this.forget(snapshot);
    let record: GatewayRecipient | undefined;
    // Only a record of this scope, whatever key the snapshot filed it under (content.md 2.7: never another scope's).
    for (const r of snapshot?.contentRecipients[scope] ?? []) if (r.scope === scope && r.day === day && (record === undefined || r.generation > record.generation)) record = r;
    if (record === undefined) {
      const at = `${scope}\u0000${day}`;
      if (keyed && snapshot !== null && !this.missing.has(at)) {
        this.missing.add(at);
        this.log({ level: "alert", event: "content_no_recipient", scope, day });
      }
      return { kind: "no_recipient" };
    }
    const id = recordId(record);
    let ok = this.verified.get(id);
    if (ok === undefined) {
      let keys: RecipientVerifyingKeys;
      try {
        keys = await this.keysFor(spec);
      } catch {
        keys = new Map();
      }
      ok = await verifyRecipient({ ...record }, keys);
      this.verified.set(id, ok);
      if (!ok) {
        // A record that does not verify was written by something that is not the content Worker, or with a
        // key the gateway does not have (content.md 2.7): never sealed to, said once per record and isolate.
        this.log({ level: "alert", event: "content_recipient_invalid", scope, day, generation: record.generation, sig_key_id: record.sigKeyId });
      }
    }
    return ok ? { kind: "ok", record } : { kind: "recipient_invalid", record };
  }

  private forget(snapshot: GatewaySnapshot): void {
    this.version = snapshot.version;
    const listed = new Set<string>();
    for (const records of Object.values(snapshot.contentRecipients)) for (const r of records) listed.add(recordId(r));
    for (const id of this.verified.keys()) if (!listed.has(id)) this.verified.delete(id);
  }
}

function recordId(r: GatewayRecipient): string {
  return `${r.scope}\u0000${r.day}\u0000${r.generation}\u0000${r.recipient}\u0000${r.sigKeyId}\u0000${r.sig}`;
}

/** What one isolate holds for content: its budget, its verified recipients, and the most of a keyed part it stores. */
export class ContentState {
  readonly budget: ContentBudget;
  readonly recipients: RecipientBook;
  /**
   * The most of each part a request with a usable key stores: CONTENT_CAP, as the Rust server's; the Worker sets
   * nothing else. A test of what the cap cuts passes a smaller one, so its bodies are a few MiB past it, not 40.
   */
  readonly cap: number;
  constructor(maxBytes: number, recipients = new RecipientBook(), cap = CONTENT_CAP) {
    this.budget = new ContentBudget(maxBytes);
    this.recipients = recipients;
    this.cap = cap;
  }
}

/**
 * R2 as the writer needs it (content.md 3.3): each object written once, create-only (an
 * `If-None-Match: *` condition, which R2 checks atomically: the second write of a key gets null), with
 * its SHA-256 (R2 refuses bytes that do not match) and the digest in its metadata, as a
 * FixedLengthStream of the sealed chunks, never joined into one buffer. A null answer is told apart by
 * the object's metadata: the same digest is an earlier attempt that did write.
 */
export function r2ContentStore(bucket: ContentBucket): ContentStore {
  return {
    async put(key, parts, length, sha256) {
      const { readable, writable } = new FixedLengthStream(length);
      const writer = writable.getWriter();
      const pumping = (async () => {
        for (const p of parts) await writer.write(p);
        await writer.close();
      })();
      pumping.catch(() => {});
      let written: R2Object | null;
      try {
        written = await bucket.put(key, readable, {
          onlyIf: new Headers({ "if-none-match": "*" }),
          sha256,
          customMetadata: { sha256 },
          httpMetadata: { contentType: "application/octet-stream" },
        });
      } catch (error) {
        writer.abort(error).catch(() => {});
        throw error;
      }
      await pumping.catch(() => {});
      if (written !== null) return "stored";
      const head = await bucket.head(key);
      return head?.customMetadata?.sha256 === sha256 ? "same" : "conflict";
    },
    async delete(keys) {
      // R2 deletes at most 1,000 keys a call (developers.cloudflare.com/r2/api/workers/workers-api-reference/).
      for (let at = 0; at < keys.length; at += 1000) await bucket.delete(keys.slice(at, at + 1000));
    },
  };
}

/**
 * The keyless limits (content.md 9): a request whose workspace is not known stores content and an index
 * row only within its sender's and its location's rate (two Rate Limiting bindings, each counted per
 * Cloudflare location); past either, neither is written and the point says `keyless_rate`.
 */
export interface KeylessLimits {
  allow(sender: string | null): Promise<boolean>;
}

export function keylessLimits(perSender: RateLimit | undefined, perLocation: RateLimit | undefined): KeylessLimits | null {
  if (perSender === undefined && perLocation === undefined) return null;
  return {
    async allow(sender) {
      // A binding that fails does not stop the request's record: it fails open.
      const sent = perSender === undefined ? true : await perSender.limit({ key: `sender:${sender ?? "unknown"}` }).then((r) => r.success, () => true);
      if (!sent) return false;
      return perLocation === undefined ? true : await perLocation.limit({ key: "keyless" }).then((r) => r.success, () => true);
    },
  };
}

export interface RequestContentDeps {
  readonly cfg: GatewayConfig;
  readonly state: ContentState;
  /** The content bucket through the request's Outbound (background calls). */
  readonly bucket: ContentBucket;
  readonly clock: () => number;
  /** The timers the writer's deadline and puts run on (`GatewayDeps.waitTimers`): the platform's when absent. */
  readonly timers?: WriterTimers;
  readonly background: (p: Promise<unknown>) => void;
  readonly retained: Retained;
  readonly log: (event: Record<string, unknown>) => void;
}

/** One request's content: its writer, or why it has none. */
export class RequestContent implements AnswerSink {
  readonly placement: Placement;
  private readonly writer: ContentWriter | null;
  private readonly none: { readonly status: "failed" | "shed"; readonly reason: ContentReason } | null;
  private readonly deps: RequestContentDeps;
  private responseHead: { readonly status: number; readonly headers: Headers } | null = null;

  private constructor(deps: RequestContentDeps, placement: Placement, writer: ContentWriter | null, none: RequestContent["none"]) {
    this.deps = deps;
    this.placement = placement;
    this.writer = writer;
    this.none = none;
  }

  /**
   * The request's content from its placement (content.md 2.7): the day's recipient of its scope, from
   * the snapshot the request read, verified; then the writer, or `shed` when the budget has no room.
   */
  static async open(deps: RequestContentDeps, snapshot: GatewaySnapshot | null, placement: Placement, requestId: string, startedMs: number): Promise<RequestContent> {
    const scope = scopeLabel(placementScope(placement));
    const day = utcDay(startedMs);
    const keyed = placement.kind !== "anonymous";
    const found = await deps.state.recipients.lookup(snapshot, deps.cfg.contentRecipientKeys, scope, day, placement.kind === "workspace");
    if (found.kind !== "ok") return new RequestContent(deps, placement, null, { status: "failed", reason: found.kind });
    const writer = ContentWriter.open({
      budget: deps.state.budget,
      store: r2ContentStore(deps.bucket),
      settings: {
        pieceChunks: deps.cfg.contentPieceBytes / CHUNK_SEALED_BYTES,
        requestBlockBytes: deps.cfg.contentRequestBlockBytes,
        deflateLevel: deps.cfg.contentDeflateLevel,
        putTimeoutMs: deps.cfg.contentPutTimeoutMs,
      },
      recipient: found.record.recipient,
      scope,
      day,
      generation: found.record.generation,
      base: objectKey(placement, startedMs, requestId),
      requestId,
      startedMs,
      caps: keyed ? { request: deps.state.cap, response: deps.state.cap } : { request: KEYLESS_CONTENT_CAP, response: KEYLESS_CONTENT_CAP },
      clock: deps.clock,
      ...(deps.timers === undefined ? {} : { timers: deps.timers }),
      background: deps.background,
      log: deps.log,
      onHeld: (bytes) => deps.retained.set("content", bytes),
    });
    if (writer === null) return new RequestContent(deps, placement, null, { status: "shed", reason: "isolate_budget" });
    return new RequestContent(deps, placement, writer, null);
  }

  /** The answer's bytes, as the client is sent them. */
  push(bytes: Uint8Array): void {
    this.writer?.push(bytes);
  }

  end(): void {}

  /** The held request body (tiers A and B). */
  requestHeld(bytes: Uint8Array): void {
    this.writer?.requestHeld(bytes);
  }

  /**
   * A spooled request body (tier C): read by the writer from its start, decrypted, its first part up to the
   * cap (the writer cancels the read there); `open` reads it through the request's Outbound (spool.ts `spoolPlaintext`).
   */
  requestSpooled(open: () => Promise<ReadableStream<Uint8Array> | null>, length: number): void {
    const writer = this.writer;
    if (writer === null) return;
    const empty = () => new ReadableStream<Uint8Array>({ start: (c) => c.close() });
    const reading = open().then(
      (plain) => writer.requestStream(plain ?? empty(), plain === null ? 0 : length),
      () => writer.requestStream(empty(), 0),
    );
    this.deps.background(reading);
  }

  /** The request path let go of its body (an upstream answered). */
  releaseRequest(): void {
    this.writer?.releaseRequest();
  }

  /** Resolves once the writer needs nothing more of a spooled body. */
  get requestDone(): Promise<void> {
    return this.writer?.requestDone ?? Promise.resolve();
  }

  attempt(record: AttemptRecord): void {
    this.writer?.attempt(record);
  }

  /** The response's status and headers as the client got them (the details record's). */
  responseStarted(status: number, headers: Headers): void {
    this.responseHead ??= { status, headers };
  }

  get responseHeaders(): Headers | null {
    return this.responseHead?.headers ?? null;
  }

  /** Ends the content by `deadline`; never throws. */
  async finish(o: { readonly deadline: number; readonly details: DetailsRecord; readonly requestComplete: boolean }): Promise<WriterResult> {
    if (this.writer === null) return notWritten(this.none!.status, this.none!.reason);
    return this.writer.finish(o);
  }

  /** Drops what the writer holds, writing nothing (a keyless request past its limit). */
  discard(): void {
    this.writer?.discard();
  }
}
