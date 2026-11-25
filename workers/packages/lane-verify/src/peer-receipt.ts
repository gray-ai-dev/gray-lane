/**
 * The customer's check of a stack-routed request's two receipts (docs/confidential-lane-stack-routing.md §4.8):
 * the entry's outer receipt names each peer attempt only by a commitment (`peer.answered.peer`, `peer.failed.peer`,
 * `@gray/attest` `peerCommitment`), and the entry serves, per attempt number, what the commitment opens to:
 *
 *     GET /v1/aci/receipts/{id}/peers/{n}
 *       → {n, attestation: {report, nonce, tls_spki_sha256, host, relay_id}, receipt: <inner receipt> | null}
 *
 * the stack VM's ACI report the entry verified before it sent (with the nonce and TLS SPKI it verified it under, the
 * VM's host and the relay the route named), and the stack VM's own receipt for the attempt (the inner receipt, fetched
 * late by the entry when it did not come with the answer). `verifyPeerReceipts` checks, per attempt number, with ids
 * `peer:<n>:…`:
 *
 * 1. the attestation, as the entry checked it (`verifyPeerAttestation`, layout `stack`, against Gray's signed stack
 *    list the customer supplies): DCAP, the compose and OS image pinned by the list, a stack release, a sealed boot of
 *    the named relay, the TLS SPKI in the keyset;
 * 2. the commitment: the outer event's `peer` is `peerCommitment` of that attestation's keyset digest, compose hash,
 *    OS image and relay image and the outer `inner.receipt_sha256` (so the served report is the one the entry pinned);
 * 3. when the outer receipt names the inner one, the served inner receipt is it (its JCS SHA-256 and its id);
 * 4. the inner receipt verifies under the attested stack keyset (`verifyResponseReceipt`: signature, grammar, the
 *    customer's bytes as `request.received`, each attempt's forwarded body replayed, the relay's own changes as
 *    `attempt:K:relay_changes`, the relay image the attested boot runs, and for the served attempt when `responseBytes`
 *    is supplied, `response_events_sha256` or `response_body_sha256` and `response_served_attempt`, including undoing
 *    any declared `response.returned.rewrites` against the customer's response bytes);
 * 5. its `peer.entry` names this outer receipt (the entry's keyset digest, the outer receipt id and the attempt number),
 *    so an inner receipt cannot be shown under another request;
 * 6. inner `request.received` equals outer `request.received`, and for the attempt that served the answer, inner
 *    `response.returned`'s `events_sha256` or `body_sha256` equals the outer one's (L6). When the attempt's
 *    `peer.forwarded` declares the entry's ops on the hop's body (`modified`, docs/design/one-address.md: the routing
 *    preference the client stated in the body, `remove_member /provider`), the customer's bytes with those ops replayed
 *    under the published rewrite policy are what the stack VM must have received: the inner receipt is checked against
 *    them (step 4) and its `request.received` compared with their digest.
 *
 * A missing inner receipt fails where the stack VM must have made one: a hop that answered and dialed a vendor (or did
 * not say), and an attempt that may have reached the stack VM and was not refused by it before any frame. An attempt
 * that sent nothing, or that the stack VM refused before any frame, has none to show.
 */
import {
  EVENT_PEER_ANSWERED,
  EVENT_PEER_ENTRY,
  EVENT_PEER_FAILED,
  EVENT_PEER_FORWARDED,
  EVENT_REQUEST_CONTINUATION_EXPANDED,
  EVENT_REQUEST_RECEIVED,
  EVENT_RESPONSE_RETURNED,
  adoptKeyset,
  bodyHash,
  eventType,
  findEvent,
  findEvents,
  isDigestField,
  isJcsValue,
  jcsBytes,
  peerCommitment,
  reportKeysetValue,
  requestModifiedSchema,
  sha256BareHex,
  type RelayStackChanges,
  type RequestModifiedEvent,
} from "@gray/attest";
import { isLaneProtocol, replayForwarded, rewriteRuleFor, ruleAllowsValue, textPolicyOf } from "@gray/lane";
import { get, isObject, parseStrict, type Json } from "@gray/json";
import type { QuoteVerifier } from "./attestation.ts";
import { verifyPeerAttestation, type PeerReleaseList } from "./peer.ts";
import {
  checkContinuationExpandedEvent,
  protocolForEndpoint,
  verifyResponseReceipt,
  type ReceiptCheck,
  type ReceiptContinuationExpanded,
  type StackReceiptSummary,
  type TemplateText,
} from "./receipt.ts";
import { STACK_RELAY_ID_PATTERN } from "./stack-boot.ts";

/** The stack VM's refusals before any frame (`@gray/lane-wire` PEER_REFUSAL_STATUS): it registered nothing, so it made no receipt. */
export const PEER_REFUSED_BEFORE_FRAMES: ReadonlySet<string> = new Set([
  "peer_malformed",
  "peer_unknown",
  "peer_audience",
  "peer_replayed",
  "peer_body_mismatch",
  "route_unconfigured",
  "foreign_relay",
]);

/** What the entry verified a stack VM with (the answer's `attestation`). */
export interface PeerAttestationAnswer {
  /** The stack VM's ACI report, as the entry got it. */
  readonly report: Json;
  /** The nonce the entry attested with, 64 lower-case hex. */
  readonly nonce: string;
  /** SHA-256 of the SPKI egress saw on the stack VM's TLS, 64 lower-case hex. */
  readonly tls_spki_sha256: string;
  /**
   * The stack VM's host (no scheme), or "" for a VM the entry reaches over the session the VM's peerlink holds
   * (docs/design/relay-outbound-only.md §3.5: no host; the entry attested it under "", the relay pin its identity rule).
   */
  readonly host: string;
  /** The relay the route named. */
  readonly relay_id: string;
}

/** One answer of `GET /v1/aci/receipts/{id}/peers/{n}`. */
export interface PeerAnswer {
  readonly n: bigint;
  readonly attestation: PeerAttestationAnswer;
  /** The inner receipt document, or null when the stack VM holds none for the attempt. */
  readonly receipt: Json | null;
}

export type ReadPeerAnswerResult = { readonly ok: true; readonly answer: PeerAnswer } | { readonly ok: false; readonly message: string };

const HEX32 = /^[0-9a-f]{64}$/;
const HOST = /^[a-z0-9.-]{1,253}$/;

/** Read an answer's text with the strict reader (duplicate keys refused, integers as bigint); no member beyond the contract. */
export function readPeerAnswerText(text: string): ReadPeerAnswerResult {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch (error) {
    return { ok: false, message: `not JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
  return readPeerAnswer(value);
}

/** The same check on a value already read with the strict reader. */
export function readPeerAnswer(value: Json): ReadPeerAnswerResult {
  const refuse = (message: string): ReadPeerAnswerResult => ({ ok: false, message });
  if (!isObject(value)) return refuse("the answer is not an object");
  const extra = Object.keys(value).filter((key) => key !== "n" && key !== "attestation" && key !== "receipt");
  if (extra.length > 0) return refuse(`unknown member ${extra[0]}`);
  const n = get(value, "n");
  if (typeof n !== "bigint" || n < 1n || n > 2_147_483_647n) return refuse("n is an attempt number from 1 to 2^31-1");
  const attestation = get(value, "attestation");
  if (!isObject(attestation)) return refuse("attestation is not an object");
  const members = ["report", "nonce", "tls_spki_sha256", "host", "relay_id"];
  const unknown = Object.keys(attestation).filter((key) => !members.includes(key));
  if (unknown.length > 0) return refuse(`unknown attestation member ${unknown[0]}`);
  const report = get(attestation, "report");
  const nonce = get(attestation, "nonce");
  const spki = get(attestation, "tls_spki_sha256");
  const host = get(attestation, "host");
  const relayId = get(attestation, "relay_id");
  if (!isObject(report)) return refuse("attestation.report is not an object");
  if (typeof nonce !== "string" || !HEX32.test(nonce)) return refuse("attestation.nonce is not 32 bytes as lower-case hex");
  if (typeof spki !== "string" || !HEX32.test(spki)) return refuse("attestation.tls_spki_sha256 is not 32 bytes as lower-case hex");
  if (typeof host !== "string" || (host !== "" && !HOST.test(host))) return refuse("attestation.host is not a lower-case host name or empty (a VM reached over its session)");
  if (typeof relayId !== "string" || !STACK_RELAY_ID_PATTERN.test(relayId)) return refuse("attestation.relay_id is not a deployment id");
  const receipt = get(value, "receipt");
  if (receipt === undefined) return refuse("receipt is missing (null when the stack VM holds none)");
  if (receipt !== null && !isObject(receipt)) return refuse("receipt is not a receipt document or null");
  return { ok: true, answer: { n, attestation: { report, nonce, tls_spki_sha256: spki, host, relay_id: relayId }, receipt } };
}

/** One answer event of the outer receipt (`peer.answered` or `peer.failed`), in log order. */
export interface OuterPeerAttempt {
  readonly n: bigint;
  readonly outcome: "answered" | "failed";
  /** `peer.answered.dialed`; null for `peer.failed` or when the hop did not say. */
  readonly dialed: boolean | null;
  readonly inner: { readonly receipt_id: string; readonly receipt_sha256: string } | null;
  readonly peer: string;
  /** `peer.failed.code` and `sent`; null for `peer.answered`. */
  readonly code: string | null;
  readonly sent: boolean | null;
  /** The entry's declared ops on the hop's body, from the `peer.forwarded` this event answers; null without any. */
  readonly modified: readonly Json[] | null;
}

/** The outer receipt's peer attempts, in log order (empty for a receipt that forwarded nothing to a stack VM). */
export function outerPeerAttempts(outer: Json): OuterPeerAttempt[] {
  const log = get(outer, "event_log");
  if (!Array.isArray(log)) return [];
  const out: OuterPeerAttempt[] = [];
  // Each answer event answers the `peer.forwarded` just before it (the outer grammar's `peer_order`).
  let modified: readonly Json[] | null = null;
  for (const event of log as readonly Json[]) {
    const type = eventType(event);
    if (type === EVENT_PEER_FORWARDED) {
      const declared = get(event, "modified");
      modified = Array.isArray(declared) ? (declared as readonly Json[]) : null;
      continue;
    }
    if (type !== EVENT_PEER_ANSWERED && type !== EVENT_PEER_FAILED) continue;
    const n = get(event, "n");
    const peer = get(event, "peer");
    if (typeof n !== "bigint" || typeof peer !== "string") continue;
    if (type === EVENT_PEER_ANSWERED) {
      const dialed = get(event, "dialed");
      const inner = get(event, "inner");
      const id = isObject(inner) ? get(inner, "receipt_id") : undefined;
      const sha = isObject(inner) ? get(inner, "receipt_sha256") : undefined;
      out.push({
        n,
        outcome: "answered",
        dialed: typeof dialed === "boolean" ? dialed : null,
        inner: typeof id === "string" && typeof sha === "string" ? { receipt_id: id, receipt_sha256: sha } : null,
        peer,
        code: null,
        sent: null,
        modified,
      });
    } else {
      const code = get(event, "code");
      const sent = get(event, "sent");
      out.push({ n, outcome: "failed", dialed: null, inner: null, peer, code: typeof code === "string" ? code : null, sent: typeof sent === "boolean" ? sent : null, modified });
    }
  }
  return out;
}

/** Whether nothing of the attempt reached a stack VM's lane: the entry has no stack VM's record of it to serve. */
function reachedNothing(attempt: OuterPeerAttempt): boolean {
  return attempt.outcome === "failed" && attempt.sent === false;
}

/**
 * The attempt numbers whose `/peers/{n}` answer the check needs: each number once, in log order, unless the last attempt
 * of that number sent nothing (the entry serves the last attempt of a number).
 */
export function peerNumbersToFetch(outer: Json): bigint[] {
  const last = new Map<bigint, OuterPeerAttempt>();
  for (const attempt of outerPeerAttempts(outer)) last.set(attempt.n, attempt);
  return [...last.values()].filter((attempt) => !reachedNothing(attempt)).map((attempt) => attempt.n);
}

/** Why an answer could not be had (the fetch's error, or the entry's error code). */
export interface PeerAnswerError {
  readonly error: string;
}

export interface VerifyPeerReceiptsOptions {
  /** The outer receipt document, already verified under the attested entry's keyset. */
  readonly outer: Json;
  /** The exact request body the customer sent. */
  readonly receivedBody: Uint8Array;
  /** Optional expanded body plaintext when the outer receipt records `request.continuation_expanded`. */
  readonly expandedBody?: Uint8Array;
  /** The raw response bytes the customer received, SSE framing included, when kept. */
  readonly responseBytes?: Uint8Array;
  /** The relay's template texts, for its declared appends (as for a direct receipt). */
  readonly templates: readonly TemplateText[];
  /** Gray's signed stack list (`lane/stack/release-list.json`) with its key, and its freshness document when given. */
  readonly releaseList: PeerReleaseList;
  readonly quoteVerifier: QuoteVerifier;
  readonly nowSecs: bigint;
  /** The answers by attempt number (decimal text), as `peerNumbersToFetch` named them. */
  readonly answers: ReadonlyMap<string, PeerAnswer | PeerAnswerError>;
}

/** What one attempt number's records said, for the machine output. */
export interface PeerReceiptSummary {
  readonly n: string;
  readonly host: string | null;
  readonly relay_id: string | null;
  readonly relay_image: string | null;
  readonly keyset_digest: string | null;
  readonly compose_hash: string | null;
  readonly inner_receipt_id: string | null;
  readonly inner_receipt_sha256: string | null;
  /** The inner receipt's attempts (S26), the relay's own changes per attempt included, or null without one. */
  readonly stack: StackReceiptSummary | null;
}

export interface PeerReceiptsVerification {
  readonly ok: boolean;
  readonly checks: readonly ReceiptCheck[];
  readonly peers: readonly PeerReceiptSummary[];
}

/** Check every peer attempt of a verified outer receipt against the entry's answers (the module's comment). */
export async function verifyPeerReceipts(options: VerifyPeerReceiptsOptions): Promise<PeerReceiptsVerification> {
  const checks: ReceiptCheck[] = [];
  const peers: PeerReceiptSummary[] = [];
  const attempts = outerPeerAttempts(options.outer);
  if (attempts.length === 0) {
    checks.push(skip("peers", "the receipt names no peer attempt: no stack VM served any part of the request"));
    return { ok: true, checks, peers };
  }
  const outerEvents = get(options.outer, "event_log");
  const outerExpandedEvents = Array.isArray(outerEvents) ? findEvents(outerEvents as readonly Json[], EVENT_REQUEST_CONTINUATION_EXPANDED) : [];
  let outerExpanded: ReceiptContinuationExpanded | null = null;
  if (outerExpandedEvents.length > 1) {
    checks.push(fail("continuation_expanded", "outer receipt carries more than one request.continuation_expanded event"));
  } else if (outerExpandedEvents.length === 1) {
    const outerProtocol = protocolForEndpoint(String(get(options.outer, "endpoint") ?? ""));
    const checked = checkContinuationExpandedEvent(outerExpandedEvents[0]!, outerProtocol, options.receivedBody, options.expandedBody);
    checks.push(checked.check);
    if (checked.ok) outerExpanded = checked.event;
  }
  const lastOf = new Map<bigint, OuterPeerAttempt>();
  for (const attempt of attempts) lastOf.set(attempt.n, attempt);
  for (const [index, attempt] of attempts.entries()) {
    const id = `peer:${attempt.n}`;
    if (lastOf.get(attempt.n) !== attempt) {
      // The relay's next origin was tried within the same attempt number: the entry keeps the last one.
      if (reachedNothing(attempt) || (attempt.code !== null && PEER_REFUSED_BEFORE_FRAMES.has(attempt.code))) {
        checks.push(skip(`${id}:origin:${index + 1}`, `not checked: this try sent nothing a stack VM recorded (${String(attempt.code)}); the next origin was tried`));
      } else {
        checks.push(fail(`${id}:origin:${index + 1}`, "an earlier try of this attempt number reached a stack VM, and only the last try's records are served"));
      }
      continue;
    }
    if (reachedNothing(attempt)) {
      checks.push(skip(id, `not checked: nothing reached a stack VM (${String(attempt.code)})`));
      continue;
    }
    const answer = options.answers.get(attempt.n.toString());
    if (answer === undefined || "error" in answer) {
      checks.push(fail(`${id}:fetch`, `the entry served no record of this attempt${answer === undefined ? "" : `: ${answer.error}`}`));
      peers.push(emptySummary(attempt.n));
      continue;
    }
    peers.push(await checkPeer(attempt, answer, options, checks, outerExpanded));
  }
  return { ok: checks.every((check) => check.status !== "fail"), checks, peers };
}

async function checkPeer(
  attempt: OuterPeerAttempt,
  answer: PeerAnswer,
  options: VerifyPeerReceiptsOptions,
  checks: ReceiptCheck[],
  outerExpanded: ReceiptContinuationExpanded | null,
): Promise<PeerReceiptSummary> {
  const id = `peer:${attempt.n}`;
  const summary = { ...emptySummary(attempt.n), host: answer.attestation.host, relay_id: answer.attestation.relay_id } as { -readonly [K in keyof PeerReceiptSummary]: PeerReceiptSummary[K] };
  if (answer.n !== attempt.n) {
    checks.push(fail(`${id}:answer`, `the entry answered for attempt ${answer.n}`));
    return summary;
  }

  // 1. The attestation, as the entry checked it before it sent (section 4.3).
  const served = answer.attestation;
  const verified = await verifyPeerAttestation(served.report, {
    layout: "stack",
    releaseList: options.releaseList,
    nonce: served.nonce,
    tlsSpkiSha256: served.tls_spki_sha256,
    host: served.host,
    nowSecs: options.nowSecs,
    expectedRelayId: served.relay_id,
    quoteVerifier: options.quoteVerifier,
  });
  const v = verified.verification;
  const facts = v?.stackBoot?.ok === true && v.stackBoot.facts?.phase === "sealed" ? v.stackBoot.facts : null;
  if (!verified.ok || v === null || v.keysetDigest === null || v.composeHash === null || v.osImageHash === null || facts === null) {
    const failed = verified.checks.filter((check) => check.status === "fail");
    if (failed.length === 0) checks.push(fail(`${id}:attestation`, "the stack VM's report did not verify"));
    for (const check of failed) checks.push(fail(`${id}:attestation:${check.id}`, check.detail));
    checks.push(skip(`${id}:inner_receipt`, "not checked: the stack VM's attestation did not verify"));
    return summary;
  }
  const relayImage = facts.image.image;
  summary.relay_image = relayImage;
  summary.keyset_digest = v.keysetDigest;
  summary.compose_hash = v.composeHash;
  const listLine = verified.checks.find((check) => check.id === "release_list")?.detail ?? "";
  checks.push(pass(`${id}:attestation`, `stack VM ${served.host === "" ? "over its session" : served.host}: keyset ${v.keysetDigest}, stack release ${v.composeHash}, OS image ${v.osImageHash}; ${listLine}`));
  checks.push(pass(`${id}:relay`, `deployment ${facts.identity.relayId} runs ${relayImage} (signed by the deployment key)`));

  // 2. The commitment opens to this boot and the outer receipt's inner digest.
  const commitment = peerCommitment({
    keysetDigest: v.keysetDigest,
    composeHash: v.composeHash,
    osImageHash: v.osImageHash,
    relayImage,
    innerReceiptSha256: attempt.inner?.receipt_sha256 ?? null,
  });
  if (commitment === attempt.peer) checks.push(pass(`${id}:commitment`, `the outer receipt's peer ${attempt.peer} is this stack VM's boot${attempt.inner === null ? "" : " and its inner receipt digest"}`));
  else checks.push(fail(`${id}:commitment`, `the outer receipt's peer is ${attempt.peer}; this attestation${attempt.inner === null ? "" : " and the inner digest"} commit to ${commitment}`));

  // 3. Presence and digest of the inner receipt.
  const receipt = answer.receipt;
  if (receipt === null) {
    const why = missingReason(attempt);
    if (why === null) checks.push(fail(`${id}:inner_receipt`, "no inner receipt: the stack VM's record of what it did with the request (and what the deployment changed) is missing"));
    else checks.push(skip(`${id}:inner_receipt`, `none: ${why}`));
    return summary;
  }
  if (!isJcsValue(receipt)) {
    checks.push(fail(`${id}:inner_receipt`, "the inner receipt is not an ACI canonicalizable JSON document"));
    return summary;
  }
  const digest = sha256BareHex(jcsBytes(receipt));
  const receiptId = get(receipt, "receipt_id");
  summary.inner_receipt_sha256 = digest;
  summary.inner_receipt_id = typeof receiptId === "string" ? receiptId : null;
  if (attempt.inner === null) {
    checks.push(skip(`${id}:inner_digest`, `the outer receipt names no inner digest (it did not come with the answer); ${digest} is held to its signature and peer.entry below`));
  } else if (digest !== attempt.inner.receipt_sha256 || receiptId !== attempt.inner.receipt_id) {
    checks.push(fail(`${id}:inner_digest`, `the outer receipt names ${attempt.inner.receipt_id} with SHA-256 ${attempt.inner.receipt_sha256}; the served one is ${String(receiptId)} with ${digest}`));
  } else {
    checks.push(pass(`${id}:inner_digest`, `${attempt.inner.receipt_id}, SHA-256 ${digest}`));
  }

  // What the stack VM received:
  // - Without outer `request.continuation_expanded`: the customer's bytes, after any declared `peer.forwarded.modified` ops.
  // - With verified outer `request.continuation_expanded`: the expanded body whose digest is `expanded_body_sha256`
  //   (optionally after declared `peer.forwarded.modified` ops).
  let hopBody = options.receivedBody;
  let expandedHopBody: Uint8Array | undefined = options.expandedBody;
  let validatedEntryModified: RequestModifiedEvent[] | undefined;
  if (outerExpanded !== null) {
    if (attempt.modified !== null) {
      const parsedOps: RequestModifiedEvent[] = [];
      for (const rawOp of attempt.modified) {
        const parsed = requestModifiedSchema.safeParse(rawOp);
        if (!parsed.success) {
          checks.push(fail(`${id}:entry_rewrite`, `malformed peer.forwarded.modified op: ${parsed.error.issues.map((i) => i.message).join("; ")}`));
          return summary;
        }
        parsedOps.push(parsed.data as RequestModifiedEvent);
      }
      const policy = textPolicyOf(parsedOps);
      const opsLabel = parsedOps.map((op) => `${op.op} ${op.path}`).join(", ");
      const disallowed = parsedOps.filter((op) => {
        if (op.declared_in !== policy.id) return true;
        const rule = rewriteRuleFor(policy, "open_ai_responses", { op: op.op, path: op.path });
        return rule === undefined || op.value_sha256 !== undefined || !ruleAllowsValue(rule, op.value);
      });
      if (disallowed.length > 0) {
        checks.push(fail(`${id}:entry_rewrite`, `the entry's declared op(s) on the expanded hop body (${opsLabel}) are not allowed by ${policy.id}`));
        return summary;
      }
      if (options.expandedBody !== undefined) {
        const replayed = replayForwarded(options.expandedBody, "open_ai_responses", parsedOps, [], policy);
        if (replayed === null) {
          checks.push(fail(`${id}:entry_rewrite`, `the entry's declared op(s) on the expanded hop body (${opsLabel}) do not replay on the expanded body`));
          return summary;
        }
        expandedHopBody = replayed;
        checks.push(pass(`${id}:entry_rewrite`, `the entry sent the zero-retention expanded body with ${opsLabel}: ${bodyHash(replayed)}`));
      } else {
        checks.push(
          skip(
            `${id}:entry_rewrite`,
            `not compared: the entry declared ${opsLabel} (each one ${policy.id} allows) on the expanded body ${outerExpanded.expanded_body_sha256}, which stays sealed in the entry, so they are not replayed`,
          ),
        );
      }
      validatedEntryModified = parsedOps;
    }
  } else if (attempt.modified !== null) {
    const protocol = protocolForEndpoint(String(get(options.outer, "endpoint")));
    const declared = attempt.modified as unknown as readonly RequestModifiedEvent[];
    // Under the policy the ops name: v1, or v3 on a Codex route whose string `input` the entry wrapped.
    const replayed = protocol !== null && isLaneProtocol(protocol) ? replayForwarded(options.receivedBody, protocol, declared, [], textPolicyOf(declared)) : null;
    const ops = attempt.modified.map((op) => `${String(get(op, "op"))} ${String(get(op, "path"))}`).join(", ");
    if (replayed === null) {
      checks.push(fail(`${id}:entry_rewrite`, `the entry's declared op(s) on the hop's body (${ops}) do not replay on the received body under the published rewrite policy`));
      return summary;
    }
    checks.push(pass(`${id}:entry_rewrite`, `the entry sent the received body with ${ops}: ${bodyHash(replayed)}`));
    hopBody = replayed;
  }

  // 4. The inner receipt under the attested stack keyset (with the relay's changes per attempt, and the
  // customer's response bytes for the attempt that served the answer).
  const keysetValue = reportKeysetValue(served.report);
  const sealed = keysetValue === undefined ? null : adoptKeyset(keysetValue);
  if (sealed === null || sealed.digest !== v.keysetDigest) {
    checks.push(fail(`${id}:inner_keyset`, "the stack VM's report carries no keyset that hashes to its verified digest"));
    return summary;
  }
  const outerEvents = get(options.outer, "event_log") as readonly Json[];
  const outerReturned = findEvent(outerEvents, EVENT_RESPONSE_RETURNED);
  const servedAttempt = get(outerReturned, "served_attempt") === attempt.n;
  // The client got only part of what the stack VM released: it left mid-stream (frames already on the hop never reached
  // it), or the entry ended the stream with Gray's error. The outer response.returned is not tied to the inner one.
  const partial = get(outerReturned, "replaced_error") === true ? "replaced_error" : get(outerReturned, "served_as") === "client_left" ? "client_left" : null;
  const inner = await verifyResponseReceipt(receipt, {
    receivedBody: outerExpanded !== null && expandedHopBody !== undefined ? expandedHopBody : hopBody,
    templates: options.templates,
    keyset: sealed,
    expectedKeysetDigest: v.keysetDigest,
    expectedRelayImage: relayImage,
    ...(outerExpanded === null
      ? {}
      : {
          ...(options.expandedBody === undefined ? {} : { expandedBody: options.expandedBody }),
          outerContinuationExpanded: {
            expandedBodySha256: outerExpanded.expanded_body_sha256,
            ...(validatedEntryModified === undefined ? {} : { modified: validatedEntryModified }),
          },
        }),
    ...(servedAttempt && partial === null && options.responseBytes !== undefined
      ? { responseBytes: options.responseBytes, allowKeepAliveComments: true }
      : {}),
  });
  // For the served attempt with responseBytes, stackChecks emits response_events_sha256 / response_body_sha256
  // and response_served_attempt (including undoing declared rewrites) against the customer's bytes; without
  // responseBytes (or for non-served attempts, or a partial answer, whose bytes the outer receipt alone ties),
  // suppress the inner response_stack_digest skip because step 6 compares outer and inner digests directly.
  for (const check of inner.checks) if (check.id !== "response_stack_digest") checks.push({ ...check, id: `${id}:${check.id}` });
  summary.stack = inner.stack;
  const document = inner.receiptId === null ? null : receipt;
  if (document === null || !inner.ok) return summary;

  // 5. peer.entry names this outer receipt.
  const events = get(document, "event_log") as readonly Json[];
  const entry = findEvent(events, EVENT_PEER_ENTRY);
  const outerDigest = get(options.outer, "workload_keyset_digest");
  const outerId = get(options.outer, "receipt_id");
  if (entry === undefined) {
    checks.push(fail(`${id}:peer_entry`, "the inner receipt has no peer.entry: it does not say it served this entry's request"));
  } else {
    const wrong: string[] = [];
    if (get(entry, "keyset_digest") !== outerDigest) wrong.push(`entry keyset ${String(get(entry, "keyset_digest"))}, not ${String(outerDigest)}`);
    if (get(entry, "receipt_id") !== outerId) wrong.push(`receipt ${String(get(entry, "receipt_id"))}, not ${String(outerId)}`);
    if (get(entry, "n") !== attempt.n) wrong.push(`attempt ${String(get(entry, "n"))}, not ${attempt.n}`);
    if (wrong.length === 0) checks.push(pass(`${id}:peer_entry`, `served entry ${String(outerDigest)} for receipt ${String(outerId)}, attempt ${attempt.n}`));
    else checks.push(fail(`${id}:peer_entry`, `the inner receipt names ${wrong.join("; ")}`));
  }

  // 6. The same request in, and for the served attempt the same answer out (L6).
  const outerReceived = get(findEvent(outerEvents, EVENT_REQUEST_RECEIVED), "body_hash");
  const innerReceived = get(findEvent(events, EVENT_REQUEST_RECEIVED), "body_hash");
  if (outerExpanded !== null) {
    if (attempt.modified === null) {
      if (innerReceived === outerExpanded.expanded_body_sha256) {
        checks.push(
          pass(
            `${id}:request_received`,
            `the stack VM received the entry's zero-retention continuation expanded body (${outerExpanded.expanded_body_sha256})`,
          ),
        );
      } else {
        checks.push(
          fail(
            `${id}:request_received`,
            `the outer request.continuation_expanded.expanded_body_sha256 is ${outerExpanded.expanded_body_sha256}, the inner request.received ${String(innerReceived)}`,
          ),
        );
      }
    } else if (expandedHopBody !== undefined) {
      const sent = bodyHash(expandedHopBody);
      if (innerReceived === sent) {
        checks.push(
          pass(
            `${id}:request_received`,
            `the stack VM received the zero-retention expanded body with declared entry op(s) (${sent})`,
          ),
        );
      } else {
        checks.push(
          fail(
            `${id}:request_received`,
            `the expanded body with declared entry op(s) is ${sent}, the inner request.received ${String(innerReceived)}`,
          ),
        );
      }
    } else if (typeof innerReceived === "string" && isDigestField(innerReceived)) {
      checks.push(
        skip(
          `${id}:request_received`,
          `not compared: the stack VM received ${innerReceived}, the entry's ${attempt.modified.length} declared op(s) over the expanded body ${outerExpanded.expanded_body_sha256}, which stays sealed in the entry, so they are not replayed`,
        ),
      );
    } else {
      checks.push(fail(`${id}:request_received`, `the inner request.received is missing or malformed (${String(innerReceived)})`));
    }
  } else if (attempt.modified !== null) {
    // The outer receipt's own request.received is the customer's bytes (checked against them with the outer receipt).
    const sent = bodyHash(hopBody);
    if (innerReceived === sent) checks.push(pass(`${id}:request_received`, `the stack VM received the bytes the entry sent (${sent}): the entry's received ${String(outerReceived)} with its declared op(s)`));
    else checks.push(fail(`${id}:request_received`, `the entry's received ${String(outerReceived)} with its declared op(s) is ${sent}, the inner request.received ${String(innerReceived)}`));
  } else if (outerReceived === innerReceived) checks.push(pass(`${id}:request_received`, `the stack VM received the bytes the entry received (${String(outerReceived)})`));
  else checks.push(fail(`${id}:request_received`, `the outer request.received is ${String(outerReceived)}, the inner ${String(innerReceived)}`));
  if (servedAttempt) {
    const innerReturned = findEvent(events, EVENT_RESPONSE_RETURNED);
    const member = get(outerReturned, "events_sha256") !== undefined ? "events_sha256" : "body_sha256";
    const outerValue = get(outerReturned, member);
    const innerValue = get(innerReturned, member);
    if (typeof outerValue === "string" && outerValue === innerValue) checks.push(pass(`${id}:response_returned`, `the client got what the stack VM released: ${member} ${outerValue}`));
    else if (partial === "client_left") checks.push(skip(`${id}:response_returned`, `not compared: the client left; partial answer, the outer ${member} ${String(outerValue)} covers what reached it (client_left)`));
    else if (partial === "replaced_error") checks.push(skip(`${id}:response_returned`, `not compared: the client got this attempt's events, then Gray's error (replaced_error); the outer ${member} is ${String(outerValue)}`));
    else checks.push(fail(`${id}:response_returned`, `the outer response.returned ${member} is ${String(outerValue)}, the inner ${String(innerValue)}`));
  } else {
    checks.push(skip(`${id}:response_returned`, "not compared: this attempt did not serve the answer"));
  }
  return summary;
}

/** Why an attempt may have no inner receipt, or null when the stack VM must have made one. */
function missingReason(attempt: OuterPeerAttempt): string | null {
  if (attempt.outcome === "answered") return attempt.dialed === false && attempt.inner === null ? "the stack VM dialed no vendor for this attempt" : null;
  if (attempt.sent !== true) return `nothing reached the stack VM (${String(attempt.code)})`;
  if (attempt.code !== null && PEER_REFUSED_BEFORE_FRAMES.has(attempt.code)) return `the stack VM refused the attempt before any frame (${attempt.code})`;
  return null;
}

function emptySummary(n: bigint): PeerReceiptSummary {
  return { n: n.toString(), host: null, relay_id: null, relay_image: null, keyset_digest: null, compose_hash: null, inner_receipt_id: null, inner_receipt_sha256: null, stack: null };
}

/** The changes the relay made per inner attempt (for callers that print them), in the inner receipt's order. */
export function peerRelayChanges(summary: PeerReceiptSummary): readonly { readonly attempt: string; readonly changed: RelayStackChanges | null }[] {
  return (summary.stack?.attempts ?? []).filter((attempt) => attempt.forwarded_body_jcs_sha256 !== null).map((attempt) => ({ attempt: attempt.n, changed: attempt.changed }));
}

function pass(id: string, detail: string): ReceiptCheck {
  return { id, status: "pass", detail };
}

function fail(id: string, detail: string): ReceiptCheck {
  return { id, status: "fail", detail };
}

function skip(id: string, detail: string): ReceiptCheck {
  return { id, status: "skip", detail };
}
