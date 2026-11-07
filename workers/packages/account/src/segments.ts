import { REGIONS, type ShardAddress } from "./address.ts";
import type { BatchItem } from "./protocol.ts";

/**
 * The hourly on-chain entry of a workspace whose account is a root with shards (docs/cloudflare-
 * native.md 5.7; docs/cloudflare-native/ledger.md section 9 item 1). The server version's AccountDO
 * numbers every charge of the account in one sequence and commits an entry to
 * keccak256(salt || leaf_1 || ... || leaf_n) (docs/onchain-credit.md 4.3,
 * workers/credit/src/lib/requests-hash.ts). One sequence per account is a single point, and an
 * hour of leaves (7.2 million at 2,000 requests a second) does not fit one call of the root. So:
 *
 * - each shard numbers its own charges and keeps a hash chain over their leaves in its lease row,
 *   updated once per batch: chain_0 = 32 zero bytes, chain_k = keccak256(chain_{k-1} || leaf_k);
 * - a leaf is the server version's 192 bytes, abi.encode(uint64 chargeSeq, bytes32 requestKey,
 *   uint64 amount, bytes32 providerKey, uint64 providerAmount, bytes32 evidenceHash), with chargeSeq
 *   the shard's number times 2^40 plus the shard's own charge number (still a uint64);
 * - an entry is a list of segments, one per shard with charges: abi.encode(uint64 shard number,
 *   uint64 first charge number, uint64 last charge number, uint64 amount, bytes32 chain before the
 *   first, bytes32 chain after the last), and requestsHash = keccak256(salt || segment_1 || ... ||
 *   segment_n) with the segments in shard-number order;
 * - gray-jobs recomputes every segment from PostgreSQL (credit_usage by shard and charge number, its
 *   accrual), counting the segment's rows before it compares (workers/jobs/src/ledger/segments.ts).
 *
 * The contract stores the hash and never checks how it was made (docs/onchain-credit.md:78, :127):
 * this is an off-chain format. Its parts are fixed here and nowhere else: the shard (shard.ts), the
 * root's sealing (workers/credit/src/api/account-root.ts) and the jobs' check use these functions.
 *
 * Keccak-256 comes from the caller (a Durable Object passes viem's or @noble/hashes'): this package
 * has no dependency of its own, so the credit Worker can take it from source (its own lockfile).
 */

/** Ethereum's Keccak-256 over `data` (32 bytes out). */
export type Keccak256 = (data: Uint8Array) => Uint8Array;

/** A 32-byte value as the leaves and segments carry it: 0x and 64 lowercase hex digits. */
export const HEX32 = /^0x[0-9a-f]{64}$/;

export function isHex32(v: unknown): v is string {
  return typeof v === "string" && HEX32.test(v);
}

/** The chain of a shard before its first charge, and the provider key of a charge that owes nobody. */
export const ZERO_HASH = `0x${"00".repeat(32)}`;

/**
 * The regions in the order their shards are numbered. A shard's number is part of every leaf and
 * segment it is in, so the order never changes: a new location hint is appended (a test checks that
 * every region of @gray/config is here).
 */
export const SEGMENT_REGIONS = ["wnam", "enam", "sam", "weur", "eeur", "apac", "apac-ne", "apac-se", "oc", "afr", "me"] as const;

/** Shard numbers per region: the largest ACCOUNT_SHARD_COUNT (MAX_SHARD_COUNT, 32) fits, and the format does not move with it. */
export const SHARDS_PER_REGION = 32;

/**
 * A leaf's chargeSeq is shardNumber * 2^40 + the shard's charge number. 2^40 charges is 33 years of
 * a shard at its measured ceiling of 1,060 a second (scaling.md section 5), and the largest
 * chargeSeq, 11 * 32 * 2^40, stays below 2^53: a safe integer in JavaScript and in PostgreSQL's
 * int8 (credit_usage.charge_seq).
 */
export const SHARD_SEQ_LIMIT = 2 ** 40;

/** The shard's number within its workspace: its region's place in SEGMENT_REGIONS times 32, plus its index. */
export function shardNumber(a: Pick<ShardAddress, "region" | "index">): number {
  const region = (SEGMENT_REGIONS as readonly string[]).indexOf(a.region);
  if (region < 0) throw new RangeError(`region ${a.region} has no shard numbers`);
  if (!Number.isInteger(a.index) || a.index < 0 || a.index >= SHARDS_PER_REGION) throw new RangeError(`shard index ${a.index} is out of range`);
  return region * SHARDS_PER_REGION + a.index;
}

/** The leaf's chargeSeq of charge number `seq` (1 and up) of the shard at `a`. */
export function chargeSeqOf(a: Pick<ShardAddress, "region" | "index">, seq: number): number {
  if (!Number.isSafeInteger(seq) || seq < 1 || seq >= SHARD_SEQ_LIMIT) throw new RangeError(`charge number ${seq} is out of range`);
  return shardNumber(a) * SHARD_SEQ_LIMIT + seq;
}

/** One charge as an entry commits to it (docs/onchain-credit.md 4.3). */
export interface ChargeLeaf {
  readonly chargeSeq: number;
  readonly requestKey: string;
  readonly amount: number;
  readonly providerKey: string;
  readonly providerAmount: number;
  readonly evidenceHash: string;
}

/** One shard's charges in an entry: its charge numbers `fromSeq` to `toSeq`, their amount, and its chain before and after them. */
export interface Segment {
  /** The shard's name, `workspace/region/index` (not hashed: its number is). */
  readonly shard: string;
  readonly number: number;
  readonly fromSeq: number;
  readonly toSeq: number;
  readonly amount: number;
  readonly prevChain: string;
  readonly chain: string;
}

const ENCODER = new TextEncoder();
const PROVIDER_DOMAIN = ENCODER.encode("gray.provider.v1");

/** A non-negative safe integer as a 32-byte big-endian word (abi.encode of a uint up to 2^53). */
function word(n: number, what: string): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`${what} must be a non-negative safe integer, not ${n}`);
  const out = new Uint8Array(32);
  let v = BigInt(n);
  for (let i = 31; i >= 24 && v > 0n; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bytes32(hex: string, what: string): Uint8Array {
  if (!isHex32(hex)) throw new RangeError(`${what} must be 0x and 64 lowercase hex digits`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

function hex(bytes: Uint8Array): string {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** keccak256("gray.provider.v1" || provider workspace id), both UTF-8 (workers/credit/src/lib/requests-hash.ts providerKeyOf). */
export function providerKeyOf(keccak: Keccak256, workspace: string): string {
  return hex(keccak(concat([PROVIDER_DOMAIN, ENCODER.encode(workspace)])));
}

/** The leaf's 192 bytes: abi.encode(uint64, bytes32, uint64, bytes32, uint64, bytes32). */
export function leafBytes(leaf: ChargeLeaf): Uint8Array {
  return concat([
    word(leaf.chargeSeq, "chargeSeq"),
    bytes32(leaf.requestKey, "requestKey"),
    word(leaf.amount, "amount"),
    bytes32(leaf.providerKey, "providerKey"),
    word(leaf.providerAmount, "providerAmount"),
    bytes32(leaf.evidenceHash, "evidenceHash"),
  ]);
}

/**
 * The leaf of a charged batch item of the shard at `a`, by the server's rule (crates/gray-ledger/src/
 * usage.rs `charge_fields`): a charge with an accrual names its provider's key and the payable (0
 * without a quote), one without an accrual the zero key and 0.
 */
export function leafOfItem(keccak: Keccak256, a: Pick<ShardAddress, "region" | "index">, item: BatchItem): ChargeLeaf {
  if (item.outcome !== "charged" || item.chargeSeq === null) throw new RangeError("only a charge has a leaf");
  const owes = item.accrualId !== null;
  if (owes && item.provider === null) throw new RangeError("an accrual names its provider");
  return {
    chargeSeq: chargeSeqOf(a, item.chargeSeq),
    requestKey: item.requestKey,
    amount: item.amount,
    providerKey: owes ? providerKeyOf(keccak, item.provider!) : ZERO_HASH,
    providerAmount: owes ? (item.payable ?? 0) : 0,
    evidenceHash: item.evidenceHash ?? "",
  };
}

/** The chain after `leaf`: keccak256(chain before || leaf). */
export function chainStep(keccak: Keccak256, prev: string, leaf: ChargeLeaf): string {
  return hex(keccak(concat([bytes32(prev, "chain"), leafBytes(leaf)])));
}

/** The segment's 192 bytes: abi.encode(uint64 number, uint64 fromSeq, uint64 toSeq, uint64 amount, bytes32 prevChain, bytes32 chain). */
export function segmentBytes(s: Segment): Uint8Array {
  if (!Number.isSafeInteger(s.fromSeq) || !Number.isSafeInteger(s.toSeq) || s.fromSeq < 1 || s.toSeq < s.fromSeq || s.toSeq >= SHARD_SEQ_LIMIT) {
    throw new RangeError(`segment ${s.shard} covers no charges (${s.fromSeq}..${s.toSeq})`);
  }
  return concat([
    word(s.number, "number"),
    word(s.fromSeq, "fromSeq"),
    word(s.toSeq, "toSeq"),
    word(s.amount, "amount"),
    bytes32(s.prevChain, "prevChain"),
    bytes32(s.chain, "chain"),
  ]);
}

/** An entry's requestsHash: keccak256(salt || segment_1 || ... || segment_n), the segments in strictly increasing shard-number order. */
export function segmentsHash(keccak: Keccak256, salt: string, segments: readonly Segment[]): string {
  if (segments.length === 0) throw new RangeError("an entry has at least one segment");
  for (let i = 1; i < segments.length; i++) {
    if (segments[i]!.number <= segments[i - 1]!.number) throw new RangeError("an entry's segments are in strictly increasing shard-number order");
  }
  return hex(keccak(concat([bytes32(salt, "salt"), ...segments.map(segmentBytes)])));
}

/** Every region a shard can be in has shard numbers (checked by the unit tests against @gray/config). */
export function unnumberedRegions(): string[] {
  return (REGIONS as readonly string[]).filter((r) => !(SEGMENT_REGIONS as readonly string[]).includes(r));
}
