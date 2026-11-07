/**
 * Customer-stated routing preferences for one request (crates/gray-gateway/src/routing.rs), held to the
 * conformance fixtures of area `routing-preferences`.
 *
 * A preference may only narrow or reorder the candidates a request was already eligible for. It never
 * relaxes exact-model matching, verification, admitted quotes, regional policy, trust inspection or the
 * reservation ceiling: those are decided before a preference is consulted, and a preference that empties
 * the candidate set is reported as such rather than served by something the customer did not ask for.
 *
 * The field names follow the `provider` object that OpenRouter and the Vercel AI Gateway already expose
 * (`order`, `only`, `ignore`, `allow_fallbacks`, `sort`), so a client that speaks either of those needs no
 * new vocabulary.
 *
 * Here: how a request states one (`Preference.take`, `fromHeader`) and a key or workspace stores one
 * (`parseDefault`), read exactly as routing.rs reads `Preference` (see `statedOf`); how the
 * levels layer (`layered`) and what the layered preference decides (`admits`, `position`, `selected`,
 * `affinityAllowed`, `exploration`, `allowsOtherOperators`, `withinMaxPrice`); and cache affinity
 * (`affinityKey`, `Affinity`, `affinityTtlMs`). The route references themselves (`provider_ref`,
 * `supplier_ref`, `registered_refs`) are @gray/snapshot's. Where the gateway applies a preference
 * (inference.rs `layered_over`, `retain_admitted`, `within_max_price`) is workers/gateway's.
 *
 * Pure code: no I/O; the affinity map is the caller's to keep.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { type Json, type JsonObject, get, isArray, isObject, parseStrict, toJsonString } from "@gray/json";
import { type CanonicalRequest, type Protocol, anthropicCache, promptBlocks } from "@gray/protocol";
import type { Exploration, RankingPolicy } from "./index.ts";

/**
 * What the customer wants the eligible candidates ordered by (`RequestedSort`). Deliberately its own type
 * rather than the deployment's `RankingPolicy`: the deployment policy also decides whether an approved
 * supplier quote is required, and a customer may not change admission by asking for a different order.
 */
export type RequestedSort = "balanced" | "latency" | "throughput" | "price";
const SORTS: readonly RequestedSort[] = ["balanced", "latency", "throughput", "price"];

/** Whether a request may return to the endpoint that last served the same cache prefix (`AffinityMode`). */
export type AffinityMode = "auto" | "off";
const AFFINITY_MODES: readonly AffinityMode[] = ["auto", "off"];

/**
 * Whether a relay serving the request on the confidential lane may change it (`RelayChangesMode`,
 * docs/relay-request-changes.md): `allow` lets a relay change the request outside the kept limits, each change
 * recorded in the receipt; `exclude` serves it only as Gray states it, since the lane registers it so that egress
 * refuses any change of the relay's own. No route outside the lane reads it.
 */
export type RelayChangesMode = "allow" | "exclude";
const RELAY_CHANGES_MODES: readonly RelayChangesMode[] = ["allow", "exclude"];

/**
 * Per-million-token ceilings in micro-USD (`MaxPrice`), compared against the customer rate a route would
 * actually be billed at; null where the level states none.
 */
export interface MaxPrice {
  readonly input: bigint | null;
  readonly output: bigint | null;
}

/** The request header that carries a preference beside the body (`x-gray-routing`). */
export const ROUTING_HEADER = "x-gray-routing";

/** What a preference is read from: a request's headers, by name (`Headers.get`). */
export interface HeaderSource {
  get(name: string): string | null;
}

/** Bounds the work one request can ask of selection (routing.rs `MAX_REFS`, `REF_LEN`). */
const MAX_REFS = 32;
const REF_LEN = 64;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The fields of `Preference` serde reads. */
const FIELDS = ["order", "only", "ignore", "allow_fallbacks", "sort", "max_price", "affinity", "relay_changes"] as const;

/** A preference as one level stated it, before `validated`. */
interface Stated {
  readonly order: readonly string[];
  readonly only: readonly string[];
  readonly ignore: readonly string[];
  readonly allowFallbacks: boolean;
  readonly sort: RequestedSort | null;
  readonly maxPrice: MaxPrice | null;
  readonly affinity: AffinityMode;
  readonly relayChanges: RelayChangesMode;
}

/** serde refused the value: the reader's only error, since every refusal answers alike. */
class Refused extends Error {
  constructor() {
    super("refused");
    this.name = "Refused";
  }
}

function refuse(): never {
  throw new Refused();
}

/** `Vec<String>`: a sequence of strings. */
function strings(value: Json): string[] {
  if (!isArray(value)) refuse();
  return value.map((item) => (typeof item === "string" ? item : refuse()));
}

/**
 * A ceiling (routing.rs `ceiling`): a whole number of micro-USD. serde_json reads a float as no integer at all
 * (`1.0`, `0.0`, `1e3`, `1e-400` after underflow, one past u64), nor a negative one, and has no negative-zero
 * integer: it reads `-0` as the float `-0.0` (as it reads `-0.0`, `-0e5` and `-1e-400`, which underflows to it;
 * @gray/json `serdeNumber`), which is the number 0 and is taken as 0 (product lead, 2026-10-23, release 4
 * decision 11).
 */
function ceiling(value: Json): bigint {
  if (typeof value === "number" && Object.is(value, -0)) return 0n;
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) refuse();
  return value;
}

/** `Option<u64>` read by `ceiling`: null is None. */
function optionalCeiling(value: Json): bigint | null {
  return value === null ? null : ceiling(value);
}

/**
 * A unit variant of a `snake_case` enum, as serde_json reads an enum: the variant's name as a string, or a
 * map of exactly that one key whose value is the unit (null).
 */
function unitVariant<T extends string>(value: Json, variants: readonly T[]): T {
  let name: string;
  if (typeof value === "string") {
    name = value;
  } else if (isObject(value)) {
    const keys = Object.keys(value);
    if (keys.length !== 1) refuse();
    name = keys[0]!;
    if (get(value, name) !== null) refuse();
  } else {
    refuse();
  }
  return variants.find((variant) => variant === name) ?? refuse();
}

/**
 * `MaxPrice` (`deny_unknown_fields`, both fields `#[serde(default)]`): an object of its two fields, missing
 * ones left unset. An object only (routing.rs `FromObject`): serde's derived struct also reads a sequence
 * stating the fields in order, which the contract never states (release 4 decision 8).
 */
function maxPriceOf(value: Json): MaxPrice {
  if (!isObject(value)) refuse();
  let input: bigint | null = null;
  let output: bigint | null = null;
  for (const key of Object.keys(value)) {
    const member = get(value, key)!;
    if (key === "input_microusd_per_million") input = optionalCeiling(member);
    else if (key === "output_microusd_per_million") output = optionalCeiling(member);
    else refuse();
  }
  return { input, output };
}

/**
 * `Preference` as routing.rs reads it from a value (`serde_json::from_value`): an object of its fields with
 * `deny_unknown_fields`, every field `#[serde(default)]` (`allow_fallbacks` true). `narrowed_by`, `requested`
 * and `own_only` are `#[serde(skip)]`: naming one is an unknown field. An object only (routing.rs
 * `FromObject`; product lead, 2026-10-23, release 4 decision 8): serde's derived struct also reads a sequence
 * stating the fields in their declaration order, so `[]` read as no preference and `[["<ref>"]]` as an order,
 * and every sequence is refused instead (`take-provider-array-*`, `default-array-order`).
 */
function statedOf(value: Json): Stated {
  let order: string[] = [];
  let only: string[] = [];
  let ignore: string[] = [];
  let allowFallbacks = true;
  let sort: RequestedSort | null = null;
  let maxPrice: MaxPrice | null = null;
  let affinity: AffinityMode = "auto";
  let relayChanges: RelayChangesMode = "allow";
  const read = (field: (typeof FIELDS)[number], member: Json) => {
    switch (field) {
      case "order":
        order = strings(member);
        break;
      case "only":
        only = strings(member);
        break;
      case "ignore":
        ignore = strings(member);
        break;
      case "allow_fallbacks":
        if (typeof member !== "boolean") refuse();
        allowFallbacks = member;
        break;
      case "sort":
        sort = member === null ? null : unitVariant(member, SORTS);
        break;
      case "max_price":
        maxPrice = member === null ? null : maxPriceOf(member);
        break;
      case "affinity":
        affinity = unitVariant(member, AFFINITY_MODES);
        break;
      case "relay_changes":
        relayChanges = unitVariant(member, RELAY_CHANGES_MODES);
        break;
    }
  };
  if (!isObject(value)) refuse();
  for (const key of Object.keys(value)) {
    const field = FIELDS.find((f) => f === key) ?? refuse();
    read(field, get(value, key)!);
  }
  return { order, only, ignore, allowFallbacks, sort, maxPrice, affinity, relayChanges };
}

/**
 * `Preference::validated`: at most MAX_REFS references in each list, each REF_LEN ASCII hex digits (either
 * case: a reference is compared as written, so an uppercase one names nothing registered), and a
 * `max_price` stating at least one ceiling.
 */
function validated(stated: Stated): Stated {
  const lists = [stated.order, stated.only, stated.ignore];
  if (lists.some((list) => list.length > MAX_REFS)) refuse();
  // Rust's `len()` counts bytes; a string of REF_LEN ASCII hex digits is REF_LEN bytes, and nothing else is.
  const hex = new RegExp(`^[0-9A-Fa-f]{${REF_LEN}}$`);
  if (lists.some((list) => list.some((value) => !hex.test(value)))) refuse();
  if (stated.maxPrice !== null && stated.maxPrice.input === null && stated.maxPrice.output === null) refuse();
  return stated;
}

/** `HeaderValue::to_str`: visible ASCII and the tab only. */
function visibleAscii(text: string): boolean {
  return /^[\t\x20-\x7e]*$/.test(text);
}

/** The tighter of two optional ceilings; a level that states none does not loosen one that does (`narrowest`). */
function narrowest(a: bigint | null, b: bigint | null): bigint | null {
  if (a !== null && b !== null) return a < b ? a : b;
  return a ?? b;
}

/** What `Preference.take` read: the preference, or why the request is refused (400). */
export type Taken = { readonly ok: true; readonly preference: Preference } | { readonly ok: false; readonly code: "routing_invalid" | "routing_ambiguous" };

/**
 * One request's routing preference (routing.rs `Preference`), as one level stated it or as `layered`
 * combined the levels.
 */
export class Preference {
  /** Explicit try order. Candidates named here are attempted in this order, ahead of any ranking, and no exploratory probe may displace them. */
  readonly order: readonly string[];
  /** Allow list. Empty means every eligible candidate is allowed. */
  readonly only: readonly string[];
  /** Deny list, applied after `only`. */
  readonly ignore: readonly string[];
  /**
   * `false` keeps the request at one operator: no route of another operator serves it, while a repeat at that
   * operator still follows the retry rules (OpenRouter, whose vocabulary this is: "allow backup providers when
   * the primary is unavailable"; a repeat of the same provider is no backup). With `order` it also keeps the
   * request to the routes the order names (`admits`).
   */
  readonly allowFallbacks: boolean;
  readonly sort: RequestedSort | null;
  readonly maxPrice: MaxPrice | null;
  /** `auto` lets a request that states a cache intent return to the endpoint that last served the same cache prefix; `off` routes it by ranking alone. */
  readonly affinity: AffinityMode;
  /**
   * `allow` lets a relay on the confidential lane change the request outside the kept limits, each change recorded
   * in the receipt; `exclude` serves it only by relays that make no change of their own to it (the lane registers
   * its stack attempts without `relay_changes`). Exclude at any level holds.
   */
  readonly relayChanges: RelayChangesMode;
  /**
   * Every allow list the levels stated, kept apart rather than merged (`narrowed_by`). A reference is an
   * opaque digest, so no string comparison can tell that an endpoint belongs to a supplier; a candidate knows
   * both of its names, so each list is applied to the candidate instead: it must be named by every one.
   */
  readonly narrowedBy: readonly (readonly string[])[];
  /**
   * The references the request itself named as a selection, once `layered` combined it with the stored
   * defaults; null before layering. Only these are checked when the request is served: a default's names are
   * checked when it is stored, and a stale name in a default is a name no route answers to.
   */
  readonly requested: readonly string[] | null;
  /**
   * How many references the request's own `only` named, once `layered` combined it with the stored defaults
   * (whose allow lists `narrowedBy` keeps apart, leaving the layered `only` empty); null before layering, where
   * the own `only` is `only` itself (`own_only`). What the request log counts as `only` (`ownOnlyLen`).
   */
  private readonly ownOnly: number | null;

  private constructor(stated: Stated, narrowedBy: readonly (readonly string[])[], requested: readonly string[] | null, ownOnly: number | null = null) {
    this.order = stated.order;
    this.only = stated.only;
    this.ignore = stated.ignore;
    this.allowFallbacks = stated.allowFallbacks;
    this.sort = stated.sort;
    this.maxPrice = stated.maxPrice;
    this.affinity = stated.affinity;
    this.relayChanges = stated.relayChanges;
    this.narrowedBy = narrowedBy;
    this.requested = requested;
    this.ownOnly = ownOnly;
  }

  /** No preference (`Preference::default`). */
  static readonly DEFAULT = new Preference({ order: [], only: [], ignore: [], allowFallbacks: true, sort: null, maxPrice: null, affinity: "auto", relayChanges: "allow" }, [], null);

  /** The preference serde reads from `value`, validated; null where the server refuses it. */
  private static read(value: Json): Preference | null {
    try {
      return new Preference(validated(statedOf(value)), [], null);
    } catch (error) {
      if (error instanceof Refused) return null;
      throw error;
    }
  }

  /** `serde_json::from_str::<Preference>` of `text`, validated: a key stated twice at any depth is refused (a derived struct refuses a duplicate field, and every object of a preference is one; the sort's and affinity's one-key map form takes no second key at all). */
  private static readText(text: string): Preference | null {
    let value: Json;
    try {
      value = parseStrict(text);
    } catch {
      return null;
    }
    return Preference.read(value);
  }

  /**
   * A stored default, as the scope that set it stated it (`Preference::parse_default`). A default this
   * version cannot parse is an error rather than an absent restriction: an organization that set one on its
   * key or workspace must never have it silently dropped.
   */
  static parseDefault(stored: string): Preference | "routing_default_invalid" {
    return Preference.readText(stored) ?? "routing_default_invalid";
  }

  /** The header form alone, for a request whose body has no place for a routing object, a multipart form (`Preference::from_header`). */
  static fromHeader(headers: HeaderSource): Preference | "routing_invalid" {
    const header = headers.get(ROUTING_HEADER);
    if (header === null) return Preference.DEFAULT;
    if (!visibleAscii(header)) return "routing_invalid";
    return Preference.readText(header) ?? "routing_invalid";
  }

  /**
   * Reads the preference and removes it from `body` (`Preference::take`), so the upstream never receives a
   * field it did not define: first-party APIs reject unknown body fields, which would turn every preference
   * into a 400 from the provider. The `provider` member of a body that is an object, or the header; both at
   * once is ambiguous. The header is read as `fromHeader` reads it, as the preference itself, so a key stated
   * twice is refused by both readers (product lead, 2026-10-23, release 4 decision 9). The body's member is a
   * value the body's parse already read, where a key stated twice keeps its last value as every body field
   * does.
   */
  static take(body: Json, headers: HeaderSource): Taken {
    let inBody: Json | undefined;
    if (isObject(body) && Object.hasOwn(body, "provider")) {
      inBody = get(body, "provider")!;
      delete (body as JsonObject).provider;
    }
    const inHeader = headers.get(ROUTING_HEADER);
    if (inBody !== undefined && inHeader !== null) return { ok: false, code: "routing_ambiguous" };
    if (inBody === undefined && inHeader === null) return { ok: true, preference: Preference.DEFAULT };
    if (inBody === undefined) {
      const read = Preference.fromHeader(headers);
      return typeof read === "string" ? { ok: false, code: read } : { ok: true, preference: read };
    }
    const preference = Preference.read(inBody);
    return preference === null ? { ok: false, code: "routing_invalid" } : { ok: true, preference };
  }

  /** States nothing (`is_default`). */
  isDefault(): boolean {
    return (
      this.narrowedBy.length === 0 &&
      this.order.length === 0 &&
      this.only.length === 0 &&
      this.ignore.length === 0 &&
      this.allowFallbacks &&
      this.sort === null &&
      this.maxPrice === null &&
      this.affinity === "auto" &&
      this.relayChanges === "allow"
    );
  }

  /**
   * Layers a request's preference (this) over the defaults its API key and its workspace set, most specific
   * first (`Preference::layered`).
   *
   * A restriction only ever gets tighter: an organization that refused fallbacks, named an allow list,
   * excluded a supplier or set a price ceiling on its key cannot have that widened by a request. Choices that
   * are not restrictions, the try order and the sort, are the caller's, so the most specific one that states
   * anything wins.
   *
   * `published` is every published route as its (route, supplier) references, which decides whether a name in
   * the order can still order anything once the levels' filters apply. `registered` is every reference naming
   * a registered endpoint (@gray/snapshot `registeredRefs`), which tells a name the request mistyped from one
   * whose routes left.
   */
  layered(key: Preference | null, workspace: Preference | null, published: readonly (readonly [string, string])[], registered: ReadonlySet<string>): Preference {
    const requested = [...this.selected()];
    // Whether the order settled below is the request's own, so that a name in it naming no registered
    // endpoint is the caller's to correct.
    const ordersItself = this.order.length > 0;
    const stated = [this, key, workspace].filter((level): level is Preference => level !== null);
    // Every allow list any level states: `only`, and the `order` of a level that refuses fallbacks, since that
    // is what refusing them means (taking the most specific `order` alone would let a request name a provider
    // its key or workspace pin had excluded).
    const narrowedBy = [...stated.map((p) => p.only), ...stated.filter((p) => !p.allowFallbacks).map((p) => p.order), ...stated.flatMap((p) => p.narrowedBy)]
      .filter((list) => list.length > 0)
      .map((list) => [...list]);
    const ignore: string[] = [];
    for (const named of stated.flatMap((p) => p.ignore)) if (!ignore.includes(named)) ignore.push(named);
    const prices = stated.map((p) => p.maxPrice).filter((price): price is MaxPrice => price !== null);
    const maxPrice = prices.length === 0 ? null : prices.reduce((a, b) => ({ input: narrowest(a.input, b.input), output: narrowest(a.output, b.output) }));
    // The most specific order states the preference.
    const order = stated.map((p) => p.order).find((o) => o.length > 0) ?? [];
    // The order is settled below; left empty until then so the filters it is settled against are the
    // levels' lists alone. The levels' own `only` lists are applied through `narrowedBy`, so `only` stays
    // empty: a merged list could not express them.
    const base: Stated = {
      order: [],
      only: [],
      ignore,
      allowFallbacks: stated.every((p) => p.allowFallbacks),
      sort: stated.find((p) => p.sort !== null)?.sort ?? null,
      maxPrice,
      affinity: stated.some((p) => p.affinity === "off") ? "off" : "auto",
      relayChanges: stated.some((p) => p.relayChanges === "exclude") ? "exclude" : "allow",
    };
    const ownOnly = this.ownOnlyLen();
    const unsettled = new Preference(base, narrowedBy, requested, ownOnly);
    // With fallbacks allowed, a name keeps its place only while some route it names survives the filters; a
    // route knows both of its names. A name that names no registered endpoint at all stays when the request
    // wrote it, so the request is refused as `routing_unknown_provider`; one whose routes left the snapshot
    // orders nothing and is dropped, except under a refusal, where the order is the allow list and the stale
    // name must keep confining it. Under a refusal the order is settled against the pins alone (the orders
    // the no-fallback levels stated themselves): a pin decides who may serve, and every other filter leaves a
    // name where it is.
    const pins = stated.filter((p) => !p.allowFallbacks && p.order.length > 0).map((p) => p.order);
    const survives = (provider: string, supplier: string) =>
      unsettled.allowFallbacks ? unsettled.admits(provider, supplier) : pins.every((pin) => Preference.names(pin, provider, supplier));
    const settled = order.filter((named) => {
      const routes = published.filter(([provider, supplier]) => provider === named || supplier === named);
      if (routes.length === 0) return (ordersItself && !registered.has(named)) || !unsettled.allowFallbacks;
      return routes.some(([provider, supplier]) => survives(provider, supplier));
    });
    return new Preference({ ...base, order: settled }, narrowedBy, requested, ownOnly);
  }

  /** An explicit customer order always wins over cache affinity: the customer asked for a specific endpoint (`affinity_allowed`). */
  affinityAllowed(): boolean {
    return this.affinity === "auto" && this.order.length === 0;
  }

  /**
   * Every reference the request named as a selection (`selected`), which is what must name a registered
   * endpoint for the request to be satisfiable at all. On a layered preference that is the request's own
   * `order` and `only` (`requested`), not the stored defaults', which are checked when they are stored.
   */
  selected(): readonly string[] {
    if (this.requested !== null) return this.requested;
    return [...this.order, ...this.only];
  }

  /**
   * How many references the request's own `only` names (`own_only_len`), which is what the request log and the
   * wide event count as `only` (`preference_facts`, `routing_only_len`; product lead, 2026-10-23, release 4
   * decision 10). A layered preference's own `only` is always empty, each level's allow list being in
   * `narrowedBy`; the stored defaults' lists are not the request's and are not counted.
   */
  ownOnlyLen(): number {
    return this.ownOnly ?? this.only.length;
  }

  private static names(list: readonly string[], provider: string, supplier: string): boolean {
    return list.some((v) => v === provider || v === supplier);
  }

  /**
   * Whether a candidate survives the customer's filters (`admits`): not ignored, inside `only`, inside the
   * order while fallbacks are refused, and named by every list in `narrowedBy`.
   */
  admits(provider: string, supplier: string): boolean {
    if (Preference.names(this.ignore, provider, supplier)) return false;
    if (this.only.length > 0 && !Preference.names(this.only, provider, supplier)) return false;
    if (!this.allowFallbacks && this.order.length > 0 && !Preference.names(this.order, provider, supplier)) return false;
    return this.narrowedBy.every((list) => Preference.names(list, provider, supplier));
  }

  /** Position in the explicit order, or null for a candidate the order did not name (`position`): unnamed candidates keep their ranked order behind the named ones. */
  position(provider: string, supplier: string): number | null {
    const at = this.order.findIndex((v) => v === provider || v === supplier);
    return at < 0 ? null : at;
  }

  /** Whether an input and an output rate (micro-USD per million) are within `max_price` (`within_max_price`). */
  withinMaxPrice(input: bigint, output: bigint): boolean {
    const price = this.maxPrice;
    if (price === null) return true;
    return (price.input === null || input <= price.input) && (price.output === null || output <= price.output);
  }

  /** An explicit order suppresses exploration (`exploration`). */
  exploration(): Exploration {
    return this.order.length === 0 ? "allowed" : "suppressed";
  }

  /** Whether a route of an operator not yet tried may serve this request after an attempt failed: `allow_fallbacks` (`allows_other_operators`). */
  allowsOtherOperators(): boolean {
    return this.allowFallbacks;
  }

  /** The ranking policy the request is ordered by: its sort (`RequestedSort::ordering_policy`), else the deployment's. */
  orderingPolicy(deployment: RankingPolicy): RankingPolicy {
    return this.sort ?? deployment;
  }
}

// ---------------------------------------------------------------- cache affinity

/**
 * Per-protocol lifetime of an affinity entry, in milliseconds (`affinity_ttl_ms`). Upstream prompt caches
 * expire on their own schedule, and these are at or below the shortest documented upstream lifetime: an
 * entry that expires early only costs a cache hit, while one that outlives its upstream cache sends a
 * request somewhere for a benefit that is no longer there.
 */
export function affinityTtlMs(protocol: Protocol): bigint {
  switch (protocol) {
    // An ephemeral breakpoint lives at least five minutes, refreshed on each read (platform.claude.com, Prompt caching).
    case "anthropic_messages":
      return 300_000n;
    // In-memory retention, the default for an organization with Zero Data Retention, typically keeps an entry
    // five to ten minutes of inactivity (developers.openai.com, Prompt caching). Only GPT-5.6 and later promise
    // thirty minutes, and the protocol does not say which model generation a relay serves.
    case "open_ai_chat":
    case "open_ai_responses":
      return 300_000n;
    // Only the text-generation protocols carry a prompt prefix an upstream could have cached; a Gemini
    // `cachedContent` lives as long as its creator set, which the request does not say. The shorter lifetime
    // is the safe default.
    default:
      return 300_000n;
  }
}

/** Marks an entry a request may read but does not write, in an affinity key (`READ_ONLY`). */
const READ_ONLY = "~";

const encoder = new TextEncoder();

/** A length as Rust's `usize::to_le_bytes` on a 64-bit target: 8 bytes, little-endian. */
function lengthBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(length), true);
  return bytes;
}

/**
 * The affinity key of an Anthropic request that states a breakpoint (`prefix_key`). Anthropic has no key
 * field: an upstream entry is a hash of the prefix ending at a breakpoint, written only there, and a request
 * reads it by walking back from each of its own breakpoints (@gray/protocol `anthropicCache`). The key names
 * the entry at each breakpoint, which this request writes, and every position in those windows, longest
 * prefix first, which it may read. These are stability hashes, not the provider's own.
 */
function prefixKey(seed: Uint8Array, body: Json): string | null {
  const blocks = promptBlocks("anthropic_messages", body);
  // A request marking more blocks than Anthropic takes is refused upstream and writes no entry, so it names none.
  const cache = anthropicCache(blocks, body);
  if (cache === undefined) return null;
  const last = cache.reads.length - 1;
  const hasher = sha256.create();
  hasher.update(seed);
  const prefixes: string[] = [];
  for (let index = 0; index <= last; index++) {
    const unit = blocks[index]!.digest();
    hasher.update(lengthBytes(unit.len));
    hasher.update(unit.sha256);
    prefixes.push(bytesToHex(hasher.clone().digest()));
  }
  const entries: string[] = [];
  for (let index = last; index >= 0; index--) {
    if (!cache.reads[index]) continue;
    entries.push(cache.writes.includes(index) ? prefixes[index]! : `${READ_ONLY}${prefixes[index]!}`);
  }
  return entries.join(" ");
}

/** The entries an affinity key names, in the order they are worth reading, each with whether the request writes it (`named_entries`). */
function namedEntries(key: string): (readonly [entry: string, written: boolean])[] {
  return key
    .split(" ")
    .filter((entry) => entry !== "")
    .map((entry) => (entry.startsWith(READ_ONLY) ? ([entry.slice(READ_ONLY.length), false] as const) : ([entry, true] as const)));
}

/**
 * The affinity key for one request, or null when it states no cache intent (`affinity_key`). Gray acts only
 * on a cache intent the request states: an explicit cache key, or an explicit Anthropic cache breakpoint; it
 * never infers one from the shape of a prompt. The key is opaque outside this module, and the workspace is
 * part of every entry, so an entry can only ever be read or written by the workspace that created it.
 */
export function affinityKey(workspaceId: string, request: CanonicalRequest, body: Json): string | null {
  const hints = request.cache_hints;
  if (hints === null) return null;
  // `serde_json::to_vec(&(workspace_id, &request.model, request.protocol, signal))`.
  const seed = (signal: string) => encoder.encode(toJsonString([workspaceId, request.model, request.protocol, signal]));
  // A customer-supplied key: already forwarded upstream by design, so keying on it exposes nothing new.
  if (hints.key !== null) return bytesToHex(sha256(seed(`stated:${hints.key}`)));
  // The parser sets Anthropic's hints only from the breakpoint fields `prefixKey` reads too.
  if (!(hints.read || hints.write)) return null;
  return prefixKey(seed("prefix"), body);
}

/**
 * The server's affinity bounds (`Affinity::default`): at most this many entries per workspace, for at most this
 * many workspaces, constants in routing.rs, where the map lives in the server's process. A map built without
 * bounds takes them (the conformance fixtures' default); the gateway's isolate map takes its own,
 * AFFINITY_ENTRIES_PER_WORKSPACE and AFFINITY_WORKSPACES (@gray/config), sized from the isolate's memory.
 */
export const AFFINITY_PER_WORKSPACE = 512;
export const AFFINITY_WORKSPACES = 4096;

interface AffinityEntry {
  readonly endpointId: string;
  readonly expiresAtMs: bigint;
}

interface AffinityShard {
  readonly entries: Map<string, AffinityEntry>;
  /** When the shard's last entry expires: entries only ever expire or are evicted closest to expiry first. */
  expiresAtMs: bigint;
}

/**
 * Which endpoint last served a given cache prefix, so the next request in the same conversation can reuse
 * the upstream cache that is only warm there (`Affinity`). Upstream prompt caches are isolated per provider
 * account, so a warm conversation routed to another supplier is a guaranteed miss.
 *
 * It is a latency optimization, not a routing authority: losing it only costs the next request of each
 * conversation a cache miss. Times are Unix milliseconds as u64 (`bigint`): an expiry saturates at u64's
 * largest value, as `saturating_add` does.
 */
export class Affinity {
  /** Keyed by workspace, then by affinity key: one workspace filling its own shard can never evict another's entries. */
  private readonly workspaces = new Map<string, AffinityShard>();
  /** While every workspace slot is taken, the earliest time any shard can have emptied, before which looking for a free slot cannot find one. */
  private nextSweepMs = 0n;
  /** Sweeps run, which is what bounds the time a full map is walked for (the tests read it). */
  sweeps = 0;
  private readonly perWorkspace: number;
  private readonly maxWorkspaces: number;

  /** At most `perWorkspace` entries for each of at most `maxWorkspaces` workspaces; the server's by default (`Affinity::default`). */
  constructor(perWorkspace = AFFINITY_PER_WORKSPACE, maxWorkspaces = AFFINITY_WORKSPACES) {
    this.perWorkspace = perWorkspace;
    this.maxWorkspaces = maxWorkspaces;
  }

  /**
   * The endpoint that last served the longest live entry this key may read, if any (`target`). The caller
   * must still confirm the endpoint is eligible: this is a preference among candidates, never a route source.
   */
  target(workspaceId: string, key: string, nowMs: bigint): string | null {
    const entries = this.workspaces.get(workspaceId)?.entries;
    if (entries === undefined) return null;
    for (const [entry] of namedEntries(key)) {
      const found = entries.get(entry);
      if (found !== undefined && found.expiresAtMs > nowMs) return found.endpointId;
    }
    return null;
  }

  /**
   * Records the endpoint that served this key, under each entry the key writes, with `nowMs` the time the
   * attempt was dispatched, when the upstream read the prefix (`record`). Called when an attempt closes as a
   * delivered answer: the first request of a conversation is always a miss, and a failed attempt warmed no
   * cache, so it neither forms an entry nor renews one.
   */
  record(workspaceId: string, key: string, endpointId: string, protocol: Protocol, nowMs: bigint): void {
    if (this.workspaces.size >= this.maxWorkspaces && !this.workspaces.has(workspaceId)) {
      // Expired workspaces are only collected under pressure, and a sweep drops whole shards; while the map
      // stays full no sweep runs until a shard can have emptied.
      if (nowMs < this.nextSweepMs) return;
      this.sweeps += 1;
      for (const [id, shard] of this.workspaces) if (!(shard.expiresAtMs > nowMs)) this.workspaces.delete(id);
      if (this.workspaces.size >= this.maxWorkspaces) {
        let soonest: bigint | null = null;
        for (const shard of this.workspaces.values()) if (soonest === null || shard.expiresAtMs < soonest) soonest = shard.expiresAtMs;
        this.nextSweepMs = soonest ?? 0n;
        return;
      }
    }
    let shard = this.workspaces.get(workspaceId);
    if (shard === undefined) {
      shard = { entries: new Map(), expiresAtMs: 0n };
      this.workspaces.set(workspaceId, shard);
    }
    const sum = nowMs + affinityTtlMs(protocol);
    const expiresAtMs = sum > U64_MAX ? U64_MAX : sum;
    const entries = shard.entries;
    for (const [entry, written] of namedEntries(key)) {
      if (!written) continue;
      if (entries.size >= this.perWorkspace && !entries.has(entry)) {
        for (const [name, held] of entries) if (!(held.expiresAtMs > nowMs)) entries.delete(name);
        if (entries.size >= this.perWorkspace) {
          // Drop the entry closest to expiry rather than refuse to record: the newest conversation is the one
          // still running. Rust's `HashMap` order decides between equal expiries; that tie is not pinned.
          let oldest: string | null = null;
          let oldestAt: bigint | null = null;
          for (const [name, held] of entries) {
            if (oldestAt === null || held.expiresAtMs < oldestAt) {
              oldest = name;
              oldestAt = held.expiresAtMs;
            }
          }
          if (oldest !== null) entries.delete(oldest);
        }
      }
      entries.set(entry, { endpointId, expiresAtMs });
    }
    if (expiresAtMs > shard.expiresAtMs) shard.expiresAtMs = expiresAtMs;
  }
}
