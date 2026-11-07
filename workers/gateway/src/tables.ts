import type { Region, ShardCountTable } from "@gray/account";
import { DispatchBudgets } from "@gray/routing";
import { LRUCache } from "lru-cache";
import { DegradedAdmissions } from "./admission.ts";
import { EndpointCounts } from "./endpoints.ts";
import { ShardRests } from "./rests.ts";

/**
 * The tables a gateway isolate learns as it serves, one entry per workspace or endpoint it meets: K per
 * workspace and region (@gray/account `admitWithRetry` reads it), shards per endpoint and region
 * (endpoints.ts), the rests each endpoint's shard last said it holds (rests.ts `ShardRests`, which ranking reads
 * for one report interval at most), and the home shards a degraded admission alerted (admission.ts). An isolate lives for
 * hours and serves every workspace that reaches its colo, so each table keeps ISOLATE_TABLE_ENTRIES at
 * most, the least recently used going first (lru-cache, the npm package; docs/cloudflare-native/gateway.md
 * section 9, "isolate 里的表"). What falls out is learned again at no cost: a count falls back to 1, whose
 * shard (index 0) always exists and answers with the count; a degraded admission is said again at alert
 * level under the same alert key, which the alerting groups.
 */

/** K per workspace and region, bounded (`ShardCountTable` of @gray/account). */
export class BoundedShardCounts implements ShardCountTable {
  private readonly table: LRUCache<string, number>;

  constructor(max: number) {
    this.table = new LRUCache<string, number>({ max });
  }

  get(workspace: string, region: Region): number {
    return this.table.get(`${workspace}/${region}`) ?? 1;
  }

  learn(workspace: string, region: Region, shardCount: number): void {
    if (Number.isInteger(shardCount) && shardCount >= 1) this.table.set(`${workspace}/${region}`, shardCount);
  }

  /** Entries kept now (tests). */
  get size(): number {
    return this.table.size;
  }

  /** The most entries kept (tests, the leak harness). */
  get max(): number {
    return this.table.max;
  }
}

/** The isolate's tables, each bounded by the same ISOLATE_TABLE_ENTRIES. */
export class IsolateTables {
  readonly max: number;
  readonly shardCounts: BoundedShardCounts;
  readonly endpointCounts: EndpointCounts;
  readonly shardRests: ShardRests;
  readonly degraded: DegradedAdmissions;
  /**
   * The isolate's exploration budget (`reserve_dispatch`): bounded by its own group count, the server's
   * `RankingConfig::max_endpoints` (4,096; ranking.rs:91), not by ISOLATE_TABLE_ENTRIES.
   */
  readonly dispatchBudgets: DispatchBudgets;

  constructor(max: number) {
    this.max = max;
    this.shardCounts = new BoundedShardCounts(max);
    this.endpointCounts = new EndpointCounts(max);
    this.shardRests = new ShardRests(max);
    this.degraded = new DegradedAdmissions(max);
    this.dispatchBudgets = new DispatchBudgets();
  }
}
