/**
 * A map of the most recently used entries, bounded by the total size of its entries. By default an
 * entry's size is the length of its key: pattern texts and schema texts, which a client chooses and
 * which may be as long as a schema (64 KiB, MAX_SCHEMA_BYTES). A caller whose values grow faster
 * than their keys passes its own size (the compiled validators, src/schema.ts). What falls out is
 * worked out again. Pure code.
 */
export class Recent<V> {
  private readonly entries = new Map<string, { readonly value: V; readonly size: number }>();
  private total = 0;
  private maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (entry !== undefined) {
      this.entries.delete(key);
      this.entries.set(key, entry);
    }
    return entry?.value;
  }

  /** Keeps `value` unless its size alone passes the bound; drops the oldest entries past it. */
  set(key: string, value: V, size = key.length): void {
    if (size > this.maxSize || this.entries.has(key)) return;
    this.entries.set(key, { value, size });
    this.total += size;
    this.shrink();
  }

  /** A new bound (the gateway's configuration, src/settings.ts); entries past it are dropped now. */
  resize(maxSize: number): void {
    this.maxSize = maxSize;
    this.shrink();
  }

  private shrink(): void {
    for (const [key, entry] of this.entries) {
      if (this.total <= this.maxSize) break;
      this.entries.delete(key);
      this.total -= entry.size;
    }
  }
}

/**
 * The default bound of a `Recent` map of verdicts and translations: 1 Mi UTF-16 units of keys, about
 * 2 MiB of the isolate's 128 MB (C1 in docs/cloudflare-native.md). The gateway's
 * TRUST_VERDICT_CACHE_KEY_UNITS.
 */
export const RECENT_KEY_UNITS = 1 << 20;
