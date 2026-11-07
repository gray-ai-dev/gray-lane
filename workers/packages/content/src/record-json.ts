/**
 * The JSON text of a record (an attempt, the details, a frame's object): JSON.stringify's, but a `bigint` member is
 * written as the integer it is, where JSON.stringify throws. A record read back with @gray/json `parsePlainWide`
 * holds a Rust u64 or i64 past 2^53 as a bigint (record.rs `Attempt`'s `rest_until_ms` at u64::MAX), and is written
 * on (the content Worker's frames to the console) as the server wrote it. A record without one is JSON.stringify's
 * text byte for byte.
 */
export function recordJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch (error) {
    // "Do not know how to serialize a BigInt": the record holds one somewhere.
    if (!(error instanceof TypeError)) throw error;
    return written(value) ?? "null";
  }
}

/** JSON.stringify's writing of `value`, members in their order, with a bigint as its integer; undefined where JSON.stringify leaves the member out. */
function written(value: unknown): string | undefined {
  if (typeof value === "bigint") return value.toString();
  if (value === undefined || typeof value === "function" || typeof value === "symbol") return undefined;
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => written(v) ?? "null").join(",")}]`;
  const parts: string[] = [];
  for (const [key, member] of Object.entries(value)) {
    const text = written(member);
    if (text !== undefined) parts.push(`${JSON.stringify(key)}:${text}`);
  }
  return `{${parts.join(",")}}`;
}
