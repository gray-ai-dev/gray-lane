import { rustTrim } from "./text.ts";

/**
 * How two model names are compared (crates/gray-control/src/model_names.rs `model_name_key`): the one
 * comparison of model names there is. The response model names a mapping once declared, and the rule that
 * none may be another model's ID, are gone with them: Gray no longer reads the model an answer names.
 */

/**
 * `release_date`: the plain name and the release date of `key`, a model name that ends in a `-YYYYMMDD` or
 * `-YYYY-MM-DD` that is a real calendar date in 2000-2099; the date as YYYYMMDD, a number that orders as
 * the dates do. Undefined when it ends in none.
 */
export function releaseDate(key: string): { readonly plain: string; readonly date: number } | undefined {
  for (const [length, pattern] of [
    [9, /^-(\d{4})(\d{2})(\d{2})$/],
    [11, /^-(\d{4})-(\d{2})-(\d{2})$/],
  ] as const) {
    const split = key.length - length;
    if (split <= 0) continue;
    const m = pattern.exec(key.slice(split));
    if (!m) continue;
    const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const date = new Date(Date.UTC(year, month - 1, day));
    const real = date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
    if (real && year >= 2000 && year < 2100) return { plain: key.slice(0, split), date: year * 10_000 + month * 100 + day };
  }
  return undefined;
}

/** `strip_release_date`: `key` without a trailing release date (`releaseDate`). */
export function stripReleaseDate(key: string): string {
  return releaseDate(key)?.plain ?? key;
}

/**
 * `model_name_key`: case, a vendor or `models/` prefix, a variant after `:` or `@`, `.` against `_` against
 * `-`, and a trailing release date do not tell models apart.
 */
export function modelNameKey(id: string): string {
  // `trim` is Unicode White_Space and `to_ascii_lowercase` touches ASCII letters only, as in Rust.
  let key = rustTrim(id).replace(/[A-Z]/g, (ch) => ch.toLowerCase());
  key = key.split("/").at(-1) ?? "";
  key = key.split(/[:@]/)[0] ?? "";
  key = key.replace(/[._]/g, "-");
  return stripReleaseDate(key);
}
