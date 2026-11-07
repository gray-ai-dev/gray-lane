/**
 * The JSON Pointer subset a `request.modified` event may name: an absolute RFC 6901 pointer with
 * one or two reference tokens, i.e. a top-level member or one level inside a top-level object.
 *
 * Two tokens are enough for every rewrite Gray declares today: the output cap, the model and the
 * end-user fields are top-level, while `metadata.user_id` and `stream_options.include_usage` are
 * one object deep. Arrays are deliberately not addressable: a path that names an array element
 * would need a `seq` rule (which occurrence after the edit?) and no Gray rewrite does.
 *
 * Tokens are decoded (`~1` is `/`, `~0` is `~`); an empty token, a dangling `~`, a relative
 * pointer, or a third token is a refusal, never a guess. The pointer is a value a receipt reader
 * can see; this module is the one place that turns it into member names.
 */
import { refusal, type Refusal } from "./refusal.ts";

/** The deepest pointer the lane accepts: a top-level member and one object inside it. */
export const MAX_POINTER_TOKENS = 2;

/** The longest pointer text an event may carry. */
export const MAX_POINTER_LENGTH = 256;

export interface JsonPointer {
  readonly tokens: readonly string[];
}

export type PointerRefusalCode = "path";

/** A parsed pointer, or a refusal that never echoes the path back. */
export function parseJsonPointer(path: unknown): { readonly ok: true; readonly pointer: JsonPointer } | Refusal<PointerRefusalCode> {
  if (typeof path !== "string") return refusal("path", "the path is not a string");
  if (!path.isWellFormed()) return refusal("path", "the path is not well formed UTF-16");
  if (path.length === 0 || path[0] !== "/") return refusal("path", "the path is not an absolute JSON Pointer");
  if (path.length > MAX_POINTER_LENGTH) return refusal("path", "the path is longer than the lane's limit");
  const raw = path.slice(1).split("/");
  if (raw.length > MAX_POINTER_TOKENS) return refusal("path", "the path is deeper than one object inside the top level");
  const tokens: string[] = [];
  for (const part of raw) {
    if (part.length === 0) return refusal("path", "a path token is empty");
    let token = "";
    for (let index = 0; index < part.length; index += 1) {
      const char = part[index] as string;
      if (char !== "~") {
        token += char;
        continue;
      }
      const next = part[index + 1];
      if (next === "0") token += "~";
      else if (next === "1") token += "/";
      else return refusal("path", "a path token holds a `~` that is not `~0` or `~1`");
      index += 1;
    }
    tokens.push(token);
  }
  return { ok: true, pointer: { tokens } };
}
