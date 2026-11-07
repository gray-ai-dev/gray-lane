/**
 * The relay's own body changes of one attempt (`relay_stack.changed`, docs/relay-request-changes.md),
 * replayed on the body Gray's declared ops and appends produced, so a customer recomputes the forwarded
 * `body_jcs_sha256` when the receipt carries the values.
 *
 * The body is read as `@gray/lane`'s tree of the comparison form (`stackJsonTree`: RFC 8785 with every
 * number token as written, read with the parser `stackCanonical` uses, so the replay reads a body exactly
 * as the digest does and no raw JSON read is involved). Each value the receipt carries (`value_jcs`) is
 * read the same way and must already be in the comparison form. The entries apply in order as RFC 6902
 * does: `add` sets a member or inserts at an array index (`-` appends), `remove` and `replace` need the
 * target.
 */
import type { RelayBodyChange } from "@gray/attest";
import { stackJsonTree, stackTreeText, type StackJsonTree } from "@gray/lane";

type Tree = StackJsonTree;

const UTF8 = new TextEncoder();

/** The forwarded body: `body` with `entries` applied, in the comparison form; null when they do not apply or the body cannot be read exactly. */
export function applyRelayChanges(body: Uint8Array, entries: readonly RelayBodyChange[]): Uint8Array | null {
  const root = stackJsonTree(body);
  if (root === null) return null;
  for (const entry of entries) {
    const value = entry.value_jcs === undefined ? null : readValue(entry.value_jcs);
    if (entry.op !== "remove" && value === null) return null;
    if (!applyEntry(root, entry, value)) return null;
  }
  return UTF8.encode(stackTreeText(root));
}

/** One entry on the tree, in place. */
function applyEntry(root: Tree, entry: RelayBodyChange, value: Tree | null): boolean {
  const tokens = entry.path
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
  const last = tokens.pop()!;
  let parent: Tree | undefined = root;
  for (const token of tokens) {
    parent = parent === undefined ? undefined : child(parent, token);
  }
  if (parent === undefined || parent.kind === "text") return false;
  if (parent.kind === "object") {
    if (entry.op !== "add" && !parent.members.has(last)) return false;
    if (entry.op === "remove") parent.members.delete(last);
    else parent.members.set(last, value!);
    return true;
  }
  const items = parent.items;
  const index = last === "-" && entry.op === "add" ? items.length : arrayIndex(last);
  if (index === null || index > items.length || (entry.op !== "add" && index === items.length)) return false;
  if (entry.op === "add") items.splice(index, 0, value!);
  else if (entry.op === "remove") items.splice(index, 1);
  else items[index] = value!;
  return true;
}

function child(tree: Tree, token: string): Tree | undefined {
  if (tree.kind === "object") return tree.members.get(token);
  if (tree.kind === "array") {
    const index = arrayIndex(token);
    return index === null ? undefined : tree.items[index];
  }
  return undefined;
}

/** RFC 6901's array index: `0` or digits without a leading zero. */
function arrayIndex(token: string): number | null {
  if (!/^(0|[1-9][0-9]*)$/.test(token)) return null;
  const index = Number(token);
  return Number.isSafeInteger(index) ? index : null;
}

/** A value the receipt carries: its text, read exactly, and already in the comparison form. */
function readValue(text: string): Tree | null {
  const tree = stackJsonTree(UTF8.encode(text));
  return tree !== null && stackTreeText(tree) === text ? tree : null;
}
