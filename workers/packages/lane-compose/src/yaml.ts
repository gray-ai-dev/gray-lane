/**
 * The compose text as the `yaml` package reads it, with the strictness of deploy/tee/app-compose.mjs
 * (D58, D93): duplicate keys, parse errors and warnings are refused, and so are anchors, aliases,
 * merge keys and custom tags, found in the syntax tree because the resolved value would hide exactly
 * the override compose-go applies (`<<` is an ordinary key in YAML 1.2, an unknown tag only a
 * warning). Standard tags (`tag:yaml.org,2002:*`) are allowed.
 */
import { isAlias, isPair, isScalar, parseDocument, visit } from "yaml";

/** A parsed YAML value: mappings as Maps (keys are not always strings), sequences as arrays. */
export type YamlValue = null | boolean | number | bigint | string | YamlValue[] | YamlMap;
export type YamlMap = Map<unknown, YamlValue>;

export type YamlResult =
  | { readonly ok: true; readonly value: YamlMap }
  | { readonly ok: false; readonly code: "docker_compose_file_invalid" | "yaml_syntax_forbidden" | "yaml_warning" };

export function isYamlMap(value: unknown): value is YamlMap {
  return value instanceof Map;
}

/** The first anchor, alias, merge key or custom tag in the document, or undefined. */
function forbiddenSyntax(document: ReturnType<typeof parseDocument>): string | undefined {
  let found: string | undefined;
  visit(document, (_key, node) => {
    if (isAlias(node)) found = "alias";
    else if (isPair(node)) {
      if (isScalar(node.key) && node.key.value === "<<") found = "merge key";
    } else if (node !== null && typeof node === "object" && "anchor" in node && typeof node.anchor === "string") {
      found = "anchor";
    } else if (node !== null && typeof node === "object" && "tag" in node && typeof node.tag === "string" && !node.tag.startsWith("tag:yaml.org,2002:")) {
      found = "custom tag";
    }
    return found === undefined ? undefined : visit.BREAK;
  });
  return found;
}

export function parseComposeText(text: string): YamlResult {
  const document = parseDocument(text, { uniqueKeys: true, prettyErrors: false });
  if (document.errors.length > 0) return { ok: false, code: "docker_compose_file_invalid" };
  // A `%YAML 1.1` directive changes how this parser resolves scalars; compose-go does not follow it.
  if (document.directives?.yaml.explicit === true) return { ok: false, code: "yaml_syntax_forbidden" };
  if (forbiddenSyntax(document) !== undefined) return { ok: false, code: "yaml_syntax_forbidden" };
  if (document.warnings.length > 0) return { ok: false, code: "yaml_warning" };
  let value: unknown;
  try {
    value = document.toJS({ mapAsMap: true, maxAliasCount: 0 });
  } catch {
    return { ok: false, code: "docker_compose_file_invalid" };
  }
  if (!isYamlMap(value)) return { ok: false, code: "docker_compose_file_invalid" };
  return { ok: true, value };
}
