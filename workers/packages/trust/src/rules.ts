/**
 * The operator rules that read a declared call's arguments for Gray itself
 * (crates/gray-gateway/src/trust.rs): exact HTTPS hosts for URL arguments (`inspect_url`,
 * `validate_domains`) and the literal command grammar (`literal_words`, `inspect_command`,
 * `safe_package_spec`). These rules never execute or fetch anything. URLs are read with the platform's
 * WHATWG URL parser, as the Rust code reads them with the `url` crate (rust-url follows the same
 * standard); the command grammar is deliberately not a shell parser, and unsupported grammar is
 * refused rather than interpreted.
 */
import { compareUtf8, utf8Length } from "@gray/json";
import type { CommandPolicy } from "./config.ts";
import { refuse } from "./violations.ts";

/** `char::is_control`: general category Cc (U+0000 to U+001F, U+007F to U+009F). */
function isControl(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
}

/** `char::is_whitespace`: the White_Space property. */
function isWhitespace(code: number): boolean {
  return (
    (code >= 0x09 && code <= 0x0d) ||
    code === 0x20 ||
    code === 0x85 ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000
  );
}

function parseUrl(text: string): URL | undefined {
  try {
    return new URL(text);
  } catch {
    return undefined;
  }
}

/**
 * `validate_domains`: each domain must be what `https://{domain}` parses to as its host, exactly:
 * lowercase, no port, no trailing dot, no path, query, fragment or credentials. Returns the
 * `TrustConfigError` text, or undefined.
 */
export function domainProblem(domains: ReadonlySet<string>): string | undefined {
  for (const domain of [...domains].sort(compareUtf8)) {
    const url = parseUrl(`https://${domain}`);
    if (url === undefined) return "invalid exact HTTPS domain";
    if (
      url.hostname !== domain ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== "" ||
      url.username !== "" ||
      url.password !== "" ||
      domain.includes(":") ||
      domain.endsWith(".")
    ) {
      return "domains must be lowercase exact hosts without ports or wildcards";
    }
  }
  return undefined;
}

/** `inspect_url`: an `https` URL on port 443, without credentials, whose host is one of `domains`. */
export function inspectUrl(value: string, domains: ReadonlySet<string>): void {
  for (const ch of value) {
    const code = ch.codePointAt(0) as number;
    if (isControl(code) || isWhitespace(code) || ch === "\\") refuse("trust_url_not_allowed");
  }
  const url = parseUrl(value);
  if (url === undefined) refuse("trust_url_not_allowed");
  // `port_or_known_default() == Some(443)`: for https, the WHATWG parser drops an explicit 443.
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "" || !domains.has(url.hostname)) {
    refuse("trust_url_not_allowed");
  }
}

/** `safe_package_spec`. */
export function safePackageSpec(value: string): boolean {
  if (value === "" || value.startsWith("-") || value.startsWith(".") || value.startsWith("/")) return false;
  if (value.includes("..") || value.includes(":")) return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const alnum = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
    if (!alnum && !"@/._-=^~".includes(value[i] as string)) return false;
  }
  return !value.includes("/") || (value.startsWith("@") && value.split("/").length === 2);
}

/** The characters `literal_words` refuses outright: shell syntax it does not interpret. */
const SHELL_SYNTAX = ";|&$`\\<>()[]{}*?!#";

/**
 * `literal_words`: a small literal-argument grammar, not a shell parser. Words are separated by
 * spaces; single or double quotes group text (no escapes); control characters and any shell syntax
 * are refused, as is a command longer than 16,384 bytes (trust.rs, the same bound).
 */
export function literalWords(text: string): string[] {
  if (utf8Length(text) > 16_384) refuse("trust_command_not_allowed");
  for (const ch of text) {
    if (isControl(ch.codePointAt(0) as number) || SHELL_SYNTAX.includes(ch)) refuse("trust_command_not_allowed");
  }
  let quote: string | undefined;
  let word = "";
  const words: string[] = [];
  for (const ch of text) {
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else word += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === " ") {
      if (word !== "") {
        words.push(word);
        word = "";
      }
    } else {
      word += ch;
    }
  }
  if (quote !== undefined) refuse("trust_command_not_allowed");
  if (word !== "") words.push(word);
  return words;
}

/** The package manager and package words of an install command, if `words` is one. */
function installOf(words: readonly string[]): { manager: "pip" | "npm" | "cargo"; packages: readonly string[] } | undefined {
  const [a, b, c, d] = words;
  if ((a === "pip" || a === "pip3") && b === "install") return { manager: "pip", packages: words.slice(2) };
  if ((a === "python" || a === "python3") && b === "-m" && c === "pip" && d === "install") return { manager: "pip", packages: words.slice(4) };
  if (a === "npm" && b === "install") return { manager: "npm", packages: words.slice(2) };
  if (a === "cargo" && b === "add") return { manager: "cargo", packages: words.slice(2) };
  return undefined;
}

/** `inspect_command`. */
export function inspectCommand(text: string, policy: CommandPolicy): void {
  if (policy.allowedCommands.has(text)) return;
  const words = literalWords(text);
  const install = installOf(words);
  if (install !== undefined) {
    const allowed = policy.allowedPackages.get(install.manager);
    if (allowed === undefined) refuse("trust_package_not_allowed");
    if (install.packages.length === 0 || install.packages.some((p) => !safePackageSpec(p) || !allowed.has(p))) {
      refuse("trust_package_not_allowed");
    }
    return;
  }
  if (words[0] === "curl" && words[1] === "-q" && words.length === 3) return inspectUrl(words[2] as string, policy.downloadDomains);
  if (words[0] === "curl" && words[1] === "-q" && words[2] === "-fsS" && words.length === 4) return inspectUrl(words[3] as string, policy.downloadDomains);
  refuse("trust_command_not_allowed");
}
