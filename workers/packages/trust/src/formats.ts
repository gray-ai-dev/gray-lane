/**
 * Formats as the Rust gate's schema validator decides them. jsonschema 0.33.0 (trust.rs
 * `schema_validator`, formats asserted) checks
 *
 * - `email` with `is_valid_email` (jsonschema-0.33.0/src/keywords/format.rs lines 289-311): the
 *   `email_address` crate 0.2.9 parses the string under its default options
 *   (`EmailAddress::from_str`: a display name and domain literals allowed, no least number of
 *   labels), then jsonschema checks the domain once more: inside brackets an IPv6 address after
 *   `IPv6:`, else an IPv4 address, each with Rust's own parser, and any other domain with
 *   `is_valid_hostname`;
 * - `hostname` with that same `is_valid_hostname` (lines 317-358): ASCII letters, digits and hyphens;
 * - `ipv4` and `ipv6` with `Ipv4Addr::from_str` and `Ipv6Addr::from_str` (lines 576-582);
 * - `idn-hostname` with `is_valid_idn_hostname` (lines 360-491): `idna`'s UTS #46 and RFC 5892's
 *   context rules, then `is_valid_hostname` on the ASCII form;
 * - `idn-email` with `is_valid_idn_email` (lines 313-315): the same parse and literals as `email`, and
 *   a domain that is no literal as `idn-hostname`.
 *
 * The survey (docs/cloudflare-native/trust.md section 4.4) measured npm's readings of these against
 * jsonschema's verdicts. Rust's IPv4 and IPv6 parsers accept exactly RFC 2673's and RFC 4291's forms,
 * and @hyperjump/json-schema-formats (maintained, MIT, already under json-schema-library) decided every
 * string as Rust did, so the addresses are its. No library reads an email address, or a hostname, as
 * `email_address` and jsonschema do (the nearest differ on dozens of the fixtures' addresses), so those
 * are ports: `email_address`'s parser (email_address-0.2.9/src/lib.rs lines 918-1179) and jsonschema's
 * `is_valid_hostname`, function for function, each under its Rust name and in its order of checks, as
 * the owner's decision of 2026-10-24 allows. Where Rust counts a length it counts UTF-8 bytes. Where it asks
 * a character's Unicode property this asks the runtime the same property: `char::is_alphanumeric` is
 * Alphabetic or a Number (Nd, Nl, No), `char::is_whitespace` is White_Space; Rust 1.98 and workerd's V8
 * both have Unicode 17.0 (measured 2026-10-24). The `trust-schema` conformance area holds these to
 * jsonschema's verdicts; the survey also cross-checked them on every code point in six places of an
 * address (6.7 million addresses), 2.3 million random addresses, 500,000 random IP addresses and
 * 300,000 random hostnames, and found none decided apart. Internationalised hostnames (`idn-hostname`,
 * an `idn-email` domain) are UTS #46, which tr46 (jsdom's, maintained, MIT) implements as `idna` does,
 * on the same Unicode 17.0.0 tables: none decided apart over every code point in a label, the random
 * corpora's hostnames and domains and a million addresses; jsonschema's context rules around it are
 * ported.
 *
 * Strings here are well formed: the gateway's JSON reader refuses a lone surrogate as serde_json
 * does (@gray/json), so every string a schema checks is one Rust could hold. One that is not is no
 * address.
 */
/// <reference path="./tr46.d.ts" />
import { utf8Length } from "@gray/json";
import { isIPv4, isIPv6 } from "@hyperjump/json-schema-formats";
import { toASCII, toUnicode } from "tr46";

// --- email_address 0.2.9 ------------------------------------------------------------------------

/** `LOCAL_PART_MAX_LENGTH`, `DOMAIN_MAX_LENGTH`, `SUB_DOMAIN_MAX_LENGTH`, in UTF-8 bytes. */
const LOCAL_PART_MAX_LENGTH = 64;
const DOMAIN_MAX_LENGTH = 254;
const SUB_DOMAIN_MAX_LENGTH = 63;

/** `char::is_alphanumeric` (core/src/char/methods.rs): `Alphabetic` or `N` (Nd, Nl, No). */
const ALPHANUMERIC = /^[\p{Alphabetic}\p{N}]$/u;

/**
 * `char::is_whitespace`: White_Space. Every White_Space character is in the Basic Multilingual Plane
 * and none is a surrogate, so a string is trimmed unit by unit.
 */
const WHITE_SPACE = /^\p{White_Space}$/u;

/** `str::trim`: White_Space off both ends (not JavaScript's `trim`, which also takes U+FEFF and keeps U+0085). */
function trim(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && WHITE_SPACE.test(text.charAt(start))) start += 1;
  while (end > start && WHITE_SPACE.test(text.charAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

function isAlphanumeric(c: number): boolean {
  return ALPHANUMERIC.test(String.fromCodePoint(c));
}

/** The code points of `text`. */
function chars(text: string): number[] {
  return Array.from(text, (c) => c.codePointAt(0) as number);
}

/** `"!#$%&'*+-/=?^_\`{|}~"`: the specials of `is_atext`. */
const ATEXT_SPECIALS = new Set(Array.from("!#$%&'*+-/=?^_`{|}~", (c) => c.charCodeAt(0)));

/** `is_atext`. */
function isAtext(c: number): boolean {
  return isAlphanumeric(c) || ATEXT_SPECIALS.has(c) || isUtf8NonAscii(c);
}

/**
 * `is_utf8_non_ascii`, as the crate writes it: it matches the big-endian bytes of the code point (not
 * of its UTF-8 encoding) against the UTF-8 byte ranges, so it holds only for U+C280 to U+DFBF whose
 * low byte is 0x80 to 0xBF (the arms whose first byte is not 0 are beyond U+10FFFF). That takes, for
 * example, the unassigned U+D7A4 in a local part and U+C280 in a quoted one, and no other non-ASCII
 * character in a quoted local part or a domain literal.
 */
function isUtf8NonAscii(c: number): boolean {
  const b0 = (c >>> 24) & 0xff;
  const b1 = (c >>> 16) & 0xff;
  const b2 = (c >>> 8) & 0xff;
  const b3 = c & 0xff;
  const tail = (b: number) => b >= 0x80 && b <= 0xbf;
  if (b0 === 0x00 && b1 === 0x00 && b2 >= 0xc2 && b2 <= 0xdf && tail(b3)) return true;
  if (b0 === 0x00 && b1 === 0xe0 && b2 >= 0xa0 && b2 <= 0xbf && tail(b3)) return true;
  if (b0 === 0x00 && b1 >= 0xe1 && b1 <= 0xec && tail(b2) && tail(b3)) return true;
  if (b0 === 0x00 && b1 === 0xed && b2 >= 0x80 && b2 <= 0x9f && tail(b3)) return true;
  if (b0 === 0x00 && b1 >= 0xee && b1 <= 0xef && tail(b2) && tail(b3)) return true;
  if (b0 === 0xf0 && b1 >= 0x90 && b1 <= 0xbf && tail(b2) && tail(b3)) return true;
  if (b0 >= 0xf1 && b0 <= 0xf3 && tail(b1) && tail(b2) && tail(b3)) return true;
  return b0 === 0xf4 && b1 >= 0x80 && b1 <= 0x8f && tail(b2) && tail(b3);
}

/** `is_atom`. */
function isAtom(s: string): boolean {
  return s !== "" && chars(s).every(isAtext);
}

/** `is_dot_atom_text`. */
function isDotAtomText(s: string): boolean {
  return s.split(".").every(isAtom);
}

/** `is_vchar`. */
function isVchar(c: number): boolean {
  return c >= 0x21 && c <= 0x7e;
}

/** `is_wsp`. */
function isWsp(c: number): boolean {
  return c === 0x20 || c === 0x09;
}

/** `is_qtext_char`. */
function isQtextChar(c: number): boolean {
  return c === 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) || isUtf8NonAscii(c);
}

/** `is_qcontent`: qtext and white space, and `\` before a visible ASCII character. */
function isQcontent(s: string): boolean {
  const cs = chars(s);
  for (let i = 0; i < cs.length; i += 1) {
    const c = cs[i] as number;
    if (c === 0x5c) {
      i += 1;
      const quoted = cs[i];
      if (quoted === undefined || !isVchar(quoted)) return false;
    } else if (!(isWsp(c) || isQtextChar(c))) {
      return false;
    }
  }
  return true;
}

/** `is_dtext_char`. */
function isDtextChar(c: number): boolean {
  return (c >= 0x21 && c <= 0x5a) || (c >= 0x5e && c <= 0x7e) || isUtf8NonAscii(c);
}

/** `split_display_email`: undefined for `Error::MissingEndBracket`. */
function splitDisplayEmail(text: string): { readonly display: string; readonly email: string } | undefined {
  // `text.rsplit_once(" <")`: " <" cannot overlap itself, so its last occurrence is the split.
  const at = text.lastIndexOf(" <");
  if (at < 0) return { display: "", email: text };
  const right = trim(text.slice(at + 2));
  if (!right.endsWith(">")) return undefined;
  return { display: trim(text.slice(0, at)), email: right.slice(0, -1) };
}

/** `split_parts`: local part, domain and display name; undefined for its errors. */
function splitParts(address: string): { readonly local: string; readonly domain: string; readonly display: string } | undefined {
  const split = splitDisplayEmail(address);
  if (split === undefined) return undefined;
  // `split_at`: `rsplit_once('@')`, `Error::MissingSeparator` without one.
  const at = split.email.lastIndexOf("@");
  if (at < 0) return undefined;
  return { local: split.email.slice(0, at), domain: split.email.slice(at + 1), display: split.display };
}

/**
 * Whether `text` is longer than `max` UTF-8 bytes. A UTF-16 unit is at least one byte, so a text of
 * more units than `max` is decided without encoding it (an upstream's string can be megabytes long).
 */
function longerThan(text: string, max: number): boolean {
  return text.length > max || utf8Length(text) > max;
}

/** `parse_local_part`. */
function parseLocalPart(part: string): boolean {
  if (part === "") return false;
  if (longerThan(part, LOCAL_PART_MAX_LENGTH)) return false;
  const bytes = utf8Length(part);
  if (part.startsWith('"') && part.endsWith('"')) {
    // `part.len() <= 2`: a lone quote, or two with nothing between.
    if (bytes <= 2) return false;
    return isQcontent(part.slice(1, -1));
  }
  return isDotAtomText(part);
}

/** `parse_text_domain` with `minimum_sub_domains` 0 (the default). */
function parseTextDomain(part: string): boolean {
  for (const sub of part.split(".")) {
    if (sub === "") return false;
    const cs = chars(sub);
    if (!isAlphanumeric(cs[0] as number)) return false;
    if (!isAlphanumeric(cs[cs.length - 1] as number)) return false;
    if (longerThan(sub, SUB_DOMAIN_MAX_LENGTH)) return false;
    if (!isAtom(sub)) return false;
  }
  return true;
}

/** `parse_domain` with `allow_domain_literal` (the default). */
function parseDomain(part: string): boolean {
  if (part === "") return false;
  if (longerThan(part, DOMAIN_MAX_LENGTH)) return false;
  // `parse_literal_domain`.
  if (part.startsWith("[") && part.endsWith("]")) return chars(part.slice(1, -1)).every(isDtextChar);
  return parseTextDomain(part);
}

/**
 * `parse_address` under `Options::default()` (`EmailAddress::from_str`): the address's domain when it
 * parses, as `EmailAddress::domain` gives it back (`split_parts` again), else undefined.
 */
function parseAddress(address: string): string | undefined {
  const parts = splitParts(address);
  if (parts === undefined) return undefined;
  // `(display.is_empty(), local_part.starts_with('<'), allow_display_text)`: with the display name
  // allowed, only `(true, true, true)`, `Error::MissingDisplayName`, is refused before the parts are.
  if (parts.display === "" && parts.local.startsWith("<")) return undefined;
  if (!parseLocalPart(parts.local) || !parseDomain(parts.domain)) return undefined;
  return parts.domain;
}

// --- jsonschema 0.33.0 --------------------------------------------------------------------------

const DOT = 0x2e;
const HYPHEN = 0x2d;

/** `VALID_CHARS` of `is_valid_hostname`: ASCII letters, digits and `-`. */
function isHostnameChar(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === HYPHEN;
}

/**
 * `is_valid_hostname` (format `hostname`, and an address's domain), which reads bytes: at most 253, no
 * trailing dot, labels of 1 to 63 that neither start nor end with `-`. A byte outside `VALID_CHARS`
 * fails it wherever it stands, and every byte of a non-ASCII character is outside, so a non-ASCII
 * string fails at once; an ASCII one has a byte per unit.
 */
export function isValidHostname(hostname: string): boolean {
  // More than 253 units is more than 253 bytes, refused whatever the bytes are.
  if (hostname.length > 253) return false;
  for (let i = 0; i < hostname.length; i += 1) if (hostname.charCodeAt(i) > 0x7f) return false;
  const len = hostname.length;
  if (len === 0 || hostname.charCodeAt(len - 1) === DOT) return false;
  let labelStart = 0;
  for (let i = 0; i < len; i += 1) {
    const c = hostname.charCodeAt(i);
    if (c === DOT) {
      const labelLen = i - labelStart;
      if (labelLen === 0 || labelLen > 63 || hostname.charCodeAt(labelStart) === HYPHEN || hostname.charCodeAt(i - 1) === HYPHEN) return false;
      labelStart = i + 1;
    } else if (!isHostnameChar(c)) {
      return false;
    }
  }
  const lastLabelLen = len - labelStart;
  return !(lastLabelLen === 0 || lastLabelLen > 63 || hostname.charCodeAt(labelStart) === HYPHEN || hostname.charCodeAt(len - 1) === HYPHEN);
}

/**
 * `Ipv4Addr::from_str` (format `ipv4`, and a domain literal): RFC 2673's dotted quad, four decimal
 * octets of at most 255 without a leading zero, as @hyperjump/json-schema-formats checks it; that is
 * the language of Rust's parser (core/src/net/parser.rs `read_ipv4_addr`: up to three digits, no zero
 * prefix, a u8, the whole input), and the survey found no string they decide apart.
 */
export function isValidIpv4(text: string): boolean {
  return isIPv4(text);
}

/**
 * `Ipv6Addr::from_str` (format `ipv6`, and an `IPv6:` domain literal): RFC 4291's text form (RFC
 * 3986's `IPv6address`: up to eight groups of one to four hex digits, one `::` standing for at least
 * one group, a dotted quad only as the last two groups), as @hyperjump/json-schema-formats checks it;
 * that is the language of Rust's `read_ipv6_addr`, and the survey found no string they decide apart.
 */
export function isValidIpv6(text: string): boolean {
  return isIPv6(text);
}

/**
 * `is_valid_email_impl`: the address parses, and its domain is `[IPv6:` an IPv6 address `]`, `[` an
 * IPv4 address `]`, or a hostname as `isHostname` reads it.
 */
function isValidEmailImpl(email: string, isHostname: (hostname: string) => boolean): boolean {
  if (!email.isWellFormed()) return false;
  const domain = parseAddress(email);
  if (domain === undefined) return false;
  // `domain.strip_prefix('[').and_then(|d| d.strip_suffix(']'))`
  if (domain.startsWith("[") && domain.endsWith("]")) {
    const literal = domain.slice(1, -1);
    return literal.startsWith("IPv6:") ? isValidIpv6(literal.slice("IPv6:".length)) : isValidIpv4(literal);
  }
  return isHostname(domain);
}

/** `is_valid_email` (`is_valid_email_impl` with `is_valid_hostname`). */
export function isValidEmail(email: string): boolean {
  return isValidEmailImpl(email, isValidHostname);
}

/**
 * The code points before which `is_valid_idn_hostname` takes a ZERO WIDTH JOINER (RFC 5892 appendix
 * A.2, the viramas jsonschema lists), in its order.
 */
const VIRAMAS: ReadonlySet<number> = new Set([
  0x094d, 0x09cd, 0x0a4d, 0x0acd, 0x0b4d, 0x0bcd, 0x0c4d, 0x0ccd, 0x0d4d, 0x0dca, 0x0e3a, 0x0f84, 0x1039, 0x1714, 0x1734, 0x17d2, 0x1a60,
  0x1b44, 0x1baa, 0x1bf2, 0x1bf3, 0x2d7f, 0xa806, 0xa8c4, 0xa953, 0xabed, 0x10a3f, 0x11046, 0x1107f, 0x110b9, 0x11133, 0x111c0, 0x11235,
  0x112ea, 0x1134d, 0x11442, 0x114c2, 0x115bf, 0x1163f, 0x116b6, 0x1172b, 0x11839, 0x119e0, 0x11a34, 0x11a47, 0x11a99, 0x11c3f, 0x11d44,
  0x11d45, 0x11d97,
]);

/** The code points `is_valid_idn_hostname` refuses wherever they stand ("DISALLOWED"). */
const IDN_DISALLOWED: ReadonlySet<number> = new Set([0x0640, 0x07fa, 0x302e, 0x302f, 0x3031, 0x3032, 0x3033, 0x3034, 0x3035, 0x303b]);

const inRange = (c: number | undefined, low: number, high: number): boolean => c !== undefined && c >= low && c <= high;

/**
 * `is_valid_idn_hostname` (format `idn-hostname` from draft 7 on, and an `idn-email` domain; lines
 * 360-491): `idna` 1.1.0's UTS #46 ToASCII with the STD3 rules, hyphens checked and DNS lengths
 * verified (`Uts46::to_ascii(.., AsciiDenyList::STD3, Hyphens::Check, DnsLength::Verify)`, which always
 * checks bidi and joiners, nontransitionally), ToUnicode of that, RFC 5892's context rules over the
 * Unicode form, and `is_valid_hostname` on the ASCII form. UTS #46 is tr46 6.0.0's (jsdom's, under
 * whatwg-url; MIT), whose tables are Unicode 17.0.0, the version of `idna`'s (ICU4X 2.3, ICU 78); the
 * survey found no string they decide apart (docs/cloudflare-native/trust.md section 4.4). The context
 * rules are jsonschema's, ported in its order: they run over the whole hostname, labels and dots alike.
 */
export function isValidIdnHostname(hostname: string): boolean {
  if (!hostname.isWellFormed()) return false;
  const ascii = toASCII(hostname, {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    useSTD3ASCIIRules: true,
    transitionalProcessing: false,
    verifyDNSLength: true,
  });
  if (ascii === null) return false;
  // `to_unicode(.., AsciiDenyList::EMPTY, Hyphens::Allow)`, whose errors jsonschema ignores.
  const unicode = toUnicode(ascii, { checkBidi: true, checkJoiners: true, transitionalProcessing: false }).domain;
  const chars = Array.from(unicode, (c) => c.codePointAt(0) as number);
  let previous = 0;
  let hasKatakanaMiddleDot = false;
  let hasHiraganaKatakanaHan = false;
  let hasArabicIndicDigits = false;
  let hasExtendedArabicIndicDigits = false;
  for (let i = 0; i < chars.length; i += 1) {
    const current = chars[i] as number;
    const next = chars[i + 1];
    if (current === 0x200d) {
      // ZERO WIDTH JOINER (A.2).
      if (!VIRAMAS.has(previous)) return false;
    } else if (current === 0x00b7) {
      // MIDDLE DOT (A.3).
      if (previous !== 0x6c || next !== 0x6c) return false;
    } else if (current === 0x0375) {
      // Greek KERAIA (A.4).
      if (!inRange(next, 0x0370, 0x03ff)) return false;
    } else if (current === 0x05f3 || current === 0x05f4) {
      // Hebrew GERESH and GERSHAYIM (A.5, A.6).
      if (!inRange(previous, 0x0590, 0x05ff)) return false;
    } else if (current === 0x30fb) {
      hasKatakanaMiddleDot = true;
    } else if (inRange(current, 0x3040, 0x309f) || inRange(current, 0x30a0, 0x30ff) || inRange(current, 0x4e00, 0x9fff)) {
      // Hiragana, Katakana or Han (A.7).
      hasHiraganaKatakanaHan = true;
    } else if (inRange(current, 0x0660, 0x0669)) {
      hasArabicIndicDigits = true;
    } else if (inRange(current, 0x06f0, 0x06f9)) {
      hasExtendedArabicIndicDigits = true;
    } else if (IDN_DISALLOWED.has(current)) {
      return false;
    }
    previous = current;
  }
  if ((hasKatakanaMiddleDot && !hasHiraganaKatakanaHan) || (hasArabicIndicDigits && hasExtendedArabicIndicDigits)) return false;
  return isValidHostname(ascii);
}

/**
 * `is_valid_idn_email` (lines 313-315: `is_valid_email_impl` with `is_valid_idn_hostname`): the same
 * parse and domain literals as `email`, a domain that is no literal read as `idn-hostname` reads it.
 */
export function isValidIdnEmail(email: string): boolean {
  return isValidEmailImpl(email, isValidIdnHostname);
}
