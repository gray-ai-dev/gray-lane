/**
 * Patterns as the Rust gate compiles them: jsonschema 0.33 hands every `pattern` and
 * `patternProperties` key to `ecma::to_rust_regex` (jsonschema-0.33.0/src/ecma.rs), then builds the
 * result with the `regex` crate (`PatternOptions::regex()`, trust.rs `schema_validator`). The engine
 * here is that same crate (src/engine.ts), so what remains to port is the translation, which reads a
 * pattern as ECMA-262 wrote it:
 *
 * 1. `\cX` with an ASCII letter X, which Rust's syntax does not have, becomes the control character
 *    X % 32. Any other first parse error ends the translation: look-around and backreferences return
 *    the pattern unchanged (the `regex` build then refuses it; `format: "regex"` accepts it), every
 *    other error fails it.
 * 2. Perl classes take ECMA-262's ASCII meaning: `\d` becomes `[0-9]`, `\w` `[A-Za-z0-9_]`, `\s` a
 *    fixed set of ten characters (written out below, as jsonschema writes it), and the capitals
 *    their negations. Inside a bracketed class the replacement is a nested class, which Rust allows.
 * 3. A bell escape `\a` outside a bracketed class fails the translation.
 *
 * jsonschema finds these on regex-syntax's syntax tree. Here they are found as escape units (a
 * backslash and the character after it), which is the same thing everywhere except inside a
 * verbose-mode comment, where a backslash is text. When a pattern can turn verbose mode on, each
 * unit that could sit in a comment (a `#` before it on its line: a comment runs from `#` to the end
 * of the line, regex-syntax's `x` flag) is first asked of the engine itself: replaced by an escape
 * Rust refuses everywhere (`\y`), the pattern still parses only if the unit sits in a comment, which
 * is then left alone. Whether a bell sits in a bracketed class is asked the same way (`\b` is refused
 * only there). Each question is one parse in the engine (src/engine.ts `parseRust`), charged to the
 * request; the answers are kept for the pattern when the request runs out of allowance first, so a
 * retry goes on from there.
 */
import { type CompileAllowance, buildRust, configureBuiltCache, currentCompileAllowance, matchRust, parseRust, RegexEngineBusy } from "./engine.ts";
import { RECENT_KEY_UNITS, Recent } from "./recent.ts";

/** ecma.rs `Ecma262Translator::replace`, character for character. */
const SPACE_SET = " \t\n\r\u000b\u000c ﻿  ";
const PERL_CLASSES: Readonly<Record<string, string>> = {
  d: "[0-9]",
  D: "[^0-9]",
  w: "[A-Za-z0-9_]",
  W: "[^A-Za-z0-9_]",
  s: `[${SPACE_SET}]`,
  S: `[^${SPACE_SET}]`,
};

/** `ast::ErrorKind::UnsupportedLookAround` and `UnsupportedBackreference` (regex-syntax-0.8.11/src/ast/mod.rs). */
const PASSED_THROUGH = new Set([
  "look-around, including look-ahead and look-behind, is not supported",
  "backreferences are not supported",
]);

/** Thrown out of a translation whose pattern the engine could not parse within its largest instance. */
class Undecided extends Error {}

/**
 * The parse error regex-syntax reports first for `pattern` (its kind, the message's last line), or
 * null when it parses. jsonschema only parses here (`to_rust_regex`), and so does the probe
 * (src/engine.ts `parseRust`). Throws `Undecided`.
 */
function parseError(pattern: string): string | null {
  const parsed = parseRust(pattern);
  if (parsed.kind === "undecided") throw new Undecided();
  if (parsed.kind === "parsed") return null;
  const at = parsed.message.lastIndexOf("\nerror: ");
  return at < 0 ? parsed.message : parsed.message.slice(at + "\nerror: ".length);
}

interface Unit {
  /** Offset of the backslash, in UTF-16 code units. */
  readonly at: number;
  /** Length of the unit in UTF-16 code units. */
  readonly length: number;
  /** The text that replaces it, or "bell" for `\a`. */
  readonly replace: string | "bell";
}

const ASCII_LETTER = /^[A-Za-z]$/;

/** The escape units the translation acts on, in order: `\cX` (X an ASCII letter), Perl classes, `\a`. */
function units(pattern: string): { control: Unit[]; perl: Unit[] } {
  const control: Unit[] = [];
  const perl: Unit[] = [];
  let i = 0;
  while (i < pattern.length) {
    if (pattern.charCodeAt(i) !== 0x5c) {
      i += 1;
      continue;
    }
    const next = pattern.codePointAt(i + 1);
    if (next === undefined) break;
    const ch = String.fromCodePoint(next);
    if (ch === "c") {
      const letter = pattern.codePointAt(i + 2);
      if (letter !== undefined && ASCII_LETTER.test(String.fromCodePoint(letter))) {
        control.push({ at: i, length: 3, replace: String.fromCharCode(letter % 32) });
        i += 3;
        continue;
      }
    } else if (Object.hasOwn(PERL_CLASSES, ch)) {
      perl.push({ at: i, length: 2, replace: PERL_CLASSES[ch] as string });
    } else if (ch === "a") {
      perl.push({ at: i, length: 2, replace: "bell" });
    }
    i += 1 + ch.length;
  }
  return { control, perl };
}

/** `pattern` with each unit replaced by `text(unit)` (units sorted by offset, non-overlapping). */
function splice(pattern: string, replaced: ReadonlyArray<readonly [Unit, string]>): string {
  let out = "";
  let from = 0;
  for (const [unit, text] of replaced) {
    out += pattern.slice(from, unit.at) + text;
    from = unit.at + unit.length;
  }
  return out + pattern.slice(from);
}

/** A flag group that can turn on verbose mode (`(?x)`, `(?ix:`); false positives cost only time. */
const VERBOSE_FLAG = /\(\?[A-Za-z-]*x[A-Za-z-]*[:)]/;

/**
 * What the engine answered for each unit of a pattern (keyed `comment:` or `bell:` and the unit's
 * offset), so that a translation the request's allowance stopped goes on from there next time.
 */
type Answers = Map<string, boolean>;

/**
 * Whether the pattern still parses with `text` in place of `unit` and every other listed unit
 * neutralised to a literal that is valid anywhere (`\x41`). Remembered in `answers` under `key`.
 */
function probe(pattern: string, all: readonly Unit[], unit: Unit, text: string, answers: Answers, key: string): boolean {
  let answer = answers.get(key);
  if (answer === undefined) {
    answer = parseError(splice(pattern, all.map((u) => [u, u === unit ? text : "\\x41"] as const))) === null;
    answers.set(key, answer);
  }
  return answer;
}

/**
 * Whether `unit` sits in a verbose-mode comment, where its backslash is text. A comment runs from a
 * `#` to the end of its line, so a unit with no `#` before it on its line is not in one.
 */
function inComment(pattern: string, all: readonly Unit[], unit: Unit, answers: Answers): boolean {
  const hash = pattern.indexOf("#", pattern.lastIndexOf("\n", unit.at) + 1);
  if (hash < 0 || hash > unit.at) return false;
  return probe(pattern, all, unit, "\\y", answers, `comment:${unit.at}`);
}

export type Translation =
  /** The translated pattern, which the `regex` build may still refuse. */
  | { readonly kind: "translated"; readonly pattern: string }
  /** Look-around or a backreference: returned unchanged; the build refuses it. */
  | { readonly kind: "unsupported" }
  | { readonly kind: "invalid" }
  /**
   * Parsing it took more than the engine's largest instance (src/engine.ts `parseRust`): not a regex
   * for `format: "regex"`, and refused as a schema pattern, as its build, which parses the same text
   * under a smaller budget, would be. Not kept in `translations`.
   */
  | { readonly kind: "undecided" };

/**
 * Translations by pattern text: the patterns of schemas, which come back with every request of an
 * agent. A translation that falls out is worked out again (its probes parse again in the engine,
 * src/engine.ts). `format: "regex"` on an answer's arguments asks about an upstream's strings, which
 * repeat little across answers and may be long: they are looked up here but never kept
 * (`translate`'s `remember`), so they cannot push the schemas' patterns out; they are kept for their
 * own answer only (`answerTranslations`).
 */
const translations = new Recent<Translation>(RECENT_KEY_UNITS);

/**
 * The translations of an upstream's strings, for as long as the answer that carries them is checked:
 * by the allowance its checks are charged to (src/engine.ts `currentCompileAllowance`; one per answer,
 * src/policy.ts `ToolSchemas`). A string the answer repeats, or that both the client's schema and an
 * operator's check, is parsed once, so it costs the answer's allowance once, as deciding it costs Rust
 * nothing it could run out of. Nothing of it outlives the answer. Each entry but a string too long to
 * parse at all (more than an engine instance's 31.7 MiB) was charged a probe, at least 4 KiB
 * (src/engine.ts `probeCharge`), so an answer keeps at most 32,768 of them; their keys are the
 * answer's own strings.
 */
const answerTranslations = new WeakMap<CompileAllowance, Map<string, Translation>>();

/** The current answer's translations of an upstream's strings, or undefined outside an allowance. */
function answerScope(): Map<string, Translation> | undefined {
  const allowance = currentCompileAllowance();
  if (allowance === undefined) return undefined;
  let scope = answerTranslations.get(allowance);
  if (scope === undefined) {
    scope = new Map();
    answerTranslations.set(allowance, scope);
  }
  return scope;
}

const UNDECIDED: Translation = { kind: "undecided" };

/**
 * The engine's answers for patterns whose translation the request's allowance stopped. Each is sized
 * by an upper bound fixed when it is kept: its key and an entry for each escape unit, at most one per
 * two UTF-16 units of the pattern, counted as 8 units each.
 */
const unfinished = new Recent<Answers>(RECENT_KEY_UNITS);

/**
 * `ecma::to_rust_regex`, remembered per pattern (`translations`). With `remember` false (an upstream's
 * string) a translation already kept is used, and this one is kept for the current answer only
 * (`answerTranslations`): not in `translations`, and not the engine's answers when the allowance
 * stops it (an answer's check is not retried).
 */
export function translate(pattern: string, remember = true): Translation {
  let translation = translations.get(pattern);
  if (translation !== undefined) return translation;
  const answer = remember ? undefined : answerScope();
  translation = answer?.get(pattern);
  if (translation !== undefined) return translation;
  const answers = (remember ? unfinished.get(pattern) : undefined) ?? new Map<string, boolean>();
  try {
    translation = translateNow(pattern, answers);
  } catch (error) {
    if (!(error instanceof Undecided)) {
      if (remember && error instanceof RegexEngineBusy && answers.size > 0) unfinished.set(pattern, answers, 5 * pattern.length);
      throw error;
    }
    translation = UNDECIDED;
  }
  if (remember) {
    if (translation !== UNDECIDED) translations.set(pattern, translation);
  } else {
    answer?.set(pattern, translation);
  }
  return translation;
}

function translateNow(pattern: string, answers: Answers): Translation {
  const verbose = VERBOSE_FLAG.test(pattern);
  const found = units(pattern);
  const everything = [...found.control, ...found.perl].sort((a, b) => a.at - b.at);
  // 1. Control escapes, unless in a comment.
  const controls = found.control.filter((u) => !(verbose && inComment(pattern, everything, u, answers)));
  const withControls = splice(
    pattern,
    controls.map((u) => [u, u.replace] as const),
  );
  const first = parseError(withControls);
  if (first !== null) return PASSED_THROUGH.has(first) ? { kind: "unsupported" } : { kind: "invalid" };
  // 2. and 3., on the same offsets shifted by the control replacements.
  const shift = (at: number) => controls.filter((u) => u.at < at).reduce((sum) => sum - 2, at);
  const perl = found.perl
    .filter((u) => !(verbose && inComment(pattern, everything, u, answers)))
    .map((u) => ({ ...u, at: shift(u.at) }));
  const remaining = perl.filter((u) => u.replace !== "bell");
  for (const bell of perl.filter((u) => u.replace === "bell")) {
    // Outside a bracketed class (where `\b` is refused) a bell fails the translation.
    if (probe(withControls, perl, bell, "\\b", answers, `bell:${bell.at}`)) return { kind: "invalid" };
  }
  const translated = splice(
    withControls,
    remaining.map((u) => [u, u.replace as string] as const),
  );
  if (translated !== withControls && parseError(translated) !== null) return { kind: "invalid" };
  return { kind: "translated", pattern: translated };
}

/**
 * `format: "regex"`: `to_rust_regex` succeeds (jsonschema-0.33.0/src/keywords/format.rs
 * `is_valid_regex`). A pattern already built translated, so a schema checked again after admission
 * (against its meta-schema, which asks this of every `pattern`) works out nothing new. `remember`
 * false for an upstream's string (`translate`).
 */
export function isRegexFormat(pattern: string, remember = true): boolean {
  const kind = translate(pattern, remember).kind;
  return kind === "translated" || kind === "unsupported";
}

/** The bound of the translation and compile-outcome maps, in UTF-16 units of keys (src/settings.ts). */
export function configurePatternCaches(keyUnits: number): void {
  translations.resize(keyUnits);
  unfinished.resize(keyUnits);
  configureBuiltCache(keyUnits);
}

/**
 * A pattern a schema keyword holds. It does not hold the compiled regex: the engine keeps those in a
 * bounded cache and frees what falls out (src/engine.ts), so each match asks the engine, which
 * compiles the pattern again if it has to. A validator kept for a long time costs no engine memory.
 */
export interface CompiledPattern {
  /** `Regex::is_match`. Throws `RegexEngineTrapped` when the engine trapped (src/engine.ts). */
  isMatch(text: string): boolean;
}

/**
 * A pattern as a schema keyword compiles it: translated, then built under the compile budget;
 * undefined when either refuses it (Rust's `InvalidToolSchema`). Deciding parses in the prober and
 * compiles in a build instance of its own (src/engine.ts), so it does not throw `RegexEngineTrapped`;
 * it throws `RegexEngineBusy` when the request's allowance is spent.
 */
export function compilePattern(pattern: string): CompiledPattern | undefined {
  const translation = translate(pattern);
  if (translation.kind !== "translated" || !buildRust(translation.pattern).ok) return undefined;
  const rust = translation.pattern;
  return { isMatch: (text: string) => matchRust(rust, text) };
}
