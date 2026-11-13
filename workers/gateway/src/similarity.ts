/**
 * strsim 0.11's `jaro_winkler` (the crate the server's model suggestions use: crates/gray-gateway/src/
 * model_resolution.rs `suggest`), compared by Unicode scalar value as strsim compares `chars()`. Ported
 * line for line rather than taken from an npm package: the suggestions a 404 names must be the server's,
 * and the packages differ from strsim in the details that decide them (the match window for short strings,
 * the 0.7 boost threshold, the 4-character prefix). Checked against the server's own outputs by the
 * `model-catalog` conformance area.
 */

/** `generic_jaro`. */
export function jaro(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  if (x.length === 0 && y.length === 0) return 1;
  if (x.length === 0 || y.length === 0) return 0;
  const range = Math.max(0, Math.floor(Math.max(x.length, y.length) / 2) - 1);
  const xFlags = new Array<boolean>(x.length).fill(false);
  const yFlags = new Array<boolean>(y.length).fill(false);
  let matches = 0;
  for (let i = 0; i < x.length; i++) {
    const min = i > range ? i - range : 0;
    const max = Math.min(y.length, i + range + 1);
    for (let j = min; j < max; j++) {
      if (x[i] === y[j] && !yFlags[j]) {
        xFlags[i] = true;
        yFlags[j] = true;
        matches++;
        break;
      }
    }
  }
  if (matches === 0) return 0;
  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < x.length; i++) {
    if (!xFlags[i]) continue;
    while (!yFlags[k]) k++;
    if (x[i] !== y[k]) transpositions++;
    k++;
  }
  transpositions = Math.floor(transpositions / 2);
  return (matches / x.length + matches / y.length + (matches - transpositions) / matches) / 3;
}

/** `generic_jaro_winkler`: Jaro with a boost of 0.1 per common leading character, up to 4, above 0.7. */
export function jaroWinkler(a: string, b: string): number {
  const sim = jaro(a, b);
  if (sim <= 0.7) return sim;
  const x = [...a];
  const y = [...b];
  let prefix = 0;
  while (prefix < 4 && prefix < x.length && prefix < y.length && x[prefix] === y[prefix]) prefix++;
  return sim + 0.1 * prefix * (1 - sim);
}
