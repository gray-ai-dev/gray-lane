/**
 * Amounts of money in the messages of Gray-worded errors, written as the Rust gateway writes them.
 */

/**
 * Rust's `format!("{:.N}", x)`: the exact value of `x` rounded to `digits` decimals, a tie to the
 * even digit (Rust formats from the exact binary value; `Number.prototype.toFixed` rounds a tie up,
 * so it is not used for the rounding: `1.125` is `1.12` here and in Rust, `1.13` from toFixed).
 * Exact for finite `x` below 10^21 whose binary value has at most 100 decimals, which every amount
 * of whole micro-USD in dollars has.
 */
export function formatFixed(x: number, digits: number): string {
  if (!Number.isFinite(x) || Math.abs(x) >= 1e21) throw new RangeError(`formatFixed: ${x} is out of range`);
  const negative = x < 0 || Object.is(x, -0);
  const [whole = "0", fraction = ""] = Math.abs(x).toFixed(100).split(".");
  const kept = fraction.slice(0, digits);
  const rest = fraction.slice(digits);
  const first = rest[0];
  let up = false;
  if (first !== undefined && first > "5") up = true;
  else if (first === "5") {
    if (/[1-9]/.test(rest.slice(1))) up = true;
    else {
      // Exactly half: to the even digit.
      const last = kept.length > 0 ? kept[kept.length - 1] : whole[whole.length - 1];
      up = Number(last) % 2 === 1;
    }
  }
  let all = whole + kept;
  if (up) all = (BigInt(all) + 1n).toString().padStart(all.length, "0");
  const integer = all.slice(0, all.length - digits) || "0";
  const decimals = all.slice(all.length - digits);
  return `${negative ? "-" : ""}${integer}${digits > 0 ? `.${decimals}` : ""}`;
}

/**
 * An amount of micro-USD as dollars, to the cent when it is at least one dollar and to the
 * micro-dollar below (`inference::usd`): `$1.20`, `$0.004567`, `$0.13`.
 */
export function usd(microusd: bigint): string {
  const dollars = Number(microusd) / 1_000_000;
  const abs = microusd < 0n ? -microusd : microusd;
  if (abs >= 1_000_000n) return `$${formatFixed(dollars, 2)}`;
  const text = formatFixed(dollars, 6).replace(/0+$/, "");
  return `$${text.endsWith(".") ? `${text}00` : text}`;
}

/**
 * `microusd` in dollars, exactly and with at least the cents, as a customer reads an amount owed
 * (`decimal::dollars`): `$1.234567`, `$1.20`, `$0.004567`, `$0.00`.
 */
export function dollars(microusd: bigint): string {
  if (microusd < 0n) throw new RangeError("dollars: a negative amount");
  const whole = microusd / 1_000_000n;
  const fraction = (microusd % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  const text = fraction.length > 0 ? `${whole}.${fraction}` : `${whole}`;
  return `$${text}${fraction.length === 0 ? "." : ""}${"0".repeat(Math.max(0, 2 - fraction.length))}`;
}
