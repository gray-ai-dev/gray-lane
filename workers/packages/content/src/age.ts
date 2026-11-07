/**
 * typage, loaded at its first use, never while a Worker's main module loads: its @noble/curves (2.4.0)
 * draws random values when its modules are evaluated (16 to 99 bytes, measured in workerd 2026-10-19),
 * and workerd refuses random values in the global scope, so a static import would stop the gateway and
 * the content Worker from starting. A dynamic import is evaluated inside the request that first needs it
 * (wrangler's bundler keeps a dynamically imported module's evaluation lazy).
 */
type Typage = typeof import("age-encryption");

let loaded: Promise<Typage> | null = null;

export function age(): Promise<Typage> {
  loaded ??= import("age-encryption");
  return loaded;
}
