import { age } from "./age.ts";

/**
 * Content identities (docs/cloudflare-native/content.md 2.2 and 2.4): one X25519 age identity per
 * scope, UTC day and generation, made by typage, kept in PostgreSQL only wrapped by CONTENT_KWK.
 *
 * `wrapped` = nonce (12 bytes) ‖ AES-256-GCM(CONTENT_KWK, the identity's `AGE-SECRET-KEY-1...` text),
 * the associated data `gray.content-identity.v1:{scope}:{day}:{generation}:{recipient}`: the way the
 * server wraps data keys (crates/gray-control/src/content_keys.rs), under a label of its own, so a key
 * of the server's format never opens as an identity here, and a wrapped identity moved to another
 * scope, day or generation, or paired with another recipient, does not open.
 */

const NONCE_BYTES = 12;
const utf8 = new TextEncoder();
const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function identityAad(scope: string, day: number, generation: number, recipient: string): string {
  return `gray.content-identity.v1:${scope}:${day}:${generation}:${recipient}`;
}

/** A new identity and its recipient. */
export async function newIdentity(): Promise<{ readonly identity: string; readonly recipient: string }> {
  const { generateX25519Identity, identityToRecipient } = await age();
  const identity = await generateX25519Identity();
  return { identity, recipient: await identityToRecipient(identity) };
}

/** The recipient of an identity. */
export async function recipientOf(identity: string): Promise<string> {
  return (await age()).identityToRecipient(identity);
}

/** An identity's text, checked for its form (typage refuses anything else when it is used). */
export function identityFromString(text: string): string {
  if (!/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(text)) throw new RangeError("not an X25519 age identity");
  return text;
}

/** Wraps an identity under the key-wrapping key (an AES-GCM CryptoKey). */
export async function wrapIdentity(kwk: CryptoKey, scope: string, day: number, generation: number, recipient: string, identity: string): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: utf8.encode(identityAad(scope, day, generation, recipient)) }, kwk, utf8.encode(identity)),
  );
  const out = new Uint8Array(NONCE_BYTES + sealed.length);
  out.set(nonce, 0);
  out.set(sealed, NONCE_BYTES);
  return out;
}

/** Opens a wrapped identity; null when it does not authenticate under this key and these names. */
export async function unwrapIdentity(kwk: CryptoKey, scope: string, day: number, generation: number, recipient: string, wrapped: Uint8Array): Promise<string | null> {
  if (wrapped.length <= NONCE_BYTES) return null;
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: wrapped.subarray(0, NONCE_BYTES), additionalData: utf8.encode(identityAad(scope, day, generation, recipient)) }, kwk, wrapped.subarray(NONCE_BYTES)),
    );
  } catch {
    return null;
  }
  try {
    return identityFromString(strict.decode(plain));
  } catch {
    return null;
  } finally {
    plain.fill(0);
  }
}
