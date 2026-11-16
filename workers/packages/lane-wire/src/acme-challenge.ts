import { z } from "zod";
import { BridgeWireError } from "./error.ts";

/**
 * `acme.challenge`: an entry asks the bridge to set or clear one DNS-01 challenge value (docs/design/entry-replicas.md
 * ER5). With several entry replicas behind one name a certificate order validates by DNS-01, and no DNS credential is
 * inside the CVM (D45, EI2), so the bridge writes the `_acme-challenge` TXT record with a token of its own, for the
 * names on its allowlist only (EI7).
 *
 * The document is what the ACME client's HTTP DNS provider sends (lego `providers/dns/httpreq`: `{fqdn, value}` to
 * `/present` and `/cleanup`), with the action as a member: the lane's entrypoint forwards each as one signed call.
 * `fqdn` is the record's full name as the client gives it, `_acme-challenge.<name>` with or without the root's
 * trailing dot and in either case; both sides compare `acmeChallengeNameOf(fqdn)`, lower-case without the dot. `value`
 * is the key authorization's digest (RFC 8555 section 8.4: the base64url of a SHA-256, 43 characters, no padding).
 *
 * `present` adds the value beside any other under the name: two replicas ordering at once each hold their own, which
 * DNS-01 allows. `cleanup` removes that value alone. The answer says whether the call changed the zone: a `present`
 * of a value already there and a `cleanup` of one that is not are both done, with `changed` false.
 *
 * The target is `acme/<name>`, so a signature over one name's call never verifies as another's.
 */

/** The prefix of the target a call signs: `acme/<name>`. */
export const ACME_CHALLENGE_TARGET_PREFIX = "acme/";
/** The label every DNS-01 challenge record's name begins with (RFC 8555 section 8.4). */
export const ACME_CHALLENGE_LABEL = "_acme-challenge.";

export const ACME_CHALLENGE_ACTIONS = ["present", "cleanup"] as const;
export type AcmeChallengeAction = (typeof ACME_CHALLENGE_ACTIONS)[number];

/** A DNS-01 value: the base64url of a SHA-256 digest without padding (RFC 8555 section 8.4, RFC 4648 section 5). */
export const ACME_CHALLENGE_VALUE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** `_acme-challenge.` and a DNS name of two or more labels, lower-case, without the root's dot. */
export const ACME_CHALLENGE_NAME_PATTERN = /^_acme-challenge(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){2,}$/;
/** A DNS name's longest text form without the root's dot (RFC 1035 section 2.3.4: 255 octets on the wire). */
export const ACME_CHALLENGE_NAME_MAX_CHARS = 253;

/** `fqdn` as both sides compare it: lower-case, without the root's trailing dot. Null when it is not a challenge record's name. */
export function acmeChallengeNameOf(fqdn: string): string | null {
  const name = (fqdn.endsWith(".") ? fqdn.slice(0, -1) : fqdn).toLowerCase();
  return name.length <= ACME_CHALLENGE_NAME_MAX_CHARS && ACME_CHALLENGE_NAME_PATTERN.test(name) ? name : null;
}

export const acmeChallengeSchema = z
  .object({
    action: z.enum(ACME_CHALLENGE_ACTIONS),
    fqdn: z
      .string()
      .max(ACME_CHALLENGE_NAME_MAX_CHARS + 1)
      .refine((fqdn) => acmeChallengeNameOf(fqdn) !== null, "a challenge record's name: _acme-challenge.<DNS name>, with or without the trailing dot"),
    value: z.string().regex(ACME_CHALLENGE_VALUE_PATTERN, "43 characters of base64url (RFC 8555 section 8.4)"),
  })
  .strict();
export type AcmeChallengeDto = z.infer<typeof acmeChallengeSchema>;

/**
 * The answer: the value is set (`present`) or gone (`cleanup`). `changed` says whether this call wrote: a record
 * created or deleted, or false when the name already held the value, or held no such record.
 */
export const acmeChallengeAnswerSchema = z.object({ done: z.literal(true), changed: z.boolean() }).strict();
export type AcmeChallengeAnswerDto = z.infer<typeof acmeChallengeAnswerSchema>;

/** `acme/<name>`, the target a call for `fqdn` signs. */
export function acmeChallengeTarget(fqdn: string): string {
  const name = acmeChallengeNameOf(fqdn);
  if (name === null) throw new BridgeWireError("invalid_target", null, "a challenge record's name is _acme-challenge.<DNS name>");
  return `${ACME_CHALLENGE_TARGET_PREFIX}${name}`;
}
