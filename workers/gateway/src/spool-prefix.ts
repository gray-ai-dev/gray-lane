/**
 * Where the gateway keeps request content for the length of a request in the content bucket. Its own module,
 * with nothing imported, so the production tooling can check the bucket's lifecycle rule against it
 * (workers/production/src/provision.ts `spoolRuleProblem`): the `spool/` rule (a day) deletes what a
 * request did not.
 */

/** A tier C request body, sealed to a key only its request holds (spool.ts; docs/cloudflare-native/content.md 3.8). */
export const SPOOL_PREFIX = "spool/v2/";
