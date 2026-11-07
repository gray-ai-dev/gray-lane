/**
 * The longest credential lease the lane accepts (D35, implementing D21).
 *
 * A relay seals a credential bundle whose `expires_at` is its lease over the accounts: at that second
 * the TEE refuses every account of the relay, and the relay must seal a fresh bundle. One day is the
 * single source of the bound in three places:
 *
 * - `@gray/relay-connector`'s `checkBundleFreshness` refuses a bundle whose
 *   `expires_at - issued_at` exceeds it (the TEE, and any reader of the same rule);
 * - `@gray/relay-kit`'s daemon config uses it as the upper bound of `lease_lifetime`;
 * - `deploy/tee/release/sign-release-list.mjs` requires an OS image's `retire_after` to be at least
 *   this long after the list that first sets it, so a relay that still runs that image can attest it
 *   and send its whole-relay revoke before the image leaves the signed list (D21).
 *
 * It is a `bigint` because every Unix-seconds value on this wire is one (`@gray/json`'s u64 rule).
 */
export const MAX_CREDENTIAL_LEASE_SECONDS = 86_400n;
