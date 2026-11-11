import { sha256BareHex } from "@gray/attest";

/**
 * The sign-in proxy's account names (docs/design/relay-sign-in-in-vm.md §3.1, D3): the handle map egress takes
 * (`PUT /v1/stack/ops/sign-in-proxy`), from which egress serves each subscription account's `login.proxy_url`
 * (`http://<handle>@10.231.11.2:8080`) in `account-state`, before its first sign-in too. The handle is a Gray-made name for the account (account ids may hold `:`, which a
 * Basic proxy username cannot), stable across boots: the first 32 hex of SHA-256 over the relay id and the account id.
 * It is no secret and the URL carries no password (design v3: the listener is the container's alone).
 */

/** Egress's relay listener (`@gray/lane-compose` layout.ts `EGRESS_ADDRESS`, port 8080), where `CONNECT` is answered. */
export const SIGN_IN_PROXY_ADDRESS = "10.231.11.2:8080";
const HANDLE_DOMAIN = "gray-sign-in-handle/v1";

/** The vendors whose accounts sign in through the proxy (design §3.5). */
export const SIGN_IN_PROXY_VENDORS: ReadonlySet<string> = new Set(["chatgpt_codex", "anthropic", "gemini_code_assist", "antigravity"]);

/** An account's handle: 32 lower hex. */
export function signInHandle(relayId: string, accountId: string): string {
  return sha256BareHex(new TextEncoder().encode(`${HANDLE_DOMAIN}\n${relayId}\n${accountId}`)).slice(0, 32);
}


/** Whether an account of `vendor` with a credential of `type` signs in (a subscription account, not an API key). */
export function signsIn(vendor: string, type: string): boolean {
  return SIGN_IN_PROXY_VENDORS.has(vendor) && type !== "api_key";
}
