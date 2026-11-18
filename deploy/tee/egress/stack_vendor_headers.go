package main

import (
	"net/http"
	"slices"
	"strings"
)

// The vendor's header set of a relay call (S32a, owner 2026-11-18). Gray sets no client-identity header on a
// customer's request: the vendor gets the client's own headers, as the entry registered them with the rid
// (stack_client_headers.go), and the relay's own values in place of any it sends (stackRelayHeader, stack_changes.go),
// each difference recorded in the receipt. Before 2026-11-18 an account could register a client identity (a user-agent,
// x-stainless-*, generated session and request ids) that egress wrote on its calls in place of the client's; that is
// retired, and egress keeps no identity, list or id generator for it.
//
// Gray's own set, the base every call starts from:
//
//   - the credential headers, the relay's (S15: their values are the sealed credential's);
//   - content-type application/json (S18 proved the body JSON), and accept: the client's, else `*/*` (@gray/protocol
//     DEFAULT_ACCEPT, what Gray's own requests send when the client names none); a relay call then takes the relay's
//     own content type and accept-encoding (stackRelayFraming, stack_coding.go: egress decodes the answer it
//     digests), an account test asks for identity;
//   - the behaviour headers (S32): the client's anthropic-version (else 2023-06-01), the client's anthropic-beta
//     tokens plus the OAuth beta on an Anthropic OAuth call, the client's openai-beta; each list in the client's
//     order, without repeats, joined with ", ";
//   - on /chatgpt the credential form's `originator: codex_cli_rs` (relay-connector CHATGPT_CODEX_ORIGINATOR) unless
//     the client sent one;
//   - every other client header the entry registered, its value as the client sent it.
//
// An account test has no client: its set is the credential form's alone, no user-agent, no x-stainless-*, no
// session or request id (what Gray's own lane sends for that credential form).

const (
	stackCodexOriginator    = "codex_cli_rs"
	stackDefaultAccept      = "*/*"
	stackCredentialValueMax = 16 << 10
)

// stackCredentialHeaders are each route's credential form names (S15), the only relay values forwarded as Gray's own.
var stackCredentialHeaders = withCompat(map[string][]string{
	"/anthropic": {"authorization", "x-api-key"},
	"/openai":    {"authorization"},
	"/chatgpt":   {"authorization", "chatgpt-account-id"},
}, true, func(openAICompatibleVendor) []string { return []string{"authorization"} })

// stackCallCredentialType is the credential type a relay call's header form names (relay-connector authHeaders:
// x-api-key is an Anthropic API key, authorization on /anthropic its OAuth access token; /openai takes API keys
// and /chatgpt OAuth access tokens).
func stackCallCredentialType(routeName string, h http.Header) string {
	switch {
	case routeName == "/anthropic" && len(h.Values("X-Api-Key")) > 0:
		return "api_key"
	case routeName == "/openai":
		return "api_key"
	}
	if _, compat := compatVendorOfRoute(routeName); compat {
		return "api_key"
	}
	return "oauth_access_token"
}

// stackCredentialTypes are the credential types each vendor takes (relay-connector credentialClass).
var stackCredentialTypes = withCompat(map[string][]string{
	"anthropic":     {"api_key", "oauth_access_token"},
	"openai":        {"api_key"},
	"chatgpt_codex": {"oauth_access_token"},
}, false, func(openAICompatibleVendor) []string { return []string{"api_key"} })

// orderedTokens is a comma-separated list's words in order, without repeats, then the extras not yet in it.
func orderedTokens(list string, extras []string) []string {
	var tokens []string
	for _, part := range strings.Split(list, ",") {
		if token := strings.Trim(part, " \t"); token != "" && !slices.Contains(tokens, token) {
			tokens = append(tokens, token)
		}
	}
	for _, token := range extras {
		if !slices.Contains(tokens, token) {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

// stackVendorHeader is Gray's header set for a call (see the top of this file). credential holds the call's
// credential headers (a relay call's own, an account test's given form); client the registration's headers, the
// client's own by lower-case name (empty for an account test).
func stackVendorHeader(rt route, credential http.Header, client map[string]string, oauth bool) http.Header {
	out := http.Header{}
	for _, name := range stackCredentialHeaders[rt.name] {
		if values := credential.Values(name); len(values) > 0 {
			out[http.CanonicalHeaderKey(name)] = slices.Clone(values)
		}
	}
	// The client's own headers; the rule passes no credential or framing name, and the behaviour headers and accept
	// are written below.
	for name, value := range client {
		if !stackVendorWritten[name] && !stackFramingHeaders[name] && !slices.Contains(stackCredentialHeaders[rt.name], name) {
			out.Set(name, value)
		}
	}
	out.Set("Content-Type", "application/json")
	accept := stackDefaultAccept
	if sent, ok := client["accept"]; ok {
		accept = sent
	}
	out.Set("Accept", accept)
	if rt.name == "/anthropic" {
		version := stackAnthropicVersion
		if sent, ok := client["anthropic-version"]; ok {
			version = sent
		}
		out.Set("Anthropic-Version", version)
		var extras []string
		if oauth {
			extras = []string{stackOAuthBeta}
		}
		if tokens := orderedTokens(client["anthropic-beta"], extras); len(tokens) > 0 {
			out.Set("Anthropic-Beta", strings.Join(tokens, ", "))
		}
	} else if tokens := orderedTokens(client["openai-beta"], nil); len(tokens) > 0 {
		out.Set("Openai-Beta", strings.Join(tokens, ", "))
	}
	if _, sent := client["originator"]; rt.name == "/chatgpt" && !sent {
		out.Set("Originator", stackCodexOriginator)
	}
	return out
}

// stackVendorWritten are the client's headers stackVendorHeader writes in its own way: accept (with Gray's default)
// and the behaviour headers (the version's default, the beta lists in one spelling).
var stackVendorWritten = setOf("accept", "anthropic-version", "anthropic-beta", "openai-beta")
