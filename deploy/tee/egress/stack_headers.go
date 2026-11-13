package main

import (
	"net/http"
	"slices"
	"strings"
)

// S32: a relay call's headers are part of the request check. Behaviour headers (versions and betas change
// output limits, context, tools and price) must carry the client's values, registered with the rid, plus
// only what the credential form needs; every other header passes only by name from its route's list, and a
// name off the list is refused (stack_header_refused), since an unknown header could carry a second
// credential or switch a vendor feature on.
//
// The lists come from what reaches a vendor today:
//   - the lane's own requests: laneHeaders (workers/gateway/src/lane/hooks.ts: content-type, the
//     protocol's version and beta headers) over relay-connector's authHeaders (packages/relay-connector/
//     src/auth.ts: x-api-key or authorization, anthropic-version, the OAuth beta, chatgpt-account-id,
//     originator), and the Accept every Gray request carries (@gray/protocol withDefaultAccept);
//   - what the stack entry forwards to the container (gateway/src/lane/stack.ts: content-type, accept,
//     user-agent and the behaviour headers) and what the three migrated relays add (D2 round 2:
//     the credential form, originator on /chatgpt, Go's default user-agent);
//   - the client-identity headers a subscription account is sent with, which relays set from their own
//     client profiles: the conformance tool's fake entry (x-stainless-lang, x-app on Messages; originator
//     and session_id on Codex), sub2api's Claude Code profile (pkg/claude/constants.go: user-agent, eight
//     x-stainless-*, x-app, anthropic-dangerous-direct-browser-access) and Codex headers
//     (openai_gateway_forward.go: originator, version, session_id, conversation_id), CLIProxyAPI's Claude
//     and Codex request builders (x-claude-code-session-id, x-client-request-id, session_id, session-id,
//     version, thread-id), and Codex CLI's own (relay-connector auth.ts notes session-id and thread-id).
//     Their values are the relay's. Headers those builders also set that switch behaviour or state
//     (x-codex-beta-features, x-openai-internal-codex-responses-lite, x-codex-turn-state, …) are not listed.

// stackOAuthBeta is the beta an Anthropic OAuth credential is sent with (relay-connector ANTHROPIC_OAUTH_BETA).
const stackOAuthBeta = "oauth-2025-04-20"

// stackAnthropicVersion is the version the Anthropic credential forms carry when the client named none
// (relay-connector ANTHROPIC_VERSION, the lane's laneHeaders default).
const stackAnthropicVersion = "2023-06-01"

// stackBehaviourHeaders are the client headers a registration carries per vendor (S32), the protocol's own
// version and beta headers (@gray/protocol nativeHeaders). The entry registers Chat's openai-beta whatever the
// route's vendor, so an OpenAI-compatible vendor takes it too: the client's value passes, as on /openai.
var stackBehaviourHeaders = withCompat(map[string][]string{
	"anthropic":     {"anthropic-version", "anthropic-beta"},
	"openai":        {"openai-beta"},
	"chatgpt_codex": {"openai-beta"},
}, false, func(openAICompatibleVendor) []string { return []string{"openai-beta"} })

// stackPassHeaders are the names of Gray's own header set by route (S32's lists): the credential form's, the
// body's type, Accept, the identity headers above and Accept-Encoding. They no longer bound what a relay call may
// carry (stackHeaderRefusal); the tests hold every name egress writes to one role on them.
var stackPassHeaders = withCompat(map[string]map[string]bool{
	"/anthropic": setOf("x-api-key", "authorization", "content-type", "accept", "accept-encoding", "user-agent",
		"x-app", "anthropic-dangerous-direct-browser-access", "x-claude-code-session-id", "x-client-request-id"),
	"/openai": setOf("authorization", "content-type", "accept", "accept-encoding", "user-agent"),
	"/chatgpt": setOf("authorization", "chatgpt-account-id", "content-type", "accept", "accept-encoding", "user-agent",
		"originator", "version", "session_id", "session-id", "conversation_id", "thread-id", "x-client-request-id"),
}, true, func(openAICompatibleVendor) map[string]bool {
	return setOf("authorization", "content-type", "accept", "accept-encoding", "user-agent")
})

// stackPassPrefixes are name prefixes that are client identity the same way: the Stainless SDK telemetry of Claude Code.
var stackPassPrefixes = map[string][]string{
	"/anthropic": {"x-stainless-"},
}

// stackRefusedHeaderMax bounds the header name a refusal names, as egress bounds a refusal path (S32: 256
// UTF-16 units; a header name is ASCII).
const stackRefusedHeaderMax = 256

func setOf(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// stackHeaderRefusal is the header of a relay call egress refuses, or "". A relay's headers reach the vendor as it
// sent them, each change recorded (stack_changes.go `stackRelayHeader`), whatever the customer chose (owner,
// 2026-11-12: a customer who asks for relays that change nothing means the request's content, not the client's
// headers). Refused are the headers that add a credential or switch the account (stackAccountRefusal), and, for a
// customer who chose that (kept: the rid has no `relay_changes`), a change to a behaviour header the customer sent.
func stackHeaderRefusal(rt route, req *stackRequest, relay http.Header, kept bool) string {
	if name := stackAccountRefusal(rt, relay); name != "" {
		return name
	}
	if kept {
		return stackKeptBehaviourRefusal(req, relay)
	}
	return ""
}

// stackKeptBehaviourRefusal names a behaviour header (`anthropic-version`, a beta list) the customer sent and the
// relay's call would change: another version, or a beta list without one of the customer's values. They are the
// customer's own request parameters, as the body is. A header the relay does not send keeps the customer's value
// (Gray's set carries it), and a relay may add values to a list.
func stackKeptBehaviourRefusal(req *stackRequest, relay http.Header) string {
	sent := map[string]string{}
	present := map[string]bool{}
	for name, values := range relay {
		lower := strings.ToLower(name)
		sent[lower] = joinValues(sent[lower], values)
		present[lower] = true
	}
	for _, name := range stackBehaviourHeaders[req.vendor] {
		client, asked := req.headers[name]
		if !asked || !present[name] {
			continue
		}
		if name == "anthropic-version" {
			if sent[name] != client {
				return name
			}
			continue
		}
		got := listValues(sent[name])
		for value := range listValues(client) {
			if !got[value] {
				return name
			}
		}
	}
	return ""
}

func joinValues(joined string, values []string) string {
	for _, value := range values {
		if joined != "" {
			joined += ", "
		}
		joined += value
	}
	return joined
}

func hasPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// sameValues compares two comma-separated lists by their values, the way a vendor reads a beta list: the
// forwarded list must hold every value of the client's and nothing else but extras (the credential form's
// beta, an identity's). Order, spacing and repeats do not count: the three migrated relays rejoin the list
// differently, and egress writes the list itself in one spelling (S32a).
func sameValues(forwarded, client string, extras []string) bool {
	want := listValues(client)
	got := listValues(forwarded)
	for value := range want {
		if !got[value] {
			return false
		}
	}
	for value := range got {
		if !want[value] && !slices.Contains(extras, value) {
			return false
		}
	}
	return true
}

func listValues(list string) map[string]bool {
	values := map[string]bool{}
	for _, part := range strings.Split(list, ",") {
		if value := strings.Trim(part, " \t"); value != "" {
			values[value] = true
		}
	}
	return values
}

// refusedHeaderName is the name a header refusal reports, cut to stackRefusedHeaderMax bytes.
func refusedHeaderName(name string) string {
	if len(name) > stackRefusedHeaderMax {
		return name[:stackRefusedHeaderMax]
	}
	return name
}
