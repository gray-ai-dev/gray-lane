package main

import (
	"net/http"
	"slices"
	"strings"
)

// S32: a relay call's headers are part of the request check. Since 2026-11-12 (docs/relay-request-changes.md) a
// relay's headers reach the vendor as it sent them, each difference from Gray's own set recorded in the receipt
// (stack_changes.go `stackRelayHeader`); refused are only the headers that add a credential or switch the account
// (P6), and, for a customer who chose relays that change nothing, a change to a behaviour header the customer sent.
// Gray's own set (stack_vendor_headers.go) starts from the client's own headers, which the entry registers with the
// rid under one closed rule (stack_client_headers.go, owner 2026-11-18); S32's per-route name lists and S32a's
// account identities, which once bounded and replaced those names, are retired.

// stackOAuthBeta is the beta an Anthropic OAuth credential is sent with (relay-connector ANTHROPIC_OAUTH_BETA).
const stackOAuthBeta = "oauth-2025-04-20"

// stackAnthropicVersion is the version the Anthropic credential forms carry when the client named none
// (relay-connector ANTHROPIC_VERSION, the lane's laneHeaders default).
const stackAnthropicVersion = "2023-06-01"

// stackBehaviourHeaders are the client's behaviour headers per vendor (S32), the protocol's own version and beta
// headers (@gray/protocol nativeHeaders), which Gray's set writes in one spelling and a customer who chose relays
// that change nothing keeps. An OpenAI-compatible vendor takes Chat's openai-beta, as /openai does.
var stackBehaviourHeaders = withCompat(map[string][]string{
	"anthropic":     {"anthropic-version", "anthropic-beta"},
	"openai":        {"openai-beta"},
	"chatgpt_codex": {"openai-beta"},
}, false, func(openAICompatibleVendor) []string { return []string{"openai-beta"} })

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
