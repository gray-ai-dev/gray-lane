package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
)

// Since 2026-11-02 (docs/relay-request-changes.md) this is the header set of a rid without `relay_changes`, a
// customer who chose relays that change nothing, and the default of every other: under `relay_changes` the relay's
// own values replace these, recorded in the receipt (stackRelayHeader, stack_changes.go), and the registered
// identity fills only the names the relay does not send.
//
// S32a (2026-10-29, the owner's trust-model question): the relay's container chooses no value that reaches the
// vendor except the account's credential, whose value its SHA-256 already fixes (S15). S32 let it choose the
// values of the client-identity headers (user-agent, x-stainless-*, originator, session_id, …) and the spelling
// of the beta lists (order, spacing, repeats), so a container could encode request content into them. Now egress
// writes the vendor's header set itself:
//
//   - the credential headers, the relay's (S15: their values are the sealed credential's);
//   - content-type application/json (S18 proved the body JSON), accept-encoding identity (S16), and accept `*/*`
//     (@gray/protocol DEFAULT_ACCEPT, what Gray's own requests send when the client names none) unless the
//     account's identity registers one;
//   - the behaviour headers from the registration (S32): the client's anthropic-version (else 2023-06-01), the
//     client's anthropic-beta tokens plus the OAuth beta on an Anthropic OAuth call plus the identity's betas,
//     the client's openai-beta; each list in the client's order, without repeats, joined with ", ";
//   - on /chatgpt the credential form's `originator: codex_cli_rs` (relay-connector CHATGPT_CODEX_ORIGINATOR)
//     unless the identity registers one;
//   - the account's registered identity (a closed list of names per route): its static headers as registered, and its generated headers with
//     egress's own values: a request id per call (random), a session id per conversation (HMAC of the
//     conversation token the entry registers with the rid under a per-boot egress key; random per rid without
//     one), both as RFC 9562 version-4 UUIDs, the form the vendors' clients send.
//
// The relay's own headers are only checked: a name off the route's lists or a behaviour header other than the
// client's is stack_header_refused as before (S32). Every identity, generated or framing value the relay sends is
// ignored (owner, 2026-10-29): the vendor gets the account's registered static values in its place, egress's own
// ids, and nothing of an identity header the account does not register. So the relay's program may send anything
// there (Go's default user-agent included); what reaches the vendor is what the relay registered per account.
// stack_identity_mismatch, the refusal of a value other than the registered one, is retired: reserved, never
// written. An account with no registered identity sends what Gray's own lane sends for its credential form
// (relay-connector authHeaders over the lane's headers): no user-agent, no x-stainless-*, no session or request
// id, which is the path Gray's own relays serve today.

// The bounds of a registered identity.
const (
	stackIdentityHeadersMax = 16
	stackIdentityValueMax   = 512
	stackIdentityBetasMax   = 8
	stackIdentityBetaMax    = 64
	stackCodexOriginator    = "codex_cli_rs"
	stackDefaultAccept      = "*/*"
	stackSessionDomain      = "gray-stack-session/v1"
	stackCredentialValueMax = 16 << 10
)

// stackIdentityStatic are the identity headers a value is registered for, by route, a closed list (S34): the
// Stainless names are those of Claude Code's SDK (sub2api's Claude Code profile, pkg/claude/constants.go);
// another x-stainless-* name still passes S32's check and is dropped. stackRequestIDHeaders and
// stackSessionIDHeaders are the generated ones. Every name is on S32's pass lists (stack_headers.go);
// stack_identity_test.go holds the lists to each other and stack_health_lists_test.go to @gray/lane-wire's
// STACK_IDENTITY_HEADERS and STACK_IDENTITY_GENERATED.
var (
	stackIdentityStatic = withCompat(map[string]map[string]bool{
		"/anthropic": setOf("user-agent", "accept", "x-app", "anthropic-dangerous-direct-browser-access", "x-stainless-lang",
			"x-stainless-package-version", "x-stainless-os", "x-stainless-arch", "x-stainless-runtime", "x-stainless-runtime-version",
			"x-stainless-retry-count", "x-stainless-timeout"),
		"/openai":  setOf("user-agent", "accept"),
		"/chatgpt": setOf("user-agent", "accept", "originator", "version"),
	}, true, func(openAICompatibleVendor) map[string]bool { return setOf("user-agent", "accept") })
	stackRequestIDHeaders = map[string]map[string]bool{
		"/anthropic": setOf("x-client-request-id"),
		"/chatgpt":   setOf("x-client-request-id"),
	}
	stackSessionIDHeaders = map[string]map[string]bool{
		"/anthropic": setOf("x-claude-code-session-id"),
		"/chatgpt":   setOf("session_id", "session-id", "conversation_id", "thread-id"),
	}
	// stackCredentialHeaders are each route's credential form names (S15), the only relay values forwarded.
	stackCredentialHeaders = withCompat(map[string][]string{
		"/anthropic": {"authorization", "x-api-key"},
		"/openai":    {"authorization"},
		"/chatgpt":   {"authorization", "chatgpt-account-id"},
	}, true, func(openAICompatibleVendor) []string { return []string{"authorization"} })
)

// stackIdentity is an account's registered client identity (S32a): static header values by lower-case name, the
// extra anthropic-beta tokens of its client, and the generated headers its client sends.
type stackIdentity struct {
	headers   map[string]string
	betas     []string
	generated map[string]bool
}

// wireIdentity is an account row's `identity` (and an account test's), every member required.
type wireIdentity struct {
	Headers   *map[string]string `json:"headers"`
	Betas     *[]string          `json:"betas"`
	Generated *[]string          `json:"generated"`
}

func staticIdentityName(routeName, name string) bool { return stackIdentityStatic[routeName][name] }

func generatedIdentityName(routeName, name string) bool {
	return stackRequestIDHeaders[routeName][name] || stackSessionIDHeaders[routeName][name]
}

// isTokenWord is lower-case letters, digits and `-`.
func isTokenWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// validIdentityValue is a registered value: 1-512 bytes of printable ASCII, no space at either end.
func validIdentityValue(value string) bool {
	if value == "" || len(value) > stackIdentityValueMax || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// validBetaToken is S44's beta word, `^[a-z0-9-]{1,64}$`.
func validBetaToken(token string) bool {
	return token != "" && len(token) <= stackIdentityBetaMax && isTokenWord(token)
}

// parseIdentity checks an identity for an account of vendor; nil is no identity.
func parseIdentity(vendor string, w *wireIdentity) (*stackIdentity, bool) {
	if w == nil {
		return nil, true
	}
	routeName := stackVendors[vendor]
	if w.Headers == nil || w.Betas == nil || w.Generated == nil || len(*w.Headers) > stackIdentityHeadersMax ||
		len(*w.Betas) > stackIdentityBetasMax || (vendor != "anthropic" && len(*w.Betas) > 0) {
		return nil, false
	}
	identity := &stackIdentity{headers: map[string]string{}, generated: map[string]bool{}}
	for name, value := range *w.Headers {
		if !staticIdentityName(routeName, name) || !validIdentityValue(value) {
			return nil, false
		}
		identity.headers[name] = value
	}
	for _, token := range *w.Betas {
		if !validBetaToken(token) || slices.Contains(identity.betas, token) {
			return nil, false
		}
		identity.betas = append(identity.betas, token)
	}
	for _, name := range *w.Generated {
		if !generatedIdentityName(routeName, name) || identity.generated[name] {
			return nil, false
		}
		identity.generated[name] = true
	}
	return identity, true
}

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

// stackBetaExtras are the anthropic-beta tokens a call may add to the client's: the OAuth beta on an OAuth call,
// and the identity's.
func stackBetaExtras(oauth bool, identity *stackIdentity) []string {
	var extras []string
	if oauth {
		extras = append(extras, stackOAuthBeta)
	}
	if identity != nil {
		extras = append(extras, identity.betas...)
	}
	return extras
}

// stackVendorHeader is S32a's header set egress sends the vendor (see the top of this file). credential holds the
// call's credential headers (a relay call's own, an account test's given form); client the registration's
// behaviour headers; sessionID the call's session id.
func stackVendorHeader(rt route, credential http.Header, client map[string]string, oauth bool, identity *stackIdentity, sessionID string) http.Header {
	out := http.Header{}
	for _, name := range stackCredentialHeaders[rt.name] {
		if values := credential.Values(name); len(values) > 0 {
			out[http.CanonicalHeaderKey(name)] = slices.Clone(values)
		}
	}
	out.Set("Content-Type", "application/json")
	out.Set("Accept", stackDefaultAccept)
	out.Set("Accept-Encoding", "identity")
	if rt.name == "/anthropic" {
		version := stackAnthropicVersion
		if sent, ok := client["anthropic-version"]; ok {
			version = sent
		}
		out.Set("Anthropic-Version", version)
		if tokens := orderedTokens(client["anthropic-beta"], stackBetaExtras(oauth, identity)); len(tokens) > 0 {
			out.Set("Anthropic-Beta", strings.Join(tokens, ", "))
		}
	} else if tokens := orderedTokens(client["openai-beta"], nil); len(tokens) > 0 {
		out.Set("Openai-Beta", strings.Join(tokens, ", "))
	}
	if rt.name == "/chatgpt" {
		out.Set("Originator", stackCodexOriginator)
	}
	if identity == nil {
		return out
	}
	for name, value := range identity.headers {
		out.Set(name, value)
	}
	for name := range identity.generated {
		if stackRequestIDHeaders[rt.name][name] {
			out.Set(name, randomUUID())
		} else {
			out.Set(name, sessionID)
		}
	}
	return out
}

// uuidText is 16 bytes as an RFC 9562 version-4 UUID: the version and variant bits set, lower-case 8-4-4-4-12.
func uuidText(b [16]byte) string {
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	text := hex.EncodeToString(b[:])
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:32]
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return uuidText(b)
}

// sessionID is a rid's session id: HMAC-SHA256(key, "gray-stack-session/v1" 0x00 conversation) as a UUID, so one
// conversation keeps one id for the boot and the id says nothing about the token; a random one without a token.
func sessionID(key []byte, conversation string) string {
	if conversation == "" {
		return randomUUID()
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stackSessionDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(conversation))
	var b [16]byte
	copy(b[:], mac.Sum(nil))
	return uuidText(b)
}

// newSessionKey is the per-boot key of session ids: 32 random bytes held only in this process.
func newSessionKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}
