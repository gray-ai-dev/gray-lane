package main

// The client's own headers (owner, 2026-11-18): Gray sets no client-identity header on a customer's request, and the
// client's own go through unchanged. The entry passes the client headers one closed rule names to the relay's
// container and registers the same set with the rid as `headers` (S32); egress checks the registration against the
// rule and starts the vendor's header set from those values (stackVendorHeader), so a relay that forwards them as it
// got them changes nothing, and one that sends none still has the vendor get the client's.
//
// The rule is @gray/lane-wire's src/stack-client-headers.ts, written here a second time; stack_client_headers_test.go
// holds the two lists to each other and both suites to testdata/stack-client-headers-vectors.json. A header passes when
// its lower-case name is one of stackClientHeaderNames, or starts with one of its protocol's prefixes (and is longer)
// and is not one of stackClientHeaderRefused.

// stackClientHeaderNames pass on every protocol: the client's user-agent and accept, and its app, session and request
// ids (Claude Code's `x-app`, `x-claude-code-session-id`, `x-client-request-id`; Codex CLI's `originator`, `version`,
// `session_id`, `session-id`, `conversation_id`, `thread-id`; the other agents' session headers the lane's request log
// reads: OpenCode's, goose's, MiniMax Code's and a subagent's parent).
var stackClientHeaderNames = setOf("user-agent", "accept", "x-app", "x-client-request-id", "x-claude-code-session-id",
	"originator", "version", "session_id", "session-id", "conversation_id", "thread-id",
	"x-session-id", "x-opencode-session-id", "agent-session-id", "x-mavis-session-id", "x-parent-session-id")

// stackClientHeaderPrefixes pass by protocol: the vendor's own headers (its behaviour headers among them), the SDKs'
// Stainless telemetry and Codex CLI's own (`x-codex-*`: its turn state and feature switches; Gray does not change the
// client's request).
var stackClientHeaderPrefixes = map[string][]string{
	protocolAnthropicMessages: {"anthropic-", "x-stainless-", "x-codex-"},
	protocolOpenAIChat:        {"openai-", "x-stainless-", "x-codex-"},
	protocolOpenAIResponses:   {"openai-", "x-stainless-", "x-codex-"},
}

// stackClientHeaderRefused never pass: they choose the organization or project an OpenAI key bills as (P6).
var stackClientHeaderRefused = setOf("openai-organization", "openai-project")

// stackClientHeadersMaxBytes bounds a registration's headers, their names and values in bytes, as the entry does.
const stackClientHeadersMaxBytes = 16 << 10

// stackClientHeaderPassed reports whether a client header of this name passes on protocol.
func stackClientHeaderPassed(protocol, name string) bool {
	if stackClientHeaderRefused[name] || !isLowerHeaderName(name) {
		return false
	}
	if stackClientHeaderNames[name] {
		return true
	}
	for _, prefix := range stackClientHeaderPrefixes[protocol] {
		if len(name) > len(prefix) && name[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// isLowerHeaderName is an RFC 9110 field name (token characters) without an upper-case letter.
func isLowerHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' ||
			c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		default:
			return false
		}
	}
	return true
}

// validClientHeaders is a registration's `headers`: every name passes the rule on protocol, every value is a field
// value without a control character but tab, and all of them fit stackClientHeadersMaxBytes.
func validClientHeaders(protocol string, headers map[string]string) bool {
	size := 0
	for name, value := range headers {
		if !stackClientHeaderPassed(protocol, name) {
			return false
		}
		for i := 0; i < len(value); i++ {
			if (value[i] < 0x20 && value[i] != '\t') || value[i] == 0x7f {
				return false
			}
		}
		size += len(name) + len(value)
	}
	return size <= stackClientHeadersMaxBytes
}
