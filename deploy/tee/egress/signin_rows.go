package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

// The vendor sign-in rows (docs/design/relay-sign-in-in-vm.md §3.3, §4.1): per account vendor, the exact calls a
// sign-in or a refresh may make through egress (the CONNECT proxy), each a flow, a method, a host and a path; the
// token endpoints among them, whose answers become the account's tokens; the hosts an authorize URL handed to a person
// may name; and the device-code endpoint whose answer egress reads to make the person's prompt. A vendor added later
// is a row here, reviewed as code: no Go changes.
//
// Version 2 (2026-11-13) made the paths an allowlist. Version 1 opened hosts by path prefix (auth.openai.com every
// path) less a list of refused words, so any subscription account's tunnel could reach a vendor step that mails an
// address the call names (a "send me a code" step), and that address could carry data out of the VM. Now:
//
//   - every account: the row's `calls`, each by its exact method and path (no other spelling, no other method);
//   - a `password` account also: its own sign-in steps, `password_steps`, by host and path prefix less the refused
//     words, as version 1 had them. Gray has no record of the steps a relay's password sign-in calls (none of the
//     reference programs has one, and no official client signs in by password), so they are not yet exact; what such
//     a step may send is bounded instead by the address rule (stack_login.go loginAddressCode).
//
// The calls are the ones the reference relay programs make through the proxy (read in their pinned source,
// 2026-11-13): ChatGPT's device code, its poll and the token exchange (CLIProxyAPI ad8bdd3 sdk/auth/codex_device.go,
// internal/auth/codex/openai_auth.go), the second token endpoint of CLIProxyAPI's SIWC tokens (siwc_auth.go, refresh
// only, D7), sub2api 0a2a29b's and new-api e835b1b's token exchange and refresh (internal/pkg/openai/oauth.go,
// service/codex_oauth.go); Claude's token exchange and refresh (CLIProxyAPI internal/auth/claude/anthropic_auth.go,
// sub2api internal/pkg/oauth/oauth.go). An authorize page and a code or callback page are opened by the person's own
// browser, never through the proxy, so no row lists them.

//go:embed vendor-sign-in-v2.json
var vendorSignInJSON []byte

const signInRowsVersion = 2

// The flows of a row's calls.
const (
	signInFlowToken      = "token"
	signInFlowDeviceCode = "device_code"
	signInFlowDevicePoll = "device_poll"
)

// signInCallRule is one call a sign-in or a refresh may make: exactly this method, host and (raw) path.
type signInCallRule struct {
	Flow   string `json:"flow"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

type signInDeviceCode struct {
	// Host, Path and TokenPath are the row's device_code and device_poll calls (set by parseSignInRows).
	Host string `json:"-"`
	Path string `json:"-"`
	// TokenPath is the device flow's poll for the authorization (OpenAI's own step, RFC 8628 §3.4 at a vendor that
	// answers RFC 8628 at the token endpoint has none): a call there outside an open session is refused.
	TokenPath string `json:"-"`
	// UserCodeFields: the answer's members that may carry the code, first present wins (OpenAI answers `user_code`
	// or `usercode`; RFC 8628 §3.2 `user_code`).
	UserCodeFields []string `json:"user_code_fields"`
	// VerificationURI is the address the person opens when the vendor's answer names none it may be trusted with
	// (OpenAI's is the Codex CLI's constant). Empty: the answer's RFC 8628 `verification_uri`, on an authorize host.
	VerificationURI string `json:"verification_uri"`
	// ExpiresInSeconds when the answer carries no RFC 8628 `expires_in`.
	ExpiresInSeconds int64 `json:"expires_in_seconds"`
}

type signInEndpoint struct {
	Host string
	Path string
}

type signInRow struct {
	// Calls are the exact calls every subscription account of the vendor may make (flow token, device_code,
	// device_poll).
	Calls []signInCallRule `json:"calls"`
	// PasswordSteps maps each host a `password` account's own sign-in steps may call to its open path prefixes (null:
	// every path), less the refused words (loginPathAllowed). Only a password account's tunnels reach these.
	PasswordSteps map[string][]string `json:"password_steps"`
	// AccountIDClaim: a token answer's access token must carry the ChatGPT account id claim serving names.
	AccountIDClaim bool              `json:"account_id_claim"`
	AuthorizeHosts []string          `json:"authorize_hosts"`
	DeviceCode     *signInDeviceCode `json:"device_code"`

	// TokenEndpoints: the calls of flow token, where the vendor's sign-in and refresh end (set by parseSignInRows).
	TokenEndpoints []signInEndpoint `json:"-"`
}

type signInRowsFile struct {
	Version int                  `json:"version"`
	Vendors map[string]signInRow `json:"vendors"`
}

// signInRows is the parsed table; loginTokenEndpoints (stack_login.go) is a view of it.
var signInRows = mustSignInRows(vendorSignInJSON)

func mustSignInRows(data []byte) map[string]signInRow {
	rows, err := parseSignInRows(data)
	if err != nil {
		panic("vendor-sign-in-v2.json: " + err.Error())
	}
	return rows
}

func parseSignInRows(data []byte) (map[string]signInRow, error) {
	var file signInRowsFile
	if !decodeControl(data, &file) {
		return nil, fmt.Errorf("not a strict rows document")
	}
	if file.Version != signInRowsVersion || len(file.Vendors) == 0 {
		return nil, fmt.Errorf("version or vendors")
	}
	for vendor, row := range file.Vendors {
		if err := checkSignInRow(&row); err != nil {
			return nil, fmt.Errorf("%s: %w", vendor, err)
		}
		file.Vendors[vendor] = row
	}
	return file.Vendors, nil
}

// checkSignInRow checks a row and sets what it derives from its calls: the token endpoints and the device code's
// endpoints.
func checkSignInRow(row *signInRow) error {
	seen := map[signInEndpoint]bool{}
	var device, poll []signInCallRule
	for _, call := range row.Calls {
		// Every flow is a POST (RFC 6749 §3.2, RFC 8628 §3.1, OpenAI's device steps). The path is the one spelling the
		// programs send: no query, no percent-encoding, no dot segment, no trailing or repeated slash.
		at := signInEndpoint{Host: call.Host, Path: call.Path}
		if call.Method != http.MethodPost || !validSignInHost(call.Host) || !strings.HasPrefix(call.Path, "/") || !validRawPath(call.Path) ||
			strings.ContainsAny(call.Path, "%?#;") || path.Clean(call.Path) != call.Path || seen[at] {
			return fmt.Errorf("call %+v", call)
		}
		seen[at] = true
		switch call.Flow {
		case signInFlowToken:
			row.TokenEndpoints = append(row.TokenEndpoints, at)
		case signInFlowDeviceCode:
			device = append(device, call)
		case signInFlowDevicePoll:
			poll = append(poll, call)
		default:
			return fmt.Errorf("flow %q", call.Flow)
		}
	}
	if len(row.TokenEndpoints) == 0 {
		return fmt.Errorf("no token endpoint")
	}
	for host, prefixes := range row.PasswordSteps {
		if !validSignInHost(host) {
			return fmt.Errorf("password step host %q", host)
		}
		for _, prefix := range prefixes {
			if !strings.HasPrefix(prefix, "/") || !validRawPath(prefix) || strings.Contains(prefix, "%") {
				return fmt.Errorf("prefix %q", prefix)
			}
		}
		if prefixes != nil && len(prefixes) == 0 {
			return fmt.Errorf("password step host %q opens nothing", host)
		}
	}
	if len(row.AuthorizeHosts) == 0 {
		return fmt.Errorf("no authorize host")
	}
	for _, host := range row.AuthorizeHosts {
		if !validSignInHost(host) {
			return fmt.Errorf("authorize host %q", host)
		}
	}
	d := row.DeviceCode
	if d == nil {
		if len(device) > 0 || len(poll) > 0 {
			return fmt.Errorf("device calls without a device code")
		}
		return nil
	}
	if len(device) != 1 || len(poll) > 1 || (len(poll) == 1 && poll[0].Host != device[0].Host) || len(d.UserCodeFields) == 0 ||
		d.ExpiresInSeconds < 60 || d.ExpiresInSeconds > 3600 {
		return fmt.Errorf("device code")
	}
	d.Host, d.Path = device[0].Host, device[0].Path
	if len(poll) == 1 {
		d.TokenPath = poll[0].Path
	}
	if d.VerificationURI != "" {
		u, err := url.Parse(d.VerificationURI)
		if err != nil || u.Scheme != "https" || !row.authorizeHost(u.Host) || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("verification uri")
		}
	}
	return nil
}

// validSignInHost is a lower-case DNS name of at least two labels, no port.
func validSignInHost(host string) bool {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return !strings.Contains(host, "..")
}

// call is whether the row lists this exact call: the method, the host and the path as sent (not decoded, not
// cleaned: a spelling the row does not list is refused, whatever the server would read it as).
func (row signInRow) call(method, host, rawPath string) bool {
	for _, c := range row.Calls {
		if c.Method == method && c.Host == host && c.Path == rawPath {
			return true
		}
	}
	return false
}

// tunnelHost is whether an account's tunnel may go to host: a host of the row's calls, or for a password account
// also a host of its sign-in steps.
func (row signInRow) tunnelHost(host string, password bool) bool {
	for _, c := range row.Calls {
		if c.Host == host {
			return true
		}
	}
	_, step := row.PasswordSteps[host]
	return password && step
}

// passwordStep is whether a password account's call is one of its sign-in steps: a step host, the decoded path under
// one of its prefixes, and no refused word.
func (row signInRow) passwordStep(host, decoded string) bool {
	prefixes, known := row.PasswordSteps[host]
	return known && loginPathAllowed(loginHostRule{prefixes: prefixes}, decoded)
}

func (row signInRow) authorizeHost(host string) bool {
	for _, h := range row.AuthorizeHosts {
		if h == host {
			return true
		}
	}
	return false
}

// signInDomains is every host of every row (the calls' and the password steps'), sorted: the names the Gray sign-in
// CA's name constraints must cover.
func signInDomains(rows map[string]signInRow) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		for _, c := range row.Calls {
			seen[c.Host] = true
		}
		for host := range row.PasswordSteps {
			seen[host] = true
		}
	}
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// loginTables is each vendor's token rule.
func loginTables(rows map[string]signInRow) map[string]loginTokenRule {
	endpoints := map[string]loginTokenRule{}
	for vendor, row := range rows {
		rule := loginTokenRule{accountIDClaim: row.AccountIDClaim}
		for _, endpoint := range row.TokenEndpoints {
			rule.endpoints = append(rule.endpoints, loginTokenEndpoint{endpoint.Host, endpoint.Path})
		}
		endpoints[vendor] = rule
	}
	return endpoints
}
