package main

import (
	_ "embed"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The vendor sign-in rows (docs/design/relay-sign-in-in-vm.md §3.5, §4.1): per account vendor, the hosts and paths a
// sign-in or a refresh may call through egress (the CONNECT proxy), the token endpoint
// whose answers become the account's tokens, the hosts an authorize URL handed to a person may name, and the
// device-code endpoint whose answer egress reads to make the person's prompt. A vendor added later is a row here,
// reviewed as code: no Go changes.

//go:embed vendor-sign-in-v1.json
var vendorSignInJSON []byte

const signInRowsVersion = 1

type signInDeviceCode struct {
	Host string `json:"host"`
	Path string `json:"path"`
	// TokenPath is the device flow's poll for the authorization (OpenAI's own step, RFC 8628 §3.4 at a vendor that
	// answers RFC 8628 at the token endpoint has none): a call there outside an open session is refused.
	TokenPath string `json:"token_path"`
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
	Host string `json:"host"`
	Path string `json:"path"`
}

type signInRow struct {
	// Hosts maps each sign-in host to its open path prefixes; null opens every path but the refused words.
	Hosts map[string][]string `json:"hosts"`
	// TokenEndpoints: where the vendor's sign-in and refresh end, as the reference relay programs call them (read
	// 2026-11-11): auth.openai.com/oauth/token (Codex CLI, CLIProxyAPI, sub2api, new-api),
	// auth.openai.com/api/accounts/oauth/token (CLIProxyAPI's ChatGPT sign-in, internal/auth/codex/siwc_auth.go),
	// platform.claude.com/v1/oauth/token (Claude Code, CLIProxyAPI, sub2api).
	TokenEndpoints []signInEndpoint `json:"token_endpoints"`
	// AccountIDClaim: a token answer's access token must carry the ChatGPT account id claim serving names.
	AccountIDClaim bool              `json:"account_id_claim"`
	AuthorizeHosts []string          `json:"authorize_hosts"`
	DeviceCode     *signInDeviceCode `json:"device_code"`
}

type signInRowsFile struct {
	Version int                  `json:"version"`
	Vendors map[string]signInRow `json:"vendors"`
}

// signInRows is the parsed table; loginHosts and loginTokenEndpoints (stack_login.go) are views of it.
var signInRows = mustSignInRows(vendorSignInJSON)

func mustSignInRows(data []byte) map[string]signInRow {
	rows, err := parseSignInRows(data)
	if err != nil {
		panic("vendor-sign-in-v1.json: " + err.Error())
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
		if err := checkSignInRow(row); err != nil {
			return nil, fmt.Errorf("%s: %w", vendor, err)
		}
	}
	return file.Vendors, nil
}

func checkSignInRow(row signInRow) error {
	if len(row.Hosts) == 0 {
		return fmt.Errorf("no hosts")
	}
	for host, prefixes := range row.Hosts {
		if !validSignInHost(host) {
			return fmt.Errorf("host %q", host)
		}
		for _, prefix := range prefixes {
			if !strings.HasPrefix(prefix, "/") || !validRawPath(prefix) || strings.Contains(prefix, "%") {
				return fmt.Errorf("prefix %q", prefix)
			}
		}
		if prefixes != nil && len(prefixes) == 0 {
			return fmt.Errorf("host %q opens nothing", host)
		}
	}
	if len(row.TokenEndpoints) == 0 {
		return fmt.Errorf("no token endpoint")
	}
	for _, endpoint := range row.TokenEndpoints {
		if !row.opens(endpoint.Host, endpoint.Path) {
			return fmt.Errorf("token endpoint not open")
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
	if d := row.DeviceCode; d != nil {
		if !row.opens(d.Host, d.Path) || (d.TokenPath != "" && !row.opens(d.Host, d.TokenPath)) || len(d.UserCodeFields) == 0 ||
			d.ExpiresInSeconds < 60 || d.ExpiresInSeconds > 3600 {
			return fmt.Errorf("device code")
		}
		if d.VerificationURI != "" {
			u, err := url.Parse(d.VerificationURI)
			if err != nil || u.Scheme != "https" || !row.authorizeHost(u.Host) || u.User != nil || u.Fragment != "" {
				return fmt.Errorf("verification uri")
			}
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

// opens is whether the row lets a call reach host at the decoded path.
func (row signInRow) opens(host, decoded string) bool {
	prefixes, known := row.Hosts[host]
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

// signInDomains is every host of every row, sorted: the names the Gray sign-in CA's name constraints must cover.
func signInDomains(rows map[string]signInRow) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		for host := range row.Hosts {
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

// loginTables is the rows as the v1.9 route's two tables.
func loginTables(rows map[string]signInRow) (map[string]map[string]loginHostRule, map[string]loginTokenRule) {
	hosts := map[string]map[string]loginHostRule{}
	endpoints := map[string]loginTokenRule{}
	for vendor, row := range rows {
		hosts[vendor] = map[string]loginHostRule{}
		for host, prefixes := range row.Hosts {
			hosts[vendor][host] = loginHostRule{prefixes: prefixes}
		}
		rule := loginTokenRule{accountIDClaim: row.AccountIDClaim}
		for _, endpoint := range row.TokenEndpoints {
			rule.endpoints = append(rule.endpoints, loginTokenEndpoint{endpoint.Host, endpoint.Path})
		}
		endpoints[vendor] = rule
	}
	return hosts, endpoints
}
