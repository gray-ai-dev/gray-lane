package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// maxSpecBytes is the whole-member cap from the E2 egress member of the sealed
// credential. The same cap applies to the per-request header: the two forms are
// one value, so a header the sidecar accepts is a bundle member the relay could
// have sealed (and the other way round).
const maxSpecBytes = 1024

// 255 is SOCKS5 RFC 1929's one-byte length field (and the same bound in relay-connector's
// E2 validation and relay-kit's source checks, F2 D15). D24 restricts the characters to
// printable ASCII 0x21-0x7e as well: no space, no control byte, no non-ASCII.
const maxCredentialBytes = 255

// specError is deliberately value-free. It names the member that failed (or a
// fixed reason) and never includes the host, username, password or the JSON
// text: the header is a relay secret and may reach a log or an error page.
type specError struct {
	reason string
}

func (e *specError) Error() string { return "egress spec: " + e.reason }

func specErr(reason string) error { return &specError{reason: reason} }

// egressSpec is the validated, structured form. The program never parses a URL
// string for it: the proxy URL is assembled from these fields with url.URL and
// url.UserPassword.
type egressSpec struct {
	kind     string
	host     string
	port     int
	username *string
	password *string
}

// wireSpec is the JSON shape used only to decode the header. Pointers tell an
// absent member from an empty one; unknown members are rejected by the decoder
// and an explicit null is rejected by checkSpecMembers before this decode (a
// pointer alone cannot tell null from absent).
type wireSpec struct {
	Type     *string `json:"type"`
	Host     *string `json:"host"`
	Port     *int    `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
}

// parseEgressSpec turns the x-gray-egress header into a spec. Absent means
// direct (nil, nil). Present means exactly one value; an empty, duplicated or
// invalid value is refused before any dial.
func parseEgressSpec(values []string) (*egressSpec, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, specErr("more than one header value")
	}
	raw := values[0]
	if len(raw) > maxSpecBytes {
		return nil, specErr("over 1024 bytes")
	}
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, specErr("not a JSON object")
	}
	if err := checkSpecMembers(trimmed); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var wire wireSpec
	if err := dec.Decode(&wire); err != nil {
		return nil, specErr("not a JSON object")
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, specErr("trailing data")
	}

	if wire.Type == nil {
		return nil, specErr("type is missing")
	}
	switch *wire.Type {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, specErr("type")
	}
	if wire.Host == nil || *wire.Host == "" {
		return nil, specErr("host is missing")
	}
	if err := checkEgressHost(*wire.Host); err != nil {
		return nil, err
	}
	if wire.Port == nil || *wire.Port < 1 || *wire.Port > 65535 {
		return nil, specErr("port")
	}
	if (wire.Username == nil) != (wire.Password == nil) {
		return nil, specErr("username and password must be both present or both absent")
	}
	if wire.Username != nil {
		if !validCredential(*wire.Username) {
			return nil, specErr("username")
		}
		if !validCredential(*wire.Password) {
			return nil, specErr("password")
		}
	}
	return &egressSpec{
		kind:     *wire.Type,
		host:     *wire.Host,
		port:     *wire.Port,
		username: wire.Username,
		password: wire.Password,
	}, nil
}

// checkSpecMembers performs the two checks a struct decoder alone does not do
// exactly: it rejects duplicate members and members that differ from the
// lower-case wire names only by case (encoding/json matches struct fields
// case-insensitively). It uses the standard json.Decoder, not a tokenizer of
// our own.
func checkSpecMembers(raw string) error {
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return specErr("not a JSON object")
	}
	seen := make(map[string]bool, 5)
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return specErr("not a JSON object")
		}
		key, ok := keyToken.(string)
		if !ok {
			return specErr("not a JSON object")
		}
		switch key {
		case "type", "host", "port", "username", "password":
		default:
			return specErr("unknown member")
		}
		if seen[key] {
			return specErr("duplicate member")
		}
		seen[key] = true
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return specErr("not a JSON object")
		}
		// An explicit null is not an absent member (D59: relay-connector's schema refuses it,
		// so the header must refuse it too). The check runs on every member; the fields that
		// were already refused for other reasons keep their own value-free error.
		if string(discard) == "null" {
			return specErr("null member")
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return specErr("not a JSON object")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return specErr("trailing data")
	}
	return nil
}

// checkEgressHost applies the E2 host rules: printable ASCII, no userinfo, no
// trailing dot, no backslash and no percent escape. A colon is allowed only for
// an IPv6 literal, and brackets are refused because the wire form is structured
// fields, not a URL (the program adds the brackets when it builds the proxy
// URL). Path, query and fragment delimiters are refused too: they cannot occur
// in a host and would make the value look like the URL string this format
// exists to avoid.
func checkEgressHost(host string) error {
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return specErr("host is not printable ASCII")
		}
	}
	if strings.ContainsAny(host, "@\\%") {
		return specErr("host")
	}
	if strings.HasSuffix(host, ".") {
		return specErr("host has a trailing dot")
	}
	if strings.ContainsAny(host, "/?#") {
		return specErr("host")
	}
	if strings.ContainsAny(host, "[]") {
		return specErr("host has brackets")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return specErr("host")
	}
	return nil
}

// validCredential applies D24: at most 255 bytes and only printable ASCII 0x21-0x7e. Empty is
// valid ("both present and empty" is a defined proxy form), and the byte scan is exact because the
// accepted set is ASCII: a UTF-8 continuation byte is above 0x7e and is refused.
func validCredential(s string) bool {
	if len(s) > maxCredentialBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// proxyURL is the only place a proxy URL is made. There is no url.Parse of a
// header value anywhere in the program.
func (s *egressSpec) proxyURL() *url.URL {
	u := &url.URL{
		Scheme: s.kind,
		Host:   net.JoinHostPort(s.host, strconv.Itoa(s.port)),
	}
	if s.username != nil {
		u.User = url.UserPassword(*s.username, *s.password)
	}
	return u
}
