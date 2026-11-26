package main

import (
	"net/http"
	"net/url"
	"strings"
)

// route is one of the closed destinations: the first three vendors' and one per OpenAI-compatible vendor (vendors.go). Every field is a constant:
// no request value can add a host, a port or a scheme to the upstream URL.
type route struct {
	name       string // the only part of the path that may reach a log line
	prefix     string // the request path prefix accepted by this route
	host       string // the only host this route may connect to
	vendorPath string // the official path prefix mirrored from @gray/lane origin.ts
}

var routeTable = append([]route{
	{name: "/anthropic", prefix: "/anthropic/", host: "api.anthropic.com", vendorPath: "/v1/"},
	{name: "/openai", prefix: "/openai/", host: "api.openai.com", vendorPath: "/v1/"},
	{name: "/chatgpt", prefix: "/chatgpt/", host: "chatgpt.com", vendorPath: "/backend-api/codex/"},
}, compatRoutes()...)

// matchRoute returns the route whose prefix the raw (still percent-encoded)
// request path starts with. Matching the raw path means a percent-encoded
// spelling of a route prefix is not silently decoded here; it is refused.
func matchRoute(escapedPath string) (route, bool) {
	for _, rt := range routeTable {
		if strings.HasPrefix(escapedPath, rt.prefix) {
			return rt, true
		}
	}
	return route{}, false
}

// hostMatches enforces the Host contract from E1: the request must name the
// route's official origin, not the unix socket's local label. workerd sends
// the URL host as Host, so the L4 wiring calls the egress binding with
// `http://api.anthropic.com/anthropic/...` and this check ties the route and
// the Host together. A port, a trailing dot or any other name is refused.
func hostMatches(r *http.Request, rt route) bool {
	host := r.Host
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return false
		}
	}
	return strings.EqualFold(host, rt.host)
}

// allowedMethod is the closed method set of the official HTTP APIs. CONNECT is
// refused before this check; TRACE and extension methods are refused here.
func allowedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

// target builds the upstream URL from the route constant and the raw path the
// request line carried. The official path rule is checked after the route prefix
// is removed, exactly as origin.ts checks the URL a lane request would fetch:
// `/v1/` for Anthropic and OpenAI, `/backend-api/codex/` for ChatGPT.
//
// The forwarded spelling is the received one byte for byte (D76). URL.Opaque
// carries the request-target path, so Go's EscapedPath canonicalisation cannot
// rewrite it: EscapedPath would turn `|` into `%7C` and `%2F` into a real `/`
// when URL.RawPath is not a valid encoding. The query travels separately in
// RawQuery/ForceQuery, exactly as it was received.
func (rt route) target(r *http.Request) (*url.URL, bool) {
	if r.URL == nil || r.URL.Fragment != "" {
		return nil, false
	}
	// Check the literal characters on the raw path, not EscapedPath: EscapedPath turns a
	// literal backslash/space/control into %XX, which would hide the character that
	// checkOfficialUpstream refuses (D62). The server's RequestURI is the exact spelling (so
	// `%00` stays `%00` and a literal NUL stays literal); tests that build a request directly
	// fall back to RawPath/Path.
	rawPath := rawPathOf(r)
	// A raw '#' would start a fragment for any parser that reads the target as a URL (D59); planTarget refuses it
	// in the request-target already, and target refuses it here too, so the WHATWG comparison below never reads a
	// path that a URL parser would have cut.
	if !validRawPath(rawPath) || strings.Contains(rawPath, "#") {
		return nil, false
	}
	if !strings.HasPrefix(rawPath, rt.prefix) {
		return nil, false
	}
	rest := strings.TrimPrefix(rawPath, rt.prefix)
	upstreamPath := "/" + rest
	// origin.ts compares the WHATWG pathname, where dot segments are resolved: `/v1/../x` is `/x` there. The same
	// comparison here keeps egress from relying on the main lane alone for a path that climbs out of the prefix
	// (LD-1/2); one that stays under it is still forwarded as received.
	if !strings.HasPrefix(upstreamPath, rt.vendorPath) || !strings.HasPrefix(whatwgPathname(upstreamPath), rt.vendorPath) {
		return nil, false
	}
	return &url.URL{
		Scheme:     "https",
		Host:       rt.host,
		Opaque:     upstreamPath,
		RawQuery:   r.URL.RawQuery,
		ForceQuery: r.URL.ForceQuery,
	}, true
}

// rawPathOf is the path as it was spelled on the wire. net/http sets RequestURI for every server
// request (the unmodified request-target); a directly built test request may leave it empty, in
// which case RawPath keeps the original spelling only when it differs from the canonical escape of
// Path, and Path is the best remaining spelling.
func rawPathOf(r *http.Request) string {
	if r.RequestURI != "" {
		if query := strings.IndexByte(r.RequestURI, '?'); query >= 0 {
			return r.RequestURI[:query]
		}
		return r.RequestURI
	}
	if r.URL == nil {
		return ""
	}
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.Path
}

// validRawPath is the main lane's path rule (@gray/lane origin.ts checkOfficialUpstream, D62),
// applied to the raw path this program received. The upstream host is a constant and the path
// cannot leave it, so the sidecar-only traversal bans are gone: `%2F`, `%5C`, `%00` and literal or
// encoded `..` are forwarded exactly as the main lane passed them (laneFetch slices the original
// path, then this program carries it in URL.Opaque for the request line, D76), as long as the path
// stays under the vendor prefix once its dot segments are resolved (target). The two refusals
// that remain are the ones checkOfficialUpstream also makes anywhere in its URL: a literal
// backslash (some readers treat it
// as a separator, some as a host byte) and a raw space/control byte (the parser strips or
// re-encodes it, so the text and the sent request differ). A percent-encoded form of either is an
// ordinary byte and is allowed.
func validRawPath(raw string) bool {
	if strings.Contains(raw, "\\") {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return false
		}
	}
	return true
}

// whatwgPathname is the pathname the WHATWG URL parser makes of an https URL whose path is path (URL Standard, path
// state), as far as a comparison with a vendor prefix can tell: each single-dot (`.`, `%2e`) and double-dot (`..`,
// `.%2e`, `%2e.`, `%2e%2e`, either case) segment is resolved, a double dot dropping the segment before it, and a dot
// segment at the end leaves the path ending in '/'. The parser's other changes cannot move a prefix match: it
// percent-encodes no byte a vendor prefix holds, and the backslash it reads as a separator is refused before this
// (validRawPath). As the parser does, it reads the path only up to a '?' or '#', where the query or fragment starts.
func whatwgPathname(path string) string {
	if end := strings.IndexAny(path, "?#"); end >= 0 {
		path = path[:end]
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	out := make([]string, 0, len(segments))
	for i, segment := range segments {
		last := i == len(segments)-1
		switch strings.ToLower(segment) {
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case ".", "%2e":
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, segment)
		}
	}
	return "/" + strings.Join(out, "/")
}
