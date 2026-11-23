package main

import (
	"net/http"
	"strings"
)

// hopByHopHeaders are removed in both directions (RFC 7230 section 6.1).
// Proxy-Connection is the de-facto header old proxies use; it is hop-by-hop too.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// protectedAuthHeaders are end-to-end credential headers that an inbound Connection
// header must never strip via hop-by-hop smuggling.
var protectedAuthHeaders = map[string]bool{
	"Authorization":      true,
	"X-Api-Key":          true,
	"X-Goog-Api-Key":     true,
	"Chatgpt-Account-Id": true,
}

// stripHopByHop removes the fixed list and every header named by a Connection
// header, except protected auth headers. Header.Del canonicalizes the name, so
// the comparison is case-insensitive.
func stripHopByHop(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				if protectedAuthHeaders[http.CanonicalHeaderKey(token)] {
					continue
				}
				h.Del(token)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
