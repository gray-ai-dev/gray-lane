// Copyright 2026 The Gray Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Gray: ordered request field encoding (../../http2/gray.go, ../../README.md).

package httpcommon

import (
	"fmt"
	"sort"
	"strings"
)

// orderedContentLength marks where EncodeHeaders writes the Content-Length field. It is not a valid field name, so
// no header map key equals it once validateHeaders has passed.
const orderedContentLength = "\x00content-length"

// ContentLengthMode is whether a request's header block carries content-length (EncodeHeadersParam.ContentLength).
type ContentLengthMode uint8

const (
	// ContentLengthDefault is shouldSendReqContentLength's rule.
	ContentLengthDefault ContentLengthMode = iota
	// ContentLengthSend sends it whenever the length is known, 0 included.
	ContentLengthSend
	// ContentLengthOmit never sends it.
	ContentLengthOmit
)

// sendContentLength is whether EncodeHeaders writes content-length under mode.
func sendContentLength(mode ContentLengthMode, method string, contentLength int64) bool {
	switch mode {
	case ContentLengthSend:
		return contentLength >= 0
	case ContentLengthOmit:
		return false
	}
	return shouldSendReqContentLength(method, contentLength)
}

var defaultPseudoOrder = []string{":authority", ":method", ":path", ":scheme", ":protocol"}

// orderPseudo returns the request pseudo-header names in order: order's, then the rest in the default order.
func orderPseudo(order []string) ([]string, error) {
	if len(order) == 0 {
		return defaultPseudoOrder, nil
	}
	out := make([]string, 0, len(defaultPseudoOrder))
	seen := make(map[string]bool, len(defaultPseudoOrder))
	for _, p := range order {
		known := false
		for _, d := range defaultPseudoOrder {
			known = known || d == p
		}
		if !known || seen[p] {
			return nil, fmt.Errorf("invalid pseudo-header order entry %q", p)
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, d := range defaultPseudoOrder {
		if !seen[d] {
			out = append(out, d)
		}
	}
	return out, nil
}

// orderHeaderKeys returns h's keys in order: the keys order names (case-insensitively; orderedContentLength where it
// names "content-length"), then the rest sorted by lower-cased name.
func orderHeaderKeys(h map[string][]string, order []string) []string {
	out := make([]string, 0, len(h)+1)
	if len(order) == 0 {
		for k := range h {
			out = append(out, k)
		}
		sortHeaderKeys(out)
		return out
	}
	byLower := make(map[string][]string, len(h))
	for k := range h {
		lower := strings.ToLower(k)
		byLower[lower] = append(byLower[lower], k)
	}
	used := make(map[string]bool, len(order))
	for _, name := range order {
		lower := strings.ToLower(name)
		if used[lower] {
			continue
		}
		used[lower] = true
		if lower == "content-length" {
			out = append(out, orderedContentLength)
			continue
		}
		keys := byLower[lower]
		sort.Strings(keys)
		out = append(out, keys...)
	}
	rest := make([]string, 0, len(h))
	for lower, keys := range byLower {
		if !used[lower] {
			rest = append(rest, keys...)
		}
	}
	sortHeaderKeys(rest)
	return append(out, rest...)
}

func sortHeaderKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		li, lj := strings.ToLower(keys[i]), strings.ToLower(keys[j])
		if li != lj {
			return li < lj
		}
		return keys[i] < keys[j]
	})
}
