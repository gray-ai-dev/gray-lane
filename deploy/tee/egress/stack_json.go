package main

// Strict JSON for the relay-stack checks (S18, S19): which texts count as JSON, their comparison form,
// and the member and element access the request check needs.
//
// The comparison form (S32) is RFC 8785 (JCS) with every number token kept exactly as written: no
// whitespace, object members sorted by the UTF-16 code units of their names at every depth, strings in
// their minimal escaped form, `true`/`false`/`null`, and each number as the bytes of its token. JCS's
// own number rule reads a number as a double, so `9007199254740993` and `…992`, or `3`, `3.0` and `3e0`,
// would compare equal; here they differ, as do `1e2` and `1E2`, and `-0` and `0`. Two values are equal
// when their comparison forms are. The TypeScript side (@gray/lane's stack-digest.ts) writes the same
// form, and testdata/stack-vectors.json holds both to it.
//
// The parser is the standard library's encoding/json/jsontext (Go 1.27, no GOEXPERIMENT). It already
// refuses what the checks must refuse: a duplicate member name at any depth (compared after
// unescaping, RFC 7493 section 2.3), invalid UTF-8, and an escaped lone surrogate. The form is its own
// jsontext.Value.Format with ReorderRawObjects (RFC 8785 section 3.2.3 member order) and with
// CanonicalizeRawInts and CanonicalizeRawFloats off, which keeps each number token as written; Format
// re-escapes strings minimally and writes no whitespace by default. jsontext does all of this in one
// place and adds no module to this program, so the Dockerfile build stays network-free.
//
// Two rules are added on top, so that both sides of S19 call exactly the same texts JSON. The
// TypeScript side (@gray/lane's stack-digest.ts) gates a text with @gray/json's parseStrict, which
// is serde_json's reading: at most SERDE_MAX_DEPTH (127) nested containers, and a number that
// overflows a double is an error. jsontext allows 10000 levels and reads an overflowing number as
// ±MaxFloat64 (its jsonwire.ParseFloat clamps), where RFC 8785 has no form for it and JavaScript reads
// Infinity. So a text nested deeper than 127 containers, or holding a number whose nearest double is
// infinite, is not JSON here either.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// stackMaxDepth is serde_json's recursion limit as @gray/json holds it (SERDE_MAX_DEPTH,
// workers/packages/json/src/index.ts): 127 nested containers. The gateway reads every client body
// with that parser, so no stack request is nested deeper.
const stackMaxDepth = 127

var errStackNotJSON = errors.New("not strict JSON")

// checkStrictJSON accepts exactly one JSON value, optionally surrounded by whitespace, under
// jsontext's default rules plus the depth and finite-number rules above.
func checkStrictJSON(data []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	values := 0
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || values > 0 {
			// A second top-level value: jsontext reads a stream of them, a body is one.
			return errStackNotJSON
		}
		switch tok.Kind() {
		case jsontext.KindBeginObject, jsontext.KindBeginArray:
			if dec.StackDepth() > stackMaxDepth {
				return errStackNotJSON
			}
		case jsontext.KindNumber:
			// The grammar is already checked; only the magnitude is. An underflow reads as zero,
			// as in JavaScript and serde_json.
			if f, _ := strconv.ParseFloat(tok.String(), 64); math.IsInf(f, 0) {
				return errStackNotJSON
			}
		}
		if dec.StackDepth() == 0 {
			values++
		}
	}
	if values != 1 {
		return errStackNotJSON
	}
	return nil
}

// comparisonForm rewrites *value, a copy, into the comparison form (see the top of this file). Format
// works in place and may shorten the slice, so it takes the pointer.
func comparisonForm(value *jsontext.Value) error {
	return value.Format(jsontext.ReorderRawObjects(true), jsontext.CanonicalizeRawInts(false), jsontext.CanonicalizeRawFloats(false))
}

// stackCanonical is S19's canon: the comparison form of data when it is strict JSON, else data itself.
func stackCanonical(data []byte) []byte {
	if checkStrictJSON(data) != nil {
		return data
	}
	value := jsontext.Value(slices.Clone(data))
	if err := comparisonForm(&value); err != nil {
		return data
	}
	return value
}

// stackJCSSHA256 is SHA-256 of stackCanonical(data), lower hex: S19's non-stream body digest
// (digestStackBody) and S18's forwarded_jcs_sha256 (S26 body_jcs_sha256), one function so the two are
// the same value by construction. It lives here because the conformance tool compiles the S18 check
// from stack_check.go, stack_policy.go, stack_json.go and stack_seam.go alone
// (deploy/relay/conformance/Dockerfile).
func stackJCSSHA256(data []byte) string {
	sum := sha256.Sum256(stackCanonical(data))
	return hex.EncodeToString(sum[:])
}

// canonicalText is the comparison form of a value already accepted by checkStrictJSON. Raw values of a
// checked text always format; the empty answer for one that does not never equals the form of any
// value, so a comparison fails closed.
func canonicalText(value jsontext.Value) string {
	if value == nil {
		return ""
	}
	canonical := jsontext.Value(slices.Clone(value))
	if err := comparisonForm(&canonical); err != nil {
		return ""
	}
	return string(canonical)
}

// sameStackJSON is equality of two present values under the comparison form. Equal bytes are equal
// values, so a relay that forwards a member unchanged costs no formatting.
func sameStackJSON(left, right jsontext.Value) bool {
	if bytes.Equal(left, right) {
		return true
	}
	a := canonicalText(left)
	return a != "" && a == canonicalText(right)
}

// stackObject is one JSON object: its members' exact texts by name, and the names in JCS order
// (RFC 8785 section 3.2.3, UTF-16 code units), the order a refusal path is searched in.
type stackObject struct {
	names   []string
	members map[string]jsontext.Value
}

// objectOf reads value as an object, or reports false when it is not one. value must come from a
// text checkStrictJSON accepted (no duplicate names, valid UTF-8).
func objectOf(value jsontext.Value) (stackObject, bool) {
	if value.Kind() != jsontext.KindBeginObject {
		return stackObject{}, false
	}
	dec := jsontext.NewDecoder(bytes.NewReader(value))
	if _, err := dec.ReadToken(); err != nil {
		return stackObject{}, false
	}
	object := stackObject{members: map[string]jsontext.Value{}}
	for dec.PeekKind() != jsontext.KindEndObject {
		token, err := dec.ReadToken()
		if err != nil {
			return stackObject{}, false
		}
		// A token is valid only until the decoder's next call.
		name := token.String()
		member, err := dec.ReadValue()
		if err != nil {
			return stackObject{}, false
		}
		object.names = append(object.names, name)
		object.members[name] = slices.Clone(member)
	}
	slices.SortFunc(object.names, compareUTF16)
	return object, true
}

// elementsOf reads value as an array, or reports false when it is not one.
func elementsOf(value jsontext.Value) ([]jsontext.Value, bool) {
	if value.Kind() != jsontext.KindBeginArray {
		return nil, false
	}
	dec := jsontext.NewDecoder(bytes.NewReader(value))
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	var elements []jsontext.Value
	for dec.PeekKind() != jsontext.KindEndArray {
		element, err := dec.ReadValue()
		if err != nil {
			return nil, false
		}
		elements = append(elements, slices.Clone(element))
	}
	return elements, true
}

// stringOf reads value as a JSON string, or reports false when it is not one.
func stringOf(value jsontext.Value) (string, bool) {
	if value.Kind() != jsontext.KindString {
		return "", false
	}
	text, err := jsontext.AppendUnquote(nil, value)
	if err != nil {
		return "", false
	}
	return string(text), true
}

// quoteJSON is the JCS text of the JSON string s (s is valid UTF-8).
func quoteJSON(s string) jsontext.Value {
	quoted, err := jsontext.AppendQuote(nil, s)
	if err != nil {
		return nil
	}
	return jsontext.Value(canonicalText(quoted))
}

// compareUTF16 orders member names as RFC 8785 sorts them: by their UTF-16 code units. It differs
// from Go's byte order only between a supplementary character and U+E000..U+FFFF.
func compareUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	return slices.Compare(ua, ub)
}

// unionNames is the JCS-ordered union of name lists.
func unionNames(lists ...[]string) []string {
	seen := map[string]bool{}
	var names []string
	for _, list := range lists {
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	slices.SortFunc(names, compareUTF16)
	return names
}

// pointerToken escapes one RFC 6901 reference token.
func pointerToken(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

// firstDifference is the JSON pointer of the first place two values differ under the comparison form, or ""
// when they are equal. Absent is nil. Objects are searched in JCS member order, arrays by index; a
// value of another kind, or of another type on each side, differs as a whole.
func firstDifference(pointer string, received, forwarded jsontext.Value) string {
	switch {
	case received == nil && forwarded == nil:
		return ""
	case received == nil || forwarded == nil:
		return pointer
	case sameStackJSON(received, forwarded):
		return ""
	}
	if left, ok := objectOf(received); ok {
		if right, ok := objectOf(forwarded); ok {
			for _, name := range unionNames(left.names, right.names) {
				if path := firstDifference(pointer+"/"+pointerToken(name), left.members[name], right.members[name]); path != "" {
					return path
				}
			}
			return pointer
		}
	}
	if left, ok := elementsOf(received); ok {
		if right, ok := elementsOf(forwarded); ok {
			for index := 0; index < max(len(left), len(right)); index++ {
				var l, r jsontext.Value
				if index < len(left) {
					l = left[index]
				}
				if index < len(right) {
					r = right[index]
				}
				if path := firstDifference(pointer+"/"+strconv.Itoa(index), l, r); path != "" {
					return path
				}
			}
		}
	}
	return pointer
}
