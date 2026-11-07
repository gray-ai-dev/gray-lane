package main

import "encoding/json"

// The S20a seam (docs/confidential-lane-supply-implementation.md §5), word for word. The checks themselves are
// pure functions in stack_check.go (S18) and stack_digest.go (S19), built and tested on their own branch; the
// listener, control API and feed take them as values (stack.go), so each half builds and tests alone. When the
// two branches meet, these three declarations must exist exactly once in the package.

// S18: accepted is the JSON object {"ops":[…],"appended":[…],"forwarded_jcs_sha256":"…"}: what the relay
// did, its member edits as request.modified ops and its appends as RelayAppends (S26 relay_stack.appended),
// and the lower-hex SHA-256 of the forwarded body's comparison form, RFC 8785 with number tokens as written
// (S26 body_jcs_sha256, S32); refusedPath is the JSON pointer of the first difference the spec does not cover,
// cut to whole tokens within 256 UTF-16 units ("" when accepted); err is a malformed body or spec, or a
// refusal no token of whose path fits (S32), which the listener answers as a refusal without a path.
type stackRequestCheck func(protocol string, received, forwarded []byte, rewrite json.RawMessage) (accepted json.RawMessage, refusedPath string, err error)

// S19: one per attempt; Write returns the lower-hex digests of the events p completed, Close those of a final
// unterminated event (WHATWG dispatch rules decide whether it counts). Held is the bytes its buffers hold
// between calls (their capacity), which egress counts in -stack-max-bytes (S17): a single long `data` line
// is held whole until its event ends.
type stackEventDigester interface {
	Write(p []byte) []string
	Close() []string
	Held() int
}

// Non-stream bodies: JCS when the body parses as JSON, else the raw bytes.
type stackBodyDigest func(body []byte) string
