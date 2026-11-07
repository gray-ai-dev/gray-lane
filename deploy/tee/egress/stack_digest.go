package main

// S19, the per-event digest of a vendor stream, and the body digest of a non-stream answer
// (docs/confidential-lane-supply-implementation.md §5). Egress computes them over the vendor's bytes
// for the feed; the entry computes the same over what the relay container passes back
// (@gray/lane's stack-digest.ts) and releases an event only when the two agree. The golden vectors
// in testdata/stack-vectors.json hold both sides to one answer.
//
//	digest = SHA-256(type || 0x0A || canon(data))
//
// type is the event's `event` field (empty when it has none), data its `data` lines joined by LF,
// and canon the JCS form when data is strict JSON (stack_json.go), else the data bytes.
//
// The events are those the WHATWG HTML event-stream rules dispatch (section 9.2.6, "Interpreting an
// event stream"): lines end at CRLF, LF or CR; one leading BOM (EF BB BF) is dropped; a blank line
// dispatches the event when at least one `data` line was seen, and always clears the event type; a
// line starting with a colon is a comment; a field's value is what follows the first colon, less one
// leading space; `event` and `data` are the only fields that count (`id`, `retry` and unknown fields
// change nothing here); at the end of the stream an event whose blank line has not arrived is
// discarded. So comments and keep-alives are never events, and Close dispatches nothing: a CR that
// ends the stream already ended its line in Write.
//
// The rules run on bytes rather than on decoded text. For UTF-8 input that is the same thing (CR and
// LF never occur inside a multibyte sequence, and the field names are ASCII). For bytes that are not
// UTF-8 it is stricter than a decoder's U+FFFD replacement: the digest covers the bytes themselves,
// so two different invalid sequences never hash alike, and neither side has to reproduce a decoder's
// replacement rules.
//
// The parser is written here (about forty lines) rather than taken from a library: the maintained Go
// SSE packages (tmaxmax/go-sse, launchdarkly/eventsource, the vendor SDKs' ssestream) read from an
// io.Reader and hand out decoded events, while S20a needs a push interface that returns digests per
// written chunk and keeps the raw bytes; the SDK decoders also split lines with bufio.ScanLines,
// which does not end a line at a lone CR. The shared vectors are the cross-check: the TypeScript side
// frames with @gray/protocol's SseFrames, and both run the same CRLF/CR/LF, BOM, comment, multi-line
// and unterminated cases.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// stackSSEDigester is S19's stackEventDigester for one attempt's stream.
type stackSSEDigester struct {
	bomSeen   int  // leading bytes matched against the BOM so far; -1 once the stream start is past
	crEnded   bool // the last byte was a CR that ended a line: an LF right after it belongs to that CR
	line      []byte
	eventType []byte
	data      []byte
	hasData   bool
	// failed is set once an event of type `error` or `response.failed` was dispatched (S34 stream_error).
	failed bool
	// onEvent, when set, takes each dispatched event instead of its digest (an account test reads event types
	// only, S44); the slices are valid during the call.
	onEvent func(eventType, data []byte)
}

// streamFailed reports whether the stream carried an `error` or `response.failed` event (S34 stream_error).
func (d *stackSSEDigester) streamFailed() bool { return d.failed }

var _ stackEventDigester = (*stackSSEDigester)(nil)

func newStackEventDigester() stackEventDigester {
	return &stackSSEDigester{}
}

// Write consumes p and returns the digests of the events whose blank line p completed, in order.
func (d *stackSSEDigester) Write(p []byte) []string {
	var digests []string
	for len(p) > 0 {
		if d.bomSeen >= 0 {
			if p[0] == utf8BOM[d.bomSeen] {
				d.bomSeen++
				p = p[1:]
				if d.bomSeen == len(utf8BOM) {
					d.bomSeen = -1
				}
				continue
			}
			// Not a BOM after all: the bytes matched so far start the first line (none is a CR or LF).
			d.line = append(d.line, utf8BOM[:d.bomSeen]...)
			d.bomSeen = -1
		}
		if d.crEnded {
			d.crEnded = false
			if p[0] == '\n' {
				p = p[1:]
				continue
			}
		}
		end := bytes.IndexAny(p, "\r\n")
		if end < 0 {
			d.line = append(d.line, p...)
			break
		}
		d.line = append(d.line, p[:end]...)
		if digest, ok := d.endLine(); ok {
			digests = append(digests, digest)
		}
		d.line = d.line[:0]
		d.crEnded = p[end] == '\r'
		p = p[end+1:]
	}
	return digests
}

// Held is the capacity of the line, event type and data buffers: the event in progress, and what a long
// line or event before it left allocated (the buffers are reused, not shrunk).
func (d *stackSSEDigester) Held() int {
	return cap(d.line) + cap(d.eventType) + cap(d.data)
}

// Close ends the stream. WHATWG discards an event whose blank line never came, so there is never a
// final event to count; the state is cleared so a reused digester starts a new stream.
func (d *stackSSEDigester) Close() []string {
	*d = stackSSEDigester{onEvent: d.onEvent}
	return nil
}

// endLine processes one complete line (without its end), reporting a dispatched event's digest.
func (d *stackSSEDigester) endLine() (string, bool) {
	line := d.line
	if len(line) == 0 {
		if !d.hasData {
			d.eventType = d.eventType[:0]
			return "", false
		}
		if string(d.eventType) == "error" || string(d.eventType) == "response.failed" {
			d.failed = true
		}
		if d.onEvent != nil {
			d.onEvent(d.eventType, d.data)
			d.eventType, d.data, d.hasData = d.eventType[:0], d.data[:0], false
			return "", false
		}
		digest := stackEventDigest(d.eventType, d.data)
		d.eventType, d.data, d.hasData = d.eventType[:0], d.data[:0], false
		return digest, true
	}
	if line[0] == ':' {
		return "", false
	}
	field, value := line, []byte(nil)
	if colon := bytes.IndexByte(line, ':'); colon >= 0 {
		field, value = line[:colon], line[colon+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
	}
	switch string(field) {
	case "event":
		d.eventType = append(d.eventType[:0], value...)
	case "data":
		if d.hasData {
			d.data = append(d.data, '\n')
		}
		d.data = append(d.data, value...)
		d.hasData = true
	}
	return "", false
}

// stackEventDigest is S19's digest of one dispatched event, lower hex.
func stackEventDigest(eventType, data []byte) string {
	hash := sha256.New()
	hash.Write(eventType)
	hash.Write([]byte{'\n'})
	hash.Write(stackCanonical(data))
	return hex.EncodeToString(hash.Sum(nil))
}

var _ stackBodyDigest = digestStackBody

// digestStackBody is the digest of a non-stream answer: SHA-256 of its JCS form when it is strict
// JSON, else of its bytes, lower hex.
func digestStackBody(body []byte) string {
	return stackJCSSHA256(body)
}
