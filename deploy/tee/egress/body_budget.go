package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
)

var errBodyBudgetExceeded = errors.New("egress in-flight body budget exceeded")

// bodyBudget bounds the total bytes of request bodies held in memory across all
// in-flight requests at once (vendor, /route/, /peer/, control and relay-stack).
// Every caller reserves bytes before buffering and releases them via defer when
// the handler returns.
type bodyBudget struct {
	max  atomic.Int64
	used atomic.Int64
}

func (b *bodyBudget) tryTake(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		used := b.used.Load()
		if used+n > b.max.Load() {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func (b *bodyBudget) give(n int64) {
	if n > 0 {
		b.used.Add(-n)
	}
}

// bodyHold tracks one request's share of a bodyBudget so it can grow while a
// chunked body is read and always be released once via defer.
type bodyHold struct {
	budget *bodyBudget
	bytes  int64
}

func (h *bodyHold) grow(n int64) bool {
	if n <= 0 || h == nil || h.budget == nil {
		return true
	}
	if !h.budget.tryTake(n) {
		return false
	}
	h.bytes += n
	return true
}

func (h *bodyHold) shrink(n int64) {
	if n <= 0 || h == nil || h.budget == nil || h.bytes == 0 {
		return
	}
	n = min(n, h.bytes)
	h.budget.give(n)
	h.bytes -= n
}

func (h *bodyHold) free() {
	if h == nil || h.budget == nil || h.bytes == 0 {
		return
	}
	h.budget.give(h.bytes)
	h.bytes = 0
}

func noopRelease() {}

// readRequestBody reads a request body up to max bytes under the server's
// global in-flight body budget. It always returns a non-nil release function
// (idempotent and safe from any goroutine, so a handler may defer it and also
// hand it to sentBody; safe to defer immediately). On any error, reserved bytes
// are released before returning.
func (s *server) readRequestBody(r *http.Request, maxBytes int64) ([]byte, int64, func(), error) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, 0, noopRelease, nil
	}
	if r.ContentLength > maxBytes {
		return nil, 0, noopRelease, errBodyTooLargeRequest
	}
	hold := &bodyHold{budget: &s.bodyBudget}
	if r.ContentLength > 0 {
		if !hold.grow(r.ContentLength) {
			return nil, 0, noopRelease, errBodyBudgetExceeded
		}
		body := make([]byte, r.ContentLength)
		n, err := io.ReadFull(r.Body, body)
		if err != nil {
			hold.free()
			return nil, int64(n), noopRelease, err
		}
		return body[:n], int64(n), sync.OnceFunc(hold.free), nil
	}
	var body []byte
	chunk := make([]byte, 32*1024)
	for {
		// Read at most one byte past maxBytes so an oversized chunked body logs maxBytes+1
		// and trips errBodyTooLargeRequest before reserving budget for excess bytes.
		limit := min(int64(len(chunk)), maxBytes-int64(len(body))+1)
		n, err := r.Body.Read(chunk[:limit])
		if int64(len(body)+n) > maxBytes {
			hold.free()
			return nil, int64(len(body) + n), noopRelease, errBodyTooLargeRequest
		}
		if n > 0 {
			var ok bool
			if body, ok = growBudgeted(body, n, maxBytes, hold); !ok {
				hold.free()
				return nil, int64(len(body)), noopRelease, errBodyBudgetExceeded
			}
			body = append(body, chunk[:n]...)
		}
		if errors.Is(err, io.EOF) {
			return body, int64(len(body)), sync.OnceFunc(hold.free), nil
		}
		if err != nil {
			hold.free()
			return nil, int64(len(body)), noopRelease, err
		}
	}
}

func growBudgeted(held []byte, n int, limit int64, hold *bodyHold) ([]byte, bool) {
	need := int64(len(held) + n)
	if need <= int64(cap(held)) {
		return held, true
	}
	size := min(max(2*int64(cap(held)), need), max(limit, need))
	if !hold.grow(size - int64(cap(held))) {
		size = need
		if !hold.grow(size - int64(cap(held))) {
			return held, false
		}
	}
	grown := make([]byte, len(held), size)
	copy(grown, held)
	return grown, true
}

// budgetedBuffer is a growable byte buffer whose backing capacity is reserved from hold before
// allocating (bounded by limit when limit > 0). When hold is nil it grows without budget checks.
type budgetedBuffer struct {
	buf            []byte
	limit          int64
	hold           *bodyHold
	budgetExceeded bool
}

func (b *budgetedBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.hold != nil {
		var ok bool
		if b.buf, ok = growBudgeted(b.buf, len(p), b.limit, b.hold); !ok {
			b.budgetExceeded = true
			return 0, errBodyBudgetExceeded
		}
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *budgetedBuffer) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	if b.hold != nil {
		var ok bool
		if b.buf, ok = growBudgeted(b.buf, len(s), b.limit, b.hold); !ok {
			b.budgetExceeded = true
			return 0, errBodyBudgetExceeded
		}
	}
	b.buf = append(b.buf, s...)
	return len(s), nil
}

func (b *budgetedBuffer) WriteByte(c byte) error {
	if b.hold != nil {
		var ok bool
		if b.buf, ok = growBudgeted(b.buf, 1, b.limit, b.hold); !ok {
			b.budgetExceeded = true
			return errBodyBudgetExceeded
		}
	}
	b.buf = append(b.buf, c)
	return nil
}

func (b *budgetedBuffer) Len() int { return len(b.buf) }

// sentBody is a held request body as one vendor call sends it (forward and forwardPeer, on the /route/, vendor and
// /peer/ paths). The call needs the bytes until the transport has read them to their end or closed them, and until
// the answer's head has arrived: net/http asks for a body again (GetBody) only for a retry or a redirect, both before
// Do returns. Once both have happened letGo runs, once: the body's share of the in-flight budget goes back and the
// bytes are dropped, so the collector may take them while the answer streams on. Without it a call held its body
// until its handler returned, the whole answer long: a streamed answer pinned the request it answered, and a form the
// entry let go of when its answer's head came (docs/design/standard-media-at-entry.md section 2.3) stayed in egress's
// budget for the rest of the answer, which the entry's sum of forms (LANE_FORM_HELD_MAX_BYTES) does not count.
type sentBody struct {
	mu       sync.Mutex
	body     []byte
	readers  []*sentBodyReader
	answered bool
	letGo    func()
}

// sentBodyReader is one read of a sentBody: the first, and one more for each GetBody.
type sentBodyReader struct {
	owner  *sentBody
	reader *bytes.Reader
	done   bool
}

func newSentBody(body []byte, letGo func()) *sentBody {
	return &sentBody{body: body, letGo: letGo}
}

// attach makes b the request's body, with its length and a GetBody that reads it again.
func (b *sentBody) attach(req *http.Request) {
	first, _ := b.open()
	req.Body = first
	req.GetBody = b.open
	req.ContentLength = int64(len(b.body))
}

// open is a fresh read of the bytes; after letGo there are none to read, which only a retry after Do returned could
// ask for, and net/http makes none.
func (b *sentBody) open() (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.body == nil {
		return nil, errors.New("egress let the request body go once it was sent and answered")
	}
	read := &sentBodyReader{owner: b, reader: bytes.NewReader(b.body)}
	b.readers = append(b.readers, read)
	return read, nil
}

// responded is called once Do returned, with an answer or an error: no read of the body starts after it.
func (b *sentBody) responded() {
	b.mu.Lock()
	b.answered = true
	release := b.releasable()
	b.mu.Unlock()
	if release != nil {
		release()
	}
}

// releasable drops the bytes and returns letGo when the call needs them no more; nil otherwise. Callers hold b.mu.
func (b *sentBody) releasable() func() {
	if !b.answered || b.body == nil {
		return nil
	}
	for _, read := range b.readers {
		if !read.done {
			return nil
		}
	}
	b.body = nil
	for _, read := range b.readers {
		read.reader = nil
	}
	b.readers = nil
	return b.letGo
}

func (r *sentBodyReader) Read(p []byte) (int, error) {
	r.owner.mu.Lock()
	if r.reader == nil {
		r.owner.mu.Unlock()
		return 0, io.EOF
	}
	n, err := r.reader.Read(p)
	var release func()
	if err == io.EOF {
		r.done = true
		release = r.owner.releasable()
	}
	r.owner.mu.Unlock()
	if release != nil {
		release()
	}
	return n, err
}

func (r *sentBodyReader) Close() error {
	r.owner.mu.Lock()
	r.done = true
	release := r.owner.releasable()
	r.owner.mu.Unlock()
	if release != nil {
		release()
	}
	return nil
}
