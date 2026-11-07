package main

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// S35's error hold: for a relay call whose vendor answer has status ≥ 400, egress holds head and body until the
// body ends, passes 64 KiB (stackErrorBodyMax, the bytes it holds for `error_body` anyway) or 10 s pass
// (ERROR_BODY_WAIT_MS), then classifies the answer and applies the rules, writes the `response` record, and only
// then forwards head and body to the relay, byte for byte; the rest of a longer answer streams as any answer
// does. S20 still holds: no byte changes, only an error's delivery waits for its end. A relay that retries after
// reading the error therefore never meets the account the error just cooled.

// stackErrorHoldWait is @gray/errors ERROR_BODY_WAIT_MS (upstream.ts), the longest Gray waits for an error body.
const stackErrorHoldWait = 10 * time.Second

// errorHolder is an observer that holds an error answer whole before anything of it is recorded or written.
type errorHolder interface {
	holds(status int) bool
	// holdChunk keeps a copy of p; false when the budget cannot (the answer is then cut, S17).
	holdChunk(p []byte) bool
	// release classifies what is held (complete: the vendor's body ended within the hold) and queues the
	// `response` record; it returns the held bytes, which are then observed and written as the answer's first
	// bytes. false when the record does not fit.
	release(status int, header http.Header, complete bool) ([]byte, bool)
	afterHold(wait time.Duration, fire func()) *time.Timer
}

// forwardHeld is forward's path for a held answer (resp's head is not written yet). It returns forward's codes.
func (s *server) forwardHeld(rec *responseRecorder, resp *http.Response, obs upstreamObserver, holder errorHolder) string {
	chunks := readChunks(resp.Body)
	// The reader may be blocked in Read: forward's deferred Body.Close ends that read, and stop lets it return.
	defer chunks.stop()
	expired := make(chan struct{})
	timer := holder.afterHold(stackErrorHoldWait, func() { close(expired) })
	defer timer.Stop()
	var held int
	complete := false
	var readErr error
holding:
	for {
		select {
		case c := <-chunks.out:
			if len(c.p) > 0 {
				if !holder.holdChunk(c.p) {
					return errEgressLimit
				}
				held += len(c.p)
			}
			switch {
			case errors.Is(c.err, io.EOF):
				complete = true
				break holding
			case c.err != nil:
				readErr = c.err
				break holding
			}
			chunks.next()
			if held > stackErrorBodyMax {
				break holding
			}
		case <-expired:
			break holding
		}
	}
	body, ok := holder.release(resp.StatusCode, resp.Header, complete)
	if !ok {
		return errEgressLimit
	}
	copyHeader(rec.Header(), resp.Header)
	rec.WriteHeader(resp.StatusCode)
	controller := http.NewResponseController(rec)
	// The head goes first, alone, as forward sends it: net/http would sniff a Content-Type onto an untyped
	// answer whose first write carried bytes (D126: the vendor's headers reach the relay as they are).
	if code := writeObserved(rec, controller, obs, nil); code != "" {
		return code
	}
	if code := writeObserved(rec, controller, obs, body); code != "" {
		return code
	}
	// The rest ends as forward's loop does: at the vendor's EOF, or once the declared length is written
	// (declaredLengthWritten says why the EOF cannot be waited for).
	written := int64(len(body))
	switch {
	case complete || declaredLengthWritten(resp, written):
		return ""
	case readErr != nil:
		return errResponseRead
	}
	for {
		c := <-chunks.out
		if code := writeObserved(rec, controller, obs, c.p); code != "" {
			return code
		}
		written += int64(len(c.p))
		if errors.Is(c.err, io.EOF) || declaredLengthWritten(resp, written) {
			return ""
		}
		if c.err != nil {
			return errResponseRead
		}
		chunks.next()
	}
}

// writeObserved is one chunk of forward's loop: observed, written and flushed (an empty chunk flushes the head).
func writeObserved(rec *responseRecorder, controller *http.ResponseController, obs upstreamObserver, p []byte) string {
	if len(p) > 0 {
		if !obs.chunk(p) {
			return errEgressLimit
		}
		if _, err := rec.Write(p); err != nil {
			return errClientWrite
		}
	}
	if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return errClientWrite
	}
	return ""
}

// chunkReader reads a body on its own goroutine, one chunk at a time, so a hold can stop waiting without ending
// the read: out carries each chunk (its bytes valid until next is called) and the read's error; the reader waits
// for next before it reads again, and returns after an error or once stop is called.
type chunkReader struct {
	out  chan readChunk
	more chan struct{}
	done chan struct{}
	once sync.Once
}

type readChunk struct {
	p   []byte
	err error
}

func readChunks(body io.Reader) *chunkReader {
	r := &chunkReader{out: make(chan readChunk), more: make(chan struct{}), done: make(chan struct{})}
	go func() {
		buffer := make([]byte, forwardBufferBytes)
		for {
			n, err := body.Read(buffer)
			select {
			case r.out <- readChunk{p: buffer[:n], err: err}:
			case <-r.done:
				return
			}
			if err != nil {
				return
			}
			select {
			case <-r.more:
			case <-r.done:
				return
			}
		}
	}()
	return r
}

// next lets the reader reuse its buffer and read on; only after a chunk without an error.
func (r *chunkReader) next() {
	select {
	case r.more <- struct{}{}:
	case <-r.done:
	}
}

func (r *chunkReader) stop() { r.once.Do(func() { close(r.done) }) }
