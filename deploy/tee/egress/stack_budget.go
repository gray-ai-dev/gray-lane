package main

import (
	"container/list"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// stackBudget is -stack-max-bytes (S17): one bound on every byte egress holds on the relay-stack path, so a
// relay or a vendor answer cannot grow egress, a Gray process, until it is killed. Each holder takes bytes
// before it holds them and gives them back when it lets them go:
//
//   - a registration: its decoded body, rewrite spec and protocol, until the rid ends;
//   - a relay connection: what net/http holds for it at most (relayConnBytes), until it closes;
//   - a relay call: egress's copy of its headers, forward's copy buffer, a direct call's HTTP/2 receive
//     window (relayStreamWindow) and its body as it is read, until the call returns;
//   - an attempt: the vendor's response headers, the held answer (a non-stream body or an error body, by
//     capacity, as bytes arrive) and the SSE digester's buffers (stackEventDigester.Held), until it ends;
//   - a feed: every record line queued for the entry, until the entry's GET has written it or the feed is
//     dropped.
//
// A debug copy of a forwarded body (stackRequest.recordForwarded) is held at a lower rank (stackSpare): only in
// bytes no other holder needs, and a take that does not fit takes them back first, oldest first, so an optional
// copy never makes a call fail that would have gone through without it.
//
// What stays outside it (copies inside one function call, kernel socket buffers, the runtime) is in README
// "Memory budget", with what bounds each.
type stackBudget struct {
	max  atomic.Int64 // read on every accept and call; set once by newStack (a test may lower it)
	used atomic.Int64

	// spares are the debug copies held, oldest first, and spareBytes their bytes (within used). spareMu guards
	// them and every copy's state; it is taken after a request's mu, never before.
	spareMu    sync.Mutex
	spares     list.List
	spareBytes int64
}

// take holds n more bytes if they fit, taking back debug copies when only their bytes are in the way; false leaves
// the budget as it was (and every copy held).
func (b *stackBudget) take(n int64) bool {
	if b.tryTake(n) {
		return true
	}
	b.spareMu.Lock()
	defer b.spareMu.Unlock()
	if b.used.Load()-b.spareBytes+n > b.max.Load() {
		return false
	}
	for {
		if b.tryTake(n) {
			return true
		}
		oldest := b.spares.Front()
		if oldest == nil {
			return false
		}
		b.dropSpareLocked(oldest.Value.(*stackSpare))
	}
}

// tryTake holds n more bytes if they fit as the budget stands.
func (b *stackBudget) tryTake(n int64) bool {
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

// stackSpare is one debug copy's feed line in the budget: held until the feed's reader claims it to write it, the
// feed drops it, or a take needs its bytes.
type stackSpare struct {
	line []byte
	size int64
	elem *list.Element // in the budget's spares while held; nil after
}

// takeSpare holds line as a debug copy if it fits without taking anything back; nil when it does not.
func (b *stackBudget) takeSpare(line []byte) *stackSpare {
	size := int64(cap(line))
	b.spareMu.Lock()
	defer b.spareMu.Unlock()
	if !b.tryTake(size) {
		return nil
	}
	spare := &stackSpare{line: line, size: size}
	spare.elem = b.spares.PushBack(spare)
	b.spareBytes += size
	return spare
}

// claimSpare hands a held copy's line to the feed's reader, whose bytes it then gives back once written; nil when
// the budget took the copy back.
func (b *stackBudget) claimSpare(spare *stackSpare) ([]byte, int64) {
	b.spareMu.Lock()
	defer b.spareMu.Unlock()
	if spare.elem == nil {
		return nil, 0
	}
	line, size := spare.line, spare.size
	b.spares.Remove(spare.elem)
	b.spareBytes -= size
	spare.elem, spare.line = nil, nil
	return line, size
}

// releaseSpare gives back a copy nobody will write (a dropped feed); nothing when it is no longer held.
func (b *stackBudget) releaseSpare(spare *stackSpare) {
	b.spareMu.Lock()
	defer b.spareMu.Unlock()
	if spare.elem != nil {
		b.dropSpareLocked(spare)
	}
}

func (b *stackBudget) dropSpareLocked(spare *stackSpare) {
	b.spares.Remove(spare.elem)
	b.spareBytes -= spare.size
	spare.elem, spare.line = nil, nil
	b.give(spare.size)
}

// force holds n bytes whether or not they fit: only for the few small records that must reach the entry
// (`end`, `done`, a refusal without its path). A later take fails while the budget is over.
func (b *stackBudget) force(n int64) { b.used.Add(n) }

func (b *stackBudget) give(n int64) { b.used.Add(-n) }

// stackHold is one holder's share of the budget, so it can grow, shrink to what it still holds, and give
// everything back once. It belongs to one goroutine.
type stackHold struct {
	budget *stackBudget
	bytes  int64
}

func (h *stackHold) grow(n int64) bool {
	if n <= 0 {
		return true
	}
	if !h.budget.take(n) {
		return false
	}
	h.bytes += n
	return true
}

func (h *stackHold) shrink(n int64) {
	n = min(n, h.bytes)
	h.budget.give(n)
	h.bytes -= n
}

func (h *stackHold) free() { h.shrink(h.bytes) }

var errStackBudget = errors.New("egress stack budget exceeded")

// readHeldBody reads a relay call's body under the budget: a declared length is taken whole before the
// read, a chunked body as its buffer grows (doubling, or exactly what is needed when doubling does not
// fit). The buffer's capacity is what the hold covers. The errors are readRequestBody's, plus
// errStackBudget.
func readHeldBody(r *http.Request, max int64, hold *stackHold) ([]byte, int64, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, 0, nil
	}
	if r.ContentLength > max {
		return nil, 0, errBodyTooLargeRequest
	}
	if r.ContentLength > 0 {
		if !hold.grow(r.ContentLength) {
			return nil, 0, errStackBudget
		}
		body := make([]byte, r.ContentLength)
		n, err := io.ReadFull(r.Body, body)
		return body[:n], int64(n), err
	}
	var body []byte
	chunk := make([]byte, 32*1024)
	for {
		n, err := r.Body.Read(chunk)
		if int64(len(body)+n) > max {
			return body, int64(len(body) + n), errBodyTooLargeRequest
		}
		if n > 0 {
			var ok bool
			if body, ok = growHeld(body, n, max, hold); !ok {
				return body, int64(len(body)), errStackBudget
			}
			body = append(body, chunk[:n]...)
		}
		if errors.Is(err, io.EOF) {
			return body, int64(len(body)), nil
		}
		if err != nil {
			return body, int64(len(body)), err
		}
	}
}

// growHeld makes room for n more bytes in held, taking the added capacity from hold first: double the
// capacity (at most limit), or only what is needed when the doubled size does not fit the budget. The old
// array is garbage once copied.
func growHeld(held []byte, n int, limit int64, hold *stackHold) ([]byte, bool) {
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

// headerBytes is the size of a header block's names and values, the bytes a copy of it holds.
func headerBytes(h http.Header) int64 {
	var n int64
	for name, values := range h {
		for _, value := range values {
			n += int64(len(name) + len(value))
		}
	}
	return n
}

// relayMaxHeaderBytes is the relay listener's MaxHeaderBytes: the request line and header block of the largest
// call a vendor accepts. The three vendor hosts are behind Cloudflare (each answers with `server: cloudflare` and
// a `cf-ray`, checked 2026-10-29), whose limits are 16 KB for a URL and 128 KB for all request headers
// (developers.cloudflare.com/fundamentals/reference/connection-limits, "Request limits"), taken here as KiB; a
// larger call cannot reach a vendor. The unix socket keeps net/http's default (1 MiB): only the entry, Gray's
// own code, writes to it.
const relayMaxHeaderBytes = (16 + 128) << 10

// relayConnBytes is the most net/http holds for one relay-listener connection (Go 1.27.2): the request line and
// header block up to relayMaxHeaderBytes and the 4,096 bytes of slop its read limit allows
// (net/http/server.go initialReadLimitSize), the header map's entries at textproto's 200 bytes each
// (net/textproto/reader.go mapEntryOverhead) for at most DefaultMaxHeaderValueCount (500) values, and the
// connection's 4 KiB read and write buffers (server.go newBufioReader at bufio's default size,
// newBufioWriterSize(…, 4<<10)).
const relayConnBytes = relayMaxHeaderBytes + 4096 + http.DefaultMaxHeaderValueCount*200 + 4096 + 4<<10

// relayStreamWindow is a direct relay call's HTTP/2 receive window: Go's own default receive buffer per stream
// for its HTTP/2 server, 1 MiB (net/http/internal/http2/config.go setConfigDefaults; a client's default is 4 MiB
// per stream and 1 GiB per connection). The transport opens the window again only as egress reads
// (transportResponseBody.Read) and refuses DATA beyond it, so a relay that reads slowly leaves at most this much
// vendor data per call in the transport; a round trip still carries 1 MiB, far above a token stream.
const relayStreamWindow = 1 << 20

// relayHTTP2Config is the direct relay transport's HTTP/2 settings. Each call takes its stream window from the
// budget, so the streams of one connection never buffer more than the budget together; the connection window
// is the budget, so it never binds first and one slow stream cannot stall the connection's others.
func relayHTTP2Config(cfg config) *http.HTTP2Config {
	return &http.HTTP2Config{MaxReceiveBufferPerStream: relayStreamWindow, MaxReceiveBufferPerConnection: int(cfg.stackMaxBytes)}
}

// relayCallBytes is what a relay call holds in the transport and in forward besides its headers and body:
// forward's copy buffer and, on an HTTP/2 vendor connection, its stream's receive window (window; 0 on HTTP/1.1,
// whose backlog sits in the kernel's socket buffer, README "Memory budget").
func relayCallBytes(window int64) int64 {
	return forwardBufferBytes + window
}

// holdConnections takes relayConnBytes from the budget for each accepted relay connection until it closes. A
// connection the budget cannot hold is closed at once: to the relay it is a connection that failed before egress
// answered, which it may retry (S21a).
func (st *stack) holdConnections(l net.Listener) net.Listener {
	return &heldListener{Listener: l, stack: st}
}

type heldListener struct {
	net.Listener
	stack *stack
}

func (l *heldListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.stack.budget.take(relayConnBytes) {
			l.stack.relayConns.Add(1)
			return &heldConn{Conn: conn, stack: l.stack}, nil
		}
		_ = conn.Close()
	}
}

// heldConn gives its bytes back when net/http closes it (net/http has put the connection's buffers back by
// then), before the close itself, so a peer that sees the connection end finds the bytes back. It keeps
// CloseWrite, which net/http uses to end a refused request without resetting the connection.
type heldConn struct {
	net.Conn
	stack *stack
	once  sync.Once
}

func (c *heldConn) Close() error {
	c.once.Do(func() {
		c.stack.budget.give(relayConnBytes)
		c.stack.relayConns.Add(-1)
		if closed := c.stack.relayConnClosed; closed != nil {
			closed()
		}
	})
	return c.Conn.Close()
}

func (c *heldConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
