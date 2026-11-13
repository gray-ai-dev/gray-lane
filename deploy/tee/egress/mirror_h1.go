package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Outbound HTTP/1.1 client transport for mirrored vendor connections. It writes the request line and header fields
// itself, in the wire order and field-name casing captured on the relay container's tunnel connection
// (mirror_http_tap.go, buildOrderedHeaders), and leaves the response to the standard library (http.ReadResponse).
// Connections come only from dial (mirror_dial.go): there is no fallback dialer.

// mirrorH1MaxIdle bounds the idle connections one pool entry keeps.
const mirrorH1MaxIdle = 8

// mirrorH1MaxResponseHeaderBytes bounds a response's status line and header fields, as net/http.Transport's
// MaxResponseHeaderBytes default (10 MiB) bounded the transport before.
const mirrorH1MaxResponseHeaderBytes = 10 << 20

// mirrorH1Client is one pool entry's HTTP/1.1 transport.
type mirrorH1Client struct {
	cfg  config
	dial func(ctx context.Context) (net.Conn, error)

	mu   sync.Mutex
	idle []*mirrorH1Conn
	// retired: a connection that goes idle closes instead (Retire).
	retired bool
}

type mirrorH1Conn struct {
	conn      net.Conn
	lr        *mirrorH1LimitReader
	br        *bufio.Reader
	bw        *bufio.Writer
	idleTimer *time.Timer
	closed    bool
}

// mirrorH1LimitReader limits what the response reader may take from the connection while a response head is read
// (net/http's persistConn does the same around its own reader).
type mirrorH1LimitReader struct {
	r      io.Reader
	remain int64 // < 0: no limit
}

func (l *mirrorH1LimitReader) Read(p []byte) (int, error) {
	if l.remain == 0 {
		return 0, errMirrorH1HeaderTooLarge
	}
	if l.remain > 0 && int64(len(p)) > l.remain {
		p = p[:l.remain]
	}
	n, err := l.r.Read(p)
	if l.remain > 0 {
		l.remain -= int64(n)
	}
	return n, err
}

var errMirrorH1HeaderTooLarge = fmt.Errorf("mirror h1: response header larger than %d bytes", mirrorH1MaxResponseHeaderBytes)

func newMirrorH1Client(cfg config, dial func(ctx context.Context) (net.Conn, error)) *mirrorH1Client {
	return &mirrorH1Client{cfg: cfg, dial: dial}
}

func (t *mirrorH1Client) takeIdle() *mirrorH1Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.idle) > 0 {
		n := len(t.idle) - 1
		c := t.idle[n]
		t.idle[n] = nil
		t.idle = t.idle[:n]
		if c.idleTimer != nil {
			c.idleTimer.Stop()
			c.idleTimer = nil
		}
		if !c.closed {
			return c
		}
	}
	return nil
}

func (t *mirrorH1Client) putIdle(c *mirrorH1Conn) {
	t.mu.Lock()
	if c.closed || t.retired || len(t.idle) >= mirrorH1MaxIdle {
		c.closed = true
		t.mu.Unlock()
		_ = c.conn.Close()
		return
	}
	if t.cfg.idleConnTimeout > 0 {
		c.idleTimer = time.AfterFunc(t.cfg.idleConnTimeout, func() {
			t.evictIdle(c)
		})
	}
	t.idle = append(t.idle, c)
	t.mu.Unlock()
}

func (t *mirrorH1Client) evictIdle(target *mirrorH1Conn) {
	t.mu.Lock()
	found := false
	for i, c := range t.idle {
		if c == target {
			t.idle = append(t.idle[:i], t.idle[i+1:]...)
			c.closed = true
			c.idleTimer = nil
			found = true
			break
		}
	}
	t.mu.Unlock()
	if found {
		_ = target.conn.Close()
	}
}

// Retire closes the idle connections now and each busy one as its call ends.
func (t *mirrorH1Client) Retire() {
	t.mu.Lock()
	t.retired = true
	t.mu.Unlock()
	t.CloseIdleConnections()
}

func (t *mirrorH1Client) CloseIdleConnections() {
	t.mu.Lock()
	conns := t.idle
	t.idle = nil
	for _, c := range conns {
		c.closed = true
		if c.idleTimer != nil {
			c.idleTimer.Stop()
			c.idleTimer = nil
		}
	}
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.conn.Close()
	}
}

func canReplayRequest(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// RoundTrip sends req on an idle connection or a new one. A request that failed on a reused connection (the vendor
// may have closed it while idle) is sent once more on a new connection when its body can be replayed.
func (t *mirrorH1Client) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.dial == nil {
		return nil, errMirrorNoDial
	}
	ctx := req.Context()
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req = req.Clone(ctx)
			req.Body = body
		}

		var c *mirrorH1Conn
		reused := false
		if attempt == 0 {
			if idle := t.takeIdle(); idle != nil {
				c = idle
				reused = true
			}
		}
		if c == nil {
			raw, err := t.dial(ctx)
			if err != nil {
				return nil, err
			}
			lr := &mirrorH1LimitReader{r: raw, remain: -1}
			c = &mirrorH1Conn{
				conn: raw,
				lr:   lr,
				br:   bufio.NewReaderSize(lr, 16<<10),
				bw:   bufio.NewWriterSize(raw, 16<<10),
			}
		}

		if trace := httptrace.ContextClientTrace(ctx); trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: c.conn, Reused: reused})
		}

		resp, err := t.roundTripConn(req, c)
		if err == nil {
			return resp, nil
		}
		if !reused || ctx.Err() != nil || !canReplayRequest(req) {
			return nil, err
		}
	}
	return nil, errors.New("mirror h1: connection unavailable")
}

func (t *mirrorH1Client) roundTripConn(req *http.Request, c *mirrorH1Conn) (*http.Response, error) {
	ctx := req.Context()
	stopCancel := context.AfterFunc(ctx, func() { _ = c.conn.Close() })

	closeAfter, err := writeOrderedH1Request(req, c.bw)
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{Err: err})
	}
	if err != nil {
		stopCancel()
		_ = c.conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	var timedOut atomic.Bool
	var respTimer *time.Timer
	if t.cfg.responseHeaderTimeout > 0 {
		respTimer = time.AfterFunc(t.cfg.responseHeaderTimeout, func() {
			timedOut.Store(true)
			_ = c.conn.Close()
		})
	}
	resp, err := readMirrorH1Response(c, req, trace)
	if respTimer != nil {
		respTimer.Stop()
	}
	stopCancel()
	if err != nil {
		_ = c.conn.Close()
		if timedOut.Load() {
			return nil, context.DeadlineExceeded
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	keepAlive := !resp.Close && !req.Close && !closeAfter && resp.ProtoAtLeast(1, 1)
	if resp.Body == nil || resp.Body == http.NoBody {
		if keepAlive {
			t.putIdle(c)
		} else {
			_ = c.conn.Close()
		}
		return resp, nil
	}

	body := &mirrorH1Body{
		rc:        resp.Body,
		t:         t,
		c:         c,
		keepAlive: keepAlive,
	}
	body.stopCtx = context.AfterFunc(ctx, func() {
		body.canceled.Store(true)
		_ = c.conn.Close()
	})
	resp.Body = body
	return resp, nil
}

// readMirrorH1Response reads the final response to req, skipping informational (1xx) responses as net/http does,
// with the response heads together bounded by mirrorH1MaxResponseHeaderBytes.
func readMirrorH1Response(c *mirrorH1Conn, req *http.Request, trace *httptrace.ClientTrace) (*http.Response, error) {
	c.lr.remain = mirrorH1MaxResponseHeaderBytes
	defer func() { c.lr.remain = -1 }()
	first := true
	for {
		if first && trace != nil && trace.GotFirstResponseByte != nil {
			if _, err := c.br.Peek(1); err == nil {
				trace.GotFirstResponseByte()
			}
		}
		first = false
		resp, err := http.ReadResponse(c.br, req)
		if err != nil {
			return nil, err
		}
		// 101 Switching Protocols is final; egress never asks for an upgrade, so the caller sees it as is.
		if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			// The head is read; the body (bufio's buffered part and the rest) is not bounded by the header limit.
			return resp, nil
		}
		if trace != nil && trace.Got1xxResponse != nil {
			if err := trace.Got1xxResponse(resp.StatusCode, map[string][]string(resp.Header)); err != nil {
				return nil, err
			}
		}
	}
}

// writeOrderedH1Request writes req's head and body; closeAfter is a Connection: close in its head, after whose
// response the connection is not used again.
func writeOrderedH1Request(req *http.Request, bw *bufio.Writer) (closeAfter bool, err error) {
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", req.Method, uri); err != nil {
		return false, err
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	wire := wireMetaOf(req.Context())
	headers := buildOrderedHeaders(req, wire, host, false)

	hasBody := req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
	// The body is chunked when the client's was (buildOrderedHeaders put Transfer-Encoding in the set, where the
	// client had it) or its length is unknown (the field then goes last).
	wireChunked := false
	for _, h := range headers {
		switch http.CanonicalHeaderKey(h.name) {
		case "Transfer-Encoding":
			wireChunked = true
		case "Connection":
			closeAfter = strings.EqualFold(h.value, "close")
		}
	}
	chunked := wireChunked || (hasBody && req.ContentLength < 0)

	for _, h := range headers {
		if chunked && http.CanonicalHeaderKey(h.name) == "Content-Length" {
			continue
		}
		if _, err := fmt.Fprintf(bw, "%s: %s\r\n", h.name, h.value); err != nil {
			return closeAfter, err
		}
	}
	if chunked && !wireChunked {
		if _, err := bw.WriteString("Transfer-Encoding: chunked\r\n"); err != nil {
			return closeAfter, err
		}
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return closeAfter, err
	}
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}

	switch {
	case chunked:
		// httputil's chunked writer frames each Write as one chunk; Close writes the last chunk, and the empty
		// trailer section ends the body (an empty chunked body is that alone).
		cw := httputil.NewChunkedWriter(bw)
		if req.Body != nil {
			_, err = io.Copy(cw, req.Body)
			_ = req.Body.Close()
		}
		if err == nil {
			if err = cw.Close(); err == nil {
				_, err = bw.WriteString("\r\n")
			}
		}
	case hasBody:
		_, err = io.Copy(bw, req.Body)
		_ = req.Body.Close()
	case req.Body != nil:
		_ = req.Body.Close()
	}
	if err != nil {
		return closeAfter, err
	}
	return closeAfter, bw.Flush()
}

type mirrorH1Body struct {
	rc        io.ReadCloser
	t         *mirrorH1Client
	c         *mirrorH1Conn
	keepAlive bool
	stopCtx   func() bool
	canceled  atomic.Bool
	once      sync.Once
}

func (b *mirrorH1Body) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if errors.Is(err, io.EOF) {
		b.finish(true)
	} else if err != nil {
		b.finish(false)
		if b.canceled.Load() {
			return n, context.Canceled
		}
	}
	return n, err
}

func (b *mirrorH1Body) Close() error {
	err := b.rc.Close()
	b.finish(false)
	return err
}

func (b *mirrorH1Body) finish(sawEOF bool) {
	b.once.Do(func() {
		if b.stopCtx != nil {
			b.stopCtx()
		}
		_ = b.rc.Close()
		if sawEOF && b.keepAlive && !b.canceled.Load() {
			b.t.putIdle(b.c)
		} else {
			_ = b.c.conn.Close()
		}
	})
}
