package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// The vendor tunnel (README "The relay's TLS handshake reaches the vendor"). On the relay listener `CONNECT
// <vendor API host>:443` opens a tunnel in which the relay program makes its own TLS handshake for that host, as it
// would through any HTTPS proxy; the certificate is a leaf of the Gray CA in the relay's trust bundle (signin_ca.go).
// Egress ends the TLS, keeps the ClientHello (mirror_hello.go), and runs each request inside as the relay call it is
// (stack_relay.go): `POST /v1/messages` to `api.anthropic.com` is the call `POST /anthropic/v1/messages` on the
// listener, with every check of S16. On the outbound leg egress repeats the learned ClientHello, aligns TLS 1.3
// session resumption across the two legs (mirror_sessions.go), replays the HTTP/2 connection preface learned before
// customer requests arrived (mirror_transport.go), and preserves per-request header ordering (mirror_http_tap.go).
//
// No proxy credential: the request names its rid and its account as every relay call does. Inside the tunnel the
// client speaks HTTP/2 when its hello offers `h2` and HTTP/1.1 otherwise, as with any HTTPS server; on HTTP/2 each
// stream is one relay call, and many run at once. The sign-in proxy's tunnels (signin_proxy.go) handle the tunnel's
// TLS, session tickets and HTTP framing the same way.

const (
	routeVendorTunnel    = "/v1/relay/vendor-tunnel"
	errStackHelloRefused = "stack_hello_refused"
	errStackTunnelReady  = "stack_tunnel_not_ready"
	vendorTunnelPort     = "443"
	vendorTunnelIdle     = 90 * time.Second
	vendorTunnelShake    = 10 * time.Second
	// vendorTunnelStreams is an HTTP/2 tunnel's SETTINGS_MAX_CONCURRENT_STREAMS, the calls one tunnel carries at
	// once: the least RFC 9113 6.5.2 recommends ("no smaller than 100"). A client with more opens another tunnel or
	// waits, as its HTTP/2 library does at any server's limit.
	vendorTunnelStreams = 100
	// vendorTunnelWindow is an HTTP/2 tunnel's receive window, the connection's and each stream's: the least net/http
	// takes for a connection (HTTP2Config.MaxReceiveBufferPerConnection, "at least 64KiB"; Go 1.27.2). net/http opens
	// a window again only as a call reads its body, so a tunnel's request bodies wait in it up to this, all streams
	// together; a body's bytes are in the call's own share once read (stack_relay.go).
	vendorTunnelWindow = 64 << 10
	// vendorTunnelFrame is the largest frame an HTTP/2 tunnel reads: SETTINGS_MAX_FRAME_SIZE's least value (RFC 9113
	// 6.5.2), which is also the least net/http takes (HTTP2Config.MaxReadFrameSize).
	vendorTunnelFrame = 16 << 10
	// vendorTunnelHTTP2Bytes is what net/http holds for an HTTP/2 tunnel's connection (Go 1.27.2,
	// net/http/internal/http2 server.go newServerConn): request bodies not yet read, a window; the frame read buffer,
	// one frame and its 9-byte header; the two HPACK tables at their initial size (initialHeaderTableSize, 4,096
	// bytes: egress raises neither limit); and the 4 KiB write buffer (bufWriterPoolBufferSize).
	vendorTunnelHTTP2Bytes = vendorTunnelWindow + vendorTunnelFrame + 9 + 2*4096 + 4<<10
	// vendorTunnelBytes is what a tunnel holds beside its connection's own share (relayConnBytes, the outer CONNECT's):
	// the inner server's buffers for one request (relayConnBytes again: on HTTP/1.1 the tunnel's one call at a time,
	// on HTTP/2 the request head being read); crypto/tls's record buffers, one record each way (16 KiB of content
	// and its 5+256 bytes of framing, RFC 8446 5.2); the kept ClientHello, at most one record; and an HTTP/2
	// connection's buffers, held by every tunnel since the protocol is known only after the handshake; and the tap's
	// records no handler took yet (tapMaxPendingBytes; mirror_http_tap.go).
	vendorTunnelBytes = relayConnBytes + 2*(16384+5+256) + helloMaxBytes + vendorTunnelHTTP2Bytes + tapMaxPendingBytes
	// vendorTunnelStreamBytes is what net/http holds for one call of an HTTP/2 tunnel: a request's head and the
	// response's write buffer, as for a relay connection's one request (relayConnBytes). The call takes it first
	// thing and gives it back when it returns.
	vendorTunnelStreamBytes = relayConnBytes
)

// routeForHost is the route whose vendor host is host, spelled in lower case.
func routeForHost(host string) (route, bool) {
	for _, rt := range routeTable {
		if rt.host == host {
			return rt, true
		}
	}
	return route{}, false
}

// tunnelDomains is every name the Gray CA signs a leaf for: the sign-in hosts and the vendor API hosts.
func tunnelDomains(rows map[string]signInRow) []string {
	seen := map[string]bool{}
	for _, host := range signInDomains(rows) {
		seen[host] = true
	}
	for _, rt := range routeTable {
		seen[rt.host] = true
	}
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// vendorTunnelTarget is the route a CONNECT names, when it names a vendor API host on 443.
func vendorTunnelTarget(r *http.Request) (route, bool) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != vendorTunnelPort {
		return route{}, false
	}
	return routeForHost(host)
}

// serveVendorConnect opens a vendor tunnel.
func (s *server) serveVendorConnect(rec *responseRecorder, r *http.Request, entry *requestLog, rt route) {
	entry.Route = routeVendorTunnel
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	st := s.signIn
	st.mu.Lock()
	ca := st.ca
	st.mu.Unlock()
	if ca == nil {
		refuse(errStackTunnelReady)
		return
	}
	leaf, err := ca.leaf(rt.host, st.clock())
	if err != nil {
		refuse(errStackTunnelReady)
		return
	}
	// The tunnel's share of the budget (S17), until it ends: a relay cannot hold more of egress's memory by opening
	// tunnels than by any other call.
	if !s.stack.budget.take(vendorTunnelBytes) {
		refuse(errEgressLimit)
		return
	}
	conn, buffered, err := http.NewResponseController(rec).Hijack()
	if err != nil {
		s.stack.budget.give(vendorTunnelBytes)
		refuse(errInternal)
		return
	}
	rec.status = http.StatusOK
	_ = conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		s.stack.budget.give(vendorTunnelBytes)
		_ = conn.Close()
		return
	}
	// The tunnel's bytes go back at the connection's first close, before the connection gives its own share back, so
	// a peer that sees the tunnel end finds the budget free.
	held := &tunnelConn{Conn: conn, release: func() { s.stack.budget.give(vendorTunnelBytes) }}
	go func() {
		defer func() { _ = held.Close() }()
		// A fault in the tunnel's handshake or serving ends the tunnel, not the process (the deferred Close runs).
		defer recoverTunnel("vendor")
		s.serveVendorTunnel(&bufferedConn{Conn: held, reader: buffered.Reader}, rt, leaf)
	}()
}

// tunnelProtocols is what a tunnel answers a hello's ALPN offer with, in the server's order: a hello that offers both
// speaks HTTP/2 inside.
var tunnelProtocols = []string{"h2", "http/1.1"}

// tunnelHTTP2Config is a tunnel's HTTP/2 server settings: at most streams calls at once, and the frame size and
// receive windows a tunnel's share counts (vendorTunnelHTTP2Bytes). The handshake is the client's own and egress has
// no opinion on its cipher suite, so the suites RFC 9113 9.2.2 advises against are not a reason to end a tunnel.
func tunnelHTTP2Config(streams int) *http.HTTP2Config {
	return &http.HTTP2Config{
		MaxConcurrentStreams:          streams,
		MaxReadFrameSize:              vendorTunnelFrame,
		MaxReceiveBufferPerConnection: vendorTunnelWindow,
		MaxReceiveBufferPerStream:     vendorTunnelWindow,
		PermitProhibitedCipherSuites:  true,
	}
}

// tunnelConn runs release once, at its first Close, before the connection closes.
type tunnelConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *tunnelConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func (s *server) mirrorBinder() *sessionBinder {
	if s.mirror == nil {
		return nil
	}
	return s.mirror.binder
}

// tunnelHandshake ends the container's TLS for host on conn and returns the learned shape egress repeats for its
// hello (admit: mirror_profiles.go), the synchronized session slot state (mirror_sessions.go), or why there is no
// admitted shape. The hello is admitted in GetConfigForClient before egress answers or checks session resumption, so
// a client whose handshake has completed knows its shape is learned: a warm-up tunnel needs no request. protocols is
// what the caller serves inside, in the server's order of preference.
func tunnelHandshake(conn net.Conn, host string, leaf *tls.Certificate, wait time.Duration, protocols []string, binder *sessionBinder, admit func(*mirroredHello) (*mirroredHello, string)) (*tls.Conn, *mirroredHello, tunnelSessionInfo, string, error) {
	recorder := &helloRecorder{Conn: conn}
	var hello *mirroredHello
	var sessInfo tunnelSessionInfo
	reason := "the ClientHello is incomplete"
	tlsConn := tls.Server(recorder, &tls.Config{
		MinVersion:             tls.VersionTLS12,
		NextProtos:             protocols,
		SessionTicketsDisabled: true,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			// The name the client checks must be the CONNECT's host.
			if info.ServerName != "" && strings.ToLower(info.ServerName) != host {
				return nil, errors.New("server name differs from the CONNECT host")
			}
			// crypto/tls has read the whole ClientHello by now, before checking PSK resumption or sending ServerHello.
			var raw []byte
			if raw, reason = recorder.hello(); reason == "" {
				if hello, reason = newMirroredHello(raw); hello != nil {
					hello, reason = admit(hello)
				}
			}
			child := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				NextProtos:   protocols,
				Certificates: []tls.Certificate{*leaf},
			}
			if hello == nil || !hello.resumes || binder == nil {
				child.SessionTicketsDisabled = true
				return child, nil
			}
			binder.configureServerTLS(child, host, &sessInfo)
			return child, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = tlsConn.Close()
		return nil, nil, tunnelSessionInfo{}, "", err
	}
	if hello != nil && hello.profiles != nil && hello.profiles.learning() {
		recorder.observe(recordSizeObserver(hello))
	}
	return tlsConn, hello, sessInfo, reason, nil
}

// serveVendorTunnel serves the relay calls of one tunnel until the client closes or goes idle.
func (s *server) serveVendorTunnel(conn net.Conn, rt route, leaf *tls.Certificate) {
	tlsConn, hello, sessInfo, reason, err := tunnelHandshake(conn, rt.host, leaf, vendorTunnelShake, tunnelProtocols, s.mirrorBinder(), func(h *mirroredHello) (*mirroredHello, string) {
		return s.profiles.admitFor(h, false)
	})
	if err != nil {
		return
	}
	var innerConn net.Conn = tlsConn
	var h2Tap *h2TapConn
	var h1Tap *h1TapConn
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h2Tap = newH2TapConn(tlsConn, func(p *h2Preface) {
			s.profiles.recordH2Preface(hello, p)
		})
		h2Tap.signals = &s.mirrorSignals
		innerConn = h2Tap
	} else {
		h1Tap = newH1TapConn(tlsConn)
		h1Tap.signals = &s.mirrorSignals
		innerConn = h1Tap
	}
	done := make(chan struct{})
	var once sync.Once
	inner := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var meta *wireRequestMeta
		if h2Tap != nil {
			meta = h2Tap.take(r)
		} else if h1Tap != nil {
			meta = h1Tap.takeFor(r)
		}
		s.mirrorSignals.wireMeta(meta)
		ctx := withTunnelSession(r.Context(), sessInfo)
		if meta != nil {
			ctx = context.WithValue(ctx, wireMetaKey{}, meta)
		}
		r = r.WithContext(ctx)
		s.handled(w, r, func(rec *responseRecorder, r *http.Request, entry *requestLog) {
			s.vendorTunnelCall(rec, r, entry, rt, hello, reason)
		})
	}))
	inner.MaxHeaderBytes = relayMaxHeaderBytes
	inner.IdleTimeout = vendorTunnelIdle
	// HTTP/2 when the handshake chose it (net/http serves it on a connection whose TLS state negotiated h2), within
	// what the tunnel's share of the budget counts.
	inner.HTTP2 = tunnelHTTP2Config(vendorTunnelStreams)
	inner.ErrorLog = log.New(io.Discard, "", 0)
	inner.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			once.Do(func() { close(done) })
		}
	}
	_ = inner.Serve(&oneConnListener{conn: innerConn, done: done})
}

// recordObserveRecords is how many application-data records of a tunnel recordSizeObserver reads at most: the
// first records of a connection are where dynamic record sizing shows, and the scan ends after them.
const recordObserveRecords = 8

// recordDynamicStep is a dynamically sized record's growth: Go's crypto/tls (and so uTLS) writes its n-th
// application-data record of a connection with at most n times a TCP segment estimate of plaintext (1,208 bytes,
// conn.go maxPayloadSizeForWrite), plus the record's own overhead (recordDynamicSlack: AEAD tag, content type and
// header, with room for a CBC suite's padding and MAC).
const (
	recordDynamicStep  = 1208
	recordDynamicSlack = 64
)

// recordFullSize is the largest first record a dynamically sizing client writes (recordDynamicStep and its slack).
const recordFullSize = recordDynamicStep + recordDynamicSlack

// recordSizeObserver watches a learning tunnel's first application-data records (their length only): the n-th one
// longer than a dynamically sized n-th record can be marks the client as writing full records
// (mirroredHello.fullRecords). TLS 1.3's encrypted Finished is application data on the wire and small; it is counted
// as the first.
func recordSizeObserver(hello *mirroredHello) func(byte, int) bool {
	seen := 0
	return func(contentType byte, length int) bool {
		if contentType != 23 { // application_data
			return true
		}
		seen++
		if length > seen*recordDynamicStep+recordDynamicSlack {
			hello.profiles.noteFullRecords(hello)
			return false
		}
		return seen < recordObserveRecords
	}
}

// recoverTunnel ends a tunnel's goroutine that panicked instead of the process; the caller's deferred Close ends the
// connection. net/http recovers its handlers' panics, not this goroutine's (the handshake, the taps' setup).
func recoverTunnel(kind string) {
	if r := recover(); r != nil {
		log.Printf("egress: a %s tunnel ended after a fault: %v", kind, r)
	}
}

// writeHelloRefusal names what egress cannot repeat of the tunnel's ClientHello; nothing of the hello's bytes.
func writeHelloRefusal(w http.ResponseWriter, reason string) {
	writeError(w, http.StatusUnprocessableEntity, errorBody{Error: errStackHelloRefused, Detail: reason})
}

// vendorTunnelCall is one request inside a vendor tunnel: the relay call it spells, with the tunnel's hello.
func (s *server) vendorTunnelCall(rec *responseRecorder, r *http.Request, entry *requestLog, rt route, hello *mirroredHello, reason string) {
	entry.Route = rt.name
	// An HTTP/2 tunnel carries many calls at once, and each holds a request of its own in net/http.
	if r.ProtoMajor == 2 {
		if !s.stack.budget.take(vendorTunnelStreamBytes) {
			entry.Error = errEgressLimit
			writeRefusal(rec, errEgressLimit)
			return
		}
		defer s.stack.budget.give(vendorTunnelStreamBytes)
	}
	if hello == nil {
		entry.Error = errStackHelloRefused
		writeHelloRefusal(rec, reason)
		return
	}
	if !hello.usable() {
		entry.Error = errStackHelloRefused
		writeHelloRefusal(rec, hello.unusableReason())
		return
	}
	// The request is for the tunnel's host, in origin form; the relay listener's own paths are not in a tunnel.
	if !hostMatches(r, rt) && !strings.EqualFold(r.Host, net.JoinHostPort(rt.host, vendorTunnelPort)) {
		entry.Error = errHostRefused
		writeRefusal(rec, errHostRefused)
		return
	}
	if r.Method == http.MethodConnect || r.URL == nil || !strings.HasPrefix(r.RequestURI, "/") {
		entry.Error = errTargetRefused
		writeRefusal(rec, errTargetRefused)
		return
	}
	// The call as the plain listener spells it: the route's name, then the vendor's path.
	r.RequestURI = rt.name + r.RequestURI
	r.URL.Path = rt.name + r.URL.Path
	if r.URL.RawPath != "" {
		r.URL.RawPath = rt.name + r.URL.RawPath
	}
	s.relayCall(rec, r.WithContext(context.WithValue(r.Context(), mirrorHelloKey{}, hello)), entry)
}
