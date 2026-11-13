package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The sign-in proxy (docs/design/relay-sign-in-in-vm.md §3.1, D2, D3, D10). The relay listener (10.231.11.2:8080)
// answers `CONNECT <host>:443` with the account's proxy handle as the Basic username (`Proxy-Authorization: Basic`; the
// lane makes the handle, `PUT /v1/stack/ops/sign-in-proxy`; there is no password, D3). It
// opens a tunnel only to a sign-in host of the account vendor's row, ends TLS there with a leaf from the Gray sign-in
// CA (signin_ca.go), speaks HTTP/2 or HTTP/1.1 inside as the hello's ALPN offer allows (as a vendor tunnel does,
// mirror_tunnel.go; the owner's decision of 2026-11-12, which replaces D10's HTTP/1.1 only), and runs each request
// inside, on HTTP/2 each stream, through the sign-in route's own checks and call
// (stack_login.go loginCall): the row's exact calls (and a password account's sign-in steps), no address but the
// sealed one, no `X-Gray-Request`, no `x-gray-*` header, the body bound, GET or POST, the account's own outbound proxy,
// no redirect followed; plus the session rules (signin_session.go).
// Inference never goes this way: the rows hold no inference path.

const (
	routeSignInProxyCall = "/v1/relay/sign-in-proxy"
	// signInTunnelsMax bounds the open tunnels (each holds a TLS connection, its HTTP/1.1 buffers, about 100 KiB, and
	// an HTTP/2 connection's, vendorTunnelHTTP2Bytes, about 92 KiB); calls in them are bounded again by
	// loginInFlightMax.
	signInTunnelsMax = 32
	// signInTunnelStreams is an HTTP/2 sign-in tunnel's SETTINGS_MAX_CONCURRENT_STREAMS. A tunnel is one account's and
	// an account signs in one call at a time (stack_login.go), so four leaves room for a client that overlaps a
	// step's calls, and no tunnel alone takes the loginInFlightMax calls egress runs at once.
	signInTunnelStreams   = 4
	signInTunnelIdle      = 90 * time.Second
	signInHandshakeCap    = 10 * time.Second
	errLoginProxyAuth     = "login_proxy_auth"
	signInProxyAuthRealm  = `Basic realm="gray-sign-in"`
	signInConnectHostPort = "443"
)

// serveSignInConnect is a CONNECT on the relay listener.
func (s *server) serveSignInConnect(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = routeSignInProxyCall
	st := s.signIn
	refuse := func(code string) {
		entry.Error = code
		writeLoginRefusal(rec, code, "")
	}
	accountID, ok := st.authenticate(r.Header.Get("Proxy-Authorization"))
	if !ok {
		entry.Error = errLoginProxyAuth
		rec.Header().Set("Proxy-Authenticate", signInProxyAuthRealm)
		writeError(rec, http.StatusProxyAuthRequired, errorBody{Error: errLoginProxyAuth})
		return
	}
	// On CONNECT a host outside the row is 403 (§3.1); inside a tunnel it is 400 login_host_refused.
	refuseHost := func() {
		entry.Error = errLoginHostRefused
		writeError(rec, http.StatusForbidden, errorBody{Error: errLoginHostRefused})
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != signInConnectHostPort || host != strings.ToLower(host) {
		refuseHost()
		return
	}
	o := s.ops
	o.mu.Lock()
	account := o.accounts[accountID]
	vendor := ""
	if account != nil && subscriptionAccount(account) {
		vendor = account.vendor
	}
	password := account != nil && account.login != nil
	held := o.hold
	o.mu.Unlock()
	if vendor == "" {
		refuse(errLoginAccountUnknown)
		return
	}
	if held {
		refuse(errLoginHeld)
		return
	}
	// A host of the row's calls; for a password account also one of its sign-in steps' (signin_rows.go).
	if !signInRows[vendor].tunnelHost(host, password) {
		refuseHost()
		return
	}
	st.mu.Lock()
	ca := st.ca
	st.mu.Unlock()
	if ca == nil {
		refuse(errLoginProxyReady)
		return
	}
	leaf, err := ca.leaf(host, st.clock())
	if err != nil {
		refuse(errLoginProxyReady)
		return
	}
	if st.tunnels.Add(1) > signInTunnelsMax {
		st.tunnels.Add(-1)
		refuse(errLoginBusy)
		return
	}
	conn, buffered, err := http.NewResponseController(rec).Hijack()
	if err != nil {
		st.tunnels.Add(-1)
		refuse(errInternal)
		return
	}
	rec.status = http.StatusOK
	_ = conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		st.tunnels.Add(-1)
		_ = conn.Close()
		return
	}
	go func() {
		defer st.tunnels.Add(-1)
		defer func() { _ = conn.Close() }()
		defer recoverTunnel("sign-in")
		s.serveTunnel(&bufferedConn{Conn: conn, reader: buffered.Reader}, host, accountID, vendor, password, leaf)
	}()
}

// authenticate maps a Basic proxy credential's username, the account's handle, to its account; a password is ignored.
func (st *signInState) authenticate(header string) (string, bool) {
	username, _, ok := (&http.Request{Header: http.Header{"Authorization": {header}}}).BasicAuth()
	if !ok || header == "" {
		return "", false
	}
	st.mu.Lock()
	handle, known := st.handles[username]
	st.mu.Unlock()
	if !known {
		return "", false
	}
	return handle.account, true
}

// bufferedConn reads first what the CONNECT's reader already buffered (a client that sent its ClientHello at once).
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// serveTunnel ends TLS for host and serves the requests inside, over HTTP/2 or HTTP/1.1 as the handshake chose, until
// the client closes or goes idle.
func (s *server) serveTunnel(conn net.Conn, host, accountID, vendor string, password bool, leaf *tls.Certificate) {
	// The sign-in calls reach the vendor with the container's own handshake, session state and HTTP framing, as relay
	// calls in a vendor tunnel do (mirror_tunnel.go).
	tlsConn, hello, sessInfo, reason, err := tunnelHandshake(conn, host, leaf, signInHandshakeCap, tunnelProtocols, s.mirrorBinder(), func(h *mirroredHello) (*mirroredHello, string) {
		return s.profiles.admitFor(h, true)
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
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				if hello == nil {
					entry.Route, entry.Error = routeSignInProxyCall, errStackHelloRefused
					writeHelloRefusal(rec, reason)
					return
				}
				s.tunnelCall(rec, r.WithContext(context.WithValue(r.Context(), mirrorHelloKey{}, hello)), entry, host, accountID, vendor, password)
			})
		}),
		// A sign-in call is a few KiB: a tunnel that sends nothing gives its slot back within signInTunnelIdle.
		ReadHeaderTimeout: signInTunnelIdle,
		ReadTimeout:       loginCallCap,
		// The longest answer: a token call (loginCallCap) and its wait for the vault (at most maxLoginPersistWait).
		WriteTimeout:   loginCallCap + maxLoginPersistWait + signInHandshakeCap,
		IdleTimeout:    signInTunnelIdle,
		MaxHeaderBytes: relayMaxHeaderBytes,
		// HTTP/2 when the handshake chose it; the timeouts above are then each stream's.
		HTTP2:    tunnelHTTP2Config(signInTunnelStreams),
		ErrorLog: log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				once.Do(func() { close(done) })
			}
		},
	}
	_ = inner.Serve(&oneConnListener{conn: innerConn, done: done})
}

// tunnelCall is one request inside a tunnel: the sign-in route's checks and call, for the tunnel's account and host.
func (s *server) tunnelCall(rec *responseRecorder, r *http.Request, entry *requestLog, host, accountID, vendor string, password bool) {
	entry.Route = routeSignInProxyCall
	refuse := func(code string) {
		entry.Error = code
		writeLoginRefusal(rec, code, "")
	}
	if len(r.Header.Values(stackRequestHeader)) > 0 {
		refuse(errLoginRequestBound)
		return
	}
	// Origin-form only, for the tunnel's own host.
	if r.URL == nil || r.URL.IsAbs() || r.URL.Host != "" || !strings.HasPrefix(r.RequestURI, "/") || strings.Contains(r.RequestURI, "#") {
		refuse(errLoginPathRefused)
		return
	}
	if requestHost := strings.ToLower(r.Host); requestHost != host && requestHost != host+":"+signInConnectHostPort {
		refuse(errLoginHostRefused)
		return
	}
	rawPath := rawPathOf(r)
	if !validRawPath(rawPath) {
		refuse(errLoginPathRefused)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		refuse(errLoginMethodRefused)
		return
	}
	call := &signInCall{srv: s, account: accountID, vendor: vendor, password: password}
	s.ops.loginCall(rec, r.WithContext(context.WithValue(r.Context(), signInCallKey{}, call)), accountID, host, rawPath, entry)
}

// oneConnListener hands one connection to an http.Server, then blocks until that connection is closed.
type oneConnListener struct {
	conn net.Conn
	done chan struct{}
	mu   sync.Mutex
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
