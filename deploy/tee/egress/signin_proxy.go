package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
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
// CA (signin_ca.go), HTTP/1.1 only, and runs each request inside through the sign-in route's own checks and call
// (stack_login.go loginCall): the row's paths and refused words, no `X-Gray-Request`, no `x-gray-*` header, the body
// bound, GET or POST, the account's own outbound proxy, no redirect followed; plus the session rules (signin_session.go).
// Inference never goes this way: the rows hold no inference path.

const (
	routeSignInProxyCall = "/v1/relay/sign-in-proxy"
	// signInTunnelsMax bounds the open tunnels (each holds a TLS connection and its HTTP/1.1 buffers, about 100 KiB);
	// calls in them are bounded again by loginInFlightMax.
	signInTunnelsMax      = 32
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
	if _, open := signInRows[vendor].Hosts[host]; !open {
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

// serveTunnel ends TLS for host and serves HTTP/1.1 requests inside until the client closes or goes idle.
func (s *server) serveTunnel(conn net.Conn, host, accountID, vendor string, password bool, leaf *tls.Certificate) {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// The name the client checks must be the CONNECT's host.
			if hello.ServerName != "" && strings.ToLower(hello.ServerName) != host {
				return nil, errors.New("server name differs from the CONNECT host")
			}
			return leaf, nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), signInHandshakeCap)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	done := make(chan struct{})
	var once sync.Once
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handled(w, r, func(rec *responseRecorder, r *http.Request, entry *requestLog) {
				s.tunnelCall(rec, r, entry, host, accountID, vendor, password)
			})
		}),
		// A sign-in call is a few KiB: a tunnel that sends nothing gives its slot back within signInTunnelIdle.
		ReadHeaderTimeout: signInTunnelIdle,
		ReadTimeout:       loginCallCap,
		// The longest answer: a token call (loginCallCap) and its wait for the vault (at most maxLoginPersistWait).
		WriteTimeout:   loginCallCap + maxLoginPersistWait + signInHandshakeCap,
		IdleTimeout:    signInTunnelIdle,
		MaxHeaderBytes: relayMaxHeaderBytes,
		// HTTP/1.1 only (D10): no protocol beside it is served on the connection.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				once.Do(func() { close(done) })
			}
		},
	}
	_ = inner.Serve(&oneConnListener{conn: tlsConn, done: done})
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
