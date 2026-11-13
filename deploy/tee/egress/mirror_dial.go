package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// Vendor connections that preserve a container's transport parameters (mirror_hello.go, mirror_transport.go,
// mirror_sessions.go). net/http makes a proxied request's TLS itself, with crypto/tls, and takes HTTP/2 only from a
// *tls.Conn, so these connections have a pool of their own: egress dials the tunnel (direct, CONNECT through an http
// or https proxy, SOCKS5), makes the handshake with uTLS, and speaks what the vendor chose from the hello's ALPN
// offer: HTTP/2 via mirror_transport.go (the standard library's HTTP/2 client forked in third_party/stdhttp2,
// replaying the learned connection preface and per-request HEADERS layout) or HTTP/1.1 via mirror_h1.go (the learned header order
// and casing, responses parsed by net/http).
//
// What stays as on the other transports: the vendor's certificate is verified against egress's roots for the
// route's host, the proxy sees an end-to-end tunnel, and no two proxies share a connection (the pool's key holds the
// whole proxy spec, the vendor address, the hello's structure and the account).

// mirrorHelloKey is the request context's mirrored hello; with one, a vendor call goes through the mirror pool.
type mirrorHelloKey struct{}

// mirrorAccountKey is the request context's account (forward sets it from its observer): vendor connections and
// their session tickets are an account's own, as a relay whose software keeps a client per account has them. Two
// accounts never share a vendor connection, so the vendor never sees one connection carry two accounts' calls.
type mirrorAccountKey struct{}

// accountOf is the call's account for the pool's key: the relay call's or test's (mirrorAccountKey), else an own
// call's session scope (an account id), else "".
func accountOf(ctx context.Context) string {
	if account, _ := ctx.Value(mirrorAccountKey{}).(string); account != "" {
		return account
	}
	return ownSessionScopeOf(ctx)
}

// mirrorAccounted is an upstream observer that names the call's account.
type mirrorAccounted interface{ mirrorAccount() string }

func (o *attemptObserver) mirrorAccount() string { return o.account.id }
func (o *testObserver) mirrorAccount() string    { return o.test.account.id }

func mirroredHelloOf(ctx context.Context) *mirroredHello {
	hello, _ := ctx.Value(mirrorHelloKey{}).(*mirroredHello)
	return hello
}

// mirrorPoolEntries bounds the pool's keys: accounts × proxies × the few hello structures a relay program has. At
// the bound the entry used longest ago gives up its idle connections and leaves.
const mirrorPoolEntries = 256

// A shape that offers HTTP/2 leaves the protocol to the vendor, known only once a handshake is made. Each entry has
// two transports, each with its own pool, retries and idle timeout: the x/net/http2 fork's (which coalesces dials, so
// a burst of first calls makes one connection) and mirror_h1.go's for HTTP/1.1. Both dial only through dialVendor. A dial that finds the other protocol hands its connection to the other transport (the entry's spare)
// and answers one of these two errors; the round trip then goes there.
var (
	errMirrorHTTP1 = errors.New("the vendor chose HTTP/1.1")
	errMirrorHTTP2 = errors.New("the vendor chose HTTP/2")
)

// mirrorSpareWait is how long a spare connection waits for the entry's other transport. The round trip whose dial
// made it goes there at once, so a spare still waiting after this belongs to a call that ended (its client left
// between the two steps); nothing reads an unwatched connection, so a later call could take one the vendor had
// already closed. The wait only has to outlast the hand-over, a few goroutine switches.
const mirrorSpareWait = 5 * time.Second

const (
	mirrorProtocolUnknown int32 = iota
	mirrorProtocolHTTP1
	mirrorProtocolHTTP2
)

type proxyConnectStatusKey struct{}

type mirrorPool struct {
	cfg    config
	roots  *x509.CertPool
	dial   dialFunc
	binder *sessionBinder
	// connectCap bounds one vendor dial (proxyConnectCap; tests shorten it).
	connectCap time.Duration

	mu      sync.Mutex
	entries map[string]*mirrorEntry
	tick    uint64
}

type mirrorEntry struct {
	h1 *mirrorH1Client
	// h2 is nil for a shape that does not offer HTTP/2.
	h2 *mirrorH2Client
	// protocol is what the vendor chose at the entry's last handshake.
	protocol atomic.Int32
	// sessions holds the vendor's latest session ticket, presented once, for direct pool dials without a tunnel slot
	// (tests and fallback), when the entry's shape offers resumption; nil otherwise.
	sessions utls.ClientSessionCache

	mu sync.Mutex
	// spare is a connection one transport's dial made and the other is to take (spareHTTP2 says which); at most one.
	spare      net.Conn
	spareHTTP2 bool
	used       uint64
}

func newMirrorPool(cfg config, roots *x509.CertPool, dial dialFunc) *mirrorPool {
	return &mirrorPool{
		cfg:        cfg,
		roots:      roots,
		dial:       dial,
		binder:     newSessionBinder(nil),
		connectCap: proxyConnectCap,
		entries:    map[string]*mirrorEntry{},
	}
}

func mirrorSpecKey(spec *egressSpec) string {
	if spec == nil {
		return "direct"
	}
	key := spec.kind + "\x00" + spec.host + "\x00" + strconv.Itoa(spec.port)
	if spec.username != nil {
		key += "\x00" + *spec.username + "\x00" + *spec.password
	}
	return key
}

func (p *mirrorPool) entry(hello *mirroredHello, spec *egressSpec, addr, account string) *mirrorEntry {
	key := hello.key + "\x01" + mirrorSpecKey(spec) + "\x01" + addr + "\x01" + account
	var evicted *mirrorEntry
	defer func() {
		// Outside the pool's lock: closing connections may wait on each one's own lock and on the network.
		if evicted != nil {
			evicted.retire()
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tick++
	if e := p.entries[key]; e != nil {
		e.used = p.tick
		return e
	}
	if len(p.entries) >= mirrorPoolEntries {
		oldestKey, oldest := "", (*mirrorEntry)(nil)
		for k, e := range p.entries {
			if oldest == nil || e.used < oldest.used {
				oldestKey, oldest = k, e
			}
		}
		delete(p.entries, oldestKey)
		// Calls in flight on it end on their own connections, which then close; nothing new starts on them.
		evicted = oldest
	}
	e := &mirrorEntry{used: p.tick}
	if hello.resumes {
		// Fallback cache for direct pool calls without a tunnel slot; tunnel calls bind through p.binder.
		e.sessions = &oneShotSessionCache{}
	}
	host, _, _ := net.SplitHostPort(addr)
	// dial is one transport's dial: the other transport's spare connection, or a new one, which goes to the other
	// transport when the vendor chose its protocol. The dial is the whole connect phase: the tunnel and the vendor's
	// handshake.
	dial := func(ctx context.Context, http2Side bool) (net.Conn, error) {
		if conn := e.takeSpare(http2Side); conn != nil {
			return conn, nil
		}
		sessions := e.sessions
		if hello.resumes && p.binder != nil {
			if sess, ok := tunnelSessionOf(ctx); ok {
				sessions = p.binder.clientCache(sess.slotID, sess.resumed, key, host)
			} else if scope := ownSessionScopeOf(ctx); scope != "" {
				sessions = p.binder.clientCache("own:"+scope, true, key, host)
			}
		}
		conn, protocol, err := p.dialVendor(ctx, hello, spec, addr, sessions)
		if err != nil {
			return nil, err
		}
		if chose := protocol == "h2"; chose != http2Side {
			e.setSpare(conn, chose)
			if chose {
				return nil, errMirrorHTTP2
			}
			return nil, errMirrorHTTP1
		}
		return conn, nil
	}
	e.h1 = newMirrorH1Client(p.cfg, func(ctx context.Context) (net.Conn, error) {
		return dial(ctx, false)
	})
	if hello.h2 {
		e.h2 = newMirrorH2Client(p.cfg, hello, func(ctx context.Context) (net.Conn, error) {
			return dial(ctx, true)
		})
	}
	p.entries[key] = e
	return e
}

// setSpare keeps conn for the entry's other transport. A spare nobody took is closed: when a newer one replaces it,
// or after mirrorSpareWait.
func (e *mirrorEntry) setSpare(conn net.Conn, http2Side bool) {
	e.mu.Lock()
	old := e.spare
	e.spare, e.spareHTTP2 = conn, http2Side
	e.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	time.AfterFunc(mirrorSpareWait, func() {
		e.mu.Lock()
		waiting := e.spare == conn
		if waiting {
			e.spare = nil
		}
		e.mu.Unlock()
		if waiting {
			_ = conn.Close()
		}
	})
}

func (e *mirrorEntry) takeSpare(http2Side bool) net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.spare == nil || e.spareHTTP2 != http2Side {
		return nil
	}
	conn := e.spare
	e.spare = nil
	return conn
}

// retire closes the entry's idle connections now and its busy ones as their calls end (an entry the pool let go).
func (e *mirrorEntry) retire() {
	e.h1.Retire()
	if e.h2 != nil {
		e.h2.Retire()
	}
	e.mu.Lock()
	spare := e.spare
	e.spare = nil
	e.mu.Unlock()
	if spare != nil {
		_ = spare.Close()
	}
}

// closeIdle closes the entry's idle connections; the busy ones stay for their calls and the next ones.
func (e *mirrorEntry) closeIdle() {
	e.h1.CloseIdleConnections()
	if e.h2 != nil {
		e.h2.CloseIdleConnections()
	}
	e.mu.Lock()
	spare := e.spare
	e.spare = nil
	e.mu.Unlock()
	if spare != nil {
		_ = spare.Close()
	}
}

// closeIdle closes every idle mirrored connection; the entries stay.
func (p *mirrorPool) closeIdle() {
	p.mu.Lock()
	entries := make([]*mirrorEntry, 0, len(p.entries))
	for _, e := range p.entries {
		entries = append(entries, e)
	}
	p.mu.Unlock()
	for _, e := range entries {
		e.closeIdle()
	}
}

// errMirrorNoPreface is a call whose hello offers h2 without a learned HTTP/2 preface (mirroredHello.usable).
var errMirrorNoPreface = errors.New("mirror pool: the hello offers h2 and no HTTP/2 preface was learned for it")

// RoundTrip sends req on a vendor connection made with the request's mirrored hello.
func (p *mirrorPool) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	hello := mirroredHelloOf(ctx)
	if hello == nil {
		return nil, errors.New("mirror pool: the request has no hello")
	}
	// The vendor would read the client's handshake and then a preface no client sends: no call goes that way.
	if !hello.usable() {
		return nil, errMirrorNoPreface
	}
	spec, _ := ctx.Value(proxyContextKey{}).(*egressSpec)
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	e := p.entry(hello, spec, addr, accountOf(ctx))
	if e.h2 == nil {
		return e.h1.RoundTrip(req)
	}
	// The vendor's choice is the same from one handshake to the next but for a change on its side: one switch each
	// way is all a round trip follows.
	var resp *http.Response
	var err error
	for switches := 0; switches < 3; switches++ {
		if e.protocol.Load() == mirrorProtocolHTTP1 {
			if resp, err = e.h1.RoundTrip(req); !errors.Is(err, errMirrorHTTP2) {
				return resp, err
			}
			e.protocol.Store(mirrorProtocolHTTP2)
			continue
		}
		if resp, err = e.h2.RoundTrip(req); !errors.Is(err, errMirrorHTTP1) {
			if err == nil {
				e.protocol.Store(mirrorProtocolHTTP2)
			}
			return resp, err
		}
		e.protocol.Store(mirrorProtocolHTTP1)
	}
	return resp, err
}

// dialVendor makes one vendor connection with hello's structure and returns it with the protocol the vendor chose.
//
// With sessions, a connection presents the vendor ticket bound to the caller's session slot (mirror_sessions.go, or
// the entry's fallback cache for direct pool calls); the pre_shared_key extension is a resumed hello's last
// (RFC 8446 4.2.11) and is left out while sessions holds no ticket. No 0-RTT data is sent.
func (p *mirrorPool) dialVendor(ctx context.Context, hello *mirroredHello, spec *egressSpec, addr string, sessions utls.ClientSessionCache) (net.Conn, string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}
	helloSpec, err := hello.spec()
	if err != nil {
		return nil, "", err
	}
	if hello.shuffles.Load() {
		if err := shuffleHelloExtensions(helloSpec.Extensions); err != nil {
			return nil, "", err
		}
	}
	// The HTTP transports dial with the request's values but not its cancellation (net/http's getConn detaches it
	// with context.WithoutCancel so a later request may take the connection), so the phase timer in forward does not
	// reach this dial. Bound the whole connect phase here, as net/http bounds its own proxied CONNECT: a proxy that
	// accepts TCP and never answers otherwise holds the dial, its fd and, on HTTP/2, every coalesced dial behind it.
	ctx, stopConnect := context.WithTimeout(ctx, p.connectCap)
	defer stopConnect()
	raw, err := p.tunnel(ctx, spec, addr)
	if err != nil {
		return nil, "", err
	}
	// The vendor's certificate is checked as crypto/tls checks it: the chain against egress's roots, for host.
	config := &utls.Config{ServerName: host, RootCAs: p.roots, MinVersion: utls.VersionTLS12,
		// Full records from the start when the client writes them (mirroredHello.fullRecords); else uTLS's
		// dynamic sizing, as before.
		DynamicRecordSizingDisabled: hello.fullRecords.Load()}
	if sessions != nil {
		config.ClientSessionCache, config.OmitEmptyPsk = sessions, true
		helloSpec.Extensions = append(helloSpec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	}
	var ccs *noDummyCCSConn
	tlsTransport := raw
	if hello.sessionIDLen == 0 {
		ccs = &noDummyCCSConn{Conn: raw}
		tlsTransport = ccs
	}
	conn := utls.UClient(tlsTransport, config, utls.HelloCustom)
	if err := conn.ApplyPreset(helloSpec); err != nil {
		_ = raw.Close()
		return nil, "", err
	}
	// uTLS always makes a 32-byte session id (ApplyPreset, u_parrots.go); the hello's own length goes out instead.
	// HelloCustom keeps HandshakeState.Hello as set here until the handshake marshals it (applyPresetByID).
	if hello.sessionIDLen != 32 {
		var sessionID []byte
		if hello.sessionIDLen > 0 {
			sessionID = make([]byte, hello.sessionIDLen)
			if _, err := rand.Read(sessionID); err != nil {
				_ = raw.Close()
				return nil, "", err
			}
		}
		conn.HandshakeState.Hello.SessionId = sessionID
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	handshake, cancel := context.WithTimeout(ctx, p.cfg.tlsHandshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(handshake); err != nil {
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tls.ConnectionState{}, err)
		}
		_ = raw.Close()
		return nil, "", err
	}
	if ccs != nil {
		ccs.done.Store(true)
	}
	state := conn.ConnectionState()
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(tls.ConnectionState{
			Version:            state.Version,
			HandshakeComplete:  state.HandshakeComplete,
			DidResume:          state.DidResume,
			CipherSuite:        state.CipherSuite,
			NegotiatedProtocol: state.NegotiatedProtocol,
			ServerName:         state.ServerName,
		}, nil)
	}
	return conn, state.NegotiatedProtocol, nil
}

// proxyConnectMaxHead bounds what egress reads of an http(s) proxy's answer to its CONNECT before the stream: the
// status line and its fields, and on a refusal the body that Close drains. An answer egress acts on is a status line
// and a few fields (a 407's Proxy-Authenticate among them), so 64 KiB is many times one; net/http's Transport allows
// 10 MiB by default (MaxResponseHeaderBytes, Go 1.27.2 net/http/transport.go:336-341), more than a tunnel's dial
// should hold for a proxy. An answer past it is the proxy's connect failure (errProxyConnect).
const proxyConnectMaxHead = 64 << 10

// tunnel is a byte stream to addr: a direct connection, or one through the account's proxy. Its failures carry what
// mapUpstreamError reads from net/http's own: errProxyAuth, errProxyConnect, a dial's *net.OpError.
func (p *mirrorPool) tunnel(ctx context.Context, spec *egressSpec, addr string) (net.Conn, error) {
	if spec == nil {
		return p.dial(ctx, "tcp", addr)
	}
	proxyAddr := net.JoinHostPort(spec.host, strconv.Itoa(spec.port))
	if spec.kind == "socks5" || spec.kind == "socks5h" {
		var auth *proxy.Auth
		if spec.username != nil {
			auth = &proxy.Auth{User: *spec.username, Password: *spec.password}
		}
		// The proxy resolves the vendor's name, as with net/http's socks5.
		forward := &mirrorForward{dial: p.dial}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, forward)
		if err != nil {
			return nil, err
		}
		conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
		if err != nil {
			// A proxy that was not reached is the dial's failure, not the SOCKS exchange's.
			if forward.err != nil {
				return nil, forward.err
			}
			return nil, err
		}
		return conn, nil
	}
	conn, err := p.dial(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	// The CONNECT exchange ends with the request: a cancelled call does not wait for a silent proxy.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	fail := func(err error) (net.Conn, error) {
		stop()
		_ = conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if spec.kind == "https" {
		trace := httptrace.ContextClientTrace(ctx)
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		secured := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.roots, ServerName: spec.host})
		handshake, cancel := context.WithTimeout(ctx, p.cfg.tlsHandshakeTimeout)
		err := secured.HandshakeContext(handshake)
		cancel()
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(secured.ConnectionState(), err)
		}
		if err != nil {
			return fail(err)
		}
		conn = secured
	}
	// The request net/http's Transport writes for a tunnel.
	connect := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if spec.username != nil {
		credentials := *spec.username + ":" + *spec.password
		connect.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	if err := connect.Write(conn); err != nil {
		return fail(err)
	}
	// The answer's head is read through a limit, as net/http's Transport reads its own CONNECT answer (Go 1.27.2,
	// net/http/transport.go:2012, an io.LimitedReader of MaxResponseHeaderBytes); the limit is lifted once the head
	// is read, since the same reader carries the stream.
	limited := &io.LimitedReader{R: conn, N: proxyConnectMaxHead}
	reader := bufio.NewReader(limited)
	resp, err := http.ReadResponse(reader, connect)
	if err != nil {
		if limited.N <= 0 {
			return fail(errProxyConnect)
		}
		return fail(err)
	}
	_ = resp.Body.Close()
	if onStatus, _ := ctx.Value(proxyConnectStatusKey{}).(func(int)); onStatus != nil {
		onStatus(resp.StatusCode)
	}
	switch {
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return fail(errProxyAuth)
	case resp.StatusCode != http.StatusOK:
		return fail(errProxyConnect)
	}
	if !stop() {
		return fail(ctx.Err())
	}
	limited.N = math.MaxInt64
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// mirrorForward dials the SOCKS5 proxy with egress's dial function and keeps that dial's failure.
type mirrorForward struct {
	dial dialFunc
	err  error
}

func (f *mirrorForward) Dial(network, addr string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, addr)
}

func (f *mirrorForward) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := f.dial(ctx, network, addr)
	f.err = err
	return conn, err
}

// isMirrorTLSError is isTLSError for a handshake uTLS made: its own types for the same failures.
func isMirrorTLSError(err error) bool {
	var certificateError *utls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return true
	}
	var recordHeader utls.RecordHeaderError
	if errors.As(err, &recordHeader) {
		return true
	}
	var alert utls.AlertError
	return errors.As(err, &alert)
}

// noDummyCCSConn is the vendor connection under the uTLS client of a hello whose legacy_session_id is empty. uTLS
// v1.8.2 writes TLS 1.3's dummy ChangeCipherSpec (RFC 8446 D.4) on every TCP connection whatever the session id
// (handshake_client_tls13.go sendDummyChangeCipherSpec), but a client not in middlebox compatibility mode, the one
// whose empty session id the vendor saw, sends none. Until the handshake is over this drops a ChangeCipherSpec record
// that is not followed, in the same write, by a handshake record:
//
//   - TLS 1.3: the dummy one goes out buffered with the client's encrypted flight (outer type application_data), or
//     alone just before the second ClientHello after a HelloRetryRequest (written unbuffered). Both are dropped.
//   - TLS 1.2: the client's real ChangeCipherSpec goes out buffered with its Finished (outer type handshake). Kept.
//
// A write that is not whole TLS records goes out unchanged (crypto/tls writes whole records only).
type noDummyCCSConn struct {
	net.Conn
	done atomic.Bool
}

func (c *noDummyCCSConn) Write(p []byte) (int, error) {
	if c.done.Load() {
		return c.Conn.Write(p)
	}
	out, changed := dropDummyCCS(p)
	if !changed {
		return c.Conn.Write(p)
	}
	if len(out) > 0 {
		if n, err := c.Conn.Write(out); err != nil {
			// Report what of p was written, at most: the dropped record counts as written only with all of out.
			return min(n, len(p)-1), err
		}
	}
	return len(p), nil
}

// dropDummyCCS is p without the ChangeCipherSpec records noDummyCCSConn drops, and whether there was one.
func dropDummyCCS(p []byte) ([]byte, bool) {
	type record struct{ start, end int }
	var records []record
	for at := 0; at < len(p); {
		if len(p)-at < 5 {
			return p, false
		}
		end := at + 5 + int(binary.BigEndian.Uint16(p[at+3:at+5]))
		if end > len(p) {
			return p, false
		}
		records = append(records, record{at, end})
		at = end
	}
	var out []byte
	changed := false
	for i, r := range records {
		isCCS := p[r.start] == 20 && r.end-r.start == 6 && p[r.start+5] == 1
		if isCCS && (i+1 == len(records) || p[records[i+1].start] != 22) {
			if !changed {
				out = append(make([]byte, 0, len(p)), p[:r.start]...)
				changed = true
			}
			continue
		}
		if changed {
			out = append(out, p[r.start:r.end]...)
		}
	}
	if !changed {
		return p, false
	}
	return out, true
}
