package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The peer mode (docs/confidential-lane-stack-routing.md §4.3, §4.9; docs/design/relay-outbound-only.md §3): an
// entry's egress carries the entry's requests to a relay's stack VM, and sends a request's content only over a TLS
// session whose server key is the one the entry attested. It is on only with -peer, which config refuses beside
// -relay-listen, and it is served on the unix socket only; the relay listener refuses its paths by name (relayCall).
//
// Every stack VM takes no inbound connection (relay-outbound-only.md §9 step 8): it is reached through peerlink
// (-peer-link), which carries each connection as a stream over a session the VM dialed (peer_link.go).
//
//   - PUT /v1/peer/pins replaces the whole pin table, versioned like the stack's account table (S15). A row names
//     the relay and the keyset (`{peer, relay, spki_sha256, not_after}`, §3.3); without -peer-link every row is
//     refused.
//   - /peer/<digest>/<path> is a request to the pinned peer whose keyset digest is <digest>: peerlink's CONNECT for
//     (relay, keyset), then TLS 1.3 verified by the pin alone, the VM's certificate being self-signed (§3.3, §3.9).
//     A digest without a live pin is peer_unpinned, before any dial. A mismatch condemns the session it came from
//     and keeps the pin (§3.5, O6).
//   - GET /peer/attest/<relay>/<keyset>/healthz and GET /peer/attest/<relay>/<keyset>/v1/aci/attestation?nonce=<64
//     hex> are attest mode: no pin, no body and none of the entry's headers, so nothing but the path and the nonce
//     reaches a peer the entry has not verified (L1). The answer carries the leaf SPKI's SHA-256 egress saw, in
//     x-gray-peer-spki.
const (
	peerControlPrefix = "/v1/peer/"
	peerPinsPath      = "/v1/peer/pins"
	peerPrefix        = "/peer/"
	peerAttestPrefix  = "/peer/attest/"
	// peerVersionHeader is the entry registry's epoch (a u64 it fixes when its registry starts, so a restarted
	// lane counts above the one before it), peerPushHeader its push sequence within that epoch: both a u64 in
	// decimal text, compared in that order as the account table's version and push are.
	peerVersionHeader = "X-Gray-Peer-Version"
	peerPushHeader    = "X-Gray-Peer-Push"
	// The two headers only egress writes. Both are removed from the entry's request and from the peer's answer, so
	// neither side can put a value on them (as x-gray-egress, D64).
	peerSentHeader = "X-Gray-Peer-Sent"
	peerSPKIHeader = "X-Gray-Peer-Spki"
	// peerSessionHeader is peerlink's id of the session a channel peer's connection rode, on a peer_pin_mismatch
	// answer (design §3.5). Egress removes it from the entry's request and the peer's answer, as the two above.
	peerSessionHeader = "X-Gray-Peer-Session"
	// peerLinkHostSuffix makes a channel peer's host: `<keyset digest>.peer.gray.invalid`, the CONNECT authority
	// (design §3.2), the inner TLS's server name and the HTTP Host. `.invalid` never resolves (RFC 6761 §6.4), so
	// no dial but peerlink's can reach it.
	peerLinkHostSuffix = ".peer.gray.invalid"
	// peerRelayMaxBytes is @gray/control's LANE_RELAY_ID_PATTERN length bound (validPeerRelay).
	peerRelayMaxBytes = 128
	// The routes in the request log: no digest, host, path or query reaches a log line.
	peerControlRoute = "/v1/peer"
	peerRoute        = "/peer"
	peerAttestRoute  = "/peer/attest"
	// peerMaxPins has no measured source: an entry pins each stack relay's keysets, and this only stops a broken
	// caller.
	peerMaxPins = 1024
	// peerPinMaxTTL: a pin's not_after is at most an hour away (§4.3 step 3, `now + 1 h`).
	peerPinMaxTTL = time.Hour
	// peerMaxIdlePerPeer is the vendor transports' MaxIdleConnsPerHost; one peer is one host.
	peerMaxIdlePerPeer = 8
)

var (
	errPeerSPKIMismatch = errors.New("the peer's TLS key is not the pinned one")
	errPeerNoLeaf       = errors.New("the peer sent no certificate")
)

// peerPin is one row of the pin table. Its fields never change: a new table makes new rows, and carries an
// unchanged row's transport over, so the sessions pooled for it (verified against the same SPKI) stay.
type peerPin struct {
	digest string
	// host is `<digest>.peer.gray.invalid`: peerlink's CONNECT authority, the inner TLS's server name and the Host.
	host string
	// relay is the peer's relay id, which peerlink's CONNECT names.
	relay     string
	spki      [sha256.Size]byte
	notAfter  time.Time
	transport *http.Transport
	client    *http.Client
}

// peerTable is the pin table and the per-peer transports. Attest mode makes a transport per attestation.
type peerTable struct {
	srv *server
	// now is time.Now in production; a test replaces it to expire a pin without waiting.
	now func() time.Time

	mu   sync.Mutex
	pins map[string]*peerPin // by keyset digest
	// version and push are the highest pair a table was accepted under; set is false until the first table.
	version uint64
	push    uint64
	set     bool
}

func newPeerTable(srv *server) *peerTable {
	return &peerTable{srv: srv, now: time.Now, pins: map[string]*peerPin{}}
}

// peerTarget is what one peer transport dials through peerlink (design §3.2): the relay and keyset digest, and the
// pin's SPKI (nil in attest mode); attest is attest mode, which may ride a session the entry has not verified yet
// (§3.3, §3.5).
type peerTarget struct {
	digest string
	relay  string
	attest bool
	spki   *[sha256.Size]byte
}

// peerClient never follows a redirect: it is the peer's answer, passed to the entry, and following one would
// leave the pinned host.
func peerClient(transport *http.Transport) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// newPeerTransport is one peer's transport: HTTP/1.1 only (the stack VM's TLS ends in workerd, which speaks
// nothing else), no proxy, no compression, an idle pool kept below the server's keep-alive time
// (-peer-idle-timeout), and dialPeer for every connection. target.spki is nil for attest mode.
func (s *server) newPeerTransport(target peerTarget) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialPeer(ctx, network, addr, target)
		},
		DisableCompression:  true,
		IdleConnTimeout:     s.cfg.peerIdleTimeout,
		MaxIdleConns:        peerMaxIdlePerPeer,
		MaxIdleConnsPerHost: peerMaxIdlePerPeer,
		TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
}

// peerDialError is a connection that failed before it could carry a byte of the request; code is its peer code.
type peerDialError struct {
	code string
	err  error
	// session is peerlink's session id of the connection, when peerlink named one.
	session string
}

func (e *peerDialError) Error() string { return e.code + ": " + e.err.Error() }
func (e *peerDialError) Unwrap() error { return e.err }

// dialPeer makes one peer connection through peerlink (peer_link.go): its CONNECT for (relay, keyset), the ready
// byte and the TLS 1.3 handshake, all within -peer-link-connect-timeout. The TLS is verified by the pin alone
// (peerTLSConfig): VerifyConnection requires the leaf's SPKI to equal it, and crypto/tls aborts the handshake on the
// hook's error, so a refused session never carries a request byte. A mismatch condemns the session and keeps the pin
// (design §3.5, O6): a reboot arrives as new sessions with a new keyset, so another key on a pinned keyset's session
// is a liar or a defect, not a reboot.
func (s *server) dialPeer(ctx context.Context, _, addr string, target peerTarget) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, &peerDialError{code: errPeerConnectFailed, err: err}
	}
	if target.relay == "" || (target.spki == nil && !target.attest) {
		// A peer is always a relay's; only attest mode dials without a pin (L1).
		return nil, &peerDialError{code: errPeerConnectFailed, err: errors.New("a peer dial without a relay or a pin")}
	}
	connectContext, cancel := context.WithTimeout(ctx, s.cfg.peerLinkConnectTimeout)
	defer cancel()
	start := time.Now()
	raw, session, err := s.dialPeerLink(connectContext, target)
	if err != nil {
		return nil, err
	}
	pin := target.spki
	var observed [sha256.Size]byte
	conn := tls.Client(raw, s.peerTLSConfig(host, func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errPeerNoLeaf
		}
		observed = sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if pin != nil && subtle.ConstantTimeCompare(observed[:], pin[:]) != 1 {
			return errPeerSPKIMismatch
		}
		return nil
	}))
	if err := conn.HandshakeContext(connectContext); err != nil {
		_ = raw.Close()
		code := errPeerTLSFailed
		switch {
		case errors.Is(err, errPeerSPKIMismatch):
			code = errPeerPinMismatch
			s.condemnPeerSession(session)
		case connectContext.Err() != nil:
			// The connect bound passed during the handshake: the peer did not answer in time, which is row 13's
			// connect failure, not a TLS refusal.
			code = errPeerConnectFailed
		}
		return nil, &peerDialError{code: code, err: err, session: session}
	}
	return &peerConn{Conn: conn, spki: observed, connectMS: time.Since(start).Milliseconds()}, nil
}

// peerTLSConfig is the one TLS configuration of a peer connection: TLS 1.3, HTTP/1.1 only, and verify (the pin,
// or attest mode's record of the SPKI) as VerifyConnection. The peer's certificate is the stack VM's self-signed
// per-boot one (design §3.9): it has no chain and no name to verify, so the pin is the whole check (§3.3, O2).
// crypto/tls still calls VerifyConnection with InsecureSkipVerify set, after the server proved the key in its
// CertificateVerify, and aborts the handshake on the hook's error, so a session whose key is not the pin never
// carries a byte. tls_test.go holds every InsecureSkipVerify in this file to a literal that sets VerifyConnection.
func (s *server) peerTLSConfig(host string, verify func(tls.ConnectionState) error) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         host,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
	}
}

// peerConn is a peer session after its handshake. written counts the bytes crypto/tls accepted to send on it, so
// a request that fails knows whether any byte of it may have reached the peer (x-gray-peer-sent).
type peerConn struct {
	net.Conn
	spki      [sha256.Size]byte
	connectMS int64
	written   atomic.Int64
}

func (c *peerConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

// peerTiming is a peer request's member of its log line (X1's check on staging, design §6.3): connect_ms is the
// new session's TCP and TLS time (absent on a pooled one), head_ms the time from the request's start to the first
// byte of the peer's answer (absent when none came), reused whether the session came from the pool.
type peerTiming struct {
	ConnectMS *int64 `json:"connect_ms,omitempty"`
	HeadMS    *int64 `json:"head_ms,omitempty"`
	Reused    bool   `json:"reused"`
}

// peerTrace follows one peer request: each session net/http gave it, with that session's written count when it
// got it (net/http retries on a new session only when nothing was written, transport.go shouldRetryRequest), and
// the timing. The transport calls it from its own goroutines.
type peerTrace struct {
	start   time.Time
	silence *peerSilence

	mu     sync.Mutex
	conns  []*peerConn
	bases  []int64
	timing peerTiming
}

func (t *peerTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			t.silence.touch()
			conn, ok := info.Conn.(*peerConn)
			if !ok {
				return
			}
			t.mu.Lock()
			defer t.mu.Unlock()
			t.conns = append(t.conns, conn)
			t.bases = append(t.bases, conn.written.Load())
			t.timing.Reused = info.Reused
			t.timing.ConnectMS = nil
			if !info.Reused {
				connect := conn.connectMS
				t.timing.ConnectMS = &connect
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { t.silence.touch() },
		GotFirstResponseByte: func() {
			t.silence.touch()
			t.mu.Lock()
			defer t.mu.Unlock()
			head := time.Since(t.start).Milliseconds()
			t.timing.HeadMS = &head
		},
	}
}

// sent reports whether a byte of the request may have reached the peer: some session it got took a byte.
func (t *peerTrace) sent() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, conn := range t.conns {
		if conn.written.Load() > t.bases[i] {
			return true
		}
	}
	return false
}

// session is the last session the request got, nil when it got none.
func (t *peerTrace) session() *peerConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.conns) == 0 {
		return nil
	}
	return t.conns[len(t.conns)-1]
}

func (t *peerTrace) snapshot() *peerTiming {
	t.mu.Lock()
	defer t.mu.Unlock()
	timing := t.timing
	return &timing
}

// peerSilence ends a peer request whose peer sends nothing for -peer-silence-timeout, before its head or between
// two reads of its body (§4.9, §5 rows 11-12). It is armed when the request has a session, so the connect phase
// has only its own bound, and every byte from the peer restarts it.
type peerSilence struct {
	bound     time.Duration
	afterFunc func(time.Duration, func()) *time.Timer
	cancel    context.CancelFunc
	fired     atomic.Bool

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
}

func (p *peerSilence) touch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.stopped:
	case p.timer == nil:
		p.timer = p.afterFunc(p.bound, func() {
			p.fired.Store(true)
			p.cancel()
		})
	default:
		p.timer.Reset(p.bound)
	}
}

func (p *peerSilence) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	if p.timer != nil {
		p.timer.Stop()
	}
}

// writePeerRefusal is every answer egress itself gives on a /peer/ path: the fixed code and x-gray-peer-sent.
func writePeerRefusal(w http.ResponseWriter, code string, sent bool) {
	value := "0"
	if sent {
		value = "1"
	}
	w.Header().Set(peerSentHeader, value)
	writeRefusal(w, code)
}

// isPeerPath is every path of the peer mode, the one rule the relay listener refuses them by.
func isPeerPath(path string) bool {
	return path == "/peer" || path == "/v1/peer" || strings.HasPrefix(path, peerPrefix) || strings.HasPrefix(path, peerControlPrefix)
}

// peerTargetCode holds a /peer/ request to the vendor routes' request-target rules: origin-form, no raw `#`, no
// CONNECT, and the main lane's path rule (validRawPath).
func peerTargetCode(r *http.Request) string {
	switch {
	case r.Method == http.MethodConnect:
		return errMethodRefused
	case r.URL == nil || r.URL.IsAbs() || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" ||
		strings.Contains(r.RequestURI, "#"):
		return errTargetRefused
	case !validRawPath(rawPathOf(r)):
		return errPathRefused
	}
	return ""
}

// servePeer is a request under /peer/: attest mode, or a request to a pinned peer.
func (s *server) servePeer(rec *responseRecorder, r *http.Request, entry *requestLog) {
	path := rawPathOf(r)
	if rest, ok := strings.CutPrefix(path, peerAttestPrefix); ok {
		entry.Route = peerAttestRoute
		s.serveAttest(rec, r, rest, entry)
		return
	}
	entry.Route = peerRoute
	refuse := func(code string) {
		entry.Error = code
		writePeerRefusal(rec, code, false)
	}
	if code := peerTargetCode(r); code != "" {
		refuse(code)
		return
	}
	digest, tail, ok := strings.Cut(strings.TrimPrefix(path, peerPrefix), "/")
	switch {
	case !ok || !validPeerDigest(digest):
		refuse(errRouteRefused)
		return
	case strings.HasPrefix(tail, "/"):
		// "//" would make the request line absolute-form (url.URL.RequestURI), naming a host in the path.
		refuse(errPathRefused)
		return
	case !allowedMethod(r.Method):
		refuse(errMethodRefused)
		return
	case len(r.Header.Values(egressHeader)) != 0:
		// The hop is never proxied: a proxy spec on a peer request is a caller's mistake, not something to drop.
		refuse(errSpecRefused)
		return
	case s.peers.lookup(digest) == nil:
		refuse(errPeerUnpinned)
		return
	}
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		refuse(code)
		return
	}
	// Again after the body: the pin may have ended while it was read.
	pin := s.peers.lookup(digest)
	if pin == nil {
		refuse(errPeerUnpinned)
		return
	}
	header := outboundHeader(r.Header)
	header.Del(peerSentHeader)
	header.Del(peerSPKIHeader)
	header.Del(peerSessionHeader)
	target := &url.URL{Scheme: "https", Host: pin.host, Opaque: "/" + tail, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
	s.forwardPeer(rec, r, entry, pin.client, r.Method, target, header, body, false)
}

// serveAttest is attest mode (§4.3 step 1): /peer/attest/<relay>/<keyset>/<GET>, one of two content-free GETs over a
// stream of a session no pin covers yet (design §3.3), through peerlink's CONNECT for (relay, keyset) in attest mode.
// The request is built here from the path and the nonce alone: no body, no header of the entry's and no query but
// the nonce.
func (s *server) serveAttest(rec *responseRecorder, r *http.Request, rest string, entry *requestLog) {
	if code := peerTargetCode(r); code != "" {
		entry.Error = code
		writePeerRefusal(rec, code, false)
		return
	}
	relay, tail, ok := strings.Cut(rest, "/")
	digest, inner, nested := strings.Cut(tail, "/")
	path, query := "/"+inner, r.URL.RawQuery
	twoGets := (path == "/healthz" && query == "" && !r.URL.ForceQuery) || (path == "/v1/aci/attestation" && validAttestQuery(query))
	named := ok && nested && validPeerDigest(digest) && s.cfg.peerLink != "" && validPeerRelay(relay)
	if !named || r.Method != http.MethodGet || !twoGets || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		entry.Error = errPeerAttestRefused
		writePeerRefusal(rec, errPeerAttestRefused, false)
		return
	}
	// One transport per attestation, without a pool, as the shared attest transport: each attestation is one new
	// stream, and the SPKI egress reports is that stream's.
	transport := s.newPeerTransport(peerTarget{digest: digest, relay: relay, attest: true})
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	target := &url.URL{Scheme: "https", Host: digest + peerLinkHostSuffix, Opaque: path, RawQuery: query}
	s.forwardPeer(rec, r, entry, peerClient(transport), http.MethodGet, target, http.Header{}, nil, true)
}

// validAttestQuery is the attestation route's one query: `nonce=` and 32 bytes as 64 lower hex (@gray/attest
// isValidNonce, the nonce the lane's attestation route takes).
func validAttestQuery(query string) bool {
	nonce, ok := strings.CutPrefix(query, "nonce=")
	return ok && len(nonce) == 64 && isLowerHex(nonce)
}

// forwardPeer sends one request over a peer transport and streams the answer back unchanged: the status, the
// headers but hop-by-hop ones and egress's own, and each body chunk flushed as it is read (§4.9). reportSPKI, for
// attest mode, adds x-gray-peer-spki. The request's context is the entry's: when the entry leaves, net/http closes
// the peer connection (HTTP/1.1 has no per-request reset), and the stack VM sees its client leave.
func (s *server) forwardPeer(rec *responseRecorder, r *http.Request, entry *requestLog, client *http.Client, method string, target *url.URL, header http.Header, body []byte, reportSPKI bool) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	silence := &peerSilence{bound: s.cfg.peerSilenceTimeout, afterFunc: s.afterFunc, cancel: cancel}
	defer silence.stop()
	trace := &peerTrace{start: time.Now(), silence: silence}
	defer func() { entry.Peer = trace.snapshot() }()
	// As forward: a constant URL first, then the target this program built, never its text reparsed (D59).
	outReq, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace.clientTrace()), method, "https://"+target.Host, bytes.NewReader(body))
	if err != nil {
		entry.Error = errInternal
		writePeerRefusal(rec, errInternal, false)
		return
	}
	outReq.URL = target
	outReq.Header = header
	// The peer sees only the headers the entry sent: an absent User-Agent stays absent.
	if _, present := outReq.Header["User-Agent"]; !present {
		outReq.Header["User-Agent"] = []string{""}
	}
	outReq.Host = target.Host
	if len(body) == 0 {
		outReq.Body = http.NoBody
		outReq.ContentLength = 0
	}

	resp, err := client.Do(outReq)
	if err == nil && ctx.Err() != nil {
		// A head read after egress canceled the call (the entry left, or the silence bound fired) is the cancel's,
		// not the peer's answer: net/http's transport still returns a response its read loop got after the cancel, and
		// the cancel's TLS close_notify can bring one (the Go test VM's handler returns on it, and its server answers
		// 200). TestPeerSilenceBound forwarded such a 200 in 43 of 640 loaded runs on the build box (2026-11-09). The
		// call failed with the cancel.
		_ = resp.Body.Close()
		resp, err = nil, ctx.Err()
	}
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if r.Context().Err() != nil {
			// The entry left: nobody reads an answer.
			entry.Error = errClientWrite
			return
		}
		code, sent := peerFailure(err, trace, silence)
		entry.Error = code
		// A mismatch names the session it came from (design §3.5), which egress has condemned.
		var dialErr *peerDialError
		if code == errPeerPinMismatch && errors.As(err, &dialErr) && dialErr.session != "" {
			rec.Header().Set(peerSessionHeader, dialErr.session)
		}
		writePeerRefusal(rec, code, sent)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for _, name := range []string{egressHeader, peerSentHeader, peerSPKIHeader, peerSessionHeader} {
		resp.Header.Del(name)
	}
	stripHopByHop(resp.Header)
	copyHeader(rec.Header(), resp.Header)
	if session := trace.session(); reportSPKI && session != nil {
		rec.Header().Set(peerSPKIHeader, hex.EncodeToString(session.spki[:]))
	}
	rec.WriteHeader(resp.StatusCode)
	controller := http.NewResponseController(rec)
	if flushErr := controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
		entry.Error = errClientWrite
		return
	}
	buffer := make([]byte, forwardBufferBytes)
	var written int64
	for {
		n, readErr := resp.Body.Read(buffer)
		if n > 0 {
			silence.touch()
			if _, writeErr := rec.Write(buffer[:n]); writeErr != nil {
				entry.Error = errClientWrite
				return
			}
			if flushErr := controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
				entry.Error = errClientWrite
				return
			}
			written += int64(n)
		}
		// An answer that declared its length is whole once that many bytes are written, as forward's
		// (declaredLengthWritten): the entry has all of it and may close at once (a client without keep-alive does),
		// and net/http then ends the entry's context, before or after the peer's end reaches egress. Its context says
		// nothing more here: read at the peer's end below, it logged whole answers client_write (TestPeerPinMatch,
		// TestPeerLinkAttestMode and TestPeerAttestModeAllowsOnlyTheTwoGets in five main runs of 2026-11-09).
		if declaredLengthWritten(resp, written) {
			return
		}
		// The peer's answer ended, unless egress had canceled the call first (the entry left, or the silence bound
		// fired): net/http's transport returns a body's last chunk as io.EOF even when it comes after the request was
		// canceled, and the cancel's TLS close_notify can end the peer's answer before egress has closed the
		// connection, so the end arrives in that window (gate 5f46d5249, 2026-11-09: TestPeerClientCancelClosesTheUpstream
		// logged a whole answer; TestPeerSilenceBound ended a cut one cleanly). This answer declared no length (a short
		// declared one ends in io.ErrUnexpectedEOF), so the entry reads its end only once the handler returns: an end
		// read after the cancel is a cut answer, as any other read error below.
		if errors.Is(readErr, io.EOF) && ctx.Err() == nil {
			return
		}
		if readErr != nil {
			if r.Context().Err() != nil {
				entry.Error = errClientWrite
				return
			}
			entry.Error = errPeerFailedAfterSend
			if silence.fired.Load() {
				entry.Error = errPeerTimeout
			}
			// The status is on the wire: the answer ends without its last chunk, so the entry reads a broken
			// stream and never mistakes it for a whole one.
			panic(http.ErrAbortHandler)
		}
	}
}

// peerFailure is the code and x-gray-peer-sent of a peer request that got no answer. A request none of whose
// bytes any session took is peer_connect_failed, peer_tls_failed or peer_pin_mismatch (sent 0); once a session
// took a byte, the byte may have reached the peer (sent 1), and the code is peer_failed_after_send. peer_timeout,
// the silence bound, says either, by when it fired.
func peerFailure(err error, trace *peerTrace, silence *peerSilence) (string, bool) {
	sent := trace.sent()
	if silence.fired.Load() {
		return errPeerTimeout, sent
	}
	if sent {
		return errPeerFailedAfterSend, true
	}
	var dialErr *peerDialError
	if errors.As(err, &dialErr) {
		return dialErr.code, false
	}
	return errPeerConnectFailed, false
}

// servePeerControl is /v1/peer/: the pin table, PUT only.
func (s *server) servePeerControl(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = peerControlRoute
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	switch {
	case r.Method == http.MethodConnect:
		refuse(errMethodRefused)
	case r.URL == nil || r.URL.IsAbs() || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" ||
		strings.ContainsAny(r.RequestURI, "?#"):
		refuse(errTargetRefused)
	case rawPathOf(r) != peerPinsPath:
		refuse(errRouteRefused)
	case r.Method != http.MethodPut:
		refuse(errMethodRefused)
	default:
		s.putPins(rec, r, entry)
	}
}

// wirePin is one pin as the entry sends it (§4.3 step 3; docs/design/relay-outbound-only.md §3.3). peer is the
// keyset digest's 64 lower hex (without @gray/attest's `sha256:` prefix, the same text as the /peer/ path segment);
// relay is the relay id peerlink's CONNECT names; spki_sha256 is the keyset's TLS SPKI SHA-256 in 64 lower hex;
// not_after is Unix seconds, the first second the pin no longer holds, as a keyset's not_after. A row is refused
// without -peer-link, and a row naming an `origin` (a VM dialed by name, gone with §9 step 8) is an unknown member.
type wirePin struct {
	Peer       *string `json:"peer"`
	Relay      *string `json:"relay"`
	SPKISHA256 *string `json:"spki_sha256"`
	NotAfter   *uint64 `json:"not_after"`
}

// putPins replaces the pin table. A pin whose not_after has passed is accepted and never dialed: the table is the
// entry's, and expiry is judged at each use.
func (s *server) putPins(rec *responseRecorder, r *http.Request, entry *requestLog) {
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	version, versionOK := stackU64Header(r.Header, peerVersionHeader)
	push, pushOK := stackU64Header(r.Header, peerPushHeader)
	var rows []wirePin
	if !versionOK || !pushOK || checkStrictJSON(body) != nil || !decodeControl(body, &rows) || rows == nil || len(rows) > peerMaxPins {
		refuse(errPeerControlInvalid)
		return
	}
	// At most an hour from the current second rounded up, as a registration's expires_at.
	now := s.peers.now()
	ceiling := now.Unix() + int64(peerPinMaxTTL/time.Second)
	if now.Nanosecond() > 0 {
		ceiling++
	}
	pins := make([]*peerPin, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		pin, ok := parsePin(row, ceiling, s.cfg.peerLink != "")
		if !ok || seen[pin.digest] {
			refuse(errPeerControlInvalid)
			return
		}
		seen[pin.digest] = true
		pins = append(pins, pin)
	}
	if !s.peers.replace(version, push, pins) {
		refuse(errPeerPinsStale)
		return
	}
	rec.WriteHeader(http.StatusNoContent)
}

// parsePin is one row; channels is whether -peer-link is set, without which every row is refused.
func parsePin(row wirePin, ceiling int64, channels bool) (*peerPin, bool) {
	if !channels || row.Peer == nil || row.Relay == nil || row.SPKISHA256 == nil || row.NotAfter == nil {
		return nil, false
	}
	if !validPeerDigest(*row.Peer) || !validPeerRelay(*row.Relay) || len(*row.SPKISHA256) != 64 || !isLowerHex(*row.SPKISHA256) || *row.NotAfter > uint64(ceiling) {
		return nil, false
	}
	pin := &peerPin{digest: *row.Peer, relay: *row.Relay, host: *row.Peer + peerLinkHostSuffix, notAfter: time.Unix(int64(*row.NotAfter), 0)}
	if _, err := hex.Decode(pin.spki[:], []byte(*row.SPKISHA256)); err != nil {
		return nil, false
	}
	return pin, true
}

// replace installs a table unless (version, push) is below the highest pair accepted, as setAccounts does. A row
// equal to a current one in digest, host, relay and SPKI keeps that row's transport; every other current row's idle
// sessions are closed (sessions in use finish their request: they were verified against their own pin).
func (t *peerTable) replace(version, push uint64, pins []*peerPin) bool {
	t.mu.Lock()
	if t.set && (version < t.version || (version == t.version && push < t.push)) {
		t.mu.Unlock()
		return false
	}
	old := t.pins
	next := make(map[string]*peerPin, len(pins))
	for _, pin := range pins {
		if kept := old[pin.digest]; kept != nil && kept.host == pin.host && kept.relay == pin.relay && kept.spki == pin.spki {
			pin.transport, pin.client = kept.transport, kept.client
			delete(old, pin.digest)
		} else {
			spki := pin.spki
			pin.transport = t.srv.newPeerTransport(peerTarget{digest: pin.digest, relay: pin.relay, spki: &spki})
			pin.client = peerClient(pin.transport)
		}
		next[pin.digest] = pin
	}
	t.pins, t.version, t.push, t.set = next, version, push, true
	t.mu.Unlock()
	for _, gone := range old {
		gone.transport.CloseIdleConnections()
	}
	return true
}

// lookup is the live pin for digest, nil when there is none; a pin past its not_after is removed here.
func (t *peerTable) lookup(digest string) *peerPin {
	t.mu.Lock()
	pin := t.pins[digest]
	if pin == nil || t.now().Before(pin.notAfter) {
		t.mu.Unlock()
		return pin
	}
	delete(t.pins, digest)
	t.mu.Unlock()
	pin.transport.CloseIdleConnections()
	return nil
}

func (t *peerTable) closeIdleConnections() {
	t.mu.Lock()
	transports := make([]*http.Transport, 0, len(t.pins))
	for _, pin := range t.pins {
		transports = append(transports, pin.transport)
	}
	t.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

// validPeerRelay is a relay id as @gray/control's LANE_RELAY_ID_PATTERN (`^[A-Za-z0-9._:-]{1,128}$`, the
// relay-connector's RESOURCE_ID) but for `.` and `..`, so it is always one plain segment of attest mode's path and
// a header value as it is.
func validPeerRelay(relay string) bool {
	if relay == "" || len(relay) > peerRelayMaxBytes || relay == "." || relay == ".." {
		return false
	}
	for i := 0; i < len(relay); i++ {
		c := relay[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != ':' && c != '-' {
			return false
		}
	}
	return true
}

// validPeerDigest is a keyset digest's hex: 64 lower hex.
func validPeerDigest(digest string) bool {
	return len(digest) == 64 && isLowerHex(digest)
}
