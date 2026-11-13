package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const egressHeader = "x-gray-egress"

// proxyConnectCap is the sidecar's ceiling on the whole proxied connect phase: the TCP dial to the
// proxy, the TLS handshake with an https proxy, the CONNECT exchange, and the TLS handshake with
// the origin. It is derived from Go's own one-minute CONNECT ceiling: Go 1.27.2
// net/http/transport.go:1995 wraps every proxied CONNECT in
// `testHookProxyConnectTimeout(ctx, 1*time.Minute)` (the hook is `context.WithTimeout`,
// transport.go:1834), and the select at transport.go:2016-2019 returns `connectCtx.Err()` when it
// fires. The request phase cannot extend it: getConn detaches the request context with
// `context.WithoutCancel` (transport.go:1594-1599), and `WithTimeout` always keeps the earlier
// deadline. The sidecar arms its own timer before the proxy dial and stops it at GotConn, so its
// one-minute bound covers that whole phase, not only the CONNECT answer (D75); a configured phase
// shorter than the cap is honoured, and the README advertises the whole proxied connect phase as
// at most one minute.
const proxyConnectCap = time.Minute

// forwardBufferBytes is the copy buffer of one vendor answer: forward reads at most this much at a time and
// writes it on before reading again.
const forwardBufferBytes = 32 << 10

// proxyContextKey carries the per-request spec from ServeHTTP to Transport.Proxy.
// A context value is needed because the Transport is shared and the proxy choice
// is per request; a header on the outbound request would be the wrong mechanism
// (the transport can add or drop headers).
type proxyContextKey struct{}

var (
	errProxyAuth           = errors.New("egress proxy authentication required")
	errProxyConnect        = errors.New("egress proxy connect failed")
	errBodyTooLargeRequest = errors.New("request body too large")
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

type server struct {
	cfg              config
	client           *http.Client
	transport        *http.Transport // direct requests: HTTP/2 allowed
	proxiedTransport *http.Transport // proxied requests: HTTP/1.1 only
	// relayClient carries relay calls (S16): the same two transports, except that the direct one's HTTP/2
	// receive windows are bounded (relayHTTP2Config), so a relay that reads slowly holds at most a window
	// per call of vendor data in the transport. The entry's direct calls keep Go's defaults.
	relayClient           *http.Client
	relayTransport        *http.Transport
	relayProxiedTransport *http.Transport
	// mirror is the pool of vendor connections that repeat a container's ClientHello (mirror_dial.go).
	mirror *mirrorPool
	// profiles are the handshake shapes egress learned and repeats; relayProbe, when set, says whether the relay
	// container listens (mirror_profiles.go).
	profiles   *helloProfiles
	relayProbe func(context.Context) bool
	// mirrorSignals counts what the tunnels' taps did not record (mirror_signals.go).
	mirrorSignals mirrorSignals
	logger        *log.Logger
	// afterFunc arms the connect-phase timer (D66). It is time.AfterFunc in production; a test
	// replaces it to fire the phase deterministically instead of waiting on the wall clock.
	afterFunc func(time.Duration, func()) *time.Timer
	// stack is the relay-stack part (S14-S17): nil unless -relay-listen is set, and then the unix
	// socket also serves the control API and serveRelay is the relay listener's handler.
	stack *stack
	// ops is own calls (stack_ops.go): account upkeep on egress's own schedule, present with a relay stack.
	ops *stackOps
	// peers is the peer mode (peer.go): nil unless -peer is set. roots and dial are the vendor transports'
	// own, which every peer transport uses too.
	peers *peerTable
	// signIn is the sign-in proxy's and sessions' state (signin_session.go); used only with ops.
	signIn *signInState
	roots  *x509.CertPool
	dial   dialFunc
}

// newServer builds the transports the program uses. Production passes the pool
// loaded from the image's CA bundle (roots_production.go); a nil pool means
// crypto/x509's system roots and is used only by the e2e build without an extra
// root. Tests pass a pool built from their own CA through this unexported
// constructor, never through a flag. dial is nil in production; tests pass a
// hook that redirects a route host to an in-process listener. Neither hook can
// be reached from the command line.
func newServer(cfg config, roots *x509.CertPool, dial dialFunc, logger *log.Logger) *server {
	if dial == nil {
		dialer := &net.Dialer{Timeout: cfg.dialTimeout, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	direct := newTransport(cfg, roots, dial, true)
	proxied := newTransport(cfg, roots, dial, false)
	relayDirect := newTransport(cfg, roots, dial, true)
	relayDirect.HTTP2 = relayHTTP2Config(cfg)
	relayProxied := newTransport(cfg, roots, dial, false)
	mirror := newMirrorPool(cfg, roots, dial)
	srv := &server{
		cfg:                   cfg,
		client:                newVendorClient(direct, proxied),
		transport:             direct,
		proxiedTransport:      proxied,
		relayClient:           newVendorClient(relayDirect, relayProxied),
		mirror:                mirror,
		profiles:              newHelloProfilesWithin("", cfg.stackMaxBytes),
		relayTransport:        relayDirect,
		relayProxiedTransport: relayProxied,
		logger:                logger,
		afterFunc:             time.AfterFunc,
		signIn:                newSignInState(),
		roots:                 roots,
		dial:                  dial,
	}
	// Relay calls made in a vendor tunnel repeat the tunnel's ClientHello (mirror_dial.go).
	srv.relayClient.Transport.(*modeRoundTripper).mirror = mirror
	if cfg.peer {
		srv.peers = newPeerTable(srv)
	}
	return srv
}

func newVendorClient(direct, proxied *http.Transport) *http.Client {
	return &http.Client{
		Transport: &modeRoundTripper{direct: direct, proxied: proxied},
		// A redirect is an upstream answer, not something this program may
		// follow: following one would dial a host that is not in the route table.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// closeIdleConnections closes every transport's idle vendor connections.
func (s *server) closeIdleConnections() {
	for _, transport := range []*http.Transport{s.transport, s.proxiedTransport, s.relayTransport, s.relayProxiedTransport} {
		transport.CloseIdleConnections()
	}
	s.mirror.closeIdle()
	if s.peers != nil {
		s.peers.closeIdleConnections()
	}
}

// newTransport builds a Transport with the shared TLS, dial and limit settings.
// allowHTTP2 is false for the proxy path: net/http's bundled HTTP/2 pool is
// keyed by origin authority only, so with two proxies it can reuse the first
// proxy's multiplexed tunnel for a request that named the second proxy without
// calling Transport.Proxy at all. HTTP/1.1 pools are keyed by proxy + origin,
// so the proxy path stays HTTP/1.1. The direct path keeps HTTP/2.
func newTransport(cfg config, roots *x509.CertPool, dial dialFunc, allowHTTP2 bool) *http.Transport {
	transport := &http.Transport{
		Proxy:                  proxyFromContext,
		DialContext:            dial,
		ForceAttemptHTTP2:      allowHTTP2,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    cfg.tlsHandshakeTimeout,
		ResponseHeaderTimeout:  cfg.responseHeaderTimeout,
		IdleConnTimeout:        cfg.idleConnTimeout,
		MaxIdleConns:           64,
		MaxIdleConnsPerHost:    8,
		DisableCompression:     true,
		OnProxyConnectResponse: onProxyConnectResponse,
	}
	if !allowHTTP2 {
		// The documented way to keep a Transport on HTTP/1.1. ForceAttemptHTTP2
		// is already false; the empty map also stops ALPN from offering h2.
		transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	}
	return transport
}

// modeRoundTripper chooses the transport by whether the request carries a
// validated egress spec. The two transports never share a pool.
type modeRoundTripper struct {
	direct  *http.Transport
	proxied *http.Transport
	// mirror, when set, carries the requests that have a container's ClientHello to repeat (mirror_dial.go).
	mirror *mirrorPool
}

func (m *modeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.mirror != nil && mirroredHelloOf(req.Context()) != nil {
		return m.mirror.RoundTrip(req)
	}
	if spec, _ := req.Context().Value(proxyContextKey{}).(*egressSpec); spec != nil {
		return m.proxied.RoundTrip(req)
	}
	return m.direct.RoundTrip(req)
}

func (m *modeRoundTripper) CloseIdleConnections() {
	m.direct.CloseIdleConnections()
	m.proxied.CloseIdleConnections()
}

func proxyFromContext(req *http.Request) (*url.URL, error) {
	spec, _ := req.Context().Value(proxyContextKey{}).(*egressSpec)
	if spec == nil {
		return nil, nil
	}
	return spec.proxyURL(), nil
}

// onProxyConnectResponse turns a non-2xx CONNECT answer into a typed error, so
// the handler can tell 407 (auth) from every other tunnel failure (connect).
func onProxyConnectResponse(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
	switch {
	case res.StatusCode == http.StatusProxyAuthRequired:
		return errProxyAuth
	case res.StatusCode < 200 || res.StatusCode >= 300:
		return errProxyConnect
	default:
		return nil
	}
}

// requestPlan is the result of every check that happens before a dial: the
// route, the exact upstream URL, and the optional proxy spec.
type requestPlan struct {
	route  route
	target *url.URL
	spec   *egressSpec
}

// requestTrace records whether net/http obtained a usable connection. For an
// HTTPS request through a proxy that means the proxy dial, CONNECT and the
// origin's TLS handshake all succeeded; for a direct request it means the vendor
// dial and TLS handshake succeeded. A later failure is the origin's, not the
// proxy's or the dial's. GotConn is called by the Transport from its own
// goroutine.
type requestTrace struct {
	connected atomic.Bool
	// phaseTimer is the connect phase's deadline timer for a proxied request (D66). GotConn stops
	// it: once the tunnel and the origin TLS handshake exist, the response-header timeout takes
	// over and a stream may run for the lane's full stream limit. Stop is safe from the transport's
	// goroutine and from the deferred handler cleanup.
	phaseTimer *time.Timer
}

func (t *requestTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			t.connected.Store(true)
			if t.phaseTimer != nil {
				t.phaseTimer.Stop()
			}
		},
	}
}

// plan validates the request-target form, route, method, Host, path and the
// egress header, in that order. It never dials, resolves or reads the body. The returned error
// code is empty on success.
func (s *server) plan(r *http.Request) (requestPlan, string) {
	plan, code := planTarget(r, true)
	if code != "" {
		return plan, code
	}
	spec, err := parseEgressSpec(r.Header.Values(egressHeader))
	if err != nil {
		return plan, errSpecRefused
	}
	plan.spec = spec
	return plan, ""
}

// planTarget is plan without the egress header: the target form, route, method, Host (when
// checkHost) and path. A relay call (S16) skips the Host rule, since its Host names the relay
// listener and the outbound Host is the route's constant either way, and takes its proxy from the
// account table instead of the header.
func planTarget(r *http.Request, checkHost bool) (requestPlan, string) {
	var plan requestPlan
	if r.Method == http.MethodConnect {
		return plan, errMethodRefused
	}
	if r.URL == nil || r.URL.IsAbs() || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" {
		return plan, errTargetRefused
	}
	// net/http's server parses the request-target with ParseRequestURI, which does not split a
	// fragment: a raw '#' survives in the path or RawQuery. It would become a fragment if this
	// program turned the target back into a URL string, so it is refused here (D59). An encoded
	// %23 is an ordinary byte and stays allowed.
	if strings.Contains(r.RequestURI, "#") {
		return plan, errTargetRefused
	}
	rt, ok := matchRoute(rawPathOf(r))
	if !ok {
		return plan, errRouteRefused
	}
	plan.route = rt
	if !allowedMethod(r.Method) {
		return plan, errMethodRefused
	}
	if checkHost && !hostMatches(r, rt) {
		return plan, errHostRefused
	}
	target, ok := rt.target(r)
	if !ok {
		return plan, errPathRefused
	}
	plan.target = target
	return plan, ""
}

// ServeHTTP is the unix socket's handler: the entry's direct vendor traffic, with a relay stack the
// control API under /v1/stack/ (S14, S15), and with -peer the peer mode under /v1/peer/ and /peer/
// (peer.go). The relay listener has its own handler (serveRelay), which has neither.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := rawPathOf(r)
	switch {
	case s.ops != nil && strings.HasPrefix(path, stackOpsControlPrefix):
		s.handled(w, r, s.serveOpsControl)
	case s.stack != nil && strings.HasPrefix(path, stackControlPrefix):
		s.handled(w, r, s.serveControl)
	case s.peers != nil && strings.HasPrefix(path, peerControlPrefix):
		s.handled(w, r, s.servePeerControl)
	case s.peers != nil && strings.HasPrefix(path, peerPrefix):
		s.handled(w, r, s.servePeer)
	default:
		s.handled(w, r, s.serveDirect)
	}
}

// handled runs one request with the panic guard and writes the one log line every handled
// request produces (README "Logs"); serve fills the route, the request byte count and the code.
func (s *server) handled(w http.ResponseWriter, r *http.Request, serve func(*responseRecorder, *http.Request, *requestLog)) {
	start := time.Now()
	rec := &responseRecorder{ResponseWriter: w}
	var entry requestLog
	defer func() {
		recovered := recover()
		// http.ErrAbortHandler is a handler's request to close the connection without finishing the
		// response (a relay answer cut by the budget, S17): it is logged with its code, then passed on.
		if recovered != nil && recovered != http.ErrAbortHandler {
			entry.Error = errInternal
			if rec.status == 0 {
				writeRefusal(rec, errInternal)
			}
		}
		entry.Status = rec.status
		if entry.Status == 0 {
			entry.Status = http.StatusOK
		}
		entry.DurationMS = time.Since(start).Milliseconds()
		entry.ResponseBytes = rec.bytes
		s.logRequest(entry)
		if recovered == http.ErrAbortHandler {
			panic(http.ErrAbortHandler)
		}
	}()

	if r.Body != nil {
		defer func() { _ = r.Body.Close() }()
	}
	serve(rec, r, &entry)
}

// serveDirect is the entry's own vendor call: the plan, the body, then the vendor.
func (s *server) serveDirect(rec *responseRecorder, r *http.Request, entry *requestLog) {
	plan, code := s.plan(r)
	entry.Route = plan.route.name
	if code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	entry.Error = s.forward(r.Context(), s.client, rec, r.Method, plan, outboundHeader(r.Header), body, nil)
}

func bodyReadCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errBodyTooLargeRequest):
		return errBodyTooLarge
	default:
		return errBodyInvalid
	}
}

// outboundHeader is the request's header set as the vendor receives it: hop-by-hop headers,
// the reserved x-gray-egress and the framing headers net/http writes itself are removed, and
// every other header passes unchanged.
func outboundHeader(in http.Header) http.Header {
	header := in.Clone()
	stripHopByHop(header)
	header.Del(egressHeader)
	header.Del("Host")
	header.Del("Content-Length")
	header.Del("Transfer-Encoding")
	return header
}

// upstreamObserver sees one vendor call without changing a byte of it (S17, S20): the dial
// failure, or the response head and every body chunk before it is written, then how it ended. It
// may stop the call (false from response or chunk) when it cannot hold what it must keep; nothing
// more is then written and forward returns egress_limit.
type upstreamObserver interface {
	// failed is a call that got no response; code is the mapped 502 code.
	failed(code string)
	response(status int, header http.Header) bool
	chunk(p []byte) bool
	// finished is "" at the vendor's EOF, otherwise errClientWrite, errResponseRead or errEgressLimit.
	finished(code string)
}

// stoppedCode is the code of an answer obs stopped (false from response or chunk): errEgressLimit, unless obs
// names another (a relay call's coded answer egress cannot decode is errResponseRead, stack_coding.go).
func stoppedCode(obs upstreamObserver) string {
	if named, ok := obs.(interface{ stopCode() string }); ok && named.stopCode() != "" {
		return named.stopCode()
	}
	return errEgressLimit
}

// forward sends the planned request to the vendor and streams the answer back unchanged; obs,
// when not nil, observes it. It returns the log's error code ("" on success).
func (s *server) forward(ctx context.Context, client *http.Client, rec *responseRecorder, method string, plan requestPlan, header http.Header, body []byte, obs upstreamObserver) string {
	finish := func(code string) string {
		if obs != nil {
			obs.finished(code)
		}
		return code
	}
	trace := &requestTrace{}
	if plan.spec != nil {
		ctx = context.WithValue(ctx, proxyContextKey{}, plan.spec)
		// D66/D75: give the proxied dial the request's cancellable context with the connect-phase
		// deadline. The phase is the gateway's upstream-header wait; for an http/https proxy it is
		// capped at proxyConnectCap, one minute for the whole proxied connect phase (proxy dial,
		// proxy TLS, CONNECT and origin TLS). The timer is stopped at GotConn so it never cuts a
		// streaming answer.
		phase := s.cfg.responseHeaderTimeout
		if (plan.spec.kind == "http" || plan.spec.kind == "https") && phase > proxyConnectCap {
			phase = proxyConnectCap
		}
		phaseContext, cancel := context.WithCancel(ctx)
		defer cancel()
		ctx = phaseContext
		trace.phaseTimer = s.afterFunc(phase, cancel)
		defer trace.phaseTimer.Stop()
	}
	if accounted, ok := obs.(mirrorAccounted); ok {
		ctx = context.WithValue(ctx, mirrorAccountKey{}, accounted.mirrorAccount())
	}
	ctx = httptrace.WithClientTrace(ctx, trace.clientTrace())
	// Seed the request from a constant URL and then assign the parsed target. Building it from
	// plan.target.String() would parse the URL a second time and could change it (a raw '#', for
	// example, would move from the query to a fragment); the target this program validated is the
	// one that must reach the vendor (D59).
	outReq, err := http.NewRequestWithContext(ctx, method, "https://"+plan.route.host, bytes.NewReader(body))
	if err != nil {
		if obs != nil {
			obs.failed(errInternal)
		}
		writeRefusal(rec, errInternal)
		return errInternal
	}
	outReq.URL = plan.target
	outReq.Header = header
	// net/http would add its own User-Agent when workerd did not send one. The
	// vendor must see only the headers workerd built, so an absent header stays
	// absent (Request.write omits an empty User-Agent).
	if _, present := outReq.Header["User-Agent"]; !present {
		outReq.Header["User-Agent"] = []string{""}
	}
	outReq.Host = plan.route.host
	if len(body) == 0 {
		outReq.Body = http.NoBody
		outReq.ContentLength = 0
	}

	resp, err := client.Do(outReq)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		mapped := mapUpstreamError(err, plan.spec, trace.connected.Load())
		if obs != nil {
			obs.failed(mapped.code)
		}
		writeMappedError(rec, mapped)
		return mapped.code
	}
	defer func() { _ = resp.Body.Close() }()

	// The reserved per-request header is removed in both directions (D64): an upstream answer
	// must not be able to put a value on the header that only the lane's sidecar consumes.
	resp.Header.Del(egressHeader)
	stripHopByHop(resp.Header)
	// S35: a relay call's error answer is held until it is classified (stack_hold.go).
	if holder, ok := obs.(errorHolder); ok && holder.holds(resp.StatusCode) {
		return finish(s.forwardHeld(rec, resp, obs, holder))
	}
	if obs != nil && !obs.response(resp.StatusCode, resp.Header) {
		return finish(stoppedCode(obs))
	}
	copyHeader(rec.Header(), resp.Header)
	rec.WriteHeader(resp.StatusCode)
	controller := http.NewResponseController(rec)
	// Send the status and headers now, not only with the first body chunk: an
	// SSE client should learn the stream is open even if the first token is slow.
	if flushErr := controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
		return finish(errClientWrite)
	}
	buffer := make([]byte, forwardBufferBytes)
	var written int64
	for {
		n, readErr := resp.Body.Read(buffer)
		if n > 0 {
			// The observer digests a chunk before it is written, so the entry can hold the
			// feed record by the time the relay forwards the event (S24).
			if obs != nil && !obs.chunk(buffer[:n]) {
				return finish(stoppedCode(obs))
			}
			if _, writeErr := rec.Write(buffer[:n]); writeErr != nil {
				return finish(errClientWrite)
			}
			if flushErr := controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
				return finish(errClientWrite)
			}
			written += int64(n)
		}
		if errors.Is(readErr, io.EOF) || declaredLengthWritten(resp, written) {
			return finish("")
		}
		if readErr != nil {
			return finish(errResponseRead)
		}
	}
}

// declaredLengthWritten is true once an answer that declared its length (Content-Length, which egress passes on)
// has had that many bytes written: the answer is whole, by the same framing the client reads it with. forward
// stops there instead of reading on for the vendor's end of stream, because that end can lose a race it has no
// part in. On HTTP/2 the last DATA bytes reach the body before the transport's read loop processes the frame's
// END_STREAM; a client that has every declared byte may close its connection in that gap, net/http then cancels
// the request's context, and the transport ends the stream with that cancellation, so the next Read returns
// context.Canceled instead of io.EOF (Go 1.27.2 net/http/internal/http2/transport.go: writeRequest returns
// ctx.Err() while peerClosed is still open, cleanupWriteRequest closes bufPipe with it, and endStream's io.EOF
// then finds the pipe closed). The answer was then logged response_read and a relay attempt ended without its
// body record, although the client had all of it. HTTP/1.1 returns io.EOF with the last declared byte, so this
// changes nothing there. The transports never return more than the declared length (HTTP/2 truncates and fails
// the read, HTTP/1.1 limits the body to it).
func declaredLengthWritten(resp *http.Response, written int64) bool {
	return resp.ContentLength >= 0 && written >= resp.ContentLength
}

func readRequestBody(r *http.Request, max int64) ([]byte, int64, error) {
	if r.Body == nil {
		return nil, 0, nil
	}
	if r.ContentLength > max {
		return nil, 0, errBodyTooLargeRequest
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return body, int64(len(body)), err
	}
	if int64(len(body)) > max {
		return body, int64(len(body)), errBodyTooLargeRequest
	}
	return body, int64(len(body)), nil
}

func mapUpstreamError(err error, spec *egressSpec, connected bool) mappedError {
	// D72, S32: once GotConn fired the request may have reached the vendor, so every later failure is
	// egress_upstream_failed, a TLS alert or bad record included; certificate and hostname checks end
	// before GotConn (the transport hands over a connection only after its handshake), so they stay
	// egress_tls_failed, a pre-connect code.
	if connected {
		return mappedError{code: errUpstreamFailed}
	}
	if isTLSError(err) {
		return mappedError{code: errTLSFailed}
	}
	if spec != nil {
		if stage, ok := proxyStage(err); ok {
			return mappedError{code: errProxyFailed, stage: stage}
		}
		// Any other failure before a connection was obtained happened during
		// the proxy dial, CONNECT or the origin's TLS handshake: the tunnel is
		// the part that failed.
		return mappedError{code: errProxyFailed, stage: "connect"}
	}
	// D72: a direct request that never obtained a connection (dial or DNS)
	// failed before the vendor was reached.
	return mappedError{code: errConnectFailed}
}

func isTLSVerificationError(err error) bool {
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return true
	}
	var systemRoots x509.SystemRootsError
	if errors.As(err, &systemRoots) {
		return true
	}
	return false
}

func isTLSError(err error) bool {
	if isTLSVerificationError(err) {
		return true
	}
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &recordHeader) {
		return true
	}
	var alert *tls.AlertError
	return errors.As(err, &alert) || isMirrorTLSError(err)
}

// proxyStage classifies a failed request that had a proxy spec. "dial" is the
// TCP connection to the proxy, "auth" is a 407 or a SOCKS5 authentication
// refusal, and "connect" is every other tunnel failure (including a SOCKS5
// target refusal).
func proxyStage(err error) (string, bool) {
	if errors.Is(err, errProxyAuth) {
		return "auth", true
	}
	if errors.Is(err, errProxyConnect) {
		return "connect", true
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		switch {
		case operationError.Op == "dial":
			return "dial", true
		case operationError.Op == "proxyconnect":
			// net/http wraps a failed proxy TCP dial in a "proxyconnect"
			// OpError whose Err is the inner dial error.
			var inner *net.OpError
			if errors.As(operationError.Err, &inner) && inner.Op == "dial" {
				return "dial", true
			}
			return "connect", true
		case strings.HasPrefix(operationError.Op, "socks"):
			if operationError.Err != nil {
				message := strings.ToLower(operationError.Err.Error())
				if strings.Contains(message, "authentication") || strings.Contains(message, "invalid username/password") {
					return "auth", true
				}
			}
			return "connect", true
		}
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "dial", true
	}
	return "", false
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *responseRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type requestLog struct {
	Route         string `json:"route"`
	Status        int    `json:"status"`
	DurationMS    int64  `json:"duration_ms"`
	RequestBytes  int64  `json:"request_bytes"`
	ResponseBytes int64  `json:"response_bytes"`
	Error         string `json:"error"`
	// Peer is a peer request's timing (peer.go), absent from every other line.
	Peer *peerTiming `json:"peer,omitempty"`
}

func (s *server) logRequest(entry requestLog) {
	payload, err := json.Marshal(entry)
	if err != nil {
		return
	}
	s.logger.Print(string(payload))
}
