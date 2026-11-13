package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// POST /v1/stack/proxy-check (design §8.1; the bridge op stack.proxy_checks, E1b): the entry asks egress to test
// one of the relay's proxies from the VM, the network the relay's vendor calls leave from. The check dials the
// proxy exactly as a vendor call through that proxy does: a clone of the proxied transport (the same dial, the
// same proxy TLS and roots, CONNECT or SOCKS5 with the spec's credentials through proxyFromContext, the same
// CONNECT answer rule), a tunnel to the vendor's API host on 443, and the TLS handshake that verifies the vendor's
// certificate against egress's roots. It sends nothing: the connection is closed in GotConn, which net/http calls
// before the request is handed to the connection's writer, and the clone keeps no connection alive. No account
// credential is involved and no request reaches the vendor.
//
// The whole check is bounded by proxyConnectCap, the one-minute ceiling of a proxied vendor call's connect phase
// (server.go); a check that has not finished by then is `timeout`. The answer is always 200
// {"outcome":"ok","code":null,"latency_ms":N} (dial start to the end of the vendor's handshake) or
// {"outcome":"failed","code":C,"latency_ms":null} with one of the codes below; a malformed request is
// stack_control_invalid. The entry names `credential_missing` itself, before it asks.
const stackProxyCheckPath = "/v1/stack/proxy-check"

// stackProxyCheckBodyMax bounds the body: the proxy spec is at most maxEgressHeaderBytes and the vendor one word.
const stackProxyCheckBodyMax = 4 << 10

// The failure codes of a check (@gray/lane-wire PROXY_CHECK_CODES, less the entry's own credential_missing).
const (
	proxyCheckUnreachable         = "proxy_unreachable"
	proxyCheckAuthFailed          = "proxy_auth_failed"
	proxyCheckRefused             = "proxy_refused"
	proxyCheckUpstreamUnreachable = "upstream_unreachable"
	proxyCheckTLSFailed           = "tls_failed"
	proxyCheckTimeout             = "timeout"
)

type wireProxyCheck struct {
	Proxy  json.RawMessage `json:"proxy"`
	Vendor *string         `json:"vendor"`
}

type proxyCheckAnswer struct {
	Outcome   string  `json:"outcome"`
	Code      *string `json:"code"`
	LatencyMs *int64  `json:"latency_ms"`
}

func (s *server) serveProxyCheck(rec *responseRecorder, r *http.Request, entry *requestLog) {
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	if r.Method != http.MethodPost {
		refuse(errMethodRefused)
		return
	}
	body, readBytes, err := readRequestBody(r, stackProxyCheckBodyMax)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		refuse(code)
		return
	}
	var wire wireProxyCheck
	if !decodeControl(body, &wire) || wire.Proxy == nil || wire.Vendor == nil {
		refuse(errStackControlInvalid)
		return
	}
	host, known := stackVendorHost(*wire.Vendor)
	// The same E2 parser as the header and the account table: the same caps and refusals.
	spec, err := parseEgressSpec([]string{string(wire.Proxy)})
	if !known || err != nil {
		refuse(errStackControlInvalid)
		return
	}
	payload, err := json.Marshal(s.checkProxy(r.Context(), spec, host))
	if err != nil {
		refuse(errInternal)
		return
	}
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.Write(payload)
}

// stackVendorHost is the official host a vendor's route calls (stackVendors, routeTable).
func stackVendorHost(vendor string) (string, bool) {
	name, known := stackVendors[vendor]
	if !known {
		return "", false
	}
	for _, rt := range routeTable {
		if rt.name == name {
			return rt.host, true
		}
	}
	return "", false
}

func (s *server) checkProxy(ctx context.Context, spec *egressSpec, host string) proxyCheckAnswer {
	if hello := s.profiles.defaultHello(false); hello != nil && s.mirror != nil {
		var connectStatus atomic.Int64
		ctx = context.WithValue(ctx, proxyConnectStatusKey{}, func(status int) {
			connectStatus.Store(int64(status))
		})
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var timedOut atomic.Bool
		timer := s.afterFunc(proxyConnectCap, func() {
			timedOut.Store(true)
			cancel()
		})
		defer timer.Stop()
		var handshakes atomic.Int64
		start := time.Now()
		trace := &httptrace.ClientTrace{
			TLSHandshakeStart: func() { handshakes.Add(1) },
		}
		conn, _, err := s.mirror.dialVendor(httptrace.WithClientTrace(ctx, trace), hello, spec, net.JoinHostPort(host, "443"), nil)
		if err == nil {
			ms := time.Since(start).Milliseconds()
			_ = conn.Close()
			return proxyCheckAnswer{Outcome: "ok", LatencyMs: &ms}
		}
		code := proxyCheckCode(err, spec.kind, int(connectStatus.Load()), handshakes.Load(), timedOut.Load())
		return proxyCheckAnswer{Outcome: "failed", Code: &code}
	}
	transport := s.proxiedTransport.Clone()
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	var connectStatus atomic.Int64
	transport.OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, req *http.Request, res *http.Response) error {
		connectStatus.Store(int64(res.StatusCode))
		return onProxyConnectResponse(ctx, proxyURL, req, res)
	}
	ctx, cancel := context.WithCancel(context.WithValue(ctx, proxyContextKey{}, spec))
	defer cancel()
	var timedOut atomic.Bool
	timer := s.afterFunc(proxyConnectCap, func() {
		timedOut.Store(true)
		cancel()
	})
	defer timer.Stop()
	var handshakes atomic.Int64
	var connected atomic.Bool
	var latency atomic.Int64
	start := time.Now()
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { handshakes.Add(1) },
		GotConn: func(info httptrace.GotConnInfo) {
			latency.Store(time.Since(start).Milliseconds())
			connected.Store(true)
			_ = info.Conn.Close()
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+host+"/", http.NoBody)
	if err == nil {
		var resp *http.Response
		resp, err = transport.RoundTrip(req)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	if connected.Load() {
		ms := latency.Load()
		return proxyCheckAnswer{Outcome: "ok", LatencyMs: &ms}
	}
	code := proxyCheckCode(err, spec.kind, int(connectStatus.Load()), handshakes.Load(), timedOut.Load())
	return proxyCheckAnswer{Outcome: "failed", Code: &code}
}

// proxyCheckCode names why a check got no connection. The vendor's handshake is the last TLS handshake of the
// connect phase (the second for an https proxy, whose own handshake comes first); a failure once it started is the
// vendor's. Before it, the CONNECT answer, then proxyStage's classes and the SOCKS5 reply decide.
func proxyCheckCode(err error, kind string, connectStatus int, handshakes int64, timedOut bool) string {
	if timedOut || errors.Is(err, context.DeadlineExceeded) {
		return proxyCheckTimeout
	}
	vendorHandshake := int64(1)
	if kind == "https" {
		vendorHandshake = 2
	}
	if handshakes >= vendorHandshake {
		return proxyCheckTLSFailed
	}
	if handshakes == 1 && isTLSError(err) {
		// An https proxy whose own certificate or handshake failed: there is no proxy to talk to.
		return proxyCheckUnreachable
	}
	switch {
	case connectStatus == http.StatusProxyAuthRequired:
		return proxyCheckAuthFailed
	case connectStatus == http.StatusBadGateway, connectStatus == http.StatusServiceUnavailable, connectStatus == http.StatusGatewayTimeout:
		return proxyCheckUpstreamUnreachable
	case connectStatus != 0 && (connectStatus < 200 || connectStatus > 299):
		return proxyCheckRefused
	}
	if stage, ok := proxyStage(err); ok {
		switch stage {
		case "dial":
			return proxyCheckUnreachable
		case "auth":
			return proxyCheckAuthFailed
		}
		// "connect": a SOCKS5 reply, or a proxy that ended the tunnel's setup without a usable answer.
		if socksTargetUnreachable(err) {
			return proxyCheckUpstreamUnreachable
		}
		return proxyCheckRefused
	}
	// A failure net/http does not class (a DNS failure for the proxy's name among them): the proxy was not reached.
	return proxyCheckUnreachable
}

// socksTargetUnreachable is a SOCKS5 reply that says the proxy could not reach the target (RFC 1928 §6: 3 network
// unreachable, 4 host unreachable, 5 connection refused, 6 TTL expired), as net/http's bundled SOCKS client words
// them; every other refusal (2 not allowed by ruleset, 1 general failure, 7 and 8) is the proxy's.
func socksTargetUnreachable(err error) bool {
	// The SOCKS error may sit under net/http's own wrapping (a "proxyconnect" OpError), so the chain is walked.
	for ; err != nil; err = errors.Unwrap(err) {
		operationError, ok := err.(*net.OpError)
		if !ok || !strings.HasPrefix(operationError.Op, "socks") || operationError.Err == nil {
			continue
		}
		message := operationError.Err.Error()
		for _, reply := range []string{"network unreachable", "host unreachable", "connection refused", "TTL expired"} {
			if strings.Contains(message, reply) {
				return true
			}
		}
		return false
	}
	return false
}
