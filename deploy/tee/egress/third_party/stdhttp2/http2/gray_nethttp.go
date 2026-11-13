// Copyright 2026 The Gray Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Gray: the net/http side of the client for a caller outside net/http. net/http/http2.go connects net/http's own
// Transport to this package; HTTPTransport does the same for the client half only, with the conversions written as
// there. Line numbers are Go 1.27.2's src/net/http/http2.go (../BASE).

package http2

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// As http2.go:37-47: NoBody and LocalAddrContextKey must be net/http's values (transport.go compares request and
// response bodies with NoBody).
func init() {
	LocalAddrContextKey = http.LocalAddrContextKey
	NoBody = http.NoBody
}

// HTTPTransport is an http.RoundTripper speaking HTTP/2 only, over connections GrayConfig.DialTLSContext makes. Its
// fields are read when it is first used and must not change afterwards.
type HTTPTransport struct {
	// The net/http.Transport settings the client reads through TransportConfig (api.go; transportConfig,
	// http2.go:456-493).
	DisableCompression     bool
	DisableKeepAlives      bool
	MaxHeaderListSize      int64 // as x/net/http2.Transport.MaxHeaderListSize (http2.go:470-475); 0 means 10 MiB
	MaxResponseHeaderBytes int64
	ExpectContinueTimeout  time.Duration
	ResponseHeaderTimeout  time.Duration
	IdleConnTimeout        time.Duration
	// HTTP2 is net/http.Transport.HTTP2, already merged (mergeHTTP2Config, http2.go:495-552).
	HTTP2 Config

	Gray GrayConfig

	once sync.Once
	t2   *Transport
}

// transport is the HTTP/2 Transport, made once (as configureHTTP2, http2.go:284-292).
func (t *HTTPTransport) transport() *Transport {
	t.once.Do(func() {
		t2 := NewTransport(httpTransportConfig{t})
		t2.gray = &t.Gray
		t.t2 = t2
	})
	return t.t2
}

var errUnsupportedScheme = errors.New("http2: unsupported scheme")

// RoundTrip is http2RoundTrip (http2.go:319-351) over the Transport. Only https URLs are sent, as x/net/http2's
// Transport without AllowHTTP: the dial function always speaks TLS.
func (t *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, errUnsupportedScheme
	}
	resp := &http.Response{}
	cresp, err := t.transport().RoundTrip(&ClientRequest{
		Context:       req.Context(),
		Method:        req.Method,
		URL:           req.URL,
		Header:        Header(req.Header),
		Trailer:       Header(req.Trailer),
		Body:          req.Body,
		Host:          req.Host,
		GetBody:       req.GetBody,
		ContentLength: req.ContentLength,
		Cancel:        req.Cancel,
		Close:         req.Close,
		// The read loop fills resp.Trailer through this pointer once the body has been read to its end.
		ResTrailer: (*Header)(&resp.Trailer),
	})
	if err != nil {
		return nil, err
	}
	resp.Status = cresp.Status + " " + http.StatusText(cresp.StatusCode)
	resp.StatusCode = cresp.StatusCode
	resp.Proto = "HTTP/2.0"
	resp.ProtoMajor = 2
	resp.ProtoMinor = 0
	resp.ContentLength = cresp.ContentLength
	resp.Uncompressed = cresp.Uncompressed
	resp.Header = http.Header(cresp.Header)
	resp.Trailer = http.Header(cresp.Trailer)
	resp.Body = cresp.Body
	resp.TLS = cresp.TLS
	resp.Request = req
	return resp, nil
}

// CloseIdleConnections closes the Transport's idle connections.
func (t *HTTPTransport) CloseIdleConnections() {
	t.transport().CloseIdleConnections()
}

// Retire closes the Transport's idle connections now and each busy one as its last call ends; none takes a new
// call (ClientConn.SetDoNotReuse).
func (t *HTTPTransport) Retire() {
	p := t.transport().connPool.clientConnPool
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conns := range p.conns {
		for _, cc := range conns {
			cc.SetDoNotReuse()
			cc.closeIfIdle()
		}
	}
}

// httpTransportConfig implements TransportConfig from an HTTPTransport (transportConfig, http2.go:456-552).
type httpTransportConfig struct{ t *HTTPTransport }

func (c httpTransportConfig) MaxHeaderListSize() int64             { return c.t.MaxHeaderListSize }
func (c httpTransportConfig) MaxResponseHeaderBytes() int64        { return c.t.MaxResponseHeaderBytes }
func (c httpTransportConfig) DisableCompression() bool             { return c.t.DisableCompression }
func (c httpTransportConfig) DisableKeepAlives() bool              { return c.t.DisableKeepAlives }
func (c httpTransportConfig) ExpectContinueTimeout() time.Duration { return c.t.ExpectContinueTimeout }
func (c httpTransportConfig) ResponseHeaderTimeout() time.Duration { return c.t.ResponseHeaderTimeout }
func (c httpTransportConfig) IdleConnTimeout() time.Duration       { return c.t.IdleConnTimeout }
func (c httpTransportConfig) HTTP2Config() Config                  { return c.t.HTTP2 }
