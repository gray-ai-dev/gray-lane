// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/megaeth-labs/gray/deploy/tee/egress/third_party/stdhttp2/internal"
	"io"
	"net/textproto"
	"net/url"
	"time"
)

// Since net/http imports the http2 package, http2 cannot use any net/http types.
// This file contains definitions which exist to to avoid introducing a dependency cycle.

// Variables defined in net/http and initialized by an init func in that package.
//
// NoBody and LocalAddrContextKey have concrete types in net/http,
// and therefore can't be moved into a common package without introducing
// a dependency cycle.
var (
	NoBody              io.ReadCloser
	LocalAddrContextKey any
)

var (
	ErrAbortHandler    = internal.ErrAbortHandler
	ErrBodyNotAllowed  = internal.ErrBodyNotAllowed
	ErrNotSupported    = errors.ErrUnsupported
	ErrSkipAltProtocol = internal.ErrSkipAltProtocol
)

// A ClientRequest is a Request used by the HTTP/2 client (Transport).
type ClientRequest struct {
	Context       context.Context
	Method        string
	URL           *url.URL
	Header        Header
	Trailer       Header
	Body          io.ReadCloser
	Host          string
	GetBody       func() (io.ReadCloser, error)
	ContentLength int64
	Cancel        <-chan struct{}
	Close         bool
	ResTrailer    *Header

	// Include the per-request stream in the ClientRequest to avoid an allocation.
	stream clientStream
}

// Clone makes a shallow copy of ClientRequest.
//
// Clone is only used in shouldRetryRequest.
// We can drop it if we ever get rid of or rework that function.
func (req *ClientRequest) Clone() *ClientRequest {
	return &ClientRequest{
		Context:       req.Context,
		Method:        req.Method,
		URL:           req.URL,
		Header:        req.Header,
		Trailer:       req.Trailer,
		Body:          req.Body,
		Host:          req.Host,
		GetBody:       req.GetBody,
		ContentLength: req.ContentLength,
		Cancel:        req.Cancel,
		Close:         req.Close,
		ResTrailer:    req.ResTrailer,
	}
}

// A ClientResponse is a Request used by the HTTP/2 client (Transport).
type ClientResponse struct {
	Status        string // e.g. "200"
	StatusCode    int    // e.g. 200
	ContentLength int64
	Uncompressed  bool
	Header        Header
	Trailer       Header
	Body          io.ReadCloser
	TLS           *tls.ConnectionState
}

type Header = textproto.MIMEHeader

// TransportConfig is configuration from an http.Transport.
type TransportConfig interface {
	MaxHeaderListSize() int64
	MaxResponseHeaderBytes() int64
	DisableCompression() bool
	DisableKeepAlives() bool
	ExpectContinueTimeout() time.Duration
	ResponseHeaderTimeout() time.Duration
	IdleConnTimeout() time.Duration
	HTTP2Config() Config
}

// Gray: the server half of api.go (ServerConfig, Handler, ResponseWriter, PushOptions, ServerRequest,
// ConnState) is left out with the server.
