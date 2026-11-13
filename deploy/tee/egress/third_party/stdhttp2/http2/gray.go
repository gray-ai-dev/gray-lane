// Copyright 2026 The Gray Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Gray: the wire layout of the client connection preface and of each request's HEADERS frame, the Transport's dial
// function and response field count limit. This file, gray_nethttp.go and the hunks marked "Gray:" in transport.go,
// api.go, config.go and ../internal/httpcommon/httpcommon.go are the whole patch on Go's net/http/internal/http2
// (../README.md, ../gray.patch).

package http2

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"strings"

	"github.com/megaeth-labs/gray/deploy/tee/egress/third_party/stdhttp2/internal/httpcommon"
	"golang.org/x/net/http2/hpack"
)

// GrayConfig is a Transport's Gray-only configuration (HTTPTransport sets it).
type GrayConfig struct {
	// DialTLSContext dials every new connection; the Transport has no dial of its own. Without it a new connection
	// fails with errNoDialTLSContext.
	DialTLSContext func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)

	// Preface, when non-nil, is the connection preface new connections write instead of the Transport's own. A new
	// connection fails if it is invalid.
	Preface *ConnPreface

	// RequestLayout, when non-nil, gives each request's HEADERS priority, pseudo-header order and header order.
	RequestLayout func(*ClientRequest) RequestLayout

	// Refund, when set, is when the connection returns flow-control window to the peer (WINDOW_UPDATE): once the
	// window read and not yet returned reaches the fraction of the window, as the client being repeated does. Zero
	// fields keep the transport's rule (4 KiB, or when the return would at least double the window left).
	Refund RefundPolicy

	// MaxConcurrentStreams, when non-zero, bounds the streams one connection carries at once below what the peer
	// allows; a request past it takes another connection.
	MaxConcurrentStreams uint32

	// MaxHeaderValueCount bounds the number of fields in one response's header block (and, separately, its
	// trailers); a response over it fails like one over MaxHeaderListSize (Framer.MaxHeaderValueCount, which
	// net/http sets only on its server). 0 means 500, net/http's DefaultMaxHeaderValueCount; a negative value means
	// no limit.
	MaxHeaderValueCount int
}

var errNoDialTLSContext = errors.New("http2: Transport has no DialTLSContext")

func (t *Transport) grayPreface() *ConnPreface {
	if t.gray == nil {
		return nil
	}
	return t.gray.Preface
}

func (t *Transport) maxHeaderValueCount() int {
	n := 0
	if t.gray != nil {
		n = t.gray.MaxHeaderValueCount
	}
	switch {
	case n == 0:
		return defaultMaxHeaderValueCount
	case n < 0:
		return 0
	}
	return n
}

// PrefaceFrame is one frame of a ConnPreface. Type is FrameSettings, FrameWindowUpdate or FramePriority.
type PrefaceFrame struct {
	Type FrameType
	// Settings is a SETTINGS frame's parameters, sent in this order with these values.
	Settings []Setting
	// Increment is a stream-0 WINDOW_UPDATE frame's increment.
	Increment uint32
	// StreamID and Priority are a PRIORITY frame's stream and priority fields.
	StreamID uint32
	Priority PriorityParam
}

// ConnPreface replaces the Transport's own connection preface: after the client magic, a new connection writes
// exactly Frames, in order. RFC 9113 3.4 requires the first frame to be SETTINGS; there is exactly one SETTINGS
// frame, at most one stream-0 WINDOW_UPDATE and any number of PRIORITY frames. The connection's receive windows are
// accounted from what the frames announce: each stream's from SETTINGS_INITIAL_WINDOW_SIZE (65535 when absent), the
// connection's 65535 plus the WINDOW_UPDATE increment (65535 when no WINDOW_UPDATE is sent). The HPACK decoder's
// table is SETTINGS_HEADER_TABLE_SIZE (4096 when absent), which may not exceed Config.MaxDecoderHeaderTableSize.
// The first request's stream ID is above every PRIORITY frame's stream.
type ConnPreface struct {
	Frames []PrefaceFrame
}

// RequestLayout is the wire layout of one request's HEADERS frame.
type RequestLayout struct {
	// Priority, when non-nil and non-zero, is sent in the HEADERS frame's priority fields (PRIORITY flag set).
	Priority *PriorityParam
	// PseudoOrder orders the request pseudo-header fields (":method", ":authority", ":scheme", ":path",
	// ":protocol"); fields it leaves out follow in the default order. Unknown names are an error.
	PseudoOrder []string
	// HeaderOrder lists lower-case regular field names in the order to encode them; fields it leaves out follow,
	// sorted by name. "content-length" places the Content-Length field the transport adds.
	HeaderOrder []string
	// ContentLength says whether the HEADERS frame carries content-length (ContentLengthDefault, ContentLengthSend,
	// ContentLengthOmit). The body's framing is the same either way: DATA frames and END_STREAM.
	ContentLength ContentLengthMode
	// NeverIndexed lists lower-case field names written as HPACK literals never indexed (RFC 7541 6.2.3,
	// hpack.HeaderField.Sensitive), as a client marks its credentials.
	NeverIndexed []string
	// CookieAsSent writes each Cookie value as one field, as the client split its cookies, instead of one field per
	// cookie-pair (RFC 9113 8.2.3 allows either).
	CookieAsSent bool
}

// ContentLengthMode is RequestLayout.ContentLength.
type ContentLengthMode = httpcommon.ContentLengthMode

const (
	// ContentLengthDefault is the transport's own rule: a known non-zero length, or 0 for POST, PUT and PATCH.
	ContentLengthDefault = httpcommon.ContentLengthDefault
	// ContentLengthSend sends content-length whenever the body's length is known, 0 included (a GET's too).
	ContentLengthSend = httpcommon.ContentLengthSend
	// ContentLengthOmit never sends content-length.
	ContentLengthOmit = httpcommon.ContentLengthOmit
)

// neverIndexed reports whether the lower-case field name is in l.NeverIndexed.
func (l RequestLayout) neverIndexed(name string) bool {
	for _, n := range l.NeverIndexed {
		if n == name {
			return true
		}
	}
	return false
}

// grayWriteHeader is writeHeader with the field's HPACK representation: never indexed when sensitive.
func (cc *ClientConn) grayWriteHeader(name, value string, sensitive bool) {
	if VerboseLogs {
		log.Printf("http2: Transport encoding header %q = %q", name, value)
	}
	cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value, Sensitive: sensitive})
}

// prefacePlan is a validated ConnPreface and what it means for the connection's accounting.
type prefacePlan struct {
	frames           []PrefaceFrame
	streamRecvWindow int32
	connRecvWindow   int32
	headerTableSize  uint32
	maxReadFrameSize uint32 // 0: keep the configured read limit
	firstStreamID    uint32
}

const defaultInitialWindowSize = 65535 // RFC 9113 6.5.2

// MaxPrefacePriorityStream is the highest stream ID a ConnPreface PRIORITY frame may name. The first request's stream
// comes after it, and a connection is usable only while its next stream ID stays below 2^31-1 (isUsableLocked), so a
// PRIORITY frame near 2^31 would make every new connection unusable at once. The clients that send startup PRIORITY
// frames (Firefox up to 119) name streams 3 to 13; 255 leaves more than 2^31-256 stream IDs to the connection.
const MaxPrefacePriorityStream = 255

// maxDialsPerCall bounds the new connections one request finds, in a row, that no request could take (a peer that
// allows no stream, a connection that closed at once, a stream ID space used up): without it the pool dials again
// for ever. A new connection that other requests filled first is not counted.
const maxDialsPerCall = 3

// grayNeverUsed reports whether no request ever reserved or used cc: a fresh connection that could not take one.
func (cc *ClientConn) grayNeverUsed() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.nextStreamID == cc.firstStreamID && cc.streamsReserved == 0
}

// errFreshConnUnusable is a request whose fresh connections could not take it, maxDialsPerCall times.
var errFreshConnUnusable = errors.New("http2: new connections cannot take the request")

// RefundPolicy is GrayConfig.Refund: a fraction of each window, in 1/1024ths.
type RefundPolicy struct {
	Stream uint16
	Conn   uint16
}

// grayRefresh is the WINDOW_UPDATE threshold of a window under a policy fraction (1/1024ths); 0 keeps the default.
// The threshold is at most the window, so a reader that reads what the window let in always returns some of it.
func grayRefresh(window int32, fraction uint16) int32 {
	if fraction == 0 || fraction > 1024 {
		return 0
	}
	return max(1, int32(int64(window)*int64(fraction)/1024))
}

func (t *Transport) grayRefund() RefundPolicy {
	if t.gray == nil {
		return RefundPolicy{}
	}
	return t.gray.Refund
}

// grayCapStreams is the peer's MAX_CONCURRENT_STREAMS lowered to GrayConfig.MaxConcurrentStreams.
func (t *Transport) grayCapStreams(n uint32) uint32 {
	if t.gray != nil && t.gray.MaxConcurrentStreams != 0 {
		return min(n, t.gray.MaxConcurrentStreams)
	}
	return n
}

func (p *ConnPreface) plan(maxDecoderTable uint32) (*prefacePlan, error) {
	if p == nil {
		return nil, nil
	}
	if len(p.Frames) == 0 || p.Frames[0].Type != FrameSettings {
		return nil, errors.New("http2: ConnPreface must start with a SETTINGS frame")
	}
	pl := &prefacePlan{
		frames:           p.Frames,
		streamRecvWindow: defaultInitialWindowSize,
		connRecvWindow:   defaultInitialWindowSize,
		headerTableSize:  initialHeaderTableSize,
		firstStreamID:    1,
	}
	var sawSettings, sawWindowUpdate bool
	for _, f := range p.Frames {
		switch f.Type {
		case FrameSettings:
			if sawSettings {
				return nil, errors.New("http2: ConnPreface has more than one SETTINGS frame")
			}
			sawSettings = true
			for _, s := range f.Settings {
				if err := s.Valid(); err != nil {
					return nil, fmt.Errorf("http2: ConnPreface setting %v=%d: %w", s.ID, s.Val, err)
				}
				switch s.ID {
				case SettingNoRFC7540Priorities: // RFC 9218 2.1
					if s.Val > 1 {
						return nil, fmt.Errorf("http2: ConnPreface setting %v=%d is not 0 or 1", s.ID, s.Val)
					}
				case SettingInitialWindowSize:
					// RFC 9113 allows 0, but this client only refunds stream window as the body is read, so a
					// stream would never receive its first DATA byte.
					if s.Val == 0 {
						return nil, errors.New("http2: ConnPreface INITIAL_WINDOW_SIZE 0 would stall every response")
					}
					pl.streamRecvWindow = int32(s.Val)
				case SettingHeaderTableSize:
					if s.Val > maxDecoderTable {
						return nil, fmt.Errorf("http2: ConnPreface HEADER_TABLE_SIZE %d is above the decoder limit %d", s.Val, maxDecoderTable)
					}
					pl.headerTableSize = s.Val
				case SettingMaxFrameSize:
					pl.maxReadFrameSize = s.Val
				}
			}
		case FrameWindowUpdate:
			if sawWindowUpdate {
				return nil, errors.New("http2: ConnPreface has more than one WINDOW_UPDATE frame")
			}
			sawWindowUpdate = true
			if f.Increment < 1 || f.Increment > maxFlowWindow-defaultInitialWindowSize {
				return nil, fmt.Errorf("http2: ConnPreface WINDOW_UPDATE increment %d is outside 1..%d", f.Increment, maxFlowWindow-defaultInitialWindowSize)
			}
			pl.connRecvWindow = defaultInitialWindowSize + int32(f.Increment)
		case FramePriority:
			if f.StreamID == 0 || f.StreamID%2 == 0 || f.StreamID > MaxPrefacePriorityStream {
				return nil, fmt.Errorf("http2: ConnPreface PRIORITY stream %d is not an odd stream ID up to %d", f.StreamID, MaxPrefacePriorityStream)
			}
			if f.Priority.StreamDep == f.StreamID || !validStreamIDOrZero(f.Priority.StreamDep) {
				return nil, fmt.Errorf("http2: ConnPreface PRIORITY stream %d has dependency %d", f.StreamID, f.Priority.StreamDep)
			}
			if f.StreamID >= pl.firstStreamID {
				pl.firstStreamID = f.StreamID + 2
			}
		default:
			return nil, fmt.Errorf("http2: ConnPreface cannot send a %v frame", f.Type)
		}
	}
	return pl, nil
}

// write writes the planned frames; the caller has written the client magic.
func (pl *prefacePlan) write(fr *Framer) {
	for _, f := range pl.frames {
		switch f.Type {
		case FrameSettings:
			fr.WriteSettings(f.Settings...)
		case FrameWindowUpdate:
			fr.WriteWindowUpdate(0, f.Increment)
		case FramePriority:
			fr.WritePriority(f.StreamID, f.Priority)
		}
	}
}

// requestLayout returns req's layout, or the zero layout when the Transport has no RequestLayout.
func (t *Transport) requestLayout(req *ClientRequest) RequestLayout {
	if t.gray == nil || t.gray.RequestLayout == nil {
		return RequestLayout{}
	}
	return t.gray.RequestLayout(req)
}

// defaultMaxHeaderValueCount bounds the header (and trailer) fields of one response when
// GrayConfig.MaxHeaderValueCount is 0: net/http's DefaultMaxHeaderValueCount.
const defaultMaxHeaderValueCount = 500

// defaultMaxStreams is server.go's, left out with the server; setConfigDefaults uses it.
const defaultMaxStreams = 250 // TODO: make this 100 as the GFE seems to?

// connHeaders is server.go's, verbatim, left out with the server; the client's response handling uses it.
// From http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.2
var connHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
	"Upgrade",
}

// foreachHeaderElement is server.go's, verbatim, left out with the server; the client's response handling uses it.
func foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for f := range strings.SplitSeq(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}
