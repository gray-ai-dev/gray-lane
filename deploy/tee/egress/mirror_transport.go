package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	xh2 "github.com/megaeth-labs/gray/deploy/tee/egress/third_party/stdhttp2/http2"
)

// Outbound HTTP/2 client transport for mirrored vendor connections: the Go standard library's HTTP/2 client
// (net/http/internal/http2 of the Go release egress is built with), forked in third_party/stdhttp2 with a small patch
// (its README.md) that writes the learned connection preface (SETTINGS, stream-0 WINDOW_UPDATE and PRIORITY frames,
// in the learned order) and each request's HEADERS layout (priority fields, pseudo-header order, field order), and
// dials only through the given dial function. The HTTP/1.1 side is mirror_h1.go.

// h2MaxLearnedHeaderTable bounds the HPACK decoder table size egress allocates when replaying a learned SETTINGS
// frame (browsers use 4 KiB–64 KiB); a larger learned HEADER_TABLE_SIZE is announced as this.
const h2MaxLearnedHeaderTable = 256 << 10

// h2MaxResponseHeaderBytes bounds one response's header block, as MaxResponseHeaderBytes did on the transports
// before (net/http's default).
const h2MaxResponseHeaderBytes = 10 << 20

// h2DefaultWindowSize is the RFC 9113 initial flow-control window of a connection and of a stream.
const h2DefaultWindowSize = 65535

// errMirrorNoDial is a mirrored transport made without its dial function: it never dials the vendor itself.
var errMirrorNoDial = errors.New("mirror transport: no dial function")

type mirrorLayoutKey struct{}

// mirrorH2Client is one pool entry's HTTP/2 transport. It is rebuilt when the hello's learned preface changes during
// the pre-freeze warm-up window, so new connections replay the latest preface; connections already open keep theirs.
type mirrorH2Client struct {
	cfg   config
	hello *mirroredHello
	dial  func(ctx context.Context) (net.Conn, error)

	mu     sync.Mutex
	tr     *xh2.HTTPTransport
	prefID string
}

func newMirrorH2Client(cfg config, hello *mirroredHello, dial func(ctx context.Context) (net.Conn, error)) *mirrorH2Client {
	pref := hello.h2Preface()
	return &mirrorH2Client{
		cfg:    cfg,
		hello:  hello,
		dial:   dial,
		tr:     buildMirrorH2Transport(cfg, pref, dial),
		prefID: h2PrefaceID(pref),
	}
}

// h2PrefaceID names a learned preface's content, to tell when it changed.
func h2PrefaceID(pref *h2Preface) string {
	if pref == nil {
		return ""
	}
	b, err := json.Marshal(pref)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *mirrorH2Client) transport() *xh2.HTTPTransport {
	pref := c.hello.h2Preface()
	id := h2PrefaceID(pref)
	c.mu.Lock()
	if id == c.prefID {
		tr := c.tr
		c.mu.Unlock()
		return tr
	}
	old := c.tr
	tr := buildMirrorH2Transport(c.cfg, pref, c.dial)
	c.tr, c.prefID = tr, id
	c.mu.Unlock()
	if old != nil {
		// The old preface's connections serve their calls and close; none sits idle until its timeout.
		old.Retire()
	}
	return tr
}

func (c *mirrorH2Client) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.dial == nil {
		return nil, errMirrorNoDial
	}
	out, layout := mirrorH2Request(req, c.hello.h2Preface())
	out = out.WithContext(context.WithValue(out.Context(), mirrorLayoutKey{}, layout))
	resp, err := c.transport().RoundTrip(out)
	if err != nil {
		return nil, err
	}
	// The response's Trailer map is the transport's own: it fills it once the body has been read to its end.
	resp.Request = req
	return resp, nil
}

// Retire closes the idle connections now and each busy one as its calls end.
func (c *mirrorH2Client) Retire() {
	c.mu.Lock()
	tr := c.tr
	c.mu.Unlock()
	if tr != nil {
		tr.Retire()
	}
}

func (c *mirrorH2Client) CloseIdleConnections() {
	c.mu.Lock()
	tr := c.tr
	c.mu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

// buildMirrorH2Transport is an HTTP/2 transport that dials only through dial and writes mirrorConnPreface(pref).
func buildMirrorH2Transport(cfg config, pref *h2Preface, dial func(ctx context.Context) (net.Conn, error)) *xh2.HTTPTransport {
	preface := mirrorConnPreface(cfg, pref)
	return &xh2.HTTPTransport{
		DisableCompression:    true,
		MaxHeaderListSize:     h2MaxResponseHeaderBytes,
		IdleConnTimeout:       cfg.idleConnTimeout,
		ResponseHeaderTimeout: cfg.responseHeaderTimeout,
		HTTP2:                 xh2.Config{MaxDecoderHeaderTableSize: h2MaxLearnedHeaderTable},
		Gray: xh2.GrayConfig{
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (conn net.Conn, err error) {
				if dial == nil {
					return nil, errMirrorNoDial
				}
				// A fault in the dial (the hello's spec, uTLS's ApplyPreset, the proxy's answer) fails the call,
				// not the process: the fork dials on a goroutine of its own, where nothing else recovers.
				defer func() {
					if r := recover(); r != nil {
						conn, err = nil, fmt.Errorf("mirror transport: the vendor dial failed: %v", r)
					}
				}()
				return dial(ctx)
			},
			Preface:              preface,
			RequestLayout:        mirrorRequestLayout,
			MaxHeaderValueCount:  http.DefaultMaxHeaderValueCount,
			MaxConcurrentStreams: mirrorStreamCap(preface),
			Refund:               mirrorRefund(pref, preface),
		},
	}
}

// mirrorStreamWindow is the most an HTTP/2 vendor stream of hello's entry may hold unread: the
// SETTINGS_INITIAL_WINDOW_SIZE its connections announce (mirrorConnPreface of the hello's current preface), and at
// least relayStreamWindow, the window of connections made before the preface was learned. A relay call takes it
// from the budget (relayCallBytes), so a learned window above egress's own (a browser's 6 MiB) is paid for, not
// lowered: lowering it would change what the vendor sees.
//
// It counts the connection's frame read buffer too (SETTINGS_MAX_FRAME_SIZE, 16 KiB when not announced): the
// vendor's frames are read into it, one connection's calls share it, and each call is counted as if it held it alone.
func mirrorStreamWindow(cfg config, hello *mirroredHello) int64 {
	window, frame := int64(relayStreamWindow), int64(16384)
	pref := mirrorConnPreface(cfg, hello.h2Preface())
	if pref == nil || len(pref.Frames) == 0 {
		return window + frame
	}
	for _, s := range pref.Frames[0].Settings {
		switch s.ID {
		case xh2.SettingInitialWindowSize:
			window = max(window, int64(s.Val))
		case xh2.SettingMaxFrameSize:
			frame = int64(s.Val)
		}
	}
	return window + frame
}

// mirrorRefund is when the vendor connection returns window: at the fraction of each window at which the client
// returned its own while it read answers during learning (h2Preface.StreamRefund, ConnRefund), measured against the
// windows the client announced, which the connection announces too. Nothing learned keeps the transport's rule
// (every 4 KiB read, or when the return would double the window left).
func mirrorRefund(pref *h2Preface, preface *xh2.ConnPreface) xh2.RefundPolicy {
	if pref == nil || preface == nil || len(preface.Frames) == 0 {
		return xh2.RefundPolicy{}
	}
	stream, conn := int64(h2DefaultWindowSize), int64(h2DefaultWindowSize)
	for _, f := range preface.Frames {
		switch f.Type {
		case xh2.FrameSettings:
			for _, s := range f.Settings {
				if s.ID == xh2.SettingInitialWindowSize {
					stream = int64(s.Val)
				}
			}
		case xh2.FrameWindowUpdate:
			conn += int64(f.Increment)
		}
	}
	fraction := func(refund uint32, window int64) uint16 {
		if refund == 0 || window <= 0 {
			return 0
		}
		return uint16(min(max(int64(refund)*1024/window, 1), 1024))
	}
	return xh2.RefundPolicy{Stream: fraction(pref.StreamRefund, stream), Conn: fraction(pref.ConnRefund, conn)}
}

// mirrorStreamCap is how many calls one vendor connection carries at once under preface; 0 is no bound but the
// vendor's. A connection's DATA counts against its connection window until the call reads it, so calls whose stream
// windows together pass the connection window can stall one another behind a call whose reader is slow. A client
// that sends a stream-0 WINDOW_UPDATE has set its connection window above that for itself (Chrome's 15 MiB beside
// 6 MiB streams); one that sends none keeps 65,535 bytes for all its streams, so its vendor connections carry only
// as many calls as their stream windows fit in it, at least one.
func mirrorStreamCap(preface *xh2.ConnPreface) uint32 {
	if preface == nil || len(preface.Frames) == 0 {
		return 0
	}
	stream := uint32(h2DefaultWindowSize)
	for _, f := range preface.Frames {
		switch f.Type {
		case xh2.FrameWindowUpdate:
			return 0
		case xh2.FrameSettings:
			for _, s := range f.Settings {
				if s.ID == xh2.SettingInitialWindowSize {
					stream = s.Val
				}
			}
		}
	}
	return max(1, uint32(h2DefaultWindowSize)/max(stream, 1))
}

// h2MaxConnIncrement is the largest stream-0 WINDOW_UPDATE increment whose connection window (65535 + increment)
// stays within 2^31-1 (RFC 9113 6.9.1).
const h2MaxConnIncrement = 0x7fffffff - h2DefaultWindowSize

// mirrorConnPreface turns a learned preface into the frames a new vendor connection writes. Settings keep their
// learned IDs, order, duplicates and values, but for a HEADER_TABLE_SIZE above h2MaxLearnedHeaderTable (lowered to
// it) and values RFC 9113 forbids or that would stall every response (INITIAL_WINDOW_SIZE 0; dropped). The stream-0
// WINDOW_UPDATE is sent when the client sent one (its increment lowered to h2MaxConnIncrement), not at all when the
// client sent none, and, when that is unknown (a profile from before the field), as the learned increment or else
// egress's default. Frames go in the learned order; with no usable learned order, SETTINGS, PRIORITY frames, then
// WINDOW_UPDATE (the order of the transport before this one). Without a learned preface, Go's own client preface
// with relayHTTP2Config's windows: relayStreamWindow per stream, -stack-max-bytes as the connection increment.
func mirrorConnPreface(cfg config, pref *h2Preface) *xh2.ConnPreface {
	defaultIncrement := uint32(min(max(cfg.stackMaxBytes, 0), h2MaxConnIncrement))
	if pref == nil {
		frames := []xh2.PrefaceFrame{{Type: xh2.FrameSettings, Settings: []xh2.Setting{
			{ID: xh2.SettingEnablePush, Val: 0},
			{ID: xh2.SettingInitialWindowSize, Val: relayStreamWindow},
			{ID: xh2.SettingMaxFrameSize, Val: 1 << 20},
			{ID: xh2.SettingMaxHeaderListSize, Val: h2MaxResponseHeaderBytes},
		}}}
		if defaultIncrement > 0 {
			frames = append(frames, xh2.PrefaceFrame{Type: xh2.FrameWindowUpdate, Increment: defaultIncrement})
		}
		return &xh2.ConnPreface{Frames: frames}
	}

	settings := make([]xh2.Setting, 0, len(pref.Settings))
	for _, s := range pref.Settings {
		st := xh2.Setting{ID: xh2.SettingID(s.ID), Val: s.Val}
		switch st.ID {
		case xh2.SettingHeaderTableSize:
			st.Val = min(st.Val, h2MaxLearnedHeaderTable)
		case xh2.SettingInitialWindowSize:
			if st.Val == 0 {
				continue
			}
		case xh2.SettingNoRFC7540Priorities:
			if st.Val > 1 {
				continue
			}
		}
		if st.Valid() != nil {
			continue
		}
		settings = append(settings, st)
	}

	var prios []xh2.PrefaceFrame
	var lastStream uint32
	for _, pf := range pref.Priorities {
		// A stream past h2MaxPrefacePriorityStream would leave the connection no stream for a request (the fork's
		// ConnPreface refuses it); learning refuses such a preface, and one read from an older state file loses it.
		if pf.StreamID == 0 || pf.StreamID%2 == 0 || pf.StreamID > h2MaxPrefacePriorityStream || pf.StreamID <= lastStream {
			continue
		}
		if pf.StreamDep == pf.StreamID || pf.StreamDep > 0x7fffffff {
			continue
		}
		lastStream = pf.StreamID
		prios = append(prios, xh2.PrefaceFrame{
			Type:     xh2.FramePriority,
			StreamID: pf.StreamID,
			Priority: xh2.PriorityParam{StreamDep: pf.StreamDep, Exclusive: pf.Exclusive, Weight: pf.Weight},
		})
	}

	var increment uint32
	switch {
	case pref.ConnWindowUpdate != nil && !*pref.ConnWindowUpdate:
		increment = 0
	case pref.WindowIncrement > 0:
		increment = min(pref.WindowIncrement, h2MaxConnIncrement)
	case pref.ConnWindowUpdate == nil:
		increment = defaultIncrement
	}
	var window *xh2.PrefaceFrame
	if increment > 0 {
		window = &xh2.PrefaceFrame{Type: xh2.FrameWindowUpdate, Increment: increment}
	}

	frames := make([]xh2.PrefaceFrame, 0, 2+len(prios))
	frames = append(frames, xh2.PrefaceFrame{Type: xh2.FrameSettings, Settings: settings})
	if order := pref.usableFrameOrder(); order != nil {
		next := 0
		for _, kind := range order[1:] {
			switch kind {
			case h2FrameWindowUpdate:
				if window != nil {
					frames = append(frames, *window)
					window = nil
				}
			case h2FramePriority:
				if next < len(prios) {
					frames = append(frames, prios[next])
					next++
				}
			}
		}
		prios = prios[next:]
	}
	frames = append(frames, prios...)
	if window != nil {
		frames = append(frames, *window)
	}
	return &xh2.ConnPreface{Frames: frames}
}

// mirrorRequestLayout is the HEADERS layout mirrorH2Request put in the request's context.
func mirrorRequestLayout(req *xh2.ClientRequest) xh2.RequestLayout {
	if layout, ok := req.Context.Value(mirrorLayoutKey{}).(xh2.RequestLayout); ok {
		return layout
	}
	return xh2.RequestLayout{}
}

// mirrorH2Request is req as the vendor receives it: the header set buildOrderedHeaders decided, in the container
// client's order, with its pseudo-header order and HEADERS priority (from the request's own wire record, or else
// the learned preface's template).
func mirrorH2Request(req *http.Request, pref *h2Preface) (*http.Request, xh2.RequestLayout) {
	wire := wireMetaOf(req.Context())
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	ordered := buildOrderedHeaders(req, wire, host, true)

	hdr := make(http.Header, len(ordered)+1)
	order := make([]string, 0, len(ordered))
	seen := make(map[string]bool, len(ordered))
	var neverIndexed []string
	for _, item := range ordered {
		canon := http.CanonicalHeaderKey(item.name)
		if !seen[item.name] {
			seen[item.name] = true
			order = append(order, item.name)
			if item.sensitive {
				neverIndexed = append(neverIndexed, item.name)
			}
		}
		if canon == "Content-Length" {
			// The transport writes Content-Length itself, from the body's length, where order places it.
			continue
		}
		hdr[canon] = append(hdr[canon], item.value)
	}
	if _, ok := hdr["User-Agent"]; !ok {
		// An empty User-Agent suppresses the transport's default without sending the field.
		hdr["User-Agent"] = []string{""}
	}

	out := req.Clone(req.Context())
	out.Header = hdr
	out.Host = host
	out.Body = req.Body
	out.GetBody = req.GetBody
	out.ContentLength = req.ContentLength
	if req.ContentLength == 0 && req.Body != nil && req.Body != http.NoBody && seen["content-length"] {
		// buildOrderedHeaders put "content-length: 0" on the wire; a known-empty body makes the transport send it.
		out.Body = http.NoBody
	}

	layout := xh2.RequestLayout{
		PseudoOrder:  resolveH2PseudoOrder(wire, pref),
		HeaderOrder:  order,
		NeverIndexed: neverIndexed,
	}
	switch {
	case wire != nil:
		// The client's own record says whether content-length is on the wire (buildOrderedHeaders put it in order
		// exactly then); without one, the transport's rule as before.
		layout.ContentLength = xh2.ContentLengthOmit
		if seen["content-length"] {
			layout.ContentLength = xh2.ContentLengthSend
		}
		// buildOrderedHeaders grouped the cookies as the client split them (groupCookies): one field per value.
		layout.CookieAsSent = len(wire.cookiePairs) > 0 && len(hdr["Cookie"]) == len(wire.cookiePairs)
		if wire.hasPriority && wire.priority.StreamDep <= 0x7fffffff {
			layout.Priority = &xh2.PriorityParam{StreamDep: wire.priority.StreamDep, Exclusive: wire.priority.Exclusive, Weight: wire.priority.Weight}
		}
	case pref != nil && pref.HeadersPriority != nil && pref.HeadersPriority.StreamDep <= 0x7fffffff:
		hp := pref.HeadersPriority
		layout.Priority = &xh2.PriorityParam{StreamDep: hp.StreamDep, Exclusive: hp.Exclusive, Weight: hp.Weight}
	}
	return out, layout
}
