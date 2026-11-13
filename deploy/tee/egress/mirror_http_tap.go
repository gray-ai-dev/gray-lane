package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Wire-level HTTP/2 and HTTP/1.1 tap on the relay container's inner tunnel connection.
//
// Egress reads the container's frames passively as net/http reads from the TLS connection:
//   - On HTTP/2, while learning is still open (mirror_profiles.go), egress records the client's initial SETTINGS
//     frame (IDs, order and values), any stream-0 WINDOW_UPDATE, any startup PRIORITY frames, and any warm-up
//     HEADERS pseudo-header order and priority fields.
//   - On each request (HTTP/2 or HTTP/1.1), egress records the wire order of the request's headers (and, on HTTP/1.1,
//     their raw field-name casing and where Host sits; on HTTP/2, the pseudo-header order and priority fields).
//
// Outbound header names and values still come exclusively from egress's own policy checks (stackVendorHeader,
// stackRelayHeader, loginHeader, outboundHeader); wireRequestMeta only orders and spells the fields egress has already
// decided to forward.

type wireMetaKey struct{}

func wireMetaOf(ctx context.Context) *wireRequestMeta {
	meta, _ := ctx.Value(wireMetaKey{}).(*wireRequestMeta)
	return meta
}

type wireHeader struct {
	name  string
	value string
	// sensitive is an HTTP/2 field the client wrote as an HPACK literal never indexed (RFC 7541 6.2.3), as
	// nghttp2 and Node do for authorization; the vendor connection writes the field that way too.
	sensitive bool
}

type wireRequestMeta struct {
	protoMajor  int
	pseudoOrder []string
	hasPriority bool
	priority    h2HeadersPriority
	// headers are the fields in wire order. A pending record keeps their names, casing and never-indexed flags but
	// no value (stripWireValues), except Connection's and Transfer-Encoding's, whose values set the framing.
	headers []wireHeader
	// cookiePairs is, per Cookie field the client sent, the number of cookie-pairs in it (RFC 6265 5.4), so the
	// vendor gets the client's split of the same cookies (HTTP/2, RFC 9113 8.2.3).
	cookiePairs []int
}

type pendingWireMeta struct {
	digest [32]byte
	meta   *wireRequestMeta
	bytes  int
}

const (
	tapMaxPendingH2 = 128
	tapMaxPendingH1 = 16
	tapMaxHeaderBuf = 128 << 10
	// tapMaxPendingBytes bounds what one tap holds of records no handler took yet (wireMetaBytes): net/http answers
	// some requests without calling a handler (an HTTP/2 stream it resets for a malformed field; HTTP/1.1 `OPTIONS *`),
	// so a record may never be taken. A tunnel's share of the budget counts it (vendorTunnelBytes). 64 KiB holds the
	// names of about 40 requests of 20 fields at once; a handler takes its record as it starts.
	tapMaxPendingBytes = 64 << 10
)

// wireMetaBytes is what a pending record holds, as wireMetaBytes counts it: each field's name and kept value, and
// a fixed allowance for the slices and the record itself.
func wireMetaBytes(meta *wireRequestMeta) int {
	n := 256 + 8*len(meta.cookiePairs)
	for _, h := range meta.headers {
		n += 48 + len(h.name) + len(h.value)
	}
	for _, p := range meta.pseudoOrder {
		n += 16 + len(p)
	}
	return n
}

// stripWireValues drops meta's field values once its digest is taken: buildOrderedHeaders reads names, order,
// casing and the never-indexed flag, and the values of Connection and Transfer-Encoding only.
func stripWireValues(meta *wireRequestMeta) {
	for i := range meta.headers {
		h := &meta.headers[i]
		switch strings.ToLower(h.name) {
		case "connection", "transfer-encoding":
			if len(h.value) > 32 {
				h.value = ""
			}
		case "cookie":
			pairs := 0
			for _, part := range strings.Split(h.value, ";") {
				if strings.TrimSpace(part) != "" {
					pairs++
				}
			}
			meta.cookiePairs = append(meta.cookiePairs, pairs)
			h.value = ""
		default:
			h.value = ""
		}
	}
}

// putPending adds a record to a tap's pending list, the oldest leaving first past maxItems or tapMaxPendingBytes. A
// record over the byte cap alone is not kept. The caller holds the tap's pendingMu.
func putPending(list *[]pendingWireMeta, held *int, maxItems int, digest [32]byte, meta *wireRequestMeta) {
	stripWireValues(meta)
	size := wireMetaBytes(meta)
	if size > tapMaxPendingBytes {
		return
	}
	for len(*list) > 0 && (len(*list) >= maxItems || *held+size > tapMaxPendingBytes) {
		*held -= (*list)[0].bytes
		(*list)[0] = pendingWireMeta{}
		*list = (*list)[1:]
	}
	*list = append(*list, pendingWireMeta{digest: digest, meta: meta, bytes: size})
	*held += size
}

// takePending removes and answers the record with digest want; with dropOlder, the records before it go too. It
// answers whether records were held but none matched.
func takePending(list *[]pendingWireMeta, held *int, want [32]byte, dropOlder bool) (*wireRequestMeta, bool) {
	for i, item := range *list {
		if item.digest != want {
			continue
		}
		start := i
		if dropOlder {
			for _, older := range (*list)[:i] {
				*held -= older.bytes
			}
			start = 0
		}
		*held -= item.bytes
		*list = append((*list)[:start:start], (*list)[i+1:]...)
		return item.meta, false
	}
	return nil, len(*list) > 0
}

// wireMatchDigest names a request by its method, target and fields as net/http's HTTP/2 server hands them to the
// handler (Go 1.27.2 net/http/internal/httpcommon NewServerRequest): Cookie fields joined with "; " in their order,
// no Trailer field.
func wireMatchDigest(method, requestURI string, pairs []wireHeader) [32]byte {
	canon := make([]string, 0, len(pairs))
	var cookies []string
	for _, p := range pairs {
		lower := strings.ToLower(p.name)
		if lower == "host" || lower == "trailer" || strings.HasPrefix(lower, ":") {
			continue
		}
		if lower == "cookie" {
			cookies = append(cookies, p.value)
			continue
		}
		canon = append(canon, lower+"\x00"+p.value)
	}
	if len(cookies) > 0 {
		canon = append(canon, "cookie\x00"+strings.Join(cookies, "; "))
	}
	sort.Strings(canon)
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(requestURI))
	h.Write([]byte{0})
	for _, item := range canon {
		h.Write([]byte(item))
		h.Write([]byte{'\n'})
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

func requestMatchDigest(r *http.Request) [32]byte {
	var pairs []wireHeader
	for name, values := range r.Header {
		for _, v := range values {
			pairs = append(pairs, wireHeader{name: name, value: v})
		}
	}
	// net/http moves Cookie headers; r.Header still holds Cookie before Cookie() parses it, and Transfer-Encoding is
	// moved to r.TransferEncoding on HTTP/1.1. On HTTP/2 r.Header holds every non-pseudo field except Host (:authority).
	return wireMatchDigest(r.Method, r.RequestURI, pairs)
}

const h2ClientMagic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// tapH2MaxHeaderList is the header list net/http's HTTP/2 server takes on a tunnel, and the longest HPACK string it
// decodes: MaxHeaderBytes (relayMaxHeaderBytes) and ten fields' 32-byte overhead (Go 1.27.2,
// net/http/internal/http2 config.go:70 adjustHTTP1MaxHeaderSize; frame.go:1707 maxHeaderStringLen, and frame.go:1730
// the header budget readMetaFrame counts). net/http answers a header block past it with 431 and calls no handler, so
// the tap records nothing for one.
const tapH2MaxHeaderList = relayMaxHeaderBytes + 10*32

// h2TapConn wraps a server *tls.Conn that negotiated "h2", passively inspecting client frames as net/http reads them.
// It buffers only until a frame is whole (the 9-byte frame header and the length in it), and hands each whole frame
// of a type it records to golang.org/x/net/http2's Framer, which checks it as net/http's server does and answers the
// typed frame. DATA and the types it does not record are passed over unbuffered.
type h2TapConn struct {
	*tls.Conn
	onPreface func(*h2Preface)

	mu            sync.Mutex
	buf           bytes.Buffer
	skipBytes     int
	sawMagic      bool
	sawSettings   bool
	prefaceLocked bool
	stopped       bool
	preface       h2Preface

	// frame holds the one whole frame framer reads next.
	frame  bytes.Reader
	framer *http2.Framer

	hpackDec  *hpack.Decoder
	curStream uint32
	curMeta   *wireRequestMeta
	curSize   uint64 // the header list so far, as RFC 9113 6.5.2 counts it (hpack.HeaderField.Size)
	curOver   bool   // the header list passed tapH2MaxHeaderList
	curSkip   bool   // the header block is a trailer section (or another block on a stream already seen): not a request
	// lastStream is the highest stream a request's HEADERS opened; a client opens streams in increasing order (RFC
	// 9113 5.1.1), so a later HEADERS on a stream at or below it ends a request (trailers) and starts none.
	lastStream uint32
	curMethod  string
	curPath    string

	pendingMu    sync.Mutex
	pending      []pendingWireMeta
	pendingBytes int

	// signals, when set, counts the tap's stop and the requests no record matched (mirror_signals.go).
	signals *mirrorSignals
}

var h2TapSourceSeq atomic.Uint64

func newH2TapConn(conn *tls.Conn, onPreface func(*h2Preface)) *h2TapConn {
	t := &h2TapConn{
		Conn:      conn,
		onPreface: onPreface,
		preface:   h2Preface{source: h2TapSourceSeq.Add(1)},
	}
	t.framer = http2.NewFramer(nil, &t.frame)
	// The largest frame a tunnel's server reads (tunnelHTTP2Config's MaxReadFrameSize); a longer one ends the
	// connection there.
	t.framer.SetMaxReadFrameSize(vendorTunnelFrame)
	// 4,096 is the HPACK table size the server keeps (SETTINGS_HEADER_TABLE_SIZE's initial value; egress announces
	// no other).
	t.hpackDec = hpack.NewDecoder(4096, t.onHeaderField)
	t.hpackDec.SetMaxStringLength(tapH2MaxHeaderList)
	return t
}

func (t *h2TapConn) onHeaderField(f hpack.HeaderField) {
	if t.curMeta == nil || t.curOver || t.curSkip {
		return
	}
	if t.curSize += uint64(f.Size()); t.curSize > tapH2MaxHeaderList {
		t.curOver = true
		return
	}
	if strings.HasPrefix(f.Name, ":") {
		switch f.Name {
		case ":method":
			t.curMethod = f.Value
		case ":path":
			t.curPath = f.Value
		case ":authority", ":scheme":
		default:
			return
		}
		if len(t.curMeta.pseudoOrder) < 4 {
			seen := false
			for _, existing := range t.curMeta.pseudoOrder {
				if existing == f.Name {
					seen = true
					break
				}
			}
			if !seen {
				t.curMeta.pseudoOrder = append(t.curMeta.pseudoOrder, f.Name)
			}
		}
		return
	}
	t.curMeta.headers = append(t.curMeta.headers, wireHeader{name: f.Name, value: f.Value, sensitive: f.Sensitive})
}

func (t *h2TapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 || err != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		defer recoverTap(t.stop)
		if n > 0 {
			t.feed(p[:n])
		}
		// A deadline passing is no end of the connection's frames; net/http may read on after one.
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			t.closed()
		}
	}
	return n, err
}

// noteFrame appends a recorded startup frame to the preface's FrameOrder (h2MaxFrameOrder at most).
func (t *h2TapConn) noteFrame(kind string) {
	if len(t.preface.FrameOrder) < h2MaxFrameOrder {
		t.preface.FrameOrder = append(t.preface.FrameOrder, kind)
	}
}

// lockPreface ends the startup frames: what came before is the client's whole preface, so whether it sent a
// stream-0 WINDOW_UPDATE is known. It answers whether the preface changed (and is to be announced).
func (t *h2TapConn) lockPreface() bool {
	if t.prefaceLocked {
		return false
	}
	t.prefaceLocked = true
	if !t.sawSettings {
		return false
	}
	sent := t.preface.WindowIncrement > 0
	t.preface.ConnWindowUpdate = &sent
	return true
}

// closed ends the startup frames when the connection ends first (a warm-up closes after its preface, with no
// request), and announces the preface.
func (t *h2TapConn) closed() {
	if t.stopped || !t.lockPreface() || t.onPreface == nil {
		return
	}
	t.onPreface(t.preface.clone())
}

// recoverTap ends a tap whose feed panicked instead of the process: the tap only records, and net/http may read the
// connection on its background-read goroutine, where nothing else recovers. Deferred inside the tap's lock.
func recoverTap(stop func()) {
	if r := recover(); r != nil {
		stop()
		log.Printf("egress: the tunnel's request tap stopped after a fault: %v", r)
	}
}

// stop ends the tap for the connection: what it reads next is no longer recorded. net/http serves the connection
// as before.
func (t *h2TapConn) stop() {
	if !t.stopped {
		t.signals.tapStop()
	}
	t.stopped = true
	t.buf = bytes.Buffer{}
	t.curMeta = nil
}

func (t *h2TapConn) feed(chunk []byte) {
	if t.stopped {
		return
	}
	if t.skipBytes > 0 {
		skip := min(len(chunk), t.skipBytes)
		t.skipBytes -= skip
		chunk = chunk[skip:]
		if len(chunk) == 0 {
			return
		}
	}
	if t.buf.Len()+len(chunk) > tapMaxHeaderBuf {
		t.stop()
		return
	}
	t.buf.Write(chunk)

	if !t.sawMagic {
		if t.buf.Len() < len(h2ClientMagic) {
			return
		}
		if string(t.buf.Bytes()[:len(h2ClientMagic)]) != h2ClientMagic {
			t.stop()
			return
		}
		t.buf.Next(len(h2ClientMagic))
		t.sawMagic = true
	}

	prefaceUpdated := false
	for t.buf.Len() >= 9 {
		hdr := t.buf.Bytes()[:9]
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		ftype := http2.FrameType(hdr[3])
		if length > vendorTunnelFrame {
			t.stop()
			return
		}
		// A header block's frames are contiguous (RFC 9113 6.10); any other frame inside one ends the connection.
		if t.curMeta != nil && ftype != http2.FrameContinuation {
			t.stop()
			return
		}

		// WINDOW_UPDATE is read after the preface too: when the client returns window (h2Preface.StreamRefund).
		record := ftype == http2.FrameHeaders || ftype == http2.FrameContinuation || ftype == http2.FrameWindowUpdate ||
			(!t.prefaceLocked && (ftype == http2.FrameSettings || ftype == http2.FramePriority))
		if !record {
			// The first DATA or PING ends the startup frames (a warm-up awaits a PING's ACK, AGENTS.md).
			if (ftype == http2.FrameData || ftype == http2.FramePing) && t.lockPreface() {
				prefaceUpdated = true
			}
			t.buf.Next(9)
			if t.buf.Len() >= length {
				t.buf.Next(length)
				continue
			}
			t.skipBytes = length - t.buf.Len()
			t.buf.Reset()
			break
		}

		if t.buf.Len() < 9+length {
			break
		}
		t.frame.Reset(t.buf.Next(9 + length))
		frame, err := t.framer.ReadFrame()
		if err != nil {
			t.stop()
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() && !t.sawSettings {
				t.sawSettings = true
				t.noteFrame(h2FrameSettings)
				t.preface.Settings = make([]h2Setting, 0, min(f.NumSettings(), h2MaxPrefaceSettings))
				_ = f.ForeachSetting(func(s http2.Setting) error {
					if len(t.preface.Settings) < h2MaxPrefaceSettings {
						t.preface.Settings = append(t.preface.Settings, h2Setting{ID: uint16(s.ID), Val: s.Val})
					}
					return nil
				})
				prefaceUpdated = true
			}
		case *http2.WindowUpdateFrame:
			// The Framer refuses an increment of 0.
			switch {
			case !t.prefaceLocked:
				if f.StreamID == 0 && t.preface.WindowIncrement == 0 {
					t.preface.WindowIncrement = f.Increment
					t.noteFrame(h2FrameWindowUpdate)
					prefaceUpdated = true
				}
			case f.StreamID == 0:
				if t.preface.ConnRefund == 0 || f.Increment < t.preface.ConnRefund {
					t.preface.ConnRefund = f.Increment
					prefaceUpdated = true
				}
			default:
				if t.preface.StreamRefund == 0 || f.Increment < t.preface.StreamRefund {
					t.preface.StreamRefund = f.Increment
					prefaceUpdated = true
				}
			}
		case *http2.PriorityFrame:
			if len(t.preface.Priorities) < h2MaxPrefacePriorities {
				t.noteFrame(h2FramePriority)
				t.preface.Priorities = append(t.preface.Priorities, h2Priority{
					StreamID:  f.StreamID,
					Exclusive: f.Exclusive,
					StreamDep: f.StreamDep,
					Weight:    f.Weight,
				})
				prefaceUpdated = true
			}
		case *http2.HeadersFrame:
			// The Framer has taken off the padding (and checked its length) and the priority fields.
			meta := &wireRequestMeta{protoMajor: 2}
			if f.HasPriority() {
				meta.hasPriority = true
				meta.priority = h2HeadersPriority{
					Exclusive: f.Priority.Exclusive,
					StreamDep: f.Priority.StreamDep,
					Weight:    f.Priority.Weight,
				}
			}
			// A trailer section is decoded all the same (it updates the HPACK table) but recorded as no request.
			skip := f.StreamID <= t.lastStream
			if !skip {
				t.lastStream = f.StreamID
			}
			t.curStream, t.curMeta, t.curSize, t.curOver, t.curSkip = f.StreamID, meta, 0, false, skip
			t.curMethod, t.curPath = "", ""
			if !t.decodeHeaderBlock(f.HeaderBlockFragment(), f.HeadersEnded(), &prefaceUpdated) {
				return
			}
		case *http2.ContinuationFrame:
			// The Framer has checked that it follows its stream's HEADERS or CONTINUATION.
			if t.curMeta == nil || f.StreamID != t.curStream {
				t.stop()
				return
			}
			if !t.decodeHeaderBlock(f.HeaderBlockFragment(), f.HeadersEnded(), &prefaceUpdated) {
				return
			}
		}
	}

	if prefaceUpdated && t.sawSettings && t.onPreface != nil {
		t.onPreface(t.preface.clone())
	}
}

// decodeHeaderBlock feeds one fragment of the current header block to the HPACK decoder and, at the block's end,
// records it. It answers false when the tap stopped.
func (t *h2TapConn) decodeHeaderBlock(fragment []byte, ended bool, prefaceUpdated *bool) bool {
	if _, err := t.hpackDec.Write(fragment); err != nil {
		t.stop()
		return false
	}
	if !ended {
		return true
	}
	if err := t.hpackDec.Close(); err != nil {
		t.stop()
		return false
	}
	if t.finishHeaders() {
		*prefaceUpdated = true
	}
	return true
}

func (t *h2TapConn) finishHeaders() bool {
	meta := t.curMeta
	method, path := t.curMethod, t.curPath
	over := t.curOver || t.curSkip
	t.curMeta = nil
	t.curStream = 0
	if meta == nil || over {
		return false
	}
	prefaceUpdated := false
	if !t.prefaceLocked {
		prefaceUpdated = t.lockPreface()
		if len(meta.pseudoOrder) > 0 && len(t.preface.PseudoOrder) == 0 {
			t.preface.PseudoOrder = append([]string(nil), meta.pseudoOrder...)
			if meta.hasPriority {
				hp := meta.priority
				t.preface.HeadersPriority = &hp
			}
			prefaceUpdated = true
		}
	}
	digest := wireMatchDigest(method, path, meta.headers)
	t.pendingMu.Lock()
	putPending(&t.pending, &t.pendingBytes, tapMaxPendingH2, digest, meta)
	t.pendingMu.Unlock()
	return prefaceUpdated
}

func (t *h2TapConn) take(r *http.Request) *wireRequestMeta {
	if t == nil {
		return nil
	}
	want := requestMatchDigest(r)
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	// Streams run at once, so a record before this request's may still be its own stream's: only the match goes.
	meta, refused := takePending(&t.pending, &t.pendingBytes, want, false)
	// No record is this request's. Another stream's layout is not this request's: it goes without one (the
	// transport's own order) rather than with a wrong one.
	if refused {
		t.signals.wireMetaRefuse()
	}
	return meta
}

// Limits of net/http's HTTP/1.1 server the tap reads to (Go 1.27.2). The connection's reader is a 4,096-byte
// bufio.Reader (net/http/server.go:2055 newBufioReader, bufio's default size).
const (
	// h1ChunkLineMax is the longest chunk-size line, extensions and its CRLF included: readChunkLine reads it with
	// ReadSlice from that reader, so it fits in 4,096 bytes (net/http/internal/chunked.go:155-184; maxLineLength,
	// :19, is the same bound on the line without its CRLF). It is also the bound on a chunk's extensions.
	h1ChunkLineMax = 4096
	// h1TrailerMax: body.readTrailer needs the trailer section's end within the same reader's buffer
	// (net/http/transfer.go:930-962, seeUpcomingDoubleCRLF at :913).
	h1TrailerMax = 4096
	// h1LeadingCRLFMax: after a POST, the server drops up to four CR or LF bytes before the next request line
	// (net/http/server.go:1048-1053, numLeadingCRorLF at :4287).
	h1LeadingCRLFMax = 4
)

type h1TapState uint8

const (
	h1TapHead      h1TapState = iota // reading a request head, line by line
	h1TapBody                        // passing over a Content-Length body (remaining)
	h1TapChunkSize                   // reading a chunk-size line
	h1TapChunkData                   // passing over a chunk's data (remaining)
	h1TapChunkEnd                    // reading the CRLF after a chunk's data
	h1TapTrailer                     // reading the trailer section after the last chunk
)

// h1TapConn wraps a server *tls.Conn speaking HTTP/1.1, capturing each request's wire header names and order.
//
// It sees every byte net/http reads, in order, before net/http gets them, so the request a handler serves is
// recorded by the time the handler runs. A bounded line scan finds where each request head ends; the whole head goes
// to http.ReadRequest, the parser net/http's server runs on the same bytes, for the body framing (chunked,
// Content-Length, or none); net/textproto reads the raw field names off the same lines. The body is passed over as
// the server frames it, chunked coding by net/http's own chunk rules (h1ChunkSize). A request net/http refuses stops
// the tap; the server answers one with an error and closes the connection.
type h1TapConn struct {
	*tls.Conn

	mu        sync.Mutex
	state     h1TapState
	buf       bytes.Buffer // the head, chunk-size line, chunk CRLF or trailer section being read
	lineStart int          // where buf's current line starts (h1TapHead, h1TapTrailer)
	remaining uint64       // body or chunk-data bytes still to pass over
	leading   int          // CR or LF bytes dropped before the current head
	lastPOST  bool         // the last request was a POST (h1LeadingCRLFMax)
	stopped   bool

	pendingMu    sync.Mutex
	pending      []pendingWireMeta
	pendingBytes int

	// signals, when set, counts the tap's stop and the requests no record matched (mirror_signals.go).
	signals *mirrorSignals
}

func newH1TapConn(conn *tls.Conn) *h1TapConn {
	return &h1TapConn{Conn: conn}
}

func (t *h1TapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		defer t.mu.Unlock()
		defer recoverTap(t.stop)
		t.feed(p[:n])
	}
	return n, err
}

// stop ends the tap for the connection; net/http serves it as before.
func (t *h1TapConn) stop() {
	if !t.stopped {
		t.signals.tapStop()
	}
	t.stopped = true
	t.buf = bytes.Buffer{}
}

func (t *h1TapConn) feed(chunk []byte) {
	for len(chunk) > 0 && !t.stopped {
		var whole bool
		switch t.state {
		case h1TapBody, h1TapChunkData:
			n := min(uint64(len(chunk)), t.remaining)
			t.remaining -= n
			chunk = chunk[n:]
			if t.remaining == 0 {
				if t.state == h1TapBody {
					t.state = h1TapHead
				} else {
					t.state = h1TapChunkEnd
				}
			}
		case h1TapHead:
			if t.lastPOST && t.buf.Len() == 0 && t.leading < h1LeadingCRLFMax && (chunk[0] == '\r' || chunk[0] == '\n') {
				t.leading++
				chunk = chunk[1:]
				continue
			}
			if chunk, whole = t.takeLine(chunk, tapMaxHeaderBuf); whole && t.lineEnded() {
				t.finishHead()
			}
		case h1TapChunkSize:
			if chunk, whole = t.takeLine(chunk, h1ChunkLineMax); whole {
				size, ok := h1ChunkSize(t.buf.Bytes())
				t.buf.Reset()
				switch {
				case !ok:
					t.stop()
				case size == 0:
					t.state = h1TapTrailer
				default:
					t.state, t.remaining = h1TapChunkData, size
				}
			}
		case h1TapChunkEnd:
			// net/http reads exactly CRLF after a chunk's data (net/http/internal/chunked.go Read, "malformed chunked
			// encoding").
			chunk, whole = t.takeLine(chunk, 2)
			switch {
			case whole && string(t.buf.Bytes()) == "\r\n":
				t.buf.Reset()
				t.state = h1TapChunkSize
			case whole || t.buf.Len() >= 2:
				t.stop()
			}
		case h1TapTrailer:
			if chunk, whole = t.takeLine(chunk, h1TrailerMax); whole && t.lineEnded() {
				_, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(t.buf.Bytes()))).ReadMIMEHeader()
				if err != nil {
					t.stop()
					break
				}
				t.buf.Reset()
				t.lineStart = 0
				t.state = h1TapHead
			}
		}
	}
}

// takeLine moves chunk's bytes through its first LF onto buf, buf holding at most limit bytes; past limit the tap
// stops. It answers the rest of chunk and whether buf now ends with an LF.
func (t *h1TapConn) takeLine(chunk []byte, limit int) ([]byte, bool) {
	n := bytes.IndexByte(chunk, '\n') + 1
	whole := n > 0
	if !whole {
		n = len(chunk)
	}
	if n > limit-t.buf.Len() {
		t.stop()
		return nil, false
	}
	t.buf.Write(chunk[:n])
	return chunk[n:], whole
}

// lineEnded reports whether buf's last line, just ended by an LF, is empty (LF or CRLF alone), which ends a head or a
// trailer section as net/textproto reads lines; otherwise the next line starts after it.
func (t *h1TapConn) lineEnded() bool {
	line := t.buf.Bytes()[t.lineStart:]
	if len(line) == 1 || (len(line) == 2 && line[0] == '\r') {
		return true
	}
	t.lineStart = t.buf.Len()
	return false
}

// finishHead reads the request head in buf, records its fields, and sets up the body's framing.
func (t *h1TapConn) finishHead() {
	head := t.buf.Bytes()
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		t.stop()
		return
	}
	meta, ok := wireHeadersOf(head)
	t.buf.Reset()
	t.lineStart, t.leading = 0, 0
	if !ok {
		t.stop()
		return
	}
	// `OPTIONS *` is answered by net/http's server itself (globalOptionsHandler) and reaches no handler: no record.
	if req.Method != http.MethodOptions || req.RequestURI != "*" {
		// The digest is of the request as net/http's server parses the same head (http.ReadRequest), so the handler's
		// request matches it field for field.
		digest := requestMatchDigest(req)
		t.pendingMu.Lock()
		putPending(&t.pending, &t.pendingBytes, tapMaxPendingH1, digest, meta)
		t.pendingMu.Unlock()
	}

	t.lastPOST = req.Method == http.MethodPost
	// ReadRequest framed the body as the server will (net/http/transfer.go readTransfer): a request's only transfer
	// coding is chunked (parseTransferEncoding refuses any other, and ignores the header below HTTP/1.1), which
	// overrides Content-Length; without one, ContentLength is the body's length, 0 for none.
	switch {
	case len(req.TransferEncoding) == 1 && req.TransferEncoding[0] == "chunked":
		t.state = h1TapChunkSize
	case len(req.TransferEncoding) > 0:
		t.stop()
	case req.ContentLength > 0:
		t.state, t.remaining = h1TapBody, uint64(req.ContentLength)
	}
}

// wireHeadersOf reads a request head's field names as sent, in order, off the lines net/textproto reads (obs-fold
// continuations joined, as http.ReadRequest reads them).
func wireHeadersOf(head []byte) (*wireRequestMeta, bool) {
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(head)))
	if _, err := tp.ReadLine(); err != nil {
		return nil, false
	}
	meta := &wireRequestMeta{protoMajor: 1}
	for {
		line, err := tp.ReadContinuedLine()
		if err != nil {
			return nil, false
		}
		if line == "" {
			return meta, true
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, false
		}
		meta.headers = append(meta.headers, wireHeader{name: name, value: strings.TrimLeft(value, " \t")})
	}
}

// h1ChunkSize reads a chunk-size line, its CRLF included, as net/http's chunkedReader.beginChunk does (Go 1.27.2,
// net/http/internal/chunked.go:46-85): the line ends in CRLF with no other CR and is shorter than maxLineLength
// without it (readChunkLine, :155-184); trailing spaces and tabs go (trimTrailingWhitespace, :186-191); everything
// from the first ';' is a chunk extension and goes (removeChunkExtension, :206-213); what is left is 1 to 16 hex
// digits, no sign, space or prefix (parseHexUint, :278-300), so the size fits a uint64 without overflow.
func h1ChunkSize(line []byte) (uint64, bool) {
	p, ok := bytes.CutSuffix(line, []byte("\r\n"))
	if !ok || bytes.IndexByte(p, '\r') >= 0 || len(p) >= h1ChunkLineMax {
		return 0, false
	}
	p = bytes.TrimRight(p, " \t")
	p, _, _ = bytes.Cut(p, []byte(";"))
	if len(p) == 0 || len(p) > 16 {
		return 0, false
	}
	var n uint64
	for _, b := range p {
		switch {
		case '0' <= b && b <= '9':
			b -= '0'
		case 'a' <= b && b <= 'f':
			b = b - 'a' + 10
		case 'A' <= b && b <= 'F':
			b = b - 'A' + 10
		default:
			return 0, false
		}
		n = n<<4 | uint64(b)
	}
	return n, true
}

// takeFor is r's record. HTTP/1.1 serves a connection's requests in order, so a record before r's was never taken
// (a request net/http answered itself) and goes with it.
func (t *h1TapConn) takeFor(r *http.Request) *wireRequestMeta {
	if t == nil {
		return nil
	}
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	meta, refused := takePending(&t.pending, &t.pendingBytes, requestMatchDigest(r), true)
	if refused {
		t.signals.wireMetaRefuse()
	}
	return meta
}

// take is the oldest record (a caller without the request).
func (t *h1TapConn) take() *wireRequestMeta {
	if t == nil {
		return nil
	}
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	if len(t.pending) == 0 {
		return nil
	}
	item := t.pending[0]
	t.pendingBytes -= item.bytes
	t.pending = t.pending[1:]
	return item.meta
}

// buildOrderedHeaders orders and spells req's already-checked outbound header set according to wire (when present).
// On HTTP/2 (h2 == true), field names are lower-case and Host is omitted (sent as :authority). On HTTP/1.1, Host is
// included at the wire position where the client placed it (or first when wire has none), and raw field-name casing
// from wire is preserved.
func buildOrderedHeaders(req *http.Request, wire *wireRequestMeta, host string, h2 bool) []wireHeader {
	effective := make(map[string][]string, len(req.Header)+1)
	for name, values := range req.Header {
		if len(values) == 0 {
			continue
		}
		canon := http.CanonicalHeaderKey(name)
		if canon == "Host" || canon == "Transfer-Encoding" || canon == "Connection" || canon == "Keep-Alive" ||
			canon == "Proxy-Connection" || canon == "Upgrade" || canon == "Trailer" {
			continue
		}
		if canon == "Te" && !h2 {
			continue
		}
		// server.go sets User-Agent to []string{""} to suppress net/http's default User-Agent when none was sent.
		if canon == "User-Agent" && len(values) == 1 && values[0] == "" {
			continue
		}
		effective[canon] = values
	}

	wireHasContentLen := false
	// On HTTP/1.1, the client's chunked Transfer-Encoding value and its Connection value when it is keep-alive or
	// close: egress frames the body and keeps the connection as the client asked, the field where the client put it.
	wireChunked, wireConnection := "", ""
	if wire != nil {
		for _, w := range wire.headers {
			switch value := strings.TrimSpace(w.value); http.CanonicalHeaderKey(w.name) {
			case "Content-Length":
				wireHasContentLen = true
			case "Transfer-Encoding":
				if !h2 && strings.EqualFold(value, "chunked") {
					wireChunked = value
				}
			case "Connection":
				if !h2 && (strings.EqualFold(value, "keep-alive") || strings.EqualFold(value, "close")) {
					wireConnection = value
				}
			}
		}
	}
	if wireConnection != "" {
		effective["Connection"] = []string{wireConnection}
	}
	if h2 && wire != nil {
		if grouped, ok := groupCookies(effective["Cookie"], wire.cookiePairs); ok {
			effective["Cookie"] = grouped
		}
	}
	if _, hasCL := effective["Content-Length"]; !hasCL {
		switch {
		case wireChunked != "":
			// mirror_h1.go writes the body chunked when Transfer-Encoding is in the set.
			effective["Transfer-Encoding"] = []string{wireChunked}
		case !h2 && wire != nil && !wireHasContentLen && req.ContentLength == 0:
			// No framing field and no body on the client's wire: none on egress's.
		case h2 && wire != nil:
			// HTTP/2 frames the body with DATA and END_STREAM: content-length goes out exactly when the client sent
			// one, of the body's length (0 for none, on a GET too); mirrorH2Request has the transport follow.
			if wireHasContentLen && req.ContentLength >= 0 {
				effective["Content-Length"] = []string{strconv.FormatInt(req.ContentLength, 10)}
			}
		case req.ContentLength > 0:
			effective["Content-Length"] = []string{strconv.FormatInt(req.ContentLength, 10)}
		case req.ContentLength == 0 && req.Body != nil && ((!h2 && (req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch)) || wireHasContentLen):
			effective["Content-Length"] = []string{"0"}
		}
	}

	emitted := make(map[string]bool, len(effective)+1)
	out := make([]wireHeader, 0, len(effective)+1)
	hostEmitted := h2

	spell := func(rawName, canon string) string {
		if h2 {
			return strings.ToLower(canon)
		}
		if httpguts.ValidHeaderFieldName(rawName) {
			return rawName
		}
		return canon
	}

	if wire != nil {
		for _, w := range wire.headers {
			canon := http.CanonicalHeaderKey(w.name)
			if canon == "Host" {
				if !hostEmitted {
					out = append(out, wireHeader{name: spell(w.name, "Host"), value: host})
					hostEmitted = true
				}
				continue
			}
			if emitted[canon] {
				continue
			}
			vals, ok := effective[canon]
			if !ok {
				continue
			}
			emitted[canon] = true
			wireName := spell(w.name, canon)
			for _, v := range vals {
				out = append(out, wireHeader{name: wireName, value: v, sensitive: h2 && w.sensitive})
			}
		}
	}

	if !hostEmitted {
		out = append([]wireHeader{{name: "Host", value: host}}, out...)
	}

	remaining := make([]string, 0, len(effective))
	for canon := range effective {
		if !emitted[canon] {
			remaining = append(remaining, canon)
		}
	}
	sort.Slice(remaining, func(i, j int) bool {
		return strings.ToLower(remaining[i]) < strings.ToLower(remaining[j])
	})
	for _, canon := range remaining {
		wireName := canon
		if h2 {
			wireName = strings.ToLower(canon)
		}
		for _, v := range effective[canon] {
			out = append(out, wireHeader{name: wireName, value: v})
		}
	}
	return out
}

// groupCookies splits values' cookie-pairs into fields of pairs[i] pairs each, as the client sent them (net/http's
// HTTP/2 server joined them with "; "). It fails when the pairs do not add up (the relay changed the cookies): the
// transport then splits them its own way.
func groupCookies(values []string, pairs []int) ([]string, bool) {
	if len(values) == 0 || len(pairs) == 0 {
		return nil, false
	}
	var all []string
	for _, v := range values {
		for _, pair := range strings.Split(v, ";") {
			if pair = strings.TrimSpace(pair); pair != "" {
				all = append(all, pair)
			}
		}
	}
	total := 0
	for _, n := range pairs {
		total += n
	}
	if total != len(all) {
		return nil, false
	}
	out := make([]string, 0, len(pairs))
	for _, n := range pairs {
		out = append(out, strings.Join(all[:n], "; "))
		all = all[n:]
	}
	return out, true
}

var defaultH2PseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

// resolveH2PseudoOrder returns the 4 HTTP/2 request pseudo-headers in wire's order, falling back to preface's order
// and then the standard order.
func resolveH2PseudoOrder(wire *wireRequestMeta, preface *h2Preface) []string {
	var base []string
	if wire != nil && len(wire.pseudoOrder) > 0 {
		base = wire.pseudoOrder
	} else if preface != nil && len(preface.PseudoOrder) > 0 {
		base = preface.PseudoOrder
	}
	if len(base) == 0 {
		return defaultH2PseudoOrder
	}
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, p := range base {
		if (p == ":method" || p == ":authority" || p == ":scheme" || p == ":path") && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range defaultH2PseudoOrder {
		if !seen[p] {
			out = append(out, p)
		}
	}
	return out
}
