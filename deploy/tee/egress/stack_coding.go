package main

// Content codings on the relay path (owner, 2026-11-13). The vendor sees the relay software's own choice of coding,
// as it would on a direct call: a relay call's `Accept-Encoding` reaches the vendor as the relay sent it (S16 used
// to replace it with `identity`), less any coding egress cannot decode, and a `Content-Type` naming JSON keeps the
// relay's spelling (stackRelayFraming, in stack_changes.go, which the conformance check compiles too). The vendor's
// answer reaches the relay as the vendor coded it (S20: byte for byte, with its `Content-Encoding`); egress decodes
// a copy for what it reads itself: the S19 event and body digests, the
// `error_body` record and S35's classification. A coding egress does not decode, which only a vendor that ignores
// `Accept-Encoding` can send, ends the answer `response_read` (the end record's vendor_reset): nothing of it could
// be digested.
//
// The decoders are the maintained ones: compress/gzip and compress/flate (with compress/zlib for `deflate`, RFC
// 9110 §8.4.1.2) from the standard library, github.com/andybalholm/brotli (the pure-Go port of Google's decoder)
// and github.com/klauspost/compress/zstd, at the versions go.mod pins (both already reached egress through utls).
// They read from an io.Reader, while the observer is pushed one chunk at a time (forward's loop) and must have
// every digest of a chunk queued before the chunk goes to the relay (S24). So the decoders run on a goroutine of
// their own (stackDecoder) that hands each decoded piece to the observer and waits for it, and a chunk is done
// once that goroutine asks for more input: every byte of it was consumed, and everything the decoders could make
// of it was handed over. The observer stays the only goroutine that touches the attempt's state and budget.

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	// stackCodingsMax bounds the codings of one answer: each is a decoder with its own state (below). A vendor
	// applies one; RFC 9110 allows a list, so a few are taken.
	stackCodingsMax = 4

	// stackDecodeRatioMax bounds what one answer may decode to: at most this many bytes per vendor byte read, plus
	// stackDecodeSlackBytes. 1032:1 is DEFLATE's own limit (zlib.net/zlib_tech.html, "the limit of the deflate
	// format is 1032:1": a 258-byte match costs at least two bits), so no gzip or deflate answer can pass it; brotli
	// and zstd can describe far more output per byte (a zstd RLE block is 128 KiB from 4 bytes), and an answer that
	// does is a decompression bomb, not text. The slack lets the first bytes of an answer through before the ratio
	// can bind. Past the bound the answer is cut with egress_limit, as one the budget cannot hold.
	stackDecodeRatioMax   = 1032
	stackDecodeSlackBytes = 1 << 20

	// stackDecoderBytes is what a decoder holds besides its codings' state: the 32 KiB piece buffer it hands
	// decoded bytes over in (forward's own read size) and an allowance for its goroutine's stack (Go starts one at
	// 8 KiB and grows it with the decoders' call depth).
	stackDecoderBytes = forwardBufferBytes + 64<<10

	// stackFlateBytes bounds a gzip or deflate decoder (Go 1.27.2 compress/flate inflate.go): the 32 KiB window
	// (dictDecoder), two Huffman decoders of 512 chunks each plus their link tables (at most one 64-entry table per
	// 9-bit prefix of the 288 literal/length codes, and of the 30 distance codes, 4 bytes an entry: about 80 KiB),
	// the code-length arrays, and gzip's or zlib's header buffer; 128 KiB covers them with room.
	stackFlateBytes = 128 << 10

	// stackBrotliTablesBytes bounds a brotli decoder's tables besides its window (andybalholm/brotli v1.2.2
	// state.go, decode.go): at most 256 literal, 256 insert-and-copy and 256 distance Huffman trees of at most
	// 630, 1080 and 1080 four-byte entries (kMaxHuffmanTableSize for alphabets of 256, 704 and up to 544 symbols),
	// about 2.8 MiB, plus the context maps (256 x 64 and 256 x 4 bytes), the block-type trees and its 32 KiB input
	// buffer (readBufSize). Its window is 2^WBITS bytes plus 42 bytes of slack (kRingBufferWriteAheadSlack, 1 KiB here), WBITS
	// from the stream's first byte (brotliWindowBits).
	stackBrotliTablesBytes = 3<<20 + 32<<10 + 1<<10

	// stackZstdWindowMax is RFC 9659's window bound for the `zstd` content coding (§3: an encoder MUST NOT use a
	// window over 8 MB, and a decoder needs no more). A frame that asks for more is refused by the decoder
	// (WithDecoderMaxWindow), as one with a larger window than the stream's first frame.
	stackZstdWindowMax = 8 << 20
	// stackZstdBlockBytes bounds a zstd decoder's state besides its history (klauspost/compress v1.17.4
	// blockdec.go): the compressed block (at most 128 KiB, maxCompressedBlockSizeAlloc), the decoded block and
	// literal buffers (128 KiB each, plus compressedBlockOverAlloc), the sequence and FSE tables.
	stackZstdBlockBytes = 640 << 10
	// zstdFrameHeaderMax is the longest zstd frame header (RFC 8878 §3.1.1: 4 magic bytes, the descriptor, the
	// window descriptor, a 4-byte dictionary id and an 8-byte content size).
	zstdFrameHeaderMax = 18
)

// stackResponseCodings are an answer's content codings in the order the vendor applied them (RFC 9110 §8.4: the
// field lists them so), `identity` left out and `x-gzip` read as `gzip`. ok is false for a coding egress does not
// decode, or more than stackCodingsMax.
func stackResponseCodings(h http.Header) ([]string, bool) {
	var codings []string
	for _, value := range h.Values("Content-Encoding") {
		for _, coding := range strings.Split(value, ",") {
			coding = strings.ToLower(strings.Trim(coding, " \t"))
			switch {
			case coding == "" || coding == "identity":
				continue
			case !stackDecodableCodings[coding]:
				return nil, false
			case coding == "x-gzip":
				coding = "gzip"
			}
			codings = append(codings, coding)
		}
	}
	return codings, len(codings) <= stackCodingsMax
}

// stackDecodeSink takes what a stackDecoder makes, on the goroutine that called write or end: charge holds n more
// bytes of decoder state in the budget, decoded takes one piece of decoded bytes (valid during the call). Either
// returns false to stop the decoder (errDecodeStopped).
type stackDecodeSink interface {
	charge(n int64) bool
	decoded(p []byte) bool
}

var (
	// errDecodeStopped is the sink's own stop: it said why (the budget, the ratio bound).
	errDecodeStopped = errors.New("egress decoder stopped by its sink")
	errDecodeClosed  = errors.New("egress decoder closed")
	errBrotliWindow  = errors.New("brotli: invalid window bits")
	errZstdWindow    = errors.New("zstd: window over RFC 9659's 8 MB")
	// errDecodeTrailing is input after the codings' own end (a zlib or deflate stream ends where its data says).
	errDecodeTrailing = errors.New("egress decoder: input after the end of the coded stream")
)

const (
	decodePiece = iota
	decodeCharge
	decodeStarved
	decodeEnded
)

type decodeMessage struct {
	kind int
	p    []byte
	n    int64
	err  error
}

// stackDecoder decodes one answer's codings on its own goroutine. Its methods are called by one goroutine (the
// attempt's), which also runs every sink call: the decoder goroutine only decodes, and waits for the caller at each
// piece, each charge and whenever it needs input, so at most one of the two runs at a time.
type stackDecoder struct {
	sink   stackDecodeSink
	in     chan []byte // the next chunk, or nil for the end of the answer
	out    chan decodeMessage
	reply  chan bool
	done   chan struct{}
	exited chan struct{}
	ended  bool  // the decoder goroutine finished
	err    error // its last error (io.EOF at a clean end)
	closed bool
}

// newStackDecoder starts a decoder for codings (in applied order) and runs it until it waits for its first input.
func newStackDecoder(codings []string, sink stackDecodeSink) (*stackDecoder, error) {
	if !sink.charge(stackDecoderBytes) {
		return nil, errDecodeStopped
	}
	d := &stackDecoder{sink: sink, in: make(chan []byte), out: make(chan decodeMessage), reply: make(chan bool),
		done: make(chan struct{}), exited: make(chan struct{})}
	go d.run(codings)
	if err := d.drain(); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

// write decodes p: when it returns, every byte of p was consumed (the caller may reuse p) and everything the
// codings could make of the input so far went to the sink.
func (d *stackDecoder) write(p []byte) error {
	if d.ended {
		if d.err == io.EOF {
			return errDecodeTrailing
		}
		return d.err
	}
	select {
	case d.in <- p:
	case <-d.exited:
		return errDecodeClosed
	}
	return d.drain()
}

// end tells the decoder the answer is over and takes the rest of its output: nil when the coded stream ended
// cleanly (a truncated one is io.ErrUnexpectedEOF).
func (d *stackDecoder) end() error {
	if !d.ended {
		select {
		case d.in <- nil:
		case <-d.exited:
			return errDecodeClosed
		}
		if err := d.drain(); err != nil {
			return err
		}
	}
	if !d.ended {
		// The codings asked for more after the end of input: the stream is cut.
		return io.ErrUnexpectedEOF
	}
	if d.err == io.EOF {
		return nil
	}
	return d.err
}

// drain runs the sink for the decoder goroutine's messages until it waits for input or ends.
func (d *stackDecoder) drain() error {
	for {
		var m decodeMessage
		select {
		case m = <-d.out:
		case <-d.exited:
			return errDecodeClosed
		}
		switch m.kind {
		case decodePiece, decodeCharge:
			ok := m.kind == decodePiece && d.sink.decoded(m.p) || m.kind == decodeCharge && d.sink.charge(m.n)
			select {
			case d.reply <- ok:
			case <-d.exited:
				return errDecodeClosed
			}
			if !ok {
				return errDecodeStopped
			}
		case decodeStarved:
			return nil
		case decodeEnded:
			d.ended, d.err = true, m.err
			if m.err == io.EOF {
				return nil
			}
			return m.err
		}
	}
}

// close stops the decoder goroutine and waits for it; the decoders' memory is garbage after. Idempotent.
func (d *stackDecoder) close() {
	if d == nil || d.closed {
		return
	}
	d.closed = true
	close(d.done)
	<-d.exited
}

// post hands m to the caller; ask hands it and waits for the caller's answer. Both give up once the decoder is
// closed.
func (d *stackDecoder) post(m decodeMessage) bool {
	select {
	case d.out <- m:
		return true
	case <-d.done:
		return false
	}
}

func (d *stackDecoder) ask(m decodeMessage) bool {
	if !d.post(m) {
		return false
	}
	select {
	case ok := <-d.reply:
		return ok
	case <-d.done:
		return false
	}
}

// run is the decoder goroutine: the codings' readers stacked over the input, read in pieces until they end.
func (d *stackDecoder) run(codings []string) {
	defer close(d.exited)
	var closers []func()
	defer func() {
		for _, closeDecoder := range closers {
			closeDecoder()
		}
	}()
	var r io.Reader = &decodeFeeder{d: d}
	for i := len(codings) - 1; i >= 0; i-- {
		r = &decodeLayer{d: d, coding: codings[i], src: r, base: i == len(codings)-1, top: i == 0, closers: &closers}
	}
	piece := make([]byte, forwardBufferBytes)
	for {
		n, err := r.Read(piece)
		if n > 0 && !d.ask(decodeMessage{kind: decodePiece, p: piece[:n]}) {
			return
		}
		if err != nil {
			if !errors.Is(err, errDecodeClosed) && !errors.Is(err, errDecodeStopped) {
				d.post(decodeMessage{kind: decodeEnded, err: err})
			}
			return
		}
	}
}

// decodeFeeder is the decoders' input: the chunks the caller writes, one at a time. Asking for input with none left
// tells the caller the chunk is done (decodeStarved). It is an io.ByteReader, so compress/flate reads it without a
// bufio.Reader of its own.
type decodeFeeder struct {
	d   *stackDecoder
	cur []byte
	eof bool
}

func (f *decodeFeeder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(f.cur) == 0 {
		if f.eof {
			return 0, io.EOF
		}
		if !f.d.post(decodeMessage{kind: decodeStarved}) {
			return 0, errDecodeClosed
		}
		select {
		case chunk := <-f.d.in:
			if chunk == nil {
				f.eof = true
			} else {
				f.cur = chunk
			}
		case <-f.d.done:
			return 0, errDecodeClosed
		}
	}
	n := copy(p, f.cur)
	f.cur = f.cur[n:]
	return n, nil
}

func (f *decodeFeeder) ReadByte() (byte, error) {
	var b [1]byte
	if _, err := f.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// byteSource is a decoder's source: the feeder for the first coding undone, a 4 KiB bufio.Reader over the coding
// below it for the others (charged with the layer).
type byteSource interface {
	io.Reader
	io.ByteReader
}

// decodeLayer undoes one coding. It opens its decoder on its first read, once it can size the decoder's state from
// the stream's own header and charge it (brotli's window bits, zstd's window).
type decodeLayer struct {
	d      *stackDecoder
	coding string
	src    io.Reader
	base   bool
	// top is the coding undone last, which run reads; every other layer is read by the decoder above it.
	top     bool
	closers *[]func()
	r       io.Reader
	// done is set once the coding's own stream ended; any input after it is errDecodeTrailing.
	done bool
}

func (l *decodeLayer) Read(p []byte) (int, error) {
	n, err := l.read(p)
	if err != nil && err != io.EOF && !l.top {
		// The decoder above must not read this layer's failure as its own input's end: zstd takes an
		// io.ErrUnexpectedEOF between frames for the end of the stream, gzip one between members.
		err = layerError{err}
	}
	return n, err
}

// layerError is a lower layer's failure as the layer above it reads it: equal to no io error.
type layerError struct{ err error }

func (e layerError) Error() string { return e.err.Error() }
func (e layerError) Unwrap() error { return e.err }

func (l *decodeLayer) read(p []byte) (int, error) {
	if l.r == nil {
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	if l.done {
		return 0, l.trailing()
	}
	n, err := l.r.Read(p)
	if err == io.EOF && (l.coding == "deflate" || l.coding == "br") {
		// zlib, raw deflate and brotli streams end where their data says, before the answer's end; gzip and zstd
		// read on for another member or frame and fail on anything else.
		l.done = true
		if n == 0 {
			return 0, l.trailing()
		}
		err = nil
	}
	return n, err
}

// trailing is the end of a deflate or brotli layer: io.EOF when the input ends with the stream, else errDecodeTrailing.
func (l *decodeLayer) trailing() error {
	var b [1]byte
	n, err := io.ReadFull(l.src, b[:])
	if n > 0 {
		return errDecodeTrailing
	}
	return err
}

func (l *decodeLayer) open() error {
	var src byteSource
	if l.base {
		src = l.src.(*decodeFeeder)
	} else {
		if !l.d.ask(decodeMessage{kind: decodeCharge, n: 4 << 10}) {
			return errDecodeStopped
		}
		buffered := bufio.NewReaderSize(l.src, 4<<10)
		src = buffered
	}
	l.src = src
	switch l.coding {
	case "gzip":
		if !l.d.ask(decodeMessage{kind: decodeCharge, n: stackFlateBytes}) {
			return errDecodeStopped
		}
		z, err := gzip.NewReader(src)
		if err != nil {
			return err
		}
		l.r = z
	case "deflate":
		if !l.d.ask(decodeMessage{kind: decodeCharge, n: stackFlateBytes}) {
			return errDecodeStopped
		}
		head, err := readHead(src, 2)
		if err != nil {
			return err
		}
		prefixed := &prefixReader{head: head, src: src}
		if zlibHeader(head) {
			z, err := zlib.NewReader(prefixed)
			if err != nil {
				return err
			}
			l.r = z
		} else {
			// RFC 9110 §8.4.1.2 says zlib, but some servers send bare DEFLATE; Chromium (net/filter
			// gzip_source_stream.cc) and curl (lib/content_encoding.c) both read a stream whose first two bytes are
			// no zlib header as bare DEFLATE, and so does egress.
			l.r = flate.NewReader(prefixed)
		}
	case "br":
		head, err := readHead(src, 1)
		if err != nil {
			return err
		}
		bits, ok := brotliWindowBits(head[0])
		if !ok {
			return errBrotliWindow
		}
		if !l.d.ask(decodeMessage{kind: decodeCharge, n: 1<<bits + stackBrotliTablesBytes}) {
			return errDecodeStopped
		}
		l.r = brotli.NewReader(&prefixReader{head: head, src: src})
	case "zstd":
		head, window, err := zstdWindow(src)
		if err != nil {
			return err
		}
		if !l.d.ask(decodeMessage{kind: decodeCharge, n: zstdHistoryBytes(window) + stackZstdBlockBytes}) {
			return errDecodeStopped
		}
		z, err := zstd.NewReader(&prefixReader{head: head, src: src}, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(window), zstd.WithDecoderMaxMemory(window))
		if err != nil {
			return err
		}
		*l.closers = append(*l.closers, z.Close)
		l.r = z
	default:
		return errors.New("egress decoder: unknown coding " + l.coding)
	}
	return nil
}

// readHead reads the first n bytes of a coded stream. A stream that ends before its first byte is empty (io.EOF,
// a clean end); one that ends inside them is cut.
func readHead(src io.Reader, n int) ([]byte, error) {
	head := make([]byte, n)
	read, err := io.ReadFull(src, head)
	if err == io.EOF && read == 0 {
		return nil, io.EOF
	}
	return head, err
}

// prefixReader reads head, then src.
type prefixReader struct {
	head []byte
	src  byteSource
}

func (r *prefixReader) Read(p []byte) (int, error) {
	if len(r.head) > 0 {
		n := copy(p, r.head)
		r.head = r.head[n:]
		return n, nil
	}
	return r.src.Read(p)
}

func (r *prefixReader) ReadByte() (byte, error) {
	if len(r.head) > 0 {
		b := r.head[0]
		r.head = r.head[1:]
		return b, nil
	}
	return r.src.ReadByte()
}

// zlibHeader is RFC 1950 §2.2's header check: compression method 8, a window of at most 32 KiB, and the check bits.
func zlibHeader(head []byte) bool {
	cmf, flg := head[0], head[1]
	return cmf&0x0f == 8 && cmf>>4 <= 7 && (uint16(cmf)<<8|uint16(flg))%31 == 0
}

// brotliWindowBits is a brotli stream's WBITS from its first byte (RFC 7932 §9.1, read low bit first, as
// andybalholm/brotli decodeWindowBits does): 16, 17 + n for n of 1..7 in the next three bits, else 8 + m for m of
// 2..7 in the three after, or 17 for m = 0. m = 1 is the large-window extension, which the decoder refuses unless
// asked, and so does this.
func brotliWindowBits(first byte) (int, bool) {
	if first&1 == 0 {
		return 16, true
	}
	if n := (first >> 1) & 7; n != 0 {
		return 17 + int(n), true
	}
	switch m := (first >> 4) & 7; m {
	case 0:
		return 17, true
	case 1:
		return 0, false
	default:
		return 8 + int(m), true
	}
}

// zstdWindow reads a zstd stream's first frame header (with the library's own reader, zstd.Header) and answers the
// bytes read and the window egress allows the stream: the frame's window (a single-segment frame's content size),
// at least 1 KiB, at most stackZstdWindowMax; a stream that starts with a skippable frame gets stackZstdWindowMax.
func zstdWindow(src io.ByteReader) ([]byte, uint64, error) {
	var head []byte
	var header zstd.Header
	for {
		b, err := src.ReadByte()
		if err != nil {
			if err == io.EOF && len(head) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return nil, 0, err
		}
		head = append(head, b)
		err = header.Decode(head)
		if err == nil {
			break
		}
		if err != io.ErrUnexpectedEOF || len(head) >= zstdFrameHeaderMax {
			return nil, 0, err
		}
	}
	window := header.WindowSize
	switch {
	case header.Skippable:
		window = stackZstdWindowMax
	case header.SingleSegment:
		window = header.FrameContentSize
	}
	if window > stackZstdWindowMax {
		return nil, 0, errZstdWindow
	}
	return head, max(window, zstd.MinWindowSize), nil
}

// zstdHistoryBytes is the history buffer klauspost/compress v1.17.4 allocates for a window under
// WithDecoderLowmem (framedec.go: twice the window below its maxBlockSize of 2 MiB - 1, else the window plus
// half of it).
func zstdHistoryBytes(window uint64) int64 {
	const libraryMaxBlockSize = 1<<21 - 1
	if window < libraryMaxBlockSize {
		return int64(2 * window)
	}
	return int64(window + libraryMaxBlockSize/2)
}
