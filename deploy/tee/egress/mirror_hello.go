package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	utls "github.com/refraction-networking/utls"
)

// The mirrored ClientHello (README "The relay's TLS handshake reaches the vendor"). A relay program that opens a
// tunnel to a vendor's API host (mirror_tunnel.go) makes a TLS handshake of its own; egress ends that TLS (it has
// to read the call) and makes the vendor's handshake with the same structure: the cipher suites, the extensions and
// their order, the groups, the signature algorithms, the ALPN offer, the versions and where GREASE sits. Whatever
// TLS library or parameters the relay program uses is what the vendor sees; egress has no opinion on them.
//
// Not copied are the bytes every client makes anew for each connection, which a server only uses and cannot check:
// the random, the session id's bytes (its length is structure, and kept), the key shares (their private keys are the
// container's, so egress could not finish a handshake with them), padding (zeros by RFC 7685), the GREASE values, a
// GREASE ECH payload and any resumed session ticket or pre-shared key (egress issues its own ticket on the tunnel and
// presents the vendor's ticket on the outbound leg when both sides resume; mirror_sessions.go). Egress makes its own
// per-connection values of the same lengths. A resumed hello's early_data extension is not copied either: egress
// sends no 0-RTT data, so it does not offer any (a hello with early_data and no pre-shared key is refused).
//
// The account's proxy reads a ClientHello in the clear, so a hello the container chose while it held a customer's
// request could carry that request out of the VM. Egress therefore repeats only shapes it learned before the first
// customer request reached the container (mirror_profiles.go): after that a tunnel's hello only picks one of them.
//
// A hello egress cannot repeat is refused by name (errStackHelloRefused, the reason in `path`), never replaced by
// Go's own handshake: the relay would see a vendor transport change it did not make.

const (
	// helloMaxBytes is the largest ClientHello taken: one TLS record. The hellos measured for this change
	// (2026-11-12: Go 1.27 crypto/tls 1533 bytes, Chrome 133's shape 1753 with its X25519MLKEM768 share, Node 22 and
	// OpenSSL 3 under 600) are a ninth of it.
	helloMaxBytes = 5 + 16384
	// The list bounds are at least twice the longest list measured (2026-11-12, TestRealClientHellosAreRepeated and
	// the uTLS presets: Node 26 sends 52 cipher suites and 26 signature algorithms, OpenSSL 4 11 groups and 27
	// signature algorithms, Chrome 133's shape 18 extensions).
	helloMaxCipherSuites = 128
	helloMaxGroups       = 32
	helloMaxSignatures   = 64
	helloMaxExtensions   = 40
	helloMaxSmallList    = 8
)

// helloEarlyData is the early_data extension (RFC 8446 4.2.10), which a client sends only beside a pre-shared key.
const helloEarlyData = 42

// helloProtocols are the ALPN names a mirrored hello may offer: the two the vendors' API hosts speak.
var helloProtocols = map[string]bool{"h2": true, "http/1.1": true}

// helloKeyShareGroups are the groups uTLS makes a key share for (u_parrots.go ApplyPreset).
var helloKeyShareGroups = map[utls.CurveID]bool{
	utls.X25519: true, utls.CurveP256: true, utls.CurveP384: true, utls.CurveP521: true,
	utls.X25519MLKEM768: true, utls.X25519Kyber768Draft00: true,
}

// helloCertCompression are the certificate compression algorithms uTLS decompresses.
var helloCertCompression = map[utls.CertCompressionAlgo]bool{
	utls.CertCompressionZlib: true, utls.CertCompressionBrotli: true, utls.CertCompressionZstd: true,
}

// mirroredHello is one container ClientHello egress can repeat, together with the HTTP/2 connection preface learned
// for it while learning is open (mirror_profiles.go).
type mirroredHello struct {
	raw []byte
	// key names the hello's structure: two hellos with one key give the vendor the same handshake parameters, so
	// their vendor connections may be shared.
	key string
	// family names the same offer whatever the order of its extensions (mirror_profiles.go).
	family string
	// resumedKey and resumedFamily match a resumed ClientHello whose session_ticket or RFC 7685 padding extension
	// changed when a session ticket or pre-shared key was added.
	resumedKey    string
	resumedFamily string
	// h2 is whether the hello offers HTTP/2, which the vendor may then choose.
	h2 bool
	// resumes is whether the hello offers TLS 1.3 session resumption (helloResumes): egress then issues session
	// tickets on the container's tunnel and aligns session resumption with the vendor (mirror_sessions.go).
	resumes bool
	// offeredResumption is whether raw carried a TLS 1.3 pre_shared_key or a non-empty TLS 1.2 session_ticket.
	offeredResumption bool
	// sessionIDLen is the length of raw's legacy_session_id (part of key). A client in TLS 1.3 middlebox
	// compatibility mode (RFC 8446 D.4) sends 32 random bytes and a dummy ChangeCipherSpec; one that is not sends
	// none and no ChangeCipherSpec. Egress sends its own random bytes of this length, and the dummy
	// ChangeCipherSpec only when the length is not 0 (mirror_dial.go).
	sessionIDLen int
	// shuffles is whether egress learned two or more extension orders of this hello's family: its client orders its
	// extensions anew for each connection (Chrome since 110), so each vendor connection gets an order of egress's
	// own making (shuffleHelloExtensions). Set by helloProfiles; read at each dial.
	shuffles atomic.Bool
	// fullRecords is whether the client was seen, during learning, to write a first application-data record larger
	// than a TCP segment: it fills TLS records from the start (OpenSSL, BoringSSL, Node) rather than growing them (Go's
	// dynamic record sizing). Each vendor connection then writes full records too (uTLS DynamicRecordSizingDisabled).
	// Unknown (no large write during learning) keeps uTLS's default, dynamic sizing.
	fullRecords atomic.Bool
	// profiles is the set the shape was learned into (helloProfiles.admitFor), for what is learned after admission.
	profiles *helloProfiles

	h2Mu    sync.RWMutex
	preface *h2Preface
	// prefaceProblem is why a preface read for this shape was not taken (h2Preface.problem); its vendor calls are
	// refused as for one never read.
	prefaceProblem string
	seenVendor     bool
	seenSignIn     bool
}

// usable is whether egress repeats the shape whole: a shape that offers h2 needs its client's HTTP/2 preface, since
// without it the vendor would read a preface no client sends (README "The relay's TLS handshake reaches the vendor").
func (h *mirroredHello) usable() bool {
	return !h.h2 || h.h2Preface() != nil
}

// unusableReason is why a shape that offers h2 has no preface.
func (h *mirroredHello) unusableReason() string {
	h.h2Mu.RLock()
	problem := h.prefaceProblem
	h.h2Mu.RUnlock()
	if problem != "" {
		return "the HTTP/2 preface egress read for this handshake is one it does not repeat: " + problem
	}
	return "the handshake offers h2 and egress read no HTTP/2 preface for it before the first customer request (keep each h2 warm-up tunnel open until egress answers a PING)"
}

const (
	h2MaxPrefaceSettings   = 16
	h2MaxPrefacePriorities = 16
	h2MaxHeaderTableSize   = 65536
	// h2MaxPrefacePriorityStream is the highest stream a learned startup PRIORITY frame may name: the vendor
	// connection's first request takes the stream after it, and an HTTP/2 client can open streams only below 2^31-1,
	// so a PRIORITY frame near 2^31 would leave every new vendor connection unable to take a request. The clients
	// that send startup PRIORITY frames (Firefox to 119) name streams 3 to 13; 255 leaves 2^31-256 streams. It is
	// the fork's MaxPrefacePriorityStream (TestPrefaceBoundsAreTheForks).
	h2MaxPrefacePriorityStream = 255
	// h2MaxLearnedStreamWindow is the largest SETTINGS_INITIAL_WINDOW_SIZE egress learns: each mirrored call takes its
	// connection's stream window from the budget (mirrorStreamWindow), so it bounds what one call may hold. The
	// largest measured: Chrome 6 MiB, Go's HTTP/2 client 4 MiB, Safari 4 MiB, Firefox 128 KiB.
	h2MaxLearnedStreamWindow = 16 << 20
	// h2MaxLearnedFrameSize is the largest SETTINGS_MAX_FRAME_SIZE egress learns: the vendor connection's frame
	// read buffer grows to it, and each call takes it from the budget beside its window. Go's HTTP/2 client sends
	// 1 MiB, the largest measured; Chrome, Firefox and nghttp2 keep 16 KiB.
	h2MaxLearnedFrameSize = 1 << 20
)

// problem is why egress does not take p as a client's preface, "" when it does. budget, when positive, is egress's
// whole budget (-stack-max-bytes): a preface whose stream window and frame buffer do not fit in it could carry no
// call at all.
func (p *h2Preface) problem(budget int64) string {
	if p == nil {
		return ""
	}
	window, frame := int64(65535), int64(16384)
	for _, s := range p.Settings {
		switch s.ID {
		case 0x4: // INITIAL_WINDOW_SIZE
			if s.Val > h2MaxLearnedStreamWindow {
				return fmt.Sprintf("an HTTP/2 INITIAL_WINDOW_SIZE of %d (at most %d)", s.Val, h2MaxLearnedStreamWindow)
			}
			window = int64(s.Val)
		case 0x5: // MAX_FRAME_SIZE
			if s.Val > h2MaxLearnedFrameSize {
				return fmt.Sprintf("an HTTP/2 MAX_FRAME_SIZE of %d (at most %d)", s.Val, h2MaxLearnedFrameSize)
			}
			frame = int64(s.Val)
		}
	}
	if budget > 0 && window+frame > budget {
		return fmt.Sprintf("an HTTP/2 stream window and frame size of %d bytes, over egress's budget of %d", window+frame, budget)
	}
	for _, pr := range p.Priorities {
		if pr.StreamID > h2MaxPrefacePriorityStream {
			return fmt.Sprintf("a startup PRIORITY frame for stream %d (at most %d)", pr.StreamID, h2MaxPrefacePriorityStream)
		}
	}
	return ""
}

type h2Setting struct {
	ID  uint16 `json:"id"`
	Val uint32 `json:"val"`
}

type h2Priority struct {
	StreamID  uint32 `json:"stream_id"`
	StreamDep uint32 `json:"stream_dep"`
	Weight    uint8  `json:"weight"`
	Exclusive bool   `json:"exclusive"`
}

type h2HeadersPriority struct {
	StreamDep uint32 `json:"stream_dep"`
	Weight    uint8  `json:"weight"`
	Exclusive bool   `json:"exclusive"`
}

// h2Preface is the HTTP/2 connection preface learned from a client before customer requests arrive: its initial
// SETTINGS frame (IDs, order and values), any stream-0 WINDOW_UPDATE increment, any startup PRIORITY frames, the
// order those frames came in, whether a stream-0 WINDOW_UPDATE came at all, and any request HEADERS pseudo-header
// order and priority template observed during warm-up.
type h2Preface struct {
	source          uint64
	Settings        []h2Setting        `json:"settings"`
	WindowIncrement uint32             `json:"window_increment,omitempty"`
	Priorities      []h2Priority       `json:"priorities,omitempty"`
	PseudoOrder     []string           `json:"pseudo_order,omitempty"`
	HeadersPriority *h2HeadersPriority `json:"headers_priority,omitempty"`
	// FrameOrder is the startup frames in arrival order, one entry per frame (h2FrameSettings,
	// h2FrameWindowUpdate, h2FramePriority), up to the first HEADERS or DATA frame. Empty: unknown (a profile
	// written before the field, or a tap that did not record it).
	FrameOrder []string `json:"frame_order,omitempty"`
	// ConnWindowUpdate is whether the client sent a stream-0 WINDOW_UPDATE before its first HEADERS or DATA
	// frame; nil: unknown.
	ConnWindowUpdate *bool `json:"conn_window_update,omitempty"`
	// StreamRefund and ConnRefund are the smallest WINDOW_UPDATE increments the client sent for a stream and for its
	// connection after its preface, while it read answers during learning (a sign-in or refresh at start): when it
	// returns window, which the vendor connection then does at the same fraction of its window
	// (mirror_transport.go mirrorRefund). 0: none seen, egress's transport keeps its own rule.
	StreamRefund uint32 `json:"stream_refund,omitempty"`
	ConnRefund   uint32 `json:"conn_refund,omitempty"`
}

// The FrameOrder entries.
const (
	h2FrameSettings     = "settings"
	h2FrameWindowUpdate = "window_update"
	h2FramePriority     = "priority"
)

// h2MaxFrameOrder bounds FrameOrder: one SETTINGS, one WINDOW_UPDATE, h2MaxPrefacePriorities PRIORITY frames.
const h2MaxFrameOrder = 2 + h2MaxPrefacePriorities

// usableFrameOrder is FrameOrder when egress can replay it: SETTINGS first and once (RFC 9113 3.4), at most one
// WINDOW_UPDATE, only known entries, within h2MaxFrameOrder. Otherwise nil, and the transport falls back to its
// fixed order (mirror_transport.go mirrorConnPreface).
func (p *h2Preface) usableFrameOrder() []string {
	if p == nil || len(p.FrameOrder) == 0 || len(p.FrameOrder) > h2MaxFrameOrder || p.FrameOrder[0] != h2FrameSettings {
		return nil
	}
	windows := 0
	for _, kind := range p.FrameOrder[1:] {
		switch kind {
		case h2FrameWindowUpdate:
			windows++
		case h2FramePriority:
		default:
			return nil
		}
	}
	if windows > 1 {
		return nil
	}
	return p.FrameOrder
}

func (p *h2Preface) clone() *h2Preface {
	if p == nil {
		return nil
	}
	out := &h2Preface{
		source:          p.source,
		Settings:        append([]h2Setting(nil), p.Settings...),
		WindowIncrement: p.WindowIncrement,
		Priorities:      append([]h2Priority(nil), p.Priorities...),
		PseudoOrder:     append([]string(nil), p.PseudoOrder...),
		FrameOrder:      append([]string(nil), p.FrameOrder...),
		StreamRefund:    p.StreamRefund,
		ConnRefund:      p.ConnRefund,
	}
	if p.HeadersPriority != nil {
		hp := *p.HeadersPriority
		out.HeadersPriority = &hp
	}
	if p.ConnWindowUpdate != nil {
		sent := *p.ConnWindowUpdate
		out.ConnWindowUpdate = &sent
	}
	return out
}

func (h *mirroredHello) h2Preface() *h2Preface {
	if h == nil {
		return nil
	}
	h.h2Mu.RLock()
	defer h.h2Mu.RUnlock()
	return h.preface.clone()
}

func (h *mirroredHello) setH2Preface(p *h2Preface) bool {
	if h == nil || p == nil {
		return false
	}
	h.h2Mu.Lock()
	defer h.h2Mu.Unlock()
	if h.preface == nil {
		h.preface = p.clone()
		return true
	}
	changed := false
	// Startup preface frames (SETTINGS, stream-0 WINDOW_UPDATE, PRIORITY) often arrive in consecutive TLS records on
	// the first HTTP/2 connection; merge them when they originate from that same connection.
	if p.source != 0 && h.preface.source == p.source {
		if h.preface.WindowIncrement == 0 && p.WindowIncrement > 0 {
			h.preface.WindowIncrement = p.WindowIncrement
			changed = true
		}
		if len(p.Priorities) > len(h.preface.Priorities) {
			h.preface.Priorities = append([]h2Priority(nil), p.Priorities...)
			changed = true
		}
		if len(p.FrameOrder) > len(h.preface.FrameOrder) {
			h.preface.FrameOrder = append([]string(nil), p.FrameOrder...)
			changed = true
		}
		if h.preface.ConnWindowUpdate == nil && p.ConnWindowUpdate != nil {
			sent := *p.ConnWindowUpdate
			h.preface.ConnWindowUpdate = &sent
			changed = true
		}
	}
	if len(h.preface.PseudoOrder) == 0 && len(p.PseudoOrder) > 0 {
		h.preface.PseudoOrder = append([]string(nil), p.PseudoOrder...)
		changed = true
	}
	if h.preface.HeadersPriority == nil && p.HeadersPriority != nil {
		hp := *p.HeadersPriority
		h.preface.HeadersPriority = &hp
		changed = true
	}
	// The smallest refunds of any of the client's connections during learning.
	if p.StreamRefund != 0 && (h.preface.StreamRefund == 0 || p.StreamRefund < h.preface.StreamRefund) {
		h.preface.StreamRefund = p.StreamRefund
		changed = true
	}
	if p.ConnRefund != 0 && (h.preface.ConnRefund == 0 || p.ConnRefund < h.preface.ConnRefund) {
		h.preface.ConnRefund = p.ConnRefund
		changed = true
	}
	return changed
}

// helloRecorder keeps the bytes read from a connection until the handshake that reads them is over; after the hello
// it follows the client's TLS record headers (type and length, never content) for observe.
type helloRecorder struct {
	net.Conn
	mu   sync.Mutex
	buf  bytes.Buffer
	done bool
	// truncated: bytes past helloMaxBytes were not kept, so the records after the hello cannot be followed.
	truncated bool
	scan      recordScan
	// onRecord, once set (observe), is told each record's type and length; false ends the scan.
	onRecord func(contentType byte, length int) bool
}

// recordScan follows a TLS record stream by its 5-byte headers.
type recordScan struct {
	header [5]byte
	have   int
	skip   int
	off    bool
}

func (s *recordScan) feed(p []byte, onRecord func(byte, int) bool) {
	for len(p) > 0 && !s.off {
		if s.skip > 0 {
			n := min(s.skip, len(p))
			s.skip -= n
			p = p[n:]
			continue
		}
		n := copy(s.header[s.have:], p)
		s.have += n
		p = p[n:]
		if s.have < 5 {
			return
		}
		s.have = 0
		s.skip = int(binary.BigEndian.Uint16(s.header[3:5]))
		if onRecord != nil && !onRecord(s.header[0], s.skip) {
			s.off = true
		}
	}
}

// observe sets onRecord for the records read from now on.
func (c *helloRecorder) observe(onRecord func(contentType byte, length int) bool) {
	c.mu.Lock()
	c.onRecord = onRecord
	c.mu.Unlock()
}

func (c *helloRecorder) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	switch {
	case !c.done:
		keep := min(n, helloMaxBytes-c.buf.Len())
		c.truncated = c.truncated || keep < n
		c.buf.Write(p[:keep])
	case !c.scan.off:
		c.scan.feed(p[:n], c.onRecord)
	}
	c.mu.Unlock()
	return n, err
}

// hello stops the recording and returns the first record read, the ClientHello's, or a reason.
func (c *helloRecorder) hello() ([]byte, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = true
	b := c.buf.Bytes()
	if len(b) < 9 {
		return nil, "the ClientHello is incomplete"
	}
	record := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+record {
		return nil, "the ClientHello is longer than one TLS record"
	}
	// One handshake message filling the record: a hello split over records is not one any measured client sends.
	if message := int(b[6])<<16 | int(b[7])<<8 | int(b[8]); message != record-4 {
		return nil, "the ClientHello does not fill exactly one TLS record"
	}
	raw := append([]byte(nil), b[:5+record]...)
	// What followed the hello in the same reads starts the record scan.
	c.scan.off = c.truncated
	c.scan.feed(b[5+record:], nil)
	c.buf = bytes.Buffer{}
	return raw, ""
}

// newMirroredHello checks that egress can repeat raw and names its structure; reason says what it cannot repeat.
func newMirroredHello(raw []byte) (*mirroredHello, string) {
	spec, key, family, resumedKey, resumedFamily, h2, offeredResumption, reason := helloSpec(raw)
	if reason != "" {
		return nil, reason
	}
	return &mirroredHello{
		raw:               raw,
		key:               key,
		family:            family,
		resumedKey:        resumedKey,
		resumedFamily:     resumedFamily,
		h2:                h2,
		resumes:           helloResumes(spec),
		offeredResumption: offeredResumption,
		sessionIDLen:      int(raw[43]),
	}, ""
}

// helloResumes is whether a hello offers what TLS 1.3 resumption needs (RFC 8446 4.2.9): TLS 1.3 among its versions
// and psk_dhe_ke among its PSK key exchange modes. A client that would never resume offers no mode (crypto/tls
// without a session cache), and a server sends such a client no ticket.
func helloResumes(spec *utls.ClientHelloSpec) bool {
	tls13, dhe := false, false
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *utls.SupportedVersionsExtension:
			for _, version := range e.Versions {
				tls13 = tls13 || version == utls.VersionTLS13
			}
		case *utls.PSKKeyExchangeModesExtension:
			for _, mode := range e.Modes {
				dhe = dhe || mode == 1 // psk_dhe_ke
			}
		}
	}
	return tls13 && dhe
}

// spec is a fresh handshake description: uTLS writes each connection's own values into it.
func (h *mirroredHello) spec() (*utls.ClientHelloSpec, error) {
	spec, _, _, _, _, _, _, reason := helloSpec(h.raw)
	if reason != "" {
		return nil, fmt.Errorf("mirrored hello: %s", reason)
	}
	return spec, nil
}

// helloSpec reads raw with uTLS's own parser, keeps what is structure and drops or refuses what is not. The type
// list is closed: an extension uTLS knows but this list does not is refused, as one uTLS does not know is unless it
// is empty (an empty extension is one more yes/no in the offer, like OpenSSL's encrypt_then_mac, 22, and
// post_handshake_auth, 49).
func helloSpec(raw []byte) (*utls.ClientHelloSpec, string, string, string, string, bool, bool, string) {
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(raw)
	if err != nil {
		return nil, "", "", "", "", false, false, "unreadable: " + err.Error()
	}
	if n := len(spec.CipherSuites); n == 0 || n > helloMaxCipherSuites {
		return nil, "", "", "", "", false, false, fmt.Sprintf("%d cipher suites (at most %d)", n, helloMaxCipherSuites)
	}
	if len(spec.CompressionMethods) != 1 || spec.CompressionMethods[0] != 0 {
		return nil, "", "", "", "", false, false, "a compression method other than null"
	}
	// RFC 8446 4.1.2: legacy_session_id is 0 to 32 bytes.
	if raw[43] > 32 {
		return nil, "", "", "", "", false, false, fmt.Sprintf("a session id of %d bytes (at most 32)", raw[43])
	}
	if len(spec.Extensions) > helloMaxExtensions {
		return nil, "", "", "", "", false, false, fmt.Sprintf("%d extensions (at most %d)", len(spec.Extensions), helloMaxExtensions)
	}
	head := fmt.Sprintf("v %d %d sid %d c %v\n", spec.TLSVersMin, spec.TLSVersMax, raw[43], spec.CipherSuites)
	resumedHead := fmt.Sprintf("v %d %d c %v\n", spec.TLSVersMin, spec.TLSVersMax, spec.CipherSuites)
	// One line per extension, in the hello's order.
	var lines []string
	h2 := false
	offeredResumption := false
	dropLastPSK := false
	earlyData := -1
	protocols := func(name string, list []string) string {
		for _, protocol := range list {
			if !helloProtocols[protocol] {
				return name + " names a protocol other than h2 and http/1.1"
			}
		}
		return ""
	}
	// An extension appears once (RFC 8446 4.2); GREASE ones are told apart by where they sit.
	kinds := map[string]bool{}
	for i, extension := range spec.Extensions {
		reason := ""
		kind := fmt.Sprintf("%T", extension)
		if generic, ok := extension.(*utls.GenericExtension); ok {
			kind = fmt.Sprintf("%T %d", extension, generic.Id)
		}
		if _, grease := extension.(*utls.UtlsGREASEExtension); !grease {
			if kinds[kind] {
				return nil, "", "", "", "", false, false, "an extension twice"
			}
			kinds[kind] = true
		}
		switch e := extension.(type) {
		case *utls.SNIExtension:
			// The name is the tunnel's host, set at the dial.
			lines = append(lines, "sni\n")
		case *utls.StatusRequestExtension:
			lines = append(lines, "status\n")
		case *utls.StatusRequestV2Extension:
			lines = append(lines, "status2\n")
		case *utls.SCTExtension:
			lines = append(lines, "sct\n")
		case *utls.ExtendedMasterSecretExtension:
			lines = append(lines, "ems\n")
		case *utls.RenegotiationInfoExtension:
			lines = append(lines, "reneg\n")
		case *utls.UtlsPaddingExtension:
			// Zeros, to the hello's own length (FromRaw sets the length).
			lines = append(lines, "padding\n")
		case *utls.GREASEEncryptedClientHelloExtension:
			// uTLS makes the payload anew, of the read length.
			lines = append(lines, "ech\n")
		case *utls.SupportedCurvesExtension:
			if len(e.Curves) > helloMaxGroups {
				reason = "too many supported groups"
			}
			lines = append(lines, fmt.Sprintf("groups %v\n", e.Curves))
		case *utls.SupportedPointsExtension:
			if len(e.SupportedPoints) > helloMaxSmallList {
				reason = "too many point formats"
			}
			lines = append(lines, fmt.Sprintf("points %v\n", e.SupportedPoints))
		case *utls.SignatureAlgorithmsExtension:
			if len(e.SupportedSignatureAlgorithms) > helloMaxSignatures {
				reason = "too many signature algorithms"
			}
			lines = append(lines, fmt.Sprintf("sig %v\n", e.SupportedSignatureAlgorithms))
		case *utls.SignatureAlgorithmsCertExtension:
			if len(e.SupportedSignatureAlgorithms) > helloMaxSignatures {
				reason = "too many certificate signature algorithms"
			}
			lines = append(lines, fmt.Sprintf("sigcert %v\n", e.SupportedSignatureAlgorithms))
		case *utls.FakeDelegatedCredentialsExtension:
			if len(e.SupportedSignatureAlgorithms) > helloMaxSignatures {
				reason = "too many delegated credential algorithms"
			}
			lines = append(lines, fmt.Sprintf("delegated %v\n", e.SupportedSignatureAlgorithms))
		case *utls.ALPNExtension:
			if len(e.AlpnProtocols) > helloMaxSmallList {
				reason = "too many ALPN protocols"
			} else {
				reason = protocols("ALPN", e.AlpnProtocols)
			}
			for _, protocol := range e.AlpnProtocols {
				h2 = h2 || protocol == "h2"
			}
			lines = append(lines, fmt.Sprintf("alpn %q\n", e.AlpnProtocols))
		case *utls.ApplicationSettingsExtension:
			if len(e.SupportedProtocols) > helloMaxSmallList {
				reason = "too many application settings protocols"
			} else {
				reason = protocols("application settings", e.SupportedProtocols)
			}
			lines = append(lines, fmt.Sprintf("alps %q\n", e.SupportedProtocols))
		case *utls.ApplicationSettingsExtensionNew:
			if len(e.SupportedProtocols) > helloMaxSmallList {
				reason = "too many application settings protocols"
			} else {
				reason = protocols("application settings", e.SupportedProtocols)
			}
			lines = append(lines, fmt.Sprintf("alps2 %q\n", e.SupportedProtocols))
		case *utls.UtlsCompressCertExtension:
			if len(e.Algorithms) > helloMaxSmallList {
				reason = "too many certificate compression algorithms"
			}
			for _, algorithm := range e.Algorithms {
				if !helloCertCompression[algorithm] {
					reason = fmt.Sprintf("certificate compression algorithm %d", algorithm)
				}
			}
			lines = append(lines, fmt.Sprintf("certcomp %v\n", e.Algorithms))
		case *utls.FakeRecordSizeLimitExtension:
			// RFC 8449: 64 to 2^14+1.
			if e.Limit < 64 || e.Limit > 16385 {
				reason = fmt.Sprintf("record size limit %d", e.Limit)
			}
			lines = append(lines, fmt.Sprintf("recordsize %d\n", e.Limit))
		case *utls.PSKKeyExchangeModesExtension:
			if len(e.Modes) > helloMaxSmallList {
				reason = "too many PSK key exchange modes"
			}
			lines = append(lines, fmt.Sprintf("pskmodes %v\n", e.Modes))
		case *utls.SupportedVersionsExtension:
			if len(e.Versions) > helloMaxSmallList {
				reason = "too many supported versions"
			}
			lines = append(lines, fmt.Sprintf("versions %v\n", e.Versions))
		case *utls.SessionTicketExtension:
			// On a cold handshake the extension is empty; a client resuming a TLS 1.2 ticket carries its ticket
			// bytes here, which egress strips from the base spec and handles on the tunnel's own session state.
			if len(e.Ticket) != 0 || e.Session != nil {
				offeredResumption = true
			}
			spec.Extensions[i] = &utls.SessionTicketExtension{}
			lines = append(lines, "ticket\n")
		case *utls.KeyShareExtension:
			if len(e.KeyShares) > helloMaxSmallList {
				reason = "too many key shares"
			}
			groups := make([]utls.CurveID, 0, len(e.KeyShares))
			for j := range e.KeyShares {
				group := e.KeyShares[j].Group
				groups = append(groups, group)
				if group == utls.GREASE_PLACEHOLDER {
					// A GREASE share's key is one byte in every client that sends one.
					e.KeyShares[j].Data = []byte{0}
					continue
				}
				if !helloKeyShareGroups[group] {
					reason = fmt.Sprintf("a key share of group %d", group)
				}
				e.KeyShares[j].Data = nil
			}
			lines = append(lines, fmt.Sprintf("keyshare %v\n", groups))
		case *utls.UtlsGREASEExtension:
			// Chrome's second GREASE extension holds one zero byte; nothing measured holds more.
			if len(e.Body) > 1 {
				reason = "a GREASE extension with content"
			}
			e.Body = make([]byte, len(e.Body))
			lines = append(lines, fmt.Sprintf("grease %d\n", len(e.Body)))
		case utls.PreSharedKeyExtension:
			// RFC 8446 4.2.11: pre_shared_key MUST be the last extension in the ClientHello. Egress strips it from
			// the base spec and appends its own UtlsPreSharedKeyExtension when resuming with the vendor.
			if i != len(spec.Extensions)-1 {
				reason = "a pre-shared key that is not the last extension"
				break
			}
			offeredResumption = true
			dropLastPSK = true
		case *utls.GenericExtension:
			if e.Id == helloEarlyData {
				// Egress never sends 0-RTT data: the call is read off the tunnel after its handshake, and uTLS v1.8.2
				// cannot send EndOfEarlyData should the vendor accept early data. The extension is dropped from the
				// spec and from the keys; a hello without a pre-shared key cannot carry it (checked below).
				if len(e.Data) != 0 {
					reason = "early_data with content"
				}
				earlyData = i
				break
			}
			if len(e.Data) != 0 {
				reason = fmt.Sprintf("extension %d with content (egress repeats an extension it does not know only when it is empty)", e.Id)
			}
			lines = append(lines, fmt.Sprintf("empty %d\n", e.Id))
		default:
			reason = fmt.Sprintf("an extension egress does not repeat (%T)", extension)
		}
		if reason != "" {
			return nil, "", "", "", "", false, false, reason
		}
	}
	if earlyData >= 0 && !dropLastPSK {
		// RFC 8446 4.2.10: early data is sent under a pre-shared key; the extension alone is no client's handshake.
		return nil, "", "", "", "", false, false, "early_data without a pre-shared key"
	}
	if dropLastPSK {
		spec.Extensions = spec.Extensions[:len(spec.Extensions)-1]
	}
	if earlyData >= 0 {
		spec.Extensions = append(spec.Extensions[:earlyData:earlyData], spec.Extensions[earlyData+1:]...)
	}
	// key names the exact shape; family the same offer whatever the extensions' order, which a client that shuffles
	// its extensions (Chrome since 110) changes with every connection. resumedKey and resumedFamily omit padding and
	// session_ticket so a TLS 1.3 resumed ClientHello from OpenSSL (which omits session_ticket when offering
	// pre_shared_key) or BoringSSL/OpenSSL (which omits RFC 7685 padding once the ticket pushes the hello past 511
	// bytes) matches the cold shape learned at start.
	sum := func(h string, list []string) string {
		digest := sha256.Sum256([]byte(h + strings.Join(list, "")))
		return hex.EncodeToString(digest[:])
	}
	key := sum(head, lines)
	sorted := append([]string(nil), lines...)
	sort.Strings(sorted)

	resumedLines := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "padding\n" && line != "ticket\n" {
			resumedLines = append(resumedLines, line)
		}
	}
	resumedKey := sum(resumedHead, resumedLines)
	resumedSorted := append([]string(nil), resumedLines...)
	sort.Strings(resumedSorted)
	return spec, key, sum(head, sorted), resumedKey, sum(resumedHead, resumedSorted), h2, offeredResumption, ""
}

// shuffleHelloExtensions puts exts in a new random order, as a client that permutes its extensions per connection
// does (BoringSSL since Chrome 110, uTLS ShuffleChromeTLSExtensions): GREASE, padding and pre_shared_key keep their
// places, every other extension takes one of the other places, all orders equally likely (Fisher-Yates).
//
// The order comes from egress's own crypto/rand, never from the container: a tunnel's hello only says which learned
// family it belongs to, as it did before, so the order the vendor (and the account's proxy) sees carries nothing the
// container chose.
func shuffleHelloExtensions(exts []utls.TLSExtension) error {
	var movable []int
	for i, extension := range exts {
		switch extension.(type) {
		case *utls.UtlsGREASEExtension, *utls.UtlsPaddingExtension, utls.PreSharedKeyExtension:
		default:
			movable = append(movable, i)
		}
	}
	for i := len(movable) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		a, b := movable[i], movable[j.Int64()]
		exts[a], exts[b] = exts[b], exts[a]
	}
	return nil
}
