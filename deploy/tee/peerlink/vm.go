package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// The VM role (§3.2, §3.3, §3.6): dial every entry the lane pinned, keep cfg.sessionsPerEntry sessions to each,
// and pipe every stream an entry opens to the lane. It never terminates TLS of a stream and holds no key (O4); the
// attach signatures are made by the lane.

var errEntryPinMismatch = errors.New("the entry's TLS key is not the pinned one")

const (
	maxEntries         = 16
	maxAttestBodyBytes = 1 << 20
	// directBench is how long a direct address that failed while <name>:443 answered with the pinned key is skipped:
	// new sessions run through Cloudflare meanwhile, so a wrong address never takes a relay off the air.
	directBench = 5 * time.Minute
)

type attachToken struct {
	Session   string `json:"session"`
	IssuedMS  int64  `json:"issued_ms"`
	Signature string `json:"signature"`
}

type wireEntry struct {
	Entry      string        `json:"entry"`
	SPKISHA256 string        `json:"spki_sha256"`
	NotAfter   int64         `json:"not_after"`
	Attach     []attachToken `json:"attach"`
	// Addr is the address dialed for the entry before <entry>:443 (`stack.entry_addrs`); optional.
	Addr string `json:"addr,omitempty"`
}

type wireEntries struct {
	Relay   string      `json:"relay"`
	Keyset  string      `json:"keyset"`
	Entries []wireEntry `json:"entries"`
}

// vmEntry is one entry being dialed. relay, keyset, name and spki never change; a table that changes one of them
// replaces the entry. tokens and notAfter follow each table.
type vmEntry struct {
	relay, keyset, name string
	spki                [sha256.Size]byte
	cancel              context.CancelFunc

	mu        sync.Mutex
	tokens    []attachToken
	notAfter  time.Time
	addr      string // the table's direct address, or ""
	pinned    bool
	sessions  int
	direct    int // sessions over the direct address
	lastError string
}

type vm struct {
	cfg config
	now func() time.Time
	// dialContext reaches an entry's address; a test replaces it.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// dialLane reaches the lane for one stream; a test replaces it.
	dialLane func() (net.Conn, error)

	mu      sync.Mutex
	entries map[string]*vmEntry
	backlog chan struct{}

	benchMu sync.Mutex
	// benched holds, per entry name, a direct address that failed and until when new dials skip it.
	benched map[string]benchedAddr
}

type benchedAddr struct {
	addr  string
	until time.Time
}

func newVM(cfg config) *vm {
	d := &net.Dialer{}
	lane := &net.Dialer{Timeout: cfg.streamOpenTimeout}
	return &vm{
		cfg: cfg, now: time.Now, dialContext: d.DialContext,
		dialLane: func() (net.Conn, error) { return lane.Dial("tcp", cfg.lane) },
		entries:  map[string]*vmEntry{}, backlog: make(chan struct{}, cfg.acceptBacklog),
		benched: map[string]benchedAddr{},
	}
}

func (v *vm) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/entries", v.servePut)
	mux.HandleFunc("GET /v1/entries", v.serveList)
	mux.HandleFunc("GET /attest/{entry}/v1/aci/attestation", v.serveAttest)
	return mux
}

// directAddr is the address dialed for an entry before its name: the table's (or attest mode's) address, else
// -entry-addrs, else "" (only <name>:443, through Cloudflare, §3.2).
func (v *vm) directAddr(name, given string) string {
	if given != "" {
		return given
	}
	return v.cfg.entryAddrs[name]
}

// isBenched reports whether direct failed for name within directBench.
func (v *vm) isBenched(name, direct string) bool {
	v.benchMu.Lock()
	defer v.benchMu.Unlock()
	b, ok := v.benched[name]
	return ok && b.addr == direct && v.now().Before(b.until)
}

func (v *vm) bench(name, direct string, err error) {
	v.benchMu.Lock()
	v.benched[name] = benchedAddr{addr: direct, until: v.now().Add(directBench)}
	v.benchMu.Unlock()
	log.Printf("gray-peerlink: entry %s: direct address %s failed (%v); new dials use %s:443 for %s", name, direct, err, name, directBench)
}

func (v *vm) servePut(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var table wireEntries
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&table) != nil || !v.validTable(table) {
		refuse(w, http.StatusBadRequest, codeControlInvalid)
		return
	}
	v.apply(table)
	w.WriteHeader(http.StatusNoContent)
}

func (v *vm) validTable(t wireEntries) bool {
	if !validRelay(t.Relay) || !validKeyset(t.Keyset) || len(t.Entries) > maxEntries {
		return false
	}
	ceiling := v.now().Add(time.Hour).Unix() + 1 // not_after at most an hour away (§3.3 step 3)
	seen := map[string]bool{}
	for _, e := range t.Entries {
		if !validEntryName(e.Entry) || seen[e.Entry] || !validKeyset(e.SPKISHA256) || e.NotAfter <= 0 || e.NotAfter > ceiling ||
			len(e.Attach) < v.cfg.sessionsPerEntry || len(e.Attach) > 16 || (e.Addr != "" && !validDialAddr(e.Addr)) {
			return false
		}
		seen[e.Entry] = true
		ids := map[string]bool{}
		for _, a := range e.Attach {
			sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
			if !validSessionID(a.Session) || ids[a.Session] || a.IssuedMS <= 0 || err != nil || len(sig) != 64 {
				return false
			}
			ids[a.Session] = true
		}
	}
	return true
}

// apply installs a table: an entry with the same relay, keyset, name and SPKI keeps its sessions and takes the new
// tokens; any other is replaced, and an entry no longer listed is closed (§3.3, §3.5).
func (v *vm) apply(t wireEntries) {
	v.mu.Lock()
	defer v.mu.Unlock()
	next := map[string]*vmEntry{}
	for _, row := range t.Entries {
		var spki [sha256.Size]byte
		_, _ = hex.Decode(spki[:], []byte(row.SPKISHA256))
		notAfter := time.Unix(row.NotAfter, 0)
		if old := v.entries[row.Entry]; old != nil && old.relay == t.Relay && old.keyset == t.Keyset && old.spki == spki {
			old.mu.Lock()
			// A changed address applies from the next dial; live sessions stay where they are.
			old.tokens, old.notAfter, old.addr = row.Attach, notAfter, row.Addr
			if !old.pinned {
				// The pin was dropped on a mismatch and the lane pinned the same key again: dial afresh.
				old.mu.Unlock()
				old.cancel()
			} else {
				old.mu.Unlock()
				next[row.Entry] = old
				delete(v.entries, row.Entry)
				continue
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		e := &vmEntry{relay: t.Relay, keyset: t.Keyset, name: row.Entry, spki: spki, cancel: cancel, tokens: row.Attach, notAfter: notAfter, addr: row.Addr, pinned: true}
		next[row.Entry] = e
		for slot := 0; slot < v.cfg.sessionsPerEntry; slot++ {
			go v.keep(ctx, e, slot)
		}
	}
	for _, gone := range v.entries {
		gone.cancel()
	}
	v.entries = next
}

// keep holds one session slot of an entry (§3.6): slot i starts i × stagger late; a closed session is redialed
// after up to jitter, then with backoff from backoffMin doubling to backoffMax, reset by a session that lived
// backoffReset. A pin mismatch drops the pin and stops the slot until the lane pins the entry again.
func (v *vm) keep(ctx context.Context, e *vmEntry, slot int) {
	if !sleepCtx(ctx, time.Duration(slot)*v.cfg.stagger) {
		return
	}
	var backoff time.Duration
	for {
		e.mu.Lock()
		live := e.pinned && v.now().Before(e.notAfter) && slot < len(e.tokens)
		var token attachToken
		if live {
			token = e.tokens[slot]
		}
		e.mu.Unlock()
		if !live {
			return
		}
		start := v.now()
		err := v.session(ctx, e, token)
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		if err != nil {
			e.lastError = err.Error()
		}
		if errors.Is(err, errEntryPinMismatch) {
			// The entry rebooted (§3.3 step 4): the lane sees pinned false, attests it again and pushes a table.
			e.pinned = false
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		if v.now().Sub(start) >= v.cfg.backoffReset {
			backoff = 0
		}
		var jitter time.Duration
		if v.cfg.jitter > 0 {
			jitter = rand.N(v.cfg.jitter)
		}
		if !sleepCtx(ctx, jitter+backoff) {
			return
		}
		backoff = min(max(backoff*2, v.cfg.backoffMin), v.cfg.backoffMax)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// entryTLS is the outer TLS to an entry: no WebPKI decision (O3). The leaf's SPKI must be the attested pin, and the
// certificate must name the entry, whatever address was dialed. With pin nil (attest mode) nothing is verified and
// observed receives the leaf's SPKI.
func entryTLS(name string, pin *[sha256.Size]byte, observed *[sha256.Size]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         name,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true, // replaced by VerifyConnection: the attested pin (§3.3 step 4)
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("the entry sent no certificate")
			}
			leaf := state.PeerCertificates[0]
			spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if observed != nil {
				*observed = spki
			}
			if pin == nil {
				return nil
			}
			if subtle.ConstantTimeCompare(spki[:], pin[:]) != 1 {
				return errEntryPinMismatch
			}
			return leaf.VerifyHostname(name)
		},
	}
}

// dialEntry dials one TLS connection to an entry. With a direct address that is not benched it tries that first,
// within half the time left, and when that fails dials <name>:443 with the rest. If <name>:443 answers, the direct
// address is benched for directBench. If the direct address presents another key than the pin and <name>:443 does not
// present the pinned one: errEntryPinMismatch, nothing benched. SNI, the name check and the pin are the same on both paths. dialed receives
// the address that answered.
func (v *vm) dialEntry(ctx context.Context, network, name, direct string, pin, observed *[sha256.Size]byte, dialed *string) (net.Conn, error) {
	one := func(ctx context.Context, addr string) (net.Conn, error) {
		raw, err := v.dialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, entryTLS(name, pin, observed))
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		if dialed != nil {
			*dialed = addr
		}
		return conn, nil
	}
	fallback := net.JoinHostPort(name, "443")
	if direct == "" || direct == fallback || v.isBenched(name, direct) {
		return one(ctx, fallback)
	}
	directCtx, cancel := ctx, context.CancelFunc(func() {})
	if deadline, ok := ctx.Deadline(); ok {
		directCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/2)
	}
	conn, directErr := one(directCtx, direct)
	cancel()
	if directErr == nil || ctx.Err() != nil {
		return conn, directErr
	}
	conn, err := one(ctx, fallback)
	if err != nil {
		// Another key at the direct address and no pinned key at <name>:443 either: the entry rebooted, as far as
		// this dial can tell. The lane attests it again (§3.3 step 4).
		if errors.Is(directErr, errEntryPinMismatch) {
			return nil, errEntryPinMismatch
		}
		return nil, fmt.Errorf("direct %s: %v; %s: %w", direct, directErr, fallback, err)
	}
	v.bench(name, direct, directErr)
	return conn, nil
}

// entryClient is an HTTP/1.1 client whose every connection goes through dialEntry.
func (v *vm) entryClient(name, direct string, pin *[sha256.Size]byte, observed *[sha256.Size]byte, dialed *string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return v.dialEntry(ctx, network, name, direct, pin, observed, dialed)
			},
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// session dials one session (wss://<entry>/v1/peer/attach, §3.5), serves it until it ends, and returns why.
func (v *vm) session(ctx context.Context, e *vmEntry, token attachToken) error {
	dialCtx, cancel := context.WithTimeout(ctx, v.cfg.dialTimeout)
	defer cancel()
	header := http.Header{}
	header.Set(headerRelay, e.relay)
	header.Set(headerKeyset, e.keyset)
	header.Set(headerSession, token.Session)
	header.Set(headerIssued, strconv.FormatInt(token.IssuedMS, 10))
	header.Set(headerAttach, token.Signature)
	spki := e.spki
	e.mu.Lock()
	direct := v.directAddr(e.name, e.addr)
	e.mu.Unlock()
	var dialed string
	ws, _, err := websocket.Dial(dialCtx, "wss://"+e.name+"/v1/peer/attach", &websocket.DialOptions{
		HTTPClient: v.entryClient(e.name, direct, &spki, nil, &dialed),
		HTTPHeader: header,
	})
	if err != nil {
		return err
	}
	overDirect := direct != "" && dialed == direct
	sessionCtx, stop := context.WithCancel(ctx)
	defer stop()
	session, err := yamux.Server(newWSConn(sessionCtx, ws, v.cfg.maxMessage), muxConfig(v.cfg))
	if err != nil {
		_ = ws.CloseNow()
		return err
	}
	defer session.Close()
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-session.CloseChan():
		}
	}()
	startKeepalive(v.cfg, session)
	e.mu.Lock()
	e.sessions++
	if overDirect {
		e.direct++
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.sessions--
		if overDirect {
			e.direct--
		}
		e.mu.Unlock()
	}()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return err
		}
		go v.serveStream(stream)
	}
}

// serveStream pipes one stream to the lane (§3.1 layer 3). Above cfg.acceptBacklog streams still connecting, the
// stream is refused (§3.4, fault test 15): it closes without the ready byte.
func (v *vm) serveStream(stream *yamux.Stream) {
	select {
	case v.backlog <- struct{}{}:
	default:
		_ = stream.Close()
		return
	}
	lane, err := v.dialLane()
	<-v.backlog
	if err != nil {
		_ = stream.Close()
		return
	}
	if _, err := stream.Write([]byte{readyByte}); err != nil {
		_ = lane.Close()
		_ = stream.Close()
		return
	}
	pipe(stream, lane)
}

type wireEntryState struct {
	Entry    string `json:"entry"`
	Pinned   bool   `json:"pinned"`
	Sessions int    `json:"sessions"`
	// Addr is the entry's direct address, if any; DirectSessions of Sessions run over it, the rest through
	// <entry>:443. Benched: the direct address failed lately and new dials skip it.
	Addr           string `json:"addr,omitempty"`
	DirectSessions int    `json:"direct_sessions"`
	Benched        bool   `json:"benched,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

func (v *vm) serveList(w http.ResponseWriter, _ *http.Request) {
	v.mu.Lock()
	list := []wireEntryState{}
	for _, e := range v.entries {
		e.mu.Lock()
		direct := v.directAddr(e.name, e.addr)
		row := wireEntryState{Entry: e.name, Pinned: e.pinned, Sessions: e.sessions, Addr: direct, DirectSessions: e.direct, LastError: e.lastError}
		e.mu.Unlock()
		row.Benched = direct != "" && v.isBenched(e.name, direct)
		list = append(list, row)
	}
	v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": list})
}

// serveAttest is attest mode for an entry (§3.3 step 1): the report fetched without TLS verification, with the
// leaf's SPKI the VM saw in x-gray-peer-spki. Only the nonce reaches the entry. `addr`, optional, is the direct
// address the table carries for the entry, dialed as dialEntry dials it; x-gray-peer-addr names the address used.
func (v *vm) serveAttest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("entry")
	query, err := url.ParseQuery(r.URL.RawQuery)
	nonce, given := query.Get("nonce"), query.Get("addr")
	known := 1
	if query.Has("addr") {
		known++
	}
	if err != nil || !validEntryName(name) || len(query) != known || len(query["nonce"]) != 1 || len(query["addr"]) > 1 ||
		len(nonce) != 64 || !isLowerHex(nonce) || (query.Has("addr") && !validDialAddr(given)) {
		refuse(w, http.StatusBadRequest, codeRouteRefused)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), v.cfg.dialTimeout)
	defer cancel()
	var observed [sha256.Size]byte
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+"/v1/aci/attestation?nonce="+nonce, nil)
	if err != nil {
		refuse(w, http.StatusBadRequest, codeRouteRefused)
		return
	}
	var dialed string
	resp, err := v.entryClient(name, v.directAddr(name, given), nil, &observed, &dialed).Do(req)
	if err != nil {
		refuse(w, http.StatusBadGateway, codeEntryUnreachable)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestBodyBytes+1))
	if err != nil || len(body) > maxAttestBodyBytes {
		refuse(w, http.StatusBadGateway, codeEntryUnreachable)
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set(headerSPKI, hex.EncodeToString(observed[:]))
	w.Header().Set(headerAddr, dialed)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
