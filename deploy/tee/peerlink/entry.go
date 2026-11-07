package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// The entry role (§3.1-§3.7): sessions attached by stack VMs through the lane, streams opened on them for egress's
// CONNECT and the lane's tunnels. It holds no pin: egress verifies the inner TLS (O2) and tells peerlink which
// session to condemn (§3.5, O6).

const connectSuffix = ".peer.gray.invalid:443"

type entrySession struct {
	id, relay, keyset string
	opened            time.Time
	pinned            bool // guarded by entry.mu
	mux               *yamux.Session
	streams           atomic.Int64
}

type entry struct {
	cfg config
	now func() time.Time

	mu       sync.Mutex
	sessions map[string]*entrySession // by id
	tunnels  map[string]int           // open tunnels by relay
	next     uint64                   // round robin
}

func newEntry(cfg config) *entry {
	return &entry{cfg: cfg, now: time.Now, sessions: map[string]*entrySession{}, tunnels: map[string]int{}}
}

func (e *entry) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attach", e.serveAttach)
	mux.HandleFunc("GET /v1/tunnel", e.serveTunnel)
	mux.HandleFunc("GET /v1/sessions", e.serveSessions)
	mux.HandleFunc("POST /v1/sessions/{id}/promote", e.servePromote)
	mux.HandleFunc("DELETE /v1/sessions/{id}", e.serveDelete)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			e.serveConnect(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// reserve enters a session into the table under the caps of §3.5, before the WebSocket is accepted, so two
// attaches never both pass a cap.
func (e *entry) reserve(a attachHeader) (*entrySession, int, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if old := e.sessions[a.session]; old != nil {
		if old.relay != a.relay || old.keyset != a.keyset {
			return nil, http.StatusConflict, codeAttachConflict
		}
		// The VM redials a slot only after its session ended on its side; the old one here is a leftover.
		e.dropLocked(old)
	}
	perKeyset, unverified := 0, 0
	for _, s := range e.sessions {
		if s.relay == a.relay && s.keyset == a.keyset {
			perKeyset++
		}
		if s.relay == a.relay && !s.pinned {
			unverified++
		}
	}
	if perKeyset >= e.cfg.maxSessionsPerKeyset || (!a.pinned && unverified >= e.cfg.maxUnverifiedPerRelay) ||
		len(e.sessions) >= e.cfg.maxSessions {
		return nil, http.StatusTooManyRequests, codeAttachBusy
	}
	s := &entrySession{id: a.session, relay: a.relay, keyset: a.keyset, opened: e.now(), pinned: a.pinned}
	e.sessions[s.id] = s
	return s, 0, ""
}

func (e *entry) dropLocked(s *entrySession) {
	if e.sessions[s.id] == s {
		delete(e.sessions, s.id)
	}
	if s.mux != nil {
		go func() { _ = s.mux.Close() }()
	}
}

func (e *entry) drop(s *entrySession) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dropLocked(s)
}

// serveAttach is the lane's hand-over of a VM's attach (§3.5). The lane has made its checks and says pinned or
// unverified; peerlink holds the caps and runs the session until it ends.
func (e *entry) serveAttach(w http.ResponseWriter, r *http.Request) {
	a, ok := parseAttach(r.Header)
	if !ok {
		refuse(w, http.StatusBadRequest, codeAttachInvalid)
		return
	}
	s, status, code := e.reserve(a)
	if s == nil {
		refuse(w, status, code)
		return
	}
	// The lane's fetch carries no browser Origin; the lane is the only client of this socket.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		e.drop(s)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, err := yamux.Client(newWSConn(ctx, ws, e.cfg.maxMessage), muxConfig(e.cfg))
	if err != nil {
		e.drop(s)
		_ = ws.CloseNow()
		return
	}
	// pinned is read under the lock: the lane may promote the session (servePromote) at any time from reserve on.
	e.mu.Lock()
	live := e.sessions[s.id] == s
	s.mux = session
	pinned := s.pinned
	e.mu.Unlock()
	if !live {
		_ = session.Close()
		return
	}
	startKeepalive(e.cfg, session)
	if !pinned {
		time.AfterFunc(e.cfg.unverifiedTTL, func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			if !s.pinned {
				e.dropLocked(s)
			}
		})
	}
	<-session.CloseChan()
	e.drop(s)
}

// pick is the session a CONNECT uses: the pinned sessions of (relay, keyset) in turn (§3.4); attest mode may also
// take an unverified one, pinned ones first (§3.3).
func (e *entry) pick(relay, keyset string, attest bool) *entrySession {
	e.mu.Lock()
	defer e.mu.Unlock()
	var pinned, unverified []*entrySession
	for _, s := range e.sessions {
		if s.mux == nil || s.relay != relay || s.keyset != keyset || s.mux.IsClosed() {
			continue
		}
		if s.pinned {
			pinned = append(pinned, s)
		} else {
			unverified = append(unverified, s)
		}
	}
	candidates := pinned
	if len(candidates) == 0 && attest {
		candidates = unverified
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })
	e.next++
	return candidates[e.next%uint64(len(candidates))]
}

// pickTunnel is §5's choice: a pinned session of the relay (of keyset when given), else the newest unverified.
func (e *entry) pickTunnel(relay, keyset string) *entrySession {
	e.mu.Lock()
	defer e.mu.Unlock()
	var pinned []*entrySession
	var newest *entrySession
	for _, s := range e.sessions {
		if s.mux == nil || s.relay != relay || (keyset != "" && s.keyset != keyset) || s.mux.IsClosed() {
			continue
		}
		if s.pinned {
			pinned = append(pinned, s)
		} else if newest == nil || s.opened.After(newest.opened) {
			newest = s
		}
	}
	if len(pinned) == 0 {
		return newest
	}
	sort.Slice(pinned, func(i, j int) bool { return pinned[i].id < pinned[j].id })
	e.next++
	return pinned[e.next%uint64(len(pinned))]
}

// openStream opens a stream on s and waits for the VM's ready byte (README "Interface").
func (e *entry) openStream(s *entrySession) (net.Conn, string) {
	stream, err := s.mux.OpenStream()
	if err != nil {
		return nil, codeSessionMissing
	}
	_ = stream.SetReadDeadline(time.Now().Add(e.cfg.streamOpenTimeout))
	var ready [1]byte
	if _, err := stream.Read(ready[:]); err != nil || ready[0] != readyByte {
		_ = stream.Close()
		return nil, codeSessionRefused
	}
	_ = stream.SetReadDeadline(time.Time{})
	return stream, ""
}

// serveConnect is egress's dial (§3.2): CONNECT <keyset>.peer.gray.invalid:443, then the connection is the stream.
func (e *entry) serveConnect(w http.ResponseWriter, r *http.Request) {
	keyset, ok := strings.CutSuffix(r.Host, connectSuffix)
	relays := r.Header.Values(headerRelay)
	modes := r.Header.Values(headerMode)
	attest := len(modes) == 1 && modes[0] == "attest"
	if !ok || r.RequestURI != r.Host || !validKeyset(keyset) || len(relays) != 1 || !validRelay(relays[0]) ||
		len(modes) > 1 || (len(modes) == 1 && !attest) {
		refuse(w, http.StatusBadRequest, codeConnectInvalid)
		return
	}
	s := e.pick(relays[0], keyset, attest)
	if s == nil {
		refuse(w, http.StatusServiceUnavailable, codeSessionMissing)
		return
	}
	stream, code := e.openStream(s)
	if stream == nil {
		refuse(w, http.StatusServiceUnavailable, code)
		return
	}
	s.streams.Add(1)
	defer s.streams.Add(-1)
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		_ = stream.Close()
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n" + headerSession + ": " + s.id + "\r\n\r\n")); err != nil {
		_ = conn.Close()
		_ = stream.Close()
		return
	}
	pipe(&bufferedConn{Conn: conn, r: buffered.Reader}, stream)
}

// serveTunnel is the lane's hand-over of /v1/peer/tunnel/<relay> (§5): a WebSocket piped into a stream.
func (e *entry) serveTunnel(w http.ResponseWriter, r *http.Request) {
	relays, keysets := r.Header.Values(headerRelay), r.Header.Values(headerKeyset)
	if len(relays) != 1 || !validRelay(relays[0]) || len(keysets) > 1 || (len(keysets) == 1 && !validKeyset(keysets[0])) {
		refuse(w, http.StatusBadRequest, codeConnectInvalid)
		return
	}
	relay, keyset := relays[0], ""
	if len(keysets) == 1 {
		keyset = keysets[0]
	}
	e.mu.Lock()
	if e.tunnels[relay] >= e.cfg.maxTunnelsPerRelay {
		e.mu.Unlock()
		refuse(w, http.StatusTooManyRequests, codeTunnelBusy)
		return
	}
	e.tunnels[relay]++
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		if e.tunnels[relay]--; e.tunnels[relay] == 0 {
			delete(e.tunnels, relay)
		}
		e.mu.Unlock()
	}()
	s := e.pickTunnel(relay, keyset)
	if s == nil {
		refuse(w, http.StatusServiceUnavailable, codeSessionMissing)
		return
	}
	stream, code := e.openStream(s)
	if stream == nil {
		refuse(w, http.StatusServiceUnavailable, code)
		return
	}
	s.streams.Add(1)
	defer s.streams.Add(-1)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		_ = stream.Close()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pipe(newWSConn(ctx, ws, e.cfg.maxMessage), stream)
}

type wireSession struct {
	ID       string `json:"id"`
	Relay    string `json:"relay"`
	Keyset   string `json:"keyset"`
	State    string `json:"state"`
	OpenedMS int64  `json:"opened_ms"`
	Streams  int64  `json:"streams"`
}

func (e *entry) serveSessions(w http.ResponseWriter, r *http.Request) {
	relay := r.URL.Query().Get("relay")
	e.mu.Lock()
	list := []wireSession{}
	for _, s := range e.sessions {
		if s.mux == nil || (relay != "" && s.relay != relay) {
			continue
		}
		state := "unverified"
		if s.pinned {
			state = "pinned"
		}
		list = append(list, wireSession{ID: s.id, Relay: s.relay, Keyset: s.keyset, State: state, OpenedMS: s.opened.UnixMilli(), Streams: s.streams.Load()})
	}
	e.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": list})
}

func (e *entry) servePromote(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	s := e.sessions[r.PathValue("id")]
	if s != nil {
		s.pinned = true
	}
	e.mu.Unlock()
	if s == nil {
		refuse(w, http.StatusNotFound, codeSessionUnknown)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveDelete condemns a session (§3.5 "A pin mismatch condemns the session, not the pin"; a refused attestation).
func (e *entry) serveDelete(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	s := e.sessions[r.PathValue("id")]
	if s != nil {
		e.dropLocked(s)
	}
	e.mu.Unlock()
	if s == nil {
		refuse(w, http.StatusNotFound, codeSessionUnknown)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bufferedConn reads what the server's reader already buffered before the connection itself.
type bufferedConn struct {
	net.Conn
	r interface {
		Buffered() int
		Read([]byte) (int, error)
	}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.r != nil && c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}
