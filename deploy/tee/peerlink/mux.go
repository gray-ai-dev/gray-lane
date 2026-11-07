package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// The headers of the attach and of the unix socket's routes (README "Interface").
const (
	headerRelay   = "X-Gray-Peer-Relay"
	headerKeyset  = "X-Gray-Peer-Keyset"
	headerSession = "X-Gray-Peer-Session"
	headerState   = "X-Gray-Peer-State"
	headerIssued  = "X-Gray-Peer-Issued"
	headerAttach  = "X-Gray-Peer-Attach"
	headerMode    = "X-Gray-Peer-Mode"
	headerError   = "X-Gray-Peer-Error"
	headerSPKI    = "X-Gray-Peer-Spki"
	headerAddr    = "X-Gray-Peer-Addr"
)

// The closed codes peerlink answers with (§3.5, §3.7, §5).
const (
	codeSessionMissing   = "peer_session_missing"
	codeSessionRefused   = "peer_session_refused"
	codeConnectInvalid   = "peer_connect_invalid"
	codeAttachInvalid    = "peer_attach_invalid"
	codeAttachBusy       = "peer_attach_busy"
	codeAttachConflict   = "peer_attach_conflict"
	codeTunnelBusy       = "peer_tunnel_busy"
	codeSessionUnknown   = "peer_session_unknown"
	codeRouteRefused     = "peer_route_refused"
	codeControlInvalid   = "peer_control_invalid"
	codeEntryUnreachable = "peer_entry_unreachable"
)

// readyByte is what the VM writes on a stream once its local connection to the lane is up. The entry answers a
// CONNECT only after it (README "Interface"): a refused stream is then peer_session_refused with nothing sent
// (§3.7, fault test 15), not a broken TLS handshake.
const readyByte = 0x00

func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(headerError, code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// muxConfig is §3.4's settings. yamux's own keep-alive is off: keepalive below pings on cfg.keepAliveInterval
// and closes after cfg.pingTimeout without an answer (§3.6), which yamux's (one ping, ConnectionWriteTimeout)
// cannot express.
func muxConfig(cfg config) *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = cfg.acceptBacklog
	c.EnableKeepAlive = false
	c.ConnectionWriteTimeout = cfg.writeTimeout
	c.MaxStreamWindowSize = uint32(cfg.maxStreamWindow)
	c.LogOutput = io.Discard
	return c
}

// wsConn is a WebSocket as a net.Conn whose every message is at most max bytes: yamux writes a frame's body in one
// Write, up to the stream window (1 MiB), and websocket.NetConn sends one message per Write.
type wsConn struct {
	net.Conn
	max int
}

func newWSConn(ctx context.Context, c *websocket.Conn, maxMessage int) net.Conn {
	nc := websocket.NetConn(ctx, c, websocket.MessageBinary)
	// NetConn lifts the read limit; a message above max is the peer's error and ends the session.
	c.SetReadLimit(int64(maxMessage))
	return &wsConn{Conn: nc, max: maxMessage}
}

func (c *wsConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > c.max {
			chunk = p[:c.max]
		}
		n, err := c.Conn.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		p = p[len(chunk):]
	}
	return written, nil
}

// keepalive pings the session on every tick and closes it when no ping was answered for timeout (§3.6, fault
// test 3). tick and now are the clock; production passes a ticker and time.Now, the test a fake. Each tick is
// judged at the time it carries, so a tick is never judged later than it was sent. answered, when not nil, is
// called after each answered ping.
func keepalive(session *yamux.Session, tick <-chan time.Time, now func() time.Time, timeout time.Duration, answered func()) {
	var mu sync.Mutex
	alive := now()
	inFlight := false
	for {
		var at time.Time
		select {
		case <-session.CloseChan():
			return
		case at = <-tick:
		}
		mu.Lock()
		dead := at.Sub(alive) >= timeout
		start := !inFlight && !dead
		if start {
			inFlight = true
		}
		mu.Unlock()
		if dead {
			_ = session.Close()
			return
		}
		if start {
			go func() {
				_, err := session.Ping()
				mu.Lock()
				inFlight = false
				if err == nil {
					alive = now()
				}
				mu.Unlock()
				if err == nil && answered != nil {
					answered()
				}
			}()
		}
	}
}

func startKeepalive(cfg config, session *yamux.Session) {
	ticker := time.NewTicker(cfg.keepAliveInterval)
	go func() {
		defer ticker.Stop()
		keepalive(session, ticker.C, time.Now, cfg.pingTimeout, nil)
	}()
}

// pipe copies both ways until either side ends, then closes both: the entry cancels a request by closing its
// stream, and the far side then sees its connection close (§3.7, fault test 9).
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// validRelay is LANE_RELAY_ID_PATTERN (`^[A-Za-z0-9._:-]{1,128}$`) without `.` and `..`, as egress's rule.
func validRelay(relay string) bool {
	if relay == "" || len(relay) > 128 || relay == "." || relay == ".." {
		return false
	}
	for i := 0; i < len(relay); i++ {
		c := relay[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// validKeyset is a keyset digest: 64 lower hex, as egress's /peer/<digest>.
func validKeyset(keyset string) bool { return len(keyset) == 64 && isLowerHex(keyset) }

// validSessionID is a session id: 16 random bytes in 32 lower hex, chosen by the VM's lane and signed into the
// attach (§3.5).
func validSessionID(id string) bool { return len(id) == 32 && isLowerHex(id) }

// validEntryName is an entry's DNS name: lower case, two labels or more, no port, not an IP literal.
func validEntryName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if (label[i] < 'a' || label[i] > 'z') && (label[i] < '0' || label[i] > '9') && label[i] != '-' {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// attachHeader is what the entry's lane forwards with an attach (README "Interface").
type attachHeader struct {
	relay, keyset, session string
	pinned                 bool
}

// parseAttach reads an attach's headers. Each must appear exactly once.
func parseAttach(h http.Header) (attachHeader, bool) {
	one := func(name string) (string, bool) {
		values := h.Values(name)
		if len(values) != 1 {
			return "", false
		}
		return values[0], true
	}
	relay, ok1 := one(headerRelay)
	keyset, ok2 := one(headerKeyset)
	session, ok3 := one(headerSession)
	state, ok4 := one(headerState)
	if !ok1 || !ok2 || !ok3 || !ok4 || !validRelay(relay) || !validKeyset(keyset) || !validSessionID(session) ||
		(state != "pinned" && state != "unverified") {
		return attachHeader{}, false
	}
	return attachHeader{relay: relay, keyset: keyset, session: session, pinned: state == "pinned"}, true
}
