package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// The channel peers' dial (docs/design/relay-outbound-only.md §3.2, §3.5-§3.7; PR 1.2). A stack VM that takes no
// inbound connection keeps sessions to the entry's peerlink, and egress reaches it by asking peerlink, over its unix
// socket (-peer-link), for a stream on one of them: an HTTP/1.1 CONNECT whose authority names the keyset, as an
// http.Transport's Proxy would send it, with the standard library alone (G2). Once peerlink answers 200 the
// connection is the stream, and dialPeer runs the pinned TLS over it exactly as over a TCP connection. The
// interface is deploy/tee/peerlink/README.md "Interface".
const (
	peerLinkRelayHeader = "X-Gray-Peer-Relay"
	peerLinkModeHeader  = "X-Gray-Peer-Mode"
	peerLinkErrorHeader = "X-Gray-Peer-Error"
	// peerLinkControlHost is the Host of egress's calls to peerlink's control routes; the unix socket is the address.
	peerLinkControlHost = "peerlink"
	// peerLinkMaxRefusal bounds what egress reads of a refusal's body before it closes the connection.
	peerLinkMaxRefusal = 4 << 10
)

// dialPeerLink asks peerlink for a stream to (target.relay, target.digest) and answers the connection and the
// session id peerlink named. ctx carries -peer-link-connect-timeout. peerlink's two refusals are their own codes with
// sent 0 (§3.7): peer_session_missing (no session for the keyset; routing skips the peer, §3.6) and
// peer_session_refused (the VM refused the stream, §3.4's backlog); anything else that keeps a stream from opening
// is peer_connect_failed, as the TCP connect it replaces.
func (s *server) dialPeerLink(ctx context.Context, target peerTarget) (net.Conn, string, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", s.cfg.peerLink)
	if err != nil {
		return nil, "", &peerDialError{code: errPeerConnectFailed, err: err}
	}
	fail := func(code string, err error) (net.Conn, string, error) {
		_ = conn.Close()
		return nil, "", &peerDialError{code: code, err: err}
	}
	// The exchange below is bounded by ctx: its deadline as the socket's, its cancellation (the entry left) as an
	// immediate deadline. stop keeps the hook off the connection once it is returned.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	authority := target.digest + peerLinkHostSuffix + ":443"
	var head strings.Builder
	head.WriteString("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n")
	head.WriteString(peerLinkRelayHeader + ": " + target.relay + "\r\n")
	if target.attest {
		head.WriteString(peerLinkModeHeader + ": attest\r\n")
	}
	head.WriteString("\r\n")
	if _, err := io.WriteString(conn, head.String()); err != nil {
		return fail(errPeerConnectFailed, err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(errPeerConnectFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, peerLinkMaxRefusal))
		code := errPeerConnectFailed
		if resp.StatusCode == http.StatusServiceUnavailable {
			switch refusal := resp.Header.Get(peerLinkErrorHeader); refusal {
			case errPeerSessionMissing, errPeerSessionRefused:
				code = refusal
			}
		}
		return fail(code, fmt.Errorf("peerlink answered the CONNECT with %d", resp.StatusCode))
	}
	// A 200 to a CONNECT has no body: the connection is the stream from here on (net/http's own CONNECT does the
	// same, reading the stream through the reader that read the head). resp.Body is not touched, since closing it
	// would read the stream.
	session := resp.Header.Get(peerSessionHeader)
	if !validRID(session) {
		return fail(errPeerConnectFailed, errors.New("peerlink named no session"))
	}
	if !stop() || ctx.Err() != nil {
		return fail(errPeerConnectFailed, context.Cause(ctx))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(errPeerConnectFailed, err)
	}
	return &peerLinkConn{Conn: conn, reader: reader}, session, nil
}

// peerLinkConn reads through the reader that read peerlink's answer, so a byte it read past the head is not lost.
// bufio hands a read at least its buffer's size straight to the connection once the buffer is empty.
type peerLinkConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peerLinkConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// condemnPeerSession asks peerlink to close a session one of whose streams presented a key other than its keyset's
// pin (design §3.5, O6: a mismatch closes the session it came from; the pin stays). It runs before the refusal is
// answered, within -peer-link-connect-timeout, and is best effort: a session peerlink cannot close is still never
// trusted, since every stream on it is verified against the pin again.
func (s *server) condemnPeerSession(session string) {
	if !validRID(session) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.peerLinkConnectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://"+peerLinkControlHost+"/v1/sessions/"+session, nil)
	if err != nil {
		return
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", s.cfg.peerLink)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, peerLinkMaxRefusal))
	_ = resp.Body.Close()
}
