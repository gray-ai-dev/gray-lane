package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The defaults and bounds below are taken from the lane's own limits, not from
// guesses. The sidecar sits underneath the gateway: it must never cut a phase
// short before the gateway's own deadline does, or a slow-but-legal attempt
// would look like a transport failure created by the TEE.
//
// workers/packages/config/src/index.ts:
//   - BODY_PARSE_MAX_BYTES: default 4,194,304 (4 MiB), min 1 MiB, max 16 MiB.
//     The lane's body cap (DESIGN-lane-gateway-v2.md section B3) is this row.
//   - REQUEST_BODY_MS: default 600,000 (10 min).
//   - UPSTREAM_HEADER_MS: default 600,000 (10 min), max 3,600,000 (1 h).
//   - UPSTREAM_SILENCE_MS: default 600,000 (10 min), max 3,600,000 (1 h).
//   - STREAM_TOTAL_SECONDS: default and max 3,600 (1 h).
//
// There is no gateway connect timeout to mirror: the config row for
// UPSTREAM_ATTEMPT_SECONDS records that GRAY_UPSTREAM_CONNECT_SECONDS has no
// Worker counterpart. The dial and TLS phases therefore use the gateway's
// header wait (10 min) as their lower bound, so the sidecar still cannot be the
// component that ends an attempt the gateway would have kept waiting.
const (
	defaultSocketPath = "/run/egress.sock"

	defaultMaxBodyBytes = int64(4 << 20)  // 4,194,304: BODY_PARSE_MAX_BYTES default
	minMaxBodyBytes     = int64(1 << 20)  // 1 MiB: BODY_PARSE_MAX_BYTES min
	maxMaxBodyBytes     = int64(16 << 20) // 16 MiB: BODY_PARSE_MAX_BYTES max

	defaultPhaseTimeout = 10 * time.Minute // UPSTREAM_HEADER_MS default
	minPhaseTimeout     = 10 * time.Minute // never shorter than the gateway's header wait
	maxPhaseTimeout     = time.Hour        // UPSTREAM_HEADER_MS / STREAM_TOTAL_SECONDS max

	// The idle timeout of pooled vendor connections, mirrored ones included. It is not learned from the relay's
	// client: its warm-up tunnels close at once by design and its later calls come after learning, so no idle time
	// of its own is seen. The floor is the gateway's UPSTREAM_SILENCE_MS: a vendor connection is never closed for
	// idleness sooner than a call on it may stay silent, so a pooled connection outlives the longest quiet answer.
	defaultIdleConnTimeout = time.Hour        // STREAM_TOTAL_SECONDS max
	minIdleConnTimeout     = 10 * time.Minute // UPSTREAM_SILENCE_MS default
	maxIdleConnTimeout     = time.Hour        // STREAM_TOTAL_SECONDS max

	// requestReadTimeout bounds reading one request's headers and body from
	// workerd over the local socket. It is the gateway's REQUEST_BODY_MS, so the
	// sidecar does not give up on a body the gateway is still waiting for.
	requestReadTimeout = 10 * time.Minute
)

// The relay stack's bounds (S15, S17). They matter only with -relay-listen.
//
//   - A registration's TTL is the request's deadline (S15), and the longest deadline the gateway
//     gives a request is a stream's: STREAM_TOTAL_SECONDS, default and maximum 3,600 s, from the
//     end of the body (a buffered request's NON_STREAM_TOTAL_MS is shorter, 1,740 s). It is fixed
//     for the reason requestReadTimeout is: a shorter value would end a request the gateway still
//     serves.
//   - -stack-max-bytes is one budget for every byte egress holds on the stack path (S17,
//     stack_budget.go): registrations, relay calls' headers and bodies, held answers and error
//     bodies, the SSE digesters' buffers and the feeds' queued records. The default was set from
//     registrations alone: the entry holds every body it registers, and its isolate reset after
//     33-36 parsed 4 MB bodies, with raw bytes at about 180 MB (BODY_PARSE_MAX_BYTES and
//     BODY_RAW_MAX_BYTES rows, m0/memory.md, measured 2026-10-17), and 192 MiB (201 MB) is above
//     that. Now that answers share it, a busy lane can be refused (egress_limit) before the entry is
//     full; the value is to be measured in C3 against egress's memory under load. The minimum is one
//     body at -max-body-bytes; the maximum is a quarter of tdx.medium's 4 GiB
//     (docs/confidential-lane-supply-measurements.md §3.3), beside the relay's 1,536 MiB (S5).
//   - The registered count has no measured source: 1,024 is far above the requests one lane holds
//     at once by the bytes bound, and it only keeps a stream of tiny registrations from growing
//     the table without limit.
//   - A non-stream answer is held whole for its digest (S17: JCS needs the whole document), at
//     most ANSWER_HELD_MAX_BYTES: the gateway refuses a longer buffered answer itself (default and
//     maximum 64 MiB, minimum 1 MiB). A longer one passes to the relay unchanged with no body
//     record, so the entry cannot release it.
//   - error_body is at most 64 KiB (S17).
const (
	stackMaxTTL = time.Hour

	defaultStackMaxBytes = int64(192 << 20)
	maxStackMaxBytes     = int64(1 << 30)

	defaultStackMaxRequests = 1024
	maxStackMaxRequests     = 65536

	defaultStackMaxAnswerBytes = int64(64 << 20)
	minStackMaxAnswerBytes     = int64(1 << 20)
	maxStackMaxAnswerBytes     = int64(64 << 20)

	stackErrorBodyMax = 64 << 10
)

// The relay stack's append limits (S18): the most texts and UTF-8 bytes one request may append. The
// defaults are @gray/lane's DEFAULT_MAX_ITEMS (3) and DEFAULT_MAX_TOTAL_BYTES (8192)
// (workers/packages/lane/src/templates.ts, from review.md section 3.5 item 3), the limits the gateway
// applies to the lane's own appends; stack_check_test.go reads that source and fails when they
// differ. The count is at most stackAppendMaxEntries, because a request uses each spec entry at most
// once; the bytes at most -max-body-bytes, because the appended text is part of the forwarded body.
const (
	defaultStackAppendMaxItems = 3
	defaultStackAppendMaxBytes = 8192
)

// The peer mode's bounds (docs/confidential-lane-stack-routing.md §4.4, §4.9, §5 rows 11-13). They matter only
// with -peer.
//
//   - -peer-link-connect-timeout bounds one new peer connection (docs/design/relay-outbound-only.md §3.2):
//     peerlink's CONNECT, the VM's ready byte (§3.4) and the inner TLS handshake, all through the session's path
//     over Cloudflare. PROVISIONAL: nothing has measured that path yet. The default, 2000 ms, is a placeholder
//     about four times today's 500 ms for a path with two more crossings (the ready byte and the PoP detour); X-O1
//     on staging (§14) measures CONNECT + ready byte + inner TLS, and this default follows that measurement. The
//     minimum, 200 ms, is above the 165 ms worst new TLS connection X1 measured CVM to CVM on prod5
//     (deploy/tee/probe/routing-measure/README.md, 2026-10-31); the maximum is proxyConnectCap, the longest any
//     connect phase of this program takes.
//   - -peer-silence-timeout is how long a peer request may go without a byte from the peer, before its head or
//     between two reads of its body (rows 11 and 12, PEER_SILENCE_MS). The default is the design's 45 s: three of
//     the stack VM's 15 s hop comments (§4.5). The minimum is two comments, so one late comment never cuts a live
//     path; the maximum is UPSTREAM_SILENCE_MS's default (600,000 ms), past which the gateway's own silence limit
//     ends the attempt first. Attest mode's longest silent answer, the attestation route, took at most 1,075 ms in
//     the same measurement (X5).
//   - -peer-idle-timeout is how long a pooled peer connection is kept idle. It must stay below the time the
//     stack VM's server keeps an idle keep-alive connection, or a request can be written into a connection the
//     server is closing (§4.7's ambiguous case). That server is workerd's: its HTTP listener
//     (src/workerd/server/server.c++:6797 at v1.20261006.1, the pinned version) passes kj's default
//     HttpServerSettings, whose pipelineTimeout closes a connection 5 s after a response completed (kj
//     compat/http.h:1260 at capnproto 1be2d2a, the commit that workerd release pins). The server's clock starts when
//     its response is written, the client's when it has read the last byte, so the client's must end earlier by
//     more than one crossing of the hop: X1's warm request (a whole round trip) took at most 11 ms in region. The
//     default leaves 2 s; the maximum leaves 1 s.
const (
	minPeerConnectTimeout = 200 * time.Millisecond
	maxPeerConnectTimeout = proxyConnectCap

	// Provisional until X-O1 (see above).
	defaultPeerLinkConnectTimeout = 2000 * time.Millisecond

	defaultPeerSilenceTimeout = 45 * time.Second
	minPeerSilenceTimeout     = 30 * time.Second
	maxPeerSilenceTimeout     = 10 * time.Minute

	// maxUnixSocketPath is the longest path a unix socket address holds on both systems the tests run on:
	// sockaddr_un's sun_path is 108 bytes on Linux and 104 on Darwin, one of them the terminating NUL.
	maxUnixSocketPath = 103

	peerServerIdleTimeout  = 5 * time.Second
	defaultPeerIdleTimeout = 3 * time.Second
	minPeerIdleTimeout     = time.Second
	maxPeerIdleTimeout     = peerServerIdleTimeout - time.Second

	// -login-persist-wait (defaultLoginPersistWait, stack_login.go, 10 s): at least one lane round (5 s), at most two
	// minutes of a sign-in call held open.
	minLoginPersistWait = 5 * time.Second
	maxLoginPersistWait = 2 * time.Minute

	// -login-calls-per-minute: one account's sign-in calls in a minute. RFC 8628 section 3.5's default polling interval
	// (5 s) is 12 calls a minute; a sign-in's other calls (the code request, the pages and the token exchange) come
	// beside them, so the default doubles that rounded up to 30. At least 6 (a 10 s poll), at most 600 (10 a second).
	defaultLoginCallsPerMinute = 30
	minLoginCallsPerMinute     = 6
	maxLoginCallsPerMinute     = 600
)

// config is the complete run-time configuration of the program. Every value is
// set by a flag and validated before the socket is opened; there is no config
// file, no environment variable and no secret in it.
type config struct {
	socketPath            string
	maxBodyBytes          int64
	dialTimeout           time.Duration
	tlsHandshakeTimeout   time.Duration
	responseHeaderTimeout time.Duration
	idleConnTimeout       time.Duration
	// relayListen is S14's relay listener (an IP literal and a port); empty means no relay stack,
	// and then the unix socket has no control API either.
	relayListen         string
	stackMaxRequests    int
	stackMaxBytes       int64
	stackMaxAnswerBytes int64
	// memoryLimit is the Go runtime's soft memory limit (runtime/debug.SetMemoryLimit, what GOMEMLIMIT sets);
	// 0 leaves the runtime's own. C3 sets it from egress's measured memory under load.
	memoryLimit         int64
	stackAppendMaxItems int
	stackAppendMaxBytes int
	// peer turns on the peer mode on the unix socket (peer.go); off, its paths are refused as unknown routes. It is
	// the entry's alone, so validate refuses it beside -relay-listen.
	peer bool
	// peerLinkConnectTimeout bounds one new peer connection (provisional, see the bounds above).
	peerLinkConnectTimeout time.Duration
	peerSilenceTimeout     time.Duration
	peerIdleTimeout        time.Duration
	// peerLink is peerlink's unix socket (docs/design/relay-outbound-only.md §3.2): a pin row naming a relay (a
	// channel peer) is dialed through its CONNECT. Empty: only today's pins by origin; it needs -peer.
	peerLink string
	// signInKeyDir and signInBundle (signin_ca.go, docs/design/relay-sign-in-in-vm.md D1): the egress-only memory volume
	// the sign-in CA's key and certificate live on, and the file on the relay's read-only memory volume egress writes
	// the trust bundle to (the system roots and the sign-in CA). Both or neither, both absolute, with -relay-listen.
	signInKeyDir string
	signInBundle string
	// checkFile is the health check's mode (main.go): exit 0 if the file exists and is not empty, 1 otherwise.
	checkFile string
	// loginPersistWait bounds how long a sign-in route's token answer waits for the lane to write its family to the
	// vault (stack_persist.go awaitPersisted); past it the answer is 503 login_persist_pending.
	loginPersistWait time.Duration
	// loginCallsPerMinute bounds one account's sign-in calls in a minute: past it 429 login_rate_limited with
	// Retry-After (stack_login.go loginRate).
	loginCallsPerMinute int
	// extraRootCAPath and directDialAddress are set only by the e2e-tagged build (roots_e2e.go);
	// production keeps them empty and has no flag that could fill them.
	extraRootCAPath   string
	directDialAddress string
}

func defaultConfig() config {
	return config{
		socketPath:             defaultSocketPath,
		maxBodyBytes:           defaultMaxBodyBytes,
		dialTimeout:            defaultPhaseTimeout,
		tlsHandshakeTimeout:    defaultPhaseTimeout,
		responseHeaderTimeout:  defaultPhaseTimeout,
		idleConnTimeout:        defaultIdleConnTimeout,
		stackMaxRequests:       defaultStackMaxRequests,
		stackMaxBytes:          defaultStackMaxBytes,
		stackMaxAnswerBytes:    defaultStackMaxAnswerBytes,
		stackAppendMaxItems:    defaultStackAppendMaxItems,
		stackAppendMaxBytes:    defaultStackAppendMaxBytes,
		peerLinkConnectTimeout: defaultPeerLinkConnectTimeout,
		peerSilenceTimeout:     defaultPeerSilenceTimeout,
		peerIdleTimeout:        defaultPeerIdleTimeout,
		loginPersistWait:       defaultLoginPersistWait,
		loginCallsPerMinute:    defaultLoginCallsPerMinute,
	}
}

// stackAppendLimits are the S18 check's append limits from the flags.
func (c config) stackAppendLimits() stackAppendLimits {
	return stackAppendLimits{maxItems: c.stackAppendMaxItems, maxBytes: c.stackAppendMaxBytes}
}

// defaultStackAppendLimits are @gray/lane's limits.
func defaultStackAppendLimits() stackAppendLimits {
	return defaultConfig().stackAppendLimits()
}

// parseConfig parses and validates the command line. The flag package is used
// with ContinueOnError so tests can drive the same parser the program uses;
// every problem is reported without opening the socket.
func parseConfig(args []string, out io.Writer) (config, error) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("gray-egress", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&cfg.socketPath, "socket", cfg.socketPath, "unix socket to listen on (must be absolute; mode 0660)")
	fs.Int64Var(&cfg.maxBodyBytes, "max-body-bytes", cfg.maxBodyBytes, "largest request body accepted, in bytes")
	fs.DurationVar(&cfg.dialTimeout, "dial-timeout", cfg.dialTimeout, "timeout for one TCP dial (direct or to the proxy)")
	fs.DurationVar(&cfg.tlsHandshakeTimeout, "tls-handshake-timeout", cfg.tlsHandshakeTimeout, "timeout for one TLS handshake")
	fs.DurationVar(&cfg.responseHeaderTimeout, "response-header-timeout", cfg.responseHeaderTimeout, "timeout waiting for the upstream response headers")
	fs.DurationVar(&cfg.idleConnTimeout, "idle-conn-timeout", cfg.idleConnTimeout, "how long an idle pooled connection is kept")
	fs.StringVar(&cfg.relayListen, "relay-listen", cfg.relayListen, "relay listener, IP:port (empty: no relay stack and no control API)")
	fs.IntVar(&cfg.stackMaxRequests, "stack-max-requests", cfg.stackMaxRequests, "most relay-stack requests registered at once")
	fs.Int64Var(&cfg.stackMaxBytes, "stack-max-bytes", cfg.stackMaxBytes, "most bytes egress holds on the relay-stack path at once (registrations, relay calls, answers, feeds)")
	fs.Int64Var(&cfg.memoryLimit, "memory-limit", cfg.memoryLimit, "Go runtime soft memory limit in bytes, as GOMEMLIMIT (0: the runtime's own)")
	fs.Int64Var(&cfg.stackMaxAnswerBytes, "stack-max-answer-bytes", cfg.stackMaxAnswerBytes, "largest non-stream vendor answer held for its digest, in bytes")
	fs.IntVar(&cfg.stackAppendMaxItems, "stack-append-max-items", cfg.stackAppendMaxItems, "most registered texts one relay-stack request may append")
	fs.IntVar(&cfg.stackAppendMaxBytes, "stack-append-max-bytes", cfg.stackAppendMaxBytes, "most bytes of registered texts one relay-stack request may append")
	fs.StringVar(&cfg.signInKeyDir, "sign-in-key-dir", cfg.signInKeyDir, "egress-only directory (a memory volume) holding this boot's sign-in CA key and certificate")
	fs.StringVar(&cfg.signInBundle, "sign-in-bundle", cfg.signInBundle, "file egress writes the relay's trust bundle to (system roots and the sign-in CA)")
	fs.StringVar(&cfg.checkFile, "check-file", cfg.checkFile, "health check mode: exit 0 if this file exists and is not empty, then stop")
	fs.BoolVar(&cfg.peer, "peer", cfg.peer, "serve the peer mode on the unix socket: pinned TLS to attested lane VMs (an entry only; not with -relay-listen)")
	fs.DurationVar(&cfg.peerLinkConnectTimeout, "peer-link-connect-timeout", cfg.peerLinkConnectTimeout, "timeout for one new channel peer connection: peerlink's CONNECT, the ready byte and TLS together (provisional default)")
	fs.DurationVar(&cfg.peerSilenceTimeout, "peer-silence-timeout", cfg.peerSilenceTimeout, "longest wait for a byte from a peer, before its head or within its body")
	fs.DurationVar(&cfg.peerIdleTimeout, "peer-idle-timeout", cfg.peerIdleTimeout, "how long an idle pooled peer connection is kept (below the peer server's 5s)")
	fs.StringVar(&cfg.peerLink, "peer-link", cfg.peerLink, "peerlink's unix socket: channel peers (pins by relay) are dialed through its CONNECT (needs -peer; empty: pins by origin only)")
	fs.DurationVar(&cfg.loginPersistWait, "login-persist-wait", cfg.loginPersistWait, "how long a sign-in's token answer waits for the lane to persist its token family before 503 login_persist_pending")
	fs.IntVar(&cfg.loginCallsPerMinute, "login-calls-per-minute", cfg.loginCallsPerMinute, "one account's sign-in calls in a minute before 429 login_rate_limited")
	addExtraRootCAFlag(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

// validate rejects every value outside its bounds instead of clamping it. A
// silently clamped timeout would make the attested image's behaviour differ
// from the flags an operator believes they set.
func (c config) validate() error {
	if c.checkFile != "" {
		if !filepath.IsAbs(c.checkFile) {
			return errors.New("check-file must be absolute")
		}
		return nil
	}
	if (c.signInKeyDir == "") != (c.signInBundle == "") {
		return errors.New("sign-in-key-dir and sign-in-bundle go together")
	}
	if c.signInKeyDir != "" && (!filepath.IsAbs(c.signInKeyDir) || !filepath.IsAbs(c.signInBundle) || c.relayListen == "") {
		return errors.New("sign-in-key-dir and sign-in-bundle must be absolute and need -relay-listen")
	}
	if c.socketPath == "" {
		return errors.New("socket path is empty")
	}
	if strings.ContainsRune(c.socketPath, 0) {
		return errors.New("socket path contains a NUL byte")
	}
	if !filepath.IsAbs(c.socketPath) {
		return errors.New("socket path must be absolute")
	}
	if c.maxBodyBytes < minMaxBodyBytes || c.maxBodyBytes > maxMaxBodyBytes {
		return fmt.Errorf("max-body-bytes must be between %d and %d", minMaxBodyBytes, maxMaxBodyBytes)
	}
	if c.dialTimeout < minPhaseTimeout || c.dialTimeout > maxPhaseTimeout {
		return fmt.Errorf("dial-timeout must be between %s and %s", minPhaseTimeout, maxPhaseTimeout)
	}
	if c.tlsHandshakeTimeout < minPhaseTimeout || c.tlsHandshakeTimeout > maxPhaseTimeout {
		return fmt.Errorf("tls-handshake-timeout must be between %s and %s", minPhaseTimeout, maxPhaseTimeout)
	}
	if c.responseHeaderTimeout < minPhaseTimeout || c.responseHeaderTimeout > maxPhaseTimeout {
		return fmt.Errorf("response-header-timeout must be between %s and %s", minPhaseTimeout, maxPhaseTimeout)
	}
	if c.idleConnTimeout < minIdleConnTimeout || c.idleConnTimeout > maxIdleConnTimeout {
		return fmt.Errorf("idle-conn-timeout must be between %s and %s", minIdleConnTimeout, maxIdleConnTimeout)
	}
	if c.relayListen != "" && !validRelayListen(c.relayListen) {
		return errors.New("relay-listen must be a specific IP address and a port 1-65535")
	}
	if c.stackMaxRequests < 1 || c.stackMaxRequests > maxStackMaxRequests {
		return fmt.Errorf("stack-max-requests must be between 1 and %d", maxStackMaxRequests)
	}
	if c.stackMaxBytes < c.maxBodyBytes || c.stackMaxBytes > maxStackMaxBytes {
		return fmt.Errorf("stack-max-bytes must be between max-body-bytes and %d", maxStackMaxBytes)
	}
	// A soft limit under the budget would make the collector run without pause before the budget refused
	// anything, so a limit, when set, leaves room for at least what the budget lets egress hold.
	if c.memoryLimit != 0 && c.memoryLimit < c.stackMaxBytes {
		return errors.New("memory-limit must be 0 or at least stack-max-bytes")
	}
	if c.stackMaxAnswerBytes < minStackMaxAnswerBytes || c.stackMaxAnswerBytes > maxStackMaxAnswerBytes {
		return fmt.Errorf("stack-max-answer-bytes must be between %d and %d", minStackMaxAnswerBytes, maxStackMaxAnswerBytes)
	}
	if c.stackAppendMaxItems < 1 || c.stackAppendMaxItems > stackAppendMaxEntries {
		return fmt.Errorf("stack-append-max-items must be between 1 and %d", stackAppendMaxEntries)
	}
	if c.stackAppendMaxBytes < 1 || int64(c.stackAppendMaxBytes) > c.maxBodyBytes {
		return errors.New("stack-append-max-bytes must be between 1 and max-body-bytes")
	}
	// An entry is a default-layout lane, never a VM with a relay's container (design §0, change 3), so a relay
	// stack's egress has no peer mode at all.
	if c.peer && c.relayListen != "" {
		return errors.New("peer and relay-listen exclude each other: the peer mode is an entry's")
	}
	if c.peerLinkConnectTimeout < minPeerConnectTimeout || c.peerLinkConnectTimeout > maxPeerConnectTimeout {
		return fmt.Errorf("peer-link-connect-timeout must be between %s and %s", minPeerConnectTimeout, maxPeerConnectTimeout)
	}
	if c.peerSilenceTimeout < minPeerSilenceTimeout || c.peerSilenceTimeout > maxPeerSilenceTimeout {
		return fmt.Errorf("peer-silence-timeout must be between %s and %s", minPeerSilenceTimeout, maxPeerSilenceTimeout)
	}
	if c.loginPersistWait < minLoginPersistWait || c.loginPersistWait > maxLoginPersistWait {
		return fmt.Errorf("login-persist-wait must be between %s and %s", minLoginPersistWait, maxLoginPersistWait)
	}
	if c.loginCallsPerMinute < minLoginCallsPerMinute || c.loginCallsPerMinute > maxLoginCallsPerMinute {
		return fmt.Errorf("login-calls-per-minute must be between %d and %d", minLoginCallsPerMinute, maxLoginCallsPerMinute)
	}
	if c.peerIdleTimeout < minPeerIdleTimeout || c.peerIdleTimeout > maxPeerIdleTimeout {
		return fmt.Errorf("peer-idle-timeout must be between %s and %s", minPeerIdleTimeout, maxPeerIdleTimeout)
	}
	if c.peerLink != "" {
		switch {
		case !c.peer:
			return errors.New("peer-link needs -peer: it carries the peer mode's channel peers")
		case !filepath.IsAbs(c.peerLink) || filepath.Clean(c.peerLink) != c.peerLink || strings.ContainsRune(c.peerLink, 0):
			return errors.New("peer-link must be an absolute, clean path")
		case len(c.peerLink) > maxUnixSocketPath:
			return fmt.Errorf("peer-link must be at most %d bytes (a unix socket path)", maxUnixSocketPath)
		}
	}
	// Set only by the e2e-tagged build; empty in production.
	if c.directDialAddress != "" {
		if host, port, err := net.SplitHostPort(c.directDialAddress); err != nil || host == "" || port == "" {
			return errors.New("e2e-direct must be host:port")
		}
	}
	return nil
}

// validRelayListen accepts an IP literal that names one address (no wildcard, no host name, no
// zone) and a numeric port: the relay listener binds egress's own relay_out address and nothing
// wider (design §5.2: no `*`).
func validRelayListen(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535 && strconv.Itoa(number) == port
}
