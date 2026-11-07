package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config is every setting, from flags, else from PEERLINK_<FLAG> in the environment, else the default. The
// defaults are docs/design/relay-outbound-only.md §3.4, §3.5 and §3.6's values.
type config struct {
	role   string
	socket string

	// The session's multiplexer (§3.4).
	keepAliveInterval time.Duration
	pingTimeout       time.Duration
	writeTimeout      time.Duration
	maxStreamWindow   uint
	acceptBacklog     int
	maxMessage        int
	streamOpenTimeout time.Duration

	// Entry role (§3.5, §5).
	maxSessionsPerKeyset  int
	maxUnverifiedPerRelay int
	maxSessions           int
	unverifiedTTL         time.Duration
	maxTunnelsPerRelay    int

	// VM role (§3.6).
	lane             string
	sessionsPerEntry int
	stagger          time.Duration
	jitter           time.Duration
	backoffMin       time.Duration
	backoffMax       time.Duration
	backoffReset     time.Duration
	dialTimeout      time.Duration
	// entryAddrs maps an entry's TLS server name to the address dialed for it. An entry absent here is dialed by
	// its name on 443 through Cloudflare (§3.2). An IP:port lets a VM reach the entry's direct port inside Phala's
	// network instead; the server name (SNI and the certificate name check) stays the entry's name, and the
	// attested SPKI pin stays the trust anchor (§3.3).
	entryAddrs map[string]string
}

func defaultConfig() config {
	return config{
		keepAliveInterval:     10 * time.Second, // below the 20 s idle close through Spectrum (G8)
		pingTimeout:           30 * time.Second, // §3.6
		writeTimeout:          10 * time.Second,
		maxStreamWindow:       1 << 20, // one SSE stream is never held to yamux's 256 KiB default
		acceptBacklog:         512,
		maxMessage:            64 << 10, // below workerd's WebSocket message limit (X-O3)
		streamOpenTimeout:     10 * time.Second,
		maxSessionsPerKeyset:  4,
		maxUnverifiedPerRelay: 2,
		maxSessions:           4*256 + 64,
		unverifiedTTL:         60 * time.Second,
		maxTunnelsPerRelay:    16,
		lane:                  "10.231.12.2:443",
		sessionsPerEntry:      2, // R2
		stagger:               5 * time.Second,
		jitter:                time.Second,
		backoffMin:            time.Second,
		backoffMax:            30 * time.Second,
		backoffReset:          60 * time.Second,
		dialTimeout:           10 * time.Second,
		entryAddrs:            map[string]string{},
	}
}

// parseConfig reads args, then fills every flag not given from the environment.
func parseConfig(args []string, getenv func(string) string) (config, error) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("gray-peerlink", flag.ContinueOnError)
	fs.StringVar(&cfg.role, "role", "", "entry or vm")
	fs.StringVar(&cfg.socket, "socket", "", "the unix socket: CONNECT, attach and tunnel (entry); the entry table and attest mode (vm)")
	fs.DurationVar(&cfg.keepAliveInterval, "keepalive-interval", cfg.keepAliveInterval, "ping interval on each session")
	fs.DurationVar(&cfg.pingTimeout, "ping-timeout", cfg.pingTimeout, "a session with no ping answered for this long is closed")
	fs.DurationVar(&cfg.writeTimeout, "write-timeout", cfg.writeTimeout, "yamux ConnectionWriteTimeout")
	fs.UintVar(&cfg.maxStreamWindow, "max-stream-window", cfg.maxStreamWindow, "yamux MaxStreamWindowSize in bytes")
	fs.IntVar(&cfg.acceptBacklog, "accept-backlog", cfg.acceptBacklog, "streams a session may have opening at once; above it the VM refuses")
	fs.IntVar(&cfg.maxMessage, "max-message", cfg.maxMessage, "largest WebSocket message, both ways")
	fs.DurationVar(&cfg.streamOpenTimeout, "stream-open-timeout", cfg.streamOpenTimeout, "how long the entry waits for the VM to accept a stream")
	fs.IntVar(&cfg.maxSessionsPerKeyset, "max-sessions-per-keyset", cfg.maxSessionsPerKeyset, "entry: sessions per (relay, keyset)")
	fs.IntVar(&cfg.maxUnverifiedPerRelay, "max-unverified-per-relay", cfg.maxUnverifiedPerRelay, "entry: unverified sessions per relay")
	fs.IntVar(&cfg.maxSessions, "max-sessions", cfg.maxSessions, "entry: sessions in all")
	fs.DurationVar(&cfg.unverifiedTTL, "unverified-ttl", cfg.unverifiedTTL, "entry: an unverified session not promoted in this time is closed")
	fs.IntVar(&cfg.maxTunnelsPerRelay, "max-tunnels-per-relay", cfg.maxTunnelsPerRelay, "entry: open tunnels per relay")
	fs.StringVar(&cfg.lane, "lane", cfg.lane, "vm: the lane's address every stream is piped to")
	fs.IntVar(&cfg.sessionsPerEntry, "sessions-per-entry", cfg.sessionsPerEntry, "vm: sessions kept to each entry")
	fs.DurationVar(&cfg.stagger, "stagger", cfg.stagger, "vm: delay between an entry's session dials")
	fs.DurationVar(&cfg.jitter, "jitter", cfg.jitter, "vm: random delay added before a redial")
	fs.DurationVar(&cfg.backoffMin, "backoff-min", cfg.backoffMin, "vm: first backoff after a failed dial")
	fs.DurationVar(&cfg.backoffMax, "backoff-max", cfg.backoffMax, "vm: largest backoff")
	fs.DurationVar(&cfg.backoffReset, "backoff-reset", cfg.backoffReset, "vm: a session that lived this long resets the backoff")
	fs.DurationVar(&cfg.dialTimeout, "dial-timeout", cfg.dialTimeout, "vm: TCP, TLS and the WebSocket upgrade of one session dial")
	entryAddrs := fs.String("entry-addrs", "", "vm: comma-separated <entry name>=<host or IP>:<port>; an entry not listed is dialed as <name>:443")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		if given[f.Name] || envErr != nil {
			return
		}
		name := "PEERLINK_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if value := getenv(name); value != "" {
			if err := f.Value.Set(value); err != nil {
				envErr = fmt.Errorf("%s: %w", name, err)
			}
		}
	})
	if envErr != nil {
		return cfg, envErr
	}
	addrs, err := parseEntryAddrs(*entryAddrs)
	if err != nil {
		return cfg, err
	}
	cfg.entryAddrs = addrs
	return cfg, cfg.validate()
}

// parseEntryAddrs reads -entry-addrs: `lane.usefallback.com=203.0.113.7:8443,lane-staging.usefallback.com=...`.
func parseEntryAddrs(value string) (map[string]string, error) {
	addrs := map[string]string{}
	if strings.TrimSpace(value) == "" {
		return addrs, nil
	}
	for _, item := range strings.Split(value, ",") {
		name, addr, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || !validEntryName(name) {
			return nil, fmt.Errorf("entry-addrs: %q is not <entry name>=<host>:<port>", item)
		}
		if !validDialAddr(addr) {
			return nil, fmt.Errorf("entry-addrs: %q is not a host or IP with a port", addr)
		}
		if _, dup := addrs[name]; dup {
			return nil, fmt.Errorf("entry-addrs: %q twice", name)
		}
		addrs[name] = addr
	}
	return addrs, nil
}

// validDialAddr reports whether addr is <DNS name or IP>:<port> (-entry-addrs, a table row's addr, attest's addr).
func validDialAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	return err == nil && host != "" && validPort(port) && (net.ParseIP(host) != nil || validEntryName(host))
}

func validPort(port string) bool {
	if port == "" || len(port) > 5 || port[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
		n = n*10 + int(port[i]-'0')
	}
	return n >= 1 && n <= 65535
}

func (c config) validate() error {
	if c.role != "entry" && c.role != "vm" {
		return errors.New("role must be entry or vm")
	}
	// macOS limits a unix socket path to 103 bytes, Linux to 107; take the smaller.
	if !filepath.IsAbs(c.socket) || filepath.Clean(c.socket) != c.socket || len(c.socket) > 103 {
		return errors.New("socket must be a clean absolute path of at most 103 bytes")
	}
	type bound struct {
		name     string
		value    time.Duration
		min, max time.Duration
	}
	for _, b := range []bound{
		{"keepalive-interval", c.keepAliveInterval, time.Second, 19 * time.Second}, // below Spectrum's 20 s (G8)
		{"ping-timeout", c.pingTimeout, c.keepAliveInterval, 5 * time.Minute},
		{"write-timeout", c.writeTimeout, time.Second, time.Minute},
		{"stream-open-timeout", c.streamOpenTimeout, 100 * time.Millisecond, time.Minute},
		{"unverified-ttl", c.unverifiedTTL, time.Second, 10 * time.Minute},
		{"stagger", c.stagger, 0, time.Minute},
		{"jitter", c.jitter, 0, time.Minute},
		{"backoff-min", c.backoffMin, 10 * time.Millisecond, time.Minute},
		{"backoff-max", c.backoffMax, c.backoffMin, 10 * time.Minute},
		{"backoff-reset", c.backoffReset, time.Second, time.Hour},
		{"dial-timeout", c.dialTimeout, 100 * time.Millisecond, 2 * time.Minute},
	} {
		if b.value < b.min || b.value > b.max {
			return fmt.Errorf("%s must be between %s and %s", b.name, b.min, b.max)
		}
	}
	type count struct {
		name     string
		value    int
		min, max int
	}
	for _, n := range []count{
		{"max-stream-window", int(min(c.maxStreamWindow, 1<<31)), 256 << 10, 16 << 20}, // yamux's initial window is 256 KiB
		{"accept-backlog", c.acceptBacklog, 1, 4096},
		{"max-message", c.maxMessage, 1 << 10, 1 << 20},
		{"max-sessions-per-keyset", c.maxSessionsPerKeyset, 1, 64},
		{"max-unverified-per-relay", c.maxUnverifiedPerRelay, 1, 64},
		{"max-sessions", c.maxSessions, 1, 1 << 16},
		{"max-tunnels-per-relay", c.maxTunnelsPerRelay, 1, 1024},
		{"sessions-per-entry", c.sessionsPerEntry, 1, 8},
	} {
		if n.value < n.min || n.value > n.max {
			return fmt.Errorf("%s must be between %d and %d", n.name, n.min, n.max)
		}
	}
	if host, port, err := net.SplitHostPort(c.lane); err != nil || host == "" || !validPort(port) {
		return errors.New("lane must be <host>:<port>")
	}
	if c.role == "entry" && len(c.entryAddrs) != 0 {
		return errors.New("entry-addrs is a vm setting")
	}
	return nil
}

func loadConfig() (config, error) { return parseConfig(os.Args[1:], os.Getenv) }
