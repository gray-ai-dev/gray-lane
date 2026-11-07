// gray-isolation-check is the relay-stack layout's one-shot isolation check
// (docs/confidential-lane-supply-implementation.md §9 B; design §5.2, §9.2 item 29).
//
// deploy/tee/compose.stack.yaml runs it once per boot as the `isolation-check` service: from the relay's
// network position (relay_in and relay_out only, no volume, no capability, read-only root), after lane and
// egress started; `relay` starts only when it exits 0 (`service_completed_successfully`). It exits non-zero
// unless every item holds:
//   - no /var/run/dstack.sock, tappd.sock or docker.sock (under /var/run or /run);
//   - no default route, IPv4 or IPv6, in any routing table;
//   - the allowed endpoints (-allow: 10.231.10.2:8081 and 10.231.11.2:8080) accept a connection within
//     -wait (lane and egress only have to have started, so their listeners may come later);
//   - public names do not resolve, and 1.1.1.1:443 and [2606:4700:4700::1111]:443 do not connect;
//   - the bridge host address of each network (the subnet's first address) answers nothing on 22, 80,
//     443, 2375, 8000, 8090 or 9000, and neither does any on-link IPv6 host (the bridge's link-local
//     address) when an interface has IPv6; a RST fails too, since pre-launch drops all input from the
//     relay bridges;
//   - no TCP port of the allowed hosts but the allowed ones accepts a connection;
//   - no TCP port of the denied hosts (-deny: the `front` network's bridge host, lane, egress and peerlink,
//     docs/design/relay-outbound-only.md §3.8) answers at all, not even with a RST: the relay's position has no
//     path to `front`, so it reaches neither peerlink nor the lane's client listener that only peerlink may use;
//   - every allowed endpoint refuses the entry's peer routes with a 4xx (a pin push, a pinned request, an
//     attestation: docs/confidential-lane-stack-routing.md §4.4), so the relay cannot reach egress's peer mode.
//
// Whether a host port is published (§3.8, O1) is not visible from here: an internal network drops traffic to
// any address off its subnet, a published port's DNAT included, so the relay's position sees the same silence
// either way. The compose gates (no `ports` on any stack service, an empty `port_policy`) and dockertest/run.sh's
// probe from outside the VM hold that item.
//
// Output: one fixed line per item and a final PASS or FAIL; no value read at run time is printed. The
// arguments come from the measured compose and both gates fix them; the item lists above are fixed here.
//
// Standard library only. Routes and addresses come from rtnetlink dumps (syscall.NetlinkRIB), the IPv6
// neighbours from an unprivileged ICMPv6 echo socket (docker sets ping_group_range to every group).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	minWait = time.Second
	maxWait = 10 * time.Minute
	// Everything after the wait: DNS, duplicate address detection, the echo, the probes and the scan
	// together take seconds; this bounds a run that hangs anyway.
	runBudget = 2 * time.Minute
)

type config struct {
	// The only endpoints that may accept a connection, which must also do so (IPv4 host:port).
	allow []netip.AddrPort
	// The hosts no port of which may answer (IPv4): the networks the relay must not be on.
	deny []netip.Addr
	// How long to wait for the allowed endpoints to open.
	wait time.Duration
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "isolation-check: FAILED: the arguments are invalid")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.wait+runBudget)
	ok := report(check(ctx, cfg, newLinuxSystem()), os.Stdout, os.Stderr)
	cancel()
	if !ok {
		os.Exit(1)
	}
}

// parseConfig parses and validates the command line. Every value is checked, none clamped, and the
// flag package's own messages (which quote the input) are discarded.
func parseConfig(args []string) (config, error) {
	var cfg config
	var allow, deny string
	fs := flag.NewFlagSet("gray-isolation-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&allow, "allow", "", "the only endpoints that may answer, comma-separated IPv4 host:port (required)")
	fs.StringVar(&deny, "deny", "", "hosts no port of which may answer, comma-separated IPv4 addresses, none of them an allowed host (required)")
	fs.DurationVar(&cfg.wait, "wait", 0, "how long to wait for the allowed endpoints to open (required, 1s to 10m)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, errors.New("unexpected argument")
	}
	if allow == "" {
		return config{}, errors.New("-allow is required")
	}
	for _, field := range strings.Split(allow, ",") {
		endpoint, err := netip.ParseAddrPort(field)
		if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 {
			return config{}, errors.New("-allow takes IPv4 host:port endpoints")
		}
		if slices.Contains(cfg.allow, endpoint) {
			return config{}, errors.New("-allow names an endpoint twice")
		}
		cfg.allow = append(cfg.allow, endpoint)
	}
	if deny == "" {
		return config{}, errors.New("-deny is required")
	}
	for _, field := range strings.Split(deny, ",") {
		host, err := netip.ParseAddr(field)
		if err != nil || !host.Is4() {
			return config{}, errors.New("-deny takes IPv4 addresses")
		}
		if slices.Contains(cfg.deny, host) {
			return config{}, errors.New("-deny names a host twice")
		}
		if slices.ContainsFunc(cfg.allow, func(e netip.AddrPort) bool { return e.Addr() == host }) {
			return config{}, errors.New("-deny names an allowed host")
		}
		cfg.deny = append(cfg.deny, host)
	}
	if cfg.wait < minWait || cfg.wait > maxWait {
		return config{}, fmt.Errorf("-wait must be between %s and %s", minWait, maxWait)
	}
	return cfg, nil
}

// report prints one fixed line per item (passes on stdout, failures on stderr) and the verdict.
func report(results []result, stdout, stderr io.Writer) bool {
	ok := true
	for _, r := range results {
		if r.ok {
			fmt.Fprintf(stdout, "isolation-check: ok: %s\n", r.item)
		} else {
			ok = false
			fmt.Fprintf(stderr, "isolation-check: FAILED: %s\n", r.item)
		}
	}
	if ok {
		fmt.Fprintln(stdout, "isolation-check: PASS")
	} else {
		fmt.Fprintln(stderr, "isolation-check: FAIL: the relay must not start")
	}
	return ok
}
