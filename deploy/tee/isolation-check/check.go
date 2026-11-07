package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// What §9 B names, fixed in the binary (the image digest measures them). The layout-specific values,
// the allowed endpoints and the wait bound, come from the compose's measured `command:`.
var (
	// The bridge host address's ports §9 B lists: ssh, http(s), the docker API, and the guest
	// agent's ports (8090 is its external one, reachable from an internal network without the INPUT
	// drop, measurements §3.7).
	hostPorts = []uint16{22, 80, 443, 2375, 8000, 8090, 9000}
	// Names a relay would want: the vendors' API hosts.
	publicNames = []string{"api.anthropic.com", "api.openai.com", "chatgpt.com"}
	publicIPv4  = netip.MustParseAddrPort("1.1.1.1:443")
	publicIPv6  = netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	// The guest agent's sockets (dstack 0.6 serves both names) and docker's, under both spellings of
	// the run directory.
	socketPaths = []string{
		"/var/run/dstack.sock", "/run/dstack.sock",
		"/var/run/tappd.sock", "/run/tappd.sock",
		"/var/run/docker.sock", "/run/docker.sock",
	}
	// The entry's peer routes (docs/confidential-lane-stack-routing.md §4.4), each in a form a listener that served
	// it could not refuse with a 4xx: a valid pin push of the highest version (204), a request to a peer with no pin
	// (502) and an attestation of a name that never resolves (502). The relay may reach neither.
	peerProbes = []peerProbe{
		{method: "PUT", path: "/v1/peer/pins", body: "[]", header: map[string]string{
			"Content-Type": "application/json", "X-Gray-Peer-Version": "18446744073709551615", "X-Gray-Peer-Push": "18446744073709551615",
		}},
		{method: "POST", path: "/peer/" + strings.Repeat("0", 64) + "/v1/messages", body: "{}", header: map[string]string{"Content-Type": "application/json"}},
		{method: "GET", path: "/peer/attest/isolation-check.invalid/healthz"},
	}
)

// peerProbe is one HTTP request the check sends an allowed endpoint.
type peerProbe struct {
	method, path, body string
	header             map[string]string
}

const (
	// Between two attempts at the allowed endpoints while lane and egress start.
	waitStep = 250 * time.Millisecond
	// One connect to a bridge host port or a public address. A dropped SYN takes this long; every such
	// probe runs at once, so the whole step takes about this long.
	probeTimeout = 2 * time.Second
	// One connect of the port scan of the allowed hosts. Containers answer a closed port with a RST at
	// once; only a filtered port waits this long.
	scanTimeout = time.Second
	// Concurrent probes; well under the default soft limit of 1024 descriptors and the ephemeral range.
	probeWorkers = 128
	dnsTimeout   = 5 * time.Second
	// IPv6 duplicate address detection: one probe and a one-second retransmit by default.
	dadWait = 5 * time.Second
	dadStep = 200 * time.Millisecond
	// How long replies to the all-nodes echo are collected.
	echoWait = 1500 * time.Millisecond
)

// outcome is what one TCP connection attempt proved.
type outcome int

const (
	// The handshake completed: something listens there and the path is open.
	outcomeOpen outcome = iota
	// A RST: the address answered, nothing listens on the port.
	outcomeRefused
	// No answer before the timeout: the SYN was dropped on the way or at the host.
	outcomeSilent
	// No route, or no host at that address (ENETUNREACH, EHOSTUNREACH).
	outcomeUnreachable
	// Anything else (a local error, a cancelled context): the attempt proves nothing.
	outcomeError
)

// route is the part of a kernel route the check reads.
type route struct {
	dstLen  int
	unicast bool
}

// interfaceAddress is one address on a non-loopback interface.
type interfaceAddress struct {
	iface  string
	prefix netip.Prefix
	// IPv6 duplicate address detection has not finished (IFA_F_TENTATIVE): the address cannot be used yet.
	tentative bool
	// Duplicate address detection failed (IFA_F_DADFAILED): the address is never used.
	dadFailed bool
}

// system is everything the check observes. linuxSystem is the real one; the tests use a fake, so the
// decision logic runs without a network, a clock or root.
type system interface {
	// dial makes one TCP connection attempt to address and closes it.
	dial(ctx context.Context, address netip.AddrPort, timeout time.Duration) outcome
	// request sends probe to address over a new connection and returns the answer's status; an error when no
	// answer came within timeout.
	request(ctx context.Context, address netip.AddrPort, probe peerProbe, timeout time.Duration) (int, error)
	// resolve looks name up; nil means it resolved.
	resolve(ctx context.Context, name string) error
	// routes lists the routes of family (syscall.AF_INET or syscall.AF_INET6) in every table.
	routes(family int) ([]route, error)
	// addresses lists the addresses on every interface but loopback.
	addresses() ([]interfaceAddress, error)
	// exists reports whether anything is at path, without following a symlink.
	exists(path string) (bool, error)
	// allNodes sends ICMPv6 echo requests to ff02::1 on iface and returns who replied within wait.
	allNodes(ctx context.Context, iface string, wait time.Duration) ([]netip.Addr, error)
	now() time.Time
	sleep(ctx context.Context, d time.Duration) error
}

// The items, in the order they are reported. The texts are fixed: the output carries no value read
// at run time.
const (
	itemSockets     = "no dstack or docker socket is present"
	itemRoute4      = "no default route (ipv4)"
	itemRoute6      = "no default route (ipv6)"
	itemAllowedOpen = "the allowed endpoints are open"
	itemDNS         = "public names do not resolve"
	itemPublic4     = "a public ipv4 address is unreachable"
	itemPublic6     = "a public ipv6 address is unreachable"
	itemHost4       = "the bridge hosts' ports are unreachable over ipv4"
	itemHost6       = "the bridge hosts' ports are unreachable over ipv6"
	itemHost6Off    = "the bridge hosts' ports are unreachable over ipv6 (ipv6 is off on every interface)"
	itemOnlyAllowed = "nothing else is open on the allowed hosts"
	itemDenied      = "no port of the denied hosts answers"
	itemPeerRefused = "the allowed endpoints refuse the peer routes"
)

type result struct {
	item string
	ok   bool
}

// check runs every item of §9 B and returns one result per item. It never stops early: a run reports
// every item that failed.
func check(ctx context.Context, cfg config, sys system) []result {
	var results []result
	add := func(item string, ok bool) { results = append(results, result{item, ok}) }

	add(itemSockets, noSockets(sys))
	add(itemRoute4, noDefaultRoute(sys, syscall.AF_INET))
	add(itemRoute6, noDefaultRoute(sys, syscall.AF_INET6))
	// lane and egress only have to have started (service_started); their listeners may come later.
	add(itemAllowedOpen, waitOpen(ctx, sys, cfg.allow, cfg.wait))
	add(itemDNS, noneResolves(ctx, sys))
	add(itemPublic4, sys.dial(ctx, publicIPv4, probeTimeout) != outcomeOpen)
	add(itemPublic6, sys.dial(ctx, publicIPv6, probeTimeout) != outcomeOpen)

	addresses, settled := settledAddresses(ctx, sys)
	add(itemHost4, settled && hostsClosed(ctx, sys, bridgeHosts4(addresses, cfg.allow)))
	ipv6, live := ipv6Interfaces(addresses)
	switch {
	case !settled:
		add(itemHost6, false)
	case !live:
		add(itemHost6Off, true)
	default:
		add(itemHost6, hostsClosed(ctx, sys, bridgeHosts6(ctx, sys, ipv6, addresses)))
	}
	add(itemOnlyAllowed, onlyAllowedOpen(ctx, sys, cfg.allow))
	add(itemDenied, deniedSilent(ctx, sys, cfg.deny))
	add(itemPeerRefused, peerRoutesRefused(ctx, sys, cfg.allow))
	return results
}

// deniedSilent scans every TCP port of every denied host (docs/design/relay-outbound-only.md §3.8: `front`, where
// peerlink and the lane's client listener are): a port passes only when there is no path at all or nothing answers.
// An open port fails, and so does a RST, which shows a path to the host. From the relay's position there is no route
// to `front`, so every dial ends at once with ENETUNREACH; a run that cannot finish the scan fails (outcomeError).
// No hosts fail too: the gates always name them.
func deniedSilent(ctx context.Context, sys system, deny []netip.Addr) bool {
	if len(deny) == 0 {
		return false
	}
	var targets []netip.AddrPort
	for _, host := range deny {
		for port := 1; port <= 65535; port++ {
			targets = append(targets, netip.AddrPortFrom(host, uint16(port)))
		}
	}
	return probeAll(ctx, sys, targets, scanTimeout, func(o outcome) bool { return o == outcomeSilent || o == outcomeUnreachable })
}

// peerRoutesRefused sends every peer probe to every allowed endpoint: each must answer, and with a 4xx. A listener
// that served a probe answers 2xx or 5xx (peerProbes), and no answer proves nothing.
func peerRoutesRefused(ctx context.Context, sys system, allow []netip.AddrPort) bool {
	for _, endpoint := range allow {
		for _, probe := range peerProbes {
			status, err := sys.request(ctx, endpoint, probe, probeTimeout)
			if err != nil || status < 400 || status > 499 {
				return false
			}
		}
	}
	return true
}

func noSockets(sys system) bool {
	for _, path := range socketPaths {
		if present, err := sys.exists(path); err != nil || present {
			return false
		}
	}
	return true
}

// noDefaultRoute: no unicast route to /0 in any table.
func noDefaultRoute(sys system, family int) bool {
	routes, err := sys.routes(family)
	if err != nil {
		return false
	}
	return !slices.ContainsFunc(routes, func(r route) bool { return r.dstLen == 0 && r.unicast })
}

// waitOpen tries every endpoint until all of them accepted a connection, or the bound passes.
func waitOpen(ctx context.Context, sys system, endpoints []netip.AddrPort, bound time.Duration) bool {
	deadline := sys.now().Add(bound)
	pending := slices.Clone(endpoints)
	for {
		pending = slices.DeleteFunc(pending, func(e netip.AddrPort) bool { return sys.dial(ctx, e, probeTimeout) == outcomeOpen })
		if len(pending) == 0 {
			return true
		}
		if !sys.now().Before(deadline) || sys.sleep(ctx, waitStep) != nil {
			return false
		}
	}
}

func noneResolves(ctx context.Context, sys system) bool {
	resolved := make([]bool, len(publicNames))
	var wg sync.WaitGroup
	for i, name := range publicNames {
		wg.Go(func() {
			lookup, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()
			resolved[i] = sys.resolve(lookup, name) == nil
		})
	}
	wg.Wait()
	return !slices.Contains(resolved, true)
}

// settledAddresses waits, within dadWait, until no IPv6 address is tentative: a probe from a tentative
// address fails locally and would look like an unreachable host.
func settledAddresses(ctx context.Context, sys system) ([]interfaceAddress, bool) {
	deadline := sys.now().Add(dadWait)
	for {
		addresses, err := sys.addresses()
		if err != nil {
			return nil, false
		}
		if !slices.ContainsFunc(addresses, func(a interfaceAddress) bool { return a.tentative && !a.dadFailed }) {
			return addresses, true
		}
		if !sys.now().Before(deadline) || sys.sleep(ctx, dadStep) != nil {
			return nil, false
		}
	}
}

// bridgeHosts4 is the bridge host address of every IPv4 network the check sits on: the first address of
// the subnet, which docker gives the bridge when the network names no gateway (the gates fix S3's
// networks with a subnet only). Every allowed host must be on one of those networks; otherwise the
// bridge it sits behind is unknown and the result is nil, which hostsClosed refuses.
func bridgeHosts4(addresses []interfaceAddress, allow []netip.AddrPort) []netip.Addr {
	var hosts []netip.Addr
	var prefixes []netip.Prefix
	for _, a := range addresses {
		if !a.prefix.Addr().Is4() {
			continue
		}
		network := a.prefix.Masked()
		prefixes = append(prefixes, network)
		if gateway := network.Addr().Next(); !slices.Contains(hosts, gateway) {
			hosts = append(hosts, gateway)
		}
	}
	for _, endpoint := range allow {
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(endpoint.Addr()) }) {
			return nil
		}
	}
	return hosts
}

// ipv6Interfaces names the interfaces with a usable IPv6 address. None means the check's position has
// no IPv6 at all: docker disables it on a container's interfaces of an IPv4-only network.
func ipv6Interfaces(addresses []interfaceAddress) ([]string, bool) {
	var names []string
	for _, a := range addresses {
		if a.prefix.Addr().Is6() && !a.dadFailed && !slices.Contains(names, a.iface) {
			names = append(names, a.iface)
		}
	}
	return names, len(names) > 0
}

// bridgeHosts6 finds the on-link IPv6 hosts of every interface with IPv6: whoever answers an echo to
// all nodes, the bridge's link-local address among them. A host that drops the relay bridges' input
// (pre-launch's ip6tables rules) does not answer and is not probed; its ports are unreachable anyway.
// An interface that cannot be asked yields nil, which hostsClosed refuses.
func bridgeHosts6(ctx context.Context, sys system, ifaces []string, addresses []interfaceAddress) []netip.Addr {
	hosts := []netip.Addr{}
	for _, iface := range ifaces {
		replies, err := sys.allNodes(ctx, iface, echoWait)
		if err != nil {
			return nil
		}
		for _, host := range replies {
			own := slices.ContainsFunc(addresses, func(a interfaceAddress) bool { return a.prefix.Addr().WithZone("") == host.WithZone("") })
			if !own && !slices.Contains(hosts, host) {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

// hostsClosed probes hostPorts on every host. A port passes only when nothing answers (dropped) or
// there is no path at all; a RST fails too, because it shows the host's input chain let the packet
// through (pre-launch drops everything from the relay bridges, §9 B). nil hosts (unknown) fail.
func hostsClosed(ctx context.Context, sys system, hosts []netip.Addr) bool {
	if hosts == nil {
		return false
	}
	var targets []netip.AddrPort
	for _, host := range hosts {
		for _, port := range hostPorts {
			targets = append(targets, netip.AddrPortFrom(host, port))
		}
	}
	return probeAll(ctx, sys, targets, probeTimeout, func(o outcome) bool { return o == outcomeSilent || o == outcomeUnreachable })
}

// onlyAllowedOpen scans every TCP port of every allowed host: nothing but the allowed ports may accept
// a connection.
func onlyAllowedOpen(ctx context.Context, sys system, allow []netip.AddrPort) bool {
	var targets []netip.AddrPort
	var hosts []netip.Addr
	for _, endpoint := range allow {
		if !slices.Contains(hosts, endpoint.Addr()) {
			hosts = append(hosts, endpoint.Addr())
		}
	}
	for _, host := range hosts {
		for port := 1; port <= 65535; port++ {
			target := netip.AddrPortFrom(host, uint16(port))
			if !slices.Contains(allow, target) {
				targets = append(targets, target)
			}
		}
	}
	return probeAll(ctx, sys, targets, scanTimeout, func(o outcome) bool { return o != outcomeOpen && o != outcomeError })
}

// probeAll dials every target with probeWorkers at a time and reports whether every outcome passed.
func probeAll(ctx context.Context, sys system, targets []netip.AddrPort, timeout time.Duration, pass func(outcome) bool) bool {
	jobs := make(chan netip.AddrPort)
	var failed atomic.Bool
	var wg sync.WaitGroup
	for range min(probeWorkers, len(targets)) {
		wg.Go(func() {
			for target := range jobs {
				if !pass(sys.dial(ctx, target, timeout)) {
					failed.Store(true)
				}
			}
		})
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	return !failed.Load()
}
