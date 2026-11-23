package main

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// The dial rule (review 11-16). Every TCP connection egress opens on an account's behalf goes to a public address:
// a proxy the relay sealed with the account, or the vendor's API host when the account has none. The relay chooses
// the proxy address, and egress shares the relay_out network with the relay's own container (compose.stack.yaml), so
// without this rule a relay could point an account's proxy at 10.231.11.3 (its container), at egress's other
// networks or at the VM's loopback, and read the outcome of each proxy check or account test as a signal out of the
// isolation, or probe the VM's internal ports.
//
// The check runs in net.Dialer.Control, which sees the address being dialed after name resolution, so a proxy host
// that resolves to an internal address (DNS rebinding included) is refused the same as an IP literal. A refused
// dial fails as any dial that got no connection does: egress_proxy_failed (stage dial) or egress_connect_failed for a
// relay call, proxy_unreachable for a proxy check (stack_proxy_check.go), proxy_failed or connect_failed for an
// account test (stack_accounttest.go). No new code: the lane, the bridge and the console already carry these, and the
// panel says what proxy_unreachable can mean (frontend relay-stack.ts CHECK_FAILURE).
//
// Refused: loopback, unspecified (and all of 0.0.0.0/8), private (RFC 1918, RFC 4193), link-local unicast and
// multicast, every multicast, the IPv4 limited broadcast, carrier-grade NAT (RFC 6598), and the stack VM's own
// networks; an IPv4-mapped IPv6 address is judged as its IPv4 address. Not checked: egress's own internal dials,
// which no account names: the peer link's unix socket (peer_link.go), the relay container's listener probe
// (mirror_admission.go, the fixed 10.231.11.3:3000) and the sign-in callback (signin_session.go, the fixed
// signInCallbackHost). They dial fixed addresses of the layout, never one a relay supplies.

// errDialAddressRefused is the reason a refused dial carries (inside the *net.OpError the dial returns). It is never
// sent or logged as text: the code of the failed call is.
var errDialAddressRefused = errors.New("egress dials no private or internal address for an account: use the proxy's public address")

// internalPrefixes are the refused ranges net/netip has no method for.
var internalPrefixes = []netip.Prefix{
	// "This network" (RFC 1122 3.2.1.3): Linux connects 0.x.y.z to the host itself; IsUnspecified covers 0.0.0.0 only.
	netip.MustParsePrefix("0.0.0.0/8"),
	// Carrier-grade NAT (RFC 6598): a provider's internal network.
	netip.MustParsePrefix("100.64.0.0/10"),
	// IANA special-purpose IPv4 ranges (RFC 6890, RFC 5737, RFC 2544, RFC 1112).
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// The IPv4 limited broadcast (inside 240.0.0.0/4; kept explicit).
	netip.MustParsePrefix("255.255.255.255/32"),
	// The stack VM's own networks (compose.stack.yaml: front 10.231.12.0/24, relay_in 10.231.10.0/24, relay_out
	// 10.231.11.0/24). Inside 10.0.0.0/8 (IsPrivate) already; named so that they stay refused whatever else changes.
	netip.MustParsePrefix("10.231.0.0/16"),
	// IANA special-purpose and IPv4/IPv6 transition ranges (NAT64 RFC 6052 & RFC 8215, discard RFC 6666,
	// Teredo RFC 4380, benchmarking RFC 5180, documentation RFC 3849, 6to4 RFC 3056, deprecated site-local RFC 3879).
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// dialAddressRefused reports whether egress refuses to dial addr for an account.
func dialAddressRefused(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return true
	}
	addr = addr.WithZone("")
	for _, prefix := range internalPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// refuseInternalDial is the dialer's Control: address is the resolved ip:port about to be connected. One that does not
// parse is refused (fail closed); net.Dialer passes an IP literal here, never a name.
func refuseInternalDial(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil || dialAddressRefused(addrPort.Addr()) {
		return errDialAddressRefused
	}
	return nil
}

// accountDialer is the dialer of every account-driven connection (the vendor and relay transports and the mirror
// pool, through newServer's dial). allowInternalDials (cfg) turns the rule off; only the e2e build's
// -e2e-allow-internal-dials sets it (roots_e2e.go), for the local harnesses whose proxies and fake vendors listen on
// loopback and docker networks.
func accountDialer(cfg config) *net.Dialer {
	dialer := &net.Dialer{Timeout: cfg.dialTimeout, KeepAlive: 30 * time.Second}
	if !cfg.allowInternalDials {
		dialer.Control = refuseInternalDial
	}
	return dialer
}
