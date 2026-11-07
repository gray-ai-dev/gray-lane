package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// linuxSystem observes the container the check runs in.
type linuxSystem struct {
	// The pure-Go resolver reads the container's /etc/resolv.conf (docker's embedded DNS).
	resolver *net.Resolver
}

func newLinuxSystem() system {
	return &linuxSystem{resolver: &net.Resolver{PreferGo: true}}
}

func (s *linuxSystem) dial(ctx context.Context, address netip.AddrPort, timeout time.Duration) outcome {
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(attempt, "tcp", address.String())
	if err == nil {
		_ = conn.Close()
		return outcomeOpen
	}
	// The run's own deadline, not this probe's: the attempt proves nothing.
	if ctx.Err() != nil {
		return outcomeError
	}
	return classify(err)
}

// request is one HTTP/1.1 exchange on a new connection, never kept and with no proxy from the environment; only the
// status is read.
func (s *linuxSystem) request(ctx context.Context, address netip.AddrPort, probe peerProbe, timeout time.Duration) (int, error) {
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(attempt, probe.method, "http://"+address.String()+probe.path, strings.NewReader(probe.body))
	if err != nil {
		return 0, err
	}
	for name, value := range probe.header {
		req.Header.Set(name, value)
	}
	client := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// classify maps a failed connect to what it proves.
func classify(err error) outcome {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return outcomeRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return outcomeUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return outcomeSilent
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return outcomeSilent
	}
	return outcomeError
}

var errNoAddress = errors.New("no address")

func (s *linuxSystem) resolve(ctx context.Context, name string) error {
	addresses, err := s.resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errNoAddress
	}
	return nil
}

func (s *linuxSystem) exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

var errNetlink = errors.New("malformed rtnetlink dump")

// rtnetlink dumps every routing table; the fixed header is read field by field, the attributes with
// syscall.ParseNetlinkRouteAttr.
func (s *linuxSystem) routes(family int) ([]route, error) {
	messages, err := dump(syscall.RTM_GETROUTE, family)
	if err != nil {
		return nil, err
	}
	var routes []route
	for _, m := range messages {
		if m.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}
		// struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type (bytes), flags (u32).
		if len(m.Data) < syscall.SizeofRtMsg {
			return nil, errNetlink
		}
		routes = append(routes, route{dstLen: int(m.Data[1]), unicast: m.Data[7] == syscall.RTN_UNICAST})
	}
	return routes, nil
}

// IFA_FLAGS (linux/if_addr.h, since 3.14): the address flags as a u32; syscall predates it.
const ifaFlags = 8

func (s *linuxSystem) addresses() ([]interfaceAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback == 0 {
			names[i.Index] = i.Name
		}
	}
	messages, err := dump(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	var addresses []interfaceAddress
	for _, m := range messages {
		if m.Header.Type != syscall.RTM_NEWADDR {
			continue
		}
		// struct ifaddrmsg: family, prefixlen, flags, scope (bytes), index (u32, host order).
		if len(m.Data) < syscall.SizeofIfAddrmsg {
			return nil, errNetlink
		}
		name, ok := names[int(binary.NativeEndian.Uint32(m.Data[4:8]))]
		if !ok {
			continue
		}
		flags := uint32(m.Data[2])
		attributes, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, err
		}
		// IFA_LOCAL is the local address where it differs from IFA_ADDRESS (point-to-point IPv4);
		// IPv6 sends IFA_ADDRESS only.
		var address, local netip.Addr
		for _, a := range attributes {
			switch a.Attr.Type {
			case syscall.IFA_ADDRESS:
				address, _ = netip.AddrFromSlice(a.Value)
			case syscall.IFA_LOCAL:
				local, _ = netip.AddrFromSlice(a.Value)
			case ifaFlags:
				if len(a.Value) == 4 {
					flags = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		if local.IsValid() {
			address = local
		}
		prefix := netip.PrefixFrom(address, int(m.Data[1]))
		if !prefix.IsValid() {
			return nil, errNetlink
		}
		addresses = append(addresses, interfaceAddress{
			iface:     name,
			prefix:    prefix,
			tentative: flags&syscall.IFA_F_TENTATIVE != 0,
			dadFailed: flags&syscall.IFA_F_DADFAILED != 0,
		})
	}
	return addresses, nil
}

func dump(kind, family int) ([]syscall.NetlinkMessage, error) {
	rib, err := syscall.NetlinkRIB(kind, family)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(rib)
}

// allNodes uses an unprivileged ICMPv6 datagram ("ping") socket, the way golang.org/x/net/icmp's
// "udp6" network does: the kernel fills in the checksum and the identifier and delivers only the
// replies to this socket's identifier. Docker sets net.ipv4.ping_group_range to every group in a
// container (measured on docker 26.1), and that range governs ICMPv6 ping sockets too.
func (s *linuxSystem) allNodes(ctx context.Context, iface string, wait time.Duration) ([]netip.Addr, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "icmpv6")
	conn, err := net.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	// Echo request: type 128, code 0, checksum and identifier (set by the kernel), sequence 1.
	request := []byte{128, 0, 0, 0, 0, 0, 0, 1}
	if _, err := conn.WriteTo(request, &net.UDPAddr{IP: net.ParseIP("ff02::1"), Zone: iface}); err != nil {
		return nil, err
	}
	var replies []netip.Addr
	buffer := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return replies, nil
		}
		if err != nil {
			return nil, err
		}
		// Echo reply: type 129.
		source, ok := from.(*net.UDPAddr)
		if !ok || n < 8 || buffer[0] != 129 {
			continue
		}
		if address, ok := netip.AddrFromSlice(source.IP); ok {
			replies = append(replies, address.WithZone(source.Zone))
		}
	}
}

func (s *linuxSystem) now() time.Time { return time.Now() }

func (s *linuxSystem) sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
