//go:build e2e

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// E2E ONLY. A build with `-tags e2e` accepts one additional root CA from a file, so the local
// end-to-end harness can run fake vendors behind a test CA. The production build has neither this
// flag nor this file (`roots_production.go`), and a production test proves the option is absent.
func addExtraRootCAFlag(fs *flag.FlagSet, cfg *config) {
	fs.StringVar(&cfg.extraRootCAPath, "extra-root-ca", "", "E2E ONLY: a PEM file with one additional root CA (never set in production)")
	fs.StringVar(&cfg.directDialAddress, "e2e-direct", "", "E2E ONLY: dial this host:port for every official origin instead of resolving it (never set in production)")
	e2ePeerDial = peerDialTarget{}
	fs.Var(&e2ePeerDial, "e2e-peer-dial", "E2E ONLY: <peer host>=<ip>:<port>, dial that address for the peer host's port 443 instead of resolving it (never set in production)")
}

// e2ePeerDial is -e2e-peer-dial, kept here rather than in config so the production build's config is untouched; the
// flag set parses it as it is set, so a malformed value fails startup as any flag does.
var e2ePeerDial peerDialTarget

type peerDialTarget struct{ host, address string }

func (p *peerDialTarget) String() string {
	if p.host == "" {
		return ""
	}
	return p.host + "=" + p.address
}

func (p *peerDialTarget) Set(value string) error {
	host, address, found := strings.Cut(value, "=")
	if !found || host == "" || strings.ContainsAny(host, ":/") {
		return errors.New("must be <peer host>=<ip>:<port>")
	}
	if ip, port, err := net.SplitHostPort(address); err != nil || net.ParseIP(ip) == nil || port == "" {
		return errors.New("must be <peer host>=<ip>:<port>")
	}
	*p = peerDialTarget{host: host, address: address}
	return nil
}

// directDial is nil in production. With -e2e-direct it returns a dial hook that maps each official
// route host to the harness's TLS listener, so the direct (no-proxy) path can be exercised without
// editing /etc/hosts or reaching the real vendor. With -e2e-peer-dial it maps one peer host's port 443
// to the address of a stack VM's lane on the host (deploy/tee/e2e/peer-e2e.mjs), which cannot listen on
// 443. The URL, Host header and TLS ServerName stay the official or peer host: only the TCP address
// changes, and only in this build. The peer dial's WebPKI and SPKI checks run unchanged (peer.go).
func directDial(cfg config) dialFunc {
	peerHost, peerAddress := e2ePeerDial.host, e2ePeerDial.address
	if cfg.directDialAddress == "" && peerHost == "" {
		return nil
	}
	dialer := &net.Dialer{Timeout: cfg.dialTimeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if cfg.directDialAddress != "" && officialRouteHost(host) {
			return dialer.DialContext(ctx, network, cfg.directDialAddress)
		}
		if peerHost != "" && host == peerHost && port == "443" {
			return dialer.DialContext(ctx, network, peerAddress)
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

func officialRouteHost(host string) bool {
	for _, rt := range routeTable {
		if host == rt.host {
			return true
		}
	}
	return false
}

// rootPool returns nil, 0, nil without -extra-root-ca (nil means the crypto/x509 system pool), and
// otherwise the system pool plus the test CA. The production build's loader (D55) is not used here:
// the e2e harness owns its roots so it can run on a host without the image's bundle.
func rootPool(cfg config) (*x509.CertPool, int, error) {
	if cfg.extraRootCAPath == "" {
		return nil, 0, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pemBytes, err := os.ReadFile(cfg.extraRootCAPath)
	if err != nil {
		return nil, 0, fmt.Errorf("extra root CA: %w", err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, 0, fmt.Errorf("extra root CA: %s holds no PEM certificate", cfg.extraRootCAPath)
	}
	return pool, len(pool.Subjects()), nil
}
