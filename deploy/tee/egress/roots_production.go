//go:build !e2e

package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
)

// systemRootBundlePath is the Debian/Ubuntu CA bundle. The image copies it from the pinned Go
// build stage (D55); reading this one file, instead of letting x509 scan a directory tree, makes
// the roots part of the measured image and makes a missing bundle a startup error.
const systemRootBundlePath = "/etc/ssl/certs/ca-certificates.crt"

// Production builds have no flag that can add a root certificate: the sidecar trusts exactly the
// image's system roots (E1). The e2e-tagged build adds one, for the test CA only (`roots_e2e.go`).
func addExtraRootCAFlag(_ *flag.FlagSet, _ *config) {}

// rootPool loads the image's CA bundle and returns the pool with the number of roots. It fails
// closed: a missing, unreadable or certificate-free bundle is a startup error, because an empty
// pool would turn every vendor TLS handshake into egress_tls_failed after the lane accepted work
// (D55). The count is logged by run(); certificates themselves never are.
func rootPool(_ config) (*x509.CertPool, int, error) {
	return loadTrustBundle(systemRootBundlePath)
}

// loadTrustBundle is the testable loader behind rootPool. It takes a path rather than reading the
// constant directly so the production test can prove both the failure and the success case.
func loadTrustBundle(path string) (*x509.CertPool, int, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("system root bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, 0, fmt.Errorf("system root bundle %s holds no certificate", path)
	}
	count := len(pool.Subjects())
	if count == 0 {
		return nil, 0, fmt.Errorf("system root bundle %s is empty", path)
	}
	return pool, count, nil
}

// directDial is nil in production: the sidecar resolves each route's official host itself.
func directDial(_ config) dialFunc { return nil }
