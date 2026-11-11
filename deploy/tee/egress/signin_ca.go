package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The Gray sign-in CA (docs/design/relay-sign-in-in-vm.md D1, revision 3). Egress ends the TLS connection of every
// proxied sign-in call with a leaf certificate for the CONNECT host, signed by this CA. Egress makes the CA itself, at
// its first start in a VM boot: an ECDSA P-256 key and a self-signed certificate whose X.509 name constraints (RFC 5280
// §4.2.1.10, critical) name exactly the vendor rows' hosts. Key and certificate are written to a memory volume only
// egress mounts (-sign-in-key-dir), so an egress restart reuses them and the next boot makes new ones; the key never
// leaves that volume and the process, and no route carries it. Egress then writes the relay's trust bundle (the image's
// system roots followed by the CA certificate) to a second memory volume, mounted read-only into the relay container
// (-sign-in-bundle; compose points SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE at it).
// Without the flags (tests, the entry) there is no CA and the proxy refuses every CONNECT (503 login_proxy_unready).
//
// A CA read back from the volume is checked as one made now: a CA, critical name constraints covering every row host,
// the key its certificate's. A leaf is issued only for a host of the rows and checked under the CA before it is used. A
// leaf lives 24 h and is cached per host until 1 h before its end; its key is new for each leaf.

const (
	signInCALeafLife  = 24 * time.Hour
	signInCALeafRenew = time.Hour
	signInCABackdate  = 5 * time.Minute
	signInCAPEMMax    = 16 << 10
	signInCALife      = 397 * 24 * time.Hour
	// signInCAFile holds the CA's certificate and key, one file on egress's own volume.
	signInCAFile       = "sign-in-ca.pem"
	errLoginProxyReady = "login_proxy_unready"
	// signInSystemRoots is the image's CA bundle (the Dockerfile copies it from the pinned Go image), the first part of
	// the relay's trust bundle.
	signInSystemRoots = "/etc/ssl/certs/ca-certificates.crt"
)

type signInCA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	pool    *x509.CertPool
	certPEM []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// parseSignInCA checks the CA the lane hands over against the rows' hosts (above).
func parseSignInCA(certPEM, keyPEM []byte, domains []string, now time.Time) (*signInCA, error) {
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("certificate pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.New("certificate")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("not a CA")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("not valid now")
	}
	// Exactly the rows' hosts, no wider: a CA another egress build made for other hosts is not this one's.
	permitted := append([]string(nil), cert.PermittedDNSDomains...)
	sort.Strings(permitted)
	wanted := append([]string(nil), domains...)
	sort.Strings(wanted)
	if !cert.PermittedDNSDomainsCritical || strings.Join(permitted, ",") != strings.Join(wanted, ",") {
		return nil, errors.New("name constraints are not exactly the rows' hosts")
	}
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		return nil, errors.New("path length not zero")
	}
	if !excludesAllIPs(cert.ExcludedIPRanges) {
		return nil, errors.New("IP addresses not excluded")
	}
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("key pem")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("key")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("key type")
	}
	// The key must be the certificate's.
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if pub, ok := signer.Public().(equaler); !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("key does not match")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &signInCA{cert: cert, key: signer, pool: pool, certPEM: append([]byte(nil), certPEM...), leaves: map[string]*tls.Certificate{}}, nil
}

// excludesAllIPs: the CA's excluded IP ranges hold 0.0.0.0/0 and ::/0, so no leaf under it names an address.
func excludesAllIPs(ranges []*net.IPNet) bool {
	v4, v6 := false, false
	for _, r := range ranges {
		ones, bits := r.Mask.Size()
		v4 = v4 || (ones == 0 && bits == 32)
		v6 = v6 || (ones == 0 && bits == 128)
	}
	return v4 && v6
}

// leaf is the certificate egress shows for host, made or taken from the cache. host must already be a rows host.
func (ca *signInCA) leaf(host string, now time.Time) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if held := ca.leaves[host]; held != nil && now.Before(held.Leaf.NotAfter.Add(-signInCALeafRenew)) {
		return held, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(signInCALeafLife)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-signInCABackdate),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// Checked as a client checks it, the name constraints included, before it is ever shown.
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: host, Roots: ca.pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
	ca.leaves[host] = leaf
	return leaf, nil
}

// loadOrMakeSignInCA reuses the boot's CA from dir, or makes one there. Key and certificate are one file, written by
// one rename, so a crash never leaves half a CA. A file that is not a CA egress would make now (unreadable, other hosts,
// or not valid on a clock that moved back) is replaced by a new CA rather than stopping egress at every start; the
// relay's bundle is rewritten from it.
func loadOrMakeSignInCA(dir string, domains []string, now time.Time) (*signInCA, error) {
	file := filepath.Join(dir, signInCAFile)
	if data, err := os.ReadFile(file); err == nil {
		if certPEM, keyPEM, ok := splitCAFile(data); ok {
			if ca, err := parseSignInCA(certPEM, keyPEM, domains, now); err == nil {
				return ca, nil
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	_, allV4, _ := net.ParseCIDR("0.0.0.0/0")
	_, allV6, _ := net.ParseCIDR("::/0")
	template := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "Gray sign-in CA (this VM boot)"},
		NotBefore:                   now.Add(-signInCABackdate),
		NotAfter:                    now.Add(signInCALife),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomains:         domains,
		ExcludedIPRanges:            []*net.IPNet{allV4, allV6},
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := writeFileAtomic(file, append(append([]byte(nil), certPEM...), keyPEM...), 0o600); err != nil {
		return nil, err
	}
	return parseSignInCA(certPEM, keyPEM, domains, now)
}

// splitCAFile is the CA file's two blocks: the certificate, then the key.
func splitCAFile(data []byte) ([]byte, []byte, bool) {
	certBlock, rest := pem.Decode(data)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, false
	}
	keyBlock, rest := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, false
	}
	return pem.EncodeToMemory(certBlock), pem.EncodeToMemory(keyBlock), true
}

// writeSignInBundle writes the relay's trust bundle: the system roots, then the sign-in CA.
func writeSignInBundle(path, systemRoots string, ca *signInCA) error {
	roots, err := os.ReadFile(systemRoots)
	if err != nil {
		return err
	}
	bundle := append(bytes.TrimRight(roots, "\n"), '\n')
	bundle = append(bundle, ca.certPEM...)
	return writeFileAtomic(path, bundle, 0o644)
}

// writeFileAtomic writes data beside path and renames it into place, so a reader sees the old file or the whole new one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
