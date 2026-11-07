package main

// Self-signed mode (docs/design/relay-outbound-only.md §3.9): the relay-stack layout's lane has no public name and
// no WebPKI certificate. The entry reaches it only through the VM's peerlink and pins the SPKI the VM's attested
// keyset binds (§3.3), so the certificate carries no name anyone checks; the key is the only thing that matters, and
// it is made exactly as in ACME mode: a new EC P-256 key in memory per boot, written only to ACME_KEY_DIR on a tmpfs.
// No CA is contacted, no ACME account exists, no state directory is touched and no listener is opened.

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
)

const (
	// selfSignedEnv turns the mode on with the value "1" (the lane entrypoint passes gray-acme only TLS_DOMAIN,
	// ACME_* and LEGO_*, and no arguments, so the measured compose sets this name). `-self-signed` is the same switch
	// as a flag. Any other value is refused, so a compose cannot spell the switch in a way the gate does not see.
	selfSignedEnv  = "ACME_SELF_SIGNED"
	selfSignedFlag = "self-signed"

	// selfSignedCommonName is the subject and issuer: not a DNS name (no dot), so no hostname check can ever match it,
	// and RFC 5280 wants a non-empty subject when there is no subjectAltName.
	selfSignedCommonName = "gray-lane"

	// selfSignedValidity outlasts every keyset that can bind the key: a keyset expires at its release's
	// KEYSET_NOT_AFTER, which app-compose.mjs holds within 400 days of the release (KEYSET_WINDOW_SECONDS, D58), so a
	// boot never serves an expired certificate under a valid keyset. Clients do not read it (the entry's egress and
	// gray-relay pin the SPKI with InsecureSkipVerify, §3.3, §5); the entrypoint warns about an expired one.
	selfSignedValidity = 400 * 24 * time.Hour
	// selfSignedBackdate covers a verifier whose clock is a little behind the CVM's secure time.
	selfSignedBackdate = 5 * time.Minute

	selfSignedIssuer = "self-signed"
)

// acmeOnlyEnvs are the settings only an ACME order reads. Self-signed mode refuses each one that is set rather than
// ignoring it, so a compose cannot mix the modes, and a TLS_DOMAIN can never end up beside a key no CA certified for
// it (the keyset of a channel peer binds no domain, §3.9). The EAB names are reported by name only.
var acmeOnlyEnvs = []string{
	"TLS_DOMAIN",
	"ACME_DIRECTORY_URLS",
	"ACME_DIRECTORY_URL",
	"ACME_STATE_DIR",
	"ACME_EMAIL",
	"ACME_EAB_KID",
	"ACME_EAB_HMAC_KEY",
	"ACME_CERT_DIR",
}

// selfSignedFromEnv reads ACME_SELF_SIGNED: unset or empty is ACME mode, "1" is self-signed mode.
func selfSignedFromEnv(getenv func(string) string) (bool, error) {
	switch value := strings.TrimSpace(getenv(selfSignedEnv)); value {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, usagef("%s is %q: set it to 1 or leave it unset", selfSignedEnv, value)
	}
}

// selfSignedConfigFromEnv is configFromEnv for self-signed mode: ACME_KEY_DIR and nothing an ACME order reads.
// ACME_TLS_ALPN_ADDRESS is still checked, because the lane entrypoint always sets it (to the lane's LISTEN_ADDRESS);
// this mode opens no listener, so the value is otherwise unused.
func selfSignedConfigFromEnv(getenv func(string) string) (config, error) {
	for _, name := range acmeOnlyEnvs {
		if strings.TrimSpace(getenv(name)) != "" {
			return config{}, usagef("%s is set, but %s=1 (or -%s) makes a self-signed certificate: only an ACME order reads it, and the certificate names no domain (docs/design/relay-outbound-only.md §3.9)", name, selfSignedEnv, selfSignedFlag)
		}
	}
	keyDir, err := absoluteDir(getenv, "ACME_KEY_DIR", defaultKeyDir)
	if err != nil {
		return config{}, err
	}
	if _, _, err := challengeAddress(strings.TrimSpace(getenv("ACME_TLS_ALPN_ADDRESS"))); err != nil {
		return config{}, err
	}
	return config{SelfSigned: true, KeyDir: keyDir}, nil
}

// executeSelfSigned is one boot in self-signed mode: a fresh key, a certificate signed by that key, both written to
// the key directory as ACME mode writes them.
func executeSelfSigned(cfg config, d deps) error {
	if err := prepareKeyDir(cfg.KeyDir, d.onMemoryFilesystem); err != nil {
		return err
	}
	key, err := generateKey()
	if err != nil {
		return fmt.Errorf("generate the certificate key: %w", err)
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	leaf, certPEM, err := selfSignedCertificate(key, now())
	if err != nil {
		return err
	}
	if err := writeFile0600(filepath.Join(cfg.KeyDir, privateKeyFile), certcrypto.PEMEncode(key)); err != nil {
		return err
	}
	if err := writeFile0600(filepath.Join(cfg.KeyDir, certificateFile), certPEM); err != nil {
		return err
	}
	d.logf("gray-acme: issued_by=%s", selfSignedIssuer)
	d.logf("gray-acme: certificate_sha256=%s", certificateSHA256(leaf))
	d.logf("gray-acme: made a self-signed certificate (no CA, no name), valid until %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// selfSignedCertificate makes the leaf with the standard library: key signs its own certificate. It is a TLS server
// certificate (digitalSignature, which TLS 1.3's ECDSA CertificateVerify needs, RFC 8446 §4.4.2.2, and serverAuth),
// not a CA, with no subjectAltName.
func selfSignedCertificate(key crypto.Signer, now time.Time) (*x509.Certificate, []byte, error) {
	// RFC 5280 §4.1.2.2: positive, at most 20 octets; 128 random bits as CAs use.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("draw a serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	name := pkix.Name{CommonName: selfSignedCommonName}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		Issuer:                name,
		NotBefore:             now.Add(-selfSignedBackdate).UTC(),
		NotAfter:              now.Add(selfSignedValidity).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("make the self-signed certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse the self-signed certificate: %w", err)
	}
	if !samePublicKey(key, leaf) {
		return nil, nil, fmt.Errorf("the self-signed certificate is not for this boot's key")
	}
	return leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
