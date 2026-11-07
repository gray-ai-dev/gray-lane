// gray-acme: the one-shot ACME client of the gray-lane image (D45, D133).
//
// D133: every run generates a new certificate key in memory and orders a new certificate for
// TLS_DOMAIN with the tls-alpn-01 challenge on 443; nothing is reused. The key and certificate are
// written only to ACME_KEY_DIR, which must be a memory filesystem (the lane's tmpfs), so the key
// never reaches a volume that another compose of the same app could mount. The persistent
// ACME_STATE_DIR (the lane-certs volume) holds ACME account state only, one subdirectory per CA.
// CAs are tried in order (Google Trust Services, then Let's Encrypt, by default); the first
// certificate obtained wins. The log names the issuing CA, the account URI (for the operator's CAA
// `accounturi` record) and the certificate's SHA-256; never key material or EAB values.
//
// With ACME_SELF_SIGNED=1 or -self-signed (selfsigned.go, docs/design/relay-outbound-only.md §3.9) it makes the same
// per-boot key and a certificate that key signs itself, with no CA, no account, no state directory and no network:
// the relay-stack layout's lane, which the entry reaches only by its attested SPKI.
//
// Exit codes: 0 a certificate was obtained; 1 an operational failure (every CA failed, a file could
// not be written); 2 the environment is not a valid configuration. The lane must not start without a
// certificate from this boot, so its caller treats any non-zero exit as fatal.
package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
)

const (
	// D133: Google Trust Services first (External Account Binding, 100 new orders per hour per
	// project), Let's Encrypt as the fallback (5 certificates per identifier set per 7 days, which a
	// reissue on every boot can exhaust).
	googleDirectory      = "https://dv.acme-v02.api.pki.goog/directory"
	letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

	defaultStateDir = "/certs"
	defaultKeyDir   = "/run/lane/tls"
	// D45: tls-alpn-01 is served on 443, the port the lane publishes, on every address. D133: the lane
	// entrypoint sets ACME_TLS_ALPN_ADDRESS to the lane's own LISTEN_ADDRESS, so the challenge listener
	// binds exactly where workerd will (the relay-stack layout's front address only, the simulator's
	// high port); the compose gate refuses the name in the measured compose.
	defaultChallengePort = "443"

	// D133: account state lives under <state>/accounts/<directory host>/, so two CAs never share an
	// account file and nothing at the top level of the state directory is ours any more.
	accountsDirName = "accounts"
	accountKeyFile  = "account.key"
	accountFile     = "account.json"
	certificateFile = "fullchain.pem"
	privateKeyFile  = "privkey.pem"
	// writeFile0600's temporary files, and the D96 `.gray-acme-live-*`/`.gray-acme-current-*` names.
	tempPrefix = ".gray-acme-"
	// The D96 symlink to the canonical pair.
	legacyCurrent = "current"
)

var defaultDirectories = []string{googleDirectory, letsEncryptDirectory}

// The DNS name the certificate is for. `localhost` is allowed for the simulator; production is a
// usefallback.com subdomain (D45).
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

type config struct {
	// SelfSigned is self-signed mode (selfsigned.go): only KeyDir is set besides it.
	SelfSigned bool
	Domain     string
	CAs        []caEndpoint
	Email      string
	StateDir   string
	KeyDir     string
	// ChallengeHost is "" (every address) or an IP address; ChallengePort a TCP port.
	ChallengeHost string
	ChallengePort string
	EAB           *eabCredentials
}

// caEndpoint is one ACME directory. Host (with its port, if any) names the CA's account
// subdirectory and the CA in the log.
type caEndpoint struct {
	DirectoryURL string
	Host         string
}

// eabCredentials are the External Account Binding key id and base64url HMAC key. They are passed to
// lego only when registering at a CA whose directory sets externalAccountRequired, and never logged.
type eabCredentials struct {
	KID     string
	HMACKey string
}

// acmeClient is the part of lego this program needs for one CA. The fake in the tests implements it
// in-process, so the CA order, the account handling and the file layout are tested with no network.
type acmeClient interface {
	// ExternalAccountRequired is the directory's meta.externalAccountRequired.
	ExternalAccountRequired() bool
	// ResolveAccount returns the URI of the account that already exists for the client's key, or ""
	// when the CA answers accountDoesNotExist.
	ResolveAccount() (string, error)
	// Register creates the account for the client's key; eab is nil unless the directory requires it.
	Register(eab *eabCredentials) (string, error)
	// Obtain orders a certificate for domain with key and returns the PEM leaf and chain.
	Obtain(domain string, key crypto.Signer) ([]byte, error)
	// Details are what the CA and the ACME library said during this client's calls beyond their
	// errors: each authorization's and challenge's state and error, and lego's own lines (details.go).
	// The log prints them only when this CA fails.
	Details() []string
}

// clientFactory builds the client for one CA from the run's configuration (e-mail, challenge port).
// accountURI is "" when no URI is stored.
type clientFactory func(ca caEndpoint, cfg config, accountKey crypto.Signer, accountURI string) (acmeClient, error)

type deps struct {
	newClient clientFactory
	logf      func(format string, args ...any)
	// onMemoryFilesystem reports whether path is on tmpfs or ramfs; D133 writes the key nowhere else.
	onMemoryFilesystem func(path string) (bool, error)
	// now is the clock self-signed mode dates its certificate with; nil is time.Now.
	now func() time.Time
}

type usageError struct{ message string }

func (e *usageError) Error() string { return e.message }

func usagef(format string, args ...any) error {
	return &usageError{message: fmt.Sprintf(format, args...)}
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("")
	code := runMainArgs(os.Args[1:], os.Getenv, deps{newClient: newLegoClient, logf: log.Printf, onMemoryFilesystem: onMemoryFilesystem})
	os.Exit(code)
}

// runMain is main without arguments and without os.Exit, so the tests can assert every exit code.
func runMain(getenv func(string) string, d deps) int {
	return runMainArgs(nil, getenv, d)
}

// runMainArgs reads the one flag, -self-signed; anything else on the command line is a usage error (exit 2).
func runMainArgs(args []string, getenv func(string) string, d deps) int {
	flags := flag.NewFlagSet("gray-acme", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selfSigned := flags.Bool(selfSignedFlag, false, "make a self-signed certificate for this boot's key instead of ordering one (no CA, no account)")
	if err := flags.Parse(args); err != nil {
		d.logf("gray-acme: %v", err)
		return 2
	}
	if flags.NArg() != 0 {
		d.logf("gray-acme: unexpected argument %q", flags.Arg(0))
		return 2
	}
	cfg, err := configFromEnvMode(getenv, *selfSigned)
	if err != nil {
		d.logf("gray-acme: %v", err)
		return 2
	}
	err = execute(cfg, d)
	if err != nil {
		d.logf("gray-acme: %s", oneLine(cfg.redact(err.Error())))
		var usage *usageError
		if errors.As(err, &usage) {
			return 2
		}
		return 1
	}
	return 0
}

// configFromEnvMode is configFromEnv with the -self-signed flag: the flag or ACME_SELF_SIGNED=1 picks self-signed mode.
func configFromEnvMode(getenv func(string) string, selfSignedFlagSet bool) (config, error) {
	selfSigned, err := selfSignedFromEnv(getenv)
	if err != nil {
		return config{}, err
	}
	if selfSigned || selfSignedFlagSet {
		return selfSignedConfigFromEnv(getenv)
	}
	return configFromEnv(getenv)
}

// configFromEnv reads ACME mode's settings.
func configFromEnv(getenv func(string) string) (config, error) {
	domain := strings.TrimSpace(getenv("TLS_DOMAIN"))
	if domain == "" {
		return config{}, usagef("TLS_DOMAIN is not set")
	}
	if len(domain) > 253 || !domainRE.MatchString(domain) {
		return config{}, usagef("TLS_DOMAIN %q is not a lower-case DNS name", domain)
	}

	// The pre-D133 single directory kept the certificate key on the persistent volume. Refuse it
	// instead of guessing, so a stale compose fails loudly rather than starting a lane without a key.
	if strings.TrimSpace(getenv("ACME_CERT_DIR")) != "" {
		return config{}, usagef("ACME_CERT_DIR is no longer read (D133): set ACME_STATE_DIR for the account state and ACME_KEY_DIR for the tmpfs that receives the key and certificate")
	}

	cas, err := directoriesFromEnv(getenv)
	if err != nil {
		return config{}, err
	}

	stateDir, err := absoluteDir(getenv, "ACME_STATE_DIR", defaultStateDir)
	if err != nil {
		return config{}, err
	}
	keyDir, err := absoluteDir(getenv, "ACME_KEY_DIR", defaultKeyDir)
	if err != nil {
		return config{}, err
	}
	if within(keyDir, stateDir) || within(stateDir, keyDir) {
		return config{}, usagef("ACME_KEY_DIR %q and ACME_STATE_DIR %q must not contain each other: the key must never be on the persistent volume", keyDir, stateDir)
	}

	email := strings.TrimSpace(getenv("ACME_EMAIL"))
	if email != "" && (!strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n")) {
		return config{}, usagef("ACME_EMAIL %q is not an e-mail address", email)
	}

	host, port, err := challengeAddress(strings.TrimSpace(getenv("ACME_TLS_ALPN_ADDRESS")))
	if err != nil {
		return config{}, err
	}

	// The messages below never include the values: they are credentials.
	kid := strings.TrimSpace(getenv("ACME_EAB_KID"))
	hmacKey := strings.TrimSpace(getenv("ACME_EAB_HMAC_KEY"))
	var eab *eabCredentials
	switch {
	case kid == "" && hmacKey == "":
	case kid == "" || hmacKey == "":
		return config{}, usagef("ACME_EAB_KID and ACME_EAB_HMAC_KEY must be set together")
	default:
		// The two encodings lego's NewEAB accepts (acme/api/account.go, decodeEABHmac).
		if _, err := base64.RawURLEncoding.DecodeString(hmacKey); err != nil {
			if _, err := base64.URLEncoding.DecodeString(hmacKey); err != nil {
				return config{}, usagef("ACME_EAB_HMAC_KEY is not base64url")
			}
		}
		eab = &eabCredentials{KID: kid, HMACKey: hmacKey}
	}

	return config{Domain: domain, CAs: cas, Email: email, StateDir: stateDir, KeyDir: keyDir, ChallengeHost: host, ChallengePort: port, EAB: eab}, nil
}

// challengeAddress reads ACME_TLS_ALPN_ADDRESS, `host:port` in workerd's LISTEN_ADDRESS form: `*` or an
// empty host is every address, otherwise the host is an IP address (a name would be resolved to pick
// the listener). Unset is every address on 443.
func challengeAddress(text string) (string, string, error) {
	if text == "" {
		return "", defaultChallengePort, nil
	}
	host, port, err := net.SplitHostPort(text)
	if err != nil {
		return "", "", usagef("ACME_TLS_ALPN_ADDRESS %q is not host:port", text)
	}
	if host == "*" {
		host = ""
	}
	if host != "" && net.ParseIP(host) == nil {
		return "", "", usagef("ACME_TLS_ALPN_ADDRESS %q does not name an IP address or *", text)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", "", usagef("ACME_TLS_ALPN_ADDRESS %q does not name a TCP port", text)
	}
	return host, port, nil
}

// directoriesFromEnv reads ACME_DIRECTORY_URLS (comma separated, in order) or the one-element
// ACME_DIRECTORY_URL; setting both is ambiguous and refused.
func directoriesFromEnv(getenv func(string) string) ([]caEndpoint, error) {
	list := strings.TrimSpace(getenv("ACME_DIRECTORY_URLS"))
	single := strings.TrimSpace(getenv("ACME_DIRECTORY_URL"))
	var raw []string
	switch {
	case list != "" && single != "":
		return nil, usagef("set ACME_DIRECTORY_URLS or ACME_DIRECTORY_URL, not both")
	case list != "":
		raw = strings.Split(list, ",")
	case single != "":
		raw = []string{single}
	default:
		raw = defaultDirectories
	}
	seen := map[string]bool{}
	var cas []caEndpoint
	for _, entry := range raw {
		directory := strings.TrimSpace(entry)
		if directory == "" {
			return nil, usagef("ACME_DIRECTORY_URLS has an empty entry")
		}
		parsed, err := url.Parse(directory)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return nil, usagef("ACME directory %q is not an https URL", directory)
		}
		if !validHost(parsed) {
			return nil, usagef("ACME directory %q does not have a lower-case DNS name or IP address as its host", directory)
		}
		if seen[parsed.Host] {
			return nil, usagef("ACME directory host %s is listed twice; each CA keeps one account directory per host", parsed.Host)
		}
		seen[parsed.Host] = true
		cas = append(cas, caEndpoint{DirectoryURL: directory, Host: parsed.Host})
	}
	return cas, nil
}

// validHost keeps the account subdirectory name a plain host[:port]: no path separator and no dot
// segment can come from a directory URL.
func validHost(parsed *url.URL) bool {
	hostname := parsed.Hostname()
	if net.ParseIP(hostname) == nil && (len(hostname) > 253 || !domainRE.MatchString(hostname)) {
		return false
	}
	if port := parsed.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

func absoluteDir(getenv func(string) string, name, fallback string) (string, error) {
	dir := strings.TrimSpace(getenv(name))
	if dir == "" {
		dir = fallback
	}
	if !filepath.IsAbs(dir) {
		return "", usagef("%s %q is not an absolute path", name, dir)
	}
	dir = filepath.Clean(dir)
	if dir == "/" {
		return "", usagef("%s must not be the filesystem root", name)
	}
	return dir, nil
}

// within reports whether path is parent or below it. Both are clean absolute paths.
func within(path, parent string) bool {
	return path == parent || strings.HasPrefix(path, parent+string(filepath.Separator))
}

// redact removes the EAB values from text that may echo a CA's answer.
func (cfg config) redact(text string) string {
	if cfg.EAB == nil {
		return text
	}
	return strings.NewReplacer(cfg.EAB.HMACKey, "[redacted]", cfg.EAB.KID, "[redacted]").Replace(text)
}

// execute is one boot: a fresh key, then each CA in order until one issues (or, in self-signed mode, the key's own
// certificate).
func execute(cfg config, d deps) error {
	if cfg.SelfSigned {
		return executeSelfSigned(cfg, d)
	}
	if err := prepareKeyDir(cfg.KeyDir, d.onMemoryFilesystem); err != nil {
		return err
	}
	if err := secureDir(cfg.StateDir); err != nil {
		return err
	}
	removed, err := removeLegacyCertificate(cfg.StateDir)
	if err != nil {
		return err
	}
	if len(removed) > 0 {
		d.logf("gray-acme: removed the pre-D133 certificate key and certificate from %s: %s", cfg.StateDir, strings.Join(removed, ", "))
	}

	// D133: one key per boot, generated here and written only to the key directory.
	key, err := generateKey()
	if err != nil {
		return fmt.Errorf("generate the certificate key: %w", err)
	}
	tried := make([]string, 0, len(cfg.CAs))
	for i, ca := range cfg.CAs {
		tried = append(tried, ca.Host)
		d.logf("gray-acme: ca=%s (%d of %d)", ca.Host, i+1, len(cfg.CAs))
		leaf, certPEM, err := obtainFrom(ca, cfg, key, d.newClient, d.logf)
		if err != nil {
			// One line each, so the lane's entrypoint can report them to the bridge line by line
			// (deploy/tee/bin/entrypoint.mjs): the reason, then what the CA and lego said.
			d.logf("gray-acme: ca=%s failed: %s", ca.Host, oneLine(cfg.redact(err.Error())))
			for _, detail := range detailsOf(err) {
				d.logf("gray-acme: ca=%s detail: %s", ca.Host, oneLine(cfg.redact(detail)))
			}
			continue
		}
		if err := writeFile0600(filepath.Join(cfg.KeyDir, privateKeyFile), certcrypto.PEMEncode(key)); err != nil {
			return err
		}
		if err := writeFile0600(filepath.Join(cfg.KeyDir, certificateFile), certPEM); err != nil {
			return err
		}
		d.logf("gray-acme: issued_by=%s", ca.Host)
		d.logf("gray-acme: certificate_sha256=%s", certificateSHA256(leaf))
		d.logf("gray-acme: obtained certificate for %s from %s, valid until %s", cfg.Domain, ca.Host, leaf.NotAfter.UTC().Format(time.RFC3339))
		return nil
	}
	return fmt.Errorf("no CA issued a certificate for %s (tried %s)", cfg.Domain, strings.Join(tried, ", "))
}

// obtainFrom loads or creates this CA's account and orders one certificate for key. Once the client
// exists, an error carries the client's details (detailsOf).
func obtainFrom(ca caEndpoint, cfg config, key crypto.Signer, newClient clientFactory, logf func(string, ...any)) (leaf *x509.Certificate, certPEM []byte, err error) {
	dir := filepath.Join(cfg.StateDir, accountsDirName, ca.Host)
	accountKey, accountURI, err := readAccount(dir)
	if err != nil {
		return nil, nil, err
	}
	stored := accountKey != nil
	if !stored {
		accountKey, err = generateKey()
		if err != nil {
			return nil, nil, fmt.Errorf("generate the ACME account key: %w", err)
		}
	}
	client, err := newClient(ca, cfg, accountKey, accountURI)
	if err != nil {
		return nil, nil, fmt.Errorf("ACME client: %w", err)
	}
	defer func() {
		if err != nil {
			if details := client.Details(); len(details) > 0 {
				err = &detailedError{err: err, details: details}
			}
		}
	}()

	uri := accountURI
	if uri == "" && stored {
		// A key without its URI: a crash between account.key and account.json, or a registration
		// whose answer was lost. Ask for the account by key first; the EAB that created it is spent.
		uri, err = client.ResolveAccount()
		if err != nil {
			return nil, nil, err
		}
	}
	if uri == "" {
		var eab *eabCredentials
		if client.ExternalAccountRequired() {
			if cfg.EAB == nil {
				return nil, nil, fmt.Errorf("the directory requires External Account Binding and %s holds no account: set ACME_EAB_KID and ACME_EAB_HMAC_KEY", dir)
			}
			eab = cfg.EAB
		}
		if !stored {
			// An EAB registers exactly one account (GTS). Persist the key before registering, so a
			// registration whose answer is lost is recovered by key on the next boot, not orphaned.
			if err := writeFile0600(filepath.Join(dir, accountKeyFile), certcrypto.PEMEncode(accountKey)); err != nil {
				return nil, nil, err
			}
		}
		uri, err = client.Register(eab)
		if err != nil {
			return nil, nil, fmt.Errorf("register: %w", err)
		}
	}
	if uri == "" {
		return nil, nil, fmt.Errorf("the ACME account has no URI")
	}
	if uri != accountURI {
		if err := writeAccountURI(dir, uri); err != nil {
			return nil, nil, err
		}
	}
	// Logged before ordering: if the order fails (for example because the CAA record does not name
	// this account yet), the operator still has the value the record must carry.
	logf("gray-acme: account_uri=%s", uri)

	certPEM, err = client.Obtain(cfg.Domain, key)
	if err != nil {
		return nil, nil, fmt.Errorf("obtain a certificate for %s: %w", cfg.Domain, err)
	}
	leaf, err = parseLeaf(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("the CA returned no usable leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(cfg.Domain); err != nil {
		return nil, nil, fmt.Errorf("the CA returned a certificate that does not name %s: %w", cfg.Domain, err)
	}
	if !samePublicKey(key, leaf) {
		return nil, nil, fmt.Errorf("the CA returned a certificate for a different key")
	}
	return leaf, certPEM, nil
}

// prepareKeyDir creates the key directory, refuses anything but a memory filesystem, and removes a
// key or certificate an earlier run in the same tmpfs left, so a failed run never leaves a pair.
func prepareKeyDir(dir string, onMemoryFilesystem func(string) (bool, error)) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	memory, err := onMemoryFilesystem(dir)
	if err != nil {
		return err
	}
	if !memory {
		return usagef("ACME_KEY_DIR %s is not on a tmpfs: D133 keeps the certificate key in memory only", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == privateKeyFile || name == certificateFile || strings.HasPrefix(name, tempPrefix) {
			if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
				return fmt.Errorf("remove %s: %w", filepath.Join(dir, name), err)
			}
		}
	}
	return nil
}

// removeLegacyCertificate deletes the certificate key and certificate the pre-D133 layout kept at the
// top of the state directory: the two files, D96's `current` symlink and its `.gray-acme-*` targets
// and switch links. A top-level account.key/account.json from that layout is left alone; it is not
// read (accounts are per CA now) and an account key does not let anyone present the lane's SPKI.
func removeLegacyCertificate(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var removed []string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == privateKeyFile, name == certificateFile, name == legacyCurrent,
			strings.HasPrefix(name, legacyCurrent+"-"), strings.HasPrefix(name, tempPrefix):
		default:
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("remove %s: %w", filepath.Join(dir, name), err)
		}
		removed = append(removed, name)
	}
	if len(removed) > 0 {
		if err := syncDir(dir); err != nil {
			return removed, fmt.Errorf("sync %s: %w", dir, err)
		}
	}
	return removed, nil
}

type accountRecord struct {
	URI string `json:"uri"`
}

// readAccount returns the stored account key and URI of one CA; either may be absent. A URI without
// its key cannot sign anything and is refused rather than silently replaced.
func readAccount(dir string) (crypto.Signer, string, error) {
	if err := secureDir(dir); err != nil {
		return nil, "", err
	}
	keyPath := filepath.Join(dir, accountKeyFile)
	keyExists, err := exists(keyPath)
	if err != nil {
		return nil, "", err
	}
	var key crypto.Signer
	if keyExists {
		key, err = readSigner(keyPath)
		if err != nil {
			return nil, "", err
		}
	}
	recordPath := filepath.Join(dir, accountFile)
	recordExists, err := exists(recordPath)
	if err != nil {
		return nil, "", err
	}
	if !recordExists {
		return key, "", nil
	}
	if key == nil {
		return nil, "", fmt.Errorf("%s exists but %s does not", recordPath, keyPath)
	}
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", recordPath, err)
	}
	var record accountRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", recordPath, err)
	}
	if record.URI == "" {
		return nil, "", fmt.Errorf("%s holds no account URI", recordPath)
	}
	return key, record.URI, nil
}

func writeAccountURI(dir, uri string) error {
	data, err := json.Marshal(accountRecord{URI: uri})
	if err != nil {
		return err
	}
	return writeFile0600(filepath.Join(dir, accountFile), append(data, '\n'))
}

func certificateSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func generateKey() (crypto.Signer, error) {
	return certcrypto.GeneratePrivateKey(certcrypto.EC256)
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	leaf, err := parseLeaf(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return leaf, nil
}

func readSigner(path string) (crypto.Signer, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// lego v5 parses the SEC1 `EC PRIVATE KEY` blocks lego v4 wrote as well as the PKCS#8
	// `PRIVATE KEY` blocks it writes itself, so an account stored before the upgrade is still read.
	signer, err := certcrypto.ParsePEMPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return signer, nil
}

func syncDir(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	return nil
}

// writeFile0600 writes through a temporary file and a rename, so a reader never sees a partly
// written file. On the state volume the fsync makes the account survive a crash; on the key tmpfs it
// is a no-op and the rename alone is what matters.
func writeFile0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("create a temporary file for %s: %w", path, err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("chmod %s: %w", temporary, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", temporary, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync %s: %w", temporary, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", temporary, path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func samePublicKey(key crypto.Signer, cert *x509.Certificate) bool {
	return publicKeysEqual(key.Public(), cert.PublicKey)
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false
	}
	return string(leftDER) == string(rightDER)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", path, err)
}
