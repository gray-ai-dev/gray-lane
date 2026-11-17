package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/challenge/tlsalpn01"
	"github.com/go-acme/lego/v5/lego"
	legoLog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/providers/dns/httpreq"
	"github.com/go-acme/lego/v5/registration"
)

const (
	// docs/design/entry-replicas.md ER5, §5 row 7: how long lego waits for the challenge TXT record to be visible
	// before it asks the CA to validate, and how often it looks. lego's own defaults (challenge/dns01/
	// dns_challenge.go:24,27 in v5.6.0: 60 s, every 2 s), until M8 measures the bridge's records on staging. A record
	// not seen in time fails that CA's order (§5 row 6), and the entrypoint's hold and restart order again.
	dns01PropagationTimeout = dns01.DefaultPropagationTimeout
	dns01PollingInterval    = dns01.DefaultPollingInterval
	// dns01PropagationWait is how long a replica's order waits after it presented its records before the CA validates
	// them, in place of lego's active check (setDNS01). Measured on staging 2026-11-17, from the bridge's write through
	// Cloudflare's API to the TXT value at both of usefallback.com's nameservers (jake and jule.ns.cloudflare.com), from
	// one client, 15 trials: 5 to 58 s, median 52 s, 9 of 15 over 45 s. The CA validates from several places, each at its
	// own Cloudflare location, so the wait is about twice the slowest seen. It adds to a replica's boot.
	dns01PropagationWait = 120 * time.Second
	// One present or cleanup call to the entrypoint: httpreq's own default (providers/dns/httpreq/httpreq.go:65,
	// 30 s). It is above the entrypoint's bound on the bridge call it makes for it (LANE_BRIDGE_CALL_MS, 20 s, in
	// @gray/lane-wire wire.ts), so the entrypoint answers with the bridge's code before this client gives up.
	dns01CallTimeout = 30 * time.Second
	// The endpoint URL httpreq joins `/present` and `/cleanup` to. Its host is never resolved: the transport
	// dials ACME_DNS01_SOCKET whatever the URL names.
	dns01Endpoint = "http://localhost"
)

// keptLines keeps lego's operational lines off the service log while a CA attempt runs: D45 wants the
// account URI and the certificate SHA-256, not order URLs and challenge progress. lego logs through
// log/slog (lego v5 log.SetDefault); slog's TextHandler writes each record to this writer as one line,
// which goes to the attempt's details, and the log prints those only when that CA fails
// (`ca=<host> detail:`). The handler keeps lego's default level (Info) and drops the time, which the
// service log does not carry either. lego v5's log.Fatal (Error, then exit 1) is called only by the
// lego command, none of the library packages linked here.
type keptLines struct{ details *attemptDetails }

func (w keptLines) Write(p []byte) (int, error) {
	w.details.legoLine(string(p))
	return len(p), nil
}

func keptLogger(details *attemptDetails) *slog.Logger {
	return slog.New(slog.NewTextHandler(keptLines{details: details}, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) == 0 && attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	}))
}

// accountUser is lego's registration.User for one account key. The account's Location (its URI) is
// the KID: when it is present, lego never posts to newAccount; when it is empty, the client resolves
// or registers once.
type accountUser struct {
	key          crypto.Signer
	email        string
	registration *acme.ExtendedAccount
}

func (u *accountUser) GetEmail() string                       { return u.email }
func (u *accountUser) GetRegistration() *acme.ExtendedAccount { return u.registration }
func (u *accountUser) GetPrivateKey() crypto.Signer           { return u.key }

type legoClient struct {
	client  *lego.Client
	user    *accountUser
	details *attemptDetails
}

// newLegoClient builds the ACME client for one CA; lego.NewClient fetches the directory, so an
// unreachable CA fails here and the next CA is tried. With an account URI lego never posts to
// newAccount. The tls-alpn-01 solver is lego's own ProviderServer, which listens on
// ACME_TLS_ALPN_ADDRESS (the lane's LISTEN_ADDRESS; every address on 443 when unset) only while a
// challenge is being validated (challenge/tlsalpn01/tls_alpn_challenge_server.go) with the acme-tls/1
// ALPN protocol.
//
// The CAs are tried one after another, so the process-wide lego logger is this attempt's. lego's own
// HTTP client (its proxy, timeouts and LEGO_CA_CERTIFICATES pool) is kept; its transport is wrapped
// to record the ACME objects the CA answers (details.go), and hands lego every body unchanged.
//
// lego v5.6.0 is the first release whose tls-alpn-01 challenge certificate has the digitalSignature
// key usage (go-acme/lego#3303, #3304): Google Trust Services' validators refuse the TLS 1.3
// handshake without it (RFC 8446 §4.4.2.2), so a v4 lego could never pass GTS's challenge.
func newLegoClient(ca caEndpoint, cfg config, accountKey crypto.Signer, accountURI string) (acmeClient, error) {
	details := newAttemptDetails(cfg.Email)
	legoLog.SetDefault(keptLogger(details))
	user := &accountUser{key: accountKey, email: cfg.Email}
	if accountURI != "" {
		user.registration = &acme.ExtendedAccount{Location: accountURI}
	}
	clientConfig := lego.NewConfig(user)
	clientConfig.CADirURL = ca.DirectoryURL
	clientConfig.HTTPClient.Transport = &observingTransport{next: clientConfig.HTTPClient.Transport, details: details}
	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	if cfg.DNS01Socket != "" {
		if err := setDNS01(client, cfg); err != nil {
			return nil, fmt.Errorf("configure dns-01: %w", err)
		}
		return &legoClient{client: client, user: user, details: details}, nil
	}
	if err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(cfg.ChallengeHost, cfg.ChallengePort)); err != nil {
		return nil, fmt.Errorf("configure tls-alpn-01: %w", err)
	}
	return &legoClient{client: client, user: user, details: details}, nil
}

// setDNS01 makes dns-01 the client's only challenge (docs/design/entry-replicas.md ER5): lego's `httpreq` provider,
// unchanged, with an HTTP client whose transport dials the entrypoint's unix socket and nothing else (no proxy, no
// name lookup). httpreq posts `{"fqdn", "value"}` to `/present` and `/cleanup` (providers/dns/httpreq/httpreq.go:
// 37-40,134-145,165-176) and fails on any status but 2xx (:208-210), the entrypoint's answer body in its error. With
// ACME_DNS01_RESOLVERS (the simulator's challenge DNS server) lego's propagation check asks those servers only and
// skips the authoritative servers, which a test DNS server does not delegate to.
//
// In a CVM lego's active check cannot work (staging, 2026-11-17: both names failed with "recursive nameservers: NS
// 127.0.0.11:53 returned NXDOMAIN" for 2 min while the bridge had created both records): before presenting, lego asks
// the CVM's resolver whether the challenge name is a CNAME (challenge/dns01/dns_challenge.go GetChallengeInfo), the
// resolver caches that NXDOMAIN for the zone's negative TTL, and the recursive check then reads the cached answer. So the
// order waits dns01PropagationWait from its first check instead (lego's WrapPreCheck, as its PropagationWait does,
// once for all of the order's names) and the CA validates at Cloudflare's authoritative servers itself.
func setDNS01(client *lego.Client, cfg config) error {
	provider, err := dns01Provider(cfg.DNS01Socket)
	if err != nil {
		return err
	}
	var options []dns01.ChallengeOption
	if len(cfg.DNS01Resolvers) > 0 {
		resolverOptions := dns01.NewOptions()
		resolverOptions.RecursiveNameservers = cfg.DNS01Resolvers
		dns01.SetDefaultClient(dns01.NewClient(resolverOptions))
		options = append(options, dns01.DisableAuthoritativeNssPropagationRequirement())
	} else {
		options = append(options, dns01.WrapPreCheck(waitFromFirstCheck(dns01PropagationWait, time.Now, sleepCtx)))
	}
	return client.Challenge.SetDNS01Provider(provider, options...)
}

// waitFromFirstCheck is a pre-check that lets the CA validate once `wait` has passed since the order's first check,
// without looking up the record: lego presents every name of the order before it checks the first
// (challenge/resolver/prober.go parallelSolve; httpreq is no sequential provider), so one wait covers them all, and a
// later name waits only what is left of it.
func waitFromFirstCheck(wait time.Duration, now func() time.Time, sleep func(context.Context, time.Duration) error) dns01.WrapPreCheckFunc {
	var mu sync.Mutex
	var start time.Time
	return func(ctx context.Context, _, _, _ string, _ dns01.PreCheckFunc) (bool, error) {
		mu.Lock()
		if start.IsZero() {
			start = now()
		}
		left := wait - now().Sub(start)
		mu.Unlock()
		if left > 0 {
			if err := sleep(ctx, left); err != nil {
				return false, err
			}
		}
		return true, nil
	}
}

// sleepCtx sleeps d, or less when ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// dns01Provider is lego's httpreq provider posting to the unix socket at socket.
func dns01Provider(socket string) (*httpreq.DNSProvider, error) {
	endpoint, err := url.Parse(dns01Endpoint)
	if err != nil {
		return nil, err
	}
	return httpreq.NewDNSProviderConfig(&httpreq.Config{
		Endpoint:           endpoint,
		PropagationTimeout: dns01PropagationTimeout,
		PollingInterval:    dns01PollingInterval,
		HTTPClient: &http.Client{
			Timeout: dns01CallTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socket)
				},
				DisableKeepAlives: true,
			},
		},
	})
}

// Details are what the CA's ACME objects and lego's own log said during this attempt (details.go).
func (l *legoClient) Details() []string { return l.details.lines() }

func (l *legoClient) ExternalAccountRequired() bool {
	return l.client.GetServerMetadata().ExternalAccountRequired
}

// ResolveAccount is lego's ResolveAccountByKey (newAccount with onlyReturnExisting), which needs no
// EAB. lego sets the account URL as the JWS kid on success, so Obtain can follow on this client.
func (l *legoClient) ResolveAccount() (string, error) {
	account, err := l.client.Registration.ResolveAccountByKey(context.Background())
	if err != nil {
		var problem *acme.ProblemDetails
		if errors.As(err, &problem) && problem.Type == acme.AccountDoesNotExistErrorType {
			return "", nil
		}
		return "", fmt.Errorf("resolve the account by its key: %w", err)
	}
	l.user.registration = account
	return account.Location, nil
}

// Register uses lego's RegisterWithExternalAccountBinding when eab is set (lego signs the binding
// with the HMAC key, RFC 8555 §7.3.4) and plain Register otherwise. No e-mail is sent unless
// ACME_EMAIL names one.
func (l *legoClient) Register(eab *eabCredentials) (string, error) {
	var account *acme.ExtendedAccount
	var err error
	if eab != nil {
		account, err = l.client.Registration.RegisterWithExternalAccountBinding(context.Background(), registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  eab.KID,
			HmacEncoded:          eab.HMACKey,
		})
	} else {
		account, err = l.client.Registration.Register(context.Background(), registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return "", err
	}
	l.user.registration = account
	return account.Location, nil
}

// Obtain orders the certificate for names (an entry replica's two, or TLS_DOMAIN alone) and key. KeyType names the EC P-256 key lego v4's client
// configuration did (lego reads the type of a given key from the key itself); EnableCommonName keeps
// the CSR's common name, which lego v4 set by default and v5 sets only when asked.
func (l *legoClient) Obtain(names []string, key crypto.Signer) ([]byte, error) {
	result, err := l.client.Certificate.Obtain(context.Background(), certificate.ObtainRequest{
		Domains:          names,
		PrivateKey:       key,
		KeyType:          certcrypto.EC256,
		Bundle:           true,
		EnableCommonName: true,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Certificate) == 0 {
		return nil, fmt.Errorf("lego returned an empty certificate")
	}
	return result.Certificate, nil
}
