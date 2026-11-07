package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/tlsalpn01"
	"github.com/go-acme/lego/v5/lego"
	legoLog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"
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
	if err := client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(cfg.ChallengeHost, cfg.ChallengePort)); err != nil {
		return nil, fmt.Errorf("configure tls-alpn-01: %w", err)
	}
	return &legoClient{client: client, user: user, details: details}, nil
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

// Obtain orders the certificate for key. KeyType names the EC P-256 key lego v4's client
// configuration did (lego reads the type of a given key from the key itself); EnableCommonName keeps
// the CSR's common name, which lego v4 set by default and v5 sets only when asked.
func (l *legoClient) Obtain(domain string, key crypto.Signer) ([]byte, error) {
	result, err := l.client.Certificate.Obtain(context.Background(), certificate.ObtainRequest{
		Domains:          []string{domain},
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
