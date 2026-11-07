package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/v5/acme"
)

// What one CA attempt leaves for the operator beyond lego's returned error, so a failed order says why
// even when the lane's container log cannot be read (the lane reports these lines to the bridge,
// deploy/tee/bin/entrypoint.mjs):
//
//   - the CA's own view of the order, read from the ACME objects lego received: each authorization's
//     status and each challenge's type, status and RFC 8555 error (type, detail, subproblems). lego
//     keeps the challenge error in its error only when the authorization is already invalid; when the
//     CA keeps a challenge `processing` (RFC 8555 §8.2 retries) until lego stops polling, lego's error
//     is "the server didn't respond to our request (status=pending)" and the CA's reason is only here;
//   - lego's own log lines (which solver it chose, which challenges it could not solve, a challenge
//     listener's error), which the discard logger used to drop.
//
// The lines carry no key material, no token and no key authorization: the challenge `token` member is
// never read, and lego logs neither.
const (
	// maxDetailLines bounds the lines one attempt reports; lego's lines keep the last ones.
	maxDetailLines = 40
	// maxLineBytes bounds one log line, a failure reason included.
	maxLineBytes = 2048
	// maxObservedBytes bounds the ACME object this reads; larger bodies (none of the objects read
	// here is near it) reach lego unread.
	maxObservedBytes = 1 << 20
)

// attemptDetails collects one CA attempt's ACME objects and lego lines. lego calls the transport from
// its goroutines (the solver's), so every member is behind mu.
type attemptDetails struct {
	mu         sync.Mutex
	order      *acme.Order
	authzOrder []string
	authz      map[string]acme.Authorization
	challenges map[string]acme.Challenge
	lego       []string
	legoLost   int
	// hide is replaced in lego's lines: the account's contact address (README "Log": no e-mail).
	hide string
}

func newAttemptDetails(hide string) *attemptDetails {
	return &attemptDetails{authz: map[string]acme.Authorization{}, challenges: map[string]acme.Challenge{}, hide: hide}
}

// legoLine keeps one of lego's log lines, the last maxDetailLines of them.
func (a *attemptDetails) legoLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if a.hide != "" {
		line = strings.ReplaceAll(line, a.hide, "[contact]")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lego = append(a.lego, line)
	if len(a.lego) > maxDetailLines/2 {
		a.lego = a.lego[1:]
		a.legoLost++
	}
}

// observed is the union of the members of the three ACME objects read here (RFC 8555 §7.1.3, §7.1.4,
// §8): an order has `authorizations`, an authorization `identifier` and `challenges`, a challenge
// `type` and `url`. `token` is deliberately absent.
type observed struct {
	Status         string               `json:"status"`
	Error          *acme.ProblemDetails `json:"error"`
	Authorizations []string             `json:"authorizations"`
	Identifiers    []acme.Identifier    `json:"identifiers"`
	Identifier     *acme.Identifier     `json:"identifier"`
	Challenges     []acme.Challenge     `json:"challenges"`
	Type           string               `json:"type"`
	URL            string               `json:"url"`
	Validated      time.Time            `json:"validated"`
}

// observe records one ACME object lego received from url. Anything else (the directory, an account, a
// problem document, which lego's error already carries) is ignored.
func (a *attemptDetails) observe(url string, body []byte) {
	var o observed
	if err := json.Unmarshal(body, &o); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case len(o.Authorizations) > 0:
		a.order = &acme.Order{Status: o.Status, Authorizations: o.Authorizations, Identifiers: o.Identifiers, Error: o.Error}
	case o.Identifier != nil && len(o.Challenges) > 0:
		if _, seen := a.authz[url]; !seen {
			a.authzOrder = append(a.authzOrder, url)
		}
		a.authz[url] = acme.Authorization{Status: o.Status, Identifier: *o.Identifier, Challenges: o.Challenges}
		for _, challenge := range o.Challenges {
			challenge.Token = ""
			a.challenges[challenge.URL] = challenge
		}
	case o.Type != "" && o.URL != "":
		a.challenges[o.URL] = acme.Challenge{Type: o.Type, URL: o.URL, Status: o.Status, Validated: o.Validated, Error: o.Error}
	}
}

// lines are the attempt's details, in the order: the order's state if it failed, each authorization
// and its challenges (a challenge's latest state, from the authorization or the challenge answer
// lego read last), then lego's lines.
func (a *attemptDetails) lines() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	if a.order != nil && (a.order.Status == acme.StatusInvalid || a.order.Error != nil) {
		out = append(out, "order status="+a.order.Status+problemText(a.order.Error))
	}
	for _, url := range a.authzOrder {
		authz := a.authz[url]
		out = append(out, fmt.Sprintf("authorization %s status=%s", authz.Identifier.Value, authz.Status))
		for _, listed := range authz.Challenges {
			challenge := a.challenges[listed.URL]
			// A challenge the CA offered and nobody tried is noise; the one lego answers is always shown.
			if challenge.Status == acme.StatusPending && challenge.Error == nil && challenge.Type != "tls-alpn-01" {
				continue
			}
			line := fmt.Sprintf("challenge %s status=%s", challenge.Type, challenge.Status)
			if !challenge.Validated.IsZero() {
				line += " validated=" + challenge.Validated.UTC().Format(time.RFC3339)
			}
			out = append(out, line+problemText(challenge.Error))
		}
	}
	if a.legoLost > 0 {
		out = append(out, fmt.Sprintf("lego: (%d earlier lines not kept)", a.legoLost))
	}
	for _, line := range a.lego {
		out = append(out, "lego: "+line)
	}
	if len(out) > maxDetailLines {
		out = out[len(out)-maxDetailLines:]
	}
	return out
}

// problemText is an RFC 8555 §6.7 problem as `: <type> :: <detail>` and its subproblems; "" for none.
func problemText(p *acme.ProblemDetails) string {
	if p == nil {
		return ""
	}
	text := ": " + p.Type + " :: " + p.Detail
	if p.HTTPStatus != 0 {
		text += fmt.Sprintf(" (status %d)", p.HTTPStatus)
	}
	for _, sub := range p.SubProblems {
		text += fmt.Sprintf("; subproblem %s %s :: %s", sub.Identifier.Value, sub.Type, sub.Detail)
	}
	return text
}

// observingTransport hands lego every answer unchanged and records the ACME objects among them.
type observingTransport struct {
	next    http.RoundTripper
	details *attemptDetails
}

func (t *observingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil || response.Body == nil {
		return response, err
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "application/json" {
		return response, nil
	}
	read, readErr := io.ReadAll(io.LimitReader(response.Body, maxObservedBytes+1))
	if readErr == nil && len(read) <= maxObservedBytes {
		t.details.observe(request.URL.String(), read)
	}
	// What was read, then the rest (and any read error) from the original body, which lego closes.
	response.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(read), response.Body), Closer: response.Body}
	return response, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// detailedError is a CA attempt's error with the attempt's details.
type detailedError struct {
	err     error
	details []string
}

func (e *detailedError) Error() string { return e.err.Error() }
func (e *detailedError) Unwrap() error { return e.err }

func detailsOf(err error) []string {
	var detailed *detailedError
	if errors.As(err, &detailed) {
		return detailed.details
	}
	return nil
}

// oneLine makes text one bounded log line: an error can carry newlines (errors.Join, a CA's problem
// detail, lego v4's multi-domain errors), which a reader of lines would split.
func oneLine(text string) string {
	var parts []string
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if part = strings.Join(strings.Fields(part), " "); part != "" {
			parts = append(parts, part)
		}
	}
	line := strings.Join(parts, " | ")
	if len(line) <= maxLineBytes {
		return line
	}
	const mark = " ...(truncated)"
	cut := maxLineBytes - len(mark)
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + mark
}
