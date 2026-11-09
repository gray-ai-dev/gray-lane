package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// POST /v1/stack/account-tests (S44): the entry asks egress to send one account a fixed request of a few tokens
// and to say how it went. The body is the vendor operations table's `test:<protocol>` template (stack_ops_table.go,
// docs/relay-changes-v2.md §6): constants, the vendor's texts and the model the panel picked from the account's
// models; no text of the relay's or the container's reaches it (stackTestBody). The headers are S32a's, from the
// account's registered identity (stackVendorHeader); the call
// dials exactly as a relay call does (forward, the relay transports, the account's proxy), its error is held and
// classified the same way, and its windows and the rules apply as to a relay call. Only SSE event types are read
// (and, on Chat, whether a delta had content); nothing of the answer is kept or answered. A test bypasses cooling,
// has no rid, no feed and no record, and a passing one clears the entries whose clears include `test`.
//
// The whole test is bounded by proxyConnectCap (60 s; `timeout` past it), at most stackTestsMax run at once
// (else 503 stack_tests_busy). Each holds at most an error body (64 KiB and a read) and an SSE line of
// stackTestLineMax, outside -stack-max-bytes: four tests hold at most ~1.4 MiB.

const (
	stackAccountTestsPath = "/v1/stack/account-tests"
	stackAccountTestBody  = 128 << 10
	stackTestsMax         = 4
	stackTestLineMax      = 256 << 10
)

type wireAccountTest struct {
	TestID         *string            `json:"test_id"`
	AccountID      *string            `json:"account_id"`
	Vendor         *string            `json:"vendor"`
	CredentialType *string            `json:"credential_type"`
	Protocol       *string            `json:"protocol"`
	Model          *string            `json:"model"`
	Credential     *map[string]string `json:"credential"`
	Identity       *wireIdentity      `json:"identity"`
	Proxy          *json.RawMessage   `json:"proxy"`
	ProxyID        *string            `json:"proxy_id"`
}

// accountTestAnswer is S44's answer. code is null on ok; status, class and vendor_code are null when no vendor
// answered (vendor_code also for a 2xx).
type accountTestAnswer struct {
	Outcome      string        `json:"outcome"`
	Code         *string       `json:"code"`
	Status       *int          `json:"status"`
	Class        *string       `json:"class"`
	VendorCode   *string       `json:"vendor_code"`
	FirstByteMS  *int64        `json:"first_byte_ms"`
	FirstTokenMS *int64        `json:"first_token_ms"`
	TotalMS      int64         `json:"total_ms"`
	Windows      []stackWindow `json:"windows"`
	Cleared      int           `json:"cleared"`
}

// stackTestCredentialForms are the credential headers each (vendor, credential type) sends (relay-connector
// authHeaders): the names of the request's `credential` object, exactly.
var stackTestCredentialForms = map[string][]string{
	"anthropic/api_key":                {"x-api-key"},
	"anthropic/oauth_access_token":     {"authorization"},
	"openai/api_key":                   {"authorization"},
	"chatgpt_codex/oauth_access_token": {"authorization", "chatgpt-account-id"},
}

// validCredentialValue is a credential header's value: 1-16 KiB of printable ASCII, no space at either end.
func validCredentialValue(value string) bool {
	if value == "" || len(value) > stackCredentialValueMax || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func (s *server) serveAccountTest(rec *responseRecorder, r *http.Request, entry *requestLog) {
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	if r.Method != http.MethodPost {
		refuse(errMethodRefused)
		return
	}
	body, readBytes, err := readRequestBody(r, stackAccountTestBody)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		refuse(code)
		return
	}
	var wire wireAccountTest
	if checkStrictJSON(body) != nil || !decodeControl(body, &wire) {
		refuse(errStackControlInvalid)
		return
	}
	test, answer, ok := parseAccountTest(wire)
	if !ok {
		refuse(errStackControlInvalid)
		return
	}
	if answer == nil {
		// Past the KMS lease's end no account test reaches a vendor (stack_lease.go).
		if s.stack.lease.ended(s.stack.now()) {
			refuse(errStackCredentialUnknown)
			return
		}
		if s.stack.testsRunning.Add(1) > stackTestsMax {
			s.stack.testsRunning.Add(-1)
			refuse(errStackTestsBusy)
			return
		}
		answer = s.runAccountTest(r.Context(), test)
		s.stack.testsRunning.Add(-1)
	}
	s.ops.recordTest(test.account.id, test.model, answer)
	writeControlJSON(rec, answer)
}

// accountTest is a checked request.
type accountTest struct {
	account    stackAccount
	protocol   string
	model      string
	credential http.Header
}

// parseAccountTest checks a request (false: stack_control_invalid). An answer without a vendor call comes back
// at once: route_refused for a protocol with no route or no test template for the vendor, header_refused for an identity naming a
// header off the route's identity lists.
func parseAccountTest(w wireAccountTest) (accountTest, *accountTestAnswer, bool) {
	var t accountTest
	if w.TestID == nil || len(*w.TestID) != 32 || !isLowerHex(*w.TestID) || w.AccountID == nil || !validStackID(*w.AccountID) ||
		w.Vendor == nil || w.CredentialType == nil || w.Protocol == nil || w.Model == nil || !validModelID(*w.Model) || w.Credential == nil {
		return t, nil, false
	}
	vendor, protocol := *w.Vendor, *w.Protocol
	routeName, known := stackVendors[vendor]
	if _, protocolKnown := stackProtocolRoutes[protocol]; !known || !protocolKnown || !inList(stackCredentialTypes[vendor], *w.CredentialType) {
		return t, nil, false
	}
	form := stackTestCredentialForms[vendor+"/"+*w.CredentialType]
	if len(*w.Credential) != len(form) {
		return t, nil, false
	}
	t.credential = http.Header{}
	for _, name := range form {
		value, ok := (*w.Credential)[name]
		if !ok || !validCredentialValue(value) {
			return t, nil, false
		}
		t.credential.Set(name, value)
	}
	if (w.Proxy == nil) != (w.ProxyID == nil) {
		return t, nil, false
	}
	t.account = stackAccount{id: *w.AccountID, vendor: vendor, credentialType: *w.CredentialType}
	if w.Proxy != nil {
		spec, err := parseEgressSpec([]string{string(*w.Proxy)})
		if err != nil || !validStackID(*w.ProxyID) {
			return t, nil, false
		}
		t.account.spec, t.account.proxyID = spec, w.ProxyID
	}
	if _, routed := stackProtocolRoutes[protocol][vendor]; !routed || stackOpsTable.op(vendor, *w.CredentialType, opTestPrefix+protocol) == nil {
		return t, failedTest(testRouteRefused), true
	}
	if w.Identity != nil {
		if w.Identity.Headers != nil {
			for name := range *w.Identity.Headers {
				if !staticIdentityName(routeName, name) {
					return t, failedTest(testHeaderRefused), true
				}
			}
		}
		if w.Identity.Generated != nil {
			for _, name := range *w.Identity.Generated {
				if !generatedIdentityName(routeName, name) {
					return t, failedTest(testHeaderRefused), true
				}
			}
		}
	}
	identity, ok := parseIdentity(vendor, w.Identity)
	if !ok {
		return t, nil, false
	}
	t.account.identity = identity
	t.protocol, t.model = protocol, *w.Model
	return t, nil, true
}

func failedTest(code string) *accountTestAnswer {
	return &accountTestAnswer{Outcome: "failed", Code: &code, Windows: []stackWindow{}}
}

// stackTestBody is the table's test body for (vendor, credential type, protocol) with model picked: members in JCS
// order. False when the table has no such test.
func stackTestBody(vendor, credentialType, protocol, model string) ([]byte, bool) {
	entry := stackOpsTable[vendor+"/"+credentialType]
	if entry == nil || entry.ops[opTestPrefix+protocol] == nil {
		return nil, false
	}
	_, _, body, err := entry.ops[opTestPrefix+protocol].render(entry, opInputs{choices: map[string]string{"model": model}})
	return body, err == nil
}

// runAccountTest sends the test and reads its answer.
func (s *server) runAccountTest(ctx context.Context, t accountTest) *accountTestAnswer {
	st := s.stack
	start := st.now()
	rt, _ := routeNamed(stackVendors[t.account.vendor])
	path := stackProtocolRoutes[t.protocol][t.account.vendor]
	plan := requestPlan{route: rt, spec: t.account.spec,
		target: &url.URL{Scheme: "https", Host: rt.host, Opaque: "/" + strings.TrimPrefix(path, rt.prefix)}}
	oauth := rt.name == "/anthropic" && t.account.credentialType == "oauth_access_token"
	header := stackVendorHeader(rt, t.credential, map[string]string{}, oauth, t.account.identity, randomUUID())
	credHash, _ := stackCredential(rt, t.credential)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var timedOut atomic.Bool
	timer := st.afterFunc(proxyConnectCap, func() {
		timedOut.Store(true)
		cancel()
	})
	defer timer.Stop()
	o := &testObserver{stack: st, test: t, credHash: credHash, routeName: rt.name, start: start}
	o.events = &stackSSEDigester{onEvent: o.event}
	rec := &responseRecorder{ResponseWriter: discardWriter{header: http.Header{}}}
	body, _ := stackTestBody(t.account.vendor, t.account.credentialType, t.protocol, t.model)
	code := s.forward(ctx, s.relayClient, rec, http.MethodPost, plan, header, body, o)
	return o.answer(code, timedOut.Load())
}

func routeNamed(name string) (route, bool) {
	for _, rt := range routeTable {
		if rt.name == name {
			return rt, true
		}
	}
	return route{}, false
}

// discardWriter is the account test's end of forward: the vendor's bytes go nowhere.
type discardWriter struct{ header http.Header }

func (w discardWriter) Header() http.Header         { return w.header }
func (w discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w discardWriter) WriteHeader(int)             {}

// testObserver reads a test's answer for forward: its head, its error held (S35) and classified, its SSE event
// types.
type testObserver struct {
	stack     *stack
	test      accountTest
	credHash  string
	routeName string
	start     time.Time

	failedCode   string
	answered     bool
	status       int
	observation  stackObservation
	pending      []byte
	events       *stackSSEDigester
	firstByteMS  *int64
	firstTokenMS *int64
	terminal     bool
	failedEvent  bool
	lineTooLong  bool
}

func (o *testObserver) sinceStart() *int64 {
	ms := o.stack.now().Sub(o.start).Milliseconds()
	return &ms
}

func (o *testObserver) failed(code string) { o.failedCode = code }

func (o *testObserver) response(status int, header http.Header) bool {
	if !o.answered {
		o.observe(status, header, nil, false)
	}
	return true
}

func (o *testObserver) observe(status int, header http.Header, body []byte, complete bool) {
	o.answered, o.status = true, status
	if o.firstByteMS == nil {
		o.firstByteMS = o.sinceStart()
	}
	o.observation = newObservation(o.test.account, o.credHash, o.test.model, o.routeName, status, header, body, complete, o.stack.now())
	o.stack.health.observe(o.observation)
}

// holds is asked when the answer's head arrives, which is also its first byte.
func (o *testObserver) holds(status int) bool {
	o.firstByteMS = o.sinceStart()
	return status >= http.StatusBadRequest
}

func (o *testObserver) holdChunk(p []byte) bool {
	if len(o.pending)+len(p) <= stackErrorBodyMax+forwardBufferBytes {
		o.pending = append(o.pending, p...)
	}
	return true
}

func (o *testObserver) release(status int, header http.Header, complete bool) ([]byte, bool) {
	o.observe(status, header, o.pending, complete)
	o.pending = nil
	return nil, true
}

func (o *testObserver) afterHold(wait time.Duration, fire func()) *time.Timer {
	return o.stack.afterFunc(wait, fire)
}

// chunk reads a 2xx answer's events; false (the answer is then left) for a line past stackTestLineMax.
func (o *testObserver) chunk(p []byte) bool {
	if o.status < 200 || o.status > 299 {
		return true
	}
	o.events.Write(p)
	if o.events.Held() > stackTestLineMax {
		o.lineTooLong = true
		return false
	}
	return true
}

func (o *testObserver) finished(string) {}

// event is one dispatched SSE event: its type is the `event` field, or the data's own `type` (the Responses
// events carry both); Chat chunks have neither and are read by their data.
func (o *testObserver) event(eventType, data []byte) {
	kind := string(eventType)
	if kind == "" {
		if object, ok := objectOf(jsonData(data)); ok {
			kind, _ = stringOf(object.members["type"])
		}
	}
	switch kind {
	case "content_block_delta", "response.output_text.delta":
		o.tokenSeen()
	case "message_stop", "response.completed", "response.incomplete":
		o.terminal = true
	case "error", "response.failed":
		o.failedEvent = true
	case "":
		if o.test.protocol != protocolOpenAIChat {
			return
		}
		if string(data) == "[DONE]" {
			o.terminal = true
		} else if chatDeltaHasContent(data) {
			o.tokenSeen()
		}
	}
}

func (o *testObserver) tokenSeen() {
	if o.firstTokenMS == nil {
		o.firstTokenMS = o.sinceStart()
	}
}

// jsonData is data when it is strict JSON, else nil (which reads as no object).
func jsonData(data []byte) []byte {
	if checkStrictJSON(data) != nil {
		return nil
	}
	return data
}

// chatDeltaHasContent is a Chat chunk whose first choice's delta has a non-empty content.
func chatDeltaHasContent(data []byte) bool {
	chunk, ok := objectOf(jsonData(data))
	if !ok {
		return false
	}
	choices, ok := elementsOf(chunk.members["choices"])
	if !ok || len(choices) == 0 {
		return false
	}
	choice, ok := objectOf(choices[0])
	if !ok {
		return false
	}
	delta, ok := objectOf(choice.members["delta"])
	if !ok {
		return false
	}
	content, ok := stringOf(delta.members["content"])
	return ok && content != ""
}

// stackTestFailures map forward's pre-answer codes to the test's code and class.
var stackTestFailures = map[string][2]string{
	errConnectFailed:  {testConnectFailed, classConnect},
	errProxyFailed:    {testProxyFailed, classProxy},
	errTLSFailed:      {testTLSFailed, ""},
	errUpstreamFailed: {testUpstreamFailed, classVendorReset},
	errInternal:       {testUpstreamFailed, classGrayEnded},
}

// answer is the test's outcome from forward's code: ok when a 2xx stream reached its terminal event; else the
// first that applies of timeout (the 60 s cap), a failure before an answer, vendor_error (any other status), a
// read that failed (upstream_failed), and stream_incomplete.
func (o *testObserver) answer(code string, timedOut bool) *accountTestAnswer {
	a := &accountTestAnswer{Outcome: "failed", TotalMS: *o.sinceStart(), FirstByteMS: o.firstByteMS, FirstTokenMS: o.firstTokenMS,
		Windows: o.observation.windows}
	if a.Windows == nil {
		a.Windows = []stackWindow{}
	}
	set := func(testCode, class string) {
		a.Code = &testCode
		if class != "" {
			a.Class = &class
		}
	}
	if o.answered {
		status := o.status
		a.Status = &status
	}
	streamFailed := o.failedEvent
	switch {
	case timedOut:
		set(testTimeout, classGrayEnded)
	case !o.answered:
		failure := stackTestFailures[o.failedCode]
		if failure[0] == "" {
			failure = [2]string{testUpstreamFailed, classGrayEnded}
		}
		if failure[0] == testTLSFailed {
			failure[1] = stackRefusalClass(errTLSFailed, o.test.account.spec != nil)
		}
		set(failure[0], failure[1])
	case o.status < 200 || o.status > 299:
		set(testVendorError, o.observation.answer.class)
		vendorCode := o.observation.answer.vendorCode
		a.VendorCode = &vendorCode
	case o.lineTooLong:
		set(testStreamIncomplete, classEgressLimit)
	case code != "":
		set(testUpstreamFailed, classVendorReset)
	case !o.terminal || streamFailed:
		set(testStreamIncomplete, stackEndClass(endEOF, o.status, streamFailed, ""))
	default:
		a.Outcome, a.Class = "ok", ptr(classOK)
		a.Cleared = o.stack.health.testPassed(o.test.account.id, o.test.model, o.stack.now().UnixMilli())
	}
	return a
}

func ptr[T any](v T) *T { return &v }
