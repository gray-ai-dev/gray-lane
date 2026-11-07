package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The vendor operations table (docs/relay-changes-v2.md §6, relay-own-calls.md §3): account upkeep egress builds
// itself. The table is data reviewed like a host pin (`vendor-ops-v1.json`, embedded): per (vendor, credential type)
// it lists the operations the vendor has an endpoint for, and each operation is a template. Every value a template
// can put into a URL, a header or a body is exactly one of
//
//   - `const`: a JSON scalar fixed in the table;
//   - `account`: a field of the account's own credential (stackOpsAccountFields);
//   - `vendor`: a constant of the vendor entry (`constants`);
//   - `choice`: one item of a listed set (stackOpsChoiceSets), only in `test`, picked by a person in the panel;
//
// and `concat`, `object` and `array` only arrange those. There is no kind that reads a request, a container value or
// any other text, so no container can fill a template field: the guarantee is that no free field exists, not a filter.
//
// The loader refuses, before egress serves anything:
//
//   - a node that is not one of the kinds above, an `account` field the credential type has no such field for, a
//     `vendor` constant the entry does not define, a `choice` outside `test` or of an unknown set;
//   - a URL that is not https, has a user, a fragment or a port, or names a host outside the vendor's pins
//     (stackOpsHosts: the route's own host and the vendor's token host, reviewed as code);
//   - a storing or account-administration endpoint (stackOpsStoringSegments), an inference endpoint outside `test`, a
//     `test` on another path than the protocol's route (stackProtocolRoutes) or one that does not turn storage off;
//   - a method other than GET (limits, models) or POST (refresh, test), a GET with a body;
//   - an operation without the result members its kind reads, or a schedule outside its bounds.
//
// Results only flow in: egress reads the named members of the vendor's answer, and nothing in an answer reaches a
// later call except a refreshed token, which is a credential field again.

//go:embed vendor-ops-v1.json
var vendorOpsTableJSON []byte

const (
	stackOpsFormat = "gray-vendor-ops-v1"
	opRefresh      = "refresh"
	opLimits       = "limits"
	opModels       = "models"
	opTestPrefix   = "test:"
	// stackOpsChoiceMax bounds a listed set (relay-own-calls.md §3.1).
	stackOpsChoiceMax = 16
	// stackOpsConstMax bounds one constant's text; stackOpsLimitFieldsMax a limits result's named members.
	stackOpsConstMax       = 4 << 10
	stackOpsLimitFieldsMax = 32
	// The schedule's bounds in seconds: no table may ask for upkeep more often than once a minute or less often than
	// once a day, nor refresh more than an hour ahead of expiry.
	stackOpsEveryMin        = 60
	stackOpsEveryMax        = 86400
	stackOpsBeforeExpiryMax = 3600
)

// stackOpsHosts are the hosts each account vendor's operations may name: its route's host (routes.go), plus, for a
// vendor whose subscription tokens are refreshed at another host, that token host. Reviewed as code: the table cannot
// add a host.
var stackOpsHosts = withCompat(map[string][]string{
	"anthropic":     {"api.anthropic.com", "platform.claude.com"},
	"openai":        {"api.openai.com"},
	"chatgpt_codex": {"chatgpt.com", "auth.openai.com"},
}, false, func(v openAICompatibleVendor) []string { return []string{v.host} })

// stackOpsAccountFields are the credential fields a template may read, per credential type. An access token's
// refresh token and ChatGPT's account id are optional: an operation that reads one does not run for an account
// without it.
var stackOpsAccountFields = map[string][]string{
	"api_key":            {"api_key"},
	"oauth_access_token": {"access_token", "refresh_token", "chatgpt_account_id"},
}

// stackOpsChoiceSets are the listed sets a `test` may pick from: `model`, one of the account's models in the panel.
var stackOpsChoiceSets = []string{"model"}

// stackOpsStoringSegments are path segments of endpoints that create, read or administer stored objects or the
// account (relay-own-calls.md §3.3). No operation may name a path with one of them.
var stackOpsStoringSegments = []string{
	"files", "uploads", "batches", "threads", "assistants", "vector_stores", "fine_tuning", "fine-tuning", "fine_tunes",
	"conversations", "memory", "memories", "containers", "skills", "evals", "chatkit", "realtime", "organization",
	"organizations", "admin", "api_keys", "keys", "invites", "members", "projects", "workspaces", "billing",
}

// stackOpsInferenceSegments name the inference endpoints only a `test` may call.
var stackOpsInferenceSegments = []string{"messages", "completions", "responses", "generatecontent", "embeddings", "images", "audio"}

// opNode is one template node.
type opNode struct {
	kind     string // const, account, vendor, choice, concat, object, array
	value    json.RawMessage
	name     string
	parts    []opNode
	members  map[string]opNode
	elements []opNode
}

// opTemplate is one checked operation.
type opTemplate struct {
	op           string // refresh, limits, models, test:<protocol>
	method       string
	scheme, host string
	path, query  string
	headers      map[string]opNode
	body         *opNode
	bodyForm     string // "json" or "form"
	result       opResultSpec
	beforeExpiry int64
	every        opEvery
	confirmed    bool
	source       string
}

type opEvery struct{ Default, Min, Max int64 }

// opResultSpec names the members of the vendor's answer an operation reads, as JSON pointers.
type opResultSpec struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	ExpiresIn    string            `json:"expires_in"`
	List         string            `json:"list"`
	ID           string            `json:"id"`
	Fields       map[string]string `json:"fields"`
}

// opVendor is one (vendor, credential type) entry.
type opVendor struct {
	vendor         string
	credentialType string
	constants      map[string]string
	ops            map[string]*opTemplate
}

// opTable is the loaded table, by "vendor/credential_type".
type opTable map[string]*opVendor

func (t opTable) op(vendor, credentialType, op string) *opTemplate {
	entry := t[vendor+"/"+credentialType]
	if entry == nil {
		return nil
	}
	return entry.ops[op]
}

// stackOps is the table egress serves, loaded once at start; a table the loader refuses stops the program at its
// first use (mustLoadVendorOps), as a broken pin would.
var stackOpsTable = mustLoadVendorOps(vendorOpsTableJSON)

func mustLoadVendorOps(data []byte) opTable {
	table, err := loadVendorOps(data)
	if err != nil {
		panic("vendor-ops-v1.json: " + err.Error())
	}
	return table
}

type wireOpsTable struct {
	Format  string                   `json:"format"`
	Vendors map[string]wireOpsVendor `json:"vendors"`
}

type wireOpsVendor struct {
	Constants map[string]string `json:"constants"`
	Ops       map[string]wireOp `json:"ops"`
}

type wireOp struct {
	Method       string                     `json:"method"`
	URL          string                     `json:"url"`
	Headers      map[string]json.RawMessage `json:"headers"`
	Body         json.RawMessage            `json:"body"`
	BodyForm     string                     `json:"body_form"`
	Result       *opResultSpec              `json:"result"`
	BeforeExpiry *int64                     `json:"before_expiry_seconds"`
	Every        *opEvery                   `json:"every_seconds"`
	Confirmed    *bool                      `json:"confirmed"`
	Source       string                     `json:"source"`
}

// loadVendorOps checks a table; any refusal names the entry, the operation and the rule.
func loadVendorOps(data []byte) (opTable, error) {
	if checkStrictJSON(data) != nil {
		return nil, errors.New("not strict JSON")
	}
	var wire wireOpsTable
	if !decodeControl(data, &wire) {
		return nil, errors.New("not a vendor operations table (an unknown member, or a member of the wrong type)")
	}
	if wire.Format != stackOpsFormat {
		return nil, fmt.Errorf("format %q, want %q", wire.Format, stackOpsFormat)
	}
	table := opTable{}
	for key, wv := range wire.Vendors {
		vendor, credentialType, ok := strings.Cut(key, "/")
		if !ok || !inList(stackCredentialTypes[vendor], credentialType) {
			return nil, fmt.Errorf("%s: not a vendor and credential type egress serves", key)
		}
		entry := &opVendor{vendor: vendor, credentialType: credentialType, constants: map[string]string{}, ops: map[string]*opTemplate{}}
		for name, value := range wv.Constants {
			if name == "" || len(value) > stackOpsConstMax {
				return nil, fmt.Errorf("%s: constant %q", key, name)
			}
			entry.constants[name] = value
		}
		for name, wop := range wv.Ops {
			op, err := checkOp(entry, name, wop)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", key, name, err)
			}
			entry.ops[name] = op
		}
		table[key] = entry
	}
	return table, nil
}

func checkOp(entry *opVendor, name string, w wireOp) (*opTemplate, error) {
	op := &opTemplate{op: name, method: w.Method, headers: map[string]opNode{}, bodyForm: "json", source: w.Source}
	if w.Confirmed == nil {
		return nil, errors.New("confirmed is required (true only when a public document or the vendor's own client shows it)")
	}
	op.confirmed = *w.Confirmed
	protocol, isTest := strings.CutPrefix(name, opTestPrefix)
	switch {
	case name == opRefresh:
		if w.Method != "POST" {
			return nil, errors.New("refresh is a POST")
		}
		if entry.credentialType != "oauth_access_token" {
			return nil, errors.New("only an access token is refreshed")
		}
	case name == opLimits || name == opModels:
		if w.Method != "GET" {
			return nil, errors.New("limits and models are a GET")
		}
	case isTest:
		if _, known := stackProtocolRoutes[protocol][entry.vendor]; !known {
			return nil, errors.New("test of a protocol the vendor has no route for")
		}
		if w.Method != "POST" {
			return nil, errors.New("a test is a POST")
		}
	default:
		return nil, errors.New("not an operation Gray defines")
	}
	if err := op.checkURL(entry, protocol, isTest, w.URL); err != nil {
		return nil, err
	}
	for header, raw := range w.Headers {
		if header == "" || header != strings.ToLower(header) || !validHeaderToken(header) || opsReservedHeader(header) {
			return nil, fmt.Errorf("header %q", header)
		}
		node, err := parseOpNode(entry, isTest, raw)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", header, err)
		}
		if !node.isString() {
			return nil, fmt.Errorf("header %s: not a text", header)
		}
		op.headers[header] = node
	}
	switch w.BodyForm {
	case "", "json":
	case "form":
		op.bodyForm = "form"
	default:
		return nil, errors.New("body_form is json or form")
	}
	if len(w.Body) > 0 && string(w.Body) != "null" {
		if w.Method == "GET" {
			return nil, errors.New("a GET has no body")
		}
		node, err := parseOpNode(entry, isTest, w.Body)
		if err != nil {
			return nil, fmt.Errorf("body: %w", err)
		}
		if node.kind != "object" {
			return nil, errors.New("body: not an object")
		}
		if op.bodyForm == "form" {
			for member, value := range node.members {
				if !value.isString() {
					return nil, fmt.Errorf("body: form member %s is not a text", member)
				}
			}
		}
		op.body = &node
	} else if w.Method == "POST" {
		return nil, errors.New("a POST has a body")
	}
	if isTest {
		if err := checkTestStorage(protocol, op.body); err != nil {
			return nil, err
		}
	}
	return op, op.checkResult(name, isTest, w)
}

func (op *opTemplate) checkURL(entry *opVendor, protocol string, isTest bool, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Port() != "" || strings.Contains(raw, "#") {
		return errors.New("url: not an https URL without user, port or fragment")
	}
	if !inList(stackOpsHosts[entry.vendor], u.Host) {
		return fmt.Errorf("url: host %s is not one of the vendor's pinned hosts", u.Host)
	}
	if u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") || strings.Contains(u.Path, "/../") ||
		strings.Contains(u.Path, "/./") || strings.HasSuffix(u.Path, "/..") {
		return errors.New("url: not a plain path")
	}
	for _, segment := range strings.Split(strings.ToLower(u.Path), "/") {
		if inList(stackOpsStoringSegments, segment) {
			return fmt.Errorf("url: %s is a storing or administration endpoint", segment)
		}
		if !isTest && opsInferenceSegment(segment) {
			return errors.New("url: an inference endpoint outside test")
		}
	}
	if isTest {
		rt, _ := routeNamed(stackVendors[entry.vendor])
		want := "/" + strings.TrimPrefix(stackProtocolRoutes[protocol][entry.vendor], rt.prefix)
		if u.Host != rt.host || u.Path != want || u.RawQuery != "" {
			return errors.New("url: a test calls exactly the protocol's route")
		}
	}
	op.scheme, op.host, op.path, op.query = u.Scheme, u.Host, u.Path, u.RawQuery
	return nil
}

func opsInferenceSegment(segment string) bool {
	for _, word := range stackOpsInferenceSegments {
		if segment == word || strings.Contains(segment, ":"+word) || strings.HasPrefix(segment, word+":") {
			return true
		}
	}
	return false
}

// checkTestStorage holds a test to storage off: Responses stores by default, so its body must say `store: false`;
// Chat may say nothing or `store: false`.
func checkTestStorage(protocol string, body *opNode) error {
	store, has := body.members["store"]
	falseConst := has && store.kind == "const" && string(store.value) == "false"
	switch {
	case protocol == protocolOpenAIResponses && !falseConst:
		return errors.New("a Responses test sends store: false")
	case has && !falseConst:
		return errors.New("a test's store is false or absent")
	}
	return nil
}

func (op *opTemplate) checkResult(name string, isTest bool, w wireOp) error {
	pointer := func(p string) bool { return p == "" || strings.HasPrefix(p, "/") }
	var r opResultSpec
	if w.Result != nil {
		r = *w.Result
	}
	if !pointer(r.AccessToken) || !pointer(r.RefreshToken) || !pointer(r.ExpiresIn) || !pointer(r.List) || !pointer(r.ID) {
		return errors.New("result: a member is not a JSON pointer")
	}
	switch {
	case isTest:
		if w.Result != nil || w.BeforeExpiry != nil || w.Every != nil {
			return errors.New("a test reads its answer's events, not a result, and is not scheduled")
		}
	case name == opRefresh:
		if r.AccessToken == "" || r.List != "" || r.ID != "" || len(r.Fields) > 0 || w.Every != nil {
			return errors.New("result: refresh reads access_token (refresh_token, expires_in) only")
		}
		if w.BeforeExpiry == nil || *w.BeforeExpiry < 60 || *w.BeforeExpiry > stackOpsBeforeExpiryMax {
			return errors.New("before_expiry_seconds: 60 to 3600")
		}
		op.beforeExpiry = *w.BeforeExpiry
	case name == opModels:
		if r.List == "" || r.AccessToken != "" || r.RefreshToken != "" || r.ExpiresIn != "" || len(r.Fields) > 0 || w.BeforeExpiry != nil {
			return errors.New("result: models reads list (and id) only")
		}
	case name == opLimits:
		if len(r.Fields) == 0 || len(r.Fields) > stackOpsLimitFieldsMax || r.AccessToken != "" || r.RefreshToken != "" || r.ExpiresIn != "" ||
			r.List != "" || r.ID != "" || w.BeforeExpiry != nil {
			return errors.New("result: limits reads 1 to 32 named fields only")
		}
		for field, p := range r.Fields {
			if !validOpsFieldName(field) || p == "" || !pointer(p) {
				return fmt.Errorf("result: field %q", field)
			}
		}
	}
	if name == opLimits || name == opModels {
		if w.Every == nil || w.Every.Min < stackOpsEveryMin || w.Every.Max > stackOpsEveryMax || w.Every.Min > w.Every.Default || w.Every.Default > w.Every.Max {
			return errors.New("every_seconds: min <= default <= max within 60 s to a day")
		}
		op.every = *w.Every
	}
	op.result = r
	return nil
}

func validOpsFieldName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// opsReservedHeader are the headers net/http or egress writes, which a template cannot set.
func opsReservedHeader(name string) bool {
	switch name {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer",
		"proxy-authorization", "proxy-connection", "x-gray-egress", "x-gray-request", "cookie":
		return true
	}
	return false
}

func validHeaderToken(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// parseOpNode reads one node: an object with exactly one member naming its kind.
func parseOpNode(entry *opVendor, isTest bool, raw json.RawMessage) (opNode, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || len(members) != 1 {
		return opNode{}, errors.New("a value that is not a template node (const, account, vendor, choice, concat, object, array)")
	}
	for kind, value := range members {
		node := opNode{kind: kind}
		switch kind {
		case "const":
			trimmed := bytes.TrimSpace(value)
			if len(trimmed) == 0 || trimmed[0] == '{' || trimmed[0] == '[' || len(trimmed) > stackOpsConstMax || checkStrictJSON(trimmed) != nil {
				return opNode{}, errors.New("const: not a JSON scalar")
			}
			node.value = append(json.RawMessage(nil), trimmed...)
		case "account":
			if json.Unmarshal(value, &node.name) != nil || !inList(stackOpsAccountFields[entry.credentialType], node.name) {
				return opNode{}, fmt.Errorf("account: not a field of a %s credential", entry.credentialType)
			}
		case "vendor":
			if json.Unmarshal(value, &node.name) != nil {
				return opNode{}, errors.New("vendor: not a name")
			}
			if _, ok := entry.constants[node.name]; !ok {
				return opNode{}, fmt.Errorf("vendor: no constant %q", node.name)
			}
		case "choice":
			if !isTest {
				return opNode{}, errors.New("choice: only a test picks from a listed set")
			}
			if json.Unmarshal(value, &node.name) != nil || !inList(stackOpsChoiceSets, node.name) {
				return opNode{}, errors.New("choice: not a listed set")
			}
		case "concat":
			var parts []json.RawMessage
			if json.Unmarshal(value, &parts) != nil || len(parts) < 2 || len(parts) > 8 {
				return opNode{}, errors.New("concat: 2 to 8 parts")
			}
			for _, part := range parts {
				child, err := parseOpNode(entry, isTest, part)
				if err != nil {
					return opNode{}, err
				}
				if !child.isString() || child.kind == "concat" {
					return opNode{}, errors.New("concat: a part that is not a text")
				}
				node.parts = append(node.parts, child)
			}
		case "object":
			var children map[string]json.RawMessage
			if json.Unmarshal(value, &children) != nil || children == nil || len(children) > 32 {
				return opNode{}, errors.New("object: not an object of at most 32 members")
			}
			node.members = map[string]opNode{}
			for name, childRaw := range children {
				child, err := parseOpNode(entry, isTest, childRaw)
				if err != nil {
					return opNode{}, fmt.Errorf("%s: %w", name, err)
				}
				node.members[name] = child
			}
		case "array":
			var children []json.RawMessage
			if json.Unmarshal(value, &children) != nil || len(children) > 16 {
				return opNode{}, errors.New("array: not an array of at most 16 elements")
			}
			for _, childRaw := range children {
				child, err := parseOpNode(entry, isTest, childRaw)
				if err != nil {
					return opNode{}, err
				}
				node.elements = append(node.elements, child)
			}
		default:
			return opNode{}, fmt.Errorf("%q is not a template kind: a free value", kind)
		}
		return node, nil
	}
	return opNode{}, errors.New("unreachable")
}

// isString is a node that renders as a text: an account field, a vendor constant, a choice, a concat, or a string const.
func (n opNode) isString() bool {
	switch n.kind {
	case "account", "vendor", "choice", "concat":
		return true
	case "const":
		return len(n.value) > 0 && n.value[0] == '"'
	}
	return false
}

// opInputs are the values a template reads for one run: the account's credential fields and the panel's choice.
type opInputs struct {
	account map[string]string
	choices map[string]string
}

var errOpsInputMissing = errors.New("an input the template reads is missing")

// text renders a text node.
func (n opNode) text(entry *opVendor, in opInputs) (string, error) {
	switch n.kind {
	case "const":
		var s string
		if json.Unmarshal(n.value, &s) != nil {
			return "", errors.New("const: not a text")
		}
		return s, nil
	case "account":
		v, ok := in.account[n.name]
		if !ok || v == "" {
			return "", errOpsInputMissing
		}
		return v, nil
	case "vendor":
		return entry.constants[n.name], nil
	case "choice":
		v, ok := in.choices[n.name]
		if !ok || v == "" {
			return "", errOpsInputMissing
		}
		return v, nil
	case "concat":
		var b strings.Builder
		for _, part := range n.parts {
			s, err := part.text(entry, in)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		return b.String(), nil
	}
	return "", errors.New("not a text node")
}

// jsonValue renders a node as JSON, objects' members in sorted (JCS) order.
func (n opNode) jsonValue(entry *opVendor, in opInputs, b *bytes.Buffer) error {
	switch n.kind {
	case "const":
		b.Write(n.value)
		return nil
	case "object":
		names := make([]string, 0, len(n.members))
		for name := range n.members {
			names = append(names, name)
		}
		sort.Strings(names)
		b.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(quoteJSON(name))
			b.WriteByte(':')
			if err := n.members[name].jsonValue(entry, in, b); err != nil {
				return err
			}
		}
		b.WriteByte('}')
		return nil
	case "array":
		b.WriteByte('[')
		for i, element := range n.elements {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := element.jsonValue(entry, in, b); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	}
	s, err := n.text(entry, in)
	if err != nil {
		return err
	}
	b.Write(quoteJSON(s))
	return nil
}

// render builds the operation's target, headers and body for one run.
func (op *opTemplate) render(entry *opVendor, in opInputs) (target *url.URL, header map[string]string, body []byte, err error) {
	header = map[string]string{}
	for name, node := range op.headers {
		value, err := node.text(entry, in)
		if err != nil {
			return nil, nil, nil, err
		}
		if !validHeaderValue(value) {
			return nil, nil, nil, errors.New("a header value a header line cannot carry")
		}
		header[name] = value
	}
	if op.body != nil {
		var b bytes.Buffer
		if op.bodyForm == "form" {
			form := url.Values{}
			for name, node := range op.body.members {
				value, err := node.text(entry, in)
				if err != nil {
					return nil, nil, nil, err
				}
				form.Set(name, value)
			}
			b.WriteString(form.Encode())
		} else if err := op.body.jsonValue(entry, in, &b); err != nil {
			return nil, nil, nil, err
		}
		body = b.Bytes()
	}
	target = &url.URL{Scheme: "https", Host: op.host, Opaque: op.path, RawQuery: op.query}
	return target, header, body, nil
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if (value[i] < 0x20 && value[i] != '\t') || value[i] == 0x7f {
			return false
		}
	}
	return true
}
