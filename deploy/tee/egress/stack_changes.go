package main

// Relay changes (docs/relay-request-changes.md, owner 2026-11-02). What the relay's software does with a request is
// the relay's business: a forwarded body may differ from the customer's anywhere except the members that keep a
// customer protection (the kept limits below), and a call's headers carry the relay's own values except the names
// that would add a credential or switch the account (P6) or that egress itself must write (P5). Egress no longer refuses such a difference; it
// describes it, and the description goes into the `attempt` record as `changed` and from there into the receipt
// (`relay_stack.changed`). It does so only for a rid whose RewriteSpec says `relay_changes: true`, which the entry
// sets when it writes that event: no change is ever accepted that the receipt would not describe. Without it (a
// customer who chose relays that change nothing) the body is checked against the spec alone and the vendor gets
// Gray's own header set (S32, S32a).
//
// The kept limits of the body, each a refusal at its path as before:
//
//   - P3 model: `/model` is the route's upstream model (the RewriteSpec's model rule), and `/models` is only
//     removed, so no fallback list reaches the vendor;
//   - P4 billing and P5 the answer's form: `/stream` is the customer's (or the spec's set value on Codex), so the
//     lane reads the answer, and its usage, in the form the customer asked for; the spec's required values (Chat
//     `/stream_options/include_usage`, Codex `/store`, `/stream`) hold;
//   - P2 no vendor-side retention the relay could read back with its own credential: Chat and Responses `/store`,
//     Responses `/background` and `/conversation`, Messages `/container`, and no added or edited tool of a type
//     whose files the vendor keeps (Messages `code_execution_*`, Responses `code_interpreter`);
//   - P1 destination: no added or edited vendor-side tool that makes the vendor fetch or call an address the relay
//     chooses (Messages `/mcp_servers` and `web_fetch_*` tools, Responses `mcp` and `web_search*` tools, Chat
//     `/web_search_options`).
//
// The kept members must be equal to the customer's under the comparison form (stack_json.go): present with the
// same value, or absent on both sides. Kept tools may be removed, never added or changed: every forwarded tool of
// a kept type is one of the customer's (each used once).

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// stackKeptMembers are the top-level members of each protocol that keep a customer protection besides model,
// models and stream, which every protocol keeps (stackChecker.keeps).
var stackKeptMembers = map[string]map[string]bool{
	protocolAnthropicMessages: setOf("container", "mcp_servers"),
	protocolOpenAIChat:        setOf("store", "web_search_options"),
	protocolOpenAIResponses:   setOf("store", "background", "conversation"),
}

// stackKeptToolTypes are the `/tools` entry types (by prefix; the vendors version them) a relay may remove but not
// add or change.
var stackKeptToolTypes = map[string][]string{
	protocolAnthropicMessages: {"code_execution_", "web_fetch_"},
	protocolOpenAIResponses:   {"code_interpreter", "mcp", "web_search"},
}

const (
	// stackChangedMaxBytes bounds one attempt's `changed` JSON, and so its receipt event. A request makes at most
	// RETRY_MAX_ATTEMPTS (5, @gray/config) attempts, so the changes of a whole receipt stay within 40 KiB of the
	// peer hop's 64 KiB `end` frame (PEER_FRAME_MAX_BYTES), beside the receipt's other events.
	stackChangedMaxBytes = 8 << 10
	// stackChangeKeepMax bounds the entries the check keeps for one request; the rest only count. 8 KiB holds
	// far fewer, so this bounds memory, not the receipt.
	stackChangeKeepMax = 256
)

// stackChange is one difference: a body change at an RFC 6901 path (RFC 6902's add, remove and replace), or a
// header change by lower-case name. The byte counts are the UTF-8 lengths of the removed and added values' JCS
// texts (a header's value as sent). While the budget holds them, an add or replace carries the added value: a body
// entry as `value_jcs`, a string holding the value's comparison form (stack_json.go; a receipt is an ACI JCS
// document, whose numbers are integers, so a relay's 0.7 travels as text), a header entry as `value`.
type stackChange struct {
	Op           string `json:"op"`
	Path         string `json:"path,omitempty"`
	Name         string `json:"name,omitempty"`
	RemovedBytes int    `json:"removed_bytes"`
	AddedBytes   int    `json:"added_bytes"`
	ValueJCS     string `json:"value_jcs,omitempty"`
	Value        string `json:"value,omitempty"`
}

// valued is whether an add or replace carries its value.
func (c stackChange) valued() bool { return c.ValueJCS != "" || c.Value != "" }

// stackChanged is the `changed` of an attempt record (and of the S18 answer, where headers is empty): the body
// changes as a patch that, applied after the attempt's ops and appends to the customer's body, gives the forwarded
// body; the header changes against Gray's own header set; the body's byte totals, including omitted entries; the
// count of entries left out; and whether every add and replace carries its value.
type stackChanged struct {
	Body         []stackChange `json:"body"`
	Headers      []stackChange `json:"headers"`
	AddedBytes   int64         `json:"added_bytes"`
	RemovedBytes int64         `json:"removed_bytes"`
	Omitted      int           `json:"omitted"`
	Values       string        `json:"values"`
}

const (
	stackValuesIncluded = "included"
	stackValuesOmitted  = "omitted"
)

// keeps is whether the top-level member name keeps a limit, so a difference there stays a refusal.
func (c *stackChecker) keeps(name string) bool {
	if name == "model" || name == "models" || name == "stream" {
		return true
	}
	if rule, ok := c.spec.top[name]; ok && !rule.remove {
		return true
	}
	return stackKeptMembers[c.protocol][name]
}

// changed takes a top-level member the declared rules do not cover as the relay's change, or answers the refusal
// path of a kept limit inside it. A member holding the spec's required children (Chat's stream_options) must hold
// them; they are reported as ops, and the rest of the member as changes against the customer's member with them
// applied.
func (c *stackChecker) changed(name, path string, received, forwarded jsontext.Value) string {
	if utf16Length(path) > stackPointerMaxLength {
		// No receipt path names the member; the caller answers the refusal without a path.
		return path
	}
	if children, ok := c.spec.nested[name]; ok {
		baseline, refused := c.requiredChildren(path, children, received, forwarded)
		if refused != "" {
			return refused
		}
		received = baseline
	}
	if name == "tools" {
		if refused := c.keptTools(path, received, forwarded); refused != "" {
			return refused
		}
	}
	c.diff(path, received, forwarded)
	return ""
}

// requiredChildren checks the spec's set children of a two-token rule in the forwarded member and answers the
// customer's member with them applied, recording their ops.
func (c *stackChecker) requiredChildren(path string, children map[string]stackPathRule, received, forwarded jsontext.Value) (jsontext.Value, string) {
	var setNames []string
	for name, rule := range children {
		if !rule.remove {
			setNames = append(setNames, name)
		}
	}
	if len(setNames) == 0 {
		return received, ""
	}
	slices.SortFunc(setNames, compareUTF16)
	forwardedObject, ok := objectOf(forwarded)
	if !ok {
		return nil, path + "/" + pointerToken(setNames[0])
	}
	for _, name := range setNames {
		if value := forwardedObject.members[name]; value == nil || canonicalText(value) != string(children[name].value) {
			return nil, path + "/" + pointerToken(name)
		}
	}
	receivedObject, isObject := objectOf(received)
	switch {
	case received == nil:
		inserted := map[string]jsontext.Value{}
		for _, name := range setNames {
			inserted[name] = children[name].value
		}
		baseline := canonicalObject(setNames, inserted)
		return baseline, c.modify("insert_member", path, baseline)
	case !isObject:
		// Another type: the relay's replacement of it is its change.
		return received, ""
	}
	names := slices.Clone(receivedObject.names)
	for _, name := range setNames {
		value, childPath := children[name].value, path+"/"+pointerToken(name)
		current := receivedObject.members[name]
		var refused string
		switch {
		case current == nil:
			names = append(names, name)
			refused = c.modify("insert_member", childPath, value)
		case !sameStackJSON(current, value):
			refused = c.modify("set_member", childPath, value)
		}
		if refused != "" {
			return nil, refused
		}
		receivedObject.members[name] = value
	}
	return canonicalObject(names, receivedObject.members), ""
}

// keptTools answers the path of the first forwarded tool of a kept type that is not one of the customer's tools.
func (c *stackChecker) keptTools(path string, received, forwarded jsontext.Value) string {
	kinds := stackKeptToolTypes[c.protocol]
	forwardedTools, ok := elementsOf(forwarded)
	if len(kinds) == 0 || !ok {
		return ""
	}
	receivedTools, _ := elementsOf(received)
	used := make([]bool, len(receivedTools))
	for index, tool := range forwardedTools {
		if !keptTool(kinds, tool) {
			continue
		}
		found := false
		for candidate, customer := range receivedTools {
			if !used[candidate] && sameStackJSON(customer, tool) {
				used[candidate], found = true, true
				break
			}
		}
		if !found {
			return path + "/" + strconv.Itoa(index)
		}
	}
	return ""
}

func keptTool(kinds []string, tool jsontext.Value) bool {
	object, ok := objectOf(tool)
	if !ok {
		return false
	}
	kind, ok := stringOf(object.members["type"])
	if !ok {
		return false
	}
	for _, prefix := range kinds {
		if strings.HasPrefix(kind, prefix) {
			return true
		}
	}
	return false
}

// diff records the changes that turn received into forwarded at path (nil is absent): objects member by member in
// JCS order, arrays by their common ends and then index by index, anything else as a whole. A path past the
// receipt's bound is not written: the nearest container that fits is replaced as a whole.
func (c *stackChecker) diff(path string, received, forwarded jsontext.Value) {
	switch {
	case received == nil && forwarded == nil:
		return
	case received == nil:
		c.change("add", path, nil, forwarded)
		return
	case forwarded == nil:
		c.change("remove", path, received, nil)
		return
	case sameStackJSON(received, forwarded):
		return
	}
	if left, ok := objectOf(received); ok {
		if right, ok := objectOf(forwarded); ok {
			names := unionNames(left.names, right.names)
			if !slices.ContainsFunc(names, func(name string) bool { return utf16Length(path+"/"+pointerToken(name)) > stackPointerMaxLength }) {
				for _, name := range names {
					c.diff(path+"/"+pointerToken(name), left.members[name], right.members[name])
				}
				return
			}
		}
	}
	if left, ok := elementsOf(received); ok {
		if right, ok := elementsOf(forwarded); ok && utf16Length(path+"/"+strconv.Itoa(max(len(left), len(right)))) <= stackPointerMaxLength {
			c.diffElements(path, left, right)
			return
		}
	}
	c.change("replace", path, received, forwarded)
}

// diffElements skips the arrays' common prefix and suffix, diffs the middle pairwise, then adds the forwarded
// array's extra elements or removes the received array's (from the highest index, so each path names its element).
func (c *stackChecker) diffElements(path string, left, right []jsontext.Value) {
	prefix := 0
	for prefix < len(left) && prefix < len(right) && sameStackJSON(left[prefix], right[prefix]) {
		prefix++
	}
	suffix := 0
	for suffix < len(left)-prefix && suffix < len(right)-prefix && sameStackJSON(left[len(left)-1-suffix], right[len(right)-1-suffix]) {
		suffix++
	}
	middleLeft, middleRight := len(left)-prefix-suffix, len(right)-prefix-suffix
	paired := min(middleLeft, middleRight)
	at := func(index int) string { return path + "/" + strconv.Itoa(prefix+index) }
	for index := 0; index < paired; index++ {
		c.diff(at(index), left[prefix+index], right[prefix+index])
	}
	for index := paired; index < middleRight; index++ {
		c.change("add", at(index), nil, right[prefix+index])
	}
	for index := middleLeft - 1; index >= paired; index-- {
		c.change("remove", at(index), left[prefix+index], nil)
	}
}

// change records one body change; past stackChangeKeepMax entries it only counts.
func (c *stackChecker) change(op, path string, removed, added jsontext.Value) {
	removedText, addedText := canonicalText(removed), canonicalText(added)
	c.removedBytes += int64(len(removedText))
	c.addedBytes += int64(len(addedText))
	if len(c.changes) >= stackChangeKeepMax {
		c.omitted++
		return
	}
	entry := stackChange{Op: op, Path: path, RemovedBytes: len(removedText), AddedBytes: len(addedText)}
	if op != "remove" {
		if len(addedText) <= stackChangedMaxBytes {
			entry.ValueJCS = addedText
		} else {
			c.valuesOmitted = true
		}
	}
	c.changes = append(c.changes, entry)
}

// bodyChanged is the S18 answer's `changed`, or nil when the relay changed nothing outside the declared rules.
func (c *stackChecker) bodyChanged() *stackChanged {
	if len(c.changes) == 0 && c.omitted == 0 {
		return nil
	}
	values := stackValuesIncluded
	if c.valuesOmitted || c.omitted > 0 {
		values = stackValuesOmitted
	}
	return &stackChanged{Body: c.changes, Headers: []stackChange{}, AddedBytes: c.addedBytes, RemovedBytes: c.removedBytes, Omitted: c.omitted, Values: values}
}

// marshalStackChanged writes changed as JSON without HTML escapes (the receipt keeps the JCS text of values).
func marshalStackChanged(changed stackChanged) []byte {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(changed); err != nil {
		return nil
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

// encodeStackChanged is an attempt record's `changed`: the check's body changes and the call's header changes,
// within stackChangedMaxBytes. Over the bound it drops every value (`values: omitted`), then entries from the end,
// body first, counting them in `omitted`; the byte totals always cover every change. Nil when nothing changed.
func encodeStackChanged(body *stackChanged, headers []stackChange) json.RawMessage {
	if body == nil && len(headers) == 0 {
		return nil
	}
	out := stackChanged{Body: []stackChange{}, Headers: slices.Clone(headers), Values: stackValuesIncluded}
	if out.Headers == nil {
		out.Headers = []stackChange{}
	}
	if body != nil {
		out.Body = slices.Clone(body.Body)
		out.AddedBytes, out.RemovedBytes, out.Omitted = body.AddedBytes, body.RemovedBytes, body.Omitted
		if body.Values != stackValuesIncluded {
			out.Values = stackValuesOmitted
		}
	}
	for _, list := range [][]stackChange{out.Body, out.Headers} {
		for _, entry := range list {
			if entry.Op != "remove" && !entry.valued() {
				out.Values = stackValuesOmitted
			}
		}
	}
	if out.Values == stackValuesIncluded {
		if text := marshalStackChanged(out); text != nil && len(text) <= stackChangedMaxBytes {
			return text
		}
	}
	out.Values = stackValuesOmitted
	for _, list := range [][]stackChange{out.Body, out.Headers} {
		for index := range list {
			list[index].ValueJCS, list[index].Value = "", ""
		}
	}
	text := marshalStackChanged(out)
	for len(text) > stackChangedMaxBytes {
		// Drop entries worth the excess (and room for the count's digits), then measure again.
		excess := len(text) - stackChangedMaxBytes + 8
		for excess > 0 && len(out.Body)+len(out.Headers) > 0 {
			list := &out.Body
			if len(out.Body) == 0 {
				list = &out.Headers
			}
			last := (*list)[len(*list)-1]
			entry, _ := json.Marshal(last)
			excess -= len(entry) + 1
			*list = (*list)[:len(*list)-1]
			out.Omitted++
		}
		text = marshalStackChanged(out)
	}
	return text
}

// ---------------------------------------------------------------------------------------------------
// The relay's headers.
// ---------------------------------------------------------------------------------------------------

// stackFramingHeaders are egress's own (P5): the body's type and coding (S18 proved it JSON and egress forwards it as
// read), its length, the answer's coding, and the hop. stackRelayHeader passes over them; a relay's value for them
// is no change. Two take the relay's value afterwards (stackRelayFraming, stack_coding.go): a JSON content type, and
// the accept-encoding less the codings egress cannot decode, which is the one framing change recorded.
var stackFramingHeaders = setOf("content-type", "content-encoding", "content-length", "accept-encoding", "host",
	"transfer-encoding", "connection", "te", "trailer", "upgrade", "keep-alive", "proxy-connection")

// stackAccountHeaders are refused (P6): they carry a second credential or choose the organization or project the
// account's key acts and bills as.
var stackAccountHeaders = setOf("cookie", "proxy-authorization", "openai-organization", "openai-project")

// stackListHeaders are compared as lists of values (sameValues): the same betas in another spelling are no change.
var stackListHeaders = setOf("anthropic-beta", "openai-beta")

// stackRelayChangesOn is whether a registration's RewriteSpec carries `relay_changes: true`: the entry records the
// relay's own changes in the receipt (relay_stack.changed). Without it a relay's body change is refused and its
// headers are checked and replaced (S32, S32a), so the vendor gets the request as Gray stated it.
func stackRelayChangesOn(rewrite json.RawMessage) bool {
	object, ok := objectOf(jsontext.Value(bytes.TrimSpace(rewrite)))
	return ok && canonicalText(object.members["relay_changes"]) == "true"
}

// stackAccountRefusal is the first header name (in name order) a call under relay_changes may not send: an account
// header, or another route's credential form (this route's are S15's, checked by stackCredential).
func stackAccountRefusal(rt route, h http.Header) string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	for _, name := range names {
		if stackAccountHeaders[name] {
			return name
		}
		if !slices.Contains(stackCredentialHeaders[rt.name], name) {
			for _, other := range stackCredentialHeaders {
				if slices.Contains(other, name) {
					return name
				}
			}
		}
	}
	return ""
}

// stackRelayHeader is the vendor header set of a call under relay_changes: Gray's own (stackVendorHeader, given as
// base, so the account's registered identity is the default for every name the relay does not send) with the
// relay's values in place of Gray's for every name the relay sent, except the credential headers (already the
// relay's), the framing headers and Gray's own `x-gray-*` names (the entry's headers to the container, which a
// container that forwards what it got passes on; never the vendor's). A name sent with only empty values is
// removed. It answers the changes against base, in name order; a value that is not UTF-8 is no receipt text, so its
// change carries none.
//
// On an Anthropic OAuth call the OAuth beta stays in `anthropic-beta` whatever list the relay sends (P6): it is part of
// the credential's form, which egress owns, and without it the vendor refuses the credential. A list the relay sends
// gains it at its end; a list the relay removes leaves it alone.
func stackRelayHeader(rt route, base, relay http.Header, oauth bool) (http.Header, []stackChange) {
	out := base.Clone()
	values := map[string][]string{}
	names := make([]string, 0, len(relay))
	for name, list := range relay {
		lower := strings.ToLower(name)
		if stackFramingHeaders[lower] || strings.HasPrefix(lower, "x-gray-") || slices.Contains(stackCredentialHeaders[rt.name], lower) {
			continue
		}
		if _, seen := values[lower]; !seen {
			names = append(names, lower)
		}
		values[lower] = append(values[lower], list...)
	}
	sort.Strings(names)
	var changes []stackChange
	for _, name := range names {
		sent := joinValues("", values[name])
		if oauth && name == "anthropic-beta" {
			sent = strings.Join(orderedTokens(sent, []string{stackOAuthBeta}), ", ")
			values[name] = []string{sent}
		}
		key := http.CanonicalHeaderKey(name)
		current, present := out[key]
		before := joinValues("", current)
		switch {
		case strings.Trim(sent, " \t,") == "":
			if present {
				out.Del(key)
				changes = append(changes, stackChange{Op: "remove", Name: name, RemovedBytes: len(before)})
			}
			continue
		case present && (sent == before || stackListHeaders[name] && sameValues(sent, before, nil)):
			continue
		}
		out[key] = slices.Clone(values[name])
		change := stackChange{Op: "add", Name: name, AddedBytes: len(sent)}
		if utf8.ValidString(sent) {
			change.Value = sent
		}
		if present {
			change.Op, change.RemovedBytes = "replace", len(before)
		}
		changes = append(changes, change)
	}
	return out, changes
}

// stackDecodableCodings are the content codings egress decodes, by lower-case name (RFC 9110 §8.4.1: `x-gzip` is
// `gzip`; RFC 7932 `br`; RFC 9659 `zstd`). `compress` (LZW) and anything else are not.
var stackDecodableCodings = setOf("gzip", "x-gzip", "deflate", "br", "zstd")

// stackContentType is a relay call's vendor Content-Type: the relay's one value when it names application/json with
// no parameter but a UTF-8 charset (S18 read the body as UTF-8 JSON; another charset would have the vendor read
// other text), else application/json as before.
func stackContentType(sent []string) string {
	if len(sent) != 1 {
		return "application/json"
	}
	mediaType, params, err := mime.ParseMediaType(sent[0])
	if err != nil || mediaType != "application/json" {
		return "application/json"
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return "application/json"
		}
	}
	return sent[0]
}

// stackAcceptEncoding is a relay call's vendor Accept-Encoding: the relay's field lines as it sent them when every
// element names identity or a coding egress decodes, else those elements in order with their parameters, joined with
// ", " (`identity` when none is left, since an empty or missing field would accept any coding), with the change
// that records the difference. No lines: the relay sent none, and the vendor gets none.
func stackAcceptEncoding(sent []string) ([]string, *stackChange) {
	if len(sent) == 0 {
		return nil, nil
	}
	var kept []string
	dropped := false
	for _, line := range sent {
		for _, element := range strings.Split(line, ",") {
			element = strings.Trim(element, " \t")
			if element == "" {
				continue
			}
			coding, _, _ := strings.Cut(element, ";")
			coding = strings.ToLower(strings.Trim(coding, " \t"))
			if coding == "identity" || stackDecodableCodings[coding] {
				kept = append(kept, element)
			} else {
				dropped = true
			}
		}
	}
	if !dropped {
		return slices.Clone(sent), nil
	}
	value := strings.Join(kept, ", ")
	if value == "" {
		value = "identity"
	}
	change := &stackChange{Op: "replace", Name: "accept-encoding", RemovedBytes: len(joinValues("", sent)), AddedBytes: len(value)}
	if utf8.ValidString(value) {
		change.Value = value
	}
	return []string{value}, change
}

// stackRelayFraming puts the relay's Content-Type and Accept-Encoding on a relay call's vendor header set (out, the
// result of stackRelayHeader, which leaves framing names to egress) and adds the coding change, if any, to
// changes in name order.
func stackRelayFraming(out, relay http.Header, changes []stackChange) []stackChange {
	out.Set("Content-Type", stackContentType(relay.Values("Content-Type")))
	values, change := stackAcceptEncoding(relay.Values("Accept-Encoding"))
	out.Del("Accept-Encoding")
	if values != nil {
		out["Accept-Encoding"] = values
	}
	if change == nil {
		return changes
	}
	at, _ := slices.BinarySearchFunc(changes, change.Name, func(c stackChange, name string) int { return strings.Compare(c.Name, name) })
	return slices.Insert(changes, at, *change)
}
