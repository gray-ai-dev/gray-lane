package main

// S18, the relay-stack request check (docs/confidential-lane-supply-implementation.md §5): every
// difference between the body a relay container forwards and the body the customer sent is reported.
// A difference the RewriteSpec the entry registered allows is reported as before: its member edits as
// `request.modified` ops and its appends as @gray/attest `RelayAppend`s (S26 `relay_stack.appended`).
// Since 2026-11-02 (docs/relay-request-changes.md), under a spec with `relay_changes: true` (the entry
// records the changes in the receipt), any other difference is the relay's own change, reported as a
// patch (`changed`, stack_changes.go), unless it touches a kept limit (model, stream, the spec's required
// values, retention and vendor-side fetch members), which stays a refusal at its path. Without it, any
// other difference is a refusal, as before.
// The answer is the object {"ops":[…],"appended":[…],"changed"?:{…},"forwarded_jcs_sha256":"…"}: the last is the SHA-256 of the forwarded body's comparison form (RFC
// 8785 with number tokens as written, stack_json.go), which a customer compares with the same form of
// its own replay (S26 `body_jcs_sha256`), since the check accepts a body equal in that form, not by
// bytes. The listener copies all three into the feed's `attempt`
// record (stack_relay.go).
//
// Both bodies are read as strict JSON (stack_json.go) and compared value by value in the comparison
// form, top-level members in JCS order and nested values in JCS member order and by index, so member
// order, whitespace and string escapes are no difference and a number's spelling is one; the first
// difference refused (at a kept limit, or anywhere without relay_changes) is the refusal, named by its JSON pointer (cut to whole tokens within the
// receipt's 256 UTF-16 units, S32) and never by a value.
// What a RewriteSpec covers, with the op each change becomes (each op is checked against
// GRAY_LANE_REWRITES_V1, stack_policy.go):
//
//   - model {to}: the forwarded /model must be `to`; set_member when the customer's differs,
//     insert_member when the customer wrote none. Required, like the route mapping it comes from.
//   - cap {field, max}: where the customer wrote a cap, the forwarded /<field> may be lowered to a
//     plain integer from 1 to min(max, the customer's value) (set_member; S32: never above the
//     customer's own value, and a customer's value that is not a plain integer is not lowered); where
//     the customer wrote none, it may be inserted as an integer from 1 to max (insert_member, only where
//     the policy publishes the insert). The entry chooses max; a forwarded cap equal to the customer's
//     is no difference and needs no op whatever its value.
//   - set [{path, value}]: the forwarded body must hold value at path (Codex store/stream, Chat
//     include_usage are required, S23); set_member or insert_member as above. A two-token path whose
//     parent is absent is covered by inserting the parent as exactly the object of its set children,
//     the published insert_member of Chat's /stream_options.
//   - remove [path]: the member may be absent from the forwarded body (remove_member), or unchanged.
//     Removing a two-token path's last member removes the parent as well (the published op
//     cascades), so an emptied parent the forwarded body still holds is a refusal at the parent.
//   - append [{template_id, position, sha256, bytes}]: registered template texts at the protocol's
//     two positions, in the value shapes @gray/lane's F writes (append.ts), each matched by its UTF-8
//     byte length and the SHA-256 of those bytes: Anthropic `system` (a string grows at its ends; an
//     array gains {"type":"text","text":T} blocks at its ends; absent becomes an array of those
//     blocks), Chat `messages` (gains {"role":"developer","content":T} messages at the front and
//     after the last leading system/developer message), Responses `instructions` (a string grows at
//     its ends; absent becomes the concatenation). Each registered entry is used at most once
//     (selectAppends refuses a repeated template), and one request carries at most the limits'
//     count of texts and bytes (-stack-append-max-items, -stack-append-max-bytes).
//
// The ops reproduce the forwarded value from the received one: applying them in order to the
// customer's JSON value gives the forwarded value under JCS equality. A received or forwarded body
// that is not one strict JSON object, or a malformed RewriteSpec, is an error, not a refusal.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// stackAppendLimits bound one request's appends: at most maxItems texts of at most maxBytes UTF-8
// bytes in all. They are the -stack-append-max-items and -stack-append-max-bytes flags (config.go),
// whose defaults are @gray/lane's.
type stackAppendLimits struct {
	maxItems int
	maxBytes int
}

// stackAppendMaxEntries bounds a spec's append list. @gray/lane's registry has no count of its own;
// the bound is this matcher's: it marks the entries a request used in one uint64. A spec lists the
// relay's registered texts for one route, and a request uses at most maxItems of them.
const stackAppendMaxEntries = 64

// stackPointerMaxLength is @gray/lane's MAX_POINTER_LENGTH (pointer.ts), in UTF-16 code units as there.
const stackPointerMaxLength = 256

// stackTemplateIDMax is @gray/lane's TEMPLATE_ID rule (templates.ts): 1 to 128 of [A-Za-z0-9_.:-]. The
// id reaches receipts, so it is plain.
const stackTemplateIDMax = 128

// The parts a stackCheckError names.
const (
	stackPartProtocol  = "protocol"
	stackPartRewrite   = "rewrite"
	stackPartReceived  = "received"
	stackPartForwarded = "forwarded"
)

// stackCheckError is value-free: part says which input failed (a forwarded body is the relay's, the
// others are the entry's) and reason is a fixed phrase. It carries no member name, value or path.
type stackCheckError struct {
	part   string
	reason string
}

func (e *stackCheckError) Error() string { return "stack check: " + e.part + ": " + e.reason }

func stackCheckErr(part, reason string) error { return &stackCheckError{part: part, reason: reason} }

// newStackRequestCheck is S18 with S20a's signature, under the given append limits. run wires it with
// the flags' values.
func newStackRequestCheck(limits stackAppendLimits) stackRequestCheck {
	return func(protocol string, received, forwarded []byte, rewrite json.RawMessage) (json.RawMessage, string, error) {
		return checkStackRequestWith(limits, protocol, received, forwarded, rewrite)
	}
}

var _ stackRequestCheck = checkStackRequest

// checkStackRequest is S18 under the default limits (@gray/lane's).
func checkStackRequest(protocol string, received, forwarded []byte, rewrite json.RawMessage) (json.RawMessage, string, error) {
	return checkStackRequestWith(defaultStackAppendLimits(), protocol, received, forwarded, rewrite)
}

func checkStackRequestWith(limits stackAppendLimits, protocol string, received, forwarded []byte, rewrite json.RawMessage) (json.RawMessage, string, error) {
	slots, ok := stackAppendSlotsByProtocol[protocol]
	if !ok {
		return nil, "", stackCheckErr(stackPartProtocol, "not one of the lane's three protocols")
	}
	spec, err := parseRewriteSpec(protocol, slots, rewrite)
	if err != nil {
		return nil, "", err
	}
	spec.limits = limits
	receivedBody, err := bodyObject(received, stackPartReceived)
	if err != nil {
		return nil, "", err
	}
	forwardedBody, err := bodyObject(forwarded, stackPartForwarded)
	if err != nil {
		return nil, "", err
	}
	check := stackChecker{protocol: protocol, spec: spec}
	for _, name := range unionNames(receivedBody.names, forwardedBody.names, spec.required) {
		received, forwarded := receivedBody.members[name], forwardedBody.members[name]
		mark := len(check.modified)
		path := check.member(name, received, forwarded)
		if path != "" && spec.relayChanges && !check.keeps(name) {
			// A difference the rules do not cover is the relay's change (stack_changes.go), unless it touches
			// a kept limit inside the member.
			check.modified = check.modified[:mark]
			path = check.changed(name, "/"+pointerToken(name), received, forwarded)
		}
		if path != "" {
			if cut, ok := fitRefusalPath(path); ok {
				return nil, cut, nil
			}
			// No token fits: the refusal names the whole body. The seam has no non-empty pointer for
			// that, and an empty refusedPath means accepted, so it travels as an error, which the
			// listener answers as a refusal without a path (S32; attempt.refused's path is optional).
			return nil, "", stackCheckErr(stackPartForwarded, "differs at a member whose name is longer than a receipt path")
		}
	}
	// S26 body_jcs_sha256 is exactly digestStackBody's value (stackJCSSHA256 is its body): the customer's
	// check computes the same over its replay (@gray/lane's stackBodyDigest). The forwarded body passed
	// the strict gate, so this is the SHA-256 of its comparison form.
	answer, err := check.encode(stackJCSSHA256(forwarded))
	if err != nil {
		return nil, "", stackCheckErr(stackPartRewrite, "the accepted ops could not be written")
	}
	return answer, "", nil
}

func bodyObject(body []byte, part string) (stackObject, error) {
	if checkStrictJSON(body) != nil {
		return stackObject{}, stackCheckErr(part, "not one strict JSON text")
	}
	object, ok := objectOf(jsontext.Value(bytes.TrimSpace(body)))
	if !ok {
		return stackObject{}, stackCheckErr(part, "not a JSON object")
	}
	return object, nil
}

// ---------------------------------------------------------------------------------------------------
// The RewriteSpec.
// ---------------------------------------------------------------------------------------------------

// stackRewriteSpec is a parsed RewriteSpec, every member already held to the policy.
type stackRewriteSpec struct {
	modelTo  jsontext.Value                      // the JCS text of model.to
	capField string                              // "" when there is no cap
	capMax   uint64                              //
	top      map[string]stackPathRule            // one-token set/remove rules, by member name
	nested   map[string]map[string]stackPathRule // two-token rules, by parent then child name
	slots    stackAppendSlots                    //
	appends  []stackAppendEntry                  //
	limits   stackAppendLimits                   //
	required []string                            // top-level names a refusal search visits even when absent
	// relayChanges is the spec's `relay_changes`: the entry records the relay's own changes in the receipt
	// (relay_stack.changed), so a difference outside the rules is one, not a refusal (stack_changes.go).
	relayChanges bool
}

// stackPathRule is a set (value is the JCS text it writes) or a removal.
type stackPathRule struct {
	remove bool
	value  jsontext.Value
}

// stackAppendEntry is one registered text the relay may append: its id, where, and its UTF-8 byte
// length and SHA-256 (the text itself is the relay's published template, not egress's).
type stackAppendEntry struct {
	templateID string
	position   string
	start      bool
	bytes      int
	sum        [sha256.Size]byte
}

// validTemplateID is @gray/lane's TEMPLATE_ID: /^[A-Za-z0-9_.:-]{1,128}$/.
func validTemplateID(id string) bool {
	if id == "" || len(id) > stackTemplateIDMax {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("_.:-", c) >= 0) {
			return false
		}
	}
	return true
}

func parseRewriteSpec(protocol string, slots stackAppendSlots, rewrite json.RawMessage) (*stackRewriteSpec, error) {
	bad := func(reason string) (*stackRewriteSpec, error) {
		return nil, stackCheckErr(stackPartRewrite, reason)
	}
	if checkStrictJSON(rewrite) != nil {
		return bad("not one strict JSON text")
	}
	root, ok := objectOf(jsontext.Value(bytes.TrimSpace(rewrite)))
	if !ok {
		return bad("not a JSON object")
	}
	spec := &stackRewriteSpec{
		top:    map[string]stackPathRule{},
		nested: map[string]map[string]stackPathRule{},
		slots:  slots,
	}
	paths := map[string]bool{}
	addPath := func(path string, tokens []string, rule stackPathRule) bool {
		if paths[path] {
			return false
		}
		paths[path] = true
		if len(tokens) == 1 {
			spec.top[tokens[0]] = rule
			return true
		}
		if spec.nested[tokens[0]] == nil {
			spec.nested[tokens[0]] = map[string]stackPathRule{}
		}
		spec.nested[tokens[0]][tokens[1]] = rule
		return true
	}
	for _, name := range root.names {
		value := root.members[name]
		switch name {
		case "model":
			model, ok := objectOf(value)
			if !ok || !exactMembers(model, "to") {
				return bad("model is not {to}")
			}
			to := model.members["to"]
			if _, ok := stringOf(to); !ok || !stackRewritePolicy.allows(protocol, "set_member", "/model", to) {
				return bad("model.to is not a model the policy allows")
			}
			spec.modelTo = jsontext.Value(canonicalText(to))
		case "cap":
			capSpec, ok := objectOf(value)
			if !ok || !exactMembers(capSpec, "field", "max") {
				return bad("cap is not {field, max}")
			}
			field, ok := stringOf(capSpec.members["field"])
			if !ok || field == "" {
				return bad("cap.field is not a member name")
			}
			path := "/" + pointerToken(field)
			rule, ok := stackRewritePolicy.rule(protocol, "set_member", path)
			if !ok || rule.kind != "integer" {
				return bad("cap.field is not an output cap of the protocol")
			}
			capMax := jsontext.Value(canonicalText(capSpec.members["max"]))
			if !stackRewritePolicy.allows(protocol, "set_member", path, capMax) {
				return bad("cap.max is outside the policy's integer range")
			}
			spec.capField = field
			spec.capMax, _ = strconv.ParseUint(string(capMax), 10, 64)
			paths[path] = true
		case "set":
			entries, ok := elementsOf(value)
			if !ok {
				return bad("set is not an array")
			}
			for _, entry := range entries {
				item, ok := objectOf(entry)
				if !ok || !exactMembers(item, "path", "value") {
					return bad("a set entry is not {path, value}")
				}
				path, ok := stringOf(item.members["path"])
				if !ok {
					return bad("a set path is not a string")
				}
				tokens, ok := parseStackPointer(path)
				if !ok {
					return bad("a set path is not a supported JSON pointer")
				}
				written := jsontext.Value(canonicalText(item.members["value"]))
				if rule, ok := stackRewritePolicy.rule(protocol, "set_member", path); !ok || rule.kind != "const" || !stackRewritePolicy.allows(protocol, "set_member", path, written) {
					return bad("a set entry is not a fixed value the policy publishes")
				}
				if !addPath(path, tokens, stackPathRule{value: written}) {
					return bad("a path appears twice")
				}
			}
		case "remove":
			entries, ok := elementsOf(value)
			if !ok {
				return bad("remove is not an array")
			}
			for _, entry := range entries {
				path, ok := stringOf(entry)
				if !ok {
					return bad("a remove path is not a string")
				}
				tokens, ok := parseStackPointer(path)
				if !ok {
					return bad("a remove path is not a supported JSON pointer")
				}
				if !stackRewritePolicy.allows(protocol, "remove_member", path, nil) {
					return bad("a remove path is not one the policy publishes")
				}
				if !addPath(path, tokens, stackPathRule{remove: true}) {
					return bad("a path appears twice")
				}
			}
		case "relay_changes":
			switch canonicalText(value) {
			case "true":
				spec.relayChanges = true
			case "false":
			default:
				return bad("relay_changes is not a boolean")
			}
		case "append":
			entries, ok := elementsOf(value)
			if !ok {
				return bad("append is not an array")
			}
			if len(entries) > stackAppendMaxEntries {
				return bad("append has more than 64 entries")
			}
			for _, entry := range entries {
				item, ok := objectOf(entry)
				if !ok || !exactMembers(item, "template_id", "position", "sha256", "bytes") {
					return bad("an append entry is not {template_id, position, sha256, bytes}")
				}
				templateID, ok := stringOf(item.members["template_id"])
				if !ok || !validTemplateID(templateID) {
					return bad("an append template_id is not a template id")
				}
				position, ok := stringOf(item.members["position"])
				if !ok || (position != slots.start && position != slots.end) {
					return bad("an append position is not one of the protocol's two")
				}
				parsed := stackAppendEntry{templateID: templateID, position: position, start: position == slots.start}
				digest, ok := stringOf(item.members["sha256"])
				if !ok || len(digest) != 2*sha256.Size || !isLowerHex(digest) { // isLowerHex: stack_control.go
					return bad("an append sha256 is not 64 lower-case hex digits")
				}
				_, _ = hex.Decode(parsed.sum[:], []byte(digest))
				// A registered text is non-empty (@gray/lane refuses an empty template). A length
				// above the request's byte limit is a template that can never fit, not a bad spec.
				size, err := strconv.ParseUint(canonicalText(item.members["bytes"]), 10, 31)
				if err != nil || size == 0 {
					return bad("an append bytes is not a positive integer")
				}
				parsed.bytes = int(size)
				for _, seen := range spec.appends {
					if seen.templateID == parsed.templateID {
						return bad("an append template_id appears twice")
					}
					if seen.position == parsed.position && seen.sum == parsed.sum {
						return bad("an append text appears twice at one position")
					}
				}
				spec.appends = append(spec.appends, parsed)
			}
		default:
			return bad("unknown member")
		}
	}
	if spec.modelTo == nil {
		return bad("model is missing")
	}
	// One rule per top-level member: the policy keeps the model, the cap, the append target and the
	// set/remove paths apart today, and this keeps a future policy from making one member two rules.
	for name := range spec.nested {
		if _, ok := spec.top[name]; ok || name == "model" || name == spec.capField || name == slots.target {
			return bad("a path appears twice")
		}
	}
	for name := range spec.top {
		if name == "model" || name == slots.target {
			return bad("a path appears twice")
		}
	}
	spec.required = []string{"model"}
	for name, rule := range spec.top {
		if !rule.remove {
			spec.required = append(spec.required, name)
		}
	}
	for parent, children := range spec.nested {
		for _, rule := range children {
			if !rule.remove {
				spec.required = append(spec.required, parent)
				break
			}
		}
	}
	return spec, nil
}

// exactMembers is whether object has exactly the given member names.
func exactMembers(object stackObject, names ...string) bool {
	if len(object.names) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object.members[name]; !ok {
			return false
		}
	}
	return true
}

// fitRefusalPath cuts a refusal path to the whole reference tokens that fit in stackPointerMaxLength
// UTF-16 code units, the receipt's bound on a path (@gray/attest's attempt.refused, S32): a member name
// the relay chose has no length of its own. A cut path names the container the difference is in. It
// reports false when not even the first token fits.
func fitRefusalPath(path string) (string, bool) {
	if utf16Length(path) <= stackPointerMaxLength {
		return path, true
	}
	cut, units := "", 0
	for _, token := range strings.Split(path[1:], "/") {
		next := 1 + utf16Length(token)
		if units+next > stackPointerMaxLength {
			break
		}
		cut += "/" + token
		units += next
	}
	return cut, cut != ""
}

// utf16Length is the length of s in UTF-16 code units, the unit JavaScript strings and the receipt
// schema count in.
func utf16Length(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// parseStackPointer is @gray/lane's parseJsonPointer: an absolute RFC 6901 pointer of one or two
// non-empty tokens, at most stackPointerMaxLength UTF-16 code units, with only ~0 and ~1 escapes. It
// returns the decoded tokens.
func parseStackPointer(path string) ([]string, bool) {
	if !strings.HasPrefix(path, "/") || utf16Length(path) > stackPointerMaxLength {
		return nil, false
	}
	raw := strings.Split(path[1:], "/")
	if len(raw) > 2 {
		return nil, false
	}
	tokens := make([]string, 0, len(raw))
	for _, part := range raw {
		if part == "" {
			return nil, false
		}
		var token strings.Builder
		for i := 0; i < len(part); i++ {
			if part[i] != '~' {
				token.WriteByte(part[i])
				continue
			}
			if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
				return nil, false
			}
			if part[i+1] == '0' {
				token.WriteByte('~')
			} else {
				token.WriteByte('/')
			}
			i++
		}
		tokens = append(tokens, token.String())
	}
	return tokens, true
}

// ---------------------------------------------------------------------------------------------------
// The comparison.
// ---------------------------------------------------------------------------------------------------

type stackChecker struct {
	protocol string
	spec     *stackRewriteSpec
	modified []stackModifiedOp
	appended []stackAppendEntry
	// The relay's changes outside the declared rules (stack_changes.go): the entries kept, the byte totals of
	// all of them, the count past stackChangeKeepMax, and whether a value was too long to keep.
	changes       []stackChange
	addedBytes    int64
	removedBytes  int64
	omitted       int
	valuesOmitted bool
}

type stackModifiedOp struct {
	op    string
	path  string
	value jsontext.Value // nil for remove_member
}

// member checks one top-level member (nil is absent) and answers the refusal path, or "".
func (c *stackChecker) member(name string, received, forwarded jsontext.Value) string {
	path := "/" + pointerToken(name)
	spec := c.spec
	if rule, ok := spec.top[name]; ok {
		return c.pathRule(path, rule, received, forwarded)
	}
	if children, ok := spec.nested[name]; ok {
		return c.nestedRules(path, children, received, forwarded)
	}
	switch {
	case name == "model":
		return c.pathRule(path, stackPathRule{value: spec.modelTo}, received, forwarded)
	case spec.capField != "" && name == spec.capField:
		return c.capped(path, received, forwarded)
	case name == spec.slots.target && len(spec.appends) > 0:
		return c.appendedTo(path, received, forwarded)
	}
	return firstDifference(path, received, forwarded)
}

// modify records an op the policy allows, or answers path as the refusal.
func (c *stackChecker) modify(op, path string, value jsontext.Value) string {
	if !stackRewritePolicy.allows(c.protocol, op, path, value) {
		return path
	}
	c.modified = append(c.modified, stackModifiedOp{op: op, path: path, value: value})
	return ""
}

// pathRule applies a set (the forwarded value must be the rule's) or a removal (absent or unchanged).
func (c *stackChecker) pathRule(path string, rule stackPathRule, received, forwarded jsontext.Value) string {
	if rule.remove {
		switch {
		case received == nil && forwarded == nil:
			return ""
		case received == nil:
			return path
		case forwarded == nil:
			return c.modify("remove_member", path, nil)
		}
		return firstDifference(path, received, forwarded)
	}
	if forwarded == nil || canonicalText(forwarded) != string(rule.value) {
		return path
	}
	switch {
	case received == nil:
		return c.modify("insert_member", path, rule.value)
	case !sameStackJSON(received, forwarded):
		return c.modify("set_member", path, rule.value)
	}
	return ""
}

// capped applies cap {field, max} to the member at path.
func (c *stackChecker) capped(path string, received, forwarded jsontext.Value) string {
	switch {
	case received == nil && forwarded == nil:
		return ""
	case forwarded == nil:
		return path
	case received != nil && sameStackJSON(received, forwarded):
		return ""
	}
	written := jsontext.Value(canonicalText(forwarded))
	n, err := strconv.ParseUint(string(written), 10, 64)
	if err != nil || n > c.spec.capMax {
		return path
	}
	if received == nil {
		return c.modify("insert_member", path, written)
	}
	// S32: a cap is lowered, never raised past the customer's own value. Only a plain integer token is
	// compared; any other spelling of the customer's value cannot be bounded exactly, so it stays.
	if client, err := strconv.ParseUint(string(received), 10, 64); err != nil || n > client {
		return path
	}
	return c.modify("set_member", path, written)
}

// nestedRules applies the two-token rules under one top-level member.
func (c *stackChecker) nestedRules(path string, children map[string]stackPathRule, received, forwarded jsontext.Value) string {
	var names, setNames []string
	for name, rule := range children {
		names = append(names, name)
		if !rule.remove {
			setNames = append(setNames, name)
		}
	}
	slices.SortFunc(names, compareUTF16)
	slices.SortFunc(setNames, compareUTF16)
	missing := ""
	if len(setNames) > 0 {
		missing = path + "/" + pointerToken(setNames[0])
	}
	receivedObject, receivedIsObject := objectOf(received)
	forwardedObject, forwardedIsObject := objectOf(forwarded)
	switch {
	case received == nil && forwarded == nil:
		return missing
	case received == nil:
		// The parent was inserted: only as exactly the object of the set children, which the policy
		// publishes for Chat's stream_options.
		if missing == "" || !forwardedIsObject {
			return path
		}
		inserted := map[string]jsontext.Value{}
		for _, name := range setNames {
			inserted[name] = children[name].value
		}
		expected := canonicalObject(setNames, inserted)
		if canonicalText(forwarded) != string(expected) {
			return path
		}
		return c.modify("insert_member", path, expected)
	case forwarded == nil:
		// The parent was removed: only by removing every member it had, each under a removal rule.
		if missing != "" {
			return missing
		}
		if !receivedIsObject || len(receivedObject.names) == 0 {
			return path
		}
		for _, name := range receivedObject.names {
			if rule, ok := children[name]; !ok || !rule.remove {
				return path
			}
		}
		for _, name := range receivedObject.names {
			if refused := c.modify("remove_member", path+"/"+pointerToken(name), nil); refused != "" {
				return refused
			}
		}
		return ""
	case !forwardedIsObject:
		if missing != "" {
			return missing
		}
		return firstDifference(path, received, forwarded)
	case !receivedIsObject:
		// No published op changes the parent's type.
		return path
	}
	removed := false
	for _, name := range unionNames(receivedObject.names, forwardedObject.names, setNames) {
		childPath := path + "/" + pointerToken(name)
		receivedChild, forwardedChild := receivedObject.members[name], forwardedObject.members[name]
		rule, ok := children[name]
		var refused string
		if ok {
			removed = removed || (rule.remove && receivedChild != nil && forwardedChild == nil)
			refused = c.pathRule(childPath, rule, receivedChild, forwardedChild)
		} else {
			refused = firstDifference(childPath, receivedChild, forwardedChild)
		}
		if refused != "" {
			return refused
		}
	}
	if removed && len(forwardedObject.names) == 0 {
		// The published removal takes an emptied parent with it; a kept empty parent does not replay.
		return path
	}
	return ""
}

// canonicalObject is the JCS text of the object holding members (each a JCS text) under names.
func canonicalObject(names []string, members map[string]jsontext.Value) jsontext.Value {
	text := []byte{'{'}
	for i, name := range names {
		if i > 0 {
			text = append(text, ',')
		}
		text = append(text, quoteJSON(name)...)
		text = append(text, ':')
		text = append(text, members[name]...)
	}
	text = append(text, '}')
	return jsontext.Value(canonicalText(text))
}

// ---------------------------------------------------------------------------------------------------
// Appends.
// ---------------------------------------------------------------------------------------------------

// appendedTo checks the protocol's append target: a difference there must be registered texts in F's
// value shapes, and nothing else.
func (c *stackChecker) appendedTo(path string, received, forwarded jsontext.Value) string {
	if received == nil && forwarded == nil {
		return ""
	}
	if received != nil && forwarded != nil && sameStackJSON(received, forwarded) {
		return ""
	}
	uses, ok := c.matchAppends(received, forwarded)
	if !ok {
		if refused := firstDifference(path, received, forwarded); refused != "" {
			return refused
		}
		return path
	}
	c.appended = uses
	return ""
}

func (c *stackChecker) matchAppends(received, forwarded jsontext.Value) ([]stackAppendEntry, bool) {
	entries, limits := c.spec.appends, c.spec.limits
	switch c.protocol {
	case protocolAnthropicMessages:
		forwardedBlocks, forwardedIsArray := elementsOf(forwarded)
		if received == nil {
			if !forwardedIsArray {
				return nil, false
			}
			return matchElements(entries, limits, nil, forwardedBlocks, 0, anthropicTextBlock)
		}
		if text, ok := stringOf(received); ok {
			if forwardedText, ok := stringOf(forwarded); ok {
				return matchText(entries, limits, text, forwardedText)
			}
			return nil, false
		}
		receivedBlocks, ok := elementsOf(received)
		if !ok || !forwardedIsArray {
			return nil, false
		}
		return matchElements(entries, limits, receivedBlocks, forwardedBlocks, len(receivedBlocks), anthropicTextBlock)
	case protocolOpenAIChat:
		receivedMessages, ok := elementsOf(received)
		forwardedMessages, forwardedIsArray := elementsOf(forwarded)
		if !ok || !forwardedIsArray {
			return nil, false
		}
		// F puts instructions_after after the last leading system/developer message, and both
		// groups at the front when there is none; it refuses a messages array holding a non-object.
		after, leading := 0, true
		for index, message := range receivedMessages {
			object, ok := objectOf(message)
			if !ok {
				return nil, false
			}
			role, _ := stringOf(object.members["role"])
			if leading && (role == "system" || role == "developer") {
				after = index + 1
			} else {
				leading = false
			}
		}
		return matchElements(entries, limits, receivedMessages, forwardedMessages, after, chatDeveloperMessage)
	case protocolOpenAIResponses:
		forwardedText, ok := stringOf(forwarded)
		if !ok {
			return nil, false
		}
		if received == nil {
			return matchText(entries, limits, "", forwardedText)
		}
		text, ok := stringOf(received)
		if !ok {
			return nil, false
		}
		return matchText(entries, limits, text, forwardedText)
	}
	return nil, false
}

// anthropicTextBlock is the text of exactly {"type":"text","text":T}, the block F appends.
func anthropicTextBlock(element jsontext.Value) (string, bool) {
	object, ok := objectOf(element)
	if !ok || !exactMembers(object, "type", "text") {
		return "", false
	}
	if kind, ok := stringOf(object.members["type"]); !ok || kind != "text" {
		return "", false
	}
	return stringOf(object.members["text"])
}

// chatDeveloperMessage is the text of exactly {"role":"developer","content":T}, the message F appends.
func chatDeveloperMessage(element jsontext.Value) (string, bool) {
	object, ok := objectOf(element)
	if !ok || !exactMembers(object, "role", "content") {
		return "", false
	}
	if role, ok := stringOf(object.members["role"]); !ok || role != "developer" {
		return "", false
	}
	return stringOf(object.members["content"])
}

// appendTally takes registered entries for appended texts, each entry at most once.
type appendTally struct {
	entries []stackAppendEntry
	used    uint64
	bytes   int
	uses    []stackAppendEntry
}

// take marks the unused entry of the given side whose length and digest are text's. The spec holds
// no two entries with one text at one position, so there is at most one.
func (t *appendTally) take(start bool, text string) bool {
	if text == "" {
		return false
	}
	sum := sha256.Sum256([]byte(text))
	for index, entry := range t.entries {
		if entry.start == start && t.used&(1<<index) == 0 && entry.bytes == len(text) && entry.sum == sum {
			t.used |= 1 << index
			t.bytes += len(text)
			t.uses = append(t.uses, entry)
			return true
		}
	}
	return false
}

// matchElements finds forwarded = S ++ received[:at] ++ E ++ received[at:], where S and E are
// elements textOf reads as registered texts of the start and end positions. The first split (fewest
// start elements) that holds wins; any split that holds replays to the same value.
func matchElements(entries []stackAppendEntry, limits stackAppendLimits, received, forwarded []jsontext.Value, at int, textOf func(jsontext.Value) (string, bool)) ([]stackAppendEntry, bool) {
	added := len(forwarded) - len(received)
	if added < 1 || added > limits.maxItems {
		return nil, false
	}
	// Each split compares the same elements again; a relay that re-serializes the body would make
	// every comparison a canonicalization, so each element's JCS text is computed once.
	receivedText := make([]string, len(received))
	forwardedText := make([]string, len(forwarded))
	textAt := func(texts []string, values []jsontext.Value, index int) string {
		if texts[index] == "" {
			texts[index] = canonicalText(values[index])
		}
		return texts[index]
	}
	same := func(r, f int) bool {
		if bytes.Equal(received[r], forwarded[f]) {
			return true
		}
		text := textAt(receivedText, received, r)
		return text != "" && text == textAt(forwardedText, forwarded, f)
	}
	for before := 0; before <= added; before++ {
		after := added - before
		ok := true
		for index := 0; ok && index < at; index++ {
			ok = same(index, before+index)
		}
		for index := at; ok && index < len(received); index++ {
			ok = same(index, before+after+index)
		}
		if !ok {
			continue
		}
		tally := appendTally{entries: entries}
		for index := 0; ok && index < before; index++ {
			text, isText := textOf(forwarded[index])
			ok = isText && tally.take(true, text)
		}
		for index := before + at; ok && index < before+at+after; index++ {
			text, isText := textOf(forwarded[index])
			ok = isText && tally.take(false, text)
		}
		if ok && tally.bytes <= limits.maxBytes {
			return tally.uses, true
		}
	}
	return nil, false
}

// matchText finds forwarded = S + received + E, where S and E are concatenations of registered texts
// of the start and end positions (F concatenates the texts of one position with no separator). Each
// entry's byte length says where its text would end, so at a boundary the search hashes only the
// substring of that length for each candidate entry, and each (boundary, entry) pair at most once.
// The appended bytes are len(forwarded) - len(received), at most the byte limit, so every boundary
// lies within that many bytes of an end of the text.
func matchText(entries []stackAppendEntry, limits stackAppendLimits, received, forwarded string) ([]stackAppendEntry, bool) {
	extra := len(forwarded) - len(received)
	if extra < 1 || extra > limits.maxBytes {
		return nil, false
	}
	search := textSearch{
		entries:   entries,
		maxItems:  limits.maxItems,
		received:  received,
		forwarded: forwarded,
		lastStart: strings.LastIndex(forwarded, received),
		hashed:    map[textCandidate]bool{},
		failed:    map[textState]bool{},
	}
	if search.lastStart < 0 || !search.from(textState{}) {
		return nil, false
	}
	return search.uses, true
}

type textState struct {
	at    int
	after bool // the received text is placed; only end texts follow
	used  uint64
}

// textCandidate is one entry's text tried at one boundary.
type textCandidate struct {
	at    int
	entry int
}

type textSearch struct {
	entries   []stackAppendEntry
	maxItems  int
	received  string
	forwarded string
	lastStart int // the last offset the received text occurs at: start texts end at or before it
	hashed    map[textCandidate]bool
	failed    map[textState]bool
	uses      []stackAppendEntry
}

// fits is whether entries[index]'s text is the substring at at of its length, ending at or before limit.
func (s *textSearch) fits(at, index, limit int) bool {
	end := at + s.entries[index].bytes
	if end > limit {
		return false
	}
	key := textCandidate{at: at, entry: index}
	found, ok := s.hashed[key]
	if !ok {
		found = sha256.Sum256([]byte(s.forwarded[at:end])) == s.entries[index].sum
		s.hashed[key] = found
	}
	return found
}

func (s *textSearch) from(state textState) bool {
	if state.after && state.at == len(s.forwarded) {
		return true
	}
	if s.failed[state] {
		return false
	}
	if !state.after && strings.HasPrefix(s.forwarded[state.at:], s.received) {
		if s.from(textState{at: state.at + len(s.received), after: true, used: state.used}) {
			return true
		}
	}
	if bits.OnesCount64(state.used) < s.maxItems {
		limit := len(s.forwarded)
		if !state.after {
			limit = s.lastStart
		}
		for index, entry := range s.entries {
			if entry.start == state.after || state.used&(1<<index) != 0 || !s.fits(state.at, index, limit) {
				continue
			}
			s.uses = append(s.uses, entry)
			if s.from(textState{at: state.at + entry.bytes, after: state.after, used: state.used | 1<<index}) {
				return true
			}
			s.uses = s.uses[:len(s.uses)-1]
		}
	}
	s.failed[state] = true
	return false
}

// ---------------------------------------------------------------------------------------------------
// The answer.
// ---------------------------------------------------------------------------------------------------

// encode writes the answer, {"ops":[…],"appended":[…],"forwarded_jcs_sha256":"…"}:
//   - ops: one `request.modified` per member edit in the order found, in @gray/attest's shape (type,
//     op, path, value for a set or insert, declared_in);
//   - appended: one @gray/attest `RelayAppend` {template_id, position, text_sha256} per appended text
//     in application order (start texts in order, then end texts), the `appended` of S26's
//     `relay_stack.appended`. F groups the texts by position, so this order replays to the same bytes;
//   - forwarded_jcs_sha256: lower hex SHA-256 of the forwarded body's JCS form (S26 `body_jcs_sha256`).
func (c *stackChecker) encode(forwardedJCSSHA256 string) (json.RawMessage, error) {
	var out bytes.Buffer
	enc := jsontext.NewEncoder(&out)
	var err error
	write := func(tokens ...jsontext.Token) {
		for _, token := range tokens {
			if err == nil {
				err = enc.WriteToken(token)
			}
		}
	}
	write(jsontext.BeginObject, jsontext.String("ops"), jsontext.BeginArray)
	for _, op := range c.modified {
		write(jsontext.BeginObject,
			jsontext.String("type"), jsontext.String("request.modified"),
			jsontext.String("op"), jsontext.String(op.op),
			jsontext.String("path"), jsontext.String(op.path))
		if op.value != nil {
			write(jsontext.String("value"))
			if err == nil {
				err = enc.WriteValue(op.value)
			}
		}
		write(jsontext.String("declared_in"), jsontext.String(stackRewritePolicy.id), jsontext.EndObject)
	}
	write(jsontext.EndArray, jsontext.String("appended"), jsontext.BeginArray)
	for _, entry := range c.appended {
		write(jsontext.BeginObject,
			jsontext.String("template_id"), jsontext.String(entry.templateID),
			jsontext.String("position"), jsontext.String(entry.position),
			jsontext.String("text_sha256"), jsontext.String(hex.EncodeToString(entry.sum[:])),
			jsontext.EndObject)
	}
	write(jsontext.EndArray)
	if changed := c.bodyChanged(); changed != nil {
		write(jsontext.String("changed"))
		if err == nil {
			err = enc.WriteValue(jsontext.Value(marshalStackChanged(*changed)))
		}
	}
	write(jsontext.String("forwarded_jcs_sha256"), jsontext.String(forwardedJCSSHA256), jsontext.EndObject)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSuffix(out.Bytes(), []byte("\n"))), nil
}
