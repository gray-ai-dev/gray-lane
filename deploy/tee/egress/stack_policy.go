package main

// The published lane rewrite policy, GRAY_LANE_REWRITES_V1, as the relay-stack request check (S18)
// reads it. gray-lane-rewrites-v1.json in this directory is a byte copy of
// workers/packages/lane/policy/gray-lane-rewrites-v1.json (the Docker build copies only this
// directory); stack_policy_test.go fails when the two differ.
//
// The check holds every op it reports to this policy, the same rule @gray/lane's
// verifyForwardedWithChanges runs on a receipt: a RewriteSpec member the policy does not allow for
// the protocol is a malformed spec, and an op the policy does not allow (an insert where only a set
// is published, say) is a refusal. So every `request.modified` op the check returns names a rule of
// `declared_in`.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"unicode/utf8"
)

//go:embed gray-lane-rewrites-v1.json
var stackPolicyJSON []byte

// The lane's three protocols (@gray/lane protocol.ts), and per protocol the append target member and
// its two positions (@gray/attest RELAY_APPEND_POSITIONS, @gray/lane POSITIONS_BY_PROTOCOL).
const (
	protocolAnthropicMessages = "anthropic_messages"
	protocolOpenAIChat        = "open_ai_chat"
	protocolOpenAIResponses   = "open_ai_responses"
)

type stackAppendSlots struct {
	target string // the member F writes: system, messages, instructions
	start  string
	end    string
}

var stackAppendSlotsByProtocol = map[string]stackAppendSlots{
	protocolAnthropicMessages: {target: "system", start: "system_start", end: "system_end"},
	protocolOpenAIChat:        {target: "messages", start: "instructions_before", end: "instructions_after"},
	protocolOpenAIResponses:   {target: "instructions", start: "instructions_before", end: "instructions_after"},
}

// stackPolicy is the parsed document: per protocol, the rule for each "op path".
type stackPolicy struct {
	id        string
	protocols map[string]map[string]stackPolicyRule
}

// stackPolicyRule is one `{op, path, value?}`; kind is "" exactly for remove_member.
type stackPolicyRule struct {
	kind          string // "string", "integer", "const"
	minBytes      int
	maxBytes      int
	forbidControl bool
	min, max      uint64
	value         string // the const's JCS text
}

type wirePolicy struct {
	ID        string                      `json:"id"`
	Version   int                         `json:"version"`
	Protocols map[string][]wirePolicyRule `json:"protocols"`
}

type wirePolicyRule struct {
	Op    string           `json:"op"`
	Path  string           `json:"path"`
	Value *wirePolicyValue `json:"value"`
}

type wirePolicyValue struct {
	Kind          string          `json:"kind"`
	MinBytes      *int            `json:"min_bytes"`
	MaxBytes      *int            `json:"max_bytes"`
	ForbidControl *bool           `json:"forbid_control"`
	Min           *uint64         `json:"min"`
	Max           *uint64         `json:"max"`
	Value         json.RawMessage `json:"value"`
}

// stackRewritePolicy is loaded once; a document this program cannot read is a start-up failure, not
// a policy that allows nothing.
var stackRewritePolicy = mustLoadStackPolicy(stackPolicyJSON)

func mustLoadStackPolicy(document []byte) stackPolicy {
	policy, err := loadStackPolicy(document)
	if err != nil {
		panic("gray-lane-rewrites-v1.json: " + err.Error())
	}
	return policy
}

func loadStackPolicy(document []byte) (stackPolicy, error) {
	if err := checkStrictJSON(document); err != nil {
		return stackPolicy{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.DisallowUnknownFields()
	var wire wirePolicy
	if err := dec.Decode(&wire); err != nil {
		return stackPolicy{}, err
	}
	if wire.ID == "" || wire.Version < 1 {
		return stackPolicy{}, fmt.Errorf("no id or version")
	}
	policy := stackPolicy{id: wire.ID, protocols: map[string]map[string]stackPolicyRule{}}
	for protocol := range stackAppendSlotsByProtocol {
		list, ok := wire.Protocols[protocol]
		if !ok {
			return stackPolicy{}, fmt.Errorf("protocol %s is missing", protocol)
		}
		rules := map[string]stackPolicyRule{}
		for _, entry := range list {
			if _, ok := parseStackPointer(entry.Path); !ok {
				return stackPolicy{}, fmt.Errorf("%s: unsupported path", protocol)
			}
			rule, err := parsePolicyRule(entry)
			if err != nil {
				return stackPolicy{}, fmt.Errorf("%s %s %s: %w", protocol, entry.Op, entry.Path, err)
			}
			key := entry.Op + " " + entry.Path
			if _, seen := rules[key]; seen {
				return stackPolicy{}, fmt.Errorf("%s: repeated rule", protocol)
			}
			rules[key] = rule
		}
		policy.protocols[protocol] = rules
	}
	if len(wire.Protocols) != len(policy.protocols) {
		return stackPolicy{}, fmt.Errorf("unknown protocol")
	}
	return policy, nil
}

func parsePolicyRule(entry wirePolicyRule) (stackPolicyRule, error) {
	switch entry.Op {
	case "remove_member":
		if entry.Value != nil {
			return stackPolicyRule{}, fmt.Errorf("a removal carries a value rule")
		}
		return stackPolicyRule{}, nil
	case "set_member", "insert_member":
	default:
		return stackPolicyRule{}, fmt.Errorf("unknown op")
	}
	value := entry.Value
	if value == nil {
		return stackPolicyRule{}, fmt.Errorf("no value rule")
	}
	switch value.Kind {
	case "string":
		if value.MinBytes == nil || value.MaxBytes == nil || value.ForbidControl == nil || *value.MinBytes < 0 || *value.MaxBytes < *value.MinBytes {
			return stackPolicyRule{}, fmt.Errorf("bad string rule")
		}
		return stackPolicyRule{kind: "string", minBytes: *value.MinBytes, maxBytes: *value.MaxBytes, forbidControl: *value.ForbidControl}, nil
	case "integer":
		if value.Min == nil || value.Max == nil || *value.Max < *value.Min {
			return stackPolicyRule{}, fmt.Errorf("bad integer rule")
		}
		return stackPolicyRule{kind: "integer", min: *value.Min, max: *value.Max}, nil
	case "const":
		canonical := canonicalText(jsontext.Value(value.Value))
		if canonical == "" {
			return stackPolicyRule{}, fmt.Errorf("bad const rule")
		}
		return stackPolicyRule{kind: "const", value: canonical}, nil
	}
	return stackPolicyRule{}, fmt.Errorf("unknown value kind")
}

// rule is the policy's rule for op on path in protocol.
func (p stackPolicy) rule(protocol, op, path string) (stackPolicyRule, bool) {
	rule, ok := p.protocols[protocol][op+" "+path]
	return rule, ok
}

// allows is @gray/lane's ruleAllowsValue: whether the policy allows op on path with value (nil for a
// removal). value is a JCS text.
func (p stackPolicy) allows(protocol, op, path string, value jsontext.Value) bool {
	rule, ok := p.rule(protocol, op, path)
	if !ok {
		return false
	}
	if op == "remove_member" {
		return value == nil
	}
	if value == nil {
		return false
	}
	switch rule.kind {
	case "string":
		text, ok := stringOf(value)
		if !ok || !utf8.ValidString(text) || len(text) < rule.minBytes || len(text) > rule.maxBytes {
			return false
		}
		if rule.forbidControl {
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] == 0x7f {
					return false
				}
			}
		}
		return true
	case "integer":
		// An integer the receipt can carry, written as plain digits: the comparison form keeps a number
		// token as written (S32), so any other spelling (an exponent, a fraction, a sign) fails
		// ParseUint and is refused, and the value the op reports is the token the vendor gets.
		n, err := strconv.ParseUint(canonicalText(value), 10, 64)
		return err == nil && n >= rule.min && n <= rule.max
	case "const":
		return canonicalText(value) == rule.value
	}
	return false
}
