package main

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// What egress could not learn of a relay's tunnel traffic, for the relay to see (README "Transport signals"). A relay
// that warms up as its instructions say (deploy/relay/kit/AGENTS.md: one tunnel per TLS configuration before it
// listens, an HTTP/2 client's SETTINGS read before the tunnel closes) has a learned HTTP/2 preface for every shape
// that offers h2, and the three counts stay at 0. These are counts and closed words only, nothing of a request, and
// nothing here changes what egress sends: a call without what egress learned goes out with egress's defaults, as
// before.
//
// `GET $GRAY_EGRESS_URL/v1/relay/transport-health` on the relay listener (read-only, no body or query):
//
//	{"learning": bool, "shapes": [{"h2": bool, "h2_preface": "learned"|"default"|"refused"|"none",
//	  "h2_preface_problem": "…"?, "usable": bool, "shuffles": bool, "vendor": bool, "sign_in": bool}],
//	  "tap_stopped": N, "wire_meta_missing": N, "wire_meta_refused": N}
//
// The counts are since egress started. The lane's `GET /v1/stack/health` does not carry them: its reader in the lane
// (workers/gateway/src/lane/stack-health.ts) takes no field it does not know.

const relayTransportHealthPath = "/v1/relay/transport-health"

// mirrorSignals counts what the tunnels' taps (mirror_http_tap.go) did not record, for the life of the process. A nil
// one counts nothing.
type mirrorSignals struct {
	// tapStopped: taps that stopped recording a tunnel connection (bytes that are not what net/http's server reads,
	// a bound passed, or a fault); the connection's later calls carry no wire record.
	tapStopped atomic.Uint64
	// wireMetaMissing: tunnel calls served without a wire record of their own; they go out in egress's default field
	// order (HTTP/2: the learned preface's pseudo-header template, else Go's).
	wireMetaMissing atomic.Uint64
	// wireMetaRefused: HTTP/2 tunnel calls for which the tap held records but none was the call's; the call went out
	// without one rather than with another stream's (counted in wireMetaMissing too).
	wireMetaRefused atomic.Uint64
}

func (m *mirrorSignals) tapStop() {
	if m != nil {
		m.tapStopped.Add(1)
	}
}

func (m *mirrorSignals) wireMetaRefuse() {
	if m != nil {
		m.wireMetaRefused.Add(1)
	}
}

// wireMeta counts a tunnel call served without a wire record.
func (m *mirrorSignals) wireMeta(meta *wireRequestMeta) {
	if m != nil && meta == nil {
		m.wireMetaMissing.Add(1)
	}
}

type mirrorShapeHealth struct {
	H2 bool `json:"h2"`
	// H2Preface is "learned" once egress read the client's HTTP/2 connection preface for the shape (or another order
	// of its family), "default" when the shape offers h2 and none was read, "refused" when the preface read is one
	// egress does not repeat (H2PrefaceProblem says why), "none" for a shape without h2.
	H2Preface        string `json:"h2_preface"`
	H2PrefaceProblem string `json:"h2_preface_problem,omitempty"`
	// Usable is whether calls with the shape go out; one that offers h2 without a learned preface is refused
	// (stack_hello_refused), never sent with a preface no client sends.
	Usable   bool `json:"usable"`
	Shuffles bool `json:"shuffles"`
	// FullRecords: the client wrote a full first TLS record during learning (mirroredHello.fullRecords).
	FullRecords bool `json:"full_records"`
	// RefundLearned: the client's WINDOW_UPDATE refunds were seen during learning (h2Preface.StreamRefund).
	RefundLearned bool `json:"refund_learned"`
	Vendor        bool `json:"vendor"`
	SignIn        bool `json:"sign_in"`
}

type mirrorTransportHealth struct {
	Learning        bool                `json:"learning"`
	Shapes          []mirrorShapeHealth `json:"shapes"`
	TapStopped      uint64              `json:"tap_stopped"`
	WireMetaMissing uint64              `json:"wire_meta_missing"`
	WireMetaRefused uint64              `json:"wire_meta_refused"`
}

// shapeHealth lists the learned shapes in learning order, and whether learning is open.
func (p *helloProfiles) shapeHealth() ([]mirrorShapeHealth, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]mirrorShapeHealth, 0, len(p.shapes))
	for _, shape := range p.shapes {
		h := mirrorShapeHealth{H2: shape.h2, H2Preface: "none", Usable: shape.usable(), Shuffles: shape.shuffles.Load(),
			FullRecords: shape.fullRecords.Load(), Vendor: shape.seenVendor, SignIn: shape.seenSignIn}
		if pref := shape.h2Preface(); pref != nil {
			h.RefundLearned = pref.StreamRefund != 0 || pref.ConnRefund != 0
		}
		if shape.h2 {
			shape.h2Mu.RLock()
			learned, problem := shape.preface != nil, shape.prefaceProblem
			shape.h2Mu.RUnlock()
			switch {
			case learned:
				h.H2Preface = "learned"
			case problem != "":
				h.H2Preface, h.H2PrefaceProblem = "refused", problem
			default:
				h.H2Preface = "default"
			}
		}
		out = append(out, h)
	}
	return out, !p.frozen
}

func (s *server) transportHealth() mirrorTransportHealth {
	shapes, learning := s.profiles.shapeHealth()
	return mirrorTransportHealth{
		Learning:        learning,
		Shapes:          shapes,
		TapStopped:      s.mirrorSignals.tapStopped.Load(),
		WireMetaMissing: s.mirrorSignals.wireMetaMissing.Load(),
		WireMetaRefused: s.mirrorSignals.wireMetaRefused.Load(),
	}
}

// serveTransportHealth is `GET /v1/relay/transport-health`: a GET without a body or a query; it starts nothing.
func (s *server) serveTransportHealth(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = relayTransportHealthPath
	if r.Method != http.MethodGet || strings.ContainsAny(r.RequestURI, "?#") || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		entry.Error = errMethodRefused
		writeRefusal(rec, errMethodRefused)
		return
	}
	writeControlJSON(rec, s.transportHealth())
}
