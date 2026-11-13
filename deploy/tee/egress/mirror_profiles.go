package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// The handshake shapes egress repeats (README "The relay's TLS handshake reaches the vendor"). A hello the container
// chose while it held a customer's request could carry that request to the account's proxy, which reads a ClientHello
// in the clear. So egress learns shapes only while the container can hold no customer's request, and afterwards a
// tunnel's hello only picks one of the learned shapes:
//
//   - Learning: until the first customer request is registered (`PUT /v1/stack/requests/{rid}`), each tunnel's hello
//     that egress can repeat is kept, at most helloProfilesMax of them. The container has no volume that outlives
//     the VM's boot, so nothing of a customer is in it then; the relay's software opens a tunnel with each handshake
//     it will use when it starts, before it listens.
//   - The end of learning: the first registration egress accepts. Where egress knows the container's listener
//     (relayProbe), a registration made while nothing listens there is refused (503 stack_relay_not_ready; the entry
//     then does not call the container), so a container that is still starting loses no learning to an early request.
//   - After it: a hello with a learned shape's key is that shape; one of a learned family (the same offer, its
//     extensions in another order, as a client that shuffles them sends) gets one of the family's learned shapes, in
//     turn; any other is refused by name. What the container still chooses per vendor connection is one of at most
//     helloProfilesMax shapes: three bits, of the size of the account choice the lane already names.
//   - A family with two or more learned orders is a client that shuffles its extensions: each vendor connection of
//     it gets a fresh order from egress's own randomness (shuffleHelloExtensions), so the vendor sees one order per
//     connection as from the client itself, not a handful of fixed ones; the container still only picks the family.
//
// The shapes and the end of learning are kept on egress's own memory volume (the sign-in key directory: kept across
// an egress restart, new each boot), so a restarted egress does not learn again from a container that holds requests.
//
// This file and mirror_hello.go (with atomic_file.go) need nothing else of egress: the conformance tool compiles them
// into its own checker (deploy/relay/conformance/Dockerfile), so a relay's image meets the same rule before it meets
// a lane. What ends learning in a lane, the first registration and the probe before it, is mirror_admission.go.

const (
	// helloProfilesMax is the most shapes egress learns: the reference ports use one or two (a uTLS preset for one
	// vendor, Go's own for the rest), and a client that shuffles its extensions shows a new one per warm-up tunnel.
	helloProfilesMax  = 8
	helloProfilesFile = "hello-profiles.json"
)

type helloProfiles struct {
	mu     sync.Mutex
	shapes []*mirroredHello
	frozen bool
	// turn is the next learned shape a family's unlearned order gets.
	turn map[string]int
	// file keeps the state across an egress restart; "" keeps it in memory only.
	file string
	// budget is egress's whole budget (-stack-max-bytes) for h2Preface.problem; 0 checks the fixed bounds only.
	budget int64
}

type helloProfilesFileBody struct {
	Frozen bool         `json:"frozen"`
	Hellos [][]byte     `json:"hellos"`
	H2     []*h2Preface `json:"h2,omitempty"`
	Vendor []bool       `json:"vendor,omitempty"`
	SignIn []bool       `json:"signin,omitempty"`
	// FullRecords is each shape's mirroredHello.fullRecords.
	FullRecords []bool `json:"full_records,omitempty"`
}

// newHelloProfilesWithin is newHelloProfiles with egress's budget for the preface check (h2Preface.problem).
func newHelloProfilesWithin(dir string, budget int64) *helloProfiles {
	p := newHelloProfiles(dir)
	p.budget = budget
	return p
}

// newHelloProfiles reads dir's state, or starts learning. A state file that cannot be read is a boot that already
// ran: learning is over and nothing is learned, rather than open again.
func newHelloProfiles(dir string) *helloProfiles {
	p := &helloProfiles{turn: map[string]int{}}
	if dir == "" {
		return p
	}
	p.file = filepath.Join(dir, helloProfilesFile)
	data, err := os.ReadFile(p.file)
	if errors.Is(err, os.ErrNotExist) {
		return p
	}
	var body helloProfilesFileBody
	if err != nil || json.Unmarshal(data, &body) != nil {
		p.frozen = true
		return p
	}
	p.frozen = body.Frozen
	for i, raw := range body.Hellos {
		if hello, reason := newMirroredHello(raw); reason == "" && len(p.shapes) < helloProfilesMax {
			if i < len(body.H2) && body.H2[i] != nil {
				if problem := body.H2[i].problem(0); problem != "" {
					hello.prefaceProblem = problem
				} else {
					hello.setH2Preface(body.H2[i])
				}
			}
			if i < len(body.Vendor) {
				hello.seenVendor = body.Vendor[i]
			}
			if i < len(body.SignIn) {
				hello.seenSignIn = body.SignIn[i]
			}
			if i < len(body.FullRecords) {
				hello.fullRecords.Store(body.FullRecords[i])
			}
			hello.profiles = p
			p.shapes = append(p.shapes, hello)
		}
	}
	for _, shape := range p.shapes {
		p.markShufflingLocked(shape.family)
	}
	return p
}

// markShufflingLocked marks family's shapes as shuffling once egress learned two or more of its extension orders
// (mirroredHello.shuffles). The caller holds mu, or owns p.
func (p *helloProfiles) markShufflingLocked(family string) {
	var members []*mirroredHello
	for _, shape := range p.shapes {
		if shape.family == family {
			members = append(members, shape)
		}
	}
	if len(members) < 2 {
		return
	}
	for _, shape := range members {
		shape.shuffles.Store(true)
	}
}

// save writes the state; the caller holds mu. A write that fails leaves the state in memory (freeze fails closed).
func (p *helloProfiles) save() error {
	if p.file == "" {
		return nil
	}
	body := helloProfilesFileBody{
		Frozen: p.frozen,
		Hellos: make([][]byte, 0, len(p.shapes)),
		H2:     make([]*h2Preface, len(p.shapes)),
		Vendor: make([]bool, len(p.shapes)),
		SignIn: make([]bool, len(p.shapes)),

		FullRecords: make([]bool, len(p.shapes)),
	}
	hasH2 := false
	for i, shape := range p.shapes {
		body.Hellos = append(body.Hellos, shape.raw)
		if pref := shape.h2Preface(); pref != nil {
			body.H2[i] = pref
			hasH2 = true
		}
		body.Vendor[i] = shape.seenVendor
		body.SignIn[i] = shape.seenSignIn
		body.FullRecords[i] = shape.fullRecords.Load()
	}
	if !hasH2 {
		body.H2 = nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return writeFileAtomic(p.file, data, 0o600)
}

// admit is the learned shape a tunnel's hello stands for, or why there is none.
func (p *helloProfiles) admit(hello *mirroredHello) (*mirroredHello, string) {
	return p.admitFor(hello, false)
}

// admitFor is admit with whether the tunnel is a sign-in proxy tunnel rather than a vendor API tunnel, so egress's
// own calls pick the matching learned shape first (defaultHello).
func (p *helloProfiles) admitFor(hello *mirroredHello, signIn bool) (*mirroredHello, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mark := func(shape *mirroredHello) *mirroredHello {
		changed := false
		if signIn && !shape.seenSignIn {
			shape.seenSignIn = true
			changed = true
		} else if !signIn && !shape.seenVendor {
			shape.seenVendor = true
			changed = true
		}
		if changed && !p.frozen {
			_ = p.save()
		}
		return shape
	}
	var family []*mirroredHello
	for _, shape := range p.shapes {
		if shape.key == hello.key || (hello.offeredResumption && shape.resumedKey == hello.resumedKey) {
			return mark(shape), ""
		}
		if shape.family == hello.family || (hello.offeredResumption && shape.resumedFamily == hello.resumedFamily) {
			family = append(family, shape)
		}
	}
	if !p.frozen && len(p.shapes) < helloProfilesMax {
		hello.seenSignIn = signIn
		hello.seenVendor = !signIn
		hello.profiles = p
		p.shapes = append(p.shapes, hello)
		p.markShufflingLocked(hello.family)
		_ = p.save()
		return hello, ""
	}
	if len(family) > 0 {
		familyKey := family[0].family
		next := p.turn[familyKey]
		p.turn[familyKey] = (next + 1) % len(family)
		return mark(family[next%len(family)]), ""
	}
	if p.frozen {
		return nil, "a handshake egress did not learn before the first customer request (open a tunnel with each handshake your software uses when it starts, before it listens)"
	}
	return nil, fmt.Sprintf("more than %d handshake shapes", helloProfilesMax)
}

// noteFullRecords marks shape's client as one that writes full TLS records (mirroredHello.fullRecords), while
// learning is open.
func (p *helloProfiles) noteFullRecords(shape *mirroredHello) {
	if p == nil || shape == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.frozen || shape.fullRecords.Load() {
		return
	}
	for _, other := range p.shapes {
		if other == shape || other.family == shape.family {
			other.fullRecords.Store(true)
		}
	}
	_ = p.save()
}

// recordH2Preface records an HTTP/2 connection preface observed on a tunnel for shape while learning is still open.
// After freeze, nothing from a container connection changes the learned preface.
func (p *helloProfiles) recordH2Preface(shape *mirroredHello, preface *h2Preface) {
	if p == nil || shape == nil || preface == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.frozen {
		return
	}
	// A preface egress would not repeat (h2Preface.problem) is not learned: its shape's calls are refused by name.
	if problem := preface.problem(p.budget); problem != "" {
		for _, other := range p.shapes {
			if other == shape || other.family == shape.family {
				other.h2Mu.Lock()
				if other.preface == nil {
					other.prefaceProblem = problem
				}
				other.h2Mu.Unlock()
			}
		}
		return
	}
	changed := shape.setH2Preface(preface)
	for _, other := range p.shapes {
		if other != shape && other.family == shape.family {
			if other.setH2Preface(preface) {
				changed = true
			}
		}
	}
	if changed {
		_ = p.save()
	}
}

// defaultHello returns the first usable learned shape for vendor calls (signIn == false) or sign-in/token calls
// (signIn == true), falling back to any usable learned shape, or nil when there is none: egress's own calls then go
// with Go's own transport (crypto/tls and Go's HTTP/2 client, a client's whole handshake and preface), never with a
// learned hello and a preface no client sent. A shape is usable when it offers no h2 or its preface was learned.
func (p *helloProfiles) defaultHello(signIn bool) *mirroredHello {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, shape := range p.shapes {
		if ((signIn && shape.seenSignIn) || (!signIn && shape.seenVendor)) && shape.usable() {
			return shape
		}
	}
	for _, shape := range p.shapes {
		if shape.usable() {
			return shape
		}
	}
	return nil
}

// freeze ends learning. It fails closed: when the state cannot be written (an egress restart would learn again
// from a container that holds requests) learning stays open and the error is returned, so the registration that
// asked is refused and the container gets no customer request.
func (p *helloProfiles) freeze() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.frozen {
		return nil
	}
	p.frozen = true
	if err := p.save(); err != nil {
		p.frozen = false
		return err
	}
	return nil
}

func (p *helloProfiles) learning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.frozen
}
