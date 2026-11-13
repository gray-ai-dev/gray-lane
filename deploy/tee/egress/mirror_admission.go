package main

import (
	"context"
	"net"
	"time"
)

// The end of learning (mirror_profiles.go) in a lane: the first registration egress accepts, after a probe of the
// relay container's listener where egress knows it.

const (
	errStackRelayNotReady = "stack_relay_not_ready"

	// The relay listener and the relay container's own listener as the lane's compose places them
	// (deploy/tee/compose.stack.yaml: egress's `-relay-listen`, the relay's address on relay_out and S4's
	// GRAY_RELAY_LISTEN port). Egress probes the container only in that layout.
	stackRelayListen    = "10.231.11.2:8080"
	stackRelayContainer = "10.231.11.3:3000"
	relayProbeWait      = time.Second
)

// relayListening is a probe of the relay container's listener: whether a TCP connection to addr opens.
func relayListening(addr string) func(context.Context) bool {
	return func(ctx context.Context) bool {
		ctx, cancel := context.WithTimeout(ctx, relayProbeWait)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}

// admitRegistration ends learning at the first customer request egress accepts; "" or the refusal's code.
func (s *server) admitRegistration(ctx context.Context) string {
	if !s.profiles.learning() {
		return ""
	}
	if s.relayProbe != nil && !s.relayProbe(ctx) {
		return errStackRelayNotReady
	}
	// The learned shapes not written: learning stays open and the registration is refused like one before the
	// container listens (503, the entry does not call the container), rather than a restart learning again later.
	if err := s.profiles.freeze(); err != nil {
		s.logger.Printf("egress: the learned handshakes could not be written; the registration is refused: %v", err)
		return errStackRelayNotReady
	}
	return ""
}
