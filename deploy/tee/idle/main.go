// gray-idle: the empty slot's program (docs/design/relay-no-always-on-host.md §3.3 and 13.11 P2d). A phase-2 relay VM
// with no boot box yet (before the relay's first delivery), or one whose boot box does not open, runs no relay code:
// pre-launch imports this one static binary, taken from Gray's lane image, as the relay's slot `gray-relay-slot:boot`
// with this file as its entrypoint, so the relay service of the measured compose starts exactly as @gray/lane-compose
// fixes it (no command override) and holds nothing. It waits for SIGTERM or SIGINT and exits 0; as PID 1 of its
// container it must handle them itself, or `docker stop` would wait for its timeout.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(idle(make(chan os.Signal, 1)))
}

// idle blocks until a stop signal arrives on signals and answers the exit status.
func idle(signals chan os.Signal) int {
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	return 0
}
