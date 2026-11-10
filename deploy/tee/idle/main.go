// gray-idle: the empty slot's program (docs/design/relay-no-always-on-host.md §3.3 and 13.11 P2d). A phase-2 relay VM
// with no boot box yet (before the relay's first delivery), or one whose boot box does not open, runs no relay code:
// pre-launch imports this one static binary, taken from Gray's lane image, as the relay's slot `gray-relay-slot:boot`
// with this file as its entrypoint, so the relay service of the measured compose starts exactly as @gray/lane-compose
// fixes it (no command override) and holds nothing. It waits for SIGTERM or SIGINT and exits 0; as PID 1 of its
// container it must handle them itself, or `docker stop` would wait for its timeout.
//
// While it waits it asks the lane's config listener for the config version every pollEvery, as a relay polls it, and
// drops the answer. An outbound stack VM's lane attests and pins its entries only behind a fetch or a relay's config
// poll (workers/gateway/src/lane/entry.ts `relayConfig`), and no fetch reaches a VM before its peerlink has dialed an
// entry; without these polls the empty slot never reaches the entry, and the relay's delivery, which only the entry's
// tunnel carries, never reaches it (staging P8, 2026-11-10). The URL is the relay service's GRAY_RELAY_CONFIG_URL.
package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// pollEvery is how often the config version is asked: often enough that the entry link's first attestation follows
// the boot within seconds, as a relay's own poll would drive it.
const pollEvery = 5 * time.Second

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	if url := os.Getenv("GRAY_RELAY_CONFIG_URL"); url != "" {
		go poll(ctx, &http.Client{Timeout: 10 * time.Second}, url+"/version", pollEvery)
	}
	status := idle(make(chan os.Signal, 1))
	cancel()
	os.Exit(status)
}

// idle blocks until a stop signal arrives on signals and answers the exit status.
func idle(signals chan os.Signal) int {
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	return 0
}

// poll GETs url at once and then every every until ctx ends; each answer is read and dropped, a failure is ignored.
func poll(ctx context.Context, client *http.Client, url string, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err == nil {
			if resp, err := client.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
				_ = resp.Body.Close()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
