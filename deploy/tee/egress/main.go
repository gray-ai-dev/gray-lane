package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "gray-egress: %v\n", err)
		os.Exit(2)
	}
	if err := run(cfg, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gray-egress: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config, stdout, stderr io.Writer) error {
	if cfg.checkFile != "" {
		return checkFileMode(cfg.checkFile)
	}
	applyMemoryLimit(cfg.memoryLimit)
	logger := log.New(stderr, "", 0)
	roots, rootCount, err := rootPool(cfg)
	if err != nil {
		return err
	}
	// The production loader never returns a nil pool and fails closed on an empty bundle (D55).
	// The e2e build without -extra-root-ca returns nil, meaning the system pool, and logs nothing.
	if roots != nil {
		logger.Printf("gray-egress: loaded %d root certificates", rootCount)
	}
	// nil in production; the e2e-tagged build may return a dial hook that maps a route host to the
	// harness's listener (`roots_e2e.go`). The hook cannot be reached from the production build.
	srv := newServer(cfg, roots, directDial(cfg), logger)
	defer srv.closeIdleConnections()

	// S14: the relay listener exists only with -relay-listen, and only then does the unix socket serve
	// the control API. It is bound before the unix socket, so the ready line below means both listen.
	var relayListener net.Listener
	if cfg.relayListen != "" {
		srv.stack = newRelayStack(cfg)
		if cfg.relayListen == stackRelayListen {
			srv.relayProbe = relayListening(stackRelayContainer)
		}
		relayListener, err = listenRelay(cfg.relayListen)
		if err != nil {
			return err
		}
		defer func() { _ = relayListener.Close() }()
		relayListener = srv.stack.holdConnections(relayListener)
		// Own calls (docs/relay-changes-v2.md §6): the schedule runs from start, with or without traffic.
		srv.ops = newStackOps(srv, stackOpsTable, srv.stack.now)
		srv.ops.persistWait = cfg.loginPersistWait
		srv.ops.loginRate.perMinute = cfg.loginCallsPerMinute
		// D1: the sign-in CA, made at the first start of the boot and kept on egress's own memory volume, and the
		// relay's trust bundle, written before the relay listener serves (compose starts the relay after egress is
		// healthy, which the bundle's presence is).
		if cfg.signInKeyDir != "" {
			ca, err := loadOrMakeSignInCA(cfg.signInKeyDir, tunnelDomains(signInRows), time.Now())
			if err != nil {
				return fmt.Errorf("sign-in CA: %w", err)
			}
			if err := writeSignInBundle(cfg.signInBundle, signInSystemRoots, ca); err != nil {
				return fmt.Errorf("sign-in bundle: %w", err)
			}
			srv.signIn.ca = ca
			// The learned handshake shapes live beside the CA, for this boot (mirror_profiles.go).
			srv.profiles = newHelloProfilesWithin(cfg.signInKeyDir, cfg.stackMaxBytes)
		}
	}

	listener, err := listenUnix(cfg.socketPath)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	// D115: the host e2e waits for this line, not for the socket path and not for a duration. It is
	// printed only after listenUnix has bound the socket and set its 0660 mode (and after the relay
	// listener is bound, when there is one), so a reader that sees it can connect. stderr stays the
	// request log (README "Logs").
	writeReadyLine(stdout, cfg.socketPath)

	servers := []*http.Server{newHTTPServer(srv)}
	listeners := []net.Listener{listener}
	if relayListener != nil {
		servers = append(servers, newRelayHTTPServer(srv))
		listeners = append(listeners, relayListener)
	}

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if srv.ops != nil {
		go srv.ops.loop(signalContext)
	}
	go func() {
		<-signalContext.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, httpServer := range servers {
			if err := httpServer.Shutdown(shutdownContext); err != nil {
				_ = httpServer.Close()
			}
		}
	}()

	// Either server failing stops the program: egress never runs with one of its listeners gone.
	serveErrors := make(chan error, len(servers))
	for i := range servers {
		go func(httpServer *http.Server, listener net.Listener) {
			serveErrors <- httpServer.Serve(listener)
		}(servers[i], listeners[i])
	}
	var first error
	for range servers {
		err := <-serveErrors
		if err != nil && !errors.Is(err, http.ErrServerClosed) && first == nil {
			first = err
			for _, httpServer := range servers {
				_ = httpServer.Close()
			}
		}
	}
	return first
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler,
		// Reading one request from workerd (or the relay) is bounded by the gateway's own
		// REQUEST_BODY_MS; the sidecar must not give up first. There is no write timeout
		// because an SSE answer, or a feed, may legitimately run for an hour.
		ReadHeaderTimeout: requestReadTimeout,
		ReadTimeout:       requestReadTimeout,
		// net/http's own diagnostics are not request records and would break the
		// one-JSON-line-per-request contract; every handled request logs its own
		// line, and a malformed request is rejected before it becomes a request.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

// newRelayHTTPServer is the relay listener's server (S14): the same timeouts, and a header block no larger than
// a vendor accepts (relayMaxHeaderBytes), so a relay connection's buffers stay within relayConnBytes.
func newRelayHTTPServer(srv *server) *http.Server {
	relayServer := newHTTPServer(http.HandlerFunc(srv.relayHandler))
	relayServer.MaxHeaderBytes = relayMaxHeaderBytes
	return relayServer
}

// applyMemoryLimit sets the Go runtime's soft memory limit from -memory-limit; 0 leaves the runtime's own
// setting (no limit unless GOMEMLIMIT is in the environment). The value is C3's, from egress's measured memory.
func applyMemoryLimit(limit int64) {
	if limit > 0 {
		debug.SetMemoryLimit(limit)
	}
}

// newRelayStack is the relay stack run serves (S20a): the S18 check under the flags' append limits,
// the S19 digester and the body digest.
func newRelayStack(cfg config) *stack {
	return newStack(cfg, newStackRequestCheck(cfg.stackAppendLimits()), newStackEventDigester, digestStackBody)
}

// writeReadyLine is the one startup event on stdout. The host harness (deploy/tee/e2e/lane-e2e.mjs)
// matches this exact prefix; keep the line and the pattern in step.
func writeReadyLine(stdout io.Writer, socketPath string) {
	fmt.Fprintf(stdout, "gray-egress: listening on unix:%s\n", socketPath)
}

// listenUnix is the entry's listener. The socket is created with a 0117 umask,
// then chmod 0660, so the steady state is exactly owner and group read/write:
// S2b makes /run/gray setgid with egress's group 10100, which the socket
// inherits, and lane holds that group and nothing else of egress's. A
// pre-existing socket (a previous boot) is removed; a pre-existing regular
// file or symlink is refused rather than deleted.
func listenUnix(path string) (*net.UnixListener, error) {
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	oldUmask := syscall.Umask(0o117)
	listener, err := net.Listen("unix", path)
	syscall.Umask(oldUmask)
	if err != nil {
		return nil, err
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, errors.New("unix listener expected")
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = unixListener.Close()
		return nil, err
	}
	return unixListener, nil
}

// listenRelay is the one TCP listener in the program (S14): the address config validated, an IP literal
// that is not a wildcard, so it binds egress's relay_out address and no other interface.
func listenRelay(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path exists and is not a socket")
	}
	return os.Remove(path)
}

// checkFileMode is the compose health check (-check-file): the file exists and is not empty.
func checkFileMode(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("not ready")
	}
	return nil
}
