// Command gray-peerlink carries the entry ↔ stack VM channel of docs/design/relay-outbound-only.md: WebSocket
// sessions the VM dials, yamux streams the entry opens. See README.md.
package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gray-peerlink:", err)
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "gray-peerlink:", err)
		os.Exit(1)
	}
}

// listen opens the unix socket, removing a stale file a previous run left. Only the containers that share its
// volume reach it (§3.8); its mode lets their users connect.
func listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func run(cfg config) error {
	var handler http.Handler
	switch cfg.role {
	case "entry":
		handler = newEntry(cfg).handler()
	case "vm":
		handler = newVM(cfg).handler()
	}
	l, err := listen(cfg.socket)
	if err != nil {
		return err
	}
	// No write timeout: CONNECT and the WebSocket routes hijack their connection and live as long as it does.
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		_ = server.Close()
	}()
	log.Printf("gray-peerlink: role %s on %s", cfg.role, cfg.socket)
	if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
