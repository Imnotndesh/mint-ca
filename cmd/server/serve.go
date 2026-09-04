package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// serveListener opens a TCP listener on addr and serves handler in a
// background goroutine. When useTLS is true it loads certFile/keyFile and
// serves HTTPS. The returned stop func gracefully shuts the server down
// (closing the listener so addr can be re-bound by a subsequent call), and the
// returned error channel reports a fatal serve error (nil values / server
// shutdown are not fatal). This is the reusable primitive that lets a
// setup-mode plain-HTTP listener be swapped in-process to the ready TLS
// listener without exiting.
func serveListener(addr string, handler http.Handler, useTLS bool, certFile, keyFile string, readT, writeT, idleT time.Duration) (stop func(), errCh <-chan error, err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan error, 1)
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  readT,
		WriteTimeout: writeT,
		IdleTimeout:  idleT,
	}

	var serveLn net.Listener = ln
	if useTLS {
		cert, cerr := tls.LoadX509KeyPair(certFile, keyFile)
		if cerr != nil {
			_ = ln.Close()
			return nil, nil, fmt.Errorf("load server TLS keypair: %w", cerr)
		}
		serveLn = tls.NewListener(ln, &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
			Certificates:             []tls.Certificate{cert},
		})
	}

	go func() {
		if useTLS {
			slog.Info("listening (TLS)", "addr", ln.Addr().String())
		} else {
			slog.Info("listening (plain HTTP)", "addr", ln.Addr().String())
		}
		ch <- srv.Serve(serveLn)
	}()

	stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	return stop, ch, nil
}
