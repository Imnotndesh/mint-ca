package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// TLSMaterial is an in-memory server TLS keypair. A nil *TLSMaterial means the
// listener serves plain HTTP.
type TLSMaterial struct {
	CertPEM []byte
	KeyPEM  []byte
}

// ListenerSpec fully describes one listener generation.
type ListenerSpec struct {
	Addr    string
	Handler http.Handler
	TLS     *TLSMaterial // nil = plain HTTP
}

// Supervisor owns the single currently-active TCP/TLS listener and performs
// deterministic stop→start swaps on the same address. It is a generic,
// independently testable listener manager: it knows nothing about mint-ca,
// setup, or config.
type Supervisor struct {
	readT  time.Duration
	writeT time.Duration
	idleT  time.Duration

	mu   sync.Mutex
	srv  *http.Server
	ln   net.Listener
	wg   sync.WaitGroup
	errc chan error
}

// New returns an empty Supervisor (no listener started yet).
func New(readTimeout, writeTimeout, idleTimeout time.Duration) *Supervisor {
	return &Supervisor{
		readT:  readTimeout,
		writeT: writeTimeout,
		idleT:  idleTimeout,
		errc:   make(chan error, 1),
	}
}

// Addr returns the bound address of the current listener, or nil if none.
func (s *Supervisor) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Errors returns the channel of fatal serve errors. A non-nil value here means
// the current listener has failed and should be treated as fatal.
func (s *Supervisor) Errors() <-chan error { return s.errc }

// Start opens a listener for spec and serves it in a background goroutine.
// Bind or keypair-load errors are returned synchronously; the listener stays
// down and the caller may retry or treat the failure as fatal.
func (s *Supervisor) Start(spec ListenerSpec) error {
	ln, err := net.Listen("tcp", spec.Addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", spec.Addr, err)
	}

	var serveLn net.Listener = ln
	if spec.TLS != nil {
		cert, err := tls.X509KeyPair(spec.TLS.CertPEM, spec.TLS.KeyPEM)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("server: load TLS keypair: %w", err)
		}
		serveLn = tls.NewListener(ln, &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
			Certificates:             []tls.Certificate{cert},
		})
	}

	srv := &http.Server{
		Handler:      spec.Handler,
		ReadTimeout:  s.readT,
		WriteTimeout: s.writeT,
		IdleTimeout:  s.idleT,
	}

	s.mu.Lock()
	s.srv = srv
	s.ln = ln
	s.wg.Add(1)
	s.mu.Unlock()

	if spec.TLS != nil {
		slog.Info("listening (TLS)", "addr", ln.Addr().String())
	} else {
		slog.Info("listening (plain HTTP)", "addr", ln.Addr().String())
	}

	go func() {
		defer s.wg.Done()
		err := srv.Serve(serveLn)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case s.errc <- err:
			default:
			}
		}
	}()

	return nil
}

// Shutdown gracefully stops the current listener, waiting for in-flight
// requests to drain (bounded by ctx) and for the serve goroutine to exit, so a
// following Start on the same address cannot race a still-open socket.
func (s *Supervisor) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.ln = nil
	s.mu.Unlock()

	if srv == nil {
		return nil
	}

	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
	}
	s.wg.Wait()
	return nil
}

// Swap gracefully shuts down the current generation, then starts spec on the
// same address. Spec's TLS material should be resolved before calling Swap so
// the down-time is only Close+Listen.
func (s *Supervisor) Swap(ctx context.Context, spec ListenerSpec) error {
	if err := s.Shutdown(ctx); err != nil {
		return fmt.Errorf("server: shutdown before swap: %w", err)
	}
	return s.Start(spec)
}
