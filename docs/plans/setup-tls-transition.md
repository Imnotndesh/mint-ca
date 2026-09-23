# Plan — Robust in-process setup → ready HTTP/HTTPS transition

## Objective
Let a fresh mint-ca instance that was started *intending* TLS but with no server
certificate on disk boot into setup mode over plain HTTP, then transition the
**same process** to HTTPS using the certificate mint-ca generates during setup —
with no container restart. Today this is impossible, so operators run setup with
`MINT_TLS_DISABLED=true` and must manually restart the container afterwards to
serve HTTPS.

## Current behavior (verified)
- `internal/config/config.go` `Load()`: when `MINT_TLS_DISABLED` is not true it
  requires `MINT_TLS_CERT`/`MINT_TLS_KEY` to be set **and the files to exist on
  disk**, otherwise the process exits before anything else runs. Reproduced:

  ```
  mint-ca: 2 configuration errors:
    • MINT_TLS_CERT: file not found or not readable: /tmp/.../server.crt
    • MINT_TLS_KEY: file not found or not readable: /tmp/.../server.key
  ```

- `cmd/server/main.go` reads setup state, then starts either
  `api.BuildSetupRouter(...)` on plain HTTP or the ready router on TLS
  (`useTLS := !cfg.Server.TLSDisabled`).
- `internal/setup/handler.go` on `POST /setup/api-key` issues a server cert
  (`issueServerCert`), marks state ready, responds, then a delayed goroutine
  calls `onReady(certPEM, keyPEM)`.
- `onReady` writes the cert/key to `cfg.Server.TLSCertFile` (falling back to
  `/data/server.crt`) and signals a buffered `restartCh`.
- Main's `case <-restartCh` stops the old listener and starts the ready router
  with `useTLS = !cfg.Server.TLSDisabled`.
- `cmd/server/serve.go` `serveListener` owns the actual listen/serve/shutdown.

Consequences:
1. **The swap is unreachable on a fresh install.** Config refuses to boot with
   TLS intended and no cert. If TLS is disabled for setup, the swap keeps
   serving HTTP. So the only way to get HTTPS is a restart with the cert present.
2. `useTLS` after the swap ignores whether certs now exist.
3. The swap is fire-and-forget: `onReady` errors are only logged; a failed
   re-bind/keypair-load leaves the process with no listener, or exits.
4. Default cert paths are duplicated between `onReady` and `tlsFilePaths`.
5. The mTLS listener is never started after a swap (logged as a warning).

## Design decisions
1. **Separate TLS *intent* from TLS *material*.** `MINT_TLS_DISABLED` is intent.
   The cert/key files are material that setup produces. Boot must not require
   material that setup is responsible for creating.
2. **One small listener supervisor** (the "goroutine task manager") owns exactly
   one running listener generation and performs deterministic stop→start swaps,
   returning errors to the caller instead of logging and dropping them.
3. **Setup completion is a channel signal.** `onReady` writes the material and
   sends to a buffered channel; the main loop reacts. No sleeps, no
   fire-and-forget goroutine.
4. **Reuse the freshly generated cert in-process.** After setup, if TLS is
   intended, the ready listener serves HTTPS with the cert just written. If
   `MINT_TLS_DISABLED=true`, it stays HTTP (unchanged local-dev behavior).
5. **Fail fast only when it matters.** An already-`ready` instance with TLS
   intended but missing/unreadable certs still exits with a clear error at boot.
   Fresh/uninitialized/setup states skip that check.

## Phase 1 — Config: stop requiring cert material at boot
- `internal/config/config.go`: remove the `os.Stat` existence checks (and the
  "required" errors) for `MINT_TLS_CERT`/`MINT_TLS_KEY`.
- Resolve default paths when unset — `server.crt`/`server.key` in the data
  directory — and expose one source of truth, e.g.
  `ServerConfig.ResolvedTLSCertFile()` / `ResolvedTLSKeyFile()`, used by
  `onReady`, `tlsFilePaths`, and the mTLS listener. Keep explicit env overrides.
- Add a `ServerConfig.RequireTLSMaterial() error` (or equivalent) that main calls
  **only when setup state is `ready`**, producing the clear fatal message.
- Tests: `Load()` succeeds with TLS enabled and no files present; explicit paths
  still honoured.

## Phase 2 — Listener supervisor
New `cmd/server/manager.go`:

```go
type listenerSpec struct {
    label    string
    addr     string
    handler  http.Handler
    useTLS   bool
    certFile string
    keyFile  string
}

type serverManager struct {
    readT, writeT, idleT time.Duration
    mu   sync.Mutex
    srv  *http.Server
    wg   sync.WaitGroup
    errc chan error
}

func newServerManager(readT, writeT, idleT time.Duration) *serverManager
func (m *serverManager) Start(spec listenerSpec) error
func (m *serverManager) Stop(ctx context.Context) error
func (m *serverManager) Swap(ctx context.Context, spec listenerSpec) error
```

- `Start`: `net.Listen`, optionally wrap in TLS after `tls.LoadX509KeyPair`,
  create `http.Server`, serve in a goroutine tracked by the `WaitGroup`, and
  return bind/keypair errors synchronously.
- The serve goroutine forwards non-`ErrServerClosed` errors to `errc`.
- `Stop`: `srv.Shutdown` with a bounded timeout, ensure the listener is closed,
  then `wg.Wait()` so a following `Start` on the same `addr` cannot race the old
  socket.
- `Swap`: `Stop` then `Start`. Optionally one short retry on `EADDRINUSE`; the
  caller decides whether a persistent failure is fatal.
- Migrate the existing `serveListener` and `TestServeListener_InProcessSwap` onto
  the manager, or keep `serveListener` as a thin internal helper.

## Phase 3 — Wire setup completion through the supervisor
In `cmd/server/main.go`:
- After reading setup state: if `state == ready && !TLSDisabled`, call the
  TLS-material validation and exit with a clear error if it fails.
- `setupDone := make(chan struct{}, 1)`. `onReady(certPEM, keyPEM)` writes the
  files via the resolved paths, then non-blocking `select { case setupDone <- struct{}{}: default: }`.
  It no longer touches `restartCh`.
- Start the initial generation with `mgr.Start(...)` (setup HTTP or ready
  HTTPS/HTTP).
- Main `select`:
  - `<-setupDone`: `mgr.Swap(ctx, readySpec(useTLS = !TLSDisabled))`. On failure,
    log and retry with bounded backoff rather than exiting — a transient port
    race must not take the server down. Start mTLS when enabled.
  - `<-quit`: `mgr.Stop`, then the existing worker/store/keystore teardown.
  - `<-mgr.errc`: fatal, as today.
- Delete the `restartCh`, `newStop`, and `startServer` closure scaffolding in
  favour of the manager.
- Start the mTLS enrollment listener through one helper used both at boot and
  after the swap, replacing the current warn-only branch.

## Phase 4 — Tests
- **Regression for the reported bug:** boot a fresh instance with TLS intended
  and no cert files; complete `/setup/root-ca` + `/setup/api-key` over HTTP; then
  assert the *same process/addr* now serves HTTPS with the generated cert and
  that plain HTTP to it fails. The current suite never exercises this, because
  `TestServeListener_InProcessSwap` fabricates a cert before starting.
- **Supervisor:** `Start` returns bind errors synchronously; `Swap` replaces
  plain HTTP with TLS on the same address; `Stop` is idempotent and joins the
  serve goroutine.
- **Config/material gate:** `Load()` accepts TLS-enabled + missing cert at boot;
  the ready-state material check rejects it with the clear message.
- Keep the existing in-process-swap test green.

## Acceptance criteria
- `go build ./... && go vet ./... && go test ./...` clean.
- Fresh process/container with `MINT_TLS_DISABLED=false`, no `MINT_TLS_CERT` on
  disk, empty DB: boots to HTTP setup, completes setup, and then serves HTTPS on
  the same port/process — no restart.
- `MINT_TLS_DISABLED=true` behaviour is unchanged (always HTTP).
- An already-ready instance with missing certs still fails fast with a clear
  message.
- mTLS enrollment starts after setup when enabled.

## Explicitly out of scope
- Live certificate rotation/reload while already serving.
- Automatic ACME/Let's Encrypt provisioning of the *server* listener cert.
- Proxy/ingress changes, or docs beyond a short note in `docs/Setup.md`.

## Suggested branch / PR
`feat/setup-tls-transition` (this plan), one PR, `cmd/server` + `internal/config`
only.
