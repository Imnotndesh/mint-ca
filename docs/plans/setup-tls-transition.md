# Plan — In-process setup → ready listener transition (listener supervisor)

## Objective
A fresh mint-ca instance that *intends* to serve HTTPS but has no server
certificate yet must boot into setup mode over plain HTTP, mint its own server
cert during setup, and then move the **same process** to HTTPS using that cert —
no container restart. Today this is impossible, so operators run setup with
`MINT_TLS_DISABLED=true` and manually restart the container to get HTTPS.

## The bootstrap problem
mint-ca has a chicken-and-egg constraint: it wants to serve HTTPS, but the
certificate it would serve is issued by mint-ca itself, which only exists after
setup. So there is a mandatory two-phase lifecycle:

```
setup phase (plain HTTP)  ──setup complete──▶  ready phase (HTTPS)
```

Any correct design is therefore a **listener generation swap on the same
address**. The current code attempts this but is built wrong at three layers —
config, lifecycle wiring, and cert handling — which is why the transition is the
fragile, restart-requiring pain point.

## Current state (verified) and root causes
- `internal/config/config.go` `Load()`: when `MINT_TLS_DISABLED` is false it
  requires `MINT_TLS_CERT`/`MINT_TLS_KEY` to be set **and the files to exist**,
  else the process exits before anything runs. Reproduced:

  ```
  mint-ca: 2 configuration errors:
    • MINT_TLS_CERT: file not found or not readable: .../server.crt
    • MINT_TLS_KEY: file not found or not readable: .../server.key
  ```

  → The in-process swap is **unreachable on a genuine fresh install**, because
  the very thing setup is supposed to create is demanded at boot.
- `cmd/server/main.go` is a procedural monolith: config, store, workers, both
  routers, signal handling, the swap loop, and mTLS all live in `main()`. The
  swap is a side effect hidden in the setup handler through an `onReady`
  callback that sleeps 150 ms in a detached goroutine and then fires a buffered
  `restartCh`. Errors are logged and dropped; a failed re-bind leaves the
  process half-transitioned or dead.
- `onReady` writes the cert to `cfg.Server.TLSCertFile` (or `/data/server.crt`)
  and the ready listener re-reads it. The cert makes a disk round-trip, the
  default path is duplicated in two places, and a provided operator cert would
  be silently overwritten by the setup-issued one.
- `useTLS` after the swap is just `!TLSDisabled` — it ignores whether material
  actually exists. The mTLS listener is never started after a swap.

Root causes, distilled:
1. **TLS intent and TLS material are conflated.** Boot requires material that
   setup is responsible for producing.
2. **The transition is a buried callback + sleep**, not an explicit lifecycle.
3. **Cert material travels through disk** and path logic is duplicated/racy.

## Proposed architecture

### Components
```
internal/server/
  supervisor.go      # owns the single active listener generation
  material.go        # TLSMaterial + resolution from mode/state
cmd/server/
  main.go            # thin: config → deps → runApp
  app.go             # runApp(ctx, cfg, store, deps): the orchestration
internal/config/     # TLSMode + per-mode validation
internal/setup/      # onReady emits an event; no sleep, no listener code
```

### Design decisions

**1. Three explicit TLS modes, not one boolean.**
Derived from env, kept backward compatible:

| Mode | When | Setup phase | Ready phase |
|---|---|---|---|
| `disabled` | `MINT_TLS_DISABLED=true` | HTTP | HTTP |
| `provided` | `MINT_TLS_CERT`+`MINT_TLS_KEY` set | HTTP | HTTPS from the provided files |
| `auto` | neither of the above | HTTP | HTTPS from the setup-issued cert |

- `provided` fails fast at boot if the files are missing/unreadable (current
  behaviour for that case) — the operator explicitly asked for those files.
- `auto` places **no** file requirement at boot; the cert is minted during
  setup. This is the fix for the pain point.
- Validation lives in `config.Load` but is **mode-aware**; it never demands
  material that `auto` mode is meant to create later.

**2. An event-driven `Supervisor` owns the listener lifecycle.**
One supervisor, one active generation, deterministic stop→start:

```go
type TLSMaterial struct{ CertPEM, KeyPEM []byte } // nil = plain HTTP

type ListenerSpec struct {
    Addr    string
    Handler http.Handler
    TLS     *TLSMaterial
}

type Supervisor struct{ /* srv, wg, errc, timeouts */ }

func New(readT, writeT, idleT time.Duration) *Supervisor
func (s *Supervisor) Start(spec ListenerSpec) error          // bind/load errors returned
func (s *Supervisor) Swap(ctx context.Context, spec ListenerSpec) error
func (s *Supervisor) Shutdown(ctx context.Context) error
func (s *Supervisor) Errors() <-chan error                   // fatal serve errors
```

- `Start` does `net.Listen` (Go sets `SO_REUSEADDR`), optionally wraps TLS from
  `TLSMaterial` (in-memory `tls.X509KeyPair`, **not** a file reload), creates the
  `http.Server`, and serves in a goroutine tracked by a `WaitGroup`.
- `Swap` = graceful `Shutdown` of the current generation (drains in-flight
  requests) → `wg.Wait()` (socket provably released) → `Start` the next. No port
  race, no down window beyond the Close+Listen microseconds.
- The supervisor knows nothing about setup, config, or mint-ca; it is a generic,
  independently testable listener manager.

**3. Setup completion is an event, not a callback + sleep.**
The setup handler keeps its existing `ReadyFunc(certPEM, keyPEM []byte) error`
hook, but the implementation becomes a **non-blocking emit** on a buffered
`done chan TLSMaterial`. The handler does no listener work and sleeps nowhere.
Ordering is safe *without* the 150 ms sleep because `Swap`'s `Shutdown` drains
the in-flight `POST /setup/api-key` request before tearing the listener down.

**4. Cert material stays in memory; disk is only for restarts.**
- `auto` mode: on setup completion, the supervisor gets the cert bytes directly
  and serves TLS from memory. Separately, `onReady` **persists** the PEM to the
  data dir so the *next* boot can serve TLS without re-setup. Persistence
  failure is logged loudly but does not abort the live transition.
- `provided` mode: the provided files are the material; the setup-issued cert is
  never written over them.

**5. Single resolved-path helper.**
`config` exposes `ResolvedTLSCertFile()` / `ResolvedTLSKeyFile()` (env override,
else `<data-dir>/server.crt|key`). `onReady`, the ready-boot path, and the mTLS
listener all use it — the duplicated `/data/server.crt` literals go away.

**6. Thin `main`, testable `runApp`.**
`main.go` only parses config, opens storage, builds engines, and calls
`runApp(ctx, cfg, store, deps)`. `runApp` computes the mode, builds both
routers, creates the supervisor and `done` channel, starts the initial
generation, and runs the event loop:

```
select {
case <-done:        // setup complete
    supervisor.Swap(ctx, readySpec)     // with retry/backoff on bind race
    startMTLSIfEnabled(ctx)             // same helper used at boot and post-swap
case err := <-supervisor.Errors():
    return err                          // fatal
case <-ctx.Done():                      // SIGINT/SIGTERM
    supervisor.Shutdown(ctx); return nil
}
```

The background workers (`apiWorkers`) and HA elector are orthogonal and stay
exactly as they are — the supervisor is only about listeners.

### Restart behaviour (state == ready at boot)
- `disabled` → serve ready HTTP.
- `provided` → serve ready HTTPS from the provided files.
- `auto` → serve ready HTTPS from the persisted data-dir cert; if it is missing
  or unreadable, exit with a clear message pointing at the data dir (do **not**
  silently fall back to HTTP).

### Alternatives considered and rejected
- **Single listener, atomic handler+cert swap (self-signed during setup).**
  Removes the rebind entirely, but forces HTTPS-with-a-self-signed-cert during
  setup instead of plain HTTP. The requirement is HTTP setup → HTTPS ready, so
  a rebind is unavoidable; rejected.
- **Port multiplexing (peek TLS ClientHello vs HTTP on one socket).** One port
  serving both protocols is fragile and still needs the handler swap; rejected.
- **Only relax the config validation.** Fixes boot but leaves the
  callback+sleep swap, the disk round-trip, the overwrite bug, and unstarted
  mTLS; rejected as insufficient.

## Phases

**Phase 1 — config modes.** Add `TLSMode` derivation + mode-aware validation +
`ResolvedTLSCertFile/KeyFile`. `Load()` accepts `auto` with no files; `provided`
still requires files. Unit tests for all three modes and the mixed
one-of-two-files error.

**Phase 2 — `internal/server` supervisor.** Implement `Supervisor`,
`TLSMaterial`, `ListenerSpec`, `Start/Swap/Shutdown/Errors`. Unit tests on
ephemeral ports: plain→TLS swap on the same addr, synchronous bind-error
return, idempotent `Shutdown`, goroutine join.

**Phase 3 — orchestration.** Extract `runApp`; wire mode → initial spec; emit
`done` from `onReady` (persist-first in `auto`, never in `provided`); drive the
event loop; start mTLS via one helper at boot-ready and post-swap; remove
`restartCh`, `newStop`, `startServer`, and the 150 ms sleep. Migrate
`serveListener`/`TestServeListener_InProcessSwap` onto the supervisor.

**Phase 4 — end-to-end regression test.** Boot `auto` + fresh DB + no cert
files; complete `/setup/root-ca` + `/setup/api-key` over HTTP; assert the same
process/addr now serves HTTPS with the minted cert and that plain HTTP to it
fails. This is the test the suite currently lacks (the existing swap test
fabricates a cert before starting).

**Phase 5 — docs.** Short note in `docs/Setup.md` that fresh installs no longer
need a cert at boot and transition to HTTPS automatically.

## Acceptance criteria
- `go build ./... && go vet ./... && go test ./...` clean.
- Fresh process/container, `MINT_TLS_DISABLED=false`, no `MINT_TLS_CERT` on
  disk, empty DB: boots to HTTP setup, completes setup, then serves HTTPS on the
  same port/process — no restart.
- `MINT_TLS_DISABLED=true` unchanged (always HTTP).
- `provided` mode unchanged (uses the operator's cert; never overwritten).
- Already-`ready` + `auto` + missing persisted cert fails fast with a clear
  message.
- mTLS enrollment starts after setup when enabled.

## Explicitly out of scope
- Live cert rotation/reload while already serving.
- ACME/Let's Encrypt provisioning of the *server* listener cert.
- Proxy/ingress changes.

## Suggested branch / PR
`feat/setup-tls-transition`, one PR, touching `cmd/server`, `internal/server`
(new), `internal/config`, `internal/setup`, and `docs/Setup.md`.
