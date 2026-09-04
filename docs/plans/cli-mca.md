# Plan — `mca` CLI for mint-ca

## Objective
Build `mca`, a standalone command-line client for the mint-ca REST API
(`github.com/Imnotndesh/mint-ca`), so operators can issue, revoke, renew,
export, and audit certificates from a terminal or a CI pipeline instead of
hand-writing `curl` calls. This is a **separate Go module/binary**, not a
package inside the `mint-ca` server repo's build — treat mint-ca purely as an
HTTP API you are a client of. Do not import any `mint-ca/internal/...`
package; those are unexported from the module's public API surface by
convention (`internal/`) and cannot be imported from outside the module
anyway.

Read `docs/Api.md` and `docs/Setup.md` in the `mint-ca` repo in full before
writing code — they are the authoritative API contract. This plan summarizes
the parts relevant to the CLI, but the docs are the source of truth if
anything here goes stale.

## Ground rules
- New repo: `mca` (suggested name), Go module `github.com/<you>/mca` or
  `github.com/Imnotndesh/mca` if this becomes an official companion tool —
  confirm the module path with whoever owns the mint-ca org before publishing.
- Use [`spf13/cobra`](https://github.com/spf13/cobra) for the command tree and
  [`spf13/viper`](https://github.com/spf13/viper) (or a lighter manual
  approach — see Config below) for config/env binding. Cobra is the de facto
  standard for Go CLIs and is what a reviewer will expect.
- Go version: match mint-ca's `go.mod` (`go 1.25.0`) or newer.
- No comments explaining *what* code does; only *why*, when non-obvious.
  Follow standard `gofmt`/`go vet` cleanliness. `go build ./...` and
  `go test ./...` must pass before every commit.
- Every subcommand that calls the API must have a unit test using
  `httptest.NewServer` to fake mint-ca's responses — do not require a live
  mint-ca server to run `go test`. A small number of end-to-end tests against
  a real local mint-ca instance are welcome as a separate, opt-in test suite
  (e.g. behind a build tag `e2e` or a Makefile target `test-e2e`), but the
  default `go test ./...` must be fully self-contained.
- Distribute via `goreleaser` producing binaries for linux/darwin/windows,
  amd64/arm64. Add a GitHub Actions workflow that runs `go test ./...` on PR
  and runs `goreleaser` on tag push (`v*`).

## High-level architecture
```
mca/
  cmd/mca/main.go              # entrypoint, calls cmd.Execute()
  internal/cmd/                # cobra command tree (root.go, ca.go, cert.go, ...)
  internal/client/              # thin HTTP client wrapping the mint-ca REST API
  internal/config/              # config file + env + flag resolution
  internal/output/              # table/JSON/YAML output formatting
  internal/client/client_test.go, ...
```

### The API client (`internal/client`)
Build one hand-written HTTP client package — do NOT generate one from an
OpenAPI spec (mint-ca does not ship one). Structure:

```go
package client

type Client struct {
    BaseURL    string // e.g. https://ca.internal:8443
    APIKey     string
    HTTPClient *http.Client // must allow a custom *tls.Config for self-signed CA trust (see Config below)
}

func New(baseURL, apiKey string, httpClient *http.Client) *Client

// One method per API operation the CLI needs, e.g.:
func (c *Client) CreateRootCA(ctx context.Context, req CreateRootCARequest) (*CA, error)
func (c *Client) ListCAs(ctx context.Context) ([]CA, error)
func (c *Client) IssueCert(ctx context.Context, req IssueCertRequest) (*IssueCertResponse, error)
func (c *Client) SignCSR(ctx context.Context, req SignCSRRequest) (*SignCSRResponse, error)
func (c *Client) RevokeCert(ctx context.Context, certID string, reason *int) error
func (c *Client) ExportCert(ctx context.Context, certID, format, passcode string) ([]byte, string, error) // returns (bytes, filename)
func (c *Client) GetRenewalStatus(ctx context.Context, caID string) (*RenewalStatus, error)
func (c *Client) VerifyAuditChain(ctx context.Context) (*AuditVerifyResult, error)
// ... etc, one per subcommand below
```

Every method:
1. Marshals the request struct to JSON with `encoding/json` — **do not send
   fields the mint-ca handler doesn't declare**: the server decodes with
   `json.Decoder.DisallowUnknownFields()`, so an extra field in your request
   body causes a `400`. Mirror request struct field names exactly as
   documented in `docs/Api.md` (they are `snake_case` JSON tags).
2. Sends `Authorization: Bearer <APIKey>` on every `/api/v1/...` call. Public
   endpoints (`/pki/...`, `/healthz`) don't need it.
3. On a non-2xx response, decodes `{"error": "..."}` (mint-ca's uniform error
   shape — see `internal/api/handlers/helpers.go`'s `writeError`) and returns
   a Go error wrapping that message plus the HTTP status code. Example:
   ```go
   type APIError struct {
       StatusCode int
       Message    string
   }
   func (e *APIError) Error() string { return fmt.Sprintf("mint-ca: %d: %s", e.StatusCode, e.Message) }
   ```
4. Respects `ctx` for cancellation/timeouts (`http.NewRequestWithContext`).
5. For binary responses (`export`, SCEP raw DER, escrowed key PEM), read
   `Content-Type` / `Content-Disposition` and return raw bytes plus the
   suggested filename, don't try to JSON-decode them.

## Config resolution (highest to lowest precedence)
1. Command-line flags: `--server`, `--api-key`, `--insecure-skip-verify`,
   `--ca-cert` (path to a PEM to trust, for self-signed mint-ca deployments),
   `--output` (`table`|`json`|`yaml`, default `table`).
2. Environment variables: `MCA_SERVER`, `MCA_API_KEY`, `MCA_CA_CERT`,
   `MCA_INSECURE_SKIP_VERIFY`.
3. Config file at `~/.config/mca/config.yaml` (respect `$XDG_CONFIG_HOME` if
   set), written by `mca login` (see below). Shape:
   ```yaml
   server: https://ca.internal:8443
   api_key: <the raw key>
   ca_cert: /path/to/ca.pem   # optional
   ```
4. If `--server`/`MCA_SERVER`/config file all miss, print a clear error
   telling the user to run `mca login` or pass `--server`.

Store the API key file with `0600` permissions. Warn (don't fail) if the file
already has looser permissions, and offer `mca login --fix-permissions`.

## Command tree

Design every subcommand to mirror an mint-ca REST endpoint 1:1 wherever
possible, so the mapping is obvious to someone who already knows the API.

```
mca login --server <url> --api-key <key> [--ca-cert <path>] [--insecure-skip-verify]
    Verifies the key works (GET /api/v1/audit?limit=1) then writes the config file.

mca ca create root --name <name> --common-name <cn> [--organization ...] [--country ...]
                    [--key-algo ecdsa-p256] [--ttl-days 3650]
    -> POST /api/v1/ca/root

mca ca create intermediate --parent-ca-id <uuid> --name <name> --common-name <cn>
                            [--key-algo ...] [--ttl-days ...] [--max-path-len 0]
    -> POST /api/v1/ca/intermediate

mca ca list
    -> GET /api/v1/ca
mca ca get <caID>
    -> GET /api/v1/ca/{caID}
mca ca children <caID>
    -> GET /api/v1/ca/{caID}/children
mca ca revoke <caID>
    -> PUT /api/v1/ca/{caID}/revoke
mca ca rekey <caID> [--key-algo ...] [--ttl-days ...]
    -> POST /api/v1/ca/{caID}/rekey
mca ca cross-sign <caID> --signing-ca-id <uuid> [--ttl-days ...]
    -> POST /api/v1/ca/{caID}/cross-sign

mca cert issue --ca-id <uuid> --provisioner-id <uuid> --common-name <cn>
               [--dns <name>]... [--ip <addr>]... [--email <addr>]...
               [--ttl-seconds 86400] [--key-algo ecdsa-p256]
               [--server-auth] [--client-auth] [--profile <name>]
               [--store-key] [--key-passcode <pass>]
               [--spiffe-id spiffe://...] [--sans-uri <uri>]...
               [--out-cert <path>] [--out-key <path>] [--out-chain <path>]
    -> POST /api/v1/certs/issue
    Writes cert_pem/key_pem/chain_pem to files if --out-* given, else prints
    to stdout (respecting --output).

mca cert sign --ca-id <uuid> --provisioner-id <uuid> --csr <path-to-csr.pem>
              [--ttl-seconds ...] [--out-cert <path>] [--out-chain <path>]
    -> POST /api/v1/certs/sign

mca cert batch-sign --ca-id <uuid> --provisioner-id <uuid> --csr-dir <dir>
                     [--ttl-seconds ...]
    Reads every *.csr/*.pem in --csr-dir, builds the batch request
    (POST /api/v1/certs/batch/sign, max 1000 items — chunk if more), writes
    each result as <original-filename>.crt next to the CSR (or reports the
    per-item error).

mca cert get <certID>
    -> GET /api/v1/certs/{certID}
mca cert get --serial <serial>
    -> GET /api/v1/certs/serial/{serial}
mca cert list --ca-id <uuid>
    -> GET /api/v1/certs/ca/{caID}
mca cert revoke <certID> [--reason <int>]
    -> PUT /api/v1/certs/{certID}/revoke
mca cert key <certID> [--passcode <pass>] [--out <path>]
    -> GET /api/v1/certs/{certID}/key
mca cert export <certID> [--format tgz|p12|jks] [--passcode <pass>]
                 [--p12-password ...] [--jks-password ...] [--jks-alias ...]
                 --out <path>
    -> GET /api/v1/certs/{certID}/export?format=...
    Writes the raw response body to --out; refuses to overwrite an existing
    file without --force.

mca provisioner create --ca-id <uuid> --name <name> --type <type> [--config-json <json>]
                        [--policy-id <uuid>] [--profile-id <uuid>]
    -> POST /api/v1/provisioners
mca provisioner list --ca-id <uuid>
    -> GET /api/v1/provisioners/ca/{caID}
mca provisioner get <provisionerID>
    -> GET /api/v1/provisioners/{provisionerID}
mca provisioner enable/disable <provisionerID>
    -> PUT /api/v1/provisioners/{provisionerID}/enable | /disable

mca profile create/list/get/update/delete ...
    -> /api/v1/profiles...
mca policy create/list/get/update/delete ...
    -> /api/v1/policies...

mca approval create/list/update/delete --provisioner-id <uuid> ...
    -> /api/v1/approval/csr-rules...

mca eab create/list/delete --provisioner-id <uuid> ...
    -> /api/v1/eab/...

mca apikey create/list/rotate/delete ...
    -> /api/v1/apikeys...
    SECURITY: never print the raw key except at creation time (the API
    itself only returns the raw key once — mirror that: the CLI must not
    log/cache it beyond the single command invocation's stdout).

mca audit list [--ca-id <uuid>] [--limit N] [--offset N]
    -> GET /api/v1/audit or /api/v1/audit/ca/{caID}
mca audit verify
    -> GET /api/v1/audit/verify
    Exit code 1 if "ok": false; print broken_at_index/broken_entry_id.
mca audit merkle-root
    -> GET /api/v1/audit/merkle/root
mca audit merkle-proof <index>
    -> GET /api/v1/audit/merkle/proof/{index}
    Also implement local verification: after fetching the proof, recompute
    and compare using the same RFC 6962 algorithm mint-ca uses (see
    "Reimplementing Merkle verification" below) so the CLI's answer doesn't
    just trust the server's own opinion of itself.

mca renewal status [--ca-id <uuid>]
    -> GET /api/v1/renewal/status
    Table output: cert_id (short), subject_cn, days_left, status. Color
    "expired"/"revoked" red, "expiring_soon" yellow, "due" plain, and support
    --format json for machine consumption in scripts/cron.

mca sshca ...
    Mirror docs/Api.md section 1.11 the same way as the X.509 cert tree
    (create/list/get/rekey/cross-sign/issue/sign-user/sign-host/list-certs/
    get-cert/revoke). Lower priority — implement after the X.509 tree is
    complete and tested.

mca setup root-ca / mca setup api-key
    -> POST /setup/root-ca, POST /setup/api-key (bootstrap flow, see
    docs/Setup.md 2.5). Useful for scripting first-boot setup instead of
    curl-ing it by hand. Requires the one-time bootstrap key printed to the
    server's stdout/logs on first boot — accept it via --bootstrap-key or
    prompt interactively (don't accept it as a positional arg that ends up
    in shell history by default; support both but document the risk).

mca version
    Prints CLI version (embed via -ldflags at build time, goreleaser default).
```

### Reimplementing Merkle verification client-side
Port the verification half of `internal/audit/merkle.go`'s algorithm (you
cannot import it — it's an unexported `internal/` package). The essential
pieces, in plain Go with only `crypto/sha256` and `encoding/hex`:

- Leaf hash: `sha256(0x00 || leafBytes)` where `leafBytes` is the raw bytes
  of `hex.Decode(entry_hash)`.
- Node hash: `sha256(0x01 || left || right)`.
- Given `(entry_hash, index, size, proof []string, root_hash)` from
  `GET /api/v1/audit/merkle/proof/{index}`, reconstruct the root by mirroring
  RFC 6962 §2.1.1's recursive audit-path verification: recursively split
  `[0, size)` at `k = largest power of two < size` sub-tree width, descend
  left if `index < k` else right, consuming proof elements in order after
  each recursive step returns, combining with `nodeHash`. Compare hex output
  to `root_hash`.
- Write this as a small internal package (`internal/merkle`) with its own
  unit tests using hand-computed small trees (n=1,2,3,4,8) — do not just trust
  it matches the server; verify against manually-computed hash chains for at
  least n=1..4 the way `internal/audit/merkle_test.go` does in the mint-ca
  repo (you can read that test file for the expected shape of test cases,
  even though you can't import the package).

## TLS trust for self-signed mint-ca deployments
mint-ca commonly runs with a self-signed cert during setup (see Setup.md).
The CLI must support:
- `--ca-cert <path>`: load this PEM into a custom `x509.CertPool` and use a
  `*http.Client` with that pool as `RootCAs`.
- `--insecure-skip-verify`: sets `tls.Config.InsecureSkipVerify = true`.
  Print a loud warning to stderr every time this is used (not just once).
- Default: system trust store (works once the operator replaces the
  self-signed cert with a real one, per Setup.md's production guidance).

## Output formatting (`internal/output`)
- `table`: use `github.com/olekukonko/tablewriter` or hand-rolled
  `text/tabwriter` (prefer the stdlib `text/tabwriter` — one less dependency).
- `json`: `json.MarshalIndent` the raw API response struct.
- `yaml`: `gopkg.in/yaml.v3` marshal of the same struct.
- Every list command supports all three; every single-object "get" command
  supports `json`/`yaml` and a simple key:value table for `table`.

## Testing requirements
- `internal/client`: one test per method, using `httptest.NewServer` serving
  canned JSON matching the exact shapes in `docs/Api.md`. Cover: happy path,
  a 400 error response, a 401/403, and a network-error case (server closed).
- `internal/cmd`: use `cobra`'s command execution against a fake `client.Client`
  (define a `client.API` interface the commands depend on, so tests can pass
  a mock implementing just the methods needed — mirrors mint-ca's own
  "local interface assertion" pattern for keeping fakes small).
- `internal/merkle`: hand-computed small-tree tests as described above.
- No test may require network access or a running mint-ca instance (except
  the separately-gated e2e suite).

## Acceptance bar
- `go build ./...`, `go vet ./...`, `go test ./...` all clean.
- `mca --help` and every subcommand's `--help` render clear usage.
- README.md with: install instructions, `mca login` walkthrough, one example
  per major subcommand group (ca, cert, provisioner, audit, renewal).
- Tag `v0.1.0`, confirm `goreleaser` produces binaries for at least
  linux/amd64, darwin/arm64, windows/amd64.

## Out of scope for v0.1.0
- Interactive TUI (a plain CLI first; a Bubble Tea TUI could be a v2).
- Shell completion beyond what `cobra` generates for free (`mca completion
  bash|zsh|fish` — include this, it's free from cobra, just wire it up).
- Config profiles for multiple mint-ca servers (single `--server`/config file
  target for v0.1.0; revisit if multi-tenancy or multi-cluster use cases
  demand it).
