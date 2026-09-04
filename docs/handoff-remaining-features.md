# Handoff — Remaining mint-ca features

This doc is a starting point for implementing **SCEP (#9)**, **renewal lifecycle**
**intel (#10)**, and **ACME profile intents (#12)** in the `mint-ca` Go server.
It points at exactly where to look in the code and the integration points each
feature should hook into. Read the referenced files before writing code.

## Ground rules (follow these)

- Repo: `github.com/Imnotndesh/mint-ca`. Default branch is `master`. Convention is
  **feature branches → PR → merge** (e.g. `git checkout -b feature/scep` off master).
- Work has been merged as "wildcard-validation" (PR #21). These features are **not**
  yet implemented.
- Pre-release, single user. You do **not** need DB migrations; just extend the schema
  inline (see how `profiles`, `csr_approval_rules`, `policies` tables were added in
  `internal/storage/sqlite.go` AND `internal/storage/postgres.go` together).
- Tests required per feature. Patterns to copy:

  | Concern | File to mirror |
  |---|---|
  | REST handler + local store-interface assertion | `internal/api/handlers/approval.go`, `profiles.go` |
  | Router registration | `internal/api/router.go` (the `/api/v1` authenticated group) |
  | Config struct + env parsing + docs | `internal/config/config.go` + `docs/Setup.md` table |
  | API docs | `docs/Api.md` (sections `1.x`; currently ends at `1.15`) |
  | Background worker | `internal/workers/crl_worker.go` and `internal/renewal/renewal.go` (the `Worker` interface = `Name() string; Run(ctx) error`, added via `apiWorkers.Add(...)` in `cmd/server/main.go`) |
  | ACME order flow | `internal/acme/service.go` (`NewOrder`, `performValidation`, `FinalizeOrder`), route mounting in `internal/api/router.go` (`handlers.NewACMEHandler`) |

- Keep new store methods behind **local interface assertions** in the handler
  (like `csrApprovalStore`, `profileStore`) so you don't force every fake store in
  other packages to implement them.
- `go test ./...` must pass; `go build ./...` clean.

---

## Feature A — SCEP endpoint (#9)

SCEP (Simple Certificate Enrollment Protocol) is what MDM / Windows / iOS and
many device-management stacks expect. This is the biggest differentiator for
embedded/mobile fleets and a cross-over of the existing `mtls` + `SignCSR` work.

### Start here
- `internal/api/handlers/pki.go` — public `/pki/{caID}` routes pattern (SCEP should
  sit near here, public, no API key).
- `internal/mtls/enroll.go` — an existing "device gets a leaf" flow you can collapse
  SCEP onto.
- `internal/ca/engine.go` → `SignCSR(...)` (PCKS#10 / CSR signing already supported).
- `docs/Api.md` `## 1.15 ...` style — add a `## SCEP` section.

### Requirements
1. **Route(s)** (endpoint paths are conventional but verify):
   - `GET /pki/{caID}/scep?operation=GetCACaps`
   - `POST /pki/{caID}/scep` (PKCSReq / GetNextCACert / PKIOperation over HTTP)
   - Many stacks need both GET and POST on the same URL.
2. Support operations: `GetCACaps` (return supported flags/capabilities),
   `GetCACert`, `PKCSReq` (enroll with CSR), `GetNextCACert` (optional; mint-ca
   isn't meant to cross-cert a renewal chain — can return gracefully).
3. **Wire into an existing provisioner** by CA id + optionally an API-key/provisioner
   id for authorization. Use the `mtls`-style onboarding, or simplest: a SCEP provisioner
   that signs via `ca.Engine.SignCSR`.
4. Enforce the same policy/CSR-approval gate as normal signing if applicable
   (`internal/api/handlers/certs.go` → `enforceCSRAutoApproval`).
5. **Config**: toggle via `MINT_SCEP_ENABLED` style env (see `internal/config/config.go`,
   add a `SCEPConfig`).
6. Payload parsing/writing is the fiddliest part — SCEP wraps PKCS#7. If you want to
   avoid a full PKCS#7 dependency, at minimum support the HTTP-transported CSR path
   and clearly document limits. Prefer a well-tested Go SCEP lib if you add one
   (check `go.mod` first — currently only chi, uuid, lib/pq, mattn/sqlite3, x/crypto,
   miekg/dns).

### Tests
Router-level: `GetCACaps`, `GetCACert`, `PKCSReq` happy path returns a signed cert;
reject/deny remains consistent with CSR-approval rules. Unit-test any raw-content
parse/serialize helpers.

---

## Feature B — renewal lifecycle intel (#10)

Turn the CA into a health signal for automation by exposing per-cert renewal risk
and issuance-failure trends, derived from data that already exists.

### Start here
- `internal/renewal/renewal.go` — you already scan certs near expiry
  (`findDue`, webhook deliverer). Reuse this scanning logic.
- `internal/storage/interface.go` → look at `Certificate` fields (`NotBefore`,
  `NotAfter`, `Status`, `ProvisionerID`) and `ListAuditLogsByCA` (audit exists).
- `docs/Api.md` `## 1.15 ...` and the existing `renewalInfo` ACME section (`/acme/.../renewal-info/{certID}`, `internal/api/handlers/acme_renewalinfo_test.go`).

### Requirements
A read-only management endpoint, e.g.:
- `GET /api/v1/renewal/status` (all) and/or `GET /api/v1/renewal/status?ca_id=...`
- Response per cert: `cert_id`, `subject_cn`, `expires_at`, `days_left`,
  `status` (e.g. `valid` / `due` within lead window / `expiring_soon` within a
  shorter window / `revoked` / `expired`). Include the `days_left` thresholds from
  config (`MINT_RENEWAL_LEAD_SECONDS` and a tigher `expiring` window).
- Group/summary: counts of `due`, `expiring_soon`, `expired`, `revoked` so automation
  can alert.
- Reuse the lead window default (7 days) and the renewal config; add a
  `MINT_RENEWAL_EXPIRING_SECONDS` (default e.g. 24–48h) if useful.

### Tests
Pure classification helper unit tests (given a NotAfter + window, report the right
bucket), plus a handler `GET` returning JSON with correct counts. Mirror the
`renewal/renewal_test.go` fake-store style.

---

## Feature C — ACME profile intents (#12)

Allow an ACME order to ask for a **named certificate profile** so that
`profile`-constrained issuance works through ACME too. This bridges the management
API (`profiles`, #4, already done) and ACME worlds.

### Start here
- `internal/acme/service.go` — order/authorization/finalize flow:
  `NewOrder`, `parseOrderIdentifiers`, `performValidation`, `FinalizeOrder`.
- `internal/api/handlers/acme_renewalinfo_test.go` — how ACME handlers + response
  shapes are tested.
- `internal/api/handlers/acme.go` — the ACME handler and its
  `Profile`/provisioner config handling.
- `internal/api/handlers/profiles.go` — the profile CRUD + the `profileStore`
  interface; `internal/policy` `EvaluateProfile` already enforces a profile.
- `internal/acme/service.go`: `ProvisionerConfig` already exists; extend the JSON
  `new-order` payload and/or the provisioner config.

### Requirements
1. Allow the ACME order payload or `meta` to carry an identifier/profile hint, and let
   a provisioner optionally **pin** a profile (provisioner `profile_id` exists on the
   provisioner already — check).
2. In the issue/finalize path, resolve the (pinned or requested) `storage.Profile` by
   name/id and run `policy.EvaluateProfile(...)` against the order's identifiers +
   requested key algo before/during issuance — mirror how the REST
   `POST /api/v1/certs/issue` `"profile":"<name>"` path works in
   `internal/api/handlers/certs.go` (`loadProfileByName` + `EvaluateProfile`).
3. Standard RFC 8555 allows only DNS identifiers, so profile keys like
   subject/domain allowlists map naturally; wildcard handling must respect
   `profile.AllowWildcard` (subdomain authorization for wildcards still requires
   the normal ACME http/dns validation).
4. Expose the applicable profile in the response/metadata and document it.

### Tests
- ACME `NewOrder`/`FinalizeOrder` with a pinned + a requested profile: a request
  violating the profile (e.g. wildcard when disallowed, over-TTL) is refused.
- Matching request issues successfully, with the cert reflecting the profile.

---

## Acceptance bar
For each: `go build ./...`, `go test ./...`, and a short `docs/Api.md` +
`docs/Setup.md` (config env) entry, then push and open a PR to `master`.

---
_Generated as a handoff for the three remaining in-repo features (SCEP #9,
renewal lifecycle #10, ACME profile intents #12). Out of scope here: the
Terraform/Ansible provider (external project) and the `mca` CLI (deferred until
all APIs are documented)._
