# Plan — Multi-Tenancy for mint-ca

## Objective
Let a single running mint-ca instance (`github.com/Imnotndesh/mint-ca`) serve
several teams/customers ("tenants") with each tenant's CAs, provisioners,
profiles, policies, API keys, and certificates fully invisible to every
other tenant — while a small set of "platform admin" API keys can still see
and manage everything, for the operator running the shared instance.

**This plan modifies the mint-ca server itself** (unlike the CLI, Terraform
provider, and cert-manager plans, which are separate repos calling mint-ca's
REST API from outside). Work happens directly in this repo, on a feature
branch, following the repo's existing conventions — read `CLAUDE.md` if one
exists, otherwise infer conventions from the surrounding code exactly as
described in `docs/handoff-remaining-features.md`'s "Ground rules" section
(local interface assertions for new store methods, `fmt.Errorf("pkg:
context: %w", err)` wrapping, `slog` for logging, no unnecessary comments,
`gofmt`/`go build ./...`/`go test ./...` clean before every commit,
tests-first).

**Read this whole plan before writing any code.** This is the largest and
most invasive of the five plans in `docs/plans/` — it touches nearly every
handler in `internal/api/handlers/`. It is written as sequential phases;
each phase should be its own PR, fully tested and mergeable on its own,
because attempting the whole thing in one change is unreviewable and risky.
Do not skip ahead to a later phase before the current one's acceptance
criteria are met.

## Important discovery to verify before starting
As of the time this plan was written, `storage.APIKey` already has a `CAID
*uuid.UUID` field (`internal/storage/interface.go`) — but grep the current
codebase (`grep -rn "apiKey.CAID\|APIKey.CAID" internal/`) to confirm: **this
field is stored but not currently enforced anywhere** — no middleware or
handler filters by it. That means the shape of per-key scoping already
exists in the schema but was never wired into a real access-control
boundary. This plan supersedes/replaces that unused field with a more
general `TenantID` (a tenant can own multiple CAs, so a single `CAID` on an
API key is a strictly narrower and now-redundant concept once tenants
exist) — Phase 1 should decide, based on whatever the codebase looks like
when you start, whether to migrate `APIKey.CAID` usage into the new tenant
model or leave it as a separate, still-unused legacy field to remove in a
follow-up cleanup. Check `git log -p --follow internal/storage/interface.go`
for `CAID` on `APIKey` to see whether anything started depending on it since
this plan was written.

## Core design decisions (do not deviate without a good reason)

1. **Tenant is the scoping unit, not individual resources.** A `Tenant` is a
   new top-level entity. Every resource that should be tenant-private gets a
   `TenantID uuid.UUID` field (required, not nullable, once migrated — see
   Phase 0). A resource with no natural tenant of its own (e.g. a
   `Certificate`) is scoped **transitively** through the CA it belongs to —
   do not add a redundant `TenantID` to certificates; derive tenant
   membership from `Certificate.CAID -> CertificateAuthority.TenantID` at
   query time, in code, the same way audit logs are already filtered by
   `ca_id` in `ListAuditLogsByCA`.

2. **An API key belongs to exactly one tenant, or is a platform-admin key.**
   Add `TenantID *uuid.UUID` to `storage.APIKey` (nil = platform admin, only
   creatable by an existing platform-admin key or during initial setup —
   see Phase 1). A platform-admin key bypasses all tenant filtering. A
   tenant-scoped key can only ever see/act on rows whose `TenantID` matches
   its own. There is no "key with access to multiple specific tenants" in
   v1 — if that's needed later, it's an additive change (a join table), not
   a redesign.

3. **Enforcement happens in the handler layer, not the storage layer**,
   mirroring the existing local-interface-assertion convention: add a
   `tenantScopedStore` (or similar) local interface per handler that needs
   it, requiring `ListXByTenant`/`GetXByIDAndTenant`-shaped methods, so
   fakes elsewhere in the test suite aren't forced to implement tenant
   awareness. Do **not** try to make tenant filtering a cross-cutting SQL
   `WHERE` clause injected transparently at the `storage.Store` interface
   level — that's a much bigger refactor (every one of the ~15
   `List*`/`Get*` methods across both `sqlite.go` and `postgres.go` would
   need a tenant-aware variant) and this plan phases it in per-resource
   instead, matching how features have been added to this codebase
   historically (see `docs/handoff-remaining-features.md` and
   `docs/plans/*` for the established pattern of additive, local-interface,
   one-resource-at-a-time changes).

4. **Context propagation**: the `Auth` middleware
   (`internal/api/middleware/auth.go`) already stores the resolved
   `*storage.APIKey` in the request context under `APIKeyKey`. Add a small
   helper `middleware.TenantIDFromContext(ctx) (*uuid.UUID, bool)` that pulls
   it from there (reads `apiKey.TenantID`; `bool` is false if no API key is
   in context at all, which shouldn't happen inside the authenticated route
   group but guard anyway). Every handler that needs tenant scoping calls
   this instead of re-deriving it from scratch.

## Schema changes (additive — no destructive migration, per the codebase's
"pre-release, no migrations needed, extend inline" convention referenced in
`docs/handoff-remaining-features.md` — **confirm this is still the stated
policy before starting**; if mint-ca has since gone to a real
migration-managed schema, follow whatever that current process is instead
of what's described here)

1. New `tenants` table (both `internal/storage/sqlite.go` and
   `internal/storage/postgres.go`, in their respective big schema
   constants):
   ```sql
   CREATE TABLE IF NOT EXISTS tenants (
       id         TEXT/UUID   NOT NULL PRIMARY KEY,
       name       TEXT        NOT NULL UNIQUE,
       status     TEXT        NOT NULL DEFAULT 'active', -- 'active' | 'suspended'
       created_at DATETIME/TIMESTAMPTZ NOT NULL
   );
   ```
   Seed a single default tenant on first boot (in `internal/setup`, wherever
   the root CA/bootstrap API key are seeded today) with a **fixed, well-known
   UUID** (e.g. the all-zero UUID `00000000-0000-0000-0000-000000000000`,
   or a name-based UUIDv5 derived from a constant string like
   `"mint-ca-default-tenant"` via `uuid.NewSHA1`) so every pre-existing
   single-tenant deployment's rows can be backfilled to point at it
   deterministically without needing a runtime-generated ID.

2. Add `tenant_id` columns (`NOT NULL`, `REFERENCES tenants(id)`) to:
   `certificate_authorities`, `provisioners`, `profiles`, `policies`,
   `api_keys`, `csr_auto_approve_rules`, `eab_keys` (or whatever the actual
   EAB key table is named — check `internal/storage/sqlite.go` for the exact
   name), `ssh_certificate_authorities`. For every existing row at migration
   time, default to the seeded default tenant's ID (`DEFAULT
   '<fixed-uuid>'` in the `ALTER TABLE`/`CREATE TABLE` statement, or an
   explicit backfill `UPDATE ... SET tenant_id = '<fixed-uuid>' WHERE
   tenant_id IS NULL` if the schema is built via `CREATE TABLE IF NOT
   EXISTS` and won't retroactively add a column to an already-existing
   table — check how prior additive columns in this codebase handled that;
   `docs/handoff-remaining-features.md` mentions `profiles`,
   `csr_approval_rules`, `policies` were added this way before, so read how
   those were actually implemented in `sqlite.go`/`postgres.go` for the
   established idiom and match it exactly).

3. `Certificate` and SSH certificate records do **not** get a `tenant_id`
   column — see design decision 1. `AuditLog` similarly stays as-is;
   tenant-scoping the audit log means filtering by the tenant of `CAID`
   where present, and by the API key's own tenant for entries with no
   `CAID` (e.g. a tenant's own API-key-management actions) — Phase 5 covers
   this specifically since it's the trickiest case (some audit events, like
   the HA leader-election worker's own actions if any are ever logged, have
   no natural tenant at all and should only be visible to platform admins).

## Phase 0 — Storage & Tenant CRUD
- Add `Tenant` to `internal/storage/interface.go`:
  ```go
  type TenantStatus string
  const (
      TenantStatusActive    TenantStatus = "active"
      TenantStatusSuspended TenantStatus = "suspended"
  )
  type Tenant struct {
      ID        uuid.UUID    `json:"id"`
      Name      string       `json:"name"`
      Status    TenantStatus `json:"status"`
      CreatedAt time.Time    `json:"created_at"`
  }
  ```
  Add `CreateTenant`, `GetTenant`, `GetTenantByName`, `ListTenants`,
  `UpdateTenantStatus` to the `Store` interface directly (unlike later
  phases, Tenant CRUD has no scoping ambiguity — every deployment needs
  these regardless of which resources are tenant-aware yet, so this is the
  one place adding directly to `Store` is appropriate rather than a local
  handler interface).
- Implement in both `sqlite.go` and `postgres.go`, following the exact
  pattern of an existing simple CRUD entity in this codebase (read
  `internal/storage/sqlite.go`'s `Profile` methods — `CreateProfile`,
  `GetProfile`, `GetProfileByName`, `ListProfiles` — and mirror that
  structure precisely for `Tenant`).
- Add the schema changes from the "Schema changes" section above, including
  the seeded default tenant.
- New `TenantHandler` in `internal/api/handlers/tenant.go`:
  - `POST /api/v1/tenants` — platform-admin only (see Phase 1 for how that
    check is implemented; until Phase 1 lands, gate this behind a TODO and a
    loud comment, or implement Phase 1's platform-admin check first since
    Tenant creation is meaningless without it — consider merging Phase 0 and
    Phase 1 into one PR if that's cleaner, this plan separates them only for
    exposition).
  - `GET /api/v1/tenants` — platform-admin only.
  - `GET /api/v1/tenants/{tenantID}` — platform-admin, or a tenant-scoped key
    reading its own tenant.
  - `PUT /api/v1/tenants/{tenantID}/suspend` / `/activate` — platform-admin
    only. Suspending a tenant should cause every subsequent authenticated
    request from that tenant's API keys to fail with `403` (enforced in the
    `Auth` middleware itself, per Phase 1's design — check the tenant's
    status right after resolving the API key, before the request reaches
    any handler).
- Tests: standard CRUD unit tests for the store methods (mirror
  `internal/storage/audit_chain_test.go`'s use of `newSQLiteStore(":memory:")`
  for a fast in-process test), plus handler tests for every route above
  using a fake store (mirror the `csrApprovalFakeStore`/`auditChainFakeStore`
  local-fake pattern used throughout `internal/api/handlers/*_test.go`).

**Phase 0 acceptance**: `go build ./...`, `go test ./...` clean; a fresh
sqlite DB boots with exactly one (default) tenant; Tenant CRUD works
end-to-end; no existing behavior changes for any other resource yet (this
phase is purely additive scaffolding).

## Phase 1 — API keys become tenant-aware; platform-admin concept
- Add `TenantID *uuid.UUID` to `storage.APIKey` (nil = platform admin).
- Update `internal/api/handlers/api_keys.go`'s create endpoint: a
  platform-admin caller may create a key for any tenant (`tenant_id` in the
  request body) or another platform-admin key (`tenant_id` omitted +
  requires an explicit `"platform_admin": true"` flag in the request, so
  it's never accidental); a tenant-scoped caller may only create keys for
  their own tenant (silently force `tenant_id` to their own, ignoring/
  rejecting a mismatched value in the request body with `400`).
- Update `internal/api/middleware/auth.go`'s `Auth` middleware:
  1. After resolving the `*storage.APIKey` as it does today, if
     `apiKey.TenantID != nil`, look up that tenant (`store.GetTenant`) and
     reject with `403` if its status is `suspended`.
  2. Store the resolved `*storage.APIKey` in context exactly as it does
     today (no change needed there — `TenantID` is already reachable off
     it); add the `TenantIDFromContext` helper described in design decision
     4, in the same file or a new `internal/api/middleware/tenant.go`.
- Bootstrap flow (`internal/setup`): the very first API key created during
  `POST /setup/api-key` (see `docs/Api.md` §1.13, `docs/Setup.md` §2.5)
  should be a **platform-admin** key (`tenant_id = nil`) — the person
  standing up the instance is, by definition, the platform operator. Any
  tenant-scoped keys are created afterward, by that platform-admin key,
  via `POST /api/v1/tenants` + `POST /api/v1/apikeys` with a `tenant_id`.
- Tests: `Auth` middleware tests covering — a suspended tenant's key is
  rejected; an active tenant's key passes; a platform-admin key passes
  regardless of tenant state; `TenantIDFromContext` returns the right value
  in each case.

**Phase 1 acceptance**: platform-admin vs. tenant-scoped keys are a real,
enforced distinction; suspending a tenant actually locks it out; every
existing single-tenant deployment keeps working unchanged (its one API key,
created before this change, has `tenant_id = NULL` after migration —
**decide explicitly**: should pre-existing keys become platform-admin, or
get backfilled to the default tenant? Recommendation: backfill existing keys
to the default tenant, *not* platform-admin, since that preserves the
principle that a key's privileges shouldn't silently expand across an
upgrade — then have the bootstrap/migration path additionally mint one new
platform-admin key and print it once at startup, the same way the original
bootstrap key is printed per `docs/Setup.md` §2.5, so operators upgrading an
existing instance get a clear, one-time, loud message telling them how to
regain platform-admin access).

## Phase 2 — Scope CA, Provisioner, Profile, Policy handlers
For each of `internal/api/handlers/ca.go`, `provisioners.go`, `profiles.go`,
`policies.go`:
1. Add `TenantID` to the corresponding `storage` struct
   (`CertificateAuthority`, `Provisioner`, `Profile`, `Policy`).
2. Add tenant-aware store methods behind a local interface in each handler
   file (following the `csrApprovalStore`/`profileStore` pattern already
   used in this codebase), e.g.:
   ```go
   type tenantScopedCAStore interface {
       ListCAsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*storage.CertificateAuthority, error)
   }
   ```
   Implement the backing SQL in both `sqlite.go`/`postgres.go` as a
   `WHERE tenant_id = ?` variant of the existing `ListCAs` query.
3. On every **Create**: set `TenantID` from `middleware.TenantIDFromContext`
   (platform-admin keys creating a resource must supply an explicit
   `tenant_id` in the request body — there's no context to default to; a
   platform-admin key with no `tenant_id` in the body should be rejected
   with `400 "tenant_id is required for platform-admin-created resources"`,
   this keeps every row unambiguously owned by exactly one tenant).
4. On every **List**: if the caller is tenant-scoped, call the new
   `ListXByTenant` method instead of the unscoped `ListX`. If the caller is
   platform-admin, keep the existing unscoped behavior (platform admins see
   everything) — optionally support an explicit `?tenant_id=` query filter
   for platform-admin callers who want to narrow their view.
5. On every **Get-by-ID**: fetch normally, then compare the row's
   `TenantID` to the caller's tenant (skip the check entirely for
   platform-admin callers). **On mismatch, return `404`, not `403`** — this
   is a deliberate security choice: a tenant-scoped caller must not be able
   to distinguish "doesn't exist" from "exists but belongs to someone else"
   by response code, or they learn information about other tenants' resource
   existence/IDs. Apply this "404 on cross-tenant access" rule consistently
   to every Get/Update/Delete/Revoke/etc. across every phase of this plan —
   it's the single most important invariant multi-tenancy depends on; a
   security reviewer should be able to grep every handler for this pattern
   and find it applied uniformly.
6. **Provisioner's `CAID` cross-check**: when creating a Provisioner,
   additionally verify the referenced CA belongs to the same tenant as the
   caller (or, for platform-admin, the same tenant as the `tenant_id` given
   in the request) — otherwise a tenant could create a provisioner pointing
   at another tenant's CA. Return `400` on mismatch (this is a validation
   error, not an existence-hiding concern, since the caller already knows
   which `ca_id` they supplied).

Tests: for each handler, add cases mirroring the existing test files'
structure — tenant A cannot list/get/update tenant B's resources (expect
404), platform-admin can see both, creating a provisioner against a
foreign-tenant CA is rejected.

**Phase 2 acceptance**: CA, Provisioner, Profile, Policy are all fully
tenant-isolated per the rules above, with tests proving it; existing
single-tenant behavior (everything under the default tenant) is unchanged
for a platform-admin key, and identical in practice for a default-tenant
key since there's nothing else to be isolated from yet.

## Phase 3 — Scope Certificates (transitively) and CSR approval rules / EAB keys
- `internal/api/handlers/certs.go`: certificates have no `TenantID` of their
  own (design decision 1). Every handler that takes a `ca_id` (issue, sign,
  batch-sign) must first resolve that CA and apply the same tenant check as
  Phase 2's CA handler (404 on mismatch) **before** doing any crypto work —
  mirror exactly how `enforceCSRAutoApproval` and profile checks already run
  before `h.engine.SignCSR`/`IssueCert` in the current code, so tenant
  checking becomes just one more pre-flight gate in the same style.
- Every handler that takes a bare `cert_id` (get, revoke, export, key) must
  look up the certificate, then look up its CA, then apply the tenant check
  against the CA's `TenantID` — a two-hop lookup, but still no schema change
  needed on `Certificate` itself.
- `internal/api/handlers/approval.go` (CSR auto-approval rules) and
  `internal/api/handlers/eab.go` (EAB keys): both are keyed by
  `provisioner_id`. Add `TenantID` to `CSRAutoApproveRule` directly (it's a
  first-class resource with its own list/create/update/delete, unlike
  certificates) rather than deriving it transitively through the
  provisioner every time — set it at creation time from the provisioner's
  own `TenantID` (validated to match the caller, same as Phase 2's
  provisioner-CA check) and enforce identically to Phase 2's pattern. Decide
  the same way for EAB keys — check whether the current EAB key storage
  struct is a good candidate for a direct `TenantID` (likely yes, for the
  same reasons) versus purely transitive scoping.

**Phase 3 acceptance**: a tenant-scoped key cannot issue/sign/read/revoke/
export a certificate under another tenant's CA (404), cannot create or see
CSR approval rules or EAB keys for another tenant's provisioners (404), and
every existing single-tenant certificate operation still works unchanged.

## Phase 4 — SCEP, ACME, and SSH CA scoping
- `internal/api/handlers/scep.go`: SCEP is a **public, unauthenticated**
  endpoint (`docs/Api.md` §1.18) gated only by `MINT_SCEP_PROVISIONER_ID` —
  a single, server-wide provisioner. Multi-tenant SCEP needs either (a) one
  SCEP provisioner per tenant with distinct URL paths
  (`/pki/{caID}/scep` already includes `caID` in the path — since CAs are
  now tenant-scoped, resolving `caID` already naturally resolves which
  tenant's policy applies; **no SCEP-specific code change may be needed
  here at all** beyond making sure the provisioner referenced by
  `MINT_SCEP_PROVISIONER_ID` belongs to the same tenant as `{caID}` in the
  URL — add that one cross-check), or (b) leave single-tenant SCEP as a
  known limitation for v1 and document it. Recommendation: do (a), it's a
  small addition, not a redesign.
- ACME (`internal/acme/service.go`, `internal/api/handlers/acme.go`):
  provisioners are already resolved per-request via the URL
  (`/acme/{provisionerID}/...`); once `Provisioner.TenantID` exists from
  Phase 2, ACME issuance naturally inherits tenant scoping through the
  provisioner → CA chain with no ACME-specific authorization model needed —
  ACME itself has no API-key concept (it's client-authenticated via ACME
  account keys, a separate trust model entirely), so there is nothing to
  "scope" beyond making sure the provisioner's CA lookups go through the
  same tenant-aware code paths Phase 2/3 already built. Audit this file
  carefully rather than assuming — confirm no ACME code path bypasses the
  provisioner/CA resolution helpers Phase 2/3 touched.
- `internal/api/handlers/sshca.go`: mirror Phases 2–3's approach exactly,
  applied to `SSHCertificateAuthority` and SSH certificates, since the
  shapes are structurally identical to the X.509 CA/certificate case
  (`LogicalCAID`-based rekey, same revoke/list/get pattern).

**Phase 4 acceptance**: SCEP enrollment against a given `{caID}` is refused
if the configured SCEP provisioner belongs to a different tenant than that
CA; ACME issuance is confirmed to inherit tenant scoping correctly via
tests exercising two tenants' provisioners; SSH CA handlers pass the same
cross-tenant-404 test suite as Phase 2/3's X.509 equivalents.

## Phase 5 — Audit log, renewal status, and metrics scoping
- `internal/api/handlers/audit.go`: `ListAuditLogs` (unscoped, all entries)
  must become platform-admin-only; tenant-scoped callers get
  `ListAuditLogsByCA` filtered further by tenant (an entry's `ca_id`, when
  present, must belong to the caller's tenant; an entry with no `ca_id` at
  all — e.g. a tenant-management action — needs its own tenant attribution:
  add `TenantID *uuid.UUID` directly to `AuditLog` itself, populated from
  context at write time in `internal/api/middleware/audit.go`, so every
  entry is unambiguously attributable regardless of whether it also has a
  `ca_id`). This also affects the audit hash chain (`internal/audit`) and
  the Merkle log (`internal/audit/merkle.go`) built in a prior phase of this
  project's history — **decide and document explicitly**: is the hash chain
  one global chain across all tenants (simplest, keeps the existing
  single-`audit_chain_state` design, but means `GET /api/v1/audit/verify`
  and the Merkle endpoints must stay platform-admin-only since verifying
  requires seeing the whole chain), or does each tenant get its own
  independent chain (more isolation, meaningfully more storage/schema work:
  a `tenant_id` column on `audit_chain_state` turning the singleton row into
  one row per tenant, and the same for the Merkle tree's leaf ordering).
  **Recommendation: keep one global chain, restrict verify/Merkle endpoints
  to platform-admin.** Multi-tenant chain-splitting is a legitimate future
  enhancement but meaningfully larger scope than this phase should take on.
- `internal/api/handlers/renewal.go`: `GET /api/v1/renewal/status` already
  supports `?ca_id=` filtering (see `docs/Api.md` §1.16) — for a
  tenant-scoped caller, restrict the underlying `ForEachCert` CA iteration
  (`internal/renewal/status.go`) to only that tenant's CAs even when no
  `?ca_id=` filter is given (currently it iterates every CA via
  `store.ListCAs`; swap to the tenant-aware `ListCAsByTenant` from Phase 2
  for non-platform-admin callers).
- `internal/api/handlers/metrics.go`: the `/metrics` Prometheus endpoint is
  typically scraped by infrastructure, not per-tenant — **recommendation:
  leave `/metrics` platform-admin/operator-only** (it already requires
  authentication via the API-key middleware group) rather than trying to
  produce per-tenant Prometheus label dimensions in v1; revisit only if a
  concrete per-tenant observability requirement appears.

**Phase 5 acceptance**: a tenant-scoped key cannot read another tenant's
audit entries or renewal status; platform-admin retains full visibility;
audit/Merkle verification endpoints are explicitly platform-admin-gated with
a test proving a tenant-scoped key gets `403`.

## Phase 6 — Documentation and cleanup
- Update `docs/Api.md`: every endpoint touched above gets a note on its
  tenant-scoping behavior (mirror the level of detail already present for,
  e.g., the CSR auto-approval rules section's "default posture" callout).
- Update `docs/Setup.md`: document the platform-admin bootstrap flow, the
  `POST /api/v1/tenants` flow for onboarding a new tenant, and the migration
  behavior for existing single-tenant deployments upgrading into a
  multi-tenant-capable version (the "one new platform-admin key printed once
  at startup" behavior from Phase 1).
- Remove or repurpose the legacy unused `APIKey.CAID` field per the
  "Important discovery" section above, once you've confirmed (via the git
  history check described there) that nothing came to depend on it in the
  meantime.

## Testing philosophy across all phases
Every phase's acceptance criteria above already lists its required test
coverage; the overarching rule is: **every new authorization boundary
(tenant A vs. tenant B, tenant-scoped vs. platform-admin) needs an explicit
test proving the boundary holds**, not just a test proving the happy path
works. A handler that merely "works" without a cross-tenant-denial test is
not done, for this feature specifically — multi-tenancy is a security
boundary, and an untested security boundary is not a boundary.

## Out of scope for v1 of this feature
- Per-tenant rate limiting (the existing `internal/ratelimit` engine is
  server-wide; making it tenant-aware is a separate, additive project once
  this lands).
- Per-tenant custom domains/TLS certs for the mint-ca server itself (i.e.
  tenants reaching the API via different hostnames) — out of scope, all
  tenants share the same server endpoint and are distinguished purely by
  API key.
- Cross-tenant resource sharing/delegation (e.g. tenant A allowing tenant B
  to use one of its CAs) — no such concept in v1; every resource has exactly
  one owning tenant, full stop.
- A billing/usage-metering layer — purely an isolation feature, not a
  multi-tenant SaaS platform, in this scope.
