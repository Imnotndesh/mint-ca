# Plan — Web UI Dashboard for mint-ca

## Objective
Build a browser-based admin dashboard for mint-ca
(`github.com/Imnotndesh/mint-ca`) so an operator can manage CAs,
certificates, provisioners, profiles/policies, API keys, and review
audit/renewal status visually, instead of using `curl` or the `mca` CLI for
everything. This is a **separate repo**, a static single-page app (SPA) that
talks to mint-ca purely over its existing REST API (`docs/Api.md`) — it does
not require any change to the mint-ca server itself (the server already
serves the API over HTTPS with CORS not currently enabled; see "CORS"
below for the one change that likely *is* needed server-side, called out
explicitly since it's the one exception to "no server changes").

Read `docs/Api.md` and `docs/Setup.md` in full before starting.

## Ground rules
- Stack: **React + TypeScript + Vite**, **TanStack Query** for all API data
  fetching/caching/mutations, **Tailwind CSS** + **shadcn/ui** for
  components, **React Router** for client-side routing. This combination is
  chosen because it's extremely well-documented, has the largest available
  training/reference surface for an LLM implementer to draw on correctly,
  and matches what most operators evaluating a homelab/SME tool will expect
  to be able to read and modify themselves. Do not substitute a different
  stack (Vue, Svelte, Angular, etc.) without discussing it first — this
  plan's page-by-page instructions assume React idioms throughout.
- `npm run build`, `npm run lint`, `npm run test` must all pass clean before
  every commit. Use `eslint` + `@typescript-eslint` + `prettier`, configured
  via Vite's default TypeScript template plus those additions.
- Testing: **Vitest** + **React Testing Library** for component/page tests,
  **MSW** (Mock Service Worker) to intercept and fake mint-ca API calls in
  tests — no test may require a live mint-ca server. A small number of
  Playwright end-to-end tests against a real local mint-ca instance are
  welcome as an opt-in suite (`npm run test:e2e`, not part of the default
  `npm run test`), mirroring the e2e-suite pattern in the CLI plan.
- Accessibility: every interactive element must be keyboard-navigable and
  have an accessible name (label/aria-label) — run `eslint-plugin-jsx-a11y`
  as part of lint. This is a real requirement, not a nice-to-have, because
  admin tools are used under stress (an operator debugging a production
  outage at 2am should not be fighting a UI).

## CORS — the one server-side consideration
mint-ca's router (`internal/api/router.go`) does not currently set any CORS
headers. A browser-based SPA served from a different origin than the mint-ca
API (the common case: dashboard on `https://dashboard.example.com`, API on
`https://ca.internal:8443`) will be blocked by the browser's CORS policy
unless mint-ca sends `Access-Control-Allow-Origin` (and handles `OPTIONS`
preflight requests) for the dashboard's origin.

**This plan's primary recommendation: do not modify the mint-ca server.**
Instead, ship the dashboard with clear deployment guidance to **reverse-proxy
it behind the same origin as the API** (e.g. an nginx/Caddy config serving
the built SPA's static files at `/` and proxying `/api/`, `/pki/`, `/acme/`,
`/setup/`, `/healthz` through to the real mint-ca backend) — this sidesteps
CORS entirely and is standard practice for admin SPAs paired with a
same-deployment backend. Provide a working example (`deploy/Caddyfile` and
`deploy/nginx.conf` in the dashboard repo) as part of the deliverable.

If reverse-proxying genuinely isn't viable for a given deployment, a
follow-up, opt-in change to mint-ca's own router (a `MINT_CORS_ALLOWED_ORIGINS`
env var, applied as middleware in `internal/api/router.go`, following the
existing config-struct-plus-env-parsing pattern in `internal/config/config.go`)
would be the right shape — but do not build that as part of this dashboard
project without separately confirming it's wanted, since it's a change to a
different repo with its own review process.

## Authentication model
mint-ca has no browser-native login flow — it's a bearer API key. Design:

1. On first load with no stored session, show a **Connect** screen: fields
   for **Server URL** and **API Key**. On submit, verify the key works by
   calling a cheap authenticated endpoint (e.g. `GET /api/v1/audit?limit=1`)
   before proceeding — surface a clear error if it fails (bad key, wrong
   URL, network/TLS error — distinguish these in the error message; a
   self-signed-cert TLS error looks different from a 401 and the user needs
   to know which one they're dealing with).
2. Store `{ serverUrl, apiKey }` in `sessionStorage`, **not**
   `localStorage`, so a closed browser tab requires re-entering the key
   (reduces the blast radius of an XSS or a shared/public machine — document
   this trade-off explicitly in the README, and offer a "remember this
   server+key on this device" opt-in checkbox that, only if checked, persists
   to `localStorage` instead, with a visible warning next to the checkbox).
3. A `useAuth()` hook / React context wraps this, exposing `serverUrl`,
   `apiKey`, `logout()` (clears storage), and `isAuthenticated`.
4. Every API call goes through one central `apiClient` (see below) that
   reads the current key from this context/storage and attaches
   `Authorization: Bearer <key>` — never hand-attach headers per call-site.
5. On any `401` response from any call, immediately clear the stored session
   and redirect to the Connect screen — the key was revoked/rotated/expired.
6. Self-signed TLS: the browser handles TLS trust, not this app — if the
   mint-ca server uses a self-signed cert (common per `docs/Setup.md`'s
   first-boot behavior), the user must first navigate to the API's base URL
   directly in their browser and accept the certificate warning once, before
   the dashboard's fetch calls will succeed (browsers don't allow JS to
   override certificate trust). Document this clearly on the Connect screen
   itself as inline help text, not just in a README nobody reads at 2am.

## API client (`src/api/client.ts`)
One hand-written TypeScript client, generated types mirrored from
`docs/Api.md`'s documented request/response JSON shapes (do not attempt to
auto-generate from an OpenAPI spec — mint-ca does not ship one). Structure:

```ts
// src/api/types.ts — one interface per resource, matching docs/Api.md exactly
export interface CertificateAuthority {
  id: string;
  name: string;
  type: "root" | "intermediate";
  status: "active" | "revoked" | "expired" | "superseded";
  cert_pem: string;
  key_algo: string;
  not_before: string;
  not_after: string;
  created_at: string;
  logical_ca_id?: string;
  parent_id?: string;
}
// ... one per resource: Certificate, Provisioner, Profile, Policy, APIKey,
// AuditLogEntry, CSRAutoApproveRule, RenewalStatusResponse, etc.

// src/api/client.ts
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export class ApiClient {
  constructor(private baseUrl: string, private apiKey: string) {}

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { ...init?.headers, Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, body.error ?? res.statusText);
    }
    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
  }

  listCAs() { return this.request<CertificateAuthority[]>("/api/v1/ca"); }
  getCA(id: string) { return this.request<CertificateAuthority>(`/api/v1/ca/${id}`); }
  createRootCA(body: CreateRootCARequest) { return this.request<CertificateAuthority>("/api/v1/ca/root", { method: "POST", body: JSON.stringify(body) }); }
  // ... one method per endpoint actually used by a page below.
}
```
Every request body sent must match the exact field names in `docs/Api.md` —
mint-ca's handlers decode with `DisallowUnknownFields()`
(`internal/api/handlers/helpers.go`), so an extra field causes a `400`.
Wrap every `ApiClient` method in a TanStack Query `useQuery`/`useMutation`
hook in `src/api/hooks.ts` (e.g. `useCAs()`, `useCreateRootCA()`) — pages
should never call `ApiClient` methods directly, always through these hooks,
so caching/invalidation stays centralized (e.g. `useCreateRootCA`'s
`onSuccess` should invalidate the `useCAs` query key).

## Pages / routes

### `/` — Dashboard home
Summary cards + a renewal-risk table, the "at a glance" landing page:
- Cards: total active CAs (`GET /api/v1/ca`, count `status === "active"`),
  certs due/expiring/expired/revoked (`GET /api/v1/renewal/status`, §1.16 —
  use the `summary` object directly), audit chain health (`GET
  /api/v1/audit/verify`, §1.7 — green check or red "tampering detected"
  banner, this should be impossible to miss if `ok: false`).
- A table of the `certificates` array from `/api/v1/renewal/status`, sorted
  by `days_left` ascending, with status badges (color-coded: `expired`/
  `revoked` red, `expiring_soon` amber, `due` blue), linking each row to
  `/certificates/:id`.
- Poll this page's queries on a reasonable interval (TanStack Query's
  `refetchInterval`, e.g. 60s) so it stays live without a manual refresh —
  this is the page an operator leaves open on a second monitor.

### `/cas` — Certificate Authorities
- Table: name, type (root/intermediate), status, key algo, not_after,
  actions (view, revoke, rekey, cross-sign). Source: `GET /api/v1/ca`.
- "Create CA" button opens a form (root or intermediate — a toggle at the
  top of the form changes which fields show, per `docs/Api.md` §1.1's two
  distinct request bodies) submitting to the matching endpoint.
- `/cas/:id` detail page: full CA metadata, its `cert_pem` (with a
  copy-to-clipboard button and a "download .pem" button), its children
  (`GET /api/v1/ca/{caID}/children`), its cross-certs
  (`GET /api/v1/ca/{caID}/cross-certs`), and action buttons for revoke,
  rekey (opens a confirmation dialog explaining the logical-CA-ID behavior
  from §1.1's rekey docs, since this is a surprising operation to a new
  user — quote the relevant doc text directly in the dialog), and
  cross-sign.

### `/certificates` — Certificates
- This list is necessarily scoped to a CA (mint-ca has no "list all certs
  across all CAs" endpoint — check `docs/Api.md` §1.2, only
  `GET /api/v1/certs/ca/{caID}` exists) — so this page is really
  `/cas/:caId/certificates`, reached via a tab on the CA detail page rather
  than a standalone top-level nav item. Table: serial, subject_cn, status,
  not_after, actions (view, revoke, export, retrieve key if escrowed).
- `/certificates/:id` detail page: full cert metadata, SANs (including any
  `uri` SANs — render a `spiffe://` one specially, e.g. with a small SPIFFE
  badge, since §1.21 makes this a first-class feature worth surfacing), the
  cert PEM (copy/download), and an "Export" dropdown offering the three
  formats from §1.2's export docs — tar.gz, PKCS#12, JKS — each opening a
  small dialog for the relevant password/passcode fields before triggering
  the download (the browser `fetch` response body is a `Blob`; trigger a
  download via a temporary `<a download>` link, standard browser pattern).
- An "Issue Certificate" form (reachable from a CA's certificates tab):
  every field from §1.2's `POST /api/v1/certs/issue` request body — common
  name, DNS/IP/email/URI SANs, a dedicated SPIFFE ID input with inline
  validation feedback (mirror the client-side shape of validation described
  in `docs/plans/cli-mca.md`'s Merkle section's spirit: give immediate
  feedback rather than only surfacing the server's `400` after submit, by
  running a simple regex-based sanity check for the `spiffe://` scheme
  client-side, while still treating the server's validation as authoritative
  and displaying its exact error message if it disagrees), TTL, key algo,
  server/client auth checkboxes, profile dropdown (populated from
  `GET /api/v1/profiles`), store-key + passcode fields, and a results panel
  showing the returned `cert_pem`/`key_pem`/`chain_pem` with copy/download
  buttons **and a loud, impossible-to-miss warning that `key_pem` is shown
  exactly once and mint-ca does not retain it unless "store key" was
  checked** — this mirrors the API's own one-time-return semantics and the
  UI must not undersell how easy it is to lose that key forever.

### `/provisioners`, `/profiles`, `/policies` — Policy configuration
Standard CRUD list+detail+form pages for each, following §1.3/§1.4. These
are the most "boring," standard-CRUD-table pages in the app — implement them
last, after the more bespoke pages above, since they're the most
mechanically repetitive and benefit from whatever shared
table/form/dialog components get built for the earlier pages.

### `/approval-rules` — CSR Auto-Approval Rules
Per §1.15. List filterable by provisioner, create/edit form with the regex
fields (`allowed_common_names`, `allowed_dns`) — render a live "test a CSR
against this rule" widget if time allows (paste a CN/DNS list, get an
instant client-side regex match/no-match indicator) — this is a genuinely
useful bit of interactivity given how easy these regexes are to get subtly
wrong, and it exercises no new API surface (worth building even under time
pressure, cut something else instead).

### `/api-keys` — API Key Management
Per §1.6. List (never showing the raw key, only name/scopes/ca_id/expiry/
last_used), create (shows the raw key **exactly once**, in a modal with a
copy button and the same "you will never see this again" warning pattern as
the cert-issue page), rotate (same one-time-reveal pattern), delete (with a
confirmation dialog listing what will break — "any client using this key
will immediately lose access").

### `/eab-keys` — External Account Binding Keys
Per §1.5, same one-time-reveal pattern as API keys for the HMAC key.

### `/audit` — Audit Log
- Table of entries (`GET /api/v1/audit`, paginated per §1.7's `limit`/
  `offset`), filterable by CA.
- A prominent "Verify Chain Integrity" button calling
  `GET /api/v1/audit/verify` (§1.7) on demand (in addition to the dashboard
  home's periodic check), showing full detail on failure (`broken_at_index`,
  `broken_entry_id`) with a clear explanation of what that means.
- A "Merkle Root" panel showing the current `GET /api/v1/audit/merkle/root`
  value with a copy button and an explanation of what to do with it (pin it
  externally, compare on a later visit) — and, if time allows, a "verify an
  entry" tool: given an audit log row, fetch its
  `GET /api/v1/audit/merkle/proof/{index}` and verify it client-side using
  the same RFC 6962 algorithm described in `docs/plans/cli-mca.md`'s Merkle
  section (port that TypeScript-side using the Web Crypto API's
  `crypto.subtle.digest("SHA-256", ...)` for the hashing — this is a
  genuinely nice "trust but verify" feature for a dashboard, matching this
  project's stated differentiator around tamper-evidence, but it's also the
  single most complex piece of client logic in the whole app; if cutting
  scope under time pressure, cut this specific sub-feature before cutting
  any CRUD page, and ship the button linking out to raw JSON as a fallback).

### `/setup` — First-boot wizard
A guided flow for `docs/Setup.md` §2.5's bootstrap sequence: enter the
bootstrap key (printed to the server's console on first boot — the wizard
explains where to find it), then a form for `POST /setup/root-ca`, then
`POST /setup/api-key`, ending by dropping the user into the normal
authenticated dashboard with the newly-created key already active in their
session. Detect setup-mode automatically: a call to `GET /healthz` while the
server is in setup mode returns the distinct
`{"status":"setup", "message": "..."}` body per §1.13 — route to `/setup`
automatically when that's detected instead of the normal Connect screen.

### `/sshca` — SSH Certificate Authorities
Lower priority (build after every X.509 page above is complete and tested).
Mirror the CA/certificate pages' structure against §1.11's endpoints.

## Testing requirements
- Every page component: a Vitest + React Testing Library test rendering it
  with MSW intercepting its API calls, covering — loading state, populated
  state, an API error state (e.g. a 500 or 403 renders a visible error, not
  a blank screen or an uncaught exception), and at least one user
  interaction (a button click triggering the expected mutation/navigation).
- The API client: unit tests per method using MSW, covering success and the
  uniform `{"error": "..."}` error-decoding path.
- Auth flow: tests covering — successful connect stores the session and
  navigates to `/`, a bad key shows an error and does not navigate, a 401
  on any later call clears the session and redirects to Connect.
- Accessibility: run `eslint-plugin-jsx-a11y` in CI as a lint failure, not
  just a warning.

## Acceptance bar
- `npm run build`, `npm run lint`, `npm run test` all clean.
- Every page listed above (except `/sshca`, which is lower priority per its
  own note) implemented and tested.
- A `deploy/` directory with working Caddy and nginx reverse-proxy examples
  per the CORS section above, plus a `Dockerfile` producing a static-file
  serving image (e.g. `nginx:alpine` copying the Vite build output) so the
  whole thing can be `docker run` next to a mint-ca container.
- README covers: local dev (`npm run dev`), the CORS/reverse-proxy
  requirement, the auth/session-storage trade-off, and a screenshot or two
  of the dashboard home and cert-issue pages.

## Out of scope for v1
- Real-time updates via WebSockets/SSE — polling via TanStack Query's
  `refetchInterval` is sufficient for this project's scale (homelab/SME,
  not a hyperscale fleet dashboard).
- Dark/light theme toggle beyond whatever shadcn/ui's default theming gives
  for free — a nice-to-have, not a blocker.
- Multi-tenancy-aware UI (tenant switcher, platform-admin views) — revisit
  once/if `docs/plans/multi-tenancy.md` lands server-side; this plan's v1
  assumes a single-tenant mint-ca deployment, matching the server's current
  actual state.
- Localization/i18n.
