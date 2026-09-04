# 1. mint‑ca API Reference

All management API endpoints are served under `/api/v1` and require a valid API key sent in the `Authorization: Bearer <key>` header.  
Public PKI endpoints (CRL, OCSP, chain) are under `/pki/{caID}` and do not require authentication.  
ACME endpoints are under `/acme/{provisionerID}` and follow the ACME protocol (no API key).

## 1.1 Certificate Authorities

> **Tenant scoping (multi-tenancy):** every CA, SSH CA, provisioner, profile,
> policy, CSR auto-approval rule, EAB key, and issued certificate (scoped
> transitively via its CA) is owned by exactly one tenant. A tenant-scoped key
> only sees and can operate on its own tenant's resources — cross-tenant
> reads/updates return `404` (never `403`, to hide existence), except the
> global audit/Merkle verification and unscoped audit endpoints, which are
> **platform-admin only** (`403` for tenant keys). A platform-admin key sees
> everything. A tenant-scoped caller creates resources only within its own
> tenant; a platform admin may scope creation with an explicit `"tenant_id"`
> field on CAs/SSH CAs, defaulting to the default tenant when omitted
> (preserving single-tenant operator flows). The public SCEP endpoint refuses a
> CA whose tenant differs from its configured provisioner. See §1.6.1.

### `POST /api/v1/ca/root`
Create a new self‑signed root CA.

**Request body**
```json
{
  "name": "My Root CA",               // internal name, unique
  "common_name": "My Root CA",        // X.509 CN
  "organization": "My Org",           // optional
  "country": "US",                    // optional
  "state": "California",              // optional
  "locality": "San Francisco",        // optional
  "key_algo": "ecdsa-p256",           // ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096, ed25519
  "ttl_days": 3650                    // validity in days, default 3650
}
```

**Response (201 Created)**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My Root CA",
  "type": "root",
  "status": "active",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_algo": "ecdsa-p256",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2035-01-01T00:00:00Z",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### `POST /api/v1/ca/intermediate`
Create an intermediate CA signed by an existing parent CA.

**Request body**
```json
{
  "parent_ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Intermediate 1",
  "common_name": "Intermediate CA",
  "organization": "My Org",
  "country": "US",
  "state": "California",
  "locality": "San Francisco",
  "key_algo": "ecdsa-p256",
  "ttl_days": 1825,
  "max_path_len": 0
}
```

**Response (201 Created)** – same structure as root CA.

### `GET /api/v1/ca`
List all CAs.

**Response (200 OK)**
```json
[
  { ... CA object ... },
  ...
]
```

### `GET /api/v1/ca/{caID}`
Retrieve a single CA by ID.

### `GET /api/v1/ca/{caID}/children`
List all CAs whose `parent_id` equals the given ID.

### `PUT /api/v1/ca/{caID}/revoke`
Revoke a CA (no longer usable for issuing). No request body.

**Response (200 OK)**
```json
{ "status": "revoked" }
```

### `POST /api/v1/ca/{caID}/rekey`
Rotate a CA's signing key while preserving its identity and hierarchy position.
Creates a NEW active CA row (new ID, new key, new SubjectKeyId, same Subject,
same name constraints) signed by the same issuer (or self for a root). The
previous CA row is marked **`superseded`** — it stops signing new certificates
but already-issued leafs remain valid (they keep their original CAID). The new
row keeps the same **`logical_ca_id`** as its predecessor, so provisioners and
`ResolveActiveCA` keep resolving to it automatically — **no provisioner
repointing is required** after a re-key.

**Request body**
```json
{
  "key_algo": "ecdsa-p256", // optional; defaults to the current key algorithm
  "ttl_days": 365            // optional; defaults to remaining lifetime of the old CA
}
```

**Response (201 Created)**: the new (active) `CertificateAuthority` object.

### `POST /api/v1/ca/{caID}/cross-sign`
Issue a cross-signed certificate for CA `{caID}`'s existing public key + subject,
signed by a different CA. This builds a trust bridge during CA transitions
(e.g. an old root cross-signing a new root so clients trusting the old root can
validate the new root). The target CA's keypair is reused — this is a parallel
certificate from another issuer, stored in `ca_cross_certs`.

**Request body**
```json
{
  "signing_ca_id": "signer-ca-uuid", // required; must differ from {caID}
  "ttl_days": 1825                   // optional
}
```

**Response (201 Created)**: the stored cross-signed `CrossCert` object.

### `GET /api/v1/ca/{caID}/cross-certs`
List all cross-signed certificates issued for `{caID}`.

### `GET /pki/{caID}/chain/cross/{signingCAID}`
Public (no auth). PEM chain of the cross cert (target's public key signed by
`{signingCAID}`) followed by the signer's own chain up to its root. For clients
that trust the signing CA but not the target's native issuer.

---

## 1.2 Certificates

### `POST /api/v1/certs/issue`
Generate a new key pair and issue a certificate.

**Request body**
```json
{
  "ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "provisioner_id": "provisioner-uuid",
  "common_name": "myservice.example.com",
  "sans_dns": ["myservice.example.com", "api.example.com"],
  "sans_ip": ["10.0.0.1", "2001:db8::1"],
  "sans_email": ["admin@example.com"],
  "ttl_seconds": 86400,
  "key_algo": "ecdsa-p256",
  "server_auth": true,
  "client_auth": false,
  "profile": "web",                 // optional: enforce a named certificate profile
  "store_key": false,                 // optional: escrow the generated key for later retrieval
  "key_passcode": "",                // optional: passcode-guard the escrowed key
  "sans_uri": [],                    // optional: arbitrary URI SANs
  "spiffe_id": "spiffe://example.org/ns/default/sa/backend",  // optional: see 1.21
  "metadata": { "environment": "prod" }
}
```
The generated private key is returned once in `key_pem` and **not stored** unless
`store_key` is true. When `store_key` is true the key is encrypted at rest and
can be retrieved later via `GET /api/v1/certs/{certID}/key` (or included in an
export) — supplying `key_passcode` makes that retrieval require the passcode.

**Response (201 Created)**
```json
{
  "certificate": { ... full certificate record ... },
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n..."
}
```

### `POST /api/v1/certs/sign`
Sign a CSR submitted by the client (the private key stays with the client).

**Request body**
```json
{
  "ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "provisioner_id": "provisioner-uuid",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "ttl_seconds": 86400,
  "metadata": { "env": "prod" },
  "attestation": {                  // optional: gate signing on hardware attestation, see 1.20
    "format": "tpm2",
    "data_b64": "<base64 of the format-specific evidence>"
  }
}
```

**Response (201 Created)** – same as issue, but without `key_pem`.

### `GET /api/v1/certs/{certID}`
Retrieve a certificate record by ID.

### `GET /api/v1/certs/serial/{serial}`
Retrieve a certificate by its serial number (decimal string).

### `GET /api/v1/certs/ca/{caID}`
List all certificates issued by a given CA.

### `PUT /api/v1/certs/{certID}/revoke`
Revoke a certificate.

**Request body** (optional)
```json
{ "reason": 1 }  // RFC 5280 reason code
```

**Response (200 OK)**
```json
{ "status": "revoked" }
```

### `POST /api/v1/certs/batch/sign`
Sign many CSRs in one request (fleet / embedded provisioning). Each item is
validated and signed independently; a failing item is reported and does not
abort the rest.

**Request body**
```json
{
  "ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "provisioner_id": "provisioner-uuid",
  "metadata": { "env": "prod" },          // shared metadata (optional)
  "items": [
    { "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...", "ttl_seconds": 3600, "metadata": {} },
    { "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...", "ttl_seconds": 7200 }
  ]
}
```
Max 1000 items. Per‑item `metadata` overrides the shared metadata. Each item
may also carry its own `"attestation"` (same shape as in `POST
/api/v1/certs/sign`, see 1.20); a failed attestation fails only that item.

**Response (200 OK)**
```json
{
  "results": [
    { "index": 0, "cert_id": "...", "serial": "...", "subject_cn": "...", "cert_pem": "..." },
    { "index": 1, "error": "ca: SignCSR: ..." }
  ],
  "issued": 1,
  "failed": 1
}
```

### `GET /api/v1/certs/{certID}/key`
Retrieve the escrowed private key for a certificate. Only available when the
certificate was issued with `store_key: true`. If a key passcode was set at
issue, it must be supplied here.

**Query parameters**
| Param | Description |
|-------|-------------|
| `passcode` | The key passcode, required when the key is passcode‑protected. |

**Response (200 OK)** – `text/plain`, the PEM‑encoded private key.

`404` if the key was not stored (`store_key` was false). `400` if a passcode is
required but missing or incorrect.

### `GET /api/v1/certs/{certID}/export`
Download a tar.gz bundle of a certificate: `cert.pem`, `chain.pem`
(leaf + intermediates + root), `cert.json` manifest, `README.txt`, and
`key.pem` when the key was escrowed and a valid `passcode` is supplied.

**Query parameters**
| Param | Description |
|-------|-------------|
| `passcode` | Required to include `key.pem` when the key is passcode‑protected. |
| `format` | `p12` for a password‑protected PKCS#12 file, or `jks` for a Java KeyStore (see below). |

With `?format=p12`, the response is a single `.p12`/`.pfx` file containing the
leaf certificate, its private key, and its CA chain — for consumers that
expect one self‑contained keystore file (Windows certificate stores, network
appliances) rather than separate PEM parts. Requires an escrowed key: pass
`passcode` if the key is passcode‑protected. Additional query parameters:
| Param | Description |
|-------|-------------|
| `p12_password` | Password protecting the `.p12` file itself. Default: `changeit`. |

With `?format=jks`, the response is a Java KeyStore (`.jks`) file — for JVM
consumers (Java/Kotlin services, Android, Java-based network appliances) that
specifically expect a JKS rather than a PKCS#12 file. Same key/passcode
requirement as `p12`. Additional query parameters:
| Param | Description |
|-------|-------------|
| `jks_password` | Password protecting the `.jks` file itself. Default: `changeit`. |
| `jks_alias` | Alias the private-key entry is stored under. Default: `mint-ca`. |

### Auto‑renewal webhook (background, not request/response)
When `MINT_RENEWAL_ENABLED` and `MINT_RENEWAL_WEBHOOK_URL` are set, a background
worker scans active certificates whose `NotAfter` is within
`MINT_RENEWAL_LEAD_SECONDS` (default 7 days) and sends an HTTP **POST** with a JSON
body to the webhook URL per certificate, so an external system can renew it:

```json
{
  "cert_id": "550e8400-e29b-41d4-a716-446655440000",
  "ca_id": "...",
  "serial": "12345",
  "subject_cn": "api.example.com",
  "expires_at": "2026-01-01T00:00:00Z",
  "days_left": 5,
  "key_escrowed": false
}
```
The worker is a generic trigger: the deliverer is pluggable, so other
integrations (ACME re‑issue, a management callback, the `mca` CLI) can be wired
to the same scan without changing it.

---

## 1.3 Provisioners

### `POST /api/v1/provisioners`
Create a new provisioner (authorised entity that can request certificates).

**Request body**
```json
{
  "ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "my-provisioner",
  "type": "apikey",          // "apikey", "acme", "mtls"
  "config": {},              // provisioner‑specific configuration
  "policy_id": "policy-uuid" // optional policy binding
}
```

**Response (201 Created)** – the created provisioner object.

### `GET /api/v1/provisioners/ca/{caID}`
List all provisioners belonging to a CA.

### `GET /api/v1/provisioners/{provisionerID}`
Get a single provisioner.

### `PUT /api/v1/provisioners/{provisionerID}/enable`
Enable a disabled provisioner. No request body.

**Response (200 OK)**
```json
{ "status": "active" }
```

### `PUT /api/v1/provisioners/{provisionerID}/disable`
Disable a provisioner. No request body.

**Response (200 OK)**
```json
{ "status": "disabled" }
```

---

## 1.4 Policies

Certificates can also be constrained by a **profile** (`storage.Profile`) — a
reusable set of constraints (`allowed_key_algos`, `min/max_ttl_seconds`,
`require_san`, `allow_wildcard`) evaluated by `policy.EvaluateProfile`. A
provisioner may pin one via its `profile_id`.

### `POST /api/v1/profiles`
Create a named certificate profile.

**Request body**
```json
{
  "name": "web",
  "allowed_key_algos": ["ecdsa-p256"],
  "min_ttl_seconds": 3600,
  "max_ttl_seconds": 86400,
  "require_san": true,
  "allow_wildcard": false
}
```
**Response (201 Created)** – the created profile object.

### `GET /api/v1/profiles`
List all profiles.

### `GET /api/v1/profiles/{profileID}`
Get a single profile.

### `PUT /api/v1/profiles/{profileID}`
Update a profile (same body as create).

### `DELETE /api/v1/profiles/{profileID}`
Delete a profile.

**Referencing a profile at issuance:** `POST /api/v1/certs/issue` accepts an
optional `"profile": "<name>"` field; the named profile is resolved and enforced
with `policy.EvaluateProfile` (key‑algo, TTL min/max, require‑SAN, wildcard)
before any crypto work.

### `POST /api/v1/policies`
Create a new certificate issuance policy.

**Request body**
```json
{
  "name": "restrictive policy",
  "scope": "ca",                        // "ca" or "provisioner"
  "max_ttl_seconds": 31536000,          // maximum certificate lifetime
  "allowed_domains": ["*.example.com"], // DNS name patterns
  "denied_domains": ["*.internal"],
  "allowed_ips": ["10.0.0.0/8"],
  "allowed_sans": [],                   // future use
  "require_san": true,
  "key_algos": ["ecdsa-p256", "rsa-2048"]
}
```

**Response (201 Created)** – the policy object.

### `GET /api/v1/policies`
List all policies.

### `GET /api/v1/policies/{policyID}`
Retrieve a policy.

### `PUT /api/v1/policies/{policyID}`
Update an existing policy. Body same as create.

### `DELETE /api/v1/policies/{policyID}`
Delete a policy (will fail if referenced by a provisioner).

---

## 1.5 External Account Binding (EAB) Keys

Used to require ACME clients to present a pre‑shared credential during account registration.

### `POST /api/v1/eab/provisioner/{provisionerID}`
Create a new EAB credential for an ACME provisioner.

**Request body** (optional)
```json
{ "expires_in_seconds": 86400 }
```

**Response (201 Created)**
```json
{
  "key_id": "a1b2c3...",               // the kid that ACME client must send
  "hmac_key": "deadbeef...",           // the HMAC secret (base64? hex?)
  "expires_at": "2025-02-01T00:00:00Z",
  "note": "store hmac_key securely — it will not be shown again"
}
```

### `GET /api/v1/eab/provisioner/{provisionerID}`
List metadata of EAB credentials for a provisioner (HMAC keys not returned).

### `DELETE /api/v1/eab/{keyID}`
Revoke (mark as used) an EAB credential.

---

## 1.6 API Keys (Management)

### `POST /api/v1/apikeys`
Create a new management API key.
> The legacy optional `ca_id` field (restrict a key to one CA) is retained
> for backward compatibility; prefer tenant-based `tenant_id` scoping for
> isolation. Removing `ca_id` entirely is tracked as a follow-up cleanup.

**Request body**
```json
{
  "name": "my-key",
  "scopes": ["*"],                // scope strings, "*" for all
  "ca_id": "ca-uuid",             // optional, restrict to a CA
  "tenant_id": "tenant-uuid",     // optional; scope to a tenant
  "platform_admin": false,         // optional; create a platform-admin key
  "expires_in_seconds": 31536000,  // optional; default applies when omitted
  "never_expires": false           // optional; true for an explicit never‑expiring key
}
```
Tenant scoping (multi-tenancy):
- A **tenant-scoped caller** may only create keys for its own tenant. Any
  `tenant_id` supplied must match its own tenant (a mismatch returns `400`)
  and `platform_admin` is never permitted.
- A **platform-admin caller** (the operator; a key with no `tenant_id`) must
  choose exactly one of:
  - set `tenant_id` to mint a key scoped to that tenant, **or**
  - set `"platform_admin": true` to mint another platform-admin key.
  Omitting both returns `400` so a platform-admin key is never created
  accidentally.

When `expires_in_seconds` is omitted (and `never_expires` is false), a
conservative default lifetime of **90 days** is applied so automation tokens are
rotated by default rather than long‑lived. Keys are enforced to be rejected after
expiry, and `last_used` is tracked per key.

**Response (201 Created)**
```json
{
  "id": "key-uuid",
  "name": "my-key",
  "key": "mca_abc123...",          // raw key – store it immediately
  "scopes": ["*"],
  "tenant_id": "tenant-uuid",       // absent for platform-admin keys
  "expires_at": "2026-01-01T00:00:00Z",
  "note": "store the key securely — it will not be shown again"
}
```

### `GET /api/v1/apikeys`
List API keys (only metadata, no keys). A tenant-scoped caller sees only its
own tenant's keys (never other tenants' or platform-admin keys); a platform
admin sees all.

### `POST /api/v1/apikeys/{keyID}/rotate`
Issue a fresh bearer token for an existing key identity. Keeps its
name/scopes/CAID; the **previous secret is immediately invalidated** (its hash is
replaced) — callers must stop using it. No request body.

**Response (200 OK)**
```json
{ "id": "key-uuid", "key": "mca_new...", "note": "previous key is now invalid; store this one securely" }
```

### `DELETE /api/v1/apikeys/{keyID}`
Delete an API key. A tenant-scoped caller may only delete keys within its own
tenant; attempting to delete another tenant's or a platform-admin key returns
`404`.

---

## 1.6.1 Tenants (Multi-tenancy)

A running mint-ca instance can serve several isolated tenants. Every
tenant-private resource (CAs, provisioners, profiles, policies, API keys, …)
is owned by exactly one tenant and is invisible to every other. Tenant
management endpoints are **platform-admin only** (except reading one's own
tenant), enforced by which API key signs the request.

Every deployment always has a single seeded **default tenant** (fixed UUID
`00000000-0000-0000-0000-000000000000`) created at first boot; single-tenant
installs continue to operate entirely under it.

### `GET /api/v1/tenants`
List tenants. **Platform-admin only.**

### `POST /api/v1/tenants`
Create a new tenant. **Platform-admin only.**

**Request body**
```json
{ "name": "acme-corp" }
```
Returns `409 Conflict` if a tenant with the same name already exists.

### `GET /api/v1/tenants/{tenantID}`
Get a tenant. Platform admin sees any; a tenant-scoped caller may only read its
own tenant (a mismatch returns `404`).

### `PUT /api/v1/tenants/{tenantID}/suspend`
Suspend a tenant. **Platform-admin only.** Once suspended, every subsequent
authenticated request from that tenant's API keys is rejected with `403`.

### `PUT /api/v1/tenants/{tenantID}/activate`
Re-activate a suspended tenant. **Platform-admin only.**

---

## 1.7 Audit Log

Every mutating action is appended to a tamper-evident hash chain: each entry's
`entry_hash` is derived from its own fields plus the previous entry's
`entry_hash` (genesis chains from the empty string). Editing, deleting, or
reordering any past entry breaks the chain from that point forward, which
`GET /api/v1/audit/verify` detects.

### `GET /api/v1/audit`
List audit entries (most recent first).

**Query parameters**
- `limit` (default 50, max 500)
- `offset` (default 0)

**Response (200 OK)**
```json
[
  {
    "id": "...",
    "event_type": "POST /api/v1/certs/issue",
    "actor": "my-key",
    "ca_id": "...",
    "cert_id": "...",
    "payload": { ... },
    "ip_address": "10.0.0.1",
    "created_at": "...",
    "prev_hash": "...",
    "entry_hash": "..."
  }
]
```

### `GET /api/v1/audit/ca/{caID}`
Same as above, filtered by CA.

### `GET /api/v1/audit/merkle/root`
Returns the current Merkle Tree Head over the audit log's hash chain — an
RFC 6962 (Certificate Transparency)-style commitment, layered on top of the
hash chain in 1.7. Useful as a value to pin and compare over time: if the
root ever changes in a way not explained by new entries appended at the end,
the log was tampered with.

**Response (200 OK)**
```json
{ "root_hash": "3f...c2", "size": 1234 }
```

### `GET /api/v1/audit/merkle/proof/{index}`
Returns an inclusion proof for the audit log entry at `{index}` (0-based,
chronological — the same order `verify` walks), against the current tree —
"prove this specific entry was recorded, without downloading the whole log."

**Response (200 OK)**
```json
{
  "index": 4,
  "size": 9,
  "entry_id": "550e8400-e29b-41d4-a716-446655440000",
  "entry_hash": "a1...9f",
  "proof": ["b2...", "c3...", "d4..."],
  "root_hash": "3f...c2"
}
```
`404` if `index >= size`. A verifier recomputes the root from `entry_hash`,
`index`, `size`, and `proof` (RFC 6962 §2.1.1 audit path verification, with
0x00/0x01 domain-separated leaf/node hashing) and compares it to a
previously-pinned `root_hash` — no trust in mint-ca's own answer required for
`ok: true`, only that it matches a root the verifier already trusts.

### `GET /api/v1/audit/verify`
Walks the entire audit log's hash chain, oldest first, and reports whether it
is intact.

**Response (200 OK)** — intact:
```json
{ "ok": true, "entries": 1234, "verified_at": "2026-01-01T00:00:00Z" }
```

**Response (200 OK)** — broken (e.g. a row was edited or deleted directly in
the database, bypassing the API):
```json
{
  "ok": false,
  "entries": 1234,
  "verified_at": "2026-01-01T00:00:00Z",
  "broken_at_index": 57,
  "broken_entry_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

## 1.8 Metrics

### `GET /metrics`
Prometheus metrics (text format).

**Example output**
```
# HELP mintca_ca_total Total certificate authorities
# TYPE mintca_ca_total gauge
mintca_ca_total 2
# HELP mintca_certs_issued_total Total certificates issued
# TYPE mintca_certs_issued_total counter
mintca_certs_issued_total 42
# HELP mintca_certs_revoked_total Total certificates revoked
# TYPE mintca_certs_revoked_total counter
mintca_certs_revoked_total 3
```

---

## 1.9 Public PKI Endpoints

These are served without authentication and are meant for clients to retrieve CRLs, OCSP responses, and CA chains.

### `GET /pki/{caID}/crl`
PEM‑encoded **base** CRL.

### `GET /pki/{caID}/crl.der`
DER‑encoded base CRL (content-type `application/pkix-crl`).

### `GET /pki/{caID}/crl/delta`
PEM‑encoded **delta** CRL (RFC 5280 §5.2.4). Only populated when delta CRLs are
enabled (`MINT_CRL_DELTA_ENABLED=true`). A delta carries only the certificates
revoked after the base CRL's `ThisUpdate` and includes a `deltaCRLIndicator`
extension pointing back to the base CRL Number. When deltas are enabled and a
`MINT_ACME_BASE_URL` is set, the base CRL also advertises this address in a
Freshest CRL extension so RFC 5280‑aware clients can discover it.

### `GET /pki/{caID}/crl/delta.der`
DER‑encoded delta CRL (content-type `application/pkix-crl`).

### `POST /pki/{caID}/ocsp`
OCSP request (DER) in the body, returns DER‑encoded OCSP response.

### `GET /pki/{caID}/chain`
Full CA chain in PEM format (the CA’s own certificate plus all ancestors up to the root).

---

## 1.10 MTLS Device Enrollment

When the MTLS listener is enabled (`MINT_MTLS_ENABLED`), mint‑ca runs a **second**
mutual‑TLS listener (default `:8444`) that requires devices to present a client
certificate chained to the trusted client CA (`MINT_MTLS_CLIENT_CA`). A device is
authenticated by that certificate and issued a fresh, device‑bound leaf.

### `GET /healthz`
Liveness of the enrollment listener.

### `GET /enroll`
Authenticate via the presented client certificate and issue a device leaf.
The device identity is taken from the presented certificate's `CommonName`
(and its DNS names become SANs). Requires the presented cert to chain to the
trusted client CA.

**Response (201 Created)**
```json
{
  "certificate": { "id": "...", "subject_cn": "device-42", ... },
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
  "chain_pem": "..."
}
```

---

## 1.11 SSH Certificate Authorities

SSH CAs sign **user** and **host** certificates (OpenSSH `-cert.pub` format), distinct from the X.509 CAs above. An SSH CA is a flat signing key — no parent/child chain — and its public key is distributed for clients/servers to trust. Management endpoints require an API key; the public key endpoint under `/pki` does not.

### `POST /api/v1/sshca/`
Create a new SSH CA signing key.

**Request body**
```json
{
  "name": "my-ssh-ca",      // unique internal name
  "key_algo": "ed25519"      // "ed25519" (default) or "ecdsa-p256"
}
```

**Response (201 Created)**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "my-ssh-ca",
  "key_algo": "ssh-ed25519",
  "public_key": "ssh-ed25519 AAAA... mint-ca",
  "status": "active",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### `GET /pki/sshca/{caID}/public-key`
Public (no auth), plaintext `authorized_keys` line. Pipe it straight into `TrustedUserCAKeys` / `known_hosts` or an `@cert-authority` line.

### `GET /api/v1/sshca/`
List all SSH CAs.

### `GET /api/v1/sshca/{caID}`
Get a single SSH CA by ID. The ID may be a **logical CA id**: after a re‑key the
logical id resolves to the currently‑active row (see below).

### `POST /api/v1/sshca/{caID}/rekey`
Rotate an SSH CA's signing key. Generates a fresh keypair under a new physical
row that keeps the same **logical CA id**, and marks the old row `superseded` so
it stops signing new certificates (already‑issued certs remain valid while the
old public key is still trusted by clients).

**Request body** (optional)
```json
{ "key_algo": "ecdsa-p256" }   // optional; defaults to the existing algorithm
```
**Response (201 Created)** – the new active SSH CA row.

### `POST /api/v1/sshca/{caID}/cross-sign`
Create a **parallel active** SSH CA row that shares the target CA's key and
logical identity without superseding it. Both rows stay active, so clients
trusting either physical CA id keep working — the SSH analogue of cross‑signing.

**Request body** (optional)
```json
{ "target_ca_id": "<uuid>" }   // optional; defaults to {caID}
```
**Response (201 Created)** – the new parallel SSH CA row.

> Issuance, `GET {caID}`, `public-key`, and `krl` all resolve a logical or
> superseded id to the currently‑active row, so a stable `caID` keeps working
> through key rotation.

### `POST /api/v1/sshca/{caID}/issue` / `.../sign/user` / `.../sign/host`
Issue (sign) an SSH certificate. `/sign/user` and `/sign/host` are fixed-type aliases of `/issue` (which takes `cert_type` in the body).

**Request body** (all three share this shape)
```json
{
  "provisioner_id": "provisioner-uuid",
  "public_key": "ssh-ed25519 AAAA... mykey",   // authorized_keys line OR raw base64 wire format
  "principals": ["alice", "ops"],              // usernames (user) or hostnames (host); at least one
  "key_id": "alice",                            // free-text label in the certificate
  "ttl_seconds": 28800,                          // optional; default 8h user / 1y host
  // optional OpenSSH critical options (force-command, source-address, ...):
  "critical_options": { "force-command": "/opt/gateway", "source-address": "203.0.113.0/24" },
  // optional extra extensions (permit-open, permit-listen, ...). Merged over
  // the built-in default permit-* set — defaults are retained unless overridden:
  "extensions": { "permit-open": "host:22" }
}
```

**Response (201 Created)**
```json
{
  "certificate": { "id": "...", "ca_id": "...", "serial": 12345, "cert_type": "user", ... },
  "cert_data": "ssh-ed25519-cert-v01@openssh.com AAAA..."   // -cert.pub format, write to disk
}
```

### `GET /api/v1/sshca/{caID}/certs`
List all certificates issued by an SSH CA.

### `GET /api/v1/sshca/certs/{certID}`
Get a single SSH certificate by ID.

### `GET /api/v1/sshca/certs/serial/{caID}/{serial}`
Get an SSH certificate by its CA ID and decimal serial.

### `PUT /api/v1/sshca/certs/{certID}/revoke`
Revoke an SSH certificate. No request body.

**Response (200 OK)**
```json
{ "status": "revoked" }
```

### `GET /pki/sshca/{caID}/krl`
Public (no auth). Binary OpenSSH Key Revocation List (`application/octet-stream`), unsigned —
authenticity relies on HTTPS transport, same trust model as the x509 CRL/OCSP endpoints.
Each revoked certificate is revoked three ways in the KRL: by certificate serial
(`KRL_SECTION_CERTIFICATES`), by explicit raw key (`KRL_SECTION_EXPLICIT_KEY`), and by
SHA256 key fingerprint (`KRL_SECTION_FINGERPRINT_SHA256`). The explicit-key and fingerprint
sections reject the revoked certificate's underlying plain key even if the certificate is
never presented — covering both cert- and raw-key-based use.

**Note:** unlike CRL, sshd does not fetch KRLs live. Configure `sshd_config`:
---

## 1.12 ACME Endpoints

ACME endpoints follow the **RFC 8555** protocol. All POST requests must be wrapped in a JWS.  
The provisioner ID is part of the URL.  
Authentication is done via the JWS signature.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/acme/{provisionerID}/directory` | GET | ACME directory object |
| `/acme/{provisionerID}/new-nonce` | HEAD / POST | Obtain a replay nonce |
| `/acme/{provisionerID}/new-account` | POST | Create a new ACME account |
| `/acme/{provisionerID}/account/{accountID}` | POST | Update account or retrieve info (POST‑as‑GET) |
| `/acme/{provisionerID}/new-order` | POST | Create a new order |
| `/acme/{provisionerID}/order/{orderID}` | POST | Retrieve order |
| `/acme/{provisionerID}/order/{orderID}/finalize` | POST | Finalize order with CSR |
| `/acme/{provisionerID}/challenge/{challengeID}` | POST | Notify server that challenge is ready |
| `/acme/{provisionerID}/certificate/{certID}` | POST | Download issued certificate |
| `/acme/{provisionerID}/renewal-info/{certID}` | GET | Renewal window (RFC 9779); the certificate download response also carries a `Link: <...>;rel=renewalInfo` header |
| `/acme/{provisionerID}/key-change` | POST | Roll account over to a new key (RFC 8555 §7.3.5) |

The renewal-info response body:
```json
{
  "renewalWindow": { "start": "2026-08-16T00:00:00Z", "end": "2026-11-24T00:00:00Z" }
}
```
The window closes at `notAfter` and opens one lead-time earlier, where lead time =
`max(lifetime/5, 24h)` by default. A provisioner can override the lead time via its
`renewal_lead_period_seconds` (`ProvisionerConfig`) setting; the window never starts before
`notBefore`.

See [RFC 8555](https://tools.ietf.org/html/rfc8555) for the exact JWS payloads.  
The directory response also includes `"keyChange"` alongside `newNonce`, `newAccount`, `newOrder`, `newAuthz`.

---

## 1.13 Health & Setup

### `GET /healthz`
Health check. In setup mode it returns a `status: "setup"` message.

### `POST /setup/root-ca`
Only available during initial setup (bootstrap key required). Create the first root CA.  
Same body as `/api/v1/ca/root`. Response indicates success.

### `POST /setup/api-key`
Only available during initial setup (bootstrap key required). Create the first permanent API key and transition to ready mode.  
Request body:
```json
{ "name": "admin", "scopes": ["*"] }
```
Response includes the new API key (store it) and CA chain URL.
### ACME Key Rollover

`POST /acme/{provisionerID}/key-change`

Outer JWS is signed with the account's **current** key and authenticated via `kid` (same as any other authenticated ACME request). The outer payload is itself a JWS, signed with the **new** key using an inline `jwk` header (no `kid`):

**Inner JWS payload**
```json
{
  "account": "https://ca.example.com/acme/{provisionerID}/account/{accountID}",
  "oldKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

**Response (200 OK)** — empty body, standard ACME headers (`Replay-Nonce`).

Rejected with `urn:ietf:params:acme:error:malformed` if:
- inner `account` URL doesn't match the authenticated account,
- inner `oldKey` doesn't match the account's current key,
- the new key is already registered to another account,
- the new key was previously retired by any account's rollover (once a key is rolled off, it can never be reused — standard CA practice).

Subject to the `acme_key_change_per_account` rate limiter (default: 5/hour).
## 1.14 Rate Limiting

mint-ca enforces per-limiter request quotas using a fixed-window algorithm. Limits apply to:

| Limiter | Scope | Default | Purpose |
|---|---|---|---|
| `acme_new_account_per_ip` | client IP | 10/hour | ACME `new-account` |
| `acme_new_order_per_account` | ACME account | 50/hour | ACME `new-order`, `new-authz` |
| `acme_new_authz_per_account` | ACME account | 50/hour | reserved (currently shares the new-order limiter at call sites) |
| `acme_key_change_per_account` | ACME account | 5/hour | ACME `key-change` |
| `apikey_requests_per_key` | API key | 300/min | all `/api/v1/*` management endpoints |

When a limit is exceeded:
- ACME endpoints return an RFC 8555 `urn:ietf:params:acme:error:rateLimited` problem, HTTP 429, with a `Retry-After` header.
- Management API endpoints return `{"error":"rate limit exceeded","retry_after_seconds":N}`, HTTP 429, with `Retry-After`.

Every rejection is written to the audit log as event type `rate_limit_exceeded`.

Defaults can be overridden on **first boot only** (a value is never overwritten once a database row exists — see Setup.md). After first boot, editing limiter configs requires direct database access; a management API for this is planned but not yet implemented.

---

## 1.15 CSR Auto-Approval Rules

CSR auto‑approval rules control which CSRs a provisioner may **auto‑sign** without
review, and enforce best‑of‑default constraints. Managed under
`/api/v1/approval/csr-rules`.

**Default posture is deny:** a rule whitelists what may be signed. A CSR matching
a rule is auto‑approved; any non‑matching CommonName, any DNS SAN not in the
rule's allowlist, or a requested TTL above the rule's cap is refused. When **no**
rule exists for a provisioner, CSR signing is unchanged (no auto‑approval policy
governs it). This is opt‑in.

### `POST /api/v1/approval/csr-rules`
Create a rule.

**Request body**
```json
{
  "provisioner_id": "provisioner-uuid",
  "name": "internal-fleet",
  "allowed_common_names": ["^svc-.*\\\\.internal\\\\.example$"],  // optional regexes the CSR CN must match
  "allowed_dns": ["\\\\.internal\\\\.example$"],                 // regexes EVERY DNS SAN must match
  "max_ttl_seconds": 86400                                          // optional; default cap 90 days
}
```
**Response (201 Created)** – the stored rule (`enabled: true`).

### `GET /api/v1/approval/csr-rules`
List rules. Optionally filter with `?provisioner_id=<uuid>`.

### `PUT /api/v1/approval/csr-rules/{ruleID}`
Edit a rule (same body as create, plus `"enabled"`). 

### `DELETE /api/v1/approval/csr-rules/{ruleID}`
Delete a rule.

> Enforcement happens on `POST /api/v1/certs/sign`. The TLS/HTTPS config for CAA
> checking is configured via env (`MINT_ACME_CAA_*`, see Setup.md), not the REST API.

## 1.16 Renewal Lifecycle Intel

Read-only visibility into certificate renewal risk, derived from existing
certificate data (no separate tracking table). Useful for external automation
to alert on certs needing action.

### `GET /api/v1/renewal/status`
Optionally filter with `?ca_id=<uuid>`.

**Response (200 OK)**
```json
{
  "certificates": [
    {
      "cert_id": "cert-uuid",
      "ca_id": "ca-uuid",
      "subject_cn": "svc.example.com",
      "expires_at": "2026-09-10T00:00:00Z",
      "days_left": 5,
      "status": "due"
    }
  ],
  "summary": {
    "due": 1,
    "expiring_soon": 0,
    "expired": 0,
    "revoked": 0
  }
}
```

Only certificates that are not classified `valid` are listed (i.e. `due`,
`expiring_soon`, `expired`, or `revoked`); the `summary` gives totals per
bucket. Buckets:
- `revoked` — certificate status is revoked.
- `expired` — certificate status is expired, or `NotAfter` has passed.
- `expiring_soon` — `NotAfter` is within `MINT_RENEWAL_EXPIRING_SECONDS` (default 48h).
- `due` — `NotAfter` is within `MINT_RENEWAL_LEAD_SECONDS` (default 7 days) but
  beyond the expiring window.
- `valid` — not returned in the list, but not counted as an issue either.

## 1.17 ACME Profile Intents

ACME orders can request a named certificate profile so `profile`-constrained
issuance (see `POST /api/v1/certs/issue`'s `"profile"` field) works through
ACME too. A provisioner may instead **pin** a profile via its existing
`profile_id`, which always takes priority over a client-requested one.

### `POST /acme/{provisionerID}/new-order`
The new-order payload gains an optional `profile` field:
```json
{
  "identifiers": [{"type": "dns", "value": "svc.example.com"}],
  "profile": "internal-services"
}
```
If the provisioner has a pinned profile, `profile` is ignored and the pinned
one applies. An unknown requested profile name is rejected with `400
malformed`. The resolved profile (if any) is evaluated against the order's
identifiers immediately (e.g. rejecting a wildcard identifier when
`allow_wildcard` is false) via `urn:ietf:params:acme:error:rejectedIdentifier`.

### `POST /acme/{provisionerID}/order/{orderID}/finalize`
The same profile is re-evaluated against the submitted CSR's actual SANs and
key algorithm before issuance; a violation is rejected with
`urn:ietf:params:acme:error:badCSR`.

### Order responses
`GET`/`POST` order responses include a `"profile"` field naming the applicable
profile when one was resolved.

## 1.18 SCEP Enrollment (Simplified)

A public, unauthenticated SCEP-shaped enrollment endpoint at
`/pki/{caID}/scep`, gated by `MINT_SCEP_ENABLED` (see Setup.md). Every
enrollment is signed under one configured provisioner
(`MINT_SCEP_PROVISIONER_ID`) — a pre-release, single-user simplification.

> **Deviation from RFC 8894**: this endpoint does **not** wrap requests or
> responses in PKCS#7 (`SignedData`/`EnvelopedData`), which the full SCEP spec
> requires for `PKIOperation`. `PKCSReq` here accepts a **raw PKCS#10 CSR**
> (DER-encoded) as the POST body and returns a **raw DER leaf certificate**,
> not a PKCS#7 degenerate certs-only message. A genuine SCEP client (most
> MDM/device-management stacks) needs a PKCS#7 unwrap/wrap shim in front of
> this endpoint; `mint-ca` does not ship one (no PKCS#7 dependency in
> `go.mod`).

### `GET /pki/{caID}/scep?operation=GetCACaps`
Returns `text/plain`, newline-separated capabilities:
```
GetNextCACert
POSTPKIOperation
SHA-256
Renewal
```

### `GET /pki/{caID}/scep?operation=GetCACert`
Returns the CA certificate as `application/x-x509-ca-cert` (raw DER).

### `GET /pki/{caID}/scep?operation=GetNextCACert`
`501 Not Implemented` — mint-ca does not cross-cert a renewal chain.

### `POST /pki/{caID}/scep?operation=PKCSReq`
Body: raw DER-encoded PKCS#10 CSR. Enforces the same CSR auto-approval rules
as `POST /api/v1/certs/sign` (`403` if a rule exists for the provisioner and
this CSR does not satisfy it). On success, returns the signed leaf as
`application/x-x509-user-cert` (raw DER).

## 1.19 Action-Notification Webhook (background, not request/response)

When `MINT_EVENTS_WEBHOOK_URL` is set, mint-ca POSTs a JSON event to that URL
for every certificate issuance and revocation — so external systems (SIEM,
chat, ticketing) can react in real time instead of polling the audit log.
Delivery is asynchronous and best-effort: a failed or slow webhook never
affects the API response that triggered the event.

**`cert.issued`** — sent after `POST /api/v1/certs/issue`, `POST
/api/v1/certs/sign`, and each successfully-signed item in `POST
/api/v1/certs/batch/sign`:
```json
{
  "type": "cert.issued",
  "timestamp": "2026-01-01T00:00:00Z",
  "data": {
    "cert_id": "550e8400-e29b-41d4-a716-446655440000",
    "ca_id": "...",
    "serial": "12345",
    "subject_cn": "api.example.com",
    "not_after": "2027-01-01T00:00:00Z"
  }
}
```

**`cert.revoked`** — sent after `PUT /api/v1/certs/{certID}/revoke`:
```json
{
  "type": "cert.revoked",
  "timestamp": "2026-01-01T00:00:00Z",
  "data": {
    "cert_id": "550e8400-e29b-41d4-a716-446655440000",
    "ca_id": "...",
    "serial": "12345",
    "subject_cn": "api.example.com",
    "reason": 1
  }
}
```

## 1.20 Hardware-Attestation-Gated Issuance

`POST /api/v1/certs/sign` and each item of `POST /api/v1/certs/batch/sign` can
carry an optional `"attestation"` field, proving the CSR's key is bound to a
hardware root of trust before mint-ca signs it. Attestation is **opt-in**:
omit the field to sign as before. When present, mint-ca dispatches it to the
verifier registered for `format`; if none is registered for that format, or
verification fails, the request is refused with `403`.

```json
{
  "format": "tpm2",
  "data_b64": "<base64 of the format-specific evidence>"
}
```

Two verifiers are registered by default:

**`tpm2`** — proves possession of a TPM Endorsement Key (EK). `data_b64`
decodes to:
```json
{
  "ek_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "signature_b64": "<base64 signature, made with the EK private key, over sha256(csrDER)>"
}
```
This is a simplified binding compared to full TPM 2.0 remote attestation
(a `TPM2B_ATTEST` quote over PCRs, signed by an AK certified by the EK) —
implementing the TPM2 wire protocol needs a dependency this repo doesn't
carry yet. What's checked: the EK certificate parses, optionally chains to a
trusted root (`MINT_ATTESTATION_TPM_ROOTS_FILE`, see Setup.md — when unset,
any well-formed EK certificate is accepted, which only proves possession of
its key, not genuine TPM hardware), and the signature verifies over this
specific CSR.

**`webauthn`** — proves the CSR is backed by a WebAuthn/FIDO2 authenticator
credential (as from `navigator.credentials.create()`). `data_b64` decodes to:
```json
{
  "client_data_json_b64": "<base64 clientDataJSON>",
  "attestation_object_b64": "<base64 CBOR attestationObject>"
}
```
The `clientDataJSON.challenge` must equal `sha256(csrDER)` — set this as the
challenge when calling `navigator.credentials.create()`, binding the
attestation to this specific CSR. Supported `attStmt` formats: `packed` (with
an `x5c` attestation certificate, or self-attestation using the credential's
own key) and `none` (binding check only, no attestation signature — lower
assurance). Other formats (`android-key`, `android-safetynet`, `fido-u2f`,
`tpm`) return an explicit "unsupported" error rather than a false pass.

## 1.21 SPIFFE-Style X.509-SVIDs

`POST /api/v1/certs/issue` can embed a [SPIFFE ID](https://github.com/spiffe/spiffe)
as a URI SAN, turning the issued leaf into an X.509-SVID consumable by
SPIFFE-aware service-mesh/workload tooling (Envoy, Istio, SPIRE-adjacent
stacks) — no SPIFFE-specific protocol support is needed on mint-ca's side,
since an X.509-SVID is just an ordinary certificate with a `spiffe://` URI SAN.

- `"spiffe_id"` — a convenience field: the value is validated (scheme
  `spiffe`, non-empty lowercase trust domain, no userinfo/query/fragment, at
  most 2048 bytes) and added as a URI SAN. Invalid IDs are refused with `400`.
- `"sans_uri"` — a general list of URI SAN values. Any entry starting with
  `spiffe://` is validated the same way as `spiffe_id`; other URI schemes are
  parsed but not otherwise restricted.

`POST /api/v1/certs/sign` and `POST /api/v1/certs/batch/sign` don't take a
`spiffe_id` field — any URI SANs (including `spiffe://` ones) already present
in the submitted CSR are carried through unmodified, the same way DNS/IP/
email SANs are.

Only X.509-SVIDs are supported; JWT-SVIDs (and the SPIFFE Workload API) are
out of scope for now.
