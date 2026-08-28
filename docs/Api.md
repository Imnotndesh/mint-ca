# 1. mint‑ca API Reference

All management API endpoints are served under `/api/v1` and require a valid API key sent in the `Authorization: Bearer <key>` header.  
Public PKI endpoints (CRL, OCSP, chain) are under `/pki/{caID}` and do not require authentication.  
ACME endpoints are under `/acme/{provisionerID}` and follow the ACME protocol (no API key).

## 1.1 Certificate Authorities

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
  "metadata": { "environment": "prod" }
}
```

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
  "metadata": { "env": "prod" }
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

**Request body**
```json
{
  "name": "my-key",
  "scopes": ["*"],                // scope strings, "*" for all
  "ca_id": "ca-uuid",             // optional, restrict to a CA
  "expires_in_seconds": 31536000
}
```

**Response (201 Created)**
```json
{
  "id": "key-uuid",
  "name": "my-key",
  "key": "mca_abc123...",          // raw key – store it immediately
  "scopes": ["*"],
  "expires_at": "2026-01-01T00:00:00Z",
  "note": "store the key securely — it will not be shown again"
}
```

### `GET /api/v1/apikeys`
List all API keys (only metadata, no keys).

### `DELETE /api/v1/apikeys/{keyID}`
Delete an API key.

---

## 1.7 Audit Log

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
    "created_at": "..."
  }
]
```

### `GET /api/v1/audit/ca/{caID}`
Same as above, filtered by CA.

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

## 1.10 SSH Certificate Authorities

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
Get a single SSH CA by ID.

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

## 1.11 ACME Endpoints

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

## 1.12 Health & Setup

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
## 1.13 Rate Limiting

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
