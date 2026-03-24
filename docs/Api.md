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
  "key_algo": "ecdsa-p256",           // ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096
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
PEM‑encoded CRL.

### `GET /pki/{caID}/crl.der`
DER‑encoded CRL (content-type `application/pkix-crl`).

### `POST /pki/{caID}/ocsp`
OCSP request (DER) in the body, returns DER‑encoded OCSP response.

### `GET /pki/{caID}/chain`
Full CA chain in PEM format (the CA’s own certificate plus all ancestors up to the root).

---

## 1.10 ACME Endpoints

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

See [RFC 8555](https://tools.ietf.org/html/rfc8555) for the exact JWS payloads.  
The directory response contains URLs for all operations.

---

## 1.11 Health & Setup

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
