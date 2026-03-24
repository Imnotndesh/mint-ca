# User Guide: Setting Up mint‑ca and Issuing a Certificate

This guide walks you through the complete lifecycle of using mint‑ca, from initial setup to issuing your first certificate.  

## Assumptions
- We assume you have already installed mint‑ca (see [Installation & Configuration](Setup.md)) and that the server is running in **development mode** with TLS disabled for simplicity. 
> For production, replace `http://localhost:8080` with your HTTPS URL and use proper TLS.
- All commands use `curl` to demonstrate.  
- You will need to substitute UUIDs (returned by the server) into subsequent commands.  
- The bootstrap key is printed to stdout once; store it immediately.

---

## 3.1 Step 1: Obtain the Bootstrap Key

When mint‑ca starts for the first time, it prints the bootstrap key to the console.  
Look for output like:

```
mint-ca SETUP MODE

Bootstrap API Key (printed ONCE — save it now):

mca_abc123def4567890...

Complete setup:
POST /setup/root-ca   — create the root CA
POST /setup/api-key   — create your permanent key
...
```

Copy the key (the whole string starting with `mca_`).  
We’ll refer to it as `$BOOTSTRAP_KEY` in the commands.

> **Note**: The bootstrap key is valid only for the `/setup/*` endpoints. It is deleted automatically after you create the permanent API key.

---

## 3.2 Step 2: Create the Root CA

Use the bootstrap key to create your first root Certificate Authority.

```bash
export BOOTSTRAP_KEY="mca_abc123def4567890..."

curl -X POST http://localhost:8080/setup/root-ca \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "My Root CA",
    "organization": "My Org",
    "country": "US",
    "key_algo": "ecdsa-p256",
    "ttl_days": 3650
  }'
```

**Expected response** (201 Created):

```json
{
  "message": "root CA created — now call POST /setup/api-key",
  "ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "ca": { ... }
}
```

Save the `ca_id` (we’ll use it later).  
You can create only one root CA during setup; after that, you can create intermediates via the management API.

---

## 3.3 Step 3: Create a Permanent API Key

Now create the first permanent API key. This key will be used for all subsequent management operations.  
The bootstrap key is deleted after this step, and the server transitions to **ready mode**.

```bash
curl -X POST http://localhost:8080/setup/api-key \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "admin",
    "scopes": ["*"]
  }'
```

**Expected response** (201 Created):

```json
{
  "message": "setup complete — save your API key now, it will not be shown again",
  "api_key": "mca_987zyx...",
  "ca_id": "550e8400-e29b-41d4-a716-446655440000",
  "root_chain": "/pki/550e8400-e29b-41d4-a716-446655440000/chain"
}
```

**Store the `api_key` securely** – it will never be shown again.  
You can now use this key for all management API calls.

The server will now serve the full API under `/api/v1`.  
Any request to a non‑setup endpoint will be processed normally.

---

## 3.4 Step 4: Create an Intermediate CA (Optional)

If you want a multi‑level hierarchy, create an intermediate CA signed by the root.

```bash
export API_KEY="mca_987zyx..."
export ROOT_CA_ID="550e8400-e29b-41d4-a716-446655440000"

curl -X POST http://localhost:8080/api/v1/ca/intermediate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "parent_ca_id": "'"$ROOT_CA_ID"'",
    "name": "Intermediate 1",
    "common_name": "Intermediate CA 1",
    "key_algo": "ecdsa-p256",
    "ttl_days": 1825,
    "max_path_len": 0
  }'
```

**Expected response** (201 Created):

```json
{
  "id": "intermediate-uuid",
  "name": "Intermediate 1",
  "type": "intermediate",
  "status": "active",
  ...
}
```

Save the `id` of the intermediate CA – we will use it for certificate issuance.

---

## 3.5 Step 5: Create a Provisioner

A provisioner is an authorised entity that can request certificates.  
For API‑key based issuance, we create a provisioner of type `apikey`.

```bash
export INTERMEDIATE_CA_ID="intermediate-uuid"

curl -X POST http://localhost:8080/api/v1/provisioners \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "'"$INTERMEDIATE_CA_ID"'",
    "name": "web-provisioner",
    "type": "apikey",
    "config": {}
  }'
```

**Expected response** (201 Created):

```json
{
  "id": "provisioner-uuid",
  "ca_id": "intermediate-uuid",
  "name": "web-provisioner",
  "type": "apikey",
  "status": "active",
  "created_at": "..."
}
```

Save the `id` (provisioner UUID) – it is required when issuing certificates.

---

## 3.6 Step 6: Issue a Certificate

Now we issue a certificate for a service. We’ll let mint‑ca generate the key pair.

```bash
export PROVISIONER_ID="provisioner-uuid"

curl -X POST http://localhost:8080/api/v1/certs/issue \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "'"$INTERMEDIATE_CA_ID"'",
    "provisioner_id": "'"$PROVISIONER_ID"'",
    "common_name": "myservice.example.com",
    "sans_dns": ["myservice.example.com", "api.example.com"],
    "ttl_seconds": 86400,
    "key_algo": "ecdsa-p256",
    "server_auth": true,
    "client_auth": false,
    "metadata": { "environment": "prod" }
  }'
```

**Expected response** (201 Created):

```json
{
  "certificate": {
    "id": "cert-uuid",
    "serial": "1234567890...",
    "subject_cn": "myservice.example.com",
    ...
  },
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n..."
}
```

- `cert_pem` – the leaf certificate.
- `key_pem` – the private key (save it securely).
- `chain_pem` – the full chain (leaf + intermediate + root).  
  You can present this chain in your TLS server.

---

## 3.7 Step 7: Retrieve the CA Chain (Optional)

If you need only the CA chain (e.g., to configure a trust store), fetch it from the public endpoint:

```bash
curl http://localhost:8080/pki/$INTERMEDIATE_CA_ID/chain
```

Or for the root:

```bash
curl http://localhost:8080/pki/$ROOT_CA_ID/chain
```

The response is PEM‑encoded certificates.

---

## 3.8 Step 8: List Issued Certificates

To see all certificates issued by a CA:

```bash
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/v1/certs/ca/$INTERMEDIATE_CA_ID
```

This returns an array of certificate records (without private keys).

---

## 3.9 Step 9: Revoke a Certificate

```bash
curl -X PUT http://localhost:8080/api/v1/certs/cert-uuid/revoke \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": 1}'   # reason codes: 0=unspecified, 1=keyCompromise, etc.
```

**Response**:

```json
{ "status": "revoked" }
```

The revocation is immediately reflected in the next CRL (which is regenerated automatically at a background interval).

---

## 3.10 Additional Management Tasks

### Create an API Key for another user

```bash
curl -X POST http://localhost:8080/api/v1/apikeys \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "alice",
    "scopes": ["cert:issue", "cert:revoke"],
    "expires_in_seconds": 2592000
  }'
```

The response includes the new raw key (store it).  
The key will be automatically deleted after expiry.

### View Audit Logs

```bash
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/v1/audit?limit=10
```

### Check Server Health

```bash
curl http://localhost:8080/healthz
```

In ready mode, returns `{"status":"ok","service":"mint-ca"}`.

### Get Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

---

## 3.11 Using ACME (Optional)

If you enabled ACME (`MINT_ACME_ENABLED=true`), you can use any ACME client (like Certbot) with your mint‑ca instance.  
The ACME endpoint is `/acme/{provisionerID}/directory`.  
You must create an ACME provisioner first (type `acme`).  
Then clients can register accounts and order certificates following RFC 8555.

**Example: Create an ACME provisioner**

```bash
curl -X POST http://localhost:8080/api/v1/provisioners \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "'"$INTERMEDIATE_CA_ID"'",
    "name": "acme-provisioner",
    "type": "acme",
    "config": {
      "eab_required": false,
      "default_ttl_seconds": 86400,
      "allowed_challenge_types": ["http-01", "dns-01"]
    }
  }'
```

After creation, the directory URL becomes `http://localhost:8080/acme/{provisioner-uuid}/directory`.  
You can then use Certbot:

```bash
certbot certonly --standalone --server http://localhost:8080/acme/provisioner-uuid/directory -d example.com
```

---

## 3.12 Troubleshooting Common Issues

- **`401 Unauthorized`** – Check your `Authorization` header; it must be `Bearer <key>`.
- **`403 Forbidden`** – Your API key may not have the required scope. Use `scopes: ["*"]` for full access.
- **`404 Not Found`** – Verify that the server is in ready mode (check `/healthz`). If it returns `{"status":"setup",...}`, you haven’t completed the two setup steps.
- **`400 Bad Request`** – The request body may be malformed. Ensure JSON is valid and fields match the expected types.
- **Certificate not trusted** – Make sure you installed the root CA chain in your system’s trust store.
- **Revoked certificate still appears valid** – CRLs are regenerated on a background interval (default 1h). To force immediate update, wait up to one minute or trigger a CRL refresh via the background worker (or just wait).

---

## 3.13 Next Steps

- Explore the full API using the [API Reference](Api.md).
- Set up monitoring with Prometheus and Grafana.
- Configure backup scripts for the database and master key.
- Integrate mint‑ca with your CI/CD pipelines for automated certificate issuance.

>If you encounter issues, consult the project’s issue tracker.