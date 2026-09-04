# Mint‑CA Installation & Configuration

This document explains how to install, configure, and run mint‑ca.  
It covers both Docker and single‑binary deployment, all environment variables, and best practices.

## 2.1 Prerequisites

- **Operating System**: Linux, macOS, or Windows (WSL2 recommended for production)
- **For SQLite** (default): no extra dependencies
- **For PostgreSQL**: a running PostgreSQL server (version 12 or later)
- **For Docker**: Docker Engine 20.10+ or Podman
- **For binary**: a 64‑bit system; no runtime dependencies other than glibc

## 2.2 Installation Methods

### 2.2.1 Docker (recommended for production)

Pull the image from the container registry (replace with your actual registry):

```bash
docker pull ghcr.io/imnotndesh/mint-ca:latest
```

Run a container:

```bash
docker run -d \
  --name mint-ca \
  -p 8443:8443 \
  -v /mnt/data:/data \
  -e MINT_MASTER_KEY=$(openssl rand -hex 32) \
  -e MINT_ACME_ENABLED=true \
  -e MINT_ACME_BASE_URL=https://ca.example.com:8443 \
  -e MINT_TLS_CERT=/data/server.crt \
  -e MINT_TLS_KEY=/data/server.key \
  ghcr.io/imnotndesh/mint-ca:latest
```

**Explanation of flags**:
- `-p 8443:8443` – expose the default HTTPS port (or use `-p 8080:8080` if you run with `MINT_TLS_DISABLED=true`).
- `-v /mnt/data:/data` – persist the database, server certificates, and any other data.  
  The container expects to write to `/data`. Adjust the host path as needed.
- Environment variables (see §2.3).

**Upgrading**:
```bash
docker pull ghcr.io/imnotndesh/mint-ca:latest
docker stop mint-ca && docker rm mint-ca
docker run ...   # same arguments as before
```

### 2.2.2 Single Binary (for development or embedded use)

Download the binary from the [GitHub Releases](https://github.com/imnotndesh/mint-ca/releases) page:

```bash
wget https://github.com/imnotndesh/mint-ca/releases/download/v0.1.0/mint-ca-linux-amd64
chmod +x mint-ca-linux-amd64
```

Optionally move it to a directory in your `$PATH`:

```bash
sudo mv mint-ca-linux-amd64 /usr/local/bin/mint-ca
```

Run it:

```bash
export MINT_MASTER_KEY=$(openssl rand -hex 32)
export MINT_TLS_DISABLED=true   # for development only
./mint-ca-linux-amd64
```

All configuration is done via environment variables. No config file is used.

## 2.3 Environment Variables

The following table lists every environment variable mint‑ca recognises.  
Default values are shown; variables marked **Required** must be set.

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| **Server** | | | |
| `MINT_LISTEN_ADDR` | Address and port to bind (e.g., `:8443`, `0.0.0.0:8443`). | `:8443` | No |
| `MINT_TLS_CERT` | Path to the TLS certificate file (PEM). | – | Yes* |
| `MINT_TLS_KEY` | Path to the TLS private key file (PEM). | – | Yes* |
| `MINT_TLS_DISABLED` | Run over plain HTTP instead of HTTPS. **Never set this in production.** | `false` | No |
| `MINT_READ_TIMEOUT_SECONDS` | Maximum duration (seconds) for reading the entire request. | `30` | No |
| `MINT_WRITE_TIMEOUT_SECONDS` | Maximum duration (seconds) for writing the response. | `60` | No |
| `MINT_IDLE_TIMEOUT_SECONDS` | Maximum duration (seconds) to keep an idle connection open. | `120` | No |
| **Storage** | | | |
| `MINT_DB_DRIVER` | Database driver: `sqlite` or `postgres`. | `sqlite` | No |
| `MINT_DB_DSN` | Data source name. For SQLite: absolute file path. For PostgreSQL: connection string. | `/data/mint-ca.db` (SQLite) | For PostgreSQL |
| **Crypto** | | | |
| `MINT_MASTER_KEY` | 32‑byte hex‑encoded AES‑256 key used to encrypt CA private keys at rest. | – | **Yes** |
| **ACME** | | | |
| `MINT_ACME_ENABLED` | Enable the ACME protocol endpoints. | `false` | No |
| `MINT_ACME_BASE_URL` | Public HTTPS URL where mint‑ca is reachable (e.g., `https://ca.example.com`). | – | If ACME enabled |
| `MINT_ACME_EAB_REQUIRED` | Require External Account Binding for new ACME accounts. | `false` | No |
| `MINT_ACME_CAA_DOMAIN` | This CA's public identity used for RFC 8659 CAA checks. When set, issuance is refused unless each identifier's CAA record authorises this domain. Empty disables CAA enforcement. | – | No |
| `MINT_ACME_CAA_DNS_SERVER` | Override resolver (host:port) for CAA DNS lookups. Empty reads the system resolvers. | system | No |
| `MINT_ACME_CAA_BYPASS_LABELS` | Comma‑separated domain labels for which CAA checking is skipped (a CP/CPS exception). | – | No |
| **CRL** | | | |
| `MINT_CRL_REFRESH_INTERVAL_SECONDS` | How often (seconds) to regenerate CRLs for all active CAs. | `3600` (1h) | No |
| `MINT_CRL_VALIDITY_SECONDS` | How long (seconds) a generated CRL is valid (`NextUpdate`). | `86400` (24h) | No |
| `MINT_CRL_DELTA_ENABLED` | Publish delta CRLs (`/pki/{caID}/crl/delta`) alongside the full base CRL. Opt‑in; off by default so existing deployments are unchanged. Base CRLs then carry a Freshest CRL extension (when `MINT_ACME_BASE_URL` is set). | `false` | No |
| `MINT_CRL_BASE_REFRESH_INTERVAL_SECONDS` | How often (seconds) to regenerate the full base CRL while delta mode is on. Deltas refresh every `MINT_CRL_REFRESH_INTERVAL_SECONDS`; bases can be rebuilt less often to reduce churn. Must be ≥ the refresh interval. | defaults to `MINT_CRL_REFRESH_INTERVAL_SECONDS` | No |
| **MTLS Device Enrollment** | | | |
| `MINT_MTLS_ENABLED` | Run a second mutual‑TLS listener for device enrollment (`/enroll`). | `false` | No |
| `MINT_MTLS_LISTEN_ADDR` | Address/port the enrollment listener binds (e.g. `:8444`). | – | Yes if MTLS enabled |
| `MINT_MTLS_CLIENT_CA` | PEM of the CA cert (or chain) used to validate device client certificates. | – | Yes if MTLS enabled |
| `MINT_MTLS_CERT` / `MINT_MTLS_KEY` | Server TLS cert/key for the enrollment listener. Defaults to the main server TLS files. | main server TLS | No |
| **Certificate Auto-Renewal** | | | |
| `MINT_RENEWAL_ENABLED` | Run the background certificate auto-renewal worker. | `false` | No |
| `MINT_RENEWAL_INTERVAL_SECONDS` | How often (seconds) the worker scans for certs due for renewal. | `3600` (1h) | No |
| `MINT_RENEWAL_LEAD_SECONDS` | How long (seconds) before `NotAfter` a cert is considered due for renewal. | `604800` (7 days) | No |
| `MINT_RENEWAL_WEBHOOK_URL` | When set, mint-ca POSTs a JSON notice for each cert due for renewal so an external system can renew it. | – | No |
| `MINT_RENEWAL_EXPIRING_SECONDS` | How long (seconds) before `NotAfter` a cert is classified `expiring_soon` instead of `due` in `GET /api/v1/renewal/status`. | `172800` (48h) | No |
| `MINT_SCEP_ENABLED` | Enable the public SCEP enrollment endpoint at `/pki/{caID}/scep`. | `false` | No |
| `MINT_SCEP_PROVISIONER_ID` | The provisioner UUID every SCEP enrollment is signed under. Required if `MINT_SCEP_ENABLED=true`. | – | If SCEP enabled |
| `MINT_SCEP_DEFAULT_TTL_SECONDS` | Leaf certificate lifetime granted to SCEP enrollments. | `7776000` (90 days) | No |
| **Logging** | | | |
| `MINT_LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error`. | `info` | No |
| `MINT_LOG_JSON` | Output logs as JSON (structured) instead of human‑readable. | `false` | No |
| **Rate Limiting** (first-boot only — ignored after DB row exists) | | | |
| `MINT_RATELIMIT_NEW_ACCOUNT_WINDOW_SECONDS` / `MINT_RATELIMIT_NEW_ACCOUNT_MAX` | Override for `acme_new_account_per_ip` | 3600s / 10 | No |
| `MINT_RATELIMIT_NEW_ORDER_WINDOW_SECONDS` / `MINT_RATELIMIT_NEW_ORDER_MAX` | Override for `acme_new_order_per_account` | 3600s / 50 | No |
| `MINT_RATELIMIT_NEW_AUTHZ_WINDOW_SECONDS` / `MINT_RATELIMIT_NEW_AUTHZ_MAX` | Override for `acme_new_authz_per_account` | 3600s / 50 | No |
| `MINT_RATELIMIT_APIKEY_WINDOW_SECONDS` / `MINT_RATELIMIT_APIKEY_MAX` | Override for `apikey_requests_per_key` | 60s / 300 | No |

\* Required when `MINT_TLS_DISABLED` is `false` (the default). If you set `MINT_TLS_DISABLED=true`, these become optional.

### 2.3.1 Generating a Master Key

The master key must be 32 random bytes, hex‑encoded. Generate it with:

```bash
openssl rand -hex 32
```

Store this key securely (e.g., in a password manager or Kubernetes secret). **Do not commit it to version control.**

### 2.3.2 PostgreSQL DSN Format

Example DSN:

```
postgres://mintca:mysecret@db.example.com:5432/mintca?sslmode=require
```

The store will automatically create all necessary tables if they do not exist.

## 2.4 Data Persistence

- **SQLite**: The database file is stored at the path given by `MINT_DB_DSN` (default `/data/mint-ca.db`).  
  For Docker, mount a volume to `/data`. For binary, ensure the directory exists and is writable.
- **PostgreSQL**: The database is managed externally. Make sure the user has `CREATE TABLE` privileges.

The server also writes the TLS certificate and key (if generated during setup) to the same data directory (`server.crt` and `server.key`). It expects these files to exist on startup when TLS is enabled. If they are missing, the server will generate a temporary self‑signed certificate during the setup phase and later replace it.

## 2.5 First Boot and Setup Mode

When mint‑ca starts for the first time with an empty database, it enters **setup mode**.  
In this mode:

- The server listens on the configured address (HTTP or HTTPS) but **only** serves the `/setup/*` and `/healthz` endpoints.
- It prints a **bootstrap API key** to stdout (once). This key is valid only for the setup endpoints.
- All other requests return `503 Service Unavailable` with a hint to complete setup.

The purpose of setup mode is to securely create the initial root CA and the first permanent API key. After these steps, the server transitions to **ready mode** and begins serving the full management API.

### 2.5.1 Obtaining the Bootstrap Key

Look for a block like this in the container logs:

```
  mint-ca SETUP MODE

  Bootstrap API Key (printed ONCE — save it now):

  mca_abc123def4567890...
  
  Complete setup:
    POST /setup/root-ca   — create the root CA
    POST /setup/api-key   — create your permanent key

  After /setup/api-key completes:
    • This bootstrap key is permanently deleted
    • The server restarts its listener with TLS
```

Save the key – you will need it for the next steps.

### 2.5.2 Minimal Setup Steps

Using `curl` (or any HTTP client), perform the following two requests **before** the bootstrap key is deleted:

1. Create the root CA (see 3.2 in the user guide).
2. Create the permanent API key (see 3.3).

After the second request, the server automatically deletes the bootstrap key and restarts its HTTP listener (now in ready mode).  
If you are using Docker, the container does **not** restart; the listener is replaced in‑process, but the process stays alive.

## 2.6 Minimal Configuration (Development)

For local testing without TLS, use this minimal setup:

```bash
# Generate a master key (store it somewhere safe)
export MINT_MASTER_KEY=$(openssl rand -hex 32)

# Disable TLS (never do this in production)
export MINT_TLS_DISABLED=true

# Optional: change the listen address
export MINT_LISTEN_ADDR=:8080

# Optional: enable ACME if needed
export MINT_ACME_ENABLED=true
export MINT_ACME_BASE_URL=http://localhost:8080   # note: http for dev

# Run the binary
./mint-ca-linux-amd64
```

The server will start in setup mode; follow the steps to create the root CA and a permanent API key.  
After that, you can use `curl` with the new key to manage certificates.
## 2.7 Rate Limiting

On first boot, mint-ca seeds four default rate limiters into the database (see Api.md §1.13). The `MINT_RATELIMIT_*` env vars above only take effect the very first time — they seed the initial row and are never re-applied, so a value edited later (directly in the DB, or via a future web UI) is never clobbered by a container restart with different env vars.

To adjust limits after first boot, update the `rate_limit_configs` table directly:
```sql
UPDATE rate_limit_configs SET max_requests = 20, window_seconds = 3600
WHERE name = 'acme_new_account_per_ip';
```
Changes take effect on the next process restart (configs are loaded into memory at boot).
## 2.8 Production Considerations

- **TLS**: Always run with TLS enabled (`MINT_TLS_DISABLED=false`, the default). Provide a valid certificate and key (from a trusted CA or your own root).  
  mint‑ca will use these files to serve HTTPS. If they are missing during the first boot, it generates a self‑signed certificate to get through setup, but you must replace it after the root CA is created.
- **Master Key**: Protect it like a database password. In Kubernetes, store it in a `Secret`. In Docker, use `--env-file` or orchestration secrets.
- **Database**: For production, use PostgreSQL (with replication, backups). SQLite is fine for small to medium deployments but does not scale to high write concurrency.
- **Firewall**: Expose only the ports you need: `8443` (HTTPS) or `80` (if you use ACME http‑01 validation). The management API should be protected by the API key and ideally only accessible from trusted networks.
- **Backups**: Back up the database file (SQLite) or use PostgreSQL native backups. Also back up the master key – without it, encrypted CA keys cannot be recovered.
- **Monitoring**: The `/metrics` endpoint provides Prometheus metrics. Scrape it from your monitoring system.
- **Logging**: Use `MINT_LOG_JSON=true` and forward logs to a central system.

## 2.9 Troubleshooting

- **“missing Authorization header”** when accessing `/api/v1` → you forgot the `Bearer` token.
- **“invalid API key”** → the key is wrong or expired. Generate a new one via `/api/v1/apikeys`.
- **“server is in setup mode”** → you haven’t completed the initial setup. Perform the two POST requests.
- **“failed to open storage”** → database path is not writable (SQLite) or PostgreSQL connection failed.
- **“master key must be exactly 32 bytes”** → the `MINT_MASTER_KEY` hex string decodes to the wrong length. Regenerate with `openssl rand -hex 32`.

For further help, consult the project’s GitHub issues or community support channels.

---

**Next steps**: After installation, follow the [User Guide](UserGuide.md) to create your first certificate.