# mint-ca companion project plans

Detailed, standalone implementation plans for the larger features tracked in
project discussion but deliberately not built directly into the `mint-ca`
server repo (except where noted). Each is written so a fresh engineer or LLM
worker with no prior context on these discussions can pick it up and execute
it — read the target plan in full before starting any of them.

| Plan | Scope | Where it lives |
|---|---|---|
| [`cli-mca.md`](cli-mca.md) | `mca`, a CLI client for the mint-ca REST API | Separate repo |
| [`terraform-provider.md`](terraform-provider.md) | `terraform-provider-mintca` | Separate repo |
| [`cert-manager-webhook.md`](cert-manager-webhook.md) | Kubernetes cert-manager external issuer controller | Separate repo |
| [`web-ui-dashboard.md`](web-ui-dashboard.md) | Browser-based admin dashboard SPA | Separate repo |
| [`multi-tenancy.md`](multi-tenancy.md) | Tenant isolation for CAs/provisioners/certs/API keys | **This repo** (mint-ca server itself), phased across multiple PRs |

All four "separate repo" plans talk to mint-ca purely over its documented
REST API (`../Api.md`) and must not import any `mint-ca/internal/...` Go
package. The multi-tenancy plan is the one exception — it modifies the
mint-ca server directly and should be read alongside
`../handoff-remaining-features.md` for this repo's established conventions.
