# mint-ca companion project plans

Detailed, standalone implementation plans for the larger features tracked in
project discussion but deliberately not built directly into the `mint-ca`
server repo (except where noted). Each is written so a fresh engineer or LLM
worker with no prior context on these discussions can pick it up and execute
it — read the target plan in full before starting any of them.

| Plan | Scope | Where it lives |
|---|---|---|
| [`setup-tls-transition.md`](setup-tls-transition.md) | In-process HTTP setup → HTTPS ready transition using the freshly generated cert | **This repo** (mint-ca server: `cmd/server`, `internal/config`) |
| [`cli-mca.md`](cli-mca.md) | `mca`, a CLI client for the mint-ca REST API | Separate repo |
| [`terraform-provider.md`](terraform-provider.md) | `terraform-provider-mintca` | Separate repo |
| [`web-ui-dashboard.md`](web-ui-dashboard.md) | Browser-based admin dashboard SPA | Separate repo |

All of the "separate repo" plans talk to mint-ca purely over its documented
REST API (`../Api.md`) and must not import any `mint-ca/internal/...` Go
package. The `setup-tls-transition` plan is the exception — it modifies the
mint-ca server directly and should follow that repo's existing conventions by
example (read a recently-merged feature's code rather than a separate
conventions doc).
