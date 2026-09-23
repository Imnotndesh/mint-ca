# mint-ca companion project plans

Detailed, standalone implementation plans for the larger features tracked in
project discussion but deliberately not built directly into the `mint-ca`
server repo (except where noted). Each is written so a fresh engineer or LLM
worker with no prior context on these discussions can pick it up and execute
it — read the target plan in full before starting any of them.

| Plan | Scope | Where it lives |
|---|---|---|
| [`setup-tls-transition.md`](setup-tls-transition.md) | In-process HTTP setup → HTTPS ready transition using the freshly generated cert | **This repo** (mint-ca server: `cmd/server`, `internal/config`) |

The CLI (`cli/mca`), Terraform provider (`terraform/mintca`), and web UI
dashboard plans have all shipped and live in `mint-ca-tools`; their plan docs
have been removed.
