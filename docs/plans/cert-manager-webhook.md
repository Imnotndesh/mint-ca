# Plan — cert-manager Integration for mint-ca

## Objective
Let Kubernetes workloads get `Certificate` resources that are transparently
issued and auto-renewed by mint-ca (`github.com/Imnotndesh/mint-ca`), the
same way they would from Let's Encrypt or Vault via cert-manager, without
anyone hand-rolling CSR generation/signing/renewal logic in-cluster.

**Read this whole section before writing any code — there are two very
different integration paths, and picking the right one matters.**

## Important correction on terminology
An earlier conversation about this project described the deliverable as "a
gRPC service implementing cert-manager's Sign API." That phrasing conflates
two unrelated cert-manager extension points and is not quite right — read
carefully:

1. **cert-manager's gRPC "webhook" interface**
   (`github.com/cert-manager/cert-manager/pkg/acme/webhook`) exists
   specifically for **ACME DNS-01 challenge solvers** (e.g. a webhook that
   knows how to create a TXT record in some DNS provider on ACME's behalf).
   It has nothing to do with plugging in a non-ACME certificate authority as
   an issuer, and is **not** what this plan builds.
2. The correct, current (as of cert-manager 1.x) mechanism for a third-party
   CA to become a certificate source for cert-manager is the **external
   issuer** pattern: a small Kubernetes controller, built with
   `controller-runtime`/kubebuilder, that defines its own `Issuer`/
   `ClusterIssuer`-like CRD, watches `CertificateRequest` resources that
   reference it, and populates `status.certificate` by calling out to the
   CA's own API. This is what this plan builds. The canonical reference
   implementation to study before starting is
   [`cert-manager/sample-external-issuer`](https://github.com/cert-manager/sample-external-issuer)
   — clone it and read it end to end first; this plan's structure follows it
   closely and calls out every place mint-ca specifics replace the sample's
   placeholder logic.

## A faster alternative worth trying first
mint-ca already implements a native ACME server (`docs/Api.md` §1.12,
`/acme/{provisionerID}/...`, with optional External Account Binding — §1.5).
**cert-manager has a built-in ACME issuer.** If EAB-gated ACME issuance
(`docs/Api.md`'s ACME + EAB flow) meets your policy/profile needs, you may
not need to write any new code at all — just:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: mintca-acme
spec:
  acme:
    server: https://ca.internal:8443/acme/<provisionerID>/directory
    externalAccountBinding:
      keyID: <from POST /api/v1/eab/provisioner/{provisionerID}>
      keySecretRef:
        name: mintca-eab-hmac
        key: hmac-key
    privateKeySecretRef:
      name: mintca-acme-account-key
    solvers:
      - http01: { ... }   # or dns01, whatever validation mint-ca's ACME CAA/validation setup supports
```
Try this path, confirm with a real `Certificate` resource whether it covers
your requirements (in particular: mint-ca's ACME profile-intent feature,
§1.17, lets you pin a profile per-provisioner — check whether that alone
satisfies the policy control you need). **Only proceed with the external
issuer controller below if the ACME path doesn't give you something you
need** — e.g. synchronous non-ACME issuance semantics, exposing mint-ca
concepts (named CAs by UUID, CSR auto-approval rules, hardware attestation
statements) that don't map cleanly onto the ACME protocol, or avoiding the
ACME account/order state machine's operational overhead entirely.

The rest of this document assumes you've decided the controller is worth
building.

## Ground rules
- New repo: `cert-manager-external-issuer-mintca` (or similar; follow
  cert-manager's own naming convention:
  `<vendor>-issuer` / `cert-manager-<vendor>-issuer`).
- Scaffold with `kubebuilder init` and `kubebuilder create api`, exactly as
  `sample-external-issuer` does. Use `controller-runtime` (whatever version
  `sample-external-issuer`'s current `go.mod` pins — match it rather than
  picking independently, since API compatibility between controller-runtime
  and the Kubernetes client libraries is version-sensitive).
- Do not import any `mint-ca/internal/...` package. Talk to mint-ca purely
  over its REST API, same principle as the CLI and Terraform provider plans.
- `go build ./...`, `go vet ./...`, `go test ./...` clean before every
  commit. Use `envtest` (part of controller-runtime's testing tools, backed
  by `setup-envtest`) for controller tests against a real (but ephemeral,
  local) API server + etcd — this is standard practice for kubebuilder
  projects and what reviewers will expect; do not skip it in favor of pure
  mocks for the reconciler tests.

## Architecture
```
cert-manager-external-issuer-mintca/
  api/v1alpha1/
    mintcaissuer_types.go         # MintCAIssuer CRD (namespaced)
    mintcaclusterissuer_types.go  # MintCAClusterIssuer CRD (cluster-scoped)
    groupversion_info.go
  internal/
    controllers/
      issuer_controller.go         # reconciles MintCAIssuer/MintCAClusterIssuer: checks connectivity, sets Ready condition
      certificaterequest_controller.go  # reconciles CertificateRequest resources referencing our issuer kind
    mintca/
      client.go                    # REST client, same shape as the CLI/Terraform plans' client packages
    signer/
      signer.go                    # translates a CertificateRequest's CSR bytes into a mint-ca Sign call + response
  config/                           # kubebuilder-generated CRDs, RBAC, manager Deployment manifests
  charts/mintca-issuer/             # optional Helm chart wrapping config/, for easier install
  main.go
```

## The CRD: `MintCAIssuer` / `MintCAClusterIssuer`
Define **two** CRDs — namespaced and cluster-scoped — exactly mirroring
cert-manager's own `Issuer`/`ClusterIssuer` split, so users pick the scope
they need. Both share the same `Spec`/`Status` shape (factor into a common
Go type embedded in both, as `sample-external-issuer` does for its single
`IssuerSpec`).

```go
type MintCAIssuerSpec struct {
    // Endpoint is the mint-ca server's base URL, e.g. https://ca.internal:8443
    // +kubebuilder:validation:Required
    Endpoint string `json:"endpoint"`

    // CAID is the mint-ca CA (by UUID) this issuer signs against.
    // +kubebuilder:validation:Required
    CAID string `json:"caID"`

    // ProvisionerID is the mint-ca provisioner (by UUID) used for every
    // signing request from CertificateRequests referencing this issuer.
    // +kubebuilder:validation:Required
    ProvisionerID string `json:"provisionerID"`

    // Profile optionally names a mint-ca certificate profile to enforce
    // (see docs/Api.md 1.2's "profile" field). Only meaningful when using
    // the /certs/issue-equivalent path — see the signer design note below
    // about why CertificateRequest maps to /certs/sign, not /certs/issue,
    // and how Profile enforcement still applies there via the provisioner's
    // pinned profile if /certs/sign itself doesn't take a profile param at
    // the time you implement this; check docs/Api.md's current /certs/sign
    // request shape.
    // +optional
    Profile string `json:"profile,omitempty"`

    // APIKeySecretRef references a Secret (in the same namespace as this
    // Issuer, or a fixed operator namespace for MintCAClusterIssuer — follow
    // sample-external-issuer's pattern for that distinction) holding the
    // mint-ca API key under a well-known data key.
    // +kubebuilder:validation:Required
    APIKeySecretRef corev1.SecretKeySelector `json:"apiKeySecretRef"`

    // CABundleSecretRef optionally references a Secret holding a PEM CA
    // bundle to trust mint-ca's TLS certificate, for self-signed
    // deployments (see docs/Setup.md's TLS guidance). If unset, the system
    // trust store is used.
    // +optional
    CABundleSecretRef *corev1.SecretKeySelector `json:"caBundleSecretRef,omitempty"`
}

type MintCAIssuerStatus struct {
    // Conditions follows the standard Kubernetes conditions pattern; set a
    // "Ready" condition, mirroring cert-manager's own ConditionReady, so
    // `kubectl get mintcaissuer` output and any tooling expecting the
    // standard shape works uniformly.
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

## Reconciler 1: the Issuer controller
On every reconcile of a `MintCAIssuer`/`MintCAClusterIssuer`:
1. Resolve `APIKeySecretRef` (and `CABundleSecretRef` if set).
2. Build a `mintca.Client` and call a cheap authenticated endpoint to prove
   the key works and the CA/provisioner IDs are valid — e.g.
   `GET /api/v1/ca/{caID}` (confirms the CA exists and is reachable) and
   `GET /api/v1/provisioners/{provisionerID}` (confirms the provisioner
   exists and belongs to that CA — compare its `ca_id` field to `Spec.CAID`
   and fail Ready with a clear message if they don't match; this is exactly
   the kind of misconfiguration that's otherwise invisible until the first
   real signing attempt).
3. Set the `Ready` condition `True`/`False` accordingly, with a human-
   readable `Message` on failure (e.g. "API key rejected: 401", "provisioner
   <id> belongs to CA <other-id>, not <caID>").
4. Re-reconcile periodically (`RequeueAfter: 5 * time.Minute` is a reasonable
   default — this is a health check, not the hot path) and on Secret changes
   (watch Secrets referenced by any Issuer, via an index +
   `Owns`/`Watches` — `sample-external-issuer` demonstrates this pattern for
   its own secret watching, copy it).

## Reconciler 2: the CertificateRequest controller
This is the core of the integration. cert-manager creates a
`CertificateRequest` (with a raw CSR in `spec.request`, base64-encoded DER)
whenever a `Certificate` needs issuing/renewing, and sets
`spec.issuerRef.group`/`kind`/`name` to point at an issuer. Your controller:

1. **Filter**: only reconcile `CertificateRequest`s whose
   `spec.issuerRef.group` matches your CRD's API group (e.g.
   `mintca.<your-domain>`) — use a predicate, exactly as
   `sample-external-issuer` does, so you don't fight over the same resources
   as cert-manager's built-in issuers or other external issuers installed in
   the same cluster.
2. **Resolve the issuer**: look up the referenced `MintCAIssuer` (namespaced
   — same namespace as the `CertificateRequest`) or `MintCAClusterIssuer`
   (cluster-scoped) by `spec.issuerRef.kind`/`name`. If not found or not
   `Ready`, set the `CertificateRequest`'s `Ready` condition to `False` with
   reason `IssuerNotReady`/`IssuerNotFound` and requeue — do not error loudly
   into logs for a transient "issuer not ready yet" state, that's normal
   during cluster bootstrap ordering.
3. **Sign**: decode `spec.request` (base64 DER CSR), call
   `POST /api/v1/certs/sign` (`docs/Api.md` §1.2) with:
   ```json
   {
     "ca_id": "<issuer.spec.caID>",
     "provisioner_id": "<issuer.spec.provisionerID>",
     "csr_pem": "<PEM-encode the decoded CSR — mint-ca's endpoint takes PEM, not raw DER>",
     "ttl_seconds": <derive from spec.duration if set, else a sane default — check current API for whether ttl_seconds is required>,
     "metadata": {"k8s_certificaterequest": "<namespace>/<name>", "k8s_certificate": "<owner Certificate name if resolvable>"}
   }
   ```
   Check `docs/Api.md`'s current CSR-auto-approval-rule behavior (§1.15): if
   the referenced provisioner has approval rules configured, a CSR that
   doesn't satisfy them is refused with `403` — surface that verbatim in the
   `CertificateRequest`'s condition message (`Reason: DeniedByPolicy`) so
   the failure is visible via `kubectl describe certificaterequest`, not just
   in controller logs.
4. **Populate status** on success: `status.certificate` = the leaf `cert_pem`
   from the response, `status.ca` = the `chain_pem` (or just the issuing
   CA's own cert — check what cert-manager's `Certificate` controller
   expects here; `sample-external-issuer` shows the exact fields). Set
   `Ready: True`, `Reason: Issued`.
5. **On failure**: set `Ready: False` with a `Reason` drawn from the HTTP
   status (`DeniedByPolicy` for 403, `InvalidRequest` for 400, `Pending`/
   requeue-with-backoff for 5xx/network errors — don't treat a transient
   mint-ca outage as a permanent failure). Emit a Kubernetes `Event` on the
   `CertificateRequest` for every state transition (cert-manager's own
   issuers do this; users expect `kubectl describe` to show a timeline).
6. **Idempotency**: a `CertificateRequest` should only ever be signed once —
   if `status.certificate` is already populated, skip re-signing on
   subsequent reconciles (cert-manager itself creates a new
   `CertificateRequest` object for renewals, it doesn't mutate an old one).

## RBAC
Generate via kubebuilder markers on the controllers (`+kubebuilder:rbac:...`)
for: `get`/`list`/`watch`/`update` on `certificaterequests.cert-manager.io`
and `certificaterequests/status`, `get`/`list`/`watch` on your own
`mintcaissuers`/`mintcaclusterissuers` and their `/status`, `get`/`list`/
`watch` on `secrets` (scoped to the namespaces actually referenced — don't
request cluster-wide secret read if you can avoid it; `sample-external-issuer`
demonstrates namespace-scoped secret watching for exactly this reason).

## Testing requirements
- `envtest`-based suite (`internal/controllers/*_test.go` using
  `ginkgo`/`gomega`, matching `sample-external-issuer`'s test style — this is
  the kubebuilder-generated default, keep it rather than switching to plain
  `testing`, since it's what `envtest` scaffolding assumes) covering:
  - Issuer becomes Ready when mint-ca (faked via `httptest.NewServer`
    injected as the issuer's `endpoint`) responds successfully to the health
    check calls.
  - Issuer becomes not-Ready (with the right message) on a 401, and on a
    provisioner/CA mismatch.
  - CertificateRequest referencing a Ready issuer gets signed and
    `status.certificate` populated, when the fake mint-ca server returns a
    canned `POST /api/v1/certs/sign` response.
  - CertificateRequest gets a `DeniedByPolicy` condition when the fake server
    returns 403 with mint-ca's `{"error": "..."}` shape.
  - CertificateRequest referencing a non-existent issuer stays pending
    (doesn't crash-loop the controller).
- A `make test` target wiring `setup-envtest` exactly as kubebuilder's
  Makefile template does (kubebuilder generates this for you — don't
  hand-roll it).
- A manual/CI end-to-end smoke test (documented, not necessarily automated
  in v0.1.0) against a real local mint-ca + kind cluster: install CRDs,
  create a `MintCAClusterIssuer`, create a `Certificate`, confirm the
  resulting `Secret` contains a cert chaining to the expected mint-ca CA.

## Packaging & install
- `make manifests` (kubebuilder) generates CRDs + RBAC + a Deployment for the
  controller manager under `config/`.
- Provide a Helm chart (`charts/mintca-issuer/`) wrapping those manifests for
  easier install (`helm install mintca-issuer ...`), with values for image
  tag, replica count, and resource requests/limits — this is expected by
  most Kubernetes operators evaluating a new controller today even if the
  raw `kubectl apply -k config/default` path also works and should keep
  working.

## Acceptance bar
- `go build ./...`, `go vet ./...`, `go test ./...` (envtest suite included)
  clean.
- `MintCAIssuer` and `MintCAClusterIssuer` both implemented with passing
  Ready/not-Ready reconciliation tests.
- `CertificateRequest` signing path fully tested per the list above.
- A worked end-to-end example in `examples/` (Issuer + Certificate +
  expected Secret) that a new user can copy-paste against a real mint-ca +
  kind cluster.
- README documents both integration paths (this controller, and the "try
  ACME+EAB first" alternative above) so a future reader can make the same
  choice you did, informed by whatever changed in mint-ca's API surface
  since this plan was written.

## Out of scope for v0.1.0
- SPIFFE/SVID-aware `Certificate` annotations (mint-ca supports issuing
  SPIFFE IDs as URI SANs, §1.21 — a nice follow-up would be reading a
  `mintca.<domain>/spiffe-id` annotation off the `Certificate` resource and
  threading it through to `POST /api/v1/certs/sign`'s CSR... except CSR-based
  signing doesn't take a `spiffe_id` param, only `/certs/issue` does, and
  `/certs/issue` doesn't fit the CertificateRequest model since cert-manager
  always supplies its own CSR. If this is wanted, it likely means the CSR
  itself needs the SPIFFE URI SAN baked in before cert-manager submits it —
  investigate `Certificate.spec.uris` in current cert-manager versions,
  which does exactly this, before building anything bespoke).
- Hardware-attestation-gated issuance (§1.20) — no clean way for a
  cert-manager `CertificateRequest` to carry attestation evidence today;
  revisit only if a concrete use case appears.
- Automatic CA/provisioner discovery or multi-CA routing — v0.1.0 is one
  issuer object per (CA, provisioner) pair, explicitly configured.
