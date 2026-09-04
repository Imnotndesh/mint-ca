package handlers

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	gox509 "crypto/x509"
	"encoding/base64"

	"mint-ca/internal/approval"
	"mint-ca/internal/attestation"
	"mint-ca/internal/ca"
	"mint-ca/internal/events"
	"mint-ca/internal/policy"
	"mint-ca/internal/spiffe"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type CertHandler struct {
	engine      *ca.Engine
	policy      *policy.Engine
	store       storage.Store
	events      events.Emitter
	attestation *attestation.Registry
}

func NewCertHandler(engine *ca.Engine, policyEngine *policy.Engine, store storage.Store, emitter events.Emitter, attestationRegistry *attestation.Registry) *CertHandler {
	if emitter == nil {
		emitter = events.NoopEmitter{}
	}
	if attestationRegistry == nil {
		attestationRegistry = attestation.NewRegistry()
	}
	return &CertHandler{engine: engine, policy: policyEngine, store: store, events: emitter, attestation: attestationRegistry}
}

// attestationRequest optionally accompanies a CSR-signing request, proving
// the requested key is bound to a hardware root of trust (see
// internal/attestation). DataB64 is the format-specific evidence, base64
// encoded.
type attestationRequest struct {
	Format  string `json:"format"`
	DataB64 string `json:"data_b64"`
}

// verifyAttestation, when req is non-nil, decodes the CSR to DER and checks
// req against the handler's attestation registry. A nil req is a no-op:
// attestation is opt-in per request.
func (h *CertHandler) verifyAttestation(ctx context.Context, csrPEM string, req *attestationRequest) error {
	if req == nil {
		return nil
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return errors.New("attestation: no PEM block found in csr_pem")
	}
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		return fmt.Errorf("attestation: decode data_b64: %w", err)
	}
	result, err := h.attestation.Verify(ctx, block.Bytes, attestation.Statement{Format: req.Format, Data: data})
	if err != nil {
		return fmt.Errorf("attestation: %w", err)
	}
	if !result.Verified {
		return errors.New("attestation: statement did not verify")
	}
	return nil
}

// emitCertIssued notifies the events bus that a certificate was issued.
func (h *CertHandler) emitCertIssued(cert *storage.Certificate) {
	h.events.Emit(events.New(events.CertIssued, map[string]any{
		"cert_id":    cert.ID.String(),
		"ca_id":      cert.CAID.String(),
		"serial":     cert.Serial,
		"subject_cn": cert.SubjectCN,
		"not_after":  cert.NotAfter,
	}))
}

// emitCertRevoked notifies the events bus that a certificate was revoked.
func (h *CertHandler) emitCertRevoked(cert *storage.Certificate, reason *int) {
	h.events.Emit(events.New(events.CertRevoked, map[string]any{
		"cert_id":    cert.ID.String(),
		"ca_id":      cert.CAID.String(),
		"serial":     cert.Serial,
		"subject_cn": cert.SubjectCN,
		"reason":     reason,
	}))
}

// loadProfileByName resolves a named profile via the store, or (nil,nil) when
// the store does not support profiles at all.
func (h *CertHandler) loadProfileByName(ctx context.Context, name string) (*storage.Profile, error) {
	s, ok := h.store.(profileStore)
	if !ok {
		return nil, errors.New("store does not support profiles")
	}
	return s.GetProfileByName(ctx, name)
}

// enforceCSRAutoApproval applies CSR auto-approval rules (opt-in). If any
// rules exist for the provisioner, the CSR must satisfy one of them; otherwise
// it is refused. When no rule applies to the provisioner, behavior is unchanged
// (no auto-approval policy governs this CSR).
func (h *CertHandler) enforceCSRAutoApproval(ctx context.Context, provisionerID uuid.UUID, csrPEM string, ttlSeconds int64) error {
	return enforceCSRAutoApproval(ctx, h.store, provisionerID, csrPEM, ttlSeconds)
}

// enforceCSRAutoApproval is the store-agnostic form shared by any handler
// that signs a CSR directly (REST cert signing, SCEP), so the same
// auto-approval gate applies consistently.
func enforceCSRAutoApproval(ctx context.Context, store storage.Store, provisionerID uuid.UUID, csrPEM string, ttlSeconds int64) error {
	s, ok := store.(csrApprovalStore)
	if !ok {
		return nil
	}
	rules, err := s.ListCSRAutoApproveRules(ctx, provisionerID)
	if err != nil {
		return fmt.Errorf("load CSR approval rules: %w", err)
	}
	if len(rules) == 0 {
		return nil
	}

	csr, err := parseCSR(csrPEM)
	if err != nil {
		return err
	}
	req := approval.Request{
		ProvisionerID: provisionerID,
		CommonName:    csr.Subject.CommonName,
		SANsDNS:       csr.DNSNames,
		TTLSeconds:    ttlSeconds,
	}
	for _, rule := range rules {
		approved, decided, reason := approval.Evaluate(rule, req)
		if !decided {
			continue
		}
		if !approved {
			return errors.New("csr auto-approval: " + reason)
		}
		return nil
	}
	return errors.New("csr auto-approval: no rule approves this request")
}

func parseCSR(pemStr string) (*gox509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := gox509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	return csr, nil
}

func (h *CertHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/certs", func(r chi.Router) {
		r.Post("/issue", h.issue)
		r.Post("/sign", h.signCSR)
		r.Post("/batch/sign", h.batchSignCSR)
		r.Get("/{certID}", h.get)
		r.Get("/serial/{serial}", h.getBySerial)
		r.Get("/ca/{caID}", h.listByCA)
		r.Put("/{certID}/revoke", h.revoke)
		r.Get("/{certID}/key", h.key)
		r.Get("/{certID}/export", h.export)
	})
}

type issueCertRequest struct {
	CAID          string       `json:"ca_id"`
	ProvisionerID string       `json:"provisioner_id"`
	CommonName    string       `json:"common_name"`
	SANsDNS       []string     `json:"sans_dns"`
	SANsIP        []string     `json:"sans_ip"`
	SANsEmail     []string     `json:"sans_email"`
	TTLSeconds    int64        `json:"ttl_seconds"`
	KeyAlgo       string       `json:"key_algo"`
	ServerAuth    bool         `json:"server_auth"`
	ClientAuth    bool         `json:"client_auth"`
	Metadata      storage.JSON `json:"metadata"`
	// StoreKey persists the generated private key (keystore-encrypted, with an
	// optional passcode guard) so it can be retrieved later via the key/export
	// endpoints. Off by default: the key is returned once and never stored.
	StoreKey    bool   `json:"store_key"`
	KeyPasscode string `json:"key_passcode"`
	// Profile optionally names a certificate profile to enforce against this
	// issuance. Resolved by name and evaluated with policy.EvaluateProfile.
	Profile string `json:"profile"`
	// SANsURI adds arbitrary URI SAN values. SpiffeID is a convenience for
	// the common case: it's validated (see internal/spiffe) and appended
	// here automatically, so callers don't need to duplicate it.
	SANsURI  []string `json:"sans_uri"`
	SpiffeID string   `json:"spiffe_id"`
}

func (h *CertHandler) issue(w http.ResponseWriter, r *http.Request) {
	var req issueCertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	caID, err := uuid.Parse(req.CAID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ca_id")
		return
	}
	provID, err := uuid.Parse(req.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner_id")
		return
	}

	ips := make([]net.IP, 0, len(req.SANsIP))
	for _, s := range req.SANsIP {
		ip := net.ParseIP(s)
		if ip == nil {
			writeError(w, http.StatusBadRequest, "invalid IP in sans_ip: "+s)
			return
		}
		ips = append(ips, ip)
	}

	uris := make([]*url.URL, 0, len(req.SANsURI)+1)
	for _, v := range req.SANsURI {
		if strings.HasPrefix(v, "spiffe://") {
			u, err := spiffe.ValidateID(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			uris = append(uris, u)
			continue
		}
		u, err := url.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid URI in sans_uri: "+v)
			return
		}
		uris = append(uris, u)
	}
	if req.SpiffeID != "" {
		u, err := spiffe.ValidateID(req.SpiffeID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		uris = append(uris, u)
	}

	algo := req.KeyAlgo
	if algo == "" {
		algo = string(ca.DefaultKeyAlgo)
	}

	// Enforce a named profile (if requested) before any crypto work.
	if req.Profile != "" {
		prof, err := h.loadProfileByName(r.Context(), req.Profile)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if prof == nil {
			writeError(w, http.StatusBadRequest, "unknown profile \""+req.Profile+"\"")
			return
		}
		if err := policy.EvaluateProfile(prof, policy.CertRequest{
			KeyAlgo:    algo,
			TTLSeconds: req.TTLSeconds,
			SANsDNS:    req.SANsDNS,
			SANsIP:     ips,
			SANsEmail:  req.SANsEmail,
		}); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// Policy evaluation before any crypto work. The matched policy (if any)
	// supplies the Certificate Policies OIDs/CPS URI to embed at issuance —
	// avoids a second DB round-trip to re-resolve the same policy.
	matchedPolicy, err := h.policy.Evaluate(r.Context(), policy.CertRequest{
		CAID:          caID,
		ProvisionerID: provID,
		CommonName:    req.CommonName,
		SANsDNS:       req.SANsDNS,
		SANsIP:        ips,
		SANsEmail:     req.SANsEmail,
		TTLSeconds:    req.TTLSeconds,
		KeyAlgo:       algo,
	})
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	// Build key usage from the boolean flags.
	ku := gox509.KeyUsageDigitalSignature
	var eku []gox509.ExtKeyUsage
	if req.ServerAuth || (!req.ServerAuth && !req.ClientAuth) {
		ku |= gox509.KeyUsageKeyEncipherment
		eku = append(eku, gox509.ExtKeyUsageServerAuth)
	}
	if req.ClientAuth || (!req.ServerAuth && !req.ClientAuth) {
		eku = append(eku, gox509.ExtKeyUsageClientAuth)
	}

	var certPolicyOIDs []string
	var certPolicyCPSURI string
	if matchedPolicy != nil {
		certPolicyOIDs = matchedPolicy.PolicyOIDs
		certPolicyCPSURI = matchedPolicy.CPSURI
	}

	issued, err := h.engine.IssueCert(r.Context(), ca.IssueCertRequest{
		CAID:             caID,
		ProvisionerID:    provID,
		Requester:        actorFromContext(r),
		CommonName:       req.CommonName,
		SANsDNS:          req.SANsDNS,
		SANsIP:           ips,
		SANsEmail:        req.SANsEmail,
		SANsURI:          uris,
		TTLSeconds:       req.TTLSeconds,
		KeyAlgo:          ca.KeyAlgo(algo),
		KeyUsage:         ku,
		ExtKeyUsage:      eku,
		Metadata:         req.Metadata,
		CertPolicyOIDs:   certPolicyOIDs,
		CertPolicyCPSURI: certPolicyCPSURI,
		StoreKey:         req.StoreKey,
		KeyPasscode:      req.KeyPasscode,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.emitCertIssued(issued.Record)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"certificate": issued.Record,
		"cert_pem":    string(issued.CertPEM),
		"key_pem":     string(issued.KeyPEM),
		"chain_pem":   string(issued.ChainPEM),
	})
}

type signCSRRequest struct {
	CAID          string       `json:"ca_id"`
	ProvisionerID string       `json:"provisioner_id"`
	CSRPEM        string       `json:"csr_pem"`
	TTLSeconds    int64        `json:"ttl_seconds"`
	Metadata      storage.JSON `json:"metadata"`
	// Attestation optionally proves the CSR's key is bound to a hardware
	// root of trust (TPM, WebAuthn authenticator, ...). Opt-in: omit to sign
	// without an attestation check.
	Attestation *attestationRequest `json:"attestation,omitempty"`
}

func (h *CertHandler) signCSR(w http.ResponseWriter, r *http.Request) {
	var req signCSRRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	caID, err := uuid.Parse(req.CAID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ca_id")
		return
	}
	provID, err := uuid.Parse(req.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner_id")
		return
	}

	// CSR auto-approval rules (opt-in): if rules exist for this provisioner,
	// the CSR must be auto-approved or it is refused.
	if err := h.enforceCSRAutoApproval(r.Context(), provID, req.CSRPEM, req.TTLSeconds); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := h.verifyAttestation(r.Context(), req.CSRPEM, req.Attestation); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	issued, err := h.engine.SignCSR(r.Context(), ca.SignCSRRequest{
		CAID:          caID,
		ProvisionerID: provID,
		Requester:     actorFromContext(r),
		CSRPEM:        []byte(req.CSRPEM),
		TTLSeconds:    req.TTLSeconds,
		Metadata:      req.Metadata,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.emitCertIssued(issued.Record)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"certificate": issued.Record,
		"cert_pem":    string(issued.CertPEM),
		"chain_pem":   string(issued.ChainPEM),
	})
}

// batchSignCSR signs many caller-provided CSRs in one request (fleet/embedded
// provisioning). Each item is validated and signed independently; an item that
// fails is reported with an error and does not abort the rest (partial failure).
func (h *CertHandler) batchSignCSR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CAID          string          `json:"ca_id"`
		ProvisionerID string          `json:"provisioner_id"`
		Items         []batchSignItem `json:"items"`
		Metadata      storage.JSON    `json:"metadata"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must not be empty")
		return
	}
	caID, err := uuid.Parse(req.CAID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ca_id")
		return
	}
	provID, err := uuid.Parse(req.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner_id")
		return
	}
	if len(req.Items) > 1000 {
		writeError(w, http.StatusBadRequest, "too many items (max 1000)")
		return
	}

	// Per-item metadata overrides the shared metadata when present.
	results := make([]batchSignResult, 0, len(req.Items))
	for i, item := range req.Items {
		res := batchSignResult{Index: i}
		meta := req.Metadata
		if item.Metadata != nil {
			meta = item.Metadata
		}
		if err := h.verifyAttestation(r.Context(), item.CSRPEM, item.Attestation); err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		issued, err := h.engine.SignCSR(r.Context(), ca.SignCSRRequest{
			CAID:          caID,
			ProvisionerID: provID,
			Requester:     actorFromContext(r),
			CSRPEM:        []byte(item.CSRPEM),
			TTLSeconds:    item.TTLSeconds,
			Metadata:      meta,
		})
		if err != nil {
			res.Error = err.Error()
		} else {
			res.CertID = issued.Record.ID.String()
			res.Serial = issued.Record.Serial
			res.SubjectCN = issued.Record.SubjectCN
			res.CertPEM = string(issued.CertPEM)
			h.emitCertIssued(issued.Record)
		}
		results = append(results, res)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"issued":  countIssued(results),
		"failed":  len(results) - countIssued(results),
	})
}

// batchSignItem is one CSR to sign in a batch request.
type batchSignItem struct {
	CSRPEM      string              `json:"csr_pem"`
	TTLSeconds  int64               `json:"ttl_seconds"`
	Metadata    storage.JSON        `json:"metadata,omitempty"`
	Attestation *attestationRequest `json:"attestation,omitempty"`
}

// batchSignResult is the per-item outcome.
type batchSignResult struct {
	Index     int    `json:"index"`
	CertID    string `json:"cert_id,omitempty"`
	Serial    string `json:"serial,omitempty"`
	SubjectCN string `json:"subject_cn,omitempty"`
	CertPEM   string `json:"cert_pem,omitempty"`
	Error     string `json:"error,omitempty"`
}

func countIssued(results []batchSignResult) int {
	n := 0
	for _, res := range results {
		if res.Error == "" {
			n++
		}
	}
	return n
}

func (h *CertHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cert ID")
		return
	}
	cert, err := h.store.GetCertificate(r.Context(), id)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

// key returns the escrowed private key for a certificate. It returns 400 if a
// passcode is required but not supplied, 404 if the cert is not found, and 204/
// empty when the key was not stored (store_key=false).
func (h *CertHandler) key(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cert ID")
		return
	}
	_ = r.ParseForm()
	passcode := r.URL.Query().Get("passcode")
	keyPEM, err := h.engine.RetrieveKey(r.Context(), id, passcode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(keyPEM) == 0 {
		writeError(w, http.StatusNotFound, "no key stored for this certificate (store_key was not set)")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(keyPEM)
}

// export returns a certificate bundle: by default a tar.gz (leaf, chain,
// manifest) and, when the key was escrowed and a valid passcode is supplied,
// the key too. With ?format=p12 it instead returns a password-protected
// PKCS#12 file (requires an escrowed key + passcode, since a p12 always
// carries a key).
func (h *CertHandler) export(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cert ID")
		return
	}
	cert, err := h.store.GetCertificate(r.Context(), id)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	keyPEM, err := h.engine.RetrieveKey(r.Context(), id, r.URL.Query().Get("passcode"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if r.URL.Query().Get("format") == "p12" {
		chainPEM, err := h.engine.GetLeafChainPEM(r.Context(), cert.CAID, []byte(cert.CertPEM))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		password := r.URL.Query().Get("p12_password")
		if password == "" {
			password = pkcs12DefaultPassword
		}
		data, err := exportP12([]byte(cert.CertPEM), chainPEM, keyPEM, password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+cert.Serial+".p12\"")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}

	if r.URL.Query().Get("format") == "jks" {
		chainPEM, err := h.engine.GetLeafChainPEM(r.Context(), cert.CAID, []byte(cert.CertPEM))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		password := r.URL.Query().Get("jks_password")
		if password == "" {
			password = pkcs12DefaultPassword
		}
		alias := r.URL.Query().Get("jks_alias")
		if alias == "" {
			alias = "mint-ca"
		}
		data, err := exportJKS([]byte(cert.CertPEM), chainPEM, keyPEM, password, alias)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-java-keystore")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+cert.Serial+".jks\"")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}

	data, err := exportCert(r.Context(), h.engine, cert, keyPEM)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+cert.Serial+".tgz\"")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (h *CertHandler) getBySerial(w http.ResponseWriter, r *http.Request) {
	cert, err := h.store.GetCertificateBySerial(r.Context(), chi.URLParam(r, "serial"))
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *CertHandler) listByCA(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	certs, err := h.store.ListCertificatesByCA(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

type revokeRequest struct {
	Reason int `json:"reason"`
}

func (h *CertHandler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cert ID")
		return
	}
	var req revokeRequest
	_ = decodeJSON(r, &req)
	cert, _ := h.store.GetCertificate(r.Context(), id)
	if err := h.store.RevokeCertificate(r.Context(), id, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cert != nil {
		h.emitCertRevoked(cert, &req.Reason)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
