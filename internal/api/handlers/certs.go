package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"

	gox509 "crypto/x509"
	"mint-ca/internal/ca"
	"mint-ca/internal/policy"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type CertHandler struct {
	engine *ca.Engine
	policy *policy.Engine
	store  storage.Store
}

func NewCertHandler(engine *ca.Engine, policyEngine *policy.Engine, store storage.Store) *CertHandler {
	return &CertHandler{engine: engine, policy: policyEngine, store: store}
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

func (h *CertHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/certs", func(r chi.Router) {
		r.Post("/issue", h.issue)
		r.Post("/sign", h.signCSR)
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

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"certificate": issued.Record,
		"cert_pem":    string(issued.CertPEM),
		"chain_pem":   string(issued.ChainPEM),
	})
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

// export returns a tar.gz bundle of a certificate (leaf, chain, manifest) and,
// when the key was escrowed and a valid passcode is supplied, the key too.
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
	if err := h.store.RevokeCertificate(r.Context(), id, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
