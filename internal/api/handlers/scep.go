// SCEP support. This is a simplified, documented-limited implementation: it
// does not wrap requests/responses in PKCS#7 as the full SCEP spec (and its
// successor, draft-ietf-lamps-scep) requires for PKIOperation. It accepts a
// raw PKCS#10 CSR as the POST body and returns a raw DER leaf certificate
// instead of a PKCS#7 degenerate certs-only message. Devices/MDM stacks that
// speak full SCEP need a PKCS#7 unwrap/wrap shim in front of this endpoint;
// see docs/Api.md for the documented deviation.
package handlers

import (
	"encoding/pem"
	"errors"
	"io"
	"net/http"

	gox509 "crypto/x509"

	"mint-ca/internal/ca"
	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// scepCapabilities lists the operations/algorithms this SCEP endpoint
// supports, in the newline-separated text/plain format GetCACaps expects.
// Encryption-related capabilities (DES3/AES) are intentionally omitted since
// PKIOperation is not PKCS#7-wrapped here.
const scepCapabilities = "GetNextCACert\nPOSTPKIOperation\nSHA-256\nRenewal"

// SCEPHandler serves a simplified public SCEP enrollment endpoint at
// /pki/{caID}/scep, signing enrollments via the same CA engine and CSR
// auto-approval gate as normal CSR signing.
type SCEPHandler struct {
	engine *ca.Engine
	store  storage.Store
	cfg    config.SCEPConfig
}

func NewSCEPHandler(engine *ca.Engine, store storage.Store, cfg config.SCEPConfig) *SCEPHandler {
	return &SCEPHandler{engine: engine, store: store, cfg: cfg}
}

// RegisterRoutes mounts the SCEP routes. A no-op when SCEP is disabled, so
// the routes simply don't exist rather than returning an error at every call.
func (h *SCEPHandler) RegisterRoutes(r chi.Router) {
	if !h.cfg.Enabled {
		return
	}
	r.Route("/pki/{caID}/scep", func(r chi.Router) {
		r.Get("/", h.handleGET)
		r.Post("/", h.handlePOST)
	})
}

func (h *SCEPHandler) handleGET(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("operation") {
	case "GetCACaps":
		h.getCACaps(w, r)
	case "GetCACert":
		h.getCACert(w, r)
	case "GetNextCACert":
		// mint-ca does not cross-cert a renewal chain; report gracefully
		// rather than pretending to support CA rollover.
		writeError(w, http.StatusNotImplemented, "GetNextCACert is not supported")
	default:
		writeError(w, http.StatusBadRequest, "unsupported or missing operation")
	}
}

func (h *SCEPHandler) handlePOST(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("operation") {
	case "", "PKCSReq", "PKIOperation":
		h.pkcsReq(w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported operation")
	}
}

func (h *SCEPHandler) getCACaps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(scepCapabilities))
}

func (h *SCEPHandler) getCACert(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	caRecord, err := h.store.GetCA(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if caRecord == nil {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	der, err := pemToDER(caRecord.CertPEM)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

func (h *SCEPHandler) pkcsReq(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	provID, err := uuid.Parse(h.cfg.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SCEP provisioner is not configured")
		return
	}

	csrDER, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read CSR body: "+err.Error())
		return
	}
	csr, err := gox509.ParseCertificateRequest(csrDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CSR: "+err.Error())
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeError(w, http.StatusBadRequest, "CSR signature invalid: "+err.Error())
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enforceCSRAutoApproval(r.Context(), h.store, provID, string(csrPEM), h.cfg.DefaultTTLSeconds); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	issued, err := h.engine.SignCSR(r.Context(), ca.SignCSRRequest{
		CAID:          caID,
		ProvisionerID: provID,
		Requester:     "scep:" + csr.Subject.CommonName,
		CSRPEM:        csrPEM,
		TTLSeconds:    h.cfg.DefaultTTLSeconds,
		Metadata:      storage.JSON{"enrollment": "scep"},
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "sign CSR failed: "+err.Error())
		return
	}

	der, err := pemToDER(string(issued.CertPEM))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-user-cert")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}

func pemToDER(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("scep: invalid PEM")
	}
	return block.Bytes, nil
}
