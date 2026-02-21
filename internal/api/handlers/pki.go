package handlers

import (
	"net/http"

	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// PKIHandler serves the public PKI endpoints that must be reachable by TLS
// clients and tools like Traefik. No authentication is required on these routes
// because CRLs, OCSP responses, and CA chains are public by design.
type PKIHandler struct {
	crl   *revocation.CRLManager
	ocsp  *revocation.OCSPResponder
	ca    *ca.Engine
	store storage.Store
}

func NewPKIHandler(
	crl *revocation.CRLManager,
	ocsp *revocation.OCSPResponder,
	caEngine *ca.Engine,
	store storage.Store,
) *PKIHandler {
	return &PKIHandler{crl: crl, ocsp: ocsp, ca: caEngine, store: store}
}

func (h *PKIHandler) RegisterRoutes(r chi.Router) {
	r.Route("/pki/{caID}", func(r chi.Router) {
		r.Get("/crl", h.getCRLPEM)
		r.Get("/crl.der", h.getCRLDER)
		r.Post("/ocsp", h.respondOCSP)
		r.Get("/chain", h.getChain)
	})
}

func (h *PKIHandler) getCRLPEM(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	crlPEM, err := h.crl.GetCRL(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(crlPEM)
}

func (h *PKIHandler) getCRLDER(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	crlDER, err := h.crl.GetCRLDER(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(crlDER)
}

func (h *PKIHandler) respondOCSP(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}

	// OCSP requests can be up to a few hundred bytes. Cap the read to 4KB
	// to guard against oversized payloads.
	body := make([]byte, 4096)
	n, _ := r.Body.Read(body)
	body = body[:n]

	// Respond always returns a valid DER OCSP response — never a Go error.
	resp := h.ocsp.Respond(r.Context(), caID, body)

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (h *PKIHandler) getChain(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	chainPEM, err := h.ca.GetChainPEM(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(chainPEM)
}
