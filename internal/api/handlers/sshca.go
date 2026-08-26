package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"mint-ca/internal/sshca"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"mint-ca/internal/sshca/krl"
)

type SSHCAHandler struct {
	engine *sshca.Engine
	store  storage.Store
	krlMgr *krl.Manager
}

func NewSSHCAHandler(engine *sshca.Engine, store storage.Store, krlMgr *krl.Manager) *SSHCAHandler {
	return &SSHCAHandler{engine: engine, store: store, krlMgr: krlMgr}
}

func (h *SSHCAHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/sshca", func(r chi.Router) {
		r.Post("/", h.createCA)
		r.Get("/", h.listCAs)
		r.Get("/{caID}", h.getCA)
		r.Post("/{caID}/issue", h.issueCert)
		r.Post("/{caID}/sign/user", h.signUser)
		r.Post("/{caID}/sign/host", h.signHost)
		r.Get("/{caID}/certs", h.listCertsByCA)
	})

	r.Route("/api/v1/sshca/certs", func(r chi.Router) {
		r.Get("/{certID}", h.getCert)
		r.Get("/serial/{caID}/{serial}", h.getCertBySerial)
		r.Put("/{certID}/revoke", h.revokeCert)
	})
}

// RegisterPublicRoutes mounts the unauthenticated SSH CA endpoints on the
// public group, alongside the other /pki/* endpoints.
// RegisterPublicRoutes mounts the unauthenticated SSH CA endpoints.
func (h *SSHCAHandler) RegisterPublicRoutes(r chi.Router) {
	r.Get("/pki/sshca/{caID}/public-key", h.getPublicKey)
	r.Get("/pki/sshca/{caID}/krl", h.getKRL) // NEW
}

func (h *SSHCAHandler) getKRL(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	data, err := h.krlMgr.GetKRL(r.Context(), caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

type createSSHCARequest struct {
	Name    string `json:"name"`
	KeyAlgo string `json:"key_algo"`
}

func (h *SSHCAHandler) createCA(w http.ResponseWriter, r *http.Request) {
	var req createSSHCARequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	record, err := h.engine.CreateCA(r.Context(), sshca.CreateCARequest{
		Name:    req.Name,
		KeyAlgo: sshca.KeyAlgo(req.KeyAlgo),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, record)
}

func (h *SSHCAHandler) listCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := h.store.ListSSHCAs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cas)
}

func (h *SSHCAHandler) getCA(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	record, err := h.store.GetSSHCA(r.Context(), id)
	if err != nil || record == nil {
		writeError(w, http.StatusNotFound, "SSH CA not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

type issueSSHCertRequest struct {
	ProvisionerID string   `json:"provisioner_id"`
	CertType      string   `json:"cert_type"`
	PublicKey     string   `json:"public_key"`
	KeyID         string   `json:"key_id"`
	Principals    []string `json:"principals"`
	TTLSeconds    int64    `json:"ttl_seconds"`
}

func (h *SSHCAHandler) issueCert(w http.ResponseWriter, r *http.Request) {
	var req issueSSHCertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	certType := storage.SSHCertType(req.CertType)
	if certType != storage.SSHCertTypeUser && certType != storage.SSHCertTypeHost {
		writeError(w, http.StatusBadRequest, "invalid cert_type (must be 'user' or 'host')")
		return
	}

	h.issue(w, certType, req, r)
}

func (h *SSHCAHandler) signUser(w http.ResponseWriter, r *http.Request) {
	var req issueSSHCertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.issue(w, storage.SSHCertTypeUser, req, r)
}

func (h *SSHCAHandler) signHost(w http.ResponseWriter, r *http.Request) {
	var req issueSSHCertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.issue(w, storage.SSHCertTypeHost, req, r)
}

func (h *SSHCAHandler) issue(w http.ResponseWriter, certType storage.SSHCertType, req issueSSHCertRequest, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}

	provID, err := uuid.Parse(req.ProvisionerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provisioner_id")
		return
	}

	issued, err := h.engine.IssueCert(r.Context(), sshca.IssueCertRequest{
		CAID:           caID,
		ProvisionerID:  provID,
		Requester:      actorFromContext(r),
		CertType:       certType,
		PublicKeyInput: req.PublicKey,
		KeyID:          req.KeyID,
		Principals:     req.Principals,
		TTLSeconds:     req.TTLSeconds,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"certificate": issued.Record,
		"cert_data":   issued.CertData,
	})
}

func (h *SSHCAHandler) getPublicKey(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	record, err := h.store.GetSSHCA(r.Context(), caID)
	if err != nil || record == nil {
		writeError(w, http.StatusNotFound, "SSH CA not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(record.PublicKey))
}

func (h *SSHCAHandler) listCertsByCA(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	certs, err := h.store.ListSSHCertificatesByCA(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

func (h *SSHCAHandler) getCert(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cert ID")
		return
	}
	cert, err := h.store.GetSSHCertificate(r.Context(), id)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "SSH certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *SSHCAHandler) getCertBySerial(w http.ResponseWriter, r *http.Request) {
	caID, err := uuid.Parse(chi.URLParam(r, "caID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid CA ID")
		return
	}
	serial, err := strconv.ParseUint(chi.URLParam(r, "serial"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid serial")
		return
	}
	cert, err := h.store.GetSSHCertificateBySerial(r.Context(), caID, serial)
	if err != nil || cert == nil {
		writeError(w, http.StatusNotFound, "SSH certificate not found")
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *SSHCAHandler) revokeCert(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "certID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cert ID")
		return
	}
	if err := h.store.RevokeSSHCertificate(r.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "SSH certificate not found or already revoked")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

