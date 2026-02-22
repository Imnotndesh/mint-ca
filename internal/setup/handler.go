package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"mint-ca/internal/ca"
	"mint-ca/internal/config"
	"mint-ca/internal/storage"
)

// ReadyFunc is called by the handler when setup completes.
// Receives the PEM cert and key the server should use for TLS.
type ReadyFunc func(certPEM, keyPEM []byte) error

// Handler serves /setup/* endpoints.
type Handler struct {
	store    storage.Store
	caEngine *ca.Engine
	cfg      *config.Config
	onReady  ReadyFunc
}

func NewHandler(
	store storage.Store,
	caEngine *ca.Engine,
	cfg *config.Config,
	onReady ReadyFunc,
) *Handler {
	return &Handler{
		store:    store,
		caEngine: caEngine,
		cfg:      cfg,
		onReady:  onReady,
	}
}

func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Route("/setup", func(r chi.Router) {
		r.Use(h.requireBootstrapKey)
		r.Post("/root-ca", h.createRootCA)
		r.Post("/api-key", h.createAPIKey)
	})
}

func (h *Handler) requireBootstrapKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		sum := sha256.Sum256([]byte(auth[7:]))
		hash := hex.EncodeToString(sum[:])

		key, err := h.store.GetAPIKeyByHash(r.Context(), hash)
		if err != nil || key == nil || key.Name != bootstrapKeyName {
			writeError(w, http.StatusUnauthorized, "invalid bootstrap key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type createRootCARequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	KeyAlgo      string `json:"key_algo"`
	TTLDays      int    `json:"ttl_days"`
}

func (h *Handler) createRootCA(w http.ResponseWriter, r *http.Request) {
	var req createRootCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.CommonName == "" {
		req.CommonName = "mint-ca Root CA"
	}
	if req.KeyAlgo == "" {
		req.KeyAlgo = "ecdsa-p256"
	}
	if req.TTLDays == 0 {
		req.TTLDays = 3650
	}

	existing, _ := h.store.GetCAByName(r.Context(), "root")
	if existing != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "root CA already exists",
			"ca":      existing,
		})
		return
	}

	record, err := h.caEngine.CreateRootCA(r.Context(), ca.CreateRootCARequest{
		Name:         "root",
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Country:      req.Country,
		KeyAlgo:      ca.KeyAlgo(req.KeyAlgo),
		TTLDays:      req.TTLDays,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	slog.Info("setup: root CA created", "ca_id", record.ID)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "root CA created — now call POST /setup/api-key",
		"ca_id":   record.ID,
		"ca":      record,
	})
}

type createAPIKeyRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

func (h *Handler) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		req.Name = "admin"
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"*"}
	}

	rootCA, _ := h.store.GetCAByName(r.Context(), "root")
	if rootCA == nil {
		writeError(w, http.StatusBadRequest,
			"call POST /setup/root-ca first")
		return
	}

	// Create a provisioner so we can issue the server cert.
	prov := &storage.Provisioner{
		ID:        uuid.New(),
		CAID:      rootCA.ID,
		Name:      "setup",
		Type:      storage.ProvisionerTypeAPIKey,
		Config:    storage.JSON{},
		Status:    storage.ProvisionerStatusActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.store.CreateProvisioner(r.Context(), prov); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	serverCert, err := h.issueServerCert(r.Context(), rootCA, prov)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Create the permanent API key.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate key")
		return
	}
	rawKey := "mca_" + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(rawKey))
	hash := hex.EncodeToString(sum[:])

	newKey := &storage.APIKey{
		ID:        uuid.New(),
		Name:      req.Name,
		KeyHash:   hash,
		Scopes:    req.Scopes,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.store.CreateAPIKey(r.Context(), newKey); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := DeleteBootstrapKey(r.Context(), h.store); err != nil {
		slog.Warn("setup: could not delete bootstrap key", "err", err)
	}

	// Mark ready before responding so a restart lands in READY state.
	if err := h.store.SetSetupState(r.Context(), storage.StateReady); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	slog.Info("setup: complete")

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":    "setup complete — save your API key now, it will not be shown again",
		"api_key":    rawKey,
		"ca_id":      rootCA.ID,
		"root_chain": fmt.Sprintf("GET /pki/%s/chain", rootCA.ID),
	})

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		if err := h.onReady(serverCert.CertPEM, serverCert.KeyPEM); err != nil {
			slog.Error("setup: listener swap failed", "err", err)
		}
	}()
}

func (h *Handler) issueServerCert(
	ctx context.Context,
	rootCA *storage.CertificateAuthority,
	prov *storage.Provisioner,
) (*ca.IssuedCertificate, error) {
	sansDNS := []string{"localhost"}
	sansIP := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	if h.cfg.ACME.BaseURL != "" {
		host := stripScheme(h.cfg.ACME.BaseURL)
		if h2, _, err := net.SplitHostPort(host); err == nil {
			host = h2
		}
		if host != "" && host != "localhost" {
			if ip := net.ParseIP(host); ip != nil {
				sansIP = append(sansIP, ip)
			} else {
				sansDNS = append(sansDNS, host)
			}
		}
	}

	return h.caEngine.IssueCert(ctx, ca.IssueCertRequest{
		CAID:          rootCA.ID,
		ProvisionerID: prov.ID,
		Requester:     "setup",
		CommonName:    "mint-ca server",
		SANsDNS:       sansDNS,
		SANsIP:        sansIP,
		TTLSeconds:    int64((365 * 24 * time.Hour).Seconds()),
		KeyAlgo:       ca.KeyAlgoECDSAP256,
		KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Metadata:      storage.JSON{"issued_by": "setup"},
	})
}

func stripScheme(s string) string {
	for _, p := range []string{"https://", "http://"} {
		if len(s) >= len(p) && s[:len(p)] == p {
			return s[len(p):]
		}
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
