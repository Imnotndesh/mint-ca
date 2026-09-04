package handlers

import (
	"net/http"
	"time"

	"mint-ca/internal/config"
	"mint-ca/internal/renewal"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// RenewalHandler exposes read-only renewal-risk intel derived from existing
// certificate data, so external automation can alert on certs needing action.
type RenewalHandler struct {
	store storage.Store
	lead  time.Duration
	exp   time.Duration
}

func NewRenewalHandler(store storage.Store, cfg config.RenewalConfig) *RenewalHandler {
	lead := time.Duration(cfg.LeadSeconds) * time.Second
	if lead <= 0 {
		lead = 7 * 24 * time.Hour
	}
	exp := time.Duration(cfg.ExpiringSeconds) * time.Second
	if exp <= 0 {
		exp = 48 * time.Hour
	}
	return &RenewalHandler{store: store, lead: lead, exp: exp}
}

func (h *RenewalHandler) RegisterRoutes(r chi.Router) {
	r.Get("/api/v1/renewal/status", h.status)
}

// renewalEntry is the per-certificate renewal-risk view.
type renewalEntry struct {
	CertID    string         `json:"cert_id"`
	CAID      string         `json:"ca_id"`
	SubjectCN string         `json:"subject_cn"`
	ExpiresAt time.Time      `json:"expires_at"`
	DaysLeft  int            `json:"days_left"`
	Status    renewal.Status `json:"status"`
}

// renewalSummary groups counts by status so automation can alert on totals
// without walking the full cert list.
type renewalSummary struct {
	Due          int `json:"due"`
	ExpiringSoon int `json:"expiring_soon"`
	Expired      int `json:"expired"`
	Revoked      int `json:"revoked"`
}

type renewalStatusResponse struct {
	Certificates []renewalEntry `json:"certificates"`
	Summary      renewalSummary `json:"summary"`
}

func (h *RenewalHandler) status(w http.ResponseWriter, r *http.Request) {
	var caIDFilter uuid.UUID
	hasFilter := false
	if v := r.URL.Query().Get("ca_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ca_id")
			return
		}
		caIDFilter = id
		hasFilter = true
	}

	cas, err := h.store.ListCAs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now().UTC()
	resp := renewalStatusResponse{Certificates: []renewalEntry{}}
	for _, ca := range cas {
		if hasFilter && ca.ID != caIDFilter {
			continue
		}
		certs, err := h.store.ListCertificatesByCA(r.Context(), ca.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, c := range certs {
			st := renewal.Classify(c.Status, c.NotAfter, now, h.lead, h.exp)
			if st == renewal.StatusValid {
				continue
			}
			resp.Certificates = append(resp.Certificates, renewalEntry{
				CertID:    c.ID.String(),
				CAID:      c.CAID.String(),
				SubjectCN: c.SubjectCN,
				ExpiresAt: c.NotAfter,
				DaysLeft:  int(c.NotAfter.Sub(now).Hours() / 24),
				Status:    st,
			})
			switch st {
			case renewal.StatusDue:
				resp.Summary.Due++
			case renewal.StatusExpiringSoon:
				resp.Summary.ExpiringSoon++
			case renewal.StatusExpired:
				resp.Summary.Expired++
			case renewal.StatusRevoked:
				resp.Summary.Revoked++
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
