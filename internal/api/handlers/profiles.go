package handlers

import (
	"context"
	"net/http"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// profileStore is the minimal CRUD surface the profile handler needs. Kept
// local so fake stores in other packages don't need to implement profiles.
type profileStore interface {
	CreateProfile(ctx context.Context, p *storage.Profile) error
	GetProfile(ctx context.Context, id uuid.UUID) (*storage.Profile, error)
	GetProfileByName(ctx context.Context, name string) (*storage.Profile, error)
	ListProfiles(ctx context.Context) ([]*storage.Profile, error)
	UpdateProfile(ctx context.Context, p *storage.Profile) error
	DeleteProfile(ctx context.Context, id uuid.UUID) error
}

type ProfileHandler struct{ store storage.Store }

func NewProfileHandler(store storage.Store) *ProfileHandler {
	return &ProfileHandler{store: store}
}

func (h *ProfileHandler) RegisterRoutes(r chi.Router) {
	r.Route("/api/v1/profiles", func(r chi.Router) {
		r.Post("/", h.create)
		r.Get("/", h.list)
		r.Get("/{profileID}", h.get)
		r.Put("/{profileID}", h.update)
		r.Delete("/{profileID}", h.delete)
	})
}

type profileRequest struct {
	Name            string   `json:"name"`
	AllowedKeyAlgos []string `json:"allowed_key_algos"`
	MinTTLSeconds   int64    `json:"min_ttl_seconds"`
	MaxTTLSeconds   int64    `json:"max_ttl_seconds"`
	RequireSAN      bool     `json:"require_san"`
	AllowWildcard   bool     `json:"allow_wildcard"`
}

func (h *ProfileHandler) profilesStore() (profileStore, bool) {
	s, ok := h.store.(profileStore)
	return s, ok
}

func (h *ProfileHandler) create(w http.ResponseWriter, r *http.Request) {
	var req profileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	s, ok := h.profilesStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support profiles")
		return
	}
	p := &storage.Profile{
		ID:              uuid.New(),
		Name:            req.Name,
		AllowedKeyAlgos: req.AllowedKeyAlgos,
		MinTTLSeconds:   req.MinTTLSeconds,
		MaxTTLSeconds:   req.MaxTTLSeconds,
		RequireSAN:      req.RequireSAN,
		AllowWildcard:   req.AllowWildcard,
		CreatedAt:       time.Now().UTC(),
	}
	if err := s.CreateProfile(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *ProfileHandler) list(w http.ResponseWriter, r *http.Request) {
	s, ok := h.profilesStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support profiles")
		return
	}
	ps, err := s.ListProfiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func (h *ProfileHandler) get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid profile ID")
		return
	}
	s, ok := h.profilesStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support profiles")
		return
	}
	p, err := s.GetProfile(r.Context(), id)
	if err != nil || p == nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *ProfileHandler) update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid profile ID")
		return
	}
	var req profileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s, ok := h.profilesStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support profiles")
		return
	}
	p := &storage.Profile{
		ID:              id,
		Name:            req.Name,
		AllowedKeyAlgos: req.AllowedKeyAlgos,
		MinTTLSeconds:   req.MinTTLSeconds,
		MaxTTLSeconds:   req.MaxTTLSeconds,
		RequireSAN:      req.RequireSAN,
		AllowWildcard:   req.AllowWildcard,
	}
	if err := s.UpdateProfile(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *ProfileHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "profileID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid profile ID")
		return
	}
	s, ok := h.profilesStore()
	if !ok {
		writeError(w, http.StatusInternalServerError, "store does not support profiles")
		return
	}
	if err := s.DeleteProfile(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
