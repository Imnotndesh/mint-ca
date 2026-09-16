// Package passkey implements WebAuthn (passkey) registration and login for the
// mint-ca operator, plus short-lived step-up sessions used to require a fresh
// passkey assertion before high-risk admin actions.
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"mint-ca/internal/storage"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// UserHandle is the single operator identity passkeys are registered against.
const UserHandle = "operator"

// Store is the credential persistence surface.
type Store interface {
	CreatePasskeyCredential(ctx context.Context, c *storage.PasskeyCredential) error
	GetPasskeyCredential(ctx context.Context, id []byte) (*storage.PasskeyCredential, error)
	ListPasskeyCredentials(ctx context.Context) ([]*storage.PasskeyCredential, error)
	UpdatePasskeyCredential(ctx context.Context, c *storage.PasskeyCredential) error
	DeletePasskeyCredential(ctx context.Context, id []byte) error
}

// Service performs WebAuthn ceremonies and manages step-up sessions.
type Service struct {
	wa       *webauthn.WebAuthn
	store    Store
	stepTTL  time.Duration
	mu       sync.Mutex
	regSess  map[string]webauthn.SessionData
	authSess map[string]webauthn.SessionData
	stepUps  map[string]time.Time
}

// Config configures the passkey service.
type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
	StepUpTTL     time.Duration
}

// New builds a Service. Returns an error if the WebAuthn config is invalid.
func New(st Store, cfg Config) (*Service, error) {
	if cfg.StepUpTTL <= 0 {
		cfg.StepUpTTL = 15 * time.Minute
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: webauthn config: %w", err)
	}
	return &Service{
		wa:       wa,
		store:    st,
		stepTTL:  cfg.StepUpTTL,
		regSess:  map[string]webauthn.SessionData{},
		authSess: map[string]webauthn.SessionData{},
		stepUps:  map[string]time.Time{},
	}, nil
}

// operator implements webauthn.User over the stored credentials.
type operator struct {
	creds []webauthn.Credential
}

func (o *operator) WebAuthnID() []byte                         { return []byte(UserHandle) }
func (o *operator) WebAuthnName() string                       { return UserHandle }
func (o *operator) WebAuthnDisplayName() string                { return "mint-ca operator" }
func (o *operator) WebAuthnCredentials() []webauthn.Credential { return o.creds }

func (s *Service) loadOperator(ctx context.Context) (*operator, error) {
	recs, err := s.store.ListPasskeyCredentials(ctx)
	if err != nil {
		return nil, err
	}
	op := &operator{}
	for _, r := range recs {
		var cred webauthn.Credential
		if err := json.Unmarshal(r.CredentialJSON, &cred); err != nil {
			continue // skip unreadable rows rather than failing login entirely
		}
		op.creds = append(op.creds, cred)
	}
	return op, nil
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// BeginRegistration returns creation options and a session id the caller must
// return on Finish.
func (s *Service) BeginRegistration(ctx context.Context) (*protocol.CredentialCreation, string, error) {
	op, err := s.loadOperator(ctx)
	if err != nil {
		return nil, "", err
	}
	options, session, err := s.wa.BeginRegistration(op)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin registration: %w", err)
	}
	id := newToken()
	s.mu.Lock()
	s.regSess[id] = *session
	s.mu.Unlock()
	return options, id, nil
}

// FinishRegistration validates the attestation and stores the credential.
func (s *Service) FinishRegistration(ctx context.Context, sessionID string, body []byte) error {
	s.mu.Lock()
	session, ok := s.regSess[sessionID]
	delete(s.regSess, sessionID)
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("passkey: unknown registration session")
	}
	op, err := s.loadOperator(ctx)
	if err != nil {
		return err
	}
	cred, err := s.wa.FinishRegistration(op, session, requestFromBody(body))
	if err != nil {
		return fmt.Errorf("passkey: finish registration: %w", err)
	}
	raw, _ := json.Marshal(cred)
	return s.store.CreatePasskeyCredential(ctx, &storage.PasskeyCredential{
		ID:             cred.ID,
		UserHandle:     UserHandle,
		Name:           "passkey",
		CredentialJSON: raw,
		SignCount:      cred.Authenticator.SignCount,
		CreatedAt:      time.Now().UTC(),
	})
}

// BeginLogin returns assertion options and a session id.
func (s *Service) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	op, err := s.loadOperator(ctx)
	if err != nil {
		return nil, "", err
	}
	if len(op.creds) == 0 {
		return nil, "", fmt.Errorf("passkey: no passkeys registered")
	}
	options, session, err := s.wa.BeginLogin(op)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin login: %w", err)
	}
	id := newToken()
	s.mu.Lock()
	s.authSess[id] = *session
	s.mu.Unlock()
	return options, id, nil
}

// FinishLogin validates the assertion, updates the credential's sign counter,
// and returns a step-up token plus its expiry.
func (s *Service) FinishLogin(ctx context.Context, sessionID string, body []byte) (string, time.Time, error) {
	s.mu.Lock()
	session, ok := s.authSess[sessionID]
	delete(s.authSess, sessionID)
	s.mu.Unlock()
	if !ok {
		return "", time.Time{}, fmt.Errorf("passkey: unknown login session")
	}
	op, err := s.loadOperator(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	cred, err := s.wa.FinishLogin(op, session, requestFromBody(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("passkey: finish login: %w", err)
	}
	// Persist the new sign counter to keep replay protection intact.
	if rec, _ := s.store.GetPasskeyCredential(ctx, cred.ID); rec != nil {
		rec.SignCount = cred.Authenticator.SignCount
		now := time.Now().UTC()
		rec.LastUsed = &now
		raw, _ := json.Marshal(cred)
		rec.CredentialJSON = raw
		_ = s.store.UpdatePasskeyCredential(ctx, rec)
	}
	token := newToken()
	exp := time.Now().UTC().Add(s.stepTTL)
	s.mu.Lock()
	s.stepUps[token] = exp
	s.mu.Unlock()
	return token, exp, nil
}

// ValidateStepUp reports whether token is a live step-up session.
func (s *Service) ValidateStepUp(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.stepUps[token]
	if !ok {
		return false
	}
	if time.Now().UTC().After(exp) {
		delete(s.stepUps, token)
		return false
	}
	return true
}

// ListCredentials returns metadata (never the raw key material) for registered passkeys.
func (s *Service) ListCredentials(ctx context.Context) ([]*storage.PasskeyCredential, error) {
	return s.store.ListPasskeyCredentials(ctx)
}

// DeleteCredential removes a registered passkey by credential id.
func (s *Service) DeleteCredential(ctx context.Context, id []byte) error {
	return s.store.DeletePasskeyCredential(ctx, id)
}

// HasCredentials reports whether any passkey is registered.
func (s *Service) HasCredentials(ctx context.Context) bool {
	recs, err := s.store.ListPasskeyCredentials(ctx)
	return err == nil && len(recs) > 0
}

// requestFromBody adapts a raw JSON ceremony body into the *http.Request the
// webauthn library parses the credential/assertion from.
func requestFromBody(body []byte) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}
