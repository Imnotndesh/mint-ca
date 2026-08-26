package acme

import (
	"context"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// TestRenewalInfo_WindowOpensLateInLifetime verifies the RFC 9779 window opens
// at 80% of the certificate's lifetime and closes at NotAfter.
func TestRenewalInfo_WindowOpensLateInLifetime(t *testing.T) {
	ctx := context.Background()

	notBefore := time.Now().UTC().Add(-10 * 24 * time.Hour) // issued 10 days ago
	notAfter := time.Now().UTC().Add(90 * 24 * time.Hour)   // expires in 90 days
	certID := uuid.New()

	store := NewFakeStore()
	_ = store.CreateCertificate(ctx, &storage.Certificate{
		ID: certID, CAID: uuid.New(), Serial: "123",
		CertPEM: "PEM", Status: storage.CertStatusActive,
		NotBefore: notBefore, NotAfter: notAfter, IssuedAt: notBefore,
	})
	svc2 := NewService(store, nil, NewNonceManager(NewFakeStore(), 0), nil, "https://ca.test")

	win, prob := svc2.RenewalInfo(ctx, certID)
	if prob != nil {
		t.Fatalf("RenewalInfo: %v", prob)
	}
	// Compute the expected start from the ACTUAL stored lifetime.
	rec, _ := store.GetCertificate(ctx, certID)
	life := rec.NotAfter.Sub(rec.NotBefore)
	wantStart := rec.NotBefore.Add(time.Duration(float64(life) * 0.8))
	if !win.Start.Equal(wantStart) {
		t.Errorf("expected window.start %v, got %v", wantStart, win.Start)
	}
	if !win.End.Equal(notAfter) {
		t.Errorf("expected window.end %v, got %v", notAfter, win.End)
	}
	// Window must open in the future (clearly after issuance, before expiry).
	if !win.Start.After(notBefore) || !win.Start.Before(notAfter) {
		t.Errorf("window.start %v not strictly within (notBefore, notAfter)", win.Start)
	}
}

// TestRenewalInfo_NotFound ensures a missing cert returns a problem.
func TestRenewalInfo_NotFound(t *testing.T) {
	ctx := context.Background()
	svc := NewService(NewFakeStore(), nil, NewNonceManager(NewFakeStore(), 0), nil, "https://ca.test")

	_, prob := svc.RenewalInfo(ctx, uuid.New())
	if prob == nil {
		t.Fatal("expected a 404 problem for an unknown certificate")
	}
	if prob.Status != 404 {
		t.Errorf("expected status 404, got %d", prob.Status)
	}
}
