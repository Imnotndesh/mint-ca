package acme

import (
	"context"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func newRenewalService(t *testing.T, cert *storage.Certificate) (*Service, *fakeStore) {
	t.Helper()
	store := NewFakeStore()
	if cert != nil {
		_ = store.CreateCertificate(ctxTest, cert)
	}
	svc := NewService(store, nil, NewNonceManager(NewFakeStore(), 0), nil, "https://ca.test")
	return svc, store
}

var ctxTest = context.Background()

func certRecord(certID uuid.UUID, nb, na time.Time) *storage.Certificate {
	return &storage.Certificate{
		ID: certID, CAID: uuid.New(), Serial: "123",
		CertPEM: "PEM", Status: storage.CertStatusActive,
		NotBefore: nb, NotAfter: na, IssuedAt: nb,
	}
}

// floor: start = end - max(lifetime/5, 24h), never before notBefore.
func TestRenewalInfo_DefaultLeadIsFractionWithFloor(t *testing.T) {
	certID := uuid.New()
	now := time.Now().UTC()
	// lifetime 100 days -> leadTime = max(20d,24h)=20d -> start = notAfter-20d.
	nb := now.Add(-10 * 24 * time.Hour)
	na := now.Add(90 * 24 * time.Hour)
	svc, store := newRenewalService(t, certRecord(certID, nb, na))

	win, prob := svc.RenewalInfo(ctxTest, certID, 0)
	if prob != nil {
		t.Fatalf("RenewalInfo: %v", prob)
	}
	wantStart := na.Add(-20 * 24 * time.Hour)
	if !win.End.Equal(na) {
		t.Errorf("end: got %v want %v", win.End, na)
	}
	if !win.Start.Equal(wantStart) {
		t.Errorf("start: got %v want %v", win.Start, wantStart)
	}
	_ = store
}

// Short lifetime (< ~1 day) triggers the 24h floor; start must clamp to notAfter.
func TestRenewalInfo_ShortLifetimeUsesFloor(t *testing.T) {
	certID := uuid.New()
	now := time.Now().UTC()
	nb := now.Add(-1 * time.Hour)
	na := now.Add(12 * time.Hour) // lifetime 13h -> fraction/5 = 2.6h, floor 24h wins
	svc, _ := newRenewalService(t, certRecord(certID, nb, na))

	win, prob := svc.RenewalInfo(ctxTest, certID, 0)
	if prob != nil {
		t.Fatalf("RenewalInfo: %v", prob)
	}
	if !win.End.Equal(na) {
		t.Errorf("end: got %v want %v", win.End, na)
	}
	// start must not be before notBefore (clamp).
	if win.Start.Before(nb) {
		t.Errorf("start %v clamped below notBefore %v", win.Start, nb)
	}
}

// Explicit override wins over fraction/floor.
func TestRenewalInfo_OverrideLead(t *testing.T) {
	certID := uuid.New()
	now := time.Now().UTC()
	nb := now.Add(-10 * 24 * time.Hour)
	na := now.Add(90 * 24 * time.Hour)
	svc, _ := newRenewalService(t, certRecord(certID, nb, na))

	override := 5 * 24 * time.Hour
	win, prob := svc.RenewalInfo(ctxTest, certID, override)
	if prob != nil {
		t.Fatalf("RenewalInfo: %v", prob)
	}
	if want := na.Add(-override); !win.Start.Equal(want) {
		t.Errorf("override start: got %v want %v", win.Start, want)
	}
}

func TestRenewalInfo_NotFound(t *testing.T) {
	svc, _ := newRenewalService(t, nil)
	if _, prob := svc.RenewalInfo(ctxTest, uuid.New(), 0); prob == nil || prob.Status != 404 {
		t.Fatalf("expected 404, got %v", prob)
	}
}
