package renewal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// renewalFakeStore is a minimal store: ListCAs + ListCertificatesByCA.
type renewalFakeStore struct {
	storage.Store
	cas   []*storage.CertificateAuthority
	certs map[uuid.UUID][]*storage.Certificate
}

func (f *renewalFakeStore) Close() error { return nil }
func (f *renewalFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	return f.cas, nil
}
func (f *renewalFakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	return f.certs[caID], nil
}

func TestFindDue_ReturnsOnlyExpiringActiveCerts(t *testing.T) {
	ctx := context.Background()
	caID := uuid.New()
	store := &renewalFakeStore{
		cas:   []*storage.CertificateAuthority{{ID: caID, Status: storage.CAStatusActive}},
		certs: map[uuid.UUID][]*storage.Certificate{},
	}
	now := time.Now().UTC()
	store.certs[caID] = []*storage.Certificate{
		{ID: uuid.New(), CAID: caID, Status: storage.CertStatusActive, NotAfter: now.Add(24 * time.Hour)},      // expiring soon
		{ID: uuid.New(), CAID: caID, Status: storage.CertStatusActive, NotAfter: now.Add(30 * 24 * time.Hour)}, // not due
		{ID: uuid.New(), CAID: caID, Status: storage.CertStatusRevoked, NotAfter: now.Add(time.Hour)},          // revoked, skip
	}
	w := NewWorker(store, nil, time.Hour, 7*24*time.Hour)
	due, err := w.findDue(ctx, now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("findDue: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("expected 1 due cert, got %d", len(due))
	}
	if due[0].ID != store.certs[caID][0].ID {
		t.Error("expected the soon-expiring cert")
	}
}

func TestWebhookDeliverer_PostsNotice(t *testing.T) {
	var got Notice
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewWebhookDeliverer(ts.URL)
	err := d.Deliver(context.Background(), Notice{
		CertID:    "c1",
		CAID:      "a1",
		Serial:    "42",
		SubjectCN: "svc.example.com",
		ExpiresAt: time.Now().UTC().Add(3 * 24 * time.Hour),
		DaysLeft:  3,
	})
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if got.CertID != "c1" || got.SubjectCN != "svc.example.com" {
		t.Errorf("unexpected notice: %+v", got)
	}
}
