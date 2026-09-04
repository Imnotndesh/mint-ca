package renewal

import (
	"context"
	"testing"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

type foreachFakeStore struct {
	storage.Store
	cas   []*storage.CertificateAuthority
	certs map[uuid.UUID][]*storage.Certificate
}

func (f *foreachFakeStore) ListCAs(ctx context.Context) ([]*storage.CertificateAuthority, error) {
	return f.cas, nil
}
func (f *foreachFakeStore) ListCertificatesByCA(ctx context.Context, caID uuid.UUID) ([]*storage.Certificate, error) {
	return f.certs[caID], nil
}

func TestForEachCert_ClassifiesAndFilters(t *testing.T) {
	ca1, ca2 := uuid.New(), uuid.New()
	now := time.Now().UTC()
	store := &foreachFakeStore{
		cas: []*storage.CertificateAuthority{{ID: ca1}, {ID: ca2}},
		certs: map[uuid.UUID][]*storage.Certificate{
			ca1: {{ID: uuid.New(), CAID: ca1, Status: storage.CertStatusActive, NotAfter: now.Add(24 * time.Hour)}},
			ca2: {{ID: uuid.New(), CAID: ca2, Status: storage.CertStatusActive, NotAfter: now.Add(24 * time.Hour)}},
		},
	}
	lead, expiring := 7*24*time.Hour, 48*time.Hour

	var seen []uuid.UUID
	err := ForEachCert(context.Background(), store, nil, now, lead, expiring, func(c *storage.Certificate, s Status) {
		seen = append(seen, c.CAID)
		if s != StatusExpiringSoon {
			t.Errorf("expected expiring_soon, got %v", s)
		}
	})
	if err != nil {
		t.Fatalf("ForEachCert: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("expected 2 certs across both CAs, got %d", len(seen))
	}

	seen = nil
	filter := ca1
	err = ForEachCert(context.Background(), store, &filter, now, lead, expiring, func(c *storage.Certificate, s Status) {
		seen = append(seen, c.CAID)
	})
	if err != nil {
		t.Fatalf("ForEachCert filtered: %v", err)
	}
	if len(seen) != 1 || seen[0] != ca1 {
		t.Fatalf("expected only ca1's cert, got %+v", seen)
	}
}
