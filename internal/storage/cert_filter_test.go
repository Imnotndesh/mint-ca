package storage

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedFilteredCerts(t *testing.T, s *sqliteStore, ctx context.Context) (ca uuid.UUID) {
	ca = uuid.New()
	err := s.CreateCA(ctx, &CertificateAuthority{
		ID: ca, Name: "root", Type: CATypeRoot, Status: CAStatusActive,
		CertPEM: "CERT", KeyEnc: []byte("k"), KeyAlgo: "ecdsa-p256",
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	prov := &Provisioner{ID: uuid.New(), CAID: ca, Name: "p", Type: ProvisionerTypeAPIKey, Status: ProvisionerStatusActive, CreatedAt: time.Now().UTC()}
	if err := s.CreateProvisioner(ctx, prov); err != nil {
		t.Fatalf("create provisioner: %v", err)
	}
	now := time.Now().UTC()
	certs := []*Certificate{
		{ID: uuid.New(), CAID: ca, Serial: "1", SubjectCN: "web.example.com", Status: CertStatusActive, IssuedAt: now, ProvisionerID: prov.ID},
		{ID: uuid.New(), CAID: ca, Serial: "2", SubjectCN: "api.example.org", Status: CertStatusRevoked, IssuedAt: now, ProvisionerID: prov.ID},
	}
	for _, c := range certs {
		c.NotBefore = now.Add(-time.Minute)
		c.NotAfter = now.Add(time.Hour)
		c.CertPEM = "PCERT"
		if err := s.CreateCertificate(ctx, c); err != nil {
			t.Fatalf("create cert: %v", err)
		}
	}
	return ca
}

func TestSQLite_ListCertificatesFiltered(t *testing.T) {
	s, err := newSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	ca := seedFilteredCerts(t, s, ctx)

	// status filter
	revoked, err := s.ListCertificatesFiltered(ctx, nil, CertStatusRevoked, "", 10, 0)
	if err != nil {
		t.Fatalf("status filter: %v", err)
	}
	if len(revoked) != 1 || revoked[0].SubjectCN != "api.example.org" {
		t.Fatalf("status filter got %d", len(revoked))
	}

	// subject search (q)
	found, err := s.ListCertificatesFiltered(ctx, nil, "", "web.example", 10, 0)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(found) != 1 || found[0].SubjectCN != "web.example.com" {
		t.Fatalf("search got %d", len(found))
	}

	// ca_id + status combination
	both, err := s.ListCertificatesFiltered(ctx, &ca, CertStatusActive, "", 10, 0)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if len(both) != 1 || both[0].SubjectCN != "web.example.com" {
		t.Fatalf("combine got %d", len(both))
	}
}
