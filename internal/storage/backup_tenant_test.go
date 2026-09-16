package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSQLite_TenantExportRestore(t *testing.T) {
	ctx := context.Background()

	// Source instance with one tenant's full object graph.
	src, err := newSQLiteStore(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatalf("src store: %v", err)
	}
	defer src.Close()

	tenantID := uuid.New()
	if err := src.CreateTenant(ctx, &Tenant{ID: tenantID, Name: "acme", Status: TenantStatusActive, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	keyEnc := []byte{0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f}
	caID := uuid.New()
	if err := src.CreateCA(ctx, &CertificateAuthority{
		ID: caID, Name: "acme-root", Type: CATypeRoot, Status: CAStatusActive,
		CertPEM: "CERT", KeyEnc: keyEnc, KeyAlgo: "ecdsa-p256",
		TenantID: tenantID, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create ca: %v", err)
	}
	provID := uuid.New()
	if err := src.CreateProvisioner(ctx, &Provisioner{
		ID: provID, CAID: caID, Name: "acme-prov", Type: ProvisionerTypeAPIKey,
		Status: ProvisionerStatusActive, TenantID: tenantID, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create provisioner: %v", err)
	}
	if err := src.CreateCertificate(ctx, &Certificate{
		ID: uuid.New(), CAID: caID, Serial: "42", SubjectCN: "svc.acme",
		Status: CertStatusActive, ProvisionerID: provID, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IssuedAt: time.Now().UTC(), CertPEM: "LEAF",
	}); err != nil {
		t.Fatalf("create cert: %v", err)
	}

	data, err := src.TenantExport(ctx, tenantID.String())
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Fresh instance (its Migrate seeds only the default tenant).
	dst, err := newSQLiteStore(filepath.Join(t.TempDir(), "dst.db"))
	if err != nil {
		t.Fatalf("dst store: %v", err)
	}
	defer dst.Close()

	got, err := dst.TenantRestore(ctx, data)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got == nil || got.ID != tenantID {
		t.Fatalf("tenant not restored: %+v", got)
	}
	ca, err := dst.GetCA(ctx, caID)
	if err != nil || ca == nil {
		t.Fatalf("restored CA missing: %v", err)
	}
	if string(ca.KeyEnc) != string(keyEnc) {
		t.Fatalf("key material mismatch: got %x want %x", ca.KeyEnc, keyEnc)
	}
	if p, _ := dst.GetProvisioner(ctx, provID); p == nil {
		t.Fatal("restored provisioner missing")
	}
	if c, _ := dst.GetCertificateBySerial(ctx, "42"); c == nil {
		t.Fatal("restored certificate missing")
	}
}

func TestSQLite_TenantRestore_RejectsDuplicate(t *testing.T) {
	ctx := context.Background()
	s, err := newSQLiteStore(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer s.Close()
	id := uuid.New()
	_ = s.CreateTenant(ctx, &Tenant{ID: id, Name: "t", Status: TenantStatusActive, CreatedAt: time.Now().UTC()})
	data, err := s.TenantExport(ctx, id.String())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if _, err := s.TenantRestore(ctx, data); err == nil {
		t.Fatal("expected error restoring an existing tenant")
	}
}
